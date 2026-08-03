import asyncio
import json
from collections import deque

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from src.dashboard import server
from src.storage.models import AccountStatus


class _JsonRequest:
    def __init__(self, payload):
        self._payload = payload

    async def json(self):
        return self._payload


@pytest.mark.asyncio
async def test_exports_list_and_content_use_only_regular_txt_files(tmp_path, monkeypatch):
    export_dir = tmp_path / "exports"
    export_dir.mkdir()
    (export_dir / "cleaned.txt").write_text(
        "# header\n\nfirst@example.com----password----secret\n",
        encoding="utf-8",
    )
    (export_dir / "ignore.csv").write_text("not an export", encoding="utf-8")
    monkeypatch.setattr(server, "EXPORT_DIR", export_dir)

    response = await server._exports(make_mocked_request("GET", "/api/exports"))
    payload = json.loads(response.body)

    assert [item["name"] for item in payload["files"]] == ["cleaned.txt"]
    assert payload["files"][0]["lines"] == 1

    content_response = await server._export_content(
        make_mocked_request(
            "GET",
            "/api/exports/content?file=cleaned.txt",
        )
    )
    assert "first@example.com" in content_response.text
    assert content_response.headers["Content-Disposition"] == (
        'inline; filename="cleaned.txt"'
    )


@pytest.mark.asyncio
async def test_delete_export_removes_only_named_file(tmp_path, monkeypatch):
    export_dir = tmp_path / "exports"
    export_dir.mkdir()
    target = export_dir / "old.txt"
    keep = export_dir / "keep.txt"
    target.write_text("old", encoding="utf-8")
    keep.write_text("keep", encoding="utf-8")
    monkeypatch.setattr(server, "EXPORT_DIR", export_dir)

    request = make_mocked_request(
        "DELETE",
        "/api/exports/old.txt",
        match_info={"filename": "old.txt"},
    )
    response = await server._delete_export(request)
    payload = json.loads(response.body)

    assert payload == {
        "deleted": True,
        "deleted_file": "old.txt",
        "remaining": 1,
    }
    assert not target.exists()
    assert keep.read_text(encoding="utf-8") == "keep"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "unsafe_name",
    [
        "../outside.txt",
        "..\\outside.txt",
        "C:outside.txt",
        "keep.txt:stream.txt",
        "not-a-txt.csv",
    ],
)
async def test_delete_export_rejects_unsafe_names(
    tmp_path, monkeypatch, unsafe_name
):
    export_dir = tmp_path / "exports"
    export_dir.mkdir()
    inside = export_dir / "keep.txt"
    outside = tmp_path / "outside.txt"
    inside.write_text("inside", encoding="utf-8")
    outside.write_text("outside", encoding="utf-8")
    monkeypatch.setattr(server, "EXPORT_DIR", export_dir)
    request = make_mocked_request(
        "DELETE",
        "/api/exports/unsafe",
        match_info={"filename": unsafe_name},
    )

    with pytest.raises(web.HTTPBadRequest):
        await server._delete_export(request)

    assert inside.read_text(encoding="utf-8") == "inside"
    assert outside.read_text(encoding="utf-8") == "outside"


@pytest.mark.asyncio
async def test_cleanup_empty_exports_preserves_nonempty_and_outside_files(
    tmp_path, monkeypatch
):
    export_dir = tmp_path / "exports"
    export_dir.mkdir()
    (export_dir / "zero.txt").write_bytes(b"")
    (export_dir / "comments.txt").write_text(
        "\n# no account rows\n   \n", encoding="utf-8"
    )
    keep = export_dir / "keep.txt"
    keep.write_text("user@example.com----password----secret\n", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("do not delete", encoding="utf-8")
    monkeypatch.setattr(server, "EXPORT_DIR", export_dir)

    response = await server._cleanup_exports(_JsonRequest({"mode": "empty"}))
    payload = json.loads(response.body)

    assert payload["deleted"] == 2
    assert set(payload["deleted_files"]) == {"zero.txt", "comments.txt"}
    assert payload["remaining"] == 1
    assert keep.exists()
    assert outside.read_text(encoding="utf-8") == "do not delete"


@pytest.mark.asyncio
async def test_cleanup_rejects_unknown_mode(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "EXPORT_DIR", tmp_path / "exports")

    with pytest.raises(web.HTTPBadRequest):
        await server._cleanup_exports(_JsonRequest({"mode": "all"}))


@pytest.mark.asyncio
async def test_export_symlink_cannot_read_or_delete_outside_file(tmp_path, monkeypatch):
    export_dir = tmp_path / "exports"
    export_dir.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    link = export_dir / "linked.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks are not available in this Windows environment")
    monkeypatch.setattr(server, "EXPORT_DIR", export_dir)

    request = make_mocked_request(
        "DELETE",
        "/api/exports/linked.txt",
        match_info={"filename": "linked.txt"},
    )
    with pytest.raises(web.HTTPBadRequest):
        await server._delete_export(request)

    assert outside.read_text(encoding="utf-8") == "outside"


@pytest.mark.asyncio
async def test_import_with_no_verified_records_does_not_create_empty_export(
    tmp_path, monkeypatch
):
    from src.queues import task_queue
    from src.storage import db_manager

    class _Account:
        status = AccountStatus.FAILED

    class _Task:
        account = _Account()

    class _Queue:
        def __init__(self, max_workers):
            self.max_workers = max_workers

        async def run(self, tasks):
            return None

    class _DB:
        async def init(self):
            return None

        async def upsert(self, account):
            raise AssertionError("failed accounts must not be exported")

    export_dir = tmp_path / "exports"
    status = server._new_import_job("input.txt", 1)
    monkeypatch.setattr(server, "EXPORT_DIR", export_dir)
    monkeypatch.setattr(server, "_import_lock", None)
    monkeypatch.setattr(task_queue, "TaskQueue", _Queue)
    monkeypatch.setattr(db_manager, "get_db", lambda: _DB())

    await server._run_import_batch([_Task()], "input.txt", status=status)

    assert status["state"] == "done"
    assert status["export_file"] is None
    assert status["message"] == "无成功结果，未生成文件"
    assert not list(export_dir.glob("*.txt"))


@pytest.mark.asyncio
async def test_text_import_reuses_txt_parser_and_enqueues_batch(monkeypatch):
    captured = {}

    def fake_enqueue(tasks, source_name, rejected=0):
        captured["tasks"] = tasks
        captured["source"] = source_name
        captured["rejected"] = rejected
        return server._new_import_job(source_name, len(tasks), rejected), 1

    monkeypatch.setattr(
        server.config.browser, "executable_available", lambda: True
    )
    monkeypatch.setattr(server, "_enqueue_import", fake_enqueue)
    request = _JsonRequest({
        "content": (
            "first@example.com----pass1----abcd efgh\n"
            "invalid row\n"
            "second@example.com----pass2----secret2\n"
        )
    })

    response = await server._import_text(request)
    payload = json.loads(response.body)

    assert payload["accepted"] == 2
    assert payload["rejected"] == 1
    assert payload["queued"] is True
    assert payload["queue_position"] == 1
    assert captured["source"] == "粘贴输入"
    assert captured["rejected"] == 1
    assert captured["tasks"][0].account.gmail == "first@example.com"
    assert captured["tasks"][0].credential.totp_secret == "abcdefgh"


@pytest.mark.asyncio
async def test_import_batches_run_fifo_and_report_running_and_queued(
    tmp_path, monkeypatch
):
    from src.queues import task_queue
    from src.storage import db_manager

    started = asyncio.Event()
    release = asyncio.Event()
    run_order = []

    class _Account:
        status = AccountStatus.FAILED

    class _Task:
        def __init__(self, label):
            self.label = label
            self.account = _Account()

    class _Queue:
        def __init__(self, max_workers):
            self.max_workers = max_workers

        async def run(self, tasks):
            label = tasks[0].label
            run_order.append(label)
            if label == "first":
                started.set()
                await release.wait()

    class _DB:
        async def init(self):
            return None

        async def upsert(self, account):
            raise AssertionError("failed accounts must not be exported")

    monkeypatch.setattr(server, "EXPORT_DIR", tmp_path / "exports")
    monkeypatch.setattr(server, "_import_jobs", [])
    monkeypatch.setattr(server, "_import_pending", deque())
    monkeypatch.setattr(server, "_import_worker_task", None)
    monkeypatch.setattr(server, "_import_lock", None)
    monkeypatch.setattr(task_queue, "TaskQueue", _Queue)
    monkeypatch.setattr(db_manager, "get_db", lambda: _DB())

    first, first_position = server._enqueue_import([_Task("first")], "first.txt")
    second, second_position = server._enqueue_import([_Task("second")], "second.txt")
    await started.wait()

    active_payload = server._import_status_payload()
    assert first_position == 1
    assert second_position == 2
    assert active_payload["state"] == "running"
    assert active_payload["job_id"] == first["id"]
    assert active_payload["queue_size"] == 1
    assert [job["state"] for job in active_payload["jobs"]] == [
        "running",
        "queued",
    ]

    release.set()
    worker = server._import_worker_task
    assert worker is not None
    await worker

    final_payload = server._import_status_payload()
    assert run_order == ["first", "second"]
    assert [job["state"] for job in final_payload["jobs"]] == ["done", "done"]
    assert final_payload["queue_size"] == 0
    assert final_payload["job_id"] == second["id"]
    assert final_payload["state"] == "done"
    assert not list((tmp_path / "exports").glob("*.txt"))


@pytest.mark.asyncio
async def test_static_css_and_whitelisted_asset_are_not_cached(tmp_path, monkeypatch):
    static_dir = tmp_path / "visual-dashboard"
    asset_dir = static_dir / "assets"
    asset_dir.mkdir(parents=True)
    (static_dir / "styles.css").write_text("body {}", encoding="utf-8")
    (asset_dir / "forest-theme.png").write_bytes(b"png")
    monkeypatch.setattr(server, "STATIC_DIR", static_dir)

    css_response = await server._static(
        make_mocked_request(
            "GET",
            "/styles.css",
            match_info={"name": "styles.css"},
        )
    )
    asset_response = await server._static_asset(
        make_mocked_request(
            "GET",
            "/assets/forest-theme.png",
            match_info={"name": "forest-theme.png"},
        )
    )

    assert css_response.headers["Cache-Control"] == "no-store"
    assert asset_response.headers["Cache-Control"] == "no-store"


@pytest.mark.asyncio
async def test_static_asset_rejects_everything_outside_whitelist(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "STATIC_DIR", tmp_path)
    request = make_mocked_request(
        "GET",
        "/assets/secret.txt",
        match_info={"name": "secret.txt"},
    )

    with pytest.raises(web.HTTPNotFound):
        await server._static_asset(request)
