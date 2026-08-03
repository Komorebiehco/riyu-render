import json

import aiosqlite
import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from src.dashboard import server
from src.storage.db_manager import DBManager


async def _insert_task(db_path, account_id: str, status: str) -> None:
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            """
            INSERT INTO accounts (account_id, gmail, status, step_progress, created_at)
            VALUES (?, ?, ?, '{}', '2026-08-02T00:00:00+00:00')
            """,
            (account_id, f"{account_id}@example.com", status),
        )
        await db.commit()


@pytest.mark.asyncio
async def test_delete_task_removes_terminal_record(tmp_path, monkeypatch):
    db_path = tmp_path / "accounts.db"
    await DBManager(str(db_path)).init()
    await _insert_task(db_path, "task-done", "VERIFIED")
    monkeypatch.setattr(server, "_db_path", lambda: str(db_path))
    request = make_mocked_request(
        "DELETE",
        "/api/tasks/task-done",
        match_info={"account_id": "task-done"},
    )

    response = await server._delete_task(request)

    assert response.status == 200
    assert json.loads(response.body)["deleted"] is True
    assert await server._fetch_rows("SELECT * FROM accounts") == []


@pytest.mark.asyncio
async def test_delete_task_rejects_processing_record(tmp_path, monkeypatch):
    db_path = tmp_path / "accounts.db"
    await DBManager(str(db_path)).init()
    await _insert_task(db_path, "task-running", "SANITIZING")
    monkeypatch.setattr(server, "_db_path", lambda: str(db_path))
    request = make_mocked_request(
        "DELETE",
        "/api/tasks/task-running",
        match_info={"account_id": "task-running"},
    )

    with pytest.raises(web.HTTPConflict):
        await server._delete_task(request)

    rows = await server._fetch_rows("SELECT account_id FROM accounts")
    assert rows == [{"account_id": "task-running"}]
