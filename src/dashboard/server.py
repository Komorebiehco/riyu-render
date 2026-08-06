"""Dashboard API, TXT import/export, and static-file server.

Metrics endpoints only return operational metadata from SQLite.
TXT import and export are explicit user actions: they parse plaintext
credentials sent from the panel and write cleaned credentials to data/exports.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import math
import os
import re
import time
import uuid
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote

import aiosqlite
from aiohttp import web

from src.config import DATA_DIR, config
from src.dashboard.txt_io import parse_txt_content, write_txt_export
from src.monitor.logger import get_logger


PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATIC_DIR = PROJECT_ROOT / "visual-dashboard"
EXPORT_DIR = DATA_DIR / "exports"

log = get_logger("DASH")

COMPLETED_STATUSES = {"VERIFIED", "EXPORTED"}
PROCESSING_STATUSES = {"VALIDATING", "SANITIZING"}
FAILED_STATUSES = {"FAILED", "DEAD", "PARTIAL"}
NON_DELETABLE_STATUSES = PROCESSING_STATUSES | {"PENDING"}

_import_lock: asyncio.Lock | None = None
_import_jobs: list[dict[str, Any]] = []
_import_pending: deque[tuple[dict[str, Any], list[Any]]] = deque()
_import_worker_task: asyncio.Task[None] | None = None
_IMPORT_JOB_HISTORY_LIMIT = 50

STEP_FIELDS = (
    ("预检", ("step1_validated",)),
    ("邮箱确认", ("step2_email_changed",)),
    ("安全校验", ("step3_phone_removed",)),
    ("密钥检查", ("step4_passkeys_deleted",)),
    ("双重验证", ("step5_2fa_reset", "step5_backup_codes")),
    ("会话确认", ("step6_password_changed", "step6_all_signed_out")),
    ("授权检查", ("step7_oauth_revoked",)),
    ("结果验证", ("step8_verified",)),
)

FAILURE_LABELS = {
    "CAPTCHA_BLOCKED": "验证受限",
    "ACCOUNT_DISABLED": "账号不可用",
    "WRONG_PASSWORD": "凭证校验失败",
    "MISSING_2FA": "缺少双重验证密钥",
    "WRONG_2FA": "双重验证失败",
    "PROXY_ERROR": "网络异常",
    "BROWSER_ERROR": "浏览器不可用",
    "MAIL_TIMEOUT": "邮件超时",
    "STEP_TIMEOUT": "步骤超时",
    "UNKNOWN": "其他",
}

_INVALID_EXPORT_NAME = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_SESSION_COOKIE = "riyu_session"
_SESSION_MAX_AGE = 7 * 24 * 60 * 60


def _session_secret() -> bytes:
    secret = os.environ.get("DASHBOARD_SESSION_SECRET", "")
    if not secret:
        raise RuntimeError("DASHBOARD_SESSION_SECRET is not configured")
    return secret.encode("utf-8")


def _make_session(username: str) -> str:
    issued_at = str(int(time.time()))
    payload = f"{username}:{issued_at}"
    signature = hmac.new(_session_secret(), payload.encode(), hashlib.sha256).hexdigest()
    encoded = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    return f"v1.{encoded}.{signature}"


def _valid_session(value: str) -> bool:
    try:
        version, encoded, signature = value.split(".", 2)
        if version != "v1":
            return False
        padding = "=" * (-len(encoded) % 4)
        payload = base64.urlsafe_b64decode(encoded + padding).decode("utf-8")
        username, issued_text = payload.rsplit(":", 1)
        issued_at = int(issued_text)
    except (ValueError, UnicodeDecodeError):
        return False

    expected_user = os.environ.get("DASHBOARD_USERNAME", "coujidan")
    age = int(time.time()) - issued_at
    expected_signature = hmac.new(
        _session_secret(), payload.encode(), hashlib.sha256
    ).hexdigest()
    return (
        hmac.compare_digest(username, expected_user)
        and hmac.compare_digest(signature, expected_signature)
        and 0 <= age <= _SESSION_MAX_AGE
    )


def _safe_next(value: str | None) -> str:
    if not value or not value.startswith("/") or value.startswith("//"):
        return "/"
    return value


@web.middleware
async def _session_auth(request: web.Request, handler):
    """Protect the dashboard with a signed, short-lived browser session."""
    public_paths = {
        "/api/health",
        "/login",
        "/login.css",
        "/assets/forest-theme.png",
    }
    if request.path in public_paths:
        return await handler(request)

    if _valid_session(request.cookies.get(_SESSION_COOKIE, "")):
        return await handler(request)

    if request.path.startswith("/api/"):
        return web.json_response({"message": "authentication required"}, status=401)
    location = "/login?next=" + quote(_safe_next(request.path_qs), safe="")
    raise web.HTTPFound(location=location)


async def _login_page(_: web.Request) -> web.StreamResponse:
    response = web.FileResponse(STATIC_DIR / "login.html")
    response.headers["Cache-Control"] = "no-store"
    return response


async def _login_css(_: web.Request) -> web.StreamResponse:
    response = web.FileResponse(STATIC_DIR / "login.css")
    response.headers["Cache-Control"] = "no-store"
    return response


async def _login(request: web.Request) -> web.StreamResponse:
    data = await request.post()
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))
    expected_user = os.environ.get("DASHBOARD_USERNAME", "coujidan")
    expected_password = os.environ.get("DASHBOARD_PASSWORD", "")
    next_path = _safe_next(str(data.get("next", "/")))

    if not expected_password:
        raise web.HTTPServiceUnavailable(text="dashboard authentication is not configured")
    if not (
        hmac.compare_digest(username, expected_user)
        and hmac.compare_digest(password, expected_password)
    ):
        raise web.HTTPFound(location="/login?error=1")

    response = web.HTTPFound(location=next_path)
    response.set_cookie(
        _SESSION_COOKIE,
        _make_session(username),
        max_age=_SESSION_MAX_AGE,
        httponly=True,
        secure=os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true",
        samesite="Lax",
        path="/",
    )
    raise response


async def _logout(_: web.Request) -> web.StreamResponse:
    response = web.HTTPFound(location="/login")
    response.del_cookie(_SESSION_COOKIE, path="/")
    raise response


def mask_email(value: str) -> str:
    """Mask an email address before it leaves the backend."""
    if "@" not in value:
        return "***"
    local, domain = value.split("@", 1)
    visible = local[:2] if len(local) > 2 else local[:1]
    return f"{visible}***@{domain}"


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def public_status(status: str) -> str:
    if status in COMPLETED_STATUSES:
        return "VERIFIED"
    if status in PROCESSING_STATUSES:
        return "SANITIZING"
    if status == "PENDING":
        return "PENDING"
    return "FAILED"


def progress_percent(step_progress: str | dict[str, Any] | None) -> int:
    data = parse_step_progress(step_progress)
    completed = sum(any(bool(data.get(field)) for field in fields) for _, fields in STEP_FIELDS)
    return round(completed / len(STEP_FIELDS) * 100)


def parse_step_progress(step_progress: str | dict[str, Any] | None) -> dict[str, Any]:
    if isinstance(step_progress, str):
        try:
            return json.loads(step_progress or "{}")
        except json.JSONDecodeError:
            return {}
    return step_progress or {}


def _db_path() -> str:
    path = Path(config.db.SQLITE_PATH)
    return str(path if path.is_absolute() else PROJECT_ROOT / path)


async def _fetch_rows(sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
    async with aiosqlite.connect(_db_path()) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(sql, tuple(params)) as cursor:
            return [dict(row) for row in await cursor.fetchall()]


async def _summary(_: web.Request) -> web.Response:
    rows = await _fetch_rows("SELECT status, COUNT(*) AS count FROM accounts GROUP BY status")
    counts = {row["status"]: row["count"] for row in rows}
    total = sum(counts.values())
    completed = sum(counts.get(status, 0) for status in COMPLETED_STATUSES)
    processing = sum(counts.get(status, 0) for status in PROCESSING_STATUSES)
    pending = counts.get("PENDING", 0)
    failed = sum(counts.get(status, 0) for status in FAILED_STATUSES)
    terminal = completed + failed

    duration_rows = await _fetch_rows(
        """
        SELECT created_at, COALESCE(verified_at, sanitized_at, exported_at) AS finished_at
        FROM accounts
        WHERE status IN ('VERIFIED', 'EXPORTED')
          AND COALESCE(verified_at, sanitized_at, exported_at) IS NOT NULL
        """
    )
    durations = []
    for row in duration_rows:
        start = parse_timestamp(row["created_at"])
        finish = parse_timestamp(row["finished_at"])
        if start and finish and finish >= start:
            durations.append((finish - start).total_seconds())

    return web.json_response({
        "total": total,
        "completed": completed,
        "processing": processing,
        "pending": pending,
        "failed": failed,
        "success_rate": round(completed / terminal * 100, 1) if terminal else 0,
        "avg_elapsed_seconds": round(sum(durations) / len(durations), 1) if durations else 0,
        "distribution": {
            "VERIFIED": completed,
            "SANITIZING": processing,
            "PENDING": pending,
            "FAILED": failed,
        },
        "service": {
            "status": "online",
            "mode": "管理模式",
            "workers_configured": config.queue.MAX_WORKERS,
        },
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })


def _trend_spec(range_name: str, now: datetime) -> tuple[list[str], list[tuple[datetime, datetime]]]:
    local_now = now.astimezone()
    if range_name == "day":
        start = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
        windows = [(start + timedelta(hours=i * 4), start + timedelta(hours=(i + 1) * 4)) for i in range(6)]
        return [window[0].strftime("%H") for window in windows], windows
    if range_name == "month":
        start = (local_now - timedelta(days=29)).replace(hour=0, minute=0, second=0, microsecond=0)
        windows = [(start + timedelta(days=i * 6), start + timedelta(days=min((i + 1) * 6, 30))) for i in range(5)]
        return [f"{window[0].month}/{window[0].day}" for window in windows], windows
    start = (local_now - timedelta(days=6)).replace(hour=0, minute=0, second=0, microsecond=0)
    windows = [(start + timedelta(days=i), start + timedelta(days=i + 1)) for i in range(7)]
    return ["一二三四五六日"[window[0].weekday()] for window in windows], windows


async def _trend(request: web.Request) -> web.Response:
    range_name = request.query.get("range", "week")
    if range_name not in {"day", "week", "month"}:
        raise web.HTTPBadRequest(text="unsupported range")
    rows = await _fetch_rows("SELECT status, created_at FROM accounts")
    labels, windows = _trend_spec(range_name, datetime.now(timezone.utc))
    success = [0] * len(windows)
    failed = [0] * len(windows)
    for row in rows:
        stamp = parse_timestamp(row["created_at"])
        if not stamp:
            continue
        stamp = stamp.astimezone()
        for index, (start, end) in enumerate(windows):
            if start <= stamp < end:
                if row["status"] in COMPLETED_STATUSES:
                    success[index] += 1
                elif row["status"] in FAILED_STATUSES:
                    failed[index] += 1
                break
    return web.json_response({"labels": labels, "success": success, "failed": failed})


async def _steps(_: web.Request) -> web.Response:
    rows = await _fetch_rows("SELECT status, step_progress FROM accounts")
    total = len(rows)
    parsed_rows = [
        (row["status"], parse_step_progress(row["step_progress"]))
        for row in rows
    ]
    result = []
    for index, (name, fields) in enumerate(STEP_FIELDS, 1):
        completed = 0
        active = 0
        for status, data in parsed_rows:
            completed += int(any(bool(data.get(field)) for field in fields))
            active += int(
                status in PROCESSING_STATUSES
                and int(data.get("current_step") or 0) == index
            )
        result.append({
            "name": name,
            "completed": completed,
            "active": active,
            "rate": round(completed / total * 100, 1) if total else 0,
        })
    health = round(sum(item["rate"] for item in result) / len(result)) if result else 0
    return web.json_response({"health": health, "steps": result})


async def _failures(_: web.Request) -> web.Response:
    rows = await _fetch_rows(
        """
        SELECT COALESCE(fail_reason, 'UNKNOWN') AS reason, COUNT(*) AS count
        FROM accounts
        WHERE status IN ('FAILED', 'DEAD', 'PARTIAL')
        GROUP BY COALESCE(fail_reason, 'UNKNOWN')
        ORDER BY count DESC
        """
    )
    items = [{"reason": row["reason"], "label": FAILURE_LABELS.get(row["reason"], "其他"), "count": row["count"]} for row in rows]
    return web.json_response({"total": sum(item["count"] for item in items), "items": items})


def _elapsed_seconds(row: dict[str, Any]) -> float | None:
    start = parse_timestamp(row.get("created_at"))
    if not start:
        return None
    finish = next((parse_timestamp(row.get(field)) for field in ("verified_at", "sanitized_at", "exported_at") if row.get(field)), None)
    if not finish and row.get("status") in PROCESSING_STATUSES:
        finish = datetime.now(timezone.utc)
    if not finish or finish < start:
        return None
    return round((finish - start).total_seconds(), 1)


async def _tasks(request: web.Request) -> web.Response:
    requested_status = request.query.get("status", "all")
    query = request.query.get("query", "").strip().lower()
    try:
        limit = min(max(int(request.query.get("limit", "50")), 1), 200)
    except ValueError as exc:
        raise web.HTTPBadRequest(text="invalid limit") from exc

    rows = await _fetch_rows(
        """
        SELECT account_id, gmail, status, fail_reason, step_progress,
               created_at, sanitized_at, verified_at, exported_at
        FROM accounts
        ORDER BY created_at DESC
        LIMIT 500
        """
    )
    items = []
    for row in rows:
        normalized = public_status(row["status"])
        step_data = parse_step_progress(row["step_progress"])
        task_id = f"RY-{row['account_id'][:8].upper()}"
        masked = mask_email(row["gmail"])
        if requested_status != "all" and normalized != requested_status:
            continue
        if query and query not in task_id.lower() and query not in masked.lower():
            continue
        updated_at = step_data.get("updated_at") or next(
            (row.get(field) for field in ("verified_at", "sanitized_at", "exported_at", "created_at") if row.get(field)),
            None,
        )
        items.append({
            "id": task_id,
            "key": row["account_id"],
            "account": masked,
            "status": normalized,
            "source_status": row["status"],
            "progress": progress_percent(row["step_progress"]),
            "current_step": int(step_data.get("current_step") or 0),
            "current_step_name": step_data.get("current_step_name"),
            "elapsed_seconds": _elapsed_seconds(row),
            "updated_at": updated_at,
            "failure": FAILURE_LABELS.get(row.get("fail_reason"), "") if row.get("fail_reason") else None,
        })
        if len(items) >= limit:
            break
    return web.json_response({"items": items, "count": len(items)})


async def _delete_task(request: web.Request) -> web.Response:
    account_id = request.match_info.get("account_id", "").strip()
    if not account_id:
        raise web.HTTPBadRequest(text="缺少任务 ID")

    async with aiosqlite.connect(_db_path()) as db:
        db.row_factory = aiosqlite.Row
        await db.execute("BEGIN IMMEDIATE")
        async with db.execute(
            "SELECT status FROM accounts WHERE account_id = ?",
            (account_id,),
        ) as cursor:
            row = await cursor.fetchone()
        if not row:
            await db.rollback()
            raise web.HTTPNotFound(text="任务不存在或已被删除")
        if row["status"] in NON_DELETABLE_STATUSES:
            await db.rollback()
            raise web.HTTPConflict(text="待处理或正在处理的任务不能删除，请等待完成")
        await db.execute("DELETE FROM accounts WHERE account_id = ?", (account_id,))
        await db.commit()

    return web.json_response({"deleted": True, "id": account_id})


async def _bulk_delete_tasks(request: web.Request) -> web.Response:
    try:
        payload = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise web.HTTPBadRequest(text="无效 JSON 请求体") from exc

    raw_ids = payload.get("ids") if isinstance(payload, dict) else None
    if not isinstance(raw_ids, list):
        raise web.HTTPBadRequest(text="ids 必须是数组")
    if len(raw_ids) > 200:
        raise web.HTTPBadRequest(text="一次最多删除 200 个任务")

    account_ids = list(dict.fromkeys(
        str(value).strip() for value in raw_ids if str(value).strip()
    ))
    if not account_ids:
        return web.json_response({"deleted": 0, "skipped": [], "missing": []})

    placeholders = ",".join("?" for _ in account_ids)
    async with aiosqlite.connect(_db_path()) as db:
        db.row_factory = aiosqlite.Row
        await db.execute("BEGIN IMMEDIATE")
        async with db.execute(
            f"SELECT account_id, status FROM accounts WHERE account_id IN ({placeholders})",
            account_ids,
        ) as cursor:
            rows = await cursor.fetchall()

        statuses = {row["account_id"]: row["status"] for row in rows}
        missing = [account_id for account_id in account_ids if account_id not in statuses]
        skipped = [
            account_id for account_id in account_ids
            if statuses.get(account_id) in NON_DELETABLE_STATUSES
        ]
        deletable = [
            account_id for account_id in account_ids
            if account_id in statuses and account_id not in skipped
        ]
        if deletable:
            delete_placeholders = ",".join("?" for _ in deletable)
            await db.execute(
                f"DELETE FROM accounts WHERE account_id IN ({delete_placeholders})",
                deletable,
            )
        await db.commit()

    return web.json_response({
        "deleted": len(deletable),
        "deleted_ids": deletable,
        "skipped": skipped,
        "missing": missing,
    })


async def _clear_failed_tasks(request: web.Request) -> web.Response:
    failed_statuses = sorted(FAILED_STATUSES)
    placeholders = ",".join("?" for _ in failed_statuses)
    async with aiosqlite.connect(_db_path()) as db:
        db.row_factory = aiosqlite.Row
        await db.execute("BEGIN IMMEDIATE")
        async with db.execute(
            f"SELECT account_id FROM accounts WHERE status IN ({placeholders})",
            failed_statuses,
        ) as cursor:
            rows = await cursor.fetchall()
        deleted_ids = [row["account_id"] for row in rows]
        if deleted_ids:
            await db.execute(
                f"DELETE FROM accounts WHERE status IN ({placeholders})",
                failed_statuses,
            )
        await db.commit()

    return web.json_response({"deleted": len(deleted_ids), "deleted_ids": deleted_ids})


async def _events(_: web.Request) -> web.Response:
    rows = await _fetch_rows(
        """
        SELECT account_id, gmail, status, fail_reason, created_at,
               sanitized_at, verified_at, exported_at
        FROM accounts
        ORDER BY COALESCE(verified_at, sanitized_at, exported_at, created_at) DESC
        LIMIT 12
        """
    )
    labels = {"VERIFIED": "已完成", "SANITIZING": "处理中", "PENDING": "待处理", "FAILED": "异常"}
    items = []
    for row in rows:
        normalized = public_status(row["status"])
        event_type = {"VERIFIED": "success", "SANITIZING": "info", "PENDING": "warning", "FAILED": "error"}[normalized]
        stamp = next((row.get(field) for field in ("verified_at", "sanitized_at", "exported_at", "created_at") if row.get(field)), None)
        items.append({
            "type": event_type,
            "text": f"{mask_email(row['gmail'])} · {labels[normalized]}",
            "time": stamp,
        })
    return web.json_response({"items": items})


def _get_import_lock() -> asyncio.Lock:
    global _import_lock
    if _import_lock is None:
        _import_lock = asyncio.Lock()
    return _import_lock


def _new_import_job(
    source_name: str,
    total: int,
    rejected: int = 0,
) -> dict[str, Any]:
    return {
        "id": uuid.uuid4().hex[:12],
        "state": "queued",
        "source": source_name,
        "total": total,
        "completed": 0,
        "verified": 0,
        "failed": 0,
        "rejected": rejected,
        "export_file": None,
        "queued_at": datetime.now(timezone.utc).isoformat(),
        "started_at": None,
        "finished_at": None,
        "message": f"已排队，等待清洗 {total} 个账号",
    }


def _prune_import_jobs() -> None:
    """Bound completed in-memory history without dropping active jobs."""
    while len(_import_jobs) > _IMPORT_JOB_HISTORY_LIMIT:
        terminal_index = next(
            (
                index
                for index, job in enumerate(_import_jobs)
                if job["state"] in {"done", "error"}
            ),
            None,
        )
        if terminal_index is None:
            break
        _import_jobs.pop(terminal_index)


def _enqueue_import(
    tasks: list[Any],
    source_name: str,
    rejected: int = 0,
) -> tuple[dict[str, Any], int]:
    """Append one batch and ensure a single FIFO worker is draining it."""
    global _import_worker_task

    job = _new_import_job(source_name, len(tasks), rejected)
    _import_jobs.append(job)
    _import_pending.append((job, tasks))
    queue_position = sum(1 for item in _import_jobs if item["state"] == "queued")
    if _import_worker_task is None or _import_worker_task.done():
        _import_worker_task = asyncio.create_task(_drain_import_queue())
    return job, queue_position


async def _drain_import_queue() -> None:
    """Run queued batches strictly in submission order."""
    global _import_worker_task

    cancelled = False
    try:
        while _import_pending:
            job, tasks = _import_pending.popleft()
            await _run_import_batch(tasks, job["source"], status=job)
    except asyncio.CancelledError:
        cancelled = True
        raise
    finally:
        # There is no await between the final queue check and clearing this
        # reference, so a concurrent request cannot strand a queued batch.
        _import_worker_task = None
        if _import_pending and not cancelled:
            _import_worker_task = asyncio.create_task(_drain_import_queue())


async def _run_import_batch(
    tasks: list[Any],
    source_name: str,
    status: dict[str, Any] | None = None,
) -> None:
    from src.queues.task_queue import TaskQueue
    from src.storage.db_manager import get_db

    status = status if status is not None else _new_import_job(source_name, len(tasks))
    status.update({
        "state": "running",
        "source": source_name,
        "total": len(tasks),
        "completed": 0,
        "verified": 0,
        "failed": 0,
        "export_file": None,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
        "message": f"正在清洗 {len(tasks)} 个账号",
    })

    try:
        async with _get_import_lock():
            db = get_db()
            await db.init()

            queue = TaskQueue(max_workers=config.queue.MAX_WORKERS)
            await queue.run(tasks)

            from src.storage.models import AccountStatus

            records = []
            exported_accounts = []
            for task in tasks:
                account = task.account
                if account.status == AccountStatus.VERIFIED:
                    records.append(account.to_export_dict())
                    account.status = AccountStatus.EXPORTED
                    account.exported_at = datetime.now(timezone.utc)
                    exported_accounts.append(account)

            filename = None
            count = 0
            if records:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"cleaned_{timestamp}.txt"
                suffix = 2
                while (EXPORT_DIR / filename).exists():
                    filename = f"cleaned_{timestamp}_{suffix}.txt"
                    suffix += 1
                count = write_txt_export(records, EXPORT_DIR / filename)

            for account in exported_accounts:
                await db.upsert(account)

            status.update({
                "state": "done",
                "completed": len(tasks),
                "verified": len(records),
                "failed": len(tasks) - len(records),
                "export_file": filename,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "message": (
                    f"已生成 {filename}，共 {count} 条"
                    if filename
                    else "无成功结果，未生成文件"
                ),
            })
    except Exception as exc:
        log.exception("批量导入失败")
        status.update({
            "state": "error",
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "message": str(exc),
        })
    finally:
        _prune_import_jobs()


def _ensure_browser_ready() -> None:
    if not config.browser.executable_available():
        raise web.HTTPServiceUnavailable(
            text=(
                "浏览器尚未就绪。请重新运行 setup.cmd，或通过 "
                "CHROMIUM_PATH 指定可用的 Chrome/Edge。"
            )
        )


async def _submit_import_content(content: str, source_name: str) -> web.Response:
    credentials, invalid = parse_txt_content(content)
    if not credentials:
        raise web.HTTPBadRequest(
            text=json.dumps({
                "message": "没有可导入的有效账号",
                "invalid": invalid[:50],
            }, ensure_ascii=False),
            content_type="application/json",
        )

    from src.storage.models import SanitizeTask
    from src.storage.db_manager import get_db

    tasks = [SanitizeTask.from_credential(cred) for cred in credentials]
    db = get_db()
    await db.init()
    await db.upsert_many([task.account for task in tasks])
    job, queue_position = _enqueue_import(tasks, source_name, len(invalid))
    return web.json_response({
        "accepted": len(credentials),
        "rejected": len(invalid),
        "invalid": invalid[:50],
        "started": True,
        "queued": True,
        "job_id": job["id"],
        "state": job["state"],
        "queue_position": queue_position,
        "message": f"已导入 {len(credentials)} 个账号并加入清洗队列",
    })


async def _import_txt(request: web.Request) -> web.Response:
    _ensure_browser_ready()

    reader = await request.multipart()
    file_field = await reader.next()
    if file_field is None or file_field.name != "file":
        raise web.HTTPBadRequest(text="缺少 file 字段")

    filename = file_field.filename or ""
    if not filename.lower().endswith(".txt"):
        raise web.HTTPBadRequest(text="仅支持 .txt 文件")

    raw_content = await file_field.read()
    max_size = 5 * 1024 * 1024
    if len(raw_content) > max_size:
        raise web.HTTPRequestEntityTooLarge(
            max_size=max_size,
            actual_size=len(raw_content),
            text="文件过大，最大 5MB",
        )
    content = raw_content.decode("utf-8", errors="replace")
    source_name = Path(filename).name or "上传文件.txt"
    return await _submit_import_content(content, source_name)


async def _import_text(request: web.Request) -> web.Response:
    _ensure_browser_ready()
    try:
        payload = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise web.HTTPBadRequest(text="invalid json") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("content"), str):
        raise web.HTTPBadRequest(text="content must be a string")

    content = payload["content"]
    max_size = 5 * 1024 * 1024
    actual_size = len(content.encode("utf-8"))
    if actual_size > max_size:
        raise web.HTTPRequestEntityTooLarge(
            max_size=max_size,
            actual_size=actual_size,
            text="内容过大，最大 5MB",
        )
    return await _submit_import_content(content, "粘贴输入")


def _import_status_payload() -> dict[str, Any]:
    jobs = [dict(job) for job in _import_jobs]
    active = next((job for job in jobs if job["state"] == "running"), None)
    if active is None:
        active = next((job for job in jobs if job["state"] == "queued"), None)

    selected = active or (jobs[-1] if jobs else None)
    if selected is None:
        payload: dict[str, Any] = {
            "state": "idle",
            "source": None,
            "total": 0,
            "completed": 0,
            "verified": 0,
            "failed": 0,
            "export_file": None,
            "started_at": None,
            "finished_at": None,
            "message": "",
        }
    else:
        payload = {
            key: selected.get(key)
            for key in (
                "state",
                "source",
                "total",
                "completed",
                "verified",
                "failed",
                "export_file",
                "started_at",
                "finished_at",
                "message",
            )
        }
        payload["job_id"] = selected["id"]
        # Legacy clients only know idle/running/done/error. A queued first
        # batch is therefore exposed as running at the top level, while its
        # precise state remains available in jobs[].
        if payload["state"] == "queued":
            payload["state"] = "running"

    payload["jobs"] = jobs
    payload["queue_size"] = sum(1 for job in jobs if job["state"] == "queued")
    return payload


async def _import_status_view(_: web.Request) -> web.Response:
    return web.json_response(_import_status_payload())


def _export_root() -> Path:
    """Return the canonical export root, creating it when necessary."""
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    return EXPORT_DIR.resolve(strict=True)


def _validate_export_name(name: str) -> str:
    """Accept a plain TXT filename, never a path or Windows data stream."""
    if (
        not name
        or len(name) > 255
        or _INVALID_EXPORT_NAME.search(name)
        or name.rstrip(" .") != name
        or Path(name).name != name
        or Path(name).suffix.lower() != ".txt"
    ):
        raise web.HTTPBadRequest(text="invalid file")
    return name


def _resolve_export_file(name: str) -> Path:
    """Resolve an existing regular export file without following symlinks."""
    safe = _validate_export_name(name)
    root = _export_root()
    candidate = root / safe

    # Export files are always regular files created by this application.
    # Rejecting links also prevents reads/deletes from escaping EXPORT_DIR.
    if candidate.is_symlink():
        raise web.HTTPBadRequest(text="invalid file")
    try:
        path = candidate.resolve(strict=True)
        path.relative_to(root)
    except FileNotFoundError as exc:
        raise web.HTTPNotFound(text="file not found") from exc
    except (OSError, ValueError) as exc:
        raise web.HTTPBadRequest(text="invalid file") from exc
    if not path.is_file():
        raise web.HTTPNotFound(text="file not found")
    return path


def _export_files() -> list[Path]:
    """List safe regular TXT exports, newest first."""
    root = _export_root()
    files: list[Path] = []
    for candidate in root.iterdir():
        if candidate.suffix.lower() != ".txt" or candidate.is_symlink():
            continue
        try:
            path = candidate.resolve(strict=True)
            path.relative_to(root)
        except (FileNotFoundError, OSError, ValueError):
            continue
        if path.is_file():
            files.append(path)

    def sort_key(path: Path) -> tuple[float, str]:
        try:
            return path.stat().st_mtime, path.name
        except OSError:
            return 0.0, path.name

    return sorted(files, key=sort_key, reverse=True)


def _read_export_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="replace")


def _count_export_lines(text: str) -> int:
    return sum(
        1
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    )


async def _exports(_: web.Request) -> web.Response:
    files = []
    for path in _export_files():
        try:
            text = _read_export_text(path)
            stat = path.stat()
        except OSError:
            # A file can disappear between enumeration and inspection.
            continue
        files.append({
            "name": path.name,
            "size": stat.st_size,
            "lines": _count_export_lines(text),
            "created_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            "url": f"/api/exports/content?file={quote(path.name)}",
        })
    return web.json_response({"files": files})


async def _export_content(request: web.Request) -> web.Response:
    name = request.query.get("file", "")
    path = _resolve_export_file(name)
    text = _read_export_text(path)
    response = web.Response(text=text, content_type="text/plain", charset="utf-8")
    response.headers["Content-Disposition"] = f'inline; filename="{path.name}"'
    response.headers["Cache-Control"] = "no-store"
    return response


async def _delete_export(request: web.Request) -> web.Response:
    name = request.match_info.get("filename", "")
    path = _resolve_export_file(name)
    try:
        path.unlink()
    except FileNotFoundError as exc:
        raise web.HTTPNotFound(text="file not found") from exc
    except OSError as exc:
        log.warning("删除导出文件失败 %s: %s", path.name, exc)
        raise web.HTTPInternalServerError(text="delete failed") from exc
    return web.json_response({
        "deleted": True,
        "deleted_file": path.name,
        "remaining": len(_export_files()),
    })


async def _cleanup_exports(request: web.Request) -> web.Response:
    try:
        payload = await request.json()
    except (json.JSONDecodeError, web.HTTPBadRequest) as exc:
        raise web.HTTPBadRequest(text="invalid json") from exc
    if not isinstance(payload, dict) or payload.get("mode") != "empty":
        raise web.HTTPBadRequest(text="mode must be empty")

    deleted_files: list[str] = []
    for path in _export_files():
        try:
            if _count_export_lines(_read_export_text(path)) != 0:
                continue
            path.unlink()
            deleted_files.append(path.name)
        except FileNotFoundError:
            continue
        except OSError as exc:
            # Continue cleaning independent files while preserving any file
            # that cannot be inspected or removed safely.
            log.warning("清理导出文件失败 %s: %s", path.name, exc)

    return web.json_response({
        "deleted": len(deleted_files),
        "deleted_files": deleted_files,
        "remaining": len(_export_files()),
    })



async def test_proxy_connection(
    proxy_url: str,
    target_host: str = "www.google.com",
    target_port: int = 443,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """测试 SOCKS5 / HTTP / HTTPS 代理连通性"""
    import asyncio
    import time
    from urllib.parse import urlparse

    start = time.perf_counter()
    raw = (proxy_url or "").strip()
    if not raw:
        return {"ok": False, "error": "代理地址不能为空"}

    if "://" not in raw:
        raw = f"http://{raw}"

    try:
        parsed = urlparse(raw)
        scheme = (parsed.scheme or "http").lower()
        host = parsed.hostname
        port = parsed.port
        user = parsed.username or ""
        pwd = parsed.password or ""
    except Exception as e:
        return {"ok": False, "error": f"代理地址格式无效: {e}"}

    if not host or not port:
        return {"ok": False, "error": f"无法从 {proxy_url} 解析主机与端口"}

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
    except Exception as e:
        return {"ok": False, "error": f"无法连接到代理服务器 ({host}:{port}): {e}"}

    try:
        if scheme in ("socks5", "socks5h"):
            if user:
                writer.write(bytes([0x05, 0x02, 0x00, 0x02]))
            else:
                writer.write(bytes([0x05, 0x01, 0x00]))
            await writer.drain()

            resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
            if resp[0] != 0x05:
                return {"ok": False, "error": "服务端未响应 SOCKS5 协议标头"}

            auth_method = resp[1]
            if auth_method == 0x02:
                u_bytes = user.encode("utf-8")
                p_bytes = pwd.encode("utf-8")
                writer.write(bytes([0x01, len(u_bytes)]) + u_bytes + bytes([len(p_bytes)]) + p_bytes)
                await writer.drain()
                auth_resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
                if auth_resp[1] != 0x00:
                    return {"ok": False, "error": "SOCKS5 认证失败 (用户名/密码错误)"}
            elif auth_method != 0x00:
                return {"ok": False, "error": f"不支持的 SOCKS5 认证方法 (0x{auth_method:02x})"}

            host_bytes = target_host.encode("utf-8")
            port_bytes = target_port.to_bytes(2, "big")
            cmd = bytes([0x05, 0x01, 0x00, 0x03, len(host_bytes)]) + host_bytes + port_bytes
            writer.write(cmd)
            await writer.drain()

            conn_resp = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
            if conn_resp[1] != 0x00:
                err_codes = {
                    1: "通用协议故障",
                    2: "连接规则拒绝",
                    3: "网络不可达",
                    4: "主机不可达",
                    5: "目标拒绝连接",
                    6: "TTL 超时",
                    7: "命令不支持",
                    8: "地址格式不支持",
                }
                msg = err_codes.get(conn_resp[1], f"错误码 {conn_resp[1]}")
                return {"ok": False, "error": f"SOCKS5 目标连接失败: {msg}"}

        elif scheme in ("http", "https"):
            headers = [f"CONNECT {target_host}:{target_port} HTTP/1.1", f"Host: {target_host}:{target_port}"]
            if user:
                import base64
                creds = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                headers.append(f"Proxy-Authorization: Basic {creds}")
            headers.append("\r\n")
            writer.write("\r\n".join(headers).encode("utf-8"))
            await writer.drain()

            res_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            status = res_line.decode("utf-8", errors="ignore")
            if "200" not in status:
                match = re.search(r"HTTP/\d(?:\.\d)?\s+(\d+)(?:\s+(.*))?", status.strip())
                status_code = int(match.group(1)) if match else None
                reason = (match.group(2) or "").strip() if match else status.strip()
                category = "http_rejected"
                message = f"HTTP 代理拒绝 CONNECT ({status_code or '未知状态'})"
                if status_code == 407:
                    category = "auth_failed"
                    message = "HTTP 代理认证失败，请检查用户名和密码"
                elif status_code == 429:
                    category = "bandwidth_exhausted"
                    message = "代理供应商返回 429，套餐流量或带宽额度不足"
                return {
                    "ok": False,
                    "category": category,
                    "status_code": status_code,
                    "error": message,
                    "detail": reason,
                }
        else:
            return {"ok": False, "error": f"不支持的代理协议: {scheme}"}

        latency_ms = round((time.perf_counter() - start) * 1000, 1)
        return {
            "ok": True,
            "latency_ms": latency_ms,
            "scheme": scheme,
            "host": host,
            "port": port,
            "message": f"代理连通成功 (延迟 {latency_ms}ms)",
        }

    except asyncio.TimeoutError:
        return {"ok": False, "category": "timeout", "error": "代理测试超时"}
    except Exception as e:
        return {"ok": False, "category": "handshake_failed", "error": f"代理测试握手失败: {e}"}
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _get_proxy_settings(_: web.Request) -> web.Response:
    from src.sanitizer.stealth_browser import get_proxy_pool
    pool = get_proxy_pool()
    proxy_path = Path(config.proxy.PROXY_FILE)
    return web.json_response({
        "proxy": config.proxy.to_dict(),
        "loaded_count": len(pool),
        "file": {
            "present": proxy_path.is_file(),
            "name": proxy_path.name,
            "size": proxy_path.stat().st_size if proxy_path.is_file() else 0,
        },
    })


async def _upload_proxy_file(request: web.Request) -> web.Response:
    reader = await request.multipart()
    files: list[tuple[str, str, int]] = []
    total_size = 0
    max_file_size = 5 * 1024 * 1024
    max_total_size = 20 * 1024 * 1024
    while True:
        file_field = await reader.next()
        if file_field is None:
            break
        if file_field.name != "file":
            await file_field.read()
            continue
        filename = Path(file_field.filename or "").name
        if not filename.lower().endswith(".txt"):
            raise web.HTTPBadRequest(text="仅支持 .txt 代理池文件")
        raw_content = await file_field.read()
        if len(raw_content) > max_file_size:
            raise web.HTTPRequestEntityTooLarge(
                max_size=max_file_size,
                actual_size=len(raw_content),
                text="单个文件最大 5MB",
            )
        total_size += len(raw_content)
        if total_size > max_total_size:
            raise web.HTTPRequestEntityTooLarge(
                max_size=max_total_size,
                actual_size=total_size,
                text="本次上传文件总量最大 20MB",
            )
        try:
            content = raw_content.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise web.HTTPBadRequest(text="代理池文件必须使用 UTF-8 编码") from exc
        files.append((filename, content, len(raw_content)))

    if not files:
        raise web.HTTPBadRequest(text="至少选择一个 .txt 代理池文件")

    from src.config import DEFAULT_PROXY_FILE, save_proxy_pool, save_proxy_settings
    try:
        existing_content = ""
        if DEFAULT_PROXY_FILE.is_file():
            existing_content = DEFAULT_PROXY_FILE.read_text(encoding="utf-8")
        combined_content = "\n".join(
            part for part in [existing_content, *(content for _, content, _ in files)] if part
        )
        stored = save_proxy_pool(combined_content, DEFAULT_PROXY_FILE)
        saved = save_proxy_settings(
            mode="file",
            custom_proxy=config.proxy.CUSTOM_PROXY,
            proxy_file=stored["path"],
            proxy_api_url=config.proxy.PROXY_API_URL,
            proxy_timeout=config.proxy.PROXY_TIMEOUT,
        )
    except ValueError as err:
        raise web.HTTPBadRequest(text=str(err)) from err

    from src.sanitizer.stealth_browser import get_proxy_pool
    loaded_count = len(get_proxy_pool())
    return web.json_response({
        "status": "ok",
        "proxy": saved,
        "file": {
            "name": files[0][0] if len(files) == 1 else f"{len(files)} 个文件",
            "stored_name": stored["name"],
            "size": stored["size"],
            "count": stored["count"],
            "unique_count": stored["unique_count"],
            "uploaded_files": [name for name, _, _ in files],
            "uploaded_size": sum(size for _, _, size in files),
        },
        "loaded_count": loaded_count,
        "message": f"已追加 {len(files)} 个文件，当前共载入 {loaded_count} 个节点",
    })


async def _save_proxy_settings_view(request: web.Request) -> web.Response:
    try:
        payload = await request.json()
    except Exception:
        raise web.HTTPBadRequest(text="无效 JSON 请求体")

    mode = str(payload.get("mode", "none"))
    custom_proxy = str(payload.get("custom_proxy", ""))
    proxy_file = str(payload.get("proxy_file", "proxies.txt"))
    proxy_api_url = str(payload.get("proxy_api_url", ""))
    proxy_timeout = int(payload.get("proxy_timeout", 15))

    from src.config import save_proxy_settings
    try:
        saved = save_proxy_settings(
            mode=mode,
            custom_proxy=custom_proxy,
            proxy_file=proxy_file,
            proxy_api_url=proxy_api_url,
            proxy_timeout=proxy_timeout,
        )
    except ValueError as err:
        raise web.HTTPBadRequest(text=str(err))

    from src.sanitizer.stealth_browser import get_proxy_pool
    return web.json_response({
        "status": "ok",
        "proxy": saved,
        "loaded_count": len(get_proxy_pool()),
        "message": "代理配置保存成功",
    })


async def _test_proxy_view(request: web.Request) -> web.Response:
    payload = {}
    if request.can_read_body:
        try:
            payload = await request.json()
        except Exception:
            pass

    proxy_url = payload.get("proxy_url") or config.proxy.CUSTOM_PROXY
    if not proxy_url and config.proxy.MODE == "file":
        from src.sanitizer.stealth_browser import get_proxy_pool
        from src.config import format_proxy_url

        sample_count = min(max(int(payload.get("sample_count", 40)), 1), 50)
        pool = get_proxy_pool()
        proxies = pool.sample_proxies(sample_count)
        if not proxies:
            return web.json_response({"ok": False, "error": "代理池中没有可测试节点"})

        timeout = min(max(float(payload.get("timeout", 8.0)), 2.0), 20.0)
        targets = (
            ("www.google.com", 443),
            ("www.cloudflare.com", 443),
        )
        target_results = await asyncio.gather(*(
            test_proxy_connection(
                format_proxy_url(proxy),
                target_host=target_host,
                target_port=target_port,
                timeout=timeout,
            )
            for proxy in proxies
            for target_host, target_port in targets
        ))
        results = []
        for index in range(len(proxies)):
            checks = target_results[index * len(targets):(index + 1) * len(targets)]
            successful = next((check for check in checks if check.get("ok")), None)
            if successful:
                results.append(successful)
                continue
            categories_for_node = Counter(
                str(check.get("category", "unknown")) for check in checks
            )
            primary = categories_for_node.most_common(1)[0][0]
            representative = next(
                check for check in checks
                if str(check.get("category", "unknown")) == primary
            )
            results.append(representative)
        succeeded = [result for result in results if result.get("ok")]
        categories = Counter(
            str(result.get("category", "unknown"))
            for result in results
            if not result.get("ok")
        )
        response = {
            "ok": bool(succeeded),
            "mode": "file",
            "sampled": len(results),
            "succeeded": len(succeeded),
            "failed": len(results) - len(succeeded),
            "categories": dict(categories),
            "targets_tested": len(targets),
            "pool_size": len(pool),
        }
        if succeeded:
            fastest = min(succeeded, key=lambda item: float(item.get("latency_ms", 999999)))
            response.update({
                "latency_ms": fastest.get("latency_ms"),
                "message": f"代理池抽样通过：{len(succeeded)}/{len(results)} 个节点可用",
            })
        elif categories.get("bandwidth_exhausted") == len(results):
            response.update({
                "error": "抽样节点全部返回 429：代理套餐流量或带宽额度已耗尽，请在供应商处续费或更换代理池",
                "category": "bandwidth_exhausted",
            })
        else:
            category_labels = {
                "bandwidth_exhausted": "额度耗尽",
                "auth_failed": "认证失败",
                "timeout": "连接超时",
                "handshake_failed": "握手失败",
                "http_rejected": "HTTP 拒绝",
                "unknown": "未知错误",
            }
            breakdown = "、".join(
                f"{category_labels.get(category, category)} {count} 个"
                for category, count in categories.most_common()
            )
            response.update({
                "error": f"代理池抽样未发现可用节点：{breakdown}",
                "category": categories.most_common(1)[0][0] if categories else "unknown",
            })
        return web.json_response(response)

    if not proxy_url:
        return web.json_response({"ok": False, "error": "请先输入或选择要测试的代理地址"})

    result = await test_proxy_connection(
        proxy_url=proxy_url,
        timeout=float(payload.get("timeout", 5.0)),
    )
    return web.json_response(result)


async def _health(_: web.Request) -> web.Response:
    browser_path = config.browser.CHROMIUM_PATH
    browser_ready = config.browser.executable_available()
    return web.json_response({
        "status": "ok" if browser_ready else "degraded",
        "mode": "read_only",
        "time": datetime.now(timezone.utc).isoformat(),
        "browser": {
            "ready": browser_ready,
            "executable": Path(browser_path).name if browser_path else None,
        },
    })


async def _static(request: web.Request) -> web.StreamResponse:
    name = request.match_info.get("name") or "index.html"
    if name not in {"index.html", "styles.css", "app.js", "preview.png", "preview-mobile.png"}:
        raise web.HTTPNotFound()
    response = web.FileResponse(STATIC_DIR / name)
    response.headers["Cache-Control"] = (
        "no-store"
        if name in {"index.html", "styles.css", "app.js"}
        else "public, max-age=3600"
    )
    return response


async def _static_asset(request: web.Request) -> web.StreamResponse:
    name = request.match_info.get("name", "")
    if name not in {"forest-theme.png"}:
        raise web.HTTPNotFound()
    path = STATIC_DIR / "assets" / name
    if not path.is_file():
        raise web.HTTPNotFound()
    response = web.FileResponse(path)
    response.headers["Cache-Control"] = "no-store"
    return response


async def create_app() -> web.Application:
    from src.storage.db_manager import DBManager

    # 确保冷库表结构存在，避免空数据库首次打开时只读 API 报错。
    await DBManager(_db_path()).init()

    app = web.Application(
        client_max_size=25 * 1024 * 1024,
        middlewares=[_session_auth],
    )
    app.router.add_get("/api/health", _health)
    app.router.add_get("/login", _login_page)
    app.router.add_post("/login", _login)
    app.router.add_post("/logout", _logout)
    app.router.add_get("/api/dashboard/summary", _summary)
    app.router.add_get("/api/dashboard/trend", _trend)
    app.router.add_get("/api/dashboard/steps", _steps)
    app.router.add_get("/api/dashboard/failures", _failures)
    app.router.add_get("/api/tasks", _tasks)
    app.router.add_post("/api/tasks/bulk-delete", _bulk_delete_tasks)
    app.router.add_post("/api/tasks/clear-failed", _clear_failed_tasks)
    app.router.add_delete("/api/tasks/{account_id}", _delete_task)
    app.router.add_get("/api/events", _events)
    app.router.add_post("/api/import/txt", _import_txt)
    app.router.add_post("/api/import/text", _import_text)
    app.router.add_get("/api/import/status", _import_status_view)
    app.router.add_get("/api/exports", _exports)
    app.router.add_get("/api/exports/content", _export_content)
    app.router.add_post("/api/exports/cleanup", _cleanup_exports)
    app.router.add_delete("/api/exports/{filename}", _delete_export)
    app.router.add_get("/api/settings/proxy", _get_proxy_settings)
    app.router.add_post("/api/settings/proxy", _save_proxy_settings_view)
    app.router.add_post("/api/settings/proxy/file", _upload_proxy_file)
    app.router.add_post("/api/settings/proxy/test", _test_proxy_view)
    app.router.add_get("/assets/{name}", _static_asset)
    app.router.add_get("/login.css", _login_css)
    app.router.add_get("/", _static)
    app.router.add_get("/{name}", _static)
    return app


def run(host: str = "127.0.0.1", port: int = 8766) -> None:
    web.run_app(create_app(), host=host, port=port, print=lambda message: print(message))
