import pytest

from src.queues import task_queue
from src.storage.db_manager import DBManager
from src.storage.models import AccountStatus, FailReason, RawCredential, SanitizeTask


def _task() -> SanitizeTask:
    credential = RawCredential(gmail="person@example.com", password="secret")
    return SanitizeTask.from_credential(credential)


@pytest.mark.asyncio
async def test_upsert_many_makes_pending_accounts_visible(tmp_path):
    db = DBManager(str(tmp_path / "accounts.db"))
    await db.init()
    first = _task().account
    second = SanitizeTask.from_credential(
        RawCredential(gmail="second@example.com", password="secret")
    ).account

    await db.upsert_many([first, second])

    assert (await db.get_by_gmail("person@example.com")).status == AccountStatus.PENDING
    assert (await db.get_by_gmail("second@example.com")).status == AccountStatus.PENDING


@pytest.mark.asyncio
async def test_queue_persists_failed_engine_result(monkeypatch):
    class DB:
        def __init__(self):
            self.saved = []

        async def init(self):
            return None

        async def upsert(self, account):
            self.saved.append(account.model_copy(deep=True))

    class Engine:
        def __init__(self, db):
            self.db = db

        def run_sync(self, item):
            item.account.mark_failed(FailReason.PROXY_ERROR, "proxy unavailable")
            return item.account

    db = DB()
    monkeypatch.setattr(task_queue, "get_db", lambda: db)
    monkeypatch.setattr(task_queue, "DrissionEngine", Engine)

    queue = task_queue.TaskQueue(max_workers=1)
    await queue.run([_task()])

    assert len(db.saved) == 1
    assert db.saved[0].status == AccountStatus.FAILED
    assert db.saved[0].fail_reason == FailReason.PROXY_ERROR


@pytest.mark.asyncio
async def test_queue_marks_and_persists_unhandled_worker_exception(monkeypatch):
    class DB:
        def __init__(self):
            self.saved = []

        async def init(self):
            return None

        async def upsert(self, account):
            self.saved.append(account.model_copy(deep=True))

    class Engine:
        def __init__(self, db):
            self.db = db

        def run_sync(self, item):
            raise RuntimeError("browser crashed")

    db = DB()
    monkeypatch.setattr(task_queue, "get_db", lambda: db)
    monkeypatch.setattr(task_queue, "DrissionEngine", Engine)

    queue = task_queue.TaskQueue(max_workers=1)
    await queue.run([_task()])

    assert len(db.saved) == 1
    assert db.saved[0].status == AccountStatus.FAILED
    assert db.saved[0].fail_reason == FailReason.UNKNOWN
    assert "browser crashed" in (db.saved[0].fail_detail or "")
