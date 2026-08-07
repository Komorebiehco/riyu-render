import asyncio

import pytest
from aiohttp import web

from src.config import config
from src.dashboard import server


def _make_app() -> web.Application:
    app = web.Application()
    app[server._PROXY_OPERATION_LOCK] = asyncio.Lock()
    app[server._PROXY_AUTO_WAKE] = asyncio.Event()
    app[server._PROXY_AUTO_STATE] = {
        "running": False,
        "status": "initializing",
    }
    app[server._PROXY_AUTO_TASK] = {"task": None}
    return app


@pytest.mark.asyncio
async def test_auto_check_uses_saved_config_and_updates_public_state(monkeypatch):
    app = _make_app()
    seen = {}

    async def sample(sample_count, timeout):
        seen.update({"sample_count": sample_count, "timeout": timeout})
        return {
            "ok": True,
            "sampled": 7,
            "succeeded": 5,
            "failed": 2,
            "removed": 2,
            "pool_size": 18,
            "categories": {"timeout": 2},
        }

    monkeypatch.setattr(config.proxy, "MODE", "file")
    monkeypatch.setattr(config.proxy, "AUTO_CHECK_ENABLED", True)
    monkeypatch.setattr(config.proxy, "AUTO_CHECK_INTERVAL_SECONDS", 300)
    monkeypatch.setattr(config.proxy, "AUTO_CHECK_SAMPLE_COUNT", 7)
    monkeypatch.setattr(config.proxy, "PROXY_TIMEOUT", 11)
    monkeypatch.setattr(server, "_test_proxy_pool_sample", sample)

    result = await server._run_proxy_auto_check_once(app)
    state = app[server._PROXY_AUTO_STATE]

    assert result is not None
    assert seen == {"sample_count": 7, "timeout": 11}
    assert state["status"] == "completed"
    assert state["sampled"] == 7
    assert state["succeeded"] == 5
    assert state["removed"] == 2
    assert state["pool_size"] == 18
    assert state["last_run_at"]


@pytest.mark.asyncio
async def test_auto_check_skips_when_proxy_operation_is_busy(monkeypatch):
    app = _make_app()
    called = False

    async def sample(*_args):
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(config.proxy, "MODE", "file")
    monkeypatch.setattr(config.proxy, "AUTO_CHECK_ENABLED", True)
    monkeypatch.setattr(server, "_test_proxy_pool_sample", sample)

    lock = app[server._PROXY_OPERATION_LOCK]
    await lock.acquire()
    try:
        result = await server._run_proxy_auto_check_once(app)
    finally:
        lock.release()

    assert result is None
    assert called is False
    assert app[server._PROXY_AUTO_STATE]["status"] == "skipped_busy"


@pytest.mark.asyncio
async def test_auto_check_context_cancels_background_task(monkeypatch):
    app = _make_app()
    monkeypatch.setattr(config.proxy, "MODE", "none")
    monkeypatch.setattr(config.proxy, "AUTO_CHECK_ENABLED", True)
    context = server._proxy_auto_check_context(app)

    await anext(context)
    task = app[server._PROXY_AUTO_TASK]["task"]
    try:
        await asyncio.sleep(0)
        assert task is not None
        assert not task.done()
    finally:
        await context.aclose()

    assert task.done()
    assert app[server._PROXY_AUTO_TASK]["task"] is None


@pytest.mark.asyncio
async def test_auto_check_loop_runs_without_manual_request(monkeypatch):
    app = _make_app()
    ran = asyncio.Event()

    async def run_once(_app):
        ran.set()
        return {}

    monkeypatch.setattr(config.proxy, "MODE", "file")
    monkeypatch.setattr(config.proxy, "AUTO_CHECK_ENABLED", True)
    monkeypatch.setattr(config.proxy, "AUTO_CHECK_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(server, "_run_proxy_auto_check_once", run_once)
    context = server._proxy_auto_check_context(app)

    await anext(context)
    try:
        await asyncio.wait_for(ran.wait(), timeout=0.5)
    finally:
        await context.aclose()

    assert ran.is_set()
