import base64

import pytest
from aiohttp.test_utils import TestClient, TestServer

from src.dashboard.server import create_app


@pytest.mark.asyncio
async def test_health_is_public_and_dashboard_requires_auth(monkeypatch, tmp_path):
    monkeypatch.setenv("DASHBOARD_USERNAME", "riyu")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "secret")

    import src.config as config_module
    config_module.config.db.SQLITE_PATH = str(tmp_path / "accounts.db")

    async with TestClient(TestServer(await create_app())) as client:
        health = await client.get("/api/health")
        assert health.status == 200

        denied = await client.get("/")
        assert denied.status == 401
        assert denied.headers["WWW-Authenticate"].startswith("Basic ")

        token = base64.b64encode(b"riyu:secret").decode()
        allowed = await client.get("/", headers={"Authorization": f"Basic {token}"})
        assert allowed.status == 200
