import pytest
from aiohttp.test_utils import TestClient, TestServer

from src.dashboard.server import create_app


@pytest.mark.asyncio
async def test_health_login_and_signed_session(monkeypatch, tmp_path):
    monkeypatch.setenv("DASHBOARD_USERNAME", "coujidan")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "secret")
    monkeypatch.setenv("DASHBOARD_SESSION_SECRET", "session-secret-for-tests")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")

    import src.config as config_module
    config_module.config.db.SQLITE_PATH = str(tmp_path / "accounts.db")

    async with TestClient(TestServer(await create_app())) as client:
        health = await client.get("/api/health")
        assert health.status == 200

        denied = await client.get("/", allow_redirects=False)
        assert denied.status == 302
        assert denied.headers["Location"].startswith("/login")

        login_page = await client.get("/login")
        assert login_page.status == 200
        assert "登录 RIYU" in await login_page.text()

        bad_login = await client.post(
            "/login",
            data={"username": "coujidan", "password": "wrong"},
            allow_redirects=False,
        )
        assert bad_login.status == 302
        assert bad_login.headers["Location"] == "/login?error=1"

        login = await client.post(
            "/login",
            data={"username": "coujidan", "password": "secret"},
            allow_redirects=False,
        )
        assert login.status == 302
        assert "riyu_session=" in login.headers["Set-Cookie"]

        allowed = await client.get("/")
        assert allowed.status == 200

        logout = await client.post("/logout", allow_redirects=False)
        assert logout.status == 302
        assert logout.headers["Location"] == "/login"
