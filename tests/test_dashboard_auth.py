import pytest
from aiohttp import FormData
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

        proxy_file = tmp_path / "proxies.txt"
        monkeypatch.setattr("src.config.DEFAULT_PROXY_FILE", proxy_file)
        monkeypatch.setattr("src.config.SETTINGS_FILE", tmp_path / "settings.json")
        form = FormData()
        form.add_field(
            "file",
            b"user:pass@127.0.0.1:8080\n127.0.0.2:1080:u:p\n",
            filename="pool.txt",
            content_type="text/plain",
        )
        proxy_upload = await client.post("/api/settings/proxy/file", data=form)
        assert proxy_upload.status == 200
        proxy_payload = await proxy_upload.json()
        assert proxy_payload["loaded_count"] == 2
        assert proxy_payload["proxy"]["mode"] == "file"
        assert proxy_file.is_file()

        logout = await client.post("/logout", allow_redirects=False)
        assert logout.status == 302
        assert logout.headers["Location"] == "/login"
