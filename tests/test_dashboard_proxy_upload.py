import json

import pytest
from aiohttp.test_utils import make_mocked_request

from src.dashboard import server


class _Field:
    name = "file"

    def __init__(self, filename: str, content: bytes):
        self.filename = filename
        self._content = content

    async def read(self):
        return self._content


class _Reader:
    def __init__(self, fields):
        self._fields = iter(fields)

    async def next(self):
        return next(self._fields, None)


@pytest.mark.asyncio
async def test_upload_proxy_files_appends_to_existing_pool_and_deduplicates(tmp_path, monkeypatch):
    target = tmp_path / "proxies.txt"
    target.write_text("127.0.0.1:8080\n", encoding="utf-8")
    import src.config as config_module
    import src.sanitizer.stealth_browser as stealth_browser

    monkeypatch.setattr(config_module, "DEFAULT_PROXY_FILE", target)
    monkeypatch.setattr(
        config_module,
        "save_proxy_settings",
        lambda **kwargs: {"mode": kwargs["mode"], "proxy_file": kwargs["proxy_file"]},
    )
    monkeypatch.setattr(stealth_browser, "get_proxy_pool", lambda: [object(), object(), object()])

    request = make_mocked_request("POST", "/api/settings/proxy/file")
    reader = _Reader(
        [
            _Field("first.txt", b"127.0.0.1:8080\n127.0.0.2:8081\n"),
            _Field("second.txt", b"127.0.0.2:8081\n127.0.0.3:8082\n"),
        ]
    )

    async def multipart():
        return reader

    request.multipart = multipart
    response = await server._upload_proxy_file(request)

    payload = json.loads(response.body)
    assert payload["file"]["uploaded_files"] == ["first.txt", "second.txt"]
    assert payload["file"]["count"] == 3
    assert payload["loaded_count"] == 3
    assert target.read_text(encoding="utf-8") == (
        "127.0.0.1:8080\n127.0.0.2:8081\n127.0.0.3:8082\n"
    )
