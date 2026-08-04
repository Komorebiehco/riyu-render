import asyncio

import pytest

from src.config import config, parse_proxy_url
from src.dashboard import server
from src.sanitizer.stealth_browser import ProxyPool


class _Reader:
    async def readline(self):
        return b"HTTP/1.1 429 Not Enough Bandwidth\r\n"


class _Writer:
    def write(self, _data):
        pass

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass


class _JsonRequest:
    can_read_body = True

    def __init__(self, payload):
        self._payload = payload

    async def json(self):
        return self._payload


@pytest.mark.asyncio
async def test_http_429_is_classified_as_bandwidth_exhausted(monkeypatch):
    async def open_connection(_host, _port):
        return _Reader(), _Writer()

    monkeypatch.setattr(asyncio, "open_connection", open_connection)
    result = await server.test_proxy_connection(
        "http://user:pass@127.0.0.1:3129",
        timeout=1,
    )

    assert result["ok"] is False
    assert result["category"] == "bandwidth_exhausted"
    assert result["status_code"] == 429
    assert "额度不足" in result["error"]


def test_proxy_pool_sampling_covers_the_full_file(monkeypatch, tmp_path):
    proxy_file = tmp_path / "proxies.txt"
    proxy_file.write_text(
        "\n".join(f"127.0.0.{index}:3129" for index in range(1, 11)) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(config.proxy, "MODE", "file")
    monkeypatch.setattr(config.proxy, "PROXY_FILE", str(proxy_file))

    pool = ProxyPool()
    samples = pool.sample_proxies(4)

    assert [sample["host"] for sample in samples] == [
        "127.0.0.1",
        "127.0.0.4",
        "127.0.0.7",
        "127.0.0.10",
    ]


@pytest.mark.asyncio
async def test_file_mode_reports_when_all_samples_exhausted(monkeypatch):
    class Pool:
        def __len__(self):
            return 3300

        def sample_proxies(self, count):
            return [parse_proxy_url(f"127.0.0.{index}:3129") for index in range(1, count + 1)]

    async def exhausted(*_args, **_kwargs):
        return {
            "ok": False,
            "category": "bandwidth_exhausted",
            "status_code": 429,
            "error": "代理供应商返回 429，套餐流量或带宽额度不足",
        }

    monkeypatch.setattr(config.proxy, "MODE", "file")
    monkeypatch.setattr(config.proxy, "CUSTOM_PROXY", "")
    monkeypatch.setattr("src.sanitizer.stealth_browser.get_proxy_pool", lambda: Pool())
    monkeypatch.setattr(server, "test_proxy_connection", exhausted)

    response = await server._test_proxy_view(
        _JsonRequest({"sample_count": 8, "timeout": 3})
    )
    payload = response.body.decode("utf-8")

    assert '"sampled": 8' in payload
    assert '"targets_tested": 2' in payload
    assert '"pool_size": 3300' in payload
    assert '"succeeded": 0' in payload
    assert '"bandwidth_exhausted": 8' in payload
    assert "429" in payload
