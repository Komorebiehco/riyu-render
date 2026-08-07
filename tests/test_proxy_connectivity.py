import asyncio
import json

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
        "\n".join(
            f"user{(index - 1) // 3}:pass{(index - 1) // 3}@127.0.0.{index}:3129"
            for index in range(1, 11)
        ) + "\n",
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
async def test_file_mode_prunes_only_failed_sampled_nodes(monkeypatch, tmp_path):
    proxy_lines = [
        "http://user:pass@127.0.0.1:3129",
        "http://user:pass@127.0.0.2:3129",
        "http://user:pass@127.0.0.3:3129",
        "http://user:pass@127.0.0.4:3129",
    ]
    proxy_file = tmp_path / "proxies.txt"
    proxy_file.write_text("\n".join(proxy_lines) + "\n", encoding="utf-8")

    class Pool:
        def __init__(self):
            self.reload_calls = 0
            self.size = len(proxy_lines)

        def __len__(self):
            return self.size

        def sample_proxies(self, count):
            return [parse_proxy_url(line) for line in proxy_lines[:count - 1]]

        def reload(self):
            self.reload_calls += 1
            self.size = len(
                [line for line in proxy_file.read_text(encoding="utf-8").splitlines() if line]
            )

    pool = Pool()

    async def probe(proxy_url, *_args, **_kwargs):
        host = parse_proxy_url(proxy_url)["host"]
        if host == "127.0.0.2":
            return {"ok": True, "latency_ms": 20, "scheme": "http"}
        category = "timeout" if host == "127.0.0.1" else "handshake_failed"
        return {"ok": False, "category": category, "error": category}

    monkeypatch.setattr(config.proxy, "MODE", "file")
    monkeypatch.setattr(config.proxy, "CUSTOM_PROXY", "")
    monkeypatch.setattr(config.proxy, "PROXY_FILE", str(proxy_file))
    monkeypatch.setattr("src.sanitizer.stealth_browser.get_proxy_pool", lambda: pool)
    monkeypatch.setattr(server, "test_proxy_connection", probe)

    response = await server._test_proxy_view(_JsonRequest({"sample_count": 4, "timeout": 3}))
    payload = json.loads(response.body)

    assert payload["sampled"] == 3
    assert payload["succeeded"] == 1
    assert payload["removed"] == 2
    assert payload["initial_pool_size"] == 4
    assert payload["pool_size"] == 2
    assert pool.reload_calls == 1
    assert proxy_file.read_text(encoding="utf-8").splitlines() == [proxy_lines[1], proxy_lines[3]]


@pytest.mark.asyncio
async def test_file_mode_reports_when_all_samples_exhausted(monkeypatch, tmp_path):
    proxy_file = tmp_path / "proxies.txt"
    proxy_file.write_text(
        "\n".join(f"127.0.0.{index}:3129" for index in range(1, 9)) + "\n",
        encoding="utf-8",
    )

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
    monkeypatch.setattr(config.proxy, "PROXY_FILE", str(proxy_file))
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
    assert '"removed": 0' in payload
    assert len(proxy_file.read_text(encoding="utf-8").splitlines()) == 8
    assert "429" in payload


@pytest.mark.asyncio
async def test_file_mode_keeps_node_when_either_target_reports_quota_failure(monkeypatch, tmp_path):
    proxy_line = "http://user:pass@127.0.0.1:3129"
    proxy_file = tmp_path / "proxies.txt"
    proxy_file.write_text(proxy_line + "\n", encoding="utf-8")

    class Pool:
        def __len__(self):
            return 1

        def sample_proxies(self, _count):
            return [parse_proxy_url(proxy_line)]

    calls = 0

    async def mixed_quota_failure(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        category = "timeout" if calls == 1 else "bandwidth_exhausted"
        return {"ok": False, "category": category, "error": category}

    monkeypatch.setattr(config.proxy, "MODE", "file")
    monkeypatch.setattr(config.proxy, "PROXY_FILE", str(proxy_file))
    monkeypatch.setattr("src.sanitizer.stealth_browser.get_proxy_pool", lambda: Pool())
    monkeypatch.setattr(server, "test_proxy_connection", mixed_quota_failure)

    result = await server._test_proxy_pool_sample(1, 3)

    assert result["sampled"] == 1
    assert result["removed"] == 0
    assert proxy_file.read_text(encoding="utf-8") == proxy_line + "\n"


@pytest.mark.asyncio
async def test_none_mode_does_not_test_stale_custom_proxy(monkeypatch):
    async def unexpected_probe(*_args, **_kwargs):
        raise AssertionError("stale custom proxy should not be tested in none mode")

    monkeypatch.setattr(config.proxy, "MODE", "none")
    monkeypatch.setattr(config.proxy, "CUSTOM_PROXY", "http://127.0.0.1:8080")
    monkeypatch.setattr(server, "test_proxy_connection", unexpected_probe)

    response = await server._test_proxy_view(_JsonRequest({"timeout": 3}))
    payload = json.loads(response.body)

    assert payload["ok"] is False
    assert "请先输入" in payload["error"]


@pytest.mark.asyncio
async def test_file_mode_reports_mixed_failure_breakdown(monkeypatch):
    class Pool:
        def __len__(self):
            return 3300

        def sample_proxies(self, count):
            return [parse_proxy_url(f"127.0.0.{index}:3129") for index in range(1, count + 1)]

    calls = 0

    async def mixed_failures(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        category = "auth_failed" if calls > 6 else "bandwidth_exhausted"
        return {"ok": False, "category": category, "error": category}

    monkeypatch.setattr(config.proxy, "MODE", "file")
    monkeypatch.setattr(config.proxy, "CUSTOM_PROXY", "")
    monkeypatch.setattr("src.sanitizer.stealth_browser.get_proxy_pool", lambda: Pool())
    monkeypatch.setattr(server, "test_proxy_connection", mixed_failures)

    response = await server._test_proxy_view(
        _JsonRequest({"sample_count": 4, "timeout": 3})
    )
    payload = json.loads(response.body)

    assert "额度耗尽 3 个" in payload["error"]
    assert "认证失败 1 个" in payload["error"]
