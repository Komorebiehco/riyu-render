import pytest
from pathlib import Path
from unittest.mock import patch

from src.config import (
    config,
    format_proxy_url,
    load_persistent_settings,
    parse_proxy_url,
    save_proxy_pool,
    save_proxy_settings,
)
from src.sanitizer.stealth_browser import ProxyPool


def test_parse_proxy_url_formats():
    # SOCKS5
    p1 = parse_proxy_url("socks5://127.0.0.1:1080")
    assert p1["scheme"] == "socks5"
    assert p1["host"] == "127.0.0.1"
    assert p1["port"] == 1080
    assert p1["server"] == "socks5://127.0.0.1:1080"
    assert "username" not in p1

    # SOCKS5 with Auth
    p2 = parse_proxy_url("socks5://admin:secret@192.168.1.10:1080")
    assert p2["scheme"] == "socks5"
    assert p2["username"] == "admin"
    assert p2["password"] == "secret"
    assert p2["server"] == "socks5://192.168.1.10:1080"

    # HTTP with Auth
    p3 = parse_proxy_url("http://user:pass@proxy.example.com:8080")
    assert p3["scheme"] == "http"
    assert p3["host"] == "proxy.example.com"
    assert p3["port"] == 8080
    assert p3["username"] == "user"
    assert p3["password"] == "pass"

    # HTTPS
    p4 = parse_proxy_url("https://10.0.0.1:8443")
    assert p4["scheme"] == "https"
    assert p4["port"] == 8443

    # SOCKS5H
    p5 = parse_proxy_url("socks5h://user:pass@127.0.0.1:10800")
    assert p5["scheme"] == "socks5h"

    # Host:Port without scheme
    p6 = parse_proxy_url("127.0.0.1:7890")
    assert p6["scheme"] == "http"
    assert p6["host"] == "127.0.0.1"
    assert p6["port"] == 7890

    # User:Pass@Host:Port without scheme
    p7 = parse_proxy_url("foo:bar@127.0.0.1:7890")
    assert p7["scheme"] == "http"
    assert p7["username"] == "foo"
    assert p7["password"] == "bar"


def test_parse_proxy_url_invalid():
    with pytest.raises(ValueError, match="代理地址不能为空"):
        parse_proxy_url("")

    with pytest.raises(ValueError, match="不支持的代理协议"):
        parse_proxy_url("ftp://127.0.0.1:21")

    with pytest.raises(ValueError, match="无法解析代理主机与端口"):
        parse_proxy_url("http://invalid_no_port")


def test_format_proxy_url():
    parsed = parse_proxy_url("socks5://admin:secret@127.0.0.1:1080")
    assert format_proxy_url(parsed) == "socks5://admin:secret@127.0.0.1:1080"

    parsed_simple = parse_proxy_url("http://127.0.0.1:8080")
    assert format_proxy_url(parsed_simple) == "http://127.0.0.1:8080"


def test_proxy_pool_custom_mode():
    config.proxy.MODE = "custom"
    config.proxy.CUSTOM_PROXY = "socks5://user:pass@127.0.0.1:1080"

    pool = ProxyPool()
    assert len(pool) == 1
    p = pool.next_proxy()
    assert p is not None
    assert p["scheme"] == "socks5"
    assert p["username"] == "user"
    assert p["password"] == "pass"

    config.proxy.MODE = "none"
    pool.reload()
    assert len(pool) == 0
    assert pool.next_proxy() is None


def test_save_and_load_proxy_settings(tmp_path):
    test_settings_file = tmp_path / "settings.json"
    with patch("src.config.SETTINGS_FILE", test_settings_file):
        saved = save_proxy_settings(
            mode="custom",
            custom_proxy="socks5://127.0.0.1:1080",
            proxy_timeout=20,
            auto_check_enabled=True,
            auto_check_interval_seconds=600,
            auto_check_sample_count=12,
        )
        assert saved["mode"] == "custom"
        assert saved["custom_proxy"] == "socks5://127.0.0.1:1080"
        assert saved["proxy_timeout"] == 20
        assert saved["auto_check_enabled"] is True
        assert saved["auto_check_interval_seconds"] == 600
        assert saved["auto_check_sample_count"] == 12
        assert test_settings_file.is_file()

        # Reset config memory state and reload from file
        config.proxy.MODE = "none"
        config.proxy.CUSTOM_PROXY = ""
        config.proxy.AUTO_CHECK_ENABLED = False
        config.proxy.AUTO_CHECK_INTERVAL_SECONDS = 60
        config.proxy.AUTO_CHECK_SAMPLE_COUNT = 1
        load_persistent_settings()

        assert config.proxy.MODE == "custom"
        assert config.proxy.CUSTOM_PROXY == "socks5://127.0.0.1:1080"
        assert config.proxy.PROXY_TIMEOUT == 20
        assert config.proxy.AUTO_CHECK_ENABLED is True
        assert config.proxy.AUTO_CHECK_INTERVAL_SECONDS == 600
        assert config.proxy.AUTO_CHECK_SAMPLE_COUNT == 12

def test_parse_four_part_proxy():
    # host:port:user:pass
    p1 = parse_proxy_url("127.0.0.1:1080:myuser:mypass")
    assert p1["scheme"] == "http"
    assert p1["host"] == "127.0.0.1"
    assert p1["port"] == 1080
    assert p1["username"] == "myuser"
    assert p1["password"] == "mypass"

    # socks5://host:port:user:pass
    p2 = parse_proxy_url("socks5://127.0.0.1:1080:myuser:mypass")
    assert p2["scheme"] == "socks5"
    assert p2["host"] == "127.0.0.1"
    assert p2["port"] == 1080
    assert p2["username"] == "myuser"
    assert p2["password"] == "mypass"


def test_save_proxy_pool_validates_and_writes_atomically(tmp_path):
    target = tmp_path / "proxies.txt"
    result = save_proxy_pool(
        "# pool\nuser:pass@127.0.0.1:8080\n127.0.0.2:1080:u:p\n",
        target,
    )

    assert result["count"] == 2
    assert result["unique_count"] == 2
    assert target.read_text(encoding="utf-8") == (
        "user:pass@127.0.0.1:8080\n127.0.0.2:1080:u:p\n"
    )

    with pytest.raises(ValueError, match="无效行：2"):
        save_proxy_pool("127.0.0.1:8080\nnot-a-proxy\n", target)

    assert target.read_text(encoding="utf-8").startswith("user:pass@")
