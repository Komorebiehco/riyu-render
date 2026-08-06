import json
import os
import shutil
from pathlib import Path
from uuid import uuid4
from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.getenv("DATA_DIR", str(PROJECT_ROOT / "data"))).expanduser()
DEFAULT_PROXY_FILE = DATA_DIR / "proxies.txt"

def _path_from_text(value: str | None) -> Path | None:
    if not value:
        return None
    cleaned = os.path.expandvars(value.strip().strip('"'))
    return Path(cleaned).expanduser() if cleaned else None

def resolve_chromium_path(
    explicit_path: str | None = None,
    *,
    project_root: Path | None = None,
    environ: dict[str, str] | None = None,
) -> str:
    env = os.environ if environ is None else environ
    root = PROJECT_ROOT if project_root is None else Path(project_root)
    candidates: list[Path] = []

    override = explicit_path if explicit_path is not None else env.get("CHROMIUM_PATH")
    override_path = _path_from_text(override)
    if override_path:
        candidates.append(override_path)

    marker = root / ".runtime" / "browser.path"
    try:
        marker_path = _path_from_text(marker.read_text(encoding="utf-8"))
    except (OSError, UnicodeError):
        marker_path = None
    if marker_path:
        candidates.append(marker_path)

    candidates.append(root / ".runtime" / "chromium" / "chrome-win64" / "chrome.exe")

    playwright_roots = [
        Path.home() / ".cache" / "ms-playwright",
        Path.home() / ".cache" / "ms-playwright-go",
    ]
    configured_playwright_root = _path_from_text(env.get("PLAYWRIGHT_BROWSERS_PATH"))
    if configured_playwright_root:
        playwright_roots.insert(0, configured_playwright_root)

    for playwright_root in playwright_roots:
        try:
            candidates.extend(sorted(
                playwright_root.glob("chromium-*/chrome-linux/chrome"),
                reverse=True,
            ))
            candidates.extend(sorted(
                playwright_root.glob("chromium_headless_shell-*/chrome-linux/headless_shell"),
                reverse=True,
            ))
            candidates.extend(sorted(
                playwright_root.glob("chromium-*/chrome-linux64/chrome"),
                reverse=True,
            ))
        except OSError:
            pass

    local_app_data = env.get("LOCALAPPDATA", "")
    if local_app_data:
        playwright_root = Path(local_app_data) / "ms-playwright"
        try:
            candidates.extend(sorted(
                playwright_root.glob("chromium-*/chrome-win64/chrome.exe"),
                reverse=True,
            ))
        except OSError:
            pass

    install_locations = (
        (env.get("ProgramFiles"), "Google/Chrome/Application/chrome.exe"),
        (env.get("ProgramFiles(x86)"), "Google/Chrome/Application/chrome.exe"),
        (local_app_data, "Google/Chrome/Application/chrome.exe"),
        (env.get("ProgramFiles"), "Microsoft/Edge/Application/msedge.exe"),
        (env.get("ProgramFiles(x86)"), "Microsoft/Edge/Application/msedge.exe"),
        (local_app_data, "Microsoft/Edge/Application/msedge.exe"),
    )
    for base, suffix in install_locations:
        if base:
            candidates.append(Path(base) / Path(suffix))

    seen: set[str] = set()
    for candidate in candidates:
        key = os.path.normcase(str(candidate))
        if key in seen:
            continue
        seen.add(key)
        if candidate.is_file():
            return str(candidate)

    for command in (
        "google-chrome",
        "google-chrome-stable",
        "chrome",
        "chrome.exe",
        "msedge",
        "msedge.exe",
        "chromium",
        "chromium.exe",
    ):
        resolved = shutil.which(command, path=env.get("PATH"))
        if resolved and Path(resolved).is_file():
            return resolved

    return ""


# ── 接码邮局配置 ─────────────────────────────────────────────
class MailConfig:
    BUYER_DOMAIN: str = os.getenv("BUYER_DOMAIN", "your-buyer-domain.com")
    MAIL_CALLBACK_URL: str = os.getenv("MAIL_CALLBACK_URL", "http://127.0.0.1:8765/code")
    CODE_WAIT_TIMEOUT: int = int(os.getenv("CODE_WAIT_TIMEOUT", "30"))
    CODE_POLL_INTERVAL: float = float(os.getenv("CODE_POLL_INTERVAL", "0.5"))
    CALLBACK_SERVER_PORT: int = int(os.getenv("CALLBACK_SERVER_PORT", "8765"))

    @classmethod
    def generate_receiver(cls, gmail: str) -> str:
        prefix = gmail.replace("@gmail.com", "").replace(".", "_").replace("+", "_")
        return f"{prefix}@{cls.BUYER_DOMAIN}"


# ── 代理解析与配置 ───────────────────────────────────────────
def parse_proxy_url(url: str, default_scheme: str = "http") -> dict:
    """
    将代理 URL 解析为统一字典格式。
    代理池文件与输入框支持以下格式 (每行一个代理)：
      1. 标准带协议 URL:   socks5://user:pass@host:port
      2. HTTP/SOCKS 简写:  socks5://host:port 或 http://host:port
      3. 简易主机端口:     host:port (默认使用 http)
      4. 带有账号密码:     user:pass@host:port
      5. 代理商四段式:     host:port:user:pass 或 socks5://host:port:user:pass
    """
    raw = (url or "").strip()
    if not raw:
        raise ValueError("代理地址不能为空")

    work_url = raw
    scheme = default_scheme

    if "://" in work_url:
        scheme_part, work_url = work_url.split("://", 1)
        scheme = scheme_part.lower()

    # 处理代理商常用的 host:port:user:pass 四段式格式
    if "@" not in work_url and work_url.count(":") == 3:
        parts = work_url.split(":")
        work_url = f"{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"

    full_url = f"{scheme}://{work_url}"

    from urllib.parse import urlparse
    parsed = urlparse(full_url)
    scheme = (parsed.scheme or default_scheme).lower()
    if scheme not in ("http", "https", "socks5", "socks5h", "socks4"):
        raise ValueError(f"不支持的代理协议: {scheme}")

    if not parsed.hostname or not parsed.port:
        raise ValueError(f"无法解析代理主机与端口: {raw}")

    server = f"{scheme}://{parsed.hostname}:{parsed.port}"
    result: dict[str, str | int] = {
        "server": server,
        "scheme": scheme,
        "host": parsed.hostname,
        "port": parsed.port,
        "raw_url": raw,
    }
    if parsed.username:
        result["username"] = parsed.username
    if parsed.password:
        result["password"] = parsed.password

    return result


def format_proxy_url(proxy_dict: dict) -> str:
    """根据代理字典拼装完整的代理 URL"""
    scheme = proxy_dict.get("scheme", "http")
    host = proxy_dict.get("host", "")
    port = proxy_dict.get("port", "")
    username = proxy_dict.get("username")
    password = proxy_dict.get("password")
    if username:
        auth = f"{username}:{password}@" if password else f"{username}@"
        return f"{scheme}://{auth}{host}:{port}"
    return f"{scheme}://{host}:{port}"


class ProxyConfig:
    MODE: str = os.getenv("PROXY_MODE", "none")
    CUSTOM_PROXY: str = os.getenv("CUSTOM_PROXY", "")
    PROXY_FILE: str = os.getenv("PROXY_FILE", str(DEFAULT_PROXY_FILE))
    PROXY_API_URL: str = os.getenv("PROXY_API_URL", "")
    PROXY_TIMEOUT: int = int(os.getenv("PROXY_TIMEOUT", "15"))

    def to_dict(self) -> dict:
        return {
            "mode": self.MODE,
            "custom_proxy": self.CUSTOM_PROXY,
            "proxy_file": self.PROXY_FILE,
            "proxy_api_url": self.PROXY_API_URL,
            "proxy_timeout": self.PROXY_TIMEOUT,
        }


# ── 打码平台配置 ─────────────────────────────────────────────
class CaptchaConfig:
    PROVIDER: str = os.getenv("CAPTCHA_PROVIDER", "capsolver")
    API_KEY: str = os.getenv("CAPTCHA_API_KEY", "")
    SOLVE_TIMEOUT: int = int(os.getenv("CAPTCHA_TIMEOUT", "120"))


# ── 并发任务配置 ─────────────────────────────────────────────
class QueueConfig:
    MAX_WORKERS: int = int(os.getenv("MAX_WORKERS", "20"))
    TASK_TOTAL_TIMEOUT: int = int(os.getenv("TASK_TOTAL_TIMEOUT", "180"))
    MAX_RETRIES: int = int(os.getenv("MAX_RETRIES", "3"))
    RETRY_BASE_DELAY: float = float(os.getenv("RETRY_BASE_DELAY", "2.0"))


# ── 密码生成配置 ─────────────────────────────────────────────
class PasswordConfig:
    LENGTH: int = int(os.getenv("PASSWORD_LENGTH", "18"))
    USE_UPPERCASE: bool = True
    USE_LOWERCASE: bool = True
    USE_DIGITS: bool = True
    USE_SYMBOLS: bool = True
    SYMBOLS: str = "!@#%*-_=+"


# ── 数据库配置 ───────────────────────────────────────────────
class DBConfig:
    TYPE: str = os.getenv("DB_TYPE", "sqlite")
    SQLITE_PATH: str = os.getenv("SQLITE_PATH", str(DATA_DIR / "accounts.db"))
    POSTGRES_URL: str = os.getenv("POSTGRES_URL", "")
    ENCRYPTION_KEY: str = os.getenv(
        "ENCRYPTION_KEY",
        "0000000000000000000000000000000000000000000000000000000000000000"
    )


# ── Redis 配置 ───────────────────────────────────────────────
class RedisConfig:
    HOST: str = os.getenv("REDIS_HOST", "127.0.0.1")
    PORT: int = int(os.getenv("REDIS_PORT", "6379"))
    DB: int = int(os.getenv("REDIS_DB", "0"))
    PASSWORD: str = os.getenv("REDIS_PASSWORD", "")

    @classmethod
    def url(cls) -> str:
        if cls.PASSWORD:
            return f"redis://:{cls.PASSWORD}@{cls.HOST}:{cls.PORT}/{cls.DB}"
        return f"redis://{cls.HOST}:{cls.PORT}/{cls.DB}"


# ── 浏览器配置 ───────────────────────────────────────────────
class BrowserConfig:
    ACTION_DELAY_MIN: float = float(os.getenv("ACTION_DELAY_MIN", "0.8"))
    ACTION_DELAY_MAX: float = float(os.getenv("ACTION_DELAY_MAX", "2.0"))
    PAGE_TIMEOUT: int = int(os.getenv("PAGE_TIMEOUT", "30"))
    HEADLESS: bool = os.getenv("HEADLESS", "true").lower() == "true"
    CHROMIUM_PATH: str = resolve_chromium_path()

    def executable_available(self) -> bool:
        return bool(self.CHROMIUM_PATH and Path(self.CHROMIUM_PATH).is_file())


# ── 日志配置 ─────────────────────────────────────────────────
class LogConfig:
    LOG_DIR: str = os.getenv("LOG_DIR", "logs")
    LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    CONSOLE_OUTPUT: bool = True


SETTINGS_FILE = DATA_DIR / "settings.json"


# ── 汇总暴露 ─────────────────────────────────────────────────
class Config:
    mail = MailConfig()
    proxy = ProxyConfig()
    captcha = CaptchaConfig()
    queue = QueueConfig()
    password = PasswordConfig()
    db = DBConfig()
    redis = RedisConfig()
    browser = BrowserConfig()
    log = LogConfig()


config = Config()


def load_persistent_settings() -> None:
    if not SETTINGS_FILE.is_file():
        return
    try:
        data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        proxy_data = data.get("proxy", {})
        if "mode" in proxy_data:
            config.proxy.MODE = str(proxy_data["mode"])
        if "custom_proxy" in proxy_data:
            config.proxy.CUSTOM_PROXY = str(proxy_data["custom_proxy"])
        if "proxy_file" in proxy_data:
            config.proxy.PROXY_FILE = str(proxy_data["proxy_file"])
        if "proxy_api_url" in proxy_data:
            config.proxy.PROXY_API_URL = str(proxy_data["proxy_api_url"])
        if "proxy_timeout" in proxy_data:
            config.proxy.PROXY_TIMEOUT = int(proxy_data["proxy_timeout"])
    except Exception:
        pass


def save_proxy_settings(
    mode: str,
    custom_proxy: str = "",
    proxy_file: str = str(DEFAULT_PROXY_FILE),
    proxy_api_url: str = "",
    proxy_timeout: int = 15,
) -> dict:
    valid_modes = {"none", "custom", "file", "api"}
    if mode not in valid_modes:
        raise ValueError(f"无效的代理模式: {mode}，必须为 {valid_modes} 之一")

    if mode == "custom" and custom_proxy.strip():
        parse_proxy_url(custom_proxy.strip())

    config.proxy.MODE = mode
    config.proxy.CUSTOM_PROXY = custom_proxy.strip()
    resolved_proxy_file = proxy_file.strip() or str(DEFAULT_PROXY_FILE)
    if mode == "file" and not Path(resolved_proxy_file).is_file():
        raise ValueError("请先上传有效的代理池 TXT 文件")

    config.proxy.PROXY_FILE = resolved_proxy_file
    config.proxy.PROXY_API_URL = proxy_api_url.strip()
    config.proxy.PROXY_TIMEOUT = int(proxy_timeout)

    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    existing = {}
    if SETTINGS_FILE.is_file():
        try:
            existing = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        except Exception:
            existing = {}

    existing["proxy"] = config.proxy.to_dict()
    SETTINGS_FILE.write_text(json.dumps(existing, ensure_ascii=False, indent=2), encoding="utf-8")

    try:
        from src.sanitizer.stealth_browser import get_proxy_pool
        get_proxy_pool().reload()
    except Exception:
        pass

    return config.proxy.to_dict()


def save_proxy_pool(content: str, destination: Path | None = None) -> dict:
    """Validate and atomically store an uploaded proxy pool."""
    target = DEFAULT_PROXY_FILE if destination is None else Path(destination)
    valid_lines: list[str] = []
    invalid_line_numbers: list[int] = []

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        value = raw_line.strip().lstrip("\ufeff")
        if not value or value.startswith("#"):
            continue
        try:
            parse_proxy_url(value)
        except (TypeError, ValueError):
            invalid_line_numbers.append(line_number)
            continue
        valid_lines.append(value)

    if invalid_line_numbers:
        preview = ", ".join(str(number) for number in invalid_line_numbers[:20])
        suffix = "..." if len(invalid_line_numbers) > 20 else ""
        raise ValueError(f"代理文件包含无效行：{preview}{suffix}")
    valid_lines = list(dict.fromkeys(valid_lines))
    if not valid_lines:
        raise ValueError("代理文件中没有可用节点")

    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{uuid4().hex}.tmp")
    try:
        temporary.write_text("\n".join(valid_lines) + "\n", encoding="utf-8")
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)

    return {
        "path": str(target),
        "name": target.name,
        "count": len(valid_lines),
        "unique_count": len(set(valid_lines)),
        "size": target.stat().st_size,
    }


load_persistent_settings()
