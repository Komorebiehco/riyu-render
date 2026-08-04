# ============================================================
# stealth_browser.py — 反指纹无头浏览器封装
# 基于 Playwright + playwright-stealth
# 1 账号 = 1 独立代理 IP = 1 独立浏览器 Context
# ============================================================

from __future__ import annotations

import json
import random
import re
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator, Optional

from playwright.async_api import (
    Browser,
    BrowserContext,
    Error as PlaywrightError,
    Page,
    Playwright,
    async_playwright,
)

from src.config import config
from src.monitor.logger import get_logger

log = get_logger("BROWSER")

# Cleaning tasks are backend jobs. Keep this code-level guarantee independent
# from local .env/debug settings so no interactive Chrome/Edge window appears.
BACKEND_HEADLESS = True


class BrowserLaunchError(RuntimeError):
    """Raised when Playwright cannot start a usable Chromium-based browser."""

# ── 随机化指纹数据池 ─────────────────────────────────────────

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]

_VIEWPORTS = [
    {"width": 1920, "height": 1080},
    {"width": 1440, "height": 900},
    {"width": 1366, "height": 768},
    {"width": 1536, "height": 864},
    {"width": 1280, "height": 720},
]

_LOCALES   = ["en-US", "en-GB", "zh-CN", "zh-TW", "ja-JP"]
_TIMEZONES = ["America/New_York", "America/Los_Angeles", "Europe/London", "Asia/Tokyo", "Asia/Shanghai"]


# ── 反检测 JS 注入（替代 playwright-stealth 库）──────────────

_STEALTH_SCRIPT = """
// 1. 隐藏 webdriver 属性
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});

// 2. 伪造 plugins（无头浏览器默认为空）
Object.defineProperty(navigator, 'plugins', {
    get: () => [
        {name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer'},
        {name: 'Chrome PDF Viewer',  filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai'},
        {name: 'Native Client',      filename: 'internal-nacl-plugin'},
    ],
});

// 3. 伪造 languages
Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});

// 4. 修复 chrome 对象（无头模式下可能缺失）
if (!window.chrome) {
    window.chrome = {runtime: {}, app: {}};
}

// 5. 伪造 permissions API（避免 notification 权限被识别为 bot）
const originalQuery = window.navigator.permissions.query;
window.navigator.permissions.query = (parameters) =>
    parameters.name === 'notifications'
        ? Promise.resolve({state: Notification.permission})
        : originalQuery(parameters);

// 6. 隐藏 Headless 特征
Object.defineProperty(navigator, 'platform',    {get: () => 'Win32'});
Object.defineProperty(navigator, 'vendor',      {get: () => 'Google Inc.'});
Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => 8});
Object.defineProperty(navigator, 'deviceMemory',         {get: () => 8});
"""


# ── 代理加载器 ───────────────────────────────────────────────

class ProxyPool:
    """从文件、自定义节点或 API 加载代理，轮询分配"""

    def __init__(self):
        self._proxies: list[str] = []
        self._index = 0
        self._load()

    def _load(self) -> None:
        self._proxies = []
        mode = config.proxy.MODE
        if mode == "none":
            return
        if mode == "custom":
            if config.proxy.CUSTOM_PROXY.strip():
                self._proxies = [config.proxy.CUSTOM_PROXY.strip()]
                log.info("已配置自定义单节点代理")
        elif mode == "file":
            try:
                with open(config.proxy.PROXY_FILE, encoding="utf-8") as f:
                    self._proxies = [
                        line.strip() for line in f
                        if line.strip() and not line.startswith("#")
                    ]
                log.info(f"已加载 {len(self._proxies)} 个代理")
            except FileNotFoundError:
                log.warning(f"代理文件不存在: {config.proxy.PROXY_FILE}，将不使用代理")
        elif mode == "api":
            log.info("代理 API 模式：每次使用时动态获取")

    def reload(self) -> None:
        self._index = 0
        self._load()

    def next_proxy(self) -> Optional[dict]:
        """获取下一个代理配置（轮询）"""
        if not self._proxies:
            return None
        proxy_url = self._proxies[self._index % len(self._proxies)]
        self._index += 1
        try:
            return _parse_proxy_url(proxy_url)
        except Exception as e:
            log.warning(f"解析代理地址失败 ({proxy_url}): {e}")
            return None

    def sample_proxies(self, count: int = 8) -> list[dict]:
        """Return evenly distributed, parsed proxies without exposing raw values."""
        if not self._proxies or count <= 0:
            return []
        sample_count = min(count, len(self._proxies))
        if sample_count == 1:
            indexes = [self._index % len(self._proxies)]
        else:
            last = len(self._proxies) - 1
            indexes = [round(position * last / (sample_count - 1)) for position in range(sample_count)]
        self._index = (self._index + sample_count) % len(self._proxies)
        parsed: list[dict] = []
        for index in indexes:
            try:
                parsed.append(_parse_proxy_url(self._proxies[index]))
            except Exception as exc:
                log.warning(f"抽样代理解析失败 (位置 {index + 1}): {exc}")
        return parsed

    def __len__(self) -> int:
        return len(self._proxies)


def _parse_proxy_url(url: str) -> dict:
    from src.config import parse_proxy_url
    return parse_proxy_url(url)


# ── 全局代理池单例 ───────────────────────────────────────────
_proxy_pool = ProxyPool()

def get_proxy_pool() -> ProxyPool:
    return _proxy_pool


def _build_launch_args(viewport: dict[str, int]) -> list[str]:
    """Build browser flags shared by visible and headless sessions."""
    return [
        "--incognito",
        "--disable-blink-features=AutomationControlled",
        "--disable-infobars",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        f"--window-size={viewport['width']},{viewport['height']}",
    ]


# ── StealthBrowser 上下文管理器 ──────────────────────────────

@asynccontextmanager
async def stealth_context(
    playwright: Playwright,
    proxy_override: Optional[dict] = None,
    inject_cookies: Optional[str] = None,   # JSON 格式的 Cookie 字符串
) -> AsyncGenerator[tuple[BrowserContext, Page], None]:
    """
    异步上下文管理器：创建一个具备反指纹能力的浏览器 Context 和首页 Page。

    用法：
        async with stealth_context(playwright) as (ctx, page):
            await page.goto("https://myaccount.google.com")
            ...
    """
    # 随机化指纹
    user_agent = random.choice(_USER_AGENTS)
    viewport   = random.choice(_VIEWPORTS)
    locale     = random.choice(_LOCALES)
    timezone   = random.choice(_TIMEZONES)

    # 代理选择
    proxy = proxy_override or _proxy_pool.next_proxy()

    # 启动参数（进一步规避无头检测）
    launch_args = _build_launch_args(viewport)

    browser: Optional[Browser] = None
    context: Optional[BrowserContext] = None

    try:
        try:
            browser = await playwright.chromium.launch(
                headless=BACKEND_HEADLESS,
                args=launch_args,
                executable_path=config.browser.CHROMIUM_PATH or None,
            )
        except PlaywrightError as exc:
            first_line = str(exc).splitlines()[0].strip()
            if config.browser.CHROMIUM_PATH:
                browser_name = Path(config.browser.CHROMIUM_PATH).name
                message = f"浏览器 {browser_name} 启动失败: {first_line}"
            else:
                message = (
                    "未找到可用的 Chrome/Edge，且 Playwright Chromium 无法启动；"
                    "请重新运行 setup.cmd，或通过 CHROMIUM_PATH 指定浏览器。"
                )
            log.error(message)
            raise BrowserLaunchError(message) from exc

        context_options: dict = {
            "user_agent":          user_agent,
            "viewport":            viewport,
            "locale":              locale,
            "timezone_id":         timezone,
            "java_script_enabled": True,
            "accept_downloads":    False,
        }
        if proxy:
            context_options["proxy"] = proxy

        # Playwright 的非持久化 Context 本身不会复用用户资料；结合
        # --incognito 可让可见的 Chrome/Edge 明确显示为无痕窗口。
        context = await browser.new_context(**context_options)

        # 注入反检测脚本（对所有页面生效）
        await context.add_init_script(_STEALTH_SCRIPT)

        # 注入 Cookie（如果有卡网提供的 Cookie）
        if inject_cookies:
            try:
                cookies = json.loads(inject_cookies)
                await context.add_cookies(cookies)
                log.debug("Cookie 注入成功")
            except Exception as e:
                log.warning(f"Cookie 注入失败: {e}")

        page = await context.new_page()
        page.set_default_timeout(config.browser.PAGE_TIMEOUT * 1000)

        yield context, page

    finally:
        if context:
            try:
                await context.close()
            except Exception:
                pass
        if browser:
            try:
                await browser.close()
            except Exception:
                pass


# ── 便捷操作封装 ─────────────────────────────────────────────

async def safe_click(page: Page, selector: str, timeout: int = 5000) -> bool:
    """安全点击：找不到元素返回 False 而非抛出异常"""
    try:
        await page.click(selector, timeout=timeout)
        return True
    except Exception:
        return False


async def safe_fill(page: Page, selector: str, value: str, timeout: int = 5000) -> bool:
    """安全填写表单"""
    try:
        await page.fill(selector, value, timeout=timeout)
        return True
    except Exception:
        return False


async def wait_for_any(page: Page, selectors: list[str], timeout: int = 10000) -> Optional[str]:
    """等待多个选择器中任意一个出现，返回第一个匹配的选择器"""
    import asyncio
    tasks = [
        asyncio.create_task(_wait_single(page, sel, timeout))
        for sel in selectors
    ]
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for t in pending:
        t.cancel()
    for t in done:
        result = t.result()
        if result:
            return result
    return None


async def _wait_single(page: Page, selector: str, timeout: int) -> Optional[str]:
    try:
        await page.wait_for_selector(selector, timeout=timeout)
        return selector
    except Exception:
        return None


async def human_delay(min_s: float = None, max_s: float = None) -> None:
    """模拟人类操作间隔（随机延迟）"""
    import asyncio
    lo = min_s or config.browser.ACTION_DELAY_MIN
    hi = max_s or config.browser.ACTION_DELAY_MAX
    await asyncio.sleep(random.uniform(lo, hi))
