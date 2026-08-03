# ============================================================
# captcha_solver.py — 打码平台对接模块
# 支持 CapSolver / 2Captcha
# 自动检测并处理 Google 安全风控挑战
# ============================================================

from __future__ import annotations

import asyncio
from typing import Optional

import aiohttp
from playwright.async_api import Page

from src.config import config
from src.monitor.logger import get_logger

log = get_logger("CAPTCHA")


# ══════════════════════════════════════════════════════════════
# 打码平台客户端
# ══════════════════════════════════════════════════════════════

class CapSolverClient:
    """CapSolver API 客户端（https://capsolver.com）"""

    BASE_URL = "https://api.capsolver.com"

    def __init__(self, api_key: str):
        self._key = api_key

    async def solve_recaptcha_v2(self, website_url: str, website_key: str) -> Optional[str]:
        """解决 reCAPTCHA v2，返回 g-recaptcha-response token"""
        async with aiohttp.ClientSession() as session:
            # 1. 创建任务
            create_payload = {
                "clientKey": self._key,
                "task": {
                    "type":       "ReCaptchaV2TaskProxyless",
                    "websiteURL": website_url,
                    "websiteKey": website_key,
                }
            }
            async with session.post(f"{self.BASE_URL}/createTask", json=create_payload) as resp:
                data = await resp.json()
                if data.get("errorId", 1) != 0:
                    log.error(f"CapSolver 创建任务失败: {data.get('errorDescription')}")
                    return None
                task_id = data["taskId"]

            # 2. 轮询结果（最多等待 config.captcha.SOLVE_TIMEOUT 秒）
            return await self._poll_result(session, task_id)

    async def solve_recaptcha_v3(
        self, website_url: str, website_key: str, action: str = "verify"
    ) -> Optional[str]:
        """解决 reCAPTCHA v3"""
        async with aiohttp.ClientSession() as session:
            create_payload = {
                "clientKey": self._key,
                "task": {
                    "type":       "ReCaptchaV3TaskProxyless",
                    "websiteURL": website_url,
                    "websiteKey": website_key,
                    "pageAction": action,
                    "minScore":   0.9,
                }
            }
            async with session.post(f"{self.BASE_URL}/createTask", json=create_payload) as resp:
                data = await resp.json()
                if data.get("errorId", 1) != 0:
                    log.error(f"CapSolver 创建 v3 任务失败: {data.get('errorDescription')}")
                    return None
                task_id = data["taskId"]

            return await self._poll_result(session, task_id)

    async def _poll_result(self, session: aiohttp.ClientSession, task_id: str) -> Optional[str]:
        timeout = config.captcha.SOLVE_TIMEOUT
        elapsed = 0
        while elapsed < timeout:
            await asyncio.sleep(3)
            elapsed += 3
            async with session.post(f"{self.BASE_URL}/getTaskResult", json={
                "clientKey": self._key,
                "taskId":    task_id,
            }) as resp:
                data = await resp.json()
                if data.get("status") == "ready":
                    token = data.get("solution", {}).get("gRecaptchaResponse")
                    log.info(f"打码成功 task_id={task_id}")
                    return token
                elif data.get("status") == "failed":
                    log.error(f"打码失败 task_id={task_id}: {data}")
                    return None
        log.error(f"打码超时 ({timeout}s) task_id={task_id}")
        return None


class TwoCaptchaClient:
    """2Captcha API 客户端（https://2captcha.com）"""

    BASE_URL = "https://2captcha.com"

    def __init__(self, api_key: str):
        self._key = api_key

    async def solve_recaptcha_v2(self, website_url: str, website_key: str) -> Optional[str]:
        async with aiohttp.ClientSession() as session:
            # 提交
            async with session.post(f"{self.BASE_URL}/in.php", data={
                "key":       self._key,
                "method":    "userrecaptcha",
                "googlekey": website_key,
                "pageurl":   website_url,
                "json":      1,
            }) as resp:
                data = await resp.json()
                if data.get("status") != 1:
                    log.error(f"2Captcha 提交失败: {data}")
                    return None
                captcha_id = data["request"]

            # 轮询
            timeout = config.captcha.SOLVE_TIMEOUT
            elapsed = 0
            while elapsed < timeout:
                await asyncio.sleep(5)
                elapsed += 5
                async with session.get(f"{self.BASE_URL}/res.php", params={
                    "key":    self._key,
                    "action": "get",
                    "id":     captcha_id,
                    "json":   1,
                }) as resp:
                    data = await resp.json()
                    if data.get("status") == 1:
                        log.info(f"2Captcha 打码成功 id={captcha_id}")
                        return data["request"]
                    elif data.get("request") == "ERROR_CAPTCHA_UNSOLVABLE":
                        log.error("2Captcha: 无法识别的验证码")
                        return None
        log.error(f"2Captcha 打码超时 ({timeout}s)")
        return None


# ══════════════════════════════════════════════════════════════
# 统一打码接口
# ══════════════════════════════════════════════════════════════

def _get_client():
    """根据配置返回对应的打码客户端"""
    provider = config.captcha.PROVIDER.lower()
    key = config.captcha.API_KEY
    if not key or provider == "none":
        return None
    if provider == "capsolver":
        return CapSolverClient(key)
    if provider == "2captcha":
        return TwoCaptchaClient(key)
    raise ValueError(f"未知的打码平台: {provider}")


# ── Google reCAPTCHA 常量 ────────────────────────────────────
GOOGLE_RECAPTCHA_V2_KEY = "6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-"
GOOGLE_RECAPTCHA_V3_KEY = "6LfwuyUTAAAAAOAmoS0fdqijC2PbbdH4kjq62Y1b"


# ══════════════════════════════════════════════════════════════
# 页面级安全挑战检测与处理
# ══════════════════════════════════════════════════════════════

class CaptchaHandler:
    """
    检测 Playwright Page 上的 Google 安全风控挑战并尝试自动过验。
    在清洗引擎每个步骤完成后调用 check_and_solve() 即可。
    """

    # Google 安全挑战的识别特征
    _CHALLENGE_SELECTORS = [
        "iframe[src*='recaptcha']",
        "iframe[title*='reCAPTCHA']",
        "div[jsname='UHEVhd']",                 # 异常活动提示
        "div:has-text('Verify it')",             # 身份验证弹窗
        "div:has-text('unusual activity')",
    ]

    def __init__(self):
        self._client = _get_client()

    async def check_and_solve(self, page: Page) -> bool:
        """
        检查页面是否触发了安全挑战，如有则尝试自动过。
        返回 True 表示成功通过（或无挑战），False 表示失败。
        """
        current_url = page.url

        # 1. 检测 reCAPTCHA iframe
        try:
            frame = await page.wait_for_selector(
                "iframe[src*='recaptcha']", timeout=2000
            )
            if frame and self._client:
                log.warning(f"检测到 reCAPTCHA，调用打码平台... url={current_url}")
                token = await self._client.solve_recaptcha_v2(
                    current_url, GOOGLE_RECAPTCHA_V2_KEY
                )
                if token:
                    # 将 token 注入页面
                    await page.evaluate(
                        f"document.getElementById('g-recaptcha-response').innerHTML='{token}';"
                    )
                    await page.evaluate(
                        "___grecaptcha_cfg.clients[0].aa.l.callback(arguments[0])",
                        token
                    )
                    await asyncio.sleep(2)
                    log.info("reCAPTCHA 已注入 token")
                    return True
                else:
                    log.error("打码失败，无法过 reCAPTCHA")
                    return False
        except Exception:
            pass  # 没有 reCAPTCHA，继续检查

        # 2. 检测"异常活动"或"请验证身份"弹窗
        challenge_selectors = [
            "div[jsname='UHEVhd']",
            "div:has-text('Verify it')",
        ]
        for sel in challenge_selectors:
            try:
                el = await page.wait_for_selector(sel, timeout=2000)
                if el:
                    log.warning(f"检测到身份验证弹窗: {sel}")
                    # 尝试点击"其他验证方式"
                    try_another = await page.query_selector(
                        "a:has-text('Try another way'), button:has-text('其他方式')"
                    )
                    if try_another:
                        await try_another.click()
                        await asyncio.sleep(2)
                        log.info("已切换到其他验证方式")
                    return False  # 需要人工介入或打码平台处理
            except Exception:
                continue

        return True  # 无安全挑战

    async def is_challenge_present(self, page: Page) -> bool:
        """快速检测页面是否有安全挑战（不触发处理）"""
        for sel in self._CHALLENGE_SELECTORS:
            try:
                el = await page.query_selector(sel)
                if el:
                    return True
            except Exception:
                pass
        return False
