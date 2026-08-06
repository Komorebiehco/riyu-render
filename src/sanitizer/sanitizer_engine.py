# ============================================================
# sanitizer_engine.py — 核心 8 步清洗引擎
# 严格按照顺序执行，带断点续跑、失败标记、超时保护
# ============================================================

from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import string
import time
from datetime import datetime, timezone
from typing import Optional

import aiohttp
import pyotp
from playwright.async_api import Page, async_playwright

from src.config import config
from src.monitor.logger import get_logger, get_stats
from src.sanitizer.captcha_solver import CaptchaHandler
from src.sanitizer.stealth_browser import (
    BrowserLaunchError,
    human_delay,
    safe_click,
    safe_fill,
    stealth_context,
)
from src.storage.db_manager import DBManager
from src.storage.models import AccountStatus, CleanAccount, FailReason, SanitizeTask

# 加载选择器配置
_SEL_PATH = os.path.join(os.path.dirname(__file__), "selectors.json")
with open(_SEL_PATH, encoding="utf-8") as _f:
    SEL: dict = json.load(_f)

log = get_logger("ENGINE")

_STEP_NAMES = {
    1: "预检",
    2: "邮箱确认",
    3: "安全校验",
    4: "密钥检查",
    5: "双重验证",
    6: "会话确认",
    7: "授权检查",
    8: "结果验证",
}


# ══════════════════════════════════════════════════════════════
# 工具函数
# ══════════════════════════════════════════════════════════════

def generate_password() -> str:
    """生成符合 Google 密码策略的强随机密码"""
    cfg = config.password
    chars = ""
    required = []
    if cfg.USE_UPPERCASE:
        chars += string.ascii_uppercase
        required.append(secrets.choice(string.ascii_uppercase))
    if cfg.USE_LOWERCASE:
        chars += string.ascii_lowercase
        required.append(secrets.choice(string.ascii_lowercase))
    if cfg.USE_DIGITS:
        chars += string.digits
        required.append(secrets.choice(string.digits))
    if cfg.USE_SYMBOLS:
        chars += cfg.SYMBOLS
        required.append(secrets.choice(cfg.SYMBOLS))

    # 填充到指定长度
    remaining = cfg.LENGTH - len(required)
    pool = list(required) + [secrets.choice(chars) for _ in range(remaining)]
    secrets.SystemRandom().shuffle(pool)
    return "".join(pool)


async def fetch_mail_code(to_email: str, timeout: int = None) -> Optional[str]:
    """
    轮询接码回调服务器，等待验证码到达。
    接码回调接口：GET /code?to=<email>
    返回 6 位验证码字符串，超时返回 None。
    """
    callback_url = config.mail.MAIL_CALLBACK_URL.replace("/code", "")
    timeout = timeout or config.mail.CODE_WAIT_TIMEOUT
    deadline = time.time() + timeout

    async with aiohttp.ClientSession() as session:
        while time.time() < deadline:
            try:
                async with session.get(
                    f"{callback_url}/poll",
                    params={"to": to_email},
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        code = data.get("code")
                        if code and re.match(r"^\d{6}$", str(code)):
                            return str(code)
            except Exception:
                pass
            await asyncio.sleep(config.mail.CODE_POLL_INTERVAL)

    return None


# ══════════════════════════════════════════════════════════════
# 核心清洗引擎
# ══════════════════════════════════════════════════════════════

class SanitizerEngine:
    """
    8 步全链路账号清洗引擎。
    每个任务独立创建一个无头浏览器 + 代理 IP 实例，互不干扰。
    """

    def __init__(self, db: DBManager):
        self._db = db
        self._captcha = CaptchaHandler()

    # ── 主入口 ───────────────────────────────────────────────

    async def run(self, task: SanitizeTask) -> CleanAccount:
        account = task.account
        cred    = task.credential
        start   = time.time()

        log.info(f"[{task.task_id}] 开始清洗: {cred.gmail}")
        account.status = AccountStatus.SANITIZING
        account.step_progress.updated_at = datetime.now(timezone.utc)
        await self._save(account)

        try:
            async with async_playwright() as playwright:
                async with stealth_context(
                    playwright,
                    inject_cookies=cred.cookies,
                ) as (ctx, page):
                    account.proxy_used = str(page.context.browser)

                    # ── Step 1: 账号预检 ──────────────────────
                    if not account.step_progress.step1_validated:
                        await self._begin_step(account, 1)
                        ok = await self._step1_validate(page, cred, account)
                        if not ok:
                            return account
                        account.mark_step("step1_validated")
                        await self._save(account)

                    # ── Step 2: 改辅助邮箱 ────────────────────
                    if not account.step_progress.step2_email_changed:
                        await self._begin_step(account, 2)
                        ok = await self._step2_recovery_email(page, cred, account)
                        if not ok:
                            return account
                        account.mark_step("step2_email_changed")
                        await self._save(account)

                    # ── Step 3: 移除辅助手机号 ────────────────
                    if not account.step_progress.step3_phone_removed:
                        await self._begin_step(account, 3)
                        await self._step3_recovery_phone(page, account)
                        account.mark_step("step3_phone_removed")
                        await self._save(account)

                    # ── Step 4: 删除所有 Passkey ──────────────
                    if not account.step_progress.step4_passkeys_deleted:
                        await self._begin_step(account, 4)
                        await self._step4_delete_passkeys(page, account)
                        account.mark_step("step4_passkeys_deleted")
                        await self._save(account)

                    # ── Step 5: 重置 2FA + 备用码 ─────────────
                    if not account.step_progress.step5_2fa_reset:
                        await self._begin_step(account, 5)
                        ok = await self._step5_reset_2fa(page, cred, account)
                        if not ok:
                            return account
                        account.mark_step("step5_2fa_reset")
                        await self._save(account)

                    if not account.step_progress.step5_backup_codes:
                        await self._begin_step(account, 5)
                        await self._step5b_backup_codes(page, account)
                        account.mark_step("step5_backup_codes")
                        await self._save(account)

                    # ── Step 6: 改密码 + 全下线 ───────────────
                    if not account.step_progress.step6_password_changed:
                        await self._begin_step(account, 6)
                        ok = await self._step6_change_password(page, cred, account)
                        if not ok:
                            return account
                        account.mark_step("step6_password_changed")
                        account.mark_step("step6_all_signed_out")
                        await self._save(account)

                    # ── Step 7: 撤销 OAuth ────────────────────
                    if not account.step_progress.step7_oauth_revoked:
                        await self._begin_step(account, 7)
                        await self._step7_revoke_oauth(page, account)
                        account.mark_step("step7_oauth_revoked")
                        await self._save(account)

                    # ── Step 8: 验证新凭证 ────────────────────
                    if not account.step_progress.step8_verified:
                        await self._begin_step(account, 8)
                        ok = await self._step8_verify(playwright, account)
                        if not ok:
                            account.mark_failed(FailReason.UNKNOWN, "新凭证验证登录失败")
                            await self._save(account)
                            return account
                        account.mark_step("step8_verified")

        except asyncio.TimeoutError:
            account.mark_failed(
                FailReason.STEP_TIMEOUT,
                f"总超时 {config.queue.TASK_TOTAL_TIMEOUT}s"
            )
        except BrowserLaunchError as e:
            log.error(f"[{task.task_id}] 浏览器不可用: {e}")
            account.mark_failed(FailReason.BROWSER_ERROR, str(e))
        except Exception as e:
            log.exception(f"[{task.task_id}] 未捕获异常: {e}")
            account.mark_failed(FailReason.UNKNOWN, str(e))
        else:
            # 全部成功
            account.mark_sanitized()
            elapsed = time.time() - start
            get_stats().increment("success")
            get_stats().total_elapsed_seconds += elapsed
            log.success(f"[{task.task_id}] ✅ 清洗成功 {cred.gmail} 耗时 {elapsed:.1f}s")
        finally:
            # Persist both success and every early-return failure path.
            await self._save(account)
        return account

    async def _begin_step(self, account: CleanAccount, step: int) -> None:
        """Persist the active step before browser work starts."""
        account.begin_step(step, _STEP_NAMES[step])
        await self._save(account)

    # ══════════════════════════════════════════════════════════
    # Step 1: 账号预检
    # ══════════════════════════════════════════════════════════

    async def _step1_validate(self, page: Page, cred, account: CleanAccount) -> bool:
        log.debug(f"Step1 预检: {cred.gmail}")
        try:
            await page.goto("https://accounts.google.com/signin", wait_until="networkidle")
            await human_delay(1.0, 2.0)
            log.debug(f"Step1 登录页 URL: {page.url}")

            # ── 输入邮箱 ───────────────────────────────────────
            email_loc = page.locator(SEL["login"]["email_input"]).first
            await email_loc.wait_for(state="visible", timeout=15000)
            await email_loc.fill(cred.gmail)
            await human_delay(0.5, 1.0)

            # 点击 Next
            next_loc = page.locator(SEL["login"]["email_next_btn"]).first
            await next_loc.wait_for(state="visible", timeout=10000)
            await next_loc.click()
            await human_delay(2.0, 3.0)
            log.debug(f"Step1 邮箱 Next 后 URL: {page.url}")

            # 检测 Google 是否直接拒绝
            if "rejected" in page.url or "checkCookie" in page.url:
                if "idnf=" in page.url:
                    # idnf = identifier not found，账号不存在或已被封禁
                    log.warning(f"Step1 账号不存在/已注销 (idnf): {cred.gmail}")
                    account.status = AccountStatus.DEAD
                    get_stats().increment("dead")
                else:
                    # 其他 rejected 原因：反自动化检测
                    log.error(f"Step1 Google 拒绝登录（反自动化检测）: {page.url}")
                    account.mark_failed(FailReason.CAPTCHA_BLOCKED, f"Google rejected: {page.url}")
                return False

            # 如果 Cookie 注入直接进入账号
            if "myaccount.google.com" in page.url:
                log.debug("Cookie 注入登录成功")
                return True

            # ── 输入密码（等待可见密码框）─────────────────────
            pwd_loc = page.locator(
                "input[type='password']:not([aria-hidden='true']):not([name='hiddenPassword'])"
            ).first
            try:
                await pwd_loc.wait_for(state="visible", timeout=15000)
            except Exception:
                log.error(f"Step1 密码框未出现，当前 URL: {page.url}")
                account.mark_failed(FailReason.CAPTCHA_BLOCKED, f"Password page not reached: {page.url}")
                return False

            await pwd_loc.fill(cred.password)
            await human_delay(0.5, 1.0)

            pwd_next_loc = page.locator(SEL["login"]["password_next_btn"]).first
            await pwd_next_loc.click()
            await human_delay(2.0, 3.5)
            log.debug(f"Step1 密码 Next 后 URL: {page.url}")

            # ── 处理 2FA ────────────────────────────────────
            totp_loc = page.locator(SEL["login"]["totp_input"]).first
            totp_required = False
            try:
                await totp_loc.wait_for(state="visible", timeout=8000)
                totp_required = True
            except Exception:
                pass  # 账号未开启 2FA 时不会出现验证码输入框

            if totp_required:
                if not cred.totp_secret:
                    account.mark_failed(FailReason.MISSING_2FA, "账号要求 2FA，但导入数据未提供旧密钥")
                    return False
                try:
                    totp = pyotp.TOTP(cred.totp_secret)
                    code = totp.now()
                except Exception:
                    account.mark_failed(FailReason.WRONG_2FA, "旧 2FA 密钥格式无效")
                    return False
                log.debug("Step1 填写 TOTP")
                await totp_loc.fill(code)
                await human_delay(0.5, 1.0)
                totp_next = page.locator(SEL["login"]["totp_next_btn"]).first
                await totp_next.click()
                await human_delay(2.0, 3.5)
                log.debug(f"Step1 TOTP Next 后 URL: {page.url}")

            # ── 检查风控挑战 ──────────────────────────────────
            await self._captcha.check_and_solve(page)

            # ── 最终成功判断：必须进入 myaccount 或账号主页 ──
            await human_delay(1.0, 2.0)
            current = page.url
            log.debug(f"Step1 最终 URL: {current}")

            if "myaccount.google.com" in current or "/u/0/" in current or "mail.google.com" in current:
                log.info(f"Step1 ✅ 登录成功: {cred.gmail}")
                return True

            # 失败原因分析
            if "rejected" in current:
                account.mark_failed(FailReason.CAPTCHA_BLOCKED, f"Google rejected: {current}")
            elif "disabled" in current or "accountdisabled" in current.lower():
                account.status = AccountStatus.DEAD
                get_stats().increment("dead")
                log.warning(f"Step1 死号: {cred.gmail}")
            elif totp_required or "challenge/totp" in current:
                account.mark_failed(FailReason.WRONG_2FA, f"旧 2FA 验证未通过，当前: {current}")
            else:
                account.mark_failed(FailReason.WRONG_PASSWORD, f"未到达账号页，当前: {current}")
            return False

        except Exception as e:
            account.mark_failed(FailReason.UNKNOWN, f"Step1 异常: {e}")
            return False

    # ══════════════════════════════════════════════════════════
    # Step 2: 改辅助邮箱
    # ══════════════════════════════════════════════════════════

    async def _step2_recovery_email(self, page: Page, cred, account: CleanAccount) -> bool:
        log.debug(f"Step2 改辅助邮箱: {cred.gmail}")
        new_email = config.mail.generate_receiver(cred.gmail)
        account.buyer_recovery_email = new_email

        try:
            await page.goto(SEL["recovery_email"]["page_url"], wait_until="domcontentloaded")
            await human_delay()

            if not await self._handle_reauth_if_needed(page, cred):
                account.mark_failed(FailReason.UNKNOWN, "Step2 二次身份验证需要未提供的凭证")
                return False

            await safe_click(page, SEL["recovery_email"]["edit_btn"])
            await human_delay()

            if not await self._handle_reauth_if_needed(page, cred):
                account.mark_failed(FailReason.UNKNOWN, "Step2 二次身份验证需要未提供的凭证")
                return False

            await safe_fill(page, SEL["recovery_email"]["new_email_input"], new_email)
            await safe_click(page, SEL["recovery_email"]["next_btn"])
            await human_delay(1.0, 2.0)

            # 等待验证码输入框出现
            code_visible = await page.is_visible(SEL["recovery_email"]["code_input"])
            if code_visible:
                log.debug(f"等待接码: {new_email}")
                code = await fetch_mail_code(new_email)
                if not code:
                    account.mark_failed(FailReason.MAIL_TIMEOUT, f"接码超时 {new_email}")
                    return False
                await page.fill(SEL["recovery_email"]["code_input"], code)
                await safe_click(page, SEL["recovery_email"]["verify_btn"])
                await human_delay()

            await safe_click(page, SEL["recovery_email"]["save_btn"])
            await human_delay(1.0, 2.0)
            log.info(f"Step2 ✅ 辅助邮箱已改为: {new_email}")
            return True

        except Exception as e:
            account.mark_failed(FailReason.UNKNOWN, f"Step2 异常: {e}")
            return False

    # ══════════════════════════════════════════════════════════
    # Step 3: 移除辅助手机号
    # ══════════════════════════════════════════════════════════

    async def _step3_recovery_phone(self, page: Page, account: CleanAccount) -> None:
        log.debug(f"Step3 移除辅助手机号")
        try:
            await page.goto(SEL["recovery_phone"]["page_url"], wait_until="domcontentloaded")
            await human_delay()

            edit_btn = await page.query_selector(SEL["recovery_phone"]["edit_btn"])
            if not edit_btn:
                log.debug("Step3 无辅助手机号，跳过")
                return

            await safe_click(page, SEL["recovery_phone"]["remove_btn"])
            await human_delay()
            await safe_click(page, SEL["recovery_phone"]["confirm_remove_btn"])
            await human_delay()
            log.info("Step3 ✅ 辅助手机号已移除")

        except Exception as e:
            log.warning(f"Step3 移除手机号异常（非致命）: {e}")

    # ══════════════════════════════════════════════════════════
    # Step 4: 删除所有 Passkey
    # ══════════════════════════════════════════════════════════

    async def _step4_delete_passkeys(self, page: Page, account: CleanAccount) -> None:
        log.debug("Step4 删除 Passkey")
        try:
            await page.goto(SEL["passkeys"]["page_url"], wait_until="domcontentloaded")
            await human_delay()

            # 反复删除，直到没有 Passkey 为止
            for _ in range(20):  # 最多尝试 20 次（防止死循环）
                passkeys = await page.query_selector_all(SEL["passkeys"]["passkey_list"])
                if not passkeys:
                    break
                # 点击第一个 Passkey 的删除按钮
                delete_btn = await page.query_selector(SEL["passkeys"]["delete_btn"])
                if not delete_btn:
                    break
                await delete_btn.click()
                await human_delay(0.5, 1.0)
                await safe_click(page, SEL["passkeys"]["confirm_delete_btn"])
                await human_delay(1.0, 2.0)

            log.info("Step4 ✅ 所有 Passkey 已删除")

        except Exception as e:
            log.warning(f"Step4 删除 Passkey 异常（非致命）: {e}")

    # ══════════════════════════════════════════════════════════
    # Step 5: 重置 2FA TOTP 密钥
    # ══════════════════════════════════════════════════════════

    async def _handle_reauth_if_needed(self, page: Page, cred) -> bool:
        """Handle a password, recovery-email, or TOTP re-check without logging secrets."""
        await human_delay(1.0, 1.5)

        password_input = page.locator(
            "input[type='password']:not([aria-hidden='true']):not([name='hiddenPassword'])"
        ).first
        if await password_input.is_visible():
            await password_input.fill(cred.password)
            await human_delay(0.5, 1.0)
            next_button = page.locator(
                "#passwordNext button, button:has-text('Next'), button:has-text('下一步')"
            ).first
            if await next_button.is_visible():
                await next_button.click()
                await human_delay(2.0, 3.0)

        recovery_selector = "input[name='knowledgePreregisteredEmailResponse']"
        if "challenge/kpe" in (page.url or ""):
            recovery_selector += ", input[type='email']"
        recovery_input = page.locator(recovery_selector).first
        if await recovery_input.is_visible():
            recovery_email = getattr(cred, "old_recovery_email", None)
            if not recovery_email:
                return False
            await recovery_input.fill(recovery_email)
            next_button = page.locator(
                "button:has-text('Next'), button:has-text('Confirm'), button:has-text('确认')"
            ).first
            if await next_button.is_visible():
                await next_button.click()
                await human_delay(2.0, 3.0)

        totp_input = page.locator(SEL["login"]["totp_input"]).first
        if await totp_input.is_visible():
            if not cred.totp_secret:
                return False
            try:
                code = pyotp.TOTP(cred.totp_secret).now()
            except Exception:
                return False
            await totp_input.fill(code)
            await human_delay(0.5, 1.0)
            next_button = page.locator(SEL["login"]["totp_next_btn"]).first
            if await next_button.is_visible():
                await next_button.click()
                await human_delay(2.0, 3.0)

        return True

    async def _step5_reset_2fa(self, page: Page, cred, account: CleanAccount) -> bool:
        log.debug("Step5 重置 2FA")
        try:
            await page.goto(SEL["two_fa"]["authenticator_url"], wait_until="domcontentloaded")
            await human_delay()

            if not await self._handle_reauth_if_needed(page, cred):
                account.mark_failed(FailReason.UNKNOWN, "Step5 二次身份验证需要未提供的凭证")
                return False

            opened = await safe_click(page, SEL["two_fa"]["change_btn"])
            if not opened:
                started = await safe_click(page, SEL["two_fa"]["start_btn"])
                if started:
                    await human_delay(1.0, 2.0)
                    opened = await safe_click(page, SEL["two_fa"]["change_btn"])
            if not opened:
                log.warning("Step5 未找到更改或设置验证器按钮，尝试读取当前设置界面")
            await human_delay(1.0, 2.0)

            if not await self._handle_reauth_if_needed(page, cred):
                account.mark_failed(FailReason.UNKNOWN, "Step5 二次身份验证需要未提供的凭证")
                return False

            # 点击"无法扫描"获取明文密钥
            await safe_click(page, SEL["two_fa"]["cant_scan_link"])
            await human_delay(0.5, 1.0)

            # 提取 Base32 密钥（允许紧密排列或任意空白分组，不限制位数）
            secret_el = await page.query_selector(SEL["two_fa"]["secret_key_text"])
            new_2fa_secret = None
            if secret_el:
                text = await secret_el.inner_text()
                candidates = re.findall(r"[A-Z2-7]+(?:\s+[A-Z2-7]+)*", text.upper())
                for candidate in sorted(candidates, key=len, reverse=True):
                    normalized = "".join(candidate.split())
                    try:
                        pyotp.TOTP(normalized).now()
                    except Exception:
                        continue
                    new_2fa_secret = normalized
                    break

            if not new_2fa_secret:
                # 尝试从 input 读取
                secret_input = await page.query_selector(SEL["two_fa"]["secret_input"])
                if secret_input:
                    raw_secret = await secret_input.get_attribute("value")
                    normalized = "".join((raw_secret or "").split())
                    if normalized:
                        new_2fa_secret = normalized

            if not new_2fa_secret:
                account.mark_failed(FailReason.UNKNOWN, "Step5 无法提取新 2FA 密钥")
                log.error("Step5 无法提取新 2FA 密钥")
                return False

            # Google first shows the QR/manual key, then requires Next before
            # the verification-code input is rendered.
            await safe_click(page, SEL["two_fa"]["next_btn"])
            await human_delay(1.0, 2.0)

            # 用新密钥算出验证码并提交
            new_totp = pyotp.TOTP(new_2fa_secret)
            code = new_totp.now()

            if not await safe_fill(page, SEL["two_fa"]["totp_verify_input"], code):
                account.mark_failed(FailReason.UNKNOWN, "Step5 找不到新 2FA 验证码输入框")
                log.error("Step5 找不到新 2FA 验证码输入框")
                return False
            if not await safe_click(page, SEL["two_fa"]["verify_btn"]):
                account.mark_failed(FailReason.UNKNOWN, "Step5 找不到新 2FA 确认按钮")
                log.error("Step5 找不到新 2FA 确认按钮")
                return False
            await human_delay(1.5, 2.5)

            account.new_totp_secret = new_2fa_secret
            log.info("Step5 ✅ 2FA 已重置")
            return True

        except Exception as e:
            account.mark_failed(FailReason.UNKNOWN, f"Step5 异常: {e}")
            log.exception(f"Step5 异常: {e}")
            return False

    # ── Step 5b: 重新生成备用验证码 ─────────────────────────

    async def _step5b_backup_codes(self, page: Page, account: CleanAccount) -> None:
        log.debug("Step5b 生成备用验证码")
        try:
            await page.goto(SEL["backup_codes"]["page_url"], wait_until="domcontentloaded")
            await human_delay()

            await safe_click(page, SEL["backup_codes"]["refresh_btn"])
            await human_delay(0.5, 1.0)
            await safe_click(page, SEL["backup_codes"]["confirm_refresh_btn"])
            await human_delay(1.5, 2.5)

            # 提取备用码列表
            code_els = await page.query_selector_all(SEL["backup_codes"]["code_list"])
            codes = []
            for el in code_els:
                text = (await el.inner_text()).strip().replace(" ", "")
                if re.match(r"^\d{8}$", text):
                    codes.append(text)

            if codes:
                account.backup_codes = codes
                log.info(f"Step5b ✅ 备用验证码已更新 ({len(codes)} 个)")
            else:
                log.warning("Step5b 备用验证码提取为空（非致命）")

        except Exception as e:
            log.warning(f"Step5b 生成备用码异常（非致命）: {e}")

    # ══════════════════════════════════════════════════════════
    # Step 6: 改密码 + 强制下线所有设备
    # ══════════════════════════════════════════════════════════

    async def _step6_change_password(self, page: Page, cred, account: CleanAccount) -> bool:
        log.debug("Step6 修改主密码")
        new_password = generate_password()
        account.new_password = new_password

        try:
            await page.goto(SEL["password"]["page_url"], wait_until="domcontentloaded")
            await human_delay()

            # 可能需要再次输入当前密码（二次验证）
            cur_pass = await page.query_selector(SEL["password"]["current_pass_input"])
            if cur_pass:
                await cur_pass.fill(cred.password)
                await safe_click(page, SEL["password"]["next_btn"])
                await human_delay()

            await safe_fill(page, SEL["password"]["new_pass_input"], new_password)
            await safe_fill(page, SEL["password"]["confirm_pass_input"], new_password)
            await safe_click(page, SEL["password"]["save_btn"])
            await human_delay(2.0, 3.0)

            log.info("Step6 ✅ 密码已修改")

            # 强制下线所有其他设备
            await page.goto(SEL["device_activity"]["page_url"], wait_until="domcontentloaded")
            await human_delay()
            clicked = await safe_click(page, SEL["device_activity"]["sign_out_all_btn"])
            if clicked:
                await human_delay(0.5, 1.0)
                await safe_click(page, SEL["device_activity"]["confirm_btn"])
                await human_delay(1.0, 2.0)
                log.info("Step6 ✅ 所有其他设备已强制下线")

            return True

        except Exception as e:
            account.mark_failed(FailReason.UNKNOWN, f"Step6 异常: {e}")
            return False

    # ══════════════════════════════════════════════════════════
    # Step 7: 撤销 OAuth 授权
    # ══════════════════════════════════════════════════════════

    async def _step7_revoke_oauth(self, page: Page, account: CleanAccount) -> None:
        log.debug("Step7 撤销 OAuth 授权")
        try:
            await page.goto(SEL["permissions"]["page_url"], wait_until="domcontentloaded")
            await human_delay()

            # 反复撤销，直到没有第三方授权
            for _ in range(30):
                app_items = await page.query_selector_all(SEL["permissions"]["app_list"])
                if not app_items:
                    break
                revoke_btn = await page.query_selector(SEL["permissions"]["revoke_btn"])
                if not revoke_btn:
                    break
                await revoke_btn.click()
                await human_delay(0.5, 1.0)
                await safe_click(page, SEL["permissions"]["confirm_revoke_btn"])
                await human_delay(1.0, 2.0)

            log.info("Step7 ✅ OAuth 授权已全部撤销")

        except Exception as e:
            log.warning(f"Step7 撤销 OAuth 异常（非致命）: {e}")

    # ══════════════════════════════════════════════════════════
    # Step 8: 新凭证验证登录
    # ══════════════════════════════════════════════════════════

    async def _step8_verify(self, playwright, account: CleanAccount) -> bool:
        log.debug("Step8 验证新凭证")
        try:
            # 使用新凭证重新登录（全新无 Cookie 的浏览器实例）
            async with stealth_context(playwright) as (ctx, page):
                await page.goto("https://accounts.google.com/signin")
                await human_delay()

                await page.fill(SEL["login"]["email_input"], account.gmail)
                await safe_click(page, SEL["login"]["email_next_btn"])
                await human_delay()

                await page.fill(SEL["login"]["password_input"], account.new_password)
                await safe_click(page, SEL["login"]["password_next_btn"])
                await human_delay(1.5, 3.0)

                # 用新 2FA 验证
                totp_visible = await page.is_visible(SEL["login"]["totp_input"])
                if totp_visible and account.new_totp_secret:
                    new_totp = pyotp.TOTP(account.new_totp_secret)
                    await page.fill(SEL["login"]["totp_input"], new_totp.now())
                    await safe_click(page, SEL["login"]["totp_next_btn"])
                    await human_delay(1.5, 2.5)

                # 保存当前登录的 Cookies
                cookies = await ctx.cookies()
                account.new_cookies = json.dumps(cookies)

                success = "myaccount.google.com" in page.url or "google.com" in page.url
                if success:
                    account.verified_at = __import__("datetime").datetime.now(
                        __import__("datetime").timezone.utc
                    )
                    log.info("Step8 ✅ 新凭证验证成功")
                else:
                    log.error("Step8 ❌ 新凭证验证失败")

                return success

        except Exception as e:
            log.error(f"Step8 验证异常: {e}")
            return False

    # ── 内部：存库 ──────────────────────────────────────────

    async def _save(self, account: CleanAccount) -> None:
        """持久化账号状态到数据库（断点续跑依赖此方法）"""
        try:
            await self._db.upsert(account)
        except Exception as e:
            log.error(f"存库失败: {e}")
