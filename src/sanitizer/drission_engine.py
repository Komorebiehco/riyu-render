# ============================================================
# drission_engine.py -- DrissionPage-based 8-step sanitization engine
# Uses real Chrome browser to bypass Google anti-automation
# ============================================================

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import string
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pyotp
from DrissionPage import ChromiumPage, ChromiumOptions

from src.config import PROJECT_ROOT, config
from src.monitor.logger import get_logger, get_stats
from src.storage.db_manager import DBManager
from src.storage.models import AccountStatus, CleanAccount, FailReason, SanitizeTask

# Load selector config
_SEL_PATH = os.path.join(os.path.dirname(__file__), "selectors.json")
with open(_SEL_PATH, encoding="utf-8") as _f:
    SEL: dict = json.load(_f)

log = get_logger("DRISSION")

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


# ── Utility functions ─────────────────────────────────────────────────

def generate_password() -> str:
    """Generate a strong random password."""
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
    remaining = cfg.LENGTH - len(required)
    pool = list(required) + [secrets.choice(chars) for _ in range(remaining)]
    secrets.SystemRandom().shuffle(pool)
    return "".join(pool)


def _find_free_port() -> int:
    """Find a free local port."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


_ISOLATED_PROFILE_MARKER = ".riyu-isolated-browser-profile"
_ISOLATED_PROFILE_REGISTRY: dict[Path, str] = {}
_ISOLATED_PROFILE_REGISTRY_LOCK = threading.Lock()


def _is_registered_isolated_profile(path: Path) -> bool:
    """Accept only the exact disposable profile created by this process."""
    resolved = path.resolve()
    with _ISOLATED_PROFILE_REGISTRY_LOCK:
        expected_token = _ISOLATED_PROFILE_REGISTRY.get(resolved)
    if not expected_token or not resolved.name.startswith("task-"):
        return False

    marker = resolved / _ISOLATED_PROFILE_MARKER
    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
        marked_path = Path(payload.get("path", "")).resolve()
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError):
        return False
    return payload.get("token") == expected_token and marked_path == resolved


def _create_isolated_profile(base_dir: Optional[os.PathLike | str] = None) -> str:
    """Create a unique, disposable browser profile for one sanitization task."""
    root = Path(base_dir) if base_dir else PROJECT_ROOT / ".runtime" / "temp" / "browser_profiles"
    root.mkdir(parents=True, exist_ok=True)
    profile_dir = Path(tempfile.mkdtemp(prefix="task-", dir=root)).resolve()
    token = secrets.token_urlsafe(32)
    (profile_dir / _ISOLATED_PROFILE_MARKER).write_text(
        json.dumps({"version": 1, "path": str(profile_dir), "token": token}),
        encoding="utf-8",
    )
    with _ISOLATED_PROFILE_REGISTRY_LOCK:
        _ISOLATED_PROFILE_REGISTRY[profile_dir] = token
    return str(profile_dir)


def _cleanup_isolated_profile(profile_dir: str, attempts: int = 5) -> bool:
    """Remove only profiles created and marked by _create_isolated_profile()."""
    path = Path(profile_dir).resolve()
    if not _is_registered_isolated_profile(path):
        log.error(f"拒绝清理未验证的浏览器目录: {path}")
        return False

    for attempt in range(attempts):
        try:
            shutil.rmtree(path)
            with _ISOLATED_PROFILE_REGISTRY_LOCK:
                _ISOLATED_PROFILE_REGISTRY.pop(path, None)
            return True
        except FileNotFoundError:
            with _ISOLATED_PROFILE_REGISTRY_LOCK:
                _ISOLATED_PROFILE_REGISTRY.pop(path, None)
            return True
        except OSError as exc:
            if attempt == attempts - 1:
                log.warning(f"临时浏览器目录清理失败: {path}: {exc}")
                return False
            time.sleep(0.2 * (attempt + 1))
    return False


def _make_options(profile_dir: str, proxy_override: Optional[dict | str] = None) -> ChromiumOptions:
    """Build Chrome options using an explicitly isolated disposable profile."""
    profile_path = Path(profile_dir).resolve()
    if not _is_registered_isolated_profile(profile_path):
        raise ValueError("浏览器必须使用由任务创建的独立临时资料目录")

    # Do not inherit DrissionPage's global configs.ini: it may contain a
    # user-data-dir or other settings tied to the user's regular browser.
    opt = ChromiumOptions(read_file=False)
    if config.browser.CHROMIUM_PATH:
        opt.set_browser_path(config.browser.CHROMIUM_PATH)
    # Use a random free port to avoid conflicts
    port = _find_free_port()
    opt.set_local_port(port)
    # Remove automation flags
    opt.set_argument("--disable-blink-features=AutomationControlled")
    opt.set_argument("--no-sandbox")
    opt.set_argument("--disable-dev-shm-usage")
    opt.set_argument("--disable-infobars")
    opt.set_argument("--exclude-switches=enable-automation")
    opt.set_argument("--incognito")
    opt.set_argument("--disable-sync")
    opt.set_argument("--no-first-run")
    opt.set_argument("--no-default-browser-check")
    # Never reuse Chrome/Edge's default profile or another RIYU task profile.
    opt.set_user_data_path(str(profile_path))

    if config.browser.HEADLESS:
        opt.headless(True)

    # 配置代理服务器
    proxy = proxy_override
    if proxy is None:
        try:
            from src.sanitizer.stealth_browser import get_proxy_pool
            proxy = get_proxy_pool().next_proxy()
        except Exception:
            proxy = None

    if proxy:
        if isinstance(proxy, dict):
            from src.config import format_proxy_url
            proxy_str = format_proxy_url(proxy)
        else:
            proxy_str = str(proxy)
        opt.set_argument("--proxy-server", proxy_str)
        log.debug(f"Drission Chrome 代理设置为: {proxy_str}")

    return opt


def _normalize_displayed_totp_secret(value: Optional[str]) -> Optional[str]:
    """Normalize text read from a dedicated manual-key element."""
    groups = (value or "").split()
    if len(groups) > 1 and len({len(group) for group in groups}) != 1:
        return None
    normalized = "".join(groups).upper()
    if not normalized or not re.fullmatch(r"[A-Z2-7]+", normalized):
        return None
    try:
        pyotp.TOTP(normalized).now()
    except Exception:
        return None
    return normalized


# ══════════════════════════════════════════════════════════════
# DrissionEngine — 8-step sanitization engine (DrissionPage version)
# ══════════════════════════════════════════════════════════════

class DrissionEngine:
    """DrissionEngine: runs 8-step sanitization with a real Chrome browser via DrissionPage."""

    def __init__(self, db: DBManager):
        self._db = db

    def run_sync(self, task: SanitizeTask) -> CleanAccount:
        """Run full 8-step sanitization synchronously."""
        account = task.account
        cred = task.credential
        start = time.time()
        log.info(f"Starting sanitization: {cred.gmail}")
        account.status = AccountStatus.SANITIZING
        account.step_progress.updated_at = datetime.now(timezone.utc)
        self._save_sync(account)

        profile_dir = _create_isolated_profile()
        page: Optional[ChromiumPage] = None

        try:
            opt = _make_options(profile_dir)
            page = ChromiumPage(addr_or_opts=opt)

            # Step 1: Login
            if not account.step_progress.step1_validated:
                self._begin_step_sync(account, 1)
                ok = self._step1_login(page, cred, account)
                if not ok:
                    return account
                account.mark_step("step1_validated")
                self._save_sync(account)

            # Step 2: Change recovery email
            if not account.step_progress.step2_email_changed:
                self._begin_step_sync(account, 2)
                ok = self._step2_recovery_email(page, cred, account)
                if not ok:
                    return account
                account.mark_step("step2_email_changed")
                self._save_sync(account)

            # Step 3: Remove recovery phone
            if not account.step_progress.step3_phone_removed:
                self._begin_step_sync(account, 3)
                self._step3_recovery_phone(page, cred, account)
                account.mark_step("step3_phone_removed")
                self._save_sync(account)

            # Step 4: Delete Passkeys
            if not account.step_progress.step4_passkeys_deleted:
                self._begin_step_sync(account, 4)
                self._step4_delete_passkeys(page, cred, account)
                account.mark_step("step4_passkeys_deleted")
                self._save_sync(account)

            # Step 5: Reset / initialize 2FA
            if not account.step_progress.step5_2fa_reset:
                self._begin_step_sync(account, 5)
                ok = self._step5_reset_2fa(page, cred, account)
                if not ok:
                    return account
                account.mark_step("step5_2fa_reset")
                account.mark_step("step5_backup_codes")
                self._save_sync(account)

            # Step 6: Change password (Cookie/Sudo will be re-acquired)
            if not account.step_progress.step6_password_changed:
                self._begin_step_sync(account, 6)
                ok = self._step6_change_password(page, cred, account)
                if not ok:
                    return account
                account.mark_step("step6_password_changed")
                account.mark_step("step6_all_signed_out")
                self._save_sync(account)

            # Step 7: Revoke OAuth
            if not account.step_progress.step7_oauth_revoked:
                self._begin_step_sync(account, 7)
                self._step7_revoke_oauth(page, account)
                account.mark_step("step7_oauth_revoked")
                self._save_sync(account)

            # Step 8: Verify new credentials
            if not account.step_progress.step8_verified:
                self._begin_step_sync(account, 8)
                ok = self._step8_verify(page, cred, account)
                if not ok:
                    account.mark_failed(FailReason.UNKNOWN, "Step8 verify failed")
                    self._save_sync(account)
                    return account
                account.mark_step("step8_verified")

            account.mark_sanitized()
            elapsed = time.time() - start
            get_stats().increment("success")
            get_stats().total_elapsed_seconds += elapsed
            log.info(f"Sanitization complete: {cred.gmail} in {elapsed:.1f}s")

        except Exception as e:
            log.exception(f"Sanitization exception: {e}")
            account.mark_failed(FailReason.UNKNOWN, str(e))
        finally:
            if page is not None:
                try:
                    page.quit()
                except Exception:
                    pass
            _cleanup_isolated_profile(profile_dir)
            self._save_sync(account)

        return account

    def _begin_step_sync(self, account: CleanAccount, step: int) -> None:
        """Persist the active step before synchronous browser work starts."""
        account.begin_step(step, _STEP_NAMES[step])
        self._save_sync(account)

    # ══════════════════════════════════════════════════════════
    # Step 1: Login
    # ══════════════════════════════════════════════════════════

    def _step1_login(self, page: ChromiumPage, cred, account: CleanAccount) -> bool:
        log.debug(f"Step1 Login: {cred.gmail}")
        try:
            page.get("https://accounts.google.com/signin")
            page.wait.load_start()
            time.sleep(2)
            current = page.url
            log.debug(f"Step1 login page URL: {current}")

            # Already logged in via cookie
            if "myaccount.google.com" in current or "/u/0/" in current or "mail.google.com" in current:
                log.info(f"Step1 already logged in: {cred.gmail}")
                return True

            # Handle accountchooser redirect
            if "accountchooser" in current:
                log.debug(f"Step1 accountchooser URL: {current}")
                ac_item = page.ele(f"xpath://*[contains(text(), '{cred.gmail}')]", timeout=5)
                if ac_item:
                    try:
                        ac_item.click()
                    except Exception:
                        ac_item.click(by_js=True)
                    time.sleep(2.5)
                    current = page.url
                    log.debug(f"Step1 after accountchooser click URL: {current}")
                    if "myaccount.google.com" in current or "/u/0/" in current:
                        log.info(f"Step1 redirected to account page: {cred.gmail}")
                        return True
                else:
                    # Click "Use another account"
                    use_other = page.ele("xpath://*[contains(., 'Use another account') or contains(., 'Add account')]", timeout=5)
                    if use_other:
                        try:
                            use_other.click()
                        except Exception:
                            use_other.click(by_js=True)
                        time.sleep(2)

            # Enter email
            email_el = page.ele("#identifierId", timeout=10)
            if not email_el:
                # Check if we somehow reached account page
                if "myaccount.google.com" in page.url or "google.com" in page.url:
                    log.info(f"Step1 reached account page: {cred.gmail}")
                    return True
                account.mark_failed(FailReason.UNKNOWN, "Step1 email input not found")
                return False
            email_el.clear()
            email_el.input(cred.gmail)
            time.sleep(0.8)

            # Click Next
            next_el = page.ele("#identifierNext", timeout=10)
            if next_el:
                next_el.click()
            else:
                email_el.input("\n")
            time.sleep(3)
            log.debug(f"Step1 after email Next URL: {page.url}")

            # Check for rejected
            if "rejected" in page.url:
                if "idnf=" in page.url:
                    log.warning(f"Step1 account not found (idnf): {cred.gmail}")
                    account.status = AccountStatus.DEAD
                    get_stats().increment("dead")
                else:
                    log.error(f"Step1 Google rejected: {page.url}")
                    account.mark_failed(FailReason.CAPTCHA_BLOCKED, f"rejected: {page.url}")
                return False

            # Enter password
            pwd_el = page.ele(
                "xpath://input[@type='password' and not(@aria-hidden='true') and not(@name='hiddenPassword')]",
                timeout=15
            )
            if not pwd_el:
                log.error(f"Step1 password page not reached: {page.url}")
                account.mark_failed(FailReason.CAPTCHA_BLOCKED, f"Password page not reached: {page.url}")
                return False

            pwd_el.clear()
            pwd_el.input(cred.password)
            time.sleep(0.8)

            next_el2 = page.ele("#passwordNext", timeout=10)
            if next_el2:
                next_el2.click()
            else:
                pwd_el.input("\n")
            time.sleep(3)
            log.debug(f"Step1 after password Next URL: {page.url}")

            # Handle 2FA challenges
            # 1) 2FA selection page (challenge/selection)
            if "challenge/selection" in page.url:
                log.debug("Step1 handling 2FA selection...")
                time.sleep(1.5)

                # Try "Try another way"
                try_another = (
                    page.ele("xpath://div[@jsname='ZPoTod']") or
                    page.ele("xpath://*[contains(., 'Try another way')][@role='link']")
                )
                if try_another:
                    log.debug(f"Step1 clicking 'Try another way': {try_another.text!r}")
                    try:
                        try_another.click()
                    except Exception:
                        try_another.click(by_js=True)
                    time.sleep(2.5)

                # Find authenticator app option
                options = page.eles("xpath://div[@jsname='EBHGs']")
                auth_option = None
                for opt_el in options:
                    txt = opt_el.text
                    log.debug(f"  2FA option: {txt!r} | challengetype={opt_el.attr('data-challengetype')}")
                    if any(k in txt for k in ["Authenticator", "authenticator", "6-digit", "TOTP"]):
                        auth_option = opt_el
                        break

                if not auth_option and options:
                    for opt_el in options:
                        ctype = opt_el.attr("data-challengetype")
                        if ctype and ctype not in ["39", "53"]:  # exclude SMS/phone
                            auth_option = opt_el
                            break

                if auth_option:
                    log.debug(f"Step1 clicking 2FA option: {auth_option.text!r}")
                    try:
                        auth_option.click()
                    except Exception:
                        auth_option.click(by_js=True)
                    time.sleep(2.5)
                else:
                    log.warning("Step1 could not find preferred 2FA option")

            # 2) TOTP input
            totp_el = (
                page.ele("xpath://input[@type='tel']", timeout=8) or
                page.ele("xpath://input[@id='totpPin']", timeout=5) or
                page.ele("xpath://input[@name='totpPin']", timeout=5) or
                page.ele("xpath://input[@name='pin']", timeout=5)
            )
            if totp_el and not cred.totp_secret:
                account.mark_failed(FailReason.MISSING_2FA, "Account requires 2FA but no old secret was provided")
                return False
            if totp_el and cred.totp_secret:
                try:
                    totp = pyotp.TOTP(cred.totp_secret)
                    code = totp.now()
                except Exception:
                    account.mark_failed(FailReason.WRONG_2FA, "Old 2FA secret has an invalid format")
                    return False
                log.debug("Step1 submitting TOTP code")
                try:
                    totp_el.click()
                except Exception:
                    pass
                totp_el.clear()
                for ch in code:
                    totp_el.input(ch)
                    time.sleep(0.1)

                time.sleep(1.0)

                totp_next = (
                    page.ele("xpath://div[@id='totpNext']//button", timeout=5) or
                    page.ele("#totpNext button", timeout=5) or
                    page.ele("xpath://button[contains(., 'Next')]", timeout=5) or
                    page.ele("#totpNext", timeout=5)
                )

                if totp_next:
                    try:
                        totp_next.click()
                    except Exception:
                        totp_next.click(by_js=True)
                else:
                    totp_el.input("\n")

                time.sleep(3.5)
                if "challenge/totp" in page.url:
                    log.debug("Step1 TOTP still pending, retrying enter...")
                    totp_el.input("\n")
                    time.sleep(3.5)

                log.debug(f"Step1 after TOTP URL: {page.url}")

            time.sleep(2)
            current = page.url
            if "myaccount.google.com" in current or "/u/0/" in current or "mail.google.com" in current:
                log.info(f"Step1 login success: {cred.gmail}")
                return True

            if "rejected" in current:
                account.mark_failed(FailReason.CAPTCHA_BLOCKED, f"rejected: {current}")
            elif "disabled" in current or "accountdisabled" in current.lower():
                account.status = AccountStatus.DEAD
                get_stats().increment("dead")
            elif "challenge/totp" in current:
                account.mark_failed(FailReason.WRONG_2FA, f"Old 2FA verification failed: {current}")
            else:
                account.mark_failed(FailReason.WRONG_PASSWORD, f"Did not reach account page: {current}")
            return False

        except Exception as e:
            account.mark_failed(FailReason.UNKNOWN, f"Step1 exception: {e}")
            return False

    def handle_google_sudo_gate(self, page: ChromiumPage, password: str, totp_secret: str = None, gmail: str = None) -> bool:
        """
        While-Loop to clear Google Sudo gate (challenge/pwd and challenge/totp).
        Also handles accountchooser if session is expired.
        """
        totp_verified = False
        for cycle in range(6):
            time.sleep(2)
            current_url = page.url

            # Handle accountchooser (session expired or redirected to account selector)
            if "accountchooser" in current_url:
                log.debug(f"Sudo Gate: accountchooser detected, clicking account...")
                # Try to find and click the right account
                ac_item = None
                if gmail:
                    ac_item = page.ele(f"xpath://*[contains(text(), '{gmail}')]", timeout=3)
                if not ac_item:
                    # Click first available account
                    ac_item = (
                        page.ele("xpath://div[@data-email]", timeout=3) or
                        page.ele("xpath://li[@data-identifier]", timeout=3)
                    )
                if ac_item:
                    try:
                        ac_item.click()
                    except Exception:
                        ac_item.click(by_js=True)
                    time.sleep(2.5)
                    current_url = page.url
                else:
                    log.warning("Sudo Gate: no account found in accountchooser")
                    break

            is_pwd_challenge = (
                "/v3/signin/challenge/pwd" in current_url or
                "challenge/pwd" in current_url or
                page.ele("xpath://*[contains(text(), \"Verify it's you\") or contains(text(), 'Verify your identity')]", timeout=2)
            )

            is_totp_challenge = (
                "/v3/signin/challenge/totp" in current_url or
                "challenge/totp" in current_url or
                page.ele("xpath://*[@data-challengetype='6']", timeout=2) or
                (page.ele("xpath://input[@type='tel']", timeout=2) and "challenge" in current_url)
            )

            if not is_pwd_challenge and not is_totp_challenge:
                break

            log.debug(f"Sudo Gate cycle {cycle + 1}/6, URL: {current_url}")

            # 1. Password challenge
            if is_pwd_challenge:
                pwd_input = (
                    page.ele("xpath://input[@type='password' and not(@aria-hidden='true')]", timeout=5) or
                    page.ele("xpath://input[@name='password']", timeout=3)
                )
                if pwd_input:
                    pwd_input.click()
                    pwd_input.clear()
                    pwd_input.input(password)
                    time.sleep(0.3)
                    page.run_js(
                        "arguments[0].value = arguments[1]; arguments[0].dispatchEvent(new Event('input', { bubbles: true })); arguments[0].dispatchEvent(new Event('change', { bubbles: true }));",
                        pwd_input, password
                    )
                    time.sleep(0.5)

                    next_btn = (
                        page.ele("xpath://div[@id='passwordNext']//button", timeout=5) or
                        page.ele("#passwordNext button", timeout=5) or
                        page.ele("xpath://button[contains(., 'Next')]", timeout=5) or
                        page.ele("#passwordNext", timeout=5)
                    )
                    if next_btn:
                        try:
                            next_btn.click()
                        except Exception:
                            next_btn.click(by_js=True)
                    else:
                        pwd_input.input("\n")
                    time.sleep(3)

            # 2. TOTP 2FA challenge
            if is_totp_challenge and totp_secret:
                log.debug("Sudo Gate handling TOTP...")
                totp_code = pyotp.TOTP(totp_secret).now()
                totp_input = (
                    page.ele("xpath://input[@type='tel']", timeout=5) or
                    page.ele("xpath://input[@id='totpPin']", timeout=3)
                )
                if totp_input:
                    totp_input.click()
                    totp_input.clear()
                    for ch in totp_code:
                        totp_input.input(ch)
                        time.sleep(0.1)
                    time.sleep(0.8)
                    next_btn = (
                        page.ele("xpath://div[@id='totpNext']//button", timeout=5) or
                        page.ele("#totpNext button", timeout=5) or
                        page.ele("xpath://button[contains(., 'Next')]", timeout=5)
                    )
                    if next_btn:
                        try:
                            next_btn.click()
                        except Exception:
                            next_btn.click(by_js=True)
                    else:
                        totp_input.input("\n")
                    time.sleep(3)
                    totp_verified = "challenge/totp" not in page.url

        return totp_verified

    # ══════════════════════════════════════════════════════════
    # Step 2: Change recovery email
    # ══════════════════════════════════════════════════════════

    def _step2_recovery_email(self, page: ChromiumPage, cred, account: CleanAccount) -> bool:
        new_email = config.mail.generate_receiver(cred.gmail)
        account.buyer_recovery_email = new_email
        log.info(f"Step2 preparing to change recovery email -> {new_email}")
        try:
            page.get("https://myaccount.google.com/recovery/email")
            self.handle_google_sudo_gate(page, cred.password, cred.totp_secret, gmail=cred.gmail)
            time.sleep(2)

            trigger_el = (
                page.ele("xpath://button[contains(., 'Verify') or contains(., 'Edit')]", timeout=5) or
                page.ele("xpath://div[@jsname='AuOyIe']", timeout=5) or
                page.ele("xpath://*[contains(@aria-label, 'Verify') or contains(@aria-label, 'Edit')]", timeout=5) or
                page.ele("xpath://div[@role='button']", timeout=5)
            )
            if trigger_el:
                try:
                    trigger_el.click()
                except Exception:
                    trigger_el.click(by_js=True)
                time.sleep(2)
                self.handle_google_sudo_gate(page, cred.password, cred.totp_secret, gmail=cred.gmail)

            input_el = (
                page.ele("xpath://input[@type='email']", timeout=8) or
                page.ele("xpath://input[@name='email']", timeout=5) or
                page.ele("xpath://input", timeout=5)
            )
            if not input_el:
                account.mark_failed(FailReason.UNKNOWN, "Step2 email input not found")
                return False

            input_el.clear()
            input_el.input(new_email)
            time.sleep(0.8)

            next_btn = (
                page.ele("xpath://button[contains(., 'Next') or contains(., 'Save')]", timeout=8) or
                page.ele("xpath://div[@id='next']//button", timeout=5)
            )
            if next_btn:
                try:
                    next_btn.click()
                except Exception:
                    next_btn.click(by_js=True)
            else:
                input_el.input("\n")
            time.sleep(2.5)

            # Try to verify via email code
            code_el = page.ele("xpath://input[@type='tel' or @name='code']", timeout=6)
            if code_el:
                log.info(f"Step2 verification code required for {new_email}")
                code = self._fetch_code_sync(new_email)
                if code:
                    code_el.clear()
                    code_el.input(code)
                    time.sleep(0.8)
                    verify_btn = page.ele("xpath://button[contains(., 'Verify')]", timeout=8)
                    if verify_btn:
                        try:
                            verify_btn.click()
                        except Exception:
                            verify_btn.click(by_js=True)
                    time.sleep(2.5)
                else:
                    log.warning(f"Step2 no code received, skipping verification (needs real Cloudflare email service)")

            save_btn = page.ele("xpath://button[contains(., 'Save')]", timeout=5)
            if save_btn:
                try:
                    save_btn.click()
                except Exception:
                    save_btn.click(by_js=True)
                time.sleep(2)

            # Verify change was applied
            page.get("https://myaccount.google.com/recovery/email")
            self.handle_google_sudo_gate(page, cred.password, cred.totp_secret, gmail=cred.gmail)
            time.sleep(2)
            if new_email.lower() in page.html.lower():
                log.info(f"Step2 recovery email changed: {new_email}")
            else:
                log.warning(f"Step2 recovery email change pending verification (needs email code from Cloudflare)")

            return True

        except Exception as e:
            account.mark_failed(FailReason.UNKNOWN, f"Step2 exception: {e}")
            return False

    def _fetch_code_sync(self, to_email: str) -> Optional[str]:
        """Poll mail API for verification code, then prompt user if not found."""
        import urllib.request
        import urllib.parse
        callback = config.mail.MAIL_CALLBACK_URL.replace("/code", "")
        deadline = time.time() + config.mail.CODE_WAIT_TIMEOUT
        log.info(f"Polling for verification code for [{to_email}] (API wait up to {config.mail.CODE_WAIT_TIMEOUT}s)...")

        while time.time() < deadline:
            try:
                url = f"{callback}/poll?to={urllib.parse.quote(to_email)}"
                with urllib.request.urlopen(url, timeout=3) as resp:
                    data = json.loads(resp.read())
                    code = data.get("code", "")
                    if code and re.match(r"^\d{6}$", str(code)):
                        log.info("Got verification code from API")
                        return str(code)
            except Exception:
                pass
            time.sleep(config.mail.CODE_POLL_INTERVAL)

        log.warning(f"API timeout after {config.mail.CODE_WAIT_TIMEOUT}s for: {to_email}")
        # Backend tasks must never block on interactive console input.
        return None

    # ══════════════════════════════════════════════════════════
    # Step 3: Remove recovery phone
    # ══════════════════════════════════════════════════════════

    def _step3_recovery_phone(self, page: ChromiumPage, cred, account: CleanAccount) -> None:
        log.debug("Step3 removing recovery phone")
        try:
            page.get("https://myaccount.google.com/recovery/phone")
            self.handle_google_sudo_gate(page, cred.password, cred.totp_secret, gmail=cred.gmail)
            time.sleep(2)
            remove_btn = page.ele("xpath://button[contains(., 'Remove')]", timeout=8)
            if not remove_btn:
                log.debug("Step3 no recovery phone found, skipping")
                return
            remove_btn.click()
            time.sleep(1)
            confirm = page.ele("xpath://button[contains(., 'Remove')]", timeout=8)
            if confirm:
                confirm.click()
                time.sleep(1.5)
            log.info("Step3 recovery phone removed")
        except Exception as e:
            log.warning(f"Step3 exception: {e}")

    # ══════════════════════════════════════════════════════════
    # Step 4: Delete Passkeys
    # ══════════════════════════════════════════════════════════

    def _step4_delete_passkeys(self, page: ChromiumPage, cred, account: CleanAccount) -> None:
        log.debug("Step4 deleting Passkeys")
        try:
            page.get("https://myaccount.google.com/signinoptions/passkeys")
            self.handle_google_sudo_gate(page, cred.password, cred.totp_secret, gmail=cred.gmail)
            time.sleep(2)
            for _ in range(20):
                del_btn = page.ele(
                    "xpath://button[contains(@aria-label,'Delete') or contains(@aria-label,'Remove')]",
                    timeout=5
                )
                if not del_btn:
                    break
                del_btn.click()
                time.sleep(1)
                confirm = page.ele("xpath://button[contains(., 'Delete') or contains(., 'Remove')]", timeout=8)
                if confirm:
                    confirm.click()
                time.sleep(1.5)
            log.info("Step4 all Passkeys deleted")
        except Exception as e:
            log.warning(f"Step4 exception: {e}")

    # ══════════════════════════════════════════════════════════
    # Step 5: Reset / Initialize 2FA
    # ══════════════════════════════════════════════════════════

    def _step5_reset_2fa(self, page: ChromiumPage, cred, account: CleanAccount) -> bool:
        log.debug("Step5 resetting / initializing 2FA")
        try:
            page.get("https://myaccount.google.com/two-step-verification/authenticator")
            self.handle_google_sudo_gate(page, cred.password, cred.totp_secret, gmail=cred.gmail)
            time.sleep(2)

            start_btn = (
                page.ele("xpath://button[contains(., 'Get started') or contains(., 'Turn on 2-Step Verification')]", timeout=3) or
                page.ele("xpath://button[contains(., '开始使用') or contains(., '启用两步验证')]", timeout=2)
            )
            if start_btn:
                try:
                    start_btn.click()
                except Exception:
                    start_btn.click(by_js=True)
                time.sleep(2.5)

            change_btn = (
                page.ele("xpath://button[contains(., 'Change authenticator') or contains(., 'Set up authenticator') or contains(., 'Add authenticator')]", timeout=5) or
                page.ele("xpath://button[contains(., 'Authenticator')]", timeout=5) or
                page.ele("xpath://*[contains(text(), 'Authenticator')][@role='link' or @role='button' or self::a or self::div]", timeout=5)
            )
            if change_btn:
                log.debug("Step5 clicking Change/Set up authenticator button...")
                try:
                    change_btn.click()
                except Exception:
                    change_btn.click(by_js=True)
                time.sleep(2.5)

            cant_scan_btn = (
                page.ele("xpath://button[contains(., 'scan') or contains(., 'Scan')]", timeout=5) or
                page.ele("xpath://*[contains(., 'scan') or contains(., 'Scan')]", timeout=3)
            )
            if cant_scan_btn:
                log.debug("Step5 clicking Can't scan button...")
                try:
                    cant_scan_btn.click()
                except Exception:
                    cant_scan_btn.click(by_js=True)
                time.sleep(2.5)

            new_secret = None

            # Only inspect elements specifically associated with the manual
            # setup key. Scanning dialog prose is unsafe because ordinary
            # English words are also composed of Base32-compatible letters.
            key_locators = (
                "xpath://div[@role='dialog']//*[@jsname='B6Lgyf']",
                "xpath://div[@role='dialog']//code",
                "xpath://div[@role='dialog']//strong",
                "xpath://div[@role='dialog']//div[not(@class) and not(@jsname)]",
                "xpath://div[@role='dialog']//*[contains(., 'Your key')]/following::*[self::code or self::strong or self::span or self::div][1]",
                "xpath://div[@role='dialog']//*[contains(., '您的密钥') or contains(., '你的密钥')]/following::*[self::code or self::strong or self::span or self::div][1]",
            )
            for locator in key_locators:
                for key_el in page.eles(locator):
                    for raw_value in (key_el.attr("value"), key_el.text):
                        new_secret = _normalize_displayed_totp_secret(raw_value)
                        if new_secret:
                            break
                    if new_secret:
                        break
                if new_secret:
                    log.info("Step5 extracted the dedicated manual setup key")
                    break

            if not new_secret:
                account.mark_failed(FailReason.UNKNOWN, "Step5 could not extract the new 2FA secret")
                return False

            # Click Next to reach verification code input step
            next_btn = (
                page.ele("xpath://div[@role='dialog']//button[contains(., 'Next')]", timeout=5) or
                page.ele("xpath://button[contains(., 'Next')]", timeout=3)
            )
            if next_btn:
                try:
                    next_btn.click()
                except Exception:
                    next_btn.click(by_js=True)
                time.sleep(2.5)

            # Generate TOTP code using new secret
            new_totp = pyotp.TOTP(new_secret)
            code = new_totp.now()

            code_input = (
                page.ele("xpath://div[@role='dialog']//input[@type='tel' or @type='text' or @name='code']", timeout=5) or
                page.ele("xpath://input[@type='tel']", timeout=3)
            )
            if not code_input:
                account.mark_failed(FailReason.UNKNOWN, "Step5 could not find the new 2FA code input")
                return False
            code_input.click()
            code_input.clear()
            for ch in code:
                code_input.input(ch)
                time.sleep(0.1)
            time.sleep(1)

            verify_btn = (
                page.ele("xpath://div[@role='dialog']//button[contains(., 'Verify') or contains(., 'Done') or contains(., 'Save')]", timeout=5) or
                page.ele("xpath://button[contains(., 'Verify')]", timeout=3)
            )
            if not verify_btn:
                account.mark_failed(FailReason.UNKNOWN, "Step5 could not find the new 2FA confirm button")
                return False
            try:
                verify_btn.click()
            except Exception:
                verify_btn.click(by_js=True)
            time.sleep(3)

            verification_error = page.ele(
                "xpath://div[@role='dialog']//*[contains(., 'Wrong code') or contains(., 'Invalid code') or contains(., 'Try again') or contains(., '验证码错误') or contains(., '重试')]",
                timeout=2,
            )
            remaining_input = page.ele(
                "xpath://div[@role='dialog']//input[@type='tel' or @name='code']",
                timeout=2,
            )
            input_still_visible = False
            if remaining_input:
                try:
                    input_still_visible = bool(remaining_input.states.is_displayed)
                except Exception:
                    input_still_visible = True
            if verification_error or input_still_visible:
                account.mark_failed(
                    FailReason.WRONG_2FA,
                    "Step5 Google did not accept the new authenticator code",
                )
                log.error("Step5 Google did not accept the new authenticator code")
                return False

            account.new_totp_secret = new_secret
            log.info("Step5 2FA successfully reset")
            return True

        except Exception as e:
            account.mark_failed(FailReason.UNKNOWN, f"Step5 exception: {e}")
            log.warning(f"Step5 exception: {e}")
            return False

    # ══════════════════════════════════════════════════════════
    # Step 6: Change password + sign out all devices
    # ══════════════════════════════════════════════════════════

    def _step6_change_password(self, page: ChromiumPage, cred, account: CleanAccount) -> bool:
        new_password = generate_password()
        account.new_password = new_password
        log.info("Step6 preparing to change password")
        try:
            page.get("https://myaccount.google.com/signinoptions/password")
            self.handle_google_sudo_gate(page, cred.password, cred.totp_secret, gmail=cred.gmail)
            time.sleep(2.5)

            log.debug(f"Step6 after Sudo gate URL: {page.url}")

            # Precisely target new password fields by name attribute
            # Google password change page fields:
            #   newPassword / newPw / password (2-box layout)
            #   confirmNewPassword / confirmPw
            new_pwd_el = (
                page.ele("xpath://input[@type='password' and @name='password']", timeout=5) or
                page.ele("xpath://input[@type='password' and @name='newPassword']", timeout=3) or
                page.ele("xpath://input[@type='password' and @name='newPw']", timeout=3)
            )
            confirm_pwd_el = (
                page.ele("xpath://input[@type='password' and @name='confirmation_password']", timeout=5) or
                page.ele("xpath://input[@type='password' and @name='confirmNewPassword']", timeout=3) or
                page.ele("xpath://input[@type='password' and @name='confirmPw']", timeout=3)
            )

            if new_pwd_el:
                log.debug(f"Step6 found newPassword field (name={new_pwd_el.attr('name')!r})")
                new_pwd_el.click()
                new_pwd_el.clear()
                new_pwd_el.input(new_password)
                time.sleep(0.5)
            else:
                # Fallback: get all visible pwd inputs and fill last two
                all_visible = page.eles("xpath://input[@type='password' and not(@aria-hidden='true')]", timeout=5)
                log.debug(f"Step6 fallback: found {len(all_visible)} visible pwd inputs")
                if len(all_visible) >= 2:
                    new_pwd_el = all_visible[-2]
                    confirm_pwd_el = all_visible[-1]
                    new_pwd_el.click()
                    new_pwd_el.clear()
                    new_pwd_el.input(new_password)
                    time.sleep(0.5)
                elif len(all_visible) == 1:
                    new_pwd_el = all_visible[0]
                    new_pwd_el.click()
                    new_pwd_el.clear()
                    new_pwd_el.input(new_password)
                else:
                    log.error("Step6 cannot find any password input field on the page!")
                    account.mark_failed(FailReason.UNKNOWN, "Step6 no password inputs found")
                    return False

            if confirm_pwd_el:
                log.debug(f"Step6 found confirmNewPassword field (name={confirm_pwd_el.attr('name')!r})")
                confirm_pwd_el.click()
                confirm_pwd_el.clear()
                confirm_pwd_el.input(new_password)
                time.sleep(0.5)

            # Click Save/Change password
            save_btn = (
                page.ele("xpath://button[contains(., 'Change password') or contains(., 'Save')]", timeout=8) or
                page.ele("xpath://div[@id='passwordNext']//button", timeout=5)
            )
            if save_btn:
                log.debug(f"Step6 clicking save button: {save_btn.text!r}")
                try:
                    save_btn.click()
                except Exception:
                    save_btn.click(by_js=True)
            elif new_pwd_el:
                log.debug("Step6 no save button, pressing Enter")
                new_pwd_el.input("\n")
            time.sleep(4)

            # Check for rejection errors
            if page.ele("xpath://*[contains(text(), 'Choose a stronger password') or contains(text(), 'stronger')]", timeout=2):
                log.error("Step6 password rejected by Google - too weak")
                account.mark_failed(FailReason.UNKNOWN, "password rejected by Google")
                return False

            # Sync new password into credential object for subsequent steps
            cred.password = new_password
            log.info("Step6 password change submitted")

            # Sign out all other devices
            page.get("https://myaccount.google.com/device-activity")
            time.sleep(2)
            sign_out_all = page.ele(
                "xpath://button[contains(., 'Sign out all') or contains(., 'Sign out') or contains(., 'Logout')]",
                timeout=8
            )
            if sign_out_all:
                try:
                    sign_out_all.click()
                except Exception:
                    sign_out_all.click(by_js=True)
                time.sleep(1)
                confirm = page.ele("xpath://button[contains(., 'Sign out') or contains(., 'OK')]", timeout=8)
                if confirm:
                    try:
                        confirm.click()
                    except Exception:
                        confirm.click(by_js=True)
                time.sleep(2)
                log.info("Step6 signed out all other devices")

            return True

        except Exception as e:
            account.mark_failed(FailReason.UNKNOWN, f"Step6 error: {e}")
            log.error(f"Step6 exception: {e}")
            return False

    # ══════════════════════════════════════════════════════════
    # Step 7: Revoke OAuth tokens
    # ══════════════════════════════════════════════════════════

    def _step7_revoke_oauth(self, page: ChromiumPage, account: CleanAccount) -> None:
        log.debug("Step7 revoking OAuth tokens")
        try:
            page.get("https://myaccount.google.com/permissions")
            time.sleep(2)
            for _ in range(30):
                revoke = page.ele(
                    "xpath://button[contains(., 'Remove Access')]",
                    timeout=5
                )
                if not revoke:
                    break
                revoke.click()
                time.sleep(1)
                confirm = page.ele("xpath://button[contains(., 'OK') or contains(., 'Remove')]", timeout=8)
                if confirm:
                    confirm.click()
                time.sleep(1.5)
            log.info("Step7 all OAuth tokens revoked")
        except Exception as e:
            log.warning(f"Step7 exception: {e}")

    # ══════════════════════════════════════════════════════════
    # Step 8: Verify new credentials
    # ══════════════════════════════════════════════════════════

    def _step8_verify(self, page: ChromiumPage, cred, account: CleanAccount) -> bool:
        log.debug("Step8 verifying new credentials in a second isolated profile")
        verify_profile = _create_isolated_profile()
        verify_page: Optional[ChromiumPage] = None
        try:
            verify_page = ChromiumPage(addr_or_opts=_make_options(verify_profile))
            page = verify_page
            target_pwd = account.new_password or cred.password
            totp_secret_to_use = account.new_totp_secret or cred.totp_secret

            page.get("https://accounts.google.com/signin")
            time.sleep(2.5)

            # 1. Handle accountchooser
            if "accountchooser" in page.url:
                log.debug("Step8 handling accountchooser...")
                ac_item = page.ele(f"xpath://*[contains(text(), '{account.gmail}')]")
                if ac_item:
                    try:
                        ac_item.click()
                    except Exception:
                        ac_item.click(by_js=True)
                    time.sleep(2)
                else:
                    use_other = page.ele("xpath://*[contains(text(), 'Use another account')]")
                    if use_other:
                        try:
                            use_other.click()
                        except Exception:
                            use_other.click(by_js=True)
                        time.sleep(2)

            # Enter email if needed
            if "challenge/pwd" not in page.url:
                email_el = page.ele("#identifierId", timeout=3)
                if email_el:
                    email_el.clear()
                    email_el.input(account.gmail)
                    next_el = page.ele("#identifierNext", timeout=3)
                    if next_el:
                        next_el.click()
                    else:
                        email_el.input("\n")
                    time.sleep(2.5)

            # 2. Enter new password
            pwd_el = page.ele(
                "xpath://input[@type='password' and not(@aria-hidden='true') and not(@name='hiddenPassword')]",
                timeout=8
            )
            if pwd_el:
                log.debug("Step8 entering the new password")
                pwd_el.click()
                pwd_el.clear()
                pwd_el.input(target_pwd)
                time.sleep(0.5)

                next_btn2 = (
                    page.ele("xpath://div[@id='passwordNext']//button", timeout=5) or
                    page.ele("#passwordNext button", timeout=5) or
                    page.ele("#passwordNext", timeout=5)
                )
                if next_btn2:
                    try:
                        next_btn2.click()
                    except Exception:
                        next_btn2.click(by_js=True)
                else:
                    pwd_el.input("\n")
                time.sleep(3.5)

            # 3. Handle 2FA / Sudo challenges
            totp_verified = self.handle_google_sudo_gate(
                page,
                target_pwd,
                totp_secret_to_use,
                gmail=account.gmail,
            )

            if account.new_totp_secret and not totp_verified:
                log.error("Step8 fresh login did not verify the new 2FA secret")
                return False

            if "speedbump" in page.url or "security" in page.url:
                page.get("https://myaccount.google.com/")
                time.sleep(2.5)

            current = page.url
            if "myaccount.google.com" in current or "/u/0/" in current or "mail.google.com" in current:
                account.verified_at = datetime.now(timezone.utc)
                log.info("Step8 verify SUCCESS - new credentials confirmed")
                return True

            log.error(f"Step8 verify FAILED, stuck at URL: {current}")
            return False

        except Exception as e:
            log.error(f"Step8 exception: {e}")
            return False
        finally:
            if verify_page is not None:
                try:
                    verify_page.quit()
                except Exception:
                    pass
            _cleanup_isolated_profile(verify_profile)

    # ── Helper ────────────────────────────────────────────────

    def _save_sync(self, account: CleanAccount) -> None:
        import asyncio
        try:
            asyncio.run(self._db.upsert(account))
        except Exception as e:
            log.error(f"DB save error: {e}")
