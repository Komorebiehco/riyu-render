import pytest

from src.sanitizer import sanitizer_engine as module
from src.storage.models import CleanAccount, FailReason, RawCredential


async def _no_delay(*_args, **_kwargs):
    return None


class _Captcha:
    async def check_and_solve(self, _page):
        return True


class _Locator:
    def __init__(self, page, selector):
        self.page = page
        self.selector = selector

    @property
    def first(self):
        return self

    async def wait_for(self, **_kwargs):
        if self.selector == module.SEL["login"]["totp_input"] and not self.page.requires_totp:
            raise TimeoutError

    async def fill(self, _value):
        return None

    async def click(self):
        if self.selector == module.SEL["login"]["password_next_btn"]:
            self.page.url = (
                "https://accounts.google.com/v3/signin/challenge/totp"
                if self.page.requires_totp
                else "https://myaccount.google.com/"
            )


class _LoginPage:
    def __init__(self, requires_totp):
        self.requires_totp = requires_totp
        self.url = ""

    async def goto(self, url, **_kwargs):
        self.url = url

    def locator(self, selector):
        return _Locator(self, selector)


def _engine():
    engine = module.SanitizerEngine(db=None)
    engine._captcha = _Captcha()
    return engine


@pytest.mark.asyncio
async def test_login_without_existing_two_fa_skips_old_code(monkeypatch):
    monkeypatch.setattr(module, "human_delay", _no_delay)
    cred = RawCredential(gmail="user@example.com", password="password")
    account = CleanAccount(gmail=cred.gmail)

    result = await _engine()._step1_validate(_LoginPage(False), cred, account)

    assert result is True
    assert account.fail_reason is None


@pytest.mark.asyncio
async def test_login_requiring_two_fa_reports_missing_secret(monkeypatch):
    monkeypatch.setattr(module, "human_delay", _no_delay)
    cred = RawCredential(gmail="user@example.com", password="password")
    account = CleanAccount(gmail=cred.gmail)

    result = await _engine()._step1_validate(_LoginPage(True), cred, account)

    assert result is False
    assert account.fail_reason == FailReason.MISSING_2FA


def test_authenticator_selector_supports_first_time_setup():
    selector = module.SEL["two_fa"]["change_btn"]
    assert "Set up authenticator app" in selector
    assert "设置验证器应用" in selector
