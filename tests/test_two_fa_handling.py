import pytest

from src.sanitizer import sanitizer_engine as module
from src.sanitizer import drission_engine as drission_module
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


class _ReauthLocator:
    def __init__(self, page, selector):
        self.page = page
        self.selector = selector

    @property
    def first(self):
        return self

    async def is_visible(self):
        return "input[type='email']" in self.selector and self.page.generic_email_visible

    async def fill(self, value):
        self.page.filled.append((self.selector, value))

    async def click(self):
        self.page.clicked.append(self.selector)


class _ReauthPage:
    def __init__(self, url, *, generic_email_visible=True):
        self.url = url
        self.generic_email_visible = generic_email_visible
        self.selectors = []
        self.filled = []
        self.clicked = []

    def locator(self, selector):
        self.selectors.append(selector)
        return _ReauthLocator(self, selector)


@pytest.mark.asyncio
async def test_reauth_does_not_treat_regular_email_editor_as_challenge(monkeypatch):
    monkeypatch.setattr(module, "human_delay", _no_delay)
    page = _ReauthPage("https://myaccount.google.com/recovery/email")
    cred = RawCredential(
        gmail="user@example.com",
        password="password",
        old_recovery_email="old@example.net",
    )

    result = await _engine()._handle_reauth_if_needed(page, cred)

    assert result is True
    assert page.filled == []
    assert not any("input[type='email']" in selector for selector in page.selectors)


@pytest.mark.asyncio
async def test_reauth_allows_generic_email_input_on_recovery_challenge(monkeypatch):
    monkeypatch.setattr(module, "human_delay", _no_delay)
    page = _ReauthPage("https://accounts.google.com/challenge/kpe")
    cred = RawCredential(
        gmail="user@example.com",
        password="password",
        old_recovery_email="old@example.net",
    )

    result = await _engine()._handle_reauth_if_needed(page, cred)

    assert result is True
    assert page.filled == [
        (
            "input[name='knowledgePreregisteredEmailResponse'], input[type='email']",
            "old@example.net",
        )
    ]


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


class _DrissionElement:
    def __init__(self, page, *, kind="input"):
        self.page = page
        self.kind = kind
        self.value = ""
        self.text = ""

    def attr(self, name):
        return None if name == "data-challengetype" else ""

    def click(self, **_kwargs):
        if self.kind == "next":
            self.page.url = "https://myaccount.google.com/"

    def clear(self):
        self.value = ""

    def input(self, value):
        self.value += value


class _RecoveryChallengePage:
    def __init__(self):
        self.url = "https://accounts.google.com/challenge/kpe"
        self.recovery_input = _DrissionElement(self)
        self.next_button = _DrissionElement(self, kind="next")

    def ele(self, selector, timeout=None):
        if "knowledgePreregisteredEmailResponse" in selector and "challenge/kpe" in self.url:
            return self.recovery_input
        if ("Next" in selector or "Confirm" in selector) and "challenge/kpe" in self.url:
            return self.next_button
        return None

    def eles(self, _selector):
        return []


def test_drission_sudo_gate_accepts_old_recovery_email(monkeypatch):
    monkeypatch.setattr(drission_module.time, "sleep", lambda *_args, **_kwargs: None)
    page = _RecoveryChallengePage()

    result = drission_module.DrissionEngine(db=None).handle_google_sudo_gate(
        page,
        "password",
        gmail="user@example.com",
        recovery_email="old@example.net",
    )

    assert result is False
    assert page.recovery_input.value == "old@example.net"
    assert page.url == "https://myaccount.google.com/"
