"""Browser discovery and failure classification tests."""

from pathlib import Path

from src.config import BrowserConfig, resolve_chromium_path
from src.sanitizer.drission_engine import (
    _cleanup_isolated_profile,
    _create_isolated_profile,
    _make_options,
    _normalize_displayed_totp_secret,
)
from src.sanitizer.stealth_browser import BACKEND_HEADLESS, _build_launch_args
from src.storage.models import FailReason


def _touch(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"browser")
    return path


def test_runtime_browser_marker_is_used_without_environment_variable(tmp_path):
    browser = _touch(tmp_path / "installed" / "msedge.exe")
    marker = tmp_path / ".runtime" / "browser.path"
    marker.parent.mkdir(parents=True)
    marker.write_text(str(browser), encoding="utf-8")

    resolved = resolve_chromium_path(project_root=tmp_path, environ={"PATH": ""})

    assert resolved == str(browser)


def test_stale_marker_falls_back_to_system_browser(tmp_path):
    marker = tmp_path / ".runtime" / "browser.path"
    marker.parent.mkdir(parents=True)
    marker.write_text(str(tmp_path / "missing.exe"), encoding="utf-8")
    program_files = tmp_path / "Program Files"
    browser = _touch(program_files / "Microsoft" / "Edge" / "Application" / "msedge.exe")

    resolved = resolve_chromium_path(
        project_root=tmp_path,
        environ={"ProgramFiles": str(program_files), "PATH": ""},
    )

    assert resolved == str(browser)


def test_valid_explicit_browser_path_has_priority(tmp_path):
    explicit = _touch(tmp_path / "custom" / "chrome.exe")
    marker_browser = _touch(tmp_path / "installed" / "msedge.exe")
    marker = tmp_path / ".runtime" / "browser.path"
    marker.parent.mkdir(parents=True)
    marker.write_text(str(marker_browser), encoding="utf-8")

    resolved = resolve_chromium_path(
        explicit_path=str(explicit),
        project_root=tmp_path,
        environ={"PATH": ""},
    )

    assert resolved == str(explicit)


def test_browser_error_has_a_specific_failure_reason():
    assert FailReason.BROWSER_ERROR.value == "BROWSER_ERROR"


def test_browser_availability_checks_the_current_configured_path(tmp_path):
    config = BrowserConfig()
    config.CHROMIUM_PATH = str(tmp_path / "missing.exe")
    assert not config.executable_available()

    browser = _touch(tmp_path / "msedge.exe")
    config.CHROMIUM_PATH = str(browser)
    assert config.executable_available()


def test_browser_launch_uses_incognito_mode():
    args = _build_launch_args({"width": 1280, "height": 720})

    assert "--incognito" in args
    assert "--window-size=1280,720" in args
    assert BACKEND_HEADLESS is True


def test_drission_profiles_are_unique_and_disposable(tmp_path):
    first = Path(_create_isolated_profile(tmp_path))
    second = Path(_create_isolated_profile(tmp_path))

    try:
        assert first != second
        assert first.parent == tmp_path
        assert second.parent == tmp_path
        assert (first / ".riyu-isolated-browser-profile").is_file()
        assert (second / ".riyu-isolated-browser-profile").is_file()
    finally:
        assert _cleanup_isolated_profile(str(first))
        assert _cleanup_isolated_profile(str(second))

    assert not first.exists()
    assert not second.exists()


def test_drission_options_reject_unmarked_profile(tmp_path):
    unmarked = tmp_path / "personal-browser-profile"
    unmarked.mkdir()

    try:
        _make_options(str(unmarked))
    except ValueError as exc:
        assert "独立临时资料目录" in str(exc)
    else:
        raise AssertionError("An unmarked browser profile must never be accepted")


def test_drission_options_force_incognito_isolated_profile(tmp_path):
    profile = Path(_create_isolated_profile(tmp_path))
    try:
        options = _make_options(str(profile))

        assert Path(options.user_data_path) == profile
        assert "--incognito" in options.arguments
        assert "--disable-sync" in options.arguments
        assert f"--user-data-dir={profile}" in options.arguments
        assert options.is_headless is True
    finally:
        assert _cleanup_isolated_profile(str(profile))


def test_cleanup_refuses_personal_profile(tmp_path):
    personal = tmp_path / "Default"
    personal.mkdir()
    keep = personal / "Cookies"
    keep.write_text("keep", encoding="utf-8")

    assert not _cleanup_isolated_profile(str(personal))
    assert keep.read_text(encoding="utf-8") == "keep"


def test_cleanup_refuses_forged_marked_task_profile(tmp_path):
    forged = tmp_path / "task-forged-profile"
    forged.mkdir()
    marker = forged / ".riyu-isolated-browser-profile"
    marker.write_text(
        '{"version":1,"path":"forged","token":"forged"}',
        encoding="utf-8",
    )
    keep = forged / "Cookies"
    keep.write_text("keep", encoding="utf-8")

    assert not _cleanup_isolated_profile(str(forged))
    assert keep.read_text(encoding="utf-8") == "keep"

    try:
        _make_options(str(forged))
    except ValueError as exc:
        assert "独立临时资料目录" in str(exc)
    else:
        raise AssertionError("A forged profile marker must never be accepted")


def test_displayed_totp_secret_accepts_compact_or_even_groups():
    assert _normalize_displayed_totp_secret("avcdefg") == "AVCDEFG"
    assert _normalize_displayed_totp_secret("abcd abcd abcd") == "ABCDABCDABCD"


def test_displayed_totp_secret_rejects_dialog_prose():
    assert _normalize_displayed_totp_secret("YOUR KEY ABCD EFGH") is None
