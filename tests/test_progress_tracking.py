"""Live task-step progress tracking tests."""

from src.dashboard.server import parse_step_progress, progress_percent
from src.storage.models import AccountStatus, CleanAccount, FailReason


def test_begin_step_exposes_live_dashboard_state():
    account = CleanAccount(gmail="user@example.com")

    account.begin_step(5, "双重验证")

    assert account.status == AccountStatus.SANITIZING
    assert account.step_progress.current_step == 5
    assert account.step_progress.current_step_name == "双重验证"
    assert account.step_progress.updated_at is not None


def test_completed_steps_and_current_step_are_serialized_together():
    account = CleanAccount(gmail="user@example.com")
    account.begin_step(2, "邮箱确认")
    account.mark_step("step1_validated")
    payload = account.step_progress.model_dump_json()
    parsed = parse_step_progress(payload)

    assert parsed["current_step"] == 2
    assert parsed["current_step_name"] == "邮箱确认"
    assert progress_percent(payload) == 12


def test_failure_keeps_the_step_that_failed():
    account = CleanAccount(gmail="user@example.com")
    account.begin_step(5, "双重验证")
    account.mark_failed(FailReason.UNKNOWN, "verification input missing")

    assert account.status == AccountStatus.FAILED
    assert account.step_progress.current_step == 5
    assert account.fail_detail == "verification input missing"
