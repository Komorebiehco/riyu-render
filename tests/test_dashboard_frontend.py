from pathlib import Path


APP_JS = Path(__file__).parents[1] / "visual-dashboard" / "app.js"


def test_dashboard_online_indicator_uses_dedicated_health_probe():
    source = APP_JS.read_text(encoding="utf-8")

    assert "async function loadHealth()" in source
    assert "loadHealth()," in source
    assert "const healthResult = results[0];" in source
    assert "const online = healthResult.status === 'fulfilled';" in source
    assert "const online = results.every" not in source


def test_dashboard_task_actions_and_multi_file_proxy_upload_contract():
    source = APP_JS.read_text(encoding="utf-8")
    html = (APP_JS.parent / "index.html").read_text(encoding="utf-8")

    assert "/api/tasks/bulk-delete" in source
    assert "/api/tasks/clear-failed" in source
    assert "form.append('file', file, file.name)" in source
    assert "multiple" in html
    assert "clearFailedTasks" in html
    assert "bulkDeleteTasks" in html


def test_dashboard_proxy_test_reports_automatic_pruning():
    source = APP_JS.read_text(encoding="utf-8")
    html = (APP_JS.parent / "index.html").read_text(encoding="utf-8")

    assert "res.removed" in source
    assert "自动移除" in source
    assert "res.pool_size" in source
    assert "auto_check_enabled" in source
    assert "auto_check_interval_seconds" in source
    assert "auto_check_sample_count" in source
    assert "renderProxyAutoCheckStatus" in source
    assert "proxyAutoCheckEnabled" in html
    assert "proxyAutoCheckStatus" in html
