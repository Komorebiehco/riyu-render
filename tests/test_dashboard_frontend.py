from pathlib import Path


APP_JS = Path(__file__).parents[1] / "visual-dashboard" / "app.js"


def test_dashboard_online_indicator_uses_dedicated_health_probe():
    source = APP_JS.read_text(encoding="utf-8")

    assert "async function loadHealth()" in source
    assert "loadHealth()," in source
    assert "const healthResult = results[0];" in source
    assert "const online = healthResult.status === 'fulfilled';" in source
    assert "const online = results.every" not in source
