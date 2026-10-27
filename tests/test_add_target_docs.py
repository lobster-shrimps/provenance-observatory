"""The nightly cron stays put. A new target is a targets.yaml entry."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_readme_tells_how_to_add_a_target_without_a_new_cron():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "adding-targets.md").read_text(encoding="utf-8")
    workflow = (ROOT / ".github" / "workflows" / "observatory.yml").read_text(encoding="utf-8")
    assert "17 3 * * *" in readme
    assert "17 3 * * *" in guide
    assert 'cron: "17 3 * * *"' in workflow
    assert "targets.yaml" in readme
    assert "authorized: false" in readme
    assert "auth_env" in readme
    assert "cookie_env" in readme
    assert "api_style: template" in readme
    assert "docs/adding-targets.md" in readme
    assert "private-watch.json" in readme
    assert workflow.count('cron: "17 3 * * *"') == 1
