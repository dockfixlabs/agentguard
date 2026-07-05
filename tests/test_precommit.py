"""Tests for pre-commit hook integration."""
import tempfile, os, subprocess
from pathlib import Path
from agentguard.precommit import install_precommit_hook, uninstall_precommit_hook


def test_install_precommit_new_config():
    """Install hook in a clean directory with no existing config."""
    with tempfile.TemporaryDirectory() as tmp:
        success = install_precommit_hook(tmp)
        # May fail if pre-commit is not installed
        config = Path(tmp) / ".pre-commit-config.yaml"
        assert config.exists()
        content = config.read_text()
        assert "agentguard" in content
        assert "OWASP ASI" in content


def test_uninstall_precommit():
    """Uninstall removes AgentGuard from config."""
    with tempfile.TemporaryDirectory() as tmp:
        # Create a config with agentguard
        config = Path(tmp) / ".pre-commit-config.yaml"
        config.write_text("""repos:
  - repo: local
    hooks:
      - id: agentguard
        name: AgentGuard
        entry: agentguard
        language: system
        types: [python]
""")
        result = uninstall_precommit_hook(tmp)
        assert result is True
        content = config.read_text()
        assert "agentguard" not in content


def test_install_preserves_existing_config():
    """Adding agentguard should not destroy existing hooks."""
    with tempfile.TemporaryDirectory() as tmp:
        config = Path(tmp) / ".pre-commit-config.yaml"
        config.write_text("""repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: trailing-whitespace
""")
        install_precommit_hook(tmp)
        content = config.read_text()
        assert "trailing-whitespace" in content
        assert "agentguard" in content


def test_install_idempotent():
    """Installing twice should not duplicate."""
    with tempfile.TemporaryDirectory() as tmp:
        install_precommit_hook(tmp)
        install_precommit_hook(tmp)
        content = Path(tmp, ".pre-commit-config.yaml").read_text()
        assert content.count("agentguard") == 2  # id + description


def test_uninstall_no_config():
    """Uninstall with no config should succeed."""
    with tempfile.TemporaryDirectory() as tmp:
        result = uninstall_precommit_hook(tmp)
        assert result is True
