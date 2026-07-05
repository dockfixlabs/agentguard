"""AgentGuard pre-commit hook integration.

Install: agentguard install --pre-commit
This makes AgentGuard a mandatory gate for AI agent code commits.
"""
from __future__ import annotations
import subprocess
import sys
import os
from pathlib import Path


PRE_COMMIT_CONFIG = """repos:
  - repo: local
    hooks:
      - id: agentguard
        name: AgentGuard Security Scan
        description: Scan AI agent code for OWASP ASI Top 10 vulnerabilities
        entry: agentguard
        language: system
        types: [python, javascript, typescript]
        args: ['.']
        pass_filenames: false
        stages: [pre-commit]
"""


def install_precommit_hook(project_dir: str | None = None) -> bool:
    """Install AgentGuard as a pre-commit hook in the target project.

    Returns True if installation succeeded.
    """
    target = Path(project_dir) if project_dir else Path.cwd()
    config_path = target / ".pre-commit-config.yaml"

    # Check if pre-commit is installed
    try:
        subprocess.run(["pre-commit", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("pre-commit is not installed. Install it first:")
        print("  pip install pre-commit")
        return False

    # Check if .pre-commit-config.yaml exists
    if config_path.exists():
        existing = config_path.read_text()
        if "agentguard" in existing:
            print("AgentGuard hook already configured.")
            return True

        # Append to existing config
        print(f"Adding AgentGuard hook to existing {config_path}")
        # Insert after first 'repos:' line or append
        content = existing.rstrip() + "\n\n" + PRE_COMMIT_CONFIG
        config_path.write_text(content)
    else:
        print(f"Creating {config_path} with AgentGuard hook")
        config_path.write_text(PRE_COMMIT_CONFIG)

    # Install the hook
    try:
        subprocess.run(["pre-commit", "install"], cwd=target, check=True)
        print("AgentGuard pre-commit hook installed successfully.")
        print()
        print("Every commit will now be scanned for AI agent security vulnerabilities.")
        print("To bypass (emergency only): git commit --no-verify")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to install hook: {e}")
        return False


def uninstall_precommit_hook(project_dir: str | None = None) -> bool:
    """Remove AgentGuard from pre-commit configuration."""
    target = Path(project_dir) if project_dir else Path.cwd()
    config_path = target / ".pre-commit-config.yaml"

    if not config_path.exists():
        print("No .pre-commit-config.yaml found.")
        return True

    content = config_path.read_text()
    if "agentguard" not in content:
        print("AgentGuard not found in pre-commit config.")
        return True

    # Remove the AgentGuard hook block
    lines = content.splitlines()
    new_lines = []
    skip_block = False
    for line in lines:
        if "id: agentguard" in line:
            skip_block = True
            continue
        if skip_block and line.strip().startswith("- repo:"):
            skip_block = False
        if skip_block:
            continue
        new_lines.append(line)

    config_path.write_text("\n".join(new_lines) + "\n")
    print("AgentGuard removed from pre-commit configuration.")
    return True
