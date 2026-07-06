"""Tests for ASI-MOUNT-EXPOSURE rule (v0.7.0)."""

import pytest
from pathlib import Path
from agentguard.scanner import scan_file, scan_directory
from agentguard.rules.mount_exposure import MountExposureRule


@pytest.fixture
def rule():
    return MountExposureRule()


# --- DockerCommandLineCodeExecutor tests ---

def test_docker_executor_without_read_only(tmp_path, rule):
    """Should detect DockerCommandLineCodeExecutor without read_only=True."""
    f = tmp_path / "agent.py"
    f.write_text('''
from autogen.coding import DockerCommandLineCodeExecutor
executor = DockerCommandLineCodeExecutor(
    image="python:3.11",
    work_dir="/workspace",
    timeout=60,
)
''')
    findings = rule.scan_content(f.read_text(), str(f))
    assert len(findings) > 0, "Should detect missing read_only"
    assert findings[0].severity.value == "CRITICAL"
    assert any("read_only" in f.description.lower() for f in findings)


def test_docker_executor_with_read_only_not_flagged(tmp_path, rule):
    """Should NOT flag DockerCommandLineCodeExecutor with read_only=True."""
    f = tmp_path / "agent.py"
    f.write_text('''
from autogen.coding import DockerCommandLineCodeExecutor
executor = DockerCommandLineCodeExecutor(
    image="python:3.11",
    work_dir="/workspace",
    timeout=60,
    read_only=True,
)
''')
    findings = rule.scan_content(f.read_text(), str(f))
    assert len(findings) == 0, "Should not flag executors with read_only=True"


# --- Volume flag tests ---

def test_v_flag_with_sensitive_path(tmp_path, rule):
    """Should detect -v with /etc path."""
    f = tmp_path / "agent.py"
    f.write_text('''
import subprocess
subprocess.run("docker run -v /etc:/host_etc python:3.11", shell=True)
''')
    findings = rule.scan_content(f.read_text(), str(f))
    assert len(findings) > 0, "Should detect -v with /etc"
    assert any("CRITICAL" in str(f.severity) for f in findings)


def test_v_flag_with_root_path(tmp_path, rule):
    """Should detect -v with /root."""
    f = tmp_path / "agent.py"
    f.write_text('''
subprocess.run("docker run --rm -v /root:/host_root alpine", shell=True)
''')
    findings = rule.scan_content(f.read_text(), str(f))
    assert len(findings) > 0, "Should detect -v with /root"


def test_v_flag_with_docker_sock(tmp_path, rule):
    """Should detect -v with /var/run/docker.sock."""
    f = tmp_path / "agent.py"
    f.write_text('''
subprocess.run("docker run -v /var/run/docker.sock:/var/run/docker.sock alpine", shell=True)
''')
    findings = rule.scan_content(f.read_text(), str(f))
    assert len(findings) > 0, "Should detect -v with /var/run/docker.sock"


def test_v_flag_with_home_path(tmp_path, rule):
    """Should detect -v with /home."""
    f = tmp_path / "agent.py"
    f.write_text('''
import os
os.system("docker run -v /home/user:/home alpine")
''')
    findings = rule.scan_content(f.read_text(), str(f))
    assert len(findings) > 0, "Should detect -v with /home"


def test_v_flag_non_sensitive_not_critical(tmp_path, rule):
    """Should flag -v with non-sensitive paths as HIGH, not CRITICAL."""
    f = tmp_path / "agent.py"
    f.write_text('''
subprocess.run("docker run -v ./data:/data python:3.11", shell=True)
''')
    findings = rule.scan_content(f.read_text(), str(f))
    if len(findings) > 0:
        # Non-sensitive -v should be HIGH, not CRITICAL
        assert all(f.severity.value == "HIGH" for f in findings)


# --- Mount SDK tests ---

def test_mount_bind_with_sensitive_source(tmp_path, rule):
    """Should detect Mount(type='bind') with /etc source."""
    f = tmp_path / "agent.py"
    f.write_text('''
import docker
mount = docker.types.Mount(
    type="bind",
    source="/etc",
    target="/host_etc",
)
''')
    findings = rule.scan_content(f.read_text(), str(f))
    assert len(findings) > 0, "Should detect bind mount with /etc"


def test_bind_source_in_dict(tmp_path, rule):
    """Should detect bind source in dict-style configs."""
    f = tmp_path / "agent.py"
    f.write_text('''
config = {
    "type": "bind",
    "source": "/root",
    "target": "/host_root",
}
''')
    findings = rule.scan_content(f.read_text(), str(f))
    # The bind_source pattern matches "source": "/"  and type: bind nearby
    assert len(findings) > 0, "Should detect bind source with /root in dict"


# --- Benchmark sample tests ---

def test_benchmark_mount_01():
    """Benchmark 01: DockerCommandLineCodeExecutor vulnerabilities."""
    sample = Path(__file__).parent / "samples" / "benchmark_mount_01.py"
    if not sample.exists():
        pytest.skip("Benchmark sample not found")
    findings = scan_file(sample)
    mount_findings = [f for f in findings if "MOUNT-EXPOSURE" in f.rule_id]
    assert len(mount_findings) >= 2, f"Should find >=2 mount exposures, got {len(mount_findings)}"


def test_benchmark_mount_02():
    """Benchmark 02: Docker SDK bind mounts."""
    sample = Path(__file__).parent / "samples" / "benchmark_mount_02.py"
    if not sample.exists():
        pytest.skip("Benchmark sample not found")
    findings = scan_file(sample)
    mount_findings = [f for f in findings if "MOUNT-EXPOSURE" in f.rule_id]
    assert len(mount_findings) >= 3, f"Should find >=3 mount exposures, got {len(mount_findings)}"


# --- YAML scanning tests ---

def test_yaml_docker_compose_volumes(tmp_path, rule):
    """Should detect sensitive volumes in docker-compose.yml."""
    f = tmp_path / "docker-compose.yml"
    f.write_text('''
version: "3"
services:
  agent:
    image: python:3.11
    volumes:
      - /etc:/host_etc
      - /var/run/docker.sock:/var/run/docker.sock
      - ./data:/data
''')
    findings = rule.scan_content(f.read_text(), str(f))
    assert len(findings) >= 2, f"Should find >=2 mount exposures in YAML, got {len(findings)}"


def test_yaml_mounts_bind_source(tmp_path, rule):
    """Should detect bind mounts with source in YAML."""
    f = tmp_path / "docker-compose.yml"
    f.write_text('''
services:
  executor:
    image: python:3.11
    mounts:
      - type: bind
        source: /root
        target: /host_root
''')
    findings = rule.scan_content(f.read_text(), str(f))
    assert len(findings) > 0, "Should detect bind mount source in YAML"


def test_yaml_safe_volumes_not_flagged(tmp_path, rule):
    """Should NOT flag relative/non-sensitive volumes in YAML."""
    f = tmp_path / "docker-compose.yml"
    f.write_text('''
services:
  app:
    image: python:3.11
    volumes:
      - ./data:/data
      - ./config:/config:ro
''')
    findings = rule.scan_content(f.read_text(), str(f))
    assert len(findings) == 0, "Should not flag safe volume mounts"


# --- Dockerfile tests ---

def test_dockerfile_volume_sensitive(tmp_path, rule):
    """Should detect VOLUME with sensitive path in Dockerfile."""
    f = tmp_path / "Dockerfile"
    f.write_text('''
FROM python:3.11
VOLUME /etc
CMD ["python"]
''')
    findings = rule.scan_content(f.read_text(), str(f))
    # VOLUME /etc should trigger MEDIUM
    assert len(findings) > 0, "Should detect VOLUME /etc in Dockerfile"


# --- Safe patterns ---

def test_commented_code_not_flagged(tmp_path, rule):
    """Commented-out docker commands should not be flagged."""
    f = tmp_path / "agent.py"
    f.write_text('# subprocess.run("docker run -v /etc:/host_etc alpine")')
    findings = rule.scan_content(f.read_text(), str(f))
    assert len(findings) == 0, "Should not flag comments"


def test_non_code_file_not_scanned(tmp_path, rule):
    """Non-code files should return empty."""
    f = tmp_path / "README.md"
    f.write_text("docker run -v /etc:/host_etc")
    findings = rule.scan_content(f.read_text(), str(f))
    assert len(findings) == 0, "Should not scan .md files"
