"""ASI-MOUNT-EXPOSURE: Docker Host Filesystem Mount Exposure (CWE-732, CVSS 8.6)

Detects Docker container executors and runtimes that expose host filesystem paths
via volume/bind mounts — a critical vector in AI agent code executors.

Based on the AutoGen Docker code executor analysis (Issue #7917):
DockerCommandLineCodeExecutor without read_only=True allows container breakout
and host filesystem compromise through bind-mounted sensitive paths.

This is a NOVEL rule beyond OWASP ASI — existing SAST tools do not check for
AI agent-specific Docker mount patterns.
"""
from __future__ import annotations
import re
from agentguard.models import Finding, Rule, Severity


# Sensitive host paths that should never be bind-mounted into containers
SENSITIVE_HOST_PATHS = [
    "/etc", "/root", "/home", "/var/run/docker.sock",
    "/proc", "/sys", "/dev", "/boot", "/tmp",
    "/var/log", "/var/lib", "/opt",
]

# Sensitive path patterns (regex)
SENSITIVE_PATH_RE = re.compile(
    r"(?:/etc\b|/root\b|/home\b|/var/run/docker\.sock|"
    r"/proc\b|/sys\b|/boot\b|/dev\b|"
    r"\$HOME|~/|%HOME%|%USERPROFILE%)",
    re.IGNORECASE
)


class MountExposureRule(Rule):
    """Detects Docker host filesystem mount exposure in AI agent code.

    Scans Python, JavaScript/TypeScript, YAML, and Dockerfile content for
    patterns where containers are configured with unrestricted host filesystem
    access, exposing the host to code execution within the container.
    """
    rule_id = "ASI-MOUNT-EXPOSURE"
    rule_name = "Host Filesystem Mount Exposure"
    severity = Severity.HIGH
    cwe = "CWE-732"
    cvss = 8.6

    # --- Code patterns (Python/JS/TS) ---

    # DockerCommandLineCodeExecutor without read_only=True
    DOCKER_EXECUTOR_RE = re.compile(
        r"DockerCommandLineCodeExecutor\s*\(",
        re.IGNORECASE
    )
    READ_ONLY_RE = re.compile(
        r"read_only\s*=\s*True",
        re.IGNORECASE
    )

    # volumes=[...] patterns with host paths
    VOLUMES_LIST_RE = re.compile(
        r"volumes?\s*[:=]\s*\[",
        re.IGNORECASE
    )

    # mounts=[...] in container/docker configs
    MOUNTS_LIST_RE = re.compile(
        r"mounts?\s*[:=]\s*\[",
        re.IGNORECASE
    )

    # -v /host:/container command-line flag
    VOLUME_FLAG_RE = re.compile(
        r"-v\s+[/~$%]",
        re.IGNORECASE
    )

    # bind mount with source pointing to sensitive directory
    BIND_SOURCE_RE = re.compile(
        r"['\"]source['\"]\s*:\s*['\"]([/~]|(?:\$|\%)HOME)",
        re.IGNORECASE
    )
    BIND_TYPE_RE = re.compile(
        r"['\"]type['\"]\s*:\s*['\"]bind['\"]",
        re.IGNORECASE
    )

    # docker-compose / docker SDK volume specifications
    DOCKER_VOLUME_RE = re.compile(
        r"(?:docker_client|docker\.from_env|compose|container)\b.*volumes?",
        re.IGNORECASE
    )

    # mount with type bind
    MOUNT_BIND_RE = re.compile(
        r"Mount\s*\(\s*.*type\s*=\s*['\"]bind['\"]",
        re.IGNORECASE
    )

    # --- YAML patterns ---
    YAML_VOLUMES_RE = re.compile(
        r"^\s*volumes?\s*:\s*$",
        re.IGNORECASE
    )

    YAML_MOUNTS_RE = re.compile(
        r"^\s*mounts?\s*:\s*$",
        re.IGNORECASE
    )

    YAML_SOURCE_RE = re.compile(
        r"^\s*source\s*:\s*(['\"])([/~$%]|\.\./)",
        re.IGNORECASE
    )

    YAML_BIND_TYPE_RE = re.compile(
        r"^\s*type\s*:\s*bind\s*$",
        re.IGNORECASE
    )

    def _is_yaml_file(self, file: str) -> bool:
        ext = file.rsplit(".", 1)[-1].lower() if "." in file else ""
        return ext in ("yaml", "yml")

    def _is_dockerfile(self, file: str) -> bool:
        name = file.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
        return name in ("dockerfile",) or name.startswith("dockerfile.")

    def scan_line(self, line: str, line_num: int, file: str) -> list[Finding]:
        return []

    def scan_content(self, content: str, file: str) -> list[Finding]:
        findings = []
        lines = content.splitlines()

        if self._is_yaml_file(file):
            return self._scan_yaml(content, file)

        if self._is_dockerfile(file):
            return self._scan_dockerfile(content, file)

        ext = file.rsplit(".", 1)[-1].lower() if "." in file else ""
        if ext not in ("py", "js", "ts", "jsx", "tsx", "mjs", "cjs"):
            return findings

        return self._scan_code(content, file)

    def _scan_code(self, content: str, file: str) -> list[Finding]:
        findings = []
        lines = content.splitlines()

        # Phase 1: DockerCommandLineCodeExecutor without read_only=True
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            if self.DOCKER_EXECUTOR_RE.search(stripped):
                # Check if read_only=True appears on the same or following lines
                ctx_end = min(len(lines), i + 5)
                context = "\n".join(lines[i - 1:ctx_end])
                if not self.READ_ONLY_RE.search(context):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=Severity.CRITICAL,
                        file=file,
                        line=i,
                        snippet=stripped[:200],
                        description="DockerCommandLineCodeExecutor without read_only=True — container has unrestricted host filesystem write access",
                        recommendation="Always set read_only=True on DockerCommandLineCodeExecutor. Use volume mounts with explicit read-only options for any required host paths.",
                        confidence=0.95,
                    ))

        # Phase 2: Check volumes and mounts for sensitive paths
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            # Check for -v flag with sensitive paths
            if self.VOLUME_FLAG_RE.search(stripped):
                if SENSITIVE_PATH_RE.search(stripped):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=Severity.CRITICAL,
                        file=file,
                        line=i,
                        snippet=stripped[:200],
                        description="Container volume flag (-v) with sensitive host path — exposes host filesystem to container",
                        recommendation="Avoid bind-mounting sensitive host directories. Use Docker volumes or restrict to specific, non-sensitive paths.",
                        confidence=0.9,
                    ))
                else:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=Severity.HIGH,
                        file=file,
                        line=i,
                        snippet=stripped[:200],
                        description="Container volume flag (-v) detected — verify the host path is non-sensitive and the mount is read-only",
                        recommendation="Ensure volume mounts are read-only and never expose sensitive host paths (/etc, /root, /home, /var/run/docker.sock).",
                        confidence=0.7,
                    ))

            # Check for volumes=[...] and mounts=[...] with sensitive paths
            if self.VOLUMES_LIST_RE.search(stripped) or self.MOUNTS_LIST_RE.search(stripped):
                # Check the next few lines for sensitive paths
                ctx_end = min(len(lines), i + 10)
                ctx = "\n".join(lines[i - 1:ctx_end])
                if SENSITIVE_PATH_RE.search(ctx):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=Severity.CRITICAL,
                        file=file,
                        line=i,
                        snippet=stripped[:200],
                        description="Container volume/mount configuration includes sensitive host path — host filesystem exposure risk",
                        recommendation="Remove mounts to sensitive paths. Use named Docker volumes or restrict to specific app directories with read-only access.",
                        confidence=0.9,
                    ))

            # Check for bind source mounts
            if self.BIND_SOURCE_RE.search(stripped):
                # Check nearby context for type: bind
                ctx_start = max(0, i - 5)
                ctx_end = min(len(lines), i + 3)
                ctx = "\n".join(lines[ctx_start:ctx_end])
                if self.BIND_TYPE_RE.search(ctx):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=Severity.CRITICAL,
                        file=file,
                        line=i,
                        snippet=stripped[:200],
                        description="Bind mount with source pointing to sensitive directory — container can read/write host filesystem",
                        recommendation="Avoid bind mounts to sensitive paths. Use read-only mounts to specific directories only.",
                        confidence=0.9,
                    ))

            # Check for Mount() with type=bind — scan multiple lines
            if self.MOUNT_BIND_RE.search(stripped):
                ctx_start = max(0, i - 1)
                ctx_end = min(len(lines), i + 8)
                ctx = "\n".join(lines[ctx_start:ctx_end])
                if SENSITIVE_PATH_RE.search(ctx):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=Severity.CRITICAL,
                        file=file,
                        line=i,
                        snippet=stripped[:200],
                        description="Mount(type='bind') with sensitive host source — host filesystem exposure via Docker SDK",
                        recommendation="Use type='volume' instead of type='bind'. Restrict source paths and always set read_only=True.",
                        confidence=0.9,
                    ))

            # Check for Mount( that spans multiple lines
            if re.search(r"(?:docker\.types\.)?Mount\s*\(", stripped, re.I):
                # Check the next 10 lines for type='bind' + sensitive source
                ctx_start = i - 1
                ctx_end = min(len(lines), i + 10)
                ctx = "\n".join(lines[ctx_start:ctx_end])
                has_bind = re.search(r"type\s*=\s*['\"]bind['\"]", ctx, re.I)
                has_sensitive = SENSITIVE_PATH_RE.search(ctx)
                if has_bind and has_sensitive:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=Severity.CRITICAL,
                        file=file,
                        line=i,
                        snippet=stripped[:200],
                        description="Mount() with type='bind' and sensitive host path — container can access host filesystem",
                        recommendation="Use type='volume' instead of type='bind'. Restrict source paths and always set read_only=True.",
                        confidence=0.9,
                    ))

            # Check for source= with sensitive path in mount dict context
            if re.search(r"['\"]?source['\"]?\s*[:=]\s*['\"](/[^'\"]+)", stripped):
                # Check nearby lines for type: bind
                ctx_start = max(0, i - 6)
                ctx_end = min(len(lines), i + 4)
                ctx = "\n".join(lines[ctx_start:ctx_end])
                if re.search(r"['\"]type['\"]\s*:\s*['\"]bind['\"]", ctx, re.I):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=Severity.CRITICAL,
                        file=file,
                        line=i,
                        snippet=stripped[:200],
                        description="Bind mount source points to host path — container can access host filesystem",
                        recommendation="Avoid bind mounts to host paths. Use named Docker volumes or restrict to safe directories only.",
                        confidence=0.9,
                    ))

        return findings

    def _scan_yaml(self, content: str, file: str) -> list[Finding]:
        """Scan YAML files (docker-compose.yml, MCP configs, agent configs)
        for volume mount security issues."""
        findings = []
        lines = content.splitlines()

        in_volumes = False
        in_mounts = False
        current_source = None
        volume_indent = 0
        mount_indent = 0

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            indent = len(line) - len(line.lstrip())

            # Track YAML structure
            if re.match(r"^\s*volumes?\s*:\s*$", line):
                in_volumes = True
                volume_indent = indent
                continue
            elif in_volumes and indent <= volume_indent and not stripped.startswith("-"):
                in_volumes = False

            if re.match(r"^\s*mounts?\s*:\s*$", line):
                in_mounts = True
                mount_indent = indent
                current_source = None
                continue
            elif in_mounts and indent <= mount_indent and not stripped.startswith("-"):
                in_mounts = False
                current_source = None

            # Detect -v style in command/entrypoint strings (anywhere)
            if "-v " in stripped and SENSITIVE_PATH_RE.search(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.HIGH,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description="Command with -v flag and sensitive host path in config file",
                    recommendation="Avoid -v bind mounts in container commands. Use named volumes or restrict to safe directories.",
                    confidence=0.85,
                ))

            # In YAML, detect sensitive volume mounts
            if in_volumes:
                # Volume format: "  - ./host/path:/container/path"
                if stripped.startswith("- ") and ":" in stripped:
                    mount_spec = stripped[2:].strip().strip('"').strip("'")
                    # Split on first colon to get host path
                    host_path = mount_spec.split(":")[0]

                    if SENSITIVE_PATH_RE.search(host_path):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            severity=Severity.CRITICAL,
                            file=file,
                            line=i,
                            snippet=stripped[:200],
                            description=f"docker-compose volume mount exposes sensitive host path: {host_path}",
                            recommendation="Remove mount to sensitive path. Use named Docker volumes or restrict to app-specific directories with read_only access.",
                            confidence=0.92,
                        ))

            # In mounts section, track source/type (both orderings, handle '- ' prefix)
            if in_mounts:
                # Check for source: with sensitive path (optionally preceded by '- ')
                src_match = re.match(r"^\s*(?:-\s+)?source\s*:\s*(['\"]?)([/~$%]|\$\{?HOME)", stripped)
                type_match = re.match(r"^\s*(?:-\s+)?type\s*:\s*bind\s*$", stripped, re.I)

                if src_match:
                    current_source = stripped
                    # Check if we already saw type: bind above
                    if current_source:
                        # Look backward for type: bind (with optional '- ')
                        back_start = max(0, i - 5)
                        back_ctx = "\n".join(lines[back_start:i])
                        if re.search(r"^\s*(?:-\s+)?type\s*:\s*bind\s*$", back_ctx, re.I | re.MULTILINE):
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                rule_name=self.rule_name,
                                severity=Severity.CRITICAL,
                                file=file,
                                line=i,
                                snippet=stripped[:200],
                                description="Bind mount in YAML config with sensitive host path source",
                                recommendation="Change mount type from bind to volume. Restrict source paths to non-sensitive directories.",
                                confidence=0.9,
                            ))
                            current_source = None

                if type_match:
                    # Look backward for source with sensitive path
                    if current_source and SENSITIVE_PATH_RE.search(current_source):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            severity=Severity.CRITICAL,
                            file=file,
                            line=i,
                            snippet=f"{current_source} <-> {stripped}"[:200],
                            description="Bind mount in YAML config with sensitive host path source",
                            recommendation="Change mount type from bind to volume. Restrict source paths to non-sensitive directories.",
                            confidence=0.9,
                        ))
                    else:
                        # Source not seen yet — look forward
                        fwd_end = min(len(lines), i + 5)
                        fwd_ctx = "\n".join(lines[i:fwd_end])
                        fwd_src = re.search(r"^\s*(?:-\s+)?source\s*:\s*(['\"]?)([/~]\S+|\$\{?HOME)", fwd_ctx, re.I | re.MULTILINE)
                        if fwd_src and SENSITIVE_PATH_RE.search(fwd_src.group(0)):
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                rule_name=self.rule_name,
                                severity=Severity.CRITICAL,
                                file=file,
                                line=i,
                                snippet=f"{stripped} <-> ...source..."[:200],
                                description="Bind mount in YAML config with sensitive host path source",
                                recommendation="Change mount type from bind to volume. Restrict source paths to non-sensitive directories.",
                                confidence=0.9,
                            ))
                    current_source = None

        return findings

    def _scan_dockerfile(self, content: str, file: str) -> list[Finding]:
        """Scan Dockerfiles for volume mount exposure patterns."""
        findings = []
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # VOLUME instruction in Dockerfile
            if stripped.upper().startswith("VOLUME "):
                # This is usually fine, but flag if it's sensitive
                if SENSITIVE_PATH_RE.search(stripped):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=Severity.MEDIUM,
                        file=file,
                        line=i,
                        snippet=stripped[:200],
                        description="Dockerfile VOLUME instruction with sensitive path — ensures data persistence but could expose host paths at runtime",
                        recommendation="Only use VOLUME for app data directories, not system paths. Use Docker named volumes at runtime instead.",
                        confidence=0.6,
                    ))

        return findings
