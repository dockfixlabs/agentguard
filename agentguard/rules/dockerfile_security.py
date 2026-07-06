"""Dockerfile Security Scanning (v0.7.0)

Detects security issues in Dockerfiles including:
- Running as root (USER root or missing USER directive)
- Exposed ports without TLS/security configuration
- Secrets in ENV instructions (credential leak in Docker context)
- Unsafe RUN commands
"""
from __future__ import annotations
import re
from agentguard.models import Finding, Rule, Severity


class DockerfileSecurityRule(Rule):
    """Detects security misconfigurations in Dockerfiles.

    Scans Dockerfiles for patterns that indicate insecure container
    configurations commonly found in AI agent deployments.
    """
    rule_id = "ASI-DOCKERFILE-SECURITY"
    rule_name = "Dockerfile Security"
    severity = Severity.HIGH

    # Running as root patterns
    USER_ROOT_RE = re.compile(
        r"^\s*USER\s+(?:root|0)\b",
        re.IGNORECASE
    )

    # Missing USER directive (implies running as root)
    FROM_RE = re.compile(
        r"^\s*FROM\s+",
        re.IGNORECASE
    )

    # EXPOSE without notes about TLS
    EXPOSE_RE = re.compile(
        r"^\s*EXPOSE\s+",
        re.IGNORECASE
    )

    # Secrets in ENV instructions
    ENV_SECRET_RE = re.compile(
        r"^\s*ENV\s+.*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|AUTH)\s*=\s*\S+",
        re.IGNORECASE
    )

    # ADD with remote URLs (supply chain risk)
    ADD_URL_RE = re.compile(
        r"^\s*ADD\s+https?://",
        re.IGNORECASE
    )

    # Unsafe COPY from root
    COPY_ROOT_RE = re.compile(
        r"^\s*COPY\s+--chown=root",
        re.IGNORECASE
    )

    # HEALTHCHECK with curl to external
    HEALTHCHECK_CURL_RE = re.compile(
        r"^\s*HEALTHCHECK\s+.*curl\s+https?://",
        re.IGNORECASE
    )

    # RUN with package install without version pinning
    RUN_INSTALL_UNPINNED_RE = re.compile(
        r"^\s*RUN\s+.*(?:apt-get\s+install|apk\s+add|pip\s+install|npm\s+install\s+-g|yum\s+install)\s+(?!.*(?:--no-install-recommends|--no-cache|-y\s+-y)).*",
        re.IGNORECASE
    )

    # RUN chmod 777
    RUN_CHMOD_777_RE = re.compile(
        r"^\s*RUN\s+.*chmod\s+777",
        re.IGNORECASE
    )

    # curl | bash pattern
    CURL_BASH_RE = re.compile(
        r"curl\s+.*\|\s*(?:bash|sh|/bin/sh|/bin/bash)",
        re.IGNORECASE
    )

    def _is_dockerfile(self, file: str) -> bool:
        name = file.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
        return name in ("dockerfile",) or name.startswith("dockerfile.")

    def scan_line(self, line: str, line_num: int, file: str) -> list[Finding]:
        return []

    def scan_content(self, content: str, file: str) -> list[Finding]:
        if not self._is_dockerfile(file):
            return []

        findings = []
        lines = content.splitlines()
        has_user_directive = False
        from_line = None

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Track FROM and USER directives
            if self.FROM_RE.match(stripped):
                if from_line is None:
                    from_line = i

            if re.match(r"^\s*USER\s+", stripped, re.I):
                has_user_directive = True
                if self.USER_ROOT_RE.match(stripped):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=Severity.HIGH,
                        file=file,
                        line=i,
                        snippet=stripped[:200],
                        description="Dockerfile explicitly sets USER root — container runs with full root privileges",
                        recommendation="Always run containers as a non-root user. Create a dedicated user with minimal permissions: 'RUN useradd -m appuser && USER appuser'.",
                        confidence=0.95,
                    ))

            # EXPOSE without security context
            if self.EXPOSE_RE.match(stripped):
                # Check nearby context for TLS/SSL references
                ctx_start = max(0, i - 5)
                ctx_end = min(len(lines), i + 5)
                ctx = "\n".join(lines[ctx_start:ctx_end])
                has_tls = bool(re.search(r"(?:TLS|SSL|HTTPS|certificate|tls\.cert|cert\.pem)", ctx, re.I))

                if not has_tls:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=Severity.MEDIUM,
                        file=file,
                        line=i,
                        snippet=stripped[:200],
                        description="Dockerfile EXPOSE without visible TLS configuration — exposed port may serve unencrypted traffic",
                        recommendation="Ensure all exposed ports use TLS. Use a reverse proxy (nginx, caddy) or configure TLS directly in the application.",
                        confidence=0.65,
                    ))

            # Secrets in ENV
            if self.ENV_SECRET_RE.match(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.CRITICAL,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description="Dockerfile ENV instruction contains secret/key/token — credentials baked into image layers",
                    recommendation="Never store secrets in Dockerfile ENV. Use build-time ARG with --build-arg (still visible in history), Docker secrets, or external secret management (Vault, AWS Secrets Manager).",
                    confidence=0.92,
                ))

            # ADD from URL
            if self.ADD_URL_RE.match(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.HIGH,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description="Dockerfile ADD from remote URL — supply chain risk; remote content could change",
                    recommendation="Use COPY for local files. If remote download is necessary, verify checksums with 'RUN curl URL | sha256sum -c CHECKSUM' before use.",
                    confidence=0.8,
                ))

            # curl | bash
            if self.CURL_BASH_RE.search(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.CRITICAL,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description="Dockerfile uses curl-pipe-bash pattern — arbitrary remote code execution during build",
                    recommendation="Download scripts first, verify checksum, then execute. Never pipe curl directly to bash/sh.",
                    confidence=0.95,
                ))

            # chmod 777
            if self.RUN_CHMOD_777_RE.search(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.HIGH,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description="Dockerfile uses chmod 777 — world-writable permissions on filesystem",
                    recommendation="Use restrictive permissions (chmod 755 or 644). Never use 777 in container images.",
                    confidence=0.85,
                ))

            # Unpinned package install
            if self.RUN_INSTALL_UNPINNED_RE.search(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.LOW,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description="Package installation without version pinning or recommended flags",
                    recommendation="Pin package versions and use --no-install-recommends (apt) or --no-cache (apk) for smaller, deterministic builds.",
                    confidence=0.6,
                ))

        # Post-scan: check if no USER directive was found
        if from_line is not None and not has_user_directive:
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.HIGH,
                file=file,
                line=from_line,
                snippet=f"FROM ... (no USER directive found)",
                description="Dockerfile has no USER directive — container will run as root by default",
                recommendation="Add a non-root USER directive. Create a dedicated user: 'RUN useradd -r -s /bin/false appuser && USER appuser'.",
                confidence=0.9,
            ))

        return findings
