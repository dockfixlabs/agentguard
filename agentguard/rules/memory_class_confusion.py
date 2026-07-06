"""ASI-MEMORY-CLASS-CONFUSION: Agent Memory Class Confusion / Self-Modification (CWE-863, CVSS 7.8)

Detects agent code patterns where memory writes or class self-modifications
can alter execution constraints, permissions, or tool access — bypassing
authorization checks and enabling privilege escalation.

Based on the AutoGen memory self-modification analysis (Issue #7918):
Agent class methods that modify self.tools, self.config, self.permissions,
system_prompt, instructions, or constraints without authorization checks
can lead to unauthorized capability escalation.

This is a NOVEL rule beyond OWASP ASI — existing SAST tools do not check for
AI agent-specific memory/class self-modification patterns.
"""
from __future__ import annotations
import re
from agentguard.models import Finding, Rule, Severity


class MemoryClassConfusionRule(Rule):
    """Detects agent memory self-modification and class confusion attacks.

    Scans Python, JavaScript/TypeScript code for patterns where agent classes
    modify their own governance configuration (tools, permissions, prompts,
    constraints) without authorization checks, enabling privilege escalation.
    """
    rule_id = "ASI-MEMORY-CLASS-CONFUSION"
    rule_name = "Agent Memory Class Confusion"
    severity = Severity.HIGH
    cwe = "CWE-863"
    cvss = 7.8

    # --- Self-modification patterns (Python) ---

    # self.tools, self.config, self.permissions modifications
    SELF_TOOLS_RE = re.compile(
        r"self\.tools\s*[:=]|self\.tools\s*\.\s*append|self\.tools\s*\.\s*extend|"
        r"self\.tools\s*\.\s*add|self\.tools\s*\.\s*update|self\.tools\s*\.\s*remove|"
        r"self\.tools\s*\.\s*pop|self\.tools\s*\.\s*clear|self\.tools\s*\.\s*insert|"
        r"self\.tools\s*\.\s*__setitem__",
        re.IGNORECASE
    )

    SELF_CONFIG_RE = re.compile(
        r"self\.config\s*[:=]|self\.config\s*\.\s*update|self\.config\s*\.\s*__setitem__|"
        r"self\.config\s*\[",
        re.IGNORECASE
    )

    SELF_PERMISSIONS_RE = re.compile(
        r"self\.permissions?\s*[:=]|self\.permissions?\s*\.\s*append|self\.permissions?\s*\.\s*extend|"
        r"self\.permissions?\s*\.\s*add|self\.permissions?\s*\.\s*update|self\.permissions?\s*\.\s*remove|"
        r"self\.permissions?\s*\.\s*pop|self\.permissions?\s*\.\s*clear",
        re.IGNORECASE
    )

    # System prompt / instructions / constraints mutation
    SELF_SYSTEM_PROMPT_RE = re.compile(
        r"self\.system_prompt\s*[:=]|self\.system_prompt\s*\+=|"
        r"self\.instructions\s*[:=]|self\.instructions\s*\+=|"
        r"self\.constraints?\s*[:=]|self\.constraints?\s*\+=|"
        r"self\._system_message\s*[:=]|self\._instructions\s*[:=]|"
        r"self\.prompt\s*[:=]|self\.prompt\s*\+=|"
        r"self\.agent_config\s*[:=]|self\.agent_config\s*\.",
        re.IGNORECASE
    )

    # Self capability/role mutation
    SELF_CAPABILITY_RE = re.compile(
        r"self\.capabilit(?:y|ies)\s*[:=]|self\.capabilit(?:y|ies)\s*\.",
        re.IGNORECASE
    )

    # --- Memory write patterns ---

    # update_context / update_memory without permission checks
    MEMORY_UPDATE_RE = re.compile(
        r"\.update_context\s*\(|\.update_memory\s*\(|\.set_memory\s*\(|"
        r"\.modify_state\s*\(|\.overwrite_memory\s*\(|\.write_state\s*\(|"
        r"\.mutate_context\s*\(|\.append_to_memory\s*\(|"
        r"memory\.update\s*\(|memory\.set\s*\(|memory\.write\s*\(|"
        r"state\.update\s*\(|state\.modify\s*\(|state\.mutate\s*\(|"
        r"context\.update\s*\(|context\.mutate\s*\(|context\.set\s*\(",
        re.IGNORECASE
    )

    # --- Authorization check patterns (absence indicates vulnerability) ---

    AUTH_CHECK_RE = re.compile(
        r"(?:auth|authorize|permission_check|has_permission|check_permission|"
        r"can_modify|is_allowed|validate_access|verify_access|"
        r"require_auth|auth_required|access_control"
        r")\s*\(",
        re.IGNORECASE
    )

    # Whitelist patterns (not vulnerabilities)
    WHITELIST_RE = re.compile(
        r"self\.tools\s*=\s*\[\s*\]|self\.tools\s*=\s*\(\s*\)|"
        r"self\.tools\s*=\s*\{\s*\}|self\.tools\s*=\s*None|"
        r"self\.tools\s*=\s*set\s*\(\s*\)|"
        r"self\.tools\s*=\s*frozenset\s*\(|"
        r"self\.permissions?\s*=\s*frozenset\s*\(|"
        r"self\.(?:permissions?|tools)\s*=\s*tuple\s*\(|"
        r"__init__\s*\(",
        re.IGNORECASE
    )

    def _is_python_file(self, file: str) -> bool:
        ext = file.rsplit(".", 1)[-1].lower() if "." in file else ""
        return ext == "py"

    def _is_js_ts_file(self, file: str) -> bool:
        ext = file.rsplit(".", 1)[-1].lower() if "." in file else ""
        return ext in ("js", "ts", "jsx", "tsx", "mjs", "cjs")

    def scan_line(self, line: str, line_num: int, file: str) -> list[Finding]:
        return []

    def scan_content(self, content: str, file: str) -> list[Finding]:
        if not (self._is_python_file(file) or self._is_js_ts_file(file)):
            return []

        findings = []
        lines = content.splitlines()

        # Track which function/method each line belongs to
        current_function = None

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            # Track function/method boundaries
            func_match = re.match(r"^\s*def\s+(\w+)\s*\(", stripped)
            if func_match:
                current_function = func_match.group(1)

            # If we hit a dedent (class-level line), reset
            if stripped and not line[0].isspace() and not stripped.startswith(("def ", "class ", "@", "import ", "from ")):
                current_function = None

            # --- self.tools modification ---
            if self.SELF_TOOLS_RE.search(stripped) and not self.WHITELIST_RE.search(stripped):
                # Check if line is in __init__ (less concerning but still notable)
                is_init = (current_function == "__init__")

                # Check nearby context for auth checks
                nearby_start = max(0, i - 8)
                nearby_end = min(len(lines), i + 8)
                nearby = "\n".join(lines[nearby_start:nearby_end])
                has_auth = self.AUTH_CHECK_RE.search(nearby)

                sev = Severity.MEDIUM if is_init else Severity.HIGH
                desc = (
                    "Agent class modifies self.tools — dynamic tool registry mutation "
                    "without authorization check"
                ) if not has_auth else (
                    "Agent class modifies self.tools — verify authorization check is "
                    "robust and cannot be bypassed"
                )

                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=sev,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description=desc,
                    recommendation="Immutable tool registries should only be set in __init__(). Any runtime modifications must require explicit authorization with a robust permission check that cannot be bypassed by the agent itself.",
                    confidence=0.85 if not has_auth else 0.55,
                ))

            # --- self.config modification ---
            if self.SELF_CONFIG_RE.search(stripped):
                nearby_start = max(0, i - 8)
                nearby_end = min(len(lines), i + 8)
                nearby = "\n".join(lines[nearby_start:nearby_end])
                has_auth = self.AUTH_CHECK_RE.search(nearby)

                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.HIGH if not has_auth else Severity.MEDIUM,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description=(
                        "Agent class modifies self.config — runtime configuration "
                        "mutation without authorization check"
                    ) if not has_auth else (
                        "Agent class modifies self.config — verify configuration "
                        "changes are properly authorized"
                    ),
                    recommendation="Configuration changes should be restricted to initialization or require admin-level authorization. Guard against agent self-modification of security-relevant config.",
                    confidence=0.85 if not has_auth else 0.55,
                ))

            # --- self.permissions modification ---
            if self.SELF_PERMISSIONS_RE.search(stripped) and not self.WHITELIST_RE.search(stripped):
                nearby_start = max(0, i - 8)
                nearby_end = min(len(lines), i + 8)
                nearby = "\n".join(lines[nearby_start:nearby_end])
                has_auth = self.AUTH_CHECK_RE.search(nearby)

                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.CRITICAL if not has_auth else Severity.HIGH,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description=(
                        "Agent class modifies self.permissions — privilege escalation "
                        "via permission self-grant without authorization"
                    ) if not has_auth else (
                        "Agent class modifies self.permissions — verify that permission "
                        "changes are properly authorized and cannot be triggered by the agent itself"
                    ),
                    recommendation="Permission modifications should NEVER be possible from within agent code. Move permission logic to an external, immutable authorization service.",
                    confidence=0.9 if not has_auth else 0.6,
                ))

            # --- self.system_prompt / instructions mutation ---
            if self.SELF_SYSTEM_PROMPT_RE.search(stripped):
                nearby_start = max(0, i - 8)
                nearby_end = min(len(lines), i + 8)
                nearby = "\n".join(lines[nearby_start:nearby_end])
                has_auth = self.AUTH_CHECK_RE.search(nearby)

                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.CRITICAL if not has_auth else Severity.HIGH,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description=(
                        "Agent class mutates system_prompt/instructions — governance "
                        "bypass via prompt self-modification"
                    ) if not has_auth else (
                        "Agent class mutates system_prompt — verify authorization "
                        "prevents unauthorized prompt injection"
                    ),
                    recommendation="System prompts and instructions should be immutable. If dynamic prompts are needed, implement through an external, agent-immutable prompt manager with audit trail.",
                    confidence=0.9 if not has_auth else 0.6,
                ))

            # --- memory update without permission checks ---
            if self.MEMORY_UPDATE_RE.search(stripped):
                nearby_start = max(0, i - 8)
                nearby_end = min(len(lines), i + 8)
                nearby = "\n".join(lines[nearby_start:nearby_end])
                has_auth = self.AUTH_CHECK_RE.search(nearby)

                # Check function context
                func_start = max(0, i - 20)
                func_ctx = "\n".join(lines[func_start:i])
                is_in_thread = "thread" in func_ctx.lower() or "background" in func_ctx.lower()

                if not has_auth:
                    sev = Severity.CRITICAL if is_in_thread else Severity.HIGH
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=sev,
                        file=file,
                        line=i,
                        snippet=stripped[:200],
                        description=(
                            "Memory/context/state update without authorization check — "
                            "untrusted code can modify agent execution state"
                        ),
                        recommendation="All memory updates must be guarded by authorization checks. Implement immutable memory with append-only logs and cryptographic verification.",
                        confidence=0.88,
                    ))

            # --- self.capabilities modification ---
            if self.SELF_CAPABILITY_RE.search(stripped) and not self.WHITELIST_RE.search(stripped):
                nearby_start = max(0, i - 8)
                nearby_end = min(len(lines), i + 8)
                nearby = "\n".join(lines[nearby_start:nearby_end])
                has_auth = self.AUTH_CHECK_RE.search(nearby)

                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.HIGH if not has_auth else Severity.MEDIUM,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description="Agent class modifies self.capabilities — capability escalation without authorization",
                    recommendation="Capabilities should be defined at initialization and be immutable. Any runtime capability changes must go through an external authorization service.",
                    confidence=0.82,
                ))

        return findings
