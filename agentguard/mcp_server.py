"""MCP Server mode — scan agent code directly from Claude Code, Cursor, or any MCP client."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from agentguard.scanner import scan_directory, scan_file
from agentguard.models import Severity
from agentguard.reporter import json_report


MCP_TOOLS = {
    "scan_agent_code": {
        "description": "Scan a directory or file for AI agent security vulnerabilities. Returns findings with severity, OWASP ASI mapping, file locations, and recommendations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Directory or file path to scan",
                },
                "min_severity": {
                    "type": "string",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                    "default": "INFO",
                    "description": "Minimum severity to report",
                },
            },
            "required": ["target"],
        },
    },
    "list_rules": {
        "description": "List all active AgentGuard detection rules and their OWASP ASI mapping.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    "get_finding_details": {
        "description": "Get detailed information about a specific finding by rule ID, including remediation guidance.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "rule_id": {
                    "type": "string",
                    "description": "The rule ID to get details for (e.g. ASI01-PROMPT-INJECTION)",
                },
            },
            "required": ["rule_id"],
        },
    },
}


def _make_text_content(text: str) -> dict:
    return {"type": "text", "text": text}


def handle_tool_call(name: str, arguments: dict) -> list[dict]:
    """Handle an MCP tool call and return content blocks."""
    if name == "scan_agent_code":
        target = arguments.get("target", ".")
        min_sev = arguments.get("min_severity", "INFO")

        result = scan_directory(target)

        # Filter by severity
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        min_idx = severity_order.index(min_sev.upper())
        allowed = severity_order[:min_idx + 1]
        result.findings = [f for f in result.findings if f.severity.value in allowed]

        summary = (
            f"🔍 AgentGuard Scan Results\n"
            f"Target: {result.target}\n"
            f"Files scanned: {result.files_scanned}\n"
            f"Duration: {result.scan_duration_ms}ms\n\n"
            f"🔴 Critical: {result.critical_count}\n"
            f"🟠 High: {result.high_count}\n"
            f"🟡 Medium: {result.medium_count}\n"
            f"🔵 Low: {result.low_count}\n\n"
        )

        if result.clean:
            summary += "✅ No vulnerabilities found."
        else:
            summary += "Findings:\n\n"
            for i, f in enumerate(result.findings, 1):
                summary += f"{i}. [{f.severity.value}] {f.rule_name}\n"
                summary += f"   File: {f.file}:{f.line}\n"
                summary += f"   OWASP: {f.owasp.value if f.owasp else 'N/A'}\n"
                summary += f"   Description: {f.description}\n"
                summary += f"   Fix: {f.recommendation}\n\n"

        return [_make_text_content(summary)]

    elif name == "list_rules":
        from agentguard.rules import ALL_RULES
        lines = ["📋 AgentGuard Detection Rules\n"]
        for rule in ALL_RULES:
            owasp = rule.owasp.value if rule.owasp else "N/A"
            lines.append(f"• {rule.rule_id} — {rule.rule_name} [{rule.severity.value}] (OWASP: {owasp})")
        return [_make_text_content("\n".join(lines))]

    elif name == "get_finding_details":
        rule_id = arguments.get("rule_id", "")
        from agentguard.rules import ALL_RULES
        for rule in ALL_RULES:
            if rule.rule_id == rule_id:
                text = (
                    f"🔍 Rule Details: {rule.rule_name}\n\n"
                    f"ID: {rule.rule_id}\n"
                    f"Severity: {rule.severity.value}\n"
                    f"OWASP: {rule.owasp.value if rule.owasp else 'N/A'}\n"
                    f"Description: {rule.__doc__ or 'Agent security detection rule'}\n"
                )
                return [_make_text_content(text)]
        return [_make_text_content(f"Rule '{rule_id}' not found.")]

    return [_make_text_content(f"Unknown tool: {name}")]


def run_stdio_server() -> None:
    """Run AgentGuard as an MCP stdio server.

    Supports MCP protocol for integration with Claude Code, Cursor, Copilot, etc.

    Configuration for Claude Code (~/.claude/claude_code_config.json):
    {
      "mcpServers": {
        "agentguard": {
          "command": "python3",
          "args": ["-m", "agentguard.mcp_server"]
        }
      }
    }
    """
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = msg.get("method", "")
        msg_id = msg.get("id")
        params = msg.get("params", {})

        if method == "initialize":
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "agentguard",
                        "version": "0.1.0",
                    },
                    "capabilities": {
                        "tools": {},
                    },
                },
            }
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()

        elif method == "tools/list":
            tools = []
            for name, spec in MCP_TOOLS.items():
                tools.append({
                    "name": name,
                    "description": spec["description"],
                    "inputSchema": spec["inputSchema"],
                })
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": tools},
            }
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()

        elif method == "tools/call":
            tool_name = params.get("name", "")
            tool_args = params.get("arguments", {})
            content = handle_tool_call(tool_name, tool_args)
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"content": content},
            }
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()

        elif method == "notifications/initialized":
            pass  # acknowledgment, no response needed


if __name__ == "__main__":
    run_stdio_server()
