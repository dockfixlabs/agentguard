"""Action Chain Amplification Detection (ASI-CHAIN-AMPLIFY)

Detects destructive operations in unbounded loops that can amplify
a single agent misstep into mass destruction.
"""
from __future__ import annotations
import re
from agentguard.models import Finding, Rule, Severity


class ChainAmplificationRule(Rule):
    """Detects unbounded destructive action chains."""

    rule_id = "ASI-CHAIN-AMPLIFY"
    rule_name = "Action Chain Amplification"
    severity = Severity.CRITICAL

    DESTRUCTIVE = re.compile(
        rb"\.delete\s*\(|\.remove\s*\(|\.drop\s*\(|\.truncate\s*\(|"
        rb"\.purge\s*\(|\.destroy\s*\(|\.wipe\s*\(|\.clear\s*\(|"
        rb"\.unlink\s*\(|\.rmdir\s*\(|\.send\s*\(|\.publish\s*\(|"
        rb"\.create\s*\(.*resource|\.launch\s*\(|\.deploy\s*\(|"
        rb"\.execute\s*\(|\.run\s*\(|\.invoke\s*\(|"
        rb"\.charge\s*\(|\.transfer\s*\(|\.withdraw\s*\(|\.spend\s*\(",
        re.IGNORECASE
    )

    LOOP_START = re.compile(
        rb"(for\s+\w+\s+in\s+|while\s+(True|1)\s*:|while\s+\S)",
        re.IGNORECASE
    )

    BATCH = re.compile(
        rb"ThreadPoolExecutor|ProcessPoolExecutor|asyncio\.gather\s*\(\s*\*|"
        rb"\.map\s*\(\s*lambda|list\s*\(\s*map\s*\(|"
        rb"\.apply\s*\(\s*lambda",
        re.IGNORECASE
    )

    UNBOUNDED_SOURCE = re.compile(
        rb"\.find\s*\(|\.search\s*\(|\.query\s*\(|\.list_all\s*\(|"
        rb"\.get_all\s*\(|\.fetch_all\s*\(|\.scan\s*\(|"
        rb"tool_output|tool_result|api_response|agent_result|"
        rb"user_input|request\.(data|json|body|args)|"
        rb"\.iterate\s*\(|\.stream\s*\(",
        re.IGNORECASE
    )

    SAFETY = re.compile(
        rb"rate[_]?limit|max[_]?(attempts|retries|calls|operations|items|requests|batch)|"
        rb"throttle|backoff|sleep\s*\(|time\.sleep|"
        rb"human[_]?in[_]?the[_]?loop|approval|confirmation|review|checkpoint|"
        rb"rollback|transaction|atomic|dry[_]?run|preview|sandbox|test[_]?mode|"
        rb"batch[_]?size\s*=|chunk[_]?size\s*=|page[_]?size\s*=|limit\s*=\s*\d|"
        rb"if\s+len\s*\(|if\s+count\s*[><=]|if\s+size\s*[><=]",
        re.IGNORECASE
    )

    def scan_line(self, line, line_num, file):
        return []

    def scan_content(self, content, file):
        ext = file.rsplit(".", 1)[-1] if "." in file else ""
        if ext not in ("py", "js", "ts", "jsx", "tsx"):
            return []

        findings = []
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            encoded = line.encode("utf-8", errors="ignore")

            # Line must contain destructive operation
            if not self.DESTRUCTIVE.search(encoded):
                continue

            # Check wider context for loop + unbounded source
            ctx_start = max(0, i - 10)
            ctx_end = min(len(lines), i + 5)
            context = "\n".join(lines[ctx_start:ctx_end])
            ctx_encoded = context.encode("utf-8", errors="ignore")

            # Must be inside a loop AND have unbounded source
            if not self.LOOP_START.search(ctx_encoded):
                # Also check batch patterns
                if not self.BATCH.search(encoded):
                    continue

            if not self.UNBOUNDED_SOURCE.search(ctx_encoded):
                continue

            # Check safety patterns
            safety_start = max(0, i - 20)
            safety_end = min(len(lines), i + 15)
            safety_ctx = " ".join(lines[safety_start:safety_end])
            if self.SAFETY.search(safety_ctx.encode("utf-8", errors="ignore")):
                continue

            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.CRITICAL,
                file=file,
                line=i,
                snippet=line.strip()[:120],
                description="Destructive operation inside unbounded loop without rate limiting or checkpoint -- single trigger can amplify into mass destruction",
                recommendation="Add rate limits, batch_size caps, human-in-the-loop checkpoints, or incremental approval gates before destructive operations in loops.",
                confidence=0.85,
            ))

        return findings
