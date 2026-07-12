"""Finding Classifier — automatic categorization of scan findings.

Classifies each finding into one of four buckets:
- CONFIRMED: High-confidence, actionable vulnerability
- INVESTIGATE: Needs human review — could be real, could be FP
- LIKELY_FP: Pattern match but context suggests false positive
- CODE_PATTERN: Security-relevant but not exploitable (best practice flag)

Uses confidence score + rule-specific heuristics + file context.
"""

from __future__ import annotations

from enum import Enum
from dataclasses import dataclass, field
from collections import Counter

from agentguard.models import Finding, Severity


class Classification(str, Enum):
    CONFIRMED = "CONFIRMED"       # Actionable, high confidence, likely real
    INVESTIGATE = "INVESTIGATE"   # Needs human review, ambiguous
    LIKELY_FP = "LIKELY_FP"       # Probably false positive
    BEST_PRACTICE = "BEST_PRACTICE"  # Security-relevant pattern, not exploitable


# ── Rule severity → classification biases ────────────────────────────
# Some rules are naturally noisier. This biases the classifier's decision.

RULE_NOISE_PROFILE: dict[str, float] = {
    # Noisy rules (tend to flag legitimate patterns)
    "ASI09-AGENT-LOOP": 0.6,           # while True is common in server code
    "ASI-AGENT-COLLUSION": 0.55,       # Shared state is common in multi-agent arch
    "ASI07-CREDENTIAL-LEAK": 0.5,      # Many test/example credentials
    "ASI01-PROMPT-INJECTION": 0.45,    # Many legitimate prompt constructions
    # Moderate rules
    "ASI02-TOOL-ABUSE": 0.35,
    "ASI03-DATA-EXFIL": 0.4,
    "ASI04-EXCESSIVE-AGENCY": 0.35,
    "ASI05-SUPPLY-CHAIN": 0.3,
    "ASI06-UNSAFE-EVAL": 0.3,
    "ASI08-CONTEXT-MANIP": 0.4,
    "ASI10-TRUST-BOUNDARY": 0.35,
    # Precise rules (low noise)
    "ASI-STEGANO-INJECT": 0.15,
    "ASI-MOUNT-EXPOSURE": 0.2,
    "ASI-MEMORY-CLASS-CONFUSION": 0.2,
    "ASI-DOCKERFILE-SECURITY": 0.15,
}

# Default noise profile for rules not in the map
DEFAULT_NOISE = 0.35


@dataclass
class ClassifierResult:
    """Result of classifying a set of findings."""
    total: int
    confirmed: int
    investigate: int
    likely_fp: int
    best_practice: int
    classified: list[dict] = field(default_factory=list)  # [{rule_id, file, line, classification, reason}]


def classify_findings(findings: list[Finding]) -> tuple[list[Finding], ClassifierResult]:
    """Classify each finding and return findings with classification added to description.

    The classification is appended as a tag in the finding's description field.
    Returns (findings_with_tags, classifier_result).
    """
    counts: dict[Classification, int] = {c: 0 for c in Classification}
    classified: list[dict] = []

    tagged_findings = []
    for f in findings:
        cls, reason = _classify_one(f)
        counts[cls] += 1
        classified.append({
            "rule_id": f.rule_id,
            "file": f.file,
            "line": f.line,
            "classification": cls.value,
            "reason": reason,
        })

        # Tag the description with classification for downstream consumers
        tag = _classification_tag(cls)
        tagged_findings.append(Finding(
            rule_id=f.rule_id,
            rule_name=f.rule_name,
            severity=f.severity,
            owasp=f.owasp,
            file=f.file,
            line=f.line,
            column=f.column,
            snippet=f.snippet,
            description=f"{tag} {f.description}",
            recommendation=f.recommendation,
            confidence=f.confidence,
        ))

    result = ClassifierResult(
        total=len(findings),
        confirmed=counts[Classification.CONFIRMED],
        investigate=counts[Classification.INVESTIGATE],
        likely_fp=counts[Classification.LIKELY_FP],
        best_practice=counts[Classification.BEST_PRACTICE],
        classified=classified,
    )

    return tagged_findings, result


def _classify_one(f: Finding) -> tuple[Classification, str]:
    """Classify a single finding."""
    rule_id = f.rule_id
    severity = f.severity
    confidence = f.confidence

    # ── Rule: confidence dominates ──
    noise = RULE_NOISE_PROFILE.get(rule_id, DEFAULT_NOISE)

    # Very high confidence + CRITICAL/HIGH severity = almost certainly real
    if confidence >= 0.85 and severity in (Severity.CRITICAL, Severity.HIGH):
        return Classification.CONFIRMED, f"High confidence ({confidence:.0%}) + {severity.value} severity"

    # High confidence but MEDIUM severity
    if confidence >= 0.8:
        return Classification.INVESTIGATE, f"High confidence ({confidence:.0%}) but {severity.value} — verify impact"

    # Medium confidence — depends on severity and noise
    if 0.5 <= confidence < 0.8:
        if severity in (Severity.CRITICAL, Severity.HIGH) and noise < 0.5:
            return Classification.INVESTIGATE, f"Medium confidence ({confidence:.0%}), low-noise rule — investigate"
        elif severity == Severity.MEDIUM and noise < 0.4:
            return Classification.INVESTIGATE, f"Medium confidence ({confidence:.0%}), precise rule — worth checking"
        elif noise >= 0.5:
            return Classification.LIKELY_FP, f"Medium confidence + noisy rule (noise={noise:.0%}) — likely FP"
        else:
            return Classification.BEST_PRACTICE, f"Medium confidence ({confidence:.0%}), {severity.value} — best practice flag"

    # Low confidence
    if 0.3 <= confidence < 0.5:
        if noise >= 0.4:
            return Classification.LIKELY_FP, f"Low confidence ({confidence:.0%}) + noisy rule — probably FP"
        else:
            return Classification.BEST_PRACTICE, f"Low confidence ({confidence:.0%}) — best practice note"

    # Very low confidence (should have been filtered, but just in case)
    return Classification.LIKELY_FP, f"Very low confidence ({confidence:.0%})"


def _classification_tag(cls: Classification) -> str:
    """Return a short tag prefix for the classification."""
    tags = {
        Classification.CONFIRMED: "[CONFIRMED]",
        Classification.INVESTIGATE: "[INVESTIGATE]",
        Classification.LIKELY_FP: "[LIKELY_FP]",
        Classification.BEST_PRACTICE: "[BEST_PRACTICE]",
    }
    return tags.get(cls, "")


def describe_classification(result: ClassifierResult) -> str:
    """Human-readable summary of classification results."""
    lines.append(f"Classification: {result.total} findings categorized")
    lines.append(f"  CONFIRMED:      {result.confirmed} — actionable, high-confidence vulnerabilities")
    lines.append(f"  INVESTIGATE:    {result.investigate} — needs human review")
    lines.append(f"  BEST_PRACTICE:  {result.best_practice} — security pattern, not exploitable")
    lines.append(f"  LIKELY_FP:      {result.likely_fp} — probably false positive")

    if result.total > 0:
        confirmed_pct = result.confirmed / result.total * 100
        investigate_pct = result.investigate / result.total * 100
        lines.append(f"\n  Actionable rate: {confirmed_pct:.0f}% confirmed + {investigate_pct:.0f}% investigate")

    return "\n".join(lines)
