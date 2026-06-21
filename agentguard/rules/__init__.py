"""Detection rules package."""

from agentguard.rules.prompt_injection import PromptInjectionRule
from agentguard.rules.tool_abuse import ToolAbuseRule
from agentguard.rules.data_exfiltration import DataExfiltrationRule
from agentguard.rules.credential_leak import CredentialLeakRule
from agentguard.rules.unsafe_eval import UnsafeEvalRule
from agentguard.rules.context_manipulation import ContextManipulationRule
from agentguard.rules.trust_boundary import TrustBoundaryRule

ALL_RULES = [
    PromptInjectionRule(),
    ToolAbuseRule(),
    DataExfiltrationRule(),
    CredentialLeakRule(),
    UnsafeEvalRule(),
    ContextManipulationRule(),
    TrustBoundaryRule(),
]
