"""Detection rules package."""

from agentguard.rules.prompt_injection import PromptInjectionRule
from agentguard.rules.tool_abuse import ToolAbuseRule
from agentguard.rules.data_exfiltration import DataExfiltrationRule
from agentguard.rules.excessive_agency import ExcessiveAgencyRule
from agentguard.rules.supply_chain import SupplyChainRule
from agentguard.rules.unsafe_eval import UnsafeEvalRule
from agentguard.rules.context_manipulation import ContextManipulationRule
from agentguard.rules.agent_loop import AgentLoopRule
from agentguard.rules.trust_boundary import TrustBoundaryRule

ALL_RULES = [
    PromptInjectionRule(),
    ToolAbuseRule(),
    DataExfiltrationRule(),
    ExcessiveAgencyRule(),
    SupplyChainRule(),
    UnsafeEvalRule(),
    ContextManipulationRule(),
    AgentLoopRule(),
    TrustBoundaryRule(),
]
