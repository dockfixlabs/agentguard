"""Detection rules package."""

from agentguard.rules.prompt_injection import PromptInjectionRule
from agentguard.rules.tool_abuse import ToolAbuseRule
from agentguard.rules.data_exfiltration import DataExfiltrationRule
from agentguard.rules.excessive_agency import ExcessiveAgencyRule
from agentguard.rules.supply_chain import SupplyChainRule
from agentguard.rules.unsafe_eval import UnsafeEvalRule
from agentguard.rules.credential_leak import CredentialLeakRule
from agentguard.rules.context_manipulation import ContextManipulationRule
from agentguard.rules.agent_loop import AgentLoopRule
from agentguard.rules.trust_boundary import TrustBoundaryRule
from agentguard.rules.taint_tracking import TaintTrackingRule
from agentguard.rules.js_taint_tracking import JSTaintTrackingRule
from agentguard.rules.interprocedural import InterproceduralRule
from agentguard.rules.memory_poison import MemoryPoisoningRule
from agentguard.rules.tool_output_trust import ToolOutputTrustRule
from agentguard.rules.chain_amplify import ChainAmplificationRule
from agentguard.rules.agent_collusion import AgentCollusionRule
from agentguard.rules.prompt_template import PromptTemplateRule
from agentguard.rules.stegano_inject import SteganoInjectRule
from agentguard.rules.mount_exposure import MountExposureRule
from agentguard.rules.memory_class_confusion import MemoryClassConfusionRule
from agentguard.rules.dockerfile_security import DockerfileSecurityRule

ALL_RULES = [
    PromptInjectionRule(),
    ToolAbuseRule(),
    DataExfiltrationRule(),
    ExcessiveAgencyRule(),
    SupplyChainRule(),
    UnsafeEvalRule(),
    CredentialLeakRule(),
    ContextManipulationRule(),
    AgentLoopRule(),
    TrustBoundaryRule(),
    TaintTrackingRule(),
    JSTaintTrackingRule(),
    InterproceduralRule(),
    MemoryPoisoningRule(),
    ToolOutputTrustRule(),
    ChainAmplificationRule(),
    AgentCollusionRule(),
    PromptTemplateRule(),
    SteganoInjectRule(),
    MountExposureRule(),
    MemoryClassConfusionRule(),
    DockerfileSecurityRule(),
]
