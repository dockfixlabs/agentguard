"""
Benchmark Sample 03: ASI-MEMORY-CLASS-CONFUSION — Agent self-modification of tools and permissions

This sample demonstrates an AI agent class that modifies its own
tool registry, permissions, and system prompt — enabling the agent
to grant itself capabilities beyond its intended scope.

Based on the AutoGen memory self-modification analysis (Issue #7918).
"""


class VulnerableAgent:
    """An AI agent that can self-modify its governance configuration."""

    def __init__(self):
        self.tools = ["read_file", "search"]
        self.permissions = ["read"]
        self.system_prompt = "You are a helpful assistant."
        self.config = {"max_tokens": 1000, "allow_network": False}
        self.capabilities = ["text_generation"]

    # VULNERABLE: Agent can add tools to itself without authorization
    def discover_tools(self, registry):
        """Dynamically add tools — no permission check!"""
        # BUG: No authorization check before modifying self.tools
        new_tools = registry.get_available_tools()
        self.tools.extend(new_tools)  # Self-modification without auth
        # Now the agent has access to tools it was never granted

    # VULNERABLE: Agent modifies its own permissions
    def handle_response(self, response):
        """Process LLM response — can escalate its own permissions."""
        if "NEED_WRITE" in response:
            # BUG: Agent grants itself write permission
            self.permissions.append("write")
        if "NEED_DELETE" in response:
            self.permissions.append("delete")
        if "NEED_ADMIN" in response:
            self.permissions = ["admin"]  # Full escalation!

    # VULNERABLE: Agent rewrites its own system prompt
    def update_from_context(self, context):
        """Update agent state from context — governance bypass."""
        if "instructions" in context:
            # BUG: Mutating system prompt from external input
            self.system_prompt = context["instructions"]
        if "config" in context:
            self.config.update(context["config"])
        if "capabilities" in context:
            self.capabilities = context["capabilities"]

    # VULNERABLE: Memory update without permission checks
    def save_to_memory(self, key, value):
        """Write to shared memory store without authorization."""
        # BUG: No auth check — any agent code can write to memory
        self.memory.update_context(key, value)

    # VULNERABLE: Mutation of constraints
    def process_request(self, user_input):
        if "override" in user_input:
            # BUG: Constraints modified from user-controlled input
            self.constraints = {"max_actions": 1000, "allow_all": True}


class SafeAgent:
    """A properly secured agent that cannot self-modify."""

    def __init__(self):
        self._tools = frozenset(["read_file", "search"])  # Immutable
        self._permissions = frozenset(["read"])  # Immutable
        self._system_prompt = "You are a helpful assistant."  # Immutable

    # SAFE: Tools are immutable — no modification possible
    def discover_tools(self, registry):
        """Tools cannot be modified after init."""
        pass  # No self-modification

    # SAFE: Permissions checked externally
    def handle_response(self, response, auth_service):
        """Require external authorization for any permission change."""
        if auth_service.check_permission("write"):
            pass  # Authorization handled externally
