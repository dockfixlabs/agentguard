"""
Benchmark Sample 04: ASI-MEMORY-CLASS-CONFUSION — Shared state mutation without auth checks

This sample demonstrates agent memory and shared state patterns
where mutation occurs without authorization, enabling one agent
component to corrupt the execution state of another.

Based on the AutoGen memory self-modification analysis (Issue #7918).
"""
from typing import Any


class SharedAgentState:
    """Shared mutable state between multiple agent components."""

    def __init__(self):
        self._state = {}
        self.instructions = "Default instructions"
        self.constraints = {"max_steps": 10}
        self._tools_registry = {}

    # VULNERABLE: update_context without permission check
    def update_context(self, key: str, value: Any):
        """Update shared context — no authorization!"""
        # BUG: Any component can mutate shared state
        self._state[key] = value

    # VULNERABLE: set_memory without auth
    def set_memory(self, memory_id: str, data: dict):
        """Set memory entry without authorization."""
        self._state[f"memory:{memory_id}"] = data

    # VULNERABLE: modify_state mutation
    def modify_state(self, path: str, value: Any):
        """Deep state mutation without auth check."""
        parts = path.split(".")
        current = self._state
        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]
        current[parts[-1]] = value


class MultiAgentSystem:
    """Multi-agent system with shared mutable state."""

    def __init__(self):
        self.shared_state = SharedAgentState()

    def agent_action(self, agent_id: str, action: dict):
        """Agent performs action, potentially corrupting shared state."""
        # VULNERABLE: Agent modifies state.write directly
        if "state_update" in action:
            self.shared_state.update_context(
                action["key"],
                action["value"]
            )
        # VULNERABLE: Agent modifies instructions
        if "new_instructions" in action:
            self.shared_state.instructions = action["new_instructions"]

        # VULNERABLE: Agent modifies constraints
        if "new_constraints" in action:
            self.shared_state.constraints = action["new_constraints"]

    # VULNERABLE: Thread-based memory mutation
    def background_task(self):
        """Background task modifies state without checks."""
        import threading

        def mutate():
            # BUG: Background thread mutates memory without any auth
            self.shared_state.update_context("background", "malicious")
            self.shared_state.set_memory("sys", {"override": True})

        thread = threading.Thread(target=mutate, daemon=True)
        thread.start()
        return thread


class SecureMultiAgentSystem:
    """Properly secured multi-agent system."""

    def __init__(self):
        self._state = {}  # Private
        self._auth_service = None

    def agent_action(self, agent_id: str, action: dict):
        """Agent action with proper authorization."""
        if "state_update" in action and self._auth_service:
            # Check permission before mutating state
            if self._auth_service.check_permission(agent_id, "write_state"):
                # Log the mutation for audit
                self._auth_service.audit_log(agent_id, "state_update")
                self._state[action["key"]] = action["value"]
