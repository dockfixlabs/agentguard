FROM python:3.12-slim

LABEL org.opencontainers.image.title="AgentGuard"
LABEL org.opencontainers.image.description="Autonomous security scanner for AI agent code"
LABEL org.opencontainers.image.source="https://github.com/dockfixlabs/agentguard"
LABEL org.opencontainers.image.vendor="Dockfix Labs"
LABEL org.opencontainers.image.licenses="LGPL-3.0-only"

RUN pip install --no-cache-dir dfx-agentguard

WORKDIR /workspace

ENTRYPOINT ["agentguard"]
CMD ["."]
