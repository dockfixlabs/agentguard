"""
Benchmark Sample 01: ASI-MOUNT-EXPOSURE — DockerCommandLineCodeExecutor without read_only

This sample demonstrates a vulnerable Docker code executor configuration
commonly found in AI agent frameworks (AutoGen, CrewAI, LangChain).
The executor mounts the host filesystem without read_only protection,
allowing arbitrary host file writes from agent code.
"""
from autogen.coding import DockerCommandLineCodeExecutor


# VULNERABLE: DockerCommandLineCodeExecutor without read_only=True
# The container can write to any mounted host path
executor = DockerCommandLineCodeExecutor(
    image="python:3.11-slim",
    work_dir="/workspace",
    timeout=60,
    # BUG: read_only is missing — defaults to False
    # This allows the container to modify host files
)


# VULNERABLE: Volumes with sensitive host paths
code_executor = DockerCommandLineCodeExecutor(
    image="python:3.11-slim",
    work_dir="/workspace",
    timeout=120,
    # This exposes the ENTIRE host /etc directory to the container
    # Agent code can modify /etc/passwd, /etc/shadow, etc.
    volumes=["/etc:/host_etc:rw"],
)


# SAFE (for comparison): This pattern should NOT be flagged
safe_executor = DockerCommandLineCodeExecutor(
    image="python:3.11-slim",
    work_dir="/workspace",
    timeout=60,
    read_only=True,  # Properly configured
    volumes=["./workspace:/workspace:ro"],  # Relative path, read-only
)
