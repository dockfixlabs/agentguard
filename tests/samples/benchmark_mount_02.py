"""
Benchmark Sample 02: ASI-MOUNT-EXPOSURE — Docker SDK bind mounts with sensitive paths

This sample demonstrates vulnerable Docker SDK configurations
that bind-mount sensitive host directories into containers,
commonly used in agent MCP servers and tool executors.
"""
import docker


client = docker.from_env()

# VULNERABLE: Bind mount exposing entire /home directory
container = client.containers.run(
    "python:3.11-slim",
    "python -c 'import os; os.system(\"cat /host_home/.ssh/id_rsa\")'",
    mounts=[
        docker.types.Mount(
            type="bind",
            source="/home",
            target="/host_home",
            read_only=False,  # Read-write access to host /home!
        )
    ],
    detach=True,
)


# VULNERABLE: Mount with type=bind and source pointing to /etc
container2 = client.containers.run(
    "python:3.11-slim",
    command="ls -la /host_etc",
    mounts=[
        docker.types.Mount(
            type="bind",
            source="/etc",
            target="/host_etc",
        )
    ],
    detach=True,
)


# VULNERABLE: Command-line style -v flag with sensitive path
# Often seen in agent tool definitions
def run_in_docker(code: str) -> str:
    import subprocess
    return subprocess.check_output(
        f"docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "
        f"-v /root:/root python:3.11-slim python -c '{code}'",
        shell=True,
    )


# SAFE: Volume mount (not bind) with Docker volume
safe_container = client.containers.run(
    "python:3.11-slim",
    "python -c 'print(\"hello\")'",
    mounts=[
        docker.types.Mount(
            type="volume",
            source="app_data",
            target="/data",
        )
    ],
    detach=True,
)
