from setuptools import setup, find_packages

setup(
    name="dfx-agentguard",
    version="0.8.1",
    description="Autonomous security scanner for AI agents — detects prompt injection, tool abuse, data exfiltration, and OWASP ASI Top 10 vulnerabilities.",
    long_description=open("README.md", encoding="utf-8").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    license="LGPL-3.0-only",
    python_requires=">=3.10",
    packages=find_packages(),
    install_requires=[
        "click>=8.1",
        "rich>=13.0",
        "pydantic>=2.0",
    ],
    extras_require={
        "dev": ["pytest>=7.0", "pytest-cov", "ruff"],
        "mcp": ["mcp>=0.9"],
    },
    entry_points={"console_scripts": ["agentguard=agentguard.cli:main"]},
    author="Dockfix Labs",
    author_email="security@dockfixlabs.dev",
    url="https://github.com/dockfixlabs/agentguard",
    keywords=["ai-security", "agent-security", "owasp-asi", "prompt-injection", "mcp", "static-analysis", "llm-security"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)
