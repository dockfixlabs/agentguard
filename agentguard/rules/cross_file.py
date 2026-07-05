"""Cross-file interprocedural taint analysis -- tracks taint through imports.

Resolves Python imports to find LLM sinks in imported modules, then
traces tainted data flowing into imported functions.
"""
from __future__ import annotations
import ast, os
from pathlib import Path


def resolve_imports(file_path: str, content: str) -> dict:
    """Parse imports and return {imported_name: resolved_file_path}.

    Only resolves local project imports (same directory or subdirectories).
    Does NOT attempt to resolve third-party packages.
    """
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return {}

    file_dir = Path(file_path).parent
    resolved = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                module = alias.name
                name = alias.asname or module.split(".")[0]
                candidate = _find_module(module, file_dir)
                if candidate:
                    resolved[name] = candidate
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                module = node.module
                for alias in node.names:
                    name = alias.asname or alias.name
                    candidate = _find_module(module, file_dir)
                    if candidate:
                        resolved[name] = candidate

    return resolved


def _find_module(module: str, search_dir: Path) -> str | None:
    """Find a Python module file in the search directory tree.

    Handles: import utils (-> utils.py), from app.helpers import clean (-> app/helpers.py)
    """
    parts = module.split(".")
    for level in range(len(parts), 0, -1):
        prefix = os.sep.join(parts[:level])
        for ext in (".py", os.sep + "__init__.py"):
            candidate = search_dir / (prefix + ext)
            if candidate.is_file():
                return str(candidate)

        # Check if it's a package (dir with __init__.py)
        pkg = search_dir / prefix
        if pkg.is_dir() and (pkg / "__init__.py").is_file():
            return str(pkg / "__init__.py")

    return None


def get_imported_sinks(file_path: str, content: str) -> dict:
    """Return {imported_func_name: sink_line} for imported functions that contain LLM sinks.

    This is used to extend the single-file interprocedural catalog with
    information from imported modules.
    """
    LLM_PATTERNS = (
        "chat.completions", "completions.create", "messages.create",
        "llm.generate", "llm.chat", "llm.complete", "model.generate",
        "client.chat", "client.completions", "client.messages",
    )

    imports = resolve_imports(file_path, content)
    sink_funcs = {}

    for func_name, imp_path in imports.items():
        try:
            with open(imp_path, encoding="utf-8", errors="ignore") as f:
                imp_content = f.read()
        except Exception:
            continue

        try:
            imp_tree = ast.parse(imp_content)
        except SyntaxError:
            continue

        # Check if imported file defines a FUNCTION with the import name
        for node in ast.walk(imp_tree):
            if isinstance(node, ast.FunctionDef) and node.name == func_name:
                # Check body for LLM sinks
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        parts = []
                        func = child.func
                        while isinstance(func, ast.Attribute):
                            parts.append(func.attr)
                            func = func.value
                        if isinstance(func, ast.Name):
                            parts.append(func.id)
                        dotted = ".".join(reversed(parts))
                        if any(p in dotted for p in LLM_PATTERNS):
                            sink_funcs[func_name] = child.lineno
                            break

    return sink_funcs
