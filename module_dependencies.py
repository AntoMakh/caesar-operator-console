import shutil

from module_loader import ToolSchema


def get_missing_dependencies(tool: ToolSchema) -> list[str]:
    """Return declared executable names that cannot be found on PATH."""
    missing = []

    for dependency in tool.get("dependencies", []):
        if shutil.which(dependency) is None:
            missing.append(dependency)

    return missing