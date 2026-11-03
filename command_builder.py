from typing import Any

from module_loader import ToolSchema
from option_validation import validate_option

def build_module_command(
    tool: ToolSchema,
    option_values: dict[str, Any],
) -> list[str]:
    """Build command arguments using supplied values and module defaults."""
    command = [tool["entry"]]

    for option_name in tool["argument_order"]:
        option_info = tool["options"][option_name]
        value = option_values.get(option_name, option_info.get("default"))

        validate_option(option_name, option_info, value)
                
        if value is None:
            continue

        flag = option_info.get("flag")

        if option_info.get("type") == "boolean":
            if str(value).lower() in ("true", "yes", "1"):
                command.append(flag)
        else:
            if flag:
                command.append(flag)
            command.append(str(value))

    return command