import os
from typing import Any

from module_loader import OptionSchema

def validate_option(
    option_name: str,
    option_info: OptionSchema,
    value: Any
) -> None:
    """Raise ValueError if a value violates its option metadata."""
    if value is None:
        if option_info.get("required", False):
            raise ValueError(f"{option_name}: a value is required")
        return

    option_type = option_info.get("type", "string")

    if option_type == "string":
        return

    if option_type == "integer":
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise ValueError(f"{option_name}: must be an integer")

        try:
            number = int(value)
        except ValueError:
            raise ValueError(f"{option_name}: must be an integer") from None

        minimum = option_info.get("min")
        maximum = option_info.get("max")

        if minimum is not None and number < minimum:
            raise ValueError(f"{option_name}: must be at least {minimum}")

        if maximum is not None and number > maximum:
            raise ValueError(f"{option_name}: must be at most {maximum}")

    elif option_type == "boolean":
        if str(value).lower() not in ("true", "yes", "1", "false", "no", "0"):
            raise ValueError(f"{option_name}: must be true/false, yes/no, or 1/0")

    elif option_type == "file":
        if not isinstance(value, str):
            raise ValueError(f"{option_name}: must be a file path")

        if option_info.get("must_exist", False) and not os.path.isfile(value):
            raise ValueError(f"{option_name}: file does not exist")

    elif option_type == "choice":
        choices = option_info.get("choices") or []
        if value not in choices:
            raise ValueError(f"{option_name}: must be one of {choices}")

    else:
        raise ValueError(f"{option_name}: unknown option type '{option_type}'")