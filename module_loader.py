from typing import TypedDict, Dict, List, Optional, Any
import os
import json

class OptionSchema(TypedDict, total=False):
    required: bool
    value: Any
    default: Any
    description: str
    flag: Optional[str]
    type: str
    choices: Optional[List[str]]
    min: Optional[int]
    max: Optional[int]
    must_exist: bool

class ToolSchema(TypedDict, total=False):
    name: str
    description: str
    entry: str
    options: Dict[str, OptionSchema]
    argument_order: List[str]
    dependencies: List[str]

def normalize_module(metadata: dict, module_path: str) -> ToolSchema:
    """normalize raw metadata into runtime tool format."""
    # here, we modify to match runtime structure needed for caesar.py
    entry_path = os.path.join(module_path, metadata["entry"])

    options = {}
    module_name = metadata.get("name", os.path.basename(module_path))
    for option_name, option_info in metadata.get("options", {}).items():
        default = option_info.get("default", None)
        if isinstance(default, str) and default.strip() == "":
            print(f"[WARNING] Module '{module_name}' option '{option_name}' has an empty or whitespace-only string default. Treating it as unset.")
            default = None
        options[option_name] = {
            "required": option_info.get("required", False),
            "value": default,
            "default": default,
            "description": option_info.get("description", ""),
            "flag": option_info.get("flag"),
            "type": option_info.get("type", "string"),
            "choices": option_info.get("choices"),
            "min": option_info.get("min"),
            "max": option_info.get("max"),
            "must_exist": option_info.get("must_exist", False)
        }

    argument_order = metadata.get("argument_order", list(options.keys()))

    return {
        "name": metadata.get("name", ""),
        "description": metadata.get("description", ""),
        "entry": entry_path,
        "options": options,
        "argument_order": argument_order,
        "dependencies": metadata.get("dependencies", []),
    }
    
def validate_module_fields(metadata: dict) -> None:
    """Check the field types needed to load a module."""
    entry = metadata.get("entry")
    if not isinstance(entry, str) or not entry.strip():
        raise ValueError("'entry' must be a non-empty string")

    options = metadata.get("options", {})
    if not isinstance(options, dict):
        raise ValueError("'options' must be an object")

    for option_name, option_info in options.items():
        if not isinstance(option_info, dict):
            raise ValueError(f"option '{option_name}' must be an object")

    for field in ("argument_order", "dependencies"):
        values = metadata.get(field, [])
        if not isinstance(values, list):
            raise ValueError(f"'{field}' must be a list of strings")

        for value in values:
            if not isinstance(value, str):
                raise ValueError(f"'{field}' must contain only strings")

def load_modules(modules_dir: str = "modules") -> Dict[str, ToolSchema]:
    """load and validate all tool metadata schemas from the modules directory."""
    tools = {}
    for module_name in os.listdir(modules_dir): # for each folder in modules
        module_path = os.path.join(modules_dir, module_name) # get path to each module

        if not os.path.isdir(module_path): # if not folder, skip
            continue

        metadata_path = os.path.join(module_path, "module.json") # get path to module.json
        if not os.path.isfile(metadata_path): # if module.json doesn't exist, skip
            continue
        try:
            with open(metadata_path, "r", encoding="utf-8-sig") as metadata_file:
                metadata = json.load(metadata_file)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            print(f"[WARNING] Cannot read metadata '{metadata_path}': {error}. Skipping.")
            continue

        if not isinstance(metadata, dict):
            print(f"[WARNING] Metadata '{metadata_path}' must be a JSON object. Skipping.")
            continue
        
        try:
            validate_module_fields(metadata)
        except ValueError as error:
            print(f"[WARNING] Invalid metadata '{metadata_path}': {error}. Skipping.")
            continue

        entry_path = os.path.join(module_path, metadata["entry"])
        if not os.path.isfile(entry_path):
            print(f"[WARNING] Entry script '{metadata['entry']}' not found in '{module_name}'. Skipping.")
            continue

        invalid_argument_names = [option_name for option_name in metadata.get("argument_order", []) if option_name not in metadata.get("options", {})]
        if invalid_argument_names:
            print(f"[WARNING] Module '{module_name}' has invalid argument_order entries: {invalid_argument_names}. Skipping.")
            continue

        missing_argument_names = [option_name for option_name in metadata.get("options", {}) if option_name not in metadata.get("argument_order", list(metadata.get("options", {}).keys()))]
        if missing_argument_names:
            print(f"[WARNING] Module '{module_name}' is missing options in argument_order: {missing_argument_names}. Skipping.")
            continue

        tool = normalize_module(metadata, module_path)
        tools[module_name] = tool
        
    return tools
