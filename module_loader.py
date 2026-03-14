import os
import json

# im actually gonna comment this, it's 3:56 AM and i can barely understand

def normalize_module(metadata, module_path):
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
        "argument_order": argument_order
    }
    



def load_modules(modules_dir = "modules"):
    tools = {}
    for module_name in os.listdir(modules_dir): # for each folder in modules
        module_path = os.path.join(modules_dir, module_name) # get path to each module

        if not os.path.isdir(module_path): # if not folder, skip
            continue

        metadata_path = os.path.join(module_path, "module.json") # get path to module.json
        if not os.path.isfile(metadata_path): # if module.json doesn't exist, skip
            continue
        with open(metadata_path, "r") as f: # load metadata
            metadata = json.load(f)
        
        required_fields = ["entry"]
        missing = [field for field in required_fields if field not in metadata]
        
        if missing:
            print(f"[WARNING] Module '{module_name}' is missing required fields: {missing}. Skipping.")
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
