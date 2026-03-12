import os
import json

# im actually gonna comment this, it's 3:56 AM and i can barely understand

def normalize_module(metadata, module_path):
    # here, we modify to match runtime structure needed for caesar.py
    entry_path = os.path.join(module_path, metadata["entry"])

    options = {}
    for option_name, option_info in metadata.get("options", {}).items():
        default = option_info.get("default", None)
        options[option_name] = {
            "required": option_info.get("required", False),
            "value": default,
            "default": default
        }

    return {
        "name": metadata.get("name", ""),
        "description": metadata.get("description", ""),
        "entry": entry_path,
        "options": options
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

        tool = normalize_module(metadata, module_path)
        tools[module_name] = tool
        
    return tools
