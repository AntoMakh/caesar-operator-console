import json
import os
import re
from typing import Dict, Any

class PipelineEngine:
    def __init__(self):
        self.workflows = self.load_workflows()

    def load_workflows(self, workflows_dir: str = "workflows") -> Dict:
        workflows = {}
        if not os.path.exists(workflows_dir):
            os.mkdir(workflows_dir)
        for workflow_name in os.listdir(workflows_dir):
            workflow_path = os.path.join(workflows_dir, workflow_name)
            if not workflow_path.endswith(".json"):
                continue
            with open(workflow_path, "r") as f:
                try:
                    workflow = json.load(f)
                except json.JSONDecodeError as e:
                    print(f"[!] Warning: failed to parse {workflow_name}: {e}")
                    continue
            
            name = workflow.get("workflow_name")
            if name:
                workflows[name] = workflow
            else:
                print(f"[!] Warning: {workflow_name} is missing a workflow_name field")
                continue
        return workflows

    def resolve_templates(self, value: Any, context: Dict[str, Any]) -> Any:
        """
        Replaces {{VARAIBLE}} placeholders in a string with matching values from context dictionary.
        If value is not a string (for example: int, bool, list), returns it as-is.
        If a placeholder is not found in context, leaves it unchaned.
        """
        if not isinstance(value, str):
            return value

        def replace_match(match):
            key = match.group(1).strip()
            # if key is in context, return its string value
            # if not in context, keep original placeholder (so match.group(0))
            return str(context.get(key, match.group(0))) # match.group(0) is the default value here
        # pattern is everything in between double curly braces with group being any character that isn't a closing curly brace
        return re.sub(r"\{\{([^}]+)\}\}", replace_match, value)