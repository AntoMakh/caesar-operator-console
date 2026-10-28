from typing import TypedDict, List, NotRequired
import json
import os
import re
from typing import Dict, Any
from module_runner import run_module_and_log

class StageSchema(TypedDict):
    name: str
    tool: str
    options: NotRequired[Dict[str, Any]]
    output: NotRequired[str]
    iterate_over: NotRequired[str]

class WorkflowSchema(TypedDict, total=False):
    workflow_name: str
    required_inputs: List[str]
    fail_fast: NotRequired[bool]
    stages: list[StageSchema]

class PipelineEngine:
    def __init__(self, tools: Dict[str, Any] = None):
        self.tools = tools or {}
        self.workflows = self.load_workflows()

    def load_workflows(self, workflows_dir: str = "workflows") -> Dict[str, WorkflowSchema]:
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
        
    def run_workflow(self, workflow_name: str, initial_context: Dict[str, Any]) -> None:
        """
        Run the stages of a loaded workflow in order.

        Example:
            workflow_name:   "dns_recon"
            initial_context: {"DOMAIN": "example.com", "WORDLIST": "words.txt"}

        If a stage produces:
            ["alpha.example.com", "beta.example.com"]

        and its output name is "discovered_subdomains", save:
            context["discovered_subdomains"] = [
                "alpha.example.com",
                "beta.example.com",
            ]

        A later stage can iterate over that list using:
            "iterate_over": "discovered_subdomains"

        Returns None. Results are kept in the local context during the run.
        Running this method executes tools and writes execution logs.
        """
        context = dict(initial_context)
        workflow = self.workflows[workflow_name]
        for stage in workflow["stages"]:
            tool_name = stage["tool"]
            print(f"[*] Running stage: {stage["name"]} ({tool_name})")
            should_fail_fast = stage.get("fail_fast", workflow.get("fail_fast", False))
            if "iterate_over" not in stage:
                resolved_options = {}
                for option_name, option_value in stage["options"].items():
                    resolved_options[option_name] = self.resolve_templates(option_value, context)
                command = self.build_command(tool_name, resolved_options)
                # Example result: (["alpha.example.com", "beta.example.com"], True)
                module_output = run_module_and_log(tool_name, command, background=False)
                # [0] contains the output lines; use an empty list if there are none.
                lines = module_output[0]
                lines = lines or []
                # [1] is the success flag: False means execution failed.
                if not module_output[1]:
                    if should_fail_fast:
                        return
                    else:
                        continue
                if "output" in stage:
                    context[stage["output"]] = lines
                    print(f"[+] Saved {len(lines)} items to context['{stage['output']}']")
            else:
                items_to_loop = context.get(stage["iterate_over"], [])
                if not items_to_loop:
                    print(f"[!] Nothing to iterate on. Skipping stage.")
                    if "output" in stage:
                        context[stage["output"]] = []
                else:
                    print(f"[*] Looping over {len(items_to_loop)} items from '{stage['iterate_over']}'")
                    stage_results = []
                    for item in items_to_loop:
                        context["item"] = item

                        resolved_options = {}
                        for option_name, option_value in stage["options"].items():
                            resolved_options[option_name] = self.resolve_templates(option_value, context)
                        
                        command = self.build_command(tool_name, resolved_options)
                        module_output = run_module_and_log(tool_name, command, background=False)
                        lines = module_output[0]
                        lines = lines or []
                        stage_results.extend(lines)
                        if not module_output[1]:
                            if should_fail_fast:
                                return
                            else:
                                continue
                    if "output" in stage:
                        context[stage["output"]] = stage_results
                        print(f"[+] Saved {len(stage_results)} items to context['{stage['output']}']")
          
    def build_command(self, tool_name: str, resolved_options: Dict[str, Any]) -> List[str]:
        """
        Turn resolved options into an ordered list of command arguments.

        Example, using a tool whose entry is example.py:
            tool_name: "example"
            resolved_options:
                {"TARGET": "example.com", "THREADS": 4, "QUIET": True}

            returns:
                ["example.py", "example.com", "--threads", "4", "--quiet"]

        This example assumes THREADS uses --threads and QUIET uses --quiet.
        Argument order comes from the tool's metadata.
        This method builds the list; it does not run the tool.
        """
        tool = self.tools[tool_name]
        command = [tool["entry"]]
        for argument in tool["argument_order"]:
            arg = resolved_options.get(argument)
            if arg is None:
                continue
            argument_dict = tool["options"][argument]
            if argument_dict.get("type") == "boolean":
                if str(arg).lower() in ["true", "yes", "1"]:
                    command.append(argument_dict["flag"])
            elif argument_dict.get("flag"):
                command.append(argument_dict["flag"])
                command.append(str(arg))
            else:
                command.append(str(arg))
      
        return command


    def resolve_templates(self, value: Any, context: Dict[str, Any]) -> Any:
        """
        Replace placeholders in a value using the context dictionary.

        Example:
            value:   "https://{{item.domain}}:{{PORT}}"
            context: {"item": {"domain": "example.com"}, "PORT": 443}
            returns: "https://example.com:443"

        A non-string value, such as 443 or True, is returned unchanged.
        A missing variable stays as its original placeholder.
        """
        if not isinstance(value, str):
            return value

        def replace_match(match):
            key = match.group(1).strip()
            parts = key.split(".")
            
            current = context
            for part in parts:
                if isinstance(current, dict) and part in current.keys():
                    current = current[part]
                else:
                    return match.group(0)
            return str(current)

        # pattern is everything in between double curly braces with group being any character that isn't a closing curly brace
        return re.sub(r"\{\{([^}]+)\}\}", replace_match, value)
