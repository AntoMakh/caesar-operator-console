from typing import Optional, Dict, Any, List, Tuple
import cmd
import subprocess
from module_loader import load_modules, ToolSchema, OptionSchema
import json
import os
from module_runner import run_module_and_log
import shutil

try:
    import readline
except ImportError:
    try:
        import pyreadline3 as readline
    except ImportError:
        readline = None


class CaesarConsole(cmd.Cmd):
    intro = """
WRITTEN BY
 ________
/        \\
| b1smrk |
\\________/
                                     |__
                                     |\\/
                                     ---
                                     / | [
                              !      | |||
                            _/|     _/|-++'
                        +  +--|    |--|--|_ |-
                     { /|__|  |/\\__|  |--- |||__/
                    +---------------___[}-_===_.'____                 /\\
                ____`-' ||___-{]_| _[}-  |     |_[___\\==--            \\/   _
 __..._____--==/___]_|__|_____________________________[___\\==--____,------' .7
|                                                                          /
 \\_________________________________________________________________________|

Welcome to the Caesar Operator Console. Type help to list commands.
"""
    prompt = 'caesar > '
    settings_file = ".caesar_settings.json"

    def __init__(self):
        super().__init__()
        self.tools = load_modules()
        self.global_options = {}
        self.jobs = {}
        self.job_counter = 1

    current_tool = None

    def check_if_tool_selected(self) -> bool:
        """verify if a tool is currently selected in console."""
        if self.current_tool is None:
            print("[!] No tool is currently selected. Use 'select <tool>' to select a tool.")
            return False
        return True

    def get_current_tool(self) -> ToolSchema:
        """retrieve metadata dictionary of currently selected tool."""
        return self.tools[self.current_tool]

    def apply_global_options(self) -> None:
        """apply global environment option values to current tool options."""
        if self.current_tool is None:
            return
        tool_options = self.get_current_tool()["options"]
        for option_name, global_value in self.global_options.items():
            if option_name in tool_options:
                tool_options[option_name]["value"] = global_value

    def reset_options(self) -> None:
        """reset option values for current tool back to defaults."""
        tool_options = self.get_current_tool()["options"]
        for option_info in tool_options.values():
            option_info["value"] = option_info["default"]
        self.apply_global_options()

    def complete_tool_names(self, text: str) -> List[str]:
        matches = []
        for tool_name in self.tools:
            if tool_name.startswith(text):
                matches.append(tool_name)
        return matches

    def complete_option_names(self, text: str) -> List[str]:
        if self.current_tool is None:
            return []

        matches = []
        tool_options = self.get_current_tool()["options"]
        for option_name in tool_options:
            if option_name.startswith(text.upper()):
                matches.append(option_name)
        return matches

    def format_option_value(self, value: Any) -> str:
        if value is None:
            return "-"
        return str(value)

    def print_tool_options(self, tool: ToolSchema) -> None:
        print(f"{'OPTION':<25}{'VALUE':<40}REQUIRED")
        for option_name, option_info in tool["options"].items():
            required = "yes" if option_info["required"] else "no"
            value = self.format_option_value(option_info["value"])
            print(f"{option_name:<25}{value:<40}{required}")
            description = option_info.get("description", "")
            if description:
                print(f"  {description}")

    def get_required_unset_options(self, tool: ToolSchema) -> List[str]:
        tool_options = tool["options"]
        required_unset_options = []
        for option_name, option_info in tool_options.items():
            if option_info["required"] and option_info["value"] is None:
                required_unset_options.append(option_name)
        return required_unset_options

    def load_saved_settings(self) -> Dict[str, Any]:
        if not os.path.isfile(self.settings_file):
            return {}
        try:
            with open(self.settings_file, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            print("[!] Saved settings file is invalid. Loading empty settings.")
            return {}

    def write_saved_settings(self, data: Dict[str, Any]) -> None:
        with open(self.settings_file, "w") as f:
            json.dump(data, f, indent=4)

    def validate_option_value(self, option_name: str, option_info: OptionSchema, option_value: str) -> Tuple[bool, Optional[str]]:
        option_type = option_info.get("type", "string")

        if option_type == "string":
            return True, None
        elif option_type == "integer":
            if option_value.isdigit():
                int_value = int(option_value)
                min_val = option_info.get("min")
                max_val = option_info.get("max")
                if (min_val is not None and int_value < min_val) or (max_val is not None and int_value > max_val):
                    return False, f"Value must be in the range {min_val} to {max_val}."
                return True, None
            return False, "Value must be an integer."
        elif option_type == "file":
            if option_info["must_exist"] and not os.path.isfile(option_value):
                return False, "File does not exist."
            return True, None
        elif option_type == "choice":
            choices = option_info.get("choices", [])
            if option_value not in choices:
                return False, f"Value must be one of: {', '.join(choices)}."
            return True, None
        elif option_type == "boolean":
            if option_value.lower() in ["true", "yes", "1", "false", "no", "0"]:
                return True, None
            return False, "Value must be a boolean (true/false, yes/no, 1/0)."
        else:
            return False, f"Unknown option type: {option_type}."

    def do_help(self, arg):
        print("Available commands:")
        print("help              - Show this help message")
        print("tools             - List available tools")
        print("select <tool>     - Select a tool")
        print("info <tool>       - Show details for a tool")
        print("deselect          - Deselect current tool")
        print("options           - Show tool options")
        print("set <opt> <val>   - Set option value")
        print("unset <opt>       - Clear option value")
        print("save              - Save options of current tool")
        print("load              - Load saved settings to current tool")
        print("reset             - Reset options to defaults")
        print("check             - Check if module dependencies are met")
        print("run [-b]          - Execute tool (pass -b for background)")
        print("jobs              - List background jobs")
        print("output <job_id>   - View output of a background job")
        print("kill <job_id>     - Terminate a running background job")
        print("exit              - Exit console")
        print("setg <opt> <val>  - Set a global option value")
        print("unsetg <opt>      - Clear a global option value")
        print("goptions          - Show global options")

    def do_exit(self, arg):
        print("[*] Exiting the Caesar Operator Console. Goodbye!")
        return True
    def default(self, arg):
        print("Unknown command: " + arg +". Type 'help' to see available commands.")

    def do_tools(self, arg):
        print("Available tools:")
        name_width = max(len(tool_name) for tool_name in self.tools)
        for tool_name, tool_info in self.tools.items():
            print(f" - {tool_name:<{name_width}}  {tool_info['description']}")

    def do_select(self, arg):
        if(arg.strip() == ""):
            print("[!] Usage: select <tool>")
            return False
        tool = arg.split()[0]
        if self.current_tool:
            self.reset_options()
        if tool in self.tools:
            self.current_tool = tool
            self.apply_global_options()
            print(f"[+] Selected tool: {tool}")
            self.prompt = 'caesar (' + tool + ') > '
        else:
            print(f"[!] Tool not found: {tool}")
            print("Use 'tools' command to see available tools.")

    def complete_select(self, text, line, begidx, endidx):
        return self.complete_tool_names(text)

    def do_deselect(self, arg):
        if self.current_tool is None:
            print("[!] No tool is currently selected.")
        else:
            print(f"[-] Deselected tool: {self.current_tool}")
            tool = self.get_current_tool()
            self.reset_options()
            self.current_tool = None
            self.prompt = 'caesar > '

    def do_options(self, arg):
        if not self.check_if_tool_selected():
            return False
        print("Options for " + self.current_tool + ":")
        tool = self.get_current_tool()
        self.print_tool_options(tool)

    def do_set(self, arg):
        if not self.check_if_tool_selected():
            return False
        if(arg.strip() == ""):
            print("[!] Usage: set <option> <value>")
            return False
        parts = arg.split()
        if(len(parts) < 2):
            print("[!] Usage: set <option> <value>")
            return False
        option_name = parts[0].upper()
        option_value = " ".join(parts[1:])
        tool_options = self.get_current_tool()["options"]
        if option_name in tool_options:
            is_valid, error_msg = self.validate_option_value(option_name, tool_options[option_name], option_value)
            if not is_valid:
                print(f"[!] Invalid value for option '{option_name}': {error_msg}")
                return False
            tool_options[option_name]["value"] = option_value
            print(f"[+] Set {option_name} => {option_value}")
        else:
            print(f"[!] Option not found: {option_name}")
            print("Use 'options' command to see available options for the selected tool.")

    def do_setg(self, arg):
        if not arg.strip():
            print("[!] Usage: setg <option> <value>")
            return False
        parts = arg.split()
        if len(parts) < 2:
            print("[!] Usage: setg <option> <value>")
            return False

        option_name = parts[0].upper()
        option_value = " ".join(parts[1:])

        self.global_options[option_name] = option_value
        print(f"[+] Global option {option_name} => {option_value}")

        self.apply_global_options()        

    def do_check(self, arg):
        """check if required system dependencies exist for selected tool."""
        if not self.check_if_tool_selected():
            return False
        tool = self.get_current_tool()
        dependencies = tool.get("dependencies", [])

        all_met = True
        for dependency in dependencies:
            binary_path = shutil.which(dependency)
            if not binary_path:
                print("[-] Missing dependency: "+dependency+". Please install it to run module.")
                all_met = False

        if all_met:
            print(f"[+] All module dependencies met for {self.current_tool}.")
        else:
            return False

    def complete_set(self, text, line, begidx, endidx):
        return self.complete_option_names(text)
    
    def complete_setg(self, text, line, begidx, endidx):
        all_options = set()
        for tool_info in self.tools.values():
            all_options.update(tool_info["options"].keys())
        return [opt for opt in all_options if opt.startswith(text.upper())]

    def do_unset(self, arg):
        if not self.check_if_tool_selected():
            return False
        if(arg.strip() == ""):
            print("[!] Usage: unset <option>")
            return False
        option_name = arg.split()[0].upper()
        tool_options = self.get_current_tool()["options"]
        if option_name in tool_options:
            tool_options[option_name]["value"] = None
            print(f"[-] Unset local option {option_name}")
        else:
            print(f"[!] Option not found: {option_name}")
            print("Use 'options' command to see available options for the selected tool.")

    def do_unsetg(self, arg):
        if not arg.strip():
            print("[!] Usage: unsetg <option>")
            return False
            
        option_name = arg.split()[0].upper()
        
        if option_name in self.global_options:
            old_val = self.global_options[option_name]
            del self.global_options[option_name]
            print(f"[-] Unset global option {option_name}")
            
            for tool_name, tool_info in self.tools.items():
                if option_name in tool_info["options"]:
                    if tool_info["options"][option_name]["value"] == old_val:
                        tool_info["options"][option_name]["value"] = tool_info["options"][option_name]["default"]
        else:
            print(f"[!] Global option {option_name} is not set.")


    def complete_unset(self, text, line, begidx, endidx):
        return self.complete_option_names(text)

    def complete_unsetg(self, text, line, begidx, endidx):
        return [opt for opt in self.global_options.keys() if opt.startswith(text.upper())]

    def do_reset(self, arg):
        if not self.check_if_tool_selected():
            return False
        self.reset_options()
        print("[-] Reset all options to default values.")

    def do_goptions(self, arg):
        print("Global Options:")
        if not self.global_options:
            print("  No global options set.")
            return
        print(f"{'OPTION':<30}{'VALUE':<20}")
        print("-" * 50)
        for opt, val, in self.global_options.items():
            print(f"{opt:<30}{val:<20}")

    def build_command_string(self, tool: ToolSchema) -> List[str]:
        command = []
        command.append(tool["entry"])
        for option_name in tool["argument_order"]:
            option_info = tool["options"][option_name]
            if option_info["value"] is None: # if not required and set to none
                continue
            flag = option_info.get("flag")
            type = option_info.get("type", "string")

            if flag and type == "boolean": # if boolean flag and set to true, add flag to command, if false skip
                val = option_info["value"]
                if val.lower() in ["true", "yes", "1"]:
                    command.append(flag)
                continue

            if flag: # either required or not required and set, check if has flag (should be for optional options)
                command.append(flag)
            command.append(str(option_info["value"]))
        return command

    def do_info(self, arg):
        if arg.strip() == "":
            if not self.check_if_tool_selected():
                print("[!] Usage: info <tool>")
                return False
            else:
                arg = self.current_tool
        tool = arg.split()[0]
        if tool not in self.tools:
            print(f"[!] Tool not found: {tool}")
            print("Use 'tools' command to see available tools.")
            return False
        tool = self.tools[tool]
        print("Tool: " + tool["name"])
        print("Description: " + tool["description"])
        print("Entry: " + tool["entry"])
        print("Options:")
        self.print_tool_options(tool)

    def complete_info(self, text, line, begidx, endidx):
        return self.complete_tool_names(text)

    def do_save(self, arg):
        if not self.check_if_tool_selected():
            return False
        tool = self.get_current_tool()
        required_unset_options = self.get_required_unset_options(tool)
        if required_unset_options:
            print("[!] Cannot save options. Required options are not set:")
            for option_name in required_unset_options:
                print(f" - {option_name}")
            return False
        data = self.load_saved_settings()
        saved_options = {} # create a dictionary of options for currently selected tool
        for option_name, option_info in tool["options"].items():
            saved_options[option_name] = option_info["value"]
        data[self.current_tool] = saved_options # key: tool, value: dictionary containing values of options
        self.write_saved_settings(data)
        print(f"[+] Saved settings for {self.current_tool}")

    def do_load(self, arg):
        if not self.check_if_tool_selected():
            return False
        tool = self.get_current_tool()
        data = self.load_saved_settings()
        if self.current_tool not in data:
            print(f"[!] No saved settings found for {self.current_tool}")
            return False
        
        saved_options = data[self.current_tool]
        for option_name, option_value in saved_options.items():
            tool["options"][option_name]["value"] = option_value
        print(f"[+] Loaded settings for {self.current_tool}")

    def do_run(self, arg):
        """execute selected tool in foreground or background mode."""
        if not self.check_if_tool_selected():
            return False
        tool = self.get_current_tool()
        required_unset_options = self.get_required_unset_options(tool)
        if required_unset_options:
            print("[!] Cannot run tool. Required options are not set:")
            for option_name in required_unset_options:
                print(f" - {option_name}")
            return False
        print("[*] Running " + self.current_tool)
        self.print_tool_options(tool)
        command = self.build_command_string(tool)
        print(f"[*] Executing:\n{' '.join(command)}")
        print("-" * 50)
        if self.do_check(None) is False:
            return False

        is_background = "-b" in arg.split()
        if is_background:
            process, log_path = run_module_and_log(self.current_tool, command, background=True)
            job_id = self.job_counter
            self.jobs[job_id] = {
                "id": job_id,
                "tool": self.current_tool,
                "status": "Running",
                "log_path": log_path,
                "process": process
            }
            self.job_counter += 1
            print(f"[+] Started background job [{job_id}] for {self.current_tool}")
        else:
            run_module_and_log(self.current_tool, command, background=False)

    def do_jobs(self,arg):
        """list active and completed background jobs."""
        if not self.jobs:
            print("  No background jobs.")
            return
        
        print(f"{'JOB_ID':<10}{'TOOL':<20}{'STATUS':<15}{'LOG FILE':<40}")
        print("-" * 85)
        for job_id, job in self.jobs.items():
            if job["status"] == "Running":
                if job["process"].poll() is not None:
                    job["status"] = "Finished"
            print(f"[{job_id}]       {job['tool']:<20}{job['status']:<15}{job['log_path']:<40}")
            
    def do_output(self, arg):
        """display execution log output for a background job."""
        if not arg.strip():
            print("[!] Usage: output <job_id>")
            return
        try:
            job_id = int(arg.strip())
            if job_id not in self.jobs:
                print(f"[!] Job [{job_id}] not found.")
                return
            log_path = self.jobs[job_id]["log_path"]
            if os.path.exists(log_path):
                print(f"--- Output for Job [{job_id}] ({self.jobs[job_id]['tool']}) ---")
                with open(log_path, "r", encoding="utf-8") as f:
                    print(f.read())
            else:
                print(f"[!] Log file not found: {log_path}")
        except ValueError:
            print("[!] Job ID must be an integer.")

    def do_kill(self, arg):
        """terminate a running background job by job id."""
        if not arg.strip():
            print("[!] Usage: kill <job_id>")
            return
        try:
            job_id = int(arg.strip())
            if job_id not in self.jobs:
                print(f"[!] Job [{job_id}] not found.")
                return
            job = self.jobs[job_id]
            if job["process"].poll() is None:
                job["process"].kill()
                job["status"] = "Terminated"
                print(f"[-] Terminated job [{job_id}] ({job['tool']}).")
            else:
                print(f"[!] Job [{job_id}] is already finished.")
        except ValueError:
            print("[!] Job ID must be an integer.")


if __name__ == '__main__':
    CaesarConsole().cmdloop()
