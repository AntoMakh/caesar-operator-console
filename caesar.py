import cmd
import subprocess
from module_loader import load_modules
import json
import os

class CaesarConsole(cmd.Cmd):
    intro = "Welcome to the Caesar Operator Console. Type help to list commands.\n"
    prompt = 'caesar > '
    settings_file = ".caesar_settings.json"

    def __init__(self):
        super().__init__()
        self.tools = load_modules()

    current_tool = None

    def check_if_tool_selected(self):
        if self.current_tool is None:
            print("No tool is currently selected. Use 'select <tool>' to select a tool.")
            return False
        return True

    def get_current_tool(self):
        return self.tools[self.current_tool]

    def reset_options(self):
        tool_options = self.get_current_tool()["options"]
        for option_info in tool_options.values():
            option_info["value"] = option_info["default"]

    def complete_tool_names(self, text):
        matches = []
        for tool_name in self.tools:
            if tool_name.startswith(text):
                matches.append(tool_name)
        return matches

    def complete_option_names(self, text):
        if self.current_tool is None:
            return []

        matches = []
        tool_options = self.get_current_tool()["options"]
        for option_name in tool_options:
            if option_name.startswith(text.upper()):
                matches.append(option_name)
        return matches

    def format_option_value(self, value):
        if value is None:
            return "-"
        return str(value)

    def print_tool_options(self, tool):
        print(f"{'OPTION':<30}{'VALUE':<20}REQUIRED")
        for option_name, option_info in tool["options"].items():
            required = "yes" if option_info["required"] else "no"
            value = self.format_option_value(option_info["value"])
            print(f"{option_name:<30}{value:<20}{required}")
            description = option_info.get("description", "")
            if description:
                print(f"  {description}")

    def get_required_unset_options(self, tool):
        tool_options = tool["options"]
        required_unset_options = []
        for option_name, option_info in tool_options.items():
            if option_info["required"] and option_info["value"] is None:
                required_unset_options.append(option_name)
        return required_unset_options

    def load_saved_settings(self):
        if not os.path.isfile(self.settings_file):
            return {}
        with open(self.settings_file, "r") as f:
            return json.load(f)

    def write_saved_settings(self, data):
        with open(self.settings_file, "w") as f:
            json.dump(data, f, indent=4)

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
        print("run               - Execute tool")
        print("exit              - Exit console")

    def do_exit(self, arg):
        print("Exiting the Caesar Operator Console. Goodbye!")
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
            print("Usage: select <tool>")
            return False
        tool = arg.split()[0]
        if self.current_tool:
            self.reset_options()
        if tool in self.tools:
            self.current_tool = tool
            print("Selected tool: " + tool)
            self.prompt = 'caesar (' + tool + ') > '
        else:
            print("Tool not found: " + tool)
            print("Use 'tools' command to see available tools.")

    def complete_select(self, text, line, begidx, endidx):
        return self.complete_tool_names(text)

    def do_deselect(self, arg):
        if self.current_tool is None:
            print("No tool is currently selected.")
        else:
            print("Deselected tool: " + self.current_tool)
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
            print("Usage: set <option> <value>")
            return False
        parts = arg.split()
        if(len(parts) < 2):
            print("Usage: set <option> <value>")
            return False
        option_name = parts[0].upper()
        option_value = " ".join(parts[1:])
        tool_options = self.get_current_tool()["options"]
        if option_name in tool_options:
            tool_options[option_name]["value"] = option_value
            print("Set " + option_name + " to " + option_value)
        else:
            print("Option not found: " + option_name)
            print("Use 'options' command to see available options for the selected tool.")

    def complete_set(self, text, line, begidx, endidx):
        return self.complete_option_names(text)
    
    def do_unset(self, arg):
        if not self.check_if_tool_selected():
            return False
        if(arg.strip() == ""):
            print("Usage: unset <option>")
            return False
        option_name = arg.split()[0].upper()
        tool_options = self.get_current_tool()["options"]
        if option_name in tool_options:
            tool_options[option_name]["value"] = None
            print("Unset " + option_name)
        else:
            print("Option not found: " + option_name)
            print("Use 'options' command to see available options for the selected tool.")

    def complete_unset(self, text, line, begidx, endidx):
        return self.complete_option_names(text)

    def do_reset(self, arg):
        if not self.check_if_tool_selected():
            return False
        self.reset_options()
        print("Reset all options to default values.")

    def build_command_string(self, tool):
        command = []
        command.append(tool["entry"])
        for option_name in tool["argument_order"]:
            option_value = tool["options"][option_name]
            if option_value["value"] is not None:
                command.append(str(option_value["value"]))
        return command

    def do_info(self, arg):
        if arg.strip() == "":
            print("Usage: info <tool>")
            return False
        tool = arg.split()[0]
        if tool not in self.tools:
            print("Tool not found: " + tool)
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
            print("Cannot save options. Required options are not set:")
            for option_name in required_unset_options:
                print(f" - {option_name}")
            return False
        data = self.load_saved_settings()
        saved_options = {} # create a dictionary of options for currently selected tool
        for option_name, option_info in tool["options"].items():
            saved_options[option_name] = option_info["value"]
        data[self.current_tool] = saved_options # key: tool, value: dictionary containing values of options
        self.write_saved_settings(data)
        print(f"Saved settings for {self.current_tool}")

    def do_load(self, arg):
        if not self.check_if_tool_selected():
            return False
        tool = self.get_current_tool()
        data = self.load_saved_settings()
        if self.current_tool not in data:
            print(f"No saved settings found for {self.current_tool}")
            return False
        
        saved_options = data[self.current_tool]
        for option_name, option_value in saved_options.items():
            tool["options"][option_name]["value"] = option_value
        print(f"Loaded settings for {self.current_tool}")

    def do_run(self, arg):
        if not self.check_if_tool_selected():
            return False
        tool = self.get_current_tool()
        required_unset_options = self.get_required_unset_options(tool)
        if required_unset_options:
            print("Cannot run tool. Required options are not set:")
            for option_name in required_unset_options:
                print(f" - {option_name}")
            return False
        print("Running " + self.current_tool)
        self.print_tool_options(tool)
        command = self.build_command_string(tool)
        print("Executing:\n" + " ".join(command))
        try:
            subprocess.run(command, check=True)
        except subprocess.CalledProcessError:
            print("[!] Tool execution failed.")
        except FileNotFoundError:
            print("[!] Module entry file not found.")
        except Exception as e:
            print(f"[!] An error occurred: {e}")
            

if __name__ == '__main__':
    CaesarConsole().cmdloop()
