import cmd

class CaesarConsole(cmd.Cmd):
    intro = "Welcome to the Caesar Operator Console. Type help to list commands.\n"
    prompt = 'caesar > '
    
    tools = {
        "bismarck": {
            "description": "Bismarck service banner grabber",
            "options": {
                
            }
        },
        "napoleon": {
            "description": "Napoleon DNS Zone Transfer checker",
            "options": {
                "DOMAIN": {
                    "value": None,
                    "required": True
                }
            }
        },
        "judas": {
            "description": "Judas flag keyword Source Code grabber from directories",
            "options": {
                
            }
        }
    }

    current_tool = None


    def check_if_tool_selected(self):
        if self.current_tool is None:
            print("No tool is currently selected. Use 'select <tool>' to select a tool.")
            return False
        return True

    def do_help(self, arg):
        print("Available commands:")
        print("help - Show this help message")
        print("tools - List available tools")
        print("select <tool> - Select a tool")
        print("exit - Exit the console")
    def do_exit(self, arg):
        print("Exiting the Caesar Operator Console. Goodbye!")
        return True
    def default(self, arg):
        print("Unknown command: " + arg +". Type 'help' to see available commands.")

    def do_tools(self, arg):
        print("Available tools:")
        for tool_name, tool_info in self.tools.items():
            print(" - " + tool_name + ": " + tool_info["description"])

    def do_select(self, arg):
        if(arg.strip() == ""):
            print("Usage: select <tool>")
            return False
        tool = arg.split()[0]
        if(tool in self.tools):
            self.current_tool = tool
            print("Selected tool: " + tool)
            self.prompt = 'caesar (' + tool + ') > '
        else:
            print("Tool not found: " + tool)
            print("Use 'tools' command to see available tools.")

    def do_deselect(self, arg):
        if self.current_tool is None:
            print("No tool is currently selected.")
        else:
            print("Deselected tool: " + self.current_tool)
            self.current_tool = None
            self.prompt = 'caesar > '

    def do_options(self, arg):
        if not self.check_if_tool_selected():
            return False
        print("Options for " + self.current_tool + ":")
        tool_options = self.tools[self.current_tool]["options"]

        for option_name, option_info in tool_options.items():
            required = " (required)" if option_info["required"] else ""
            print(" - " + option_name + ": " + str(option_info["value"]) + required)


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
        option_name = parts[0]
        option_value = parts[1]
        tool_options = self.tools[self.current_tool]["options"]
        if option_name in tool_options:
            tool_options[option_name]["value"] = option_value
            print("Set " + option_name + " to " + option_value)
        else:
            print("Option not found: " + option_name)
            print("Use 'options' command to see available options for the selected tool.")



if __name__ == '__main__':
    CaesarConsole().cmdloop()