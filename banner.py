"""ASCII boot banner for the Caesar Operator Console."""

# Laurel wreath in gold; the head keeps the terminal's default color; CAESAR in red.
GOLD = "\033[38;5;220m"
RED = "\033[1;38;5;196m"
DIM = "\033[2m"
RESET = "\033[0m"

# Braille block art; do not reflow or edit these characters.
PORTRAIT = r"""⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣶⣿⣿⢿⡶⠆⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⡿⠻⠋⣠⠀⢀⣶⠇⢠⣾⡿⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣼⠟⠋⠻⢁⣴⠀⣾⣿⠀⠾⠟⠀⠈⣉⣠⣦⡤⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠸⠃⣠⡆⠀⣿⡟⠀⠛⠃⠀⠀⣶⣶⣦⣄⠉⢁⡄⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣰⡀⢰⣿⠇⠀⢉⣀⣀⠛⠿⠿⠦⠀⢀⣠⣤⣴⣾⡇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣿⠃⠀⠠⣴⣦⡈⠙⠛⠓⠀⢰⣶⣶⣿⣿⣿⣿⣿⣧⡀⠀⠀⠀⠀
⠀⠀⢀⣤⠦⡀⠰⢷⣦⠈⠉⠉⠀⣰⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀
⠀⠀⠈⠁⠀⠘⣶⣤⣄⣀⣨⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠃⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⣿⣯⡈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢨⣿⣿⣿⣷⣤⣈⡉⠛⠛⠛⠛⠻⠟⠛⠛⠛⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠙⠻⠿⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"""

LETTERS = r"""   _________    ___________ ___    ____
  / ____/   |  / ____/ ___//   |  / __ \
 / /   / /| | / __/  \__ \/ /| | / /_/ /
/ /___/ ___ |/ /___ ___/ / ___ |/ _, _/
\____/_/  |_/_____//____/_/  |_/_/ |_|"""

# Sparse braille strokes are the laurel leaves; dense cells are the solid head.
_LEAF_MAX_DOTS = 5


def _colorize_portrait(art: str) -> str:
    """Color the laurel wreath gold and leave the head in the terminal default."""
    lines = []
    for line in art.split("\n"):
        buf = []
        current = None
        for ch in line:
            code = ord(ch) - 0x2800
            dots = bin(code).count("1") if code > 0 else 0
            if 0 < dots <= _LEAF_MAX_DOTS:
                color = GOLD
            else:
                color = None
            if color != current:
                if current is not None:
                    buf.append(RESET)
                if color is not None:
                    buf.append(color)
                current = color
            buf.append(ch)
        if current is not None:
            buf.append(RESET)
        lines.append("".join(buf))
    return "\n".join(lines)


def render_banner(module_count: int, workflow_count: int) -> str:
    """Return the full boot banner, colored for the terminal, with live counts."""
    return (
        "\n"
        + _colorize_portrait(PORTRAIT) + "\n\n"
        + RED + LETTERS + RESET + "\n\n"
        + GOLD + "          Caesar Operator Console" + RESET + "\n"
        + DIM + f"     =[ modules: {module_count}    workflows: {workflow_count} ]=" + RESET + "\n"
        + DIM + "         Type help to list commands." + RESET + "\n"
    )
