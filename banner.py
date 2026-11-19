"""ASCII boot banner for the Caesar Operator Console."""

# Dark-mode palette: gold laurel wreath, white head, red CAESAR.
GOLD = "\033[38;5;220m"
WHITE = "\033[97m"
RED = "\033[1;38;5;196m"
DIM = "\033[2m"
RESET = "\033[0m"

# Braille portrait; do not reflow or edit these characters.
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

# Per-cell laurel mask taken from the reference art: G = gold leaf, H = head.
MASK = """          HHHGGGGGG   GH      
        HHHHHGGG GGGGGGH      
      HHGGGGG GG GG GGGGH     
      HHGG GG GG  GGGGGHH     
     GGGGG GGGGGGG GGHHHH     
     GG GGGGGGG HHHHHHHHHH    
  GGGHGGGGGG HHHHHHHHHHHHHH   
  GG HHHHHHHHHHHHHHHHHHHHHH   
      HHHHHHHHHHHHHHHHHHH     
       HHHHHHHHHHHHHHHHHH     
        HHHHHHHHHHHHHHHHH     
       HHHHHHHHHHHH           
       HHHHHHHHHHH            
            HHHHH             """

LETTERS = r"""   _________    ___________ ___    ____
  / ____/   |  / ____/ ___//   |  / __ \
 / /   / /| | / __/  \__ \/ /| | / /_/ /
/ /___/ ___ |/ /___ ___/ / ___ |/ _, _/
\____/_/  |_/_____//____/_/  |_/_/ |_|"""

def _colorize_portrait() -> str:
    """Color each braille cell from MASK: gold laurel leaves, white head."""
    out = []
    for art_line, mask_line in zip(PORTRAIT.split("\n"), MASK.split("\n")):
        buf = []
        current = None
        for ch, flag in zip(art_line, mask_line):
            if ord(ch) <= 0x2800:
                color = None
            elif flag == "G":
                color = GOLD
            else:
                color = WHITE
            if color != current:
                if current is not None:
                    buf.append(RESET)
                if color is not None:
                    buf.append(color)
                current = color
            buf.append(ch)
        if current is not None:
            buf.append(RESET)
        out.append("".join(buf))
    return "\n".join(out)


def render_banner(module_count: int, workflow_count: int) -> str:
    """Return the full boot banner, colored for the terminal, with live counts."""
    return (
        "\n"
        + _colorize_portrait() + "\n\n"
        + RED + LETTERS + RESET + "\n\n"
        + GOLD + "          Caesar Operator Console" + RESET + "\n"
        + DIM + f"     =[ modules: {module_count}    workflows: {workflow_count} ]=" + RESET + "\n"
        + DIM + "         Type help to list commands." + RESET + "\n"
    )
