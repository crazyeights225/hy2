from rich.panel import Panel
from rich import print as rprint
from rich.console import Console
from rich.table import Table
import hy2.core.var_types as vart
import hy2.core.utils as utils

def banner():
    print("""
                ___
               /o _)
      _.----._/ /
     /         /
  __/ \  | \  |
 /__.-'|_|--|_|
    """)
    panel = Panel.fit("[bold]Hy2", border_style="cyan")
    rprint(panel)

def playBanner(arch, target, recording_name, image_type, bin_type, command):
    table = Table(box=None)
    table.add_row('Arch:', arch)
    table.add_row('Target: ', target)
    table.add_row('Recording Name:', recording_name)
    table.add_row('Image Type:', image_type)
    table.add_row('Bin Type:', bin_type)
    cmdStr = '\n'.join([str(c) for c in command])
    table.add_row('Command:', cmdStr)

    console = Console()
    console.print(table)

def replayBanner(runtime_name, target_page):
    table = Table(box=None)
    table.add_row('Process Name:', runtime_name)
    table.add_row('Target Pages:', str(target_page))

    console = Console()
    console.print(table)

def showConfig(properties):
    table = Table()
    for k, v in properties.items():
        table.add_row(k, str(v))
    
    console = Console()
    console.print(table)

def showVars(vars):
    table = Table()
    
    # cols:
    # vname | vec | val @ addr | extras |

    for v in vars:
        vname = v.name
        vstr = utils.vecToStr(v.vec)

        vval = ""
        if type(v.abs_addr) != vart.VEmpty:
            vval = f'{v.val} @ {v.abs_addr}'
        else:
            vval = str(v.val)

        extras = ""
        
        if v.labels == []:
            pass
        else:
            lbl_str = str(v.labels[:100])
            extras = f'use: {lbl_str} '
        if v.def_label == "" or v.def_label == []:
            pass
        else:
            extras += f'def: {str(v.def_label)} '

        if v.dtype != "":
            extras += f'dtype: {v.dtype} '
        if v.static_name != "":
            extras += f'vname: {v.static_name} '
        if v.dsource != "":
            extras += f'dsource: {v.dsource} '
        if v.dintent != "":
            extras += f'dintent: {v.dintent}'

        table.add_row(vname, vstr, vval, extras)

    console = Console()
    console.print(table)
        
