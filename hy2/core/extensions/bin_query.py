import r2pipe
import atexit
import bisect
import json
import os
import re


def open_r2pipe(file_name):
    r2 = None
    try:
        r2 = r2pipe.open(file_name, flags=['-e', 'bin.verbose=false'])

        _ = r2.cmd("aaa")
        return r2
    except Exception as e:
        print(f'ERROR: radare2 could not open {file_name}: {type(e).__name__}: {e}')
        if r2 is not None:
            try:
                r2.quit()
            except Exception:
                pass
        return None

# One analysed radare2 session per binary, shared by every
# get_instructions_for_match call, instead of a new radare2 process (and a
# full "aaa") per result. r2pipe objects are only freed by the cyclic garbage
# collector and are never quit, so opening one per result left hundreds of
# radare2 processes running until opens started failing.
# All queries use a temporary seek (cmd @ addr), so sharing is safe.
_sessions = {}

def _get_session(file_name):
    s = _sessions.get(file_name)
    if s is None:
        r2 = open_r2pipe(file_name)
        if r2 is None:
            return None     # not cached: the next call tries again
        s = {'r2': r2, 'offsets': get_ie_offset(r2), 'line_table': get_line_table(r2)}
        _sessions[file_name] = s
    return s

def _drop_session(file_name):
    s = _sessions.pop(file_name, None)
    if s is not None:
        try:
            s['r2'].quit()
        except Exception:
            pass

def close_r2pipes():
    """Quit every shared radare2 session."""
    for file_name in list(_sessions):
        _drop_session(file_name)

atexit.register(close_r2pipes)

def get_ie_offset(r2):
    ie = r2.cmd("iej")
    try:
        iej = json.loads(ie)
        if len(iej) == 1:
            return iej[0]["paddr"], iej[0]["baddr"], iej[0]["vaddr"]
        elif type(iej) == list and len(iej) == 0:
            return 0
        return iej["paddr"], iej["baddr"], iej["vaddr"]
    except Exception as e:
        print(e)
        #print(e.with_traceback())
        return -1


# Returns (context, target): `pd -N @ ip` lists the N instructions *before*
# ip (ip itself is not included), so the matched instruction is fetched
# separately with `pd 1 @ ip`.
def disassemble_instruction(r2, ip, d):
    try:
        context = r2.cmd(f"pd -{d} @ {hex(ip)}") if d > 0 else ""
        target = r2.cmd(f"pd 1 @ {hex(ip)}")
        return context, target
    except Exception as e:
        print(e)
        return "", ""

def get_function_name(r2, ip):
    try:
        function_name = r2.cmd(f"afi. @ {hex(ip)}")
        return function_name
    except Exception as e:
        print(e)
        return ""

def get_function_vars(r2, ip):
    try:
        faddr = f'afv @ {hex(ip)}'
        fvars = r2.cmd(faddr)
        return fvars
    except Exception as e:
        print(e)
        return ""

# Parses one line of `afv` output:  <var|arg> <type> <name> @ <location>
#   var int idx @ rbp-0x14
#   arg char const * restrict __fmt @ r10
#   var unsigned int[16] X @ rsp-0x30
#   arg  const * __src @ r12              (empty base type)
# The type can be any number of words (unsigned int, char **, image_t ***, ...),
# so the first word is the context, the last word before '@' is the name, and
# everything in between is the type. Same format in radare2 5.5.4 and 6.x.
def parse_vars(vars):
    line = vars.strip()
    if ' @ ' not in line:
        if line != "":
            print(f'ERROR: Parsing vars {vars}')
        return None, None, "", None

    decl, v_addr = line.split(' @ ', 1)
    parts = decl.split()
    if len(parts) < 2:
        print(f'ERROR: Parsing vars {vars}')
        return None, None, "", None

    v_ctx = parts[0]
    v_name = parts[-1]
    v_type = ' '.join(parts[1:-1])
    return v_ctx, v_type, v_name, v_addr.strip()

def fvars(vars):
    vx  = {}
    for v in vars:
        vctx, vtype, vname, vaddr = parse_vars(v)
        if not vname == "":
            vx[vname] = {"ctx": vctx, "type": vtype, "addr": vaddr}
    return vx

def match_to_code(opcodes, vars):
    for v in vars.keys():
        #if f'{v} = ' in code or f'[{v}]' in code or f'{v} <' in code or f'{v} >' in code or f'{v}[' in code:
        if f'[{v}]' in opcodes:
            return v
    return None

INSTR_RE = re.compile(r'(0x[0-9a-f]+)\s+[0-9a-f\.]+\s+([^;]+?)\s*(?:;(.*))?$')
SRC_REF_RE = re.compile(r'^\S+:\d+$')

# Parses one disassembly line: <addr> <bytes> <opcodes> [; <comment>]
# The comment starts with "<file>:<line>" when debug info is available.
def parse_instruction(instr):
    addr = ""
    opcodes = ""
    source_file = ""
    code = ""
    m = INSTR_RE.search(instr.strip())
    if m:
        addr = m.group(1)
        opcodes = m.group(2).strip()
        comment = (m.group(3) or "").strip()
        p = comment.split(" ", 1)
        if SRC_REF_RE.match(p[0]):
            source_file = p[0]
            code = p[1].strip() if len(p) > 1 else ""

    return addr, opcodes, source_file, code

def instruction_lines(instr):
    # drop r2's flow-graph gutter (│ └ ┌ ...) in front of the address
    lines = [l[l.find('0x'):].strip() for l in instr.split('\n') if '0x' in l]
    return [l for l in lines if INSTR_RE.search(l)]

def format_instructions(context, target):
    return '\n'.join(instruction_lines(context) + instruction_lines(target))

# addr/opcodes come from the matched instruction. r2 only annotates the first
# instruction of each source line, so when it has no source reference use the
# line table entry (line_ref), then the nearest preceding annotated instruction.
def parse_instructions(context, target, line_ref=""):
    tlines = instruction_lines(target)
    if not tlines:
        return "", "", "", ""
    addr, opcodes, source_file, code = parse_instruction(tlines[0])

    if source_file == "" and line_ref != "":
        source_file = line_ref

    if source_file == "":
        for l in reversed(instruction_lines(context)):
            _, _, sf, c = parse_instruction(l)
            if sf != "":
                source_file, code = sf, c
                break

    return addr, opcodes, code, source_file


# DWARF line table as a sorted [(addr, "file:line")], from `CLj`.
def get_line_table(r2):
    try:
        rows = json.loads(r2.cmd("CLj") or "[]")
        table = [(r["addr"], f'{os.path.basename(r["file"])}:{r["line"]}') for r in rows
                 if "addr" in r and "file" in r and "line" in r]
        table.sort()
        return table
    except Exception as e:
        print(e)
        return []

# Source line of the closest line-table entry at or before ip.
def lookup_source_line(table, ip):
    i = bisect.bisect_right(table, (ip, chr(0x10ffff))) - 1
    if i >= 0:
        return table[i][1]
    return ""

def get_instructions_for_match(target_file, pcs, entry_point):
    session = _get_session(target_file)
    if session == None:
        return {}, {}
    try:
        return _instructions_for_match(session, pcs, entry_point)
    except Exception:
        # a broken session (e.g. radare2 died) would fail every later
        # result too; drop it so the next call opens a fresh one
        _drop_session(target_file)
        raise

def _instructions_for_match(session, pcs, entry_point):
    r2 = session['r2']
    ie, ba, va = session['offsets']
    line_table = session['line_table']
    instrs = []
    vars = []
    funcs = []
    print(f'entry point: {hex(entry_point)}')
    #print("check ")
    for (pc, d) in pcs:
        if pc == "":
            # keep instrs/funcs aligned with the matched spec steps
            instrs.append({"addr": "", "opcodes": "", "code": "", "source_file": "", "raw": ""})
            funcs.append("")
            continue
        #print(hex(pc))
        #print(hex(abs(pc - entry_point)))
        #print(f'Entry Point: {hex(entry_point)}, haddr: {hex(ie)}, baddr: {hex(ba)}')
        if entry_point == va:
            ip = pc
        elif entry_point == ie or entry_point == 0:
            ip = pc + ba
        else:
            ip = abs(pc - (entry_point - ie))
        
        print(f'Bin IP: {hex(ip)}')
        ctx, tgt = disassemble_instruction(r2, ip, d)
        print(ctx + tgt)
        a, o, c, sf = parse_instructions(ctx, tgt, lookup_source_line(line_table, ip))
        #print(f'Address: {a} Opcodes: {o} Code: {c} Source File: {sf}')
        #print((x))
        vars = get_function_vars(r2, ip)
        vars = vars.split('\n')
        vars = fvars(vars)
        v = match_to_code(o, vars)
        

        func = get_function_name(r2, ip)
        #instrs.append(x)
        instrs.append({"addr": a, "opcodes": o, "code": c, "source_file": sf, 'raw': format_instructions(ctx, tgt)})
        #print(instrs)
        if not v == None:
            #vars.append(vars[v])
            vobj = vars[v]
            vobj['name'] = v
            instrs[-1]["var"] = vobj
        
        funcs.append(func)
    #print(funcs)
    return instrs, funcs