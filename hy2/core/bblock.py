#--------------------------------------
# File: bblock.py
#
# Purpose: Basic blocks translation (machine code to IR) using for static analysis
#--------------------------------------

import pyvex
import archinfo
import json
import re
from colorama import Fore
import hy2.core.constants as cc
import hy2.core.utils as utils
# ----------------------------------------
sub_regs = {"ah": ("rax", "16s"), "al": ("rax", "8s"), "bh": ("rbx", "16s"), "bl": ("rbx", "8s"), "ch": ("rcx", "16s"), "cl": ("rcx", "8s"), "dh": ("rdx", "16s"), "dl": ("rdx", "8s"),  "ax": ("rax", "16m"), "bx": ("rbx", "16m"), "cx": ("rcx", "16m"), "dx": ("rdx", "16m"), "eax": ("rax", "32l"), "ebx": ("rbx", "32l"), "edx": ("rdx", "32l")}

def get_eip_range(x, l):
    pc = int(x)
    s = []
    s.append(hex(pc))
    for z in l:
        pc += int(z)
        s.append(hex(pc))
    return s

class IRBlock:
    def __init__(self):
        self.pc = 0
        self.fname = ""
        
        self.pcs = []
        self.bid = ""
        self.tid = 0

        self.next = None
        self.next_fname = ""
        
        self.jump_kind = None
        self.var_table = {}
        self.var_list = []
        self.types = []

        self.is_cond = False
        self.ip_offset = 0
        self.jmp_iff = 0
        self.jmp_ift = 0

        self.return_addr = 0
    
    def toStr(self):
        for k,v in self.var_table.items():
            print(f'{k}: {v}')
        print(self.var_list)

# This function is identical to the one in ir.py
def decode_block(b, tyenv):
    idx = -1
    j = 0
    dtypes = tyenv.types
    for i in range(len(b.statements)):
        st = b.statements[i]
        if type(st) == pyvex.IRStmt.IMark:
            idx += 1
            assert (str(st.addr)) == str(b.pcs[idx])

        elif type(st) == pyvex.IRStmt.AbiHint:
            continue
        elif type(st) == pyvex.IRStmt.WrTmp:
            tmp = "t"+str(st.tmp)
            dat = str(st.data)
            # TODO: Add check that opcode is handled correctly
            if "amd64" in dat:
                pass
            op = ""
            args = ""
            t = "u"
            if "(" in dat:
                x = dat.split("(")
                op = x[0]
                args = x[-1][:-1]
                if "," in args:
                    t = "b"
            else:
                args = dat

            if "amd64" in dat and "calculate_condition" in dat:
                b.var_table[tmp] = {}
                op, arg1, arg2 = cc.encode_cpu_guest_ops(args.split(","))
                b.var_table[tmp]["op"] = [op, arg1+","+arg2]
                b.var_table[tmp]["t"] = "b"
                b.var_table[tmp]['pc'] = b.pcs[idx]
                b.var_list.append(tmp)
                dti = dtypes[j]
                b.types.append(dti)
                j += 1

            elif "GET" in dat:
                r = archinfo.ArchAMD64().translate_register_name(st.data.offset, st.data.result_size(tyenv)//8)
                if r == "d":
                    r = "rcx"
                if r in sub_regs:
                    stmp = "sr"+r
                    ops = sub_regs[r]
                    b.var_table[stmp] = {}
                    b.var_table[stmp]["op"] = [cc.encode_operation("SS"), ops[0]+","+ops[1]]
                    b.var_table[stmp]["t"] = "b"
                    b.var_table[stmp]["pc"] = b.pcs[idx]

                    b.var_list.append(stmp)
                    dti = dtypes[j]
                    b.types.append(dti)
                    j += 1
                    args = stmp
                else:
                    args = r
            elif dat[:4] == "GetI":
                opc = dat[:4]
                dt = dat[4:]
                assert dt[0] == '(' and dt[-1] == ']'
                p = dt.split(')[')
                descr = p[0][1:]
                ridx = p[1][:-1]
                b.var_table[tmp] = {}
                b.var_table[tmp]["op"] = [cc.encode_x87_fp_op(opc), ridx]
                b.var_table[tmp]["t"] = "b"
                b.var_table[tmp]["pc"] = b.pcs[idx]
                b.var_list.append(tmp)
                dti = dtypes[j]
                b.types.append(dti)
                j += 1
                continue
            
            elif op[:3] == "Add" or op[:3] == "Sub":
                pvid = args.split(",")[0]
                operr = args.split(",")[1]
                if (len("0xffffffffffffffff") == len(operr) and operr[:3] =="0xf") and pvid in b.var_table:
                    # and b.var_table[pvid]["op"][0][0] == cc.GET_OP and b.var_table[pvid]["op"][1] == "rbp":
                    b.var_table[tmp] = {}
                    if op[:3] == "Sub":
                        op = "Add" + op[3:]
                    elif op[:3] == "Add":
                        op = "Sub" + op[3:]

                    # TODO: FIXME:
                    d = str(hex((2**64) - int(operr, 16)))
                    b.var_table[tmp]["op"] = [
                        cc.encode_operation(op), f'{pvid},{d}']
                    b.var_table[tmp]["t"] = t
                    b.var_table[tmp]["pc"] = b.pcs[idx]
                    b.var_list.append(tmp)
                    dti = dtypes[j]
                    b.types.append(dti)
                    j += 1
                    continue
            
            if not tmp in b.var_table:
                if op == "":
                    op = "SET"
                b.var_table[tmp] = {}
                b.var_table[tmp]["op"] = [cc.encode_operation(op), args]
                b.var_table[tmp]["t"] = t
                b.var_table[tmp]["pc"] = b.pcs[idx]
                b.var_list.append(tmp)
                dti = dtypes[j]
                b.types.append(dti)
                j += 1
        elif type(st) == pyvex.IRStmt.Put:
            r = archinfo.ArchAMD64().translate_register_name(st.offset, st.data.result_size(tyenv)//8)
            args = r
            if args == "rip":
                continue

            if not args in b.var_table:
                b.var_table[args] = []
            
            b.var_table[args].append({"op": [cc.encode_operation("Put"), str(st.data)], "t": "u", "pc": b.pcs[idx]})

            b.var_list.append(args)
            dti = "Ity_I64"
            b.types.append(dti)
            
        elif type(st) == pyvex.IRStmt.Store:
            mid = "m"+str(st.addr)
            b.var_table[mid] = {}
            op = "Stle"
            opcode = cc.encode_operation(op)
            b.var_table[mid]["op"] = [opcode, str(st.addr)+","+str(st.data)]
            b.var_table[mid]["t"] = "b"
            b.var_table[mid]["pc"] = b.pcs[idx]
            b.var_list.append("m"+str(st.addr))
            dti = "Ity_I64"
            b.types.append(dti)
        elif type(st) == pyvex.IRStmt.Exit:
            g = str(st.guard)
            offs  = st.offsIP
            r = archinfo.ArchAMD64().translate_register_name(offs, archinfo.ArchAMD64().bits//8)
            if not r is None:
                b.sym_next = r
            gkey = "c"+g
            b.var_table[gkey] = {}
            b.var_table[gkey]["op"] = [cc.encode_operation("SET"), g]
            b.var_table[gkey]["t"] = "u"
            b.var_table[gkey]["pc"] = b.pcs[idx]
            b.var_list.append(gkey)
            
            b.is_cond = True
            b.offset_ip = offs
            b.jmp_iff = b.next
            b.jmp_ift = st.dst.value

            dti = dtypes[j]
            b.types.append(dti)
            j += 1
        elif type(st) == pyvex.IRStmt.PutI:
            op_str = str(st)
            opc = op_str[:4]
            rs = str(st.data)
            dt = op_str[4:].split("=")[0].rstrip()
            assert dt[0] == '(' and dt[-1] == ']'
            p = dt.split(')[')
            offs = p[0][1:].split(':')[0]
            vtmp = 'tf'+offs
            ridx = p[1][:-1]
            b.var_table[vtmp] = {}
            b.var_table[vtmp]["op"] = [cc.encode_x87_fp_op(opc), ridx+','+rs]
            b.var_table[vtmp]["t"] = "b"
            b.var_table[vtmp]["pc"] = b.pcs[idx]

            b.var_list.append(vtmp)
            dti = "Ity_I64"
            b.types.append(dti)

        elif type(st) == pyvex.IRStmt.Dirty:
            print(st)
            continue
        elif type(st) == pyvex.IRStmt.MBE:
            print(st)
            continue
        elif type(st) == pyvex.IRStmt.CAS:
            print(st)
            continue
        else:
            print(Fore.RED+"Error: "+str(type(st))+Fore.RESET)
            raise Exception()
    return       


def translate_block(fname, opcodes, pc, sizes, arch):
    if arch == 'i386':
        irsb = pyvex.lift(opcodes, int(pc), archinfo.ArchX86())
    else:
        irsb = pyvex.lift(opcodes, int(pc), archinfo.ArchAMD64())

    bl = IRBlock()
    bl.fname = fname
    if not len(sizes) == 0:
        bl.pcs = get_eip_range(pc, sizes)
    else:
        bl.pcs = [x.addr for x in irsb.statements if type(x) == pyvex.IRStmt.IMark]
        if len(bl.pcs) == 0:
            bl.pcs.append(pc)

    bl.statements = irsb.statements    
    bl.types = irsb.tyenv.types
    bl.next = utils.to_int(irsb.next)
    bl.jump_kind = str(irsb.jumpkind)
    if bl.jump_kind == "Ijk_Call":
        if type(bl.statements[-3]) == pyvex.IRStmt.Store:
            stdata = bl.statements[-3].data
            stdata = utils.to_int(str(stdata))
            if type(stdata) == int:
                bl.return_addr = stdata
    
    # decode block
    decode_block(bl, irsb._tyenv)
    return bl