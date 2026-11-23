#--------------------------------------
# File: solver.py
#
# Purpose: Functions used in et.py for functional representation of IR expressions
#  - functions prefixed partial check the GHOST_MEM (the current program state) before MEM (the current concrete program state)
#--------------------------------------

from colorama import Fore
import hy2.core.utils as utils
import hy2.core.c_calc as c_calc
import hy2.core.constants as cc
import copy

class GhostMemMapping:
    def __init__(self):
        self.mapping = {}
    
    def put_at(self, address, value):
        self.mapping[address] = value

    def query(self, address):
        v = self.mapping[address]
        return v

    def export(self):
        return copy.copy(self.mapping)
    
    def load_saved_state(self, state):
        self.mapping = state


MEM = None
GHOST_MEM = None

def init_ghost_mem():
    global GHOST_MEM
    GHOST_MEM = GhostMemMapping()

# lookup_regs(self, pc, tid, oid, regname)
# pc - program counter
# tid - thread id
# oid - block instance id
# regname - register name
def do_get(**kwargs):
    args = kwargs['args']
    oid = args[1]
    tid = args[2]
    pc = args[3]
    ls = args[4]
    il = utils.to_int(ls)
    if type(il) == int:
        return il,None
    #print(oid)
    v, vt = MEM.lookup_regs(pc, tid, oid, ls)
    if v is None:
        return cc.Unknown(),  None
    return v, vt

def do_partial_get(**kwargs):
    args = kwargs['args']
    oid = args[1]
    tid = args[2]
    pc = args[3]
    ls = args[4]
    il = utils.to_int(ls)
    if type(il) == int:
        return il, None
    if ls in GHOST_MEM.mapping:
        v = GHOST_MEM.query(ls)
        if v is None:
            return cc.Unknown(), None
        return v, None
    v, vt = MEM.lookup_regs(pc, tid, oid, ls)
    if v is None:
        return cc.Unknown(), None
    return v, vt

def do_put(**kwargs):
    args = kwargs['args']
    ls = args[4]
    return ls, None

def do_partial_put(**kwargs):
    args = kwargs['args']
    ls = args[4]
    rs = args[5]
    global GHOST_MEM
    GHOST_MEM.put_at(ls, rs)
    return rs, None

# vmem_lookup_address(self, pc, oid, address, rw)
# pc - program counter
# oid - block instance id
# address - address
# rw - operation type - memory read or write
def do_load(**kwargs):
    args = kwargs['args']
    oid = args[1]
    tid = args[2]
    pc = args[3]
    ls = args[4]
    v, vt = MEM.vmem_lookup_address(pc, oid, utils.to_int(ls), "mr")
    if v is None:
        #print(f'{pc} {oid} VAL: {v} {vt} LS: {ls}')
        return cc.Unknown(), None
    return v, vt

def do_partial_load(**kwargs):
    args = kwargs['args']
    oid = args[1]
    tid = args[2]
    pc = args[3]
    ls = args[4]
    addr = utils.to_int(ls)
    if addr in GHOST_MEM.mapping:
        v = GHOST_MEM.query(addr)
        if v is None:
            return cc.Unknown(), None
        return v, None
    v, vt = MEM.vmem_lookup_address(pc, oid, utils.to_int(ls), "mr")
    if v is None:
        return cc.Unknown(), None
    return v, vt

def do_store(**kwargs):
    args = kwargs['args']
    oid = args[1]
    tid = args[2]
    pc = args[3]
    ls = args[4]
    rs = args[5]
    v, vt = MEM.vmem_lookup_address(pc, oid, utils.to_int(ls), 'mw')
    #if v != rs:
    #    print(f'{pc} {oid} VAL: {v} {vt} RS: {rs}')
    #assert rs == v
    return rs, vt

def do_partial_store(**kwargs):
    args = kwargs['args']
    oid = args[1]
    tid = args[2]
    pc = args[3]
    ls = args[4]
    rs = args[5]
    global GHOST_MEM
    addr = utils.to_int(ls)
    if type(addr) == int:
        GHOST_MEM.put_at(addr, rs)
        return rs, None
    else:
        return rs, None

def do_null(**kwargs):
    return cc.Unknown(), None

# to do
def do_ss(**kwargs):
    args = kwargs['args']
    oid = args[1]
    tid = args[2]
    pc = args[3]
    ls = args[4]
    rs = args[5]

    v, vt = MEM.lookup_regs(pc, tid, oid, ls)
    ilv = utils.to_int(ls)
    if type(ilv) == int and v is None:
        v = ilv
        
    if v is None:
        return cc.Unknown(), None
    
    v = utils.to_int(v)
    if type(v) != int:
        return cc.Unknown(), None
        
    pb = utils.pad_bits(v)
    if pb is None:
        return cc.Unknown(), None

    if rs == "8s":
        return int(pb[-8:], 2),  None
    elif rs == "16s":
        return int(pb[-16:-8], 2), None
    elif rs == "16m":
        return int(pb[-16:], 2), None
    elif rs == "32l":
        return int(pb[-32:], 2), None
    else:
        #return ls,False
        return cc.Unknown(), None

def do_partial_ss(**kwargs):
    args = kwargs['args']
    oid = args[1]
    tid = args[2]
    pc = args[3]
    ls = args[4]
    rs = args[5]

    v =  None
    if ls in GHOST_MEM.mapping:
        v = GHOST_MEM.query(ls)
    else:
        v = MEM.lookup_regs(pc, tid, oid, ls)
    
    if v is None or type(v) == cc.Unknown:
        return cc.Unknown(), None
    
    v = utils.to_int(v)
    if type(v) != int:
        return cc.Unknown(), None
    
    pb = utils.pad_bits(v)
    if pb is None:
        return cc.Unknown(), None
    
    if rs == "8s":
        return int(pb[-8:], 2),  None
    elif rs == "16s":
        return int(pb[-16:-8], 2), None
    elif rs == "16m":
        return int(pb[-16:], 2), None
    elif rs == "32l":
        return int(pb[-32:], 2), None
    else:
        #return ls,False
        return cc.Unknown(), None

def do_binary_op(**kwargs):
    args = kwargs['args']
    opcode = args[0]
    ls = args[4]
    rs = args[5]
    v = c_calc.binary_op(opcode, utils.to_int(ls), utils.to_int(rs))
    return v, None


def do_ite(**kwargs):
    args = kwargs['args']
    ls = args[4]
    ift = args[5][0]
    iff = args[5][1]
    if bool(ls):
        return iff, None
    return ift, None

#def do_unary_op(**kwargs):
#    args = kwargs['args']
#    opcode = args[0]
#    ls = args[4]
#    rs = None
#    v = c_calc.binary_op(opcode, utils.to_int(ls), rs)
#    return v

def do_set(**kwargs):
    args = kwargs['args']
    return args[4], None

def do_default(**kwargs):
    raise Exception()


opsd = {
    cc.LOAD_OP: do_load,
    cc.GET_OP: do_get,
    cc.PUT_OP: do_put,
    cc.STORE_OP: do_store,
    cc.NULL_OP: do_null,
    cc.SS_OP: do_ss,
    cc.SET_OP: do_set,
    cc.ITE_OP: do_ite
}

part_opsd = {
    cc.LOAD_OP: do_partial_load,
    cc.GET_OP: do_partial_get,
    cc.PUT_OP: do_partial_put,
    cc.STORE_OP: do_partial_store,
    cc.NULL_OP: do_null,
    cc.SS_OP: do_partial_ss,
    cc.SET_OP: do_set,
    cc.ITE_OP: do_ite
}

def ops(opcode):
    if opcode in opsd:
        return opsd[opcode]
    else:
        return do_binary_op

def partial_ops(opcode):
    if opcode in part_opsd:
        return part_opsd[opcode]
    else:
        return do_binary_op