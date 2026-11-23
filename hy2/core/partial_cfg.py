
#--------------------------------------
# File: partial_cfg.py
#
# Purpose: Performs an analysis that builds and decorates (with data) a CFG model for a single execution of the target program
#--------------------------------------
import pickle
import os
from colorama import Fore
import hy2.core.var_types as vart
import hy2.core.utils as utils
import hy2.core.et as et
import hy2.core.constants as cc
import hy2.core.cfg as tcfg
from hy2.core.model import CConditionalTransition, CInvocation, CState, CTransition, CVar


# ----------------------------------
# These objects are used to create an linear execution trace which gets converted into a CFG model
class HollowInvocation:
    def ___init__(self, name):
        self.name = name
        self.args = []
        self.strs = []
    
    def __repr__(self):
        return f'{self.name}: {self.args} {self.strs}'

class HollowTransition:
    def __init__(self, dest_pc, dest, transition_type):
        self.dest_pc = dest_pc
        self.transition_type = transition_type
        self.dest = dest

    def _label(self):
        return f'{self.transition_type} {self.dest_pc}'
    
    def __repr__(self):
        return f'{self.dest_pc} {self.dest} {self.transition_type}'

class HollowConditionalTransition(HollowTransition):
    def __init__(self, dest_pc, dest, transition_type):
        super().__init__(dest_pc, dest, transition_type)
        self.jmp_ip = 0
        self.jmp_iff = 0
        self.jmp_ift = 0
    
    def __repr__(self):
        out_str = super().__repr__()
        return f'COND: {out_str}'

class HollowState:
    def __init__(self, pc, oid, bid, tid):
        self.pc = pc
        self.oid = oid
        self.bid = bid
        self.tid = tid
        self.signature = ""
        self.invocations = []
        self.transition = None
        self.next = ""
    
    def check_eq(self, s1):
        if self.pc != s1.pc:
            return False

        if len(s1.invocations) > 0 and len(self.invocations) > 0 and self.invocations[0].name != s1.invocations[0].name:
            return False
        
        if type(self.transition) != type(s1.transition):
            return False
        
        t1 = self.transition.transition_type
        if t1 != s1.transition.transition_type:
            return False

        if self.transition.transition_type == "Ijk_Call" and (self.transition.dest_pc != s1.transition.dest_pc):
            return False
        
        return True

    def __repr__(self):
        return f'{self.pc} {self.tid}'

#--------------------------------------

class CEventSeq:
    def __init__(self, varPrefix):
        self.varPrefix = varPrefix
        self.states = []

    def toConsole(self):
        for s in self.states:
            print(s)

def parseInvArgs(iargs):
    args = []
    strs = []
    for a in iargs:
        if type(a) == int:
            args.append(a)
        else:
            dat = a[0]['data']
            args.append(dat)
            if 'str' in a[0]:
                strs.append(a[0]['str'])
    return args, strs

def translate_va0(va_base, pc):
    return abs(pc - va_base)

def translate_va(target_pages, aliases, pc):
    pc = utils.to_int(pc)
    if not type(pc) == int:
        return pc
    target_base, page_name = utils.get_matching_base(pc, target_pages, aliases)
    if not target_base == None:
        abs_addr = abs(target_base-pc)
        return abs_addr
    return pc

# TODO: make base_pc a list
def createHollowState(base_pcs, base_offsets, address_data, sym_data, signature, is_cond=False, cond_data={}):
    src_pc = address_data['src_pc']
    tid = address_data['tid']
    boid = address_data['boid']
    bid = address_data['bid']
    hs = HollowState(src_pc, boid, bid, tid)
    if signature != "":
        hs.signature = signature
    
    hs.next = address_data['next']
    dest_pc =  utils.to_int(address_data['dest_pc'])
    jmp_kind = address_data['jmp_kind']
    dest_label = address_data['dest_label']
    if is_cond:
        jmp_ift = cond_data['dst_val']
        jmp_iff = utils.to_int(cond_data['dst_next'])
        jmp_ip = cond_data['offsIP']
        ht = HollowConditionalTransition(dest_pc, dest_label, jmp_kind)
        ht.jmp_iff = jmp_iff
        ht.jmp_ift = jmp_ift
        ht.jmp_ip = jmp_ip
        hs.transition = ht
    else:
        ht = HollowTransition(dest_pc, dest_label, jmp_kind)
        hs.transition = ht
    
    for x in sym_data:
        inv = HollowInvocation()
        sym = x[0]
        tid = x[1]
        args = x[2:]
        inv.name = sym
        iargs, strs = parseInvArgs(args)
        inv.args = iargs
        inv.strs = strs
        hs.invocations.append(inv)

    return hs

def merge_invocations(iinvs):
    cinv = CInvocation()
    cinv.name  = iinvs[0].name
    
    for ix in iinvs:
        cinv.args.append(ix.args)
        cinv.strs.append(ix.strs)

    return cinv

def convertToVarType(vlist):
    vs = list(set(vlist))
    if len(vs) == 1:
        return vart.VInst(vs[0])
    elif type(vs[0]) == int and type(vs[-1]) == int and (vs[0] < vs[-1]) and ((vs[-1]-vs[0]) < 8192) and list(range(vs[0],vs[-1]+1)) == vs:
        return vart.VRange(vs[0], vs[-1], 1)
    elif len(vs) < 5:
        return vart.VSet(vs)
    else:
        return vart.VRepr(vs[0])

def get_previous_model_state(model, a0):
    tn = model.get_transitions(dest=a0)
    return [t.source for t in tn]

def get_next_state(model, a0):
    return [t.dest for t in model.get_transitions(source=a0)]

import time

# This monster adds branches analyzed with static analysis to our CFG model derived from our dynamic analysis
# IN:
#  - target_pages
#  - varPrefix
#  - A - the CFG model derived in our static analysis step
#  - dupl_lables
#  - state_map - maps state identifiers to pcs
#  - mem_table
#  - ghost_branches
#  - ghost_blocks
#  - ghost_nodes
#  - ghost_state_map
#  - missing_ghost_jmps
#  - ghost_srcs
def addGhostNodes(target_pages, varPrefix, A, dupl_labels, state_map, mem_table, ghost_branches, ghost_blocks, ghost_nodes, ghost_state_map, missing_ghost_jmps, ghost_srcs):
    savedGhostStates = {}
    savedSrcPcs = {}
    savedRets = {}
    i = 0
    for j in range(len(ghost_branches)):
        branch = ghost_branches[j]
        n = len(branch["nodes"])
        k = 0

        src_sid = None
        branch_sid = None
        branch_oids = []
        branch_tids = []
        et.init_ghost_mem()

        while(k < n):
            ghost_block = ghost_blocks[i]
            ghost_node = ghost_nodes[i]

            cs = CState()
            sid = ghost_state_map[ghost_block.pc]
            if k == 0:
                past_sid = get_previous_model_state(A, sid)
                if past_sid == []:
                    pass
                else:
                    src_sid = past_sid[0]
                    if src_sid in state_map:
                        branch_pc = state_map[src_sid].transition.dest_pc
                        if type(branch_pc) == list:
                            branch_pc = branch_pc[0]
                
                        if branch_pc in ghost_state_map:
                            branch_sid = ghost_state_map[branch_pc]
                        else:
                            branch_sid = tcfg.convert_pc_to_sid(dupl_labels, state_map, branch_pc)
                
                    if branch['src'] in savedGhostStates:
                        branch_oids = savedGhostStates[branch['src']]['oid']
                        branch_tids = savedGhostStates[branch['src']]['tid']
                        et.ghost_mem_load(savedGhostStates[branch['src']]['mem'])
                    elif branch['src'] in savedSrcPcs and savedSrcPcs[branch['src']] in savedGhostStates:
                        branch_oids = savedGhostStates[savedSrcPcs[branch['src']]]['oid']
                        branch_tids = savedGhostStates[savedSrcPcs[branch['src']]]['tid']
                        et.ghost_mem_load(savedGhostStates[savedSrcPcs[branch['src']]]['mem'])
                    elif branch_sid != None and branch_sid in state_map:
                        branch_oids = state_map[branch_sid].id
                        branch_tids = state_map[branch_sid].tid
            
            cs.fname = ghost_block.fname
            cs.pc = ghost_block.pc
            cs.tid = ghost_block.tid
            cs.trid = varPrefix

            if ghost_block.is_cond:
                ct = CConditionalTransition()
                if i in missing_ghost_jmps:
                    ct.dest_pc = missing_ghost_jmps[i]
                else:
                    ct.dest_pc = translate_va(target_pages['target_pages'], target_pages['aliases'], ghost_block.next)
                ct.transition_type = ghost_block.jump_kind
                if type(ghost_block.jmp_iff) == int:
                    ct.jmp_iff = translate_va(target_pages['target_pages'], target_pages['aliases'], ghost_block.jmp_iff)
                else:
                    ct.jmp_iff = ghost_block.jmp_iff
                
                if type(ghost_block.jmp_ift) == int:
                    ct.jmp_ift = translate_va(target_pages['target_pages'], target_pages['aliases'], ghost_block.jmp_ift)
                else:
                    ct.jmp_ift = ghost_block.jmp_ift
                ct.jmp_ip = ghost_block.offset_ip

                cs.transition = ct
            else:
                ct = CTransition()
                if i in missing_ghost_jmps:
                    ct.dest_pc = missing_ghost_jmps[i]
                elif type(ghost_block.next) == int:
                    ct.dest_pc = translate_va(target_pages['target_pages'], target_pages['aliases'], ghost_block.next)
                else:
                    ct.dest_pc = ghost_block.next
                
                if ghost_block.next_fname != "":
                    ct.dest = ghost_block.next_fname
                elif k+1 < n:
                    ct.dest = ghost_blocks[i+1].fname
                ct.transition_type = ghost_block.jump_kind
                cs.transition = ct
            
            vlist = [etv for etv in ghost_node.var_table.values() if type(etv) == et.TStmt]
            vlist.sort(key=lambda x: x.pc)
            max_pc = None
            if len(vlist) > 0:
                max_pc = vlist[-1].pc

            var_map = {}
            for l in range(len(vlist)):
                var = vlist[l]
                if type(var) != et.TStmt:
                    continue
                elif var.name in ['cc_dep', 'cc_dep1', 'cc_dep2', 'rsp', 'rbp', 'cc_op']:
                    if var.name in ['rsp', 'rbp']:
                        for ix in range(len(branch_oids)):
                            oid = branch_oids[ix]
                            if len(branch_tids) == 1:
                                tid = branch_tids[0]
                            else:
                                tid = branch_tids[ix]
                            val = var.partial_solve(oid, tid)
                else:
                    vec = var.astToVec()
                    if cs.transition.transition_type == "Ijk_Call" and var.pc == max_pc and vec[0] == 'St' and 'rsp' in vec and type(vec[-1]) == int:
                        cs.return_addr = translate_va(target_pages['target_pages'], target_pages['aliases'], vec[-1])
                        if 'sym.imp.' in cs.transition.dest:
                            A, sid_src = tcfg.add_ghost_jump(A, dupl_labels, state_map, ghost_state_map, cs.transition.dest_pc, cs.return_addr)
                            if sid_src in state_map:
                                pass
                            elif (k+1) < n and branch['nodes'][k+1] == cs.transition.dest_pc:
                                savedSrcPcs[cs.return_addr] = cs.transition.dest_pc
                                ghost_blocks[i+1].next = vec[-1]
                                ghost_srcs += [cs.transition.dest_pc]
                        else:
                            off = n-k-1
                            if len(ghost_blocks) > (i+off) and (ghost_blocks[i+off].jump_kind == "Ijk_Ret" or "sym.imp." in ghost_blocks[i+off].fname) and ghost_blocks[i+off].fname == cs.transition.dest:
                                A = tcfg.add_ghost_jump_from_src(A, dupl_labels, state_map, ghost_state_map, ghost_state_map[ghost_blocks[i+off].pc], cs.return_addr)
                                ghost_blocks[i+off].next = vec[-1]
                        continue
                    var_pc = translate_va(target_pages['target_pages'], target_pages['aliases'], var.pc)
                    
                    if len(cs.variables) > 0 and vec[0] == 'LD' and cs.variables[-1].vec[0] == 'St' and cs.variables[-1].pc <= var_pc:
                        d1_idx = cs.variables[-1].vec.index('D1', 2)
                        if cs.variables[-1].vec[1:d1_idx] == vec[1:]:
                            cs.variables[-1].name = var.name
                            cs.variables[-1].vec[0] = 'StLD'
                            var_map[var.name] = len(cs.variables) - 1
                            continue
                    
                    cvar = CVar()
                    cvar.name = var.name
                    cvar.pc = var_pc
                    cvar.dsource = var.dsource
                    cvar.dintent = var.dintent
                    cvar.vec = vec
                    if vec[0] == 'Put' and len(cvar.vec) == 3 and type(cvar.vec[-1]) == str and cvar.vec[-1] in var_map:
                        cvar.val = var_map[cvar.vec[-1]]
                        et.ghost_mem_put(cvar.name, cvar.val)
                    elif vec[0] == 'Put' and len(cvar.vec) == 5 and cvar.vec[:4] == ["Put", "D1", "GET", "D2"] and cvar.vec[-1] in var_map:
                        cvar.val = var_map[cvar.vec[-1]]
                        et.ghost_mem_put(cvar.name, cvar.val)
                    else:
                        for ix in range(len(branch_oids)):
                            oid = branch_oids[ix]
                            if len(branch_tids) == 1:
                                tid = branch_tids[0]
                            else:
                                tid = branch_tids[ix]
                            val = var.partial_solve(oid, tid)
                            if vec[0] in ['LD', 'St']:
                                vtmp = val[1]
                                atmp = val[0]
                                if type(vtmp) != cc.ValError:
                                    cvar.val = vtmp
                                if type(atmp) != cc.ValError:
                                    cvar.abs_addr = atmp

                                if type(cvar.abs_addr) == int and cvar.abs_addr != 0 and cvar.abs_addr in mem_table:
                                    cvar.label += [mem_table[cvar.abs_addr]]
                                if cs.transition.transition_type == 'Ijk_Ret' and cs.transition.dest_pc == var.name and type(cvar.val) == int:
                                    cs.transition.dest_pc = translate_va(target_pages['target_pages'], target_pages['aliases'], cvar.val)
                                    A = tcfg.add_ghost_jump_from_src(A, dupl_labels, state_map, ghost_state_map, ghost_state_map[cs.pc], cs.transition.dest_pc)
                                if type(cvar.val) == cc.Unknown and cvar.label != [] and branch_sid in state_map:
                                    tmpval = state_map[branch_sid].search_for_addr(cvar.abs_addr)
                                    if tmpval == None:
                                        cvar.val = vart.VEmpty()
                                    else:
                                        cvar.val = tmpval
                                        et.ghost_mem_put(cvar.abs_addr, cvar.val)
                                if type(cvar.val) != cc.Empty and vec[0] == 'LD':
                                    var_map[cvar.name] = cvar.val
                            else:
                                if not type(val) == cc.Unknown and not type(val) == cc.ValError:
                                    cvar.val = val
                    
                    cs.variables.append(cvar)

            # if this branch branches off into another unseen branch save the state at the node with the jump statement:
            if cs.pc in ghost_srcs:
                savedGhostStates[cs.pc] = {'mem': et.ghost_mem_export(), 'oid': branch_oids, 'tid': branch_tids}
            state_map[sid] = cs
            i += 1
            k += 1

    return A, state_map

# r15 = Put(GET(rax)) [None] @ [VEmpty]
# use: [] dsource:ret sym.imp.calloc

# mt7 = St(Add(t5, Shl(t6, 3)), GET(r15)) [[9681376, 9683248, 9689152, 9678480]] @ [[9681280, 9681296, 9681304, 9681288]]

# refactor replace rax for any register
def checked_returned_from(model, state_map, sid):
    limit = 5
    depth = 0
    while depth < limit:
        s0 = get_previous_model_state(model, sid)
        s0 = [sx for sx in s0 if sx in state_map]
        if s0 != [] and s0[0] in state_map:
            st = state_map[s0[0]]
            if st.transition.transition_type == "Ijk_Ret" or "sym.imp" in st.fname:
                return 'ret ' + st.fname
            elif len(st.invocations) > 0:
                return 'ret ' + st.invocations[0].name
            else:
                if any([v0.name == "rax" and v0.vec[0] == "Put" for v0 in st.variables]):
                    return 'ret ' + st.fname
                v0_ret = [v0.dsource for v0 in st.variables if "ret" in v0.dsource]
                if len(v0_ret) > 0:
                    return  v0_ret[0]
        
            sid = s0[0]
            depth +=1 
        else:
            return None
    return None

# DEF:
#  PUT(c) - this wouldn't be a def
#  STORE(X,z) - def(x) - writing to an address versus defining the value at an address
#  i.e. init versus define
# USE:
#  PUT(var)
#  LOAD(X)

# Converts Event Sequence to CFG model and decorates with runtime data and debug info.
# IN:
#   target_pages
#   varPrefix
#   seq - sequence of blocks executed
#   et_blocks - Block objects containing a set of IR expressions structured as expression trees
#   symbols - symbolc data
#   meta - type information from source
#   sym_tids - mapping of symbolic thread ids to concrete
#   multi_enabled - multi-threaded analysis enabled
#   ghost_branches, ... - Static analysis extension
def build_event_seq(target_pages, varPrefix, seq, et_blocks, symbols, meta, sym_tids, multi_enabled=False, ghost_branches=[], missing_ghost_jumps=[], dropped_ghost_blocks={}, ghost_blocks=[], ghost_nodes=[]):
    eq = CEventSeq(varPrefix)
    print('Building CFG')

    # At - Thread Model
    A, labels, lid, dupl_labels, At = tcfg.convertToCFG(seq, multi_enabled)

    labels = dict(sorted(labels.items()))
    ghost_state_map = {}
    ghost_srcs = []
    if ghost_branches != []:
        A, ghost_state_map, ghost_srcs = tcfg.add_ghost_branch(A, lid, dupl_labels, labels, ghost_branches, missing_ghost_jumps)
        A = tcfg.add_ghost_jumps(A, dupl_labels, labels, target_pages, dropped_ghost_blocks)

    state_map = {}
    mem_table = {}
    var_count = 0

    print('Building CFG-model')
    noNodes = len(list(labels.keys()))
    print(noNodes)
    invc_time = 0
    trans_time = 0
    var_lookup_time = 0
    var_merge_time = 0
    var_reg_time = 0
    var_label_time = 0
    var_ret_time = 0
    var_reg_solve_time = 0
    var_reg_lookup_time = 0

    cnt = 0
    for sid, v in labels.items():
        cnt += 1
        if cnt%10000 == 0:
            """
            print(f'{cnt}/{noNodes} nodes converted.')
            print(f'Invocation Latency: {invc_time}')
            print(f'Transition Latency: {trans_time}')
            print(f'Var Lookup Latency: {var_lookup_time}')
            print(f'Var Merge Latency: {var_merge_time}')
            print(f'Var Ret Latency: {var_ret_time}')
            print(f'Var Reg Latency: {var_reg_time}')
            print(f'Var Reg Solve Latency: {var_reg_solve_time}')
            print(f'Var Reg Lookup Latency: {var_reg_lookup_time}')
            """
            pass
        if len(v) == 0:
            pass
        else:
            cs = CState()
            v0_bid = v[0].bid
            n = len(v)
            bx = et_blocks[v0_bid]
            v_next = v[0].next
            cs.fname = bx.name
            cs.pc = translate_va(target_pages['target_pages'], target_pages['aliases'], v[0].pc)
            cs.tid = list(set([v[i].tid for i in range(n)]))
            cs.trid = varPrefix
            cs.id = [v[i].oid for i in range(n)]
            t0_type = type(v[0].transition)

            startTime = time.time()
            k = max([len(v[i].invocations) for i in range(n)])
   
            mis = [i for i in range(n) if len(v[i].invocations) == k]
            inv_names = [v[mis[0]].invocations[j].name for j in range(k)]

            idxs = [0]*n
            for j in range(k):
                iinvs = []
                for i in range(n):
                    idx = idxs[i]
                    if idx == len(v[i].invocations):
                        pass
                    elif v[i].invocations[idx].name == inv_names[j]:
                        iinvs.append(v[i].invocations[idx])
                        idxs[i] += 1
                else:
                    pass
                cs.invocations.append(merge_invocations(iinvs))
            endTime = time.time()
            invc_time += (endTime - startTime)

            startTime = time.time()
            assert all([t0_type == type(v[i].transition) for i in range(n)])
            if t0_type == HollowConditionalTransition:
                ct = CConditionalTransition()
                ct.dest_pc = list(set([translate_va(target_pages['target_pages'], target_pages['aliases'], v[i].transition.dest_pc) for i in range(n)]))
                ct.dest = list(set([v[i].transition.dest for i in range(n)]))
                ct.transition_type = v[0].transition.transition_type

                assert all([ct.transition_type == v[i].transition.transition_type for i in range(n)])

                ct.jmp_iff = v[0].transition.jmp_iff
                ct.jmp_ift = v[0].transition.jmp_ift
                ct.jmp_ip = v[0].transition.jmp_ip
                
                cs.transition = ct
            else:
                ct = CTransition()
                ct.dest = list(set([v[i].transition.dest for i in range(n)]))
                ct.dest_pc = list(set([translate_va(target_pages['target_pages'], target_pages['aliases'], v[i].transition.dest_pc) for i in range(n)]))
                ct.transition_type = v[0].transition.transition_type
                assert all([ct.transition_type == v[i].transition.transition_type for i in range(n)])
                
                cs.transition = ct
            
            endTime = time.time()
            trans_time += (endTime - startTime)

            b_sym = None
            if v0_bid in symbols:
                b_sym = symbols[v0_bid]

            vlist = [etv for etv in bx.var_table.values() if type(etv) == et.TStmt]
            vlist.sort(key=lambda x: x.pc)
            max_pc = None
            if len(vlist) > 0:
                max_pc = vlist[-1].pc
            
            dep_map = {}
            var_map = {}
            for i in range(len(vlist)):
                var = vlist[i]

                if type(var) != et.TStmt:
                    pass
                elif var.name in ['cc_dep', 'cc_dep1', 'cc_dep2', 'rsp', 'rbp', 'cc_op']:
                    pass
                else:
                    vec =  var.astToVec()
                    if cs.transition.transition_type == "Ijk_Call" and var.pc == max_pc and vec[0] == 'St' and 'rsp' in vec and type(vec[-1]) == int:
                        cs.return_addr = translate_va(target_pages['target_pages'], target_pages['aliases'], vec[-1])
                        continue
                    
                    deps = [(vec[i],i) for i in range(len(vec)) if type(vec[i]) == str and vec[i][0] == 't']
                    if len(deps) > 0 and vec[0] == 'St' and cs.variables[-1].pc == var.pc:
                        d1_idx = vec[2:].index('D1')
                        dvec = cs.variables[-1].vec[2:]
                        sub_expr = vec[2:d1_idx+2]
                        if sub_expr == dvec:
                            vec = ['INC'] + vec[d1_idx+2:]
                    
                    var_pc = translate_va(target_pages['target_pages'], target_pages['aliases'], var.pc)

                    if len(cs.variables) > 0 and vec[0] == 'LD' and cs.variables[-1].vec[0] == 'St' and cs.variables[-1].pc <= var_pc:
                        d1_idx = cs.variables[-1].vec.index('D1', 2)
                        if cs.variables[-1].vec[1:d1_idx] == vec[1:]:
                            cs.variables[-1].name = var.name
                            cs.variables[-1].vec[0] = 'StLD'
                            var_map[var.name] = len(cs.variables) - 1
                            continue
                    
                    cvar = CVar()
                    if var.dsource[:3] == "arg" and b_sym != None:
                        if 'args' in b_sym.func:
                            arg_no = int(var.dsource.replace('arg', '')) -1
                            if arg_no < len(b_sym.func['args']):
                                cvar.dtype = b_sym.func['args'][arg_no]['dtype']
                    
                    cvar.name = var.name
                    cvar.pc = var_pc
                    cvar.dsource = var.dsource
                    if str(var_pc) in meta:
                        cvar.dtype = meta[str(var_pc)]['vtype']
                        cvar.static_name = meta[str(var_pc)]['vname']
                    elif type(var.ls) == et.TStmt and var.ls.pc != var.pc:
                        ls_pc = translate_va(target_pages['target_pages'], target_pages['aliases'], var.ls.pc)
                        if str(ls_pc)  in meta:
                            cvar.dtype = meta[str(ls_pc)]['vtype']
                            cvar.static_name = meta[str(ls_pc)]['vname']

                    # bug -> if there is block with cond before current block it will give the wrong dsource for ret
                    if cvar.dsource[:3] == 'ret':
                        startTime = time.time()
                        dsrc = checked_returned_from(A, state_map, sid)
                        if dsrc == None:
                            s0 = get_previous_model_state(A, sid)
                            s0 = [sx for sx in s0 if sx in state_map]
                            if s0 != [] and s0[0] in state_map:
                                st = state_map[s0[0]]
                                cvar.dsource = 'ret ' + st.fname
                        else:
                            cvar.dsource = dsrc
                        endTime = time.time()
                        var_ret_time += (endTime - startTime)
                    
                    cvar.dintent = var.dintent
                    cvar.vec = vec
                    labels_udpated = False
                    
                    if cvar.vec[0] != 'Put':
                        startTime = time.time()
                        vals = et.vmem_get_all_at_pc(var.pc)
                        if not vals == None:
                            vtmp = []
                            atmp = []
                            for k, entry in vals.items():
                                addr = utils.to_int(k.split('-')[1])
                                on_heap = entry[0]['on_heap']
                                val = utils.to_int(entry[0]['val'])
                                atmp += [addr]
                                lbl = f'v{varPrefix}{var_count}'
                                if addr != 0 and not addr in mem_table:
                                   mem_table[addr] = lbl
                                   labels_udpated = True
                                   if cvar.vec[0] == 'St':
                                       cvar.def_label = lbl
                                if val != 0 and on_heap:
                                    if not val in mem_table:
                                        mem_table[val] = f'v{varPrefix}{var_count}'
                                        labels_udpated = True
                                    vid = mem_table[val]
                                    if not vid in cvar.label:
                                        cvar.label += [vid]

                                vid = mem_table[addr]
                                if not vid in cvar.label:
                                    cvar.label += [vid] 

                                if cvar.def_label != '' and cvar.def_label in cvar.label:
                                    cvar.label.remove(cvar.def_label)
                                
                                vtmp += [val]
                            
                            startTime0 = time.time()
                            var_lookup_time += (startTime0 - startTime)

                            cvar.val = convertToVarType(vtmp)
                            cvar.abs_addr = convertToVarType(atmp)
                            endTime = time.time()
                            var_merge_time += (endTime - startTime0)
                    else:
                        startTimeI = time.time()
                        
                        if len(cvar.vec) == 3 and type(cvar.vec[-1]) == int:
                            cvar.val = convertToVarType([cvar.vec[-1]])
                        elif len(cvar.vec) == 3 and type(cvar.vec[-1]) == str and cvar.vec[-1][0] == 't' and cvar.vec[-1] in var_map:
                            cvar.val = cs.variables[var_map[cvar.vec[-1]]].val
                        elif len(cvar.vec) == 5 and cvar.vec[:4] == ["Put", "D1", "GET", "D2"] and cvar.vec[-1] in var_map:
                            cvar.val = cs.variables[var_map[cvar.vec[-1]]].val
                        elif len(cvar.vec) == 3 or (len(cvar.vec) == 5 and cvar.vec[:4] == ["Put", "D1", "GET", "D2"]):
                            vtmp = []
                            startTimeI = time.time()
                            for j in range(n):
                                oid = v[j].oid
                                tid = sym_tids[v[j].tid]
                                if len(cvar.vec) == 3:
                                    regname = var.name
                                else:
                                    regname = cvar.vec[-1]
                                
                                vals = et.mem_check_block_regs(var.pc, tid, oid, regname)
                            
                                vtmp += [vals[0]]
                                if vals[0] in mem_table:
                                    vid = mem_table[vals[0]]
                                    if not vid in cvar.label:
                                        cvar.label += [vid]

                            cvar.val = convertToVarType(vtmp)
                            endTimeI = time.time()
                            var_reg_lookup_time += (endTimeI - startTimeI)
                        elif not any([cvar.vec[j][0] == 't' for j in range(len(cvar.vec)) if type(cvar.vec[j]) == str]):
                            vtmp = []
                            startTimeI = time.time()
                            for j in range(n):
                                oid = v[j].oid
                                tid = sym_tids[v[j].tid]
                                retv = var.solve(oid, tid)
                                vtmp += [retv]
                                if type(retv) != int:
                                    continue
                                
                                if not retv in mem_table:
                                    mem_table[retv] = f'v{varPrefix}{var_count}'
                                    labels_udpated = True
                                
                                if retv in mem_table:
                                    vid = mem_table[retv]
                                    if not vid in cvar.label:
                                        cvar.label += [vid]

                            cvar.val = convertToVarType(vtmp)
                            endTimeI = time.time()
                            solveDelta = (endTimeI - startTimeI)
                            if solveDelta > 1:
                                pass

                            var_reg_solve_time += solveDelta
                        endTime = time.time()
                        var_reg_time += (endTime - startTime)
                    
                    if labels_udpated:
                        var_count += 1  
                    var_map[cvar.name] = len(cs.variables)
                    cs.variables.append(cvar)
           
            eq.states.append(cs)
            state_map[sid] = cs

    if len(ghost_blocks) > 0:
        A, state_map = addGhostNodes(target_pages, varPrefix, A, dupl_labels, state_map, mem_table, ghost_branches, ghost_blocks, ghost_nodes, ghost_state_map, missing_ghost_jumps, ghost_srcs)

    return state_map, A, At

#-----------------------------
import graphviz

def build_graph_vis(transitions, labels, out_dir, file_name='model'):
    e = graphviz.Digraph('G', filename=file_name, format='png')
    nodes = []
    for t in transitions:
        t0 = t[0]
        s0 = t[1]
        d0 = t[2]
        if not s0 in nodes:
            if s0 in labels:
                l  = labels[s0]
                label = l.graphLabel()
                e.node(s0, label=label)
            else:
                e.node(s0, label=s0)
            nodes.append(s0)
        if not d0 in nodes:
            if d0 in labels:
                l = labels[d0]
                label = l.graphLabel()
                e.node(d0, label=label)
            else:
                e.node(d0, label=d0)
            nodes.append(d0)
        e.edge(s0, d0, t0)
    
    print('Rendering diagram...')
    try:
        e.render(directory=out_dir)
    except Exception as ex:
        print('ERROR: '+str(ex))

def export_cfg_diagram(out_dir, A, labels):
    tr0 = tcfg.parse_transitions(A)
    build_graph_vis(tr0, labels, out_dir)

def export_trace(trace, out_file):
    with open(out_file, "wb") as f:
        pickle.dump(trace, f)

def export_partial_model(target_path, target, test_case_name, event_seq, cfg, lib_trace_id, At=None):
    if lib_trace_id == "":
        cfg_file = os.path.join(target_path, target, f'{test_case_name}-cfg.bin')
        backing_file = os.path.join(target_path, target, f'{test_case_name}-backing.bin')

        if At != None:
            thread_model_file = os.path.join(target_path, target, f'{test_case_name}-threadmodel.bin')
            export_trace(At, thread_model_file)
            tcfg.create_model_graph(At)

        export_trace(event_seq, backing_file)
        export_trace(cfg, cfg_file)
        print('Done!')
    else:
        test_case_dir = os.path.join(target_path, target, test_case_name)
        if not os.path.exists(test_case_dir):
            os.mkdir(test_case_dir)
        
        cfg_file = os.path.join(test_case_dir, f'{lib_trace_id}-cfg.bin')
        backing_file = os.path.join(test_case_dir, f'{lib_trace_id}-backing.bin')
        export_trace(event_seq, backing_file)
        export_trace(cfg, cfg_file)
        print('Done!')


def import_trace(in_file):
    bin_data = None
    try:
        f = open(in_file, 'rb')
        bin_data = pickle.load(f)
        
        if type(bin_data) == str:
            return None
        f.close()
    except:
        pass
    return bin_data