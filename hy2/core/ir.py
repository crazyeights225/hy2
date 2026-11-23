#--------------------------------------
# File: ir.py
#
# Purpose: Converts machine code to IR and inits other analysis steps
#--------------------------------------
# Internal IR and interface with:
# - expression trees
# - partial CFG
#----------------------------------------------
# IMPORTS:
import pyvex
import archinfo
import json
import colorama as Fore
import os


from hy2.core.vmem import Vmem
import hy2.core.et as et
import hy2.core.constants as cc
import hy2.core.utils as utils
import hy2.core.compress_vec as comprvec
import hy2.core.partial_cfg as pcfg

#----------------------------------------------
# DATA: - ?? I don't remember what this was for?
glob_table = {}

GLOBAL_CONFIG = None

TARGET = ""
# TODO: Fix this:
def set_target(name):
    global TARGET
    TARGET = name

class BlockDecorator:
    def __init__(self, bid):
        self.bid = bid
        self.func = {}
        self.dtypes = []
        self.ctx = []

class IRBlock:
    def __init__(self):
        self.bid = 0
        self.pcs = []
        self.fname = ""
        self.image_name = ""
        self.pname = ""
        self.types = []
        self.fsize = 0
        self.next = None
        self.jump_kind = None
        self.var_table = {}
        self.var_list = []
        self.signature = ""
        self.invocation_data = {}
        self.sym_data = []
        # TODO: Remove me
        self.lid0 = 0

    
    def add_symbol_data(self, bid, name, data):
        self.sym_data.append([name]+data)

    def mergeBlocks(self, other):
        self.invocation_data['pc'] = other.pcs[0]
        self.invocation_data['bid'] = other.bid
        self.invocation_data['fname'] = other.fname
        self.sym_data += other.sym_data
        self.next = other.next
    

class IRConstructor:
    def __init__(self, target, local_bin, arch):
        self.target = target
        self.local_bin = local_bin
        self.arch = arch
        
        self.blocks = {}
        self.et_blocks = {}

        self.bid = 0
        self.block_occurance_order = []
        self.line_no = 0

        self.constants = {}
        self.funcs = {}
        self.data_types = {}
        self.refs = {}
        self.ctx = {}
        self.meta = {}

        self.ro_sect = {}
        self.branches ={}
        self.ghost_blocks = {}

    # Load static data
    def loadDefs(self):
        target_dir = os.path.join(GLOBAL_CONFIG.target_path, self.target, "defs.json")
        if os.path.exists(target_dir):
            f = open(target_dir, 'r')
            data = json.load(f)
            f.close()
            self.constants = data['constants']
            self.funcs = data['funcs']
            self.data_types = data['structs']
        
        target_dir = os.path.join(GLOBAL_CONFIG.target_path, self.target, "ctx.json")
        if os.path.exists(target_dir):
            with open(target_dir, 'r') as f:
                data = json.load(f)
                self.ctx = data
    
        target_dir = os.path.join(GLOBAL_CONFIG.target_path, self.target, "meta.json")
        if os.path.exists(target_dir):
            with open(target_dir, 'r') as f:
                data = json.load(f)
                self.meta = data
    
    def set_target_bin(self, name):
        set_target(name)

    # Function: build_event_sequence
    # Purpose: Parse sequence of basic blocks into sequence of expression trees
    # Then for each block in the trace, solve, and create a state in our event sequence
    def build_asts(self, block_regs):
        self.loadDefs()
        pmem = Vmem()
        pmem.block_regs = block_regs
        pmem.read_in_vmem_log()

        # (last_fname) this is incorrect when blocks aren't unique but it should get overwritten later
        last_fname = ""
        last_block = ""
        for bid in self.blocks.keys():
            b = self.blocks[bid]
       
            etb = et.ETBlock(b.pcs[0], b.jump_kind, b.fname, False, b.next, last_fname, b.fsize)
            
            # check expression trees for block
            etb.lazy_eval_solver(b.var_table, b.var_list, b.types)

            if GLOBAL_CONFIG.static_enabled and type(b.statements[-1]) ==  pyvex.IRStmt.Exit:
                jmp_iff = b.statements[-1].dst.value
                jmp_ift = b.next
                jmp_iff = utils.to_int(jmp_iff)
                jmp_ift = utils.to_int(jmp_ift)


                if type(jmp_iff) == int:
                    self.ghost_blocks[jmp_iff] = b.pcs[0]

                if type(jmp_ift) == int:
                    self.ghost_blocks[jmp_ift] = b.pcs[0]

            if last_block != "" and self.blocks[last_block].jump_kind and b.fname.replace('sym.', '').replace('imp.','') in self.funcs:
                bd = BlockDecorator(bid)
                bd.func = self.funcs[b.fname.replace('sym.', '').replace('imp.', '')]
                if bd.func['fname'] in self.ctx:
                    for a in bd.func['args']:
                        if a['name'] in self.ctx[bd.func['fname']]:
                            bd.ctx.append(self.ctx[bd.func['fname']])
            
                self.refs[bid] = bd
            
            self.et_blocks[bid] = etb
            last_fname = b.fname
            last_block = bid

        et.set_vmem(pmem)

    def ghost_ir_to_est(self, pcs, jump_kind, fname, next_fname, last_fname, fsize, var_table, var_list, btypes):
        etb = et.ETBlock(pcs[0], jump_kind, fname, False, next_fname, last_fname, fsize)
        etb.lazy_eval_solver(var_table, var_list, btypes)
        return etb

    # Build an event sequence from the observed sequence of blocks
    # each block has pc, fname, and edge to next block
    def do_build_cfg(self, seq, backtrace, trace_data, resolve_ghost_addrs={}):
        if len(backtrace) == 1 and type(backtrace[0]) == list:
            backtrace = backtrace[0]
        backtrace = comprvec.compressVec(backtrace)
        base_pc =self.ro_sect['base']
        if type(base_pc) == int:
            base_pc = [base_pc]
        base_off = [0]
        if 'offset' in self.ro_sect:
            base_off = self.ro_sect['offset']
        
        missing_ghost_jmps = {}
        ghost_to_update = None
        for i in range(len(backtrace)):
            if len(backtrace[i]) == 2:
                bx,_ = backtrace[i]
                boid = i
            elif len(backtrace[i]) == 4:
                bx,_,boid,no_skipped = backtrace[i]
            else:
                bx,_,boid= backtrace[i]

            eb = self.et_blocks[bx]
            b = self.blocks[bx]
            bdec = None
            
            tb = trace_data[boid]
            tid = tb["tid"]
            sym_data = tb["sym_data"]
            signature = b.signature

            JMP_CPU_DEPEND_FLAG = False
            if i != len(backtrace) - 1:
                if len(backtrace[i+1]) == 2:
                    by,_ = backtrace[i+1]
                    byoid = i+1
                elif len(backtrace[i+1]) == 4:
                    by,_,byoid,_ = backtrace[i+1]
                else:
                    by,_,byoid= backtrace[i+1]
                bly = self.et_blocks[by]
                dest_pc = bly.pc
                dest_label = bly.name
                dest_bid = i+1
                nbdec = None
                JMP_CPU_DEPEND_FLAG = bly.CPU_DEPEND_FLAG
                if by in self.refs:
                    nbdec = self.refs[by]
            else:
                dest_pc = b.next
                dest_bid = None
                dest_label = b.next
                nbdec = None

            # pyvex Exit jmp_kind is a condition
            if len(b.statements) > 0 and type(b.statements[-1]) == pyvex.IRStmt.Exit:
                st = b.statements[-1]
                src_pc = eb.pc
                dst_val = st.dst.value
                offsIP = st.offsIP
                jmp_kind = st.jumpkind
                address_data = {"tid": tid, "boid": boid, "bid": bx, "src_pc": src_pc, "dest_pc": dest_pc, "next": b.next, "dest_bid": dest_bid, "dest_label": dest_label, "jmp_kind": jmp_kind}
                
                cond_data={'dst_val': dst_val, 'dst_next': b.next, 'offsIP': offsIP, 'jmp_kind': jmp_kind}
                ht = pcfg.createHollowState(base_pc, base_off, address_data, sym_data, signature, True, cond_data)
                if ht.pc in resolve_ghost_addrs:
                    ghost_to_update = resolve_ghost_addrs[ht.pc]
                seq.append(ht)
            else:
                src_pc = eb.pc
                address_data = {"tid": tid, "boid": boid, "bid": bx, "src_pc": src_pc, "dest_pc": dest_pc, "next": b.next, "dest_bid": dest_bid, "dest_label": dest_label, "jmp_kind": b.jump_kind}
                
                ht = pcfg.createHollowState(base_pc, base_off, address_data, sym_data, signature, False)
                if b.jump_kind == 'Ijk_Ret' and ghost_to_update != None:
                    missing_ghost_jmps[ghost_to_update] = ht.transition.dest_pc
                    ghost_to_update = None
                seq.append(ht)
        return seq, missing_ghost_jmps

    # Convert runtime data to a CFG model
    # IN:
    #  target - the name of the target program
    #  test_case_name - the name of the test case executed
    #  varPrefix - the identifier for the test case
    #  backtrace - the sequence of blocks executed
    #  trace_data - describes the properties of blocks in the sequence
    #  sym_tids - map of symbolic thread ids to concrete thread ids
    #  lib_trace_id - identifier for entry point to library when analyzing libraries
    #  For Static Extension:
    #  -------
    #  ghost_branches - static branches we are adding to the analysis 
    #  ghost_nodes
    #  ghost_blocks
    #  missing_ghost_jumps
    #  dropped_ghost_blocks - 
    def build_cfg(self, target, test_case_name, varPrefix, backtrace, trace_data, sym_tids, lib_trace_id="", ghost_branches=[], ghost_nodes=[], ghost_blocks=[], missing_ghost_jumps=[], dropped_ghost_blocks={}):
        seq = []
         
        if lib_trace_id != "":
            for bsub in backtrace:
                seq, _ = self.do_build_cfg(seq, bsub, trace_data, missing_ghost_jumps)
            eventSeq, A0 = pcfg.build_event_seq(self.ro_sect, varPrefix, seq, self.et_blocks, self.refs, self.meta, sym_tids)
            pcfg.export_partial_model(GLOBAL_CONFIG.target_path, target, test_case_name, eventSeq, A0, lib_trace_id)
        else:
            seq, mgj = self.do_build_cfg(seq, backtrace, trace_data, missing_ghost_jumps)
            eventSeq, A0, At = pcfg.build_event_seq(self.ro_sect, varPrefix, seq, self.et_blocks, self.refs, self.meta, sym_tids, GLOBAL_CONFIG.enable_multithread_analysis, ghost_branches, mgj, dropped_ghost_blocks, ghost_blocks, ghost_nodes)
            #pcfg.export_cfg_diagram(os.path.join(GLOBAL_CONFIG.target_path, target), A0, eventSeq)          
            pcfg.export_partial_model(GLOBAL_CONFIG.target_path, target, test_case_name, eventSeq, A0, lib_trace_id, At)
        
        #eventSeq.toConsole()

    # Convert vex ir to our internal ir
    # IN:
    #  b - block object
    # 
    #  OUT:
    #  var_table - (k, v) => k is the identier assigned to IR expressions by pyvex, v contains the IR statement 
    #  var_list - list of IR expressions by identifier
    #
    # NOTE: This is very ineffecient - it converts vex expressions to strings and then parses them instead of just handling the expression objects themselves
    def decode_block(self, b, tyenv):
        idx = -1
        b.lid0 = self.line_no
        dtypes = tyenv.types
        j = 0
        for i in range(len(b.statements)):
            st = b.statements[i]
            if type(st) == pyvex.IRStmt.IMark:
                idx+=1
                assert (str(st.addr)) == str(b.pcs[idx])
            
            elif type(st) == pyvex.IRStmt.AbiHint:
                continue
            elif type(st) == pyvex.IRStmt.WrTmp:
                tmp = "t"+str(st.tmp)
                dat = str(st.data)
                if "amd64" in dat:
                    print(st)
                    print(b.fname)
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
                    b.var_table[tmp]['lid'] = self.line_no
                    b.var_list.append(tmp)
                    dti = dtypes[j]
                    b.types.append(dti)
                    self.line_no +=1
                    j += 1
                
                elif "GET" in dat:
                    r = archinfo.ArchAMD64().translate_register_name(st.data.offset, st.data.result_size(tyenv)//8)
                    if r == "d":
                        r = "rcx"
                    if r in cc.sub_regs:
                        stmp = "sr"+r
                        ops = cc.sub_regs[r]
                        b.var_table[stmp] = {}
                        b.var_table[stmp]["op"] = [cc.encode_operation("SS"), ops[0]+","+ops[1]]
                        b.var_table[stmp]["t"] = "b"
                        b.var_table[stmp]["pc"] = b.pcs[idx]
                        b.var_table[stmp]['lid'] = self.line_no
                        b.var_list.append(stmp)
                        dti = dtypes[j]
                        b.types.append(dti)
                        self.line_no += 1
                        j += 1
                        args = stmp
                    else:
                        args = r
                elif op[:3] == "Add" or op[:3] == "Sub":
                    pvid = args.split(",")[0]
                    operr = args.split(",")[1]
                    if (len("0xffffffffffffffff") == len(operr) and operr[:3]=="0xf") and pvid in b.var_table:
                        #and b.var_table[pvid]["op"][0][0] == cc.GET_OP and b.var_table[pvid]["op"][1] == "rbp":
                        b.var_table[tmp] = {}
                        if op[:3] == "Sub":
                            op = "Add" + op[3:]
                        elif op[:3] == "Add":
                            op= "Sub" + op[3:]
                        
                        # TODO: FIXME:
                        d = str(hex((2**64) - int(operr, 16)))
                        b.var_table[tmp]["op"] = [cc.encode_operation(op), f'{pvid},{d}']
                        b.var_table[tmp]["t"] = t
                        b.var_table[tmp]["pc"] = b.pcs[idx]
                        b.var_table[tmp]["lid"] = self.line_no
                        self.line_no += 1
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
                    b.var_table[tmp]["lid"] = self.line_no
                    self.line_no += 1
                    b.var_list.append(tmp)
                    dti = dtypes[j]
                    b.types.append(dti)
                    j += 1
            elif type(st) == pyvex.IRStmt.Put:
                glob_table[st.offset] = st.data
                r = archinfo.ArchAMD64().translate_register_name(st.offset, st.data.result_size(tyenv)//8)
                args = r
                if args == "rip":
                    continue
                if not args in b.var_table:
                    b.var_table[args] = []
                
                b.var_table[args].append({"op": [cc.encode_operation("Put"), str(st.data)], "t": "u", "pc": b.pcs[idx], "lid": self.line_no})

                self.line_no += 1
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
                b.var_table[mid]['lid'] = self.line_no
                self.line_no += 1
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
                b.var_table[gkey]['lid'] = self.line_no
                self.line_no += 1
                b.var_list.append(gkey)
                dti = dtypes[j]
                b.types.append(dti)
                j += 1
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
        self.line_no += 1
        return

    def translate_block(self, opcodes, fname, pc, image_name, process_name, signature, fsize, bid):
        if self.arch == 'i386':
            irsb = pyvex.lift(opcodes, int(pc), archinfo.ArchX86())
        else:
            irsb = pyvex.lift(opcodes, int(pc), archinfo.ArchAMD64())

        bl = IRBlock()
        bl.pcs = [x.addr for x in irsb.statements if type(x)==pyvex.IRStmt.IMark]
        if len(bl.pcs) == 0:
            bl.pcs.append(pc)
        
        #bl.types = irsb.tyenv.types
        bl.fname = fname
        bl.image_name = image_name
        bl.pname = process_name
        bl.statements = irsb.statements

        if fsize != None:
            bl.fsize =  fsize
        bl.types = irsb.tyenv.types
        
        if utils.is_hex(str(irsb.next)):
            bl.next = str(hex(int(str(irsb.next), 16)))
            assert int(bl.next, 16) == int(str(irsb.next), 16)
        else:
            bl.next = str(irsb.next)
        bl.jump_kind = str(irsb.jumpkind)

        self.decode_block(bl, irsb._tyenv)
        self.blocks[bid] = bl




