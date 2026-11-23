import time
import io
import os
import capstone
from colorama import Fore
import signal
import json
from hy2.core.dt_table import DiscreteTimeTable
import sys
import logging
from hy2.core.utils import telescope, md5, checkOnHeap
import hy2.orch.panda_docker as panda_docker

analysis_active = False
target_asid = 0
target_tids = []
last_regs = {}

stack_pointers = {
    "x86_64": "RSP",
    "x86": "ESP",
    'i386': 'ESP'
}

fcalls = []
last_stack_size = 0
trigger_check_stack = False


class ScrapeCapture:
    def __init__(self):
        # Targeting
        self.target_type = ""
        self.target_proc_name = ""
        self.target_page_names = []
        self.target_tids = []
        self.target_space = ""

        # Symbols
        self.symbols = {}
        self.symbols_data = {}

        # Blocks
        self.blocks = {}
        self.block_order = []
        self.bid = 0
        self.last_tid_block = {}
        
        # Functions
        self.functions = {}
        self.fid = 0
        
        # Target Pages:
        self.target_pages = []
        self.proc_pages = []
        self.aliases = {}
        
        # Calls:
        self.call_data = {}
        self.missing_oos_bid = 0
        self.missing_oos_var = []
        
        # Lib Pages:
        self.entry_points = []
        self.exit_points = []
        self.process_pages = {}

        self.ext_funcs = {}
        self.ext_funcs_data = {}
        self.ext_funcs_pages = []
        
        self.reg_table = DiscreteTimeTable()
        self.vmem_stream = open("vmem_stream.log", 'w')
        
    # The log file handle can't be pickled (used to send the capture back from the docker container)
    def __getstate__(self):
        state = self.__dict__.copy()
        state.pop("vmem_stream", None)
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        # vmem_stream.log was already written by the process that ran the replay
        self.vmem_stream = io.StringIO()

    def add_process_page(self, address, name, size):
        if address not in self.process_pages:
            self.process_pages[address] = {'name': name, "size": size}

    def print_debug(self):
        print(f'Blocks: {len(self.blocks.keys())}')
        print(f'        {len(self.block_order)}')
        print(f'Target Pages: {str(self.target_pages)}')


    def map_out_sequential_pages(self):
        last_base = 0
        last_offset = 0
        for (b, o, _) in self.target_pages:
            if b == (last_base + last_offset):
                if last_base in self.aliases:
                    self.aliases[b] = self.aliases[last_base]
                else:
                    self.aliases[b] = last_base
        
            last_base = b
            last_offset = o
    
    # TO DO: FINISH ME!
    def get_matching_base(self, pc):
        for (b, o, _) in self.target_pages:
            if pc > b and pc < (b + o):
                if b in self.aliases:
                    return self.aliases[b]
                return b
    
        return None

    def check_in_ext_pages(self, pc):
        for (b, o) in self.ext_funcs_pages:
            if pc > b and pc < (b + o):
                print(self.ext_funcs_data)
                fname = self.ext_funcs_data[b]['fname']
                return True, fname
        return False, None
    
    def check_is_new_function(self, pc, sp):
        if sp in self.functions:
            return False, self.functions[sp]["id"]
        else:
            cfid = "unknown-"+str(self.fid)
            self.functions[sp] = {"id": cfid, "pc": pc}
            self.fid+=1
            return True, cfid

    def get_last_block(self, pc, tid):
        if len(self.block_order) == 0:
            return "X", 0

        for i in range(len(self.block_order)-1, -1, -1):
            b, t = self.block_order[i]
            bl = self.blocks[b]
            if t == tid and bl["pc"] <= pc and (bl["pc"]+bl["size"]) > pc:
                return i, bl['pc']
        return "X", 0
    
    def record_entry_points(self, pc):
        self.entry_points.append(len(self.block_order)-1)
        self.exit_points.append(pc)

    def check_in_target(self, pc):
        return any([pc > tb and pc < (tb + to) for (tb, to, tn) in self.target_pages])
    
    def lib_check_in_process(self, pc):
        return any([pc > tb and pc < (tb + to) for (tb, to, tn) in self.proc_pages])
    
    def is_target(self, pc, name, tid, is_kernel, check_type="proc"):
        if check_type == "proc":
            if self.target_space == "kernel":
                return analysis_active and (name == self.target_proc_name or name == self.target_proc_name[:15]) and tid in self.target_tids and is_kernel
            else:
                return analysis_active and (name == self.target_proc_name or name == self.target_proc_name[:15]) and tid in self.target_tids and self.check_in_target(pc)
        if check_type == "mem":
            return analysis_active and (name == self.target_proc_name or name == self.target_proc_name[:15]) and tid in self.target_tids and self.check_in_target(pc)
        if check_type == "tids":
            return analysis_active and (name == self.target_proc_name or name == self.target_proc_name[:15]) and not tid in self.target_tids and self.check_in_target(pc)
        if check_type == "lib":
            return (name == self.target_proc_name or name == self.target_proc_name[:15]) and tid in self.target_tids and self.lib_check_in_process(pc)
        if check_type == "call":
            return analysis_active and tid in self.target_tids and (name == self.target_proc_name or name == self.target_proc_name[:15])
        if check_type == "sys":
            return analysis_active and tid in self.target_tids and (name == self.target_proc_name or name == self.target_proc_name[:15]) and len(self.block_order) > 0
        
        return False

    def add_call_data(self, pc, tid, fname, args):
        if len(self.block_order) == 0:
            return
        bid = len(self.block_order) - 1
        if not bid in self.call_data:
            self.call_data[bid] = []
        self.call_data[bid].append({"pc": pc, "tid": tid, "fname": fname, "args": args})

    def add_block(self, pc, tid, insn, sp, in_kernel, size, block_regs, func_name=""):        
        in_target = True  # wth?
        if in_target:
            _, fid = self.check_is_new_function(sp, pc)
            psid = f'{pc}-{size}'
            if not psid in self.blocks:
                self.blocks[psid] = {"pc": pc, "insn": insn, "func_id": fid, "in_target": in_target, "size": size}
                if func_name != "":
                    self.blocks[psid]["func_name"] = func_name

                self.block_order.append((psid, tid))
                self.last_tid_block[tid] = len(self.block_order) - 1
            else:
                self.block_order.append((psid, tid))
                #print(f'{psid} {tid}')
                self.last_tid_block[tid] = len(self.block_order) - 1

            self.reg_table.add_values_at(tid, block_regs, len(self.block_order)-1)

            self.bid +=1
            if self.bid % 1000 == 0:
                self.print_debug()

    def add_vmem(self, pc, tid, addr, data):
        bid, bpc = self.get_last_block(pc, tid)
        if bid == "X":
            return
        assert addr > 0
        assert bpc <= pc
        bid_addr_idx = f'{bid}-{addr}'
        data['pc'] = pc
        data['tid'] = tid
        data['idx'] = bid_addr_idx
        line = json.dumps(data)
        self.vmem_stream.write(line+'\n')
    
    def add_symbols(self, pc, symbol_name):
        assert not (pc in self.symbols and self.symbols[pc]!=symbol_name)
        self.symbols[pc] = symbol_name

    def add_symbols_data(self, pc, tid, data, sysc=False):
        if len(self.blocks) == 0 or tid not in self.last_tid_block:
            print("Dropping call "+str(sysc) + " " + str(data))
            return
        
        bid = self.last_tid_block[tid]
        #len(self.block_order) -1
        if not bid in self.symbols_data:
            self.symbols_data[bid] = []
            if not sysc:
                # to do:
                self.missing_oos_bid = bid
                self.missing_oos_var = []
                i = 0
                for x in data:
                    if len(x) == 1 and int(x[0]["data"]) > 0xfff and not "str" in x[0]:
                        self.missing_oos_var.append((int(x[0]["data"]), i))

                    i+=1
        #print(data)
        if sysc:
            self.symbols_data[bid].append([pc, tid]+data)
        else:
            self.symbols_data[bid].append([pc, tid]+data)
        return bid
    
    # I forget what this does
    def update_symbols_data(self, data):
        for i in range(len(self.missing_oos_var)):
            if i >= len(data):
                break
            x = self.missing_oos_var[i]
            z = data[i]
            self.symbols_data[self.missing_oos_bid][0][2+x[1]] = z

bb_exec_latency = 0
vm_read_latency = 0
vm_write_latency  = 0
hook_latency = 0 
sys_read_latency = 0
pswitch_latency = 0

def export_latency():
    return {"bb_exec": bb_exec_latency, "vm_read": vm_read_latency, "vm_write": vm_write_latency, "hook": hook_latency, "sys_read": sys_read_latency, "process_active": pswitch_latency}

def print_latency(logging_enabled=False):
    if logging_enabled:        
        logging.debug(f'BB Exec: {bb_exec_latency}')
        logging.debug(f'VM Read: {vm_read_latency}')
        logging.debug(f'VM Write: {vm_write_latency}')
        logging.debug(f'Hook: {hook_latency}')
        logging.debug(f'sys_read: {sys_read_latency}')
        logging.debug(f'Process Active: {pswitch_latency}')
    
    print(f'BB Exec: {bb_exec_latency}')
    print(f'VM Read: {vm_read_latency}')
    print(f'VM Write: {vm_write_latency}')
    print(f'Hook: {hook_latency}')
    print(f'sys_read: {sys_read_latency}')
    print(f'Process Active: {pswitch_latency}')
    

skipped_symbols_cached = {}

scrape_capture = ScrapeCapture()
read_hook_on = False
last_block = False
last_pc = 0
seen = []

af_triggered_funcs = []
# I don't remember what this does:
def check_af_target_pages(pc, ext_func_data):
    for ext in af_triggered_funcs:
        b,a = ext_func_data[ext]['page']
        if pc > b and pc < (b + a):
            return True
    return False

def popExtFuncAddr(addr):
    global af_triggered_funcs
    idx = af_triggered_funcs.index(addr)
    af_triggered_funcs.pop(idx)


def check_af_ret(pc, ext_func_data):
    global af_triggered_funcs
    rets = [ext_func_data[a]['ret'] for a in af_triggered_funcs]
    if pc in rets:
        idx = rets.index(pc)
        af_triggered_funcs.pop(idx)


# Function: do_run_replay
# ARGS:
# - recording_name - name of recording file
# - target - target process name
# - target_pages - name of executable backing target pages within the process
# - out_of_scope - parts of the target (function names) that are out scope
def do_run_replay(glob_config, recording_name, target, target_pages, out_of_scope, image_type, inclusions = [], inclusions_named = [], target_type='prog', arch="x86_64"):
    if panda_docker.use_docker(glob_config):
        return do_run_replay_docker(glob_config, recording_name, target, target_pages, out_of_scope, image_type, inclusions, inclusions_named, target_type, arch)

    from pandare import Panda  # imported here so the module can be loaded on hosts without pandare

    if arch == "x86_64":
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    else:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    
    scrape_capture.target_type = target_type
    scrape_capture.target_proc_name = target
    scrape_capture.target_space = glob_config.target_space

    target_trunc = target[:15]
    target_page_trunc = [t[:15] for t in target_pages]
    targetPages = target_pages + target_page_trunc
    skipped_symbols = out_of_scope
    no_skipped = len(skipped_symbols.keys())

    if image_type == "generic":
        panda = Panda(generic=arch)
    else:
        panda_flags = ["-show-cursor", "-display", 'none', "-loadvm", "srvd1", "-k", "en-us","-nographic"]
        panda = Panda(arch='x86_64', qcow=glob_config.guest_image, os="linux", mem="8192M", expect_prompt="ubuntu@ubuntu", extra_args=panda_flags,  os_version="linux-64-ubuntu:5.4.0-122-generic")

    panda.enable_precise_pc()
    panda.enable_memcb()
    panda.enable_all_callbacks()
    panda.require('osi')
    
    # To analyze multiple processes uncomment this, and comment out the next line:
    #@panda.cb_before_block_exec
    @panda.cb_before_block_exec(procname=target_trunc)
    def bb_exec_cb(cpu, tb):
        start = time.time()
        asid = panda.current_asid(cpu)
        name = panda.get_process_name(cpu)
        pc = tb.pc
        global scrape_capture
        global skipped_symbols_cached
        global last_block
        global last_pc
        global af_triggered_funcs

        tobj = panda.plugins['osi'].get_current_thread(cpu)
        tid = tobj.tid
        in_kernel = panda.in_kernel(cpu)

        is_ext_func = False
        ext_func_name = ""

        if pc in scrape_capture.ext_funcs.values():
            funcName = [k for k,v in scrape_capture.ext_funcs.items() if v == pc][0]
            if 'is_named' in scrape_capture.ext_funcs_data[pc] and scrape_capture.ext_funcs_data[pc]['is_named']:
                #scrape_capture.ext_funcs_data[pc]['fname'] = funcName
                ext_func_name = funcName
            else:
                ra = panda.arch.get_return_address(cpu)
                scrape_capture.ext_funcs_data[pc]['fname'] = funcName
                ext_func_name = funcName
                scrape_capture.ext_funcs_data[pc]['ret'] = ra
                af_triggered_funcs.append(pc)
            is_ext_func = True
        
        if af_triggered_funcs != [] and check_af_target_pages(pc, scrape_capture.ext_funcs_data):
            is_ext_func = True
        
        if af_triggered_funcs != []:
            check_af_ret(pc, scrape_capture.ext_funcs_data)
        
        extb, extfn = scrape_capture.check_in_ext_pages(pc)
        if extb:
            ext_func_name = extfn
            is_ext_func = True

        if scrape_capture.is_target(pc, name, tid, in_kernel, check_type="tids"):
            scrape_capture.target_tids.append(tid)
        
        if not scrape_capture.is_target(pc, name, tid, in_kernel, check_type="proc") and not is_ext_func:
            if scrape_capture.is_target(pc, name, tid, in_kernel, check_type="lib"):
                last_pc = pc
            else:
                last_pc = 0
            
            last_block = False
            return

        instrs = b""
        if pc in skipped_symbols_cached and skipped_symbols_cached[pc]["is_call"]:
            fname = skipped_symbols_cached[pc]["fname"]
            scrape_capture.add_call_data(pc, tid, fname, [telescope(panda, cpu, panda.arch.get_arg(cpu, 0)), telescope(panda, cpu, panda.arch.get_arg(cpu, 1)), telescope(panda, cpu, panda.arch.get_arg(cpu, 2)), telescope(panda, cpu, panda.arch.get_arg(cpu, 3))])
            
            return
        
        size = tb.size
        code = panda.virtual_memory_read(cpu, pc, size)
        dis = md.disasm(code, pc)   
        instrs =  b"".join([d.bytes for d in dis])
        
        if no_skipped > 0:
            base_pc = scrape_capture.get_matching_base(pc)
            if base_pc != None and base_pc > 0:
                abs_addr = abs(base_pc-pc)

                #print(abs_addr)
                b_abs_addr = abs_addr.to_bytes(4, 'little')

                bhash = md5(b_abs_addr + instrs)
                if bhash in skipped_symbols:
                    fname = skipped_symbols[bhash]
                    skipped_symbols_cached[pc] = fname
                    if fname["is_call"]:
                        scrape_capture.add_call_data(pc, tid, fname["fname"], [telescope(panda, cpu, panda.arch.get_arg(cpu, 0)), telescope(panda, cpu, panda.arch.get_arg(cpu, 1)), telescope(panda, cpu, panda.arch.get_arg(cpu, 2)), telescope(panda, cpu, panda.arch.get_arg(cpu, 3))])
                
                    return
            
        
        block_regs = {}
            
        for reg, idx in panda.arch.registers.items():
            val = panda.arch.get_reg(cpu, idx)
            tdat = []
            if not reg[1:] in ["SP", "BP"] and val > 0xfff:
                tdat = telescope(panda, cpu, val)
            block_regs[reg.lower()] = {"val": val, "telescope": tdat}
        
        if last_pc != 0 and target_type == "lib":
            scrape_capture.record_entry_points(last_pc)
        scrape_capture.add_block(pc, tid, instrs, panda.arch.get_reg(cpu, stack_pointers[arch]), in_kernel, size, block_regs, ext_func_name)
        
        last_pc = 0
        last_block = True
        end = time.time()
        global bb_exec_latency
        bb_exec_latency += end - start
        return
    
    def mmap_cb(**kwargs):
        args = kwargs['args']
        cpu = args[0]
        asid = panda.current_asid(cpu)
        name = panda.get_process_name(cpu)
        tobj = panda.plugins['osi'].get_current_thread(cpu)
        tid = tobj.tid

        global scrape_capture
        if not scrape_capture.is_target(0, name, tid, False, check_type="call"):
            return

        get_proc_mapping(cpu)

    def read_cb(**kwargs):
        start = time.time()
        args = kwargs['args']
        cpu = args[0]
        asid = panda.current_asid(cpu)
        name = panda.get_process_name(cpu)
        tobj = panda.plugins['osi'].get_current_thread(cpu)
        tid = tobj.tid

        global scrape_capture
        if not scrape_capture.is_target(0, name, tid, False, check_type="call"):
            return
        
        pc = args[1]
        fd = args[2]
        buf = args[3]
        size = args[4]
        #print(f'--------> READ: on_sys_read {name} {pc} {fd} {buf} {size}')
        scrape_capture.add_symbols(pc, {"libname": "syscall", "symname": 'on_sys_read'})
        scrape_capture.add_symbols_data(pc, tid, [fd, buf, size], sysc=True)
        end =  time.time()
        global sys_read_latency
        sys_read_latency += end - start

    """    
    def write_cb(**kwargs):
        start = time.time()
        args = kwargs['args']
        cpu = args[0]
        asid = panda.current_asid(cpu)
        name = panda.get_process_name(cpu)
        tobj = panda.plugins['osi'].get_current_thread(cpu)
        tid = tobj.tid

        if not analysis_active or not tid in target_tids or name != target:
            return
        
        
        pc = args[1]
        fd = args[2]
        buf = args[3]
        size = args[4]
        
        global scrape_capture
        scrape_capture.add_symbols(pc, {"libname": "syscall", "symname": 'on_sys_write'})
        scrape_capture.add_symbols_data(pc, tid, [fd, buf, size], sysc=True)
        end =  time.time()
        global sys_read_latency
        sys_read_latency += end - start
    """

    def try_get_arg(panda, env, arg_no):
        try:
            return panda.arch.get_arg(env, arg_no)
        except:
            return None

    #@panda.hook_symbol(None, None)
    #def hook_symbols(env, tb, h):
    def hook_symbols(**kwargs):
        start = time.time()
        args = kwargs['args']
        env = args[0]

        asid = panda.current_asid(env)
        name = panda.get_process_name(env)
        tobj = panda.plugins['osi'].get_current_thread(env)
        tid = tobj.tid
        global scrape_capture
        
        tb = args[1]
        h = args[2]
        libname = panda.ffi.string(h.sym.section)
        symname = panda.ffi.string(h.sym.name)
        pc = tb.pc

        if not scrape_capture.is_target(0, name, tid, False, check_type="sys"):
            return        
        
        scrape_capture.add_symbols(pc, {"libname": libname, 'symname': symname})
        if not arch == 'i386':
            cbid = scrape_capture.add_symbols_data(pc, tid, [telescope(panda, env, panda.arch.get_arg(env, 0)), telescope(panda, env, panda.arch.get_arg(env, 1)), telescope(panda, env, panda.arch.get_arg(env, 2)), telescope(panda, env, panda.arch.get_arg(env, 3)), telescope(panda, env, panda.arch.get_arg(env, 4))])
        else:
            cbid = scrape_capture.add_symbols_data(pc, tid, [telescope(panda, env, panda.arch.get_reg(env, panda.arch.registers["EDI"])), telescope(panda, env, panda.arch.get_reg(env, panda.arch.registers["ESI"])), telescope(panda, env, panda.arch.get_reg(env, panda.arch.registers["EDX"])), telescope(panda, env, panda.arch.get_reg(env, panda.arch.registers["ECX"]))])
        """
        cargs = []
        arg0 = try_get_arg(panda, env, 0)
        if not arg0 == None:
            cargs.append(telescope(panda, env, arg0))
        arg1 = try_get_arg(panda, env, 1)
        if not arg1 == None:
            cargs.append(telescope(panda, env, arg1))
        arg2 = try_get_arg(panda, env, 2)
        if not arg2 == None:
            cargs.append(telescope(panda, env, arg2))
        arg3 = try_get_arg(panda, env, 3)
        if not arg3 == None:
            cargs.append(telescope(panda, env, arg3))
        cbid = scrape_capture.add_symbols_data(pc, tid, cargs)
        """
        data = []
        if cbid == scrape_capture.missing_oos_bid:
            for x in scrape_capture.missing_oos_var:
                data.append(telescope(panda, env, x[0]))
        
        scrape_capture.update_symbols_data(data)

        end = time.time()
        global hook_latency
        hook_latency += end - start
        return
    
    def offset_get_target_ptr(cpustate, addr, offset):
        ret = panda.ffi.new("char[]",4)
        size = panda.ffi.cast("target_ptr_t", panda.ffi.sizeof(ret))
        faddr = panda.ffi.cast("target_ptr_t", addr+offset)
        panda.virtual_memory_read(cpustate,faddr,ret,size)
        return ret 

    def resolve_symbol_address(cpu, func_name):
        asid = panda.current_asid(cpu)
        symbol = panda.ffi.new("char[]", bytes(func_name, "utf8"))
        obj = panda.plugins["dynamic_symbols"].resolve_symbol(cpu, asid, panda.ffi.NULL, symbol)
        return obj.address
    
    def get_proc_mapping(cpu):
        fname = panda.get_mappings(cpu)
        global scrape_capture
        for f in fname:
            name = panda.ffi.string(f.name)
            csize = panda.ffi.cast("target_ulong", f.size)
            cbase = panda.ffi.cast("target_ulong", f.base)
            size = int(csize)
            base = int(cbase)
            print(f'{name} {size} {base}')
            try:
                scrape_capture.add_process_page(base, name.decode(), size)
                for (pageName, funcName) in inclusions:
                        if (pageName in name.decode() or ("libc" not in name.decode() and pageName == "")) and not funcName in scrape_capture.ext_funcs:
                            addr = resolve_symbol_address(cpu, funcName)
                            if addr != 0:
                                scrape_capture.ext_funcs[funcName] = addr
                                scrape_capture.ext_funcs_data[addr] = {}
                                scrape_capture.ext_funcs_data[addr]['page'] = (base, size)
                
                for inc in inclusions_named:
                    if inc["pagename"] in name.decode() or ("libc" in name.decode() and "libc" in inc["pagename"]):
                        funcName = inc["fname"].replace("sym.", "")
                        addr = resolve_symbol_address(cpu, funcName)
                        if addr != 0:
                            print(Fore.LIGHTMAGENTA_EX + f'[>] {funcName}' + Fore.RESET)
                            scrape_capture.ext_funcs_pages.append((addr, inc["size"]))
                            assert addr > base and addr < (base + size)

                            if not addr in scrape_capture.ext_funcs_data:
                                scrape_capture.ext_funcs_data[addr] = {}
                                scrape_capture.ext_funcs_data[addr]['page'] = (base, size)
                                scrape_capture.ext_funcs_data[addr]['fname'] = inc['fname']
                                scrape_capture.ext_funcs_data[addr]['fsize'] = inc['size']
                
                #if name.decode() in [target_pages, target_page_trunc]:    
                if name.decode() in targetPages:
                    if not (base, size, name.decode()) in scrape_capture.target_pages:
                        scrape_capture.target_pages.append((base, size, name.decode()))
                if target_type == "lib" and name.decode() in [target, target_trunc]:
                    if not (base, size) in scrape_capture.proc_pages:
                        scrape_capture.proc_pages.append((base, size, name.decode()))
            except:
                pass
        scrape_capture.map_out_sequential_pages()
    
    #def gen_on_translate_cb():
    #    panda.cb_insn_translate(enabled=True)(lambda x,y: True)
    
    #def gen_on_insn_exec_cb():
    #    panda.cb_insn_exec()(lambda *args: insn_exec(args=args))
    
    #def gen_before_block_exec_cb():
    #    panda.cb_before_block_exec()(lambda *args: bb_exec_cb(args=args))
    
    def gen_on_mmap_cb():
        panda.ppp('syscalls2', 'on_sys_mmap_return')(lambda *args: mmap_cb(args=args))

    def gen_on_read_cb():
        panda.ppp('syscalls2', 'on_sys_read_enter')(lambda *args: read_cb(args=args))
    
    def gen_hook_symbols_cb():
        panda.hook_symbol(None, None)(lambda *args: hook_symbols(args=args))

    def gen_virt_mem_write_cb():
        panda.cb_virt_mem_after_write()(lambda *args: mem_callback('mw', args=args))
    
    def gen_virt_mem_read_cb():
        panda.cb_virt_mem_after_read()(lambda *args: mem_callback('mr', args=args))
    
    """
    typedef struct osi_module_struct {
    target_ptr_t modd;
    target_ptr_t base;
    target_ptr_t size;
    char *file;
    char *name;
    } OsiModule;
    """
    
    @panda.ppp("osi", "on_task_change")
    def task_change(cpu):
        start = time.time()
        global analysis_active
        global target_asid
        #global target_tids
        global scrape_capture
        name = panda.get_process_name(cpu)
        tobj = panda.plugins['osi'].get_current_thread(cpu)
        tid = tobj.tid

        print(f'Process {name} started... {target_asid} {panda.current_asid(cpu)}')

        if (name == target or name == target_trunc) and not analysis_active:
            target_asid = panda.current_asid(cpu)
            scrape_capture.target_tids.append(tid)
            analysis_active = True
            print('Initializing callbacks....')
            #gen_on_translate_cb()
            #gen_on_insn_exec_cb()
            #gen_before_block_exec_cb()
            gen_on_read_cb()
            gen_hook_symbols_cb()
            if image_type != "generic":
                gen_on_mmap_cb()
            #gen_virt_mem_read_cb()
            #gen_virt_mem_write_cb()

        if (name == target or name == target_trunc) and analysis_active and not tid in scrape_capture.target_tids:
            scrape_capture.target_tids.append(tid)
            
        if (name == target or name == target_trunc) and analysis_active:            
            fname = panda.get_mappings(cpu)
            total_size = 0
            
            
            scrape_capture.print_debug()
            
            pid = tobj.pid
            #print("--------------------------------> "+str(tid) + " " + str(pid))

            for f in fname:
                name = panda.ffi.string(f.name)
                csize = panda.ffi.cast("target_ulong", f.size)
                cbase = panda.ffi.cast("target_ulong", f.base)
                size = int(csize)
                base = int(cbase)
                #print(f'{name} {size} {base}')
                try:
                    scrape_capture.add_process_page(base, name.decode(), size)
                    for (pageName, funcName) in inclusions:
                        if (pageName in name.decode() or ("libc" not in name.decode() and pageName == "")) and not funcName in scrape_capture.ext_funcs:
                            addr = resolve_symbol_address(cpu, funcName)
                            if addr != 0:
                                scrape_capture.ext_funcs[funcName] = addr
                                scrape_capture.ext_funcs_data[addr] = {}
                                scrape_capture.ext_funcs_data[addr]['page'] = (base, size)
                    
                    for inc in inclusions_named:
                        if inc["pagename"] in name.decode() or ("libc" in name.decode() and "libc" in inc["pagename"]):
                            funcName = inc["fname"].replace("sym.", "")
                            addr = resolve_symbol_address(cpu, funcName)
                            if addr != 0:
                                #print(Fore.LIGHTMAGENTA_EX + f'[>] {funcName} {addr}' + Fore.RESET)
                                scrape_capture.ext_funcs_pages.append((addr, inc["size"]))
                                if not addr in scrape_capture.ext_funcs_data:
                                    scrape_capture.ext_funcs_data[addr] = {}
                                    scrape_capture.ext_funcs_data[addr]['page'] = (base, size)
                                    scrape_capture.ext_funcs_data[addr]['fname'] = inc['fname']
                                    scrape_capture.ext_funcs_data[addr]['fsize'] = inc['size']

                    #if name.decode() in [target_pages, target_page_trunc]:
                    if name.decode() in targetPages:
                        if not (base, size, name.decode()) in scrape_capture.target_pages:
                            scrape_capture.target_pages.append((base, size,name.decode()))
                except:
                    pass
                scrape_capture.map_out_sequential_pages()
        end = time.time()
        global pswitch_latency
        pswitch_latency += end - start
    
    def mem_callback(cpu, pc, addr, size, buf, is_write):
        asid = panda.current_asid(cpu)
        name = panda.get_process_name(cpu)
        m_rw = "mr"
        if is_write:
            m_rw = "mw"

        val = panda.ffi.string(buf)
        i_val = int.from_bytes(val, byteorder='little')

        global scrape_capture
        on_heap = False
        if i_val > 4096:
            on_heap = checkOnHeap(panda, cpu, i_val)
        tobj = panda.plugins['osi'].get_current_thread(cpu)
        tid = tobj.tid        
        scrape_capture.add_vmem(pc, tid, addr, {"val": i_val, "on_heap": on_heap, "size": size, "rw": m_rw})
        return

    
    @panda.cb_virt_mem_after_write(procname=target_trunc)
    def virt_mem_after_write(cpu, pc, addr, size, buf):
        start = time.time()
        asid = panda.current_asid(cpu)
        name = panda.get_process_name(cpu)
        tobj = panda.plugins['osi'].get_current_thread(cpu)
        tid = tobj.tid
        if (af_triggered_funcs != [] and check_af_target_pages(pc, scrape_capture.ext_funcs_data)) or scrape_capture.is_target(pc, name, tid, False, "mem"):
            mem_callback(cpu, pc, addr, size, buf, True)
        else:
            b, _ = scrape_capture.check_in_ext_pages(pc)
            if b:
                mem_callback(cpu, pc, addr, size, buf, True)
        end = time.time()
        global vm_write_latency
        vm_write_latency += end - start
        return

    @panda.cb_virt_mem_after_read(procname=target_trunc)
    def virt_mem_after_read(cpu, pc, addr, size, buf):
        start = time.time()
        asid = panda.current_asid(cpu)
        name = panda.get_process_name(cpu)
        tobj = panda.plugins['osi'].get_current_thread(cpu)
        tid = tobj.tid

        if (af_triggered_funcs != [] and check_af_target_pages(pc, scrape_capture.ext_funcs_data)) or scrape_capture.is_target(pc, name, tid, False, "mem"):
            mem_callback(cpu, pc, addr, size, buf, False)
        else:
            b, _ = scrape_capture.check_in_ext_pages(pc) 
            if b:
                mem_callback(cpu, pc, addr, size, buf, False)
        end = time.time()
        global vm_read_latency
        vm_read_latency += end - start

        return

    
    def handler(signum, frame):
        panda.end_analysis()
        raise Exception("panda-re is hanging!")

    def run_replay():
        signal.signal(signal.SIGALRM, handler)
        # YIKES:
        #signal.alarm(320)
        #signal.alarm(420)
        signal.alarm(680)
        #gen_hook_symbols_cb()
        panda.run_replay(recording_name)
        time.sleep(1)
        signal.alarm(0)
        print("done!")
        global scrape_capture
        #scrape_capture.reg_stream.close()
        
    return run_replay()


# Runs do_run_replay inside the pandare docker container (see panda_docker.py),
# then loads the capture and latencies back into this module.
def do_run_replay_docker(glob_config, recording_name, target, target_pages, out_of_scope, image_type, inclusions = [], inclusions_named = [], target_type='prog', arch="x86_64"):
    global scrape_capture, bb_exec_latency, vm_read_latency, vm_write_latency, hook_latency, sys_read_latency, pswitch_latency
    job = {
        "action": "replay",
        "config": panda_docker.config_to_dict(glob_config),
        "args": {
            "recording_name": recording_name, "target": target, "target_pages": target_pages,
            "out_of_scope": out_of_scope, "image_type": image_type, "inclusions": inclusions,
            "inclusions_named": inclusions_named, "target_type": target_type, "arch": arch,
        },
    }
    extra = panda_docker.guest_image_paths(glob_config) if image_type != "generic" else []
    # Release our handle, the container (re)writes vmem_stream.log
    scrape_capture.vmem_stream.close()
    result_file = panda_docker.run_job(glob_config, job, extra)
    result = panda_docker.load_result(result_file)
    scrape_capture = result["scrape_capture"]
    lat = result["latency"]
    bb_exec_latency = lat["bb_exec"]
    vm_read_latency = lat["vm_read"]
    vm_write_latency = lat["vm_write"]
    hook_latency = lat["hook"]
    sys_read_latency = lat["sys_read"]
    pswitch_latency = lat["process_active"]
