#--------------------------------------
# File: main.py
#
# Purpose: Interface between the CLI and the analysis modules
#--------------------------------------
import hy2.core.ir as ir
import json
import os
from colorama import Fore
import time
import hy2.core.utils as utils
import hy2.static_ext as static_ext
import hy2.core.model_infer as model_infer
import logging
import hy2.core.partial_cfg as pcfg
import hy2.core.checker as checker

# Latency names used in stats.json, mapped from the names panda_replay.export_latency() uses
STATS_LATENCY_KEYS = {'trace_analysis': 'trace_analysis', 'vm_read': 'vm_read', 'vm_write': 'vm_write',
                      'bb_exec': 'bb_exec', 'hook': 'hook_symbols', 'hook_symbols': 'hook_symbols',
                      'process_active': 'context_switch', 'context_switch': 'context_switch',
                      'sys_read': 'sys_read', 'total': 'total'}

# Records one trace run (test case) in <target>/stats.json. Each test case
# keeps its own entry under "runs" (re-running it replaces the entry), and the
# top-level no_blocks / latency / errors shown in the web UI are totals over runs.
def update_stats_file(target_path, target, tc_name, no_blocks, errors, data):
    stats_file = os.path.join(target_path, target, 'stats.json')
    stats = {}
    if os.path.exists(stats_file):
        try:
            with open(stats_file, 'r') as f:
                stats = json.load(f)
        except Exception:
            stats = {}
    runs = stats.get('runs', {})

    latency = {}
    for k, v in (data or {}).items():
        if k in STATS_LATENCY_KEYS and isinstance(v, (int, float)):
            latency[STATS_LATENCY_KEYS[k]] = v
    runs[tc_name] = {'no_blocks': no_blocks, 'errors': [str(e) for e in errors], 'latency': latency,
                     'time': time.strftime('%Y-%m-%d %H:%M:%S')}

    totals = {'trace_analysis': 0, 'vm_read': 0, 'vm_write': 0, 'bb_exec': 0, 'hook_symbols': 0, 'context_switch': 0}
    for r in runs.values():
        for k, v in r['latency'].items():
            totals[k] = totals.get(k, 0) + v
    stats['runs'] = runs
    stats['latency'] = totals
    stats['no_blocks'] = sum(r['no_blocks'] for r in runs.values())
    stats['errors'] = ''.join(f'{t}: {e}\n' for t, r in runs.items() for e in r['errors'])
    with open(stats_file, 'w') as f:
        json.dump(stats, f, indent=2)

# I don't remember what this does...
def getSymbolsData(symbols, symbols_data, call_data, block_id, baddr, in_target):
    sym_data = []
    if baddr in symbols:
        b_func = f'{symbols[baddr]["libname"]}-{symbols[baddr]["symname"]}'
        if not in_target and f'{baddr}-{block_id}' in symbols_data:
            d = symbols_data[f'{baddr}-{block_id}']
            sym_data.append([b_func] + d)
    
    if block_id in symbols_data:
        d = symbols_data[block_id]
        for di in d:
            dpc = di[0]
            dcall = 'syscall'
            if dpc in symbols:
                dcall = f'{symbols[dpc]["libname"]}-{symbols[dpc]["symname"]}'
            dargs = di[1:]
            sym_data.append([dcall]+dargs)

    if block_id in call_data:
        d = call_data[block_id]
        for di in d:
            dpc = di['pc']
            dname = di["fname"]
            dargs = di["args"]
            sym_data.append([dname]+dargs)

    return sym_data

def do_print_model(target_path, target):
    if not "/" in target:
        model_path = os.path.join(target_path, target)
    else:
        model_path = target
    if '.json' in model_path:
        model_path = model_path[:-5]
    
    if "_tc_" in model_path and not "-backing.bin" in model_path:
        model_path = f'{model_path}-backing.bin'
    elif not "_tc_" in model_path:
        model_path = os.path.join(model_path, 'model.labels')
    
    m = pcfg.import_trace(model_path)
    for sid, m0 in m.items():
        print(sid, end=' ')
        m0.toConsole()

def do_infer_model(GLOB_CONF, target):
    target_path = GLOB_CONF.target_path
    out_dir = os.path.join(target_path, target)
    target_files = os.listdir(out_dir)
    trace_files = [os.path.join(target_path, target, x) for x in target_files if ".bin" in x]
    trace_ids = list(set([os.path.basename(t).split('-')[0] for t in trace_files]))
    target_profile = os.path.join(GLOB_CONF.target_path, target, 'profile.json')
    f  = open(target_profile, 'r')
    dat = json.load(f)
    f.close()
    if "enable_multithread_analysis" in dat:
        GLOB_CONF.enable_multithread_analysis = dat["enable_multithread_analysis"]
    
    if "enable_backedge_analysis" in dat:
        GLOB_CONF.enable_backedge_analysis = dat["enable_backedge_analysis"]
    
    model_infer.infer_model(GLOB_CONF, target, trace_ids)

def do_check(GLOB_CONF, target):
    if "/" in target:
        target = target.split("/")[-2]
    target_profile = os.path.join(GLOB_CONF.target_path, target, 'profile.json')
    f  = open(target_profile, 'r')
    dat = json.load(f)
    f.close()
    if "enable_multithread_analysis" in dat:
        GLOB_CONF.enable_multithread_analysis = dat["enable_multithread_analysis"]
    
    if "enable_backedge_analysis" in dat:
        GLOB_CONF.enable_backedge_analysis = dat["enable_backedge_analysis"]
    
    properties_list = []
    if 'properties' in dat:
        properties_list = dat['properties']
    else:
        properties_list = os.listdir(os.path.join(GLOB_CONF.property_dir, 'json'))
        properties_list.remove('lib.json')
    
    #checker.do_check(GLOB_CONF, target, properties_list)
    checker.initialize_check(GLOB_CONF, target, properties_list) 

# TO DO: Re-implement Me!
def libTraceToPartialCFG():
    pass


# IN:
# target
# target_page
# test_case_name
# target_pages
# bobjs
# ro_sect
# symbols
# blocks 
# block_traceback
# symbol_data
# block_regs
# call_data
# local_bin_path
# arch 
# stat_data
# target_space
# ext_data

# blocks in blocks table are indexed by pc-size
def traceToPartialCFG(target, target_page, test_case_name, target_pages, bobjs, ro_sect, symbols, blocks, block_traceback, symbol_data, block_regs, call_data, local_bin_path, GLOB_CONF, arch='x86_64', stat_data={}, ext_data={}):
    startTime = time.time()
    ir_constructor = ir.IRConstructor(target, local_bin_path, arch)
    ir_constructor.set_target_bin(target)

    ir.GLOBAL_CONFIG = GLOB_CONF
    ir.GLOBAL_CONFIG.toStr()
    block_trace = []
    rel_addrs = []
    aliases = utils.get_sequential_pages(target_pages)
    
    trace_summary = {'labels': {}, 'count': 0}

    varCode = utils.getVarPrefix(GLOB_CONF.target_path, target, test_case_name)
    
    #TODO: Fix me!
    if not ro_sect == None:
        bP, oP = utils.getPageList(target_page, target_pages)
        ro_sect['base'] = bP
        ro_sect['offset'] = oP
        ro_sect['target_pages'] = target_pages
        ro_sect['aliases'] = aliases
        ir_constructor.ro_sect = ro_sect

    # TODO: Implement me!
    #if GLOB_CONF.target_space == "kernel":
    #    symbols = utils.readKernelSyms()

    for k,b in blocks.items():
        baddr = b["pc"]
        b_func = b['func_id']
        if baddr in symbols:
            b_func = f'{symbols[baddr]["libname"]}-{symbols[baddr]["symname"]}'
            if not b_func in trace_summary['labels']:
                trace_summary['labels'][b_func] = 0
            trace_summary['labels'][b_func] += 1
    
        if b['in_target']:
            if GLOB_CONF.target_space == "kernel":
                b_sign = ""
                b_fsize = 0
                target_base, page_name = utils.get_matching_base(baddr, target_pages, aliases)
                if not target_base == None:
                    abs_addr = abs(target_base-baddr)
                    saddr = str(abs_addr)
                    if saddr in symbols:
                        b_func = symbols[saddr]
                elif str(baddr) in symbols:
                    b_func = symbols[str(baddr)]
            else:
                b_sign = ""
                b_fsize = 0
                target_base, page_name = utils.get_matching_base(baddr, target_pages, aliases)
                if not target_base == None:
                    abs_addr = abs(target_base-baddr)
                    rel_addrs.append(abs_addr)
                    b_abs_addr = abs_addr.to_bytes(4, 'little')
                    bhash = utils.md5(b_abs_addr + b["insn"])

                    sabs_addr = str(abs_addr)
                    if page_name in bobjs and sabs_addr in bobjs[page_name]:
                        #if sabs_addr in bobjs and page_name == target:
                        # The length of these should always be 1 or 2
                        idx = 0
                        binst_objs = bobjs[page_name][sabs_addr]
                        len_bobjs = len(binst_objs)
                        if len_bobjs > 1:
                            if binst_objs[1]["bhash"] == bhash:
                                idx = 1
                    
                        b_func = binst_objs[idx]["fname"]
                        b_sign = binst_objs[idx]["signature"]
                        b_fsize = binst_objs[idx]["fsize"]
                    
                        if not b_func in trace_summary['labels']:
                            trace_summary['labels'][b_func] = 0
                        trace_summary['labels'][b_func] += 1
                    else:
                        pass
                else:
                    print(baddr)
                    raise Exception()
            
            block_trace.append(baddr)
            # TODO: REFACTOR THIS!
            if "func_name" in b:
                b_func = b["func_name"]
            # insn - raw bytes of block
            # b_func - function name
            # baddr - block addr
            # target - target name
            # target - target name
            # b_sign - function signature
            # b_fsize - function size
            # k - block id
            ir_constructor.translate_block(b["insn"], b_func, baddr, target, target, b_sign, b_fsize, k)
    
    ir_constructor.build_asts(block_regs)
    ghost_blocks_drop = {}
    block_data = {}

    lbt = len(block_traceback)
    trace_summary["count"] = lbt
    new_block_traceback = []
    i = 0
    sym_tid = 0
    symb_tids = {}
    while i < lbt:
        block_id = i

        bid, tid = block_traceback[i]

        if tid in symb_tids:
            symb_tid = symb_tids[tid]
        else:
            symb_tid = f'{varCode}{sym_tid}'
            symb_tids[tid] = symb_tid
            sym_tid += 1
        
        b = blocks[bid]
        baddr = b["pc"]
        if baddr in ir_constructor.ghost_blocks:
            ghost_blocks_drop[baddr] = ir_constructor.ghost_blocks[baddr]
        
        b_func = b['func_id']
        block_data[block_id] = {"tid": 0, "sym_data": []}
        block_data[block_id]["tid"] = symb_tid

        sym_data = getSymbolsData(symbols, symbol_data, call_data, block_id, baddr, b['in_target'])
        block_data[block_id]['sym_data'] = sym_data
        new_block_traceback += [(bid, symb_tid, i)]
        i += 1
    
    if len(ir_constructor.ghost_blocks) > 0:
        # pass in ext_pages from panda_replay, filter out ghost_blocks in ext_pages
        ghost_blocks, ghost_nodes, ghost_branches, mgj = static_ext.callGhostBranches(GLOB_CONF, target, local_bin_path, bobjs, block_trace, ir_constructor, target_pages, aliases, ghost_blocks_drop, ext_data)
        tids_map = {v: k for k, v in symb_tids.items()}
        ir_constructor.build_cfg(target, test_case_name, varCode, new_block_traceback, block_data, tids_map, "",ghost_branches, ghost_nodes, ghost_blocks, mgj, ghost_blocks_drop)

    else:
        tids_map = {v: k for k, v in symb_tids.items()}
        ir_constructor.build_cfg(target, test_case_name, varCode, new_block_traceback, block_data, tids_map, "")

    endTime = time.time()
    traceAnalysisLatency = endTime - startTime
    # passed back to miner.run_replay, which records it in stats.json
    if not "latency" in stat_data:
        stat_data['latency'] = {}
    stat_data['latency']['trace_analysis'] = traceAnalysisLatency
    logging.debug(f'Var Code: {varCode} Test Case Name: {test_case_name}')
    print(f'Var Code: {varCode} Test Case Name: {test_case_name}')
    logging.debug(f'Latency (Trace Analysis): {traceAnalysisLatency}')
    print(f'Latency (Trace Analysis): {traceAnalysisLatency}')