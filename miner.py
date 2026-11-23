#!/usr/bin/env python3

#--------------------------------------
# File: miner.py
#
# Purpose: Command Line Interface for the tool, used to access different functions
#--------------------------------------

import json
import os
import time
import hy2.orch.panda_play as panda_play
import hy2.orch.panda_replay as panda_replay
import hy2.core.termui as termui
import hy2.core.glob_conf as gconf
import hy2.core.utils as utils
import hy2.main as hy2m

GLOBAL_CONFIG_FILE = "config.json"
GLOBAL_CONFIG = gconf.GlobalConfig()

import logging
logging.basicConfig(level=logging.DEBUG, filename='miner.log', format='%(levelname)s - %(message)s')

# ----------------------------------

def read_symbols_file(target):
    symbols_file = f'{target}_symbols.json'
    bbobjs = {}
    with open(symbols_file, "r") as f:
        bbobjs = json.load(f)
    if 'rodata' in bbobjs:
        return bbobjs['symbols'], bbobjs['rodata']
    return bbobjs["symbols"], None

def read_inclusions_named(target):
    inclusions_file = os.path.join(GLOBAL_CONFIG.target_path, target, "inclusions_named_symbols.json")
    if not os.path.exists(inclusions_file):
        return None
    
    f  = open(inclusions_file, 'r')
    inclusions = json.load(f)
    f.close()
    return inclusions

def get_exclusions(symbols, funcs):
    skipped_symbols = {}
    for s,v in symbols.items():
        for v0 in v:
            if v0["fname"] in funcs:
                s0 = v0["bhash"]
                skipped_symbols[s0] = {"fname": v0["fname"], "is_call": v0["is_call"]}
    
    return skipped_symbols

# ----------------------------------

def loadGlobalConfigFile():
    utils.loadGlobalConfigFile(GLOBAL_CONFIG_FILE, GLOBAL_CONFIG)

def run_play(test_file):
    loadGlobalConfigFile()
    data = None
    with open(test_file, 'r') as f:
        data = json.load(f)
    
    if data == None:
        print('Error: Could not load test case file!')

    arch = data['arch']
    target = data['target']
    recording_name = data['recording_name']
    image_type = data['image_type']
    bin_type = data['bin_type']
    artifacts_dir = GLOBAL_CONFIG.mount_path
    if 'artifacts_dir' in data:
        artifacts_dir = data['artifacts_dir']
    if 'timeout' in data:
        timeout = int(data['timeout'])
    else:
        timeout = 5
    command = data['command']
    termui.playBanner(arch, target, recording_name, image_type, bin_type, command)
    GLOBAL_CONFIG.toStr()

    extern = False
    if bin_type == "extern":
        extern = True
    
    preconditions = []
    if 'preconditions' in data:
        preconditions = data['preconditions']
    postconditions = []
    if 'postconditions' in data:
        postconditions = data['postconditions']

    panda_play.do_play(GLOBAL_CONFIG, image_type, arch, recording_name, command, target, timeout, preconditions, postconditions, artifacts_dir, extern)
    print('play done....')

def run_replay(profile_file):
    loadGlobalConfigFile()

    f = open(profile_file, "r")
    data = json.load(f)
    f.close()
    
    # FIX ME:
    target = profile_file.split("/")[-2]
    if "space" in data:
        target_space = data["space"]
        GLOBAL_CONFIG.target_space = target_space
    
    if "enable_multithread_analysis" in data:
        GLOBAL_CONFIG.enable_multithread_analysis = data["enable_multithread_analysis"]

    GLOBAL_CONFIG.static_enabled = utils.loadConfigFile(GLOBAL_CONFIG.target_path, target)

    runtime_name = data['target']
    if 'process_name' in data:
        runtime_name = data['process_name']
    
    target_page = runtime_name
    if "target_pages" in data:
        target_page = data["target_pages"]
    if type(target_page) == str:
        target_page = [target_page]
    
    if 'type' in data:
        target_type = data['type']
    else:
        target_type = 'prog'
    image_type = data["image_type"]
    recording_name = data["recording_name"]
    arch = data['arch']

    local_bin_path = ""
    if "local_bin_path" in data:
        local_bin_path = data['local_bin_path']
    elif "target_path" in data and os.path.isfile(os.path.join(GLOBAL_CONFIG.mount_path, data['target_path'])):
        local_bin_path = os.path.join(GLOBAL_CONFIG.mount_path, data['target_path'])
    elif os.path.isfile(os.path.join(GLOBAL_CONFIG.mount_path, runtime_name)):
        local_bin_path = os.path.join(GLOBAL_CONFIG.mount_path, runtime_name)
    elif "bin_type" in data and data['bin_type'] == 'built-in':
        local_bin_path = os.path.join(GLOBAL_CONFIG.mount_path, f'{runtime_name}.bin')

    bobjs, ro_sect = read_symbols_file(os.path.join(GLOBAL_CONFIG.target_path, target, target))

    skipped_symbols = {}
    if "out_of_scope" in data:
        out_of_scope = data["out_of_scope"]
        skipped_symbols = get_exclusions(bobjs, out_of_scope)
    else:
        out_of_scope = []

    if "inclusions" in data:
        inclusions = data['inclusions']
    else:
        inclusions = []
    
    inclusions_named = []
    if "inclusions_named" in data:
        inclusions_named = read_inclusions_named(target)

    bbobjs = {}
    if len(target_page) > 1:
        for tp in target_page:
            tp0 = tp.split('.')[0]
            if tp != target and os.path.exists(os.path.join(GLOBAL_CONFIG.mount_path, target, f'{tp0}_symbols.json')):
                si, _ = read_symbols_file(os.path.join(GLOBAL_CONFIG.mount_path, target, tp0))
                bbobjs[tp] = si
            else:
                bbobjs[tp] = bobjs
    else:
        bbobjs[target_page[0]] = bobjs
    
    termui.replayBanner(runtime_name, target_page)
    start_time = time.time()
    
    panda_replay.do_run_replay(GLOBAL_CONFIG, recording_name, runtime_name, target_page, skipped_symbols, image_type, inclusions, inclusions_named, target_type, arch)

    trace_data = panda_replay.scrape_capture
    trace_data.vmem_stream.close()

    target_pages = trace_data.target_pages
    block_backtrace = trace_data.block_order
    tc_name = os.path.basename(profile_file).split('.')[0]
    if len(block_backtrace) == 0:
        print('[ERROR] Target not active, check logs.')
        hy2m.update_stats_file(GLOBAL_CONFIG.target_path, target, tc_name, 0, ['Target not active, no blocks traced'], panda_replay.export_latency())
        return
    process_pages = trace_data.process_pages
    latency = panda_replay.export_latency()
    stat_data = {'pages': process_pages, 'latency': latency}
    ext_data = {}
    if len(inclusions_named) > 0:
        ext_data = {'pages': trace_data.ext_funcs_pages, 'page_data': trace_data.ext_funcs_data, 'inclusion_paths': data['inclusion_paths'], 'inclusions_named': data['inclusions_named'], 'inc_named_data': inclusions_named}
    
    if target_type == 'prog':
        try:
            hy2m.traceToPartialCFG(target, target_page, tc_name, target_pages, bbobjs, ro_sect, trace_data.symbols, trace_data.blocks, block_backtrace, trace_data.symbols_data, trace_data.reg_table, trace_data.call_data, local_bin_path, GLOBAL_CONFIG, arch, stat_data, ext_data) 
        except Exception as e:
            latency['total'] = time.time() - start_time
            hy2m.update_stats_file(GLOBAL_CONFIG.target_path, target, tc_name, len(block_backtrace), [f'Trace analysis failed: {type(e).__name__}: {e}'], latency)
            raise
    else:
        print('TO DO!')
        return

    end_time = time.time()
    total_latency = end_time - start_time
    # traceToPartialCFG adds trace_analysis to stat_data['latency'] (the same dict as latency)
    latency['total'] = total_latency
    hy2m.update_stats_file(GLOBAL_CONFIG.target_path, target, tc_name, len(block_backtrace), [], latency)
    logging.debug(f'Total: {total_latency}')
    panda_replay.print_latency(True)
    print((f'Total: {total_latency}'))

def run_model(target):
    if "/" in target:
        target = target.split("/")[-2]
    loadGlobalConfigFile()
    hy2m.do_infer_model(GLOBAL_CONFIG, target)

def run_check(target):
    loadGlobalConfigFile()
    hy2m.do_check(GLOBAL_CONFIG, target)

def run_print(target):
    loadGlobalConfigFile()
    t = GLOBAL_CONFIG.target_path
    hy2m.do_print_model(t, target)

import hy2.symres.symbol_resolution as symres
def run_symres(target):
    loadGlobalConfigFile()

    f = open(target, 'r')
    data = json.load(f)
    runtime_name = data['target']

    local_bin_path = ""
    if "local_bin_path" in data:
        local_bin_path = data['local_bin_path']
    elif "target_path" in data and os.path.isfile(os.path.join(GLOBAL_CONFIG.mount_path, data['target_path'])):
        local_bin_path = os.path.join(GLOBAL_CONFIG.mount_path, data['target_path'])
    elif os.path.isfile(os.path.join(GLOBAL_CONFIG.mount_path, runtime_name)):
        local_bin_path = os.path.join(GLOBAL_CONFIG.mount_path, runtime_name)
    elif "bin_type" in data and data['bin_type'] == 'built-in':
        local_bin_path = os.path.join(GLOBAL_CONFIG.mount_path, f'{runtime_name}.bin')
    
    symres.resolve_symbols(GLOBAL_CONFIG.target_path, "", local_bin_path, "", runtime_name)

import dbg

def dbg_workloadList(target):
    loadGlobalConfigFile()
    dbg.print_tc_list(os.path.join(GLOBAL_CONFIG.target_path, target))

def dbg_showModel(target):
    loadGlobalConfigFile()
    dbg.build_graph_vis_model(os.path.join(GLOBAL_CONFIG.target_path, target))

def dbg_results(target):
    loadGlobalConfigFile()
    dbg.dbg_results(GLOBAL_CONFIG.target_path, target)

import argparse
parser = argparse.ArgumentParser()
parser.add_argument('-c', '--config', action='store', type=str, help='config file for testing')
parser.add_argument('-a', '--action', action='store', type=str, help='action')
parser.add_argument('-v', '--verbose', action='store_true', required=False)
args = vars(parser.parse_args())

def main():
    termui.banner()
    config_file = args['config']
    action = args['action']
    verbose_flag = False
    if 'verbose' in args:
        verbose_flag = args['verbose']

    if action == "play":
        run_play(config_file)
    elif action == "replay":
        run_replay(config_file)
    elif action == "model":
        run_model(config_file)
    elif action == "check":
        run_check(config_file)
    elif action == "print":
        run_print(config_file)
    elif action == "symres":
        run_symres(config_file)
    elif action == "dbg.WorkloadList":
        dbg_workloadList(config_file)
    elif action == "dbg.showModel":
        dbg_showModel(config_file)
    elif action == "dbg.results":
        dbg_results(config_file)
    else:
        print('USAGE:')
        print('------')
        print('miner.py -c <CONFIG FILE> -a <ACTION>')
        print('')
        print('actions:')
        print('--------')
        print('- play: record execution to be replayed\n- replay: replay and trace execution, build partial model\n- model: build model of example\n- check: check against security policies\n- print: print call traces for a particular example')

if __name__ == "__main__":
    main()