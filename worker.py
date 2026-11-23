#!/usr/bin/env python3

#--------------------------------------
# File: worker.py
#
# Purpose: Our queue interface, which allows us to organize and run tasks sequentially
#--------------------------------------
import asyncio
import json
import os
from colorama import Fore
import time

import hy2.core.utils as utils
from hy2.core.glob_conf import GlobalConfig
import hy2.symres.symbol_resolution as symres
import hy2.symres.type_resolution as typeres

GLOBAL_CONFIG_FILE = "config.json"
GLOBAL_CONFIG = utils.loadGlobalConfigFile(GLOBAL_CONFIG_FILE, GlobalConfig())

async def call_program(args):
    cmd = " ".join(args)
    process = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    # Wait for output:
    stdout, stderr = await process.communicate()
    print(stderr.decode("utf-8"))
    return stdout

def play_cmd(profile_file):
    args = ['python3', 'miner.py', '-c', profile_file, '-a', 'play']
    out = asyncio.run(call_program(args))
    print(out.decode('utf-8'))

def replay_cmd(config_file):
    args = ['python3', 'miner.py', '-c', config_file, '-a', 'replay']
    out = asyncio.run(call_program(args))
    print(out.decode('utf-8'))

def model_cmd(config_file):
    args = ['python3', 'miner.py', '-c', config_file, '-a', 'model']
    out = asyncio.run(call_program(args))
    print(out.decode('utf-8'))

def check_cmd(config_file):
    args = ['python3', 'miner.py', '-c', config_file, '-a', 'check']
    out = asyncio.run(call_program(args))
    print(out.decode('utf-8'))

def get_test_cases(target):
    test_dir = os.path.join(GLOBAL_CONFIG.target_path, target)
    test_cases = [os.path.join(test_dir, t) for t in os.listdir(test_dir) if f'{target}_tc_' in t and '.json' in t]
    return test_cases

def run_loop(test_case):
    print('Calling play...')
    play_cmd(test_case)
    print('Calling replay...')
    replay_cmd(test_case)
    print('done...')

def run_ingest(target):
    profile_path = os.path.join(GLOBAL_CONFIG.target_path, target, 'profile.json')
    if not os.path.exists(profile_path):
        return
    
    f = open(profile_path, 'r')
    profile = json.load(f)
    f.close()

    f0 = open('ingest.txt', 'r')
    dat = f0.read()
    f0.close()

    test_cases = dat.split('\n')
    for t0 in test_cases:
        if t0 == '':
            continue
        new_test_case = profile
        new_test_case['command'] = []
        new_test_case['command'] += [{"cmd": t0, "type": "async"}]
        tc_name = os.path.join(GLOBAL_CONFIG.target_path, target, f'{target}_tc_{utils.md5(str(new_test_case).encode("utf-8"))}.json')
        with open(tc_name, 'w') as f:
            json.dump(new_test_case, f)
    
    print(f'{len(test_cases)} test cases created...')

def run_trace(target):
    if '.json' in target:
        run_loop(target)
    else:
        startTime = time.time()
        test_cases = get_test_cases(target)
        n = len(test_cases)
        print(f'Running {n} for {target}...')
        j = 0
        for x in test_cases:
            run_loop(x)
            j += 1
            print(f'{j}/{n} Test cases executed....')
        endTime = time.time()
        traceAnalysisLatency = endTime - startTime
        print(f'Latency: {traceAnalysisLatency}')

def run_symbol_resolution_inclusions(target):
    f = open(os.path.join(GLOBAL_CONFIG.target_path, target, 'profile.json'), 'r')
    data = json.load(f)
    f.close()
    if not 'inclusion_paths' in data:
        return
    image_type = data['image_type']
    inclusion_paths = data['inclusion_paths']
    inclusions = data['inclusions_named']
    for inc in inclusion_paths.keys():
        inc_bin = inclusion_paths[inc]
        inc_funcs = [i[0] for i in inclusions if i[1] == inc]
        symres.resolve_symbols_for_inclusions(inc_bin, inc_funcs, "", target)

def run_symbol_resolution(target):
    target_bin = os.path.join(GLOBAL_CONFIG.mount_path, target)
    target_bin_dbg = os.path.join(GLOBAL_CONFIG.target_path, target, 'dbg', target)
    target_bin_dbg0 = os.path.join(GLOBAL_CONFIG.target_path, target, 'dbg', f'{target}_dbg')
    if os.path.exists(target_bin_dbg):
        target_bin = target_bin_dbg
    if os.path.exists(target_bin_dbg0):
        target_bin = target_bin_dbg0
    if not os.path.exists(target_bin) and not os.path.isfile(target_bin):
        f = open(os.path.join(GLOBAL_CONFIG.target_path, target, 'profile.json'), 'r')
        data = json.load(f)
        f.close()
        target_bin = data['target_path']
    symres.resolve_symbols(GLOBAL_CONFIG.target_path, GLOBAL_CONFIG.dumps_path, target_bin, target)
    run_symbol_resolution_inclusions(target)
    typeres.preprocessMeta(target_bin, os.path.join(GLOBAL_CONFIG.target_path, target))

def run_model(target):
    print(f'Running model for {target}')
    model_cmd(target)
    print(f'done...')

def run_check(target):
    print(f'Running checker for {target}')
    check_cmd(target)
    print(f'done...')

def mainloop(queue):
    i = 0
    for z in queue:
        if 'task' in z and 'target' in z:
            if z['task'] == 'ingest':
                run_ingest(z['target'])
            if z['task'] == 'trace':
                run_trace(z['target'])
            if z['task'] == 'symbol resolution':
                run_symbol_resolution(z['target'])
            if z['task'] == 'model':
                run_model(z['target'])
            if z['task'] == 'check':
                run_check(z['target'])
        i+=1
        print(f'{i}/{len(queue)} jobs done...')


def read_in_queue():
    queue = []
    with open('queue.json', 'r') as f:
        data = json.load(f)
        queue = data['queue']
    return queue

def main():
    job_queue = read_in_queue()
    if len(job_queue) == 0:
        print('Nothing to do....exiting!')
    mainloop(job_queue)

if __name__ == "__main__":
    main()