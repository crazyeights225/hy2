#--------------------------------------
# File: dbg.py
#
# Purpose: Provides some helper functions for debugging
#--------------------------------------
import json
import os
import pickle
from colorama import Fore
import graphviz

from rich import print as rprint
from rich.console import Console
from rich.table import Table
from rich.columns import Columns
from rich.panel import Panel

def print_tc_list(target_dir):
    if not os.path.exists(target_dir):
        return
    
    target_files = os.listdir(target_dir)
    target_files = [os.path.join(target_dir, x) for x in target_files if '_tc_' in x and '.json' in x]

    for tc in target_files:
        with open(tc, 'r') as f:
            dat = json.load(f)
            cmds = dat['command']
            print('\n'.join([c['cmd'] for c in cmds]))

def parse_transitions(A):
    trs = A.get_triggers(*list(A.states.keys()))
    tr0 = []
    for t in trs:
        t0 = A.get_transitions(trigger=t)
        for ti in t0:
            tr0.append([t, ti.source, ti.dest])
    return tr0

def build_graph_vis_model(target_dir):
    model_path = os.path.join(target_dir, "model.trace")
    labels_path = os.path.join(target_dir, "model.labels")

    if not os.path.exists(model_path):
        return

    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    with open(labels_path, 'rb') as f:
        labels = pickle.load(f)
    
    e = graphviz.Digraph('G', filename='model', format='png')
    nodes = []

    transitions = parse_transitions(model)
    for t in transitions:
        t0 = t[0]
        s0 = t[1]
        d0 = t[2]

        if not s0 in nodes:
            if s0 in labels:
                l = labels[s0]
                label = l.graphLabel()
                e.node(s0, label=f'{s0} {label}')
            else:
                e.node(s0, label=s0)
            nodes += [s0]
        if s0 in labels:
            t0 = labels[s0].graphTransitionLabel()
        if not d0 in nodes:
            if d0 in labels:
                l = labels[d0]
                label = l.graphLabel()
                e.node(d0, label=f'{d0} {label}')
            else:
                e.node(d0, label=d0)
            nodes += [d0]
        e.edge(s0, d0, t0)

    print('Rendering diagram...')
    try:
        e.render(directory=target_dir)
    except Exception as ex:
        print('ERROR: '+str(ex))


def dbg_results(target_path, target):
    results_dir = os.path.join(target_path, target, 'results')
    if not os.path.exists(results_dir):
        return
    
    results = os.listdir(results_dir)
    results = [rf for rf in results if '_summary.json' not in rf]
    for i in range(len(results)):
        r0 = results[i]
        with open(os.path.join(results_dir, r0), 'r') as f:
            res0 = json.load(f)
            k0 = list(res0.keys())[0]
            name = res0[k0]['name']

            panel = Panel.fit(f'Result ID: {k0}\nProperty Name: {name}', border_style="cyan")
            rprint(panel)

            matchObj = res0[k0]['match']
            funcs = res0[k0]['match_funcs']
            vars = matchObj['variables']
            expl = res0[k0]['explanation']

            var_table = Table()
            var_table.add_column('Attribute')
            var_table.add_column('Value')
            for k, v in vars.items():
                var_table.add_row(k, str(v))

            call_trace = '\n'.join([f'-> {funcs[i]}' for i in range(len(funcs)) if i == 0 or (funcs[i] != funcs[i-1])])
            call_trace_panel = Panel.fit(call_trace, title='Call Trace')

            expl_panel = Panel.fit(expl, title='Constraints')
            cols = [var_table, expl_panel, call_trace_panel]
            console = Console()
            console.print(Columns(cols))



            