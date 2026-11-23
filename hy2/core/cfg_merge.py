#--------------------------------------
# File: cfg_merge.py
#
# Purpose: Merges multiple CFG models (produced from seperate executions) into a single CFG model (that describes all executions)
#--------------------------------------

from transitions import Machine
from colorama import Fore
from rich.progress import track
from hy2.core.utils import ThreadMachine, TState

def parse_transitions(A):
    trs = A.get_triggers(*list(A.states.keys()))
    tr0 = []
    for t in trs:
        t0 = A.get_transitions(trigger=t)
        for ti in t0:
            tr0.append([t, ti.source, ti.dest])
    return tr0

def parse_transitions_objs(A):
    trs = A.get_triggers(*list(A.states.keys()))
    tr0 = []
    for t in trs:
        t0 = A.get_transitions(trigger=t)
        for ti in t0:
            tr0.append([t, A.states[ti.source], A.states[ti.dest]])
    return tr0

def parse_transitions_partial(A, labels):
    trs = A.get_triggers(*list(A.states.keys()))
    tr0 = []
    for t in trs:
        t0 = A.get_transitions(trigger=t)
        for ti in t0:
            #assert ti.source in labels and ti.dest in labels
            if ti.source in labels and ti.dest in labels:
                tr0.append([t, ti.source, ti.dest])
    return tr0

def from_event_seq(lid, labels, new_labels, dupl_labels):
    q0 = 'S'+str(lid)
    lid += 1
    assert q0 not in new_labels
    new_labels[q0] = []
    
    node_translation = {}
    node_translation[q0] = q0

    for k, v in labels.items():
        s1 = labels[k]
        qn = f'S{lid}'
        assert not qn in new_labels
        new_labels[qn] = [s1]
        
        bid = s1.pc
        if not bid in dupl_labels:
            dupl_labels[bid] = []
        dupl_labels[bid] += [qn]
        node_translation[k] = qn
        lid+=1
    
    return new_labels, node_translation, lid, dupl_labels

def translate_event_seq_transitions(A, node_translation):
    trs = A.get_triggers(*list(A.states.keys()))
    tr0 = []
    for t in trs:
        t0 = A.get_transitions(trigger=t)
        for ti in t0:
            if not ti.source in node_translation or not ti.dest in node_translation:
                print(f'ERROR: {ti.source} {ti.dest}')
                continue
            s0 = node_translation[ti.source]
            s1 = node_translation[ti.dest]
            tr0.append([t, s0, s1])
    return tr0

def translate_thread_model(At, node_translation):
    trs = At.get_triggers(*list(At.states.keys()))
    tr0 = []
    for t in trs:
        t0 = At.get_transitions(trigger=t)
        for ti in t0:
            s0 = [node_translation[s] for s in At.states[ti.source].label]
            s1 = [node_translation[s] for s in At.states[ti.dest].label]
            tr0.append((t, s0, s1))
    return tr0

# The number of lookups to find a dropped state should never be more than 2
def lookup_dropped_state(dropped_states, s0):
    i = 0
    max_retries = 10
    while s0 in dropped_states:
        s0 = dropped_states[s0]
        i += 1
        if i > max_retries:
            break
    return s0

def check_merged_states(sn0, sn1):
    if not type(sn1) == list:
        sn1 = [sn1]
    for s1 in sn1:
        if type(sn0) == list:
            bt = all([s0.check_eq(s1) for s0 in sn0])
            if not bt:
                return False
        else:
            bt = sn0.check_eq(s1)
            if not bt:
                return False
    return True

import hy2.core.model as model

def get_next_model_state(model, a0):
    return [t.dest for t in model.get_transitions(source=a0)]

def get_prev_model_state(model, a0):
    tn = model.get_transitions(dest=a0)
    return [t.source for t in tn]

# Check if n0 dominates n1:
def check_dominance(A, labels, n0, n1):
    if len(get_prev_model_state(A, n0)) == 1:
        return False

    workQueue = [n0]
    visited = []
    print(f'Checking dominance: {n0} {n1}')

    while True:
        if len(workQueue) == 0:
            break
        s0 = workQueue.pop(0)
        if s0 == n1:
            return True
        s1 = get_next_model_state(A, s0)
        for s in s1:
            if s in visited:
                continue
            workQueue.append(s)
            visited.append(s)
    
    return False


def get_candidates(A, labels):
    candidates = []
    for sid, node in labels.items():
        if type(node) == list:
            if len(node) == 0:
                continue
            else:
                n0 = node[0]
        else:
            n0 = node
        
        if type(n0.transition) == model.CConditionalTransition:
            for src in get_prev_model_state(A, sid):
                candidates += [(sid, src)]
                for src0 in get_prev_model_state(A, src):
                    candidates += [(src, src0)]
            for n1 in get_next_model_state(A, sid):
                candidates += [(n1, sid)]
                for n2 in get_next_model_state(A, n1):
                    candidates += [(n2, n1)]
        else:
            srcs = get_prev_model_state(A, sid)
            if len(srcs) > 1:
                for src in srcs:
                    candidates += [(sid, src)]
    return candidates

def do_check_dominance(A, labels):
    print("Checking for backedges...")
    candidates = get_candidates(A, labels)
    for c in candidates:
        b = check_dominance(A, labels, c[0], c[1])
        if b:
            labels[c[0]].back_edge = c[1]
        
    return labels

def rebuild_automata(labels, dropped_states, transitions, Ati=None, Att=[]):
    q0_initial = 'S0'
    print('[debug] rebuilding cfg')
    A = Machine(states=[q0_initial], initial=q0_initial, auto_transitions=False)
    for k in labels.keys():
        if not k in dropped_states and not k == q0_initial:
            A.add_state(k)
    
    new_trs = []
    state_mapping = {}
    for t in transitions:
        s0 = t[1]
        s1 = t[2]
        #assert s0 in labels and s1 in labels
        if not s0 in labels or not s1 in labels:
            print('dbg')
            continue
        elif t[1] in dropped_states or t[2] in dropped_states:
            s0 = t[1]
            s1 = t[2]
            if s0 in dropped_states:
                s0_ = lookup_dropped_state(dropped_states, s0)
                state_mapping[s0] = s0_
                s0 = s0_
            if s1 in dropped_states:
                s1_ = lookup_dropped_state(dropped_states, s1)
                state_mapping[s1] = s1_
                s1 = s1_
            
            if not s0 in dropped_states and not s1 in dropped_states and not (s0, s1) in new_trs:
                A.add_transition(t[0], s0, s1)
                new_trs.append((s0, s1))
        else:
            A.add_transition(t[0], t[1], t[2])
            new_trs.append((t[1], t[2]))
    At0 = None
    if Att != []:
        At0 = ThreadMachine(states=[Ati], initial=Ati, auto_transitions=False)
        new_trt = []
        for t in Att:
            s0 = t[1]
            s0n = str(s0)
            s1 = t[2]
            s1n = str(s1)
            if not s0n in At0.states:
                new_tm_state = [state_mapping[s] if s in state_mapping else s for s in s0]
                s0n = str(new_tm_state)
                if not s0n in At0.states:
                    s0o = TState(s0n)
                    s0o.label = new_tm_state
                    At0.add_state(s0o)
            if not s1n in At0.states:
                new_tm_state = [state_mapping[s] if s in state_mapping else s for s in s1]
                s1n = str(new_tm_state)
                if not s1n in At0.states:
                    s1o = TState(s1n)
                    s1o.label = new_tm_state
                    At0.add_state(s1o)
            
            if not (s0n, s1n) in new_trt:
                At0.add_transition(t[0], s0n, s1n)
                new_trt.append((s0n, s1n))
    return A, At0
    
def rebuild_cfgs(labels, dupl_labels, transitions, Ati=None, Att=[]):
    merged = True
    dropped_states = {}

    while merged:
        merged = False
        vv = list(dupl_labels.values())
        for vi in track(range(len(vv)), description="Processing...."):
            v = vv[vi]
            
            if len(v) > 1:
                for i in range(len(v)):
                    x0 = v[i]
                    if x0 in dropped_states:
                        continue
                    for j in range(i+1, len(v)):
                        x1 = v[j]
                        if x1 in dropped_states:
                            continue
                        else:
                            st0 = labels[x0]
                            st1 = labels[x1]
                            eqc = check_merged_states(st0, st1)
                            if eqc:
                                merged = True
                                dropped_states[x1] = x0
                                labels[x0] += labels[x1]
                                labels[x1] = []
                            else:
                                pass
    
    A0, At = rebuild_automata(labels, dropped_states, transitions, Ati, Att)
    print('[debug] done cfg merge')
    return A0, labels, At

def cfg_merge_partial(a0_labels, CFG, labels, max_lid, transitions0, At0, Ati=None, Att0=[]):
    lid = max_lid
    dupl_labels = {}
    for k, v in a0_labels.items():
        vid =  v.pc
        if not vid in dupl_labels:
            dupl_labels[vid] = []
        dupl_labels[vid] += [k]
    
    new_labels = {}
    for k,v in a0_labels.items():
        new_labels[k] = [v]
    
    transitions = transitions0
    model_labels, node_translation, lid, dupl_labels = from_event_seq(lid, labels, new_labels, dupl_labels)

    transitions += translate_event_seq_transitions(CFG, node_translation)

    thread_transitions = Att0
    thread_transitions += translate_thread_model(At0, node_translation)
    A, model_labels, At = rebuild_cfgs(model_labels, dupl_labels, transitions, Ati, thread_transitions)
    
    return A, model_labels, lid, At

def cfg_merge(CFGs, labels, Ats, backedge_analysis=False):
    lid = 0
    model_labels = {}
    dupl_labels = {}

    transitions = []
    transitions_threads = []
    for i in range(len(CFGs)):
        labels0 = labels[i]
        CFG0 = CFGs[i]
        At = Ats[i]
        model_labels, node_translation, lid, dupl_labels = from_event_seq(lid, labels0, model_labels, dupl_labels)

        transitions += translate_event_seq_transitions(CFG0, node_translation)
        if not At == None:
            transitions_threads += translate_thread_model(At, node_translation)
    
    Ati = None
    if not Ats[0] == None:
        Ati = Ats[0].initial
    
    A, model_labels, At = rebuild_cfgs(model_labels, dupl_labels, transitions, Ati, transitions_threads)
    
    if backedge_analysis:
        do_check_dominance(A, model_labels)

    return A, model_labels, lid, At