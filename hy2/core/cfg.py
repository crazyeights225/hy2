#--------------------------------------
# File: cfg.py
#
# Purpose: Builds the initial partial CFG model
#--------------------------------------

# Builds partial_cfg model
from transitions import Machine
from colorama import Fore
from rich.progress import track
from hy2.core.utils import ThreadMachine, TState, to_int, get_matching_base
import copy
import graphviz

def create_model_graph(model):
    tr0 = parse_transitions(model)
    e = graphviz.Digraph('G', filename="thread_model", format='png')
    for t in tr0:
        s0 = t[1]
        d0 = t[2]
        e.node(s0)
        e.node(d0)
        e.edge(s0, d0)

    print('Rendering diagram...')
    try:
        e.render()
    except Exception as ex:
        print('ERROR: '+str(ex))

lid = 0
def from_linear_trace(L, build_thread_model=False):
    global lid
    q0 = "S"+str(lid)
    lid += 1
    A = Machine(states=[q0], initial=q0, auto_transitions=False)
    labels = {}
    labels[q0] = []
    qf = 'Sf'
    dupl_labels = {}

    At = None
    if build_thread_model:
        last_tm_state = TState(str([]))
        last_tm_state.label = []
        p0 = last_tm_state
        At = ThreadMachine(states=[p0], initial=p0, auto_transitions=False)
        
    thread_mapping = {}
    q1 = f'S{lid}'
    A.add_state(q1)
    t0 = 'lambda'
    A.add_transition(t0, q0, q1)
    lid += 1
    qn = q1
    s0 = None
    l0 = ''
    n_dest_pc = None
    for i in range(len(L)):
        s1 = L[i]
        en = s1.transition._label()
        if build_thread_model:
            ti0 = L[i].tid
            new_tm_state = copy.copy(last_tm_state.label)
            if not ti0 in thread_mapping:
                thread_mapping[ti0] = len(new_tm_state)
                new_tm_state += [0]
            idx = thread_mapping[ti0]
            new_tm_state[idx] = qn
            new_tm_obj = TState(str(new_tm_state))
            new_tm_obj.label = new_tm_state
            At.add_state(new_tm_obj)
            At.add_transition('switch', last_tm_state,  new_tm_obj)
            last_tm_state = new_tm_obj

        if i == len(L) - 1:
            labels[qn] = [s1]
            bid = s1.pc
            if not bid in dupl_labels:
                dupl_labels[bid] = []
            dupl_labels[bid] += [qn]
            A.add_transition(en, qn, qf)
        else:
            labels[qn] = [s1]
            bid = s1.pc
            if not bid in dupl_labels:
                dupl_labels[bid] = []
            dupl_labels[bid] += [qn]
            qm = f'S{lid}'
            A.add_state(qm)
            if n_dest_pc == None or n_dest_pc == bid:
                A.add_transition(en, qn, qm)
            
            n_dest_pc = s1.transition.dest_pc
            lid += 1
            l0 = qn
            qn = qm

            s0 = s1
    print('Creating Linear Graph')

    return A, labels, dupl_labels, lid, At

def find_in_sid_in_cfg(labels, sids):
    for sid in sids:
        if sid in labels and labels[sid] != []:
            return sid
    return None

def convert_pc_to_sid(dupl_labels, labels, pc):
    if not pc in dupl_labels:
        return None
    sids = dupl_labels[pc]
    return find_in_sid_in_cfg(labels, sids)

def add_ghost_branch(A, sid, dupl_labels, labels, branches, mgj):
    ghost_node_mapping = {}
    i = 0
    ghost_srcs = []
    for b in branches:
        branch_src_pc = b['src']
        branch_dest_pc = b['dest_pc']
        if i in mgj:
            branch_dest_pc = mgj[i]
        if branch_src_pc in dupl_labels:
            sids_src = dupl_labels[branch_src_pc]
            sid_src = find_in_sid_in_cfg(labels, sids_src)
        elif branch_src_pc in ghost_node_mapping:
            sid_src = ghost_node_mapping[branch_src_pc]
            ghost_srcs += [branch_src_pc]
        else:
            sid_src = f'S{sid}'
            ghost_node_mapping[branch_src_pc] = sid_src
            A.add_state(sid_src)
            sid += 1

        sid_dest = None
        if not branch_dest_pc == None and branch_dest_pc in dupl_labels:
            sids_dest = dupl_labels[branch_dest_pc]
            sid_dest = find_in_sid_in_cfg(labels, sids_dest)
        elif branch_dest_pc in ghost_node_mapping:
            sid_dest = ghost_node_mapping[branch_dest_pc]

        
        bnodes = b['nodes']
        if len(bnodes) == 1 and branch_src_pc == bnodes[0] and sid_dest == None:
            i+=1
            continue

        qn = sid_src
        for n in bnodes:
            sid0 = f'S{sid}'
            A.add_state(sid0)
            A.add_transition('ghost_jmp', qn, sid0)
            ghost_node_mapping[n] = sid0
            qn = sid0
            sid +=1
            i+=1

        if not sid_dest == None:
            A.add_transition('ghost_jmp', qn, sid_dest)

    return A, ghost_node_mapping, ghost_srcs

def add_ghost_jump_from_src(A, dupl_labels, labels, ghost_state_map, sid_src, pc_ret):
    if pc_ret in dupl_labels:
        sids_dest = dupl_labels[pc_ret]
        sid_dest = find_in_sid_in_cfg(labels, sids_dest)
    elif pc_ret in ghost_state_map:
        sid_dest = ghost_state_map[pc_ret]
    else:
        return A
    A.add_transition('ghost_jmp', sid_src, sid_dest)
    return A

"""
def translate_virt_addr(base_pcs, base_offsets, pc):
    for i in range(len(base_pcs)):
        if pc >= base_pcs[i] and pc < (base_pcs[i]+base_offsets[i]):
            return abs(pc - base_pcs[i])
    return pc
"""

def translate_va(target_pages, aliases, pc):
    pc = to_int(pc)
    if not type(pc) == int:
        return pc
    target_base, page_name = get_matching_base(pc, target_pages, aliases)
    if not target_base == None:
        abs_addr = abs(target_base-pc)
        return abs_addr
    return pc

def add_ghost_jump(A, dupl_labels, labels, ghost_state_map, src_pc, dest_pc):
    if src_pc in dupl_labels:
        sids_src = dupl_labels[src_pc]
        sid_src = find_in_sid_in_cfg(labels, sids_src)
    elif src_pc in ghost_state_map:
        sid_src = ghost_state_map[src_pc]
    
    sid_dest = None
    if dest_pc in dupl_labels:
        sids_dest = dupl_labels[dest_pc]
        sid_dest = find_in_sid_in_cfg(labels, sids_dest)
    elif dest_pc in ghost_state_map:
        sid_dest = ghost_state_map[dest_pc]

    if sid_dest != None:
        A.add_transition('ghost_jmp', sid_src, sid_dest)
    return A, sid_src

def add_ghost_jumps(A, dupl_labels, labels, target_pages, ghost_jumps):
    for k,v in ghost_jumps.items():
        #src_pc = translate_va(target_pages['target_pages'], target_pages['aliases'], v)
        #dest_pc = translate_va(target_pages['target_pages'], target_pages['aliases'], k)
        src_pc = v
        dest_pc = k
        sids_src = dupl_labels[src_pc]
        sid_src = find_in_sid_in_cfg(labels, sids_src)
        sids_dest = dupl_labels[dest_pc]
        sid_dest = find_in_sid_in_cfg(labels, sids_dest)
        A.add_transition('ghost_jmp', sid_src, sid_dest)
    
    return A

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

def remove_duplicate_transitions(trs):
    trs1 =  []
    for t in trs:
        if not t in trs1:
            trs1.append(t)
    return trs1

def lookup_dropped_state(dropped_states, s0):
    i = 0
    max_tries = 3
    while s0 in dropped_states:
        s0 = dropped_states[s0]
        i += 1
        if i > max_tries:
            break
    return s0

def check_merged_states(sn0, sn1):
    #for s1 in sn1:
    #    bt = all([s0.check_eq(s1) for s0 in sn0])
    #    if not bt:
    #        return False
    #return True
    s0 = sn0[0]
    s1 = sn1[0]
    return s0.check_eq(s1)


def rebuild_automata(A, dropped_states, labels, At=None):
    states = list(A.states.keys())
    print('Parsing transitions...')
    trs = parse_transitions(A)
    print('Adding states..')
    A1 = Machine(states=[A.initial], initial=A.initial, auto_transitions=False)
    for s in states:
        if s == A.initial or s in dropped_states:
            continue
        else:
            A1.add_state(s)
    
    print('Adding new transitions...')
    new_trs = []
    i = 0
    n = len(trs)
    state_mapping = {}
    for t in trs:
        if t[1] in dropped_states or t[2] in dropped_states:
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
                A1.add_transition(t[0], s0, s1)
                new_trs.append((s0, s1))
        elif not (t[1], t[2]) in new_trs:
            A1.add_transition(t[0], t[1], t[2])
            new_trs.append((t[1], t[2]))
        
        i+=1

    At0 = None
    if At != None:
        At0 = ThreadMachine(states=[At.initial], initial=At.initial, auto_transitions=False)
        for k, v in At.states.items():
            if not any([x in state_mapping for x in v.label]):
                At0.add_state(v)
        trt = parse_transitions_objs(At)
        new_trt = []
        for t in trt:
            s0 = t[1]
            s1 = t[2]
            if not s0.name in At0.states:
                new_tm_state = [state_mapping[s] if s in state_mapping else s for s in s0.label]
                s0n = str(new_tm_state)
                if not s0n in At0.states:
                    s0o = TState(s0n)
                    s0o.label = new_tm_state
                    At0.add_state(s0o)
            else:
                s0n = s0.name
            if s1.name in At0.states:
                s1n = s1.name
            else:
                new_tm_state = [state_mapping[s] if s in state_mapping else s for s in s1.label]
                s1n = str(new_tm_state)
                if not s1n in At0.states:
                    s1o = TState(s1n)
                    s1o.label = new_tm_state
                    At0.add_state(s1o)

            if not (s0n, s1n) in new_trt:
                At0.add_transition(t[0], s0n, s1n)
                new_trt.append((s0n, s1n))
    return A1, At0

def build_cfg(A, labels, dupl_labels, At):
    states = list(A.states.keys())
    merged = True
    dropped_states = {}
    
    while merged:
        merged = False
        vv = list(dupl_labels.values())
        for vi in track(range(len(vv)), description="Processing..."):
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
    print('Done!')
    print("Rebuilding Model...")
    A0, At0 = rebuild_automata(A, dropped_states, labels, At)
    return A0, labels, At0

def convertToCFG(L, multi_enabled):
    A, labels, dupl_labels, lid, At = from_linear_trace(L, multi_enabled)
    A, new_labels, At = build_cfg(A, labels, dupl_labels, At)
    print("Done!")
    return A, new_labels, lid, dupl_labels, At
