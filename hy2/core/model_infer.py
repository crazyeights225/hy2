#--------------------------------------
# File: model_infer.py
#
# Purpose: Merges multiple CFG models, and the data within the nodes
#--------------------------------------

import pickle
import hy2.core.model as mod
import hy2.core.cfg_merge as cfg_merge
import os
import hy2.core.partial_cfg as pcfg
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


def check_list(x):
    if type(x) == list:
        return x
    return [x]

def merge_variables(merge_table, vars):
    n = len(vars)
    v0 = vars[0]

    v0.label = sum([vars[i].label for i in range(n)], [])
    #global merge_table
    v0tmp = []
    v0s = set(v0.label)
    for i in range(len(v0.label)):
        if v0.label[i] in merge_table:
            mv0x = merge_table[v0.label[i]]
            v0tmp += mv0x
            merge_table[v0.label[i]] |= v0s
        else:
            merge_table[v0.label[i]] = v0s
            v0tmp += [v0.label[i]]
    
    v0.label = list(set(v0tmp))
    vdsb = sum([check_list(vars[i].dsource) for i in range(n) if not "unknown" in vars[i].dsource and vars[i].dsource != ''], [])
    if vdsb != []:
        dsb = all([vdsb[0].replace('sym.imp.', '') == vdsb[i].replace('sym.imp.', '').replace("'", "").replace("blibc-2.27.so-b", "") for i in range(len(vdsb))])
        v0.dsource = vdsb[0]
        if not dsb:
            if 'ret' == v0.dsource[:3]:
                v0.dsource = list(set(vdsb))
            else:
                assert dsb
    v0.def_label = sum([check_list(vars[i].def_label) for i in range(n) if vars[i].def_label != "" and vars[i].def_label != []], [])

    v0.abs_addr = sum([check_list(vars[i].abs_addr) for i in range(n)], [])
    
    if len(list(set(v0.abs_addr))) == 1:
        v0.abs_addr = [v0.abs_addr[0]]
    
    v0.val = sum([check_list(vars[i].val) for i in range(n)], [])
    if len(list(set(v0.val))) == 1:
        v0.val = [v0.val[0]]

    return merge_table, v0

def merge_invocations(invs):
    i0 = invs[0]
    n = len(invs)
    assert all([i0.name == invs[i].name] for i in range(n))
    for i in range(1, n):
        i0.args += invs[i].args
    return i0

def merge_conditional_transitions(trans):
    n = len(trans)
    t0 = trans[0]
    b =  all([t0.dest == trans[i].dest for i in range(n)])
    if not b:
        dest_merged = sum([check_list(trans[i].dest) for i in range(n)], [])
        di = [td for td in dest_merged if "unknown" not in td]
        t0.dest = list(set(di))
    
    t0.dest_bid = [trans[i].dest_bid for i in range(n)]
    t0.dest_pc = sum([check_list(trans[i].dest_pc) for i in range(n)], [])
    return t0

def merge_transitions(trans):
    n = len(trans)
    t0 = trans[0]

    b =  all([t0.dest == trans[i].dest for i in range(n)])
    if not b:
        dest_merged = sum([check_list(trans[i].dest) for i in range(n)], [])
        di = [td for td in dest_merged if "unknown" not in td]
        t0.dest = di
    
    t0.dest_pc = sum([check_list(trans[i].dest_pc) for i in range(n)], [])
    return t0

def merge_states(merge_table, states):
    m = len(states)
    s0 = states[0]
    s0_fnames = list(set([states[i].fname for i in range(m) if not 'unknown' in states[i].fname]))
    
    if s0_fnames == []:
        s0.fname = states[0].fname
    else:
        s0.fname = s0_fnames[0]
    n = len(states[0].variables)

    s0.id = [states[i].id for i in range(m)]
    s0.tid = sum([check_list(states[i].tid) for i in range(m)], [])
    s0.tid = list(set(s0.tid))
    s0.trid = sum([check_list(states[i].trid) for i in range(m)], [])
    s0.trid = list(set(s0.trid))
    s0.return_addr = states[0].return_addr

    assert all([s0.return_addr == states[i].return_addr for i in range(m)])
    t0s = [s.transition for s in states]
    if type(s0.transition) == mod.CConditionalTransition:
        s0.transition = merge_conditional_transitions(t0s)
    else:
        s0.transition = merge_transitions(t0s)

    variables = []
    n = max([len(states[i].variables) for i in range(m)])
    mis = [i for i in range(m) if len(states[i].variables) == n]
    var_names = [states[mis[0]].variables[j].name for j in range(n)]
    vidxs = [0]*m
    for j in range(n):
        vars_i = []
        for i in range(m):
            idx = vidxs[i]
            if idx == len(states[i].variables):
                pass
            elif states[i].variables[idx].name == var_names[j]:
                vars_i.append(states[i].variables[idx])
                vidxs[i] += 1
            else:
                pass
        try:
            merge_table, vobj = merge_variables(merge_table, vars_i)
            variables.append(vobj)
        except:
            for st in states:
                print(st)
            raise Exception()
    s0.variables = variables

    invocations = []
    k = max([len(states[i].invocations) for i in range(m)])
    mis = [i for i in range(m) if len(states[i].invocations) == k]
    inv_names = [states[mis[0]].invocations[j].name for j in range(k)]

    idxs = [0]*m
    for j in range(k):
        iinvs = []
        for i in range(m):
            idx = idxs[i]
            if idx == len(states[i].invocations):
                pass
            elif states[i].invocations[idx].name == inv_names[j]:
                iinvs.append(states[i].invocations[idx])
                idxs[i] += 1
            else:
                pass
        invocations.append(merge_invocations(iinvs))
    
    s0.invocations = invocations
    s0.build_name_store()
    return merge_table, s0

def convert_to_model(labels):
    new_labels = {}
    i = 0
    merge_table = {}
    n = len(list(labels.keys()))
    for k, v in labels.items():
        if len(v) == 0:
            pass
        else:
            merge_table, m = merge_states(merge_table, v)
            new_labels[k] = m
        if i % 10 == 0:
            print(f'{i}/{n} States Merged...')
        i += 1
    return new_labels

def read_in_partial_cfg(out_dir, trace_id):
    cfg_file = os.path.join(out_dir, f'{trace_id}-cfg.bin')
    backing_file = os.path.join(out_dir, f'{trace_id}-backing.bin')
    cfg = pcfg.import_trace(cfg_file)
    lab = pcfg.import_trace(backing_file)
    return cfg, lab

def read_in_thread_model(out_dir, trace_id):
    thread_model_file = os.path.join(out_dir, f'{trace_id}-threadmodel.bin')
    thread_model = pcfg.import_trace(thread_model_file)
    return thread_model


# This merged pairs of CFGs at once instead of all of them, but was slower for some reason
# This would need to be used for larger models
def infer_model_partial(out_dir, trace_ids):
    # We can convert our event_seq cfg model directly to a final model:
    if len(trace_ids) == 1:
        trace_id = trace_ids[0]
        cfg_file = os.path.join(out_dir, f'{trace_id}-cfg.bin')
        backing_file = os.path.join(out_dir, f'{trace_id}-backing.bin')

        cfg = pcfg.import_trace(cfg_file)
        lab = pcfg.import_trace(backing_file)
        
        with open(os.path.join(out_dir, 'model.labels'), 'wb') as f:
            pickle.dump(lab, f)
        
        with open(os.path.join(out_dir, 'model.trace'), 'wb') as f:
            pickle.dump(cfg, f)

        print('Done!')
        return
    
    cfgs = []
    labels = []

    trid0 = trace_ids[0]
    trid1 = trace_ids[1]

    cfg0, lab0 = read_in_partial_cfg(out_dir, trid0)
    At0 = read_in_thread_model(out_dir, trid0)
    cfg1, lab1 = read_in_partial_cfg(out_dir, trid1)
    At1 = read_in_thread_model(out_dir, trid1)
    A0, new_labels, lid0, At = cfg_merge.cfg_merge([cfg0, cfg1], [lab0, lab1], [At0, At1])
    model_labels = convert_to_model(new_labels)
    transitions = cfg_merge.parse_transitions_partial(A0, model_labels)
    Ati = None
    Ats = []
    if not At == None:
        Ati = At.initial
        Ats = cfg_merge.parse_transitions_objs(At)
    
    n = len(trace_ids)
    for i in range(2, n):
        trace_id = trace_ids[i]
        cfg0, lab0 = read_in_partial_cfg(out_dir, trace_id)
        At0 = read_in_thread_model(out_dir, trace_id)
        if cfg0 == None:
            continue

        A0, model_labels, lid0, At = cfg_merge.cfg_merge_partial(model_labels, cfg0, lab0, lid0, transitions, At0, Ati, Ats)
        model_labels = convert_to_model(model_labels)
        transitions = cfg_merge.parse_transitions_partial(A0, model_labels)
        if At != None:
           Ats = cfg_merge.parse_transitions_objs(At)
        
        if i%4 == 0:
            print(f'{i}/{n} models merged...')

    with open(os.path.join(out_dir, 'model.labels'), 'wb') as f:
        pickle.dump(model_labels, f)
        
    with open(os.path.join(out_dir, 'model.trace'), 'wb') as f:
        pickle.dump(A0, f)

    if At != None:
        with open(os.path.join(out_dir, 'thread_model.bin'), 'wb') as f:
            pickle.dump(At, f)

def infer_model(GLOB_CONF, target, trace_ids):
    out_dir = os.path.join(GLOB_CONF.target_path, target)

    # We can convert our event_seq cfg model directly to a final model:
    if len(trace_ids) == 1:
        trace_id = trace_ids[0]
        cfg_file = os.path.join(out_dir, f'{trace_id}-cfg.bin')
        backing_file = os.path.join(out_dir, f'{trace_id}-backing.bin')

        cfg = pcfg.import_trace(cfg_file)
        lab = pcfg.import_trace(backing_file)
    
        if GLOB_CONF.enable_backedge_analysis:
            cfg_merge.do_check_dominance(cfg, lab)
        #tr0 = cfg_merge.parse_transitions(cfg)
        #build_graph_vis(tr0, lab, out_dir)
        
        thread_model_path = os.path.join(out_dir, f'{trace_id}-threadmodel.bin')
        if os.path.exists(thread_model_path):
            f = open(thread_model_path, 'rb')
            thread_model = pickle.load(f)
            f.close()
            with open(os.path.join(out_dir, 'threadmodel.bin'), "wb") as f:
                pickle.dump(thread_model, f)
        
        with open(os.path.join(out_dir, 'model.labels'), 'wb') as f:
            pickle.dump(lab, f)
        
        with open(os.path.join(out_dir, 'model.trace'), 'wb') as f:
            pickle.dump(cfg, f)
        
        print('Done!')
        return
    
    cfgs = []
    labels = []
    Ats = []
    for i in range(len(trace_ids)):
        trace_id = trace_ids[i]
        cfg0, lab0 = read_in_partial_cfg(out_dir, trace_id)
        At = read_in_thread_model(out_dir, trace_id)
        if cfg0 == None:
            continue
        cfgs.append(cfg0)
        labels.append(lab0)
        Ats += [At]

    A0, new_labels, tr0, At = cfg_merge.cfg_merge(cfgs, labels, Ats, GLOB_CONF.enable_backedge_analysis)
    new_labels = convert_to_model(new_labels)
    with open(os.path.join(out_dir, 'model.labels'), 'wb') as f:
        pickle.dump(new_labels, f)
        
    with open(os.path.join(out_dir, 'model.trace'), 'wb') as f:
        pickle.dump(A0, f)

    if not At == None:
        with open(os.path.join(out_dir, 'thread_model.bin'), 'wb') as f:
            pickle.dump(At, f)
    
    #tr0 = cfg_merge.parse_transitions(A0)
    #build_graph_vis(tr0, new_labels, out_dir)   