
#--------------------------------------
# File: results_post_processor.py
#
# Purpose: Adds additional information to results
#--------------------------------------

import os
import json
import pickle

import hy2.core.extensions.bin_query as bin_map
import hy2.core.model as mod
import hy2.core.utils as utils

from rich.progress import track


def get_call_site_pc(state):
    pcs = [v.pc for v in state.variables if type(v.pc) == int]
    if pcs:
        return max(pcs)
    return state.pc if type(state.pc) == int else ""

def export_result_summary(target_dir, target, labels, call_trace, spec, match):
    trace = []
    match_pcs = []
    test_cases = []
    varCodeMap, noCases = utils.getAllVarPrefixes(target_dir, target)
    allFlag = False
    i = 0
    for c in call_trace:
        if i < len(match['states']) and c == match['states'][i]:
            v = match['vars'][i]
            mst = match['states'][i]
            if not mst in labels:
                state_obj = {'state': 'match', 'spec': spec[i], 'var': mst}
                trace.append(state_obj)
                # placeholder keeps match_pcs aligned with the spec steps
                match_pcs.append(("", 0))
                i += 1
                continue
            if len(labels[mst].trid) > 0:
                vpt =  [varCodeMap[vp] for vp in labels[mst].trid if vp in varCodeMap]
                if len(vpt) == noCases:
                    allFlag = True
                else:
                    test_cases += vpt
            
            v = v[1][0]
            if type(v) == list:
                vid = v
            else:
                vid = labels[mst].lookup_name(v, True)
            var_match = {}
            # Exactly one (pc, depth) entry per matched spec step, so that
            # beautify[i] lines up with spec[i].
            if type(vid) == mod.CVar:
                var_match['fname'] = labels[mst].fname
                d = max([int(x[1:]) for x in vid.vec if type(x) == str and x[0] == 'D'] or [1])
                match_pcs.append((vid.pc, d))
            elif type(vid) == mod.CInvocation or type(vid) == mod.CTransition:
                var_match['fname'] = labels[mst].fname
                vargs, arg_pcs = labels[mst].find_args()
                vargs += "\n"
                var_match['vargs'] = vargs
                # The call is the last instruction of the block, i.e. the
                # highest pc among its variables (the return address push).
                # Show it with the argument setup as context.
                call_pc = get_call_site_pc(labels[mst])
                ctx = len([a for a in arg_pcs if a != "" and a < call_pc]) if call_pc != "" else 0
                match_pcs.append((call_pc, max(ctx, 1)))
            else:
                var_match = {"str": str(vid)}
                match_pcs.append(("", 0))
            state_obj = {}
            state_obj["state"] = "match"
            state_obj["spec"] = spec[i]
            state_obj["var"] = var_match
            trace.append(state_obj)
            i+=1
        else:
            pass
    
    if allFlag and test_cases == []:
        test_cases = ["all"]
    
    return trace, match_pcs, test_cases

def postprocess_result(target_dir, target, result_id, labels, target_file):
    result_folder = os.path.join(target_dir, 'results')
    result_id_file = os.path.join(result_folder, f'{result_id}.json')

    result_summary_file = os.path.join(result_folder, f'{result_id}_summary.json')
    #if os.path.exists(result_summary_file):
    #   return

    f = open(result_id_file, 'r')
    data = json.load(f)
    f.close()
    res = data[result_id]
    summary = {}
    match = res['match']
    spec = res['spec']
    call_trace = res['calltrace']
    tres, match_pcs, test_cases = export_result_summary(target_dir, target, labels, call_trace, spec, match)

    summary['trace'] = tres
    summary['test_cases'] = ', '.join(list(set(test_cases)))
    if 'explain_spec' in data[result_id]:
        explain_specs = data[result_id]['explain_spec']
    else:
        explain_specs = data[result_id]['spec']
    
    print(match_pcs)
    if 'base_pc' in data[result_id]:
        instrs, funcs = bin_map.get_instructions_for_match(target_file, match_pcs, data[result_id]['base_pc'])
        summary["beautify"] = []
        for i in range(len(instrs)):
            explain_spec = ""
            if i < len(explain_specs):
                explain_spec = explain_specs[i]
            summary["beautify"].append({"instr": instrs[i], "func": funcs[i], "spec": explain_spec})

    with open(result_summary_file, 'w') as f:
        json.dump(summary, f)
    
    print('Done!')

def create_results_list(target, results_folder, results_file):
    data = []
    result_ids = []
    results = os.listdir(results_folder)
    for r in results:
        if '_summary' in r:
            continue
        rpath = os.path.join(results_folder, r)
        res = {}
        res['id'] = r.replace('.json', '')
        result_ids += [res['id']]
        res['page'] = f'/result?name={target}&id={res["id"]}'

        f = open(rpath, 'r')
        dat = json.load(f)
        
        v = dat[res['id']]
        res['name'] = v['name']
        res['severity'] = v['severity']

        if 'conclusion' in v:
            if type(v['conclusion']) == str:
                res['conclusion'] = v['conclusion']
            else:
                res['conclusion'] = 'Review Required'
        else:
            res['conclusion'] = 'Review Required'

        f.close()
        data.append(res)

    with open(results_file, 'w') as f:
        json.dump(data, f)

    print('Done!')
    return result_ids

CONCLUSION_RANK = {'sat': 0, 'Review Required': 1, 'unsat': 2}

def _step_ref(step):
    instr = step.get('instr', {})
    return {'addr': instr.get('addr', ''), 'source_file': instr.get('source_file', ''),
            'func': (step.get('func') or '').strip(), 'code': (instr.get('code') or '').strip()}

GROUP_BY_MODES = ('sink', 'origin', 'none')
DEFAULT_GROUP_BY = 'sink'

def load_group_by(property_dir):
    """
    Property name -> grouping mode, from the optional "group_by" field of each
    property JSON ("sink" when absent):
      sink   - matches ending at the same instruction are one finding (e.g. the
               out-of-bounds STORE, reached from several allocations)
      origin - matches starting at the same instruction are one finding (e.g.
               the unchecked malloc call, whose result is used in many places)
      none   - every match is its own finding
    """
    modes = {}
    json_dir = os.path.join(property_dir, 'json')
    if not os.path.isdir(json_dir):
        return modes
    for p in os.listdir(json_dir):
        if not p.endswith('.json') or p == 'lib.json':
            continue
        try:
            with open(os.path.join(json_dir, p), 'r') as f:
                dat = json.load(f)
        except (OSError, ValueError):
            continue
        if not isinstance(dat, dict) or 'name' not in dat:
            continue
        mode = dat.get('group_by', DEFAULT_GROUP_BY)
        if mode not in GROUP_BY_MODES:
            print(f'{p}: unknown group_by "{mode}", using "{DEFAULT_GROUP_BY}"')
            mode = DEFAULT_GROUP_BY
        modes[dat['name']] = mode
    return modes

def _ungroup(entries):
    """results.json entries as create_results_list writes them, also when the file is already grouped."""
    out = []
    for e in entries:
        if 'witnesses' not in e:
            out.append(e)
            continue
        for w in e['witnesses']:
            out.append({'id': w['id'], 'page': w['page'], 'name': e['name'],
                        'severity': e.get('severity'), 'conclusion': w.get('conclusion')})
    return out

def _callers_by_return(labels):
    """return address -> states that make a call returning there."""
    idx = {}
    for st in (labels or {}).values():
        ra = getattr(st, 'return_addr', None)
        if type(ra) == int and ra != 0:
            idx.setdefault(ra, []).append(st)
    return idx

def _origin_call_pc(labels, callers, match):
    """
    Model pc of the call site a match starts from, when its first step is a
    call (an i- variable), else None. The checker sometimes matches that step
    on the import stub's own state (e.g. sym.imp.calloc) instead of the
    caller's; those are resolved to the caller, the state whose call returns
    to the next matched state, so both kinds of match share one origin.
    """
    states, mvars = match.get('states', []), match.get('vars', [])
    if not states or states[0] not in labels or not mvars:
        return None
    try:
        v = mvars[0][1][0]
    except (IndexError, TypeError):
        return None
    if not (type(v) == str and v.startswith('i-')):
        return None
    st = labels[states[0]]
    if (st.fname or '').startswith('sym.imp.'):
        if len(states) < 2 or states[1] not in labels:
            return None
        cands = [c for c in callers.get(labels[states[1]].pc, [])
                 if c.transition is not None and st.fname in (c.transition.dest or [])]
        if len(cands) != 1:
            return None
        st = cands[0]
    pc = get_call_site_pc(st)
    return pc if type(pc) == int else None

# Collapses the per-match results into findings. Which matches are the same
# finding depends on the property's group_by mode (see load_group_by): by
# default all matches of the same property that end at the same instruction
# (the sink, e.g. the out-of-bounds STORE) are one finding, reached through
# several paths/allocation sites.
# results.json gets one entry per finding (a representative result plus the
# list of witnesses); the individual result files are left untouched.
# Running it again on an already grouped results.json regroups from scratch.
# labels (the model) lets group_by "origin" key call origins on the call site
# (see _origin_call_pc); without it the origin's resolved address is used.
def group_results(target, results_folder, results_file, group_by=None, labels=None):
    group_by = group_by or {}
    callers = _callers_by_return(labels) if labels else {}
    with open(results_file, 'r') as f:
        entries = _ungroup(json.load(f))

    groups = {}
    for e in entries:
        summary = {}
        sp = os.path.join(results_folder, f"{e['id']}_summary.json")
        if os.path.exists(sp):
            with open(sp, 'r') as f:
                summary = json.load(f)
        beautify = summary.get('beautify', [])
        steps = [s for s in beautify if s.get('instr', {}).get('addr')]
        sink = _step_ref(steps[-1]) if steps else None
        origin = _step_ref(steps[0]) if steps else None
        mode = group_by.get(e['name'], DEFAULT_GROUP_BY)
        key = None
        stub = False
        if mode == 'sink' and sink:
            key = sink['addr']
        elif mode == 'origin':
            call_pc = None
            if labels:
                rp = os.path.join(results_folder, f"{e['id']}.json")
                if os.path.exists(rp):
                    with open(rp, 'r') as f:
                        call_pc = _origin_call_pc(labels, callers, json.load(f).get(e['id'], {}).get('match', {}))
            if call_pc is not None:
                key = ('pc', call_pc)
            # only the first spec step is an origin; if it did not resolve,
            # steps[0] is some later step and would merge unrelated matches
            elif beautify and beautify[0].get('instr', {}).get('addr'):
                key = origin['addr']
            # prefer a representative whose shown origin is the call, not the stub
            stub = bool(origin) and origin['func'].startswith('sym.imp.')
        # without a resolved anchor there is nothing to group on
        key = (e['name'], key) if key is not None else (e['name'], 'id:' + e['id'])
        complete = len(steps) == len(beautify) and len(steps) > 0
        groups.setdefault(key, []).append((e, sink, origin, summary.get('test_cases', ''), complete, mode, stub))

    findings = []
    for key, members in groups.items():
        # representative: feasible first, then a fully resolved summary
        members.sort(key=lambda m: (CONCLUSION_RANK.get(m[0].get('conclusion'), 1), not m[4], m[6], m[0]['id']))
        rep, sink, origin, mode = members[0][0], members[0][1], members[0][2], members[0][5]
        finding = dict(rep)
        finding['count'] = len(members)
        finding['group_by'] = mode
        finding['sink'] = sink
        finding['origin'] = origin
        finding['witnesses'] = [{'id': m[0]['id'], 'page': m[0]['page'], 'conclusion': m[0].get('conclusion'),
                                 'test_cases': m[3], 'origin': m[2], 'sink': m[1]} for m in members]
        findings.append(finding)

    findings.sort(key=lambda x: (x['name'], -x['count'], x['id']))
    with open(results_file, 'w') as f:
        json.dump(findings, f)

    print(f'Grouped {len(entries)} results into {len(findings)} findings')
    return findings

def get_bin_path(GLOB_CONF, target):
    config_file = os.path.join(GLOB_CONF.target_path, target, 'profile.json')
    f = open(config_file, 'r')
    config = json.load(f)
    f.close()
    is_extern = config['bin_type']
    target_file = config['target']
    if is_extern == 'built-in':
        target_dbg_file = os.path.join(GLOB_CONF.target_path, target, 'dbg', f'{target_file}_dbg')
        target_file = os.path.join(GLOB_CONF.dumps_path, f'{target_file}.bin')
        if os.path.exists(target_dbg_file):
            target_file = target_dbg_file
        elif not os.path.exists(target_file):
            target_file = os.path.join(GLOB_CONF.dumps_path, f'{config["target_pages"]}.bin')
    else:
        target_dbg_file = os.path.join(GLOB_CONF.target_path, target, 'dbg', f'{target_file}_dbg')
        target_dbg_bins_file = os.path.join(GLOB_CONF.mount_path, f'{target_file}_dbg')
        if os.path.exists(target_dbg_file):
            target_file = target_dbg_file
        elif os.path.exists(target_dbg_bins_file):
            target_file = target_dbg_bins_file
        elif not os.path.isfile(os.path.join(GLOB_CONF.mount_path, target_file)):
            target_file = config['target_path']
        else:
            target_file = os.path.join(GLOB_CONF.mount_path, target_file)
    
    return target_file

def post_process_results(GLOB_CONF, target, labels):
    results_folder = os.path.join(GLOB_CONF.target_path, target, 'results')
    results_file = os.path.join(GLOB_CONF.target_path, target, 'results.json')
    if not os.path.exists(results_folder):
        return
    
    result_ids = create_results_list(target, results_folder, results_file)
    bin_file = get_bin_path(GLOB_CONF, target)
    try:
        for i in track(range(len(result_ids)), description='Processing....'):
            result_id = result_ids[i]
            postprocess_result(os.path.join(GLOB_CONF.target_path, target), target, result_id, labels, bin_file)
    finally:
        # one radare2 session served every result; quit it now
        bin_map.close_r2pipes()

    group_results(target, results_folder, results_file, load_group_by(GLOB_CONF.property_dir), labels)
    print('Done!')

def regroup_results(GLOB_CONF, target):
    """Regroup an already post-processed target, e.g. after changing a property's group_by."""
    results_folder = os.path.join(GLOB_CONF.target_path, target, 'results')
    results_file = os.path.join(GLOB_CONF.target_path, target, 'results.json')
    if not os.path.exists(results_file):
        return
    labels = None
    labels_file = os.path.join(GLOB_CONF.target_path, target, 'model.labels')
    if os.path.exists(labels_file):
        with open(labels_file, 'rb') as f:
            labels = pickle.load(f)
    return group_results(target, results_folder, results_file, load_group_by(GLOB_CONF.property_dir), labels)


