#--------------------------------------
# File: backend.py
#
# Purpose: Backend for web application
#--------------------------------------
import os
import re
import ast
import json
import shutil
import time
import datetime
import pickle
import hy2.core.utils as utils
from hy2.core.glob_conf import GlobalConfig

GLOBAL_CONFIG_FILE = "config.json"
GLOBAL_CONFIG = utils.loadGlobalConfigFile(GLOBAL_CONFIG_FILE, GlobalConfig())

def get_queue():
    queue = ''
    with open('queue.json', 'r') as f:
        try:
            data = json.load(f)
            queue = '\n'.join([str(item) for item in data['queue']])
        except:
            pass
    targets = sorted([x for x in os.listdir(GLOBAL_CONFIG.target_path) if os.path.isdir(os.path.join(GLOBAL_CONFIG.target_path, x))])
    return {'queue': queue, 'targets': targets, 'tasks': TARGET_TASKS}

def update_queue(data):
    new_queue = []
    for x in data.split('\n'):
        x = x.strip()
        if x == '':
            continue
        try:
            x = x.replace("'", '"')
            new_queue.append(json.loads(x))
        except:
            print('ERROR: Couldn\'t decode: '+x)

    with open('queue.json', 'w') as f:
        json.dump({'queue': new_queue}, f)  

def add_to_queue(task):
    with open('queue.json', 'r') as f:
        text = f.read()
    
    text = text.strip()
    if text != '':
        try:
            data = json.loads(text)
        except:
            return {'status': "Failed: Couldn't load queue file"}
    else:
        data = {'queue': []}
    
    try:
        data['queue'] += [task]
        with open('queue.json',  'w') as f:
            json.dump(data, f)
        return {'status': 'Success!'}
    except:
        return {'status': "Failed: Couldn't parse job"}

def clear_queue():
    with open('queue.json', 'w') as f:
        json.dump({'queue': []}, f)

# Per-target tasks run by worker.py, in pipeline order
TARGET_TASKS = ['symbol resolution', 'trace', 'model', 'check']

def queue_target_tasks(name, tasks=None):
    if not name or not os.path.isdir(os.path.join(GLOBAL_CONFIG.target_path, name)):
        return {'status': f'Failed: Unknown target {name}', 'added': 0}
    if tasks is None:
        tasks = TARGET_TASKS
    tasks = [t for t in TARGET_TASKS if t in tasks]
    if tasks == []:
        return {'status': 'Failed: No tasks selected', 'added': 0}

    with open('queue.json', 'r') as f:
        text = f.read().strip()
    if text != '':
        try:
            data = json.loads(text)
        except:
            return {'status': "Failed: Couldn't load queue file", 'added': 0}
    else:
        data = {'queue': []}

    # A task already waiting for this target is moved, not duplicated, so the
    # tasks always run in pipeline order (e.g. trace after symbol resolution).
    jobs = [{'target': name, 'task': t} for t in tasks]
    moved = len([j for j in data['queue'] if j in jobs])
    data['queue'] = [j for j in data['queue'] if j not in jobs] + jobs

    with open('queue.json', 'w') as f:
        json.dump(data, f)

    status = f'Queued {len(jobs)} task{"" if len(jobs) == 1 else "s"} for {name}'
    if moved > 0:
        status += f' ({moved} already queued, moved to the end)'
    return {'status': status, 'added': len(jobs) - moved, 'queue': get_queue()['queue']}


def get_settings():
    f = open(GLOBAL_CONFIG_FILE, 'r')
    dat = json.load(f)
    f.close()
    data  = {}
    dat = dat['globals']
    data['max_depth'] = dat['max_depth']
    data['toggle_infeasible'] = 'False'
    if 'show_infeasible' in dat:
        b = dat['show_infeasible']
        if not b:
            data['toggle_infeasible'] = "True"
    
    return data

def update_settings(data):
    f = open(GLOBAL_CONFIG_FILE, 'r')
    dat = json.load(f)
    f.close()
    if data.get('maxdepth'):
        dat['globals']['max_depth'] = int(data['maxdepth'])
    show_infeasible = 'toggleinfeasible' not in data   # checkbox means "hide infeasible"
    dat['globals']['show_infeasible'] = show_infeasible
    GLOBAL_CONFIG.show_infeasible = show_infeasible
    with open(GLOBAL_CONFIG_FILE, 'w') as f:
        json.dump(dat, f, indent=4)

    
def create_target_profile(data):
    name = data['name']
    if not os.path.exists(os.path.join(GLOBAL_CONFIG.target_path, name)):
        os.mkdir(os.path.join(GLOBAL_CONFIG.target_path, name))
    
    profile_data = {'target_path': '', 'recording_name': 'sample', 'arch': 'x86_64', 'image_type': 'generic', 'bin_type': 'extern', 'out_of_scope': [], 'type': 'prog', 'target_pages': [], 'preconditions': [], 'postconditions': []}
    profile_data['target'] = name
    
    target_path = data['targetpath']
    if target_path == "":
        target_path = GLOBAL_CONFIG.mount_path
    profile_data['target_path'] = target_path
    profile_data['arch'] = data['arch']
    profile_data['image_type'] = data['imagetype']
    profile_data['bin_type'] = data['bintype']
    profile_data['target_type'] = data['targettype'] 
    profile_data['target_pages'] = data['targetlib'].split(',')
    preconditions = data['preconditions']
    postconditions = data['postconditions']
    if preconditions != "":
        profile_data['preconditions'] = preconditions.split('\n')
    if postconditions != "":
        profile_data['postconditions'] = postconditions.split('\n')
    

    if profile_data['bin_type'] == 'extern':
        if target_path == GLOBAL_CONFIG.mount_path and os.path.exists(os.path.join(GLOBAL_CONFIG.mount_path, name)):
            pass
        else:
            shutil.copy(target_path, GLOBAL_CONFIG.mount_path)

    with open(os.path.join(GLOBAL_CONFIG.target_path, name, 'profile.json'), 'w') as f:
        json.dump(profile_data, f)
    

    symbols_file_init = {"symbols": {}}
    with open(os.path.join(GLOBAL_CONFIG.target_path, name, f'{name}_symbols.json'), 'w') as f:
        json.dump(symbols_file_init, f)
    
    with open('queue.json', 'r') as f:
        data = json.load(f)
    
    data['queue'] += [{'target': name, 'task': 'symbol resolution'}]
    with open('queue.json', 'w') as f:
        json.dump(data, f)

def update_target_profile(data):
    name = data['name']
    if not os.path.exists(os.path.join(GLOBAL_CONFIG.target_path, name)):
        return
    
    current_profile_data = {}
    f = open(os.path.join(GLOBAL_CONFIG.target_path, name, 'profile.json'), 'r')
    current_profile_data = json.load(f)
    f.close()

    print(data)

    profile_data  = current_profile_data
    profile_data['target'] = name
    
    target_path = data['targetpath']
    if target_path == "":
        target_path = GLOBAL_CONFIG.mount_path
    profile_data['target_path'] = target_path
    profile_data['arch'] = data['arch']
    profile_data['image_type'] = data['imagetype']
    profile_data['bin_type'] = data['bintype']
    profile_data['target_type'] = data['targettype'] 
    profile_data['target_pages'] = data['targetpages'].split(',')
    preconditions = data['preconditions']
    postconditions = data['postconditions']
    if preconditions != "":
        profile_data['preconditions'] = preconditions.split('\n')
    if postconditions != "":
        profile_data['postconditions'] = postconditions.split('\n')
    
    with open(os.path.join(GLOBAL_CONFIG.target_path, name, 'profile.json'), 'w') as f:
        json.dump(profile_data, f)

def add_input_example(target, input_data):
    target_dir = os.path.join(GLOBAL_CONFIG.target_path, target)
    if not os.path.exists(target_dir):
        return 1
    template_file = os.path.join(GLOBAL_CONFIG.target_path, target, 'profile.json')
    f = open(template_file, 'r')
    data = json.load(f)
    f.close()
    new_test_case = data
    new_test_case['command'] = []
    try:
        cs = json.loads(input_data)
        if type(cs) == dict:
            new_test_case['command'] = [cs]
        elif type(cs) == list:
            new_test_case['command'] = cs
    except:
        cmds = input_data.split('\n')
        for cmd in cmds:
            try:
                cmd = cmd.rstrip()
                if cmd[-1] == ',':
                    cmd = cmd[:-1]
                new_test_case['command'].append(json.loads(cmd))
            except:
                print('[ERROR]: Could not parse command: '+str(cmd))
                return 1

    if new_test_case['command'] == []:
        return 1
    tc_name = os.path.join(target_dir, f'{target}_tc_{utils.md5(str(input_data).encode("utf-8"))}.json')
    with open(tc_name, 'w') as f:
        json.dump(new_test_case, f)
    return 0


def get_index_stats():
    data = {}
    target_files = os.listdir(GLOBAL_CONFIG.target_path)
    target_files = [x for x in target_files if os.path.isdir(os.path.join(GLOBAL_CONFIG.target_path, x))]
    no_targets = len(target_files)
    data['no_targets'] = no_targets
    
    property_files = os.listdir(GLOBAL_CONFIG.property_dir)
    no_properties = len(property_files) - 1
    data['no_properties'] = no_properties

    today = datetime.datetime.now()
    date_time = today.strftime("%H:%M:%S")
    hr = int(date_time.split(":")[0])
    if hr < 12:
        data['heading'] = "Good Morning!"
    elif hr < 16:
        data['heading'] = "Good Afternoon!"
    else:
        data['heading'] = "Good Evening!"
    
    sorted_mtime_desc = sorted(target_files, key=lambda t: -os.stat(os.path.join(GLOBAL_CONFIG.target_path, t)).st_mtime)
    top_5 = sorted_mtime_desc[:5]
    data["top_5"] = top_5
    by_name = {t['id']: t for t in get_target_list()}
    data["recent"] = [by_name[t] for t in top_5 if t in by_name]
    data["no_violations"] = sum(t['violations'] for t in by_name.values())
    data["no_analyzed"] = sum(1 for t in by_name.values() if t['results'] is not None)
    return data

def get_target_list():
    files = []
    for x in sorted(os.listdir(GLOBAL_CONFIG.target_path)):
        tdir = os.path.join(GLOBAL_CONFIG.target_path, x)
        if not os.path.isdir(tdir):
            continue
        item = {"filename": x, "id": x, "results": None, "violations": 0, "review": 0}
        results = _load_json(os.path.join(tdir, 'results.json'))
        if isinstance(results, list):
            item['results'] = len(results)
            for r in results:
                k = verdict_key(r.get('conclusion'))
                if k in ('violation', 'review'):
                    item[{'violation': 'violations', 'review': 'review'}[k]] += 1
        profile = _load_json(os.path.join(tdir, 'profile.json'), {})
        item['arch'] = profile.get('arch', '')
        item['inputs'] = len([t for t in os.listdir(tdir) if '_tc_' in t and t.endswith('.json')])
        item['updated'] = datetime.datetime.fromtimestamp(os.stat(tdir).st_mtime).strftime('%Y-%m-%d %H:%M')
        files.append(item)
    return files

# ---------------------------------------------------------------
# Results: helpers that turn raw result files into structured data
# for the web UI.
# ---------------------------------------------------------------
VERDICTS = {
    'violation':  {'label': 'Violation',    'hint': 'Constraints are satisfiable (sat): the property violation is feasible.'},
    'infeasible': {'label': 'Infeasible',   'hint': 'Constraints are unsatisfiable (unsat): the violation cannot occur on this path.'},
    'review':     {'label': 'Needs review', 'hint': 'The solver could not decide this result; inspect it manually.'},
}

def verdict_key(conclusion):
    return {'sat': 'violation', 'unsat': 'infeasible'}.get(conclusion, 'review')

def _target_dir(name):
    return os.path.join(GLOBAL_CONFIG.target_path, name)

def _load_json(path, default=None):
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except (OSError, ValueError):
        return default

def _load_results_list(name, verdict=None):
    """
    results.json in display order: grouped by property, groups with the most
    violations first. Filtered by the show_infeasible setting and, optionally,
    by verdict ('violation' / 'infeasible' / 'review').
    """
    results = _load_json(os.path.join(_target_dir(name), 'results.json'), [])
    if not GLOBAL_CONFIG.show_infeasible:
        results = [r for r in results if r.get('conclusion') != 'unsat']
    violations = {}
    for r in results:
        violations[r.get('name', '')] = violations.get(r.get('name', ''), 0) + (r.get('conclusion') == 'sat')
    results = sorted(results, key=lambda r: (-violations[r.get('name', '')], r.get('name', '')))
    if verdict in VERDICTS:
        results = [r for r in results if verdict_key(r.get('conclusion')) == verdict]
    return results

def _split_source_ref(ref):
    """'bof2.c:17' -> ('bof2.c', 17)"""
    if not ref or ':' not in ref:
        return ref or '', None
    path, line = ref.rsplit(':', 1)
    try:
        return path, int(line)
    except ValueError:
        return ref, None

def _parse_spec(spec):
    """'STORE(a,b) (x like y)   (z == False) ' -> event, args, conditions"""
    spec = (spec or '').strip()
    m = re.match(r'([^\s(]+)\((.*?)\)(.*)', spec, re.S)
    if not m:
        return {'event': spec, 'args': [], 'conds': [], 'raw': spec}
    args = [a.strip() for a in m.group(2).split(',') if a.strip()]
    conds = [c.strip() for c in re.findall(r'\(([^()]*)\)', m.group(3)) if c.strip()]
    return {'event': m.group(1), 'args': args, 'conds': conds, 'raw': spec}

def _split_top_level(text, sep=','):
    parts, depth, cur = [], 0, ''
    for ch in text:
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth -= 1
        if ch == sep and depth == 0:
            parts.append(cur.strip())
            cur = ''
        else:
            cur += ch
    if cur.strip():
        parts.append(cur.strip())
    return parts

def _take_bracket_list(text):
    """If text starts with '[', return (items, remainder); else (None, text)."""
    s = text.lstrip()
    if not s.startswith('['):
        return None, text
    depth = 0
    for i, ch in enumerate(s):
        if ch == '[':
            depth += 1
        elif ch == ']':
            depth -= 1
            if depth == 0:
                return _split_top_level(s[1:i]), s[i + 1:]
    return None, text

def parse_explanation(text):
    """
    The solver explanation is laid out as:
        [constraint, ...]
        sat | unsat
        [witness assignment, ...] | n/a
        ERROR!/WARNING: diagnostics...
    Anything that doesn't fit is kept in 'raw'.
    """
    out = {'constraints': [], 'solver': None, 'witness': [], 'diagnostics': [], 'raw': text or ''}
    if not text:
        return out
    constraints, rest = _take_bracket_list(text)
    if constraints is None:
        lines = text.strip().split('\n')
        rest = text
    else:
        out['constraints'] = constraints
    lines = rest.strip().split('\n')
    if lines and lines[0].strip() in ('sat', 'unsat', 'unknown'):
        out['solver'] = lines[0].strip()
        rest = '\n'.join(lines[1:])
        witness, rest2 = _take_bracket_list(rest)
        if witness is not None:
            out['witness'] = [w.split('=', 1) if '=' in w else [w, ''] for w in witness]
            out['witness'] = [[k.strip(), v.strip()] for k, v in out['witness']]
            rest = rest2
        elif rest.strip().startswith('n/a'):
            rest = rest.strip()[3:]
    # Deduplicate diagnostics, keeping first-seen order
    counts = {}
    for line in rest.strip().split('\n'):
        line = line.strip()
        if not line or line in ('ERROR!:', 'WARNING:'):
            continue
        counts[line] = counts.get(line, 0) + 1
    out['diagnostics'] = [{'text': k, 'count': v, 'level': 'error' if k.startswith('ERROR') else 'warning'}
                          for k, v in counts.items()]
    return out

def _source_root(name):
    dbg_src = os.path.join(_target_dir(name), 'dbg', 'src')
    if os.path.exists(dbg_src):
        return dbg_src
    profile = _load_json(os.path.join(_target_dir(name), 'profile.json'), {})
    return profile.get('src_path', '')

_src_cache = {}
def _read_source_lines(path):
    try:
        mtime = os.stat(path).st_mtime
    except OSError:
        return None
    cached = _src_cache.get(path)
    if cached and cached[0] == mtime:
        return cached[1]
    try:
        with open(path, 'r', errors='replace') as f:
            lines = f.read().split('\n')
    except OSError:
        return None
    _src_cache[path] = (mtime, lines)
    return lines

def _snippet(lines, marks, context=4):
    """Build merged hunks around the marked lines. marks: {line_no: [labels]}"""
    if not lines or not marks:
        return []
    ranges = sorted((max(1, l - context), min(len(lines), l + context)) for l in marks)
    merged = []
    for s, e in ranges:
        if merged and s <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    return [[{'no': n, 'text': lines[n - 1], 'marks': marks.get(n, [])} for n in range(s, e + 1)]
            for s, e in merged]

def _summary_steps(summary):
    steps = []
    for b in (summary or {}).get('beautify', []):
        instr = b.get('instr', {})
        path, line = _split_source_ref(instr.get('source_file', ''))
        if line is None:
            # radare comment parsing sometimes yields a type name ('void', 'size_t'...)
            # instead of file:line; treat as unknown and drop the bogus code text too
            path = ''
            instr = dict(instr, code='')
        steps.append({
            'spec': _parse_spec(b.get('spec', '')),
            'func': (b.get('func') or '').strip(),
            'file': path,
            'line': line,
            'code': (instr.get('code') or '').strip(),
            'addr': instr.get('addr', ''),
            'opcodes': (instr.get('opcodes') or '').strip(),
            'raw': instr.get('raw', ''),
            'var': instr.get('var') if isinstance(instr.get('var'), dict) else None,
        })
    return steps

def _main_func(funcs):
    """First function that isn't an import stub or unresolved block."""
    funcs = [f for f in funcs if f]
    for f in funcs:
        if not f.startswith(('sym.imp.', 'unknown')):
            return f
    return funcs[0] if funcs else ''

def _summary_location(summary, result_file=None):
    """Short 'where' info for result lists."""
    steps = _summary_steps(summary)
    for s in steps:
        if s['file']:
            return {'file': s['file'], 'line': s['line'], 'func': s['func'], 'code': s['code']}
    funcs = [s['func'] for s in steps]
    funcs += [t['var'].get('fname') for t in (summary or {}).get('trace', []) if isinstance(t.get('var'), dict)]
    if not any(funcs) and result_file:
        data = _load_json(result_file, {})
        for v in data.values():
            funcs = v.get('match_funcs', []) if isinstance(v, dict) else []
    func = _main_func(funcs)
    if func:
        return {'file': '', 'line': None, 'func': func, 'code': ''}
    return None

def _step_location(ref):
    """Location dict (as _summary_location) from a grouped finding's sink/origin ref."""
    if not ref or not ref.get('addr'):
        return None
    path, line = _split_source_ref(ref.get('source_file', ''))
    if line is None:
        path = ''
    return {'file': path, 'line': line, 'func': ref.get('func', ''), 'code': ref.get('code', ''), 'addr': ref.get('addr', '')}

def _short_inputs(test_cases):
    """'tgt_tc_f8a8ea52....json, tgt_tc_7428...json' -> 'f8a8ea52, 74281035'; 'all' -> 'all inputs'."""
    tcs = [t.strip() for t in (test_cases or '').split(',') if t.strip()]
    if tcs == ['all']:
        return 'all inputs'
    return ', '.join(re.sub(r'\.json$', '', t).split('_tc_')[-1][:8] for t in tcs) or '—'

def _group_ends(f):
    """(shared end, per-match end) of a grouped finding: ('sink', 'origin') unless its property groups by origin."""
    if f.get('group_by') == 'origin':
        return 'origin', 'sink'
    return 'sink', 'origin'

def _grouping_summary(findings):
    """
    What group_results() collapsed: for every finding with more than one
    match, the representative shown in the list and the duplicates hidden
    behind it. None when results.json is not grouped or nothing was merged.
    """
    if not any('witnesses' in f for f in findings):
        return None
    groups = []
    for f in findings:
        ws = f.get('witnesses', [])
        if len(ws) < 2:
            continue
        shared, other = _group_ends(f)
        hidden = [dict(w, verdict=verdict_key(w.get('conclusion')), loc=_step_location(w.get(other)),
                       inputs_short=_short_inputs(w.get('test_cases')))
                  for w in ws if w.get('id') != f['id']]
        rep = next((w for w in ws if w.get('id') == f['id']), {})
        others = {(w.get(other) or {}).get('addr') for w in ws}
        tcs = set()
        for w in ws:
            tcs.update(t.strip() for t in (w.get('test_cases') or '').split(',') if t.strip())
        verdicts = {'violation': 0, 'infeasible': 0, 'review': 0}
        for w in ws:
            verdicts[verdict_key(w.get('conclusion'))] += 1
        groups.append({
            'name': f.get('name', ''), 'rep_id': f['id'], 'count': len(ws),
            'anchor': _step_location(f.get(shared)), 'anchor_kind': shared, 'other_kind': other,
            'rep_loc': _step_location(rep.get(other)),
            'distinct': len(others - {None, ''}), 'test_cases': sorted(tcs),
            'verdicts': verdicts, 'hidden': hidden,
        })
    matches = sum(f.get('count', 1) for f in findings)
    return {'matches': matches, 'findings': len(findings), 'hidden': matches - len(findings),
            'merged': len(groups), 'groups': sorted(groups, key=lambda g: -g['count'])}

def _find_finding(name, id):
    """The grouped results.json entry that contains result `id` (as representative or witness)."""
    for r in _load_json(os.path.join(_target_dir(name), 'results.json'), []):
        if r.get('id') == id or any(w.get('id') == id for w in r.get('witnesses', [])):
            return r
    return None

def _unique(seq):
    seen = set()
    return [x for x in seq if not (x in seen or seen.add(x))]

def _as_list(v):
    """Values are sometimes stored as the repr of a Python list; turn those into real lists."""
    if isinstance(v, str) and v.startswith('[') and v.endswith(']'):
        try:
            parsed = ast.literal_eval(v)
            if isinstance(parsed, list):
                return parsed
        except (ValueError, SyntaxError):
            pass
    return v

def get_result_by_id(name, id, verdict_filter=None):
    target_dir = _target_dir(name)
    results_dir = os.path.join(target_dir, 'results')
    result = _load_json(os.path.join(results_dir, f'{id}.json'))
    if not result or id not in result:
        return None
    data = result[id]
    summary = _load_json(os.path.join(results_dir, f'{id}_summary.json'), {})

    res = {'name': name, 'id': id}

    # Grouped finding this result belongs to; the pager steps through
    # findings, so a witness takes its finding's position.
    finding = _find_finding(name, id)
    list_id = finding['id'] if finding else id
    if finding and finding.get('witnesses'):
        shared, other = _group_ends(finding)
        res['finding'] = {
            'count': finding.get('count', len(finding['witnesses'])),
            'rep_id': finding['id'],
            'anchor': _step_location(finding.get(shared)), 'anchor_kind': shared, 'other_kind': other,
            'witnesses': [dict(w, verdict=verdict_key(w.get('conclusion')), loc=_step_location(w.get(other)))
                          for w in finding['witnesses']],
        }

    # Position within the result list (same order as the profile page)
    ids = [r['id'] for r in _load_results_list(name, verdict_filter)]
    if list_id not in ids and verdict_filter:
        verdict_filter = None
        ids = [r['id'] for r in _load_results_list(name)]
    res['filter'] = verdict_filter
    if list_id in ids:
        idx = ids.index(list_id)
        res['position'] = idx + 1
        res['total'] = len(ids)
        res['prev_id'] = ids[idx - 1] if len(ids) > 1 else None
        res['next_id'] = ids[(idx + 1) % len(ids)] if len(ids) > 1 else None

    res['property'] = data.get('name', 'Unknown property')
    res['property_descr'] = data.get('property_descr', '')
    res['severity'] = (data.get('severity') or 'unknown').lower()
    res['conclusion'] = data.get('conclusion', '')
    res['verdict'] = verdict_key(res['conclusion'])
    res['verdict_info'] = VERDICTS[res['verdict']]
    res['solver'] = parse_explanation(data.get('explanation', ''))
    res['test_cases'] = summary.get('test_cases', '')
    res['functions'] = _unique([f for f in data.get('match_funcs', []) if f])
    res['main_func'] = _main_func(res['functions'])
    res['spec'] = [_parse_spec(s) for s in data.get('spec', [])]

    variables = data.get('match', {}).get('variables', {})
    res['variables'] = [{'entry': k, 'value': _as_list(v)} for k, v in variables.items()]

    # Matched steps, each with a little source context if we have the source
    steps = _summary_steps(summary)
    root = _source_root(name)
    for s in steps:
        s['source'] = []
        if root and s['file'] and s['line']:
            lines = _read_source_lines(os.path.join(root, s['file']))
            if lines:
                s['source'] = _snippet(lines, {s['line']: [s['spec']['event']]}, context=3)
    res['steps'] = steps
    res['has_source'] = any(s['source'] for s in steps)

    # Execution trace: group consecutive 'trace' events so the important
    # spec/var events stand out.
    groups = []
    for i, e in enumerate(data.get('str', [])):
        ev = e.get('event', '')
        if ev == 'trace':
            if groups and groups[-1]['kind'] == 'trace':
                groups[-1]['events'].append({'i': i, 'html': e.get('str', '')})
                continue
            groups.append({'kind': 'trace', 'events': [{'i': i, 'html': e.get('str', '')}]})
        else:
            groups.append({'kind': ev or 'other', 'events': [{'i': i, 'html': e.get('str', '')}]})
    res['trace'] = groups
    res['trace_len'] = len(data.get('str', []))
    return res

def get_result_source(name, id):
    """All matched source locations for a result, grouped by file with merged context hunks."""
    summary = _load_json(os.path.join(_target_dir(name), 'results', f'{id}_summary.json'), {})
    root = _source_root(name)
    by_file = {}
    for s in _summary_steps(summary):
        if s['file'] and s['line']:
            by_file.setdefault(s['file'], {}).setdefault(s['line'], []).append(s['spec']['event'])
    files = []
    for path, marks in by_file.items():
        lines = _read_source_lines(os.path.join(root, path)) if root else None
        files.append({'file': path, 'found': bool(lines),
                      'hunks': _snippet(lines, marks, context=8) if lines else [],
                      'marks': sorted(marks)})
    return {'files': files, 'has_root': bool(root)}

def get_property_list():
    property_list  = os.listdir(os.path.join(GLOBAL_CONFIG.property_dir, 'dsl'))
    data = [{'name': p, 'id': p.split('.')[0]} for p in property_list]
    return data

def read_property(name):
    property_file = os.path.join(GLOBAL_CONFIG.property_dir, 'dsl', f'{name}.txt')
    f = open(property_file, 'r')
    dat = f.read()
    f.close()
    data = {}
    p = dat.split('---', 1)
    header = p[0]
    header_prop = header.split('\n')
    for hp in header_prop:
        xs = hp.split(':', 1)
        if xs[0] in ["Name", "name"]:
            data['name'] = xs[1].lstrip()
        elif xs[0] in ["Severity", "severity"]:
            data['severity'] = xs[1].lstrip()
        elif xs[0] in ["Notes", "notes"]:
            data['notes'] = xs[1].lstrip()
        else:
            pass
    definition = p[1]
    data['definition'] = definition
    return data


def get_property_name(pname, selected):
    with open(pname, 'r') as f:
        dat = json.load(f)
        return {'id': os.path.basename(pname), 'name': dat['name'], 'selected': str(selected)}

def get_selected_properties(name):
    properties_dir = os.path.join(GLOBAL_CONFIG.property_dir, 'json')
    properties = os.listdir(properties_dir)
    
    target_config = os.path.join(GLOBAL_CONFIG.target_path, name, 'profile.json')
    target_properties = []
    with open(target_config, 'r') as f:
        dat = json.load(f)
        if 'properties' in dat:
            target_properties = dat['properties']

    pnames = [get_property_name(os.path.join(properties_dir, p), (p in target_properties)) for p in properties if p != 'lib.json']    
    return pnames

def update_selected_properties(name, request_form):
    properties_dir = os.path.join(GLOBAL_CONFIG.property_dir, 'json')
    properties_list = os.listdir(properties_dir)
    filtered_properties = [p for p in properties_list if p in request_form and request_form[p] == 'on']
    target_config = os.path.join(GLOBAL_CONFIG.target_path, name, 'profile.json')
    
    with open(target_config, 'r') as f:
        data = json.load(f)
    
    data['properties'] = filtered_properties

    with open(target_config, 'w') as f:
        json.dump(data, f)

def get_target_config(name):
    profile_file = os.path.join(GLOBAL_CONFIG.target_path, name, 'profile.json')
    f = open(profile_file, 'r')
    data = json.load(f)
    f.close()
    if not 'target_path' in data:
        data['target_path'] = GLOBAL_CONFIG.mount_path
    if not 'type' in data:
        data['type'] = 'prog'
    if not 'target_pages' in data:
        data['target_pages'] = [data['target']]

    target_path = os.path.join(GLOBAL_CONFIG.target_path, name)
    input_examples = [t for t in os.listdir(target_path) if f'{name}_tc_' in t and '.json' in t]
    data['properties'] = get_selected_properties(name)
    return data, input_examples

def get_input_example(name, tid):
    tc_file = os.path.join(GLOBAL_CONFIG.target_path, name, tid)
    f = open(tc_file, 'r')
    data = json.load(f)
    f.close()
    d = {}
    d['cmds'] = '\n'.join([str(c) for c in data['command']])
    return d

def read_stats(name):
    stats_file = os.path.join(GLOBAL_CONFIG.target_path, name, 'stats.json')
    if not os.path.exists(stats_file):
        data = {'no_blocks': 0, 'errors': ""}
        data['latency'] = {'trace_analysis': 0, 'vm_read': 0, 'vm_write': 0, 'bb_exec': 0, 'hook_symbols': 0, 'context_switch': 0}
        with open(stats_file, 'w') as f:
            json.dump(data, f)
        return data
    else:
        f = open(stats_file, 'r')
        data = json.load(f)
        f.close()
        return data

# Trace runs for the diagnostics panel, newest first. Runs are recorded in
# stats.json by miner.py; test cases traced before that (a -cfg.bin exists but
# no stats entry) are listed without numbers.
def _stats_runs(name, stats):
    tdir = os.path.join(GLOBAL_CONFIG.target_path, name)
    runs = []
    recorded = stats.get('runs', {}) if isinstance(stats.get('runs'), dict) else {}
    for tc, r in recorded.items():
        runs.append({'tc': tc, 'short': tc.replace(f'{name}_tc_', '')[:10], 'recorded': True,
                     'time': r.get('time', ''), 'no_blocks': r.get('no_blocks', 0),
                     'trace_analysis': r.get('latency', {}).get('trace_analysis'),
                     'total': r.get('latency', {}).get('total'), 'errors': r.get('errors', [])})
    for fn in os.listdir(tdir):
        if fn.startswith(f'{name}_tc_') and fn.endswith('-cfg.bin'):
            tc = fn[:-len('-cfg.bin')]
            if tc in recorded:
                continue
            mtime = datetime.datetime.fromtimestamp(os.stat(os.path.join(tdir, fn)).st_mtime)
            runs.append({'tc': tc, 'short': tc.replace(f'{name}_tc_', '')[:10], 'recorded': False,
                         'time': mtime.strftime('%Y-%m-%d %H:%M:%S'), 'no_blocks': None,
                         'trace_analysis': None, 'total': None, 'errors': []})
    runs.sort(key=lambda r: r['time'], reverse=True)
    return runs

def get_target_profile(name):
    profile_file = os.path.join(GLOBAL_CONFIG.target_path, name, 'profile.json')
    f = open(profile_file, 'r')
    data = json.load(f)

    data['name'] = name
    data['initials'] = name[:2]

    test_files = os.listdir(os.path.join(GLOBAL_CONFIG.target_path, name))
    input_example_files = [t for t in test_files if '_tc_' in t and '.json' in t]

    data['no_input_examples'] = len(input_example_files)
    data['input_examples'] = test_files

    saved_trace_files = [t for t in test_files if '_tc_' in t and '-backing.bin' in t]
    data['no_trace_files'] = len(saved_trace_files)

    if 'model.trace' in test_files:
        data['is_modeled'] = "true"

    data['stats'] = read_stats(name)
    data['stats']['runs_list'] = _stats_runs(name, data['stats'])
    if data['stats']['errors'] == "":
        data['stats']['errors'] = 'None to report.'
    results_folder = os.path.join(GLOBAL_CONFIG.target_path, name, 'results')
    results_file = os.path.join(GLOBAL_CONFIG.target_path, name, 'results.json')
    all_results = _load_json(results_file, []) if os.path.exists(results_folder) else []
    counts = {'violation': 0, 'infeasible': 0, 'review': 0}
    for r in all_results:
        counts[verdict_key(r.get('conclusion'))] += 1
    data['stats']['no_results'] = len(all_results)
    data['stats']['no_paths'] = sum(r.get('count', 1) for r in all_results)
    data['grouping'] = _grouping_summary(all_results)
    data['stats']['no_results_sat'] = counts['violation']
    data['stats']['no_results_unsat'] = counts['infeasible']
    data['stats']['no_results_review'] = counts['review']
    data['hidden_infeasible'] = (not GLOBAL_CONFIG.show_infeasible) and counts['infeasible'] > 0

    groups = {}
    for r in _load_results_list(name):
        summary = _load_json(os.path.join(results_folder, f"{r['id']}_summary.json"), {})
        item = dict(r)
        item['verdict'] = verdict_key(r.get('conclusion'))
        item['severity'] = (r.get('severity') or 'unknown').lower()
        # grouped findings are located where their matches meet: the sink
        # (where the violation happens), or the origin for group_by "origin"
        item['location'] = _step_location(r.get(_group_ends(r)[0])) or _summary_location(summary, os.path.join(results_folder, f"{r['id']}.json"))
        item['count'] = r.get('count', 1)
        item['inputs'] = summary.get('test_cases', '')
        g = groups.setdefault(r.get('name', 'Unknown property'),
                              {'name': r.get('name', 'Unknown property'), 'severity': item['severity'],
                               'results': [], 'counts': {'violation': 0, 'infeasible': 0, 'review': 0}})
        g['results'].append(item)
        g['counts'][item['verdict']] += 1
    # Most actionable groups first
    data['result_groups'] = list(groups.values())   # already in display order
    if all_results:
        data['has_results'] = "true"

    if f'{name}_symbols.json' in test_files:
        data['symbols'] = "true"
    
    return data

def query_target(target, trace_id, block_id, query):
    target_path = os.path.join(GLOBAL_CONFIG.target_path, target)
    input_examples = [t for t in os.listdir(target_path) if f'{target}_tc_' in t and '.json' in t]
    if trace_id == None:
        return {'target': target, 'input_examples': input_examples}

    if '.json' in trace_id:
        trace_id = trace_id.split('.json')[0]
        trace_id = f'{trace_id}-backing.bin'
    
    trace_file = os.path.join(GLOBAL_CONFIG.target_path, target, trace_id)
    try:
        f = open(trace_file, 'rb')
        labels = pickle.load(f)
        f.close()
        labels = list(labels.values())
        htmlStr = ""
        if query != None and query != "":
            for l in labels:
                if l.fname in query or query in l.fname:
                    htmlStr += l.export_html()
            
        elif block_id != None and block_id != "":
            if type(block_id) == str:
                block_id = int(block_id)
            blocks =  labels[block_id:block_id+50]
            for b in blocks:
                htmlStr += b.export_html()
        else:
            blocks = labels[:50]
            for b in blocks:
                htmlStr += b.export_html()
    except:
        return {'target': target, 'input_examples': input_examples, 'status': 'Error: Error Reading Trace File'}

    return {'target': target, 'input_examples': input_examples, 'input_example': trace_id, 'body': htmlStr}
