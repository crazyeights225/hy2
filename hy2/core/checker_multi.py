#--------------------------------------
# File: checker_multi.py
#
# Purpose: Version of checker for mulit-threaded programs, requires a thread id in the state whilst traversing the program model
#
# The program is walked through the thread model instead of the program model.
# A state of the walk is (active thread, thread state):
#   thread state  - state in the thread model, its label is the list of program
#                   model states (one per thread) at that point
#   active thread - index into that label of the thread that is executing
# The program model state that is checked against the property is
#   threadModel.states[thread state].label[active thread]
# Each thread has its own call stack, so call_stack is a list of call stacks.
#--------------------------------------

import hy2.core.check_helpers as chh
import hy2.core.cfg_traversal as trav
import hy2.core.z3_interface as z3_interface
import copy
import os
import json
from math import factorial
from colorama import Fore
import hy2.core.utils as utils

from threading import Thread, Event, Lock
from queue import Queue, Empty
import traceback

class Check:
    def __init__(self, property_name, property_severity):
        self.property_name = property_name
        self.property_severity = property_severity

        self.model = None
        self.threadModel = None
        self.labels = {}
        self.rule = None
        self.aliases = {}
        self.same_state = {}

        self.squeue = None
        self.export_lock = Lock()
        self.visited = {}
        self.vars = {}
        self.current_call_trace = {}
        self.current_match_states = {}
        self.last_match = {}
        self.candidatePool = []
        self.match_count = 0
        self.recursion_depth = 0

    def get_next_model_state(self, model, a0):
        return [t.dest for t in model.get_transitions(source=a0)]

    def get_previous_model_state(self, model, a0):
        tn = model.get_transitions(dest=a0)
        return [t.source for t in tn]

    # program model state of the active thread in thread state st0
    def get_label(self, active_s0, st0):
        return self.threadModel.states[st0].label[active_s0]

    def export(self, target_out, match, transaction_id=""):
        model = self.model
        labels = self.labels
        spec = self.rule
        data = {}
        res_ids = []
        target_out = os.path.join(target_out, 'results')
        if not os.path.exists(target_out):
            os.mkdir(target_out)

        else:
            res_files = os.listdir(target_out)
            res_ids = [r.replace(".json", "") for r in res_files]

        sanit_match_states = [s[0] for s in match.match_states]
        tid = match.get_id(self.property_name, sanit_match_states)

        # TODO
        if os.path.exists(os.path.join(target_out, f'{tid}.json')):
            pass

        attr_map = match.map_model_states_to_attr(spec.match_attributes_to_states())
        mvars = [(match.vars[i], match.match_states[i][0]) for i in range(len(match.vars))]
        export_spec = spec.export_all_specs()

        var_map = {}

        # Do this step in z3_interface to capture use and def
        for k,v in attr_map.items():
            sid = v[0]
            pid = v[1]
            vid = v[2]
            if not sid in var_map:
                var_map[sid] = []
            var_map[sid] += [(k, pid, vid)]

        html_str = []
        i = 0
        pctr = 0
        match_funcs = []
        for c in match.call_trace:
            html_str += [{"event": "trace", "str": labels[c].export_html_summary()}]
            match_funcs += [labels[c].fname]
            if f'S{pctr}' in match.trace_back and match.trace_back[f'S{pctr}'] == i:
                check_dupl = []
                print_spec_state = True
                if c in var_map:
                    for cv in var_map[c]:
                        if print_spec_state:
                            pid = cv[1]
                            html_str += [{"event": "spec", "str": spec.nodes[pid].export()}]
                            print_spec_state = False

                        if not cv[2] in check_dupl:
                            if type(cv[2]) == list:
                                check_dupl += [cv[2]]
                                continue
                            var = labels[c].lookup_name(cv[2], True)
                            if var != None:
                                html_str += [{"event": "var", "str": f'{cv[0]}: {var.export_html()}'}]
                            check_dupl += [cv[2]]
                pctr += 1
            i += 1

        # TODO: FIXME!
        after_init = self.get_next_model_state(model, model.initial)
        entry_point = 0
        if len(after_init) > 0 and after_init[0] in labels:
            entry_point = labels[after_init[0]].pc

        try:
            explain_res, explain_stmt = z3_interface.do_explain(labels, match.var_table, attr_map, match.call_trace, spec.vuln)
        except Exception as e:
            print(e)
            explain_res = ""
            explain_stmt = ""
        data = {}
        var_table_str = {k: str(v) for k, v in match.var_table.items()}
        data[tid] = {'name': self.property_name, 'severity': self.property_severity, 'str': html_str, "match": {"states": sanit_match_states, "vars": match.vars, "variables": var_table_str}, 'spec': export_spec, "calltrace": match.call_trace, 'base_pc': entry_point, "explanation": explain_stmt, 'conclusion': explain_res, 'match_funcs': match_funcs}


        with open(os.path.join(target_out, f'{tid}.json'), 'w') as f:
            res = {tid: data[tid]}
            json.dump(res, f)

    # get a list of states that match the initial state of the property,
    # one candidate for every thread state the matching program state appears in
    # (the thread it belongs to is the active thread)
    def match_initial_states(self):
        print(Fore.GREEN+f' Checking {self.rule.name}'+Fore.RESET)
        s0 = self.rule.machine.initial
        states = list(self.model.states.keys())
        print(f'[*DEBUG*]: No. of States: {len(states)}')

        if self.rule.nodes[s0].action in self.aliases:
            action = self.aliases[self.rule.nodes[s0].action]
        else:
            action = self.rule.nodes[s0].action

        initial_candidatePool = []
        no_matches = 0

        trs = self.rule.machine.get_triggers(self.rule.machine.initial)
        assert len(trs) == 1
        self.rule.machine.trigger(trs[0])
        t1 = self.rule.machine.state

        for a0 in states:
            if a0 in self.labels:
                m = self.labels[a0].check_against_state(a0, action, self.rule.nodes[s0].vars, self.rule.nodes[s0].conditions, {})
                no_matches += len(m)

                if len(m) > 0:
                    thread_states, idxs = trav.queryStateInThreadModel(self.threadModel, a0)
                    for i in range(len(thread_states)):
                        idx = idxs[i]
                        st0 = thread_states[i]
                        call_stack = [[] for _ in self.threadModel.states[st0].label]
                        for mi in m:
                            sid, vid, var_table, iidx = mi
                            var_table = copy.copy(var_table)
                            if not "discrete_time" in var_table and t1 in self.rule.nodes and self.rule.nodes[t1].has_condition("discrete_time"):
                                var_table["discrete_time"] = 0
                            candid = chh.ConcurCandidate(idx, st0, 'z0', t1, [], call_stack, var_table)

                            candid.vars += [(iidx, vid)]
                            candid.last_match = vid
                            candid.call_trace += [sid]
                            candid.match_states += [(sid, 0)]
                            if not candid in initial_candidatePool:
                                initial_candidatePool += [candid]
        return initial_candidatePool, no_matches

    # s0 - current model state - by index in current thread state (active thread)
    # st0 - current thread state
    # z0 - previous thread state
    # t0 - current property state
    # call_stack
    # var_table
    # call_trace
    def check_state(self, thread_id, s0, st0, z0, t0, call_stack, var_table, call_trace):
        matches = []
        si0 = self.get_label(s0, st0)

        if self.rule.nodes[t0].action == "FINAL":
            trs = self.threadModel.get_triggers(st0)
            if len(trs) == 0:
                t1 = self.get_next_model_state(self.rule.machine, t0)[0]
                candidate = chh.ConcurCandidate(s0, st0, z0, t1, self.visited[thread_id], call_stack, var_table)
                candidate.vars = self.vars[thread_id]
                candidate.call_trace = self.current_call_trace[thread_id] + call_trace + [si0]
                candidate.match_states = self.current_match_states[thread_id] + [(si0, len(candidate.call_trace)-1)]

                # REFACTOR:
                cid = hash(candidate)
                if not cid in self.candidatePool:
                    self.candidatePool += [cid]
                    self.squeue.put(candidate)

                return True
            return False

        elif not si0 in self.labels:
            print(Fore.RED + 'ERROR!' + Fore.RESET)
            return True

        action = self.rule.nodes[t0].action
        if action in self.aliases:
            action = self.aliases[action]

        m = self.labels[si0].check_against_state(si0, action, self.rule.nodes[t0].vars, self.rule.nodes[t0].conditions, var_table)
        if self.same_state[thread_id]:
            for m0 in m:
                if m0[1][0][0] in ["c", "i"] and self.last_match[thread_id][0][0] == m0[1][0]:
                    print(f'DEBUG: Skipping {m0[1]} {self.last_match[thread_id]}')
                    continue
                elif m0[1][0] == self.last_match[thread_id][0]:
                    print(f'DEBUG: Skipping {m0[1]} {self.last_match[thread_id]}')
                    continue
                elif not m0[1][0][0] in ["c", "i"] and m0[1][1] < self.last_match[thread_id][1]:
                    print(f'DEBUG: Skipping {m0[1]} {self.last_match[thread_id]}')
                    continue
                else:
                    matches += [m0]
        else:
            matches += m

        if len(matches) > 0:
            t1 = self.get_next_model_state(self.rule.machine, t0)[0]
            for m in matches:
                midx = m[3]
                var_match = m[1]
                new_var_table = {**var_table, **m[2]}

                candidate = chh.ConcurCandidate(s0, st0, z0, t1, copy.copy(self.visited[thread_id]),  copy.copy(call_stack), new_var_table)
                candidate.last_match = var_match
                candidate.vars = self.vars[thread_id] + [(midx, var_match)]
                candidate.call_trace = self.current_call_trace[thread_id] + call_trace + [si0]
                candidate.match_states = self.current_match_states[thread_id] + [(si0, len(candidate.call_trace)-1)]

                cid = hash(candidate)
                if not cid in self.candidatePool:
                    self.candidatePool += [cid]
                    self.squeue.put(candidate)

            if self.rule.nodes[t0].has_condition("first_only"):
                return True

        return False

    # z0 - prev thread state
    # active_s0 - active thread
    # thread_s0 - current thread state
    # t0 - property state
    # call_stack - one call stack per thread
    def check_visited(self, thread_id, z0, active_s0, thread_s0, t0, call_stack, update=True):
        c0 = call_stack[:1] + [call_stack[i] for i in range(1,len(call_stack)) if call_stack[i] != call_stack[i-1]]
        current_walk_state = utils.md5(f'{z0}-{active_s0}-{thread_s0}-{t0}-{c0}'.encode())

        if current_walk_state in self.visited[thread_id]:
            return True

        if not self.same_state[thread_id] and update:
            self.visited[thread_id].append(current_walk_state)

        return False


    # IN:
    # thread_id - thread_id for running checker
    # active_s0 - active thread
    # thread_s0 - thread state
    # z0 - prev thread state
    # t0 - current property state
    # var_table
    # call_stack
    def walkModel(self, thread_id, active_s0, thread_s0, z0, t0, var_table, call_stack):
        workQueue = [(active_s0, thread_s0, z0, call_stack, [])]

        while True:
            if workQueue == []:
                break
            active_s0, thread_s0, z0, call_stack, call_trace = workQueue.pop(0)
            if self.check_visited(thread_id, z0, active_s0, thread_s0, t0, call_stack):
                if len(self.visited[thread_id]) > self.traversal_limit:
                    raise trav.TraversalDepthException(len(self.visited[thread_id]))
                continue

            if (self.rule.nodes[t0].has_condition("discrete_time") and self.rule.nodes[t0].get_rhs_cond("discrete_time") < len(call_trace)) or (self.rule.nodes[t0].has_condition("first_only") and len(call_trace) > 2):
                continue

            check = self.check_state(thread_id, active_s0, thread_s0, z0, t0, call_stack, var_table, call_trace)
            if check:
                continue
            else:
                self.same_state[thread_id] = False
                next_states, next_active_threads, co0 = trav.get_successor_states_concur(self.threadModel, self.labels, active_s0, thread_s0, call_stack)
                si0 = self.get_label(active_s0, thread_s0)
                for i in range(len(next_states)):
                    s1 = next_states[i]
                    a1 = next_active_threads[i]
                    c0 = trav.update_callstack_concur(copy.copy(call_stack), co0[i])
                    if self.check_visited(thread_id, thread_s0, a1, s1, t0, c0, update=False):
                        continue
                    workQueue += [(a1, s1, thread_s0, c0, call_trace+[si0])]

    # THIS IS BROKEN:
    # ------------------------------
    def do_trace_back_from_match(self, labels, model, a0, m0, visited, callstack=[]):
        paths = []
        s2 = self.get_previous_model_state(model, a0)
        if len(s2) == 0 or a0 == m0:
            return [[a0]]
        for a2 in s2:
            c0 = copy.copy(callstack)
            if not a2 == a0 and not a2 in visited:
                if a2 in labels and labels[a2].transition.transition_type == 'Ijk_Call':
                    if len(callstack) == 0:
                        pass
                    else:
                        peek = c0[0]
                        if labels[a2].return_addr == peek:
                            c0 = c0[1:]
                        else:
                            continue
                elif a2 in labels and labels[a2].transition.transition_type == "Ijk_Ret":
                    if labels[a0].pc in labels[a2].transition.dest_pc:
                        c0 = [labels[a0].pc] + c0
                    else:
                        continue
                elif a2 in labels and labels[a2].transition.transition_type == "Ijk_Boring" and len(labels[a2].invocations) > 0:
                    if len(labels[a2].transition.dest_pc) > 0:
                        pass
                    elif labels[a0].pc in labels[a2].transition.dest_pc:
                        c0 = [labels[a0].pc] + c0
                    else:
                        continue
                visited.append(a2)
                new_paths = self.do_trace_back_from_match(labels, model, a2, m0, visited, c0)
                new_paths = [[a0]+p0 for p0 in new_paths]
                paths += new_paths
        if len(paths) == 0:
            paths = [[a0]]
        return paths

    # Function: trace_back_from_match
    # beginning at state a0, walk backwards through model to initial state
    def trace_back_from_match(self, labels, model, a0, c0):
        paths = []
        s0  = model.initial
        if type(a0) == tuple:
            a0 = a0[0]
        s1 = self.get_previous_model_state(model, a0)

        for a1 in s1:
            if a1 == s0 or a1 == a0:
                continue
            elif a1 in labels and labels[a1].transition.transition_type == "Ijk_Call":

                if labels[a1].return_addr == labels[c0].pc:
                    new_paths = self.do_trace_back_from_match(labels, model, a1, s0, [a1, a0], [])
                    new_paths = [p0[::-1] for p0 in new_paths]
                    paths += new_paths
                else:
                    continue
            else:
                new_paths = self.do_trace_back_from_match(labels, model, a1, s0, [a1, a0], [])
                new_paths = [p0[::-1] for p0 in new_paths]
                paths += new_paths

        return paths

    # Get all the states between the matched states in the specification:
    # Check conditions for anti against them
    def check_anti_pattern(self, match, not_logic):
        if len(self.rule.anti) == 1:
            not_trace = self.rule.anti
        elif not_logic[1] == not_logic[3]:
            not_trace = [self.rule.anti[not_logic[1]]]
        else:
            not_trace = self.rule.anti[not_logic[1]:not_logic[3]+1]
        start_idx = not_logic[0]
        end_idx = not_logic[2]
        t0 = not_trace[0]
        vars = match.var_table
        k = 0
        j = 0
        si, ei, call_trace = match.get_between(start_idx, end_idx)
        antiVars = {}

        for z in call_trace:
            if type(z) == tuple:
                v = self.labels[z[1]]
            else:
                v = self.labels[z]
            name = v.fname
            j += 1
            matches = []
            if self.rule.nodes[t0].action in self.aliases:
                m = v.check_against_state(t0, self.aliases[self.rule.nodes[t0].action], self.rule.nodes[t0].vars, self.rule.nodes[t0].conditions, vars)
                matches += m
            else:
                m = v.check_against_state(t0, self.rule.nodes[t0].action, self.rule.nodes[t0].vars, self.rule.nodes[t0].conditions, vars)
                matches += m

            if len(matches) != 0:
                k += 1
                if self.rule.nodes[t0].label != "":
                    antiVars[self.rule.nodes[t0].label] = True
                else:
                    antiVars[t0] = True

                if len(not_trace) == k:
                    return True, antiVars

                vmerged = {}
                vkeys = matches[0][2].keys()
                for vk in vkeys:
                    vmerged[vk] = [matches[i][2][vk] for i in range(len(matches))]

                vars = {**vars, **vmerged}

                t0 = not_trace[k]
                if self.rule.nodes[t0].has_condition("discrete_time"):
                    vars["discrete_time"] = 0

            if self.rule.nodes[t0].has_condition("discrete_time"):
                vars["discrete_time"] += 1

        if self.rule.nodes[t0].label != "":
            antiVars[self.rule.nodes[t0].label] = False
        else:
            antiVars[t0] = False
        return False, antiVars

    def processExample(self, target_dir, not_logic, candidate, transaction_id):
        matchObj = chh.Match()
        matchObj.var_table = candidate.var_table
        sanit_call_trace = []
        for s in candidate.call_trace:
            if type(s) == tuple:
                sanit_call_trace.append(s[1])
            else:
                sanit_call_trace.append(s)
        matchObj.call_trace = sanit_call_trace
        matchObj.match_states = candidate.match_states
        matchObj.vars = candidate.vars
        matchObj.toTraceback()
        checkedNot = False

        if len(self.rule.anti) > 0:
            antiVars = {}
            for a in not_logic:
                _,atmp = self.check_anti_pattern(matchObj, a)
                antiVars = {**antiVars, **atmp}
            b = self.rule.solveAntiExpression(antiVars)
            checkedNot = b

        if not checkedNot:
            paths = self.trace_back_from_match(self.labels, self.model, matchObj.match_states[0], matchObj.call_trace[0])
            matchObj.path += paths

            assert len(matchObj.call_trace) > 0
            self.match_count += 1
            self.export_lock.acquire()
            try:
                self.export(target_dir, matchObj, transaction_id)
            except Exception as e:
                print(e)
                traceback.print_exc()
            self.export_lock.release()
        else:
            print(Fore.YELLOW + '[DEBUG] NOT pattern matches trace!' + Fore.RESET)

    def mainloop(self, target_dir, not_logic, transaction_id, candidatePool):
        self.squeue = Queue()
        noCan = 0
        for c in candidatePool:
            self.squeue.put(c)
            noCan += 1
        lock = Lock()

        def threadLoop(threadID):
            no_tries = 0
            iteration_count = 0
            while True:
                if not self.squeue.empty():
                    candidate = None
                    try:
                        lock.acquire()
                        candidate = self.squeue.get(block=True, timeout=1)
                        lock.release()
                    except Empty:
                        lock.release()
                        continue

                    t0 = candidate.current_property_state

                    if (len(self.rule.machine.get_triggers(t0)) == 0):
                        print(Fore.RED + "[INFO] Match Found!" + Fore.RESET)
                        self.processExample(target_dir, not_logic, candidate, transaction_id)
                    else:
                        var_table = candidate.var_table
                        if not "discrete_time" in var_table and t0 in self.rule.nodes and self.rule.nodes[t0].has_condition("discrete_time"):
                            var_table["discrete_time"] = 0


                        active_s0 = candidate.current_model_state
                        thread_s0 = candidate.current_thread_state
                        z0 = candidate.previous_model_state
                        self.visited[threadID] = candidate.visited

                        self.last_match[threadID] = candidate.last_match
                        self.same_state[threadID] = True
                        self.vars[threadID] = candidate.vars
                        self.current_call_trace[threadID] = candidate.call_trace
                        self.current_match_states[threadID] = candidate.match_states

                        try:
                            self.walkModel(threadID, active_s0, thread_s0, z0, t0, var_table, candidate.call_stack)
                        except RecursionError:
                            print(self.recursion_depth)
                            self.recursion_depth = 0
                        except trav.TraversalDepthException as e:
                            print(e)
                        except AssertionError as e:
                            print(e)
                    print(f'{iteration_count}/{noCan} candidates checked....')

                    iteration_count += 1
                    if iteration_count > self.infinite_loop_check:
                        print(Fore.RED + "[CRITICAL ERROR]: Number of iterations exceeded expected limit! Exiting Immediately" + Fore.RESET)
                        return

                    self.squeue.task_done()
                elif no_tries < 5:
                    no_tries += 1
                else:
                    break

        threadPool = []
        n = 1
        for i in range(n):
            t = Thread(target=threadLoop, args=(i,))
            threadPool.append(t)

        for i in range(n):
            threadPool[i].start()

        for i in range(n):
            threadPool[i].join()

        print('Exiting mainloop....')

    def doCheck(self, target_dir, transaction_id=""):
        # the walk is over the thread model, so limits are based on its size
        no_states = len(list(self.threadModel.states.keys()))
        self.traversal_limit = 2*no_states
        if self.traversal_limit < 2000:
            self.traversal_limit = 2000

        candidatePool, no_matches = self.match_initial_states()
        if len(candidatePool) == 0:
            print(Fore.YELLOW + "[INFO] 0 initial state matches found. Nothing to do." + Fore.RESET)
            return
        print(Fore.LIGHTBLUE_EX + f'[INFO] Found {no_matches} initial state matches.' + Fore.RESET)
        print(Fore.RED + f'[INFO] Initial Size of Candidate Pool: {len(candidatePool)}' + Fore.RESET)

        not_logic = self.rule.get_anti_slices()

        self.infinite_loop_check = factorial(no_matches * len(self.rule.not_anti))
        if self.infinite_loop_check < len(candidatePool)*no_states:
            self.infinite_loop_check = len(candidatePool)*no_states

        self.mainloop(target_dir, not_logic, transaction_id, candidatePool)

        print(f'{self.match_count} Matches Found!')


def do_check(GLOB_CONF, target, property_models, aliases, thread_model, model, labels):
    for p in property_models:
        check = Check(p.name, p.severity)
        check.aliases = aliases
        check.rule = p
        check.model= model
        check.labels = labels
        check.threadModel = thread_model

        check.doCheck(os.path.join(GLOB_CONF.target_path, target))

