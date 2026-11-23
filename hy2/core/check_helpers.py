#--------------------------------------
# File: check_helpers.py
#
# Purpose: Helper functions for checker
#--------------------------------------

import hy2.core.utils as utils
from transitions import Machine, State

translate_ops = {
    "eq": "==",
    "lt": "<",
    "gt": ">",
    "in": "in",
    "lte": "<=",
    "gte": ">=",
    "nin": "not in",
    "like": "like"
}

def doSolveBoolExpr(expression, vars):
    ls = None
    rs = None
    if "ls" in expression and type(expression["ls"]) == dict:
        ls = doSolveBoolExpr(expression["ls"], vars)
    elif "ls" in expression and expression["ls"] in vars:
        ls = vars[expression["ls"]]
    
    if "rs" in expression and type(expression["rs"]) == dict:
        rs = doSolveBoolExpr(expression["rs"], vars)
    elif "rs" in expression and expression["rs"] in vars:
        rs = vars[expression["rs"]]
    
    if ls == None or rs == None:
        raise Exception("ERROR: Can't solve bool expression")
    
    
    if expression["op"] == "or":
        return ls or rs
    
    return ls and rs

def conditionToStr(condition, delim=' '):
    out_str = ""
    for c in condition:
        if 'and' in c:
            if out_str != "":
                out_str += delim + ' ' + conditionToStr(c['and'], delim='and')
            else:
                out_str += ' ' + conditionToStr(c['and'], delim='and')
        elif 'or' in c:
            if out_str != '':
                out_str += delim + ' ' + conditionToStr(c['or'], delim='or')
            else:
                out_str += ' ' + conditionToStr(c['or'], delim='or')
        else:
            if out_str != '':
                out_str += f'{delim} ({c["ls"]} {translate_ops[c["op"]]} {c["rs"]}) '
            else:
                out_str += f' ({c["ls"]} {translate_ops[c["op"]]} {c["rs"]}) '
    return out_str


class Node:
    def __init__(self, action):
        self.action = action
        #self.param_idx = -1
        self.vars = {}
        self.conditions = []
        self.exists = True
        self.start = -1
        self.end = -1
        self.is_mandatory = True
        self.direction = "then"
        self.label = ""
        self.optional = []
    
    def __repr__(self) -> str:
        return f'{self.action}: {self.start} -> {self.end}'
    
    def debug_str(self):
        return f'{self.action}, {self.start}, {self.end}'

    def has_condition(self, cond_ls):
        return any(["ls" in x and x["ls"] == cond_ls for x in self.conditions])
    
    def get_rhs_cond(self, cond_ls):
        rs = [x["rs"] for x in self.conditions if "ls" in x and x["ls"] == cond_ls and "rs" in x]
        if len(rs) > 0:
            return rs[0]
        return None

    def export(self):
        out_str = ""
        out_str += utils.bold_text(utils.color_text('deep_purple', self.action))
        attrs = ', '.join([f'{k} = {v}' for k, v in self.vars.items()])
        if attrs != "":
            out_str += '\n'
            out_str += 'with ' + attrs
        out_str += '\n'
        if self.conditions != []:
            out_str += 'where '
            out_str += conditionToStr(self.conditions)
        return out_str

class ModelMachine:
    def __init__(self):
        self.name = ""
        self.severity = ""
        self.machine = None
        self.anti = []
        self.not_anti = []
        self.nodes = {}
        self.sid = 0
        self.aid = 0
        self.q0 = ""
        self.collection = []
        self.vuln = []
        self.vtypes = {}

        self.antiExpr = {}
    
    def __repr__(self):
        out_str = f'NODES: {self.nodes}\nNOT ANTI: {self.not_anti}\nANTI: {self.anti}\nSTATES: {self.machine.states}'
        return out_str
    
    def match_attributes_to_states(self):
        attr_map = {}
        for sid, node in self.nodes.items():
            for v in node.vars.values():
                attr_map[v] = sid
        return attr_map

    def get_anti_slices(self):
        slices = []
        start = -1
        start_idx = -1
        for i in range(len(self.anti)):
            y = self.anti[i]
            x = self.nodes[y]
            if not x.start == -1:
                start = x.start
                start_idx = i            
            if not x.end == -1:
                end = x.end
                end_idx = i
                slices.append((start, start_idx, end, end_idx))
                start = -1
                start_idx = -1
                
        if start_idx != -1:
            end = -1
            end_idx = -1
            slices.append((start, start_idx, end, end_idx))
        return slices

    def solveAntiExpression(self, anti_terms):
        if self.antiExpr == {}:
            return all([b for b in anti_terms.values()])
        res = doSolveBoolExpr(self.antiExpr, anti_terms)
        return res

    def add_state(self, node):
        if self.q0 == "":
            raise Exception("ERROR: q0 should not be NULL")
        
        q1 = f'S{self.sid}'
        self.machine.add_state(q1)
        self.machine.add_transition(f'{node.action} -> {",".join(node.vars.keys())}', self.q0, q1)
        self.nodes[self.q0] = node
        self.not_anti.append(self.q0)
        self.sid +=1
        self.q0 = q1


    # TODO: Fix me
    def get_ith_state(self, i):
        if type(i) == int:
            sid = self.not_anti[i]
        else:
            sid = i
        n = self.nodes[sid]
        node_str = f'{n.action}('+','.join(n.vars.keys())+')' 
        if len(n.conditions) > 0:
            node_str += conditionToStr(n.conditions)
        return node_str
    
    def export_all_specs(self):
        specs = []
        for k in self.not_anti:
            specs.append(self.get_ith_state(k))
        return specs

def load_property_model(data, name, severity, aliases, sem_info):
    print(f'[INFO] Loading model {name}')
    machine = Machine()
    model_machine = ModelMachine()

    model_machine.name = name
    model_machine.severity = severity
    if "vtypes" in data:
        model_machine.vtypes = data['vtypes']
    if "anti_expr" in data:
        model_machine.antiExpr = data["anti_expr"]
    
    # Setup Model:
    q0 = "S"+str(model_machine.sid)
    model_machine.sid +=1
    model_machine.machine = Machine(states=[q0], initial=q0, auto_transitions=False)
    model_machine.q0 = q0

    started_anti = ''
    current_anti_group = ''

    var_list = []
    n = len(data["model"])
    for i in range(n):
        s = data["model"][i]
        node= Node(s["action"])
        if "label" in s:
            node.label = s["label"]
        
        # PARSE ATTRIBUTES:
        if "as" in s or "attributes" in s:
            kw = "as"
            if "attributes" in s:
                kw = "attributes"
            for k, v in s[kw].items():
                node.vars[k] = v

        if "cond" in s:
            cond = s["cond"]
            for j in range(len(cond)):
                c = cond[j]
                if 'rs' in c and type(c['rs']) == str:
                    if c['rs'] in sem_info:
                        sdef = sem_info[c['rs']]
                        sdef_attrs = sdef['attributes']
                        sdef_conds = sdef['conditions']
                        for sk, sv in sdef_attrs.items():
                            node.vars[sk] = sv
                        node.conditions += sdef_conds
                        continue
                    elif "$" in c['rs']:
                        sub_idx = c['rs'].index('$')
                        
                        if c['rs'][sub_idx+1:] in aliases:
                            sub = aliases[c['rs'][sub_idx+1:]]
                            b = c['rs'][:sub_idx]
                            if len(b) > 0:
                                sub = [f'{b}{s}' for s in sub]
                            cond[j]['rs'] = sub
                node.conditions += [cond[j]]

        if "vuln" in s:
            model_machine.vuln.append(s["vuln"])
        
        if "type" in data["model"][i] and data["model"][i]["type"] == "anti":
            aid = "A"+str(model_machine.aid)
            model_machine.anti.append(aid)
            model_machine.nodes[aid] = node
            model_machine.aid += 1
            if 'group' in data['model'][i] and current_anti_group != data['model'][i]['group'] and current_anti_group != '':
                model_machine.nodes[started_anti].end = model_machine.not_anti[-1]
                started_anti = ''
            
            if started_anti == '':
                model_machine.nodes[aid].start = model_machine.not_anti[-1]
                if 'group' in data['model'][i]:
                    current_anti_group = data['model'][i]['group']
            started_anti = aid
        else:
            model_machine.add_state(node)
            if started_anti != '':
                model_machine.nodes[started_anti].end = model_machine.not_anti[-1]
                started_anti = ''
    
    return model_machine


class Match:
    def __init__(self, backtrace=[]):
        self.backtrace = backtrace # contains name or state no (?)
        #self.var0 = var_id
        # temp variable used to match specifications
        self.var_table = {}
        # states that match specification states
        self.match_states = []
        # indices of match states in call trace
        self.trace_back = {}
        # all states between first and last match state
        self.call_trace = []
        # variable lid of matches
        self.vars = []
        self.export_str = ""

        # conditions on the path
        self.conditions = []
        self.cond_objs = []
        self.call_stack = []

        # path
        self.path = []

    def add_match_state(self, s, v, t):
        self.call_trace = [s] + self.call_trace
        self.match_states = [s] + self.match_states
        self.trace_back[t] = len(self.call_trace) -1
        self.vars = [v] + self.vars

    def add_call_state(self, s):
        self.call_trace = [s] + self.call_trace
        
    def add_state(self, s):
        self.backtrace = [s] + self.backtrace


    def set_match_states(self, matches):
        i = 0
        for x in matches:
            sid, vid, lab_id, idx = x
            self.trace_back[i] = idx
            self.vars.append((lab_id, vid))
            self.match_states.append(sid)
            i+=1
    
    def toTraceback(self):
        for i,m in enumerate(self.match_states):
            self.trace_back[f'S{i}'] = m[1]
    
    def get_between(self, start, end):
        s0 = self.trace_back[start]
        if end == -1:
            return s0, len(self.call_trace)-1, self.call_trace[s0:]
        else:
            s1 = self.trace_back[end]
            return s0, s1, self.call_trace[s0:s1]


    def map_model_states_to_attr(self, prop_attr_map):
        state_map = {}
        var_map = {}
        i = 0
        for k, v in self.trace_back.items():
            state_map[k] = self.call_trace[v]
            var = self.vars[i][1][0]
            var_map[k] = var
            i += 1
        attr_map = {}
        for attr, sid in prop_attr_map.items():
            if sid in state_map:
                attr_map[attr] = (state_map[sid], sid, var_map[sid])
                if f'{attr}.VAR' in self.var_table:
                    attr_map[f'{attr}.VAR'] = (state_map[sid], sid, self.var_table[f'{attr}.VAR'])
        return attr_map

    def __hash__(self) -> int:
        return hash(str(self.print_obj()))
    
    def __eq__(self, other: object) -> bool:
        return str(self) == str(other)
    
    def __str__(self) -> str:
        return str(self.print_obj())
    
    def print_obj(self) -> str:
        out_str = ""
        out_str = "Backtrace:\n"+str(self.backtrace)
        out_str += "\nMatch States:\n"+str(self.match_states)
        out_str += "\nTrace Back:\n"+str(self.trace_back)
        out_str += "\nCall Trace:"+str(self.call_trace)
        out_str += "\nStates: "+str(self.backtrace)
        out_str += "\nVar Table: "+str(self.var_table)
        out_str += str(self.vars)
        return out_str
    
    def export(self):
        return self.backtrace
    
    # name - property name
    # vars - labels of variables that match events in the counter-example
    #  back-trace
    #  ctrace - all states between first match state and last match state
    def get_id(self, name, ctrace):
        return utils.md5(f'{name}-{ctrace}-{self.vars}'.encode())

# Candidate for multi-threaded programs:
#  cms  - active thread (index into the thread state's label)
#  ctms - current thread state (state in the thread model)
#  pms  - previous thread state
#  cs   - one call stack per thread
class ConcurCandidate:
    def __init__(self, cms, ctms, pms, cps, v, cs, vt):
        self.current_model_state = cms
        self.current_thread_state = ctms
        self.previous_model_state = pms
        self.current_property_state = cps
        self.var_table = vt
        self.visited = v
        self.call_stack = cs
        self.call_trace = []
        self.match_states = []
        self.vars = []
        self.last_match = ''

    def __hash__(self):
        return hash(str(self.vars)+str(self.match_states))

    def __eq__(self, c1: object) -> bool:
        if 'discrete_time' in c1.var_table:
            c1.var_table['discrete_time'] = 0
        if 'discrete_time' in self.var_table:
            self.var_table['discrete_time'] = 0

        return self.current_model_state == c1.current_model_state and self.current_thread_state == c1.current_thread_state and self.previous_model_state == c1.previous_model_state and self.current_property_state == c1.current_property_state and self.vars == c1.vars and self.var_table == c1.var_table and self.call_trace == c1.call_trace and self.match_states == c1.match_states

class Candidate:
    def __init__(self, cms, pms, cps, v, cs, vt):
        self.current_model_state = cms
        self.previous_model_state = pms
        self.current_property_state = cps
        self.var_table = vt
        self.visited = v
        self.call_stack = cs
        self.call_trace = []
        self.match_states = []
        self.vars = []
        self.last_match = ''
        
    def __hash__(self):
        return hash(str(self.vars)+str(self.match_states))

    def getFirstLastMatchStates(self):
        s0 = self.match_states[0][0]
        s1 = self.match_states[-1][0]
        return s0, s1

    def __repr__(self):
        out_str = "MATCH:\n"
        out_str += " -> ".join([str(m) for m in self.match_states])
        out_str += "\n"
        out_str += "VAR TABLE:\n"
        for k, v in self.var_table.items():
            out_str += f'{k}:  {v}\n'
        out_str += '\n'
        out_str += ' '.join([str(v) for v in self.vars])
        out_str += '\n'
        return out_str
    
    def __eq__(self, c1: object) -> bool:
        if 'discrete_time' in c1.var_table:
            c1.var_table['discrete_time'] = 0
        if 'discrete_time' in self.var_table:
            self.var_table['discrete_time'] = 0
        
        return self.current_model_state == c1.current_model_state and self.previous_model_state == c1.previous_model_state and self.current_property_state == c1.current_property_state and self.vars == c1.vars and self.var_table == c1.var_table and self.call_trace == c1.call_trace and self.match_states == c1.match_states
