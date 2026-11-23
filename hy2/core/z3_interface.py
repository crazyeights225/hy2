import z3
from colorama import Fore

import hy2.core.var_types as vart
import hy2.core.model as mod
import hy2.core.utils as utils

def gt(ls, rs):
    return ls > rs

def lt(ls, rs):
    return ls < rs

def gte(ls, rs):
    return ls >= rs

def lte(ls, rs):
    return ls <= rs

def neq(ls, rs):
    return ls != rs

def eq(ls, rs):
    return ls == rs

def add(ls, rs):
    return ls + rs

def subtract(ls, rs):
    return ls - rs

def mul(ls, rs):
    return ls * rs

def cmps(ls, rs):
    return ((ls > 0) == bool(rs))

def cmp_odd(ls, rs):
    return ((ls%2 == 1) == bool(rs))

def cmp_even(ls, rs):
    return ((ls%2 == 0) == bool(rs))


ops = {
    "eq": eq,
    "gt": gt,
    "lt": lt,
    "gte": gte,
    "lte": lte,
    "neq": neq,
    "add": add,
    "sub": subtract,
    "Add": add,
    "Sub": subtract,
    "Mul": mul,
    "CmpEQ": eq,
    "CmpLE": lte,
    "CmpLT": lt,
    "CmpGT": gt,
    "CmpGE": gte,
    "CmpNE": neq,
    "CMPS": cmps,
    "CmpZ_CPU": eq,
    "+": add,
    "CMPODD": cmp_odd,
    "CMPEVEN": cmp_even,
    "CasCmpEQ": eq
}

def opConvert(op, ls):
    if op == 'Shl':
        return f'{ls} * 2**'
    elif op == 'Shr':
        return f'{ls} >>'
    elif op == 'Add':
        return f'{ls} + '
    elif op == 'Sub':
        return f'{ls} - '
    else:
        print(op)
        #raise Exception('TO DO: Finish Me!')
        print("TO DO: Finish Me!")
        return op

def swapOps(op):
    if op == "CmpEQ":
        return "neq"
    if op == "CmpLT":
        return "CmpGE"
    if op == "CmpGT":
        return "CmpLE"
    if op == "CmpLE":
        return "CmpGT"
    if op == "CmpGE":
        return "CmpLT"
    if op == "CMPODD":
        return "CMPEVEN"
    raise Exception(f"ERROR: Unknown op: {op}")

class ExplainError:
    def __init__(self, msg):
        self.msg = msg
    
    def __repr__(self):
        return self.msg

class BTree:
    def __init__(self, bid):
        self.op = None
        self.ls = None
        self.rs = None
        self.name = None
        self.bid = bid
    
    # Args:
    # varSymbol - symbol to replace in the expression with varInst
    # varInst - z3 instance
    def mapToPredicate(self, varSymbol, varInst):
        if not self.op in ops:
            return ExplainError(f"ERROR!: {self.op} not in ops")
        
        sub_ls = None
        sub_rs = None
        if type(self.ls) == str:
            if self.ls == varSymbol:
                sub_ls = varInst
            else:
                sub_ls = z3.Int(f'{self.bid}-{self.ls}')
        elif type(self.ls) == int:
            sub_ls = self.ls
        else:
            sub_ls = self.ls.mapToPredicate(varSymbol, varInst)
            if sub_ls == None:
                return ExplainError(f'ERROR: sub_ls is None')
            if type(sub_ls) == ExplainError:
                return sub_ls
        
        if self.rs == None:
            return ops[self.op](sub_ls)
        else:
            if type(self.rs) == str:
                if self.rs == varSymbol:
                    sub_rs = varInst
                else:
                    sub_rs = z3.Int(f'{self.bid}-{self.rs}')
            elif type(self.rs) == int:
                sub_rs = self.rs
            else:
                sub_rs = self.rs.mapToPredicate(varSymbol, varInst)
                if type(sub_rs) == ExplainError:
                    return sub_rs
        
        if type(sub_ls) == ExplainError:
            return sub_ls
        if type(sub_rs) == ExplainError:
            return sub_rs


        if self.name != None and self.name == varSymbol:
            return ops['eq'](varInst, ops[self.op](sub_ls, sub_rs))

        return ops[self.op](sub_ls, sub_rs)

    def unrollVec(self, vec):
        self.op = vec[0]
        depth = vec[1]
        v0 = vec[2:]
        if depth in v0:
            idx = v0.index(depth)
            v1 = v0[:idx]
            v2 = v0[idx+1:]
        else:
            v1 =  v0
            v2 = []
        
        if len(v1) == 0:
            pass
        elif len(v1) == 1:
            self.ls = v1[0]
        elif len(v1) == 2:
            self.ls = v1[1]
        else:
            ls = BTree(self.bid)
            ls.unrollVec(v1)
            self.ls = ls
        
        if len(v2) == 0:
            pass
        elif len(v2) == 1:
            self.rs = v2[0]
        elif len(v2) == 2:
            self.rs = v2[1]
        else:
            rs = BTree(self.bid)
            rs.unrollVec(v2)
            self.rs = rs

class ExplainModel:
    def __init__(self):
        self.outOfScope = []
        self.explainVars = []
        self.stmts = []
        self.cVars = []
        self.condsStmts = []
        self.errors = []

    def addStmt(self, stmt):
        self.stmts += [stmt]
    
    def addOutOfScopeCondition(self, condName, varName, ls, op, rs, dsource):
        pass

    def export(self):
        suppl_checks = []
        if any(["is linear" in x for x in self.stmts]):
            suppl_checks += ["loop"]
        return {"stmts": str(self), 'supplement': suppl_checks}

    def __repr__(self):
        out_str = "\n".join([str(s) for s in self.errors])
        return out_str
    

def find_def(model, path, vid):
    for p in path:
        s = model[p]
        for v in s.variables:
            if v.def_label == vid:
                v.toConsole()

def find_use(model, path, vn, vsid, vid):
    for p in path:
        s = model[p]
        for v in s.variables:
            if v.name == vn and p == vsid:
                continue
            if vid in v.label:
                v.toConsole()

# (state, var) -> path
# - ie. offset.VAR
# - find def and use
# - look for conditions on path

# process:
# add vulns to model
# walk path, add conditions to model
# walk path again - use def and use to connect conditions with vars/vulns

# model - program model
# var_map - match.var_table
# var_table - attr_map
# path - call_trace (path through the model)
# vulns - vulns

def do_explain(model, var_map, var_table, path, vulns):
    s = z3.Solver()
    expr_map = {}
    explain_model = ExplainModel()

    
    def find_def_on_path(model, path, vid):
        i = 0
        for p in path:
            s = model[p]
            for v in s.variables:
                if v.def_label == vid:
                    if v.dsource != '':
                        explain_model.errors += [f'WARNING: dsource of {vid}-{p} is {v.dsource}']
                    return v, i
            i+=1
        return None, None
    
    def add_vulns_to_model():
        vuln_vars = []
        for v in vulns:
            ls = v['ls']
            op = v['op']
            rs = v['rs']
            lsExpr = z3.Int(ls)
            rsExpr = z3.Int(rs)
            expr_map[ls] = lsExpr
            expr_map[rs] = rsExpr
            s.add(ops[op](lsExpr, rsExpr))
            if type(ls) == str:
                vuln_vars += [ls]
            if type(rs) == str:
                vuln_vars += [rs]
        return vuln_vars
    
    # Add conditions on the error path to our model of path constraints:
    def add_conditions_to_model():
        cond_deps = []
        for p in path:
            st = model[p]
            if type(st.transition) == mod.CConditionalTransition:
                var = st.find_condition_var()
                if not var == None:
                    vx = var.checkVarDeps()
                    cond_deps += [(p, vi, st.lookup_name(vi).label) for vi in vx]
                    explain_model.errors += [f'WARNING: dsource of {vi} is {st.lookup_name(vi).dsource} in {var.name}' for vi in vx if st.lookup_name(vi).dsource != '']
                    btree = BTree(p)
                    btree.unrollVec(var.vec)
                    c =  btree.mapToPredicate(None, None)
                    if type(c) == ExplainError:
                        explain_model.errors += [str(c)]
                    elif c != None:
                        s.add(c)
        return cond_deps

    # TODO: Trace vars to def in model
    def explain(vuln_vars, cond_deps):
        for v in vuln_vars:
            if f'{v}.VAR' in var_table and var_map[f'{v}.VAR'] != None:
                vi = var_table[f'{v}.VAR']
            else:
                if v in var_map and type(var_map[v]) == int:
                    s.add(ops['eq'](expr_map[v], var_map[v]))
                    continue
                if v in var_map and type(var_map[v]) == vart.VInst:
                    s.add(ops['eq'](expr_map[v], var_map[v].v))
                    continue

                vi = var_table[v]

            sid = vi[0]
            vn = vi[2]
            var = model[sid].lookup_name(vn)
            if var == None:
                continue

            if var.dsource != '':
                explain_model.errors += [f'WARNING: dsource of {vn}-{sid} is {var.dsource}']

            # Add block id to var name
            if var.label != []:
                
                for vl in var.label:
                    d, ds = find_def_on_path(model, path, vl)
                    if d == None:
                        continue
                    # add d to model
                    sid = path[ds]
                    dv = z3.Int(f'{sid}-{d.name}')
                    if d.check_is_const():
                        dval = d.vec[-1]
                        s.add(ops['eq'](dv, dval))
                    last_var = dv
                    last_var_name = d.name
                    last_block = path[ds]
                    for p in path[ds:]:
                        st = model[p]
                        for vx in st.variables:
                            if vx.check_label(vl):
                                # add to model
                                vxv = z3.Int(f'{p}-{vx.name}')
                                if vx.dsource != '':
                                    explain_model.errors += [f'WARNING: dsource of {vx.name}-{p} is {vx.dsource}']
                                if vx.vec[0] in ["St", "StLD"] and last_var_name in vx.getRS() and last_block == p:
                                    vrs = vx.getRS()
                                    btree = BTree(p)
                                    btree.unrollVec(vrs[1:])
                                    
                                    c =  btree.mapToPredicate(None, None)
                                    if type(c) == ExplainError:
                                        explain_model.errors += [c]
                                    elif c != None:
                                        s.add(ops['eq'](vxv, c))
                                    else:
                                        continue
                                else:
                                    s.add(ops['eq'](last_var, vxv))
                                last_var = vxv
                                last_var_name = vx.name
                                last_block = p
                            
                    s.add(ops['eq'](expr_map[v], last_var))

   
    vuln_vars = add_vulns_to_model()
    cond_deps = add_conditions_to_model()
    explain(vuln_vars, cond_deps)

    satStr = str(s.check())
    modelStr = str(s)
    if satStr == 'sat':
        m = s.model()
        exStr = str(m)
    else:
        exStr = 'n/a'
    result = f'{modelStr}\n{satStr}\n{exStr}'
    result += f'\n{explain_model}'
    
    return satStr, result
