#--------------------------------------
# File: et.py
#
# Purpose: Expression Tree
#    - functional representation of our IR expressions
#    - used for variable operation reduction (the step removing intermediate expressions to form more complex expressions)
#--------------------------------------

from colorama import Fore
import hy2.core.termui as tui
import hy2.core.utils as utils
import hy2.core.c_calc as c_calc
import hy2.core.constants as cc
import hy2.core.solver as solv
import copy
# -----------------------------------
def get_instance_no(t1l, i, idx):
    return t1l[:idx].count(i)

def get_last_element_before_idx(t1l, i, ix):
    try:
        return len(t1l) - (t1l[::-1][(len(t1l)-ix):].index(i)+(len(t1l)-ix))-1
    except:
        return None

def set_vmem(vmem):
    solv.MEM = vmem

def ghost_mem_load(x):
    solv.GHOST_MEM.load_saved_state(x)

def init_ghost_mem():
    solv.init_ghost_mem()

def ghost_mem_put(x, y):
    solv.GHOST_MEM.put_at(x, y)

def ghost_mem_export():
    return solv.GHOST_MEM.export()

def vmem_get_all_at_pc(pc):
    return solv.MEM.vmem_get_all_at_pc(pc)

def mem_check_block_regs(pc, tid, oid, regname):
    return solv.MEM.check_block_regs(pc, tid, oid, regname)


# This is for storing variables whose value is set more than once within a block
# ie. rsp and rbp
class TDTTable:
    def __init__(self):
        self.name = ""
        self.values = {}
        self.val = {}
        self.deps = {}
    
    def add_value_at_t(self, t, v, v0=None):
        if t == '':
            return
        self.values[t] = v
        if not v0 == None:
            self.val[t] = utils.to_int(v0)
    
    def get_value_at_t(self, t):
        v0 = None
        times = list(self.values.keys())
        times.sort()
        for t0 in times:
            if t0 > t:
                break
            v0 = self.values[t0]
        return v0
    
    # TODO: Add assertions
    def calculate_diff(self):
        min_v = -1
        max_v = 0
        for k, v in self.val.items():
            if type(v) == str:
                self.val[k] = utils.to_int(v)
                v = self.val[k]
                if type(v) == str:
                    continue
            if v == None:
                continue
            if v < min_v or min_v < 0:
                min_v = v
            if v > max_v:
                max_v = v
        return (max_v - min_v), min_v, max_v
    
    def print_stmt(self):
        out_str = ''
        for k, v in self.values.items():
            out_str += f'   {k}: {v}'
            if k in self.val:
                out_str += f' {self.val[k]}'
            out_str += '\n'
        return out_str

    def __repr__(self):
        return self.print_stmt()
    
    def print_tui(self):
        out_str_expr = ''
        out_str_val = ''
        for k, v in self.values.items():
            out_str_expr += f'   {k}: {v}\n'
            out_str_val += f'{self.val[k]}\n'
            if k in self.deps:
                out_str_expr += str(self.deps[k])
        return out_str_expr, out_str_val


# TVar - describes a dependency on another variable in the block
# ie.
# t12 = LOAD(0x1234)
# t2 = Add(t12,2)
# t12 in ET of t2 would be a TVar
# lookup t12 in block
class TVar:
    def __init__(self, id):
        self.id = id
        self.dsource = ""
        self.dintent = ""
        self.val = ""
        self.cast = ""
    
    def solve(self, tid, oid):
        return self.id

    def partial_solve(self, tid, oid):
        return self.id

    def __repr__(self):
        return str(self.id)

# TTerm - a terminal (ie. a concrete values)
# ie. t2 = Add(1,2) - 1 and 2 would be TTerms
class TTerm:
    def __init__(self, val, casts):
        self.val = val
        self.dsource = ""
        self.dintent = ""
        self.casts = casts

    
    def solve(self, tid, oid):
        return self.val

    def partial_solve(self, tid, oid):
        return self.val
    
    def __repr__(self):
        return str(self.val)

# I have no idea what this is
# I think I created it to store the size of current stack frame (?)
class TEVar:
    def __init__(self):
        self.abs_addr = ""
        self.size = 0
        self.name = ""

# REFACTOR: remove lid
class TStmt:
    def __init__(self, pc, op, ls, rs, casts=[]):
        self.pc = pc
        self.op = op
        self.ls = ls
        self.rs = rs
        self.casts = casts
        self.name = ""
        self.abs_addr = ""
        self.dsource = ""
        self.dintent =  ""
        self.tvar = ""
        self.dtype = ""
        self.deps = []

    # for solving on static branches:
    #  IN: oid - identifier for instance of block
    #      tid - thread id
        
    # OUT: retv - value calculated
    #      lsv - value calculated for address in STORE(address, value)
    def partial_solve(self, oid, tid):
        if self.rs == None:
            lsv = self.ls.partial_solve(oid, tid)
            if self.op[0] == cc.PUT_OP:
                retv, _ = solv.partial_ops(self.op[0])(args=[self.op, oid, tid, self.pc, self.name, lsv])
                return retv
            else:
                retv, _ = solv.partial_ops(self.op[0])(args=[self.op, oid, tid, self.pc, lsv, None])
                if self.op[0] == cc.LOAD_OP:
                    return (lsv, retv)
                return retv
        else:
            if type(self.ls) == list:
                lsv0 = self.ls[0].partial_solve(oid, tid)
                lsv1 = self.ls[1].partial_solve(oid, tid)
                lsv = [lsv0, lsv1]
            else:
                lsv = self.ls.partial_solve(oid, tid)
            
            if type(self.rs) == list:
                rsv0 = self.rs[0].partial_solve(oid, tid)
                rsv1 = self.rs[1].partial_solve(oid, tid)
                rsv = [rsv0, rsv1]
            else:
                rsv = self.rs.partial_solve(oid, tid)
            
            retv, _ = solv.partial_ops(self.op[0])(args=[self.op, oid, tid, self.pc, lsv, rsv])
            if self.op[0] == cc.STORE_OP:
                return (lsv, retv)
            return retv
    
    def solve(self, oid, tid):
        if self.rs == None:
            lsv = self.ls.solve(oid, tid)
            retv, _ = solv.ops(self.op[0])(args=[self.op, oid, tid, self.pc, lsv, None])
            return retv
        else:
            lsv = self.ls.solve(oid, tid)
            if type(self.rs) == list:
                rsv0 = self.rs[0].solve(oid, tid)
                rsv1 = self.rs[1].solve(oid, tid)
                rsv = [rsv0, rsv1]
            else:
                rsv = self.rs.solve(oid, tid)
            retv, _ = solv.ops(self.op[0])(args=[self.op, oid, tid, self.pc, lsv, rsv])
            return retv
    
    # Converts the expression tree to a linear vector:
    # ex.    ADD
    #        / \
    #       x   10
    # becomes: ["Add", "D1", "x", "D1", 10]
    def astToVec(self, depth=1):
        opStr = cc.decode_op[self.op[0]]
        if self.rs == None:
            if type(self.ls) == TStmt:
                return [opStr, f'D{depth}'] + self.ls.astToVec(depth+1)
            elif type(self.ls) == TVar:
                return [opStr, f'D{depth}', self.ls.id]
            elif type(self.ls) == TTerm:
                return [opStr, f'D{depth}', self.ls.val]
            else:
                return [opStr, f'D{depth}', self.ls]
        else:
            layer = []
            ls = []
            if type(self.ls) == TStmt:
                ls = [opStr, f'D{depth}'] + self.ls.astToVec(depth+1)
            elif type(self.ls) == TVar:
                ls = [opStr, f'D{depth}', self.ls.id]
            elif type(self.ls) == TTerm:
                ls = [opStr, f'D{depth}', self.ls.val]
            elif type(self.ls) == list:
                ls += [opStr, f'D{depth}']
                sub_ls = []
                for elem in self.ls:
                    if type(elem) == TVar:
                        sub_ls += [elem.id]
                    elif type(elem) == TTerm:
                        sub_ls += [elem.val]
                    elif type(elem) == TStmt:
                        sub_ls += [elem.astToVec(depth+1)]
                    else:
                        sub_ls += [elem]
                ls += sub_ls
            else:
                ls = [opStr, f'D{depth}', self.ls]
            
            rs = []
            if type(self.rs) == TStmt:
                rs = [f'D{depth}'] + self.rs.astToVec(depth+1)
            elif type(self.rs) == TVar:
                rs  = [f'D{depth}', self.rs.id]
            elif type(self.rs) == TTerm:
                rs = [f'D{depth}', self.rs.val]
            elif type(self.rs) == list:
                rs += [f'D{depth}']
                sub_rs = []
                for elem in self.rs:
                    if type(elem) == TVar:
                        sub_rs += [elem.id]
                    elif type(elem) == TTerm:
                        sub_rs += [elem.val]
                    elif type(elem) == TStmt:
                        sub_rs += [elem.astToVec(depth+1)]
                    else:
                        sub_rs += [elem]
                rs += sub_rs
            else:
                rs = [f'D{depth}', self.rs]

            return ls + rs
     
    # Returns a list of operators in the expression tree
    #  ie. 
    #      Add(Sub(t10, 3), 10)
    #      would return [Add, Sub]
    def flatten(self):
        if type(self.rs) == None:
            if type(self.ls) == TStmt:
                if self.op[0] in cc.CAST_OPS:
                    opl = self.ls.flatten()
                    if self.ls.tvar != "":
                        self.tvar = self.ls.tvar
                    return opl
                else:
                    opl =  [self.op[0]] + self.ls.flatten()
                    if self.ls.tvar != "":
                        self.tvar = self.ls.tvar
                    return opl
            if type(self.ls) == TTerm:
                return [self.ls.val]
            elif type(self.ls) == TVar:
                self.tvar = self.ls.id
                return []
            else:
                return []
        else:
            opList =  []
            if not self.op[0] in cc.CAST_OPS:
                opList += [self.op[0]]
            if type(self.ls) == TStmt:
                opList += self.ls.flatten()
                if self.ls.tvar != "":
                    self.tvar = self.ls.tvar
            elif type(self.ls) == TTerm:
                opList += [self.ls.val]
            elif type(self.ls) == TVar:
                self.tvar = self.ls.id
            if type(self.rs) == TStmt:
                opList += self.rs.flatten()
                if self.rs.tvar != "":
                    self.tvar = self.rs.tvar
            elif type(self.rs) == TTerm:
                opList += [self.rs.val]
            elif type(self.rs) == TVar:
                self.tvar = self.rs.id
            
            return opList
    
    def get_val_subexpr(self, val):
        if self.op[0] == cc.GET_OP:
            return str(self.ls)
        if val == None or val == "":
            return cc.Unknown()
        return val

    def check_by_prog(self):
        if self.op[0] == cc.PUT_OP:
            return type(self.ls) == TTerm or type(self.ls) == int or type(self.ls) == str
        elif self.op[0] == cc.STORE_OP:
            return type(self.rs) == TTerm or type(self.rs) == int or type(self.rs) == str
        return False

    # tree to string
    def asRaw(self):
        out_str = ''
        op_str = cc.opStr(self.op)
        if self.name != "":
            out_str += f'{self.name} = '
        if type(self.ls) == TStmt:
            lstr =  self.ls.asRaw()
        else:
            lstr = str(self.ls)
        if self.rs != None:
            if type(self.rs) == TStmt:
                rstr = self.rs.asRaw()
            else:
                rstr = str(self.rs)
            return out_str + f'{op_str}({str(lstr)}, {str(rstr)})'
        else:
            return out_str + f'{op_str}({str(lstr)})'

    def __repr__(self):
        out_str = ''
        op_str = cc.opStr(self.op)
        if self.dsource != "":
            out_str += Fore.LIGHTBLUE_EX + self.dsource + Fore.RESET
            out_str += " "
        if self.dintent != "":
            out_str += Fore.LIGHTBLUE_EX + self.dintent + Fore.RESET
            out_str += " "
        if self.name != "":
            out_str += f'{self.name} = '
        if self.rs != None:
            return out_str + f'{op_str}({str(self.ls)}, {str(self.rs)})'
        else:
            return out_str + f'{op_str}({str(self.ls)})'

    # Labels dsource and dintent based on register used/accessed
    #  with arg - being function params
    #   iargs - being arguments in function call
    def check(self, fid, iarg_no):
        if self.op[0] == cc.GET_OP or self.op[0] == cc.SS_OP:
            if str(self.ls)[1:] == "di":
                self.dsource = "arg1"
            elif str(self.ls)[1:] == "si":
                self.dsource = "arg2"
            elif str(self.ls)[1:] == "ax":
                self.dsource = "ret "+fid
        
        elif self.op[0] == cc.PUT_OP:
            if str(self.name)[1:] in ["di", "si", "dx", "cx", "8", "9"]:
                self.dintent = f'iarg{iarg_no+1}'

        if type(self.ls) == TStmt and self.ls.dsource != '':
            self.dsource = self.ls.dsource
        if self.rs != None and type(self.rs) == TStmt and self.rs.dsource != '':
            self.dsource = self.rs.dsource

# Variable Instance:
class VarInst:
    def __init__(self):
        self.val = ""
        self.ls = ["", None, None]
        self.ls_val = ""
        self.rs = ["", None, None]
        self.rs_val = ""
        self.abs_addr = ""
        self.telescope = None
        self.lid = ""
        self.deps = []

        self.deep_deps = {}

# lid0 - line number of the first statement in the block
# line number each opcode executed has a unique line number

# Move TVar dependency check from eval_stmt to when the expression tree is built


class ETBlock:
    def __init__(self, pc, jmp_kind, fname, has_sym_data, next_fname, last_fname, fsize):
        self.jmp_kind = jmp_kind
        self.pc = pc
        self.name = fname
        self.has_sym_data = has_sym_data
        self.fsize = fsize
        self.next_fname = next_fname
        self.last_fname = last_fname
        
        self.CPU_DEPEND_FLAG = False

        self.vl = []
        self.var_list = []
        self.var_table = {}

        self.tmp_var_table = {}
        self.tmp_var_list = []

        self.export_addr = 0

        self.put_ctr = 0
    
    def __repr__(self):
        out_str = f'[{self.pc}]: {self.name}\n'
        for k, v in self.var_table.items():
            out_str += f'{v}\n'
        
        out_str += f'\n---> {self.jmp_kind} {self.next_fname}'
        return out_str

    def replaceWithMacro(self, MOP, vid):
        v = self.var_table[vid]
        if type(v) == TStmt:
            if v.tvar != "":
                v.op = MOP
                v.ls = TVar(v.tvar)
                v.rs = TTerm(1, [])
                self.var_table[vid] = v
            else:
                # TODO: Finish me
                pass
        else:
            # TODO: Finish me
            pass
    
    def get_var(self, vid, i):
        v = self.var_table[vid]
        if type(v) == TDTTable:
            var = v.get_value_at_t(i)
            return var
        return v

    # With list of IR expressions, and index in this list
    # Create an expression tree by locating other statements that the current statement is dependent on, and adding them to the tree
    # IN:
    # tid - thread id [X]
    # t1l - list of vars
    # t1 - table of vars
    # i - var name
    # ix - var index
    # casts - collect casts
    def solve_arg(self, t1l, t1, i, ix, casts=[]):
        if not i in t1:
            return TTerm(utils.to_int(i), casts)
    
        elif not i in t1l:
            return TTerm(utils.to_int(i), casts)
        
        elif ix < t1l.index(i):
            return TTerm(utils.to_int(i), casts)

        elif type(t1[i]) == list and len(t1[i]) == 1:
            self.vl.append(i)
            x = t1[i][0]
            idx = t1l.index(i)
            tstmt = TStmt(x['pc'], x["op"][0], self.solve_arg( t1l, t1, x["op"][1], idx), None, casts)
            tstmt.check(self.last_fname, self.put_ctr)
            return tstmt
        
        elif type(t1[i]) == list:
            self.vl.append(i)
        
            idx = get_last_element_before_idx(t1l, i, ix)
            if idx is None:
                return TTerm(i, casts)
        
            i1 = get_instance_no(t1l, i, idx)
            
            y = t1[i][i1]
            tstmt =  TStmt(y['pc'], y["op"][0], self.solve_arg(t1l, t1, y["op"][1], idx), None, casts)
            tstmt.check(self.last_fname, self.put_ctr)
            return tstmt
        
        elif t1[i]["t"] == "u":
            self.vl.append(i)
            x = t1[i]
            idx = t1l.index(i)
            op = x["op"][0]
            arg = x["op"][1]

            if op[0] == cc.SET_OP:
                return self.solve_arg(t1l, t1, arg, idx, casts)

            if op[0] in cc.CAST_OPS:
                c1 = casts + [op]
                return self.solve_arg(t1l, t1, arg, idx, casts=c1)
        
            if op[0] == cc.LOAD_OP:

                if not i in self.var_table:
                    tstmt = TStmt(x['pc'], op, self.solve_arg(t1l, t1, arg, idx), None, casts)
                    tstmt.name = i
                    tstmt.check(self.last_fname, self.put_ctr)
                    self.var_table[i] = tstmt
                    self.var_list.append(i)
                
                if i in self.var_table:
                    return TVar(i)
                else:
                    print(self.var_table.keys())
                    raise Exception("ERROR")

            if op[0] == cc.PUT_OP:
                tstmt = TStmt(x['pc'], op, self.solve_arg(t1l, t1, arg, idx), None, casts)
                tstmt.name = i
                tstmt.check(self.last_fname, self.put_ctr)
                return tstmt

            tstmt = TStmt(x['pc'], x["op"][0], self.solve_arg(t1l, t1, x["op"][1], idx), None, casts)
            tstmt.check(self.last_fname, self.put_ctr)
            return tstmt
        else:
            self.vl.append(i)
            x = t1[i]
            op = x["op"][0]
            args = t1[i]["op"][1].split(",")
            idx = t1l.index(i)
            t1l1 = t1l
            if op[0] == cc.ITE_OP:
                tstmt = TStmt(x["pc"], op, self.solve_arg(t1l1, t1, args[0], idx), [self.solve_arg(t1l1, t1, args[1], idx), self.solve_arg(t1l1, t1, args[2], idx)], casts)
                return tstmt
            
            if op[0] == cc.PUTI_OP:
                tstmt = TStmt(x["pc"], op, [self.solve_arg(t1l1, t1, args[0], idx), self.solve_arg(t1l1, t1, args[1], idx)], self.solve_arg(t1l1, t1, args[2], idx), casts)
                return tstmt            
            if op[0] == cc.STORE_OP:
                tstmt = TStmt(x["pc"], op, self.solve_arg(t1l1, t1, args[0], idx), self.solve_arg(t1l1, t1, args[1], idx), casts)
                return tstmt

            if op[0] in cc.encode_cpu_ops:
                self.CPU_DEPEND_FLAG = True
            tstmt =  TStmt(x["pc"], x["op"][0], self.solve_arg(t1l1, t1, args[0], idx), self.solve_arg(t1l1, t1, args[1], idx), casts)
            tstmt.check(self.last_fname, self.put_ctr)
            return tstmt

    def checkMacro(self, vid, tstmt):
        opList = tstmt.flatten()
        if str(opList) in cc.macros_lookup:
            newOp = cc.macros_lookup[str(opList)]
            self.replaceWithMacro(newOp, vid)

    # I forget exactly what this does
    # IN:
    # t1 - var table from ir
    # tl1 - var list from ir
    # tv - variable name i in tl1
    # i - index of tv in tl1
    def do_solve_arg(self, t1, tl1, tv, i, btype):
        ti = t1[tv]
        if type(ti) == list:
            idx = get_instance_no(tl1, tv, i)
            tx = ti[idx]
            tstmt = TStmt(tx['pc'], tx['op'][0], self.solve_arg(tl1, t1, tx['op'][1], i), None)
            tstmt.name = tv
            tstmt.check(self.last_fname, self.put_ctr)

            if type(tstmt) == TTerm:    
                return

            if len(ti) == 1:
                if tstmt.op[0] == cc.PUT_OP and "iarg" in tstmt.dintent:
                    self.put_ctr += 1
                self.var_table[tv] = tstmt
                self.var_list.append(tv)
                return
            
            if not tv in self.var_table:
                self.var_table[tv] = TDTTable()
                self.var_table[tv].name = tv
            
            self.var_table[tv].add_value_at_t(len(self.var_list), tstmt)
            self.var_list.append(tv)
        else:
            if tv in self.var_list:
                raise Exception()
            
            tstmt = self.solve_arg(tl1, t1, tv, tl1.index(tv))
            if type(tstmt) == TVar:
                return
            if tv in self.var_table:
                print("oh nos")
            tstmt.name = tv
            tstmt.dtype = btype
            if type(tstmt) == TStmt:
                tstmt.check(self.last_fname, self.put_ctr)

                if tstmt.op[0] == cc.PUT_OP and "iarg" in tstmt.dintent:
                    self.put_ctr += 1
            self.var_table[tv] = tstmt
            if tstmt.name[:2] == "ct":
                self.checkMacro(tv, tstmt)
            self.var_list.append(tv)
    
    # parse block into set of expression trees
    # IN:
    # t1 - var_table from ir
    # tl1 - var_list from ir
    def lazy_eval_solver(self, t1, tl1, types):
        self.vl = []
        
        for i in range(len(tl1)-1, -1, -1):
            ti = tl1[i]
            if (not ti in self.vl) or type(t1[ti]) == list:
                ts = self.do_solve_arg(t1, tl1, ti, i, types[i])
