from colorama import Fore
import hy2.core.utils as utils
import hy2.core.constants as cc
import hy2.core.var_types as vart
def to_int(x):
    if type(x) == cc.Unknown:
        return x
    elif type(x) == vart.VInst or type(x) == vart.VRepr:
        return x.v
    elif type(x) == vart.VRange:
        return list(range(x.start, x.stop, x.step))
    elif type(x) == vart.VSet:
        return x.vals
    if x == None:
        return None
    if type(x) == int or type(x) == vart.VEmpty:
        return x
    if x[:2] == "0x":
        return int(x, 16)
    else:
        try:
            return int(x)
        except:
            return x

# Temporarily leaving these like this in case other checks are required
def not_eq(ls, rs):
    return ls != rs

# TODO: FIXME
tmp_ops = ["ADD", "SUB", "MUL", "SHL"]
def is_eq(ls, rs):
    if ls in tmp_ops:
        return ls.lower() == rs[:3].lower()
    elif rs in tmp_ops:
        return ls[:3].lower() == rs.lower()
    elif rs == "ret" and ls[:3] == "ret":
        return True
    elif type(ls) == vart.VSet and type(rs) == int:
        return rs in ls.vals
    elif ls == rs:
        return True
    elif type(ls) == str and type(rs) == int:
        return to_int(ls) == rs
    elif type(ls) == vart.VSet and type(rs) == list:
        return ls in rs
    elif type(ls) == list and type(rs) == int:
        return rs in ls
    elif type(rs) == list and type(ls) == int:
        return ls in rs
    elif type(ls) == str and type(rs) == str and rs in ls.replace('sym.imp.', ''):
        return True
    elif type(ls) == str and type(rs) == str and ls.replace('sym.', '') == rs:
        return True
    elif type(ls) == str and type(rs) == str and ("lib" in ls or "lib" in rs):
        #print(ls.split(".")[-1] == rs.replace("'", "").split("_")[-1])
        if "lib" in rs:
            return ls.split(".")[-1] == rs.replace("b'", '').replace("'", "").replace("_", '').split('-')[-1]
        else:
            #print(ls.replace("b'", '').replace("'", "").replace("_", '').split('-')[-1])
            #print(rs.split(".")[-1])
            return rs.split(".")[-1] == ls.replace("b'", '').replace("'", "").replace("_", '').split('-')[-1].replace('libc', '')
    return ls == rs

def l_eq(ls, rs):
    try:
        return to_int(ls) <= to_int(rs)
    except:
        return False

def lt(ls, rs):
    try:
        return to_int(ls) < to_int(rs)
    except:
        return False

def gt(ls, rs):
    return ls > rs

def check_in(ls, rs):
    if rs[0] in tmp_ops:
        if type(ls) == int:
            return False
        return ls[:3].upper() in rs
    if type(ls) == str and "ret" in ls:
        return ls.split(" ")[0] in rs
    return ls in rs

def check_not_in(ls, rs):
    if type(ls) == int:
        return not ls in rs
    if ls[:3] == 'ret' and rs[:3] == 'ret':
        return not 'ret '+ls.split('-')[-1].replace("b'",'').replace("'","") in rs
    return not ls in rs

def like(ls, rs):
    if type(ls) == str and type(rs) == list:
        return ls in rs
    
    return any(ls0 in rs for ls0 in ls)

op = {
    "eq": is_eq,
    "neq": not_eq,
    "lte": l_eq,
    "lt": lt,
    "gt": gt,
    "in": check_in,
    "nin": check_not_in,
    "like": like
}

# -----------------------------------------------
# Model data classes (built by partial_cfg / model_infer)

class CInvocation:
    def __init__(self):
        self.name = ""
        self.args = []
        self.strs = []
    
    def __repr__(self) -> str:
        return f'{self.name}({",".join([str(x) for x in self.args])})'

    def export_html(self):
        return utils.color_text('light_blue', self.name) + '(' + (",".join([str(x) for x in self.args]))[:100] + "..." + ')'

class CTransition:
    def __init__(self):
        self.dest = []
        self.src_pc  = 0
        self.dest_bid = []
        self.dest_pc = []
        self.transition_type = ""
    
    def __repr__(self) -> str:
        return f'{self.transition_type} dest: {self.dest} -> {self.dest_pc}'

    def toConsole(self):
        print(self)

    def export_html(self):
        dest_str = ','.join([str(d) for d in self.dest])
        out = utils.color_text('red_pink', dest_str) + '@' + str(self.dest_pc)
        out += f' {utils.color_text("light_green", self.transition_type)}'
        return out

class CConditionalTransition(CTransition):
    def __init__(self):
        super().__init__()
        self.jmp_ip = 0
        self.jmp_iff = 0
        self.jmp_ift = 0
        self.linked_var = ""

    def __repr__(self):
        out_str = super().__repr__()
        out_str += f'JMP IP: {self.jmp_ip} JMP IFF {self.jmp_iff} JMP IFT {self.jmp_ift}\n'
        return out_str

    def toConsole(self):
        print(self)
    
    def export_html(self):
        out = super().export_html()
        out += f' JMP IP: {self.jmp_ip} JMP IFF {self.jmp_iff} JMP IFT {self.jmp_ift}'
        return out

class CVar:
    def __init__(self):
        self.name = ""
        self.pc = ""
        self.abs_addr = vart.VEmpty()
        self.label = []
        self.def_label = ""
        
        self.vec = []
        self.val = vart.VEmpty()
        self.dsource = ""
        self.dintent = ""
        self.is_constant =  False

        self.static_name = ""
        self.dtype = ""

        self.expression = None

    # Fields read by the checker (check_action / check_aliases) that the hy2
    # model builder does not produce. They are read-only so pickled models
    # (which don't store them) still load and match.
    @property
    def is_invariant(self):
        return len(self.vec) > 2 and self.check_is_const()

    # dvec held one vec per observed instance; hy2 only keeps the merged vec,
    # so that is the single known instance.
    @property
    def dvec(self):
        return [self.vec]

    @property
    def lsv(self):
        return []

    @property
    def has_tvar(self):
        return False

    def check_is_const(self):
        return (self.vec[0] == "Put" and self.vec[-2] == "D1" and type(self.vec[-1]) == int) or (self.vec[0] == "St" and self.vec[-2] == "D1" and type(self.vec[-1]) == int)
    
    def check_label(self, vl):
        return vl in self.label

    def checkVarDeps(self):
        return [x for x in self.vec if type(x) == str and x[0] == 't']

    def getSize(self):
        return utils.dtypeToSize(self.dtype)

    def getLS(self):
        try:
            ls_idx = self.vec.index('D1', 2)
            return self.vec[:ls_idx]
        except:
            return self.vec
    
    def getRS(self):
        try:
            rs_idx = self.vec.index('D1', 2)
            return self.vec[rs_idx:]
        except:
            return None
    
    def export_html(self):
        out_str = ""
        out_str += utils.bold_text(utils.color_text('purple', self.name))
        if self.static_name != "":
            out_str += f" ({utils.color_text('green', self.static_name)}) "
        out_str += f' = {utils.vecToStr(self.vec)}'
        if type(self.abs_addr) != vart.VEmpty:
            out_str += f' = {self.val} @ {self.abs_addr}'
        else:
            out_str += f' = {self.val}'
        
        if self.dtype != "":
            out_str += f' ({utils.color_text("light_green", self.dtype)}) '
        
        if self.def_label == '':
            out_str += '\n'
            out_str += utils.color_text('lilac', 'use: ') + f'{str(self.label)[:100]+"..."}'

        else:
            out_str += '\n'
            out_str += utils.color_text('red', 'def: ') + f'{self.def_label}' + utils.color_text('lilac', ' use: ') + f'{str(self.label)[:100] + "..."}'

        add_nl = True 
        if self.dsource != "":
            out_str += f' {utils.bold_text("dsource:")} {self.dsource}'
        if self.dintent != "":
            out_str += f' {utils.bold_text("dintent:")} {self.dintent}'
        
        #out_str += '\n'
        return out_str

    def toConsole(self):
        print(f'[{self.pc}] ' + Fore.CYAN + self.name + Fore.RESET + f' = {utils.vecToStr(self.vec)}', end='')
        if type(self.abs_addr) != vart.VEmpty:
            print(f' {self.val} @ {self.abs_addr}')
        else:
            print(f' {self.val}')
        
        lbl_str = str(self.label)[:100]
        if self.def_label == '' or self.def_label == []:
            print(Fore.LIGHTMAGENTA_EX + 'use: ' + Fore.RESET + f'{lbl_str}', end='')
        else:
            print(Fore.LIGHTRED_EX + 'def: ' + Fore.RESET + f'{self.def_label}' + Fore.LIGHTMAGENTA_EX + ' use: '+Fore.RESET + f'{lbl_str}', end='')
        
        add_nl = True
        if self.dtype != "":
            print(f' dtype: {self.dtype}, vname: {self.static_name}')
            add_nl = False
        if self.dsource != "":
            print(Fore.YELLOW +' dsource:'+Fore.RESET + f' {self.dsource}')
            add_nl = False
        if self.dintent != "":
            print(f' dintent: {self.dintent}')
            add_nl = False

        if add_nl:
            print('')       

def check_cond(conds, var_table, var_table_tmp, cond_type="and"):
    cond_match = True
    if cond_type == "or":
        cond_match = False

    for c in conds:
        if "or" in c:
            or_conds = c["or"]
            cond_match = check_cond(or_conds, var_table, var_table_tmp, cond_type="or")
            if not cond_match:
                break
        elif "and" in c:
            and_conds = c["and"]
            cmatch = check_cond(and_conds, var_table, var_table_tmp, cond_type="and")
            if not cmatch and cond_type == "and":
                cond_match = False
                break
            elif cmatch and cond_type == "or":
                cond_match = True
                break
        else:
            cls = c['ls']
            crs = c['rs']
            cop = c['op']
            ls = None
            rs = None
            if cls == "first_only":
                continue
            if cls in var_table:
                ls = var_table[cls]

            if type(crs) == list or type(crs) == bool:
                rs = crs
            elif crs in var_table:
                rs = var_table[crs]
                assert not (cls in var_table and crs in var_table)
            elif crs in var_table_tmp:
                rs = var_table_tmp[crs]

            if cls in var_table_tmp:
                ls = var_table_tmp[cls]
            
            if rs == None:
                tmp_rs = to_int(crs)
                if type(tmp_rs) == int:
                    rs = tmp_rs
                
                elif crs in tmp_ops or crs in ["ret"]:
                    rs = crs
                
                elif "const" in crs:
                    rs = crs.replace('const.', '')

            #print(f'Check condition: {cls} = {ls} {cop} {crs} = {rs} {type(ls)} {type(rs)}')
            if (ls == None and type(rs) == cc.Unknown) or (rs == None and type(ls) == cc.Unknown):
                cond_match = False
                continue

            if "label" in cls and "label" in crs and (ls == None or rs == None):
                cond_match = False
                continue
            if "label" in cls and "label" in crs and type(ls) == str and type(rs) == list:
                #rs = [a.split(' ')[0] for a in rs]
                #ls = ls.split(' ')
                ls = [ls]

            if ls == None or rs == None:
                if cond_type == "or":
                    continue
                else:
                    raise Exception(f'ERROR: {cls} = {ls}, {crs} = {rs}, {c}')

            if not cop in op:
                raise Exception(f'Missing OP: {cop}')
        
            #print(f'Check condition: {ls} {cop} {rs} {type(ls)} {type(rs)}')
            #print(op[cop](ls, rs))
            #print(ls == rs)
            sat = op[cop](ls, rs)
            #if not ((type(crs) == str) and ('label' in crs or 'label' in cls)):
            sls = str(ls)[:250]
            srs = str(rs)[:250]
            print(Fore.LIGHTMAGENTA_EX + f'Check condition: {cls} {sls} {cop} {crs} {srs} {type(ls)} {type(rs)} {sat}' + Fore.RESET)
            
            if not sat:
                if cond_type == "and":
                    cond_match = False
                    break
            else:
                cond_match = True
                if cond_type == "or":
                    break
    
    return cond_match

class VariantOp:
    def __init__(self, sl):
        self.slice = sl
    
    def __repr__(self):
        return str(self.slice)

from copy import copy
def do_check_cond(conds, var_table, var_table_tmp, sid, name):
    n = 0
    idxs = []
    matches = []
    var_table_base = {}
    for k,v in var_table_tmp.items():
        if type(v) == list and len(v) == 0:
            var_table_base[k] = v
        elif type(v) == list and len(v) == 1:
            assert type(v[0]) != list
            var_table_base[k] = v[0]
        elif type(v) == list and 'label' in k:
            var_table_base[k] = v
        elif type(v) == list:
            idxs.append(k)
            n = len(v)
        else:
            var_table_base[k] = v
    
    if len(idxs) == 0:
        #print(var_table_tmp)
        #assert var_table_tmp == var_table_base
        if len(conds) == 0:
            matches.append((sid, name, var_table_base, 0))
        else:
            sat = check_cond(conds, var_table, var_table_base)
            if sat:
                matches.append((sid, name, var_table_base, 0))
        return matches

    #print(n)
    #print(idxs)
    #print(var_table_tmp)
    #print(n)
    if len(conds) == 0:
        return [(sid, name, var_table_tmp, 0)]
    
    # fix me: so a single match has a list of vars, instead of many duplicates
    satL = []
    for i in range(n):
        for k in idxs:
            print(var_table_tmp[k])
            print(var_table_tmp)
            var_table_base[k] = var_table_tmp[k][i]
        if len(conds) == 0:
            #matches.append((sid, name, copy(var_table_base), i))
            satL += [True]
        else:
            #print(var_table_base)
            sat = check_cond(conds, var_table, var_table_base)
            #if sat:
            #    #matches.append((sid, name, copy(var_table_base), i))
            satL.append(sat)   
    if any(satL):
        return [(sid, name, var_table_tmp, 0)]
    return []

def translate_load_store(action):
    if action == "VAR":
        return ['LD', 'St', 'StLD']
    elif action == "STORE":
        return ['St', 'StLD']
    return ['LD', 'StLD']

import itertools

def sanit_list(x):
    if type(x) != list:
        y = to_int(x)
        if type(y) != int:
            return []
        return [y]
    else:
        l =  [to_int(z) for z in x if type(to_int(z))==int]
        if len(l) > 0 and type(l[0]) == list:
            return sum(l, [])
        return l

class CState:
    # root_invocation is not set by the hy2 model builder; older pickled
    # models may still carry it.
    root_invocation = ""

    def __init__(self):
        self.id = []
        self.trid = []
        self.pc = 0
        self.tid = []
        self.fname = ""
        self.invocations = []
        self.signature = ""

        self.variables = []
        self.name_store = {}
        self.transition = None
        self.return_addr = 0
        self.back_edge = ""
    
    def graphLabel(self):
        return f'{self.pc} {self.fname}'
    
    def graphTransitionLabel(self):
        return f'{self.transition.dest_pc} {self.transition.dest}'

    def find_condition_var(self):
        if not type(self.transition) == CConditionalTransition:
            return None

        for v in self.variables:
            if v.name[:2] == "ct":
                return v
        
        return None

    def find_args(self):
        out_str = "\n".join([v.export_html() for v in self.variables if "iarg" in v.dintent])
        arg_pcs = [v.pc for v in self.variables if 'iarg' in v.dintent]
        return out_str, arg_pcs

    def export_html_summary(self):
        return f'{self.pc} {self.tid} {utils.bold_text(self.fname)} -> {self.transition.export_html()} INVS: {len(self.invocations)} \n'
    
    def export_html(self):
        out_str = f'-------------------------------\n{self.pc} {self.tid} {self.fname}\n'
        for v in self.variables:
            out_str += v.export_html()

        out_str += '\n' + self.transition.export_html()
        #out_str += '\n\n'
        return out_str

    def toConsole(self):
        print(f'\n-------------------\n{self.tid} {self.pc}   ' + Fore.LIGHTRED_EX + self.fname + Fore.RESET + '\n')
        for v in self.variables:
            v.toConsole()
        
        self.transition.toConsole()
        if self.back_edge != "":
            print(f'BACKEDGE: {self.back_edge} ', end='')
        print(f'RET: {self.return_addr} INVs:')
        for i in self.invocations:
            print(i)
    
    # no idea what this does:    
    def search_for_addr(self, addr):
        for i in range(len(self.variables)-1, -1, -1):
            if addr == self.variables[i].abs_addr:
                return self.variables[i].val
        return None

    def check_eq(self, other):
        if self.pc != other.pc:
            return False
        
        if self.transition.transition_type != other.transition.transition_type:
            return False
        
        if self.transition.transition_type == cc.J_CALL and self.transition.dest_pc != other.transition.dest_pc:
            if type(other.transition.dest_pc) == type(self.transition.dest_pc):
                return False
            elif type(other.transition.dest_pc) == int and type(self.transition.dest_pc) == list and not other.transition.dest_pc in self.transition.dest_pc:
                return False
            elif type(other.transition.dest_pc) == list and type(self.transition.dest_pc) == int and not self.transition.dest_pc in other.transition.dest_pc:
                return False
        
        v0 = len(self.variables)
        v1 = len(other.variables)
        if v0 != v1: 
            if v0 == 0 or v1 == 0:
                return False
            if not self.variables[0].pc == other.variables[0].pc or not self.variables[0].name == other.variables[0].name:
                return False
            if v0 > 1 and v1 > 1 and not self.variables[1].pc == other.variables[1].pc:
                return False
        

        return True

    def lookup_by_name(self, name, op):
        if op[0] == cc.STORE_OP:
            return [v.abs_addr for v in self.variables if v.name.split('-')[0] == name][0]
        else:
            l =  [v.val for v in self.variables if v.name.split('-')[0] == name]
            if len(l) > 0:
                return l[0]
            return []

    # hy2: name_store is only filled for some models (build_name_store is not
    # always called), so fall back to searching the variables by name, and
    # return None (not self) when the name is not found. ex is accepted for
    # the callers that pass it (checker trace_back, results_post_processor).
    def find_var(self, name):
        if name in self.name_store:
            return self.variables[self.name_store[name]]
        for v in self.variables:
            if v.name == name:
                return v
        return None

    def lookup_name(self, name, ex=False):
        if type(name) == str and "i-" in name:
            if len(self.invocations) == 0:
                return self.transition
            return self.invocations[int(name.replace('i-', ''))]
        if type(name) == str and 'c-' in name:
            lv = self.transition.linked_var
            if lv == "":
                if self.variables[-1].name[0] == 'c':
                    return self.variables[-1]
                return None
            v = self.find_var(lv)
            return v

        return self.find_var(name)

    # check against action in specifications
    def check_action(self, sid, action, vars, conds, var_table):
        matches = []
        if action == "CALLRET":
            if self.transition.transition_type == "Ijk_Ret" or (self.transition.transition_type == "Ijk_Boring" and len(self.invocations) > 0):
                var_match = True
                var_table_tmp = {}
                for v0, v1 in vars.items():
                    if v0 == "fname":
                        var_table_tmp[v1] = self.fname
                    else:
                        var_match = False
                if var_match:
                    matches += do_check_cond(conds, var_table, var_table_tmp, sid, (self.id, self.pc))
        
        elif action == "CALL":
            if self.transition.transition_type == "Ijk_Call":
                var_match = True
                var_table_tmp = {}
                for v0, v1 in vars.items():
                    if v0 == "call.fname":
                        var_table_tmp[v1] = self.transition.dest
                    elif v0 == "call.args":
                        arg_labels = []
                        for v in self.variables:
                            if "arg" in v.dintent and len(v.vec) == 3 and type(v.vec[-1]) == str and v.vec[-1][0] == 't':
                                    base_var = v.vec[-1]
                                    bvar = self.lookup_name(base_var)
                                    #print(var)
                                    if bvar != None:
                                        arg_labels += bvar.label
                        if arg_labels == []:
                            var_match = False
                            break
                        var_table_tmp[v1] = arg_labels
                    else:
                        var_match = False
                        break
                
                if var_match:
                    matches += do_check_cond(conds, var_table, var_table_tmp, sid, (self.id, self.pc))
        
        elif action in ["LOAD", "STORE", "VAR"]:
            #print("debug")
            print(self.fname)
            new_op = translate_load_store(action)
            for v in self.variables:
                if v.vec[0] in new_op:
                    var_match = True
                    var_table_tmp = {}
                    for v0, v1 in vars.items():
                        if v0 == "name":
                            var_table_tmp[v1] = v.name
                        elif v0 == "tid":
                            var_table_tmp[v1] = self.tid
                        elif v0 == "val":
                            var_table_tmp[v1] = v.val
                        elif v0 == "lsv":
                            var_table_tmp[v1] = v.lsv
                        elif v0 == "dtype" and v.dtype != "":
                            var_table_tmp[v1] = v.dtype
                        elif v0 == "dsource":
                            var_table_tmp[v1] = v.dsource
                        elif v0 == "ls.dsource" and v.dsource != '':
                            if v.vec[0] == 'St' or v.vec[0] == 'StLD':  
                                rs_idx =  v.vec.index('D1', 2)
                            else:
                                rs_idx = len(v.vec)

                            if 'rax' in v.vec[:rs_idx]:
                                var_table_tmp[v1] = v.dsource.replace('ret ', '')
                            else:
                                dep = [v0 for v0 in v.vec[:rs_idx] if type(v0) == str and v0[0] == 't']
                                ls_dsrc = []
                                for d in dep:
                                    dvar = self.lookup_name(d)
                                    if dvar != None and dvar.dsource != '':
                                        ls_dsrc += [dvar.dsource.replace('ret ', '')]
                                if ls_dsrc != []:
                                    var_table_tmp[v1] = ls_dsrc
                                else:
                                    var_match = False
                                    break
                        elif v0 == "addr" and type(v.abs_addr) != list:
                            var_table_tmp[v1] = v.abs_addr                               
                        elif v0 == "addr" and len(v.abs_addr) > 0:
                            var_table_tmp[v1] = v.abs_addr
                        elif v0 == "base.label":
                            print(v.vec)
                            if len(v.vec) > 5 and v.vec[3] == "D2" and type(v.vec[4]) != int and v.vec[4][0] == "t":
                                #var_table_tmp[v1] = [v.dvec[i][4] for i in range(len(v.dvec))]
                                base_var = v.vec[4]
                                bvar = self.lookup_name(base_var)
                                #print(var)
                                if bvar != None:
                                    var_table_tmp[v1] = bvar.label
                            else:
                                # TODO: Finsh Me!
                                print("TO DO! Finish ME!")
                                print(v.vec)
                                var_match = False
                        elif v0 == "base":
                            #print(v.label)
                            print(v.vec)
                            if len(v.vec) > 5 and v.vec[3] == "D2" and type(v.vec[4]) != int and v.vec[4][0] == "t":
                                base_var = v.vec[4]
                                var_table_tmp[v1] = self.lookup_by_name(base_var, action)
                                assert var_table_tmp[v1] != None
                            
                            elif len(v.vec) > 7 and v.vec[3] == 'D2' and v.vec[4] == 'GET' and type(v.vec[5]) == str:
                                if v.vec[0] == 'LD' and len(v.vec) == 9 and v.vec[2] == "Add" and v.vec[7] == "D2" and type(v.vec[8]) == int:
                                    voffset = v.vec[8]
                                    vaddr = sanit_list(v.abs_addr)
                                    vbase = [vaddr[i] - voffset for i in range(len(vaddr))]
                                    var_table_tmp[v1] = vbase
                                    assert var_table_tmp[v1] != None

                                elif v.vec[0] == 'LD' and len(v.vec) > 8 and v.vec[2] == "Add":
                                    # TODO: Finish Me!
                                    print(v.vec)
                                    #raise Exception()
                                    print("TO DO: Fix Me!")
                                    var_match = False
                                    
                                else:
                                    base_var = v.vec[6]
                                    rv = self.lookup_by_name(base_var, action)
                                    if not rv == []:
                                        var_table_tmp[v1] = rv
                                        assert var_table_tmp[v1] != None
                            

                            elif "n" in var_table and "addr" in var_table and (type(v.abs_addr) != list or len(v.abs_addr) > 0) and len(v.vec) >= 7:
                                if type(v.abs_addr) == vart.VInst:
                                    aa = sanit_list([v.abs_addr.v])
                                else:
                                    aa = sanit_list(v.abs_addr)
                                vta = sanit_list(var_table['addr'])
                                vtn = sanit_list(var_table['n'])

                                if len(aa) > 0 and len(vta) > 0 and len(vtn) > 0 and any((vtai > aai and vtai + vtni < aai) for aai,vtai,vtni in itertools.product(*[aa,vta,vtn])):
                                    var_table_tmp[v1] = var_table['addr']
                            if not v1 in var_table_tmp:
                                #print(self.id)
                                #print(v.raw_str)
                                #print(v.abs_addr)
                                #print('missing base')
                                var_match = False
                        elif v0 == "is_invariant":
                            var_table_tmp[v1] = v.is_invariant
                        elif v0 in ["vlabel", "label"]:
                            var_table_tmp[v1] = v.label
                        elif v0 == "size":
                            var_table_tmp[v1] = v.getSize()
                        elif v0 in ["ls.lhs", "ls.ls"] and len(v.vec) > 3:
                            if v.vec[3] == 'D2' and type(v.vec[4]) == str and v.vec[4][0] == 't':
                                base_var = v.vec[4]
                                bvar = self.lookup_name(base_var)
                                #print(var)
                                if bvar != None:
                                    var_table_tmp[v1] = bvar.label
                            if not v1 in var_table_tmp:
                                #print('missing ptr')
                                var_match = False

                        elif v0 in ["ls.rhs", "ls.rs"] and len(v.vec) > 6:
                            if v.vec[3] == 'D2' and 'D2' in v.vec[4:]:
                                d2_idx = v.vec[4:].index('D2')
                                adj_idx = 4+d2_idx
                                vd2 = v.vec[adj_idx+1]
                                if type(vd2) == int:
                                    var_table_tmp[v1] = vd2
                                elif type(vd2) == str and vd2[0] == 't' and (len(v.vec) == adj_idx+2 or v.vec[adj_idx+2] == 'D1'):
                                    # TO DO: Check this!
                                    base_var = vd2
                                    bvar = self.lookup_name(base_var)
                                    #print(var)
                                    if bvar != None:
                                        var_table_tmp[v1] = bvar.label
                                else:
                                    if 'D1' in v.vec[2:]:
                                        rhs_idx = v.vec[2:].index('D1')
                                        var_table_tmp[v1] = VariantOp(v.vec[adj_idx+1:rhs_idx+2])
                                    else:
                                        var_table_tmp[v1] = VariantOp(v.vec[adj_idx+1:])
                            else:
                                var_match = False
                        elif v0  in ["ls.rhs.dsource", "ls.rs.dsource", "offset.dsource"] and len(v.vec) > 6:
                            raise Exception("TO DO: Not Implemented")

                        elif v0 in ["ls.rhs.is_invariant", "ls.rs.is_invariant"] and len(v.vec) > 6:
                            tmp = [x[6] for x in v.dvec if x[5] == "D2" and (type(x[6]) == int or x[6][0] == 't' or x[6] != v.vec[6])]
                            if tmp == []:
                                var_table_tmp[v1] = True
                            else:
                                bchk = [type(t) == int for t in tmp]
                                assert(len(list(set(bchk))) == 1)
                                var_table_tmp[v1] = bchk[0]
                                print('>> DEBUG')
                                print(v.name)
                                print(v.vec[6])
                                print(var_table_tmp[v1])
                                if not var_table_tmp[v1] and v.vec[5] == "D2" and v.vec[6][0] == 't':
                                    print('DEBUG2')
                                    tvar = v.vec[6]
                                    print(tvar)
                                    var = self.lookup_name(tvar)
                                    #print(var)
                                    if var != None and var.is_invariant:
                                        var_table_tmp[v1] = True
                        
                        elif v0 == "ls.op":
                            var_table_tmp[v1] = v.vec[2]
                        elif v0 == "rs.size":
                            var_table_tmp[v1] = v.getSize()
                        elif v0 == "rs.op":
                            rs_idx = v.vec[2:].index("D1")
                            rs_op = v.vec[2:][rs_idx+1]
                            var_table_tmp[v1] = rs_op
                        elif v0 == "rs.ls.dsource":
                            rs_idx = v.vec[2:].index("D1")
                            rs_vec = v.vec[2:][rs_idx:]
                            rs_vars = [rsi for rsi in rs_vec if type(rsi) == str and rsi[0]=='t']
                            rsvd = []
                            if len(rs_vars) > 0:
                                for rsv in rs_vars:
                                    rsv0 = self.lookup_name(rsv)
                                    if rsv0 != None and rsv0.dsource != '':
                                        rsvd += [rsv0.dsource.replace('ret ', '')]
                                if rsvd != []:
                                    var_table_tmp[v1] = list(set(rsvd))
                                else:
                                    var_match = False
                            else:
                                var_match = False
                        elif v0 in ["rs.ls", "rs.lhs"] and len(v.vec) > 2:
                            rs = v.vec[v.vec.index('D1', 2)+1:]
                            if len(rs) < 2 or not rs[1] == 'D2' or not 'D2' in rs[2:]:
                                var_match = False
                            else:
                                rs_idx = rs.index('D2', 2)
                                var_table_tmp[v1] = rs[3:rs_idx]
                        elif v0 in ["rs.rs", "rs.rhs"] and len(v.vec) > 2:
                            rs = v.vec[v.vec.index('D1', 2)+1:]
                            if len(rs) < 2 or not rs[1] == 'D2' or not 'D2' in rs[2:]:
                                var_match = False
                            else:
                                rs_idx = rs.index('D2', 2)
                                var_table_tmp[v1] = rs[3:rs_idx]
                        elif v0 in ["rs.rs.is_invariant", "rs.rhs.is_invariant"]:
                            if v.vec[-2] == "D2":
                                rs_rs = v.vec[-1]
                                var_table_tmp[v1] = (type(rs_rs) == int)
                            else:
                                var_table_tmp[v1] = False
                        else:
                            var_match = False
                    
                    if var_match:
                        #print(var_table)
                        #print(var_table_tmp)
                        #if action == 'STORE':
                        #    print(v.vec)
                        #    print(var_table)
                        #    print(var_table_tmp)
                        
                        matches += do_check_cond(conds, var_table, var_table_tmp, sid, (v.name.split("-")[0], v.pc))
                        
                        #print(matches)
                        """
                        if len(conds) == 0:
                            m.append((sid, v.name.split("-")[0], var_table_tmp, 0))
                        else:
                            print(Fore.YELLOW + "[DEBUG]:" + Fore.RESET)
                            print(v.raw_str)
                            print(var_table_tmp)
                            print(var_table)
                            #print(var_table_tmp)
                            cond_match = check_cond(conds, var_table, var_table_tmp)
                            if cond_match:
                                m.append((sid, v.name.split("-")[0], var_table_tmp, 0))
                        """

        elif action == "Put" or action == "PUT" or action == "VAR*":
            for v in self.variables:
                if v.vec[0] == "Put" or (action == "VAR*" and v.vec[0] in ["Put", "LD", "St"]):
                    var_match = True
                    var_table_tmp = {}
                    print(v.vec)
                    for v0, v1 in vars.items():
                        if v0 == 'deps':
                            vd = [vo for vo in v.vec if type(vo) == str and vo[0] == 't']
                            if vd == []:
                                var_match = False
                                break
                            var_table_tmp[v1] = vd
                        elif v0 == "var.name":
                            var_table_tmp[v1] = v.name
                        elif v0 == "val":
                            var_table_tmp[v1] = v.val
                        # hy2 addition (from the refactor, used by properties/json):
                        elif v0 == 'dtype.size':
                            var_table_tmp[v1] = v.getSize()
                        elif v0 == "has_tvar":
                            var_table_tmp[v1] = v.has_tvar
                        elif v0 == "tvar_dsource" and v.has_tvar:
                            var_table_tmp[v1] = v.tvar_dsource
                        elif v0 == "tvar_dintent" and v.has_tvar:
                            var_table_tmp[v1] = v.tvar_dintent
                        elif v0 == "ls.op" and len(v.vec) > 4 and v.vec[3] == 'D2':
                            var_table_tmp[v1] = v.vec[2]
                        elif v0 == "ls.lhs" and len(v.vec) > 4 and v.vec[3] == 'D2':
                            if 'D2' in v.vec[4:]:
                                rs_idx = v.vec.index('D2', 4)
                                var_table_tmp[v1] = VariantOp(v.vec[4:rs_idx])
                            else:
                                var_table_tmp[v1] = v.vec[4:]
                        elif v0 == "ls.rhs" and len(v.vec) > 4 and v.vec[3] == 'D2' and 'D2' in v.vec[4:]:
                            var_table_tmp[v1] = VariantOp(v.vec[v.vec.index('D2',4)+1:])
                        elif v0 == "dintent" and v.dintent != "":
                            var_table_tmp[v1] = v.dintent
                        elif v0 == "dsource"  and v.dsource != "":
                            var_table_tmp[v1] = v.dsource
                        elif v0 == "label":
                            deps = [v0 for v0 in v.vec if type(v0) == str and v0[0] == 't']
                            dlabels = []
                            for d in deps:
                                dvar = self.lookup_name(d)
                                if dvar != None:
                                    dlabels += dvar.label
                            if dlabels != []:
                                var_table_tmp[v1] = dlabels
                        else:
                            var_match = False
                    
                    if var_match:
                        """
                        if len(conds) == 0:
                            m.append((sid, v.name.split("-")[0], var_table_tmp, 0))
                        else:
                            cond_match = check_cond(conds, var_table, var_table_tmp)
                            if cond_match:
                                m.append((sid, v.name.split("-")[0], var_table_tmp, 0))
                        """
                        matches += do_check_cond(conds, var_table, var_table_tmp, sid, (v.name.split("-")[0], v.pc))
                        
        
        elif action == "RET":
            for v in self.variables:
                if v.dsource[:3] == "ret":
                    returned_from = v.dsource.split(' ')[1]

                    var_match = True
                    var_table_tmp = {}
                    for v0, v1 in vars.items():
                        if v0 == "var.name":
                            var_table_tmp[v1] = v.name
                        elif v0 == "addr" and v.abs_addr != "":
                            var_table_tmp[v1] = v.abs_addr
                        elif v0 == "val":
                            var_table_tmp[v1] = v.val
                        elif v0 in ["vlabel", "label"]:
                            var_table_tmp[v1] = [x[0] for x in v.dvec if x[0] != v.vec[0]]
                            if len(var_table_tmp[v1]) == 0:
                                var_table_tmp[v1] = v.label
                        elif v0 == "ret.fname":
                            #print(returned_from)
                            #print(var_table)
                            var_table_tmp[v1] = returned_from
                        else:
                            var_match = False
                            break
                    
                    if var_match:
                        """
                        if len(conds) == 0:
                            m.append((sid, v.name.split("-")[0], var_table_tmp, 0))
                        else:
                            cond_match = check_cond(conds, var_table, var_table_tmp)
                            if cond_match:
                                #print(var_table_tmp)
                                m.append((sid, v.name.split("-")[0], var_table_tmp, 0))
                        """
                        #print(var_table_tmp)
                        #print(var_table)
                        
                        matches += do_check_cond(conds, var_table, var_table_tmp, sid, (v.name.split("-")[0], v.pc))
                        #if len(matches) > 0:
                        #    print(self.id)
                        #print(matches)

        elif action == "COND":
            print('debug')
            if type(self.transition) == CConditionalTransition:
                #print(self)
                var_match = True
                var_table_tmp = {}
                # hy2: linked_var is never set by the model builder, so use the
                # lookup_name("c-") fallback (last variable, if it is the condition)
                v = self.lookup_name("c-")
                if v == None:
                    var_match = False
                else:
                    for v0, v1 in vars.items():
                        if v0  == "op":
                            var_table_tmp[v1] = v.vec[0]
                        elif v0 == "tid":
                            var_table_tmp[v1] = self.tid
                        elif v0 == "rs.val" and v.vec[-2] == "D1" and type(v.vec[-1]) == int:
                            var_table_tmp[v1] = v.vec[-1]
                        elif v0 == "ls.var" and v.vec[1] == "D1":
                            var_table_tmp[v1] = v.vec[2]
                        elif v0 == "lsv":
                            if v.vec[1] == 'D1' and type(v.vec[2]) == str and v.vec[2][0] == 't':
                                base_var = v.vec[2]
                                bvar = self.lookup_name(base_var)
                                #print(var)
                                if bvar != None:
                                    var_table_tmp[v1] = bvar.val

                            if not v1 in var_table_tmp:
                                #print('missing ptr')
                                var_match = False
                        elif v0 == "dsource":
                            if v.dsource[:3] == "ret":
                                var_table_tmp[v1] = v.dsource.split(' ')[1]
                            else:
                                var_table_tmp[v1] = v.dsource
                        # hy2 additions (from the refactor, used by properties/json):
                        elif v0 == "ls.label":
                            ls_var = v.getLS()
                            ls_t = [x for x in ls_var if type(x) == str and x[0]=='t']
                            if ls_t == []:
                                var_match = False
                                break
                            assert len(ls_t) == 1
                            lsv = self.lookup_name(ls_t[0])
                            if lsv != None:
                                var_table_tmp[v1] = lsv.label
                        elif v0 == "rs.label":
                            rs_var = v.getRS()
                            rs_t = [x for x in rs_var if type(x) == str and x[0]=='t']
                            if rs_t == []:
                                var_match = False
                                break
                            assert len(rs_t) == 1
                            rsv = self.lookup_name(rs_t[0])
                            if rsv != None:
                                var_table_tmp[v1] = rsv.label
                        else:
                            var_match = False

                if var_match:
                    """
                    if len(conds) == 0:
                        m.append((sid, f"c-{self.id}", var_table_tmp, 0))
                    else:
                        if check_cond(conds, var_table, var_table_tmp):
                            m.append((sid, f"c-{self.id}", var_table_tmp,  0))
                    """
                    #print(self)
                    matches += do_check_cond(conds, var_table, var_table_tmp, sid, (f'c-{self.id}', self.pc))
        
        else:
            if self.root_invocation.replace('sym.imp.', '') == action:
                var_match = True
                var_table_tmp = {}
                for v0, v1 in vars.items():
                    vidx = to_int(v0)
                    if v0 == "fname":
                        var_table_tmp[v1] = self.root_invocation.replace('sym.imp.', '')
                    else:
                        # TO DO: Implement Me! (hy2: was a raise, which aborted every remaining rule;
                        # the invocations below still handle argument indices)
                        var_match = False
                        break
                if var_match:
                    matches += do_check_cond(conds, var_table, var_table_tmp, sid, (f'i-0', self.pc))
            
            if self.transition.transition_type == "Ijk_Call" and len(self.transition.dest) > 0:
                inv_prefix = "sym.imp."
                if all([d[:3] == 'sym.' and not 'sym.imp.' in d for d in self.transition.dest]):
                    inv_prefix = 'sym.'
                
                if all([d.replace(inv_prefix, '') == action for d in self.transition.dest]):
                    var_match = True
                    var_table_tmp = {}
                    for v0, v1 in vars.items():
                        vidx = to_int(v0)
                        if v0 == "fname":
                            var_table_tmp[v1] = self.transition.dest[0]
                        else:
                            # TO DO: Implement Me! (hy2: was a raise, which aborted every remaining rule;
                            # the invocations below still handle argument indices)
                            var_match = False
                            break
                    if var_match:
                        matches += do_check_cond(conds, var_table, var_table_tmp, sid, (f'i-0', self.pc))
            
            if len(self.invocations) > 0:
                i = 0
                for x in self.invocations:
                    #print(x.name.split('-')[-1].replace("b'","")[:-1])
                    xname = x.name.split('-')[-1].replace("b'", "").replace("'", "")
                    if x.name == action or xname == action:
                        #print(x.name.split('-')[-1].replace("b'",""))
                        var_match = True
                        var_table_tmp = {}
                        for v0, v1 in vars.items():
                            vidx = to_int(v0)
                            if v0 == "fname":
                                #var_table_tmp[v1] = self.fname
                                var_table_tmp[v1] = x.name
                            elif type(vidx) == int and len(x.args) > vidx:
                                # FIXME: Refactor
                                var_table_tmp[v1] = x.args[vidx]
                            else:
                                var_match = False
                                break
                        if var_match:
                            """
                            if len(conds) == 0:
                                m.append((sid, f'i-{i}', var_table_tmp,  0))
                            else:
                                if check_cond(conds, var_table, var_table_tmp):
                                    m.append((sid, f'i-{i}', var_table_tmp,  0))
                            """
                            matches += do_check_cond(conds, var_table, var_table_tmp, sid, (f'i-{i}', self.pc))
                        
                    i+=1
        #print(m)
        #print("RET")
        return matches

    # check against action, where multiple actions are accepted
    def check_aliases(self, sid, aliases, vars, conds, var_table):
        matches = []
        if self.root_invocation.replace('sym.imp.', '') in aliases:
            xname = self.root_invocation.replace('sym.imp.', '')
            print(xname)
            mcall = aliases[xname]
            var_match = True
            var_table_tmp = {}
            if len(list(vars.keys())) == 1 and "fname" in vars:
                var_table_tmp[vars['fname']] = self.root_invocation
            else:
                for v0, v1 in vars.items():
                    if v0 == "fname":
                        var_table_tmp[v1] = self.root_invocation
                        continue
                    attr = None
                    arg_idx = -1
                    if "." in v0:
                        p = v0.split(".")
                        arg_idx = int(mcall[p[0]])
                        attr = p[1]
                    else:
                        if v0 in mcall:
                            arg_idx = int(mcall[v0])
                        else:
                            arg_idx = int(v0)-1
                
                    if arg_idx == -1:
                        var_match = False
                        break

                    iarg = f'iarg{arg_idx+1}'
                    for v in self.variables:
                        if v.dintent != "" and v.dintent == iarg:
                            if attr == None:
                                if type(v.val) == vart.VEmpty and type(v.vec[-1]) == str and v.vec[-1][0] == 't':
                                    dv = v.vec[-1]
                                    bvar = self.lookup_name(dv)
                                    if bvar != None:
                                        var_table_tmp[v1] = bvar.val
                                
                                else:
                                    var_table_tmp[v1] = v.val
                            else:
                                if attr == "label":
                                    if len(v.vec) == 3 and type(v.vec[-1]) == str and v.vec[-1][0] == 't':
                                        base_var = v.vec[-1]
                                        bvar = self.lookup_name(base_var)
                                        if bvar != None:
                                            var_table_tmp[v1] = bvar.label
                                    elif len(v.label) > 0:
                                        var_table_tmp[v1] = v.label
                                    #if not v1 in var_table_tmp:
                                    #    var_match = False
                                    #    break
                                elif attr == "dep":
                                    deps = [vx for vx in v.vec if type(vx) == str and vx[0] == 't']
                                    if not deps == []:
                                        var_table_tmp[v1] = deps
                                elif attr == "ls.op":
                                    var_table_tmp[v1] = v.vec[2]
                                elif attr == "dsource":
                                    deps = [vx for vx in v.vec if type(vx) == str and vx[0] == 't']
                                    dsrc = []
                                    for d in deps:
                                        dvar = self.lookup_name(d)
                                        if dvar != None and dvar.dsource != "":
                                            dsrc += [dvar.dsource.replace('ret ', '')]
                                        if dsrc != []:
                                            var_table_tmp[v1] = dsrc
                                elif attr == "size":
                                    var_table_tmp[v1] = v.getSize()
                                elif attr == "val":
                                    var_table_tmp[v1] = v.val
                                elif attr == "addr":
                                    var_table_tmp[v1] = v.abs_addr
                                elif attr == "is_invariant":
                                    var_table_tmp[v1] = v.is_invariant
                                else:
                                    var_match = False
                                    break
                    
                    if not v1 in var_table_tmp:
                        print(v1)
                        var_match = False
                        break
            if var_match:
                matches += do_check_cond(conds, var_table, var_table_tmp, sid, ("i-0", self.pc))

        if self.fname in aliases or self.fname.replace('sym.imp.', '') in aliases and len(self.invocations) > 0:
            var_match = True
            var_table_tmp = {}
            # TO DO: FIX ME, this won't work when there are exclusions, and the calls are in the wrong order:
            x = self.invocations[0]
            if self.fname in aliases:
                mcall = aliases[self.fname]
            else:
                mcall = aliases[self.fname.replace('sym.imp.', '')]
            #print(self.fname)
            for v0, v1 in vars.items():
                vidx = to_int(v0)
                if type(vidx) == int and len(x.args) > vidx:
                    var_table_tmp[v1] = x.args[vidx]
                elif v0 in mcall and mcall[v0] != 'ret':
                    var_idx = int(mcall[v0])
                    if len(x.args) > var_idx:
                        # FIXME: Refactor
                        var_table_tmp[v1] = x.args[var_idx]
                        assert var_table_tmp[v1] != None
                    else:
                        var_match = False
                        break
                elif v0 == "fname":
                    var_table_tmp[v1] = self.fname
                else:
                    var_match = False
                    break
            if var_match:
                """
                if len(conds) == 0:
                    m.append((sid, f'i-0', var_table_tmp,  0))
                else:
                    #print(var_table_tmp)
                    if check_cond(conds, var_table, var_table_tmp):
                        m.append((sid, f'i-0', var_table_tmp,  0))
                """
                matches += do_check_cond(conds, var_table, var_table_tmp, sid, ('i-0', self.pc))
            #return m
        i=0
        for x in self.invocations:
            #if 'set' in x.name:
            #    print(x.name)
            #print(x.name.split('-')[-1].replace("b'", "").replace("'", "")  in aliases)
            if x.name in aliases or x.name.split('-')[-1].replace("b'", "").replace("'", "") in aliases:
                xname = x.name.split('-')[-1].replace("b'", "").replace("'", "")
                print(xname)
                #if 'open' in xname:
                #    print(self)
                mcall = aliases[xname]
                var_match = True
                var_table_tmp = {}
                for v0, v1 in vars.items():
                    if v0 == "fname":
                        var_table_tmp[v1] = x.name
                    #elif ".label" in v0:
                    #    var_table_tmp[v1] = ""
                    elif ".is_invariant" in v0:
                        var_table_tmp[v1] = False
                    elif v0 in mcall and mcall[v0] != "ret":
                        var_idx = int(mcall[v0])
                        if len(x.args) > var_idx:
                            # FIXME: Refactor
                            var_table_tmp[v1] = x.args[var_idx]
                            assert var_table_tmp[v1] != None
                        else:
                            var_match = False
                    #elif v0.split(".")[0] in mcall:
                    #    var_idx = int(mcall[v0.split('.')[0]])
                    #    if len(x.args) > var_idx:
                    #        # FIXME: Refactor
                    #        var_table_tmp[v1] = x.args[var_idx]
                    #        assert var_table_tmp[v1] != None
                    #    else:
                    #        var_match = False
                    else:
                        var_match = False
                if var_match:
                    """"
                    if len(conds) == 0:
                        m.append((sid, f'i-{i}', var_table_tmp,  0))
                    else:
                        cond_match = check_cond(conds, var_table, var_table_tmp)
                        #print(var_table_tmp)
                        if cond_match:
                            m.append((sid, f'i-{i}', var_table_tmp,  0))
                    """
                    matches += do_check_cond(conds, var_table, var_table_tmp, sid, (f'i-{i}', self.pc))
            i+=1
        
        inv_prefix = 'sym.imp.'
        if all([d[:3] == 'sym.imp.' and not 'sym.imp.' in d for d in self.transition.dest]):
            inv_prefix = 'sym.'
        if  self.transition.transition_type == 'Ijk_Call' and len(self.transition.dest) > 0 and all([d.replace(inv_prefix, '') in aliases for d in self.transition.dest]):
            print(self.transition.dest)
            xname = self.transition.dest[0].replace(inv_prefix, '')
            #print("HERE")
            #x.name.split('-')[-1].replace("b'", "").replace("'", "")
            #print(xname)
            #print(self)
            mcall = aliases[xname]
            var_match = True
            var_table_tmp = {}
            if len(list(vars.keys())) == 1 and "fname" in vars:
                var_table_tmp[vars['fname']] = self.transition.dest[0]
            else:
                var_table_tmp = {}
                for v0, v1 in vars.items():
                    if v0 == "fname":
                        var_table_tmp[v1] = self.transition.dest[0]
                        continue
                    attr = None
                    arg_idx = -1
                    if "." in v0:
                        p = v0.split(".")
                        arg_idx = int(mcall[p[0]])
                        attr = p[1]
                    else:
                        if v0 in mcall:
                            arg_idx = int(mcall[v0])
                        else:
                            arg_idx = int(v0)-1
                    if arg_idx == -1:
                        var_match = False
                        break
                    iarg = f'iarg{arg_idx+1}'
                    #print(iarg)
                    for v in self.variables:
                        if v.dintent != "" and v.dintent == iarg:
                            if attr == None:
                                #print(v.val)
                                #print(v.vec)
                                if type(v.val) == vart.VEmpty and type(v.vec[-1]) == str and v.vec[-1][0] == 't':
                                    dv = v.vec[-1]
                                    bvar = self.lookup_name(dv)
                                    #print(var)
                                    if bvar != None:
                                        var_table_tmp[v1] = bvar.val
                                else:
                                    var_table_tmp[v1] = v.val
                                assert var_table_tmp[v1] != None
                            else:

                                if attr == "label":
                                    if len(v.vec) == 3 and type(v.vec[-1]) == str and v.vec[-1][0] == 't':
                                        base_var = v.vec[-1]
                                        bvar = self.lookup_name(base_var)
                                        #print(var)
                                        if bvar != None:
                                            var_table_tmp[v1] = bvar.label
                                    elif len(v.label) > 0:
                                        var_table_tmp[v1] = v.label
                                    """
                                    if len(v.dvec) > 0:
                                        #print(v.dvec)
                                        var_table_tmp[v1] = [x[0] for x in v.dvec if x[0] != v.vec[0]]
                                        if len(var_table_tmp[v1]) == 0 and len(v.vec) == 3 and type(v.vec[-1]) == int:
                                            var_table_tmp[v1] = v.vec[-1]
                                        elif len(var_table_tmp[v1]) == 0:
                                            var_table_tmp[v1] = [x[2] for x in v.dvec if len(x) == 3 and x[0] == "Put" and x[1] == "D1" and x[2][0] == 'v']
                                            if len(var_table_tmp[v1]) == 0:
                                                var_table_tmp[v1] = f'{v.name}-{sid}'
                                        
                                    else:
                                        var_table_tmp[v1] = f'{v.name}-{sid}'
                                    """
                                elif attr == "dep":
                                    deps = [v0 for v0 in v.vec if type(v0) == str and v0[0] == 't']
                                    if not deps == []:
                                        var_table_tmp[v1] = deps
                                elif attr == "ls.op":
                                    var_table_tmp[v1] = v.vec[2]
                                elif attr == "dsource":
                                    deps = [v0 for v0 in v.vec if type(v0) == str and v0[0] == 't']
                                    dsrc = []
                                    for d in deps:
                                        dvar = self.lookup_name(d)
                                        if dvar != None and dvar.dsource != "":
                                            dsrc += [dvar.dsource.replace('ret ', '')]
                                    if dsrc != []:
                                        var_table_tmp[v1] = dsrc
                                
                                elif attr == "size":
                                    var_table_tmp[v1] = v.getSize()
                                elif attr == "val":
                                    var_table_tmp[v1] = v.val
                                elif attr == "addr":
                                    var_table_tmp[v1] = v.abs_addr
                                elif attr == "is_invariant":
                                    var_table_tmp[v1] = v.is_invariant
                                else:
                                    var_match = False
                                    break
                    if not v1 in var_table_tmp:
                        print(f'MISSING: {v1}')
                        var_match = False
                        break                
            if var_match:
                #print(var_table)
                #print(var_table_tmp)
                #print(self)
                #print('checking')
                matches += do_check_cond(conds, var_table, var_table_tmp, sid, ("i-0", self.pc))
        #print(m)
        #print(matches)
        return matches
    
    # Calls check_action, check_aliases
    def check_against_state(self, sid, actions, vars, conds, var_table):
        if type(actions) == str and actions == "LOOP":
            if check_cond(conds, var_table, {"pc": self.pc}):
                return [(sid, self.fname, {"pc": self.pc}, 0)]
            else:
                return []
        elif type(actions) == str and actions == "RETURN":
            if self.transition.transition_type == "Ijk_Ret":
                if check_cond(conds, var_table, {vars["fname"]: self.fname}):
                    return [(sid, self.fname, {vars["fname"]: self.fname}, 0)]
                else:
                    return []
            else:
                return []
        # hy2 additions (from the refactor, used by properties/json):
        elif type(actions) == str and actions == "LOOPHEADER":
            return self.check_loopheader(sid, vars, conds, var_table)
        elif type(actions) == str and actions == "EDGE":
            return self.check_edge(sid, vars, conds, var_table)
        elif type(actions) == str:
            return self.check_action(sid, actions, vars, conds, var_table)
        else:
            return self.check_aliases(sid, actions, vars, conds, var_table)

    def check_loopheader(self, sid, vars, conds, var_table):
        if self.back_edge == "":
            return []
        matches = []
       
        var_match = True
        var_table_tmp = {}
        for v0, v1 in vars.items():
            if v0 == "pc":
                var_table_tmp[v1] = self.pc
            elif v0 == "fname":
                var_table_tmp[v1] = self.fname
            else:
                print('DEBUG: ' + v0)
                var_match = False
                break

        if var_match:
            matches += do_check_cond(conds, var_table, var_table_tmp, sid, (self.id, self.pc))
        return matches
    
    def check_edge(self, sid, vars, conds, var_table):
        matches = []
       
        var_match = True
        var_table_tmp = {}
        for v0, v1 in vars.items():
            if v0 == "pc":
                var_table_tmp[v1] = self.pc
            elif v0 == "fname":
                var_table_tmp[v1] = self.fname
            elif v0 == "jmp.dest":
                var_table_tmp[v1] = self.transition.dest_pc
            else:
                print('DEBUG: ' + v0)
                var_match = False
                break

        if var_match:
            matches += do_check_cond(conds, var_table, var_table_tmp, sid, (self.id, self.pc))
        return matches
    
    def build_name_store(self):
        i = 0
        for v in self.variables:
            k = v.name
            self.name_store[k] = i
            i+=1
