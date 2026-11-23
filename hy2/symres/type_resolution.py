# Gets type information from binary using r2 if available
# Specificially useful for statically allocated buffers ie. char buf[40]
import r2pipe
import json
import os

def open_r2pipe(file_name):
    try:
        r2 = r2pipe.open(file_name, flags=['-e', 'bin.verbose=false'])
        _ = r2.cmd('aaa')
        return r2
    except:
        return None

def get_ie_offset(r2):
    ie = r2.cmd("iej")
    try:
        iej = json.loads(ie)
        if len(iej) == 1:
            return iej[0]["paddr"], iej[0]["baddr"]
        elif len(iej) == 0:
            return 0
        return iej["paddr"], iej["baddr"]
    except Exception as e:
        print(e)
        print(e.with_traceback(None))
        return -1

def getFunctionList(r2):
    afl = r2.cmd('aflj')
    funcs = []
    try:
        afls = json.loads(afl)
        for f in afls:
            fname = f['name']
            if not 'sym.imp.' in fname:
                funcs.append(fname)
        return funcs
    except:
        return []

def getMetaTypes(r2):
    c = r2.cmd('Ct')
    c = c.rstrip()
    ct = c.split('\n')
    metaTypes = []
    for x in ct:
        p = x.split(' ', 1)
        metaTypes.append({'address': p[0], 'dtype': p[1]})
    return metaTypes

def getDataTypes(r2):
    ie, ba = get_ie_offset(r2)
    funcs = getFunctionList(r2)
    vars = {}
    for fn in funcs:
        _ = r2.cmd(f's {fn}')
        afv = r2.cmd('afv')
        afvx = r2.cmd('afvx')
        afvx = afvx.strip()
        fxs = afvx.split('\n')

        afv = afv.strip()
        vas = afv.split('\n')
        fvars = {}
        for v in vas:
            if v == '':
                continue
            p =  v.split('@', 1)
            var = p[0].strip()
            addr = p[1].strip()
            if var[:3] == 'var' or var[:3] == 'arg':
                var = var[4:]
                var_type = ' '.join(var.split(' ')[:-1])
                var_name = var.split(' ')[-1]
                fvars[var_name] = var_type
        
        for fx in fxs:
            fx = fx.lstrip()
            vname = fx.split(' ')[0]
            if vname in fvars:
                addrs = fx.split(' ')[-1]
                addrs = addrs.split(',')
                if len(addrs) == 1 and addrs[0] == vname:
                    continue
                for addr in addrs:
                    bbaddr = int(addr, 16)
                    bb_addr = abs(ba -  bbaddr)
                    vars[int(bb_addr)] = {'vname': vname, 'vtype': fvars[vname]}
    
    return vars

def preprocessMeta(binFile, target):
    r2 = open_r2pipe(binFile)
    m = getDataTypes(r2)
    with open(os.path.join(target, 'meta.json'), 'w') as f:
        json.dump(m, f)
    print("Done!")