# Matches blocks to symbols
# Follows the runtime defintion of blocks instead of the "static" one
# meaning that it will split blocks on call ops, and will join blocks that follow each other sequently without a jump.
import r2pipe
import json
import os
import hashlib
import signal

# Calculate md5 sum of bytestring:
def md5(buf):
    hash_md5 = hashlib.md5()
    for i in range(0, len(buf),4096):
        if i + 4096 > len(buf):
            chunk = buf[i:]
        else:
            chunk = buf[i:i+4096]
        hash_md5.update(chunk)
    return hash_md5.hexdigest()


def r2_open_pipe(file_name):
    r2 = r2pipe.open(file_name, flags=['-e', 'bin.verbose=false'])
    r2.cmd('e anal.timeout = 720')
    _ = r2.cmd('aa')
    return r2

def handler(signum, frame):
    raise Exception("r2 is hanging!")

# Get list of function names, addresses, size (bytes), and signatures in the binary:
# r2 -A -qq -c 'aflj' <bin name>
# 
# return as json indexed by offset
def get_function_names(r2):
    fl = r2.cmd("aflj")
    offset_key = "addr"
    # in older versions it was offset
    try:
        flj = json.loads(fl)
        funcs = {}
        for f in flj:
            # in newer versions offset = addr
            assert f[offset_key] not in funcs

            funcs[f[offset_key]] = {"offset": f[offset_key], "name": f["name"], "size": f["size"], "signature": f["signature"]}
        return funcs
    except Exception as e:
        print(f'ERROR: get_function_names: {e}')
        return None

def print_block(obj, p=''):
    print('--> '+p+" "+obj['func_id'])
    if type(obj["addr"]) == str:
        print(' - '+obj["addr"])
    else:
        print(' - '+(str(hex(obj["addr"]))))
    print(' - '+str(obj["size"]))

# matches anonymous function call patterns (ie. when a pointer to a function is an argument), found in some examples in cb_multios
# returns a list of addresses where call is made
def search_specific_to_cs_multios(r2):
    data = r2.cmd("/ad call rax")
    addrs = [int(x.split(" ")[0], 16) for x in data.split("\n") if x[:2] == "0x"]
    return addrs

def check_split_call(r2, xrefs, anon_calls, start_addr, size, func_id, from_addr=None):
    if from_addr == None:
        from_addr = start_addr
    in_target_block = False
    new_blocks = []
    for addr in anon_calls:
        if addr >= start_addr and addr <= (start_addr+size):
            _ = r2.cmd(f's {addr}')
            s = r2.cmd('pdl')
            saddr = s.split('\n')[0]
            if saddr == '':
                continue
            op_off = int(saddr)
            new_blocks.append(addr+op_off)
    
    for x in xrefs:
        if x["type"] == "CALL":
            if "from" in x:
                addr = x["from"]
            else:
                addr = x['at']
            if addr >= start_addr and addr <= (start_addr+size):
                _ = r2.cmd(f's {addr}')
                s = r2.cmd('pdl')
                saddr = s.split('\n')[0]
                if saddr == '':
                    continue
                op_off = int(saddr)
                new_blocks.append(addr+op_off)
    
    blocks = []
    saddr_tmp = start_addr
    tsize = 0
    end_addr = start_addr + size
    new_blocks = list(set(new_blocks))
    new_blocks.sort()
    for i in range(len(new_blocks)):
        nsize = new_blocks[i] - saddr_tmp
        assert nsize > 0
        blocks.append({"addr": saddr_tmp, "size": nsize, "func_id": func_id})
        saddr_tmp = new_blocks[i]
        tsize += nsize

    if len(new_blocks) > 0:
        if new_blocks[-1] != end_addr:
            nsize = abs(end_addr-new_blocks[-1])
            if nsize < 0:
                print(start_addr)
                print(end_addr)
                print(new_blocks)

                print(nsize)
            
            assert nsize > 0
            blocks.append({"addr": new_blocks[-1], "size": nsize, "func_id": func_id})
            tsize += nsize

    return blocks

import traceback

def get_bb_info(r2):
    #xrs = r2.cmd('axj') # <--- older versions only of r2 (<= 5.5)
    xrs = r2.cmd('axlj') # <--- newer versions
    xrj = {}
    try:
        xrj = json.loads(xrs)
    except Exception as e:
        print(f'ERROR: get_bb_info: {e}')
        return None,None

    anonymous_call_instr = search_specific_to_cs_multios(r2)

    bb = r2.cmd("ablj")
    
    conditional_branches = []
    try:
        bbj = json.loads(bb)
        blocks = []
        if "blocks" in bbj:
            bbs = bbj["blocks"]
        else:
            bbs = bbj
        
        
        for i in range(len(bbs)):
            b = bbs[i]
            func_id = "f"+("_".join(str(x) for x in b["fcns"]))
            if "fail" in b:
                conditional_branches.append(b["fail"])
                if "jump" in b:
                    conditional_branches.append(b["jump"])
            
            # What was I checking here?
            if "jump" in b and b["jump"] == int(b["addr"], 16) + b["size"] and int(bbs[i+1]["addr"],16) == b["jump"]:
                tblocks = check_split_call(r2, xrj, anonymous_call_instr, int(b["addr"],16), b["size"], func_id)
                if tblocks != []:
                    blocks +=  tblocks
                else:
                    blocks.append({"addr": b["addr"], "size": b["size"], "func_id": func_id})
                
                tblocks = check_split_call(r2, xrj, anonymous_call_instr, int(b["addr"],16), b["size"]+bbs[i+1]["size"], func_id, int(bbs[i+1]["addr"], 16))
                if tblocks != []:
                    blocks += tblocks
                else:
                    blocks.append({"addr": b["addr"], "size": b["size"]+bbs[i+1]["size"], "func_id": func_id})
                continue
            tblocks = check_split_call(r2, xrj, anonymous_call_instr, int(b["addr"],16), b["size"], func_id)
            
            if tblocks != []:
                blocks += tblocks
            else:
                blocks.append({"addr": b["addr"], "size": b["size"], "func_id": func_id})
        
        return blocks, conditional_branches
    except Exception as e:
        print(f'ERROR: get_bb_info: {e}')
        traceback.print_exc()
        return None, None

def get_function_info(r2, fname):
    cmd = f'afij {fname}'
    fi = r2.cmd(cmd)
    try:
        fij = json.loads(fi)
        if type(fij) == list:
            fij0 = fij[0]
            return {"offset": fij0["offset"], "fname": fij0["name"], "size": fij0["size"]}
        else:
            return None
    except Exception as e:
        return None

def build_symbols_for_inclusions(r2, target_bin, inclusions):
    symbols_map = []
    for inc in inclusions:
        incf = inc[0]
        sym = get_function_info(r2, incf)
        if sym == None:
            raise Exception()
        sym["pagename"] = os.path.basename(target_bin)
        symbols_map += [sym]
    
    return symbols_map


def build_block_mapping_for_function(r2, fname):
    s_cmd = f's {fname}'
    bb_cmd = 'afbj'
    r2.cmd(s_cmd)
    xrs = r2.cmd('axffj')
    xrj = {}
    try:
        xrj = json.loads(xrs)
    except Exception as e:
        print(xrs)
        print(e)
        return None
    
    anonymous_call_instr = []
    
    bbi = r2.cmd(bb_cmd)
    try:
        bbj = json.loads(bbi)
        blocks = []
        if "blocks" in bbj:
            bbs = bbj["blocks"]
        else:
            bbs = bbj

        for i in range(len(bbs)):
            b = bbs[i]
            func_id = "f"+str(b['addr'])
            
            # What was I checking here?
            if "jump" in b and b["jump"] == b["addr"] + b["size"] and bbs[i+1]["addr"] == b["jump"]:
                tblocks = check_split_call(r2, xrj, anonymous_call_instr, b["addr"], b["size"], func_id)
                if tblocks != []:
                    blocks +=  tblocks
                else:
                    blocks.append({"addr": b["addr"], "size": b["size"], "func_id": func_id})
                
                tblocks = check_split_call(r2, xrj, anonymous_call_instr, b["addr"], b["size"]+bbs[i+1]["size"], func_id, bbs[i+1]["addr"])
                if tblocks != []:
                    blocks += tblocks
                else:
                    blocks.append({"addr": b["addr"], "size": b["size"]+bbs[i+1]["size"], "func_id": func_id})
                continue
            tblocks = check_split_call(r2, xrj, anonymous_call_instr, b["addr"], b["size"], func_id)
            if tblocks != []:
                blocks += tblocks
            else:
                blocks.append({"addr": b["addr"], "size": b["size"], "func_id": func_id})
        
        return blocks
    except Exception as e:
        print(e)
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

def build_block_mapping_for_inclusions(r2, target_bin, inclusions):
    blocks = {}
    ie, ba = get_ie_offset(r2)
    print(f'ie: {ie}, ba: {ba}')

    for inc in inclusions:
        incf = inc[0]
        bl0 = build_block_mapping_for_function(r2, incf)
        for bl in bl0:
            blo = {}
            blo['func_id'] = bl['func_id']
            blo['fname'] = incf
            bb_addr = abs(bl['addr'] - ba)
            blo['addr'] = bb_addr
            blo['bsize'] = bl['size']
            if not bb_addr in blocks:
                blocks[bb_addr] = []
            blocks[bb_addr] += [blo] 
    return blocks

def get_rodata_section(r2):
    ie, ba = get_ie_offset(r2)
    secs = r2.cmd("iSj")
    try:
        secsj = json.loads(secs)
        for x in secsj:
            if x['name'] == '.rodata':
                paddr = x['paddr']
                vaddr = x['vaddr']
                size = x['size']
                vsize = x['vsize']
                assert size == vsize
                assert paddr == vaddr
                return {'addr': paddr, 'size': size, 'ie': ie}
        return {'ie': ie}
    except Exception as e:
        print(f'ERROR: get_rodata_section: {e}')
        return {'ie': ie}

def split_bin(bytes_string, blocks, baddr):
    block_codes = []
    for b in blocks:
        if type(b["addr"]) == str:
            addr = int(b["addr"], 16)
        else:
            addr = b["addr"]
        addr = abs(addr-baddr)
        size = b["size"]
        block_codes.append(bytes_string[addr:addr+size])
    return block_codes

def find_symbol_for_block(funcs, ie, baddr):
    for f in funcs:
        if (baddr >= f["offset"]) and (baddr < (f["offset"] + f["size"])):
            return f["name"], f["signature"], f["size"] - (baddr - f["offset"])
    

    print(baddr)
    for x in funcs:
        print(f'{x["name"]} {x["offset"]} {x["offset"] + x["size"]}')
    return None, None, None

def debug_get_block_bin(target_file, hash):
    bytes_string = b''
    with open(target_file, "rb") as f:
        bytes_string = f.read()
    
    ie, ba = get_ie_offset(target_file)
    bb = get_bb_info(target_file)
    blocks = split_bin(bytes_string, bb)
    for i in range(len(blocks)):
        b  = blocks[i]
        bhash = md5(b)
        if bhash == hash:
            return b
    return None

def get_imports_list(r2):
    imports_blob = r2.cmd('iij')
    try:
        imports = json.loads(imports_blob)
        imports_list = []
        for ix in imports:
            name = ix['name']
            itype = ix['type']
            imp = {'name': name, 'type': itype, 'included': False}
            imports_list += [imp]
        return imports_list
    except:
        return []

def resolve_symbols_per_block(r2, target_file):
    bytes_string = b''
    with open(target_file, "rb") as f:
        bytes_string = f.read()
    
    ie, ba = get_ie_offset(r2)

    bb, conditional_branches = get_bb_info(r2)

    if bb == None:
        return {}, []
    blocks = split_bin(bytes_string, bb, ba)
    cb = [abs(ba - a) for a in conditional_branches]

    funs = get_function_names(r2)
    bobjs = {}
    for i in range(len(blocks)):
        b = blocks[i]
        bbaddr = bb[i]["addr"]
        bsize = bb[i]["size"]

        if type(bbaddr) == str:
            bbaddr = int(bbaddr, 16)
        fname = None
        fsign = None
        fsize = 0
        if not funs == None:
            fname, fsign, fsize = find_symbol_for_block(funs.values(), ie, bbaddr)
        if fname == None:
            fname = "unknown"
            fsign = "unknown"
        is_call = False
        if not funs == None and bbaddr in funs:
            is_call = True
        bb_addr = abs(ba -  bbaddr)
        b_baddr = bb_addr.to_bytes(4, 'little')
        
        bhash = md5(b_baddr + b)
        if bhash in bobjs:
            print(bobjs[bhash])
            print(f'{bb[i]["func_id"]} {bb_addr} {bbaddr} {fname} {bhash} {bb[i]["size"]}')
        
        assert (bhash not in bobjs) or (bhash in bobjs and bobjs[bhash]['fname'] == fname and bobjs[bhash]['addr'] == bbaddr)
        #print(f'{bb[i]["func_id"]} {bb_addr} {bbaddr} {fname} {bhash} {b} {bb[i]["size"]} {is_call}')
        
        bl = {"func_id": bb[i]["func_id"], "addr": bbaddr, "fname": fname, "signature": fsign, "is_call": is_call, "fsize": fsize, "bsize": bb[i]["size"], "bhash": bhash}
        if not bb_addr in bobjs:
            bobjs[bb_addr] = []
        bobjs[bb_addr] += [bl]
    return bobjs, cb

def resolve_symbols_for_inclusions(target_path, target_bin, inclusions=[], test_case_name="", target_name=""):
    r2 = r2_open_pipe(target_bin)
    bbobjs = build_block_mapping_for_inclusions(r2, target_bin, inclusions)
    syms = build_symbols_for_inclusions(r2, target_bin, inclusions)

    if test_case_name == "":
        test_case_name = target_name
    if target_name == "":
        pass
    else:
        pass

    target_file_path = os.path.join(target_path, test_case_name)
    inclusions_named_symbols_file = os.path.join(target_file_path, "inclusions_named_symbols.json")
    inclusions_named_mapping_file = os.path.join(target_file_path, "inclusions_named_mapping.json")
    data = {}
    if os.path.exists(inclusions_named_mapping_file):
        f = open(inclusions_named_mapping_file, 'r')
        try:
            data = json.load(f)
        except:
            data = {}
        f.close()

    page_name = os.path.basename(target_bin)
    if page_name[-4:] == '.bin':
        page_name = page_name[:-4]
    data[page_name] = bbobjs
    with open(inclusions_named_mapping_file, 'w') as f:
        json.dump(data, f)

    if os.path.exists(inclusions_named_symbols_file):
        f = open(inclusions_named_symbols_file, 'r')
        try:
            s0 = json.load(f)
            syms += s0
        except:
            pass
        f.close()

    with open(inclusions_named_symbols_file, 'w') as f:
        json.dump(syms, f)


def resolve_symbols(target_dir, dumps_dir, target_bin, test_case_name="", target_name=""):
    r2 = r2_open_pipe(target_bin)
    bbobjs, cb = resolve_symbols_per_block(r2, target_bin)
    #rodata_section = get_rodata_section(r2)
    rodata_section = {}
    data = {"symbols": bbobjs, "branches": list(set(cb)), 'rodata': rodata_section}
    
    global no_blocks
    no_blocks = len(list(bbobjs.keys()))

    imports = get_imports_list(r2)

    bin_name = os.path.basename(target_bin)
    if os.path.dirname(target_bin) == dumps_dir:
        bin_name = bin_name.replace('.bin', '')
    
    if test_case_name == "":
        test_case_name = bin_name
    if target_name == "":
        symbols_file = f'{test_case_name}_symbols.json'
        imports_file = f'{test_case_name}_imports.json'
    else:
        symbols_file = f'{target_name}_symbols.json'
        imports_file = f'{target_name}_imports.json'
    
    target_file_path = os.path.join(target_dir, test_case_name)
    symbols_file_path = os.path.join(target_file_path, symbols_file)
    imports_file_path = os.path.join(target_file_path, imports_file)
    with open(symbols_file_path, 'w') as f:
        json.dump(data, f)
    
    with open(imports_file_path, 'w') as f:
        json.dump(imports, f)

if __name__ == "__main__":
    pass