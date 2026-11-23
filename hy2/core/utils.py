# HELPERS:
import hashlib
import re
import json
import os


def loadGlobalConfigFile(GLOBAL_CONFIG_FILE, GLOBAL_CONFIG):
    f = open(GLOBAL_CONFIG_FILE, 'r')
    conf_data = json.load(f)
    dat = conf_data['globals']
    GLOBAL_CONFIG.target_path = dat['target_directory']
    GLOBAL_CONFIG.mount_path = dat['mount_path']
    GLOBAL_CONFIG.max_static_depth = dat['max_depth']
    GLOBAL_CONFIG.property_dir = dat['property_directory']
    if 'snapshot_name' in dat:
        GLOBAL_CONFIG.snapshot_name = dat['snapshot_name']
    if 'guest_image' in dat:
        GLOBAL_CONFIG.guest_image = dat['guest_image']
    if "show_infeasible" in dat:
        GLOBAL_CONFIG.show_infeasible = dat['show_infeasible']
    # PANDA docker container options (see hy2/orch/panda_docker.py)
    for key in ('panda_backend', 'docker_image', 'docker_cmd', 'docker_extra_args'):
        if key in dat:
            setattr(GLOBAL_CONFIG, key, dat[key])
    f.close()
    return GLOBAL_CONFIG

def loadConfigFile(path, target):
    #config_path = os.path.join(path, target, 'config.json')
    config_path = os.path.join(path, target, 'profile.json')
    enable_static_analysis = False
    if not os.path.exists(config_path):
        return enable_static_analysis
    f = open(config_path, 'r')
    data = json.load(f)
    f.close()
    if "enable_static_analysis" in data:
        enable_static_analysis = data['enable_static_analysis']
    return enable_static_analysis


def get_semantic_info(target_path):
    profile_file = os.path.join(target_path, 'profile.json')
    if not os.path.exists(profile_file):
        return {}
    sem_info = {}
    with open(profile_file, 'r') as f:
        dat = json.load(f)
        if 'semantic_info' in dat:
            sem_info = dat['semantic_info']
    return sem_info

data_type_sizes = {"8": 1, "16": 2, "32": 4, "64": 8, 'V128': 16}
dt_sizes = {'char': 1, 'int': 4, "int *": 8, "size_t": 8, "FILE *": 216, "long int": 4, 'BYTE': 1, "double": 8, "size_t": 4}

def dtypeToSize(dtype):
    if dtype == "Ity_I64" or dtype == "signed int64_t" or dtype == "signed int":
        return data_type_sizes["64"]
    if dtype == "Ity_I32" or dtype == "uint32_t":
        return data_type_sizes["32"]
    if dtype == "Ity_I16":
        return data_type_sizes["16"]
    if dtype == "Ity_I8":
        return data_type_sizes["8"]
    if dtype == "Ity_V128":
        return data_type_sizes['V128']
    if dtype == "Ity_I1":
        return 1
    if "[" in dtype:
        dt = dtype.split("[")[0]
        x = dtype.split("[")[1].replace("[",'').replace("]",'')
        if dt in dt_sizes:
            return dt_sizes[dt] * int(x)
        if "*" in dt:
            return 8*int(x)
        print(f'[ERROR]: dtype: {x}*{dtype}')
        return "v"
    if "int64_t" == dtype or "unsigned int" == dtype:
        return "v"
    if "char **" == dtype or "char * *" == dtype:
        return "v"
    if "char *" == dtype or "char const *" == dtype:
        return "v"
    if "int *" == dtype or "void *" == dtype:
        return "v"
    if dtype in ["JFIF *", "BMP *", "MBITSTR *", "HUFCODEC *", "FBITSTR *", "BYTE *", "BMPFILEHEADER", "time_t", "uid_t", "struct timeval *", "time_t *", "timeval"]:
        return "v"
    if type(dtype) == list:
        print(dtype)
        raise Exception() 
    if dtype in dt_sizes:
        return dt_sizes[dtype] 
    if dtype == "":
        return "v"
    else:
        print(f'[ERROR]: dtype: {dtype}')
        return "v"
    #else:
    #    raise Exception(f"ERROR! {dtype}")

hex_pattern = r'^0x[0-9a-f]+$'
def is_hex(x):
    m = re.match(hex_pattern, x)
    if m:
        return True
    return False

def pad_bits(x):
    try:
        y = bin(x).replace('0b', '')
        if y[0] == '-':
            return "-"+("0"*(64 - len(y[1:]))+y[1:])
        else:
            return "0"*(64-len(y))+y
    except:
        return None

def to_int(x):
    if x == None:
        return None
    if type(x) == int:
        return x
    if not type(x) == str:
        #return x
        x = str(x)
    if x[:2] == "0x":
        return int(x, 16)
    else:
        try:
            return int(x)
        except:
            return x

def md5(buf):
    hash_md5 = hashlib.md5()
    for i in range(0, len(buf),4096):
        if i + 4096 > len(buf):
            chunk = buf[i:]
        else:
            chunk = buf[i:i+4096]
        hash_md5.update(chunk)
    return hash_md5.hexdigest()

def checkOnHeap(panda, cpu, val):
    str_data = val.to_bytes(16, byteorder='little')
    val = int.from_bytes(str_data[:8], byteorder='little')
    try:    
        _ = panda.virtual_memory_read(cpu, val, 4)
        return True
    except ValueError:
        return False


# Copied and modified from pandare -> panda/panda/python/core/pandare
def telescope(panda, cpu, val, bsize=16, phys=False):
    '''
    Given a value, check if it's a pointer by seeing if we can map it to physical memory.
    If so, recursively print where it points
    to until
    1) It points to a string (then print the string)
    2) It's code (then disassembly the insn)
    3) It's an invalid pointer
    4) It's the 5th time we've done this, break

    TODO Should use memory protections to determine string/code/data
    '''

    rdata = []
    #print(val)
    str_data = val.to_bytes(16, byteorder='little')
    #print(str_data)

    val = int.from_bytes(str_data[:8], byteorder='little')
    #print(hex(val))
    for _ in range(5): # Max chain of 5
        #print("-> 0x{:0>8x}".format(val), end="\t")
        rdata.append({"data": "{}".format(val)})
        if val == 0:
            #print()
            return rdata

        str_val = ""
        for d in str_data:
            if d >= 0x20 and d < 0x7F:
                str_val += chr(d)
            else:
                break
        if len(str_val) > 2:
            #print("== \"{}\"".format(str_val))
            rdata[-1]["str"] = str_val
        
        
        # Consider that val points to a string. Test and print
        try:
            if phys:
                str_data = panda.physical_memory_read(val, bsize)
            else:
                str_data = panda.virtual_memory_read(cpu, val, bsize)
        except ValueError:
            #print()
            #str_data = []
            try:
                str_data = panda.virtual_memory_read(cpu, val, 4)
            
            except:
                try:
                    str_data = panda.virtual_memory_read(cpu, val, 1)
                    #print(str_data)
                except:
                    #print(":(")
                    return rdata
        
        #print(str_data)
        data = str_data[:8] # Truncate to 4 bytes
        val = int.from_bytes(data, byteorder='little')
        #print(hex(val))

    #print("-> ...")
    #print(rdata)
    return rdata

import os
def getCode(i):
	return chr((i % 26) + 97)

def getIndexCode(i):
	n = (i // 26) - 1
    # its very unlikely there will ever be more than 26*26 traces
	assert n < 26
	if i < 26:
		return getCode(i)
	return getCode(n) + getCode(i)


def getVarPrefix(target_dir, target, test_case_name):
    targets = os.listdir(os.path.join(target_dir, target))
    targets = [x for x in targets if f'{target}_tc' in x and ".json" in x]
    targets.sort()
    idx = targets.index(test_case_name+'.json')
    return getIndexCode(idx)

def getAllVarPrefixes(target_dir, target):
    targets = os.listdir(target_dir)
    targets = [x for x in targets if f'{target}_tc' in x and ".json" in x]
    targets.sort()
    n = len(targets)
    return {getIndexCode(i): targets[i] for i in range(n)}, n

# =========================================================

def get_sequential_pages(target_pages):
    last_base = 0
    last_offset = 0
    aliases = {}
    for (b, o, _) in target_pages:
        if b == (last_base + last_offset):
            if last_base in aliases:
                aliases[b] = aliases[last_base]
            else:
                aliases[b] = last_base
        
        last_base = b
        last_offset = o
    return aliases

def get_matching_base(pc, target_pages, aliases):
    for (b, o, n) in target_pages:
        if pc > b and pc < (b + o):
            if b in aliases:
                return aliases[b],n
            return b,n
    
    return None,None


# merge pages to (addr, size) all consequetive pages in target
def parsePages(target, pages):
    target_pages = [(b,o) for (b,o,n) in pages if n == target]
    target_pages.sort(key=lambda x: x[0])
    print(target_pages)
    new_pages = []
    new_offsets = []
    last_base = 0
    last_offset = 0
    for (b,o) in target_pages:
        if b == (last_base + last_offset):
            new_offsets[-1] += o
            last_offset += o
        elif b >= last_base and (b + o) <= (last_base + last_offset):
            pass
        else:
            last_base = b
            last_offset = o
            new_pages += [b]
            new_offsets += [o]
    
    return new_pages, new_offsets


def getPageList(targets, target_pages):
    pages = []
    offsets = []
    for t in targets:
        p, o = parsePages(t, target_pages)
        pages += p
        offsets += o
    return pages, offsets

def check_ext_pages(addr, ext_data):
    if not 'pages' in ext_data:
        return None, None, None
    
    for (b, o) in ext_data['pages']:
        if addr > b and addr < (b + o):
            pn = ext_data['page_data'][b]
            pname = [x[1] for x in ext_data['inclusions_named'] if x[0] == pn['fname']][0]
            return pn['page'][0], ext_data['inclusion_paths'][pname], pname
    return None, None, None

def get_page_for_address(addr, target_pages, aliases, is_ext=False):
    if is_ext:
        b, bpath, bname = check_ext_pages(addr, target_pages)
        return b, bname
    else:
        return get_matching_base(addr, target_pages, aliases)

def loadExtBObjs(path, target):
    ext_mapping_file = os.path.join(path, target, 'inclusions_named_mapping.json')
    f = open(ext_mapping_file, 'r')
    dat = json.load(f)
    f.close()
    return dat

# --------------------------------

def vecToStr(vec):
    op = vec[0]
    depth = vec[1]

    v0 = vec[2:]
    if depth in v0:
        idx = v0.index(depth)
        v1 = v0[:idx]
        v2 = v0[idx+1:]
    else:
        v1 = v0
        v2 = []

    ls = ""
    rs = ""
    if len(v1) == 0:
        pass
    elif len(v1) == 1:
        ls = v1[0]
    elif len(v1) == 2:
        ls = v1[1]
    else:
        ls = vecToStr(v1)
    

    if len(v2) == 0:
        pass
    elif len(v2) == 1:
        rs = v2[0]
    elif len(v2) == 2:
        rs = v2[1]
    else:
        rs = vecToStr(v2)
    
    if rs == "":
        return f'{op}({ls})'
    return f'{op}({ls}, {rs})'

# =========================================================

html_colors = ['light_blue', 'purple', 'red', 'lemon', 'green', 'pink', 'blue', 'pale_blue', 'yellow', 'lilac', 'light_green', 'indigo', 'deep_purple', 'red_pink', 'grey']
html_color_codes = {h: f'l{i+1}' for (i, h) in enumerate(html_colors)}

def color_text(color, txt):
    cc = html_color_codes[color]
    return f'<span class="{cc}">{txt}</span>'

def bold_text(txt):
    return f'<b>{txt}</b>'

# =============================================================
from transitions import Machine,State

class TState(State):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.label = []

class ThreadMachine(Machine):
    state_cls = TState
