import r2pipe
import json

def open_r2pipe(file_name):
    try:
        r2 = r2pipe.open(file_name, flags=['-e', 'bin.verbose=false'])
        _ = r2.cmd("aaa")
        return r2
    except:
        return None

def get_ba_offset(r2):
    ie = r2.cmd('iej')
    try:
        iej = json.loads(ie)
        if type(iej) == list and len(iej) == 1:
            return iej[0]["baddr"]
        return iej["baddr"]
    except:
        return -1

def get_block_info(r2, addr):
    bb_info = r2.cmd(f"abj @ {addr}")
    try:
        bbj = json.loads(bb_info)
        return bbj
    except:
        return None

def get_block(r2, addr, size):
    return r2.cmd(f'pcs {size} @ {addr}')


def do_get_block(file_name, addr, size):
    r2_pipe = open_r2pipe(file_name)
    return get_block(r2_pipe, addr, size)

def get_address_for_function(r2, func_name):
    return r2.cmd(f'afo {func_name}')
