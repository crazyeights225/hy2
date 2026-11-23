#--------------------------------------
# File: static_ext.py
#
# Purpose: Static Analysis Extension
# During program execution we encounter conditional jumps
# i.e.:   --- cond  ---
#         |            |
#         |            |
#        false        true 
#         |            |
#         .            .
# We explore the branches of the conditions that we did not observe at execution by mutating values observed along the branch using state transformers
#  We extract and translate to IR the machine code on these unseen branches, and convert each block to a stateful function ie. ST(S) => (S', O)
#--------------------------------------

from colorama import Fore
import hy2.core.extensions.block_query as qbb
import hy2.core.utils as utils
import hy2.core.bblock as bblock
import time
import os

def ghostBranches(GLOB_CONF, local_bin_path, bobjs, visited, iir, target_pages, aliases, ghost_blocks_drop, block_list, is_ext=False):
    r2_bin = qbb.open_r2pipe(local_bin_path)
    base_addr = qbb.get_ba_offset(r2_bin)
    if base_addr < 0:
        return

    def translateGhostBlock(addr):
        target_base, page_name = utils.get_page_for_address(addr, target_pages, aliases, is_ext)
        if not target_base == None:
            abs_addr = abs(target_base - addr)
            sabs_addr = str(abs_addr)

            if sabs_addr in bobjs[page_name]:
                binst = bobjs[page_name][sabs_addr]
                bsize = min([bi["bsize"] for bi in binst])
                bin_addr = base_addr + abs_addr
                bb_byte_string = qbb.get_block(r2_bin, bin_addr, bsize)
                bb_byte_string = bb_byte_string.rstrip()
                assert bb_byte_string[0] ==  '"' and bb_byte_string[-1] == '"'
                bb_byte_string = bb_byte_string[1:-1]
                bb_byte_string = bb_byte_string.encode().decode('unicode_escape').encode("raw_unicode_escape")
                if len(bb_byte_string) == 0:
                    return None, None
                    
                if is_ext:
                    print(f'[dbg]: {binst[0]["fname"]} {abs_addr}')
                fname = binst[0]['fname']
                ghost_block = bblock.translate_block(fname, bb_byte_string, addr, [], iir.arch)
                if is_ext:
                    fsize = [x['size'] for x in target_pages['inc_named_data'] if x['fname'] == fname][0]
                else:
                    fsize = binst[0]['fsize']
                
                ghost_est = iir.ghost_ir_to_est(ghost_block.pcs, ghost_block.jump_kind, fname, 'unknown', 'unknown', fsize, ghost_block.var_table, ghost_block.var_list, ghost_block.types)
                
                ghost_block.pc = bin_addr

                return ghost_block, ghost_est
            else:
                print(Fore.YELLOW + f'[ERROR]: {sabs_addr}@{page_name} not in BObjs' + Fore.RESET)
                return None, None
        else:
            print(Fore.RED + f'[ERROR]: {addr} not in target pages' + Fore.RESET)
            return None, None

    missing_ghost_jmps = {}
    ghost_branches = []
    ghost_blocks = []
    ghost_nodes = []
    
    # src_addr - address of branch that jumps to unseen branch
    # baddr - address of unseen branch
    def add_branch(src_baddr, baddr):
        i = 0
        current_branch = []
        current_branch_pcs = []

        ghost_branch0 = None
        ghost_block0 = None
        ghost_node0 = None

        new_branch = []
        callstack = []
        depth = GLOB_CONF.max_static_depth
        while(i < depth):
            ghost_block, ghost_est = translateGhostBlock(baddr)
            if ghost_block == None or ghost_est == None:
                return None, None, None, None
            
            # I forget what this does:
            next_pc = ghost_block.next
            if type(next_pc) == int:
                # if current block has conditional jump, we add a new unseen branch to list returned, and explore it in later iteration
                # and visit the other branch:
                if ghost_block.is_cond:
                    if next_pc == ghost_block.jmp_iff and not ghost_block.jmp_ift in visited:
                        new_branch += [(baddr, ghost_block.jmp_ift)]
                    elif next_pc == ghost_block.jmp_ift and not ghost_block.jmp_iff in visited:
                        new_branch += [(baddr, ghost_block.jmp_iff)]

            # If block has call stmt - we need the return address
            if ghost_block.jump_kind == "Ijk_Call" and type(ghost_block.return_addr) == int and ghost_block.return_addr > 0:
                    callstack = [ghost_block.return_addr] + callstack
            
            # I forget what this does
            if type(next_pc) == int and not next_pc in visited and (i+1) < depth:
                if len(current_branch) > 0:
                    current_branch[i-1][0].next_fname = ghost_block.fname
                current_branch += [(ghost_block, ghost_est)]
                current_branch_pcs += [ghost_block.pc]
                baddr = next_pc
                i += 1
            elif (ghost_block.jump_kind == "Ijk_Ret" or "sym.imp." in ghost_block.fname) and len(callstack) > 0 and not callstack[0] in visited and (i+1) < depth:
                ret_to = callstack.pop(0)
                if len(current_branch) > 0:
                    current_branch[i-1][0].next_fname = ghost_block.fname
                ghost_block.next = ret_to
                current_branch += [(ghost_block, ghost_est)]
                current_branch_pcs += [ghost_block.pc]
                baddr = ret_to
                i += 1
            else:
                # This is the end of the branch:
                abs_addr = None
                if type(next_pc) == int:
                    target_base, _ = utils.get_page_for_address(next_pc, target_pages, aliases, is_ext)
                    abs_addr = abs(target_base - next_pc)
                    src_addr = abs(target_base - src_baddr)
                if type(src_baddr) == int:
                    target_base, _ = utils.get_page_for_address(src_baddr, target_pages, aliases, is_ext)
                    src_addr = abs(target_base - src_baddr)
                
                current_branch += [(ghost_block, ghost_est)]
                current_branch_pcs += [ghost_block.pc]

                ghost_branch0 = [{"src": src_addr, "dest_pc": abs_addr, "nodes": current_branch_pcs}]

                ghost_block0 = [c[0] for c in current_branch]
                ghost_node0 = [c[1] for c in current_branch]

                if ghost_block.jump_kind == "Ijk_Ret" or "sym.imp." in ghost_block.fname:
                    if len(callstack) > 0:
                        ghost_branch0[0]['dest_pc'] = callstack[0]
                        ghost_block0[-1].next = callstack[0]
                    else:
                        idx = len(ghost_blocks)
                        missing_ghost_jmps[src_addr] = idx + len(ghost_node0) - 1
                elif len(callstack) > 1 or (len(callstack) == 1 and callstack[0] != ghost_block.return_addr):
                    for c in callstack:
                        if not c in visited:
                            new_branch += [(c, c)]
                
                if ghost_block.jump_kind == "Ijk_Call" and type(ghost_block.return_addr) == int:
                    if type(next_pc) == int and (ghost_block.return_addr, ghost_block.return_addr) in new_branch:
                        idx = new_branch.index((ghost_block.return_addr, ghost_block.return_addr))
                        new_branch[idx] = (next_pc, ghost_block.return_addr)
                    else:
                        if type(next_pc) == int:
                            new_branch += [(next_pc, ghost_block.return_addr)]
                        else:
                            new_branch += [(ghost_block.return_addr, ghost_block.return_addr)]
                return new_branch, ghost_branch0, ghost_block0, ghost_node0
    
    gb_items = block_list
    checked_branches = []

    # loop through the list of unseen branches:
    while True:
        if gb_items == []:
            break
        
        # skip branches we have executed concretely:
        baddr, v = gb_items.pop(0)
        if baddr in ghost_blocks_drop:
            continue
        
        new_branch, ghost_branch0, ghost_block0, ghost_node0 = add_branch(v, baddr)
        checked_branches += [(v, baddr)]
        if not ghost_branch0 == None:
            ghost_branches += ghost_branch0
            ghost_blocks += ghost_block0
            ghost_nodes += ghost_node0
        
        if type(new_branch) == list:
            for x in new_branch:
                new_src = x[0]
                new_baddr = x[1]
                if not new_src == None and not (new_baddr, new_src) in checked_branches:
                    # add new branches discovered to analyze:
                    gb_items += [(new_baddr, new_src)]
                    checked_branches += [(new_baddr, new_src)]
    return ghost_blocks, ghost_nodes, ghost_branches, missing_ghost_jmps


# IN:
# -----------
# target
# local_bin_path
# bbobjs
# visited
# ir_constructor
# target_pages
# aliases
# ghost_blocks_drop
# ext_data
def callGhostBranches(GLOB_CONF, target, local_bin_path, bbobjs, visited, ir_constructor, target_pages, aliases, ghost_blocks_drop, ext_data):
    
    # ghost_blocks => (jmp_addr, pc of block with conditional jmp)
    gbs = list(ir_constructor.ghost_blocks.items())
    gb_map = {}
    for gb0 in gbs:
        baddr, v = gb0
        if baddr in ghost_blocks_drop:
            continue
        
        # get the base address and name of page with the address of the unseen branch
        b, page_name = utils.get_matching_base(baddr, target_pages, aliases)
        if not b == None:
            if not page_name in gb_map:
                    gb_map[page_name] = []
            gb_map[page_name] += [(baddr, v)]
        else:
            # for single functions in external libraries => get the page name
            b, _, page_name = utils.check_ext_pages(baddr, ext_data)
            if not b == None:
                if not page_name in gb_map:
                    gb_map[page_name] = []
                gb_map[page_name] += [(baddr, v)]
            else:
                print(Fore.RED + 'ERROR' + Fore.RESET)
                print(baddr)
                print(ext_data)
    
    ghost_blocks = []
    ghost_branches  = []
    ghost_nodes = []
    missing_ghost_jmps = {}

    # loop through pages
    # perform static analysis on the set of unseen branches in each page
    for pg, blist in gb_map.items():
        # page is target:
        if pg == target or pg.replace('.bin', '') == target:
            gb0, gbr0, gn0, msj = ghostBranches(GLOB_CONF, local_bin_path, bbobjs, visited, ir_constructor, target_pages, aliases, ghost_blocks_drop, blist, False)
            ghost_blocks += gb0
            ghost_branches += gbr0
            ghost_nodes += gn0
            missing_ghost_jmps = {**missing_ghost_jmps, **msj}
        else:
            bobj_tmp = utils.loadExtBObjs(target)
            bin_path = ext_data['inclusion_paths'][pg]
            
            rem_bin_path = os.path.basename(bin_path)
            rem_bin_path = rem_bin_path + '.bin'
            rem_bin_path = os.path.join(GLOB_CONF.mount_path, "dumps", rem_bin_path)
            if os.path.exists(rem_bin_path):
                bin_path = rem_bin_path
            
            gb0, gbr0, gn0, msj = ghostBranches(GLOB_CONF, bin_path, bobj_tmp, visited, ir_constructor, ext_data, {}, ghost_blocks_drop, blist, True)
            ghost_blocks += gb0
            ghost_branches += gbr0
            ghost_nodes += gn0
            missing_ghost_jmps = {**missing_ghost_jmps, **msj}
    
    return ghost_blocks, ghost_branches, ghost_nodes, missing_ghost_jmps

