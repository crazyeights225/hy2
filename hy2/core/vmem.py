#--------------------------------------
# File: vmem.py
#
# Purpose: Provides an interface for virtual memory, and registry data
#--------------------------------------
from colorama import Fore
import json
from hy2.core.constants import singleton

@singleton
class Vmem:
    def __init__(self):
        self.vmem = {}
        self.block_regs = {}
        self.mem_access = {}
        self.no_errors = 0
    
    # Reads in vmem log data log created at runtime
    def read_in_vmem_log(self):
        f = open('vmem_stream.log', 'r')
        dat = f.read()
        data = dat.split("\n")
        #print(dat)
        for s in data:
            try:
                x = json.loads(s)
                pc = x['pc']
                idx = x['idx']
                if not pc in self.vmem:
                    self.vmem[pc] = {}
                if not idx in self.vmem[pc]:
                    self.vmem[pc][idx] = []
                self.vmem[pc][idx].append(x)
            except:
                print(Fore.RED + "(vmem) ERROR: " + s + Fore.RESET)
        
        f.close()
    
    # "Block regs", ie. the values in the registry before the block executes have replaced the registry values before each instruction is executed
    # This works because each block modifies each registry value only once typically, and if not the operations get chained together so that if rbp = rbp + 10, rbp = rbp = rbp + 20, becomes rbp = rbp + 10 + 20
    def check_block_regs(self, pc, tid, oid, regname):
        v = self.block_regs.get_value_at_t(tid, regname, oid)
        if v == None:
            print('ERROR')
            self.no_errors += 1
            return None, None
        else:
            return v["val"], v["telescope"]

    def lookup_regs(self, pc, tid, oid, regname):
        v, vt = self.check_block_regs(pc, tid, oid, regname)
        return v, vt
    
    def vmem_get_all_at_pc(self, pc):
        if str(pc) in self.vmem:
            pc = str(pc)
        
        if not pc in self.vmem:
            return None
        else:
            return self.vmem[pc]
    
    def vmem_lookup_address(self, pc, oid, address, rw, l_no=''):
        if str(pc) in self.vmem:
            pc = str(pc)
    
        if not pc in self.vmem:
            self.no_errors += 1
            return None, None

        addr = self.vmem[pc]
        oid_addr_idx = f'{oid}-{address}'
        if not oid_addr_idx in addr:
            self.no_errors += 1
            return None, None
        else:
            v = addr[oid_addr_idx]
            if len(v) > 1:
                if v[0]['rw'] == rw:
                    return v[0]['val'], None
                elif v[1]['rw'] == rw:
                    return v[1]['val'], None
                else:
                    return None, None
            else:
                return v[0]['val'], None