#--------------------------------------
# File: dt_table.py
#
# Purpose: "Discrete Time" table
#  Creates a table such that each values can be searched by key, and time
#  For example:
#  key | time | value
#  ----|------|------
#    a |  1   |   2
#    a |  4   | 10
#    a |  10  | 24
#   
#   query(a,1) = 2
#   query(a, 6) = 10
#   - the table returns the last value of 'a' when t is not in the table
#--------------------------------------
from sys import getsizeof
from bisect import bisect_left

# Takes sorted list, returns closest value to targetVal
# If two numbers are equally close, returns the smallest
def take_closest(arr, targetVal):
    pos = bisect_left(arr, targetVal)
    if pos == 0:
        return arr[0]
    return arr[pos - 1]

class DiscreteTimeTable:
    def __init__(self):
        self.values = {}
        self.tails = {}
    
    # rid - registry key id (rsp, rbp, rax, ..)
    # t - is block number (ie. discrete time, each block is a tick)
    # v - value
    def add_value_at(self, tid, rid, t, v):
        trid = f'{tid}{rid}'
        if t == '':
            return
        
        if not trid in self.values:
            self.values[trid] = {}
            self.tails[trid] = 0
        
        elif self.values[trid][self.tails[trid]] == v:
            return
        
        self.values[trid][t] = v
        self.tails[trid] = t


    def add_values_at(self, tid, regs, t):
        for rid, v in regs.items():
            self.add_value_at(tid, rid, t, v)
    

    def get_value_at_t(self, tid, reg_id, t):
        trid = f'{tid}{reg_id}'

        if not trid in self.values:
            #print(trid)
            return None
        if t in self.values[trid]:
            return self.values[trid][t]
        
        else:
            #print('[DEBUG] Linear search in dt table')
            v0 = None
            k0 = list(self.values[trid].keys())
            i0  = take_closest(k0, t)
            return self.values[trid][i0]

    def __sizeof__(self) -> int:
        return getsizeof(self.values) + getsizeof(self.tails)