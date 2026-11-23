#--------------------------------------
# File: constants.py
#
# Purpose: 
#   - contains opcodes used in our internal IR
#   - and types used to encode variable values
#--------------------------------------

def singleton(class_):
    instances = {}

    def get_instance(*args, **kwargs):
        if class_ not in instances:
            instances[class_] = class_(*args, **kwargs)
        return instances[class_]

    return get_instance

class Unknown:
    def __init__(self):
        pass
    
    def __repr__(self) -> str:
        return "Unknown"
    
    def __str__(self):
        return "UNKNOWN"

    def __eq__(self, o):
        if type(o) == Unknown:
            return True
        return False

    def __hash__(self) -> int:
        return hash("Unknown")

class Empty:
    def __init__(self):
        pass

    def __repr__(self):
        return "Empty"
    
    def __str__(self):
        return "Empty"
    
    def __eq__(self, o):
        return False

class ValError:
    def __init__(self, a, b="", error=""):
        self.a = a
        self.b = b
        self.error = error
    
    def __repr__(self) -> str:
        return f"ValError: ({self.a}, {self.b}) -> {self.error}"
    
    def __hash__(self) -> int:
        return hash("ValError")

    def __eq__(self, o):
        if type(o) == ValError:
            return True
        return False

sub_regs = {"ah": ("rax", "16s"), "al": ("rax", "8s"), "bh": ("rbx", "16s"), "bl": ("rbx", "8s"), "ch": ("rcx", "16s"), "cl": ("rcx", "8s"), "dh": ("rdx", "16s"), "dl": ("rdx", "8s"),  "ax": ("rax", "16m"), "bx": ("rbx", "16m"), "cx": ("rcx", "16m"), "dx": ("rdx", "16m"), "eax": ("rax", "32l"), "ebx": ("rbx", "32l"), "edx": ("rdx", "32l")}

    
TBOR = "Ijk_Boring"
TCALL = "Ijk_Call"
TRET = "Ijk_Ret"

LOAD_OP = 0
STORE_OP = 1
PUT_OP = 2
GET_OP = 3
ADD_OP = 4
SUB_OP = 5
CMPEQ_OP = 6
CMPLE_OP = 7
CMPGE_OP = 8
CMPNE_OP = 9
AND_OP = 10
OR_OP = 11
XOR_OP = 12
SHL_OP = 13
SHR_OP = 14
SAR_OP = 15
MULL_OP = 16
CTZ_OP = 17
CLZ_OP = 18
NOT_OP = 19
MUL_OP = 20
CAST_OP = 21
CMPGT_OP = 22
CMPLT_OP = 23
SS_OP = 24
CAST64_OP = 25
CAST32_OP = 26
CAST32U_OP = 27
CAST1U_OP = 28
SET_OP = 29
NULL_OP = 30
CAST8U_OP = 31
CAST32S_OP = 32
ITE_OP = 33
CAST128HI_OP = 34
CAST8S_OP = 35
CAST16U_OP = 36
CAST16S_OP = 37
CAST64HL_OP = 38
DIVMODU128_OP = 39
CAST128_OP = 40
DIVMODU64_OP = 41
CAST64HI_OP = 42
DIV_OP = 43
CAST32HL_OP = 44
DIVMODS128_OP = 47
DIVMODS64_OP = 48
CASTF32_OP = 49
CAST64F_OP = 50
CMPF64_OP = 51
CAST64U_OP = 66

CMPNS_OP = 45
CMPS_OP = 46

# AMD64 CPU OPS
CMPLCPU_OP = 47
CMPNLCPU_OP = 48
CMPBCPU_OP = 49
CMPNBCPU_OP = 50
CMPZCPU_OP = 51
CMPNZCPU_OP = 52
CMPBECPU_OP = 53
CMPNBECPU_OP = 54
CMPSCPU_OP = 55
CMPNSCPU_OP = 56
CMPPCPU_OP = 57
CMPNPCPU_OP = 59
CMPLECPU_OP = 60
CMPNLECPU_OP = 61
CMPOCPU_OP = 62
CMPNOCPU_OP = 63

"""
For Reference:

typedef
   enum {
      AMD64CondO      = 0,  /* overflow           */
      AMD64CondNO     = 1,  /* no overflow        */

      AMD64CondB      = 2,  /* below              */
      AMD64CondNB     = 3,  /* not below          */

      AMD64CondZ      = 4,  /* zero               */
      AMD64CondNZ     = 5,  /* not zero           */

      AMD64CondBE     = 6,  /* below or equal     */
      AMD64CondNBE    = 7,  /* not below or equal */

      AMD64CondS      = 8,  /* negative           */
      AMD64CondNS     = 9,  /* not negative       */

      AMD64CondP      = 10, /* parity even        */
      AMD64CondNP     = 11, /* not parity even    */

      AMD64CondL      = 12, /* less               */
      AMD64CondNL     = 13, /* not less           */

      AMD64CondLE     = 14, /* less or equal      */
      AMD64CondNLE    = 15, /* not less or equal  */

      AMD64CondAlways = 16  /* HACK */
   }
   AMD64Condcode;


"""

CASCMPNE_OP = 64

CAST16HL_OP = 66
CASTI64S_OP = 65

MAX_OP = 67
MIN_OP = 69

REINTERP_OP = 68

CAST32HI_OP = 70
CAST16_OP = 71

CMPODD_OP = 72

GETI_OP = 73
PUTI_OP = 74

REINTERPF_OP = 75

encode_cpu_ops = [CMPOCPU_OP, CMPNOCPU_OP, CMPBCPU_OP, CMPNBCPU_OP, CMPZCPU_OP, CMPNZCPU_OP, CMPBECPU_OP, CMPNBECPU_OP, CMPSCPU_OP, CMPNSCPU_OP, CMPPCPU_OP, CMPNPCPU_OP, CMPLCPU_OP, CMPNLCPU_OP, CMPLECPU_OP, CMPNLECPU_OP]


macros_list = {
    "CMPS": str([AND_OP, SHR_OP, 31, 1]),
    "CMPODD": str([CMPEQ_OP, SUB_OP, AND_OP, ADD_OP, SHR_OP, SAR_OP, 31, 31, 1, SHR_OP, SAR_OP, 31, 31, 1])
}


COND_OPS = [CMPEQ_OP, CMPNE_OP, CMPGE_OP, CMPGT_OP, CMPLE_OP, CMPLT_OP, CMPNS_OP, CMPS_OP]

CAST_OPS = [CAST64_OP, CAST32_OP, CAST32_OP, CAST1U_OP, CAST8U_OP, CAST32S_OP, CAST128HI_OP, CAST8S_OP, CAST16U_OP, CAST16S_OP, CAST64HL_OP, CAST128_OP, CAST64HI_OP, CAST32HL_OP, CAST32U_OP, CASTF32_OP, CAST64F_OP, CAST64U_OP, CAST16HL_OP]

LE = 0
BE = 1

J_BORING = 0
J_CALL = 1
J_COND = 2
J_EXIT = 3

DT_NULL = 0
DT_I8 = 1
DT_I16 = 2
DT_I32 = 3
DT_I64 = 4
DT_8U = 5
DT_16U = 6
DT_32U = 7
DT_64U = 8

DT_8S = 9
DT_16S = 10
DT_32S = 11
DT_64S = 12

DT_V128 = 13
DT_1U = 14
DT_I1 = 15
DT_32F = 16
DT_64F = 17

DT_64F0x2 = 18

DTs_32 = [DT_32U, DT_I32, DT_32S, DT_32F]
DTs_64 = [DT_I64, DT_64S, DT_64U]
DTs_8 = [DT_I8, DT_8U, DT_8S]
DTs_16 = [DT_I16, DT_16S, DT_16U]

# DTs:
# ----
# Mul - signless multiply
# Mull - widening multiply
# Clz - count trailing zeroes
# Ctz - count leading zeroes

# divmod - low half div, high half mod
# Divmod64to64 - 64 - 1st arg, 64 - 2nd arg

# 16to8 - low half
# 16HIto8 - high half
# 8HLto16 -> (I8, I8) -> I16

# H - high
# L - low

# F - float, V - simb (?)

# Some of these operations not correctly done, in almost all cases there values are not used in any meaningful way
encode_op = {
    "Add": ADD_OP,
    "Sub": SUB_OP,
    "And": AND_OP,
    "Or": OR_OP,
    "LD": LOAD_OP,
    "St": STORE_OP,
    "GET": GET_OP,
    "Put": PUT_OP,
    "MPut": PUT_OP,
    "CmpEQ": CMPEQ_OP,
    "CmpLE": CMPLE_OP,
    "CmpGE": CMPGE_OP,
    "CmpGT": CMPGT_OP,
    "CmpLT": CMPLT_OP,
    "CmpNE": CMPNE_OP,
    "Xor": XOR_OP,
    "Shl": SHL_OP,
    "Shr": SHR_OP,
    "Sar": SAR_OP,
    "Mull": MULL_OP,
    "Ctz": CTZ_OP,
    "Clz": CLZ_OP,
    "Not": NOT_OP,
    "Mul": MUL_OP,
    "SS": SS_OP,
    "64to": CAST64_OP,
    "32to": CAST32_OP,
    "32Uto": CAST32U_OP,
    "1Uto": CAST1U_OP,
    "SET": SET_OP,
    "NULL": NULL_OP,
    "8Uto": CAST8U_OP,
    "32Sto": CAST32S_OP,
    "ITE": ITE_OP,
    "128HIto": CAST128HI_OP,
    "8Sto": CAST8S_OP,
    "16Uto": CAST16U_OP,
    "16Sto": CAST16S_OP,
    "64HLto": CAST64HL_OP,
    "DivModU128to": DIVMODU128_OP,
    "128to": CAST128_OP,
    "V128to": CAST128_OP,
    "V128HIto": CAST128_OP,
    "DivModU64to": DIVMODU64_OP,
    "64HIto": CAST64HI_OP,
    "Div": DIV_OP,
    "32HLto": CAST32HL_OP,
    "CMPS": CMPS_OP,
    "CMPNS": CMPNS_OP,
    "DivModS128to": DIVMODS128_OP,
    "DivModS64to": DIVMODS64_OP,
    "F32to": CASTF32_OP,
    "F64to": CAST64F_OP,
    "I32Sto": CAST32S_OP,
    "CmpF64": CMPF64_OP,
    "CmpL_CPU": CMPLCPU_OP,
    "CmpNL_CPU": CMPNLCPU_OP,
    "CmpB_CPU": CMPBCPU_OP,
    "CmpNB_CPU": CMPNBCPU_OP,
    "CmpZ_CPU": CMPZCPU_OP,
    "CmpNZ_CPU": CMPNZCPU_OP,
    "CmpBE_CPU": CMPBECPU_OP,
    "CmpNBE_CPU": CMPNBECPU_OP,
    "CmpS_CPU": CMPSCPU_OP,
    "CmpNS_CPU": CMPNSCPU_OP,
    "CmpP_CPU": CMPPCPU_OP,
    "CmpNP_CPU": CMPNPCPU_OP,
    "CmpLE_CPU": CMPLECPU_OP,
    "CmpNLE_CPU": CMPNLECPU_OP,
    "CmpO_CPU": CMPOCPU_OP,
    "CmpNO_CPU": CMPNOCPU_OP,
    "CasCmpNE": CASCMPNE_OP,
    "I64Sto": CASTI64S_OP,
    "64Uto": CAST64U_OP,
    "16HLto": CAST16HL_OP,
    "Max": MAX_OP,
    "Min": MIN_OP,
    "ReinterpI64as": REINTERP_OP,
    "ReinterpF64as": REINTERPF_OP,
    "32HIto": CAST32HI_OP,
    "16to": CAST16_OP,
    "CMPODD": CMPODD_OP,
    "CasCmpEQ": CMPEQ_OP,
    "PutI": PUTI_OP,
    "GetI": GETI_OP
}

decode_op = {v: k for k,v in encode_op.items()}
decode_op[PUT_OP] = "Put"

encode_type = {
    "32": DT_I32,
    "32U": DT_32U,
    "U32": DT_32U,
    "32S": DT_32S,
    "8": DT_I8,
    "8U": DT_8U,
    "U8": DT_8U,
    "8S": DT_8S,
    "64": DT_I64,
    "64S": DT_64S,
    "64U": DT_64U,
    "U64": DT_64U,
    "16": DT_I16,
    "16U": DT_16U,
    "U16": DT_16U,
    "16S": DT_16S,
    "V128": DT_V128,
    "1U": DT_1U,
    "1": DT_I1,
    "I32": DT_I32,
    "I64": DT_I64,
    "I8": DT_I8,
    "I16": DT_I16,
    "U64": DT_64U,
    "128": DT_V128,
    "S64": DT_64S,
    "S128": DT_V128,
    "32F0x4": DT_32F,
    "F32": DT_32F,
    "F64": DT_64F,
    "I32S": DT_32S,
    "S32": DT_32S,
    "64F0x2": DT_64F0x2,
    "I64S": DT_64S,
    "U32": DT_32U,
    "8x16": DT_I16,
    "32x4": DT_I32,
    "32F0x4": DT_32F,
    "32Fx4": DT_32F,
    "64Fx2": DT_64F,
    "64x2": DT_I64
}

decode_type = {
    DT_NULL: "",
    DT_I32: "I32",
    DT_32U: "32U",
    DT_32S: "32S",
    DT_I8: "I8",
    DT_8U: "8U",
    DT_8S: "8S",
    DT_I64: "I64",
    DT_64S: "64S",
    DT_64U: "64U",
    DT_I16: "I16",
    DT_16U: "16U",
    DT_16S: "16S",
    DT_V128: "V128",
    DT_1U: "1U",
    DT_I1: "I1",
    DT_32F: "32F",
    DT_64F: "64F",
    DT_64F0x2: "64F0x2"
}

encode_endianess = {
    "le": LE,
    "be": BE
}

decode_endianess = {
    LE: "le",
    BE: "be"
}

supported_types = ["32", "32U", "32S", "8", "8U", "8S", "64", "64S", "64U", "16", "16U", "16S", "V128", "1U", "1", "I32", "I64", "I8", "I16", "U64", '128', "64HI", "S64","S128", "32F0x4", "F32", "F64", "I32S", "S32", "64F0x2", "I64S", "U32", "8x16", '32x4', '32Fx4', "64Fx2", "U8", "U16", "U32", "U64", "64x2"]

DEFAULT_ENDIANESS = LE

macros_lookup = {
    macros_list["CMPS"]: CMPS_OP.to_bytes(1,byteorder='little')+DT_1U.to_bytes(1,byteorder='little')+DEFAULT_ENDIANESS.to_bytes(1,byteorder='little'),
    macros_list["CMPODD"]: CMPODD_OP.to_bytes(1, byteorder='little')+DT_1U.to_bytes(1, byteorder='little')+DEFAULT_ENDIANESS.to_bytes(1, byteorder='little')
}

def opStr(op):
    if type(op) == str:
        return op
    
    opcode = op[0]
    dtype = op[1]
    endianess = op[2]
    op = decode_op[opcode]
    dt = decode_type[dtype]
    ed = decode_endianess[endianess]
    return f'{op}{ed}{dt}'

def opcStr(op):
    opcode = op[0]
    op = decode_op[opcode]
    return op

def get_op(op):
    return [k for k in encode_op.keys() if op[:len(k)] == k]

def get_bin_op(op):
    if op[:4] == "PutI" or op[:4] == "GetI":
        return op[:4]

    op_name = get_op(op)
    if len(op_name) == 0:
        return None
    if len(op_name) > 1:
        if op[:4]!="Mull" or op[:6] != "DivMod":
            assert len(op_name) > 1
        if op_name[0] == "Div":
            return op_name[1]
        elif op[:6] == "DivMod":
            return op_name[0]
        else:
            return "Mull"
    
    bop = op_name[0]
    return bop

def encode_cpu_guest_ops(args):
    op = int(args[0],16)
    op = encode_cpu_ops[op]
    arg1 = args[2]
    arg2 = args[3]
    return op.to_bytes(1,byteorder='little')+DT_NULL.to_bytes(1, byteorder='little')+DEFAULT_ENDIANESS.to_bytes(1,byteorder='little'), arg1, arg2

# x87 FP registers:
# GetI
# PutI

# PutI(96:8xF64)[t39:-7]
# PutI(offset:nxt)[ix,bias]
# offset - of first element in array 
# n - no of elements
# t - type of each element
# [ix,bias] - indexing
# ix - variable part 
# bias - constant offset
# index = (ix + bias) % n

def encode_x87_fp_op(op):
    return encode_op[op].to_bytes(1, byteorder='little') + DT_NULL.to_bytes(1, byteorder='little') + DEFAULT_ENDIANESS.to_bytes(1, byteorder='little')

import logging
# ENCODING:
# (op-code, datatype, endianness) - 3 bytes
def encode_operation(op):
    op_name = get_bin_op(op)
    if op_name == None:
        #return None
        if "amd64" in op or 'x86g' in op or "InterleaveLO8x16" in op or "InterleaveLO64x2" in op or "GetMSBs8x16" in op or "ExpCmpNE64" in op:
            #pass
            #else:
            #logging.debug(f'Unknown opcode {op}')
            return NULL_OP.to_bytes(1,byteorder='little')+DT_NULL.to_bytes(1,byteorder='little')+DEFAULT_ENDIANESS.to_bytes(1,byteorder='little')
        print(op)
        raise Exception()
    
    #if op_name == None:
    #    print(op_name)
    #    print(op)
    #    raise Exception()

    bop = op_name
    op_code = encode_op[bop]
    n = len(bop)
    if op_code == LOAD_OP or op_code == STORE_OP:
        op_end = op.replace(":","")[2:4]
        if not op_end in encode_endianess:
            print(op)
            print(op_end)
            raise Exception()
        endian_code = encode_endianess[op_end]
        n += 2
    else:
        endian_code = DEFAULT_ENDIANESS
    
    if op_code in [STORE_OP, PUT_OP, SS_OP, SET_OP, ITE_OP, CMPF64_OP]:
        type_code = DT_NULL
    else:
        c_type = op[n:]
        c_type = c_type.replace(":", "")
        if not c_type in supported_types:
            #return None
            print(op)
            print(c_type)
            raise Exception
        type_code = encode_type[c_type]
    
    return op_code.to_bytes(1,byteorder='little')+type_code.to_bytes(1,byteorder='little')+endian_code.to_bytes(1,byteorder='little')

def decode_operation(op):
    return op[0],op[1],op[2]