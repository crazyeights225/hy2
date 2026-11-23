#--------------------------------------
# File: c_calc.py
#
# Purpose: A set of functions that perform the same operation as a particular instruction
# Note: casting not handled correctly
#--------------------------------------

from ctypes import *
import hy2.core.constants as cc
import struct

# FIXME: Some of the cast operations are not implemented/implemented incorrectly
# https://stackoverflow.com/a/16445458
def bin2float(binary):
    return struct.unpack('!f',struct.pack('!I', int(binary, 2)))[0]

def float32_bit_pattern(value):
    return sum(b << 8*i for i,b in enumerate(struct.pack('f', value)))

def checkErrorType(a, b):
    if type(a) == cc.ValError or type(a) == cc.Unknown:
        return a, True
    
    if type(b) == cc.ValError or type(b) == cc.Unknown:
        return b, True
    
    return None, False

def tryConvertToNumericType(a):
    if type(a) == int or type(a) == float:
        return a
    try:
        a = int(a)
        return a
    except:
        return cc.ValError(f"Can't convert str: {a} to a numeric type")

def add_c(a, b, dt=None):
    a = tryConvertToNumericType(a)
    b = tryConvertToNumericType(b)
    err, is_error = checkErrorType(a, b)
    if is_error:
        return err
    if a == None or b == None:
        return None
    return a + b

def sub_c(a, b, dt=None):
    err, is_error = checkErrorType(a, b)
    if is_error:
        return err
    a = tryConvertToNumericType(a)
    b = tryConvertToNumericType(b)
    if type(a) == cc.ValError:
        return a
    if type(b) == cc.ValError:
        return b
    return a - b

def and_c(a, b, dt=None):
    a = tryConvertToNumericType(a)
    b = tryConvertToNumericType(b)
    err, is_error = checkErrorType(a, b)
    if is_error:
        return err
    if a == None or b == None:
        return cc.Unknown()

    if type(a) == float and type(b) == float:
        try:
            fa = float32_bit_pattern(a)
            fb = float32_bit_pattern(b)
            r = fa & fb
            rf = bin(r)
            return bin2float(rf)
        except:
            return cc.ValError("ERROR: error applying not on a float")
    return a & b

def or_c(a, b, dt=None):
    a = tryConvertToNumericType(a)
    b = tryConvertToNumericType(b)
    err, is_error = checkErrorType(a, b)
    if is_error:
        return err

    return a | b

def cmp_eq_c(a, b, dt=None):
    err, is_error = checkErrorType(a, b)
    if is_error:
        return err
    return (a == b)

def cmp_le_c(a, b, dt=None):
    err, is_error = checkErrorType(a, b)
    if is_error:
        return err
    a = tryConvertToNumericType(a)
    b = tryConvertToNumericType(b)
    if type(a) == cc.ValError:
        return a
    if type(b) == cc.ValError:
        return b  
    return a <= b


def cmp_ge_c(a, b, dt=None):
    a = tryConvertToNumericType(a)
    b = tryConvertToNumericType(b)
    err, is_error = checkErrorType(a, b)
    if is_error:
        return err
    return a >= b

def cmp_lt_c(a, b, dt=None):
    err, is_error = checkErrorType(a, b)
    if is_error:
        return err
    a = tryConvertToNumericType(a)
    b = tryConvertToNumericType(b)
    if type(a) == cc.ValError:
        return a
    if type(b) == cc.ValError:
        return b
    return a < b

def cmp_gt_c(a, b, dt=None):
    err, is_error = checkErrorType(a, b)
    if is_error:
        return err
    return a > b

def cmp_ne_c(a, b, dt=None):
    err, is_error = checkErrorType(a, b)
    if is_error:
        return err
    return a != b

def xor_c(a, b, dt=None):
    a = tryConvertToNumericType(a)
    b = tryConvertToNumericType(b)
    err, is_error = checkErrorType(a, b)
    if is_error:
        return err
    return (a^b)

def shl_c(a, b, dt=None):
    a = tryConvertToNumericType(a)
    b = tryConvertToNumericType(b)
    err, is_error = checkErrorType(a, b)
    if is_error:
        return err
    
    return (a << b)

def shr_c(a, b, dt=None):
    a = tryConvertToNumericType(a)
    b = tryConvertToNumericType(b)
    err, is_error = checkErrorType(a, b)
    if is_error:
        return err
    return (a >> b)

def sar_c(a, b, dt):
    a = tryConvertToNumericType(a)
    b = tryConvertToNumericType(b)
    err, is_error = checkErrorType(a, b)
    if is_error:
        return err
    ba = 32
    if dt in cc.DTs_16:
        ba = 16
    if dt in cc.DTs_64:
        ba = 64
    if dt in cc.DTs_8:
        ba = 8
    
    sb = (2**(ba-1))
    sign = a & sb
    a &= (sb-1)
    a >>= b
    a |= sign
    return a

def mull_c(a, b, dt=None):
    err, is_error = checkErrorType(a, b)
    if is_error:
        return err
    a = tryConvertToNumericType(a)
    b = tryConvertToNumericType(b)
    if type(a) == cc.ValError:
        return a
    if type(b) == cc.ValError:
        return b
    return a*b

def not_c(a, b=None, dt=None):
    if type(a) == cc.ValError:
        return a
    elif type(a) == cc.Unknown:
        return a
    elif type(a) == float:
        # TODO: Fix me
        # not necessarily a 32-bit val
        try:
            fb = float32_bit_pattern(a)
            not_a = ~fb
            b = bin(not_a)
            return bin2float(b)
        except:
            return cc.ValError("ERROR: error applying not on a float")
    a = tryConvertToNumericType(a)
    if type(a) != int:
        return a
    return ~a

# NOT CORRECT:
def ctz_c(a, b=None, dt=None):
    a = tryConvertToNumericType(a)
    err, is_err = checkErrorType(a,b)
    if is_err:
        return err
    
    s = bin(a)[2:]
    return len(s) - len(s.rstrip('0'))

def clz_c(a, b=None, dt=None):
    a = tryConvertToNumericType(a)
    err, is_err = checkErrorType(a,b)
    if is_err:
        return err
    
    sl = 32
    if dt in cc.DTs_16:
        sl = 16
    if dt in cc.DTs_64:
        sl = 64
    
    s = bin(a)[2:]
    s = '0'*(sl-len(s)) + s
    return len(s) - len(s.lstrip('0'))

def max_c(a, b, dt=None):
    a = tryConvertToNumericType(a)
    b = tryConvertToNumericType(b)
    err, is_err = checkErrorType(a,b)
    if is_err:
        return err
    if a == None or b == None:
        return cc.Unknown()
    if a >= b:
        return a
    return b

def min_c(a, b, dt=None):
    a = tryConvertToNumericType(a)
    b = tryConvertToNumericType(b)
    err, is_err = checkErrorType(a, b)
    if is_err:
        return err
    if a == None or b == None:
        return cc.Unknown()
    if a >= b:
        return b
    else:
        return a

def cast_to_null(a):
    return a

def cast_to_int64(a, b=None, dt=None):
    a = tryConvertToNumericType(a)
    if type(a) == cc.ValError:
        return a    
    if type(a) == float:
        a = int(a)
    return c_int64(a).value

def cast_to_int32(a, b=None, dt=None):
    a = tryConvertToNumericType(a)
    if type(a) == cc.ValError:
        return a
    if type(a) == float:
        a = int(a)
    return c_int32(a).value

def cast_to_int16(a, b=None, dt=None):
    if type(a) == cc.Unknown or type(a) == cc.ValError:
        return a
    if a == None:
        return cc.Unknown()
    return c_int16(a).value

def cast_to_int8(a, b=None, dt=None):
    if type(a) == cc.Unknown or type(a) == cc.ValError:
        return a
    return c_int8(a).value

def cast_to_int64u(a, b=None, dt=None):
    if type(a) == cc.Unknown or type(a) == cc.ValError:
        return a
    return c_uint64(a).value

def cast_to_int32u(a, b=None, dt=None):
    if type(a) == cc.Unknown or type(a) == cc.ValError:
        return a
    return c_uint32(a).value

def cast_to_int16u(a, b=None, dt=None):
    if type(a) == cc.Unknown or type(a) == cc.ValError:
        return a
    return c_uint16(a).value

def cast_to_int8u(a, b=None, dt=None):
    if type(a) == cc.Unknown or type(a) == cc.ValError:
        return a
    return c_uint8(a).value

def cast_to_int128(a):
    return a

def cast_to_ubyte1(a, b=None, dt=None):
    if type(a) == cc.Unknown or type(a) == cc.ValError:
        return a
    return c_ubyte(a).value

def cast_to_byte1(a, b=None, dt=None):
    if type(a) == cc.Unknown or type(a) == cc.ValError:
        return a
    return c_byte(a).value

def cast_to_int32f(a, b=None, dtype=None):
    a = tryConvertToNumericType(a)
    if type(a) == cc.ValError:
        return a
    return c_float(a).value

def cast_to_int64f(a, b=None, dt=None):
    if type(a) == cc.Unknown:
        return a
    a = tryConvertToNumericType(a)
    if type(a) == cc.ValError:
        return a
    return c_float(a).value

def cmps_op(a, b, dt):
    sl = 32
    if dt in cc.DTs_16:
        sl = 16
    if dt in cc.DTs_64:
        sl = 64
    a = tryConvertToNumericType(a)
    if type(a) == cc.ValError:
        return a
    c = a >> (sl - 1)
    return c & 1

# INCORRECT:
def divmod_c(a, b, dt):
    sl = 32
    if dt in cc.DTs_16:
        sl = 16
    if dt in cc.DTs_64:
        sl = 64
    a = tryConvertToNumericType(a)
    b = tryConvertToNumericType(b)
    if type(a) == cc.ValError:
        return a
    if type(b) == cc.ValError:
        return b
    if b == 0:
        return cc.ValError(a, b, "Div by Zero")
    c,d = divmod(a, b)
    r = shl_c(d, sl)
    r = r + c
    return r

def div_c(a, b, dt=None):
    a = tryConvertToNumericType(a)
    b = tryConvertToNumericType(b)
    err, is_error = checkErrorType(a, b)
    if is_error:
        return err
    if b == 0:
        return cc.ValError(a, b, "Div by Zero")
    c, d = divmod(a, b)
    return c

def cmp_z_c(a, b, dt=None):
    return a == 0

def cmp_nz_c(a, b, dt=None):
    return a != 0

# TODO: These are incorrect:
def cmp_s_c(a, b, dt=None):
    a = tryConvertToNumericType(a)
    if type(a) == cc.ValError:
        return a
    return a < 0

def cmp_ns_c(a, b, dt=None):
    return a > 0

def cmp_cpu_cond_nbe(a, b=None, dt=None):
    err, is_err = checkErrorType(a, b)
    if is_err:
        return err
    return a > b

def cmp_p_cpu(a, b=None, dt=None):
    if type(a) == cc.Unknown:
        return a
    if type(a) == cc.ValError:
        return a
    
    if type(a) == float:
        try:
            fb = float32_bit_pattern(a)
            b = bin(fb)[2:]
            return (sum([b0 == '1' for b0 in b]) % 2) == 0
        except:
            return cc.ValError("Error: CmpPCPU: float")
    else:
        b = bin(a)[2:]
        return (sum([b0 == '1' for b0 in b]) % 2) == 0

def cmp_np_cpu(a, b=None, dt=None):
    r = cmp_p_cpu(a, b, dt)
    if type(r) == bool:
        return not r
    return r 


# --------------------------

def cmp_o_c(a, b, dt=None):
    if type(a) == cc.Unknown or type(a) == cc.ValError:
        return a
    if a == None:
        return cc.Unknown()

    return a < 0

def cmp_be_c(a, b, dt=None):
    err, is_err = checkErrorType(a, b)
    if is_err:
        return err
    return a <= b

# COND NO: 0 t59):Ity_I6
# COND NO: 128 t59):Ity_I6
def cmp_no_c(a, b, dt=None):
    err, is_err = checkErrorType(a, b)
    if is_err:
        return err
    return a > 0

def reinterp_op_c(a, b=None, dt=None):
    if type(a) == cc.Unknown:
        return a
    a = tryConvertToNumericType(a)
    if type(a) == cc.ValError:
        return a
    b = bin(a)
    f = bin2float(b)
    return f

def reinterpf_op_c(a, b=None, dt=None):
    if type(a) == cc.Unknown:
        return a
    a0 = tryConvertToNumericType(a)
    if type(a0) == cc.ValError:
        return a0
    
    if type(a0) == int:
        return a0
    
    elif type(a0) == float:
        f0 = float32_bit_pattern(a0)
        return f0
    else:
        return cc.Unknown()

def x87_fp_op_c(a=None, b=None, dt=None):
    return cc.Unknown()

# Implement HI cast
bin_ops = {
    cc.ADD_OP: add_c,
    cc.SUB_OP: sub_c,
    cc.AND_OP: and_c,
    cc.OR_OP: or_c,
    cc.CMPEQ_OP: cmp_eq_c,
    cc.CMPLE_OP: cmp_le_c,
    cc.CMPGE_OP: cmp_ge_c,
    cc.CMPGT_OP: cmp_gt_c,
    cc.CMPLT_OP: cmp_lt_c,
    cc.CMPNE_OP: cmp_ne_c,
    cc.XOR_OP: xor_c,
    cc.SHL_OP: shl_c,
    cc.SHR_OP: shr_c,
    cc.SAR_OP: sar_c,
    cc.MULL_OP: mull_c,
    cc.CTZ_OP: ctz_c,
    cc.CLZ_OP: clz_c,
    cc.NOT_OP: not_c,
    cc.MUL_OP: mull_c,
    cc.CAST64_OP: cast_to_int64,
    cc.CAST32_OP: cast_to_int32,
    cc.CAST32U_OP: cast_to_int32u,
    cc.CAST1U_OP: cast_to_ubyte1,
    cc.CAST8U_OP: cast_to_int8u,
    cc.CAST32S_OP: cast_to_int32,
    cc.CAST128HI_OP: cast_to_int128,
    cc.CAST8S_OP: cast_to_int8,
    cc.CAST16U_OP: cast_to_int16u,
    cc.CAST16S_OP: cast_to_int16,
    cc.CAST64HL_OP: cast_to_int64,
    cc.DIVMODU128_OP: divmod_c,
    cc.CAST128_OP: cast_to_int128,
    cc.DIVMODU64_OP: divmod_c,
    cc.DIV_OP: div_c,
    cc.CMPS_OP: cmps_op,
    cc.DIVMODS128_OP: divmod_c,
    cc.DIVMODS64_OP: divmod_c,
    cc.CAST64HI_OP: cast_to_int64,
    cc.CAST32HL_OP: cast_to_int32,
    cc.CASTF32_OP: cast_to_int32f,
    cc.CAST64F_OP: cast_to_int64f,
    cc.CMPF64_OP: cast_to_int64f,
    cc.CMPLCPU_OP: cmp_lt_c,
    cc.CMPNLCPU_OP: cmp_ge_c,
    cc.CMPZCPU_OP: cmp_z_c,
    cc.CMPNZCPU_OP: cmp_nz_c,
    cc.CASCMPNE_OP: cmp_ne_c,
    cc.CMPSCPU_OP: cmp_s_c,
    cc.CMPLECPU_OP: cmp_le_c,
    cc.CMPNLECPU_OP: cmp_gt_c,
    cc.CASTI64S_OP: cast_to_int64,
    cc.CAST64U_OP: cast_to_int64u,
    cc.CMPNOCPU_OP: cmp_no_c,
    cc.CAST16HL_OP: cast_to_int16,
    cc.CMPBECPU_OP: cmp_be_c,
    cc.CMPOCPU_OP: cmp_o_c,
    cc.CMPNSCPU_OP: cmp_ns_c,
    cc.CMPNBECPU_OP: cmp_cpu_cond_nbe,
    cc.MAX_OP: max_c,
    cc.MIN_OP: min_c,
    cc.REINTERP_OP: reinterp_op_c,
    cc.CMPPCPU_OP: cmp_p_cpu,
    cc.CMPNPCPU_OP: cmp_np_cpu,
    cc.CAST32HI_OP: cast_to_int32,
    cc.CAST16_OP: cast_to_int16,
    cc.GETI_OP: x87_fp_op_c,
    cc.PUTI_OP: x87_fp_op_c,
    cc.REINTERPF_OP: reinterpf_op_c
}

cast_ops = {
    cc.DT_NULL: cast_to_null,
    cc.DT_I8: cast_to_int8,
    cc.DT_I16: cast_to_int16,
    cc.DT_I32: cast_to_int32,
    cc.DT_I64: cast_to_int64,
    cc.DT_I1: cast_to_byte1,
    cc.DT_1U: cast_to_ubyte1,
    cc.DT_8U: cast_to_int8u,
    cc.DT_16U: cast_to_int16u,
    cc.DT_32U: cast_to_int32u,
    cc.DT_64U: cast_to_int64u,
    cc.DT_8S: cast_to_int8,
    cc.DT_16S: cast_to_int16,
    cc.DT_32S: cast_to_int32,
    cc.DT_64S: cast_to_int64,
    cc.DT_V128: cast_to_int128,
    cc.DT_32F: cast_to_int32f,
    cc.DT_64F: cast_to_int64f,
    cc.DT_64F0x2: cast_to_int64f,
}


bops = {"Add": add_c, "Sub": sub_c, "And": and_c, "Or": or_c, "CmpEQ": cmp_eq_c, "CmpLE": cmp_le_c, "CmpGE": cmp_ge_c, "CmpGT": cmp_gt_c, "CmpLT": cmp_lt_c, "CmpNE": cmp_ne_c, "Xor": xor_c, "Shl": shl_c, "Shr": shr_c, "Sar": sar_c, "Mull": mull_c, "Ctz": ctz_c, "Clz": clz_c, "Not": not_c, "Mul": mull_c, "Max": max_c}
cast_op = {"32": cast_to_int32, "64": cast_to_int64, "16S": cast_to_int16, "16": cast_to_int16, "8": cast_to_int8, "32U": cast_to_int32u, "64U": cast_to_int64u, "8U": cast_to_int8u, "32S": cast_to_int32, "64S": cast_to_int64, "V128": cast_to_int128, "16U": cast_to_int16u, "8S": cast_to_int8, "1U": cast_to_ubyte1, "1": cast_to_byte1}

supported_types = ["32", "32U", "32S", "8", "8U", "8S", "64", "64S", "64U", "16", "16U", "16S", "V128", "1U", "1"]


def get_op(op):
    return [k for k in bops.keys() if k in op]

def get_bin_op(op):
    op_name = get_op(op)
    if len(op_name) == 0:
        return None
    if len(op_name) > 1 and op[:4]!="Mull":
        assert len(op_name) > 1
    
    bop = op_name[0]
    return bop


def binary_op(op, a, b):
    op, dtype, end = cc.decode_operation(op)
    if not op in bin_ops:
        print(op)
        raise Exception()
    retv = bin_ops[op](a, b, dtype)
    if type(retv) == cc.Unknown or type(retv) == cc.ValError:
        return retv
    return cast_ops[dtype](retv)

def is_cast_op(op):
    if not "to" in op:
        return False
    ts = op.split("to")
    return ts[0] in supported_types and ts[1] in supported_types

def cast_oper(op, a):
    ts = op.split("to")
    t1 = ts[0]
    t2 = ts[1]
    if not t1 in supported_types or not t2 in supported_types:
        return None
    
    else:
        return cast_op[t2](cast_op[t1](a))
