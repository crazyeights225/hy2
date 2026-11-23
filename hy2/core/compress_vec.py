#--------------------------------------
# File: compress_vec.py
#
# Purpose: if we have a repeating sequence of blocks (ie. such as in a for loop) the goal is to remove all but the first and the last instance of these repeating blocks in the sequence.
# For instance: A,B,A,B,A,B,C,D would become A,B,A,B,C,D
# For the following for loop we are looking to analyze first and last iteration:
# for(int i=0; i<n; i++){}
# That is when i=0 and i=9
#--------------------------------------

# Input: list of tuples: (block id, thread id, block instance id)
# Consider only the block id, and thread id

# This is very ugly, needs to be replaced.

def lookahead(v, i, k):
    return v[i:i+k]

def blockInstEq(p0, p, k):
    return all([(p0[i][0] == p[i][0]) and (p0[i][1] == p[i][1]) for i in range(k)])

n = 3
def lookaheadN(v, i, k):
    patterns = []
    m = i
    for j in range(n):
        patterns.append(lookahead(v, m, k))
        m += k
    return patterns, all([(k == len(p) and blockInstEq(patterns[0], p, k)) for p in patterns])

def compressSubVec(vec, i, p, k):
    m = i
    pj = []
    cnt = 0
    while True:
        pi = lookahead(vec, m, k)
        if k > len(pi) or not blockInstEq(p, pi, k):
            break
        pj = pi
        m += k
        cnt += 1
    return pj, m, cnt

def addIndexCnt(v, i, cnt=0):
    if len(v) == 3:
        if cnt > 0:
            return (v[0], v[1], v[2], cnt)
        return v
    else:
        if cnt > 0:
            return (v[0], v[1], i, cnt)
        return (v[0], v[1], i)

# This is a monster
def compressVec(vec):
    nvec = []
    i = 0
    while i < len(vec):
        p, bp = lookaheadN(vec, i, 1)
        if bp:
            pj, i0, cnt = compressSubVec(vec, i, p[0], 1)
            nvec += [addIndexCnt(p[0][j], i+j) for j in range(1)]
            nvec += [addIndexCnt(pj[j], (i0-1)+j, cnt) for j in range(1)]
            i = i0
        else:
            p, bp = lookaheadN(vec, i, 2)
            if bp:
                pj, i0, cnt = compressSubVec(vec, i, p[0], 2)
                nvec += [addIndexCnt(p[0][j], i+j) for j in range(2)]
                nvec += [addIndexCnt(pj[j], (i0-2)+j, cnt) for j in range(2)]
                i = i0
            else:
                p, bp = lookaheadN(vec, i, 3)
                if bp:
                    pj, i0, cnt = compressSubVec(vec, i, p[0], 3)
                    nvec += [addIndexCnt(p[0][j], i+j) for j in range(3)]
                    nvec += [addIndexCnt(pj[j], (i0-3)+j, cnt) for j in range(3)]
                    i = i0
                else:
                    p, bp = lookaheadN(vec, i, 4)
                    if bp:
                        pj, i0, cnt = compressSubVec(vec, i, p[0], 4)
                        nvec += [addIndexCnt(p[0][j], i+j) for j in range(4)]
                        nvec += [addIndexCnt(pj[j], (i0-4)+j, cnt) for j in range(4)]
                        i = i0
                    else:
                        p, bp = lookaheadN(vec, i, 5)
                        if bp:
                            pj, i0, cnt = compressSubVec(vec, i, p[0], 5)
                            nvec += [addIndexCnt(p[0][j], i+j) for j in range(5)]
                            nvec += [addIndexCnt(pj[j], (i0-5)+j, cnt) for j in range(5)]
                            i = i0
                        else:
                            nvec.append(addIndexCnt(vec[i], i))
                            i += 1
    return nvec
