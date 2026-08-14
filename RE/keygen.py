#!/usr/bin/env python3
"""
KeyGenCrackmeSlim Keygen
========================
Generates valid serial numbers for any username.

Usage:
    python keygen.py <name>
    python keygen.py  (interactive mode)
"""

import struct
import sys

MASK64 = 0xFFFFFFFFFFFFFFFF
MASK32 = 0xFFFFFFFF
STEP   = 0xD6E8FEB86659FD93

# ─── VM Bytecode ──────────────────────────────────────────────────────────────
BYTECODE_HEX = (
    "4f 0c 4c 4c 00 00 00 00 ca 00 97 16 a6 7c 31 40 "
    "ca c2 d2 d2 00 00 00 00 4b 26 a3 84 54 c0 71 8d "
    "a6 45 59 59 00 00 00 00 7e 33 1e 2f ed de a9 ae "
    "38 5e 5f df 00 00 00 00 96 37 88 78 f9 9a bf cd "
    "f7 c0 c4 c4 00 00 00 00 fc 68 8e 48 78 af c4 bd "
    "2f 7d bd 7c 00 00 00 00 8b aa 46 d8 d1 28 f5 6d "
    "7c 40 40 40 00 00 00 00 4e f4 35 34 93 31 10 f4 "
    "5c fc ff 7f 00 00 00 00 2c b4 20 80 5b f9 fd e5 "
    "71 7d 9d bd 00 00 00 00 d5 35 1a 14 90 d2 ee 8d "
    "9d f8 f8 d0 00 00 00 00 f5 62 0c 23 be 1f 1a e5 "
    "36 bd be 3e 00 00 00 00 9d 70 89 cd f2 b7 79 de "
    "fa 19 15 11 00 00 00 00 53 be c0 be ff 51 88 f5 "
    "c0 fc c4 d4 00 00 00 00 1a e4 2e 17 8c 6a 9a 08 "
    "17 fd 3d 1d 00 00 00 00 38 63 b6 28 50 59 ed 10 "
    "a0 72 72 22 00 00 00 00 41 67 98 7f 5a e5 25 47 "
    "f1 5a 56 56 00 00 00 00 76 97 59 20 55 be 0e 52 "
    "9b ad 2c 6c 00 00 00 00 0a f6 ab 69 8d 61 b2 66 "
    "ac dd 1c 5c 00 00 00 00 0f 17 4a 46 13 04 72 5f "
    "80 65 65 c5 00 00 00 00 3a 45 d2 21 a7 dc 2e 2b "
    "41 84 82 83 00 00 00 00 73 31 02 1a 4f 14 86 06 "
    "21 55 55 41 00 00 00 00 20 44 68 30 aa d2 57 14 "
    "db 2d 0d 4d 00 00 00 00 fb 71 5a 0a 7e eb 6a d2 "
    "47 9b 9b 99 00 00 00 00 01 e8 15 0b 08 3d cf 7c "
    "00 5b 5b 4f 00 00 00 00 31 cf 30 ea 42 34 d4 06 "
    "f9 9c 9a 9a 00 00 00 00 7f e9 4e 63 19 b0 4d cc "
    "3b 55 55 5d 00 00 00 00 58 2b b1 c1 c0 60 54 38 "
    "18 82 82 82 00 00 00 00 dd d9 4a bf 53 95 82 75 "
    "f0 bf bd bd 00 00 00 00 6f f2 2c e2 86 e6 be 28 "
    "3c 0e 3e 5e 00 00 00 00 c8 15 ca 10 aa 45 e1 19 "
    "80 4d 8c 0d 00 00 00 00 0a a0 fc 7d 0e e1 30 07 "
    "92 e5 e5 45 00 00 00 00 72 f8 60 fc 97 88 2a 5b "
    "11 55 5d 4d 00 00 00 00 b5 82 74 38 05 06 56 42 "
    "9a 7e fd 7c 00 00 00 00 9b 51 07 92 9a 3d f8 34 "
    "57 c0 c6 c5 00 00 00 00 83 3a 81 d8 79 b5 c5 43 "
    "f4 15 f5 d5 00 00 00 00 a5 6a 13 16 5d 56 ab 3a "
    "fe 3e 3e 7e 00 00 00 00 d3 eb 0f 69 ac f2 e0 f8 "
    "21 c8 e8 e8 00 00 00 00 b3 40 ab 78 94 eb 3a 41 "
    "a8 51 59 45 00 00 00 00 cb ef 92 fe 76 79 55 a0 "
    "38 c6 f6 ce 00 00 00 00 04 0a 6f f5 a6 53 dd e6 "
    "e6 4a 4a 5e 00 00 00 00 52 d2 9f 99 98 ac 97 3c "
    "d7 dc 5c 5d 00 00 00 00 5e 72 f7 76 aa 30 70 bd "
    "66 85 85 05 00 00 00 00 86 36 24 e8 ac ac 2f 35 "
    "71 fd 7e ff 00 00 00 00 a2 c9 70 ed 5d 28 ff c3 "
    "77 f5 b5 55 00 00 00 00 e8 fd 50 42 c5 d8 ae 70 "
    "c6 86 80 87 00 00 00 00 00 96 26 93 3a 1e 83 c0 "
    "d1 d8 d8 f0 00 00 00 00 44 78 bf 3b 1f 39 1e e1 "
    "2f 8d cd 4d 00 00 00 00 88 d4 66 2c 9f bb 6f f4 "
    "92 56 56 16 00 00 00 00 8c 17 85 56 81 6b 66 a2 "
    "dd 46 45 44 00 00 00 00 20 af 35 db 7b 0a 47 e9 "
    "f2 87 80 81 00 00 00 00 52 55 0c f1 71 5a 82 ba "
    "f7 32 32 62 00 00 00 00 7f eb 50 94 73 1b 26 d6 "
    "3f 54 48 58 00 00 00 00 b5 23 e2 27 a9 84 13 99 "
    "ce 91 99 99 00 00 00 00 00 c1 50 8d 68 8e b5 26 "
    "db 19 17 13 00 00 00 00 4e d3 a3 53 77 bc 8d bf "
    "71 45 46 44 00 00 00 00 62 5b d0 15 e7 b7 40 5a "
    "62 06 06 56 00 00 00 00 95 b8 ae 77 20 85 65 69 "
    "45 1c 9f 9d 00 00 00 00 5f e4 71 c7 43 53 3e 52 "
    "62 12 12 02 00 00 00 00 a7 bc 47 d6 30 6f 27 15 "
    "c6 05 45 85 00 00 00 00 8d f2 cf a5 23 c9 2c 78 "
    "34 9d fd 3d 00 00 00 00 eb 5c 92 7c cf a5 e9 1e "
    "21 40 42 43 00 00 00 00 e5 52 14 06 bc 9e 46 23 "
    "8f 4c 4c 48 00 00 00 00 e4 5b 88 64 4b fc 15 c1 "
    "51 fc cc dc 00 00 00 00 8a f7 4d 9f 62 f3 9b 4d "
    "d7 62 12 32 00 00 00 00 eb 47 3e 3c a3 51 27 d0 "
    "72 46 45 47 00 00 00 00 38 d2 76 ab df 4b 43 95 "
    "cf c3 c3 c6 00 00 00 00 26 81 af 22 0f f9 c6 36 "
    "63 e6 de fe 00 00 00 00 a5 28 be 26 6e 2c da 1d "
    "06 94 94 96 00 00 00 00 e5 8a 37 7a 78 f7 4c 1e "
    "26 cc cd cd 00 00 00 00 60 ab 6a 32 2b 50 37 9e "
    "8e 3c 3d bc 00 00 00 00 8e 03 3a 25 ac c2 f0 fc "
    "99 1d 1d 1d 00 00 00 00 76 41 d0 12 60 9b 74 2f "
    "2c 46 06 06 00 00 00 00 f0 ea 49 f8 6e b0 60 87 "
    "84 40 50 4c 00 00 00 00 0c 27 d1 b3 2a 21 10 06 "
    "8b 80 80 80 00 00 00 00 8a 72 a7 c4 49 f4 80 67 "
    "d4 62 22 22 00 00 00 00 b5 88 d6 64 d1 82 22 b7 "
    "9b c8 e8 f8 00 00 00 00 29 da 3e 89 2b 82 19 f2 "
    "f8 5a 5a 5a 00 00 00 00 97 2a c6 f1 b8 af 96 b1 "
    "e8 d4 f4 f4 00 00 00 00 01 19 1c 15 e6 d4 9e 8d "
    "02 5b 4b 5b 00 00 00 00 0c 57 83 ab 96 4d d6 86 "
    "64 dc dc dc 00 00 00 00 fb 96 d4 18 8b cd 73 66 "
    "9c be be be 00 00 00 00 7c 8b d8 cd 9e d8 7d 93 "
    "a7 4c 4d 4d 00 00 00 00 7b 33 f2 ff 47 aa 35 d1 "
    "ca dd 5d dd 00 00 00 00 ff 30 20 6d 65 6e ee 93 "
    "4b ff ff ff 00 00 00 00 06 51 5e 45 db 20 ff 45"
)

def _parse(hex_str):
    tokens = hex_str.replace('\n', ' ').split()
    return bytes(int(t, 16) for t in tokens)

def _ror8(val, n):
    n &= 7
    return ((val >> n) | (val << (8 - n))) & 0xFF

def _key0(counter):
    c = (counter ^ 0x9E3779B97F4A7C15) & MASK64
    c = (c ^ (c >> 29)) & MASK64
    v6 = (0xBF58476D1CE4E5B9 * c) & MASK64
    return (v6 ^ (v6 >> 31)) & 0xFF, v6

def _key1(pc):
    t = (pc * 0xD6E8FEB86659FD93) & MASK64
    t = (t ^ 0x9E3779B97F4A7C15) & MASK64
    t2 = (t ^ (t >> 0x1D)) & MASK64
    t3 = (t2 * 0xBF58476D1CE4E5B9) & MASK64
    k = ((t3 >> 0x27) ^ (t3 >> 8)) & 0xFF
    return k, t3

def _decode_op(raw, kb):
    return kb ^ _ror8(raw, kb)

def _decode_reg(raw, pc):
    k, _ = _key1(pc)
    return _ror8(raw, (k >> 3) & 0x1F) ^ k

def _decode_imm(raw8, pc):
    _, t3 = _key1(pc)
    raw = struct.unpack('>Q', raw8)[0]
    d = (raw ^ t3) & MASK64
    return (d ^ (t3 >> 0x1F)) & MASK64

# Pre-decode bytecode
_bc = _parse(BYTECODE_HEX)
_N  = len(_bc) // 16
_insns = []
_cnt = 0
for _i in range(_N):
    _b = _bc[_i*16:(_i+1)*16]
    _kb, _ = _key0(_cnt)
    _op  = _decode_op(_b[0], _kb)
    _a   = _decode_reg(_b[1], _i)
    _b2  = _decode_reg(_b[2], _i)
    _c   = _decode_reg(_b[3], _i)
    _imm = _decode_imm(_b[8:16], _i)
    _insns.append((_op, _a, _b2, _c, _imm))
    _cnt = (_cnt + STEP) & MASK64


def generate_serial(name: str) -> str:
    """
    Generate a valid serial for the given name.
    Returns serial in format 'XXXXXXXX-XXXXXXXX-XXXXXXXX'.
    """
    mem = bytearray(4096)
    # Name at mem[256]
    nb = name.encode('utf-8')[:127]
    mem[256:256+len(nb)] = nb
    # Struct at mem[0]: name_ptr, part1(dummy), part2(dummy), part3(dummy), result
    struct.pack_into('<Q', mem, 0, 256)
    struct.pack_into('<I', mem, 8,  0)
    struct.pack_into('<I', mem, 12, 0)
    struct.pack_into('<I', mem, 16, 0)
    struct.pack_into('<I', mem, 20, 0)
    
    R = [0] * 16
    ZF = CF = SF = OF = 0
    pc = 0
    running = True
    steps = 0
    
    def rdm(addr, sz):
        if addr < 0 or addr+sz > len(mem):
            return 0
        d = mem[addr:addr+sz]
        if sz == 1: return d[0]
        if sz == 2: return struct.unpack_from('<H', d)[0]
        if sz == 4: return struct.unpack_from('<I', d)[0]
        if sz == 8: return struct.unpack_from('<Q', d)[0]
        return 0
    
    while running and steps < 200000 and pc < _N:
        op, a, b, c, imm = _insns[pc]
        pc += 1; steps += 1
        
        if   op == 0:  pass                                              # NOP
        elif op == 1:  R[a] = R[b]                                      # MOV
        elif op == 2:  R[a] = imm                                       # LOADI
        elif op == 3:                                                    # ADD
            v = (R[b] + R[c]) & MASK64
            ZF = 1 if v==0 else 0; SF = v>>63
            CF = 1 if R[b]+R[c] > MASK64 else 0; R[a] = v
        elif op == 4:                                                    # SUB
            v = (R[b] - R[c]) & MASK64
            ZF = 1 if v==0 else 0; SF = v>>63
            CF = 1 if R[b]<R[c] else 0; R[a] = v
        elif op == 5:  R[a] = (R[b] * R[c]) & MASK64                   # IMUL
        elif op == 6:                                                    # AND
            R[a] = R[b] & R[c]; ZF=1 if R[a]==0 else 0; SF=R[a]>>63; CF=OF=0
        elif op == 7:                                                    # OR
            R[a] = R[b] | R[c]; ZF=1 if R[a]==0 else 0; SF=R[a]>>63; CF=OF=0
        elif op == 8:                                                    # XOR
            R[a] = R[b] ^ R[c]; ZF=1 if R[a]==0 else 0; SF=R[a]>>63; CF=OF=0
        elif op == 9:  R[a] = (~R[b]) & MASK64                         # NOT
        elif op == 10:                                                   # SHL
            sh = imm & 63; R[a] = (R[b]<<sh)&MASK64
            ZF=1 if R[a]==0 else 0; SF=R[a]>>63
        elif op == 11:                                                   # SHR
            sh = imm & 63; R[a] = R[b]>>sh
            ZF=1 if R[a]==0 else 0; SF=R[a]>>63
        elif op == 12: R[a] = rdm((R[b]+imm)&MASK64, 1)               # LOADB
        elif op == 13: R[a] = rdm((R[b]+imm)&MASK64, 2)               # LOADW
        elif op == 14: R[a] = rdm((R[b]+imm)&MASK64, 4)               # LOADD
        elif op == 15: R[a] = rdm((R[b]+imm)&MASK64, 8)               # LOADQ
        elif op == 20:                                                   # CMP
            v = (R[b]-R[c])&MASK64; ZF=1 if v==0 else 0
            CF=1 if R[b]<R[c] else 0; SF=v>>63; OF=0
        elif op == 21:                                                   # TEST
            v = R[b]&R[c]; ZF=1 if v==0 else 0; SF=v>>63; CF=OF=0
        elif op == 22: pc = imm & MASK64                               # JMP
        elif op == 23:                                                   # JZ
            if ZF: pc = imm & MASK64
        elif op == 24:                                                   # JNZ
            if not ZF: pc = imm & MASK64
        elif op == 25:                                                   # JA
            if not CF and not ZF: pc = imm & MASK64
        elif op == 26:                                                   # JB
            if CF: pc = imm & MASK64
        elif op == 31: running = False                                  # HALT
    
    p1 = R[2] & MASK32
    p2 = R[3] & MASK32
    p3 = R[6] & MASK32
    return f'{p1:08X}-{p2:08X}-{p3:08X}'


# ─── Main ─────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("=" * 45)
    print("  SlimVM Keygen Challenge - Keygen")
    print("  KeyGenCrackmeSlim.exe")
    print("=" * 45)
    print()
    
    if len(sys.argv) > 1:
        names = sys.argv[1:]
    else:
        names = []
        while True:
            try:
                n = input("Enter name (Ctrl+C to quit): ").strip()
                if n:
                    names = [n]
                    break
            except (KeyboardInterrupt, EOFError):
                print()
                sys.exit(0)
    
    for name in names:
        if not name:
            print("Error: name cannot be empty")
            continue
        serial = generate_serial(name)
        print(f"Name:   {name}")
        print(f"Serial: {serial}")
        print()
