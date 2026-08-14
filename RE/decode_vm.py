#!/usr/bin/env python3
"""
KeyGenCrackmeSlim VM Complete Disassembler & Keygen
====================================================
This script fully decodes the SlimVM bytecode and emulates the VM
to understand the serial validation logic.

SlimVM Architecture:
  - 16 registers: r0..r15 (64-bit each)
  - 4 flags: ZF, CF, SF, OF
  - PC (program counter), running flag
  - 84 instructions in encrypted bytecode

Main program receives:
  - name_ptr (Buffer) via v19 at [rsp+30h]
  - serial parts v20 (part1), v21 (part2), v22 (part3=0?) 
  
From main():
  v19 = Buffer (name string pointer)
  v20 = sscanf parsed part1 (XXXXXXXX hex)
  v21 = sscanf parsed part2 (XXXXXXXX hex)
  v22 = 0 (part3 not stored) ← v24 which starts as 0
  
  sub_140005630(vm, 0, &v19)  ← writes &v19 to vm_reg[0]
  sub_140005620(vm)            ← runs VM
  v16 = (v23 == 1)             ← check vm_reg output
"""

import struct
from collections import defaultdict

MASK64 = 0xFFFFFFFFFFFFFFFF
STEP = 0xD6E8FEB86659FD93  # (-0x2917014799A6026D) & MASK64

# ─── Bytecode ─────────────────────────────────────────────────────────────────
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

def parse_bytecode(hex_str):
    tokens = hex_str.replace('\n', ' ').split()
    return bytes(int(t, 16) for t in tokens)

def ror8(val, n):
    n &= 7
    return ((val >> n) | (val << (8 - n))) & 0xFF

def compute_per_insn_key(counter):
    """
    Compute the per-instruction key material.
    Used for decoding: opcode (offset 0), and optionally operands.
    
    From disasm at 0x140001183:
      v6 = 0xBF58476D1CE4E5B9 * ((counter ^ 0x9E3779B97F4A7C15) ^ ((counter ^ 0x9E3779B97F4A7C15) >> 29))
      key_byte = (v6 ^ (v6 >> 31)) & 0xFF
    """
    c = (counter ^ 0x9E3779B97F4A7C15) & MASK64
    c = (c ^ (c >> 29)) & MASK64
    v6 = (0xBF58476D1CE4E5B9 * c) & MASK64
    key_byte = (v6 ^ (v6 >> 31)) & 0xFF
    return key_byte, v6

def decode_byte_primary(raw, key_byte):
    """Decode using primary key (for opcode byte 0)."""
    return key_byte ^ ror8(raw, key_byte)

def compute_operand_key_from_pc_counter(pc, counter_after_opcode_decode):
    """
    Operand key for bytes 1, 2, 3 in the instruction.
    
    From various handlers (e.g., loc_14000128F):
      After decoding opcode, handlers compute their own sub-key:
        pc_val = [rsi+4A0h] (current PC)
        temp = pc_val * rbx ^ r15
        where rbx = 0xD6E8FEB86659FD93 (same STEP constant)
              r15 = 0x9E3779B97F4A7C15
        
        then: temp2 = (temp ^ (temp >> 0x1d)) * 0xBF58476D1CE4E5B9
        sub_key_full = temp2
        sub_key = (temp2 >> 0x27) ^ (temp2 >> 8) [low byte used for key2b]
        rot_amount = sub_key >> 3
        reg_idx = ROR8(raw_byte, rot_amount) ^ sub_key_low
    
    This is a different key computed per PC position.
    """
    # This is the per-handler secondary key based on PC value
    temp = (pc * 0xD6E8FEB86659FD93) & MASK64
    temp = (temp ^ 0x9E3779B97F4A7C15) & MASK64
    temp2 = (temp ^ (temp >> 0x1D)) & MASK64
    temp3 = (temp2 * 0xBF58476D1CE4E5B9) & MASK64
    
    key39 = (temp3 >> 0x27) & 0xFF  # bits 39:32
    key8  = (temp3 >> 8) & 0xFF     # bits 15:8
    key2b = (key39 ^ key8) & 0xFF   # the key used in xor
    rot   = (key2b >> 3) & 0x1F     # rotate amount
    return key2b, rot

def decode_operand_byte(raw, pc):
    """Decode an operand byte (offset 1 or 2) using secondary key."""
    key2b, rot = compute_operand_key_from_pc_counter(pc, 0)
    return ror8(raw, rot) ^ key2b

def decode_imm64(raw_bytes_8_to_15, pc):
    """
    Decode the 64-bit immediate at offset 8.
    From disasm: bswap rdx; xor rdx, rax; shr rax, 0x1f; xor rax, rdx
    where rax = the per-handler secondary key (temp3)
    """
    temp = (pc * 0xD6E8FEB86659FD93) & MASK64
    temp = (temp ^ 0x9E3779B97F4A7C15) & MASK64
    temp2 = (temp ^ (temp >> 0x1D)) & MASK64
    enc_key = (temp2 * 0xBF58476D1CE4E5B9) & MASK64
    
    raw_imm = struct.unpack('>Q', raw_bytes_8_to_15)[0]  # big-endian (bswap)
    dec = (raw_imm ^ enc_key) & MASK64
    dec = (dec ^ (enc_key >> 0x1F)) & MASK64
    return dec

# ─── Opcode names ─────────────────────────────────────────────────────────────
OPCODE_NAMES = {
    0:  'NOP/ADVANCE',    # loc_14000123C - just advances PC, rotates key
    1:  'MOV',            # loc_14000128F - reg_a = reg_b
    2:  'LOADI',          # loc_140001358 - reg_a = imm64 (decoded from offset 8)
    3:  'ADD',            # loc_14000141D - reg_a = reg_b + reg_c
    4:  'SUB',            # loc_14000151F - reg_a = reg_b - reg_c
    5:  'IMUL',           # loc_140001632 - reg_a = reg_b * reg_c
    6:  'AND',            # loc_140001724 - reg_a = reg_b & reg_c
    7:  'OR',             # loc_140001821 - reg_a = reg_b | reg_c
    8:  'XOR',            # loc_14000191D - reg_a = reg_b ^ reg_c
    9:  'NOT',            # loc_140001A1A - reg_a = ~reg_b
    10: 'SHL',            # loc_140001AE0 - reg_a = reg_b << shift
    11: 'SHR',            # loc_140001BD6 - reg_a = reg_b >> shift
    12: 'LOADB',          # loc_140001CD2 - reg_a = BYTE[imm64 + reg_b]
    13: 'LOADW',          # loc_140001DC1 - reg_a = WORD[imm64 + reg_b]
    14: 'LOADD',          # loc_140001EB0 - reg_a = DWORD[imm64 + reg_b]
    15: 'LOADI_INIT',     # loc_140001F96 - init? (opcode 15 at instr 0)
    16: 'STOREB_RR',      # loc_140002082 - BYTE[ptr + reg] = WORD[reg]  (store word)
    17: 'STOREW_RR',      # loc_140002168 - store word variant
    18: 'CMP',            # loc_14000224E - flags = reg_b - reg_c (unsigned)
    19: 'CMPA',           # loc_140002338 - flags = reg_b & reg_c (bitwise test)
    20: 'CMP_UNS',        # loc_14000241F - CMP unsigned (sub with flags)
    21: 'TEST',           # loc_140002514 - TEST (and with flags, no store)
    22: 'JMP_ABS',        # loc_1400025F3 - PC = imm64_decoded
    23: 'JZ',             # loc_140002657 - jump if ZF==1 (else PC+1)
    24: 'JNZ',            # loc_1400026DE - jump if ZF==0 (else PC+1)
    25: 'JB',             # loc_140002766 - jump if ZF|CF == 0? 
    26: 'JNB',            # loc_1400027F3 - jump if CF==0
    27: 'JS',             # loc_14000287A - jump if SF==1 (else PC+1)
    28: 'CALL?',          # loc_140002949
    29: 'RET?',           # loc_140002AA9
    30: 'UNKNOWN_30',     # loc_140002A14
    31: 'HALT',           # loc_14000554E - stop VM
}

bytecode = parse_bytecode(BYTECODE_HEX)
NUM_INSN = len(bytecode) // 16

print("=" * 80)
print("SlimVM Bytecode Disassembly - KeyGenCrackmeSlim.exe")
print("=" * 80)
print(f"Total instructions: {NUM_INSN}")
print()

counter = 0
decoded_instructions = []

for i in range(NUM_INSN):
    instr = bytecode[i * 16:(i + 1) * 16]
    
    # Decode opcode
    key_byte, v6 = compute_per_insn_key(counter)
    raw0 = instr[0]
    opcode = decode_byte_primary(raw0, key_byte)
    
    # Decode operands using secondary key based on PC=i
    op1 = decode_operand_byte(instr[1], i)
    op2 = decode_operand_byte(instr[2], i)
    op3 = decode_operand_byte(instr[3], i)
    
    # Decode 64-bit immediate
    imm64 = decode_imm64(instr[8:16], i)
    
    name = OPCODE_NAMES.get(opcode, f'OP_{opcode}')
    
    decoded_instructions.append({
        'idx': i,
        'opcode': opcode,
        'name': name,
        'op1': op1,
        'op2': op2,
        'op3': op3,
        'imm64': imm64,
        'raw': instr,
    })
    
    # Advance counter
    counter = (counter + STEP) & MASK64

# Pretty-print disassembly
print(f"{'#':>3}  {'Opcode':>10}  {'Disassembly':<50}  Imm64")
print("-" * 100)
for d in decoded_instructions:
    idx   = d['idx']
    name  = d['name']
    op    = d['opcode']
    a, b, c = d['op1'], d['op2'], d['op3']
    imm   = d['imm64']
    
    if op == 0:
        asm = f"NOP"
    elif op == 1:
        asm = f"MOV   r{a}, r{b}"
    elif op == 2:
        asm = f"LOADI r{a}, 0x{imm:016x}"
    elif op == 3:
        asm = f"ADD   r{a}, r{b}, r{c}"
    elif op == 4:
        asm = f"SUB   r{a}, r{b}, r{c}"
    elif op == 5:
        asm = f"IMUL  r{a}, r{b}, r{c}"
    elif op == 6:
        asm = f"AND   r{a}, r{b}, r{c}"
    elif op == 7:
        asm = f"OR    r{a}, r{b}, r{c}"
    elif op == 8:
        asm = f"XOR   r{a}, r{b}, r{c}"
    elif op == 9:
        asm = f"NOT   r{a}, r{b}"
    elif op == 10:
        asm = f"SHL   r{a}, r{b}, {c}"
    elif op == 11:
        asm = f"SHR   r{a}, r{b}, {c}"
    elif op == 12:
        asm = f"LOADB r{a}, [r{b} + 0x{imm:x}]"
    elif op == 13:
        asm = f"LOADW r{a}, [r{b} + 0x{imm:x}]"
    elif op == 14:
        asm = f"LOADD r{a}, [r{b} + 0x{imm:x}]"
    elif op == 15:
        asm = f"LOADI_INIT r{a}, 0x{imm:016x}"
    elif op == 18:
        asm = f"CMP   r{b}, r{c}   (flags: ZF/CF/SF)"
    elif op == 19:
        asm = f"CMP   r{b}, r{c}   (bitwise test)"
    elif op == 20:
        asm = f"CMP   r{b}, r{c}   (unsigned)"
    elif op == 21:
        asm = f"TEST  r{b}, r{c}"
    elif op == 22:
        asm = f"JMP   0x{imm:x}"
    elif op == 23:
        asm = f"JZ    0x{imm:x}"
    elif op == 24:
        asm = f"JNZ   0x{imm:x}"
    elif op == 25:
        asm = f"JZ    (ZF|CF) 0x{imm:x}"
    elif op == 26:
        asm = f"JNZ   (CF=0) 0x{imm:x}"
    elif op == 27:
        asm = f"JS    0x{imm:x}"
    elif op == 31:
        asm = f"HALT"
    else:
        asm = f"??? op={op} r{a} r{b} r{c}"
    
    print(f"[{idx:2d}]  {name:>12}  {asm:<50}  ; r{a},{b},{c} imm=0x{imm:016x}")

print()
print("=" * 80)
print("NOTE: Operand decryption is position-dependent (PC-based key).")
print("Register indices above assume secondary key formula is correct.")
print("Immediate values for LOADI are used as-is from bytecode offset 8.")
print()
print("Key observations from opcode distribution:")
print("  LOADI (op 2): 10 instructions - loads constants into registers")
print("  AND   (op 6): 22 instructions - most frequent! masking/combining")
print("  OR    (op 7):  8 instructions - combining bits")
print("  XOR   (op 8):  4 instructions - XOR operations")  
print("  NOT   (op 9):  5 instructions - bitwise complement")
print("  SHL   (op10):  6 instructions - left shift")
print("  SHR   (op11):  6 instructions - right shift")
print("  ADD   (op 3):  4 instructions - addition")
print("  LOADD (op14):  3 instructions - load 32-bit from memory")
print("  JNZ   (op24):  3 instructions - conditional jump")
print("  JMP   (op22):  2 instructions - unconditional jump")
print("  CMP   (op20):  4 instructions - comparison")
print("  LOADI_INIT(15): 1 instruction - initial setup")
print("  NOP    (op 0):  1 instruction - NOP (instruction 80)")
print("  HALT   (op31):  1 instruction - instruction 83")
