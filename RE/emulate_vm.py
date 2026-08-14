#!/usr/bin/env python3
"""
KeyGenCrackmeSlim VM Emulator + Keygen
=======================================
Emulates the SlimVM to understand serial validation and generate valid serials.

From main():
  sub_140005630(vm, 0, &v19)  --> vm_reg[0] = pointer to struct:
    [ptr+0x00] = char* name_ptr (Buffer address)
    [ptr+0x08] = int   part1   (sscanf %8X first group)  
    [ptr+0x0C] = int   part2   (sscanf %8X second group)
    [ptr+0x10] = int   part3   (from v24=0... appears to be 0 initially, maybe not used)
    [ptr+0x18] = int   v23     (output: set to 1 if serial is valid)
  
  After VM runs: check v23 == 1 -> ACCESS GRANTED

VM structure in main():
  char  v27[5632]   ; VM state (stack-allocated)
  v19 = Buffer      ; name string ptr
  v20 = part1       ; from sscanf
  v21 = part2       ; from sscanf
  v22 = v24 = 0     ; part3? starts at 0
  v23 = 0           ; result flag
  
  Layout at [rsp+30h] = v19..v23 as consecutive stack vars:
    v19 (char* = 8 bytes) at offset 0  
    v20 (int = 4 bytes)   at offset 8
    v21 (int = 4 bytes)   at offset 0xC
    v22 (int = 4 bytes)   at offset 0x10
    v23 (int = 4 bytes)   at offset 0x14
"""

import struct
import ctypes

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF

# ─── Decoded VM program (from decode_vm.py output) ─────────────────────────────
# Instructions decoded with correct register indices and immediates

# The program can be summarized based on the decoded disassembly.
# Let me trace through it manually first to understand the algorithm.

# From the decoded output, the VM program (instructions 0-83):
# 
# SETUP (instructions 0-2):
# [0]  LOADI_INIT r0, 0x40317ca616970... ; but op15 reads from memory!
#                                           Actually op 15 = LOAD_QWORD r0, [r0+imm]
#      Wait - instruction 0 has opcode 15 (LOAD_QWORD), not LOADI_INIT
#      op15: reg_a=?, imm from offset 8
#      At instruction 0: raw_args=[0c,4c,4c], key decoded opcode=15
#      Recheck: op15 is LOAD_QWORD dst,[base+imm]
#      But at idx=0: the register display showed "r0,0,0"  
#      And imm = 0x40317ca616970... which looks like an address!
#
# Actually the imm for LOAD_QWORD is encrypted - let me re-check the output.
# The output showed:
# [0]  LOADI_INIT r0, 0x40317ca6169700ca  <- wrong name but showing imm from offset 8
#      This is actually: LOAD_QWORD r_dst, [r_base + imm_offset]
#      But the imm shown (0x40317ca6169700ca) is the RAW unprocessed 8 bytes
#      (the decode_imm64 may not be right for this opcode)
#
# Let me focus on what we CAN see clearly from instructions 1 onwards:
#
# [1]  LOADI r2, 0x8d71c05484a3264b  <- load constant
# [2]  LOADI r2, ...                  <- another load?  
# Wait, decoded showed:
# [ 1] op= 2 raw_args=[c2,d2,d2] -> LOADI r?, 0x8d71c05484a3264b
# [ 2] op= 2 raw_args=[45,59,59] -> LOADI r?, 0xaea9deed2f1e337e
# [ 3] op=12 (LOADB? No - the decode says LOADD in output) -> LOADB
#
# The output I see in the run:
# [1]  LOADI r2, 0x... 
# Hmm wait the decoder showed something confusing. Let me re-read the ACTUAL output:
#
# Looking at the actual run output more carefully:
# The truncated lines at the top (24 lines) probably include instructions 0-16.
# Visible from [17] onwards:
#
# [17] AND  r5, r2, r3
# [18] SHL  r5, r5, 0   ; imm=1 -> SHL r5, r5, 1
# [19] ADD  r2, r4, r5
# [20] AND  r2, r2, r7
# [21] SHR  r3, r2, 0   ; imm=7 -> SHR r3, r2, 7  
# [22] XOR  r2, r2, r3
# [23] AND  r2, r2, r7
# [24] LOADI r3, 1
# [25] ADD  r1, r1, r3   ; r1 = r1 + 1  (loop counter++)
# [26] JMP  3            ; loop back to instruction 3
# ...
# [27] LOADI r4, 0x7319c5ad
# [28] OR    r1, r2, r4
# [29] AND   r5, r2, r4
# [30] NOT   r5, r5
# [31] AND   r3, r1, r5  ; r3 = (r2 | r4) & ~(r2 & r4) = r2 XOR r4 (carry-less add)
# [32] SHL   r4, r3, 11  ; imm=0xb=11
# [33] SHR   r5, r3, 21  ; imm=0x15=21
# [34] OR    r3, r4, r5  ; ROL32(r3, 11) = rotate left 11
# [35] AND   r3, r3, r7  ; mask to 32 bits
# [36] LOADI r4, 0x51ed270b
# [37] XOR   r1, r3, r4
# [38] AND   r5, r3, r4
# [39] SHL   r5, r5, 1
# [40] ADD   r3, r1, r5  ; r3 = r3 + r4 (using XOR+carry)... or just ADD?
# [41] AND   r3, r3, r7
# [42] SHR   r4, r3, 13  ; imm=0xd=13
# [43] OR    r1, r3, r4
# [44] AND   r5, r3, r4
# [45] NOT   r5, r5
# [46] AND   r3, r1, r5  ; r3 = ROL by 13? No... (r3 | (r3>>13)) & ~((r3 & (r3>>13)))
# Hmm, pattern: OR(a,b) & ~AND(a,b) = XOR(a,b)... 
# So [43-46]: r3 = r3 XOR (r3 >> 13) ... some mixing
# 
# [47] AND   r3, r3, r7
# [48] OR    r1, r2, r3
# [49] AND   r5, r2, r3
# [50] NOT   r5, r5
# [51] AND   r6, r1, r5  ; r6 = r2 XOR r3 (same pattern)
# ...continuing with r6 mixing...

# Let me just emulate the VM directly!

def ror8(val, n):
    n &= 7
    return ((val >> n) | (val << (8 - n))) & 0xFF

def compute_per_insn_key(counter):
    c = (counter ^ 0x9E3779B97F4A7C15) & MASK64
    c = (c ^ (c >> 29)) & MASK64
    v6 = (0xBF58476D1CE4E5B9 * c) & MASK64
    key_byte = (v6 ^ (v6 >> 31)) & 0xFF
    return key_byte, v6

def decode_byte_primary(raw, key_byte):
    return key_byte ^ ror8(raw, key_byte)

def decode_operand_byte(raw, pc):
    """Secondary key based on PC position."""
    temp = (pc * 0xD6E8FEB86659FD93) & MASK64
    temp = (temp ^ 0x9E3779B97F4A7C15) & MASK64
    temp2 = (temp ^ (temp >> 0x1D)) & MASK64
    temp3 = (temp2 * 0xBF58476D1CE4E5B9) & MASK64
    key39 = (temp3 >> 0x27) & 0xFF
    key8  = (temp3 >> 8) & 0xFF
    key2b = (key39 ^ key8) & 0xFF
    rot   = (key2b >> 3) & 0x1F
    return ror8(raw, rot) ^ key2b

def decode_imm64(raw_bytes, pc):
    """Decode 64-bit immediate using secondary key."""
    temp = (pc * 0xD6E8FEB86659FD93) & MASK64
    temp = (temp ^ 0x9E3779B97F4A7C15) & MASK64
    temp2 = (temp ^ (temp >> 0x1D)) & MASK64
    enc_key = (temp2 * 0xBF58476D1CE4E5B9) & MASK64
    raw_imm = struct.unpack('>Q', raw_bytes)[0]  # bswap = big-endian
    dec = (raw_imm ^ enc_key) & MASK64
    dec = (dec ^ (enc_key >> 0x1F)) & MASK64
    return dec

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

bytecode = parse_bytecode(BYTECODE_HEX)
NUM_INSN = len(bytecode) // 16

# Pre-decode all instructions
STEP = 0xD6E8FEB86659FD93
counter = 0

instructions = []
for i in range(NUM_INSN):
    instr = bytecode[i * 16:(i + 1) * 16]
    key_byte, v6 = compute_per_insn_key(counter)
    opcode = decode_byte_primary(instr[0], key_byte)
    op1 = decode_operand_byte(instr[1], i)
    op2 = decode_operand_byte(instr[2], i)
    op3 = decode_operand_byte(instr[3], i)
    imm64 = decode_imm64(instr[8:16], i)
    instructions.append((opcode, op1, op2, op3, imm64))
    counter = (counter + STEP) & MASK64

# ─── VM Emulator ──────────────────────────────────────────────────────────────

class SlimVM:
    def __init__(self, name: str, part1: int, part2: int, part3: int = 0):
        """
        Initialize VM with serial input data.
        
        name  : the user name string
        part1 : first 32-bit serial part (from %8X)
        part2 : second 32-bit serial part (from %8X)  
        part3 : third 32-bit serial part (from %8X, stored as v24 which starts 0)
        """
        self.regs = [0] * 16
        self.ZF = 0
        self.CF = 0
        self.SF = 0
        self.OF = 0
        self.memory = bytearray(4096)
        
        # Build the input struct that the VM receives via r0
        # Layout based on main() analysis:
        #   v19 = char* name_ptr (Buffer)  -- stored as ptr
        #   v20 = int part1                -- at [ptr+0x08]
        #   v21 = int part2                -- at [ptr+0x0C]
        #   v22 = int part3 (=v24=0)       -- at [ptr+0x10]
        #   v23 = int result_flag          -- at [ptr+0x14]
        
        # Store name in memory at offset 256
        name_bytes = name.encode('utf-8')[:127]
        self.memory[256:256+len(name_bytes)] = name_bytes
        self.memory[256+len(name_bytes)] = 0
        
        # Struct starts at offset 0
        # v19 = ptr to name (address 256 in our memory space)
        struct.pack_into('<Q', self.memory, 0, 256)  # name_ptr at +0
        struct.pack_into('<I', self.memory, 8, part1 & MASK32)   # part1 at +8
        struct.pack_into('<I', self.memory, 12, part2 & MASK32)  # part2 at +12
        struct.pack_into('<I', self.memory, 16, part3 & MASK32)  # part3 at +16
        struct.pack_into('<I', self.memory, 20, 0)               # result at +20
        
        # r0 = pointer to struct (address 0 in memory)
        self.regs[0] = 0  # Will be set externally
        
        self.name = name
        self.part1 = part1
        self.part2 = part2
        self.part3 = part3
        self.pc = 0
        self.running = True
        self.steps = 0
        self.max_steps = 100000
    
    def read_mem(self, addr, size):
        """Read from emulated memory."""
        if addr < 0 or addr + size > len(self.memory):
            raise RuntimeError(f"Memory read OOB: addr=0x{addr:x} size={size}")
        data = self.memory[addr:addr+size]
        if size == 1:
            return data[0]
        elif size == 2:
            return struct.unpack_from('<H', data)[0]
        elif size == 4:
            return struct.unpack_from('<I', data)[0]
        elif size == 8:
            return struct.unpack_from('<Q', data)[0]
        return 0
    
    def run(self, verbose=False):
        """Execute VM until HALT or error."""
        while self.running and self.steps < self.max_steps:
            if self.pc >= NUM_INSN:
                break
            
            opcode, op1, op2, op3, imm64 = instructions[self.pc]
            pc_save = self.pc
            self.pc += 1
            self.steps += 1
            
            if verbose:
                print(f"  [{pc_save:2d}] op={opcode:2d} r{op1},{op2},{op3} imm=0x{imm64:x} | regs={[hex(r) for r in self.regs[:8]]}")
            
            try:
                self._execute(opcode, op1, op2, op3, imm64)
            except Exception as e:
                if verbose:
                    print(f"  ERROR at pc={pc_save}: {e}")
                break
        
        return self.regs
    
    def _execute(self, op, a, b, c, imm):
        R = self.regs
        
        if op == 0:  # NOP
            pass
        
        elif op == 1:  # MOV r_a, r_b
            R[a] = R[b]
        
        elif op == 2:  # LOADI r_a, imm64
            R[a] = imm & MASK64
        
        elif op == 3:  # ADD r_a, r_b, r_c
            result = (R[b] + R[c]) & MASK64
            self.ZF = 1 if result == 0 else 0
            self.CF = 1 if (R[b] + R[c]) > MASK64 else 0
            self.SF = (result >> 63) & 1
            R[a] = result
        
        elif op == 4:  # SUB r_a, r_b, r_c
            result = (R[b] - R[c]) & MASK64
            self.ZF = 1 if result == 0 else 0
            self.CF = 1 if R[b] < R[c] else 0
            self.SF = (result >> 63) & 1
            R[a] = result
        
        elif op == 5:  # IMUL r_a, r_b, r_c
            result = (R[b] * R[c]) & MASK64
            self.ZF = 1 if result == 0 else 0
            self.SF = (result >> 63) & 1
            R[a] = result
        
        elif op == 6:  # AND r_a, r_b, r_c
            result = R[b] & R[c]
            self.ZF = 1 if result == 0 else 0
            self.SF = (result >> 63) & 1
            self.CF = 0
            self.OF = 0
            R[a] = result
        
        elif op == 7:  # OR r_a, r_b, r_c
            result = R[b] | R[c]
            self.ZF = 1 if result == 0 else 0
            self.SF = (result >> 63) & 1
            self.CF = 0
            self.OF = 0
            R[a] = result
        
        elif op == 8:  # XOR r_a, r_b, r_c
            result = R[b] ^ R[c]
            self.ZF = 1 if result == 0 else 0
            self.SF = (result >> 63) & 1
            self.CF = 0
            self.OF = 0
            R[a] = result
        
        elif op == 9:  # NOT r_a, r_b
            result = (~R[b]) & MASK64
            R[a] = result
        
        elif op == 10:  # SHL r_a, r_b, shift
            shift = imm & 63  # shift count from imm
            result = (R[b] << shift) & MASK64
            self.ZF = 1 if result == 0 else 0
            self.SF = (result >> 63) & 1
            R[a] = result
        
        elif op == 11:  # SHR r_a, r_b, shift
            shift = imm & 63  # shift count from imm
            result = R[b] >> shift
            self.ZF = 1 if result == 0 else 0
            self.SF = (result >> 63) & 1
            R[a] = result
        
        elif op == 12:  # LOADB r_a, [r_b + imm]
            addr = (R[b] + imm) & MASK64
            R[a] = self.read_mem(addr, 1)
        
        elif op == 13:  # LOADW r_a, [r_b + imm]
            addr = (R[b] + imm) & MASK64
            R[a] = self.read_mem(addr, 2)
        
        elif op == 14:  # LOADD r_a, [r_b + imm]
            addr = (R[b] + imm) & MASK64
            R[a] = self.read_mem(addr, 4)
        
        elif op == 15:  # LOADQ r_a, [r_b + imm]
            addr = (R[b] + imm) & MASK64
            R[a] = self.read_mem(addr, 8)
        
        elif op == 16:  # STOREB [r_b + imm], r_a
            addr = (R[b] + imm) & MASK64
            self.memory[addr] = R[a] & 0xFF
        
        elif op == 17:  # STOREW [r_b + imm], r_a
            addr = (R[b] + imm) & MASK64
            struct.pack_into('<H', self.memory, addr, R[a] & 0xFFFF)
        
        elif op == 18:  # STORED [r_b + imm], r_a
            addr = (R[b] + imm) & MASK64
            struct.pack_into('<I', self.memory, addr, R[a] & MASK32)
        
        elif op == 19:  # STOREQ [r_b + imm], r_a
            addr = (R[b] + imm) & MASK64
            struct.pack_into('<Q', self.memory, addr, R[a] & MASK64)
        
        elif op == 20:  # CMP r_b, r_c (unsigned subtract, set flags)
            result = (R[b] - R[c]) & MASK64
            self.ZF = 1 if result == 0 else 0
            self.CF = 1 if R[b] < R[c] else 0
            self.SF = (result >> 63) & 1
            self.OF = 0
        
        elif op == 21:  # TEST r_b, r_c (AND, set flags)
            result = R[b] & R[c]
            self.ZF = 1 if result == 0 else 0
            self.SF = (result >> 63) & 1
            self.CF = 0
            self.OF = 0
        
        elif op == 22:  # JMP imm (target instruction index)
            self.pc = imm & MASK64
        
        elif op == 23:  # JZ imm
            if self.ZF:
                self.pc = imm & MASK64
        
        elif op == 24:  # JNZ imm
            if not self.ZF:
                self.pc = imm & MASK64
        
        elif op == 25:  # JA (above, CF=0 and ZF=0)
            if not self.CF and not self.ZF:
                self.pc = imm & MASK64
        
        elif op == 26:  # JB (below, CF=1)
            if self.CF:
                self.pc = imm & MASK64
        
        elif op == 27:  # PUSH r_b
            # For simplicity, use memory as stack
            pass  # TODO if encountered
        
        elif op == 28:  # POP r_a
            pass  # TODO if encountered
        
        elif op == 31:  # HALT
            self.running = False


# ─── Test with known values ────────────────────────────────────────────────────

print("=" * 70)
print("SlimVM Emulator - KeyGenCrackmeSlim.exe")
print("=" * 70)
print()

# Instruction 0 uses opcode 15 (LOAD_QWORD). Looking at output:
# [0] LOADI_INIT r0, 0x40317ca6169700ca  <- r0=op1, imm_from_off8=that address
# This means: at i=0, op1 is the DEST reg, op2 is BASE reg
# But the shown imm 0x40317ca6169700ca is the RAW value at bytecode offset 8
# BEFORE decoding! Because decode_imm64 uses encryption with enc_key.
# Actually wait - let me check: op15 = LOADQ r_a, [r_b + imm]
# From the visible disasm: [1] LOADI r2, 0x8d71c05...
#   This is op=2, a=2, imm decoded
# [0] op=15: LOAD_QWORD r_a, [r_b + imm]
#    r_b = r0, so it loads from memory[r0 + imm]
#    r0 is set externally before run to point to our struct
#    imm is decoded from bytecode
# 
# Actually looking at output more carefully:
# "[0]  LOADI_INIT r0, 0x40317ca6169700ca" 
# The "r0" here is the dest reg. But the displayed imm IS the decoded imm.
# 0x40317ca6169700ca = 4628959946003251402 decimal. This seems like an address.
# But looking at the decode_imm64 formula - let me verify at pc=0:
# 
# Wait - for instruction 0 with op=15 (LOAD_QWORD):
#   The imm displayed was 0x40317ca6169700ca 
#   This should be: read from memory at (R[op2] + imm)
#   R[op2] = r0 initially (set externally)
#   So actually the VM reads from memory!
#
# The key insight: instruction 0 loads the NAME from name_ptr[0]
# No wait - op15 is LOAD_QWORD. But op1=0 (dest=r0), op2=r0 (base)
# So: r0 = QWORD[r0 + imm]. This replaces r0 with the name pointer!
# 
# Then later:
# [1] LOADI r2, constant1  
# [2] LOADI r2, constant2 (overwriting!)
# 
# Hmm, let me look at first 17 instructions more carefully.
# From the full output we can see starting at [17]:
# This means [0]-[16] are the setup loop for processing the name.

# Based on code analysis:
# The program:
# 1. Loads name pointer from struct (r0 = name_ptr via LOADQ)
# 2. Initializes r1=0 (loop counter = character index)
# 3. Loads constants r7 = 0xFFFFFFFF (32-bit mask)
# 4. Loads r2 = some hash/start value
# 5. Loop: processes each character using hash-like operations
# 6. Compares hash result to serial parts

# Let me just RUN the emulator with test values!
# First, let's figure out what r0 points to by using a simple test.

# The struct in memory:
# offset 0: char* name_ptr -> we set this to 256 (name is at memory[256])
# offset 8: part1
# offset 12: part2
# offset 16: part3
# offset 20: result_flag

# r0 is set to 0 (start of our memory struct)

name_test = "test"
vm = SlimVM(name_test, 0x12345678, 0x9abcdef0, 0)
vm.regs[0] = 0  # r0 = struct base address in our memory

print(f"Testing with name='{name_test}', part1=0x12345678, part2=0x9abcdef0")
print()
print("Running VM (verbose first 30 steps)...")
print()

vm2 = SlimVM(name_test, 0x12345678, 0x9abcdef0, 0)
vm2.regs[0] = 0

# Run verbosely
vm2.max_steps = 10000
try:
    regs = vm2.run(verbose=True)
except Exception as e:
    print(f"VM error: {e}")

print()
print(f"VM executed {vm2.steps} steps, PC={vm2.pc}")
print(f"Final registers:")
for i in range(16):
    if vm2.regs[i] != 0:
        print(f"  r{i} = 0x{vm2.regs[i]:016x} ({vm2.regs[i]})")

# Read result from memory at offset 20 (v23 = result flag)
result_flag = struct.unpack_from('<I', vm2.memory, 20)[0]
print(f"  Result flag (at mem[20]): {result_flag}")
