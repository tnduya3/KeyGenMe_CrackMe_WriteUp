#!/usr/bin/env python3
"""
KeyGenCrackmeSlim VM Bytecode Analyzer
Decodes and analyzes the 84-instruction VM program stored at 0x140007520

VM Architecture (SlimVM):
  - 16 general-purpose 64-bit registers: r0..r15
  - Each bytecode instruction: 16 bytes
  - Dispatch key: rotated per instruction (obfuscated control flow)
  
Bytecode layout per instruction (16 bytes):
  offset 0:   encrypted opcode byte (decrypted via dispatch key)
  offset 1:   operand byte A (encrypted via per-instruction key)
  offset 2:   operand byte B (encrypted via per-instruction key)
  offset 3:   operand byte C (encrypted - used in some handlers)
  offset 4-7: (padding/unused 0x00000000)
  offset 8-15: 64-bit immediate value (for LOADI, etc.)

Decryption process (deduced from disasm at 0x14000116a - 0x1400011b7):
  For instruction i:
    key_material = 0xBF58476D1CE4E5B9 * ((counter XOR 0x9E3779B97F4A7C15) ^ ((counter XOR 0x9E3779B97F4A7C15) >> 29))
    key_byte = key_material ^ (key_material >> 31)  [low byte]
    decrypted_opcode = ROR8(bytecode[i*16 + 0], key_byte) XOR key_byte
    counter -= 0x2917014799A6026D  (per instruction)
    
  But the handler selection uses a DISPATCH TABLE (off_140007270) indexed by decrypted_opcode.
  The decrypted opcode must be < 0x20 (32) to be valid.
"""

import struct

# Raw bytecode at 0x140007520 (1344 bytes = 84 instructions × 16 bytes)
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
    """Parse hex string into bytes"""
    tokens = hex_str.replace('\n', ' ').split()
    return bytes(int(t, 16) for t in tokens)

def ror8(val, n):
    """Rotate right 8-bit value by n"""
    n &= 7
    return ((val >> n) | (val << (8 - n))) & 0xFF

def compute_key(counter):
    """
    Compute the per-instruction decryption key.
    Based on: v6 = 0xBF58476D1CE4E5B9 * (counter ^ 0x9E3779B97F4A7C15 ^ ((counter ^ 0x9E3779B97F4A7C15) >> 29))
    key_byte = (v6 ^ (v6 >> 31)) & 0xFF
    """
    MASK64 = 0xFFFFFFFFFFFFFFFF
    c = (counter ^ 0x9E3779B97F4A7C15) & MASK64
    c = c ^ (c >> 29)
    v6 = (0xBF58476D1CE4E5B9 * c) & MASK64
    key_byte = (v6 ^ (v6 >> 31)) & 0xFF
    return key_byte, v6

def decode_opcode_byte(raw_byte, key_byte, v6_full):
    """
    Decode a single byte using ROR then XOR.
    v7 = v6 ^ (v6>>31) ^ ROR8(*v4, v6^(v6>>31))
    But since key_byte = v6 ^ (v6>>31) already:
    v7 = key_byte ^ ROR8(raw_byte, key_byte)
    """
    rot_amount = key_byte & 0x7F  # The rotate uses low bits
    return key_byte ^ ror8(raw_byte, rot_amount)

def decode_operand_byte(raw_byte, op_key, v6_full):
    """
    Decode an operand byte using a secondary key derived from v6_full.
    Based on handler disasm: 
      key2 = (v6_full >> 39) ^ (v6_full >> 8)  [different bits used]
      rot  = key2 >> 3
      decoded = ROR8(raw, rot) ^ key2_low
    This varies per handler - we'll try to match it.
    """
    return raw_byte  # placeholder - needs per-handler analysis

# Dispatch table addresses extracted from off_140007270 data
# Format: 8-byte little-endian pointers
DISPATCH_TABLE_HEX = (
    "3c 12 00 40 01 00 00 00 "  # [0]  -> 0x14000123c
    "8f 12 00 40 01 00 00 00 "  # [1]  -> 0x14000128f
    "58 13 00 40 01 00 00 00 "  # [2]  -> 0x140001358
    "1d 14 00 40 01 00 00 00 "  # [3]  -> 0x14000141d
    "1f 15 00 40 01 00 00 00 "  # [4]  -> 0x14000151f
    "32 16 00 40 01 00 00 00 "  # [5]  -> 0x140001632
    "24 17 00 40 01 00 00 00 "  # [6]  -> 0x140001724
    "21 18 00 40 01 00 00 00 "  # [7]  -> 0x140001821
    "1d 19 00 40 01 00 00 00 "  # [8]  -> 0x14000191d
    "1a 1a 00 40 01 00 00 00 "  # [9]  -> 0x140001a1a
    "e0 1a 00 40 01 00 00 00 "  # [10] -> 0x140001ae0
    "d6 1b 00 40 01 00 00 00 "  # [11] -> 0x140001bd6
    "d2 1c 00 40 01 00 00 00 "  # [12] -> 0x140001cd2
    "c1 1d 00 40 01 00 00 00 "  # [13] -> 0x140001dc1
    "b0 1e 00 40 01 00 00 00 "  # [14] -> 0x140001eb0
    "96 1f 00 40 01 00 00 00 "  # [15] -> 0x140001f96
    "82 20 00 40 01 00 00 00 "  # [16] -> 0x140002082
    "68 21 00 40 01 00 00 00 "  # [17] -> 0x140002168
    "4e 22 00 40 01 00 00 00 "  # [18] -> 0x14000224e
    "38 23 00 40 01 00 00 00 "  # [19] -> 0x140002338
    "1f 24 00 40 01 00 00 00 "  # [20] -> 0x14000241f
    "14 25 00 40 01 00 00 00 "  # [21] -> 0x140002514
    "f3 25 00 40 01 00 00 00 "  # [22] -> 0x1400025f3
    "57 26 00 40 01 00 00 00 "  # [23] -> 0x140002657
    "de 26 00 40 01 00 00 00 "  # [24] -> 0x1400026de
    "66 27 00 40 01 00 00 00 "  # [25] -> 0x140002766
    "f3 27 00 40 01 00 00 00 "  # [26] -> 0x1400027f3
    "7a 28 00 40 01 00 00 00 "  # [27] -> 0x14000287a
    "49 29 00 40 01 00 00 00 "  # [28] -> 0x140002949
    "a9 2a 00 40 01 00 00 00 "  # [29] -> 0x140002aa9
    "14 2a 00 40 01 00 00 00 "  # [30] -> 0x140002a14
    "4e 55 00 40 01 00 00 00 "  # [31] -> 0x14000554e (HALT?)
)

def parse_dispatch_table(hex_str):
    tokens = hex_str.replace('\n', ' ').split()
    data = bytes(int(t, 16) for t in tokens)
    table = []
    for i in range(0, len(data), 8):
        addr = struct.unpack_from('<Q', data, i)[0]
        table.append(addr)
    return table

dispatch_table = parse_dispatch_table(DISPATCH_TABLE_HEX)

print("=== SlimVM Dispatch Table (32 handlers) ===")
for i, addr in enumerate(dispatch_table):
    print(f"  opcode[{i:2d}] -> 0x{addr:x}")

print("\n=== VM Bytecode Decryption ===")
bytecode = parse_bytecode(BYTECODE_HEX)
assert len(bytecode) == 1344, f"Expected 1344 bytes, got {len(bytecode)}"

MASK64 = 0xFFFFFFFFFFFFFFFF
STEP = (-0x2917014799A6026D) & MASK64  # = 0xD6E8FEB86659FD93

print(f"\nTotal instructions: {len(bytecode)//16}")
print(f"Counter step: 0x{STEP:016x}")
print()

counter = 0  # r11, starts at 0 and decrements by STEP per instruction
results = []

for i in range(len(bytecode) // 16):
    instr = bytecode[i*16:(i+1)*16]
    raw_byte0 = instr[0]  # encrypted opcode
    
    key_byte, v6 = compute_key(counter)
    decoded_opcode = key_byte ^ ror8(raw_byte0, key_byte)
    
    # The 64-bit immediate at offset 8 (little-endian)
    imm64 = struct.unpack_from('<Q', instr, 8)[0]
    
    valid = decoded_opcode < 0x20
    handler_addr = dispatch_table[decoded_opcode] if valid else None
    
    results.append({
        'idx': i,
        'raw': instr.hex(' '),
        'raw_byte0': raw_byte0,
        'raw_byte1': instr[1],
        'raw_byte2': instr[2],
        'raw_byte3': instr[3],
        'counter': counter,
        'key_byte': key_byte,
        'v6': v6,
        'decoded_opcode': decoded_opcode,
        'valid': valid,
        'handler_addr': handler_addr,
        'imm64': imm64,
    })
    
    # Advance counter
    counter = (counter + STEP) & MASK64

print(f"{'#':>3} {'Raw[0:4]':>12} {'Key':>4} {'OpCode':>7} {'Handler':>12} {'Imm64':>18} {'Valid':>6}")
print("-" * 75)
for r in results:
    raw_preview = ' '.join(f'{b:02x}' for b in bytecode[r['idx']*16:r['idx']*16+4])
    handler_str = f"0x{r['handler_addr']:x}" if r['handler_addr'] else "INVALID"
    print(f"{r['idx']:>3} {raw_preview:>12} {r['key_byte']:>4x} {r['decoded_opcode']:>7d} {handler_str:>12} {r['imm64']:>18x} {str(r['valid']):>6}")

# Count opcodes
from collections import Counter
opcode_counts = Counter(r['decoded_opcode'] for r in results if r['valid'])
print(f"\n=== Opcode Frequency ===")
for op, cnt in sorted(opcode_counts.items()):
    addr_str = f"0x{dispatch_table[op]:x}" if op < len(dispatch_table) else "?"
    print(f"  opcode {op:2d} ({addr_str}): {cnt:3d} times")

# Show raw bytes[1..3] alongside opcode for each instruction
print(f"\n=== Decoded Instructions (opcode + raw operands) ===")
for r in results:
    raw1, raw2, raw3 = r['raw_byte1'], r['raw_byte2'], r['raw_byte3']
    print(f"[{r['idx']:2d}] op={r['decoded_opcode']:2d} raw_args=[{raw1:02x},{raw2:02x},{raw3:02x}] imm=0x{r['imm64']:016x}")
