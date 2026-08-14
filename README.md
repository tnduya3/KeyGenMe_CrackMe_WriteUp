# KeyGenCrackmeSlim.exe - Reverse Engineering Analysis

## Binary Overview

| Property | Value |
|----------|-------|
| File | `KeyGenCrackmeSlim.exe` |
| Size | 32,768 bytes |
| Architecture | x86-64 (PE64) |
| Image Base | `0x140000000` |
| Compiler | MSVC (C++ with STL) |
| Protection | Obfuscated VM (SlimVM) |
| Challenge type | Name-based keygen |

---

## Challenge Description

The program presents a "SlimVM Keygen Challenge". It prompts for:
1. **Name** - arbitrary non-empty string
2. **Serial** - format `XXXXXXXX-XXXXXXXX-XXXXXXXX` (3 x 8 hex digits)

If the serial matches the expected value for the given name, it prints `ACCESS GRANTED`.

---

## High-Level Program Flow

```
main()
  1. Print banner "SlimVM Keygen Challenge"
  2. Read name via fgets (max 128 chars)
  3. Validate name is non-empty
  4. Read serial via fgets
  5. Parse serial with sscanf("%8X-%8X-%8X") -> part1, part2, part3
  6. Initialize VM state (SlimVM_init_state, 5632 bytes on stack)
  7. Load 84-instruction bytecode into VM (SlimVM_load_program)
  8. Set vm.reg[0] = &input_struct {name_ptr, part1, part2, part3=0, result=0}
  9. Execute VM (SlimVM_execute -> SlimVM_run)
  10. Check if result_flag == 1 -> ACCESS GRANTED or INVALID
```

---

## VM Architecture: SlimVM

### VM State Structure (5632 bytes)

| Offset | Size | Description |
|--------|------|-------------|
| `+0x000` | 128 | Registers r0..r15 (16 x 8-byte uint64) |
| `+0x080` | 64 | Internal VM stack (8 x 8-byte) |
| `+0x480` | 8 | Stack depth counter |
| `+0x488` | 1 | ZF (Zero Flag) |
| `+0x489` | 1 | CF (Carry Flag) |
| `+0x48A` | 1 | SF (Sign Flag) |
| `+0x48B` | 1 | OF (Overflow Flag) |
| `+0x490` | 8 | Bytecode pointer |
| `+0x498` | 8 | Total instruction count (84) |
| `+0x4A0` | 8 | PC (Program Counter) |
| `+0x4A8` | 1 | Running flag (1=active) |

### Instruction Encoding (16 bytes each)

```
Offset 0:   byte  -- encrypted opcode
Offset 1:   byte  -- encrypted register A (destination)
Offset 2:   byte  -- encrypted register B (source 1)
Offset 3:   byte  -- encrypted register C (source 2)
Offset 4-7: bytes -- zero padding
Offset 8-15: qword -- encrypted 64-bit immediate value
```

### Decryption Algorithm

**Opcode Decryption** (Sliding splitmix64 key, per instruction):
```python
counter = 0  # starts at 0, decrements by 0x2917014799A6026D each instruction
c = (counter ^ 0x9E3779B97F4A7C15) ^ ((counter ^ 0x9E3779B97F4A7C15) >> 29)
v6 = 0xBF58476D1CE4E5B9 * c
key_byte = (v6 ^ (v6 >> 31)) & 0xFF
opcode = key_byte ^ ROR8(raw_byte, key_byte)
```

**Operand Decryption** (PC-based secondary key):
```python
t = (pc * 0xD6E8FEB86659FD93) ^ 0x9E3779B97F4A7C15
t2 = t ^ (t >> 29)
t3 = t2 * 0xBF58476D1CE4E5B9
key2 = ((t3 >> 39) ^ (t3 >> 8)) & 0xFF
reg = ROR8(raw_byte, key2 >> 3) ^ key2
```

**Immediate Decryption** (same PC-based key):
```python
raw_imm = BSWAP_64(bytecode[8:16])   # big-endian read
imm = (raw_imm ^ t3) ^ (t3 >> 31)
```

### Obfuscated Control Flow

The VM uses an **indirect jump table** for dispatch:
- `g_slimvm_dispatch_table` at `0x140007270`: 32 x 8-byte function pointers
- Dispatch key `[rsp+var_1030]` is updated with different operations per handler
  (shld, shrd, XOR, add, multiply) to defeat static analysis
- After each instruction: `jmp [rsp+rcx*8+var_838]` where rcx = next PC

---

## VM Instruction Set (32 Opcodes)

| Opcode | Mnemonic | Operation |
|--------|----------|-----------|
| 0 | NOP | No operation |
| 1 | MOV | `reg_a = reg_b` |
| 2 | LOADI | `reg_a = imm64` |
| 3 | ADD | `reg_a = reg_b + reg_c` (with flags) |
| 4 | SUB | `reg_a = reg_b - reg_c` (with flags) |
| 5 | IMUL | `reg_a = reg_b * reg_c` |
| 6 | AND | `reg_a = reg_b & reg_c` |
| 7 | OR | `reg_a = reg_b \| reg_c` |
| 8 | XOR | `reg_a = reg_b ^ reg_c` |
| 9 | NOT | `reg_a = ~reg_b` |
| 10 | SHL | `reg_a = reg_b << imm64` |
| 11 | SHR | `reg_a = reg_b >> imm64` |
| 12 | LOADB | `reg_a = *(uint8_t*)(reg_b + imm64)` |
| 13 | LOADW | `reg_a = *(uint16_t*)(reg_b + imm64)` |
| 14 | LOADD | `reg_a = *(uint32_t*)(reg_b + imm64)` |
| 15 | LOADQ | `reg_a = *(uint64_t*)(reg_b + imm64)` |
| 16 | STOREB | `*(uint8_t*)(reg_b + imm64) = reg_a` |
| 17 | STOREW | `*(uint16_t*)(reg_b + imm64) = reg_a` |
| 18 | STORED | `*(uint32_t*)(reg_b + imm64) = reg_a` |
| 19 | STOREQ | `*(uint64_t*)(reg_b + imm64) = reg_a` |
| 20 | CMP | `flags = reg_b - reg_c` (discard result) |
| 21 | TEST | `flags = reg_b & reg_c` (discard result) |
| 22 | JMP | `PC = imm64` |
| 23 | JZ | `if ZF: PC = imm64 else PC+1` |
| 24 | JNZ | `if !ZF: PC = imm64 else PC+1` |
| 25 | JA | `if !CF && !ZF: PC = imm64` |
| 26 | JB | `if CF: PC = imm64` |
| 27 | PUSH | Push register to VM stack |
| 28 | POP | Pop from VM stack to register |
| 31 | HALT | Stop VM execution |

---

## VM Program Disassembly (84 Instructions)

### Phase 1: Initialization (Instructions 0-2)

```asm
[0]  LOADQ r0, [r0 + 0]    ; r0 = *r0 = name_ptr (pointer to name string)
[1]  LOADI r2, 0x4D3C2B1A  ; r2 = initial hash seed
[2]  LOADI r7, 0xFFFFFFFF  ; r7 = 32-bit mask
```

### Phase 2: Name Hash Loop (Instructions 3-26, loops back to 3)

```asm
[3]  LOADB r3, [r1 + 0]    ; r3 = name[r1] (current character)
[4]  LOADI r4, 0            ; r4 = 0 (null terminator)
[5]  CMP   r3, r4           ; compare char to null
[6]  JZ    27               ; if null, exit loop
[7]  OR    r4, r2, r3       ; \
[8]  AND   r5, r2, r3       ;  | Bitwise XOR via XNOR trick:
[9]  NOT   r5, r5           ;  | r2 = (r2|char) & ~(r2&char)
[10] AND   r2, r4, r5       ; r2 = r2 XOR char
[11] SHL   r4, r2, 5        ; r4 = r2 << 5
[12] SHR   r5, r2, 27       ; r5 = r2 >> 27
[13] OR    r2, r4, r5       ; r2 = ROL32(r2, 5)
[14] AND   r2, r2, r7       ; mask to 32 bits
[15] LOADI r3, 0x13579BDF   ; mixing constant
[16-20]   r2 = r2 + 0x13579BDF  ; add constant (carry-save implementation)
[21] SHR   r3, r2, 7        ; r3 = r2 >> 7
[22] XOR   r2, r2, r3       ; r2 = r2 ^ (r2 >> 7)
[23] AND   r2, r2, r7       ; mask to 32 bits
[24] LOADI r3, 1
[25] ADD   r1, r1, r3       ; r1++ (char index)
[26] JMP   3                ; loop back
```

**Hash function per character:**
```python
h = ((h ^ ord(c)) rot_left 5) + 0x13579BDF
h = h ^ (h >> 7)
h &= 0xFFFFFFFF
```

### Phase 3: Serial Part Computation (Instructions 27-67)

After the loop, **r2 = name_hash**. Three serial parts are derived:

```asm
; --- Compute serial part 1 (stored in r3) ---
[27] LOADI r4, 0x7319C5AD
[28-31]  r3 = r2 XOR 0x7319C5AD    ; XOR with constant (XNOR trick)
[32-34]  r3 = ROL32(r3, 11)        ; Rotate left 11 bits
[35] AND  r3, r3, r7
[36] LOADI r4, 0x51ED270B
[40] ADD  r3, ..., ...             ; r3 = r3 + 0x51ED270B
[41] AND  r3, r3, r7
[42-46]  r3 = r3 ^ (r3 >> 13)     ; Final mixing

; --- Compute serial part 2 (stored in r6) ---
[52] LOADI r4, 0x9E3779B9          ; Golden ratio constant
[53-67]  r6 = additional mixing using r2, r3, r4
         r6 = ROL32((r2 XOR r3 XOR 0x9E3779B9), 17) XOR ...
```

### Phase 4: Serial Verification (Instructions 68-83)

```asm
[68]  LOADD r4, [r0 + 8]     ; r4 = input_struct.part1
[69]  CMP   r4, r2            ; compare part1 with computed r2 (name_hash)
[70]  JNZ   81                ; fail if not equal

[71]  LOADD r4, [r0 + 12]    ; r4 = input_struct.part2
[72]  CMP   r4, r3            ; compare part2 with computed r3
[73]  JNZ   81                ; fail

[74]  LOADD r4, [r0 + 16]    ; r4 = input_struct.part3
[75]  CMP   r4, r6            ; compare part3 with computed r6
[76]  JNZ   81                ; fail

[77]  LOADI r4, 1             ; success
[79]  JMP   83
[80]  NOP
[81]  LOADI r4, 0             ; failure
[83]  HALT
```

---

## Serial Generation

The keygen emulates the VM completely. For any name:
1. Run VM with dummy serial (0,0,0)
2. Read resulting registers: r2, r3, r6
3. Format as `{r2:08X}-{r3:08X}-{r6:08X}`

### Example Serials

| Name | Serial |
|------|--------|
| `test` | `8B5384B2-A3F3397C-7E65FD26` |
| `admin` | `93ACAD17-FD351787-7AE78C00` |
| `user` | `8B5523E6-B91A4E31-DE4B0571` |
| `Alice` | `D080EC22-1B397DEA-0D12CE66` |
| `Bob` | `43D3564B-A6896CF3-60996DEA` |
| `John Doe` | `CCB2E478-AAFE82D6-D9585588` |
| `ANTIGRAVITY` | `5C52AF8D-AD3B4174-DAEF4AB3` |

---


## Tools Created

| File | Purpose |
|------|---------|
| `RE/analyze_vm.py` | Decode opcodes from raw bytecode (early exploration) |
| `RE/decode_vm.py` | Full VM disassembler with operand decryption |
| `RE/emulate_vm.py` | VM emulator with verbose trace support |
| `RE/keygen.py` | **Final keygen tool** - generate serials for any name |

---

## Methodology

1. **Binary Survey** - `survey_binary` to identify entry points, strings, imports
2. **Decompile main** - Identified VM init pattern and input struct layout  
3. **Dispatch Table Analysis** - Read raw bytes at `off_140007270` to extract 32 handler addresses
4. **Bytecode Extraction** - Read 1344 bytes from `unk_140007520`
5. **Key Schedule Reverse** - Traced splitmix64-style encryption from disasm at `0x140001170`
6. **Handler Analysis** - Subagent analyzed all 32 handlers from the 17,184-line disasm JSON
7. **Operand Decryption** - Derived secondary PC-based key formula from handler pattern at `0x14000241F`
8. **VM Emulation** - Python VM emulator with full instruction set
9. **Algorithm Extraction** - Traced hash computation and serial derivation from verbose VM trace
10. **Keygen** - Emulator reused: run with dummy serial, read r2/r3/r6 as expected values
