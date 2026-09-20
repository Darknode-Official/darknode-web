// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
//
// Reverse Engineering Comprehensive Reference Database
// x86/x64 instructions, ARM, file formats, tool commands, anti-RE techniques

// ============================================================================
// x86/x64 INSTRUCTION REFERENCE
// ============================================================================
export const X86_INSTRUCTIONS = [
  // --- Data Movement ---
  { mnemonic: "MOV", opcode: "89/8B", category: "data-movement", description: "Move data between registers or memory", example: "MOV EAX, EBX", flags: "None", notes: "Most common instruction; cannot move memory-to-memory" },
  { mnemonic: "MOVZX", opcode: "0FB6/0FB7", category: "data-movement", description: "Move with zero-extension", example: "MOVZX EAX, BYTE [ESI]", flags: "None", notes: "Extends smaller value to larger register with zeros" },
  { mnemonic: "MOVSX", opcode: "0FBE/0FBF", category: "data-movement", description: "Move with sign-extension", example: "MOVSX EAX, BYTE [ESI]", flags: "None", notes: "Extends smaller value preserving sign bit" },
  { mnemonic: "LEA", opcode: "8D", category: "data-movement", description: "Load effective address", example: "LEA EAX, [EBX+ECX*4+10]", flags: "None", notes: "Computes address without memory access; often used for arithmetic" },
  { mnemonic: "XCHG", opcode: "87", category: "data-movement", description: "Exchange register/memory with register", example: "XCHG EAX, EBX", flags: "None", notes: "Atomic when used with memory; implicit LOCK prefix" },
  { mnemonic: "PUSH", opcode: "50+r/FF/6A/68", category: "data-movement", description: "Push value onto stack", example: "PUSH EAX", flags: "None", notes: "Decrements ESP then stores value" },
  { mnemonic: "POP", opcode: "58+r/8F", category: "data-movement", description: "Pop value from stack", example: "POP EBX", flags: "None", notes: "Loads value then increments ESP" },
  { mnemonic: "PUSHA/PUSHAD", opcode: "60", category: "data-movement", description: "Push all general-purpose registers", example: "PUSHAD", flags: "None", notes: "Saves EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI; not valid in 64-bit mode" },
  { mnemonic: "POPA/POPAD", opcode: "61", category: "data-movement", description: "Pop all general-purpose registers", example: "POPAD", flags: "None", notes: "Restores registers saved by PUSHAD; not valid in 64-bit mode" },
  { mnemonic: "CBW/CWDE/CDQE", opcode: "98", category: "data-movement", description: "Sign-extend AL/AX/EAX", example: "CDQE", flags: "None", notes: "CBW: AL→AX, CWDE: AX→EAX, CDQE: EAX→RAX" },
  { mnemonic: "CWD/CDQ/CQO", opcode: "99", category: "data-movement", description: "Sign-extend AX/EAX/RAX into DX:AX/EDX:EAX/RDX:RAX", example: "CDQ", flags: "None", notes: "Used before IDIV to set up dividend" },
  { mnemonic: "BSWAP", opcode: "0FC8+r", category: "data-movement", description: "Byte swap (reverse byte order)", example: "BSWAP EAX", flags: "None", notes: "Converts between big-endian and little-endian" },
  { mnemonic: "CMOV{cc}", opcode: "0F40+", category: "data-movement", description: "Conditional move based on flags", example: "CMOVZ EAX, EBX", flags: "None", notes: "Avoids branch misprediction; cc = condition code" },
  { mnemonic: "MOVS/MOVSB/MOVSW/MOVSD", opcode: "A4/A5", category: "data-movement", description: "Move string (byte/word/dword)", example: "REP MOVSB", flags: "None", notes: "Copies ESI→EDI, increments both; REP prefix for block copy" },
  { mnemonic: "LODS/LODSB/LODSW/LODSD", opcode: "AC/AD", category: "data-movement", description: "Load string into accumulator", example: "LODSB", flags: "None", notes: "Loads [ESI] into AL/AX/EAX, increments ESI" },
  { mnemonic: "STOS/STOSB/STOSW/STOSD", opcode: "AA/AB", category: "data-movement", description: "Store accumulator to string", example: "REP STOSB", flags: "None", notes: "Stores AL/AX/EAX to [EDI], increments EDI; REP for memset" },

  // --- Arithmetic ---
  { mnemonic: "ADD", opcode: "01/03/05/81", category: "arithmetic", description: "Integer addition", example: "ADD EAX, 10", flags: "OF,SF,ZF,AF,PF,CF", notes: "Sets carry flag on unsigned overflow, overflow flag on signed" },
  { mnemonic: "ADC", opcode: "11/13/15/81", category: "arithmetic", description: "Add with carry", example: "ADC EDX, 0", flags: "OF,SF,ZF,AF,PF,CF", notes: "Adds operands plus carry flag; used for multi-precision arithmetic" },
  { mnemonic: "SUB", opcode: "29/2B/2D/81", category: "arithmetic", description: "Integer subtraction", example: "SUB ESP, 0x20", flags: "OF,SF,ZF,AF,PF,CF", notes: "Common for stack frame allocation" },
  { mnemonic: "SBB", opcode: "19/1B/1D/81", category: "arithmetic", description: "Subtract with borrow", example: "SBB EDX, 0", flags: "OF,SF,ZF,AF,PF,CF", notes: "Subtracts operand plus carry; multi-precision subtraction" },
  { mnemonic: "MUL", opcode: "F7/6", category: "arithmetic", description: "Unsigned multiply", example: "MUL ECX", flags: "OF,CF", notes: "Result in EDX:EAX (32-bit) or RDX:RAX (64-bit)" },
  { mnemonic: "IMUL", opcode: "F7/5, 0FAF, 6B, 69", category: "arithmetic", description: "Signed multiply", example: "IMUL EAX, EBX, 5", flags: "OF,CF", notes: "One, two, or three operand forms available" },
  { mnemonic: "DIV", opcode: "F7/6", category: "arithmetic", description: "Unsigned divide", example: "DIV ECX", flags: "Undefined", notes: "EDX:EAX / operand → EAX quotient, EDX remainder; #DE on div by zero" },
  { mnemonic: "IDIV", opcode: "F7/7", category: "arithmetic", description: "Signed divide", example: "IDIV ECX", flags: "Undefined", notes: "Use CDQ before to sign-extend EAX into EDX:EAX" },
  { mnemonic: "INC", opcode: "FF/0, 40+r", category: "arithmetic", description: "Increment by 1", example: "INC ECX", flags: "OF,SF,ZF,AF,PF", notes: "Does NOT set carry flag (unlike ADD r, 1)" },
  { mnemonic: "DEC", opcode: "FF/1, 48+r", category: "arithmetic", description: "Decrement by 1", example: "DEC ECX", flags: "OF,SF,ZF,AF,PF", notes: "Does NOT set carry flag (unlike SUB r, 1)" },
  { mnemonic: "NEG", opcode: "F7/3", category: "arithmetic", description: "Two's complement negation", example: "NEG EAX", flags: "OF,SF,ZF,AF,PF,CF", notes: "Equivalent to SUB 0, operand; CF=1 unless operand was 0" },

  // --- Logical ---
  { mnemonic: "AND", opcode: "21/23/25/81", category: "logical", description: "Bitwise AND", example: "AND EAX, 0xFF", flags: "SF,ZF,PF; OF=CF=0", notes: "Often used to mask bits or test alignment" },
  { mnemonic: "OR", opcode: "09/0B/0D/81", category: "logical", description: "Bitwise OR", example: "OR EAX, EAX", flags: "SF,ZF,PF; OF=CF=0", notes: "OR reg,reg is a common idiom to test for zero" },
  { mnemonic: "XOR", opcode: "31/33/35/81", category: "logical", description: "Bitwise exclusive OR", example: "XOR EAX, EAX", flags: "SF,ZF,PF; OF=CF=0", notes: "XOR reg,reg is the standard zero-register idiom" },
  { mnemonic: "NOT", opcode: "F7/2", category: "logical", description: "Bitwise NOT (ones complement)", example: "NOT EAX", flags: "None", notes: "Flips all bits; does not affect flags" },
  { mnemonic: "TEST", opcode: "85/A9/F7", category: "logical", description: "Bitwise AND without storing result", example: "TEST EAX, EAX", flags: "SF,ZF,PF; OF=CF=0", notes: "Sets flags like AND but discards result; common before JZ/JNZ" },
  { mnemonic: "SHL/SAL", opcode: "C1/4, D1/4", category: "logical", description: "Shift left (logical/arithmetic)", example: "SHL EAX, 3", flags: "OF,SF,ZF,PF,CF", notes: "Equivalent to multiply by 2^n; CF = last bit shifted out" },
  { mnemonic: "SHR", opcode: "C1/5, D1/5", category: "logical", description: "Shift right logical (zero fill)", example: "SHR EAX, 1", flags: "OF,SF,ZF,PF,CF", notes: "Unsigned divide by 2^n" },
  { mnemonic: "SAR", opcode: "C1/7, D1/7", category: "logical", description: "Shift right arithmetic (sign-preserving)", example: "SAR EAX, 1", flags: "OF,SF,ZF,PF,CF", notes: "Signed divide by 2^n; preserves sign bit" },
  { mnemonic: "ROL", opcode: "C1/0, D1/0", category: "logical", description: "Rotate left", example: "ROL EAX, 8", flags: "OF,CF", notes: "Bits shifted out left re-enter from right" },
  { mnemonic: "ROR", opcode: "C1/1, D1/1", category: "logical", description: "Rotate right", example: "ROR EAX, 8", flags: "OF,CF", notes: "Bits shifted out right re-enter from left" },
  { mnemonic: "RCL", opcode: "C1/2, D1/2", category: "logical", description: "Rotate left through carry", example: "RCL EAX, 1", flags: "OF,CF", notes: "33-bit rotation including carry flag" },
  { mnemonic: "RCR", opcode: "C1/3, D1/3", category: "logical", description: "Rotate right through carry", example: "RCR EAX, 1", flags: "OF,CF", notes: "33-bit rotation including carry flag" },
  { mnemonic: "BT", opcode: "0FA3, 0FBA/4", category: "logical", description: "Bit test", example: "BT EAX, 5", flags: "CF", notes: "Copies specified bit to carry flag" },
  { mnemonic: "BTS", opcode: "0FAB, 0FBA/5", category: "logical", description: "Bit test and set", example: "BTS [flags], 3", flags: "CF", notes: "Copies bit to CF then sets it to 1" },
  { mnemonic: "BTR", opcode: "0FB3, 0FBA/6", category: "logical", description: "Bit test and reset", example: "BTR [flags], 3", flags: "CF", notes: "Copies bit to CF then clears it to 0" },
  { mnemonic: "BTC", opcode: "0FBB, 0FBA/7", category: "logical", description: "Bit test and complement", example: "BTC [flags], 3", flags: "CF", notes: "Copies bit to CF then flips it" },
  { mnemonic: "BSF", opcode: "0FBC", category: "logical", description: "Bit scan forward (find lowest set bit)", example: "BSF EAX, EBX", flags: "ZF", notes: "ZF=1 if source is 0; result undefined if ZF=1" },
  { mnemonic: "BSR", opcode: "0FBD", category: "logical", description: "Bit scan reverse (find highest set bit)", example: "BSR EAX, EBX", flags: "ZF", notes: "ZF=1 if source is 0; useful for log2 computation" },

  // --- Control Flow ---
  { mnemonic: "JMP", opcode: "EB/E9/FF", category: "control-flow", description: "Unconditional jump", example: "JMP 0x401000", flags: "None", notes: "Short (EB, ±128), near (E9), or indirect (FF /4)" },
  { mnemonic: "JZ/JE", opcode: "74/0F84", category: "control-flow", description: "Jump if zero/equal", example: "JZ target", flags: "Tests ZF", notes: "ZF=1; most common conditional jump" },
  { mnemonic: "JNZ/JNE", opcode: "75/0F85", category: "control-flow", description: "Jump if not zero/not equal", example: "JNZ target", flags: "Tests ZF", notes: "ZF=0" },
  { mnemonic: "JA/JNBE", opcode: "77/0F87", category: "control-flow", description: "Jump if above (unsigned >)", example: "JA target", flags: "Tests CF,ZF", notes: "CF=0 AND ZF=0" },
  { mnemonic: "JAE/JNB/JNC", opcode: "73/0F83", category: "control-flow", description: "Jump if above or equal (unsigned >=)", example: "JAE target", flags: "Tests CF", notes: "CF=0" },
  { mnemonic: "JB/JNAE/JC", opcode: "72/0F82", category: "control-flow", description: "Jump if below (unsigned <)", example: "JB target", flags: "Tests CF", notes: "CF=1" },
  { mnemonic: "JBE/JNA", opcode: "76/0F86", category: "control-flow", description: "Jump if below or equal (unsigned <=)", example: "JBE target", flags: "Tests CF,ZF", notes: "CF=1 OR ZF=1" },
  { mnemonic: "JG/JNLE", opcode: "7F/0F8F", category: "control-flow", description: "Jump if greater (signed >)", example: "JG target", flags: "Tests ZF,SF,OF", notes: "ZF=0 AND SF=OF" },
  { mnemonic: "JGE/JNL", opcode: "7D/0F8D", category: "control-flow", description: "Jump if greater or equal (signed >=)", example: "JGE target", flags: "Tests SF,OF", notes: "SF=OF" },
  { mnemonic: "JL/JNGE", opcode: "7C/0F8C", category: "control-flow", description: "Jump if less (signed <)", example: "JL target", flags: "Tests SF,OF", notes: "SF≠OF" },
  { mnemonic: "JLE/JNG", opcode: "7E/0F8E", category: "control-flow", description: "Jump if less or equal (signed <=)", example: "JLE target", flags: "Tests ZF,SF,OF", notes: "ZF=1 OR SF≠OF" },
  { mnemonic: "JS", opcode: "78/0F88", category: "control-flow", description: "Jump if sign (negative)", example: "JS target", flags: "Tests SF", notes: "SF=1" },
  { mnemonic: "JNS", opcode: "79/0F89", category: "control-flow", description: "Jump if not sign (positive)", example: "JNS target", flags: "Tests SF", notes: "SF=0" },
  { mnemonic: "JO", opcode: "70/0F80", category: "control-flow", description: "Jump if overflow", example: "JO target", flags: "Tests OF", notes: "OF=1; signed overflow detected" },
  { mnemonic: "JP/JPE", opcode: "7A/0F8A", category: "control-flow", description: "Jump if parity even", example: "JP target", flags: "Tests PF", notes: "PF=1" },
  { mnemonic: "CALL", opcode: "E8/FF/9A", category: "control-flow", description: "Call procedure", example: "CALL 0x401000", flags: "None", notes: "Pushes return address then jumps; near (E8) or indirect (FF /2)" },
  { mnemonic: "RET/RETN", opcode: "C3/C2", category: "control-flow", description: "Return from procedure", example: "RET", flags: "None", notes: "Pops return address; C2 adds immediate to ESP (stdcall cleanup)" },
  { mnemonic: "LOOP", opcode: "E2", category: "control-flow", description: "Decrement ECX and jump if nonzero", example: "LOOP label", flags: "None", notes: "Deprecated in modern code; compilers use DEC+JNZ instead" },
  { mnemonic: "INT", opcode: "CD", category: "control-flow", description: "Software interrupt", example: "INT 3", flags: "IF,TF", notes: "INT 3 (0xCC) = breakpoint; INT 0x80 = Linux syscall (32-bit)" },
  { mnemonic: "SYSCALL", opcode: "0F05", category: "control-flow", description: "Fast system call (64-bit)", example: "SYSCALL", flags: "Many", notes: "64-bit Linux/Windows system call entry; faster than INT 0x80" },
  { mnemonic: "SYSENTER", opcode: "0F34", category: "control-flow", description: "Fast system call (32-bit)", example: "SYSENTER", flags: "Many", notes: "32-bit fast syscall; used by Windows and some Linux builds" },
  { mnemonic: "NOP", opcode: "90", category: "control-flow", description: "No operation", example: "NOP", flags: "None", notes: "Actually XCHG EAX,EAX; multi-byte NOPs: 0F1F /0" },
  { mnemonic: "HLT", opcode: "F4", category: "control-flow", description: "Halt processor", example: "HLT", flags: "None", notes: "Privileged; halts until interrupt; ring 0 only" },
  { mnemonic: "ENTER", opcode: "C8", category: "control-flow", description: "Create stack frame", example: "ENTER 0x20, 0", flags: "None", notes: "Equivalent to PUSH EBP; MOV EBP,ESP; SUB ESP,imm" },
  { mnemonic: "LEAVE", opcode: "C9", category: "control-flow", description: "Destroy stack frame", example: "LEAVE", flags: "None", notes: "Equivalent to MOV ESP,EBP; POP EBP" },

  // --- Comparison ---
  { mnemonic: "CMP", opcode: "39/3B/3D/81", category: "comparison", description: "Compare (subtract without storing)", example: "CMP EAX, 10", flags: "OF,SF,ZF,AF,PF,CF", notes: "Sets flags like SUB but discards result" },
  { mnemonic: "SCAS/SCASB/SCASW/SCASD", opcode: "AE/AF", category: "comparison", description: "Scan string (compare AL/AX/EAX with [EDI])", example: "REPNE SCASB", flags: "OF,SF,ZF,AF,PF,CF", notes: "REPNE SCASB = strchr/strlen; searches for AL in string at EDI" },
  { mnemonic: "CMPS/CMPSB/CMPSW/CMPSD", opcode: "A6/A7", category: "comparison", description: "Compare strings", example: "REPE CMPSB", flags: "OF,SF,ZF,AF,PF,CF", notes: "REPE CMPSB = memcmp; compares [ESI] with [EDI]" },

  // --- Flag Manipulation ---
  { mnemonic: "CLC", opcode: "F8", category: "flags", description: "Clear carry flag", example: "CLC", flags: "CF=0", notes: "Used before ADC chains" },
  { mnemonic: "STC", opcode: "F9", category: "flags", description: "Set carry flag", example: "STC", flags: "CF=1", notes: "Often used to signal error in return" },
  { mnemonic: "CMC", opcode: "F5", category: "flags", description: "Complement carry flag", example: "CMC", flags: "CF=!CF", notes: "Toggles carry flag" },
  { mnemonic: "CLD", opcode: "FC", category: "flags", description: "Clear direction flag", example: "CLD", flags: "DF=0", notes: "String ops go forward (ESI++, EDI++)" },
  { mnemonic: "STD", opcode: "FD", category: "flags", description: "Set direction flag", example: "STD", flags: "DF=1", notes: "String ops go backward (ESI--, EDI--)" },
  { mnemonic: "PUSHF/PUSHFD", opcode: "9C", category: "flags", description: "Push flags register", example: "PUSHFD", flags: "None", notes: "Saves EFLAGS to stack" },
  { mnemonic: "POPF/POPFD", opcode: "9D", category: "flags", description: "Pop flags register", example: "POPFD", flags: "All", notes: "Restores EFLAGS from stack; used in anti-debug (TF detection)" },
  { mnemonic: "LAHF", opcode: "9F", category: "flags", description: "Load AH from flags", example: "LAHF", flags: "None", notes: "AH = SF:ZF:0:AF:0:PF:1:CF" },
  { mnemonic: "SAHF", opcode: "9E", category: "flags", description: "Store AH into flags", example: "SAHF", flags: "SF,ZF,AF,PF,CF", notes: "Sets lower 8 bits of flags from AH" },

  // --- SSE/AVX (common in modern code) ---
  { mnemonic: "MOVAPS", opcode: "0F28/0F29", category: "sse", description: "Move aligned packed single-precision", example: "MOVAPS XMM0, [EAX]", flags: "None", notes: "16-byte aligned; #GP on unaligned access" },
  { mnemonic: "MOVUPS", opcode: "0F10/0F11", category: "sse", description: "Move unaligned packed single-precision", example: "MOVUPS XMM0, [EAX]", flags: "None", notes: "Slower than MOVAPS but no alignment requirement" },
  { mnemonic: "MOVDQA", opcode: "660F6F/660F7F", category: "sse", description: "Move aligned double quadword", example: "MOVDQA XMM1, XMM0", flags: "None", notes: "Integer SIMD aligned move" },
  { mnemonic: "MOVDQU", opcode: "F30F6F/F30F7F", category: "sse", description: "Move unaligned double quadword", example: "MOVDQU XMM0, [ECX]", flags: "None", notes: "Integer SIMD unaligned move" },
  { mnemonic: "MOVSD", opcode: "F20F10/F20F11", category: "sse", description: "Move scalar double-precision", example: "MOVSD XMM0, [EAX]", flags: "None", notes: "Moves 64-bit double; low qword of XMM" },
  { mnemonic: "MOVSS", opcode: "F30F10/F30F11", category: "sse", description: "Move scalar single-precision", example: "MOVSS XMM0, [EAX]", flags: "None", notes: "Moves 32-bit float; low dword of XMM" },
  { mnemonic: "ADDSS", opcode: "F30F58", category: "sse", description: "Add scalar single-precision", example: "ADDSS XMM0, XMM1", flags: "None", notes: "Adds low float" },
  { mnemonic: "ADDSD", opcode: "F20F58", category: "sse", description: "Add scalar double-precision", example: "ADDSD XMM0, XMM1", flags: "None", notes: "Adds low double" },
  { mnemonic: "MULSS", opcode: "F30F59", category: "sse", description: "Multiply scalar single-precision", example: "MULSS XMM0, XMM1", flags: "None", notes: "Multiplies low float" },
  { mnemonic: "DIVSD", opcode: "F20F5E", category: "sse", description: "Divide scalar double-precision", example: "DIVSD XMM0, XMM1", flags: "None", notes: "Divides low double" },
  { mnemonic: "COMISS", opcode: "0F2F", category: "sse", description: "Compare scalar single-precision (ordered)", example: "COMISS XMM0, XMM1", flags: "ZF,PF,CF", notes: "Sets x87 comparison flags; used before Jcc" },
  { mnemonic: "COMISD", opcode: "660F2F", category: "sse", description: "Compare scalar double-precision (ordered)", example: "COMISD XMM0, XMM1", flags: "ZF,PF,CF", notes: "Sets x87 comparison flags; used before Jcc" },
  { mnemonic: "PXOR", opcode: "660FEF", category: "sse", description: "Packed XOR (128-bit)", example: "PXOR XMM0, XMM0", flags: "None", notes: "PXOR XMM,XMM is the SSE zero-register idiom" },
  { mnemonic: "CVTSI2SD", opcode: "F20F2A", category: "sse", description: "Convert integer to scalar double", example: "CVTSI2SD XMM0, EAX", flags: "None", notes: "Int to double conversion" },
  { mnemonic: "CVTTSD2SI", opcode: "F20F2C", category: "sse", description: "Convert scalar double to integer (truncate)", example: "CVTTSD2SI EAX, XMM0", flags: "None", notes: "Double to int with truncation (C-style cast)" },

  // --- Crypto/AES-NI ---
  { mnemonic: "AESENC", opcode: "660F38DC", category: "crypto", description: "AES single round encryption", example: "AESENC XMM0, XMM1", flags: "None", notes: "Hardware AES; part of AES-NI extension" },
  { mnemonic: "AESENCLAST", opcode: "660F38DD", category: "crypto", description: "AES last round encryption", example: "AESENCLAST XMM0, XMM1", flags: "None", notes: "Final AES encryption round" },
  { mnemonic: "AESDEC", opcode: "660F38DE", category: "crypto", description: "AES single round decryption", example: "AESDEC XMM0, XMM1", flags: "None", notes: "Hardware AES decryption" },
  { mnemonic: "AESKEYGENASSIST", opcode: "660F3ADF", category: "crypto", description: "AES key generation assist", example: "AESKEYGENASSIST XMM1, XMM0, 0x01", flags: "None", notes: "Generates round keys" },
  { mnemonic: "RDRAND", opcode: "0FC7/6", category: "crypto", description: "Read hardware random number", example: "RDRAND EAX", flags: "CF", notes: "CF=1 if valid random; CF=0 if DRNG not ready" },
  { mnemonic: "RDTSC", opcode: "0F31", category: "system", description: "Read time-stamp counter", example: "RDTSC", flags: "None", notes: "EDX:EAX = TSC; often used in timing attacks and anti-debug" },
  { mnemonic: "CPUID", opcode: "0FA2", category: "system", description: "CPU identification", example: "CPUID", flags: "None", notes: "EAX=leaf; returns info in EAX,EBX,ECX,EDX; used for VM detection" },
];

// ============================================================================
// ARM INSTRUCTION REFERENCE
// ============================================================================
export const ARM_INSTRUCTIONS = [
  { mnemonic: "MOV", category: "data-movement", description: "Move value to register", example: "MOV R0, #42", notes: "Can use barrel shifter: MOV R0, R1, LSL #2" },
  { mnemonic: "MVN", category: "data-movement", description: "Move NOT (bitwise complement)", example: "MVN R0, R1", notes: "R0 = ~R1" },
  { mnemonic: "MOVW", category: "data-movement", description: "Move wide (16-bit immediate to lower half)", example: "MOVW R0, #0x1234", notes: "ARMv6T2+; clears upper 16 bits" },
  { mnemonic: "MOVT", category: "data-movement", description: "Move top (16-bit immediate to upper half)", example: "MOVT R0, #0x5678", notes: "Pair with MOVW for 32-bit immediate load" },
  { mnemonic: "LDR", category: "data-movement", description: "Load register from memory", example: "LDR R0, [R1, #4]", notes: "Pre/post-indexed; LDR R0, =label for address load" },
  { mnemonic: "STR", category: "data-movement", description: "Store register to memory", example: "STR R0, [SP, #-4]!", notes: "Pre-indexed with writeback (!)" },
  { mnemonic: "LDM", category: "data-movement", description: "Load multiple registers", example: "LDMIA SP!, {R0-R3}", notes: "IA/IB/DA/DB variants; fast block load" },
  { mnemonic: "STM", category: "data-movement", description: "Store multiple registers", example: "STMDB SP!, {R4-R11,LR}", notes: "STMDB SP! = PUSH; function prologue" },
  { mnemonic: "PUSH", category: "data-movement", description: "Push registers onto stack", example: "PUSH {R4-R7,LR}", notes: "Alias for STMDB SP!" },
  { mnemonic: "POP", category: "data-movement", description: "Pop registers from stack", example: "POP {R4-R7,PC}", notes: "Alias for LDMIA SP!; POP {PC} = return" },
  { mnemonic: "ADD", category: "arithmetic", description: "Add", example: "ADD R0, R1, R2", notes: "Three-operand: Rd = Rn + operand2" },
  { mnemonic: "ADC", category: "arithmetic", description: "Add with carry", example: "ADC R0, R1, R2", notes: "Rd = Rn + operand2 + C" },
  { mnemonic: "SUB", category: "arithmetic", description: "Subtract", example: "SUB R0, R1, #10", notes: "Rd = Rn - operand2" },
  { mnemonic: "RSB", category: "arithmetic", description: "Reverse subtract", example: "RSB R0, R1, #0", notes: "Rd = operand2 - Rn; RSB R0, R0, #0 = negate" },
  { mnemonic: "MUL", category: "arithmetic", description: "Multiply", example: "MUL R0, R1, R2", notes: "Rd = Rm * Rs (lower 32 bits)" },
  { mnemonic: "MLA", category: "arithmetic", description: "Multiply-accumulate", example: "MLA R0, R1, R2, R3", notes: "Rd = Rm * Rs + Rn" },
  { mnemonic: "UMULL", category: "arithmetic", description: "Unsigned multiply long", example: "UMULL R0, R1, R2, R3", notes: "RdHi:RdLo = Rm * Rs (64-bit result)" },
  { mnemonic: "SMULL", category: "arithmetic", description: "Signed multiply long", example: "SMULL R0, R1, R2, R3", notes: "Signed 64-bit result" },
  { mnemonic: "SDIV", category: "arithmetic", description: "Signed divide", example: "SDIV R0, R1, R2", notes: "ARMv7-A optional; R0 = R1 / R2" },
  { mnemonic: "UDIV", category: "arithmetic", description: "Unsigned divide", example: "UDIV R0, R1, R2", notes: "ARMv7-A optional" },
  { mnemonic: "AND", category: "logical", description: "Bitwise AND", example: "AND R0, R1, #0xFF", notes: "Rd = Rn & operand2" },
  { mnemonic: "ORR", category: "logical", description: "Bitwise OR", example: "ORR R0, R1, R2", notes: "Rd = Rn | operand2" },
  { mnemonic: "EOR", category: "logical", description: "Bitwise XOR", example: "EOR R0, R0, R0", notes: "Zero-register idiom on ARM" },
  { mnemonic: "BIC", category: "logical", description: "Bit clear (AND NOT)", example: "BIC R0, R1, #0x80", notes: "Rd = Rn & ~operand2; clear specific bits" },
  { mnemonic: "LSL", category: "logical", description: "Logical shift left", example: "LSL R0, R1, #3", notes: "Alias for MOV with barrel shifter" },
  { mnemonic: "LSR", category: "logical", description: "Logical shift right", example: "LSR R0, R1, #1", notes: "Unsigned right shift" },
  { mnemonic: "ASR", category: "logical", description: "Arithmetic shift right", example: "ASR R0, R1, #1", notes: "Signed right shift; preserves sign" },
  { mnemonic: "ROR", category: "logical", description: "Rotate right", example: "ROR R0, R1, #8", notes: "Circular right rotation" },
  { mnemonic: "CMP", category: "comparison", description: "Compare (subtract, set flags only)", example: "CMP R0, #0", notes: "Sets NZCV flags; no result written" },
  { mnemonic: "CMN", category: "comparison", description: "Compare negative (add, set flags only)", example: "CMN R0, #1", notes: "Like CMP but adds instead of subtracts" },
  { mnemonic: "TST", category: "comparison", description: "Test bits (AND, set flags only)", example: "TST R0, #1", notes: "Sets flags from Rn & operand2; no result" },
  { mnemonic: "TEQ", category: "comparison", description: "Test equivalence (XOR, set flags only)", example: "TEQ R0, R1", notes: "Sets flags from Rn ^ operand2" },
  { mnemonic: "B", category: "control-flow", description: "Branch", example: "B loop_start", notes: "PC-relative; ±32MB range" },
  { mnemonic: "BL", category: "control-flow", description: "Branch with link (call)", example: "BL printf", notes: "LR = return address; then branch" },
  { mnemonic: "BX", category: "control-flow", description: "Branch and exchange (ARM/Thumb switch)", example: "BX LR", notes: "BX LR = return; low bit of target selects Thumb/ARM" },
  { mnemonic: "BLX", category: "control-flow", description: "Branch with link and exchange", example: "BLX R0", notes: "Call with possible ARM/Thumb switch" },
  { mnemonic: "CBZ", category: "control-flow", description: "Compare and branch if zero", example: "CBZ R0, done", notes: "Thumb-2 only; limited range" },
  { mnemonic: "CBNZ", category: "control-flow", description: "Compare and branch if not zero", example: "CBNZ R0, loop", notes: "Thumb-2 only" },
  { mnemonic: "IT", category: "control-flow", description: "If-Then block (Thumb-2)", example: "ITE EQ", notes: "Up to 4 conditional instructions; ITE = if-then-else" },
  { mnemonic: "SVC", category: "system", description: "Supervisor call (system call)", example: "SVC #0", notes: "ARM equivalent of INT/SYSCALL; Linux: R7=syscall#" },
  { mnemonic: "MRS", category: "system", description: "Move status register to general register", example: "MRS R0, CPSR", notes: "Read CPSR or SPSR" },
  { mnemonic: "MSR", category: "system", description: "Move to status register", example: "MSR CPSR_f, R0", notes: "Write CPSR/SPSR fields; privileged for some fields" },
  { mnemonic: "CLZ", category: "arithmetic", description: "Count leading zeros", example: "CLZ R0, R1", notes: "Useful for log2; returns 32 if input is 0" },
  { mnemonic: "REV", category: "data-movement", description: "Byte-reverse word", example: "REV R0, R1", notes: "Endian swap; ARMv6+" },
  { mnemonic: "RBIT", category: "logical", description: "Reverse bits", example: "RBIT R0, R1", notes: "Reverses all 32 bits; ARMv6T2+" },
  { mnemonic: "LDREX", category: "atomic", description: "Load exclusive (for atomics)", example: "LDREX R0, [R1]", notes: "Sets exclusive monitor; pair with STREX" },
  { mnemonic: "STREX", category: "atomic", description: "Store exclusive (for atomics)", example: "STREX R2, R0, [R1]", notes: "R2=0 success, R2=1 fail; CAS building block" },
  { mnemonic: "DMB", category: "barrier", description: "Data memory barrier", example: "DMB ISH", notes: "Ensures memory ordering; ISH = inner shareable" },
  { mnemonic: "DSB", category: "barrier", description: "Data synchronization barrier", example: "DSB SY", notes: "Ensures completion of memory operations" },
  { mnemonic: "ISB", category: "barrier", description: "Instruction synchronization barrier", example: "ISB SY", notes: "Flushes pipeline; needed after cache/TLB maintenance" },
  { mnemonic: "VFMA.F32", category: "fpu", description: "Fused multiply-add (float)", example: "VFMA.F32 S0, S1, S2", notes: "S0 = S0 + S1*S2 with single rounding" },
  { mnemonic: "VLDR", category: "fpu", description: "Load float register from memory", example: "VLDR D0, [R0]", notes: "Loads single (S) or double (D) float" },
  { mnemonic: "VSTR", category: "fpu", description: "Store float register to memory", example: "VSTR S0, [SP]", notes: "Stores single or double float" },
];

// ============================================================================
// CALLING CONVENTIONS
// ============================================================================
export const CALLING_CONVENTIONS = [
  {
    name: "cdecl",
    platform: "x86 (C default)",
    args: "Pushed right-to-left on stack",
    return_value: "EAX (or EDX:EAX for 64-bit)",
    stack_cleanup: "Caller cleans stack (ADD ESP, n after CALL)",
    callee_saved: "EBX, ESI, EDI, EBP, ESP",
    caller_saved: "EAX, ECX, EDX",
    notes: "Default for C on x86; allows variadic functions because caller knows arg count",
    prologue: "PUSH EBP; MOV EBP, ESP; SUB ESP, locals",
    epilogue: "MOV ESP, EBP; POP EBP; RET"
  },
  {
    name: "stdcall",
    platform: "x86 (Win32 API)",
    args: "Pushed right-to-left on stack",
    return_value: "EAX (or EDX:EAX for 64-bit)",
    stack_cleanup: "Callee cleans stack (RET n)",
    callee_saved: "EBX, ESI, EDI, EBP, ESP",
    caller_saved: "EAX, ECX, EDX",
    notes: "Used by Win32 API (WINAPI/__stdcall); smaller caller code; no variadic support",
    prologue: "PUSH EBP; MOV EBP, ESP; SUB ESP, locals",
    epilogue: "MOV ESP, EBP; POP EBP; RET imm16"
  },
  {
    name: "fastcall",
    platform: "x86 (MSVC)",
    args: "First 2 args in ECX, EDX; rest on stack right-to-left",
    return_value: "EAX",
    stack_cleanup: "Callee cleans stack",
    callee_saved: "EBX, ESI, EDI, EBP, ESP",
    caller_saved: "EAX, ECX, EDX",
    notes: "MSVC __fastcall; GCC __attribute__((fastcall)); faster for small arg counts",
    prologue: "PUSH EBP; MOV EBP, ESP; (save ECX/EDX to locals)",
    epilogue: "MOV ESP, EBP; POP EBP; RET imm16"
  },
  {
    name: "thiscall",
    platform: "x86 (MSVC C++)",
    args: "'this' pointer in ECX; rest on stack right-to-left",
    return_value: "EAX",
    stack_cleanup: "Callee cleans stack (non-variadic); caller cleans (variadic)",
    callee_saved: "EBX, ESI, EDI, EBP, ESP",
    caller_saved: "EAX, ECX, EDX",
    notes: "MSVC C++ member functions; GCC uses cdecl with 'this' as first stack arg",
    prologue: "PUSH EBP; MOV EBP, ESP; (save ECX as this)",
    epilogue: "MOV ESP, EBP; POP EBP; RET imm16"
  },
  {
    name: "System V AMD64 ABI",
    platform: "x86-64 (Linux, macOS, BSD)",
    args: "RDI, RSI, RDX, RCX, R8, R9 (integer/pointer); XMM0-XMM7 (float); rest on stack",
    return_value: "RAX (+ RDX for 128-bit); XMM0 (+ XMM1 for float)",
    stack_cleanup: "Caller",
    callee_saved: "RBX, RBP, R12-R15, RSP",
    caller_saved: "RAX, RCX, RDX, RSI, RDI, R8-R11, XMM0-XMM15",
    notes: "Red zone: 128 bytes below RSP usable without SUB RSP; 16-byte stack alignment at CALL",
    prologue: "PUSH RBP; MOV RBP, RSP; SUB RSP, locals (or use red zone for leaf)",
    epilogue: "LEAVE; RET"
  },
  {
    name: "Microsoft x64",
    platform: "x86-64 (Windows)",
    args: "RCX, RDX, R8, R9 (integer/pointer); XMM0-XMM3 (float); rest on stack; 32-byte shadow space",
    return_value: "RAX; XMM0 (float)",
    stack_cleanup: "Caller",
    callee_saved: "RBX, RBP, RDI, RSI, R12-R15, RSP, XMM6-XMM15",
    caller_saved: "RAX, RCX, RDX, R8-R11, XMM0-XMM5",
    notes: "Shadow space: 32 bytes always reserved above return address even for <4 args; no red zone",
    prologue: "SUB RSP, 28h+ (shadow + locals + alignment); MOV [RSP+shadow], RCX...",
    epilogue: "ADD RSP, 28h+; RET"
  },
  {
    name: "ARM AAPCS",
    platform: "ARM (32-bit)",
    args: "R0-R3 (first 4 args); rest on stack; D0-D7 (float/double if VFP)",
    return_value: "R0 (+ R1 for 64-bit); D0 (float/double)",
    stack_cleanup: "Caller",
    callee_saved: "R4-R11, SP (R13), LR (R14 — saved then restored to PC)",
    caller_saved: "R0-R3, R12 (IP), LR",
    notes: "8-byte stack alignment at public interface; R12 is intra-procedure scratch (IP)",
    prologue: "PUSH {R4-R11, LR}; SUB SP, SP, #locals",
    epilogue: "ADD SP, SP, #locals; POP {R4-R11, PC}"
  },
  {
    name: "ARM64 (AAPCS64)",
    platform: "AArch64",
    args: "X0-X7 (integer/pointer); D0-D7 (float); rest on stack",
    return_value: "X0 (+ X1 for 128-bit); D0 (float)",
    stack_cleanup: "Caller",
    callee_saved: "X19-X28, X29 (FP), X30 (LR), SP, D8-D15",
    caller_saved: "X0-X18, X30 (LR also caller-saved for tail calls), D0-D7, D16-D31",
    notes: "X29 = frame pointer; X30 = link register; X18 = platform register (reserved on some OS); 16-byte SP alignment",
    prologue: "STP X29, X30, [SP, #-frame]!; MOV X29, SP",
    epilogue: "LDP X29, X30, [SP], #frame; RET"
  },
];

// ============================================================================
// PE (PORTABLE EXECUTABLE) FILE FORMAT
// ============================================================================
export const PE_FORMAT = {
  dos_header: {
    description: "DOS MZ header at offset 0; backwards-compatible with MS-DOS",
    size: "64 bytes",
    fields: [
      { offset: "0x00", size: 2, name: "e_magic", value: "0x5A4D", description: "MZ signature (Mark Zbikowski)" },
      { offset: "0x02", size: 2, name: "e_cblp", description: "Bytes on last page of file" },
      { offset: "0x04", size: 2, name: "e_cp", description: "Pages in file" },
      { offset: "0x06", size: 2, name: "e_crlc", description: "Relocations" },
      { offset: "0x08", size: 2, name: "e_cparhdr", description: "Size of header in paragraphs" },
      { offset: "0x0A", size: 2, name: "e_minalloc", description: "Minimum extra paragraphs" },
      { offset: "0x0C", size: 2, name: "e_maxalloc", description: "Maximum extra paragraphs" },
      { offset: "0x0E", size: 2, name: "e_ss", description: "Initial SS value" },
      { offset: "0x10", size: 2, name: "e_sp", description: "Initial SP value" },
      { offset: "0x12", size: 2, name: "e_csum", description: "Checksum" },
      { offset: "0x14", size: 2, name: "e_ip", description: "Initial IP value" },
      { offset: "0x16", size: 2, name: "e_cs", description: "Initial CS value" },
      { offset: "0x18", size: 2, name: "e_lfarlc", description: "Offset to relocation table" },
      { offset: "0x1A", size: 2, name: "e_ovno", description: "Overlay number" },
      { offset: "0x3C", size: 4, name: "e_lfanew", description: "Offset to PE header (critical for PE parsing)" },
    ]
  },
  nt_headers: {
    description: "PE signature + COFF file header + optional header",
    fields: [
      { offset: "+0x00", size: 4, name: "Signature", value: "0x00004550", description: "PE\\0\\0 signature" },
    ]
  },
  coff_header: {
    description: "IMAGE_FILE_HEADER — 20 bytes after PE signature",
    fields: [
      { offset: "+0x04", size: 2, name: "Machine", description: "Target architecture", values: { "0x014C": "i386", "0x8664": "AMD64", "0xAA64": "ARM64", "0x01C4": "ARMv7" } },
      { offset: "+0x06", size: 2, name: "NumberOfSections", description: "Section count" },
      { offset: "+0x08", size: 4, name: "TimeDateStamp", description: "UTC Unix timestamp of build" },
      { offset: "+0x0C", size: 4, name: "PointerToSymbolTable", description: "COFF symbol table offset (0 for images)" },
      { offset: "+0x10", size: 4, name: "NumberOfSymbols", description: "Number of COFF symbols" },
      { offset: "+0x14", size: 2, name: "SizeOfOptionalHeader", description: "Size of optional header (0xE0 for PE32, 0xF0 for PE32+)" },
      { offset: "+0x16", size: 2, name: "Characteristics", description: "Flags", values: { "0x0002": "EXECUTABLE_IMAGE", "0x0020": "LARGE_ADDRESS_AWARE", "0x0100": "32BIT_MACHINE", "0x2000": "DLL" } },
    ]
  },
  optional_header: {
    description: "IMAGE_OPTIONAL_HEADER — contains entry point, image base, data directories",
    pe32_magic: "0x10B",
    pe32plus_magic: "0x20B",
    key_fields: [
      { name: "Magic", size: 2, description: "0x10B = PE32, 0x20B = PE32+ (64-bit)" },
      { name: "AddressOfEntryPoint", size: 4, description: "RVA of entry point (OEP in packed binaries)" },
      { name: "ImageBase", size: "4/8", description: "Preferred load address (0x400000 exe, 0x10000000 dll)" },
      { name: "SectionAlignment", size: 4, description: "Section alignment in memory (usually 0x1000)" },
      { name: "FileAlignment", size: 4, description: "Section alignment on disk (usually 0x200)" },
      { name: "SizeOfImage", size: 4, description: "Total size of image in memory" },
      { name: "SizeOfHeaders", size: 4, description: "Size of all headers (rounded to FileAlignment)" },
      { name: "Checksum", size: 4, description: "Image checksum (required for drivers/system DLLs)" },
      { name: "Subsystem", size: 2, description: "Required subsystem", values: { 1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI" } },
      { name: "DllCharacteristics", size: 2, description: "Security flags", values: { "0x0020": "HIGH_ENTROPY_VA", "0x0040": "DYNAMIC_BASE (ASLR)", "0x0100": "NX_COMPAT (DEP)", "0x0400": "NO_SEH", "0x4000": "GUARD_CF" } },
      { name: "NumberOfRvaAndSizes", size: 4, description: "Number of data directory entries (usually 16)" },
    ]
  },
  data_directories: {
    description: "IMAGE_DATA_DIRECTORY array — RVA + Size pairs for each table",
    entries: [
      { index: 0, name: "Export Table", description: "Exported functions (DLLs)" },
      { index: 1, name: "Import Table", description: "Imported DLLs and functions (critical for analysis)" },
      { index: 2, name: "Resource Table", description: "Icons, strings, version info, embedded files" },
      { index: 3, name: "Exception Table", description: "Exception handler info (.pdata on x64)" },
      { index: 4, name: "Certificate Table", description: "Authenticode digital signatures" },
      { index: 5, name: "Base Relocation Table", description: "Fixups for ASLR relocation" },
      { index: 6, name: "Debug Directory", description: "Debug info (PDB path, build GUID)" },
      { index: 9, name: "TLS Table", description: "Thread Local Storage — TLS callbacks run before OEP (anti-debug)" },
      { index: 10, name: "Load Config", description: "SEH handler table, CFG function table, security cookie" },
      { index: 11, name: "Bound Import", description: "Pre-bound DLL timestamps (optimization)" },
      { index: 12, name: "IAT", description: "Import Address Table (overwritten by loader with function pointers)" },
      { index: 13, name: "Delay Import", description: "Delay-loaded DLLs" },
      { index: 14, name: "CLR Runtime Header", description: ".NET metadata (cor20 header) — indicates managed code" },
    ]
  },
  section_header: {
    description: "IMAGE_SECTION_HEADER — 40 bytes per section",
    fields: [
      { name: "Name", size: 8, description: "Section name (e.g. .text, .data, .rdata, .rsrc, .reloc)" },
      { name: "VirtualSize", size: 4, description: "Size in memory" },
      { name: "VirtualAddress", size: 4, description: "RVA when loaded" },
      { name: "SizeOfRawData", size: 4, description: "Size on disk" },
      { name: "PointerToRawData", size: 4, description: "File offset to section data" },
      { name: "Characteristics", size: 4, description: "Section flags", values: { "0x00000020": "CNT_CODE", "0x00000040": "CNT_INITIALIZED_DATA", "0x00000080": "CNT_UNINITIALIZED_DATA", "0x20000000": "MEM_EXECUTE", "0x40000000": "MEM_READ", "0x80000000": "MEM_WRITE" } },
    ],
    common_sections: [
      { name: ".text", description: "Executable code", typical_flags: "CODE | MEM_EXECUTE | MEM_READ" },
      { name: ".data", description: "Initialized read/write data (global variables)", typical_flags: "INITIALIZED_DATA | MEM_READ | MEM_WRITE" },
      { name: ".rdata", description: "Read-only data (strings, vtables, import descriptors)", typical_flags: "INITIALIZED_DATA | MEM_READ" },
      { name: ".bss", description: "Uninitialized data", typical_flags: "UNINITIALIZED_DATA | MEM_READ | MEM_WRITE" },
      { name: ".rsrc", description: "Resources (icons, dialogs, version info)", typical_flags: "INITIALIZED_DATA | MEM_READ" },
      { name: ".reloc", description: "Base relocations for ASLR", typical_flags: "INITIALIZED_DATA | MEM_READ | MEM_DISCARDABLE" },
      { name: ".edata", description: "Export table", typical_flags: "INITIALIZED_DATA | MEM_READ" },
      { name: ".idata", description: "Import table", typical_flags: "INITIALIZED_DATA | MEM_READ | MEM_WRITE" },
      { name: ".tls", description: "Thread-local storage", typical_flags: "INITIALIZED_DATA | MEM_READ | MEM_WRITE" },
      { name: ".pdata", description: "Exception info (x64)", typical_flags: "INITIALIZED_DATA | MEM_READ" },
      { name: "UPX0", description: "UPX packer — compressed section (empty on disk)", typical_flags: "UNINITIALIZED_DATA | MEM_EXECUTE | MEM_READ | MEM_WRITE" },
      { name: "UPX1", description: "UPX packer — packed data + decompressor stub", typical_flags: "INITIALIZED_DATA | MEM_EXECUTE | MEM_READ | MEM_WRITE" },
    ]
  }
};

// ============================================================================
// ELF (EXECUTABLE AND LINKABLE FORMAT)
// ============================================================================
export const ELF_FORMAT = {
  elf_header: {
    description: "ELF header at offset 0 — identifies file type, architecture, entry point",
    size: "52 bytes (32-bit) / 64 bytes (64-bit)",
    fields: [
      { offset: "0x00", size: 4, name: "e_ident[EI_MAG]", value: "0x7F 'E' 'L' 'F'", description: "ELF magic number" },
      { offset: "0x04", size: 1, name: "e_ident[EI_CLASS]", description: "Class: 1=32-bit, 2=64-bit" },
      { offset: "0x05", size: 1, name: "e_ident[EI_DATA]", description: "Endianness: 1=little, 2=big" },
      { offset: "0x06", size: 1, name: "e_ident[EI_VERSION]", description: "ELF version (1)" },
      { offset: "0x07", size: 1, name: "e_ident[EI_OSABI]", description: "OS ABI: 0=System V, 3=Linux, 9=FreeBSD" },
      { offset: "0x10", size: 2, name: "e_type", description: "Type: 1=REL, 2=EXEC, 3=DYN (shared/PIE), 4=CORE" },
      { offset: "0x12", size: 2, name: "e_machine", description: "Architecture: 3=x86, 0x3E=x86-64, 0x28=ARM, 0xB7=AArch64" },
      { offset: "0x18", size: "4/8", name: "e_entry", description: "Entry point virtual address" },
      { offset: "0x1C/0x20", size: "4/8", name: "e_phoff", description: "Program header table offset" },
      { offset: "0x20/0x28", size: "4/8", name: "e_shoff", description: "Section header table offset" },
      { offset: "0x2C/0x38", size: 2, name: "e_phentsize", description: "Program header entry size" },
      { offset: "0x2E/0x3A", size: 2, name: "e_phnum", description: "Number of program headers" },
      { offset: "0x30/0x3C", size: 2, name: "e_shentsize", description: "Section header entry size" },
      { offset: "0x32/0x3E", size: 2, name: "e_shnum", description: "Number of section headers" },
      { offset: "0x34/0x40", size: 2, name: "e_shstrndx", description: "Section name string table index" },
    ]
  },
  program_header: {
    description: "Describes segments for the runtime loader",
    fields: [
      { name: "p_type", description: "Segment type", values: { 0: "PT_NULL", 1: "PT_LOAD (loadable)", 2: "PT_DYNAMIC (dynamic linking info)", 3: "PT_INTERP (interpreter path)", 4: "PT_NOTE", 6: "PT_PHDR", 0x6474E550: "PT_GNU_EH_FRAME", 0x6474E551: "PT_GNU_STACK", 0x6474E552: "PT_GNU_RELRO" } },
      { name: "p_flags", description: "Segment permissions: 1=X, 2=W, 4=R (e.g. 5=R+X for .text, 6=R+W for .data)" },
      { name: "p_offset", description: "File offset of segment" },
      { name: "p_vaddr", description: "Virtual address in memory" },
      { name: "p_paddr", description: "Physical address (usually same as p_vaddr)" },
      { name: "p_filesz", description: "Size in file (0 for .bss)" },
      { name: "p_memsz", description: "Size in memory (≥ p_filesz; difference is zero-filled)" },
      { name: "p_align", description: "Alignment (usually page size: 0x1000)" },
    ],
    security_relevant: [
      { type: "PT_GNU_STACK", description: "Stack permissions; if X flag is present, stack is executable (NX bypass). 'execstack' tool or paxctl can set this." },
      { type: "PT_GNU_RELRO", description: "Read-only after relocation. Partial RELRO: .init_array/.fini_array/.got writable. Full RELRO: .got.plt also read-only (prevents GOT overwrite)." },
      { type: "PT_INTERP", description: "Path to dynamic linker (usually /lib64/ld-linux-x86-64.so.2). Can be changed to hijack loading process." },
    ]
  },
  section_header: {
    description: "Describes sections for linker and tools (not needed at runtime)",
    common_sections: [
      { name: ".text", description: "Executable code", flags: "ALLOC | EXECINSTR" },
      { name: ".data", description: "Initialized read/write data", flags: "ALLOC | WRITE" },
      { name: ".rodata", description: "Read-only data (strings, constants)", flags: "ALLOC" },
      { name: ".bss", description: "Uninitialized data (zero at load)", flags: "ALLOC | WRITE", type: "NOBITS" },
      { name: ".plt", description: "Procedure Linkage Table (lazy binding stubs)", flags: "ALLOC | EXECINSTR" },
      { name: ".got", description: "Global Offset Table (resolved addresses)", flags: "ALLOC | WRITE" },
      { name: ".got.plt", description: "GOT for PLT entries (overwrite target for exploits)", flags: "ALLOC | WRITE" },
      { name: ".dynsym", description: "Dynamic symbol table", flags: "ALLOC" },
      { name: ".dynstr", description: "Dynamic string table", flags: "ALLOC" },
      { name: ".dynamic", description: "Dynamic linking information", flags: "ALLOC | WRITE" },
      { name: ".init", description: "Initialization code (runs before main)", flags: "ALLOC | EXECINSTR" },
      { name: ".fini", description: "Finalization code (runs after main)", flags: "ALLOC | EXECINSTR" },
      { name: ".init_array", description: "Array of constructor function pointers", flags: "ALLOC | WRITE" },
      { name: ".fini_array", description: "Array of destructor function pointers", flags: "ALLOC | WRITE" },
      { name: ".rel.plt / .rela.plt", description: "Relocations for PLT entries", flags: "ALLOC" },
      { name: ".note.gnu.build-id", description: "Build ID (unique binary identifier)", flags: "ALLOC" },
      { name: ".eh_frame", description: "Exception handling frame info (DWARF CFI)", flags: "ALLOC" },
      { name: ".debug_info", description: "DWARF debug information", flags: "None (not loaded)" },
      { name: ".symtab", description: "Full symbol table (stripped in release)", flags: "None" },
      { name: ".strtab", description: "String table for .symtab", flags: "None" },
    ]
  },
  security_mitigations: [
    { name: "NX/DEP (W^X)", check: "readelf -l binary | grep GNU_STACK", enabled: "No E (execute) flag on GNU_STACK", description: "Non-executable stack; prevents shellcode on stack" },
    { name: "ASLR", check: "cat /proc/sys/kernel/randomize_va_space (2=full)", enabled: "System-wide setting + PIE binary", description: "Randomizes stack, heap, mmap, and (with PIE) text base" },
    { name: "PIE", check: "readelf -h binary | grep Type (DYN = PIE, EXEC = no PIE)", enabled: "e_type is ET_DYN", description: "Position-Independent Executable; enables full ASLR for text segment" },
    { name: "Stack Canary", check: "readelf -s binary | grep __stack_chk_fail", enabled: "Symbol present", description: "Random value on stack before return address; detects buffer overflow" },
    { name: "RELRO (Partial)", check: "readelf -l binary | grep GNU_RELRO", enabled: "PT_GNU_RELRO present", description: "Makes .init_array, .fini_array, .got read-only after relocation" },
    { name: "RELRO (Full)", check: "readelf -d binary | grep BIND_NOW", enabled: "BIND_NOW flag + GNU_RELRO", description: "Also makes .got.plt read-only; prevents GOT overwrite attacks" },
    { name: "FORTIFY_SOURCE", check: "readelf -s binary | grep __*_chk", enabled: "__printf_chk etc. present", description: "Compile-time buffer overflow checks on string/memory functions" },
    { name: "CFI (Control Flow Integrity)", check: "readelf -n binary (CET property)", enabled: "IBT/SHSTK in GNU property note", description: "Intel CET: shadow stack + indirect branch tracking" },
  ]
};

// ============================================================================
// IDA PRO SHORTCUTS AND COMMANDS
// ============================================================================
export const IDA_PRO_COMMANDS = [
  // Navigation
  { shortcut: "G", action: "Go to address", description: "Jump to a specific address or name" },
  { shortcut: "Space", action: "Toggle graph/text view", description: "Switch between graph and linear disassembly" },
  { shortcut: "Esc", action: "Go back", description: "Return to previous navigation position" },
  { shortcut: "Ctrl+Enter", action: "Go forward", description: "Undo Esc navigation" },
  { shortcut: "X", action: "Cross-references to", description: "Show all references TO the current symbol/address" },
  { shortcut: "Ctrl+X", action: "Cross-references from", description: "Show all references FROM the current instruction" },
  { shortcut: "Ctrl+L", action: "Jump to name", description: "Show list of all named items" },
  { shortcut: "Ctrl+P", action: "Jump to function", description: "Show list of all functions" },
  { shortcut: "Ctrl+S", action: "Jump to segment", description: "Show list of segments" },
  { shortcut: "Ctrl+E", action: "Jump to entry point", description: "Show entry points" },
  { shortcut: "Ctrl+G", action: "Jump to segment register", description: "Jump by segment register value" },
  { shortcut: "Alt+I", action: "Search immediate value", description: "Find all instructions using a constant" },
  { shortcut: "Alt+T", action: "Search text", description: "Search disassembly text" },
  { shortcut: "Alt+B", action: "Search bytes", description: "Search for byte sequence (hex)" },
  { shortcut: "Ctrl+F", action: "Search in current function", description: "Quick search in current function" },

  // Analysis & Naming
  { shortcut: "N", action: "Rename", description: "Rename address/function/variable" },
  { shortcut: "Y", action: "Set type", description: "Set the type of a function or variable (C declaration)" },
  { shortcut: ";", action: "Add comment", description: "Add repeatable comment" },
  { shortcut: ":", action: "Add comment (non-repeatable)", description: "Comment shown only at this address" },
  { shortcut: "Ins", action: "Add anterior comment", description: "Comment line before the instruction" },
  { shortcut: "P", action: "Create function", description: "Define a function starting at cursor" },
  { shortcut: "U", action: "Undefine", description: "Convert defined item back to raw bytes" },
  { shortcut: "C", action: "Code", description: "Convert bytes to code (disassemble)" },
  { shortcut: "D", action: "Data", description: "Convert to data (db/dw/dd/dq)" },
  { shortcut: "A", action: "ASCII string", description: "Convert bytes to string" },
  { shortcut: "O", action: "Offset", description: "Convert number to offset reference" },
  { shortcut: "H", action: "Hex/decimal toggle", description: "Toggle between hex and decimal display" },
  { shortcut: "R", action: "Character constant", description: "Display as character constant ('A')" },
  { shortcut: "M", action: "Enum member", description: "Convert to enum member" },
  { shortcut: "T", action: "Struct offset", description: "Convert to structure offset" },
  { shortcut: "Alt+Q", action: "Edit struct variable", description: "Apply structure to a location" },

  // Structs & Enums
  { shortcut: "Shift+F9", action: "Open Structures window", description: "View/edit structure definitions" },
  { shortcut: "Shift+F10", action: "Open Enums window", description: "View/edit enum definitions" },
  { shortcut: "Insert (in Structs)", action: "Add struct", description: "Create new structure definition" },
  { shortcut: "D (in Structs)", action: "Add field", description: "Add field to structure" },

  // Views & Windows
  { shortcut: "F5", action: "Decompile (Hex-Rays)", description: "Show pseudocode (requires Hex-Rays decompiler)" },
  { shortcut: "Tab", action: "Switch disasm/pseudocode", description: "Toggle between disassembly and decompiler" },
  { shortcut: "Shift+F4", action: "Names window", description: "List all named items" },
  { shortcut: "Shift+F7", action: "Segments window", description: "List all segments" },
  { shortcut: "Shift+F12", action: "Strings window", description: "List all detected strings" },
  { shortcut: "Ctrl+1", action: "Quick view", description: "Show available views menu" },
  { shortcut: "F12", action: "Flow chart", description: "Show function flow chart" },

  // Debugging
  { shortcut: "F2", action: "Set breakpoint", description: "Toggle breakpoint at cursor" },
  { shortcut: "F7", action: "Step into", description: "Execute one instruction (enter calls)" },
  { shortcut: "F8", action: "Step over", description: "Execute one instruction (skip calls)" },
  { shortcut: "F9", action: "Continue", description: "Run until next breakpoint" },
  { shortcut: "Ctrl+F7", action: "Run to cursor", description: "Execute until cursor position" },
  { shortcut: "Ctrl+F2", action: "Terminate", description: "Stop debugging" },
  { shortcut: "F4", action: "Run to cursor (alt)", description: "Alternative run to cursor" },

  // Hex-Rays Decompiler
  { shortcut: "/ (in pseudocode)", action: "Add comment", description: "Add comment in decompiler" },
  { shortcut: "N (in pseudocode)", action: "Rename variable", description: "Rename local variable in decompiler" },
  { shortcut: "Y (in pseudocode)", action: "Set variable type", description: "Change type of variable in decompiler" },
  { shortcut: "= (in pseudocode)", action: "Rename label", description: "Rename a label in decompiler" },
  { shortcut: "Ctrl+Shift+W", action: "Copy to assembly", description: "Copy pseudocode to assembly" },

  // Patching
  { shortcut: "Edit > Patch program", action: "Patch bytes", description: "Modify bytes in the database" },
  { shortcut: "Keypatch plugin", action: "Assemble instruction", description: "Type assembly, get bytes (plugin)" },

  // Scripting
  { shortcut: "Shift+F2", action: "IDC/Python script", description: "Open script command window" },
  { shortcut: "Alt+F7", action: "Load script file", description: "Run a script from file" },
  { shortcut: "Alt+F9", action: "Recent scripts", description: "Show recently run scripts" },

  // Other
  { shortcut: "Ctrl+W", action: "Save database", description: "Save IDA database (.idb/.i64)" },
  { shortcut: "Ctrl+Z", action: "Undo", description: "Undo last action (IDA 7.3+)" },
  { shortcut: "Ctrl+Shift+Z", action: "Redo", description: "Redo last undone action" },
];

// ============================================================================
// GHIDRA SHORTCUTS AND COMMANDS
// ============================================================================
export const GHIDRA_COMMANDS = [
  { shortcut: "G", action: "Go to address", description: "Navigate to address or label" },
  { shortcut: "L", action: "Rename", description: "Rename symbol/label at cursor" },
  { shortcut: ";", action: "Set comment (EOL)", description: "End-of-line comment" },
  { shortcut: "Ctrl+;", action: "Set comment (plate)", description: "Plate comment (before function)" },
  { shortcut: "Enter", action: "Follow reference", description: "Navigate to referenced address" },
  { shortcut: "Alt+Left", action: "Go back", description: "Previous navigation location" },
  { shortcut: "Alt+Right", action: "Go forward", description: "Next navigation location" },
  { shortcut: "D", action: "Disassemble", description: "Convert bytes to instructions" },
  { shortcut: "C", action: "Clear code", description: "Clear defined code/data" },
  { shortcut: "F", action: "Create function", description: "Define function at cursor" },
  { shortcut: "T", action: "Set data type", description: "Apply data type at cursor" },
  { shortcut: "Ctrl+Shift+E", action: "Export program", description: "Export program to file" },
  { shortcut: "Ctrl+Shift+T", action: "Retype variable", description: "Change variable type" },
  { shortcut: "Ctrl+L", action: "Retype return", description: "Change function return type" },
  { shortcut: "P", action: "Edit function signature", description: "Edit parameters and calling convention" },
  { shortcut: "Ctrl+E", action: "Show references to", description: "Find all XRefs to this address" },
  { shortcut: "Ctrl+Shift+F", action: "Show references from", description: "Find all XRefs from this address" },
  { shortcut: "Shift+[", action: "Create array", description: "Define array at cursor" },
  { shortcut: "Shift+S", action: "Create structure", description: "Define/edit structure" },
  { shortcut: "B", action: "Set bookmark", description: "Create a bookmark" },
  { shortcut: "Ctrl+B", action: "Show bookmarks", description: "List all bookmarks" },
  { shortcut: "Ctrl+Shift+E", action: "Search memory", description: "Search for bytes in memory" },
  { shortcut: "S", action: "Search strings", description: "Open defined strings window" },
  { shortcut: "Ctrl+F", action: "Find text", description: "Search in listing text" },
  { shortcut: "Ctrl+Shift+H", action: "Highlight forward", description: "Highlight all matching items" },
  { shortcut: "Middle click", action: "Highlight", description: "Highlight register/variable" },
  { shortcut: "1-9", action: "Data size (in Listing)", description: "Create data of byte/word/dword size" },
  // Decompiler
  { shortcut: "Ctrl+E (decompiler)", action: "Show references", description: "XRefs in decompiler" },
  { shortcut: "L (decompiler)", action: "Rename variable", description: "Rename local in decompiler" },
  { shortcut: "Ctrl+L (decompiler)", action: "Retype variable", description: "Change variable type in decompiler" },
  { shortcut: "Shift+G (decompiler)", action: "Graph control flow", description: "Show control flow graph" },
  { shortcut: "Ctrl+Shift+G", action: "Graph function calls", description: "Show call graph" },
  // Scripting
  { shortcut: "Script Manager (Window menu)", action: "Script Manager", description: "Browse and run Ghidra scripts (Java/Python)" },
  { shortcut: "Ctrl+Alt+F5", action: "Run last script", description: "Re-execute most recent script" },
  // Analysis
  { shortcut: "A", action: "Auto-analyze", description: "Re-run auto analysis" },
  { shortcut: "Ctrl+Shift+D", action: "Disassemble ARM/Thumb", description: "Switch between ARM and Thumb disassembly" },
  // Navigation
  { shortcut: "Ctrl+Home", action: "Go to beginning", description: "Navigate to start of program" },
  { shortcut: "Ctrl+End", action: "Go to end", description: "Navigate to end of program" },
  { shortcut: "Ctrl+Shift+N", action: "Go to next undefined", description: "Find next undefined bytes" },
  { shortcut: "N", action: "Next occurrence", description: "Go to next search match" },
  // Windows
  { shortcut: "Window > Functions", action: "Function list", description: "Show all defined functions" },
  { shortcut: "Window > Symbol Table", action: "Symbol table", description: "All symbols" },
  { shortcut: "Window > Data Type Manager", action: "Type manager", description: "Browse/edit data types" },
  { shortcut: "Window > Decompiler", action: "Decompiler view", description: "Open decompiler window" },
  { shortcut: "Window > Bytes", action: "Hex view", description: "Show raw hex bytes" },
  { shortcut: "Window > Script Console", action: "Script console", description: "Interactive Python/Java console" },
];

// ============================================================================
// RADARE2 / RIZIN COMMANDS
// ============================================================================
export const R2_COMMANDS = [
  // Info
  { command: "i", description: "File info summary", example: "i", category: "info" },
  { command: "ia", description: "Show all info (imports, exports, symbols, sections, etc.)", example: "ia", category: "info" },
  { command: "iI", description: "Binary info (arch, bits, endian, OS, class)", example: "iI", category: "info" },
  { command: "ie", description: "Entry points", example: "ie", category: "info" },
  { command: "ii", description: "Imports", example: "ii", category: "info" },
  { command: "iE", description: "Exports", example: "iE", category: "info" },
  { command: "is", description: "Symbols", example: "is", category: "info" },
  { command: "iS", description: "Sections", example: "iS", category: "info" },
  { command: "iz", description: "Strings in data section", example: "iz", category: "info" },
  { command: "izz", description: "Strings in entire binary", example: "izz", category: "info" },
  { command: "il", description: "Libraries", example: "il", category: "info" },
  { command: "ic", description: "Classes (C++ / ObjC)", example: "ic", category: "info" },
  { command: "ih", description: "Headers info", example: "ih", category: "info" },
  { command: "iM", description: "Show main address", example: "iM", category: "info" },

  // Analysis
  { command: "aa", description: "Analyze all (basic analysis)", example: "aa", category: "analysis" },
  { command: "aaa", description: "Analyze all autoname functions", example: "aaa", category: "analysis" },
  { command: "aaaa", description: "Full analysis (emulation + experimental)", example: "aaaa", category: "analysis" },
  { command: "afl", description: "List functions", example: "afl", category: "analysis" },
  { command: "afll", description: "List functions (long format)", example: "afll", category: "analysis" },
  { command: "afl~main", description: "Find main function", example: "afl~main", category: "analysis" },
  { command: "af", description: "Analyze function at current address", example: "af", category: "analysis" },
  { command: "afn", description: "Rename function", example: "afn my_func", category: "analysis" },
  { command: "afi", description: "Function info", example: "afi", category: "analysis" },
  { command: "afv", description: "List function variables", example: "afv", category: "analysis" },
  { command: "afvn", description: "Rename function variable", example: "afvn new_name old_name", category: "analysis" },
  { command: "ax", description: "Show cross-references", example: "ax", category: "analysis" },
  { command: "axt", description: "XRefs to current address", example: "axt @ sym.func", category: "analysis" },
  { command: "axf", description: "XRefs from current address", example: "axf", category: "analysis" },
  { command: "agf", description: "Function graph (ASCII art)", example: "agf", category: "analysis" },
  { command: "agC", description: "Call graph (global)", example: "agC", category: "analysis" },
  { command: "VV", description: "Visual graph mode", example: "VV", category: "analysis" },
  { command: "ahi", description: "Set immediate base (hex, decimal, etc.)", example: "ahi 16", category: "analysis" },

  // Seeking / Navigation
  { command: "s", description: "Print current address", example: "s", category: "seek" },
  { command: "s addr", description: "Seek to address", example: "s 0x401000", category: "seek" },
  { command: "s main", description: "Seek to symbol", example: "s main", category: "seek" },
  { command: "s+", description: "Seek forward (redo)", example: "s+", category: "seek" },
  { command: "s-", description: "Seek backward (undo)", example: "s-", category: "seek" },
  { command: "sf", description: "Seek to function start", example: "sf", category: "seek" },
  { command: "sf.", description: "Seek to function end", example: "sf.", category: "seek" },
  { command: "sn", description: "Seek to next function", example: "sn", category: "seek" },
  { command: "sp", description: "Seek to previous function", example: "sp", category: "seek" },

  // Print / Disassemble
  { command: "pd", description: "Print disassembly", example: "pd 20", category: "print" },
  { command: "pdf", description: "Print disassembly of function", example: "pdf", category: "print" },
  { command: "pdc", description: "Print decompiled C (r2dec/r2ghidra)", example: "pdc", category: "print" },
  { command: "pdg", description: "Print Ghidra decompilation (r2ghidra)", example: "pdg", category: "print" },
  { command: "px", description: "Print hex dump", example: "px 64", category: "print" },
  { command: "pxw", description: "Print hex words (32-bit)", example: "pxw 32", category: "print" },
  { command: "ps", description: "Print string", example: "ps @ 0x402000", category: "print" },
  { command: "psz", description: "Print zero-terminated string", example: "psz", category: "print" },
  { command: "pf", description: "Print formatted", example: "pf xxS addr1 addr2 str", category: "print" },
  { command: "p8", description: "Print hex bytes (raw)", example: "p8 10", category: "print" },

  // Writing / Patching
  { command: "w", description: "Write string", example: "w hello", category: "write" },
  { command: "wx", description: "Write hex bytes", example: "wx 9090", category: "write" },
  { command: "wa", description: "Write assembly", example: "wa nop;nop", category: "write" },
  { command: "wao", description: "Write assembly operation", example: "wao nop", category: "write" },
  { command: "wc", description: "List write changes", example: "wc", category: "write" },
  { command: "wci", description: "Commit changes to file", example: "wci", category: "write" },

  // Search
  { command: "/", description: "Search string", example: "/ password", category: "search" },
  { command: "/x", description: "Search hex bytes", example: "/x 4d5a", category: "search" },
  { command: "/R", description: "Search ROP gadgets", example: "/R pop rdi", category: "search" },
  { command: "/Rl", description: "List ROP gadgets (all)", example: "/Rl", category: "search" },
  { command: "/a", description: "Search assembly pattern", example: "/a jmp eax", category: "search" },
  { command: "/r", description: "Search xrefs to address", example: "/r sym.imp.system", category: "search" },
  { command: "/c", description: "Search crypto constants", example: "/c", category: "search" },

  // Debug
  { command: "db", description: "Set breakpoint", example: "db 0x401000", category: "debug" },
  { command: "db-", description: "Remove breakpoint", example: "db- 0x401000", category: "debug" },
  { command: "dbl", description: "List breakpoints", example: "dbl", category: "debug" },
  { command: "dc", description: "Continue execution", example: "dc", category: "debug" },
  { command: "ds", description: "Step into", example: "ds", category: "debug" },
  { command: "dso", description: "Step over", example: "dso", category: "debug" },
  { command: "dr", description: "Show registers", example: "dr", category: "debug" },
  { command: "dr=", description: "Show registers (formatted)", example: "dr=", category: "debug" },
  { command: "dm", description: "Show memory maps", example: "dm", category: "debug" },
  { command: "dbt", description: "Backtrace", example: "dbt", category: "debug" },
  { command: "dcu", description: "Continue until address", example: "dcu main", category: "debug" },

  // Flags / Comments
  { command: "f", description: "List flags", example: "f", category: "flags" },
  { command: "f name", description: "Set flag at current address", example: "f my_label", category: "flags" },
  { command: "f-name", description: "Remove flag", example: "f-my_label", category: "flags" },
  { command: "CC", description: "Add comment", example: "CC this is a comment", category: "flags" },
  { command: "CC-", description: "Remove comment", example: "CC-", category: "flags" },

  // Visual Mode
  { command: "V", description: "Enter visual mode", example: "V", category: "visual" },
  { command: "VV", description: "Enter visual graph mode", example: "VV", category: "visual" },
  { command: "V!", description: "Visual panels mode", example: "V!", category: "visual" },
  { command: "p/P (in visual)", description: "Cycle through print modes", example: "(press p)", category: "visual" },
  { command: "q", description: "Quit visual mode / r2", example: "q", category: "visual" },

  // Project
  { command: "Ps", description: "Save project", example: "Ps myproject", category: "project" },
  { command: "Po", description: "Open project", example: "Po myproject", category: "project" },

  // Emulation
  { command: "ae", description: "ESIL expression", example: "ae rax,1,+", category: "emulation" },
  { command: "aes", description: "ESIL step", example: "aes", category: "emulation" },
  { command: "aep", description: "ESIL pin at address", example: "aep", category: "emulation" },
  { command: "aeim", description: "Initialize ESIL VM memory", example: "aeim", category: "emulation" },
  { command: "aeip", description: "Set ESIL instruction pointer", example: "aeip", category: "emulation" },

  // Misc
  { command: "~", description: "Grep output (internal grep)", example: "afl~main", category: "misc" },
  { command: "@@", description: "Iterate over (foreach)", example: "pdf @@ is~imp.", category: "misc" },
  { command: "> file", description: "Redirect output to file", example: "pdf > func.asm", category: "misc" },
  { command: "?", description: "Help", example: "?", category: "misc" },
  { command: "?v", description: "Evaluate expression", example: "?v 0x41 - 0x20", category: "misc" },
  { command: "?e", description: "Echo string", example: "?e hello", category: "misc" },
  { command: "e", description: "Show/set config", example: "e asm.syntax=att", category: "misc" },
  { command: "eco", description: "Color themes", example: "eco monokai", category: "misc" },
  { command: "r2pm", description: "Package manager", example: "r2pm -i r2ghidra", category: "misc" },
];

// ============================================================================
// ANTI-REVERSING TECHNIQUES
// ============================================================================
export const ANTI_REVERSING = [
  {
    name: "IsDebuggerPresent",
    category: "anti-debug",
    platform: "Windows",
    description: "Checks PEB.BeingDebugged flag (offset 0x02 in PEB)",
    detection: "kernel32!IsDebuggerPresent returns 1 if debugger attached",
    bypass: "Patch PEB.BeingDebugged to 0; set breakpoint on API and modify return value; ScyllaHide plugin"
  },
  {
    name: "CheckRemoteDebuggerPresent",
    category: "anti-debug",
    platform: "Windows",
    description: "Checks if a remote debugger is attached via NtQueryInformationProcess",
    detection: "CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged)",
    bypass: "Hook NtQueryInformationProcess; return STATUS_SUCCESS with debugged=FALSE"
  },
  {
    name: "NtQueryInformationProcess",
    category: "anti-debug",
    platform: "Windows",
    description: "ProcessDebugPort (0x07), ProcessDebugObjectHandle (0x1E), ProcessDebugFlags (0x1F)",
    detection: "DebugPort != 0, DebugObjectHandle exists, or DebugFlags == 0 indicates debugger",
    bypass: "Hook ntdll!NtQueryInformationProcess; ScyllaHide patches all three checks"
  },
  {
    name: "NtQuerySystemInformation",
    category: "anti-debug",
    platform: "Windows",
    description: "SystemKernelDebuggerInformation class reveals kernel debugger",
    detection: "Returns KdDebuggerEnabled and KdDebuggerNotPresent flags",
    bypass: "Hook the syscall; modify return buffer"
  },
  {
    name: "PEB flags",
    category: "anti-debug",
    platform: "Windows",
    description: "Multiple PEB fields reveal debugging: NtGlobalFlag, heap flags",
    detection: "PEB.NtGlobalFlag == 0x70 (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS) when debugged",
    bypass: "Clear NtGlobalFlag; use _NO_DEBUG_HEAP=1 environment variable"
  },
  {
    name: "Timing checks (RDTSC)",
    category: "anti-debug",
    platform: "Cross-platform",
    description: "Measures time between instructions; single-stepping causes large delays",
    detection: "RDTSC before and after code block; difference > threshold = debugger",
    bypass: "Hardware breakpoints instead of software; modify RDTSC return; TrapFlag"
  },
  {
    name: "INT 2D",
    category: "anti-debug",
    platform: "Windows",
    description: "Kernel debug interrupt; behaves differently under debugger",
    detection: "INT 2D causes debugger to single-step, skipping the next byte",
    bypass: "Patch INT 2D to NOP; handle in exception handler"
  },
  {
    name: "Hardware breakpoint detection",
    category: "anti-debug",
    platform: "Cross-platform",
    description: "Reads debug registers DR0-DR3 to detect hardware breakpoints",
    detection: "GetThreadContext → check DR0-DR3 for non-zero values",
    bypass: "Clear DRx in context; use software breakpoints; hook GetThreadContext"
  },
  {
    name: "Software breakpoint detection (0xCC scan)",
    category: "anti-debug",
    platform: "Cross-platform",
    description: "Scans code section for INT3 (0xCC) bytes inserted by debugger",
    detection: "CRC32/checksum of .text section; compare at runtime",
    bypass: "Use hardware breakpoints; page guard breakpoints; modify checksum"
  },
  {
    name: "TLS callbacks",
    category: "anti-debug",
    platform: "Windows",
    description: "TLS callback functions execute before OEP; can perform anti-debug before debugger breaks",
    detection: "Code in TLS callback checks for debugger before main entry",
    bypass: "Set breakpoint on TLS callback (IDA: Options > Debugger > Events; x64dbg: System Breakpoint)"
  },
  {
    name: "ptrace(PTRACE_TRACEME)",
    category: "anti-debug",
    platform: "Linux",
    description: "Process traces itself; second ptrace attach (debugger) fails",
    detection: "ptrace(PTRACE_TRACEME, 0, 0, 0) returns -1 if already traced",
    bypass: "LD_PRELOAD hook ptrace to return 0; patch call; use /proc/pid/status TracerPid check instead"
  },
  {
    name: "/proc/self/status TracerPid",
    category: "anti-debug",
    platform: "Linux",
    description: "Reads /proc/self/status for TracerPid field; non-zero means traced",
    detection: "grep TracerPid /proc/self/status; value > 0 = debugger attached",
    bypass: "Seccomp filter; hook open/read; modify /proc filesystem"
  },
  {
    name: "Exception-based anti-debug",
    category: "anti-debug",
    platform: "Cross-platform",
    description: "Triggers exception (div by zero, access violation); debugger intercepts before handler",
    detection: "If exception handler runs, no debugger; if not reached, debugger caught it",
    bypass: "Pass exception to application (F9 in x64dbg; 'pass exception' in GDB)"
  },
  {
    name: "UPX packing",
    category: "packer",
    platform: "Cross-platform",
    description: "Open-source executable packer; compresses code, decompresses at runtime",
    detection: "UPX0/UPX1 section names; upx -d to unpack",
    bypass: "upx -d file.exe; or set breakpoint at OEP after decompression (tail jump)"
  },
  {
    name: "Themida/WinLicense",
    category: "packer",
    platform: "Windows",
    description: "Commercial protector with VM, anti-debug, anti-dump, code mutation",
    detection: "Extremely large sections, import obfuscation, driver-level anti-debug",
    bypass: "Very difficult; dump + reconstruct imports; specialized unpackers; Scylla for IAT reconstruction"
  },
  {
    name: "VMProtect",
    category: "packer",
    platform: "Windows",
    description: "Converts x86 code to custom bytecode interpreted by a VM",
    detection: ".vmp0/.vmp1 sections; huge code size increase; custom VM dispatcher loop",
    bypass: "Extremely difficult; VM analysis, symbolic execution; devirtualization tools (research-grade)"
  },
  {
    name: "Control flow obfuscation",
    category: "obfuscation",
    platform: "Cross-platform",
    description: "Opaque predicates, dead code insertion, control flow flattening, bogus jumps",
    detection: "Switch-based dispatcher (flattening), always-true/false branches (opaque predicates)",
    bypass: "Symbolic execution; pattern matching; deobfuscation scripts (Miasm, Triton, angr)"
  },
  {
    name: "String encryption",
    category: "obfuscation",
    platform: "Cross-platform",
    description: "Strings are encrypted in binary; decrypted at runtime with XOR/RC4/custom cipher",
    detection: "No readable strings in .rodata; decryption function called before string use",
    bypass: "Set breakpoint after decryption; dump memory; FLOSS tool for automatic string extraction"
  },
  {
    name: "Import obfuscation",
    category: "obfuscation",
    platform: "Windows",
    description: "IAT is empty/minimal; real imports resolved at runtime via GetProcAddress with hashed names",
    detection: "Minimal import table; many calls to GetProcAddress; hash-based API resolution",
    bypass: "Identify hash algorithm; build hash→name lookup; IDA plugin hashdb; runtime API logging"
  },
  {
    name: "Anti-VM (virtual machine detection)",
    category: "anti-vm",
    platform: "Cross-platform",
    description: "Detects execution inside VMware/VirtualBox/QEMU/Hyper-V to evade sandboxes",
    detection: "Check CPUID hypervisor bit, VM-specific registry keys, MAC OUI (00:0C:29 VMware, 08:00:27 VBox), specific files/drivers, SMBIOS strings",
    bypass: "Harden VM: change MAC, remove tools, modify CPUID, patch SMBIOS, use bare-metal sandbox"
  },
  {
    name: "Anti-sandbox",
    category: "anti-vm",
    platform: "Cross-platform",
    description: "Detects automated analysis environments (Cuckoo, Any.Run, Joe Sandbox)",
    detection: "Check username (sandbox/malware), low RAM (<4GB), few files on desktop, no recent files, mouse movement, uptime",
    bypass: "Configure sandbox with realistic user profile, RAM, files, simulate user activity"
  },
  {
    name: "Self-modifying code",
    category: "obfuscation",
    platform: "Cross-platform",
    description: "Code modifies itself at runtime; static disassembly shows wrong instructions",
    detection: "VirtualProtect calls to make code writable; writes to code section",
    bypass: "Dynamic analysis; dump after modification; trace execution"
  },
  {
    name: "Code virtualization (custom VM)",
    category: "obfuscation",
    platform: "Cross-platform",
    description: "Translates native code to custom bytecode with unique instruction set per build",
    detection: "Large dispatcher loop; bytecode table; handler array; context structure",
    bypass: "Identify VM handler table → map virtual opcodes → devirtualize; extremely time-consuming"
  },
];

// ============================================================================
// COMMON CODE PATTERNS IN REVERSE ENGINEERING
// ============================================================================
export const CODE_PATTERNS = [
  {
    name: "Function prologue (x86)",
    pattern: "PUSH EBP; MOV EBP, ESP; SUB ESP, N",
    description: "Standard function setup: save frame pointer, allocate local variables",
    hex: "55 89 E5 83 EC XX",
    notes: "N = local variable space; some compilers use ENTER instruction instead"
  },
  {
    name: "Function prologue (x64 SysV)",
    pattern: "PUSH RBP; MOV RBP, RSP; SUB RSP, N",
    description: "64-bit function setup with frame pointer",
    hex: "55 48 89 E5 48 83 EC XX",
    notes: "Leaf functions may skip frame pointer; -fomit-frame-pointer"
  },
  {
    name: "Function epilogue",
    pattern: "LEAVE; RET",
    description: "Restore frame pointer and return",
    hex: "C9 C3",
    notes: "LEAVE = MOV ESP,EBP; POP EBP; sometimes MOV/POP used explicitly"
  },
  {
    name: "Virtual function call (vtable dispatch)",
    pattern: "MOV RAX, [RCX]; CALL [RAX+offset]",
    description: "Load vtable pointer from object, call function at vtable offset",
    hex: "48 8B 01 FF 50 XX",
    notes: "RCX/RDI = this pointer; first qword of object = vtable pointer; offset/8 = vtable index"
  },
  {
    name: "Switch table (jump table)",
    pattern: "CMP reg, N; JA default; JMP [table + reg*4]",
    description: "Compiler-optimized switch statement using indexed jump table",
    hex: "83 F8 XX 77 XX FF 24 85 XX XX XX XX",
    notes: "N = number of cases - 1; table contains target addresses; may use subtract to normalize"
  },
  {
    name: "Switch table (computed offset)",
    pattern: "CMP; JA default; MOVZX; JMP [RIP + table + reg*4]",
    description: "PIC-friendly switch with relative offsets in table",
    notes: "Table entries are relative offsets, not absolute addresses (for ASLR compatibility)"
  },
  {
    name: "String copy loop",
    pattern: "LODSB; STOSB; TEST AL, AL; JNZ loop",
    description: "Copy null-terminated string from ESI to EDI",
    notes: "Sometimes optimized to DWORD copies with alignment handling"
  },
  {
    name: "memset pattern",
    pattern: "REP STOSB/STOSD",
    description: "Fill memory with byte/dword value in AL/EAX",
    notes: "ECX = count; EDI = destination; direction flag must be clear (CLD)"
  },
  {
    name: "memcpy pattern",
    pattern: "REP MOVSB/MOVSD",
    description: "Copy memory block from ESI to EDI",
    notes: "ECX = count; modern compilers may use SSE/AVX for large copies"
  },
  {
    name: "Position-independent code (thunk)",
    pattern: "CALL next; next: POP EBX",
    description: "Get current instruction pointer (x86 PIC); EBX = base for GOT access",
    hex: "E8 00 00 00 00 5B",
    notes: "x86 has no direct way to read EIP; this is the standard PIC pattern; x64 uses RIP-relative"
  },
  {
    name: "Structured Exception Handler (SEH) setup",
    pattern: "PUSH handler; PUSH FS:[0]; MOV FS:[0], ESP",
    description: "Install exception handler on SEH chain",
    notes: "Windows x86 only; x64 uses table-based exceptions (.pdata)"
  },
  {
    name: "C++ exception handling (try/catch)",
    pattern: "MOV [EBP-4], -1; ... MOV [EBP-4], 0; ...",
    description: "MSVC uses a state variable at [EBP-4] to track which destructors to call",
    notes: "-1 = initial state; increments at each try block entry; funclet-based on x64"
  },
  {
    name: "Canary check",
    pattern: "MOV reg, FS:[0x28]; ... XOR reg, FS:[0x28]; JNZ __stack_chk_fail",
    description: "Stack canary verification before return",
    hex: "64 48 8B 04 25 28 00 00 00",
    notes: "Linux: FS:[0x28] (x64) or GS:[0x14] (x86); Windows: __security_cookie"
  },
  {
    name: "Multiply by constant (strength reduction)",
    pattern: "LEA EAX, [REG+REG*2] (multiply by 3); SHL + ADD combinations",
    description: "Compiler replaces MUL with LEA/SHL/ADD for known constants",
    notes: "x*3 = LEA [x+x*2]; x*5 = LEA [x+x*4]; x*7 = LEA [x+x*8]-x; x*10 = LEA [x+x*4],SHL 1"
  },
  {
    name: "Division by constant (magic number)",
    pattern: "MOV reg, magic; MUL/IMUL; SHR result, shift",
    description: "Compiler replaces DIV with multiply-by-reciprocal for known divisors",
    notes: "n/3 → IMUL 0xAAAAAAAB then SHR; recognizable by large magic constant before MUL"
  },
  {
    name: "Tail call optimization",
    pattern: "JMP function (instead of CALL+RET)",
    description: "Compiler replaces CALL+RET with JMP when return value is passed through",
    notes: "Looks like a jump to another function at the end of current function"
  },
  {
    name: "Loop with induction variable",
    pattern: "XOR ECX, ECX; loop: ...; INC ECX; CMP ECX, N; JL loop",
    description: "Standard counted for loop",
    notes: "Compiler may use DEC+JNZ (counting down) or unroll small loops"
  },
];

// ============================================================================
// WINDOWS API CATEGORIES FOR MALWARE ANALYSIS
// ============================================================================
export const WINDOWS_API_CATEGORIES = {
  file_operations: {
    description: "File system access — creating, reading, writing, deleting files",
    suspicious_apis: [
      { api: "CreateFileA/W", risk: "medium", description: "Open/create file; check path for sensitive locations" },
      { api: "ReadFile", risk: "low", description: "Read from file handle" },
      { api: "WriteFile", risk: "medium", description: "Write to file; could be dropping payload" },
      { api: "DeleteFileA/W", risk: "high", description: "Delete file; may be covering tracks" },
      { api: "CopyFileA/W", risk: "medium", description: "Copy file; self-replication or staging" },
      { api: "MoveFileA/W", risk: "medium", description: "Move/rename file" },
      { api: "FindFirstFileA/W", risk: "low", description: "Directory enumeration; may be searching for targets" },
      { api: "GetTempPathA/W", risk: "low", description: "Get temp directory; common staging location" },
      { api: "SetFileAttributesA/W", risk: "medium", description: "Hide files (HIDDEN, SYSTEM attributes)" },
    ]
  },
  registry_operations: {
    description: "Windows Registry access — persistence, configuration, system modification",
    suspicious_apis: [
      { api: "RegOpenKeyExA/W", risk: "medium", description: "Open registry key" },
      { api: "RegSetValueExA/W", risk: "high", description: "Write registry value; persistence if Run/RunOnce keys" },
      { api: "RegDeleteValueA/W", risk: "medium", description: "Delete registry value" },
      { api: "RegCreateKeyExA/W", risk: "high", description: "Create new registry key" },
      { api: "RegQueryValueExA/W", risk: "low", description: "Read registry value; may read config or detect AV" },
    ],
    persistence_keys: [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
      "HKLM\\SYSTEM\\CurrentControlSet\\Services",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    ]
  },
  network_operations: {
    description: "Network communication — C2 callbacks, data exfiltration, lateral movement",
    suspicious_apis: [
      { api: "WSAStartup", risk: "medium", description: "Initialize Winsock; indicates network activity" },
      { api: "socket", risk: "medium", description: "Create socket" },
      { api: "connect", risk: "high", description: "Connect to remote host; C2 communication" },
      { api: "send/recv", risk: "high", description: "Send/receive data; C2 protocol" },
      { api: "InternetOpenA/W", risk: "high", description: "Initialize WinINet; HTTP-based C2" },
      { api: "InternetOpenUrlA/W", risk: "high", description: "Open URL; download payload or C2 beacon" },
      { api: "HttpOpenRequestA/W", risk: "high", description: "Create HTTP request; C2 communication" },
      { api: "HttpSendRequestA/W", risk: "high", description: "Send HTTP request" },
      { api: "InternetReadFile", risk: "medium", description: "Read HTTP response; download stage" },
      { api: "URLDownloadToFileA/W", risk: "high", description: "Download file from URL; drive-by download" },
      { api: "WinHttpOpen", risk: "high", description: "Initialize WinHTTP (newer than WinINet)" },
      { api: "DnsQuery_A/W", risk: "medium", description: "DNS query; DNS tunneling or C2 over DNS" },
      { api: "getaddrinfo", risk: "low", description: "Resolve hostname" },
      { api: "gethostname", risk: "low", description: "Get local hostname; reconnaissance" },
    ]
  },
  process_operations: {
    description: "Process creation and manipulation — injection, execution, evasion",
    suspicious_apis: [
      { api: "CreateProcessA/W", risk: "high", description: "Create new process; may execute payload" },
      { api: "OpenProcess", risk: "high", description: "Open process handle; injection target" },
      { api: "VirtualAllocEx", risk: "high", description: "Allocate memory in remote process; injection setup" },
      { api: "WriteProcessMemory", risk: "high", description: "Write to remote process memory; injection" },
      { api: "CreateRemoteThread", risk: "high", description: "Create thread in remote process; classic injection" },
      { api: "NtCreateThreadEx", risk: "high", description: "Low-level remote thread creation; harder to detect" },
      { api: "QueueUserAPC", risk: "high", description: "Queue APC to remote thread; APC injection" },
      { api: "NtQueueApcThread", risk: "high", description: "Low-level APC injection" },
      { api: "SetWindowsHookExA/W", risk: "high", description: "Install hook; DLL injection via hooks" },
      { api: "NtUnmapViewOfSection", risk: "high", description: "Unmap section; process hollowing" },
      { api: "GetProcAddress", risk: "medium", description: "Resolve API at runtime; dynamic import resolution" },
      { api: "LoadLibraryA/W", risk: "medium", description: "Load DLL; may load malicious library" },
      { api: "ShellExecuteA/W", risk: "high", description: "Execute program or open file" },
      { api: "WinExec", risk: "high", description: "Execute program (legacy API)" },
      { api: "TerminateProcess", risk: "high", description: "Kill process; may target AV/EDR" },
      { api: "EnumProcesses", risk: "medium", description: "List processes; AV detection" },
      { api: "CreateToolhelp32Snapshot", risk: "medium", description: "Process/thread/module enumeration" },
    ]
  },
  crypto_operations: {
    description: "Cryptographic operations — ransomware encryption, C2 encryption, credential theft",
    suspicious_apis: [
      { api: "CryptAcquireContextA/W", risk: "medium", description: "Get crypto provider; encryption setup" },
      { api: "CryptGenKey", risk: "medium", description: "Generate encryption key" },
      { api: "CryptEncrypt", risk: "high", description: "Encrypt data; ransomware encryption" },
      { api: "CryptDecrypt", risk: "medium", description: "Decrypt data; unpacking or config decryption" },
      { api: "CryptImportKey", risk: "medium", description: "Import key; may import C2 server's public key" },
      { api: "CryptExportKey", risk: "high", description: "Export key; ransomware may exfiltrate key" },
      { api: "BCryptEncrypt", risk: "high", description: "Modern CNG encryption" },
      { api: "BCryptGenerateSymmetricKey", risk: "medium", description: "Generate symmetric key (CNG)" },
      { api: "CryptStringToBinaryA/W", risk: "low", description: "Decode Base64/hex; decoding obfuscated strings" },
    ]
  },
  service_operations: {
    description: "Windows Service manipulation — persistence, privilege escalation",
    suspicious_apis: [
      { api: "OpenSCManagerA/W", risk: "high", description: "Open Service Control Manager" },
      { api: "CreateServiceA/W", risk: "high", description: "Install service; persistence mechanism" },
      { api: "StartServiceA/W", risk: "high", description: "Start a service" },
      { api: "ChangeServiceConfig2A/W", risk: "high", description: "Modify service configuration" },
    ]
  },
  privilege_operations: {
    description: "Privilege manipulation and token operations",
    suspicious_apis: [
      { api: "AdjustTokenPrivileges", risk: "high", description: "Enable/disable token privileges; SeDebugPrivilege for injection" },
      { api: "OpenProcessToken", risk: "medium", description: "Get process token; check privileges" },
      { api: "LookupPrivilegeValueA/W", risk: "low", description: "Get privilege LUID" },
      { api: "ImpersonateLoggedOnUser", risk: "high", description: "Impersonate another user's token" },
      { api: "DuplicateTokenEx", risk: "high", description: "Duplicate access token; token manipulation" },
      { api: "CreateProcessWithTokenW", risk: "high", description: "Create process as another user" },
    ]
  },
  evasion_apis: {
    description: "APIs commonly used for defense evasion",
    suspicious_apis: [
      { api: "VirtualProtect", risk: "high", description: "Change memory protection; make code writable or data executable" },
      { api: "VirtualAlloc (PAGE_EXECUTE_READWRITE)", risk: "high", description: "Allocate RWX memory; shellcode execution" },
      { api: "NtAllocateVirtualMemory", risk: "high", description: "Low-level memory allocation; syscall-level evasion" },
      { api: "Sleep/NtDelayExecution", risk: "low", description: "Delay execution; sandbox evasion (long sleep)" },
      { api: "GetTickCount/QueryPerformanceCounter", risk: "low", description: "Timing check; sandbox/debugger detection" },
      { api: "IsDebuggerPresent", risk: "medium", description: "Anti-debug check" },
      { api: "OutputDebugStringA/W", risk: "low", description: "Anti-debug (error behavior differs)" },
      { api: "NtSetInformationThread (ThreadHideFromDebugger)", risk: "high", description: "Hide thread from debugger" },
    ]
  }
};

// ============================================================================
// USEFUL TOOLS LIST
// ============================================================================
export const RE_TOOLS = [
  { name: "IDA Pro", category: "disassembler", platform: "Windows/Linux/macOS", description: "Industry-standard interactive disassembler + Hex-Rays decompiler", cost: "Commercial ($1,800+)", url: "hex-rays.com" },
  { name: "Ghidra", category: "disassembler", platform: "Windows/Linux/macOS", description: "NSA's open-source reverse engineering suite with decompiler", cost: "Free", url: "ghidra-sre.org" },
  { name: "Binary Ninja", category: "disassembler", platform: "Windows/Linux/macOS", description: "Modern disassembler with IL-based analysis", cost: "Commercial ($300+)", url: "binary.ninja" },
  { name: "radare2/rizin", category: "disassembler", platform: "Cross-platform", description: "Open-source command-line reverse engineering framework", cost: "Free", url: "radare.org" },
  { name: "Cutter", category: "disassembler", platform: "Cross-platform", description: "GUI frontend for rizin/radare2 with Ghidra decompiler integration", cost: "Free", url: "cutter.re" },
  { name: "x64dbg", category: "debugger", platform: "Windows", description: "Open-source x64/x32 debugger for Windows", cost: "Free", url: "x64dbg.com" },
  { name: "WinDbg", category: "debugger", platform: "Windows", description: "Microsoft's debugger for user-mode and kernel-mode debugging", cost: "Free", url: "Microsoft Store" },
  { name: "GDB", category: "debugger", platform: "Linux/macOS", description: "GNU Debugger; supports remote debugging, scripting (Python)", cost: "Free", url: "gnu.org/software/gdb" },
  { name: "GEF/pwndbg/peda", category: "debugger", platform: "Linux", description: "GDB enhancement plugins for exploit development", cost: "Free", url: "github.com" },
  { name: "LLDB", category: "debugger", platform: "macOS/Linux", description: "LLVM debugger; default on macOS", cost: "Free", url: "lldb.llvm.org" },
  { name: "Frida", category: "dynamic", platform: "Cross-platform", description: "Dynamic instrumentation toolkit; inject JS into processes", cost: "Free", url: "frida.re" },
  { name: "DynamoRIO", category: "dynamic", platform: "Windows/Linux", description: "Runtime code manipulation system; build custom analysis tools", cost: "Free", url: "dynamorio.org" },
  { name: "Pin", category: "dynamic", platform: "Windows/Linux/macOS", description: "Intel's dynamic binary instrumentation framework", cost: "Free", url: "intel.com" },
  { name: "angr", category: "analysis", platform: "Cross-platform (Python)", description: "Binary analysis platform with symbolic execution", cost: "Free", url: "angr.io" },
  { name: "Triton", category: "analysis", platform: "Cross-platform", description: "Dynamic binary analysis framework; symbolic execution + taint analysis", cost: "Free", url: "triton-library.github.io" },
  { name: "Capstone", category: "library", platform: "Cross-platform", description: "Disassembly framework (multi-arch); API for building tools", cost: "Free", url: "capstone-engine.org" },
  { name: "Keystone", category: "library", platform: "Cross-platform", description: "Assembler framework (companion to Capstone)", cost: "Free", url: "keystone-engine.org" },
  { name: "Unicorn", category: "library", platform: "Cross-platform", description: "CPU emulator framework based on QEMU; emulate code snippets", cost: "Free", url: "unicorn-engine.org" },
  { name: "pefile (Python)", category: "library", platform: "Cross-platform", description: "Parse and modify PE files", cost: "Free", url: "pypi.org/project/pefile" },
  { name: "LIEF", category: "library", platform: "Cross-platform", description: "Parse/modify PE, ELF, Mach-O, Android formats", cost: "Free", url: "lief-project.github.io" },
  { name: "PE-bear", category: "viewer", platform: "Windows", description: "PE file viewer and editor with visual section map", cost: "Free", url: "github.com/hasherezade/pe-bear" },
  { name: "CFF Explorer", category: "viewer", platform: "Windows", description: "PE editor with hex view, import/export tables, resource viewer", cost: "Free", url: "ntcore.com" },
  { name: "readelf/objdump", category: "viewer", platform: "Linux", description: "GNU binutils ELF inspection tools", cost: "Free", url: "System package" },
  { name: "strings", category: "utility", platform: "Cross-platform", description: "Extract printable strings from binary", cost: "Free", url: "System tool" },
  { name: "FLOSS", category: "utility", platform: "Cross-platform", description: "FireEye Labs Obfuscated String Solver; extract encrypted strings", cost: "Free", url: "github.com/mandiant/flare-floss" },
  { name: "Detect It Easy (DIE)", category: "utility", platform: "Cross-platform", description: "Packer/compiler/linker detection", cost: "Free", url: "github.com/horsicq/Detect-It-Easy" },
  { name: "Binwalk", category: "utility", platform: "Cross-platform", description: "Firmware analysis; extract embedded files and filesystems", cost: "Free", url: "github.com/ReFirmLabs/binwalk" },
  { name: "Volatility", category: "memory", platform: "Cross-platform (Python)", description: "Memory forensics framework; analyze memory dumps", cost: "Free", url: "volatilityfoundation.org" },
];
