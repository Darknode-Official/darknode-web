// Reverse Engineering Reference Database — comprehensive reference for security research
// Educational reference for authorized security testing only.

export const REVERSE_ENGINEERING_DB = {
  x86Instructions: {
    dataMovement: [
      { mnemonic: "MOV", operands: "dest, src", description: "Copy src to dest. Most common instruction.", example: "MOV EAX, 0x41414141 ; EAX = 0x41414141", flags: "None" },
      { mnemonic: "MOVZX", operands: "dest, src", description: "Move with zero extension (unsigned). Smaller src into larger dest, upper bits zeroed.", example: "MOVZX EAX, BYTE [ESI] ; load byte, zero-extend to 32-bit", flags: "None" },
      { mnemonic: "MOVSX", operands: "dest, src", description: "Move with sign extension (signed). Preserves sign bit into larger register.", example: "MOVSX EAX, BYTE [ESI] ; load byte, sign-extend to 32-bit", flags: "None" },
      { mnemonic: "LEA", operands: "dest, mem", description: "Load Effective Address. Computes address without memory access. Often used for arithmetic.", example: "LEA EAX, [EBX+ECX*4+8] ; EAX = EBX + ECX*4 + 8 (no memory read)", flags: "None" },
      { mnemonic: "PUSH", operands: "src", description: "Decrement ESP by operand size, then store src at [ESP]. Pushes value onto stack.", example: "PUSH EBP ; save frame pointer\nPUSH 0x41414141 ; push immediate", flags: "None" },
      { mnemonic: "POP", operands: "dest", description: "Load value from [ESP] into dest, then increment ESP. Pops value from stack.", example: "POP EBP ; restore frame pointer", flags: "None" },
      { mnemonic: "XCHG", operands: "op1, op2", description: "Exchange values between two operands atomically.", example: "XCHG EAX, EBX ; swap EAX and EBX", flags: "None" },
      { mnemonic: "CDQ", operands: "", description: "Convert Doubleword to Quadword. Sign-extends EAX into EDX:EAX. Used before IDIV.", example: "CDQ ; if EAX < 0, EDX = 0xFFFFFFFF, else EDX = 0", flags: "None" },
      { mnemonic: "CMOV*", operands: "dest, src", description: "Conditional move. CMOVE/CMOVZ, CMOVNE/CMOVNZ, CMOVG, CMOVL, etc. Move only if condition flag is set.", example: "CMOVZ EAX, EBX ; if ZF=1, EAX = EBX", flags: "None" },
      { mnemonic: "BSWAP", operands: "reg", description: "Byte swap — reverses byte order of 32/64-bit register. Converts between big/little endian.", example: "BSWAP EAX ; 0x12345678 -> 0x78563412", flags: "None" }
    ],
    arithmetic: [
      { mnemonic: "ADD", operands: "dest, src", description: "dest = dest + src. Sets CF on unsigned overflow, OF on signed overflow.", example: "ADD EAX, 1 ; increment EAX", flags: "CF, ZF, SF, OF, PF, AF" },
      { mnemonic: "SUB", operands: "dest, src", description: "dest = dest - src. Sets CF on unsigned borrow.", example: "SUB ESP, 0x20 ; allocate 32 bytes on stack", flags: "CF, ZF, SF, OF, PF, AF" },
      { mnemonic: "INC", operands: "dest", description: "dest = dest + 1. Does NOT affect CF (unlike ADD 1).", example: "INC ECX ; ECX++", flags: "ZF, SF, OF, PF, AF" },
      { mnemonic: "DEC", operands: "dest", description: "dest = dest - 1. Does NOT affect CF.", example: "DEC ECX ; ECX--", flags: "ZF, SF, OF, PF, AF" },
      { mnemonic: "MUL", operands: "src", description: "Unsigned multiply. EAX * src, result in EDX:EAX (32-bit) or RDX:RAX (64-bit).", example: "MUL EBX ; EDX:EAX = EAX * EBX", flags: "CF, OF" },
      { mnemonic: "IMUL", operands: "dest, src [, imm]", description: "Signed multiply. 1-operand: like MUL. 2-operand: dest *= src. 3-operand: dest = src * imm.", example: "IMUL EAX, EBX, 10 ; EAX = EBX * 10", flags: "CF, OF" },
      { mnemonic: "DIV", operands: "src", description: "Unsigned divide. EDX:EAX / src, quotient in EAX, remainder in EDX. Division by zero = #DE.", example: "XOR EDX, EDX ; clear EDX\nDIV EBX ; EAX = EDX:EAX / EBX, EDX = remainder", flags: "Undefined" },
      { mnemonic: "IDIV", operands: "src", description: "Signed divide. Use CDQ before to sign-extend EAX into EDX:EAX.", example: "CDQ\nIDIV EBX ; signed divide", flags: "Undefined" },
      { mnemonic: "NEG", operands: "dest", description: "Two's complement negation. dest = -dest (equivalent to 0 - dest).", example: "NEG EAX ; EAX = -EAX", flags: "CF, ZF, SF, OF, PF, AF" },
      { mnemonic: "ADC", operands: "dest, src", description: "Add with carry. dest = dest + src + CF. Used for multi-precision arithmetic.", example: "ADC EDX, 0 ; add carry to high dword", flags: "CF, ZF, SF, OF, PF, AF" },
      { mnemonic: "SBB", operands: "dest, src", description: "Subtract with borrow. dest = dest - src - CF. Used for multi-precision subtraction.", example: "SBB EDX, 0 ; subtract borrow from high dword", flags: "CF, ZF, SF, OF, PF, AF" }
    ],
    logic: [
      { mnemonic: "AND", operands: "dest, src", description: "Bitwise AND. Clears CF and OF. Common for masking bits.", example: "AND EAX, 0xFF ; keep only lowest byte", flags: "CF=0, OF=0, ZF, SF, PF" },
      { mnemonic: "OR", operands: "dest, src", description: "Bitwise OR. Clears CF and OF. Common for setting bits.", example: "OR EAX, 0x80000000 ; set highest bit", flags: "CF=0, OF=0, ZF, SF, PF" },
      { mnemonic: "XOR", operands: "dest, src", description: "Bitwise XOR. XOR reg, reg is the standard way to zero a register (smaller than MOV reg, 0).", example: "XOR EAX, EAX ; EAX = 0 (common idiom)", flags: "CF=0, OF=0, ZF=1, SF, PF" },
      { mnemonic: "NOT", operands: "dest", description: "Bitwise NOT (one's complement). Flips all bits.", example: "NOT EAX ; EAX = ~EAX", flags: "None" },
      { mnemonic: "SHL / SAL", operands: "dest, count", description: "Shift left (logical/arithmetic — identical). Multiply by 2^count. Low bits filled with 0.", example: "SHL EAX, 2 ; EAX *= 4", flags: "CF (last bit shifted out), ZF, SF, OF, PF" },
      { mnemonic: "SHR", operands: "dest, count", description: "Shift right (logical / unsigned). Divide by 2^count. High bits filled with 0.", example: "SHR EAX, 1 ; unsigned EAX /= 2", flags: "CF, ZF, SF, OF, PF" },
      { mnemonic: "SAR", operands: "dest, count", description: "Shift right (arithmetic / signed). Preserves sign bit. High bits filled with sign bit.", example: "SAR EAX, 1 ; signed EAX /= 2", flags: "CF, ZF, SF, OF, PF" },
      { mnemonic: "ROL", operands: "dest, count", description: "Rotate left. Bits shifted out the left re-enter on the right.", example: "ROL EAX, 8 ; rotate left by one byte", flags: "CF, OF" },
      { mnemonic: "ROR", operands: "dest, count", description: "Rotate right. Bits shifted out the right re-enter on the left.", example: "ROR EAX, 13 ; common in hash functions", flags: "CF, OF" },
      { mnemonic: "TEST", operands: "op1, op2", description: "Bitwise AND without storing result. Only sets flags. Common for checking if a value is zero.", example: "TEST EAX, EAX ; sets ZF if EAX == 0\nJZ target ; jump if EAX was zero", flags: "CF=0, OF=0, ZF, SF, PF" },
      { mnemonic: "BT", operands: "base, offset", description: "Bit Test. Copy bit at position 'offset' in 'base' to CF.", example: "BT EAX, 3 ; CF = bit 3 of EAX", flags: "CF" },
      { mnemonic: "BTS", operands: "base, offset", description: "Bit Test and Set. Copy bit to CF, then set it to 1.", example: "BTS EAX, 3 ; CF = old bit 3, bit 3 = 1", flags: "CF" },
      { mnemonic: "BSF", operands: "dest, src", description: "Bit Scan Forward. Find position of lowest set bit.", example: "BSF EAX, EBX ; EAX = index of lowest 1-bit in EBX", flags: "ZF" },
      { mnemonic: "BSR", operands: "dest, src", description: "Bit Scan Reverse. Find position of highest set bit.", example: "BSR EAX, EBX ; EAX = index of highest 1-bit in EBX", flags: "ZF" }
    ],
    controlFlow: [
      { mnemonic: "CMP", operands: "op1, op2", description: "Compare by subtracting op2 from op1 without storing result. Sets flags for conditional jumps.", example: "CMP EAX, 10\nJGE label ; jump if EAX >= 10 (signed)", flags: "CF, ZF, SF, OF, PF, AF" },
      { mnemonic: "JMP", operands: "target", description: "Unconditional jump. Direct (address), indirect (register/memory), short/near/far.", example: "JMP 0x401000 ; direct\nJMP EAX ; indirect (common in switch tables)", flags: "None" },
      { mnemonic: "JE / JZ", operands: "target", description: "Jump if Equal / Jump if Zero. ZF=1.", example: "CMP EAX, 0\nJE zero_handler", flags: "reads ZF" },
      { mnemonic: "JNE / JNZ", operands: "target", description: "Jump if Not Equal / Not Zero. ZF=0.", example: "TEST EAX, EAX\nJNZ not_null", flags: "reads ZF" },
      { mnemonic: "JG / JNLE", operands: "target", description: "Jump if Greater (signed). ZF=0 AND SF=OF.", example: "CMP EAX, EBX\nJG eax_greater", flags: "reads ZF, SF, OF" },
      { mnemonic: "JGE / JNL", operands: "target", description: "Jump if Greater or Equal (signed). SF=OF.", example: "CMP EAX, 10\nJGE at_least_ten", flags: "reads SF, OF" },
      { mnemonic: "JL / JNGE", operands: "target", description: "Jump if Less (signed). SF!=OF.", example: "CMP EAX, 0\nJL negative", flags: "reads SF, OF" },
      { mnemonic: "JLE / JNG", operands: "target", description: "Jump if Less or Equal (signed). ZF=1 OR SF!=OF.", example: "CMP EAX, EBX\nJLE eax_lte_ebx", flags: "reads ZF, SF, OF" },
      { mnemonic: "JA / JNBE", operands: "target", description: "Jump if Above (unsigned). CF=0 AND ZF=0.", example: "CMP EAX, 0xFF\nJA too_large", flags: "reads CF, ZF" },
      { mnemonic: "JAE / JNB / JNC", operands: "target", description: "Jump if Above or Equal (unsigned). CF=0.", example: "CMP EAX, EBX\nJAE eax_gte_ebx_unsigned", flags: "reads CF" },
      { mnemonic: "JB / JNAE / JC", operands: "target", description: "Jump if Below (unsigned) / Jump if Carry. CF=1.", example: "SUB EAX, EBX\nJB underflow", flags: "reads CF" },
      { mnemonic: "JBE / JNA", operands: "target", description: "Jump if Below or Equal (unsigned). CF=1 OR ZF=1.", example: "CMP EAX, 10\nJBE at_most_ten", flags: "reads CF, ZF" },
      { mnemonic: "JS", operands: "target", description: "Jump if Sign (negative). SF=1.", example: "SUB EAX, EBX\nJS result_negative", flags: "reads SF" },
      { mnemonic: "JO", operands: "target", description: "Jump if Overflow. OF=1.", example: "ADD EAX, EBX\nJO overflow_handler", flags: "reads OF" },
      { mnemonic: "CALL", operands: "target", description: "Push return address (next instruction) onto stack, then jump to target. Establishes a stack frame.", example: "CALL printf ; pushes return addr, jumps to printf", flags: "None" },
      { mnemonic: "RET", operands: "[n]", description: "Pop return address from stack into EIP and jump there. Optional n pops n extra bytes (stdcall cleanup).", example: "RET ; pop EIP, continue after CALL\nRET 8 ; pop EIP + clean 8 bytes of args (stdcall)", flags: "None" },
      { mnemonic: "LOOP", operands: "target", description: "Decrement ECX, jump to target if ECX != 0. Deprecated — compilers prefer DEC + JNZ.", example: "MOV ECX, 10\nlabel:\n  ; body\nLOOP label ; repeat 10 times", flags: "None" },
      { mnemonic: "INT", operands: "n", description: "Software interrupt. INT 3 = breakpoint (0xCC), INT 0x80 = Linux syscall (32-bit), INT 0x2E = Windows syscall (legacy).", example: "INT 3 ; debugger breakpoint\nINT 0x80 ; Linux 32-bit syscall", flags: "IF, TF" },
      { mnemonic: "SYSCALL", operands: "", description: "64-bit system call instruction (replaces INT 0x80 on x86-64). Syscall number in RAX, args in RDI, RSI, RDX, R10, R8, R9.", example: "MOV RAX, 1 ; sys_write\nMOV RDI, 1 ; stdout\nSYSCALL", flags: "RCX, R11 clobbered" },
      { mnemonic: "NOP", operands: "", description: "No Operation (0x90). Used for alignment, NOP sleds in exploits, and patching out instructions.", example: "NOP ; 1-byte NOP\nNOP DWORD [EAX] ; multi-byte NOP (66 0F 1F 00)", flags: "None" }
    ],
    string: [
      { mnemonic: "REP MOVSB/D", operands: "", description: "Repeat move string byte/dword. Copies ECX bytes/dwords from ESI to EDI. Used by memcpy.", example: "MOV ECX, 100\nREP MOVSB ; copy 100 bytes from ESI to EDI", flags: "None" },
      { mnemonic: "REP STOSB/D", operands: "", description: "Repeat store string byte/dword. Fills ECX bytes/dwords at EDI with AL/EAX. Used by memset.", example: "XOR EAX, EAX\nMOV ECX, 100\nREP STOSD ; zero 400 bytes at EDI", flags: "None" },
      { mnemonic: "REPNE SCASB", operands: "", description: "Repeat scan string until match. Scans for AL in [EDI], decrements ECX. Used by strlen.", example: "XOR AL, AL\nMOV ECX, -1\nREPNE SCASB\nNOT ECX\nDEC ECX ; ECX = strlen", flags: "ZF" },
      { mnemonic: "REP CMPSB", operands: "", description: "Repeat compare string bytes. Compares ESI vs EDI byte by byte. Used by memcmp/strcmp.", example: "MOV ECX, len\nREP CMPSB\nJE strings_equal", flags: "ZF, CF, SF, OF" }
    ]
  },

  callingConventions: [
    { name: "cdecl", platform: "x86 (C default)", description: "Arguments pushed right-to-left on stack. Caller cleans up stack. Return value in EAX. EBX, ESI, EDI, EBP are callee-saved.", example: "push arg2\npush arg1\ncall func\nadd esp, 8  ; caller cleanup" },
    { name: "stdcall", platform: "x86 (Win32 API)", description: "Arguments pushed right-to-left on stack. Callee cleans up stack (RET n). Used by all Windows API functions.", example: "push arg2\npush arg1\ncall func  ; func does RET 8" },
    { name: "fastcall", platform: "x86 (MSVC)", description: "First two integer/pointer args in ECX, EDX. Rest on stack right-to-left. Callee cleanup.", example: "mov edx, arg2\nmov ecx, arg1\ncall func" },
    { name: "thiscall", platform: "x86 (C++ MSVC)", description: "Like cdecl but 'this' pointer passed in ECX. Other args on stack right-to-left.", example: "mov ecx, this_ptr\npush arg1\ncall method" },
    { name: "System V AMD64 ABI", platform: "x86-64 (Linux/macOS)", description: "First 6 integer args: RDI, RSI, RDX, RCX, R8, R9. First 8 float args: XMM0-XMM7. Return in RAX (int) or XMM0 (float). Stack 16-byte aligned before CALL. RBX, RBP, R12-R15 callee-saved.", example: "mov rdi, arg1\nmov rsi, arg2\nmov rdx, arg3\ncall func" },
    { name: "Microsoft x64", platform: "x86-64 (Windows)", description: "First 4 integer args: RCX, RDX, R8, R9. First 4 float args: XMM0-XMM3. 32-byte shadow space required on stack. Return in RAX. RBX, RBP, RDI, RSI, R12-R15 callee-saved.", example: "sub rsp, 28h  ; shadow + alignment\nmov rcx, arg1\nmov rdx, arg2\ncall func\nadd rsp, 28h" }
  ],

  registers: {
    x86_64: [
      { name: "RAX/EAX/AX/AL", purpose: "Accumulator. Return value. Used by MUL/DIV/CDQ.", notes: "Caller-saved in both ABIs" },
      { name: "RBX/EBX/BX/BL", purpose: "Base register. General purpose.", notes: "Callee-saved in all conventions" },
      { name: "RCX/ECX/CX/CL", purpose: "Counter (LOOP, REP, shifts). Win64 1st arg. Fastcall 1st arg. Thiscall 'this'.", notes: "Clobbered by SYSCALL" },
      { name: "RDX/EDX/DX/DL", purpose: "Data. High half of multiply/divide. Win64 2nd arg. Fastcall 2nd arg.", notes: "Caller-saved" },
      { name: "RSI/ESI/SI/SIL", purpose: "Source index for string ops. SysV 2nd arg.", notes: "Callee-saved on Win64, caller-saved on SysV" },
      { name: "RDI/EDI/DI/DIL", purpose: "Destination index for string ops. SysV 1st arg.", notes: "Callee-saved on Win64, caller-saved on SysV" },
      { name: "RSP/ESP/SP", purpose: "Stack pointer. Points to top of stack.", notes: "Must be preserved across calls" },
      { name: "RBP/EBP/BP", purpose: "Base/frame pointer. Points to current stack frame.", notes: "Callee-saved. Omitted with -fomit-frame-pointer" },
      { name: "R8-R9", purpose: "Win64: 3rd-4th args. SysV: 5th-6th args.", notes: "Caller-saved" },
      { name: "R10-R11", purpose: "Scratch registers.", notes: "Caller-saved. R11 clobbered by SYSCALL" },
      { name: "R12-R15", purpose: "General purpose.", notes: "Callee-saved in both ABIs" },
      { name: "RIP/EIP", purpose: "Instruction pointer. Address of next instruction to execute.", notes: "Not directly writable (except via JMP/CALL/RET)" },
      { name: "RFLAGS/EFLAGS", purpose: "Status flags: CF, ZF, SF, OF, PF, AF, DF, IF, TF.", notes: "Modified by arithmetic/logic. Read by conditional jumps." }
    ],
    flags: [
      { flag: "CF (Carry)", bit: 0, description: "Set on unsigned overflow/underflow. Used by JB/JAE/ADC/SBB." },
      { flag: "PF (Parity)", bit: 2, description: "Set if lowest byte of result has even number of 1-bits. Rarely used in modern code." },
      { flag: "AF (Adjust)", bit: 4, description: "BCD arithmetic carry from bit 3 to bit 4. Essentially unused in modern code." },
      { flag: "ZF (Zero)", bit: 6, description: "Set if result is zero. Used by JE/JNE, TEST, CMP." },
      { flag: "SF (Sign)", bit: 7, description: "Set if result is negative (MSB = 1). Used by JS/JNS, signed comparisons." },
      { flag: "TF (Trap)", bit: 8, description: "Single-step mode. CPU generates #DB after each instruction. Used by debuggers." },
      { flag: "IF (Interrupt)", bit: 9, description: "If clear, maskable hardware interrupts are disabled. Only modifiable in ring 0." },
      { flag: "DF (Direction)", bit: 10, description: "If set, string operations go backward (decrement ESI/EDI). CLD clears, STD sets." },
      { flag: "OF (Overflow)", bit: 11, description: "Set on signed overflow. Used by JO/JNO, signed comparisons (JG/JL)." }
    ]
  },

  compilerPatterns: [
    {
      pattern: "if/else",
      c_code: "if (x > 10) { a(); } else { b(); }",
      assembly: "cmp [x], 10\njle .else\ncall a\njmp .end\n.else:\ncall b\n.end:",
      notes: "Compiler often inverts the condition (> becomes jle to else branch). The 'true' branch falls through."
    },
    {
      pattern: "for loop",
      c_code: "for (int i = 0; i < n; i++) { body(i); }",
      assembly: "xor ecx, ecx       ; i = 0\n.loop:\ncmp ecx, [n]\njge .end\npush ecx\ncall body\npop ecx\ninc ecx\njmp .loop\n.end:",
      notes: "Optimizing compilers may count down instead of up, unroll iterations, or use loop variable in a register."
    },
    {
      pattern: "while loop",
      c_code: "while (cond()) { body(); }",
      assembly: ".loop:\ncall cond\ntest eax, eax\njz .end\ncall body\njmp .loop\n.end:",
      notes: "GCC with -O2 may transform to do-while with an initial conditional jump."
    },
    {
      pattern: "switch/case (jump table)",
      c_code: "switch(x) { case 0: a(); break; case 1: b(); break; case 2: c(); break; }",
      assembly: "cmp eax, 2\nja .default\njmp [.table + eax*4]\n.table: dd .case0, .case1, .case2\n.case0: call a / jmp .end\n.case1: call b / jmp .end\n.case2: call c / jmp .end",
      notes: "Dense switch uses jump table (O(1) lookup). Sparse switch becomes if/else chain (JE comparisons)."
    },
    {
      pattern: "Function prologue (x86)",
      c_code: "void func(int a, int b) { int local; ... }",
      assembly: "push ebp\nmov ebp, esp\nsub esp, N      ; allocate locals\npush esi        ; save callee-saved regs\npush edi",
      notes: "Sets up stack frame. EBP+8 = first arg, EBP+C = second arg, EBP-4 = first local."
    },
    {
      pattern: "Function epilogue (x86)",
      c_code: "return value;",
      assembly: "mov eax, [result]  ; return value in EAX\npop edi\npop esi\nmov esp, ebp       ; or: leave\npop ebp\nret",
      notes: "LEAVE instruction = MOV ESP, EBP + POP EBP. Compiler may use either form."
    },
    {
      pattern: "Function prologue (x64 SysV)",
      c_code: "long func(long a, long b) { long local; ... }",
      assembly: "push rbp\nmov rbp, rsp\nsub rsp, N\n; args already in rdi, rsi, rdx, rcx, r8, r9",
      notes: "With -fomit-frame-pointer: no push rbp/mov rbp,rsp. Locals addressed via RSP offsets."
    },
    {
      pattern: "Struct field access",
      c_code: "struct S { int a; int b; char c; };\ns->b = 42;",
      assembly: "mov dword [eax+4], 42  ; eax = struct pointer, offset 4 = field b",
      notes: "Struct fields are at fixed offsets from the base pointer. Padding/alignment may add gaps."
    },
    {
      pattern: "Array indexing",
      c_code: "int arr[100]; x = arr[i];",
      assembly: "mov eax, [ebx + ecx*4]  ; ebx = arr base, ecx = index, *4 for int size",
      notes: "LEA is often used to compute array addresses. Scale factor reveals element size (1=byte, 2=short, 4=int, 8=long)."
    },
    {
      pattern: "Virtual function call (C++ vtable)",
      c_code: "obj->virtualMethod();",
      assembly: "mov eax, [ecx]          ; load vtable pointer from object\nmov edx, [eax + 0Ch]   ; load function pointer at vtable offset\ncall edx               ; indirect call",
      notes: "Object's first qword/dword is vtable pointer. Vtable is array of function pointers. Offset identifies which virtual function."
    },
    {
      pattern: "Multiplication by constant",
      c_code: "y = x * 3;",
      assembly: "lea eax, [ecx + ecx*2]  ; eax = ecx * 3",
      notes: "Compilers replace multiplications with LEA, shift+add combos. x*5 = LEA [reg+reg*4], x*7 = LEA [reg+reg*2] then LEA [reg+orig*4]."
    },
    {
      pattern: "Division by constant (unsigned)",
      c_code: "y = x / 10;",
      assembly: "mov eax, 0xCCCCCCCD\nmul ecx              ; EDX:EAX = x * magic\nshr edx, 3           ; EDX = x / 10",
      notes: "Compilers replace division with multiply-by-reciprocal + shift. The magic constant and shift count identify the divisor."
    }
  ],

  antiDebugging: [
    {
      technique: "IsDebuggerPresent",
      api: "kernel32!IsDebuggerPresent",
      description: "Checks the PEB.BeingDebugged flag. Returns non-zero if a user-mode debugger is attached.",
      bypass: "Patch PEB.BeingDebugged to 0, or NOP out the check. In x64dbg: set PEB.BeingDebugged = 0 in dump.",
      detection: "Trivially detected by static analysis (import or GetProcAddress call)."
    },
    {
      technique: "CheckRemoteDebuggerPresent",
      api: "kernel32!CheckRemoteDebuggerPresent",
      description: "Checks if a debugger is attached to the process (works for remote debuggers too). Calls NtQueryInformationProcess internally.",
      bypass: "Hook the API to always return FALSE, or patch NtQueryInformationProcess.",
      detection: "Check imports for CheckRemoteDebuggerPresent."
    },
    {
      technique: "NtQueryInformationProcess (DebugPort)",
      api: "ntdll!NtQueryInformationProcess",
      description: "With ProcessDebugPort (7), returns the debug port handle. Non-zero = debugger attached. More reliable than IsDebuggerPresent.",
      bypass: "Hook NtQueryInformationProcess to return 0 for class 7. ScyllaHide plugin does this automatically.",
      detection: "Look for calls with second arg = 7 or 0x1E (ProcessDebugObjectHandle) or 0x1F (ProcessDebugFlags)."
    },
    {
      technique: "Timing checks (RDTSC)",
      api: "RDTSC instruction / QueryPerformanceCounter / GetTickCount",
      description: "Measure time between two points. Debugging causes delays that exceed normal execution time.",
      bypass: "Hardware breakpoints (no INT 3 overhead), or patch the timing check threshold.",
      detection: "Look for RDTSC, QueryPerformanceCounter, GetTickCount64 pairs with comparison."
    },
    {
      technique: "Hardware breakpoint detection",
      api: "GetThreadContext / DR0-DR7",
      description: "Read debug registers via GetThreadContext. DR0-DR3 hold hardware breakpoint addresses. Non-zero = breakpoints set.",
      bypass: "Clear hardware breakpoints before the check, or hook GetThreadContext to return zeroed DR registers.",
      detection: "Look for GetThreadContext calls followed by checks on context.Dr0-Dr3."
    },
    {
      technique: "INT 3 / INT 2D scanning",
      api: "Self-scanning",
      description: "Scan own code section for 0xCC (INT 3) bytes that weren't in the original binary. Detects software breakpoints.",
      bypass: "Use hardware breakpoints instead of software breakpoints. Or patch the scanning routine.",
      detection: "Look for code that reads its own .text section and searches for 0xCC."
    },
    {
      technique: "TLS Callbacks",
      api: "PE TLS Directory",
      description: "Thread Local Storage callbacks execute before the entry point. Anti-debug checks here run before the debugger's initial breakpoint.",
      bypass: "Set breakpoint on TLS callback address (visible in PE headers). x64dbg breaks on TLS callbacks by default.",
      detection: "Check IMAGE_TLS_DIRECTORY in PE headers for AddressOfCallBacks."
    },
    {
      technique: "Self-modifying code",
      api: "VirtualProtect + runtime code modification",
      description: "Code decrypts or modifies itself at runtime. Static analysis shows encrypted/garbage instructions.",
      bypass: "Set breakpoint after decryption, then analyze the decrypted code. Dump memory after decryption.",
      detection: "Look for VirtualProtect calls changing .text to PAGE_EXECUTE_READWRITE."
    },
    {
      technique: "Exception-based control flow",
      api: "SEH / VEH",
      description: "Intentionally trigger exceptions (div by zero, access violation, INT 3). The exception handler contains the real logic. Debuggers may intercept the exception.",
      bypass: "Pass exceptions to the application (Shift+F9 in x64dbg). Configure debugger to ignore specific exceptions.",
      detection: "Look for SetUnhandledExceptionFilter, AddVectoredExceptionHandler, or SEH chain manipulation."
    },
    {
      technique: "NtSetInformationThread (ThreadHideFromDebugger)",
      api: "ntdll!NtSetInformationThread",
      description: "With ThreadHideFromDebugger (0x11), the thread becomes invisible to debuggers. Breakpoints on this thread stop working.",
      bypass: "Hook NtSetInformationThread to skip class 0x11 calls. ScyllaHide handles this.",
      detection: "Look for NtSetInformationThread with second arg = 0x11."
    }
  ],

  toolReference: {
    ghidra: [
      { shortcut: "G", action: "Go to address" },
      { shortcut: "L", action: "Rename symbol/label" },
      { shortcut: "T", action: "Retype variable/parameter" },
      { shortcut: ";", action: "Add comment (EOL)" },
      { shortcut: "Ctrl+Shift+;", action: "Add plate comment (block)" },
      { shortcut: "D", action: "Disassemble at cursor" },
      { shortcut: "F", action: "Create function at cursor" },
      { shortcut: "Ctrl+E", action: "Edit bytes" },
      { shortcut: "Ctrl+Shift+E", action: "Patch instruction" },
      { shortcut: "X / Ctrl+Shift+F", action: "Find references to" },
      { shortcut: "Space", action: "Toggle decompiler/listing view" },
      { shortcut: "Ctrl+T", action: "Define structure" },
      { shortcut: "Middle click", action: "Navigate forward/back" }
    ],
    idapro: [
      { shortcut: "G", action: "Go to address" },
      { shortcut: "N", action: "Rename" },
      { shortcut: "Y", action: "Set type" },
      { shortcut: ";", action: "Add comment" },
      { shortcut: "Ins", action: "Add anterior comment" },
      { shortcut: "P", action: "Create function" },
      { shortcut: "U", action: "Undefine" },
      { shortcut: "C", action: "Convert to code" },
      { shortcut: "D", action: "Convert to data" },
      { shortcut: "A", action: "Convert to ASCII string" },
      { shortcut: "X", action: "Cross-references to" },
      { shortcut: "Ctrl+X", action: "Cross-references from" },
      { shortcut: "F5", action: "Decompile (Hex-Rays)" },
      { shortcut: "Tab", action: "Toggle text/graph view" },
      { shortcut: "Alt+T", action: "Text search" },
      { shortcut: "Alt+B", action: "Binary search" }
    ],
    x64dbg: [
      { shortcut: "F2", action: "Toggle breakpoint" },
      { shortcut: "F7", action: "Step into" },
      { shortcut: "F8", action: "Step over" },
      { shortcut: "F9", action: "Run" },
      { shortcut: "Shift+F9", action: "Run (pass exception to app)" },
      { shortcut: "Ctrl+F9", action: "Run until return" },
      { shortcut: "Ctrl+G", action: "Go to address" },
      { shortcut: "Ctrl+B", action: "Binary search in memory" },
      { shortcut: "Ctrl+E", action: "Edit memory" },
      { shortcut: "Space", action: "Assemble instruction" },
      { shortcut: ";", action: "Add comment" },
      { shortcut: "N / Ctrl+N", action: "Label / view labels" },
      { shortcut: "Ctrl+A", action: "Analyze module" }
    ]
  },

  fileFormats: {
    pe: {
      description: "Portable Executable — Windows executables (.exe, .dll, .sys, .ocx)",
      sections: [
        { name: ".text", description: "Executable code. Usually marked as IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ. RWX = suspicious." },
        { name: ".data", description: "Initialized global/static variables. Read-write." },
        { name: ".rdata", description: "Read-only data: string literals, import/export tables, debug info, constants." },
        { name: ".bss", description: "Uninitialized data. May not exist on disk (virtual size only)." },
        { name: ".rsrc", description: "Resources: icons, dialogs, version info, embedded files. Resource hacker can browse." },
        { name: ".reloc", description: "Base relocation table. Applied when DLL loads at non-preferred address. Absence + no ASLR = fixed base." },
        { name: ".edata", description: "Export table. DLL exported function names, ordinals, addresses." },
        { name: ".idata", description: "Import table. Lists DLLs and functions the binary imports. IAT is patched at load time." },
        { name: ".tls", description: "Thread Local Storage. Contains TLS callbacks that run before main entry point." },
        { name: "UPX0/UPX1", description: "Packed by UPX. UPX0 is empty (virtual only), UPX1 contains compressed data. 'upx -d' to unpack." }
      ],
      securityFeatures: [
        { feature: "ASLR", check: "DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040)", description: "Address Space Layout Randomization. Base address randomized on each load." },
        { feature: "DEP/NX", check: "DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT (0x0100)", description: "Data Execution Prevention. Non-executable stack/heap. Prevents simple shellcode execution." },
        { feature: "CFG", check: "DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF (0x4000)", description: "Control Flow Guard. Validates indirect call targets. Blocks ROP/JOP attacks." },
        { feature: "Authenticode", check: "Security Directory in PE Optional Header", description: "Digital signature. Validates publisher identity and file integrity." },
        { feature: "SafeSEH", check: "Load Config Directory SEHandlerTable", description: "Safe Structured Exception Handling. Whitelist of valid exception handlers." },
        { feature: "High Entropy ASLR", check: "DllCharacteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA (0x0020)", description: "64-bit ASLR with full address space randomization." }
      ]
    },
    elf: {
      description: "Executable and Linkable Format — Linux/Unix executables, shared libraries, core dumps",
      sections: [
        { name: ".text", description: "Executable code. Mapped read+execute." },
        { name: ".data", description: "Initialized read-write data." },
        { name: ".rodata", description: "Read-only data: string constants, jump tables." },
        { name: ".bss", description: "Uninitialized data. Zero-filled at runtime." },
        { name: ".plt", description: "Procedure Linkage Table. Stubs for lazy dynamic linking. Each entry is a JMP to GOT." },
        { name: ".got / .got.plt", description: "Global Offset Table. Contains resolved addresses of external functions. Target of GOT overwrite attacks." },
        { name: ".dynamic", description: "Dynamic linking information. NEEDED entries list required shared libraries." },
        { name: ".symtab / .dynsym", description: "Symbol tables. Function and variable names with addresses." },
        { name: ".strtab / .dynstr", description: "String tables for symbol names." },
        { name: ".init / .fini", description: "Constructor/destructor code. .init runs before main, .fini after." },
        { name: ".init_array / .fini_array", description: "Arrays of function pointers called before/after main. Overwrite = code execution." },
        { name: ".note.gnu.build-id", description: "Unique build identifier hash." }
      ],
      securityFeatures: [
        { feature: "RELRO", check: "readelf -l binary | grep GNU_RELRO && readelf -d binary | grep BIND_NOW", description: "Partial RELRO: GOT is read-only after relocation. Full RELRO (+ BIND_NOW): entire GOT read-only, no lazy binding. Prevents GOT overwrite." },
        { feature: "NX (Stack)", check: "readelf -l binary | grep GNU_STACK", description: "If GNU_STACK has RW (no E), stack is non-executable. RWE = executable stack (very vulnerable)." },
        { feature: "PIE", check: "readelf -h binary | grep Type: should show DYN", description: "Position Independent Executable. Full ASLR for the main binary (not just libraries). Type DYN = PIE, EXEC = no PIE." },
        { feature: "Stack Canary", check: "objdump -d binary | grep __stack_chk_fail", description: "If __stack_chk_fail is referenced, stack canaries are enabled. Detects stack buffer overflows." },
        { feature: "Fortify Source", check: "objdump -d binary | grep _chk", description: "Compile-time and runtime buffer overflow checks for string/memory functions (__printf_chk, __memcpy_chk)." }
      ]
    }
  },

  cryptoIdentification: [
    { algorithm: "AES", indicator: "S-box lookup table", signature: "63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 (first 16 bytes of AES S-box)", tool: "findcrypt-ghidra, signsrch" },
    { algorithm: "AES (inverse)", indicator: "Inverse S-box", signature: "52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB", tool: "findcrypt-ghidra" },
    { algorithm: "DES", indicator: "Initial permutation table", signature: "58 50 42 34 26 18 0A 02 60 52 44 36 28 1A 0C 04", tool: "findcrypt-ghidra" },
    { algorithm: "RC4", indicator: "KSA loop pattern", signature: "256-byte state array initialization: for(i=0;i<256;i++) S[i]=i; then swap loop with key", tool: "Look for 256-iteration loop initializing sequential bytes, then a swap loop" },
    { algorithm: "MD5", indicator: "T-table constants", signature: "D76AA478 E8C7B756 242070DB C1BDCEEE (first 4 MD5 round constants)", tool: "findcrypt-ghidra" },
    { algorithm: "SHA-1", indicator: "Initial hash values", signature: "67452301 EFCDAB89 98BADCFE 10325476 C3D2E1F0", tool: "findcrypt-ghidra" },
    { algorithm: "SHA-256", indicator: "Initial hash values", signature: "6A09E667 BB67AE85 3C6EF372 A54FF53A 510E527F 9B05688C 1F83D9AB 5BE0CD19", tool: "findcrypt-ghidra" },
    { algorithm: "SHA-512", indicator: "Initial hash values (64-bit)", signature: "6A09E667F3BCC908 BB67AE8584CAA73B", tool: "findcrypt-ghidra" },
    { algorithm: "RSA", indicator: "Large integer arithmetic", signature: "Public exponent 65537 (0x10001) commonly used. Look for big number multiply/modexp.", tool: "Look for BigInteger or multi-precision arithmetic libraries" },
    { algorithm: "Base64", indicator: "Alphabet string", signature: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ (standard) or custom alphabet", tool: "strings | grep -E '[A-Za-z0-9+/]{64}'" },
    { algorithm: "CRC32", indicator: "Polynomial table", signature: "Look for 256-entry lookup table with values derived from polynomial 0xEDB88320 (reflected) or 0x04C11DB7", tool: "findcrypt-ghidra" },
    { algorithm: "Blowfish", indicator: "P-array initial values", signature: "243F6A88 85A308D3 13198A2E 03707344 (first 4 P-array values, derived from pi)", tool: "findcrypt-ghidra" },
    { algorithm: "Twofish", indicator: "MDS matrix / q-box", signature: "Look for 4x4 MDS matrix multiplication and two fixed 8x8 permutation tables (q0 and q1)", tool: "findcrypt-ghidra" },
    { algorithm: "ChaCha20", indicator: "Constant string", signature: "'expand 32-byte k' (0x61707865 3320646E 79622D32 6B206574) in initial state", tool: "strings, findcrypt-ghidra" },
    { algorithm: "XOR cipher", indicator: "Simple XOR loop", signature: "Single-byte or multi-byte XOR: data[i] ^= key[i % keylen]. Look for XOR in a loop with constant or short key.", tool: "xortool, CyberChef XOR Brute Force" }
  ]
};
