// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
// Binary & Threat Triage mini-tools: read-only parsers, decoders, formatters and
// accurate reference tables a defender uses to understand suspicious files and threat
// data the analyst already has. Everything here is decode / parse / format / lookup on
// user-supplied data. Nothing generates executable code or payloads. See _schema.md.

const S = (v) => (v == null ? "" : String(v));

// ---- bytes from a pasted hex / base64 blob ----
function b64ToU8(s) {
  let t = String(s).trim().replace(/-/g, "+").replace(/_/g, "/").replace(/\s+/g, "");
  while (t.length % 4) t += "=";
  const bin = atob(t);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
function toBytes(s, fmt, H) {
  s = S(s).trim();
  if (!s) return new Uint8Array(0);
  if (fmt === "Base64") return b64ToU8(s);
  if (fmt === "Hex") return H.fromHex(s);
  // Auto: looks like hex (after stripping 0x / \x / separators) -> hex, else base64.
  const hc = s.replace(/0x/gi, "").replace(/\\x/gi, "").replace(/[\s,;:]/g, "");
  if (/^[0-9a-fA-F]+$/.test(hc) && hc.length % 2 === 0 && hc.length) return H.fromHex(hc);
  try { return b64ToU8(s); } catch (e) { return H.fromHex(s); }
}

// ---- integer reads ----
function rU(u, off, len, le) {
  let v = 0;
  for (let i = 0; i < len; i++) { const b = u[off + (le ? i : len - 1 - i)]; if (b === undefined) return null; v += b * Math.pow(2, 8 * i); }
  return v;
}
function rUBig(u, off, len, le) {
  let v = 0n;
  for (let i = 0; i < len; i++) { const b = u[off + (le ? i : len - 1 - i)]; if (b === undefined) return null; v += BigInt(b) << BigInt(8 * i); }
  return v;
}
const hx = (n, w) => (n == null ? "?" : "0x" + Number(n).toString(16).padStart(w || 0, "0"));
const hxB = (n, w) => (n == null ? "?" : "0x" + n.toString(16).padStart(w || 0, "0"));

// ---- flexible integer parse ("0x40", "40h", "64", "DEADBEEF") ----
function pint(s) {
  s = S(s).trim().replace(/^#/, "");
  if (!s) return null;
  if (/^0x[0-9a-f]+$/i.test(s)) return parseInt(s.slice(2), 16);
  if (/^[0-9a-f]+h$/i.test(s)) return parseInt(s.slice(0, -1), 16);
  if (/^-?\d+$/.test(s)) return parseInt(s, 10);
  if (/^[0-9a-f]+$/i.test(s)) return parseInt(s, 16);
  return null;
}

const isPrintable = (b) => b === 9 || b === 10 || b === 13 || (b >= 0x20 && b <= 0x7e);
const asciiOf = (u) => { let o = ""; for (let i = 0; i < u.length; i++) o += u[i] >= 0x20 && u[i] <= 0x7e ? String.fromCharCode(u[i]) : "."; return o; };

// decode a list of [bitValue, name] flags set in val
function decodeFlags(map, val) {
  const set = [], extra = [];
  let covered = 0;
  for (const [bit, name] of map) if ((val & bit) === bit && bit !== 0) { set.push(name + " (" + hx(bit) + ")"); covered |= bit; }
  const unknown = (val & ~covered) >>> 0;
  if (unknown) extra.push("unrecognised bits: " + hx(unknown));
  return { set, extra };
}
function renderTable(rows, filter) {
  const f = S(filter).trim().toLowerCase();
  const hits = f ? rows.filter((r) => r.join(" ").toLowerCase().includes(f)) : rows;
  if (!hits.length) return { error: "No match for \"" + filter + "\"." };
  return hits.map((r) => r.join("  |  ")).join("\n");
}

// ---------------- reference data (only entries verified correct) ----------------
const PE_MACHINE = { 0x0: "UNKNOWN", 0x14c: "I386 (x86)", 0x166: "R4000 (MIPS LE)", 0x1c0: "ARM", 0x1c2: "THUMB", 0x1c4: "ARMNT (ARM Thumb-2)", 0x200: "IA64 (Itanium)", 0x5032: "RISCV32", 0x5064: "RISCV64", 0x5128: "RISCV128", 0x8664: "AMD64 (x64)", 0xaa64: "ARM64 (AArch64)", 0xebc: "EFI byte code" };
const PE_CHARS = [[0x0001, "RELOCS_STRIPPED"], [0x0002, "EXECUTABLE_IMAGE"], [0x0004, "LINE_NUMS_STRIPPED"], [0x0008, "LOCAL_SYMS_STRIPPED"], [0x0010, "AGGRESSIVE_WS_TRIM"], [0x0020, "LARGE_ADDRESS_AWARE"], [0x0080, "BYTES_REVERSED_LO"], [0x0100, "32BIT_MACHINE"], [0x0200, "DEBUG_STRIPPED"], [0x0400, "REMOVABLE_RUN_FROM_SWAP"], [0x0800, "NET_RUN_FROM_SWAP"], [0x1000, "SYSTEM"], [0x2000, "DLL"], [0x4000, "UP_SYSTEM_ONLY"], [0x8000, "BYTES_REVERSED_HI"]];
const PE_SUBSYS = { 0: "UNKNOWN", 1: "NATIVE (driver / native)", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI (console)", 5: "OS2_CUI", 7: "POSIX_CUI", 8: "NATIVE_WINDOWS", 9: "WINDOWS_CE_GUI", 10: "EFI_APPLICATION", 11: "EFI_BOOT_SERVICE_DRIVER", 12: "EFI_RUNTIME_DRIVER", 13: "EFI_ROM", 14: "XBOX", 16: "WINDOWS_BOOT_APPLICATION" };
const PE_DLLCHARS = [[0x0020, "HIGH_ENTROPY_VA (64-bit ASLR)"], [0x0040, "DYNAMIC_BASE (ASLR)"], [0x0080, "FORCE_INTEGRITY"], [0x0100, "NX_COMPAT (DEP)"], [0x0200, "NO_ISOLATION"], [0x0400, "NO_SEH"], [0x0800, "NO_BIND"], [0x1000, "APPCONTAINER"], [0x2000, "WDM_DRIVER"], [0x4000, "GUARD_CF (Control Flow Guard)"], [0x8000, "TERMINAL_SERVER_AWARE"]];
const PE_SCN = [[0x00000020, "CNT_CODE"], [0x00000040, "CNT_INITIALIZED_DATA"], [0x00000080, "CNT_UNINITIALIZED_DATA"], [0x02000000, "MEM_DISCARDABLE"], [0x04000000, "MEM_NOT_CACHED"], [0x08000000, "MEM_NOT_PAGED"], [0x10000000, "MEM_SHARED"], [0x20000000, "MEM_EXECUTE"], [0x40000000, "MEM_READ"], [0x80000000, "MEM_WRITE"]];
const PE_DATADIR = ["Export Table", "Import Table", "Resource Table", "Exception Table", "Certificate Table (Security)", "Base Relocation Table", "Debug", "Architecture", "Global Ptr", "TLS Table", "Load Config Table", "Bound Import", "IAT (Import Address Table)", "Delay Import Descriptor", "CLR Runtime Header (.NET)", "Reserved (must be zero)"];
const ELF_TYPE = { 0: "ET_NONE", 1: "ET_REL (relocatable / object)", 2: "ET_EXEC (executable)", 3: "ET_DYN (shared object / PIE)", 4: "ET_CORE (core dump)" };
const ELF_MACHINE = { 0: "None", 2: "SPARC", 3: "x86 (Intel 80386)", 8: "MIPS", 20: "PowerPC", 21: "PowerPC 64", 22: "IBM S/390", 40: "ARM", 42: "SuperH", 43: "SPARC v9 (64-bit)", 50: "IA-64 (Itanium)", 62: "x86-64 (AMD64)", 183: "AArch64 (ARM64)", 243: "RISC-V", 258: "LoongArch" };
const ELF_OSABI = { 0: "System V (UNIX)", 1: "HP-UX", 2: "NetBSD", 3: "Linux", 6: "Solaris", 7: "AIX", 8: "IRIX", 9: "FreeBSD", 12: "OpenBSD", 64: "ARM EABI", 97: "ARM", 255: "Standalone (embedded)" };
const ELF_SHT = { 0: "SHT_NULL", 1: "SHT_PROGBITS", 2: "SHT_SYMTAB", 3: "SHT_STRTAB", 4: "SHT_RELA", 5: "SHT_HASH", 6: "SHT_DYNAMIC", 7: "SHT_NOTE", 8: "SHT_NOBITS (.bss)", 9: "SHT_REL", 10: "SHT_SHLIB", 11: "SHT_DYNSYM", 14: "SHT_INIT_ARRAY", 15: "SHT_FINI_ARRAY", 16: "SHT_PREINIT_ARRAY", 17: "SHT_GROUP", 18: "SHT_SYMTAB_SHNDX" };
const MACHO_CPU = { 7: "x86 (i386)", 0x01000007: "x86_64", 12: "ARM", 0x0100000c: "ARM64", 18: "PowerPC", 0x01000012: "PowerPC64" };
const MACHO_FT = { 1: "MH_OBJECT (.o)", 2: "MH_EXECUTE", 3: "MH_FVMLIB", 4: "MH_CORE", 5: "MH_PRELOAD", 6: "MH_DYLIB (.dylib)", 7: "MH_DYLINKER", 8: "MH_BUNDLE", 9: "MH_DYLIB_STUB", 10: "MH_DSYM", 11: "MH_KEXT_BUNDLE" };
// File magic signatures: [hex prefix, description]. Longest match wins.
const MAGICS = [
  ["89504e470d0a1a0a", "PNG image"], ["474946383761", "GIF image (87a)"], ["474946383961", "GIF image (89a)"],
  ["ffd8ff", "JPEG image"], ["424d", "BMP image"], ["49492a00", "TIFF image (little-endian)"], ["4d4d002a", "TIFF image (big-endian)"],
  ["25504446", "PDF document"], ["7b5c727466", "RTF document"], ["d0cf11e0a1b11ae1", "MS Office legacy / OLE Compound File (doc/xls/ppt/msi)"],
  ["504b0304", "ZIP archive (also jar/apk/docx/xlsx/odf)"], ["504b0506", "ZIP archive (empty)"], ["504b0708", "ZIP archive (spanned)"],
  ["1f8b", "gzip compressed"], ["425a68", "bzip2 compressed"], ["377abcaf271c", "7-Zip archive"], ["526172211a0700", "RAR archive (v1.5+)"], ["526172211a070100", "RAR archive (v5)"],
  ["28b52ffd", "Zstandard compressed"], ["04224d18", "LZ4 frame"], ["fd377a585a00", "XZ compressed"],
  ["4d534346", "Microsoft Cabinet (CAB)"], ["213c617263683e", "ar archive / Debian .deb / static lib"], ["edabeedb", "RPM package"],
  ["4d5a", "DOS/PE executable (MZ)"], ["7f454c46", "ELF executable"], ["feedface", "Mach-O 32-bit"], ["feedfacf", "Mach-O 64-bit"],
  ["cefaedfe", "Mach-O 32-bit (byte-swapped)"], ["cffaedfe", "Mach-O 64-bit (byte-swapped)"], ["cafebabe", "Java class file OR Mach-O universal (fat) binary"],
  ["0061736d", "WebAssembly module (wasm)"], ["664c6143", "FLAC audio"], ["4f676753", "Ogg media"], ["494433", "MP3 with ID3 tag"],
  ["52494646", "RIFF container (WAV/AVI/WEBP)"], ["1a45dfa3", "Matroska / WebM (EBML)"], ["000001ba", "MPEG program stream"],
  ["3c3f786d6c", "XML document"], ["3c21444f43", "HTML document (<!DOC)"], ["2321", "Script with shebang (#!)"],
];
// Windows API reference: [name, dll, plain-language purpose / why analysts flag it]
const WINAPI = [
  ["VirtualAlloc", "kernel32", "Reserve/commit memory in the current process. Flagged when paired with RWX protection to stage shellcode."],
  ["VirtualAllocEx", "kernel32", "Allocate memory inside ANOTHER process. Classic first step of remote code injection."],
  ["VirtualProtect", "kernel32", "Change the protection of a memory region, e.g. make data pages executable. Flagged for unpacking/self-modifying code."],
  ["WriteProcessMemory", "kernel32", "Write bytes into another process's memory. Used to deliver injected code."],
  ["ReadProcessMemory", "kernel32", "Read another process's memory. Used for credential theft and inspection."],
  ["CreateRemoteThread", "kernel32", "Start a thread in another process. Classic way to execute injected code."],
  ["NtCreateThreadEx", "ntdll", "Low-level remote thread creation, often used to evade CreateRemoteThread hooks."],
  ["OpenProcess", "kernel32", "Get a handle to another process by PID; prerequisite for injection and memory access."],
  ["CreateProcess", "kernel32", "Launch a new program. Suspicious when spawning cmd/powershell or using suspended-process tricks."],
  ["ShellExecute", "shell32", "Run a file, document or URL via the shell. Used to launch payloads or open lures."],
  ["WinExec", "kernel32", "Legacy call to run a command line. Simple execution primitive in older malware."],
  ["LoadLibrary", "kernel32", "Load a DLL at runtime. Used for dynamic API resolution and DLL-based payloads."],
  ["GetProcAddress", "kernel32", "Resolve a function's address by name/ordinal. Hallmark of dynamic API resolution to hide imports."],
  ["GetModuleHandle", "kernel32", "Get a handle to an already-loaded module; often precedes GetProcAddress."],
  ["LdrLoadDll", "ntdll", "Low-level DLL load used to bypass LoadLibrary monitoring."],
  ["SetWindowsHookEx", "user32", "Install a system or thread hook. Used for keylogging and DLL injection into other processes."],
  ["GetAsyncKeyState", "user32", "Read whether a key is pressed. Common keylogger building block."],
  ["RegSetValueEx", "advapi32", "Write a registry value. Used for persistence (Run keys) and storing config."],
  ["RegCreateKeyEx", "advapi32", "Create/open a registry key for writing; persistence and configuration."],
  ["RegOpenKeyEx", "advapi32", "Open a registry key; recon of config/autorun locations."],
  ["RegQueryValueEx", "advapi32", "Read a registry value; config and environment checks."],
  ["CreateServiceW", "advapi32", "Install a Windows service. Persistence and running with SYSTEM privileges."],
  ["StartServiceW", "advapi32", "Start a service; execution/persistence."],
  ["OpenSCManagerW", "advapi32", "Open the service control manager; prerequisite for service install."],
  ["CreateMutex", "kernel32", "Create a named mutex. Malware often uses a fixed mutex name as an infection marker."],
  ["InternetOpenUrlA", "wininet", "Open an HTTP/FTP URL (WinINet). Used to download payloads or reach C2."],
  ["InternetReadFile", "wininet", "Read data from a WinINet handle; download / C2 receive."],
  ["URLDownloadToFile", "urlmon", "Download a URL straight to disk. Very common dropper primitive."],
  ["WinHttpSendRequest", "winhttp", "Send an HTTP request via WinHTTP; download / C2."],
  ["connect", "ws2_32", "Open a TCP/IP connection (Winsock). Network/C2 activity."],
  ["send", "ws2_32", "Send bytes over a socket; C2/exfiltration."],
  ["recv", "ws2_32", "Receive bytes over a socket; C2 command receive."],
  ["CryptEncrypt", "advapi32", "Encrypt data with CryptoAPI. Flagged in ransomware and C2 config encryption."],
  ["CryptDecrypt", "advapi32", "Decrypt data with CryptoAPI; unpacking encrypted config/payloads."],
  ["IsDebuggerPresent", "kernel32", "Check for an attached debugger. Anti-analysis / anti-debug."],
  ["CheckRemoteDebuggerPresent", "kernel32", "Check if a debugger is attached via a kernel query; anti-debug."],
  ["NtQueryInformationProcess", "ntdll", "Query process info (e.g. ProcessDebugPort). Used for anti-debug checks."],
  ["GetTickCount", "kernel32", "Millisecond uptime counter. Used in timing-based sandbox evasion."],
  ["Sleep", "kernel32", "Delay execution. Long sleeps are used to outlast sandbox analysis."],
  ["CreateToolhelp32Snapshot", "kernel32", "Snapshot running processes/modules. Used to enumerate or find security tools."],
  ["Process32Next", "kernel32", "Iterate processes from a snapshot; process discovery."],
  ["GetThreadContext", "kernel32", "Read a thread's registers. Used in process hollowing."],
  ["SetThreadContext", "kernel32", "Set a thread's registers (e.g. redirect entry point). Core of process hollowing."],
  ["ResumeThread", "kernel32", "Resume a suspended thread; completes hollowing/injection."],
  ["NtUnmapViewOfSection", "ntdll", "Unmap a memory section. Used to carve out a victim image in process hollowing."],
  ["QueueUserAPC", "kernel32", "Queue an asynchronous procedure call to a thread; APC-based code injection."],
  ["AdjustTokenPrivileges", "advapi32", "Enable/disable token privileges such as SeDebugPrivilege; privilege escalation."],
  ["OpenProcessToken", "advapi32", "Get a process's access token; token manipulation / privilege checks."],
  ["MapViewOfFile", "kernel32", "Map a file/section into memory; shared memory and some injection techniques."],
  ["CreateFileMappingW", "kernel32", "Create a file mapping object; shared memory / injection."],
];
const SYSCALLS_X64 = { 0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat", 6: "lstat", 7: "poll", 8: "lseek", 9: "mmap", 10: "mprotect", 11: "munmap", 12: "brk", 13: "rt_sigaction", 14: "rt_sigprocmask", 16: "ioctl", 21: "access", 22: "pipe", 23: "select", 32: "dup", 33: "dup2", 35: "nanosleep", 39: "getpid", 41: "socket", 42: "connect", 43: "accept", 44: "sendto", 45: "recvfrom", 46: "sendmsg", 47: "recvmsg", 49: "bind", 50: "listen", 51: "getsockname", 54: "setsockopt", 55: "getsockopt", 56: "clone", 57: "fork", 58: "vfork", 59: "execve", 60: "exit", 61: "wait4", 62: "kill", 63: "uname", 72: "fcntl", 78: "getdents", 79: "getcwd", 80: "chdir", 82: "rename", 83: "mkdir", 84: "rmdir", 85: "creat", 86: "link", 87: "unlink", 88: "symlink", 89: "readlink", 90: "chmod", 92: "chown", 101: "ptrace", 102: "getuid", 104: "getgid", 105: "setuid", 106: "setgid", 107: "geteuid", 108: "getegid", 157: "prctl", 158: "arch_prctl", 165: "mount", 169: "reboot", 186: "gettid", 202: "futex", 231: "exit_group", 257: "openat", 263: "unlinkat", 293: "pipe2", 302: "prlimit64", 318: "getrandom", 322: "execveat" };
const SYSCALL_ABI = [
  ["x86_64 (Linux)", "number in RAX; args RDI, RSI, RDX, R10, R8, R9; instruction: syscall; return in RAX"],
  ["x86 / i386 (Linux)", "number in EAX; args EBX, ECX, EDX, ESI, EDI, EBP; instruction: int 0x80; return in EAX"],
  ["ARM / EABI (Linux)", "number in r7; args r0-r6; instruction: svc #0; return in r0"],
  ["AArch64 / ARM64 (Linux)", "number in x8; args x0-x5; instruction: svc #0; return in x0"],
];
const X86_MNEM = [
  ["mov", "Copy a value between registers/memory/immediate."], ["lea", "Load effective address (compute an address without dereferencing)."],
  ["push", "Push a value onto the stack (decrements the stack pointer)."], ["pop", "Pop a value off the stack."],
  ["call", "Push the return address and jump to a subroutine."], ["ret", "Return from a subroutine (pop the return address)."],
  ["jmp", "Unconditional jump."], ["je", "Jump if equal / zero flag set."], ["jne", "Jump if not equal / zero flag clear."],
  ["jz", "Jump if zero flag set."], ["jnz", "Jump if zero flag clear."], ["jg", "Jump if greater (signed)."], ["jl", "Jump if less (signed)."],
  ["ja", "Jump if above (unsigned)."], ["jb", "Jump if below (unsigned)."],
  ["add", "Integer addition."], ["sub", "Integer subtraction."], ["inc", "Increment by one."], ["dec", "Decrement by one."],
  ["imul", "Signed multiply."], ["mul", "Unsigned multiply."], ["idiv", "Signed divide."], ["div", "Unsigned divide."],
  ["and", "Bitwise AND."], ["or", "Bitwise OR."], ["xor", "Bitwise XOR (xor reg,reg zeroes a register)."], ["not", "Bitwise NOT."],
  ["shl", "Shift left (logical)."], ["shr", "Shift right (logical)."], ["sar", "Shift right (arithmetic, keeps sign)."], ["rol", "Rotate left."], ["ror", "Rotate right."],
  ["cmp", "Compare two values (sets flags, like sub but discards result)."], ["test", "Bitwise AND that only sets flags."],
  ["nop", "No operation (used for padding/alignment)."], ["int3", "Breakpoint interrupt (0xCC), often a software breakpoint."], ["int", "Software interrupt (e.g. int 0x80 legacy Linux syscall)."],
  ["syscall", "Fast system call entry on x86-64."], ["sysenter", "Fast system call entry (older x86)."],
  ["leave", "Tear down a stack frame (mov rsp,rbp; pop rbp)."], ["enter", "Set up a stack frame."],
  ["loop", "Decrement RCX and jump if not zero."], ["cdq", "Sign-extend EAX into EDX:EAX."], ["movzx", "Move with zero-extension."], ["movsx", "Move with sign-extension."],
  ["hlt", "Halt the processor."], ["cpuid", "Query CPU identification/features (used in anti-VM checks)."], ["rdtsc", "Read the timestamp counter (used in timing/anti-analysis checks)."],
];
const X86_OPCODES = [
  ["90", "NOP - no operation"], ["CC", "INT3 - breakpoint"], ["C3", "RET - near return"], ["C2 iw", "RET imm16 - near return and pop"],
  ["CB", "RETF - far return"], ["E8 cd", "CALL rel32 - call near, relative"], ["E9 cd", "JMP rel32 - jump near, relative"], ["EB cb", "JMP rel8 - jump short"],
  ["CD ib", "INT imm8 - software interrupt (CD 80 = int 0x80)"], ["0F 05", "SYSCALL"], ["0F 34", "SYSENTER"], ["F4", "HLT"],
  ["FA", "CLI - clear interrupt flag"], ["FB", "STI - set interrupt flag"], ["C9", "LEAVE"], ["CF", "IRET - interrupt return"],
  ["50+r", "PUSH r (50-57)"], ["58+r", "POP r (58-5F)"], ["68 id", "PUSH imm32"], ["6A ib", "PUSH imm8"],
  ["9C", "PUSHF/PUSHFD/PUSHFQ"], ["9D", "POPF/POPFD/POPFQ"], ["F3", "REP / REPE prefix"], ["F2", "REPNE prefix"],
  ["66", "operand-size override prefix"], ["67", "address-size override prefix"], ["F0", "LOCK prefix"],
];
const EFLAGS = [[0x0001, "CF - Carry"], [0x0004, "PF - Parity"], [0x0010, "AF - Auxiliary Carry"], [0x0040, "ZF - Zero"], [0x0080, "SF - Sign"], [0x0100, "TF - Trap (single-step)"], [0x0200, "IF - Interrupt Enable"], [0x0400, "DF - Direction"], [0x0800, "OF - Overflow"]];
const X86_REGS = `64-bit | 32-bit | 16-bit | 8-bit low | typical role
RAX | EAX | AX | AL | return value / accumulator
RBX | EBX | BX | BL | callee-saved base register
RCX | ECX | CX | CL | counter; 1st arg (MS x64)
RDX | EDX | DX | DL | 2nd arg; I/O
RSI | ESI | SI | SIL | source index (string ops); arg (SysV)
RDI | EDI | DI | DIL | destination index; 1st arg (SysV)
RBP | EBP | BP | BPL | frame/base pointer
RSP | ESP | SP | SPL | stack pointer
R8  | R8D | R8W | R8B | argument register
R9  | R9D | R9W | R9B | argument register
R10-R15 | R10D.. | R10W.. | R10B.. | general purpose (R12-R15 callee-saved)
RIP | EIP | - | - | instruction pointer
RFLAGS | EFLAGS | FLAGS | - | status/condition flags`;
const ABI = [
  ["System V AMD64 (Linux/macOS)", "int/ptr args: RDI, RSI, RDX, RCX, R8, R9; return RAX (RDX:RAX for 128-bit); callee-saved RBX, RBP, R12-R15; stack 16-byte aligned at call."],
  ["Microsoft x64 (Windows)", "int/ptr args: RCX, RDX, R8, R9 (rest on stack); return RAX; caller provides 32-byte shadow space; callee-saved RBX, RBP, RDI, RSI, R12-R15."],
  ["cdecl (x86)", "args pushed right-to-left on the stack; CALLER cleans the stack; return in EAX."],
  ["stdcall (x86, Win32 API)", "args pushed right-to-left; CALLEE cleans the stack (ret N); return in EAX."],
  ["fastcall (Microsoft x86)", "first two int args in ECX, EDX; the rest on the stack; return in EAX."],
  ["thiscall (MSVC x86)", "the 'this' pointer is passed in ECX; other args on the stack."],
];
const MEMPROT = { 0x01: "PAGE_NOACCESS", 0x02: "PAGE_READONLY", 0x04: "PAGE_READWRITE", 0x08: "PAGE_WRITECOPY", 0x10: "PAGE_EXECUTE", 0x20: "PAGE_EXECUTE_READ", 0x40: "PAGE_EXECUTE_READWRITE", 0x80: "PAGE_EXECUTE_WRITECOPY" };
const MEMPROT_MOD = [[0x100, "PAGE_GUARD"], [0x200, "PAGE_NOCACHE"], [0x400, "PAGE_WRITECOMBINE"]];
const LOLBAS = [
  ["certutil.exe", "Certificate utility. Abused to download files (-urlcache -f) and to base64-decode payloads (-decode)."],
  ["mshta.exe", "Runs HTA/JScript/VBScript. Abused to execute remote scripts (mshta http://...)."],
  ["rundll32.exe", "Runs an exported DLL function. Abused to execute DLLs and JavaScript."],
  ["regsvr32.exe", "Registers DLLs. Abused for the 'Squiblydoo' remote scriptlet technique (/i:URL scrobj.dll)."],
  ["bitsadmin.exe", "Background Intelligent Transfer Service tool. Abused to download files and run commands."],
  ["powershell.exe", "PowerShell. Abused for fileless execution and encoded commands (-enc)."],
  ["wmic.exe", "WMI command line. Abused for process execution and reconnaissance."],
  ["cscript.exe", "Windows Script Host (console). Runs VBScript/JScript."],
  ["wscript.exe", "Windows Script Host (windowed). Runs VBScript/JScript."],
  ["msiexec.exe", "Windows Installer. Can install local or remote MSI packages."],
  ["installutil.exe", "The .NET installer utility. Abused to run assemblies and bypass application allowlists."],
  ["regasm.exe", "Registers .NET assemblies. Abused for code execution."],
  ["regsvcs.exe", "Registers .NET COM+ services. Abused for code execution."],
  ["msbuild.exe", "The build engine. Abused to compile and run inline C# tasks from a project file."],
  ["mavinject.exe", "Injects a DLL into a running process."],
  ["schtasks.exe", "Manages scheduled tasks. Used for persistence."],
  ["sc.exe", "Service control. Used to create/start services for persistence."],
  ["forfiles.exe", "Selects files and can execute a command per file."],
  ["odbcconf.exe", "ODBC configuration. Can load a DLL via its REGSVR action."],
];
const REG_AUTORUN = [
  ["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "Programs run at machine logon (all users)."],
  ["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "Run once at next logon, then deleted."],
  ["HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "Programs run at the current user's logon."],
  ["HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "Run once for the current user, then deleted."],
  ["HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "32-bit Run key on 64-bit Windows."],
  ["HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit", "Userinit executables at logon; a classic persistence hijack."],
  ["HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell", "The logon shell; hijacked to append a payload."],
  ["HKLM\\SYSTEM\\CurrentControlSet\\Services", "Service definitions; auto-start services are a common persistence point."],
  ["HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", "Debugger values here hijack execution of a named program (IFEO)."],
  ["HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs", "DLLs loaded into most GUI processes (legacy, often disabled by Secure Boot)."],
];
const ATTACK = [
  ["T1059", "Command and Scripting Interpreter", "Execution"], ["T1059.001", "PowerShell", "Execution"], ["T1059.003", "Windows Command Shell", "Execution"], ["T1059.005", "Visual Basic", "Execution"], ["T1059.006", "Python", "Execution"],
  ["T1055", "Process Injection", "Defense Evasion / Privilege Escalation"], ["T1053", "Scheduled Task/Job", "Execution / Persistence"], ["T1053.005", "Scheduled Task", "Persistence"],
  ["T1547", "Boot or Logon Autostart Execution", "Persistence"], ["T1547.001", "Registry Run Keys / Startup Folder", "Persistence"],
  ["T1543", "Create or Modify System Process", "Persistence"], ["T1543.003", "Windows Service", "Persistence"], ["T1569", "System Services", "Execution"], ["T1569.002", "Service Execution", "Execution"],
  ["T1027", "Obfuscated Files or Information", "Defense Evasion"], ["T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion"],
  ["T1105", "Ingress Tool Transfer", "Command and Control"], ["T1071", "Application Layer Protocol", "Command and Control"], ["T1071.001", "Web Protocols", "Command and Control"],
  ["T1041", "Exfiltration Over C2 Channel", "Exfiltration"], ["T1573", "Encrypted Channel", "Command and Control"], ["T1090", "Proxy", "Command and Control"], ["T1095", "Non-Application Layer Protocol", "Command and Control"],
  ["T1486", "Data Encrypted for Impact", "Impact"], ["T1490", "Inhibit System Recovery", "Impact"],
  ["T1082", "System Information Discovery", "Discovery"], ["T1083", "File and Directory Discovery", "Discovery"], ["T1057", "Process Discovery", "Discovery"], ["T1016", "System Network Configuration Discovery", "Discovery"], ["T1033", "System Owner/User Discovery", "Discovery"],
  ["T1003", "OS Credential Dumping", "Credential Access"], ["T1003.001", "LSASS Memory", "Credential Access"], ["T1555", "Credentials from Password Stores", "Credential Access"],
  ["T1056", "Input Capture", "Collection / Credential Access"], ["T1056.001", "Keylogging", "Collection"], ["T1113", "Screen Capture", "Collection"], ["T1005", "Data from Local System", "Collection"],
  ["T1112", "Modify Registry", "Defense Evasion"], ["T1070", "Indicator Removal", "Defense Evasion"], ["T1070.004", "File Deletion", "Defense Evasion"],
  ["T1562", "Impair Defenses", "Defense Evasion"], ["T1562.001", "Disable or Modify Tools", "Defense Evasion"],
  ["T1218", "System Binary Proxy Execution", "Defense Evasion"], ["T1218.005", "Mshta", "Defense Evasion"], ["T1218.010", "Regsvr32", "Defense Evasion"], ["T1218.011", "Rundll32", "Defense Evasion"],
  ["T1036", "Masquerading", "Defense Evasion"], ["T1497", "Virtualization/Sandbox Evasion", "Defense Evasion"], ["T1620", "Reflective Code Loading", "Defense Evasion"],
  ["T1134", "Access Token Manipulation", "Defense Evasion / Privilege Escalation"], ["T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation"], ["T1548.002", "Bypass User Account Control", "Privilege Escalation"],
  ["T1021", "Remote Services", "Lateral Movement"], ["T1021.001", "Remote Desktop Protocol", "Lateral Movement"], ["T1570", "Lateral Tool Transfer", "Lateral Movement"],
  ["T1047", "Windows Management Instrumentation", "Execution"], ["T1204", "User Execution", "Execution"], ["T1204.002", "Malicious File", "Execution"],
  ["T1566", "Phishing", "Initial Access"], ["T1566.001", "Spearphishing Attachment", "Initial Access"], ["T1190", "Exploit Public-Facing Application", "Initial Access"],
];
const TACTICS = [
  ["TA0043", "Reconnaissance"], ["TA0042", "Resource Development"], ["TA0001", "Initial Access"], ["TA0002", "Execution"], ["TA0003", "Persistence"], ["TA0004", "Privilege Escalation"], ["TA0005", "Defense Evasion"], ["TA0006", "Credential Access"], ["TA0007", "Discovery"], ["TA0008", "Lateral Movement"], ["TA0009", "Collection"], ["TA0011", "Command and Control"], ["TA0010", "Exfiltration"], ["TA0040", "Impact"],
];
const KILLCHAIN = [["1", "Reconnaissance", "Research and select targets."], ["2", "Weaponization", "Pair an exploit with a deliverable payload."], ["3", "Delivery", "Transmit the weapon to the target (email, web, USB)."], ["4", "Exploitation", "Trigger the exploit on the target."], ["5", "Installation", "Install malware / a backdoor for persistence."], ["6", "Command & Control (C2)", "Establish a channel for remote control."], ["7", "Actions on Objectives", "Achieve the goal (exfiltration, destruction)."]];
const DIAMOND = [["Adversary", "The actor conducting the intrusion."], ["Capability", "The tools and techniques used (malware, exploits)."], ["Infrastructure", "The physical/logical resources used (C2 servers, domains)."], ["Victim", "The target of the activity (people, assets, networks)."]];
const PYRAMID = [["1 - Hash Values", "Trivial for attackers to change."], ["2 - IP Addresses", "Easy to change."], ["3 - Domain Names", "Simple to change (but costs a little)."], ["4 - Network/Host Artifacts", "Annoying for the attacker to change."], ["5 - Tools", "Challenging to replace."], ["6 - TTPs", "Tough - changing behaviour is hardest of all."]];
const TLP = [["TLP:RED", "Not for disclosure; restricted to those explicitly named in the exchange."], ["TLP:AMBER", "Limited disclosure; share only within your organization and its clients on a need-to-know basis."], ["TLP:AMBER+STRICT", "Limited disclosure; restricted to your organization only."], ["TLP:GREEN", "Limited disclosure; share within your community/sector but not publicly."], ["TLP:CLEAR", "Disclosure is not limited; information may be shared freely (formerly TLP:WHITE)."]];
const WIN_DLLS = [
  ["kernel32.dll", "Core Win32: memory, files, processes, threads, loading libraries."], ["ntdll.dll", "Low-level NT syscall stubs and the loader (Nt*/Zw*/Ldr*)."],
  ["user32.dll", "Windows, messages, input, hooks (UI layer)."], ["gdi32.dll", "Graphics Device Interface (drawing)."],
  ["advapi32.dll", "Registry, services, security tokens/privileges, legacy CryptoAPI."], ["ws2_32.dll", "Winsock 2 TCP/IP sockets."],
  ["wininet.dll", "High-level HTTP/FTP client (WinINet)."], ["winhttp.dll", "HTTP client for services (WinHTTP)."],
  ["shell32.dll", "Shell operations such as ShellExecute."], ["ole32.dll", "COM/OLE core."], ["oleaut32.dll", "OLE automation (BSTR, VARIANT)."],
  ["crypt32.dll", "Certificates and cryptographic message handling (CryptoAPI)."], ["bcrypt.dll", "Cryptography Next Generation (CNG) primitives."],
  ["secur32.dll", "Security Support Provider Interface (SSPI) authentication."], ["netapi32.dll", "Networking/SMB management APIs."],
  ["psapi.dll", "Process Status API (enumerate processes/modules)."], ["dbghelp.dll", "Debugging/symbol helper (minidumps, stack walks)."],
  ["iphlpapi.dll", "IP Helper (adapters, ARP, routing tables)."], ["wtsapi32.dll", "Remote Desktop/Terminal Services sessions."], ["userenv.dll", "User profiles and environment."],
];
const PACKERS = [
  ["UPX0 / UPX1 / UPX2", "UPX (Ultimate Packer for eXecutables)."], [".aspack / .adata", "ASPack."], [".petite", "Petite."],
  [".MPRESS1 / .MPRESS2", "MPRESS."], [".nsp0 / .nsp1 / .nsp2", "NsPack."], [".vmp0 / .vmp1", "VMProtect."],
];



export const TOOLS = [
  // ---------------- PE (Windows) ----------------
  { id: "bi-pe-header", name: "PE Header Inspector", cat: "bininspect", desc: "Decode a pasted PE/EXE/DLL's first bytes: DOS header, PE signature, COFF header (machine, sections, timestamp) and the section table.", tags: ["pe", "exe", "dll", "coff", "portable executable", "header"],
    inputs: [{ k: "data", label: "File bytes (hex or base64)", type: "textarea", rows: 6, placeholder: "4D5A90000300..." }, { k: "fmt", label: "Input format", type: "select", opts: ["Auto", "Hex", "Base64"], value: "Auto" }],
    run(v, H) {
      const u = toBytes(v.data, v.fmt, H);
      if (!u.length) return "";
      if (u[0] !== 0x4d || u[1] !== 0x5a) return { error: "No MZ signature (0x4D 0x5A) at offset 0 - not a DOS/PE file." };
      const e = rU(u, 0x3c, 4, true);
      if (e == null) return { error: "File too short to read e_lfanew at 0x3C (paste more bytes)." };
      const L = ["DOS header: MZ signature OK", "e_lfanew (PE header offset): " + hx(e, 8) + " (" + e + ")"];
      if (u[e] !== 0x50 || u[e + 1] !== 0x45 || u[e + 2] !== 0 || u[e + 3] !== 0)
        return { out: L.join("\n") + "\n\n[!] No 'PE\\0\\0' signature at e_lfanew - truncated or not a PE." };
      L.push("PE signature: 'PE\\0\\0' OK", "");
      const c = e + 4;
      const machine = rU(u, c, 2, true), nsec = rU(u, c + 2, 2, true), ts = rU(u, c + 4, 4, true), optsz = rU(u, c + 16, 2, true), chars = rU(u, c + 18, 2, true);
      L.push("COFF file header:");
      L.push("  Machine:           " + hx(machine, 4) + "  " + (PE_MACHINE[machine] || "(unknown)"));
      L.push("  NumberOfSections:  " + nsec);
      L.push("  TimeDateStamp:     " + hx(ts, 8) + "  " + (ts ? new Date(ts * 1000).toISOString().replace(".000Z", "Z") + " UTC" : "(0 / not set)"));
      L.push("  SizeOfOptionalHdr: " + optsz + " (" + hx(optsz, 4) + ")");
      const cf = decodeFlags(PE_CHARS, chars || 0);
      L.push("  Characteristics:   " + hx(chars, 4) + (cf.set.length ? "  " + cf.set.join(", ") : ""));
      const optoff = c + 20, magic = rU(u, optoff, 2, true);
      if (magic != null) L.push("  OptionalHdr Magic: " + hx(magic, 4) + "  " + (magic === 0x10b ? "PE32" : magic === 0x20b ? "PE32+ (64-bit)" : magic === 0x107 ? "ROM" : "(unknown)"));
      const secoff = optoff + (optsz || 0);
      L.push("", "Sections [name  VirtAddr  VirtSize  RawPtr  RawSize  Flags]:");
      const cap = Math.min(nsec || 0, 96);
      if (!cap) L.push("  (none declared)");
      for (let i = 0; i < cap; i++) {
        const so = secoff + i * 40;
        if (so + 40 > u.length) { L.push("  [section " + i + " is beyond the pasted bytes - paste more to see it]"); break; }
        let name = ""; for (let j = 0; j < 8; j++) { const ch = u[so + j]; if (!ch) break; name += String.fromCharCode(ch); }
        L.push("  " + (name || "(unnamed)").padEnd(9) + " " + hx(rU(u, so + 12, 4, true), 8) + "  " + hx(rU(u, so + 8, 4, true), 8) + "  " + hx(rU(u, so + 20, 4, true), 8) + "  " + hx(rU(u, so + 16, 4, true), 8) + "  " + hx((rU(u, so + 36, 4, true)) >>> 0, 8));
      }
      return L.join("\n");
    } },

  { id: "bi-pe-machine", name: "PE Machine Type Reference", cat: "bininspect", desc: "Look up an IMAGE_FILE_MACHINE value (the target CPU in a PE/COFF header) by hex value or name.", tags: ["pe", "machine", "cpu", "image_file_machine"],
    inputs: [{ k: "q", label: "Machine value or name (e.g. 0x8664 or amd64)", type: "text", placeholder: "0x8664" }],
    run(v) {
      const rows = Object.entries(PE_MACHINE).map(([k, n]) => [hx(Number(k), 4), n]);
      const q = S(v.q).trim(); if (!q) return rows.map((r) => r.join("  |  ")).join("\n");
      const p = pint(q);
      if (p != null && PE_MACHINE[p] !== undefined) return hx(p, 4) + "  ->  " + PE_MACHINE[p];
      return renderTable(rows, q);
    } },

  { id: "bi-pe-characteristics", name: "PE Characteristics Decoder", cat: "bininspect", desc: "Decode the COFF Characteristics field of a PE header into its IMAGE_FILE_* flags (DLL, executable, large-address-aware, ...).", tags: ["pe", "characteristics", "flags", "coff"],
    inputs: [{ k: "val", label: "Characteristics value (prefix 0x for hex)", type: "text", placeholder: "0x2102" }],
    run(v) {
      const n = pint(v.val); if (n == null) return ""; if (n < 0 || n > 0xffff) return { error: "Expected a 16-bit value (0x0000-0xFFFF)." };
      const d = decodeFlags(PE_CHARS, n);
      return hx(n, 4) + "\n" + (d.set.length ? d.set.map((x) => "  " + x).join("\n") : "  (no flags set)") + (d.extra.length ? "\n  " + d.extra.join("; ") : "");
    } },

  { id: "bi-pe-subsystem", name: "PE Subsystem Reference", cat: "bininspect", desc: "Look up an IMAGE_SUBSYSTEM value from a PE optional header (GUI, console, native driver, EFI, ...).", tags: ["pe", "subsystem", "gui", "console"],
    inputs: [{ k: "q", label: "Subsystem value or name", type: "text", placeholder: "3" }],
    run(v) {
      const rows = Object.entries(PE_SUBSYS).map(([k, n]) => [k, n]);
      const q = S(v.q).trim(); if (!q) return rows.map((r) => r.join("  |  ")).join("\n");
      const p = pint(q);
      if (p != null && PE_SUBSYS[p] !== undefined) return p + "  ->  " + PE_SUBSYS[p];
      return renderTable(rows, q);
    } },

  { id: "bi-pe-dllcharacteristics", name: "PE DllCharacteristics Decoder", cat: "bininspect", desc: "Decode the DllCharacteristics field: shows mitigations such as ASLR (DYNAMIC_BASE), DEP (NX_COMPAT) and Control Flow Guard.", tags: ["pe", "dllcharacteristics", "aslr", "dep", "cfg", "mitigations"],
    inputs: [{ k: "val", label: "DllCharacteristics value (prefix 0x for hex)", type: "text", placeholder: "0x8160" }],
    run(v) {
      const n = pint(v.val); if (n == null) return ""; if (n < 0 || n > 0xffff) return { error: "Expected a 16-bit value (0x0000-0xFFFF)." };
      const d = decodeFlags(PE_DLLCHARS, n);
      return hx(n, 4) + "\n" + (d.set.length ? d.set.map((x) => "  " + x).join("\n") : "  (no flags set)") + (d.extra.length ? "\n  " + d.extra.join("; ") : "");
    } },

  { id: "bi-pe-section-flags", name: "PE Section Flags Decoder", cat: "bininspect", desc: "Decode a section's Characteristics (IMAGE_SCN_*) into readable flags such as MEM_EXECUTE / MEM_WRITE (writable+executable is suspicious).", tags: ["pe", "section", "scn", "rwx", "flags"],
    inputs: [{ k: "val", label: "Section Characteristics value (prefix 0x)", type: "text", placeholder: "0xE0000020" }],
    run(v) {
      const n = pint(v.val); if (n == null) return ""; const u = n >>> 0;
      const d = decodeFlags(PE_SCN, u);
      const note = (u & 0x20000000) && (u & 0x80000000) ? "\n  [!] writable AND executable (W^X violation - often seen in packed/injected code)" : "";
      return hx(u, 8) + "\n" + (d.set.length ? d.set.map((x) => "  " + x).join("\n") : "  (no flags set)") + note;
    } },

  { id: "bi-pe-datadir", name: "PE Data Directory Reference", cat: "bininspect", desc: "Reference for the 16 PE optional-header data directory slots by index (0=Export, 1=Import, 9=TLS, 14=.NET CLR, ...).", tags: ["pe", "data directory", "import", "export", "tls", "iat"],
    inputs: [{ k: "q", label: "Index 0-15 or name (blank = full list)", type: "text", placeholder: "1" }],
    run(v) {
      const rows = PE_DATADIR.map((n, i) => [String(i), n]);
      const q = S(v.q).trim(); if (!q) return rows.map((r) => r.join("  |  ")).join("\n");
      const p = pint(q);
      if (p != null && p >= 0 && p < PE_DATADIR.length) return p + "  ->  " + PE_DATADIR[p];
      return renderTable(rows, q);
    } },

  { id: "bi-pe-timestamp", name: "PE TimeDateStamp Decoder", cat: "bininspect", desc: "Convert a PE COFF TimeDateStamp (a 32-bit Unix epoch) to a readable UTC date, from a decimal value or little-endian hex bytes.", tags: ["pe", "timedatestamp", "compile time", "epoch"],
    inputs: [{ k: "val", label: "TimeDateStamp (0x hex, or decimal)", type: "text", placeholder: "0x5F5E1000" }, { k: "le", label: "Value is little-endian raw bytes (swap)", type: "checkbox", value: false }],
    run(v) {
      let n = pint(v.val); if (n == null) return "";
      if (v.le) { const b = [(n >>> 0) & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]; n = b[0] * 0x1000000 + b[1] * 0x10000 + b[2] * 0x100 + b[3]; }
      n = n >>> 0; if (!n) return "0x00000000 -> 0 (timestamp not set / zeroed)";
      return hx(n, 8) + " = " + n + "\n" + new Date(n * 1000).toISOString().replace(".000Z", "Z") + " UTC";
    } },

  { id: "bi-pe-rva-offset", name: "PE RVA / File-Offset Converter", cat: "bininspect", desc: "Convert between an RVA (virtual address) and a raw file offset using a pasted section table (name,VA,VSize,RawPtr,RawSize).", tags: ["pe", "rva", "offset", "file offset", "section"],
    inputs: [
      { k: "sections", label: "Sections: name,VA,VSize,RawPtr,RawSize (hex, one per line)", type: "textarea", rows: 5, placeholder: ".text,0x1000,0x5000,0x400,0x5000\n.data,0x6000,0x1000,0x5400,0x1000" },
      { k: "value", label: "RVA or offset to convert (hex)", type: "text", placeholder: "0x1200" },
      { k: "dir", label: "Direction", type: "select", opts: ["RVA -> File offset", "File offset -> RVA"], value: "RVA -> File offset" }],
    run(v) {
      const secs = [];
      for (const raw of S(v.sections).split(/\r?\n/)) {
        const line = raw.trim(); if (!line) continue;
        const p = line.split(/[,\t;]+/).map((x) => x.trim());
        if (p.length < 5) return { error: "Each section line needs name,VA,VSize,RawPtr,RawSize - got: " + line };
        const [name, va, vs, rp, rs] = [p[0], pint(p[1]), pint(p[2]), pint(p[3]), pint(p[4])];
        if ([va, vs, rp, rs].some((x) => x == null)) return { error: "Could not parse numbers in: " + line };
        secs.push({ name, va, vs, rp, rs });
      }
      if (!secs.length) return "";
      const n = pint(v.value); if (n == null) return "";
      if (v.dir.startsWith("RVA")) {
        for (const s of secs) if (n >= s.va && n < s.va + Math.max(s.vs, s.rs)) return "RVA " + hx(n) + "  in section " + s.name + "\n-> file offset " + hx(s.rp + (n - s.va));
        if (n < secs[0].va) return "RVA " + hx(n) + " is inside the headers (offset == RVA): " + hx(n);
        return { error: "RVA " + hx(n) + " is not inside any listed section." };
      }
      for (const s of secs) if (n >= s.rp && n < s.rp + s.rs) return "File offset " + hx(n) + "  in section " + s.name + "\n-> RVA " + hx(s.va + (n - s.rp));
      return { error: "Offset " + hx(n) + " is not inside any listed section's raw data." };
    } },

  { id: "bi-imphash", name: "Imphash (Import Hash) Calculator", cat: "bininspect", desc: "Compute the standard import-table imphash (MD5 of the lowercased dll.function list) from a pasted import list, to cluster related samples.", tags: ["imphash", "pe", "imports", "yara", "clustering", "md5"],
    inputs: [{ k: "imports", label: "Imports (dll!func or dll,func, one per line)", type: "textarea", rows: 7, placeholder: "KERNEL32.dll!GetProcAddress\nKERNEL32.dll!LoadLibraryA\nWS2_32.dll!recv" }],
    run(v, H) {
      const parts = [];
      for (const raw of S(v.imports).split(/\r?\n/)) {
        const line = raw.trim(); if (!line) continue;
        // separator between module and function is ! or , (do NOT split on the dll's own dot)
        let mod, fn;
        let m = line.match(/^(.+?)\s*[!,]\s*(.+)$/);
        if (m) { mod = m[1]; fn = m[2]; }
        else { const dm = line.match(/^(.+?\.(?:dll|ocx|sys|exe|drv))\.(.+)$/i); if (!dm) return { error: "Each line needs a DLL and a function, e.g. KERNEL32.dll!LoadLibraryA" }; mod = dm[1]; fn = dm[2]; }
        // imphash: lowercase, strip the dll/ocx/sys extension from the module name
        const dll = mod.trim().toLowerCase().replace(/\.(dll|ocx|sys)$/i, "");
        parts.push(dll + "." + fn.trim().toLowerCase());
      }
      if (!parts.length) return "";
      const str = parts.join(",");
      return "imports (" + parts.length + "): " + str + "\n\nimphash = " + H.md5(str);
    } },

  // ---------------- ELF (Linux / Unix) ----------------
  { id: "bi-elf-header", name: "ELF Header Inspector", cat: "bininspect", desc: "Decode a pasted ELF file's header: class (32/64-bit), endianness, OS ABI, type, machine and entry point.", tags: ["elf", "linux", "header", "entry point"],
    inputs: [{ k: "data", label: "File bytes (hex or base64)", type: "textarea", rows: 5, placeholder: "7F454C4602010100..." }, { k: "fmt", label: "Input format", type: "select", opts: ["Auto", "Hex", "Base64"], value: "Auto" }],
    run(v, H) {
      const u = toBytes(v.data, v.fmt, H);
      if (!u.length) return "";
      if (u[0] !== 0x7f || u[1] !== 0x45 || u[2] !== 0x4c || u[3] !== 0x46) return { error: "No ELF magic (0x7F 'E' 'L' 'F') at offset 0." };
      const cls = u[4], data = u[5], ver = u[6], osabi = u[7];
      const is64 = cls === 2, le = data === 1;
      const L = ["ELF magic OK (\\x7FELF)"];
      L.push("EI_CLASS:   " + cls + "  " + (cls === 1 ? "32-bit" : cls === 2 ? "64-bit" : "(invalid)"));
      L.push("EI_DATA:    " + data + "  " + (data === 1 ? "little-endian" : data === 2 ? "big-endian" : "(invalid)"));
      L.push("EI_VERSION: " + ver + (ver === 1 ? " (current)" : ""));
      L.push("EI_OSABI:   " + osabi + "  " + (ELF_OSABI[osabi] || "(unknown)"));
      const etype = rU(u, 16, 2, le), emach = rU(u, 18, 2, le), evers = rU(u, 20, 4, le);
      L.push("e_type:     " + hx(etype, 4) + "  " + (ELF_TYPE[etype] || (etype >= 0xff00 ? "processor-specific" : etype >= 0xfe00 ? "OS-specific" : "(unknown)")));
      L.push("e_machine:  " + hx(emach, 4) + "  " + (ELF_MACHINE[emach] || "(unknown)"));
      L.push("e_version:  " + evers);
      const entry = is64 ? rUBig(u, 24, 8, le) : rU(u, 24, 4, le);
      if (entry != null) L.push("e_entry:    " + (is64 ? hxB(entry, 16) : hx(entry, 8)));
      return L.join("\n");
    } },

  { id: "bi-elf-type", name: "ELF Type Reference", cat: "bininspect", desc: "Look up an ELF e_type value (REL object, EXEC, DYN/PIE shared object, CORE dump).", tags: ["elf", "e_type", "dyn", "pie", "core"],
    inputs: [{ k: "q", label: "e_type value or name (blank = list)", type: "text", placeholder: "3" }],
    run(v) {
      const rows = Object.entries(ELF_TYPE).map(([k, n]) => [k, n]);
      const q = S(v.q).trim(); if (!q) return rows.map((r) => r.join("  |  ")).join("\n");
      const p = pint(q); if (p != null && ELF_TYPE[p] !== undefined) return p + "  ->  " + ELF_TYPE[p];
      return renderTable(rows, q);
    } },

  { id: "bi-elf-machine", name: "ELF Machine Reference", cat: "bininspect", desc: "Look up an ELF e_machine value (target CPU) such as 62 = x86-64, 183 = AArch64, 3 = x86.", tags: ["elf", "e_machine", "cpu", "architecture"],
    inputs: [{ k: "q", label: "e_machine value or name (blank = list)", type: "text", placeholder: "62" }],
    run(v) {
      const rows = Object.entries(ELF_MACHINE).map(([k, n]) => [k, n]);
      const q = S(v.q).trim(); if (!q) return rows.map((r) => r.join("  |  ")).join("\n");
      const p = pint(q); if (p != null && ELF_MACHINE[p] !== undefined) return p + "  ->  " + ELF_MACHINE[p];
      return renderTable(rows, q);
    } },

  { id: "bi-elf-osabi", name: "ELF OS/ABI Reference", cat: "bininspect", desc: "Look up an ELF EI_OSABI value (System V, Linux, FreeBSD, ...) from the identification bytes.", tags: ["elf", "osabi", "abi"],
    inputs: [{ k: "q", label: "EI_OSABI value or name (blank = list)", type: "text", placeholder: "3" }],
    run(v) {
      const rows = Object.entries(ELF_OSABI).map(([k, n]) => [k, n]);
      const q = S(v.q).trim(); if (!q) return rows.map((r) => r.join("  |  ")).join("\n");
      const p = pint(q); if (p != null && ELF_OSABI[p] !== undefined) return p + "  ->  " + ELF_OSABI[p];
      return renderTable(rows, q);
    } },

  { id: "bi-elf-section-types", name: "ELF Section Type Reference", cat: "bininspect", desc: "Look up an ELF section header type (sh_type) such as PROGBITS, SYMTAB, DYNAMIC, NOBITS.", tags: ["elf", "sh_type", "section", "symtab", "dynamic"],
    inputs: [{ k: "q", label: "sh_type value or name (blank = list)", type: "text", placeholder: "11" }],
    run(v) {
      const rows = Object.entries(ELF_SHT).map(([k, n]) => [k, n]);
      const q = S(v.q).trim(); if (!q) return rows.map((r) => r.join("  |  ")).join("\n");
      const p = pint(q); if (p != null && ELF_SHT[p] !== undefined) return p + "  ->  " + ELF_SHT[p];
      return renderTable(rows, q);
    } },

  // ---------------- Mach-O (macOS / iOS) ----------------
  { id: "bi-macho-header", name: "Mach-O Header Inspector", cat: "bininspect", desc: "Decode a pasted Mach-O file's header: magic (32/64-bit, byte order, fat), CPU type and file type.", tags: ["mach-o", "macho", "macos", "header", "fat"],
    inputs: [{ k: "data", label: "File bytes (hex or base64)", type: "textarea", rows: 4, placeholder: "CFFAEDFE07000001..." }, { k: "fmt", label: "Input format", type: "select", opts: ["Auto", "Hex", "Base64"], value: "Auto" }],
    run(v, H) {
      const u = toBytes(v.data, v.fmt, H);
      if (u.length < 4) return "";
      // magicBE = the raw 4 bytes read in file order as a number
      const magicBE = rU(u, 0, 4, false);
      if (magicBE === 0xcafebabe || magicBE === 0xcafebabf) {
        const n = rU(u, 4, 4, false);
        return "Magic: " + hx(magicBE, 8) + "  FAT (universal) binary" + (magicBE === 0xcafebabf ? " [64-bit]" : "") + "\nArchitectures (nfat_arch): " + (n == null ? "?" : n) + "\n(a fat binary wraps several single-architecture Mach-O slices; 0xCAFEBABE is also the Java class-file magic)";
      }
      let le, is64;
      if (magicBE === 0xfeedface) { le = false; is64 = false; }      // bytes FE ED FA CE -> big-endian 32-bit
      else if (magicBE === 0xfeedfacf) { le = false; is64 = true; }  // bytes FE ED FA CF -> big-endian 64-bit
      else if (magicBE === 0xcefaedfe) { le = true; is64 = false; }  // bytes CE FA ED FE -> little-endian 32-bit
      else if (magicBE === 0xcffaedfe) { le = true; is64 = true; }   // bytes CF FA ED FE -> little-endian 64-bit
      else return { error: "No Mach-O magic (feedface/feedfacf/cafebabe or their byte-swapped forms)." };
      const cpu = rU(u, 4, 4, le), ft = rU(u, 12, 4, le), ncmds = rU(u, 16, 4, le);
      const L = ["Magic: " + hx(magicBE, 8) + "  Mach-O " + (is64 ? "64-bit" : "32-bit") + ", " + (le ? "little-endian" : "big-endian")];
      L.push("cputype:  " + hx(cpu, 8) + "  " + (MACHO_CPU[cpu >>> 0] || "(unknown)"));
      L.push("filetype: " + hx(ft, 8) + "  " + (MACHO_FT[ft] || "(unknown)"));
      if (ncmds != null) L.push("ncmds:    " + ncmds + "  (number of load commands)");
      return L.join("\n");
    } },

  { id: "bi-macho-cputype", name: "Mach-O CPU Type Reference", cat: "bininspect", desc: "Look up a Mach-O cputype value (7 = x86, 0x01000007 = x86_64, 0x0100000C = ARM64).", tags: ["mach-o", "cputype", "arm64", "x86_64"],
    inputs: [{ k: "q", label: "cputype value or name (blank = list)", type: "text", placeholder: "0x01000007" }],
    run(v) {
      const rows = Object.entries(MACHO_CPU).map(([k, n]) => [hx(Number(k), 8), n]);
      const q = S(v.q).trim(); if (!q) return rows.map((r) => r.join("  |  ")).join("\n");
      const p = pint(q); if (p != null && MACHO_CPU[p >>> 0] !== undefined) return hx(p >>> 0, 8) + "  ->  " + MACHO_CPU[p >>> 0];
      return renderTable(rows, q);
    } },

  { id: "bi-macho-filetype", name: "Mach-O File Type Reference", cat: "bininspect", desc: "Look up a Mach-O filetype value (MH_EXECUTE, MH_DYLIB, MH_BUNDLE, MH_OBJECT, ...).", tags: ["mach-o", "filetype", "dylib", "execute"],
    inputs: [{ k: "q", label: "filetype value or name (blank = list)", type: "text", placeholder: "2" }],
    run(v) {
      const rows = Object.entries(MACHO_FT).map(([k, n]) => [k, n]);
      const q = S(v.q).trim(); if (!q) return rows.map((r) => r.join("  |  ")).join("\n");
      const p = pint(q); if (p != null && MACHO_FT[p] !== undefined) return p + "  ->  " + MACHO_FT[p];
      return renderTable(rows, q);
    } },

  // ---------------- file identification ----------------
  { id: "bi-magic-bytes", name: "File Magic / Signature Identifier", cat: "bininspect", desc: "Identify a file type from the first bytes you paste by matching known magic-number signatures. Does not open any file.", tags: ["magic", "signature", "file type", "magic bytes", "identify"],
    inputs: [{ k: "data", label: "First bytes (hex or base64)", type: "textarea", rows: 3, placeholder: "89504E470D0A1A0A..." }, { k: "fmt", label: "Input format", type: "select", opts: ["Auto", "Hex", "Base64"], value: "Auto" }],
    run(v, H) {
      const u = toBytes(v.data, v.fmt, H);
      if (!u.length) return "";
      const head = Array.from(u.slice(0, 16), (b) => b.toString(16).padStart(2, "0")).join("");
      let best = null;
      for (const [sig, name] of MAGICS) if (head.startsWith(sig.toLowerCase()) && (!best || sig.length > best[0].length)) best = [sig, name];
      const pre = "first bytes: " + head.replace(/(..)/g, "$1 ").trim() + "\n";
      if (!best) return pre + "No known signature matched these leading bytes.";
      return pre + "match: " + best[1] + "  (magic " + best[0].toUpperCase().replace(/(..)/g, "$1 ").trim() + ")";
    } },

  // ---------------- byte / number formatting ----------------
  { id: "bi-byte-reformat", name: "Byte Array Reformatter", cat: "bininspect", desc: "Convert a pasted hex/byte blob between formats (\\xAA, 0xAA, C array, Python bytes, space-hex, bare hex, base64, decimal) as a pure text transform.", tags: ["bytes", "reformat", "shellcode", "c array", "python bytes", "convert"],
    inputs: [{ k: "data", label: "Bytes (hex or base64)", type: "textarea", rows: 4, placeholder: "DE AD BE EF" }, { k: "fmt", label: "Input format", type: "select", opts: ["Auto", "Hex", "Base64"], value: "Auto" }, { k: "out", label: "Output format", type: "select", opts: ["\\xAA escaped", "0xAA, comma", "C array", "Python bytes", "space hex", "bare hex", "base64", "decimal"], value: "\\xAA escaped" }],
    run(v, H) {
      const u = toBytes(v.data, v.fmt, H);
      if (!u.length) return "";
      const h = Array.from(u, (b) => b.toString(16).padStart(2, "0"));
      switch (v.out) {
        case "\\xAA escaped": return "\\x" + h.join("\\x");
        case "0xAA, comma": return h.map((x) => "0x" + x).join(", ");
        case "C array": return "unsigned char buf[" + u.length + "] = {\n  " + h.map((x) => "0x" + x).join(", ") + "\n};";
        case "Python bytes": return 'data = b"\\x' + h.join("\\x") + '"';
        case "space hex": return h.join(" ").toUpperCase();
        case "bare hex": return h.join("");
        case "base64": { let bin = ""; for (let i = 0; i < u.length; i++) bin += String.fromCharCode(u[i]); return btoa(bin); }
        case "decimal": return Array.from(u).join(", ");
        default: return h.join("");
      }
    } },

  { id: "bi-endian-swap", name: "Endianness Swapper", cat: "bininspect", desc: "Reverse byte order of each 2/4/8-byte word in a hex blob (little-endian <-> big-endian), and show the integer value of a single word.", tags: ["endian", "byteswap", "little-endian", "big-endian"],
    inputs: [{ k: "hex", label: "Hex bytes", type: "textarea", rows: 3, placeholder: "0x0010005E or 00 10 00 5E" }, { k: "width", label: "Word size (bytes)", type: "select", opts: ["2", "4", "8"], value: "4" }],
    run(v, H) {
      const u = H.fromHex(v.hex); if (!u.length) return "";
      const w = parseInt(v.width, 10);
      if (u.length % w !== 0) return { error: "Byte count (" + u.length + ") is not a multiple of the word size (" + w + ")." };
      const out = new Uint8Array(u.length);
      for (let i = 0; i < u.length; i += w) for (let j = 0; j < w; j++) out[i + j] = u[i + w - 1 - j];
      const hexOut = Array.from(out, (b) => b.toString(16).padStart(2, "0")).join("");
      let extra = "";
      if (u.length === w) extra = "\n\nas integer: LE=" + rUBig(u, 0, w, true).toString() + "  BE=" + rUBig(u, 0, w, false).toString();
      return "swapped: " + hexOut + extra;
    } },

  { id: "bi-hex-int", name: "Hex / Integer Pointer Converter", cat: "bininspect", desc: "Convert a hex address/pointer to a decimal integer or back, choosing width (16/32/64-bit), byte order and signedness.", tags: ["hex", "integer", "pointer", "address", "convert"],
    inputs: [{ k: "val", label: "Value (hex like 0x401000, or decimal)", type: "text", placeholder: "0x401000" }, { k: "dir", label: "Direction", type: "select", opts: ["Hex -> Integer", "Integer -> Hex"], value: "Hex -> Integer" }, { k: "width", label: "Width", type: "select", opts: ["16-bit", "32-bit", "64-bit"], value: "64-bit" }, { k: "signed", label: "Signed (two's complement)", type: "checkbox", value: false }],
    run(v) {
      const bits = v.width === "16-bit" ? 16 : v.width === "32-bit" ? 32 : 64;
      const mod = 1n << BigInt(bits), half = 1n << BigInt(bits - 1);
      if (v.dir === "Hex -> Integer") {
        const s = S(v.val).trim().replace(/^0x/i, ""); if (!s) return "";
        if (!/^[0-9a-f]+$/i.test(s)) return { error: "Not a hex value." };
        let n = BigInt("0x" + s) % mod;
        if (v.signed && n >= half) n -= mod;
        return "0x" + (n < 0n ? (n + mod) : n).toString(16) + " = " + n.toString() + (v.signed ? " (signed)" : " (unsigned)");
      }
      let n; try { n = BigInt(S(v.val).trim()); } catch (e) { return { error: "Not a decimal integer." }; }
      let m = ((n % mod) + mod) % mod;
      return "0x" + m.toString(16).padStart(bits / 4, "0") + "  (" + bits + "-bit)";
    } },

  { id: "bi-struct-ints", name: "Multi-Width Integer Decoder", cat: "bininspect", desc: "Interpret the first bytes of a hex blob as u8/i8, u16/i16, u32/i32 and u64/i64 in both little- and big-endian, for manual struct parsing.", tags: ["struct", "integer", "decode", "u32", "u64", "endian"],
    inputs: [{ k: "hex", label: "Hex bytes (up to 8 used)", type: "text", placeholder: "78 56 34 12" }],
    run(v, H) {
      const u = H.fromHex(v.hex); if (!u.length) return "";
      const toSigned = (val, bits) => { const half = 1n << BigInt(bits - 1), mod = 1n << BigInt(bits); return val >= half ? val - mod : val; };
      const L = [];
      L.push("byte count: " + u.length);
      L.push("u8:  " + u[0] + "   i8: " + toSigned(BigInt(u[0]), 8));
      if (u.length >= 2) { const le = rUBig(u, 0, 2, true), be = rUBig(u, 0, 2, false); L.push("u16: LE=" + le + " BE=" + be + "   i16: LE=" + toSigned(le, 16) + " BE=" + toSigned(be, 16)); }
      if (u.length >= 4) { const le = rUBig(u, 0, 4, true), be = rUBig(u, 0, 4, false); L.push("u32: LE=" + le + " BE=" + be + "   i32: LE=" + toSigned(le, 32) + " BE=" + toSigned(be, 32)); }
      if (u.length >= 8) { const le = rUBig(u, 0, 8, true), be = rUBig(u, 0, 8, false); L.push("u64: LE=" + le + " BE=" + be + "   i64: LE=" + toSigned(le, 64) + " BE=" + toSigned(be, 64)); }
      return L.join("\n");
    } },

  { id: "bi-hexdump", name: "Hexdump Formatter", cat: "bininspect", desc: "Render a pasted hex/base64 blob as a classic hexdump (offset, 16 hex bytes, ASCII gutter) for reading structure.", tags: ["hexdump", "xxd", "hexview", "ascii"],
    inputs: [{ k: "data", label: "Bytes (hex or base64)", type: "textarea", rows: 4, placeholder: "48656C6C6F2C20776F726C6421" }, { k: "fmt", label: "Input format", type: "select", opts: ["Auto", "Hex", "Base64"], value: "Auto" }],
    run(v, H) {
      const u = toBytes(v.data, v.fmt, H); if (!u.length) return "";
      const L = [];
      for (let o = 0; o < u.length; o += 16) {
        const row = u.slice(o, o + 16);
        const hexs = Array.from(row, (b) => b.toString(16).padStart(2, "0"));
        while (hexs.length < 16) hexs.push("  ");
        const left = hexs.slice(0, 8).join(" "), right = hexs.slice(8).join(" ");
        L.push(o.toString(16).padStart(8, "0") + "  " + left + "  " + right + "  |" + asciiOf(row) + "|");
      }
      return L.join("\n");
    } },

  { id: "bi-strings", name: "Strings Extractor", cat: "bininspect", desc: "Pull printable ASCII or UTF-16LE (wide) strings of a minimum length out of a pasted hex/base64 blob, like the Unix 'strings' tool.", tags: ["strings", "ascii", "wide", "unicode", "extract"],
    inputs: [{ k: "data", label: "Bytes (hex or base64)", type: "textarea", rows: 5, placeholder: "68656C6C6F00..." }, { k: "fmt", label: "Input format", type: "select", opts: ["Auto", "Hex", "Base64"], value: "Auto" }, { k: "min", label: "Minimum length", type: "range", min: 2, max: 20, step: 1, value: 4 }, { k: "mode", label: "Mode", type: "select", opts: ["ASCII", "Wide (UTF-16LE)", "Both"], value: "ASCII" }],
    run(v, H) {
      const u = toBytes(v.data, v.fmt, H); if (!u.length) return "";
      const min = H.clampInt(v.min, 2, 64, 4);
      const out = [];
      if (v.mode === "ASCII" || v.mode === "Both") {
        let cur = "", start = 0;
        for (let i = 0; i <= u.length; i++) { const b = u[i]; if (b !== undefined && b >= 0x20 && b <= 0x7e) { if (!cur) start = i; cur += String.fromCharCode(b); } else { if (cur.length >= min) out.push(hx(start, 8) + "  " + cur); cur = ""; } }
      }
      if (v.mode === "Wide (UTF-16LE)" || v.mode === "Both") {
        let cur = "", start = 0;
        for (let i = 0; i + 1 < u.length; i += 2) { const lo = u[i], hi = u[i + 1]; if (hi === 0 && lo >= 0x20 && lo <= 0x7e) { if (!cur) start = i; cur += String.fromCharCode(lo); } else { if (cur.length >= min) out.push(hx(start, 8) + "  (w) " + cur); cur = ""; } }
        if (cur.length >= min) out.push(hx(start, 8) + "  (w) " + cur);
      }
      return out.length ? out.join("\n") : "(no strings of length >= " + min + ")";
    } },

  { id: "bi-utf16-decode", name: "UTF-16 Hex Decoder", cat: "bininspect", desc: "Decode a hex/base64 blob as UTF-16 (LE or BE) text - common for Windows wide strings and some config blobs.", tags: ["utf-16", "unicode", "wide", "decode"],
    inputs: [{ k: "data", label: "Bytes (hex or base64)", type: "textarea", rows: 3, placeholder: "680065006C006C006F00" }, { k: "fmt", label: "Input format", type: "select", opts: ["Auto", "Hex", "Base64"], value: "Auto" }, { k: "endian", label: "Byte order", type: "select", opts: ["Little-endian", "Big-endian"], value: "Little-endian" }],
    run(v, H) {
      const u = toBytes(v.data, v.fmt, H); if (!u.length) return "";
      const le = v.endian === "Little-endian";
      let out = "";
      for (let i = 0; i + 1 < u.length; i += 2) { const cp = le ? u[i] | (u[i + 1] << 8) : (u[i] << 8) | u[i + 1]; out += String.fromCharCode(cp); }
      return out;
    } },

  // ---------------- decoders / de-obfuscation (inert data only) ----------------
  { id: "bi-decode-chain", name: "Layered Decode Chain", cat: "bininspect", desc: "Auto-peel nested base64 / hex / URL-encoding from an obfuscated-but-inert string, showing each layer until it stops being decodable.", tags: ["base64", "hex", "url", "layered", "deobfuscate", "decode"],
    inputs: [{ k: "text", label: "Encoded string", type: "textarea", rows: 4, placeholder: "JTYxJTYyJTYz" }, { k: "max", label: "Max layers", type: "range", min: 1, max: 12, step: 1, value: 8 }],
    run(v, H) {
      let cur = S(v.text).trim(); if (!cur) return "";
      const max = H.clampInt(v.max, 1, 12, 8);
      const printableRatio = (s) => { if (!s) return 0; let p = 0; for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); if (c === 9 || c === 10 || c === 13 || (c >= 0x20 && c <= 0x7e)) p++; } return p / s.length; };
      const L = ["layer 0 (input): " + cur];
      for (let i = 0; i < max; i++) {
        let next = null, how = "";
        // URL-encoding
        if (/%[0-9a-f]{2}/i.test(cur)) { try { const d = decodeURIComponent(cur.replace(/\+/g, " ")); if (d !== cur) { next = d; how = "url-decode"; } } catch (e) { } }
        // hex
        if (next == null) { const hs = cur.replace(/\s|0x|\\x/gi, ""); if (/^[0-9a-f]+$/i.test(hs) && hs.length >= 4 && hs.length % 2 === 0) { const d = H.fromBytes(H.fromHex(hs)); if (printableRatio(d) > 0.85) { next = d; how = "hex-decode"; } } }
        // base64
        if (next == null) { const bs = cur.replace(/\s/g, ""); if (/^[A-Za-z0-9+/_-]{8,}={0,2}$/.test(bs)) { try { const d = H.b64decode(bs, { url: /[-_]/.test(bs) }); if (d && printableRatio(d) > 0.85 && d !== cur) { next = d; how = "base64-decode"; } } catch (e) { } } }
        if (next == null || next === cur) break;
        cur = next; L.push("layer " + (i + 1) + " (" + how + "): " + cur);
      }
      if (L.length === 1) return L[0] + "\n\n(no further decodable layer detected)";
      return L.join("\n");
    } },

  { id: "bi-b64-extract", name: "Embedded Base64 Extractor", cat: "bininspect", desc: "Scan a blob of text (a report, log or config) for long base64 runs and decode each one that yields mostly printable text.", tags: ["base64", "extract", "embedded", "config", "decode"],
    inputs: [{ k: "text", label: "Text to scan", type: "textarea", rows: 6, placeholder: "...cmd /c aGVsbG8gd29ybGQ= ..." }, { k: "min", label: "Minimum length", type: "range", min: 8, max: 64, step: 4, value: 16 }],
    run(v, H) {
      const text = S(v.text); if (!text) return "";
      const min = H.clampInt(v.min, 8, 256, 16);
      const re = new RegExp("[A-Za-z0-9+/_-]{" + min + ",}={0,2}", "g");
      const seen = new Set(), out = [];
      let m;
      while ((m = re.exec(text))) {
        const tok = m[0]; if (seen.has(tok)) continue; seen.add(tok);
        try { const d = H.b64decode(tok, { url: /[-_]/.test(tok) }); let p = 0; for (let i = 0; i < d.length; i++) { const c = d.charCodeAt(i); if (c === 9 || c === 10 || c === 13 || (c >= 0x20 && c <= 0x7e)) p++; } if (d.length && p / d.length > 0.8) out.push("@" + m.index + "  " + (tok.length > 40 ? tok.slice(0, 40) + "..." : tok) + "\n   -> " + d); } catch (e) { }
      }
      return out.length ? out.join("\n") : "(no base64 run of length >= " + min + " decoded to printable text)";
    } },

  { id: "bi-powershell-decode", name: "PowerShell EncodedCommand Decoder", cat: "bininspect", desc: "Decode a PowerShell -EncodedCommand value (base64 of UTF-16LE) back to the readable script text, for incident triage.", tags: ["powershell", "encodedcommand", "enc", "base64", "utf-16", "incident response"],
    inputs: [{ k: "b64", label: "Base64 EncodedCommand value", type: "textarea", rows: 4, placeholder: "VwByAGkAdABlAC0ASABvAHMAdAAgAGgAaQA=" }],
    run(v, H) {
      let s = S(v.b64).trim(); if (!s) return "";
      s = s.replace(/^-?e(nc(odedcommand)?)?\s+/i, "").replace(/\s+/g, "");
      let u; try { u = b64ToU8(s); } catch (e) { return { error: "Not valid base64." }; }
      // PowerShell -EncodedCommand is base64 of UTF-16LE
      let out = "";
      for (let i = 0; i + 1 < u.length; i += 2) out += String.fromCharCode(u[i] | (u[i + 1] << 8));
      if (!out) return { error: "Decoded to empty string." };
      return out;
    } },

  { id: "bi-url-deobfuscate", name: "URL / Log De-obfuscator", cat: "bininspect", desc: "Recursively percent-decode an obfuscated URL from a log line, revealing double/triple-encoded payloads and reporting how many layers were peeled.", tags: ["url", "percent", "deobfuscate", "log", "decode"],
    inputs: [{ k: "url", label: "Encoded URL or log value", type: "textarea", rows: 3, placeholder: "%252e%252e%252fetc%252fpasswd" }, { k: "plus", label: "Treat + as space", type: "checkbox", value: false }],
    run(v) {
      let cur = S(v.url).trim(); if (!cur) return "";
      let layers = 0;
      for (let i = 0; i < 10; i++) {
        let s = cur; if (v.plus) s = s.replace(/\+/g, " ");
        if (!/%[0-9a-f]{2}/i.test(s)) break;
        let d; try { d = decodeURIComponent(s); } catch (e) { break; }
        if (d === cur) break; cur = d; layers++;
      }
      return "decoded (" + layers + " layer" + (layers === 1 ? "" : "s") + "):\n" + cur;
    } },

  { id: "bi-charcode-decode", name: "CharCode / Escape Decoder", cat: "bininspect", desc: "Decode String.fromCharCode(...) lists, \\xHH / \\uHHHH escapes, or comma/space-separated decimal codes back to readable text.", tags: ["fromcharcode", "escape", "\\x", "\\u", "decimal", "deobfuscate"],
    inputs: [{ k: "text", label: "Encoded sequence", type: "textarea", rows: 4, placeholder: "String.fromCharCode(104,105)  or  \\x68\\x69  or  104 105" }],
    run(v) {
      let s = S(v.text).trim(); if (!s) return "";
      // extract fromCharCode(...) argument lists, else use whole string
      const fcc = s.match(/fromCharCode\s*\(([^)]*)\)/i);
      if (fcc) s = fcc[1];
      if (/\\x[0-9a-f]{2}|\\u[0-9a-f]{4}/i.test(s)) {
        return s.replace(/\\u([0-9a-f]{4})/gi, (_, h) => String.fromCharCode(parseInt(h, 16))).replace(/\\x([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
      }
      const nums = s.split(/[,\s]+/).map((x) => x.trim()).filter(Boolean);
      if (nums.length && nums.every((n) => /^(0x)?[0-9a-f]+$/i.test(n))) {
        const hexish = nums.some((n) => /^0x/i.test(n));
        let out = "";
        for (const n of nums) { const code = /^0x/i.test(n) ? parseInt(n, 16) : (hexish ? parseInt(n, 16) : parseInt(n, 10)); if (code >= 0 && code <= 0x10ffff) out += String.fromCodePoint(code); }
        return out;
      }
      return { error: "Could not recognise a fromCharCode list, \\x/\\u escapes, or a numeric code list." };
    } },

  { id: "bi-xor-bruteforce", name: "Single-Byte XOR Brute-forcer", cat: "bininspect", desc: "Try all 256 single-byte XOR keys against a hex/base64 blob and show the keys that produce mostly printable text (reveals inert XOR'd strings).", tags: ["xor", "bruteforce", "deobfuscate", "decode", "key"],
    inputs: [{ k: "data", label: "XOR'd bytes (hex or base64)", type: "textarea", rows: 4, placeholder: "27 2a 3f 3f 3c" }, { k: "fmt", label: "Input format", type: "select", opts: ["Auto", "Hex", "Base64"], value: "Auto" }, { k: "crib", label: "Known substring to look for (optional)", type: "text", placeholder: "http" }],
    run(v, H) {
      const u = toBytes(v.data, v.fmt, H); if (!u.length) return "";
      if (u.length > 4096) return { error: "Blob too large for brute-force (limit 4096 bytes)." };
      const crib = S(v.crib);
      const results = [];
      for (let k = 0; k < 256; k++) {
        let printable = 0, str = "";
        for (let i = 0; i < u.length; i++) { const b = u[i] ^ k; str += (b >= 0x20 && b <= 0x7e) || b === 9 || b === 10 || b === 13 ? String.fromCharCode(b) : "."; if ((b >= 0x20 && b <= 0x7e) || b === 9 || b === 10 || b === 13) printable++; }
        const ratio = printable / u.length;
        const hit = crib && str.toLowerCase().includes(crib.toLowerCase());
        if (ratio > 0.9 || hit) results.push({ k, ratio, str, hit });
      }
      results.sort((a, b) => (b.hit - a.hit) || (b.ratio - a.ratio));
      if (!results.length) return "(no key produced >90% printable output" + (crib ? " and no key revealed the crib" : "") + ")";
      return results.slice(0, 20).map((r) => "key 0x" + r.k.toString(16).padStart(2, "0") + (r.hit ? " [crib!]" : "") + "  (" + Math.round(r.ratio * 100) + "%)  " + r.str).join("\n");
    } },

  // ---------------- IOC handling ----------------
  { id: "bi-ioc-extract", name: "IOC Extractor", cat: "bininspect", desc: "Pull indicators (IPv4/IPv6, domains, URLs, emails, MD5/SHA-1/SHA-256 hashes) out of a pasted report or log, de-duplicated, with optional defanging.", tags: ["ioc", "extract", "indicators", "hash", "domain", "url", "defang"],
    inputs: [{ k: "text", label: "Text to scan", type: "textarea", rows: 8, placeholder: "Paste a report, log, or email body..." }, { k: "defang", label: "Defang output (hxxp, 1[.]2[.]3[.]4)", type: "checkbox", value: false }],
    run(v) {
      let t = S(v.text); if (!t) return "";
      // refang first so already-defanged indicators are caught
      t = t.replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".").replace(/\{\.\}/g, ".").replace(/\[:\]/g, ":").replace(/\[@\]/g, "@").replace(/h(?:xx|XX)p(s?)/g, "http$1").replace(/\[(:\/\/)\]/g, "$1");
      const uniq = (a) => Array.from(new Set(a));
      const grab = (re) => uniq((t.match(re) || []));
      const sha256 = grab(/\b[a-f0-9]{64}\b/gi);
      const sha1 = grab(/\b[a-f0-9]{40}\b/gi);
      const md5 = grab(/\b[a-f0-9]{32}\b/gi);
      const urls = grab(/\bhttps?:\/\/[^\s"'<>\])]+/gi);
      const emails = grab(/\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi);
      const ipv4 = grab(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g);
      const ipv6 = grab(/\b(?:[a-f0-9]{1,4}:){2,7}[a-f0-9]{1,4}\b/gi).filter((x) => x.includes("::") || x.split(":").length >= 4);
      // domains: strip ones already captured inside urls/emails
      const inOther = new Set();
      urls.concat(emails).forEach((x) => (x.match(/[a-z0-9.-]+\.[a-z]{2,}/gi) || []).forEach((d) => inOther.add(d.toLowerCase())));
      const domains = grab(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi).filter((d) => !/^\d+$/.test(d.split(".").pop()) && !inOther.has(d.toLowerCase()));
      const defang = (s) => v.defang ? s.replace(/^http/i, "hxxp").replace(/\./g, "[.]").replace(/@/g, "[@]").replace(/:\/\//, "[://]") : s;
      const section = (name, arr) => arr.length ? name + " (" + arr.length + "):\n" + arr.map((x) => "  " + defang(x)).join("\n") : null;
      const parts = [section("IPv4", ipv4), section("IPv6", ipv6), section("Domains", domains), section("URLs", urls), section("Emails", emails), section("SHA-256", sha256), section("SHA-1", sha1.filter((h) => !sha256.includes(h))), section("MD5", md5.filter((h) => !sha1.includes(h) && !sha256.includes(h)))].filter(Boolean);
      return parts.length ? parts.join("\n\n") : "(no indicators found)";
    } },

  { id: "bi-defang-refang", name: "IOC Defang / Refang", cat: "bininspect", desc: "Toggle indicators between live and safe-to-share form: defang (hxxp://1[.]2[.]3[.]4) so links are not clickable, or refang back to the real value.", tags: ["defang", "refang", "ioc", "hxxp", "safe", "neutralize"],
    inputs: [{ k: "text", label: "Indicators (one per line or inline)", type: "textarea", rows: 5, placeholder: "http://example.com/path\n198.51.100.23\nuser@example.com" }, { k: "mode", label: "Mode", type: "select", opts: ["Defang", "Refang"], value: "Defang" }],
    run(v) {
      const t = S(v.text); if (!t) return "";
      if (v.mode === "Defang") {
        return t.replace(/https?(?=:\/\/)/gi, (m) => m.toLowerCase() === "https" ? "hxxps" : "hxxp").replace(/:\/\//g, "[://]").replace(/\./g, "[.]").replace(/@/g, "[@]");
      }
      return t.replace(/\[\.\]|\(\.\)|\{\.\}/g, ".").replace(/\[:\]/g, ":").replace(/\[@\]/g, "@").replace(/\[(:\/\/)\]/g, "$1").replace(/h(?:xx|XX)p(s?)(?=:\/\/|\[:\/\/\])/gi, "http$1");
    } },

  { id: "bi-ioc-normalize", name: "IOC List Normalizer", cat: "bininspect", desc: "Refang, lowercase, de-duplicate and sort a list of indicators, grouping them by type (IP / domain / URL / email / hash) with counts.", tags: ["ioc", "normalize", "dedupe", "sort", "classify"],
    inputs: [{ k: "text", label: "Indicators (one per line)", type: "textarea", rows: 8, placeholder: "1[.]2[.]3[.]4\nEXAMPLE.com\nhxxp://bad.example/x" }],
    run(v) {
      const refang = (s) => s.replace(/\[\.\]|\(\.\)|\{\.\}/g, ".").replace(/\[:\]/g, ":").replace(/\[@\]/g, "@").replace(/\[(:\/\/)\]/g, "$1").replace(/h(?:xx|XX)p(s?)/gi, "http$1").trim();
      const items = S(v.text).split(/[\r\n,;]+/).map((x) => refang(x.trim())).filter(Boolean);
      if (!items.length) return "";
      const buckets = { "SHA-256": [], "SHA-1": [], "MD5": [], URLs: [], Emails: [], IPv4: [], Domains: [], Other: [] };
      for (const raw of items) {
        const s = raw.toLowerCase();
        if (/^[a-f0-9]{64}$/.test(s)) buckets["SHA-256"].push(s);
        else if (/^[a-f0-9]{40}$/.test(s)) buckets["SHA-1"].push(s);
        else if (/^[a-f0-9]{32}$/.test(s)) buckets["MD5"].push(s);
        else if (/^https?:\/\//.test(s)) buckets.URLs.push(raw);
        else if (/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/.test(s)) buckets.Emails.push(s);
        else if (/^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(s)) buckets.IPv4.push(s);
        else if (/^(?:[a-z0-9-]+\.)+[a-z]{2,}$/.test(s)) buckets.Domains.push(s);
        else buckets.Other.push(raw);
      }
      const out = [];
      for (const [name, arr] of Object.entries(buckets)) { if (!arr.length) continue; const u = Array.from(new Set(arr)).sort(); out.push(name + " (" + u.length + "):\n" + u.map((x) => "  " + x).join("\n")); }
      return out.join("\n\n") || "(nothing to normalize)";
    } },

  { id: "bi-import-normalize", name: "Import / Library Normalizer", cat: "bininspect", desc: "Sort, lowercase and de-duplicate a pasted list of imported DLLs/functions or shared libraries, grouped by module, to diff two samples.", tags: ["imports", "dll", "library", "normalize", "diff", "sort"],
    inputs: [{ k: "text", label: "Imports (DLL!func, dll.func or plain lib names)", type: "textarea", rows: 8, placeholder: "KERNEL32.dll!LoadLibraryA\nkernel32.dll!GetProcAddress\nlibc.so.6" }],
    run(v) {
      const lines = S(v.text).split(/[\r\n,;]+/).map((x) => x.trim()).filter(Boolean);
      if (!lines.length) return "";
      const groups = {};
      const plain = new Set();
      for (const line of lines) {
        const m = line.match(/^([^!]+?)\s*[!]\s*(.+)$/) || line.match(/^([a-z0-9_]+\.(?:dll|ocx|sys|drv))\.(.+)$/i);
        if (m) { const dll = m[1].trim().toLowerCase(), fn = m[2].trim(); (groups[dll] = groups[dll] || new Set()).add(fn); }
        else plain.add(line.toLowerCase());
      }
      const out = [];
      for (const dll of Object.keys(groups).sort()) { const fns = Array.from(groups[dll]).sort(); out.push(dll + " (" + fns.length + "):\n" + fns.map((f) => "  " + f).join("\n")); }
      if (plain.size) out.push("libraries (" + plain.size + "):\n" + Array.from(plain).sort().map((x) => "  " + x).join("\n"));
      return out.join("\n\n");
    } },

  { id: "bi-hashset-dedupe", name: "Hash List De-duplicator", cat: "bininspect", desc: "Extract and validate MD5/SHA-1/SHA-256 hashes from messy pasted text, lowercase, de-duplicate and sort them by type for clean IOC comparison.", tags: ["hash", "dedupe", "md5", "sha1", "sha256", "ioc"],
    inputs: [{ k: "text", label: "Text containing hashes", type: "textarea", rows: 7, placeholder: "D41D8CD98F00B204E9800998ECF8427E  file1\n..." }],
    run(v) {
      const t = S(v.text); if (!t) return "";
      const uniq = (a) => Array.from(new Set(a.map((x) => x.toLowerCase()))).sort();
      const sha256 = uniq(t.match(/\b[a-f0-9]{64}\b/gi) || []);
      const sha1 = uniq(t.match(/\b[a-f0-9]{40}\b/gi) || []).filter((h) => !sha256.includes(h));
      const md5 = uniq(t.match(/\b[a-f0-9]{32}\b/gi) || []).filter((h) => !sha1.includes(h) && !sha256.includes(h));
      const sec = (n, a) => a.length ? n + " (" + a.length + "):\n" + a.map((x) => "  " + x).join("\n") : null;
      const parts = [sec("SHA-256", sha256), sec("SHA-1", sha1), sec("MD5", md5)].filter(Boolean);
      return parts.length ? parts.join("\n\n") : "(no valid MD5/SHA-1/SHA-256 hashes found)";
    } },

  // ---------------- detection-rule scaffolds ----------------
  { id: "bi-yara-skeleton", name: "YARA Rule Skeleton", cat: "bininspect", desc: "Format the strings you picked into a well-formed YARA rule template (meta + strings + condition). A scaffold - it does not invent detection logic.", tags: ["yara", "rule", "skeleton", "template", "detection"],
    inputs: [
      { k: "name", label: "Rule name", type: "text", value: "Suspicious_Sample", placeholder: "My_Rule" },
      { k: "strings", label: "Strings (one per line; wrap /re/ for regex, { AA BB } stays hex)", type: "textarea", rows: 5, placeholder: "cmd.exe /c\nhxxp fragment\n{ 6A 40 68 00 30 }" },
      { k: "author", label: "Author (meta)", type: "text", placeholder: "analyst" },
      { k: "desc", label: "Description (meta)", type: "text", placeholder: "What this detects" },
      { k: "cond", label: "Condition", type: "select", opts: ["any of them", "all of them", "2 of them", "uint16(0) == 0x5A4D and any of them"], value: "any of them" }],
    run(v) {
      const name = (S(v.name).trim() || "My_Rule").replace(/[^A-Za-z0-9_]/g, "_").replace(/^(\d)/, "_$1");
      const strs = S(v.strings).split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
      const L = ["rule " + name, "{", "    meta:"];
      L.push('        author = "' + (S(v.author).trim() || "unknown").replace(/"/g, "'") + '"');
      L.push('        description = "' + (S(v.desc).trim() || "describe the detection").replace(/"/g, "'") + '"');
      L.push("    strings:");
      if (!strs.length) L.push('        $s0 = "example"');
      strs.forEach((s, i) => {
        let val;
        if (/^\{[\s0-9a-fA-F?]+\}$/.test(s)) val = s;                       // hex string
        else if (/^\/.*\/[a-z]*$/.test(s)) val = s;                          // regex
        else val = '"' + s.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"'; // text string
        L.push("        $s" + i + " = " + val);
      });
      L.push("    condition:", "        " + v.cond, "}");
      return L.join("\n");
    } },

  { id: "bi-yara-hex", name: "YARA Hex String Formatter", cat: "bininspect", desc: "Turn a hex/base64 byte blob into a YARA hex string { AA BB CC }, optionally wrapping to a width, ready to paste into a rule.", tags: ["yara", "hex string", "bytes", "format", "rule"],
    inputs: [{ k: "data", label: "Bytes (hex or base64)", type: "textarea", rows: 3, placeholder: "6A 40 68 00 30 00 00" }, { k: "fmt", label: "Input format", type: "select", opts: ["Auto", "Hex", "Base64"], value: "Auto" }, { k: "name", label: "Variable name", type: "text", value: "$a" }, { k: "wrap", label: "Bytes per line (0 = one line)", type: "range", min: 0, max: 32, step: 4, value: 16 }],
    run(v, H) {
      const u = toBytes(v.data, v.fmt, H); if (!u.length) return "";
      const h = Array.from(u, (b) => b.toString(16).padStart(2, "0").toUpperCase());
      const name = S(v.name).trim() || "$a";
      const w = H.clampInt(v.wrap, 0, 64, 16);
      if (!w) return name + " = { " + h.join(" ") + " }";
      const lines = [];
      for (let i = 0; i < h.length; i += w) lines.push("    " + h.slice(i, i + w).join(" "));
      return name + " = {\n" + lines.join("\n") + "\n}";
    } },

  { id: "bi-sigma-skeleton", name: "Sigma Rule Skeleton", cat: "bininspect", desc: "Format a Sigma detection rule scaffold (YAML) from a title, log source and field:value selection lines. A template, not generated logic.", tags: ["sigma", "yaml", "detection", "skeleton", "siem"],
    inputs: [
      { k: "title", label: "Title", type: "text", value: "Suspicious Activity", placeholder: "Suspicious PowerShell EncodedCommand" },
      { k: "product", label: "logsource product", type: "text", value: "windows", placeholder: "windows" },
      { k: "category", label: "logsource category", type: "text", value: "process_creation", placeholder: "process_creation" },
      { k: "selection", label: "Selection (field: value, one per line)", type: "textarea", rows: 5, placeholder: "Image|endswith: \\powershell.exe\nCommandLine|contains: -enc" },
      { k: "level", label: "level", type: "select", opts: ["low", "medium", "high", "critical"], value: "high" }],
    run(v) {
      const title = S(v.title).trim() || "Untitled Rule";
      const sel = S(v.selection).split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
      const L = ["title: " + title, "status: experimental", "description: Describe what this rule detects", "logsource:"];
      L.push("    product: " + (S(v.product).trim() || "windows"));
      if (S(v.category).trim()) L.push("    category: " + S(v.category).trim());
      L.push("detection:", "    selection:");
      if (!sel.length) L.push("        FieldName|contains: value");
      for (const line of sel) { const m = line.match(/^(.+?):\s*(.*)$/); L.push("        " + (m ? m[1] + ": " + m[2] : line)); }
      L.push("    condition: selection", "falsepositives:", "    - Unknown", "level: " + v.level);
      return L.join("\n");
    } },

  { id: "bi-vt-url", name: "VirusTotal Report URL Builder", cat: "bininspect", desc: "Build the VirusTotal GUI URL for a pasted hash, IP, domain or URL so you can open the report yourself. Only formats a link - it does not query anything.", tags: ["virustotal", "vt", "url", "report", "hash", "lookup"],
    inputs: [{ k: "ioc", label: "Hash / IP / domain / URL", type: "text", placeholder: "44d88612fea8a8f36de82e1278abb02f" }],
    run(v) {
      const s = S(v.ioc).trim(); if (!s) return "";
      const base = "https://www.virustotal.com/gui/";
      if (/^[a-f0-9]{64}$|^[a-f0-9]{40}$|^[a-f0-9]{32}$/i.test(s)) return base + "file/" + s.toLowerCase();
      if (/^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(s)) return base + "ip-address/" + s;
      if (/^https?:\/\//i.test(s)) return base + "search/" + encodeURIComponent(s);
      if (/^(?:[a-z0-9-]+\.)+[a-z]{2,}$/i.test(s)) return base + "domain/" + s.toLowerCase();
      return base + "search/" + encodeURIComponent(s);
    } },

  { id: "bi-base64-inspect", name: "Base64 String Inspector", cat: "bininspect", desc: "Analyse one base64 string: whether it is valid (standard or URL-safe), padding, decoded byte length, printable ratio, and any file signature of the decoded bytes.", tags: ["base64", "inspect", "validate", "analyze", "magic"],
    inputs: [{ k: "b64", label: "Base64 string", type: "textarea", rows: 3, placeholder: "TVqQAAMAAAAEAAAA//8AALg..." }],
    run(v) {
      const s = S(v.b64).trim().replace(/\s+/g, ""); if (!s) return "";
      const urlsafe = /[-_]/.test(s), std = /^[A-Za-z0-9+/]+={0,2}$/.test(s), url = /^[A-Za-z0-9_-]+={0,2}$/.test(s);
      if (!std && !url) return { error: "Not a valid base64 string (unexpected characters)." };
      let u; try { u = b64ToU8(s); } catch (e) { return { error: "Could not decode base64." }; }
      let p = 0; for (let i = 0; i < u.length; i++) if (isPrintable(u[i])) p++;
      const head = Array.from(u.slice(0, 16), (b) => b.toString(16).padStart(2, "0")).join("");
      let magic = "(none matched)"; for (const [sig, name] of MAGICS) if (head.startsWith(sig.toLowerCase())) { magic = name; break; }
      const L = ["alphabet: " + (urlsafe ? "URL-safe" : "standard"), "padding: " + (/=+$/.test(s) ? (s.match(/=+$/)[0].length + " '='") : "none"), "decoded length: " + u.length + " bytes", "printable ratio: " + (u.length ? Math.round(p / u.length * 100) : 0) + "%", "first bytes: " + head.replace(/(..)/g, "$1 ").trim(), "file signature: " + magic];
      return L.join("\n");
    } },

  // ---------------- reference tables ----------------
  { id: "bi-winapi-reference", name: "Windows API Reference", cat: "bininspect", desc: "Explain a Windows API by name in plain language and why malware analysts commonly flag it (defensive context). Accurate curated entries only.", tags: ["winapi", "api", "windows", "malware", "reference"],
    inputs: [{ k: "q", label: "API name (e.g. VirtualAllocEx)", type: "text", placeholder: "CreateRemoteThread" }],
    run(v) {
      const q = S(v.q).trim().toLowerCase().replace(/[aw]$/, (m, i, s) => s.length > 3 ? "" : m);
      const raw = S(v.q).trim().toLowerCase();
      if (!raw) return "Known APIs (" + WINAPI.length + "): " + WINAPI.map((r) => r[0]).join(", ");
      const hit = WINAPI.find((r) => r[0].toLowerCase() === raw) || WINAPI.find((r) => r[0].toLowerCase().replace(/[aw]$/, "") === q) || WINAPI.find((r) => r[0].toLowerCase().includes(raw));
      if (!hit) return { error: "No curated entry for \"" + S(v.q).trim() + "\" (entries are limited to ones verified correct)." };
      return hit[0] + "  [" + hit[1] + ".dll]\n" + hit[2];
    } },

  { id: "bi-linux-syscall", name: "Linux x86_64 Syscall Reference", cat: "bininspect", desc: "Look up a Linux x86-64 syscall by number or name (accurate for the x86_64 ABI table).", tags: ["linux", "syscall", "x86_64", "reference", "number"],
    inputs: [{ k: "q", label: "Syscall number or name (blank = list)", type: "text", placeholder: "59" }],
    run(v) {
      const q = S(v.q).trim();
      if (!q) return Object.entries(SYSCALLS_X64).map(([n, name]) => n + "  " + name).join("\n");
      if (/^\d+$/.test(q)) { const name = SYSCALLS_X64[parseInt(q, 10)]; return name ? q + "  ->  " + name : { error: "No x86_64 syscall number " + q + " in the curated table." }; }
      const lc = q.toLowerCase();
      const exact = Object.entries(SYSCALLS_X64).find(([, name]) => name === lc);
      if (exact) return "syscall \"" + lc + "\"  ->  number " + exact[0] + " (x86_64)";
      const partial = Object.entries(SYSCALLS_X64).filter(([, name]) => name.includes(lc));
      return partial.length ? partial.map(([n, name]) => n + "  " + name).join("\n") : { error: "No syscall matching \"" + q + "\"." };
    } },

  { id: "bi-syscall-convention", name: "Syscall Calling Convention", cat: "bininspect", desc: "Show how Linux system calls pass their number and arguments per architecture (x86_64, i386, ARM, AArch64).", tags: ["syscall", "convention", "registers", "abi", "arm", "x86"],
    inputs: [{ k: "q", label: "Architecture filter (blank = all)", type: "text", placeholder: "x86_64" }],
    run(v) { return renderTable(SYSCALL_ABI, v.q); } },

  { id: "bi-x86-mnemonic", name: "x86 / x64 Mnemonic Reference", cat: "bininspect", desc: "Explain what a common x86/x64 assembly mnemonic does (mov, lea, call, xor, syscall, ...).", tags: ["x86", "x64", "assembly", "mnemonic", "instruction", "disassembly"],
    inputs: [{ k: "q", label: "Mnemonic (blank = list)", type: "text", placeholder: "lea" }],
    run(v) {
      const q = S(v.q).trim().toLowerCase(); if (!q) return X86_MNEM.map((r) => r[0]).join(", ");
      const hit = X86_MNEM.find((r) => r[0] === q);
      if (hit) return hit[0] + " - " + hit[1];
      const partial = X86_MNEM.filter((r) => r[0].startsWith(q));
      return partial.length ? partial.map((r) => r[0] + " - " + r[1]).join("\n") : { error: "No curated entry for mnemonic \"" + q + "\"." };
    } },

  { id: "bi-x86-opcode", name: "x86 Common Opcode Reference", cat: "bininspect", desc: "Look up well-known x86 opcode bytes (0x90 NOP, 0xCC INT3, 0xC3 RET, 0xE8 CALL, 0x0F05 SYSCALL, ...).", tags: ["x86", "opcode", "byte", "shellcode", "nop", "int3"],
    inputs: [{ k: "q", label: "Opcode byte or keyword (blank = list)", type: "text", placeholder: "CC" }],
    run(v) {
      const q = S(v.q).trim().toLowerCase().replace(/^0x/, "");
      if (!q) return X86_OPCODES.map((r) => r[0].padEnd(7) + "  " + r[1]).join("\n");
      const hits = X86_OPCODES.filter((r) => r[0].toLowerCase().includes(q) || r[1].toLowerCase().includes(q));
      return hits.length ? hits.map((r) => r[0].padEnd(7) + "  " + r[1]).join("\n") : { error: "No opcode entry matching \"" + S(v.q).trim() + "\"." };
    } },

  { id: "bi-x86-registers", name: "x86 / x64 Register Reference", cat: "bininspect", desc: "Show the x86/x64 register size mapping (RAX/EAX/AX/AL ...) and each register's typical role.", tags: ["x86", "x64", "registers", "rax", "reference"],
    inputs: [{ k: "q", label: "Register filter (blank = full table)", type: "text", placeholder: "rsi" }],
    run(v) {
      const q = S(v.q).trim().toLowerCase(); const rows = X86_REGS.split("\n");
      if (!q) return X86_REGS;
      const hits = rows.filter((r, i) => i === 0 || r.toLowerCase().includes(q));
      return hits.length > 1 ? hits.join("\n") : { error: "No register row matching \"" + q + "\"." };
    } },

  { id: "bi-eflags", name: "x86 EFLAGS Decoder", cat: "bininspect", desc: "Decode an x86 EFLAGS value into the status flags set (CF, ZF, SF, OF, DF, ...).", tags: ["eflags", "flags", "x86", "zero flag", "carry"],
    inputs: [{ k: "val", label: "EFLAGS value (prefix 0x for hex)", type: "text", placeholder: "0x0246" }],
    run(v) {
      const n = pint(v.val); if (n == null) return "";
      const set = EFLAGS.filter(([bit]) => (n & bit) === bit).map(([, name]) => "  " + name);
      return hx(n >>> 0, 4) + "\n" + (set.length ? set.join("\n") : "  (no tracked flags set)");
    } },

  { id: "bi-abi-convention", name: "Calling Convention Reference", cat: "bininspect", desc: "Show how function arguments and return values are passed for common calling conventions (System V AMD64, Microsoft x64, cdecl, stdcall, fastcall, thiscall).", tags: ["abi", "calling convention", "stdcall", "cdecl", "systemv", "x64"],
    inputs: [{ k: "q", label: "Convention filter (blank = all)", type: "text", placeholder: "stdcall" }],
    run(v) { return renderTable(ABI, v.q); } },

  { id: "bi-win-memprotect", name: "Windows Memory Protection Constants", cat: "bininspect", desc: "Decode a Windows memory protection value (PAGE_*) such as 0x40 = PAGE_EXECUTE_READWRITE, including modifiers like PAGE_GUARD.", tags: ["pageprotect", "virtualalloc", "rwx", "memory", "windows"],
    inputs: [{ k: "val", label: "Protection value (prefix 0x), blank = list", type: "text", placeholder: "0x40" }],
    run(v) {
      const q = S(v.val).trim();
      if (!q) return Object.entries(MEMPROT).map(([k, n]) => hx(Number(k), 2) + "  " + n).join("\n") + "\nmodifiers: " + MEMPROT_MOD.map(([b, n]) => hx(b) + " " + n).join(", ");
      const n = pint(q); if (n == null) return { error: "Could not parse the value." };
      const base = n & 0xff, name = MEMPROT[base];
      if (!name) return { error: "No base PAGE_* constant for " + hx(base, 2) + "." };
      const mods = MEMPROT_MOD.filter(([b]) => (n & b) === b).map(([, nm]) => nm);
      const danger = base === 0x40 || base === 0x80 ? "  [!] writable + executable (common in shellcode/injection)" : "";
      return hx(n >>> 0) + "  ->  " + name + (mods.length ? " | " + mods.join(" | ") : "") + danger;
    } },

  { id: "bi-lolbas", name: "LOLBAS Reference", cat: "bininspect", desc: "Explain how a built-in Windows binary (certutil, mshta, rundll32, regsvr32, ...) is abused to live off the land. Defensive reference.", tags: ["lolbas", "lolbin", "living off the land", "certutil", "rundll32"],
    inputs: [{ k: "q", label: "Binary name or keyword (blank = list)", type: "text", placeholder: "certutil" }],
    run(v) {
      const q = S(v.q).trim().toLowerCase();
      if (!q) return LOLBAS.map((r) => r[0]).join(", ");
      const hits = LOLBAS.filter((r) => r[0].toLowerCase().includes(q) || r[1].toLowerCase().includes(q));
      return hits.length ? hits.map((r) => r[0] + "\n  " + r[1]).join("\n\n") : { error: "No curated LOLBAS entry matching \"" + q + "\"." };
    } },

  { id: "bi-registry-autorun", name: "Registry Autorun / Persistence Reference", cat: "bininspect", desc: "Reference of common Windows registry autorun and persistence locations (Run keys, Winlogon, services, IFEO).", tags: ["registry", "persistence", "autorun", "run key", "winlogon"],
    inputs: [{ k: "q", label: "Filter (blank = full list)", type: "text", placeholder: "winlogon" }],
    run(v) {
      const q = S(v.q).trim().toLowerCase();
      const rows = REG_AUTORUN;
      const hits = q ? rows.filter((r) => r.join(" ").toLowerCase().includes(q)) : rows;
      if (!hits.length) return { error: "No location matching \"" + q + "\"." };
      return hits.map((r) => r[0] + "\n  " + r[1]).join("\n\n");
    } },

  { id: "bi-attack-lookup", name: "MITRE ATT&CK Technique Lookup", cat: "bininspect", desc: "Look up a MITRE ATT&CK Enterprise technique by T-number or keyword, with its name and tactic. Curated accurate subset.", tags: ["mitre", "att&ck", "technique", "ttp", "tactic"],
    inputs: [{ k: "q", label: "Technique ID or keyword (e.g. T1059 or powershell)", type: "text", placeholder: "T1055" }],
    run(v) {
      const q = S(v.q).trim().toLowerCase(); if (!q) return "Curated techniques (" + ATTACK.length + "). Search by T-number or keyword, e.g. T1059 or 'injection'.";
      const hits = ATTACK.filter((r) => r[0].toLowerCase() === q || r[0].toLowerCase().startsWith(q) || r[1].toLowerCase().includes(q) || r[2].toLowerCase().includes(q));
      return hits.length ? hits.map((r) => r[0] + "  " + r[1] + "  [" + r[2] + "]").join("\n") : { error: "No curated ATT&CK entry matching \"" + S(v.q).trim() + "\"." };
    } },

  { id: "bi-attack-tactics", name: "MITRE ATT&CK Tactics Reference", cat: "bininspect", desc: "List the 14 MITRE ATT&CK Enterprise tactics with their TA numbers, or look one up by name/number.", tags: ["mitre", "att&ck", "tactics", "ta", "reference"],
    inputs: [{ k: "q", label: "Filter (blank = all 14)", type: "text", placeholder: "persistence" }],
    run(v) { return renderTable(TACTICS, v.q); } },

  { id: "bi-killchain", name: "Cyber Kill Chain Reference", cat: "bininspect", desc: "Reference for the 7 phases of the Lockheed Martin Cyber Kill Chain, from Reconnaissance to Actions on Objectives.", tags: ["kill chain", "lockheed", "phases", "reference"],
    inputs: [{ k: "q", label: "Filter (blank = all phases)", type: "text", placeholder: "delivery" }],
    run(v) {
      const q = S(v.q).trim().toLowerCase(); const hits = q ? KILLCHAIN.filter((r) => r.join(" ").toLowerCase().includes(q)) : KILLCHAIN;
      if (!hits.length) return { error: "No phase matching \"" + q + "\"." };
      return hits.map((r) => r[0] + ". " + r[1] + " - " + r[2]).join("\n");
    } },

  { id: "bi-diamond-model", name: "Diamond Model Reference", cat: "bininspect", desc: "Reference for the four core features of the Diamond Model of intrusion analysis (Adversary, Capability, Infrastructure, Victim).", tags: ["diamond model", "intrusion", "analysis", "reference"],
    inputs: [{ k: "q", label: "Filter (blank = all)", type: "text", placeholder: "infrastructure" }],
    run(v) {
      const q = S(v.q).trim().toLowerCase(); const hits = q ? DIAMOND.filter((r) => r.join(" ").toLowerCase().includes(q)) : DIAMOND;
      if (!hits.length) return { error: "No feature matching \"" + q + "\"." };
      return hits.map((r) => r[0] + " - " + r[1]).join("\n");
    } },

  { id: "bi-pyramid-of-pain", name: "Pyramid of Pain Reference", cat: "bininspect", desc: "Reference for the Pyramid of Pain, ranking indicator types by how much disrupting them hurts an attacker (hashes easiest, TTPs hardest).", tags: ["pyramid of pain", "indicators", "ttp", "reference"],
    inputs: [{ k: "q", label: "Filter (blank = all)", type: "text", placeholder: "ttp" }],
    run(v) {
      const q = S(v.q).trim().toLowerCase(); const hits = q ? PYRAMID.filter((r) => r.join(" ").toLowerCase().includes(q)) : PYRAMID;
      if (!hits.length) return { error: "No level matching \"" + q + "\"." };
      return hits.map((r) => r[0] + " - " + r[1]).join("\n");
    } },

  { id: "bi-tlp", name: "Traffic Light Protocol (TLP) Reference", cat: "bininspect", desc: "Explain the FIRST TLP 2.0 sharing levels (RED, AMBER, AMBER+STRICT, GREEN, CLEAR) used to label threat-intel sensitivity.", tags: ["tlp", "traffic light protocol", "sharing", "threat intel", "first"],
    inputs: [{ k: "q", label: "Level filter (blank = all)", type: "text", placeholder: "amber" }],
    run(v) {
      const q = S(v.q).trim().toLowerCase(); const hits = q ? TLP.filter((r) => r.join(" ").toLowerCase().includes(q)) : TLP;
      if (!hits.length) return { error: "No TLP level matching \"" + q + "\"." };
      return hits.map((r) => r[0] + "\n  " + r[1]).join("\n\n");
    } },

  { id: "bi-dll-reference", name: "Windows DLL Reference", cat: "bininspect", desc: "Explain what a common Windows DLL provides (kernel32, ntdll, ws2_32, advapi32, ...), to interpret a sample's imports.", tags: ["dll", "windows", "imports", "kernel32", "ntdll", "reference"],
    inputs: [{ k: "q", label: "DLL name or keyword (blank = list)", type: "text", placeholder: "ws2_32" }],
    run(v) {
      const q = S(v.q).trim().toLowerCase().replace(/\.dll$/, "");
      if (!q) return WIN_DLLS.map((r) => r[0]).join(", ");
      const hits = WIN_DLLS.filter((r) => r[0].toLowerCase().replace(/\.dll$/, "").includes(q) || r[1].toLowerCase().includes(q));
      return hits.length ? hits.map((r) => r[0] + "\n  " + r[1]).join("\n\n") : { error: "No curated DLL entry matching \"" + q + "\"." };
    } },

  { id: "bi-packer-sections", name: "Packer Section-Name Hints", cat: "bininspect", desc: "Map a PE section name to the packer that typically produces it (UPX0/UPX1 = UPX, .aspack = ASPack, ...). A hint, not proof.", tags: ["packer", "upx", "aspack", "section", "sections", "obfuscation"],
    inputs: [{ k: "q", label: "Section name or packer (blank = list)", type: "text", placeholder: "UPX1" }],
    run(v) {
      const q = S(v.q).trim().toLowerCase();
      if (!q) return PACKERS.map((r) => r[0] + "  ->  " + r[1]).join("\n");
      const hits = PACKERS.filter((r) => r.join(" ").toLowerCase().includes(q));
      return hits.length ? hits.map((r) => r[0] + "  ->  " + r[1]).join("\n") : "No known packer uses a section named \"" + S(v.q).trim() + "\" (unusual/unique section names can themselves be a signal).";
    } },

];
