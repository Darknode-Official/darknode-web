// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
//
// Linux Internals for Security — Comprehensive Reference
// Covers process memory layout, ELF internals, capabilities, persistence,
// container security, audit framework, and hardening.

// ============================================================================
// LINUX PROCESS MEMORY LAYOUT
// ============================================================================
export const PROCESS_MEMORY_LAYOUT = {
  description: "Virtual memory layout of a Linux process (x86-64). Addresses are typical defaults — ASLR randomizes these at runtime.",
  regions: [
    { name: "Kernel Space", address_range: "0xFFFF800000000000 — 0xFFFFFFFFFFFFFFFF", description: "Kernel code and data. Inaccessible from user mode. Mapped into every process's address space but protected by page table permissions.", writable: false, executable: false },
    { name: "Stack", address_range: "~0x7FFFFFFDE000 (grows down)", description: "Thread stack. Local variables, return addresses, saved registers. Stack smashing targets return addresses here.", writable: true, executable: false, notes: "Default 8MB limit (ulimit -s). Guard page at bottom detects overflow. Stack canaries (SSP) protect return addresses." },
    { name: "Memory-mapped region", address_range: "Variable (between heap and stack)", description: "mmap'd files, shared libraries, anonymous mappings. Shared libraries (.so) loaded here by ld-linux.", writable: "varies", executable: "varies" },
    { name: "Heap", address_range: "After BSS (grows up)", description: "Dynamic allocations (malloc/new). Managed by glibc allocator (ptmalloc2). Heap overflow and use-after-free bugs target this region.", writable: true, executable: false, notes: "brk() extends the heap. Large allocations use mmap instead." },
    { name: "BSS", address_range: "After Data", description: "Uninitialized global/static variables. Zeroed at process start. Named 'Block Started by Symbol'.", writable: true, executable: false },
    { name: "Data", address_range: "After Text", description: "Initialized global/static variables. Contains values set at compile time.", writable: true, executable: false },
    { name: "Text (Code)", address_range: "~0x400000 (PIE: randomized)", description: "Executable code. Read-only, executable. Marked non-writable to prevent code modification. ROP gadgets are found here.", writable: false, executable: true, notes: "PIE (Position-Independent Executable) randomizes base address via ASLR." },
    { name: "ELF Headers", address_range: "Start of text segment", description: "ELF magic, program headers, section headers. Parsed by the kernel and dynamic linker.", writable: false, executable: false },
  ],
  protections: [
    { name: "ASLR", description: "Address Space Layout Randomization. Randomizes stack, heap, mmap, libraries, and (with PIE) text base address. Check: cat /proc/sys/kernel/randomize_va_space (0=off, 1=partial, 2=full).", bypass: "Information leak (format string, partial overwrite), brute force (32-bit has limited entropy)" },
    { name: "NX/DEP (W^X)", description: "No-Execute bit. Memory pages are either writable OR executable, never both. Stack and heap are non-executable.", bypass: "ROP/JOP (reuse existing executable code), mprotect() to make memory executable" },
    { name: "Stack Canaries (SSP)", description: "Random value placed between local variables and return address. Checked before function returns. Terminator canary includes null byte.", bypass: "Leak canary via format string or partial overwrite, brute force (forking servers)" },
    { name: "RELRO", description: "Relocation Read-Only. Partial: GOT is read-only after relocation. Full: entire GOT is read-only (lazy binding disabled).", bypass: "Partial RELRO: overwrite GOT entries. Full RELRO: target other writable structures" },
    { name: "PIE", description: "Position-Independent Executable. Text segment base randomized by ASLR. Combined with ASLR makes all addresses unpredictable.", bypass: "Requires text base leak. Partial overwrite of lowest bytes." },
    { name: "FORTIFY_SOURCE", description: "Compile-time and runtime buffer overflow checks for common functions (memcpy, strcpy, printf, etc.). Replaces vulnerable functions with checked versions.", bypass: "Doesn't cover all functions, only works with known buffer sizes" },
    { name: "seccomp", description: "Secure Computing mode. Restricts system calls a process can make. BPF filter mode allows fine-grained syscall filtering.", bypass: "Allowed syscalls may be chained, seccomp-bpf filter bugs" },
  ],
};

// ============================================================================
// ELF FILE FORMAT
// ============================================================================
export const ELF_FORMAT = {
  description: "Executable and Linkable Format — standard binary format on Linux. Understanding ELF structure is essential for reverse engineering, malware analysis, and exploit development.",
  header: {
    fields: [
      { offset: "0x00", size: 4, name: "e_ident[EI_MAG]", description: "Magic bytes: 0x7F 'E' 'L' 'F'" },
      { offset: "0x04", size: 1, name: "e_ident[EI_CLASS]", description: "1 = 32-bit, 2 = 64-bit" },
      { offset: "0x05", size: 1, name: "e_ident[EI_DATA]", description: "1 = little-endian, 2 = big-endian" },
      { offset: "0x06", size: 1, name: "e_ident[EI_VERSION]", description: "ELF version (always 1)" },
      { offset: "0x07", size: 1, name: "e_ident[EI_OSABI]", description: "OS/ABI: 0=System V, 3=Linux, 9=FreeBSD" },
      { offset: "0x10", size: 2, name: "e_type", description: "1=REL (relocatable), 2=EXEC (executable), 3=DYN (shared object/PIE), 4=CORE" },
      { offset: "0x12", size: 2, name: "e_machine", description: "Architecture: 3=x86, 0x3E=x86-64, 0xB7=AArch64" },
      { offset: "0x18", size: 8, name: "e_entry", description: "Entry point virtual address — execution starts here" },
      { offset: "0x20", size: 8, name: "e_phoff", description: "Program header table offset" },
      { offset: "0x28", size: 8, name: "e_shoff", description: "Section header table offset" },
      { offset: "0x34", size: 2, name: "e_phentsize", description: "Size of one program header entry" },
      { offset: "0x36", size: 2, name: "e_phnum", description: "Number of program header entries" },
      { offset: "0x3A", size: 2, name: "e_shentsize", description: "Size of one section header entry" },
      { offset: "0x3C", size: 2, name: "e_shnum", description: "Number of section header entries" },
    ],
  },
  sections: [
    { name: ".text", description: "Executable code — the compiled program instructions", flags: "SHF_ALLOC | SHF_EXECINSTR" },
    { name: ".rodata", description: "Read-only data — string literals, constants", flags: "SHF_ALLOC" },
    { name: ".data", description: "Initialized writable data — global variables with initial values", flags: "SHF_ALLOC | SHF_WRITE" },
    { name: ".bss", description: "Uninitialized data — zeroed at load time, takes no space on disk", flags: "SHF_ALLOC | SHF_WRITE" },
    { name: ".plt", description: "Procedure Linkage Table — stub code for lazy dynamic linking", flags: "SHF_ALLOC | SHF_EXECINSTR" },
    { name: ".plt.got", description: "PLT entries that go directly to GOT (no lazy binding)", flags: "SHF_ALLOC | SHF_EXECINSTR" },
    { name: ".got", description: "Global Offset Table — pointers to global data", flags: "SHF_ALLOC | SHF_WRITE" },
    { name: ".got.plt", description: "GOT entries for PLT (function pointers resolved at runtime)", flags: "SHF_ALLOC | SHF_WRITE", notes: "GOT overwrite attack target — replace function pointer to hijack control flow" },
    { name: ".dynamic", description: "Dynamic linking info — needed libraries, symbol tables, relocation tables", flags: "SHF_ALLOC | SHF_WRITE" },
    { name: ".dynsym", description: "Dynamic symbol table — symbols for dynamic linking", flags: "SHF_ALLOC" },
    { name: ".dynstr", description: "Dynamic string table — names for dynamic symbols", flags: "SHF_ALLOC" },
    { name: ".rel.plt / .rela.plt", description: "Relocation entries for PLT — tell the linker where to patch", flags: "SHF_ALLOC" },
    { name: ".init", description: "Initialization code — runs before main()", flags: "SHF_ALLOC | SHF_EXECINSTR" },
    { name: ".fini", description: "Finalization code — runs after main() returns", flags: "SHF_ALLOC | SHF_EXECINSTR" },
    { name: ".init_array", description: "Array of function pointers called before main() — constructor attribute", flags: "SHF_ALLOC | SHF_WRITE", notes: "Overwrite target for persistent code execution" },
    { name: ".fini_array", description: "Array of function pointers called after main() — destructor attribute", flags: "SHF_ALLOC | SHF_WRITE", notes: "Overwrite target — called during exit()" },
    { name: ".interp", description: "Path to the dynamic linker (e.g., /lib64/ld-linux-x86-64.so.2)", flags: "SHF_ALLOC" },
    { name: ".note.gnu.build-id", description: "Unique build identifier hash", flags: "SHF_ALLOC" },
    { name: ".eh_frame", description: "Exception handling frame data — used for stack unwinding", flags: "SHF_ALLOC", notes: "Contains ROP gadget metadata that can aid exploitation" },
    { name: ".comment", description: "Compiler version string", flags: "none" },
    { name: ".symtab", description: "Full symbol table (stripped in release builds)", flags: "none" },
    { name: ".strtab", description: "String table for .symtab", flags: "none" },
    { name: ".shstrtab", description: "Section header string table — section names", flags: "none" },
    { name: ".debug_*", description: "DWARF debug info (debug_info, debug_abbrev, debug_line, etc.)", flags: "none", notes: "Only present in debug builds. Contains source file paths, line numbers, variable names." },
  ],
  loading_process: [
    "1. Kernel reads ELF header, validates magic bytes (0x7F ELF)",
    "2. Kernel reads program headers (PT_LOAD segments)",
    "3. Kernel maps PT_LOAD segments into memory at specified virtual addresses",
    "4. If PT_INTERP present, kernel loads the dynamic linker (ld-linux.so)",
    "5. Kernel sets up auxiliary vector (auxv) on stack with ELF info",
    "6. Control transfers to dynamic linker entry point",
    "7. Dynamic linker processes .dynamic section — loads needed shared libraries",
    "8. Dynamic linker performs relocations (R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT)",
    "9. Dynamic linker calls .init and .init_array functions",
    "10. Dynamic linker jumps to e_entry (typically _start → __libc_start_main → main)",
    "11. On exit: .fini_array and .fini functions called, then _exit() syscall",
  ],
};

// ============================================================================
// PTRACE FOR DEBUGGING AND INJECTION
// ============================================================================
export const PTRACE_REFERENCE = {
  description: "ptrace() is the Linux system call for process tracing — used by debuggers (GDB, strace) and for code injection. Allows reading/writing memory, registers, and controlling execution of another process.",
  requests: [
    { request: "PTRACE_TRACEME", description: "Child indicates it should be traced by parent. Used by debugged processes." },
    { request: "PTRACE_PEEKTEXT / PTRACE_PEEKDATA", description: "Read a word from the tracee's memory at given address." },
    { request: "PTRACE_POKETEXT / PTRACE_POKEDATA", description: "Write a word to the tracee's memory — code injection." },
    { request: "PTRACE_PEEKUSER", description: "Read from the tracee's user area (registers, signal info)." },
    { request: "PTRACE_POKEUSER", description: "Write to the tracee's user area — modify registers." },
    { request: "PTRACE_GETREGS", description: "Get all general-purpose registers." },
    { request: "PTRACE_SETREGS", description: "Set all general-purpose registers — redirect execution (change RIP/EIP)." },
    { request: "PTRACE_ATTACH", description: "Attach to running process. Sends SIGSTOP, makes caller the tracer. Requires same UID or CAP_SYS_PTRACE." },
    { request: "PTRACE_SEIZE", description: "Attach without stopping the tracee (Linux 3.4+)." },
    { request: "PTRACE_DETACH", description: "Detach from tracee, resume normal execution." },
    { request: "PTRACE_CONT", description: "Continue tracee execution (optionally deliver a signal)." },
    { request: "PTRACE_SINGLESTEP", description: "Execute one instruction and trap." },
    { request: "PTRACE_SYSCALL", description: "Continue, stopping at next syscall entry/exit — used by strace." },
    { request: "PTRACE_GETSIGINFO", description: "Get signal info for the signal that stopped the tracee." },
    { request: "PTRACE_SETSIGINFO", description: "Set signal info to be delivered." },
  ],
  injection_technique: [
    "1. ptrace(PTRACE_ATTACH, target_pid) — attach to target",
    "2. waitpid(target_pid) — wait for SIGSTOP",
    "3. ptrace(PTRACE_GETREGS, target_pid, &regs) — save original registers",
    "4. Find executable memory region from /proc/pid/maps",
    "5. ptrace(PTRACE_POKETEXT) — write shellcode one word at a time",
    "6. Modify RIP to point to shellcode: regs.rip = shellcode_addr",
    "7. ptrace(PTRACE_SETREGS, target_pid, &regs) — set modified registers",
    "8. ptrace(PTRACE_CONT) — resume, shellcode executes",
    "9. After shellcode: restore original code and registers",
    "10. ptrace(PTRACE_DETACH) — detach cleanly",
  ],
  anti_ptrace: [
    { technique: "PTRACE_TRACEME self-attach", description: "Process calls ptrace(PTRACE_TRACEME) on itself. Since only one tracer allowed, debugger can't attach.", bypass: "Patch the ptrace call, LD_PRELOAD to hook ptrace" },
    { technique: "Check /proc/self/status TracerPid", description: "Read TracerPid field — non-zero means being debugged.", bypass: "Patch file read, LD_PRELOAD hook for open/read" },
    { technique: "Check /proc/self/exe", description: "Detect if running under GDB/strace by checking parent process name.", bypass: "Rename debugger binary" },
    { technique: "Timing checks", description: "Measure execution time of code blocks — debugging significantly slows execution.", bypass: "Patch time calls, hardware breakpoints" },
    { technique: "Signal-based detection", description: "Send SIGTRAP to self — if debugger absorbs it, behavior changes.", bypass: "Forward signals to tracee" },
    { technique: "prctl(PR_SET_DUMPABLE, 0)", description: "Disables core dumps and ptrace attachment.", bypass: "Requires root/CAP_SYS_PTRACE to override" },
  ],
  security: {
    yama_ptrace_scope: [
      { value: 0, description: "Classic: any process can ptrace any other owned by the same user" },
      { value: 1, description: "Restricted: can only ptrace direct children (Ubuntu default)" },
      { value: 2, description: "Admin-only: only CAP_SYS_PTRACE can ptrace" },
      { value: 3, description: "No ptrace: ptrace completely disabled" },
    ],
    check_command: "cat /proc/sys/kernel/yama/ptrace_scope",
  },
};

// ============================================================================
// LD_PRELOAD HOOKING
// ============================================================================
export const LD_PRELOAD_REFERENCE = {
  description: "LD_PRELOAD environment variable specifies shared libraries loaded before all others. Functions in preloaded libraries override standard library functions. Used for hooking, rootkits, and debugging.",
  how_it_works: [
    "1. Set LD_PRELOAD=/path/to/hook.so (env var or /etc/ld.so.preload)",
    "2. Dynamic linker loads hook.so before libc and other libraries",
    "3. When program calls e.g. read(), the version in hook.so is called first",
    "4. Hook function can modify arguments, log calls, call original via dlsym(RTLD_NEXT, 'read')",
  ],
  common_hooks: [
    { function: "open / openat", purpose: "Hide files — return ENOENT for specific paths", rootkit_use: "Hide malware files from ls, find, stat" },
    { function: "readdir / readdir64", purpose: "Filter directory entries — hide specific filenames", rootkit_use: "Hide malware directories from directory listings" },
    { function: "stat / lstat / fstat", purpose: "Modify file metadata or hide files", rootkit_use: "Hide files, fake timestamps" },
    { function: "write", purpose: "Filter output — remove lines containing certain strings", rootkit_use: "Hide processes from ps output" },
    { function: "connect", purpose: "Intercept/redirect network connections", rootkit_use: "Redirect C2 connections, proxy traffic" },
    { function: "accept", purpose: "Monitor incoming connections", rootkit_use: "Log or filter connections" },
    { function: "execve", purpose: "Intercept process execution", rootkit_use: "Replace commands, inject into new processes" },
    { function: "ptrace", purpose: "Return success without actually tracing", rootkit_use: "Bypass anti-debug ptrace(TRACEME) checks" },
    { function: "strcmp / strncmp", purpose: "Make password comparisons always succeed", rootkit_use: "Backdoor authentication (return 0 for specific username)" },
    { function: "pam_authenticate", purpose: "Bypass PAM authentication", rootkit_use: "Accept any password for backdoor access" },
    { function: "getpwnam / getspnam", purpose: "Hide or add users", rootkit_use: "Hide backdoor accounts from /etc/passwd reads" },
    { function: "syslog / __syslog_chk", purpose: "Suppress log messages", rootkit_use: "Prevent malware activities from being logged" },
  ],
  persistence_file: "/etc/ld.so.preload",
  persistence_note: "Adding library path to /etc/ld.so.preload loads it into EVERY dynamically-linked process system-wide (including setuid). No LD_PRELOAD env var needed.",
  detection: [
    "Check LD_PRELOAD env var: env | grep LD_PRELOAD",
    "Check /etc/ld.so.preload: cat /etc/ld.so.preload",
    "Compare function addresses: nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep ' T read'",
    "Use statically-linked binaries (not affected by LD_PRELOAD)",
    "Check /proc/<pid>/maps for unexpected .so files",
    "strace on a command to see unexpected open/mmap calls",
  ],
  limitations: [
    "Does not work on statically-linked binaries",
    "Does not work on setuid binaries (LD_PRELOAD ignored for security)",
    "Can be detected by checking /proc/self/maps",
    "dlsym(RTLD_NEXT) only works if the real function exists in a later library",
  ],
};

// ============================================================================
// /proc FILESYSTEM SECURITY ENTRIES
// ============================================================================
export const PROC_FILESYSTEM = [
  { path: "/proc/[pid]/maps", description: "Memory mappings — virtual addresses, permissions, mapped files. Shows ASLR layout.", security_use: "Find executable regions for ROP, detect injected libraries, identify loaded modules" },
  { path: "/proc/[pid]/mem", description: "Direct access to process memory. Can read/write if permissions allow.", security_use: "Process memory dumping, runtime patching without ptrace" },
  { path: "/proc/[pid]/cmdline", description: "Command line arguments (null-separated)", security_use: "Discover running commands, find passwords passed as arguments" },
  { path: "/proc/[pid]/environ", description: "Environment variables (null-separated)", security_use: "Find API keys, passwords, secrets in environment" },
  { path: "/proc/[pid]/exe", description: "Symlink to the executable binary", security_use: "Identify the actual binary running (even if argv[0] is spoofed)" },
  { path: "/proc/[pid]/fd/", description: "Directory of open file descriptors (symlinks to opened files)", security_use: "Find open files, sockets, pipes. Deleted files still accessible via fd." },
  { path: "/proc/[pid]/status", description: "Human-readable process status: name, state, pid, ppid, uid, gid, groups, capabilities, TracerPid", security_use: "TracerPid > 0 means being debugged. Check capabilities." },
  { path: "/proc/[pid]/stat", description: "Machine-readable process stats: state, ppid, pgrp, session, tty, threads", security_use: "Process tree analysis, session detection" },
  { path: "/proc/[pid]/cgroup", description: "Control group membership", security_use: "Detect if running in a container (docker, lxc paths)" },
  { path: "/proc/[pid]/mountinfo", description: "Mount information for the process's mount namespace", security_use: "Container breakout analysis — find host filesystems mounted" },
  { path: "/proc/[pid]/ns/", description: "Namespace references (ipc, mnt, net, pid, user, uts)", security_use: "Identify namespace isolation, potential escape vectors" },
  { path: "/proc/[pid]/root", description: "Symlink to the process's root directory", security_use: "Shows chroot/container root. Compare to identify chroot escapes." },
  { path: "/proc/[pid]/loginuid", description: "Original login UID (survives su/sudo)", security_use: "Track original user across privilege changes — audit trail" },
  { path: "/proc/[pid]/seccomp", description: "Seccomp filter status (0=disabled, 1=strict, 2=filter)", security_use: "Check if process has syscall restrictions" },
  { path: "/proc/[pid]/task/", description: "Per-thread information subdirectories", security_use: "Thread analysis, detect injected threads" },
  { path: "/proc/self/", description: "Symlink to current process's /proc/[pid]", security_use: "Self-examination without knowing own PID" },
  { path: "/proc/sys/kernel/randomize_va_space", description: "ASLR setting: 0=off, 1=partial, 2=full", security_use: "Verify ASLR is enabled. Exploit dev: temporarily disable for testing." },
  { path: "/proc/sys/kernel/yama/ptrace_scope", description: "ptrace restriction level (0-3)", security_use: "Determine if ptrace injection is possible" },
  { path: "/proc/sys/kernel/kptr_restrict", description: "Kernel pointer restriction: 0=exposed, 1=hidden from non-root, 2=hidden from all", security_use: "Controls visibility of kernel addresses in /proc/kallsyms" },
  { path: "/proc/sys/kernel/dmesg_restrict", description: "Restrict dmesg to CAP_SYSLOG", security_use: "Prevent kernel log info leaks" },
  { path: "/proc/sys/kernel/modules_disabled", description: "Disable kernel module loading (one-way: once set to 1, can't be changed)", security_use: "Prevent rootkit kernel modules from loading" },
  { path: "/proc/sys/kernel/perf_event_paranoid", description: "perf_event access restriction level", security_use: "Restrict performance counter access (side-channel mitigation)" },
  { path: "/proc/sys/net/ipv4/ip_forward", description: "IP forwarding enable/disable", security_use: "Required for MITM attacks, check if host is routing" },
  { path: "/proc/sys/net/ipv4/conf/all/accept_redirects", description: "Accept ICMP redirects", security_use: "ICMP redirect attacks — should be disabled" },
  { path: "/proc/sys/net/ipv4/conf/all/send_redirects", description: "Send ICMP redirects", security_use: "Should be disabled on non-routers" },
  { path: "/proc/sys/net/ipv4/tcp_syncookies", description: "SYN cookie protection", security_use: "SYN flood defense — should be enabled" },
  { path: "/proc/sys/fs/suid_dumpable", description: "Core dump handling for SUID programs: 0=no dump, 1=dump, 2=suidsafe", security_use: "SUID core dumps may leak privileged memory" },
  { path: "/proc/sys/fs/protected_hardlinks", description: "Prevent hardlink abuse (must own file or have read/write)", security_use: "Mitigates hardlink race conditions and TOCTOU attacks" },
  { path: "/proc/sys/fs/protected_symlinks", description: "Restrict symlink following in world-writable sticky directories", security_use: "Mitigates symlink attacks in /tmp" },
  { path: "/proc/kallsyms", description: "Kernel symbol table with addresses (filtered by kptr_restrict)", security_use: "Kernel exploit development — find gadget addresses" },
  { path: "/proc/modules", description: "Loaded kernel modules", security_use: "Detect rootkit modules, verify security modules (apparmor, selinux)" },
  { path: "/proc/net/tcp", description: "TCP connection table", security_use: "Identify network connections without netstat/ss" },
  { path: "/proc/net/udp", description: "UDP connection table", security_use: "Identify UDP listeners" },
  { path: "/proc/version", description: "Kernel version string", security_use: "Identify kernel for exploit matching" },
  { path: "/proc/cpuinfo", description: "CPU information", security_use: "Sandbox/VM detection (hypervisor flag)" },
  { path: "/proc/mounts", description: "Currently mounted filesystems", security_use: "Find mounted filesystems, identify bind mounts for container escapes" },
];

// ============================================================================
// LINUX CAPABILITIES
// ============================================================================
export const LINUX_CAPABILITIES = [
  { cap: "CAP_CHOWN", bit: 0, description: "Change file ownership to any user/group", security: "Can chown any file — access any file by taking ownership", privesc: "Chown /etc/shadow, then read/modify passwords" },
  { cap: "CAP_DAC_OVERRIDE", bit: 1, description: "Bypass file read, write, and execute permission checks", security: "Read/write ANY file regardless of permissions", privesc: "Read /etc/shadow, write to /etc/passwd, modify /etc/sudoers" },
  { cap: "CAP_DAC_READ_SEARCH", bit: 2, description: "Bypass file read permission checks and directory read/execute", security: "Read any file, list any directory", privesc: "Read /etc/shadow, /root/.ssh/id_rsa, etc." },
  { cap: "CAP_FOWNER", bit: 3, description: "Bypass permission checks on operations that require file owner match", security: "Modify permissions, ACLs, immutable flags on any file", privesc: "chmod 777 /etc/shadow" },
  { cap: "CAP_FSETID", bit: 4, description: "Don't clear SUID/SGID bits when file is modified", security: "Maintain SUID after modification — backdoor binaries", privesc: "Modify SUID binary without losing SUID bit" },
  { cap: "CAP_KILL", bit: 5, description: "Send signals to any process (bypass permission check)", security: "Kill any process", privesc: "Kill security monitoring processes" },
  { cap: "CAP_SETGID", bit: 6, description: "Set process GID, manipulate supplementary GIDs", security: "Switch to any group", privesc: "Add self to root group, access group-restricted files" },
  { cap: "CAP_SETUID", bit: 7, description: "Set process UID", security: "Switch to any user including root (UID 0)", privesc: "setuid(0) → root shell" },
  { cap: "CAP_SETPCAP", bit: 8, description: "Modify process capabilities", security: "Grant or remove capabilities", privesc: "Grant CAP_SYS_ADMIN to self" },
  { cap: "CAP_LINUX_IMMUTABLE", bit: 9, description: "Set/clear immutable and append-only file attributes", security: "Remove immutable flag from protected files", privesc: "Modify files protected with chattr +i" },
  { cap: "CAP_NET_BIND_SERVICE", bit: 10, description: "Bind to privileged ports (< 1024)", security: "Run services on ports 80, 443 without root", privesc: "Low risk — commonly granted to web servers" },
  { cap: "CAP_NET_BROADCAST", bit: 11, description: "Make socket broadcasts and listen to multicasts", security: "Network scanning capabilities", privesc: "Low risk" },
  { cap: "CAP_NET_ADMIN", bit: 12, description: "Network administration: configure interfaces, routing, firewall, set promiscuous mode", security: "Full network control — packet capture, MITM, firewall modification", privesc: "Configure network for attacks, modify iptables, set promiscuous mode for sniffing" },
  { cap: "CAP_NET_RAW", bit: 13, description: "Use RAW and PACKET sockets", security: "Craft arbitrary network packets — ARP spoofing, port scanning, ICMP manipulation", privesc: "Network attacks, packet sniffing" },
  { cap: "CAP_IPC_LOCK", bit: 14, description: "Lock memory pages (mlock, mlockall)", security: "Prevent memory from being swapped — anti-forensics", privesc: "Low risk" },
  { cap: "CAP_IPC_OWNER", bit: 15, description: "Bypass permission checks for IPC operations", security: "Access any shared memory, message queue, semaphore", privesc: "Read IPC data from other processes" },
  { cap: "CAP_SYS_MODULE", bit: 16, description: "Load and unload kernel modules", security: "Insert kernel rootkits, bypass all security", privesc: "insmod rootkit.ko → full kernel control" },
  { cap: "CAP_SYS_RAWIO", bit: 17, description: "Raw I/O operations (ioperm, iopl, /dev/mem, /dev/kmem)", security: "Direct hardware and kernel memory access", privesc: "Read/write kernel memory, modify kernel structures" },
  { cap: "CAP_SYS_CHROOT", bit: 18, description: "Use chroot()", security: "Create chroot environments", privesc: "Chroot escape if combined with other capabilities" },
  { cap: "CAP_SYS_PTRACE", bit: 19, description: "Trace any process with ptrace()", security: "Debug, inject code into, read memory of ANY process", privesc: "Inject shellcode into root processes, dump credentials from memory" },
  { cap: "CAP_SYS_PACCT", bit: 20, description: "Configure process accounting", security: "Control audit/accounting", privesc: "Low risk" },
  { cap: "CAP_SYS_ADMIN", bit: 21, description: "Overloaded: mount, namespace, quotas, swapon, device mapping, and many more", security: "Near-root capabilities — most dangerous single capability", privesc: "Mount host filesystem in container (escape), create namespaces, set hostname, many more" },
  { cap: "CAP_SYS_BOOT", bit: 22, description: "Reboot and kexec_load", security: "Reboot system, load new kernel", privesc: "Load malicious kernel via kexec" },
  { cap: "CAP_SYS_NICE", bit: 23, description: "Set process scheduling priority", security: "Change scheduling class, priority", privesc: "CPU starvation attacks" },
  { cap: "CAP_SYS_RESOURCE", bit: 24, description: "Override resource limits (setrlimit, disk quota, etc.)", security: "Bypass ulimits and quotas", privesc: "Allocate excessive resources" },
  { cap: "CAP_SYS_TIME", bit: 25, description: "Set system clock", security: "Manipulate timestamps", privesc: "Anti-forensics — manipulate system time for log confusion" },
  { cap: "CAP_SYS_TTY_CONFIG", bit: 26, description: "Configure TTY devices", security: "Low risk", privesc: "Minimal" },
  { cap: "CAP_MKNOD", bit: 27, description: "Create special files with mknod", security: "Create device nodes", privesc: "Create device nodes that access kernel memory" },
  { cap: "CAP_LEASE", bit: 28, description: "Set file leases", security: "Low risk", privesc: "Minimal" },
  { cap: "CAP_AUDIT_WRITE", bit: 29, description: "Write to kernel audit log", security: "Inject fake audit events", privesc: "Anti-forensics — inject misleading audit records" },
  { cap: "CAP_AUDIT_CONTROL", bit: 30, description: "Configure audit subsystem", security: "Disable audit logging", privesc: "Disable auditing to hide activities" },
  { cap: "CAP_SETFCAP", bit: 31, description: "Set file capabilities", security: "Grant capabilities to any binary", privesc: "Set CAP_SYS_ADMIN on a binary → privilege escalation" },
  { cap: "CAP_MAC_OVERRIDE", bit: 32, description: "Override Mandatory Access Control (SELinux/AppArmor)", security: "Bypass all MAC restrictions", privesc: "Ignore SELinux labels and AppArmor profiles" },
  { cap: "CAP_MAC_ADMIN", bit: 33, description: "Administer MAC configuration", security: "Modify SELinux/AppArmor policies", privesc: "Weaken MAC policies to allow attacks" },
  { cap: "CAP_SYSLOG", bit: 34, description: "Use syslog(2) privileged operations", security: "Read kernel log ring buffer", privesc: "Access kernel addresses from dmesg" },
  { cap: "CAP_WAKE_ALARM", bit: 35, description: "Set wake alarm on real-time clock", security: "Low risk", privesc: "Minimal" },
  { cap: "CAP_BLOCK_SUSPEND", bit: 36, description: "Prevent system suspend", security: "Keep system awake", privesc: "Minimal" },
  { cap: "CAP_AUDIT_READ", bit: 37, description: "Read audit log via multicast netlink socket", security: "Access audit events", privesc: "Monitor security events for evasion" },
  { cap: "CAP_PERFMON", bit: 38, description: "Use perf_event subsystem", security: "Performance monitoring", privesc: "Side-channel attacks via performance counters" },
  { cap: "CAP_BPF", bit: 39, description: "Load BPF programs (eBPF)", security: "Kernel-level packet filtering, tracing, map access", privesc: "eBPF exploits for kernel code execution" },
  { cap: "CAP_CHECKPOINT_RESTORE", bit: 40, description: "Checkpoint and restore operations", security: "Process state manipulation", privesc: "CRIU-based attacks" },
];

// ============================================================================
// LINUX PERSISTENCE TECHNIQUES
// ============================================================================
export const LINUX_PERSISTENCE = [
  { technique: "Crontab", location: "/var/spool/cron/crontabs/<user>, /etc/crontab, /etc/cron.d/, /etc/cron.{hourly,daily,weekly,monthly}/", description: "Scheduled task execution. User crontabs and system crontabs.", detection: "crontab -l, ls /etc/cron*, auditd on crontab files" },
  { technique: "Systemd Service", location: "/etc/systemd/system/, ~/.config/systemd/user/", description: "Create a systemd unit that starts on boot. User units don't need root.", detection: "systemctl list-unit-files, check for unusual .service files" },
  { technique: "Systemd Timer", location: "/etc/systemd/system/, ~/.config/systemd/user/", description: "Systemd timer units for scheduled execution (modern cron replacement).", detection: "systemctl list-timers, check for unusual .timer files" },
  { technique: "Init Scripts (SysV)", location: "/etc/init.d/, /etc/rc.local", description: "Legacy init scripts. rc.local runs at boot on some systems.", detection: "ls /etc/init.d/, cat /etc/rc.local" },
  { technique: "Shell Profile/RC", location: "~/.bashrc, ~/.bash_profile, ~/.profile, ~/.zshrc, /etc/profile, /etc/profile.d/, /etc/bash.bashrc", description: "Execute commands when user opens a shell. Profile runs on login, RC on every interactive shell.", detection: "Check for unexpected commands in shell configs, timestamp monitoring" },
  { technique: "SSH Authorized Keys", location: "~/.ssh/authorized_keys, ~/.ssh/authorized_keys2", description: "Add attacker's public key for passwordless SSH access.", detection: "Check authorized_keys for unknown keys, auditd on file" },
  { technique: "SSH RC", location: "~/.ssh/rc, /etc/ssh/sshrc", description: "Script executed on every SSH login. Runs before user's shell.", detection: "Check for existence of ssh rc files" },
  { technique: "LD_PRELOAD / ld.so.preload", location: "/etc/ld.so.preload, LD_PRELOAD env var", description: "Load malicious shared library into every process. Global hooking.", detection: "cat /etc/ld.so.preload, env | grep LD_PRELOAD, check /proc/pid/maps" },
  { technique: "Kernel Module", location: "/lib/modules/$(uname -r)/", description: "Load malicious kernel module (rootkit). Survives reboot via /etc/modules or modprobe.d.", detection: "lsmod, check /etc/modules, /etc/modprobe.d/, module signature verification" },
  { technique: "PAM Backdoor", location: "/etc/pam.d/, /lib/security/", description: "Modify PAM configuration or replace PAM module to accept a backdoor password.", detection: "Check PAM config integrity, compare PAM module hashes" },
  { technique: "MOTD (Message of the Day)", location: "/etc/update-motd.d/", description: "Scripts in update-motd.d run as root when user logs in.", detection: "Check script permissions and contents in update-motd.d" },
  { technique: "Udev Rules", location: "/etc/udev/rules.d/", description: "Udev rules execute commands when hardware events occur (device plug).", detection: "Check for unusual udev rules" },
  { technique: "XDG Autostart", location: "~/.config/autostart/, /etc/xdg/autostart/", description: "Desktop entry files run on graphical login.", detection: "Check .desktop files in autostart directories" },
  { technique: "Git Hooks", location: ".git/hooks/ in any repository", description: "Git hooks execute on git operations (pre-commit, post-checkout, etc.).", detection: "Check git hooks in repositories" },
  { technique: "Apt/Dpkg Hooks", location: "/etc/apt/apt.conf.d/", description: "APT hooks run on package operations (install, update, upgrade).", detection: "Check apt.conf.d for unusual files" },
  { technique: "Trap / Signal Handler", location: "In running shell session", description: "Set trap on EXIT, DEBUG, or other signals to run commands on shell events.", detection: "trap -p in running shells" },
  { technique: "At Jobs", location: "/var/spool/at/", description: "One-time scheduled command execution with 'at' command.", detection: "atq, ls /var/spool/at/" },
  { technique: "Socket/xinetd Service", location: "/etc/xinetd.d/, systemd socket units", description: "Create a listening service that activates on connection.", detection: "Check xinetd configs, systemctl list-sockets" },
  { technique: "Shared Library Injection", location: "/etc/ld.so.conf.d/", description: "Add directory to library search path via ld.so.conf. Place malicious library with same name as legitimate one.", detection: "ldconfig -p, check ld.so.conf.d for unusual entries" },
  { technique: "SUID Binary", location: "Anywhere on filesystem", description: "Create or modify a SUID binary that provides root access.", detection: "find / -perm -4000 -type f, compare against known SUID list" },
  { technique: "Docker Container", location: "Docker daemon", description: "Create a privileged container with host filesystem mounted. Persists through Docker restarts.", detection: "docker ps -a, check for containers with host mounts" },
];

// ============================================================================
// IPTABLES/NFTABLES REFERENCE
// ============================================================================
export const FIREWALL_REFERENCE = {
  iptables: {
    tables: [
      { name: "filter", description: "Default table. INPUT, FORWARD, OUTPUT chains. Accept/drop/reject packets.", use: "Firewall rules" },
      { name: "nat", description: "Network Address Translation. PREROUTING, OUTPUT, POSTROUTING chains.", use: "Port forwarding, masquerading" },
      { name: "mangle", description: "Packet alteration. All five chains.", use: "Modify TTL, TOS, mark packets" },
      { name: "raw", description: "Before connection tracking. PREROUTING, OUTPUT.", use: "Skip conntrack, NOTRACK" },
      { name: "security", description: "SELinux security marking.", use: "MAC rules" },
    ],
    common_rules: [
      { rule: "iptables -A INPUT -p tcp --dport 22 -j ACCEPT", description: "Allow SSH" },
      { rule: "iptables -A INPUT -p tcp --dport 80 -j ACCEPT", description: "Allow HTTP" },
      { rule: "iptables -A INPUT -p tcp --dport 443 -j ACCEPT", description: "Allow HTTPS" },
      { rule: "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT", description: "Allow established connections" },
      { rule: "iptables -P INPUT DROP", description: "Default deny inbound" },
      { rule: "iptables -A INPUT -i lo -j ACCEPT", description: "Allow loopback" },
      { rule: "iptables -A INPUT -p icmp --icmp-type echo-request -j DROP", description: "Block ping" },
      { rule: "iptables -A INPUT -p tcp --dport 22 -m recent --set --name SSH", description: "Rate limit SSH (step 1)" },
      { rule: "iptables -A INPUT -p tcp --dport 22 -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP", description: "Rate limit SSH: drop after 4 attempts in 60s" },
      { rule: "iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080", description: "Redirect port 80 to 8080" },
      { rule: "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE", description: "NAT masquerade for outbound" },
      { rule: "iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT", description: "SYN flood protection" },
      { rule: "iptables -A OUTPUT -p tcp --dport 4444 -j DROP", description: "Block common reverse shell port" },
      { rule: "iptables -A INPUT -m string --algo bm --string 'cmd.exe' -j DROP", description: "Drop packets containing cmd.exe string" },
    ],
  },
  nftables: {
    description: "Successor to iptables. Single framework replacing iptables, ip6tables, arptables, ebtables.",
    common_rules: [
      { rule: "nft add table inet filter", description: "Create filter table" },
      { rule: "nft add chain inet filter input { type filter hook input priority 0 \\; policy drop \\; }", description: "Create input chain with default drop" },
      { rule: "nft add rule inet filter input tcp dport 22 accept", description: "Allow SSH" },
      { rule: "nft add rule inet filter input ct state established,related accept", description: "Allow established connections" },
      { rule: "nft add rule inet filter input iifname lo accept", description: "Allow loopback" },
      { rule: "nft list ruleset", description: "Show all rules" },
    ],
  },
};

// ============================================================================
// LINUX AUDITD REFERENCE
// ============================================================================
export const AUDITD_REFERENCE = {
  description: "Linux Audit Framework — kernel-level auditing system. Records syscalls, file access, user commands, and security events. Essential for forensics and compliance.",
  key_files: [
    { path: "/etc/audit/auditd.conf", description: "Audit daemon configuration (log size, rotation, space handling)" },
    { path: "/etc/audit/audit.rules", description: "Audit rules loaded at boot" },
    { path: "/etc/audit/rules.d/", description: "Directory for rule files (processed in order)" },
    { path: "/var/log/audit/audit.log", description: "Audit log file" },
  ],
  useful_rules: [
    { rule: "-w /etc/passwd -p wa -k passwd_changes", description: "Monitor password file modifications" },
    { rule: "-w /etc/shadow -p wa -k shadow_changes", description: "Monitor shadow file modifications" },
    { rule: "-w /etc/sudoers -p wa -k sudoers_changes", description: "Monitor sudoers modifications" },
    { rule: "-w /etc/ssh/sshd_config -p wa -k sshd_config", description: "Monitor SSH config changes" },
    { rule: "-w /var/log/ -p wa -k log_tampering", description: "Monitor log file modifications" },
    { rule: "-a always,exit -F arch=b64 -S execve -k command_execution", description: "Log all command executions (64-bit)" },
    { rule: "-a always,exit -F arch=b32 -S execve -k command_execution", description: "Log all command executions (32-bit)" },
    { rule: "-a always,exit -F arch=b64 -S connect -k network_connections", description: "Log all outbound network connections" },
    { rule: "-w /usr/bin/wget -p x -k suspicious_download", description: "Monitor wget execution" },
    { rule: "-w /usr/bin/curl -p x -k suspicious_download", description: "Monitor curl execution" },
    { rule: "-w /usr/bin/nc -p x -k netcat_usage", description: "Monitor netcat execution" },
    { rule: "-w /usr/bin/ncat -p x -k netcat_usage", description: "Monitor ncat execution" },
    { rule: "-w /usr/bin/ssh -p x -k ssh_usage", description: "Monitor SSH client usage" },
    { rule: "-a always,exit -F arch=b64 -S ptrace -k process_injection", description: "Monitor ptrace calls (injection detection)" },
    { rule: "-a always,exit -F arch=b64 -S init_module -S finit_module -k kernel_modules", description: "Monitor kernel module loading" },
    { rule: "-w /etc/crontab -p wa -k cron_changes", description: "Monitor crontab changes" },
    { rule: "-w /etc/cron.d/ -p wa -k cron_changes", description: "Monitor cron.d directory" },
    { rule: "-w /etc/ld.so.preload -p wa -k preload_changes", description: "Monitor LD_PRELOAD persistence" },
    { rule: "-w /etc/systemd/system/ -p wa -k systemd_changes", description: "Monitor systemd service changes" },
    { rule: "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k permission_changes", description: "Monitor permission changes" },
    { rule: "-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k privilege_changes", description: "Monitor UID/GID changes" },
    { rule: "-w /sbin/insmod -p x -k module_tools", description: "Monitor insmod usage" },
    { rule: "-w /sbin/modprobe -p x -k module_tools", description: "Monitor modprobe usage" },
  ],
  commands: [
    { cmd: "ausearch -k passwd_changes", description: "Search events by key" },
    { cmd: "ausearch -i -ts today", description: "Today's events (interpreted)" },
    { cmd: "ausearch -ua root -ts recent", description: "Recent root activity" },
    { cmd: "aureport --summary", description: "Summary report" },
    { cmd: "aureport -au", description: "Authentication report" },
    { cmd: "aureport -l", description: "Login report" },
    { cmd: "aureport -f", description: "File access report" },
    { cmd: "aureport -x", description: "Executable report" },
    { cmd: "auditctl -l", description: "List active rules" },
    { cmd: "auditctl -D", description: "Delete all rules" },
    { cmd: "auditctl -e 2", description: "Lock audit configuration (immutable until reboot)" },
  ],
};

// ============================================================================
// SYSTEMD SECURITY FEATURES
// ============================================================================
export const SYSTEMD_SECURITY = {
  description: "Systemd provides extensive sandboxing for services. These directives in unit files restrict what a service can do — defense in depth even if the service is compromised.",
  directives: [
    { directive: "ProtectSystem=strict", description: "Mount /usr, /boot, /efi, /etc as read-only. 'strict' makes entire filesystem read-only except paths listed in ReadWritePaths.", risk_reduction: "high" },
    { directive: "ProtectHome=true", description: "Make /home, /root, /run/user inaccessible (appear empty).", risk_reduction: "high" },
    { directive: "PrivateTmp=true", description: "Service gets its own /tmp and /var/tmp (isolated from other services).", risk_reduction: "medium" },
    { directive: "PrivateDevices=true", description: "Service can't access physical devices (/dev/sda, etc.). Gets minimal /dev with null, zero, random.", risk_reduction: "high" },
    { directive: "PrivateNetwork=true", description: "Service gets its own empty network namespace — no network access.", risk_reduction: "critical" },
    { directive: "PrivateUsers=true", description: "Service runs in a user namespace with no privileges.", risk_reduction: "high" },
    { directive: "NoNewPrivileges=true", description: "Process can't gain new privileges (no SUID, no capabilities escalation).", risk_reduction: "high" },
    { directive: "CapabilityBoundingSet=", description: "Restrict capabilities (empty = no capabilities). Whitelist needed ones.", risk_reduction: "critical" },
    { directive: "AmbientCapabilities=", description: "Capabilities granted to unprivileged service. More granular than running as root.", risk_reduction: "medium" },
    { directive: "RestrictNamespaces=true", description: "Prevent creating new namespaces (mount, user, network, etc.).", risk_reduction: "high" },
    { directive: "RestrictSUIDSGID=true", description: "Prevent creating SUID/SGID files.", risk_reduction: "medium" },
    { directive: "RestrictRealtime=true", description: "Prevent setting realtime scheduling.", risk_reduction: "low" },
    { directive: "MemoryDenyWriteExecute=true", description: "Prevent memory from being both writable and executable (W^X enforcement).", risk_reduction: "high" },
    { directive: "SystemCallFilter=@system-service", description: "Whitelist syscalls using predefined groups. Blocks dangerous syscalls.", risk_reduction: "critical" },
    { directive: "SystemCallArchitectures=native", description: "Only allow native syscall ABI (block 32-bit compat syscalls).", risk_reduction: "medium" },
    { directive: "LockPersonality=true", description: "Lock execution domain — prevent changing personality (no 32-bit compat).", risk_reduction: "low" },
    { directive: "ReadOnlyPaths=/path", description: "Make specific paths read-only.", risk_reduction: "medium" },
    { directive: "ReadWritePaths=/path", description: "Explicitly allow write access to specific paths (with ProtectSystem=strict).", risk_reduction: "n/a" },
    { directive: "InaccessiblePaths=/path", description: "Make specific paths completely inaccessible.", risk_reduction: "high" },
    { directive: "ProtectKernelTunables=true", description: "Make /proc/sys, /sys read-only.", risk_reduction: "high" },
    { directive: "ProtectKernelModules=true", description: "Prevent loading kernel modules.", risk_reduction: "critical" },
    { directive: "ProtectKernelLogs=true", description: "Deny access to kernel log ring buffer.", risk_reduction: "medium" },
    { directive: "ProtectControlGroups=true", description: "Make cgroup filesystem read-only.", risk_reduction: "medium" },
    { directive: "ProtectClock=true", description: "Prevent changing system clock.", risk_reduction: "low" },
    { directive: "ProtectHostname=true", description: "Prevent changing hostname.", risk_reduction: "low" },
    { directive: "IPAddressDeny=any", description: "Deny all network access via BPF.", risk_reduction: "critical" },
    { directive: "IPAddressAllow=127.0.0.1/8", description: "Allow only localhost.", risk_reduction: "high" },
  ],
  analyze_command: "systemd-analyze security <service-name>",
  analyze_description: "Gives a security score (0-10, lower is more secure) and lists which security features are enabled/missing.",
};

// ============================================================================
// CONTAINER SECURITY INTERNALS
// ============================================================================
export const CONTAINER_INTERNALS = {
  namespaces: [
    { ns: "pid", description: "Process ID isolation — PID 1 inside container, different PID on host. Processes can't see other namespace's processes.", escape_vector: "PID namespace escape via /proc on host, nsenter" },
    { ns: "net", description: "Network stack isolation — own interfaces, IP addresses, routing table, firewall rules.", escape_vector: "If CAP_NET_ADMIN: modify host network via shared interface" },
    { ns: "mnt", description: "Mount point isolation — own filesystem tree. Container sees its own root filesystem.", escape_vector: "Mount host filesystem if CAP_SYS_ADMIN present" },
    { ns: "uts", description: "UTS (hostname) isolation — own hostname and domain name.", escape_vector: "Low risk" },
    { ns: "ipc", description: "IPC isolation — own shared memory, semaphores, message queues.", escape_vector: "Shared IPC namespace allows cross-container communication" },
    { ns: "user", description: "User ID mapping — root (0) inside maps to non-root on host. Strongest isolation mechanism.", escape_vector: "Kernel vulnerabilities, misconfigured mappings" },
    { ns: "cgroup", description: "Cgroup isolation — can't see or modify host's cgroup hierarchy.", escape_vector: "If cgroup v1: writable cgroup release_agent for host code execution" },
    { ns: "time", description: "Clock namespace (Linux 5.6+) — own view of CLOCK_MONOTONIC and CLOCK_BOOTTIME.", escape_vector: "Low risk" },
  ],
  escape_techniques: [
    { name: "Privileged Container Escape", condition: "--privileged flag", description: "Privileged containers have all capabilities, access to host /dev, no seccomp/AppArmor. Mount host filesystem: mount /dev/sda1 /mnt; chroot /mnt; nsenter -t 1 -m -u -i -n -p -- /bin/bash." },
    { name: "Docker Socket Escape", condition: "/var/run/docker.sock mounted", description: "Docker socket allows creating new containers. Create privileged container with host root mounted: docker run -v /:/host --privileged -it ubuntu chroot /host." },
    { name: "CAP_SYS_ADMIN Abuse", condition: "CAP_SYS_ADMIN capability", description: "Mount host filesystems, manipulate namespaces. Use mount -t cgroup to write release_agent for host execution on cgroup v1." },
    { name: "Cgroup v1 Release Agent", condition: "Writable cgroup + CAP_SYS_ADMIN", description: "Create cgroup, set release_agent to payload on host filesystem, trigger by killing last process in cgroup. Payload executes on HOST." },
    { name: "Writable /proc/sys", condition: "ProtectKernelTunables not set", description: "Write to /proc/sys/kernel/core_pattern to set a program that runs on core dump. Trigger segfault — payload runs on host." },
    { name: "CAP_SYS_PTRACE Escape", condition: "CAP_SYS_PTRACE + shared PID namespace", description: "If PID namespace is shared with host, ptrace host processes. Inject shellcode into a host process." },
    { name: "Sensitive Mount Escape", condition: "/proc/sysrq-trigger, /dev, etc. mounted", description: "Various host paths mounted into container provide escape routes. /proc/sysrq-trigger can crash host." },
    { name: "RunC CVE-2019-5736", condition: "RunC < 1.0.0-rc6", description: "Overwrite host runc binary by exploiting /proc/self/exe handling. Next container start executes attacker's code on host." },
  ],
  detection: [
    "Check /.dockerenv file existence",
    "Check /proc/1/cgroup for docker/lxc/kubepods strings",
    "Check /proc/1/environ for container env vars",
    "Filesystem: overlay/aufs mount types",
    "Limited /dev entries (no physical devices)",
    "PID 1 is not init/systemd",
    "Hostname is random hex string",
    "cat /proc/self/status | grep CapEff — limited capabilities",
  ],
};

export default {
  PROCESS_MEMORY_LAYOUT,
  ELF_FORMAT,
  PTRACE_REFERENCE,
  LD_PRELOAD_REFERENCE,
  PROC_FILESYSTEM,
  LINUX_CAPABILITIES,
  LINUX_PERSISTENCE,
  FIREWALL_REFERENCE,
  AUDITD_REFERENCE,
  SYSTEMD_SECURITY,
  CONTAINER_INTERNALS,
};
