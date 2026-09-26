// Binary Analyzer — file analysis, hex viewer, PE/ELF parser, string extractor, entropy, disassembler.
// Copyright (c) 2026 Darknode-Official. All rights reserved.
const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// ─── Magic signatures for file type detection ─────────────────────────────
const MAGIC_SIGNATURES = [
  { magic: [0x4D, 0x5A], name: "PE (Windows Executable)", ext: "exe/dll/sys", type: "pe" },
  { magic: [0x7F, 0x45, 0x4C, 0x46], name: "ELF (Linux/Unix Executable)", ext: "elf/so/o", type: "elf" },
  { magic: [0xFE, 0xED, 0xFA, 0xCE], name: "Mach-O (macOS 32-bit)", ext: "macho", type: "macho32" },
  { magic: [0xFE, 0xED, 0xFA, 0xCF], name: "Mach-O (macOS 64-bit)", ext: "macho", type: "macho64" },
  { magic: [0xCF, 0xFA, 0xED, 0xFE], name: "Mach-O (macOS 64-bit LE)", ext: "macho", type: "macho64le" },
  { magic: [0xCE, 0xFA, 0xED, 0xFE], name: "Mach-O (macOS 32-bit LE)", ext: "macho", type: "macho32le" },
  { magic: [0xCA, 0xFE, 0xBA, 0xBE], name: "Mach-O Universal / Java Class", ext: "macho/class", type: "universal" },
  { magic: [0x25, 0x50, 0x44, 0x46], name: "PDF Document", ext: "pdf", type: "pdf" },
  { magic: [0x50, 0x4B, 0x03, 0x04], name: "ZIP Archive", ext: "zip/jar/apk/docx/xlsx", type: "zip" },
  { magic: [0x50, 0x4B, 0x05, 0x06], name: "ZIP Archive (empty)", ext: "zip", type: "zip" },
  { magic: [0x1F, 0x8B], name: "GZIP Archive", ext: "gz/tgz", type: "gzip" },
  { magic: [0x42, 0x5A, 0x68], name: "BZIP2 Archive", ext: "bz2", type: "bzip2" },
  { magic: [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00], name: "XZ Archive", ext: "xz", type: "xz" },
  { magic: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], name: "7-Zip Archive", ext: "7z", type: "7z" },
  { magic: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07], name: "RAR Archive", ext: "rar", type: "rar" },
  { magic: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], name: "PNG Image", ext: "png", type: "png" },
  { magic: [0xFF, 0xD8, 0xFF], name: "JPEG Image", ext: "jpg/jpeg", type: "jpeg" },
  { magic: [0x47, 0x49, 0x46, 0x38], name: "GIF Image", ext: "gif", type: "gif" },
  { magic: [0x42, 0x4D], name: "BMP Image", ext: "bmp", type: "bmp" },
  { magic: [0x49, 0x49, 0x2A, 0x00], name: "TIFF Image (LE)", ext: "tiff", type: "tiff" },
  { magic: [0x4D, 0x4D, 0x00, 0x2A], name: "TIFF Image (BE)", ext: "tiff", type: "tiff" },
  { magic: [0x52, 0x49, 0x46, 0x46], name: "RIFF Container (AVI/WAV/WebP)", ext: "avi/wav/webp", type: "riff" },
  { magic: [0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70], name: "MP4 Video", ext: "mp4/m4a/m4v", type: "mp4" },
  { magic: [0x00, 0x00, 0x00, 0x1C, 0x66, 0x74, 0x79, 0x70], name: "MP4 Video", ext: "mp4", type: "mp4" },
  { magic: [0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70], name: "MP4 Video", ext: "mp4", type: "mp4" },
  { magic: [0x4F, 0x67, 0x67, 0x53], name: "OGG Container", ext: "ogg/ogv/oga", type: "ogg" },
  { magic: [0x66, 0x4C, 0x61, 0x43], name: "FLAC Audio", ext: "flac", type: "flac" },
  { magic: [0x00, 0x61, 0x73, 0x6D], name: "WebAssembly Module", ext: "wasm", type: "wasm" },
  { magic: [0x64, 0x65, 0x78, 0x0A], name: "Android DEX", ext: "dex", type: "dex" },
  { magic: [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], name: "OLE2 Compound (MS Office legacy)", ext: "doc/xls/ppt", type: "ole2" },
  { magic: [0x4D, 0x44, 0x4D, 0x50], name: "Windows Minidump", ext: "dmp", type: "minidump" },
  { magic: [0x72, 0x65, 0x67, 0x66], name: "Windows Registry Hive", ext: "reg", type: "reghive" },
  { magic: [0x53, 0x51, 0x4C, 0x69, 0x74, 0x65], name: "SQLite Database", ext: "db/sqlite", type: "sqlite" },
  { magic: [0x23, 0x21], name: "Script (shebang)", ext: "sh/py/pl/rb", type: "script" },
];

// ─── Suspicious API imports ────────────────────────────────────────────────
const SUSPICIOUS_IMPORTS = {
  "VirtualAlloc": { risk: "high", desc: "Allocates memory — used for shellcode injection" },
  "VirtualAllocEx": { risk: "critical", desc: "Allocates memory in another process — remote code injection" },
  "VirtualProtect": { risk: "high", desc: "Changes memory page protection — may enable code execution in data regions" },
  "VirtualProtectEx": { risk: "critical", desc: "Changes protection in another process" },
  "WriteProcessMemory": { risk: "critical", desc: "Writes to another process memory — classic injection technique" },
  "ReadProcessMemory": { risk: "high", desc: "Reads another process memory — credential/data theft" },
  "CreateRemoteThread": { risk: "critical", desc: "Creates a thread in another process — primary injection method" },
  "CreateRemoteThreadEx": { risk: "critical", desc: "Extended remote thread creation" },
  "NtCreateThreadEx": { risk: "critical", desc: "Low-level thread creation — used to bypass hooks" },
  "RtlCreateUserThread": { risk: "critical", desc: "Undocumented thread creation — evasion technique" },
  "NtMapViewOfSection": { risk: "high", desc: "Maps a section into a process — process hollowing" },
  "NtUnmapViewOfSection": { risk: "high", desc: "Unmaps a section — process hollowing preparation" },
  "QueueUserAPC": { risk: "high", desc: "Queues APC to a thread — APC injection technique" },
  "NtQueueApcThread": { risk: "critical", desc: "Low-level APC injection" },
  "SetWindowsHookEx": { risk: "high", desc: "Installs a hook — DLL injection via hooks" },
  "GetProcAddress": { risk: "medium", desc: "Resolves API at runtime — may indicate API obfuscation" },
  "LoadLibrary": { risk: "medium", desc: "Loads a DLL — may load malicious libraries" },
  "LoadLibraryA": { risk: "medium", desc: "Loads a DLL (ANSI)" },
  "LoadLibraryW": { risk: "medium", desc: "Loads a DLL (Unicode)" },
  "LoadLibraryExA": { risk: "medium", desc: "Extended DLL loading" },
  "LoadLibraryExW": { risk: "medium", desc: "Extended DLL loading (Unicode)" },
  "WinExec": { risk: "high", desc: "Executes a command — simple command execution" },
  "ShellExecute": { risk: "high", desc: "Opens/executes a file or URL" },
  "ShellExecuteA": { risk: "high", desc: "Opens/executes a file (ANSI)" },
  "ShellExecuteW": { risk: "high", desc: "Opens/executes a file (Unicode)" },
  "ShellExecuteExA": { risk: "high", desc: "Extended file execution" },
  "ShellExecuteExW": { risk: "high", desc: "Extended file execution (Unicode)" },
  "CreateProcess": { risk: "medium", desc: "Creates a new process" },
  "CreateProcessA": { risk: "medium", desc: "Creates a new process (ANSI)" },
  "CreateProcessW": { risk: "medium", desc: "Creates a new process (Unicode)" },
  "CreateProcessAsUserA": { risk: "high", desc: "Creates process as another user — privilege escalation" },
  "CreateProcessWithLogonW": { risk: "high", desc: "Creates process with credentials" },
  "URLDownloadToFile": { risk: "critical", desc: "Downloads file from URL — dropper behavior" },
  "URLDownloadToFileA": { risk: "critical", desc: "Downloads file from URL (ANSI)" },
  "URLDownloadToFileW": { risk: "critical", desc: "Downloads file from URL (Unicode)" },
  "URLDownloadToCacheFile": { risk: "high", desc: "Downloads to browser cache" },
  "InternetOpen": { risk: "medium", desc: "Initializes WinInet — network communication" },
  "InternetOpenA": { risk: "medium", desc: "Initializes WinInet (ANSI)" },
  "InternetOpenUrl": { risk: "high", desc: "Opens a URL — C2 communication" },
  "InternetOpenUrlA": { risk: "high", desc: "Opens a URL (ANSI)" },
  "InternetReadFile": { risk: "medium", desc: "Reads data from URL" },
  "HttpOpenRequest": { risk: "medium", desc: "Creates HTTP request handle" },
  "HttpSendRequest": { risk: "medium", desc: "Sends HTTP request" },
  "HttpSendRequestA": { risk: "medium", desc: "Sends HTTP request (ANSI)" },
  "WSAStartup": { risk: "medium", desc: "Initializes Winsock — raw network communication" },
  "connect": { risk: "medium", desc: "Establishes network connection" },
  "send": { risk: "medium", desc: "Sends data over network" },
  "recv": { risk: "medium", desc: "Receives data from network" },
  "socket": { risk: "medium", desc: "Creates a network socket" },
  "bind": { risk: "medium", desc: "Binds socket to address — may act as server/listener" },
  "listen": { risk: "medium", desc: "Listens for connections — backdoor behavior" },
  "accept": { risk: "medium", desc: "Accepts incoming connection" },
  "RegOpenKeyEx": { risk: "medium", desc: "Opens a registry key" },
  "RegOpenKeyExA": { risk: "medium", desc: "Opens a registry key (ANSI)" },
  "RegSetValueEx": { risk: "high", desc: "Sets a registry value — persistence mechanism" },
  "RegSetValueExA": { risk: "high", desc: "Sets a registry value (ANSI)" },
  "RegCreateKeyEx": { risk: "high", desc: "Creates a registry key" },
  "RegDeleteKey": { risk: "medium", desc: "Deletes a registry key" },
  "RegDeleteValue": { risk: "medium", desc: "Deletes a registry value" },
  "OpenProcess": { risk: "high", desc: "Opens a handle to another process — required for injection" },
  "OpenProcessToken": { risk: "high", desc: "Opens a process token — token manipulation" },
  "AdjustTokenPrivileges": { risk: "critical", desc: "Modifies token privileges — privilege escalation" },
  "LookupPrivilegeValue": { risk: "medium", desc: "Looks up privilege LUID — precedes privilege adjustment" },
  "ImpersonateLoggedOnUser": { risk: "critical", desc: "Impersonates another user's token" },
  "DuplicateToken": { risk: "high", desc: "Duplicates an access token" },
  "DuplicateTokenEx": { risk: "high", desc: "Extended token duplication" },
  "CreateService": { risk: "high", desc: "Creates a Windows service — persistence" },
  "CreateServiceA": { risk: "high", desc: "Creates a Windows service (ANSI)" },
  "StartService": { risk: "medium", desc: "Starts a Windows service" },
  "ControlService": { risk: "medium", desc: "Sends control to a service" },
  "OpenSCManager": { risk: "medium", desc: "Opens Service Control Manager" },
  "CryptEncrypt": { risk: "medium", desc: "Encrypts data — may indicate ransomware" },
  "CryptDecrypt": { risk: "medium", desc: "Decrypts data" },
  "CryptGenKey": { risk: "medium", desc: "Generates cryptographic key" },
  "CryptAcquireContext": { risk: "low", desc: "Acquires crypto provider context" },
  "CryptCreateHash": { risk: "low", desc: "Creates hash object" },
  "CryptHashData": { risk: "low", desc: "Hashes data" },
  "NtSetInformationProcess": { risk: "high", desc: "Sets process info — anti-debug, process manipulation" },
  "IsDebuggerPresent": { risk: "medium", desc: "Checks for debugger — anti-analysis" },
  "CheckRemoteDebuggerPresent": { risk: "medium", desc: "Checks for remote debugger" },
  "NtQueryInformationProcess": { risk: "medium", desc: "Queries process info — anti-debug" },
  "OutputDebugString": { risk: "low", desc: "Sends string to debugger — sometimes anti-debug" },
  "GetTickCount": { risk: "low", desc: "Gets system uptime — timing-based anti-sandbox" },
  "GetTickCount64": { risk: "low", desc: "Gets system uptime (64-bit)" },
  "QueryPerformanceCounter": { risk: "low", desc: "High-resolution timer — timing checks" },
  "Sleep": { risk: "low", desc: "Delays execution — sandbox evasion via long sleep" },
  "SleepEx": { risk: "low", desc: "Extended sleep with alertable wait" },
  "MoveFileEx": { risk: "medium", desc: "Moves/renames file — can schedule deletion on reboot" },
  "DeleteFile": { risk: "medium", desc: "Deletes a file" },
  "DeleteFileA": { risk: "medium", desc: "Deletes a file (ANSI)" },
  "CopyFile": { risk: "medium", desc: "Copies a file — self-replication" },
  "FindFirstFile": { risk: "low", desc: "Enumerates files — file system discovery" },
  "FindNextFile": { risk: "low", desc: "Continues file enumeration" },
  "GetModuleFileName": { risk: "low", desc: "Gets module path — location awareness" },
  "GetModuleHandle": { risk: "low", desc: "Gets module base address" },
  "GetSystemDirectory": { risk: "low", desc: "Gets system directory path" },
  "GetTempPath": { risk: "low", desc: "Gets temp directory — common drop location" },
  "GetEnvironmentVariable": { risk: "low", desc: "Reads environment variable" },
  "SetFileAttributes": { risk: "medium", desc: "Changes file attributes — can hide files" },
  "CreateFile": { risk: "low", desc: "Opens/creates a file" },
  "DeviceIoControl": { risk: "high", desc: "Sends control code to device driver — rootkit behavior" },
  "NtSystemDebugControl": { risk: "critical", desc: "Low-level debug control — rootkit technique" },
};

// ─── Packer signatures ─────────────────────────────────────────────────────
const PACKER_SIGNATURES = [
  { name: "UPX", patterns: ["UPX0", "UPX1", "UPX2", "UPX!"], desc: "Ultimate Packer for eXecutables — most common packer, easily unpacked with 'upx -d'" },
  { name: "ASPack", patterns: [".aspack", ".adata", "ASPack"], desc: "Commercial packer — older but still seen in legacy malware" },
  { name: "Themida/WinLicense", patterns: [".themida", ".winlice", "Themida"], desc: "Advanced protector with VM-based obfuscation — very hard to unpack" },
  { name: "VMProtect", patterns: [".vmp0", ".vmp1", "VMProtect"], desc: "VM-based protection — converts code to bytecode for custom VM" },
  { name: "PECompact", patterns: ["PEC2", "PECompact2"], desc: "PE file compressor" },
  { name: "MPRESS", patterns: [".MPRESS1", ".MPRESS2"], desc: "Free PE compressor" },
  { name: "Armadillo", patterns: ["Armadillo", ".arma"], desc: "Commercial protector with nanomites and import elimination" },
  { name: "Obsidium", patterns: [".obsidium", "Obsidium"], desc: "Commercial protector" },
  { name: "Enigma", patterns: [".enigma1", ".enigma2", "Enigma protector"], desc: "Commercial protector with virtual machine" },
  { name: "PEtite", patterns: ["petite", ".petite"], desc: "PE executable compressor" },
  { name: "Exe32Pack", patterns: [".exe32pack"], desc: "Simple PE packer" },
  { name: "FSG", patterns: ["FSG!"], desc: "Fast Small Good packer" },
  { name: "MEW", patterns: ["MEW"], desc: "Minimal Executable compressor for Windows" },
  { name: "NsPack", patterns: [".nsp0", ".nsp1", "NsPack"], desc: "North Star packer" },
  { name: "PE-Armor", patterns: ["PE-Armor"], desc: "PE protection tool" },
  { name: "yoda's Protector", patterns: ["yP", ".yP"], desc: "Polymorphic protector" },
  { name: ".NET Reactor", patterns: [".reactor", "Eziriz"], desc: ".NET obfuscator and protector" },
  { name: "ConfuserEx", patterns: ["ConfuserEx", "Confuser"], desc: "Open-source .NET obfuscator" },
  { name: "SmartAssembly", patterns: ["SmartAssembly"], desc: "Commercial .NET obfuscator by Redgate" },
];

// ─── x86 opcode table (basic subset) ──────────────────────────────────────
const X86_OPCODES = {
  0x00: { mnemonic: "ADD", operands: "r/m8, r8", size: 2 },
  0x01: { mnemonic: "ADD", operands: "r/m32, r32", size: 2 },
  0x03: { mnemonic: "ADD", operands: "r32, r/m32", size: 2 },
  0x05: { mnemonic: "ADD", operands: "EAX, imm32", size: 5 },
  0x09: { mnemonic: "OR", operands: "r/m32, r32", size: 2 },
  0x0B: { mnemonic: "OR", operands: "r32, r/m32", size: 2 },
  0x0D: { mnemonic: "OR", operands: "EAX, imm32", size: 5 },
  0x21: { mnemonic: "AND", operands: "r/m32, r32", size: 2 },
  0x23: { mnemonic: "AND", operands: "r32, r/m32", size: 2 },
  0x25: { mnemonic: "AND", operands: "EAX, imm32", size: 5 },
  0x29: { mnemonic: "SUB", operands: "r/m32, r32", size: 2 },
  0x2B: { mnemonic: "SUB", operands: "r32, r/m32", size: 2 },
  0x2D: { mnemonic: "SUB", operands: "EAX, imm32", size: 5 },
  0x31: { mnemonic: "XOR", operands: "r/m32, r32", size: 2 },
  0x33: { mnemonic: "XOR", operands: "r32, r/m32", size: 2 },
  0x35: { mnemonic: "XOR", operands: "EAX, imm32", size: 5 },
  0x39: { mnemonic: "CMP", operands: "r/m32, r32", size: 2 },
  0x3B: { mnemonic: "CMP", operands: "r32, r/m32", size: 2 },
  0x3D: { mnemonic: "CMP", operands: "EAX, imm32", size: 5 },
  0x40: { mnemonic: "INC", operands: "EAX", size: 1 },
  0x41: { mnemonic: "INC", operands: "ECX", size: 1 },
  0x42: { mnemonic: "INC", operands: "EDX", size: 1 },
  0x43: { mnemonic: "INC", operands: "EBX", size: 1 },
  0x48: { mnemonic: "DEC", operands: "EAX", size: 1 },
  0x49: { mnemonic: "DEC", operands: "ECX", size: 1 },
  0x4A: { mnemonic: "DEC", operands: "EDX", size: 1 },
  0x4B: { mnemonic: "DEC", operands: "EBX", size: 1 },
  0x50: { mnemonic: "PUSH", operands: "EAX", size: 1 },
  0x51: { mnemonic: "PUSH", operands: "ECX", size: 1 },
  0x52: { mnemonic: "PUSH", operands: "EDX", size: 1 },
  0x53: { mnemonic: "PUSH", operands: "EBX", size: 1 },
  0x54: { mnemonic: "PUSH", operands: "ESP", size: 1 },
  0x55: { mnemonic: "PUSH", operands: "EBP", size: 1 },
  0x56: { mnemonic: "PUSH", operands: "ESI", size: 1 },
  0x57: { mnemonic: "PUSH", operands: "EDI", size: 1 },
  0x58: { mnemonic: "POP", operands: "EAX", size: 1 },
  0x59: { mnemonic: "POP", operands: "ECX", size: 1 },
  0x5A: { mnemonic: "POP", operands: "EDX", size: 1 },
  0x5B: { mnemonic: "POP", operands: "EBX", size: 1 },
  0x5C: { mnemonic: "POP", operands: "ESP", size: 1 },
  0x5D: { mnemonic: "POP", operands: "EBP", size: 1 },
  0x5E: { mnemonic: "POP", operands: "ESI", size: 1 },
  0x5F: { mnemonic: "POP", operands: "EDI", size: 1 },
  0x68: { mnemonic: "PUSH", operands: "imm32", size: 5 },
  0x6A: { mnemonic: "PUSH", operands: "imm8", size: 2 },
  0x70: { mnemonic: "JO", operands: "rel8", size: 2 },
  0x71: { mnemonic: "JNO", operands: "rel8", size: 2 },
  0x72: { mnemonic: "JB/JNAE", operands: "rel8", size: 2 },
  0x73: { mnemonic: "JNB/JAE", operands: "rel8", size: 2 },
  0x74: { mnemonic: "JE/JZ", operands: "rel8", size: 2 },
  0x75: { mnemonic: "JNE/JNZ", operands: "rel8", size: 2 },
  0x76: { mnemonic: "JBE/JNA", operands: "rel8", size: 2 },
  0x77: { mnemonic: "JA/JNBE", operands: "rel8", size: 2 },
  0x78: { mnemonic: "JS", operands: "rel8", size: 2 },
  0x79: { mnemonic: "JNS", operands: "rel8", size: 2 },
  0x7C: { mnemonic: "JL/JNGE", operands: "rel8", size: 2 },
  0x7D: { mnemonic: "JGE/JNL", operands: "rel8", size: 2 },
  0x7E: { mnemonic: "JLE/JNG", operands: "rel8", size: 2 },
  0x7F: { mnemonic: "JG/JNLE", operands: "rel8", size: 2 },
  0x83: { mnemonic: "CMP/ADD/SUB", operands: "r/m32, imm8", size: 3 },
  0x85: { mnemonic: "TEST", operands: "r/m32, r32", size: 2 },
  0x89: { mnemonic: "MOV", operands: "r/m32, r32", size: 2 },
  0x8B: { mnemonic: "MOV", operands: "r32, r/m32", size: 2 },
  0x8D: { mnemonic: "LEA", operands: "r32, m", size: 2 },
  0x90: { mnemonic: "NOP", operands: "", size: 1 },
  0xA1: { mnemonic: "MOV", operands: "EAX, moffs32", size: 5 },
  0xA3: { mnemonic: "MOV", operands: "moffs32, EAX", size: 5 },
  0xB8: { mnemonic: "MOV", operands: "EAX, imm32", size: 5 },
  0xB9: { mnemonic: "MOV", operands: "ECX, imm32", size: 5 },
  0xBA: { mnemonic: "MOV", operands: "EDX, imm32", size: 5 },
  0xBB: { mnemonic: "MOV", operands: "EBX, imm32", size: 5 },
  0xC2: { mnemonic: "RET", operands: "imm16", size: 3 },
  0xC3: { mnemonic: "RET", operands: "", size: 1 },
  0xC7: { mnemonic: "MOV", operands: "r/m32, imm32", size: 6 },
  0xC9: { mnemonic: "LEAVE", operands: "", size: 1 },
  0xCC: { mnemonic: "INT 3", operands: "(breakpoint)", size: 1 },
  0xCD: { mnemonic: "INT", operands: "imm8", size: 2 },
  0xE8: { mnemonic: "CALL", operands: "rel32", size: 5 },
  0xE9: { mnemonic: "JMP", operands: "rel32", size: 5 },
  0xEB: { mnemonic: "JMP", operands: "rel8", size: 2 },
  0xF4: { mnemonic: "HLT", operands: "", size: 1 },
  0xF7: { mnemonic: "NOT/NEG/MUL/DIV", operands: "r/m32", size: 2 },
  0xFF: { mnemonic: "CALL/JMP/PUSH", operands: "r/m32", size: 2 },
};

// ─── PE parsing helpers ────────────────────────────────────────────────────
function readU16LE(buf, offset) { return buf[offset] | (buf[offset + 1] << 8); }
function readU32LE(buf, offset) { return (buf[offset] | (buf[offset + 1] << 8) | (buf[offset + 2] << 16) | (buf[offset + 3] << 24)) >>> 0; }
function readString(buf, offset, maxLen) {
  var s = "";
  for (var i = 0; i < maxLen && offset + i < buf.length; i++) {
    if (buf[offset + i] === 0) break;
    s += String.fromCharCode(buf[offset + i]);
  }
  return s;
}

const PE_CHARACTERISTICS = {
  0x0001: "RELOCS_STRIPPED",
  0x0002: "EXECUTABLE_IMAGE",
  0x0004: "LINE_NUMS_STRIPPED",
  0x0008: "LOCAL_SYMS_STRIPPED",
  0x0020: "LARGE_ADDRESS_AWARE",
  0x0100: "32BIT_MACHINE",
  0x0200: "DEBUG_STRIPPED",
  0x2000: "DLL",
};

const PE_SUBSYSTEMS = {
  0: "Unknown", 1: "Native", 2: "Windows GUI", 3: "Windows Console",
  5: "OS/2 Console", 7: "POSIX Console", 9: "Windows CE",
  10: "EFI Application", 11: "EFI Boot Driver", 12: "EFI Runtime Driver",
  13: "EFI ROM Image", 14: "XBOX", 16: "Windows Boot Application",
};

const PE_MACHINES = {
  0x14C: "i386", 0x8664: "AMD64", 0x1C0: "ARM", 0xAA64: "ARM64",
  0x1C4: "ARMv7 Thumb", 0x200: "IA-64",
};

const ELF_TYPES = { 0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN (Shared/PIE)", 4: "CORE" };
const ELF_MACHINES = {
  0: "None", 3: "x86", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64",
  40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V",
};
const ELF_OSABI = {
  0: "System V", 1: "HP-UX", 2: "NetBSD", 3: "Linux",
  6: "Solaris", 7: "AIX", 8: "IRIX", 9: "FreeBSD", 12: "OpenBSD",
};

// ─── Entropy calculation ───────────────────────────────────────────────────
function calculateEntropy(data) {
  if (!data.length) return 0;
  var freq = new Array(256).fill(0);
  for (var i = 0; i < data.length; i++) freq[data[i]]++;
  var entropy = 0;
  var len = data.length;
  for (var j = 0; j < 256; j++) {
    if (freq[j] === 0) continue;
    var p = freq[j] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function entropyLabel(entropy) {
  if (entropy < 1) return "Very low (empty/uniform)";
  if (entropy < 3) return "Low (plain text)";
  if (entropy < 5) return "Medium (structured data)";
  if (entropy < 6.5) return "Moderately high (code)";
  if (entropy < 7.5) return "High (compressed/encrypted)";
  return "Very high (random/encrypted)";
}

function entropyColor(entropy) {
  if (entropy < 3) return "#4ecdc4";
  if (entropy < 5) return "#45b7d1";
  if (entropy < 6.5) return "#f39c12";
  if (entropy < 7.5) return "#e74c3c";
  return "#c0392b";
}

// ─── String extraction ─────────────────────────────────────────────────────
function extractStrings(data, minLen) {
  minLen = minLen || 4;
  var strings = [];
  var current = "";
  var startOffset = 0;
  for (var i = 0; i < data.length; i++) {
    var c = data[i];
    if (c >= 32 && c <= 126) {
      if (!current.length) startOffset = i;
      current += String.fromCharCode(c);
    } else {
      if (current.length >= minLen) {
        strings.push({ offset: startOffset, value: current, encoding: "ASCII" });
      }
      current = "";
    }
  }
  if (current.length >= minLen) strings.push({ offset: startOffset, value: current, encoding: "ASCII" });

  // Unicode (UTF-16LE) strings
  current = "";
  startOffset = 0;
  for (var j = 0; j < data.length - 1; j += 2) {
    var wc = data[j] | (data[j + 1] << 8);
    if (wc >= 32 && wc <= 126) {
      if (!current.length) startOffset = j;
      current += String.fromCharCode(wc);
    } else {
      if (current.length >= minLen) {
        var dup = false;
        for (var k = 0; k < strings.length; k++) {
          if (strings[k].value === current && Math.abs(strings[k].offset - startOffset) < 4) { dup = true; break; }
        }
        if (!dup) strings.push({ offset: startOffset, value: current, encoding: "UTF-16LE" });
      }
      current = "";
    }
  }
  if (current.length >= minLen) strings.push({ offset: startOffset, value: current, encoding: "UTF-16LE" });

  strings.sort(function(a, b) { return a.offset - b.offset; });
  return strings;
}

// ─── IoC extraction ────────────────────────────────────────────────────────
function extractIoCs(strings) {
  var iocs = { urls: [], ips: [], emails: [], registryPaths: [], filePaths: [], domains: [] };
  var urlRe = /https?:\/\/[^\s'"<>]{4,}/g;
  var ipRe = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  var emailRe = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  var regRe = /(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR)\\[^\s'"]{4,}/gi;
  var fileRe = /[A-Z]:\\[^\s'"<>]{4,}|\/(?:etc|usr|var|tmp|home|opt|root)\/[^\s'"<>]{2,}/g;
  var domRe = /\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|tk|cc|xyz|top|info|biz|pw|ws)\b/g;

  for (var i = 0; i < strings.length; i++) {
    var s = strings[i].value;
    var m;
    while ((m = urlRe.exec(s)) !== null) iocs.urls.push({ value: m[0], offset: strings[i].offset });
    urlRe.lastIndex = 0;
    while ((m = ipRe.exec(s)) !== null) {
      var parts = m[0].split(".");
      var valid = parts.every(function(p) { return parseInt(p) <= 255; });
      if (valid) iocs.ips.push({ value: m[0], offset: strings[i].offset });
    }
    ipRe.lastIndex = 0;
    while ((m = emailRe.exec(s)) !== null) iocs.emails.push({ value: m[0], offset: strings[i].offset });
    emailRe.lastIndex = 0;
    while ((m = regRe.exec(s)) !== null) iocs.registryPaths.push({ value: m[0], offset: strings[i].offset });
    regRe.lastIndex = 0;
    while ((m = fileRe.exec(s)) !== null) iocs.filePaths.push({ value: m[0], offset: strings[i].offset });
    fileRe.lastIndex = 0;
    while ((m = domRe.exec(s)) !== null) iocs.domains.push({ value: m[0], offset: strings[i].offset });
    domRe.lastIndex = 0;
  }

  // Deduplicate
  function dedup(arr) {
    var seen = {};
    return arr.filter(function(x) { if (seen[x.value]) return false; seen[x.value] = true; return true; });
  }
  iocs.urls = dedup(iocs.urls);
  iocs.ips = dedup(iocs.ips);
  iocs.emails = dedup(iocs.emails);
  iocs.registryPaths = dedup(iocs.registryPaths);
  iocs.filePaths = dedup(iocs.filePaths);
  iocs.domains = dedup(iocs.domains);
  return iocs;
}

// ─── YARA rule generator ───────────────────────────────────────────────────
function generateYARA(name, strings, data) {
  var unique = strings.filter(function(s) { return s.value.length >= 6 && s.value.length <= 200; }).slice(0, 20);
  var hexPatterns = [];
  // Find unique byte sequences near entry point or interesting sections
  if (data.length >= 16) {
    var epFileOffset = 0;
    // Try to find the PE entry point. AddressOfEntryPoint is a Relative
    // Virtual Address, not a file offset, so convert it via the section
    // table (mirroring parsePE) before indexing the raw file buffer.
    if (data[0] === 0x4D && data[1] === 0x5A && data.length > 64) {
      var peOffset = readU32LE(data, 0x3C);
      if (peOffset + 44 < data.length && data[peOffset] === 0x50 && data[peOffset + 1] === 0x45) {
        var epRVA = readU32LE(data, peOffset + 40); // AddressOfEntryPoint (RVA)
        var numSections = readU16LE(data, peOffset + 6);
        var sizeOptHdr = readU16LE(data, peOffset + 20);
        var secBase = peOffset + 24 + sizeOptHdr;
        for (var si = 0; si < numSections; si++) {
          var so = secBase + si * 40;
          if (so + 40 > data.length) break;
          var vaddr = readU32LE(data, so + 12);
          var vsize = readU32LE(data, so + 8);
          var praw = readU32LE(data, so + 20);
          if (epRVA >= vaddr && epRVA < vaddr + vsize) {
            epFileOffset = praw + (epRVA - vaddr);
            break;
          }
        }
      }
    }
    if (epFileOffset > 0 && epFileOffset + 16 <= data.length) {
      var pattern = [];
      for (var h = 0; h < 16; h++) pattern.push(data[epFileOffset + h].toString(16).padStart(2, "0").toUpperCase());
      hexPatterns.push("$entry = { " + pattern.join(" ") + " }");
    }
  }

  var lines = [];
  lines.push("rule " + name.replace(/[^a-zA-Z0-9_]/g, "_") + " {");
  lines.push("  meta:");
  lines.push('    description = "Auto-generated rule for ' + name.replace(/"/g, "'") + '"');
  lines.push('    author = "Darknode Binary Analyzer"');
  lines.push('    date = "' + new Date().toISOString().slice(0, 10) + '"');
  lines.push("");
  lines.push("  strings:");
  for (var i = 0; i < unique.length; i++) {
    var s = unique[i];
    var varName = "$s" + (i + 1);
    if (s.encoding === "UTF-16LE") {
      lines.push("    " + varName + ' = "' + s.value.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '" wide');
    } else {
      lines.push("    " + varName + ' = "' + s.value.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"');
    }
  }
  for (var j = 0; j < hexPatterns.length; j++) {
    lines.push("    " + hexPatterns[j]);
  }
  lines.push("");
  lines.push("  condition:");
  if (unique.length > 3) {
    lines.push("    " + Math.min(3, Math.ceil(unique.length / 2)) + " of ($s*)" + (hexPatterns.length ? " or $entry" : ""));
  } else if (unique.length > 0) {
    lines.push("    any of them");
  } else {
    lines.push("    true");
  }
  lines.push("}");
  return lines.join("\n");
}

// ─── Simple x86 disassembler ───────────────────────────────────────────────
function disassemble(data, baseAddr, maxInstructions) {
  maxInstructions = maxInstructions || 200;
  var instructions = [];
  var i = 0;
  var count = 0;
  while (i < data.length && count < maxInstructions) {
    var opcode = data[i];
    var info = X86_OPCODES[opcode];
    var addr = (baseAddr + i).toString(16).padStart(8, "0");
    if (info) {
      var bytes = [];
      for (var b = 0; b < info.size && i + b < data.length; b++) {
        bytes.push(data[i + b].toString(16).padStart(2, "0"));
      }
      var operandStr = info.operands;
      // Resolve immediate values and relative addresses
      if (info.operands.indexOf("imm32") >= 0 && i + 4 < data.length) {
        var imm32 = readU32LE(data, i + 1);
        operandStr = info.operands.replace("imm32", "0x" + imm32.toString(16).toUpperCase());
      } else if (info.operands.indexOf("imm16") >= 0 && i + 2 < data.length) {
        var imm16 = readU16LE(data, i + 1);
        operandStr = info.operands.replace("imm16", "0x" + imm16.toString(16).toUpperCase());
      } else if (info.operands.indexOf("imm8") >= 0 && i + 1 < data.length) {
        operandStr = info.operands.replace("imm8", "0x" + data[i + 1].toString(16).toUpperCase());
      } else if (info.operands.indexOf("rel32") >= 0 && i + 4 < data.length) {
        var rel32 = readU32LE(data, i + 1);
        if (rel32 > 0x7FFFFFFF) rel32 = rel32 - 0x100000000;
        var target = baseAddr + i + info.size + rel32;
        operandStr = info.operands.replace("rel32", "0x" + (target >>> 0).toString(16).toUpperCase());
      } else if (info.operands.indexOf("rel8") >= 0 && i + 1 < data.length) {
        var rel8 = data[i + 1];
        if (rel8 > 127) rel8 = rel8 - 256;
        var target8 = baseAddr + i + info.size + rel8;
        operandStr = info.operands.replace("rel8", "0x" + (target8 >>> 0).toString(16).toUpperCase());
      }
      instructions.push({
        address: addr,
        bytes: bytes.join(" "),
        mnemonic: info.mnemonic,
        operands: operandStr,
      });
      i += info.size;
    } else {
      instructions.push({
        address: addr,
        bytes: data[i].toString(16).padStart(2, "0"),
        mnemonic: "db",
        operands: "0x" + data[i].toString(16).padStart(2, "0"),
      });
      i += 1;
    }
    count++;
  }
  return instructions;
}

// ─── PE parser ─────────────────────────────────────────────────────────────
function parsePE(data) {
  var result = { valid: false };
  if (data[0] !== 0x4D || data[1] !== 0x5A) return result;
  result.valid = true;

  // DOS header
  result.dosHeader = {
    e_magic: "MZ",
    e_lfanew: readU32LE(data, 0x3C),
  };

  var pe = result.dosHeader.e_lfanew;
  if (pe + 24 > data.length) return result;
  if (data[pe] !== 0x50 || data[pe + 1] !== 0x45) { result.valid = false; return result; }

  // COFF header
  result.coffHeader = {
    machine: readU16LE(data, pe + 4),
    machineName: PE_MACHINES[readU16LE(data, pe + 4)] || "Unknown",
    numberOfSections: readU16LE(data, pe + 6),
    timeDateStamp: readU32LE(data, pe + 8),
    timeDateStr: new Date(readU32LE(data, pe + 8) * 1000).toISOString(),
    pointerToSymbolTable: readU32LE(data, pe + 12),
    numberOfSymbols: readU32LE(data, pe + 16),
    sizeOfOptionalHeader: readU16LE(data, pe + 20),
    characteristics: readU16LE(data, pe + 22),
  };

  result.coffHeader.characteristicFlags = [];
  var chars = result.coffHeader.characteristics;
  for (var bit in PE_CHARACTERISTICS) {
    if (chars & parseInt(bit)) result.coffHeader.characteristicFlags.push(PE_CHARACTERISTICS[bit]);
  }

  // Optional header
  var optStart = pe + 24;
  var magic = readU16LE(data, optStart);
  var is64 = magic === 0x20B;
  result.optionalHeader = {
    magic: magic === 0x10B ? "PE32" : (magic === 0x20B ? "PE32+" : "Unknown"),
    is64: is64,
    majorLinkerVersion: data[optStart + 2],
    minorLinkerVersion: data[optStart + 3],
    sizeOfCode: readU32LE(data, optStart + 4),
    sizeOfInitializedData: readU32LE(data, optStart + 8),
    sizeOfUninitializedData: readU32LE(data, optStart + 12),
    addressOfEntryPoint: readU32LE(data, optStart + 16),
    baseOfCode: readU32LE(data, optStart + 20),
    imageBase: is64 ? readU32LE(data, optStart + 24) : readU32LE(data, optStart + 28),
    sectionAlignment: readU32LE(data, optStart + (is64 ? 32 : 32)),
    fileAlignment: readU32LE(data, optStart + (is64 ? 36 : 36)),
    sizeOfImage: readU32LE(data, optStart + (is64 ? 56 : 56)),
    sizeOfHeaders: readU32LE(data, optStart + (is64 ? 60 : 60)),
    checksum: readU32LE(data, optStart + (is64 ? 64 : 64)),
    subsystem: readU16LE(data, optStart + (is64 ? 68 : 68)),
    subsystemName: PE_SUBSYSTEMS[readU16LE(data, optStart + (is64 ? 68 : 68))] || "Unknown",
    dllCharacteristics: readU16LE(data, optStart + (is64 ? 70 : 70)),
  };

  // DLL characteristics (security features)
  var dllChars = result.optionalHeader.dllCharacteristics;
  result.securityFeatures = {
    ASLR: !!(dllChars & 0x0040),
    DEP_NX: !!(dllChars & 0x0100),
    SEH: !(dllChars & 0x0400),
    CFG: !!(dllChars & 0x4000),
    HighEntropyASLR: !!(dllChars & 0x0020),
    ForceIntegrity: !!(dllChars & 0x0080),
    Isolation: !!(dllChars & 0x0200),
    AppContainer: !!(dllChars & 0x1000),
    GuardCF: !!(dllChars & 0x4000),
    TerminalServerAware: !!(dllChars & 0x8000),
  };

  // Sections
  var sectionOffset = optStart + result.coffHeader.sizeOfOptionalHeader;
  result.sections = [];
  for (var s = 0; s < result.coffHeader.numberOfSections; s++) {
    var so = sectionOffset + s * 40;
    if (so + 40 > data.length) break;
    var secChars = readU32LE(data, so + 36);
    var sec = {
      name: readString(data, so, 8),
      virtualSize: readU32LE(data, so + 8),
      virtualAddress: readU32LE(data, so + 12),
      rawDataSize: readU32LE(data, so + 16),
      rawDataPointer: readU32LE(data, so + 20),
      characteristics: secChars,
      readable: !!(secChars & 0x40000000),
      writable: !!(secChars & 0x80000000),
      executable: !!(secChars & 0x20000000),
    };
    sec.rwx = sec.readable && sec.writable && sec.executable;
    // Calculate entropy for the section
    if (sec.rawDataPointer > 0 && sec.rawDataSize > 0 && sec.rawDataPointer + sec.rawDataSize <= data.length) {
      sec.entropy = calculateEntropy(data.slice(sec.rawDataPointer, sec.rawDataPointer + sec.rawDataSize));
    } else {
      sec.entropy = 0;
    }
    result.sections.push(sec);
  }

  // Import table (basic parsing)
  result.imports = [];
  var importRVA = 0;
  var dataDir = optStart + (is64 ? 112 : 96);
  if (dataDir + 8 <= data.length) {
    importRVA = readU32LE(data, dataDir + 8); // Import table is data directory entry 1
  }
  if (importRVA > 0) {
    // Convert RVA to file offset
    var importFileOffset = 0;
    for (var si = 0; si < result.sections.length; si++) {
      var sec2 = result.sections[si];
      if (importRVA >= sec2.virtualAddress && importRVA < sec2.virtualAddress + sec2.virtualSize) {
        importFileOffset = sec2.rawDataPointer + (importRVA - sec2.virtualAddress);
        break;
      }
    }
    if (importFileOffset > 0) {
      var idx = 0;
      while (importFileOffset + idx * 20 + 20 <= data.length && idx < 100) {
        var iltRVA = readU32LE(data, importFileOffset + idx * 20);
        var nameRVA = readU32LE(data, importFileOffset + idx * 20 + 12);
        if (nameRVA === 0 && iltRVA === 0) break;
        // Convert name RVA to file offset
        var nameOffset = 0;
        for (var sj = 0; sj < result.sections.length; sj++) {
          var sec3 = result.sections[sj];
          if (nameRVA >= sec3.virtualAddress && nameRVA < sec3.virtualAddress + sec3.virtualSize) {
            nameOffset = sec3.rawDataPointer + (nameRVA - sec3.virtualAddress);
            break;
          }
        }
        var dllName = nameOffset > 0 ? readString(data, nameOffset, 256) : "unknown";
        result.imports.push({ dll: dllName, functions: [] });
        idx++;
      }
    }
  }

  return result;
}

// ─── ELF parser ────────────────────────────────────────────────────────────
function parseELF(data) {
  var result = { valid: false };
  if (data[0] !== 0x7F || data[1] !== 0x45 || data[2] !== 0x4C || data[3] !== 0x46) return result;
  result.valid = true;

  var is64 = data[4] === 2;
  var isLE = data[5] === 1;
  var read16 = isLE ? readU16LE : function(buf, off) { return (buf[off] << 8) | buf[off + 1]; };
  var read32 = isLE ? readU32LE : function(buf, off) { return ((buf[off] << 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3]) >>> 0; };

  result.header = {
    class: is64 ? "ELF64" : "ELF32",
    encoding: isLE ? "Little Endian" : "Big Endian",
    osabi: ELF_OSABI[data[7]] || "Unknown (" + data[7] + ")",
    type: read16(data, 16),
    typeName: ELF_TYPES[read16(data, 16)] || "Unknown",
    machine: read16(data, 18),
    machineName: ELF_MACHINES[read16(data, 18)] || "Unknown (" + read16(data, 18) + ")",
    version: read32(data, 20),
    entryPoint: is64 ? read32(data, 24) : read32(data, 24),
    phOffset: is64 ? read32(data, 32) : read32(data, 28),
    shOffset: is64 ? read32(data, 40) : read32(data, 32),
    flags: read32(data, is64 ? 48 : 36),
    ehSize: read16(data, is64 ? 52 : 40),
    phEntSize: read16(data, is64 ? 54 : 42),
    phNum: read16(data, is64 ? 56 : 44),
    shEntSize: read16(data, is64 ? 58 : 46),
    shNum: read16(data, is64 ? 60 : 48),
    shStrndx: read16(data, is64 ? 62 : 50),
  };

  // Program headers
  result.programHeaders = [];
  var PT_TYPES = { 0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 6: "PHDR", 0x6474E550: "GNU_EH_FRAME", 0x6474E551: "GNU_STACK", 0x6474E552: "GNU_RELRO", 0x6474E553: "GNU_PROPERTY" };
  for (var p = 0; p < result.header.phNum && p < 64; p++) {
    var phOff = result.header.phOffset + p * result.header.phEntSize;
    if (phOff + result.header.phEntSize > data.length) break;
    var phType = read32(data, phOff);
    var ph = {
      type: phType,
      typeName: PT_TYPES[phType] || "0x" + phType.toString(16),
    };
    if (is64) {
      ph.flags = read32(data, phOff + 4);
      ph.offset = read32(data, phOff + 8);
      ph.vaddr = read32(data, phOff + 16);
      ph.paddr = read32(data, phOff + 24);
      ph.filesz = read32(data, phOff + 32);
      ph.memsz = read32(data, phOff + 40);
    } else {
      ph.offset = read32(data, phOff + 4);
      ph.vaddr = read32(data, phOff + 8);
      ph.paddr = read32(data, phOff + 12);
      ph.filesz = read32(data, phOff + 16);
      ph.memsz = read32(data, phOff + 20);
      ph.flags = read32(data, phOff + 24);
    }
    ph.readable = !!(ph.flags & 4);
    ph.writable = !!(ph.flags & 2);
    ph.executable = !!(ph.flags & 1);
    result.programHeaders.push(ph);
  }

  // Section headers
  result.sections = [];
  var SHT_TYPES = { 0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 5: "HASH", 6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL", 11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY" };
  // Read section header string table
  var shStrTab = null;
  if (result.header.shStrndx < result.header.shNum) {
    var shStrOff = result.header.shOffset + result.header.shStrndx * result.header.shEntSize;
    if (shStrOff + result.header.shEntSize <= data.length) {
      var strTabOff = is64 ? read32(data, shStrOff + 24) : read32(data, shStrOff + 16);
      var strTabSize = is64 ? read32(data, shStrOff + 32) : read32(data, shStrOff + 20);
      if (strTabOff + strTabSize <= data.length) {
        shStrTab = data.slice(strTabOff, strTabOff + strTabSize);
      }
    }
  }

  for (var s = 0; s < result.header.shNum && s < 64; s++) {
    var shOff = result.header.shOffset + s * result.header.shEntSize;
    if (shOff + result.header.shEntSize > data.length) break;
    var nameIdx = read32(data, shOff);
    var shType = read32(data, shOff + 4);
    var shFlags = is64 ? read32(data, shOff + 8) : read32(data, shOff + 8);
    var sec = {
      nameIndex: nameIdx,
      name: shStrTab ? readString(shStrTab, nameIdx, 128) : "(idx " + nameIdx + ")",
      type: shType,
      typeName: SHT_TYPES[shType] || "0x" + shType.toString(16),
      flags: shFlags,
      addr: is64 ? read32(data, shOff + 16) : read32(data, shOff + 12),
      offset: is64 ? read32(data, shOff + 24) : read32(data, shOff + 16),
      size: is64 ? read32(data, shOff + 32) : read32(data, shOff + 20),
      writable: !!(shFlags & 1),
      allocatable: !!(shFlags & 2),
      executable: !!(shFlags & 4),
    };
    if (sec.offset > 0 && sec.size > 0 && sec.offset + sec.size <= data.length) {
      sec.entropy = calculateEntropy(data.slice(sec.offset, sec.offset + sec.size));
    } else {
      sec.entropy = 0;
    }
    result.sections.push(sec);
  }

  // Security features
  result.securityFeatures = {
    PIE: result.header.typeName === "DYN (Shared/PIE)",
    RELRO: result.programHeaders.some(function(ph) { return ph.typeName === "GNU_RELRO"; }),
    NX: result.programHeaders.some(function(ph) { return ph.typeName === "GNU_STACK" && !ph.executable; }),
    StackCanary: false, // Would need deeper analysis
  };

  return result;
}

// ─── Hash computation (using SubtleCrypto) ─────────────────────────────────
async function computeHashes(data) {
  var results = {};
  try {
    var md5 = await digestHex("MD5", data);
    results.md5 = md5 || "(not supported)";
  } catch (_) { results.md5 = "(not supported in this browser)"; }
  try {
    var sha1Buf = await crypto.subtle.digest("SHA-1", data);
    results.sha1 = Array.from(new Uint8Array(sha1Buf)).map(function(b) { return b.toString(16).padStart(2, "0"); }).join("");
  } catch (_) { results.sha1 = "(error)"; }
  try {
    var sha256Buf = await crypto.subtle.digest("SHA-256", data);
    results.sha256 = Array.from(new Uint8Array(sha256Buf)).map(function(b) { return b.toString(16).padStart(2, "0"); }).join("");
  } catch (_) { results.sha256 = "(error)"; }
  return results;
}

// MD5 implementation (SubtleCrypto doesn't support MD5)
async function digestHex(algo, data) {
  if (algo === "MD5") return md5Hex(data);
  var buf = await crypto.subtle.digest(algo.replace("-", ""), data);
  return Array.from(new Uint8Array(buf)).map(function(b) { return b.toString(16).padStart(2, "0"); }).join("");
}

function md5Hex(data) {
  // Simple MD5 implementation for binary analysis
  function md5cycle(x, k) {
    var a = x[0], b = x[1], c = x[2], d = x[3];
    a = ff(a, b, c, d, k[0], 7, -680876936); d = ff(d, a, b, c, k[1], 12, -389564586);
    c = ff(c, d, a, b, k[2], 17, 606105819); b = ff(b, c, d, a, k[3], 22, -1044525330);
    a = ff(a, b, c, d, k[4], 7, -176418897); d = ff(d, a, b, c, k[5], 12, 1200080426);
    c = ff(c, d, a, b, k[6], 17, -1473231341); b = ff(b, c, d, a, k[7], 22, -45705983);
    a = ff(a, b, c, d, k[8], 7, 1770035416); d = ff(d, a, b, c, k[9], 12, -1958414417);
    c = ff(c, d, a, b, k[10], 17, -42063); b = ff(b, c, d, a, k[11], 22, -1990404162);
    a = ff(a, b, c, d, k[12], 7, 1804603682); d = ff(d, a, b, c, k[13], 12, -40341101);
    c = ff(c, d, a, b, k[14], 17, -1502002290); b = ff(b, c, d, a, k[15], 22, 1236535329);
    a = gg(a, b, c, d, k[1], 5, -165796510); d = gg(d, a, b, c, k[6], 9, -1069501632);
    c = gg(c, d, a, b, k[11], 14, 643717713); b = gg(b, c, d, a, k[0], 20, -373897302);
    a = gg(a, b, c, d, k[5], 5, -701558691); d = gg(d, a, b, c, k[10], 9, 38016083);
    c = gg(c, d, a, b, k[15], 14, -660478335); b = gg(b, c, d, a, k[4], 20, -405537848);
    a = gg(a, b, c, d, k[9], 5, 568446438); d = gg(d, a, b, c, k[14], 9, -1019803690);
    c = gg(c, d, a, b, k[3], 14, -187363961); b = gg(b, c, d, a, k[8], 20, 1163531501);
    a = gg(a, b, c, d, k[13], 5, -1444681467); d = gg(d, a, b, c, k[2], 9, -51403784);
    c = gg(c, d, a, b, k[7], 14, 1735328473); b = gg(b, c, d, a, k[12], 20, -1926607734);
    a = hh(a, b, c, d, k[5], 4, -378558); d = hh(d, a, b, c, k[8], 11, -2022574463);
    c = hh(c, d, a, b, k[11], 16, 1839030562); b = hh(b, c, d, a, k[14], 23, -35309556);
    a = hh(a, b, c, d, k[1], 4, -1530992060); d = hh(d, a, b, c, k[4], 11, 1272893353);
    c = hh(c, d, a, b, k[7], 16, -155497632); b = hh(b, c, d, a, k[10], 23, -1094730640);
    a = hh(a, b, c, d, k[13], 4, 681279174); d = hh(d, a, b, c, k[0], 11, -358537222);
    c = hh(c, d, a, b, k[3], 16, -722521979); b = hh(b, c, d, a, k[6], 23, 76029189);
    a = hh(a, b, c, d, k[9], 4, -640364487); d = hh(d, a, b, c, k[12], 11, -421815835);
    c = hh(c, d, a, b, k[15], 16, 530742520); b = hh(b, c, d, a, k[2], 23, -995338651);
    a = ii(a, b, c, d, k[0], 6, -198630844); d = ii(d, a, b, c, k[7], 10, 1126891415);
    c = ii(c, d, a, b, k[14], 15, -1416354905); b = ii(b, c, d, a, k[5], 21, -57434055);
    a = ii(a, b, c, d, k[12], 6, 1700485571); d = ii(d, a, b, c, k[3], 10, -1894986606);
    c = ii(c, d, a, b, k[10], 15, -1051523); b = ii(b, c, d, a, k[1], 21, -2054922799);
    a = ii(a, b, c, d, k[8], 6, 1873313359); d = ii(d, a, b, c, k[15], 10, -30611744);
    c = ii(c, d, a, b, k[6], 15, -1560198380); b = ii(b, c, d, a, k[13], 21, 1309151649);
    a = ii(a, b, c, d, k[4], 6, -145523070); d = ii(d, a, b, c, k[11], 10, -1120210379);
    c = ii(c, d, a, b, k[2], 15, 718787259); b = ii(b, c, d, a, k[9], 21, -343485551);
    x[0] = add32(a, x[0]); x[1] = add32(b, x[1]); x[2] = add32(c, x[2]); x[3] = add32(d, x[3]);
  }
  function cmn(q, a, b, x, s, t) { a = add32(add32(a, q), add32(x, t)); return add32((a << s) | (a >>> (32 - s)), b); }
  function ff(a, b, c, d, x, s, t) { return cmn((b & c) | ((~b) & d), a, b, x, s, t); }
  function gg(a, b, c, d, x, s, t) { return cmn((b & d) | (c & (~d)), a, b, x, s, t); }
  function hh(a, b, c, d, x, s, t) { return cmn(b ^ c ^ d, a, b, x, s, t); }
  function ii(a, b, c, d, x, s, t) { return cmn(c ^ (b | (~d)), a, b, x, s, t); }
  function add32(a, b) { return (a + b) & 0xFFFFFFFF; }

  var n = data.length;
  var state = [1732584193, -271733879, -1732584194, 271733878];
  var tail = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  var i, s;
  for (i = 64; i <= n; i += 64) {
    var k = [];
    for (s = i - 64; s < i; s += 4) k.push(data[s] | (data[s + 1] << 8) | (data[s + 2] << 16) | (data[s + 3] << 24));
    md5cycle(state, k);
  }
  for (s = 0; s < 16; s++) tail[s] = 0;
  for (i = i - 64; i < n; i++) tail[(i & 63) >> 2] |= data[i] << ((i & 3) << 3);
  tail[(i & 63) >> 2] |= 0x80 << ((i & 3) << 3);
  if ((i & 63) > 55) { md5cycle(state, tail); for (s = 0; s < 16; s++) tail[s] = 0; }
  tail[14] = n * 8;
  md5cycle(state, tail);

  var hex = "";
  for (i = 0; i < 4; i++) {
    for (s = 0; s < 4; s++) hex += ((state[i] >> (s * 8)) & 0xFF).toString(16).padStart(2, "0");
  }
  return hex;
}

// ─── Main render function ──────────────────────────────────────────────────
export function renderBinaryAnalyzer(main) {
  var fileData = null;
  var fileName = "";
  var fileSize = 0;
  var activeTab = "upload";
  var hexPage = 0;
  var hexBytesPerPage = 512;
  var hexSearch = "";
  var hexGoto = "";
  var strMinLen = 4;
  var strFilter = "";
  var disasmOffset = 0;
  var disasmBaseAddr = 0;
  var hashes = null;

  function render() {
    var html = '<h1 class="pg-h1">Binary Analyzer</h1>';
    html += '<p class="muted pg-sub">Upload any file for deep analysis — hex view, PE/ELF parsing, string extraction, entropy, disassembly, IoC extraction, and YARA rule generation. All processing runs locally in your browser.</p>';

    if (!fileData) {
      html += '<div class="ba-upload" id="ba-drop">';
      html += '<div class="ba-upload-icon"></div>';
      html += '<div class="ba-upload-text">Drop a file here or click to select</div>';
      html += '<div class="ba-upload-sub">Supports any file type — PE, ELF, Mach-O, PDF, ZIP, images, and more</div>';
      html += '<input type="file" id="ba-file" style="display:none">';
      html += '</div>';
    } else {
      // Tab bar
      var tabs = [
        { id: "overview", label: "Overview" },
        { id: "hex", label: "Hex Viewer" },
        { id: "strings", label: "Strings" },
        { id: "entropy", label: "Entropy" },
        { id: "hashes", label: "Hashes" },
        { id: "headers", label: "Headers" },
        { id: "sections", label: "Sections" },
        { id: "imports", label: "Imports" },
        { id: "disasm", label: "Disassembler" },
        { id: "iocs", label: "IoCs" },
        { id: "packers", label: "Packers" },
        { id: "yara", label: "YARA" },
      ];
      html += '<div class="ba-file-info">';
      html += '<span class="ba-fname">' + esc(fileName) + '</span>';
      html += '<span class="ba-fsize">' + formatSize(fileSize) + '</span>';
      html += '<button class="btn ba-new-btn" id="ba-new">New File</button>';
      html += '</div>';
      html += '<div class="pc-tabs">';
      for (var t = 0; t < tabs.length; t++) {
        html += '<button class="pc-tab' + (activeTab === tabs[t].id ? " on" : "") + '" data-tab="' + tabs[t].id + '">' + esc(tabs[t].label) + '</button>';
      }
      html += '</div>';
      html += '<div class="pc-body">';

      if (activeTab === "overview") html += renderOverview();
      else if (activeTab === "hex") html += renderHex();
      else if (activeTab === "strings") html += renderStrings();
      else if (activeTab === "entropy") html += renderEntropy();
      else if (activeTab === "hashes") html += renderHashes();
      else if (activeTab === "headers") html += renderHeaders();
      else if (activeTab === "sections") html += renderSections();
      else if (activeTab === "imports") html += renderImports();
      else if (activeTab === "disasm") html += renderDisasm();
      else if (activeTab === "iocs") html += renderIoCs();
      else if (activeTab === "packers") html += renderPackers();
      else if (activeTab === "yara") html += renderYARATab();

      html += '</div>';
    }

    main.innerHTML = html;
    wireEvents();
  }

  function formatSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
    if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + " MB";
    return (bytes / 1073741824).toFixed(2) + " GB";
  }

  function detectFileType() {
    for (var i = 0; i < MAGIC_SIGNATURES.length; i++) {
      var sig = MAGIC_SIGNATURES[i];
      var match = true;
      for (var j = 0; j < sig.magic.length; j++) {
        if (j >= fileData.length || fileData[j] !== sig.magic[j]) { match = false; break; }
      }
      if (match) return sig;
    }
    return { name: "Unknown", ext: "?", type: "unknown" };
  }

  function renderOverview() {
    var type = detectFileType();
    var entropy = calculateEntropy(fileData);
    var html = '<div class="ba-overview">';
    html += '<div class="ba-ov-grid">';
    html += '<div class="ba-ov-card"><div class="ba-ov-label">File Type</div><div class="ba-ov-val">' + esc(type.name) + '</div></div>';
    html += '<div class="ba-ov-card"><div class="ba-ov-label">Extension</div><div class="ba-ov-val">' + esc(type.ext) + '</div></div>';
    html += '<div class="ba-ov-card"><div class="ba-ov-label">Size</div><div class="ba-ov-val">' + formatSize(fileSize) + ' (' + fileSize.toLocaleString() + ' bytes)</div></div>';
    html += '<div class="ba-ov-card"><div class="ba-ov-label">Entropy</div><div class="ba-ov-val" style="color:' + entropyColor(entropy) + '">' + entropy.toFixed(4) + ' — ' + entropyLabel(entropy) + '</div></div>';

    // First bytes
    var firstBytes = [];
    for (var i = 0; i < Math.min(16, fileData.length); i++) {
      firstBytes.push(fileData[i].toString(16).padStart(2, "0").toUpperCase());
    }
    html += '<div class="ba-ov-card ba-ov-wide"><div class="ba-ov-label">First 16 bytes</div><div class="ba-ov-val"><code>' + firstBytes.join(" ") + '</code></div></div>';

    // PE/ELF specific summary
    if (type.type === "pe") {
      var pe = parsePE(fileData);
      if (pe.valid) {
        html += '<div class="ba-ov-card"><div class="ba-ov-label">Architecture</div><div class="ba-ov-val">' + esc(pe.coffHeader.machineName) + ' (' + pe.optionalHeader.magic + ')</div></div>';
        html += '<div class="ba-ov-card"><div class="ba-ov-label">Subsystem</div><div class="ba-ov-val">' + esc(pe.optionalHeader.subsystemName) + '</div></div>';
        html += '<div class="ba-ov-card"><div class="ba-ov-label">Entry Point</div><div class="ba-ov-val">0x' + pe.optionalHeader.addressOfEntryPoint.toString(16).toUpperCase() + '</div></div>';
        html += '<div class="ba-ov-card"><div class="ba-ov-label">Compile Time</div><div class="ba-ov-val">' + esc(pe.coffHeader.timeDateStr) + '</div></div>';
        html += '<div class="ba-ov-card"><div class="ba-ov-label">Sections</div><div class="ba-ov-val">' + pe.coffHeader.numberOfSections + '</div></div>';
        html += '<div class="ba-ov-card"><div class="ba-ov-label">Imports</div><div class="ba-ov-val">' + pe.imports.length + ' DLLs</div></div>';
        // Security features
        html += '<div class="ba-ov-card ba-ov-wide"><div class="ba-ov-label">Security Features</div><div class="ba-ov-val">';
        var sf = pe.securityFeatures;
        var features = [
          { name: "ASLR", on: sf.ASLR },
          { name: "DEP/NX", on: sf.DEP_NX },
          { name: "SEH", on: sf.SEH },
          { name: "CFG", on: sf.CFG },
          { name: "High Entropy ASLR", on: sf.HighEntropyASLR },
        ];
        for (var f = 0; f < features.length; f++) {
          html += '<span class="ba-sec-badge ' + (features[f].on ? "ba-sec-on" : "ba-sec-off") + '">' + esc(features[f].name) + ': ' + (features[f].on ? "ON" : "OFF") + '</span>';
        }
        html += '</div></div>';
        // RWX sections warning
        var rwxSections = pe.sections.filter(function(s) { return s.rwx; });
        if (rwxSections.length) {
          html += '<div class="ba-ov-card ba-ov-wide ba-ov-warn"><div class="ba-ov-label">RWX Sections (Suspicious)</div><div class="ba-ov-val">';
          for (var r = 0; r < rwxSections.length; r++) {
            html += '<span class="ba-sec-badge ba-sec-off">' + esc(rwxSections[r].name) + ' — Read+Write+Execute</span>';
          }
          html += '</div></div>';
        }
      }
    }

    if (type.type === "elf") {
      var elf = parseELF(fileData);
      if (elf.valid) {
        html += '<div class="ba-ov-card"><div class="ba-ov-label">Architecture</div><div class="ba-ov-val">' + esc(elf.header.machineName) + ' (' + elf.header.class + ')</div></div>';
        html += '<div class="ba-ov-card"><div class="ba-ov-label">Type</div><div class="ba-ov-val">' + esc(elf.header.typeName) + '</div></div>';
        html += '<div class="ba-ov-card"><div class="ba-ov-label">Entry Point</div><div class="ba-ov-val">0x' + elf.header.entryPoint.toString(16) + '</div></div>';
        html += '<div class="ba-ov-card"><div class="ba-ov-label">OS/ABI</div><div class="ba-ov-val">' + esc(elf.header.osabi) + '</div></div>';
        html += '<div class="ba-ov-card ba-ov-wide"><div class="ba-ov-label">Security Features</div><div class="ba-ov-val">';
        var ef = elf.securityFeatures;
        var elfFeatures = [
          { name: "PIE", on: ef.PIE },
          { name: "RELRO", on: ef.RELRO },
          { name: "NX Stack", on: ef.NX },
        ];
        for (var ef2 = 0; ef2 < elfFeatures.length; ef2++) {
          html += '<span class="ba-sec-badge ' + (elfFeatures[ef2].on ? "ba-sec-on" : "ba-sec-off") + '">' + esc(elfFeatures[ef2].name) + ': ' + (elfFeatures[ef2].on ? "ON" : "OFF") + '</span>';
        }
        html += '</div></div>';
      }
    }

    html += '</div></div>';
    return html;
  }

  function renderHex() {
    var totalPages = Math.ceil(fileData.length / hexBytesPerPage);
    var start = hexPage * hexBytesPerPage;
    var end = Math.min(start + hexBytesPerPage, fileData.length);
    var html = '<div class="ba-hex-controls">';
    html += '<button class="btn" id="ba-hex-prev"' + (hexPage === 0 ? " disabled" : "") + '>&laquo; Prev</button>';
    html += '<span class="ba-hex-page">Page ' + (hexPage + 1) + ' / ' + totalPages + ' (offset 0x' + start.toString(16).toUpperCase() + ')</span>';
    html += '<button class="btn" id="ba-hex-next"' + (hexPage >= totalPages - 1 ? " disabled" : "") + '>Next &raquo;</button>';
    html += '<input class="pc-input ba-hex-goto" id="ba-hex-goto" placeholder="Go to offset (hex)" value="' + esc(hexGoto) + '">';
    html += '<button class="btn" id="ba-hex-go">Go</button>';
    html += '</div>';

    // Hex dump
    var lines = [];
    for (var i = start; i < end; i += 16) {
      var offset = i.toString(16).padStart(8, "0");
      var hex = [];
      var ascii = [];
      for (var j = 0; j < 16; j++) {
        if (i + j < end) {
          hex.push(fileData[i + j].toString(16).padStart(2, "0"));
          ascii.push(fileData[i + j] >= 32 && fileData[i + j] <= 126 ? String.fromCharCode(fileData[i + j]) : ".");
        } else {
          hex.push("  ");
          ascii.push(" ");
        }
      }
      var hexStr = hex.slice(0, 8).join(" ") + "  " + hex.slice(8).join(" ");
      lines.push('<span class="ba-hex-off">' + offset + '</span>  ' + hexStr + '  <span class="ba-hex-ascii">|' + esc(ascii.join("")) + '|</span>');
    }
    html += '<pre class="pc-hex ba-hex-view">' + lines.join("\n") + '</pre>';
    return html;
  }

  function renderStrings() {
    var strings = extractStrings(fileData, strMinLen);
    if (strFilter) {
      try {
        var re = new RegExp(strFilter, "i");
        strings = strings.filter(function(s) { return re.test(s.value); });
      } catch (_) {
        strings = strings.filter(function(s) { return s.value.toLowerCase().indexOf(strFilter.toLowerCase()) >= 0; });
      }
    }
    var shown = strings.slice(0, 500);
    var html = '<div class="ba-str-controls">';
    html += '<label class="pc-label">Min length</label><input class="pc-input" id="ba-str-min" type="number" min="2" max="100" value="' + strMinLen + '" style="width:60px">';
    html += '<label class="pc-label">Filter (text or regex)</label><input class="pc-input" id="ba-str-filter" value="' + esc(strFilter) + '" placeholder="e.g. http|password">';
    html += '<span class="muted">' + strings.length + ' strings found' + (shown.length < strings.length ? " (showing first 500)" : "") + '</span>';
    html += '</div>';
    html += '<table class="pc-table"><thead><tr><th>Offset</th><th>Encoding</th><th>String</th></tr></thead><tbody>';
    for (var i = 0; i < shown.length; i++) {
      html += '<tr><td><code>0x' + shown[i].offset.toString(16).padStart(8, "0") + '</code></td><td>' + shown[i].encoding + '</td><td class="ba-str-val">' + esc(shown[i].value) + '</td></tr>';
    }
    html += '</tbody></table>';
    return html;
  }

  function renderEntropy() {
    var overall = calculateEntropy(fileData);
    var chunkSize = Math.max(256, Math.floor(fileData.length / 64));
    var chunks = [];
    for (var i = 0; i < fileData.length; i += chunkSize) {
      var end = Math.min(i + chunkSize, fileData.length);
      var e = calculateEntropy(fileData.slice(i, end));
      chunks.push({ offset: i, entropy: e });
    }
    var html = '<div class="ba-ent">';
    html += '<h3>Overall Entropy: <span style="color:' + entropyColor(overall) + '">' + overall.toFixed(4) + '</span> — ' + entropyLabel(overall) + '</h3>';
    html += '<div class="ba-ent-bar">';
    for (var j = 0; j < chunks.length; j++) {
      var width = (100 / chunks.length).toFixed(2);
      var height = (chunks[j].entropy / 8 * 100).toFixed(1);
      html += '<div class="ba-ent-chunk" style="width:' + width + '%;height:' + height + '%;background:' + entropyColor(chunks[j].entropy) + '" title="Offset 0x' + chunks[j].offset.toString(16) + ': ' + chunks[j].entropy.toFixed(2) + '"></div>';
    }
    html += '</div>';
    html += '<div class="ba-ent-legend">';
    html += '<span style="color:#4ecdc4">Low (&lt;3)</span> ';
    html += '<span style="color:#45b7d1">Medium (3-5)</span> ';
    html += '<span style="color:#f39c12">Mod. High (5-6.5)</span> ';
    html += '<span style="color:#e74c3c">High (6.5-7.5)</span> ';
    html += '<span style="color:#c0392b">Very High (&gt;7.5)</span>';
    html += '</div>';
    html += '<div class="ba-ent-note">High entropy regions typically indicate compressed or encrypted data. Packed executables show high entropy across most sections. Legitimate executables usually have mixed entropy — low in data sections, moderate in code sections.</div>';
    html += '</div>';
    return html;
  }

  function renderHashes() {
    var html = '<div class="ba-hashes">';
    if (hashes) {
      html += '<table class="pc-table"><tbody>';
      html += '<tr><td>MD5</td><td><code>' + esc(hashes.md5) + '</code></td></tr>';
      html += '<tr><td>SHA-1</td><td><code>' + esc(hashes.sha1) + '</code></td></tr>';
      html += '<tr><td>SHA-256</td><td><code>' + esc(hashes.sha256) + '</code></td></tr>';
      html += '</tbody></table>';
      html += '<div class="ba-hash-note">Use these hashes to check VirusTotal, Hybrid Analysis, or other malware databases. SHA-256 is the preferred hash for modern threat intelligence.</div>';
    } else {
      html += '<div class="muted">Computing hashes...</div>';
    }
    html += '</div>';
    return html;
  }

  function renderHeaders() {
    var type = detectFileType();
    var html = '<div class="ba-headers">';
    if (type.type === "pe") {
      var pe = parsePE(fileData);
      if (pe.valid) {
        html += '<h3>PE Headers</h3>';
        html += '<h4>DOS Header</h4>';
        html += '<table class="pc-table"><tbody>';
        html += '<tr><td>e_magic</td><td>' + pe.dosHeader.e_magic + '</td></tr>';
        html += '<tr><td>e_lfanew (PE offset)</td><td>0x' + pe.dosHeader.e_lfanew.toString(16).toUpperCase() + '</td></tr>';
        html += '</tbody></table>';
        html += '<h4>COFF Header</h4>';
        html += '<table class="pc-table"><tbody>';
        html += '<tr><td>Machine</td><td>' + esc(pe.coffHeader.machineName) + ' (0x' + pe.coffHeader.machine.toString(16) + ')</td></tr>';
        html += '<tr><td>Number of Sections</td><td>' + pe.coffHeader.numberOfSections + '</td></tr>';
        html += '<tr><td>Compile Timestamp</td><td>' + esc(pe.coffHeader.timeDateStr) + ' (' + pe.coffHeader.timeDateStamp + ')</td></tr>';
        html += '<tr><td>Characteristics</td><td>' + pe.coffHeader.characteristicFlags.join(", ") + '</td></tr>';
        html += '</tbody></table>';
        html += '<h4>Optional Header</h4>';
        html += '<table class="pc-table"><tbody>';
        html += '<tr><td>Magic</td><td>' + pe.optionalHeader.magic + '</td></tr>';
        html += '<tr><td>Linker Version</td><td>' + pe.optionalHeader.majorLinkerVersion + '.' + pe.optionalHeader.minorLinkerVersion + '</td></tr>';
        html += '<tr><td>Entry Point</td><td>0x' + pe.optionalHeader.addressOfEntryPoint.toString(16).toUpperCase() + '</td></tr>';
        html += '<tr><td>Image Base</td><td>0x' + pe.optionalHeader.imageBase.toString(16).toUpperCase() + '</td></tr>';
        html += '<tr><td>Section Alignment</td><td>0x' + pe.optionalHeader.sectionAlignment.toString(16) + '</td></tr>';
        html += '<tr><td>File Alignment</td><td>0x' + pe.optionalHeader.fileAlignment.toString(16) + '</td></tr>';
        html += '<tr><td>Size of Image</td><td>0x' + pe.optionalHeader.sizeOfImage.toString(16) + ' (' + pe.optionalHeader.sizeOfImage + ')</td></tr>';
        html += '<tr><td>Subsystem</td><td>' + esc(pe.optionalHeader.subsystemName) + '</td></tr>';
        html += '<tr><td>Checksum</td><td>0x' + pe.optionalHeader.checksum.toString(16).toUpperCase() + '</td></tr>';
        html += '</tbody></table>';
      }
    } else if (type.type === "elf") {
      var elf = parseELF(fileData);
      if (elf.valid) {
        html += '<h3>ELF Header</h3>';
        html += '<table class="pc-table"><tbody>';
        html += '<tr><td>Class</td><td>' + elf.header.class + '</td></tr>';
        html += '<tr><td>Encoding</td><td>' + elf.header.encoding + '</td></tr>';
        html += '<tr><td>OS/ABI</td><td>' + esc(elf.header.osabi) + '</td></tr>';
        html += '<tr><td>Type</td><td>' + esc(elf.header.typeName) + '</td></tr>';
        html += '<tr><td>Machine</td><td>' + esc(elf.header.machineName) + '</td></tr>';
        html += '<tr><td>Entry Point</td><td>0x' + elf.header.entryPoint.toString(16) + '</td></tr>';
        html += '<tr><td>Program Headers</td><td>' + elf.header.phNum + ' (offset 0x' + elf.header.phOffset.toString(16) + ')</td></tr>';
        html += '<tr><td>Section Headers</td><td>' + elf.header.shNum + ' (offset 0x' + elf.header.shOffset.toString(16) + ')</td></tr>';
        html += '</tbody></table>';
        html += '<h4>Program Headers</h4>';
        html += '<table class="pc-table"><thead><tr><th>Type</th><th>Offset</th><th>VAddr</th><th>FileSz</th><th>MemSz</th><th>Flags</th></tr></thead><tbody>';
        for (var p = 0; p < elf.programHeaders.length; p++) {
          var ph = elf.programHeaders[p];
          var flags = (ph.readable ? "R" : "-") + (ph.writable ? "W" : "-") + (ph.executable ? "X" : "-");
          html += '<tr><td>' + esc(ph.typeName) + '</td><td>0x' + ph.offset.toString(16) + '</td><td>0x' + ph.vaddr.toString(16) + '</td><td>' + ph.filesz + '</td><td>' + ph.memsz + '</td><td><code>' + flags + '</code></td></tr>';
        }
        html += '</tbody></table>';
      }
    } else {
      html += '<div class="muted">No structured header parser available for this file type (' + esc(type.name) + '). Use the Hex Viewer to inspect the raw bytes.</div>';
    }
    html += '</div>';
    return html;
  }

  function renderSections() {
    var type = detectFileType();
    var html = '<div class="ba-sections">';
    if (type.type === "pe") {
      var pe = parsePE(fileData);
      if (pe.valid) {
        html += '<table class="pc-table"><thead><tr><th>Name</th><th>Virtual Size</th><th>Virtual Addr</th><th>Raw Size</th><th>Raw Offset</th><th>Permissions</th><th>Entropy</th></tr></thead><tbody>';
        for (var s = 0; s < pe.sections.length; s++) {
          var sec = pe.sections[s];
          var perms = (sec.readable ? "R" : "-") + (sec.writable ? "W" : "-") + (sec.executable ? "X" : "-");
          var rowClass = sec.rwx ? " class=\"ba-row-warn\"" : (sec.entropy > 7 ? " class=\"ba-row-alert\"" : "");
          html += '<tr' + rowClass + '><td><code>' + esc(sec.name) + '</code></td><td>0x' + sec.virtualSize.toString(16) + '</td><td>0x' + sec.virtualAddress.toString(16) + '</td><td>0x' + sec.rawDataSize.toString(16) + '</td><td>0x' + sec.rawDataPointer.toString(16) + '</td><td><code>' + perms + '</code>' + (sec.rwx ? ' <span class="ba-sec-badge ba-sec-off">RWX!</span>' : '') + '</td><td style="color:' + entropyColor(sec.entropy) + '">' + sec.entropy.toFixed(2) + '</td></tr>';
        }
        html += '</tbody></table>';
      }
    } else if (type.type === "elf") {
      var elf = parseELF(fileData);
      if (elf.valid) {
        html += '<table class="pc-table"><thead><tr><th>Name</th><th>Type</th><th>Address</th><th>Offset</th><th>Size</th><th>Flags</th><th>Entropy</th></tr></thead><tbody>';
        for (var es = 0; es < elf.sections.length; es++) {
          var esec = elf.sections[es];
          var eperms = (esec.allocatable ? "A" : "-") + (esec.writable ? "W" : "-") + (esec.executable ? "X" : "-");
          html += '<tr><td><code>' + esc(esec.name) + '</code></td><td>' + esc(esec.typeName) + '</td><td>0x' + esec.addr.toString(16) + '</td><td>0x' + esec.offset.toString(16) + '</td><td>' + esec.size + '</td><td><code>' + eperms + '</code></td><td style="color:' + entropyColor(esec.entropy) + '">' + esec.entropy.toFixed(2) + '</td></tr>';
        }
        html += '</tbody></table>';
      }
    } else {
      html += '<div class="muted">No section parser available for this file type.</div>';
    }
    html += '</div>';
    return html;
  }

  function renderImports() {
    var type = detectFileType();
    var html = '<div class="ba-imports">';
    if (type.type === "pe") {
      var pe = parsePE(fileData);
      if (pe.valid && pe.imports.length) {
        // Also scan strings for known API names
        var strings = extractStrings(fileData, 4);
        var suspFound = [];
        for (var i = 0; i < strings.length; i++) {
          var s = strings[i].value;
          if (SUSPICIOUS_IMPORTS[s]) {
            suspFound.push({ name: s, info: SUSPICIOUS_IMPORTS[s], offset: strings[i].offset });
          }
        }

        html += '<h3>Imported DLLs (' + pe.imports.length + ')</h3>';
        html += '<div class="ba-imp-list">';
        for (var d = 0; d < pe.imports.length; d++) {
          html += '<div class="ba-imp-dll"><code>' + esc(pe.imports[d].dll) + '</code></div>';
        }
        html += '</div>';

        if (suspFound.length) {
          html += '<h3>Suspicious API References (' + suspFound.length + ')</h3>';
          html += '<table class="pc-table"><thead><tr><th>API</th><th>Risk</th><th>Description</th><th>Offset</th></tr></thead><tbody>';
          for (var sf = 0; sf < suspFound.length; sf++) {
            var s2 = suspFound[sf];
            html += '<tr class="ba-row-' + s2.info.risk + '"><td><code>' + esc(s2.name) + '</code></td><td class="pc-risk-' + s2.info.risk + '">' + s2.info.risk.toUpperCase() + '</td><td>' + esc(s2.info.desc) + '</td><td>0x' + s2.offset.toString(16).padStart(8, "0") + '</td></tr>';
          }
          html += '</tbody></table>';
        }
      } else {
        html += '<div class="muted">No imports found or unable to parse import table.</div>';
      }
    } else {
      html += '<div class="muted">Import analysis is currently supported for PE files only.</div>';
    }
    html += '</div>';
    return html;
  }

  function renderDisasm() {
    var type = detectFileType();
    var entryOffset = disasmOffset;
    var baseAddr = disasmBaseAddr;
    if (type.type === "pe" && entryOffset === 0) {
      var pe = parsePE(fileData);
      if (pe.valid) {
        var ep = pe.optionalHeader.addressOfEntryPoint;
        for (var s = 0; s < pe.sections.length; s++) {
          var sec = pe.sections[s];
          if (ep >= sec.virtualAddress && ep < sec.virtualAddress + sec.virtualSize) {
            entryOffset = sec.rawDataPointer + (ep - sec.virtualAddress);
            baseAddr = pe.optionalHeader.imageBase + ep;
            break;
          }
        }
      }
    }
    var data = fileData.slice(entryOffset, Math.min(entryOffset + 2000, fileData.length));
    var instrs = disassemble(data, baseAddr, 100);

    var html = '<div class="ba-disasm">';
    html += '<div class="ba-disasm-controls">';
    html += '<label class="pc-label">File Offset (hex)</label><input class="pc-input" id="ba-dis-off" value="0x' + entryOffset.toString(16) + '">';
    html += '<label class="pc-label">Base Address (hex)</label><input class="pc-input" id="ba-dis-base" value="0x' + baseAddr.toString(16) + '">';
    html += '<button class="btn" id="ba-dis-go">Disassemble</button>';
    html += '</div>';
    html += '<table class="pc-table ba-dis-table"><thead><tr><th>Address</th><th>Bytes</th><th>Mnemonic</th><th>Operands</th></tr></thead><tbody>';
    for (var i = 0; i < instrs.length; i++) {
      var ins = instrs[i];
      var cls = "";
      if (ins.mnemonic === "CALL") cls = " class=\"ba-dis-call\"";
      else if (ins.mnemonic.startsWith("J")) cls = " class=\"ba-dis-jmp\"";
      else if (ins.mnemonic === "RET" || ins.mnemonic === "LEAVE") cls = " class=\"ba-dis-ret\"";
      else if (ins.mnemonic === "INT 3" || ins.mnemonic === "INT") cls = " class=\"ba-dis-int\"";
      else if (ins.mnemonic === "NOP") cls = " class=\"ba-dis-nop\"";
      html += '<tr' + cls + '><td><code>' + ins.address + '</code></td><td><code>' + ins.bytes + '</code></td><td><strong>' + esc(ins.mnemonic) + '</strong></td><td>' + esc(ins.operands) + '</td></tr>';
    }
    html += '</tbody></table>';
    html += '<div class="ba-dis-note">Basic x86 disassembler — decodes common opcodes (MOV, PUSH, POP, CALL, JMP, RET, NOP, INT, XOR, ADD, SUB, CMP, conditional jumps). Complex instructions show as <code>db</code> (raw bytes). For full analysis, use Ghidra, IDA Pro, or Binary Ninja.</div>';
    html += '</div>';
    return html;
  }

  function renderIoCs() {
    var strings = extractStrings(fileData, 4);
    var iocs = extractIoCs(strings);
    var html = '<div class="ba-iocs">';
    var categories = [
      { key: "urls", label: "URLs" },
      { key: "ips", label: "IP Addresses" },
      { key: "emails", label: "Email Addresses" },
      { key: "domains", label: "Domains" },
      { key: "registryPaths", label: "Registry Paths" },
      { key: "filePaths", label: "File Paths" },
    ];
    var total = 0;
    for (var c = 0; c < categories.length; c++) total += iocs[categories[c].key].length;
    html += '<h3>Indicators of Compromise — ' + total + ' found</h3>';
    for (var cat = 0; cat < categories.length; cat++) {
      var items = iocs[categories[cat].key];
      if (!items.length) continue;
      html += '<h4>' + categories[cat].label + ' (' + items.length + ')</h4>';
      html += '<table class="pc-table"><thead><tr><th>Value</th><th>Offset</th></tr></thead><tbody>';
      for (var i = 0; i < items.length; i++) {
        html += '<tr><td><code>' + esc(items[i].value) + '</code></td><td>0x' + items[i].offset.toString(16).padStart(8, "0") + '</td></tr>';
      }
      html += '</tbody></table>';
    }
    if (total === 0) {
      html += '<div class="muted">No IoCs found in extracted strings.</div>';
    }
    html += '</div>';
    return html;
  }

  function renderPackers() {
    var strings = extractStrings(fileData, 3);
    var allText = strings.map(function(s) { return s.value; }).join("\n");
    var sectionNames = [];
    var type = detectFileType();
    if (type.type === "pe") {
      var pe = parsePE(fileData);
      if (pe.valid) sectionNames = pe.sections.map(function(s) { return s.name; });
    }
    var detected = [];
    for (var p = 0; p < PACKER_SIGNATURES.length; p++) {
      var packer = PACKER_SIGNATURES[p];
      for (var pat = 0; pat < packer.patterns.length; pat++) {
        if (allText.indexOf(packer.patterns[pat]) >= 0 || sectionNames.indexOf(packer.patterns[pat]) >= 0) {
          detected.push(packer);
          break;
        }
      }
    }
    var html = '<div class="ba-packers">';
    html += '<h3>Packer/Protector Detection</h3>';
    if (detected.length) {
      html += '<div class="ba-packer-warn">Packer/protector signatures detected — the binary may be obfuscated.</div>';
      for (var d = 0; d < detected.length; d++) {
        html += '<div class="ba-packer-card">';
        html += '<div class="ba-packer-name">' + esc(detected[d].name) + '</div>';
        html += '<div class="ba-packer-desc">' + esc(detected[d].desc) + '</div>';
        html += '<div class="muted">Signatures: ' + detected[d].patterns.join(", ") + '</div>';
        html += '</div>';
      }
    } else {
      html += '<div class="pc-ck-ok">No known packer/protector signatures detected.</div>';
      // Check entropy as fallback
      var entropy = calculateEntropy(fileData);
      if (entropy > 7) {
        html += '<div class="ba-packer-warn" style="margin-top:12px">However, the file has very high entropy (' + entropy.toFixed(2) + ') which is characteristic of packed or encrypted binaries. It may use a custom or unknown packer.</div>';
      }
    }
    html += '</div>';
    return html;
  }

  function renderYARATab() {
    var strings = extractStrings(fileData, 6);
    var rule = generateYARA(fileName || "unknown", strings, fileData);
    var html = '<div class="ba-yara">';
    html += '<h3>Auto-Generated YARA Rule</h3>';
    html += '<pre class="pc-hex ba-yara-code">' + esc(rule) + '</pre>';
    html += '<button class="btn" id="ba-yara-copy">Copy Rule</button>';
    html += '<div class="ba-yara-note">This rule is auto-generated from unique strings and byte patterns found in the file. Review and refine before using in production — auto-generated rules may have high false-positive rates. For best results, manually select the most distinctive strings and patterns.</div>';
    html += '</div>';
    return html;
  }

  function wireEvents() {
    // File upload
    var drop = main.querySelector("#ba-drop");
    var fileInput = main.querySelector("#ba-file");
    if (drop) {
      drop.onclick = function() { fileInput.click(); };
      drop.ondragover = function(e) { e.preventDefault(); drop.classList.add("ba-drag"); };
      drop.ondragleave = function() { drop.classList.remove("ba-drag"); };
      drop.ondrop = function(e) {
        e.preventDefault();
        drop.classList.remove("ba-drag");
        if (e.dataTransfer.files.length) loadFile(e.dataTransfer.files[0]);
      };
    }
    if (fileInput) {
      fileInput.onchange = function() { if (fileInput.files.length) loadFile(fileInput.files[0]); };
    }

    // New file button
    var newBtn = main.querySelector("#ba-new");
    if (newBtn) {
      newBtn.onclick = function() { fileData = null; fileName = ""; fileSize = 0; hashes = null; activeTab = "upload"; render(); };
    }

    // Tab clicks
    var tabs = main.querySelector(".pc-tabs");
    if (tabs) {
      tabs.onclick = function(e) {
        var btn = e.target.closest(".pc-tab");
        if (btn) { activeTab = btn.dataset.tab; render(); }
      };
    }

    // Hex navigation
    var hexPrev = main.querySelector("#ba-hex-prev");
    var hexNext = main.querySelector("#ba-hex-next");
    var hexGoBtn = main.querySelector("#ba-hex-go");
    if (hexPrev) hexPrev.onclick = function() { if (hexPage > 0) { hexPage--; render(); } };
    if (hexNext) hexNext.onclick = function() { var total = Math.ceil(fileData.length / hexBytesPerPage); if (hexPage < total - 1) { hexPage++; render(); } };
    if (hexGoBtn) hexGoBtn.onclick = function() {
      var inp = main.querySelector("#ba-hex-goto");
      if (inp) {
        var val = parseInt(inp.value, 16) || parseInt(inp.value) || 0;
        hexPage = Math.floor(val / hexBytesPerPage);
        render();
      }
    };

    // String controls
    var strMin = main.querySelector("#ba-str-min");
    var strFilt = main.querySelector("#ba-str-filter");
    if (strMin) strMin.onchange = function() { strMinLen = parseInt(strMin.value) || 4; render(); };
    if (strFilt) strFilt.oninput = function() { strFilter = strFilt.value; render(); };

    // Disasm controls
    var disGo = main.querySelector("#ba-dis-go");
    if (disGo) disGo.onclick = function() {
      var offEl = main.querySelector("#ba-dis-off");
      var baseEl = main.querySelector("#ba-dis-base");
      if (offEl) disasmOffset = parseInt(offEl.value, 16) || parseInt(offEl.value) || 0;
      if (baseEl) disasmBaseAddr = parseInt(baseEl.value, 16) || parseInt(baseEl.value) || 0;
      render();
    };

    // YARA copy
    var yaraCopy = main.querySelector("#ba-yara-copy");
    if (yaraCopy) yaraCopy.onclick = function() {
      var code = main.querySelector(".ba-yara-code");
      if (code) navigator.clipboard.writeText(code.textContent).then(function() { yaraCopy.textContent = "Copied!"; setTimeout(function() { yaraCopy.textContent = "Copy Rule"; }, 2000); });
    };
  }

  function loadFile(file) {
    fileName = file.name;
    fileSize = file.size;
    var reader = new FileReader();
    reader.onload = function(e) {
      fileData = new Uint8Array(e.target.result);
      activeTab = "overview";
      hexPage = 0;
      hashes = null;
      render();
      // Compute hashes in background
      computeHashes(fileData).then(function(h) {
        hashes = h;
        if (activeTab === "hashes" || activeTab === "overview") render();
      });
    };
    reader.readAsArrayBuffer(file);
  }

  render();
}
