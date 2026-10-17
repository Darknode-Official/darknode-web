// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
// Plain-English help for the bininspect.js mini-tools. See help/README.md for the contract.
// These are read-only parsers, decoders, formatters and reference tables for defenders.
const PE_HEX = "4d5a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000504500006486010000105e5f0000000000000000e00022000b020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002e746578740000000010000000100000001000000004000000000000000000000000000020000060";
const ELF_HEX = "7f454c4602010103000000000000000002003e00010000000010400000000000";
const MACHO_HEX = "cffaedfe07000001030000000200000010000000";

export const HELP = {
  "bi-pe-header": {
    what: "Reads the first bytes of a Windows program (EXE/DLL) that you paste as hex or base64 and decodes its headers: the MZ and PE signatures, the COFF header (target CPU, number of sections, compile timestamp) and the section table. It never runs the file.",
    when: "You have the opening bytes of a suspicious Windows executable and want a quick structural summary without opening it in a disassembler.",
    example: { data: PE_HEX, fmt: "Auto" },
  },
  "bi-pe-machine": {
    what: "Looks up the target CPU (IMAGE_FILE_MACHINE value) from a PE header, by hex value or name. Tells you if a sample is x86, x64, ARM64 and so on.",
    when: "You pulled a Machine value out of a PE header and want to know which processor it targets.",
    example: { q: "0x8664" },
  },
  "bi-pe-characteristics": {
    what: "Decodes the COFF Characteristics number from a PE header into readable flags such as EXECUTABLE_IMAGE, DLL or LARGE_ADDRESS_AWARE.",
    when: "You read a Characteristics value and want to know, for example, whether the file is a DLL or an executable.",
    example: { val: "0x2102" },
  },
  "bi-pe-subsystem": {
    what: "Looks up the Subsystem value from a PE optional header (GUI app, console app, native driver, EFI, ...) by number or name.",
    when: "You want to know whether a Windows binary is a console program, a GUI program or a driver.",
    example: { q: "3" },
  },
  "bi-pe-dllcharacteristics": {
    what: "Decodes the DllCharacteristics number into readable flags, showing which exploit mitigations are on: ASLR (DYNAMIC_BASE), DEP (NX_COMPAT) and Control Flow Guard.",
    when: "You want to see at a glance which memory-protection mitigations a Windows binary was built with.",
    example: { val: "0x8160" },
  },
  "bi-pe-section-flags": {
    what: "Decodes a PE section's Characteristics value into flags such as MEM_EXECUTE, MEM_READ and MEM_WRITE, and warns when a section is both writable and executable.",
    when: "You are reviewing a section table and want to spot a suspicious writable-and-executable section.",
    example: { val: "0xE0000020" },
  },
  "bi-pe-datadir": {
    what: "Reference for the 16 PE data-directory slots by index: 0 is the Export table, 1 the Import table, 9 TLS, 14 the .NET header, and so on. Leave it blank for the full list.",
    when: "You are reading a PE optional header and need to know what a numbered data-directory entry points to.",
    example: { q: "1" },
  },
  "bi-pe-timestamp": {
    what: "Converts a PE compile timestamp (TimeDateStamp, a 32-bit Unix time) into a readable UTC date, from a hex or decimal value.",
    when: "You read a TimeDateStamp from a PE header and want the human date it represents (note: this value can be faked by malware).",
    example: { val: "0x5F5E1000" },
  },
  "bi-pe-rva-offset": {
    what: "Converts between a virtual address (RVA) and a raw file offset using the section table you paste in. You give name,VA,VSize,RawPtr,RawSize per section.",
    when: "You are reading a PE in a hex editor and need to turn an RVA from the headers into the file offset where those bytes actually sit (or back).",
    example: { sections: ".text,0x1000,0x5000,0x400,0x5000\n.data,0x6000,0x1000,0x5400,0x1000", value: "0x1200", dir: "RVA -> File offset" },
  },
  "bi-imphash": {
    what: "Computes the standard imphash: it lowercases your imported dll.function list, joins it and takes the MD5. Two samples with the same imphash import the same functions in the same order.",
    when: "You want a quick fingerprint of a Windows sample's imports to cluster it with related samples (works on name-based imports; resolve ordinals to names first).",
    example: { imports: "KERNEL32.dll!GetProcAddress\nKERNEL32.dll!LoadLibraryA\nWS2_32.dll!recv" },
  },
  "bi-elf-header": {
    what: "Decodes a pasted ELF file's header (Linux/Unix binaries): 32- or 64-bit, byte order, OS ABI, type (executable, shared object, core dump), target CPU and entry point.",
    when: "You have the opening bytes of a Linux binary and want its basic shape without loading it.",
    example: { data: ELF_HEX, fmt: "Auto" },
  },
  "bi-elf-type": {
    what: "Looks up an ELF e_type value: REL (object file), EXEC (executable), DYN (shared library or position-independent executable) or CORE (crash dump).",
    when: "You read an e_type and want to know whether the file is an executable, a library or a core dump.",
    example: { q: "3" },
  },
  "bi-elf-machine": {
    what: "Looks up an ELF e_machine value (the target CPU), such as 62 = x86-64, 183 = AArch64, 3 = x86.",
    when: "You read an e_machine value and want the processor it targets.",
    example: { q: "62" },
  },
  "bi-elf-osabi": {
    what: "Looks up an ELF EI_OSABI value (the target operating-system ABI), such as 0 = System V, 3 = Linux, 9 = FreeBSD.",
    when: "You read the OS/ABI byte from an ELF header and want to know which platform it targets.",
    example: { q: "3" },
  },
  "bi-elf-section-types": {
    what: "Looks up an ELF section-header type (sh_type), such as PROGBITS (code/data), SYMTAB (symbols), DYNAMIC or NOBITS (.bss).",
    when: "You are reading an ELF section header and need to know what a section-type number means.",
    example: { q: "11" },
  },
  "bi-macho-header": {
    what: "Decodes a pasted Mach-O file's header (macOS/iOS binaries): the magic (32/64-bit, byte order, or a fat/universal wrapper), the CPU type and the file type.",
    when: "You have the opening bytes of a macOS binary and want its basic shape.",
    example: { data: MACHO_HEX, fmt: "Auto" },
  },
  "bi-macho-cputype": {
    what: "Looks up a Mach-O cputype value: 7 = x86, 0x01000007 = x86_64, 0x0100000C = ARM64.",
    when: "You read a cputype from a Mach-O header and want the processor it targets.",
    example: { q: "0x01000007" },
  },
  "bi-macho-filetype": {
    what: "Looks up a Mach-O filetype value: MH_EXECUTE (program), MH_DYLIB (library), MH_BUNDLE, MH_OBJECT and so on.",
    when: "You read a Mach-O filetype and want to know whether the file is a program, a library or an object file.",
    example: { q: "2" },
  },
  "bi-magic-bytes": {
    what: "Identifies a file type from the first bytes you paste by matching them against known magic-number signatures (PNG, PDF, ZIP, ELF, PE, gzip, and many more). It does not open any file.",
    when: "You have the leading bytes of an unknown or mislabelled file and want to know what it really is.",
    example: { data: "89504E470D0A1A0A", fmt: "Auto" },
  },
  "bi-byte-reformat": {
    what: "Takes a hex or base64 byte blob and rewrites it in another text format: \\xAA escaped, 0xAA comma list, a C array, a Python bytes literal, spaced hex, bare hex, base64 or decimal. Pure text transform.",
    when: "You need to paste some captured bytes into an analysis notebook or script in a particular syntax.",
    example: { data: "DE AD BE EF", fmt: "Auto", out: "C array" },
  },
  "bi-endian-swap": {
    what: "Reverses the byte order of each 2, 4 or 8-byte word in a hex blob (little-endian to big-endian and back), and for a single word also shows its integer value both ways.",
    when: "You have a value that was stored in the wrong byte order and need to flip it, for example when reading a little-endian field by hand.",
    example: { hex: "0010005E", width: "4" },
  },
  "bi-hex-int": {
    what: "Converts a hex address or pointer to a decimal integer or back, letting you pick width (16/32/64-bit) and whether it is signed.",
    when: "You are reading an address or offset in hex and want the decimal value (or vice versa).",
    example: { val: "0x401000", dir: "Hex -> Integer", width: "64-bit" },
  },
  "bi-struct-ints": {
    what: "Interprets the first bytes of a hex blob as 8-, 16-, 32- and 64-bit integers, both signed and unsigned, in little- and big-endian, so you can read a struct field by hand.",
    when: "You are decoding a binary structure and want to see every plausible integer reading of the same bytes.",
    example: { hex: "78 56 34 12" },
  },
  "bi-hexdump": {
    what: "Shows a hex/base64 blob as a classic hexdump: an offset column, 16 hex bytes per row and an ASCII gutter on the right.",
    when: "You want to eyeball the structure of some bytes the way the xxd or hexdump tool shows them.",
    example: { data: "48656C6C6F2C20776F726C6421", fmt: "Auto" },
  },
  "bi-strings": {
    what: "Pulls readable text out of a byte blob, like the Unix 'strings' tool: runs of printable ASCII (or UTF-16 wide characters) at least as long as you set, each with its offset.",
    when: "You have a chunk of a binary and want to read the URLs, paths and messages hidden in it.",
    example: { data: "68656c6c6f0001776f726c64", fmt: "Auto", mode: "ASCII" },
  },
  "bi-utf16-decode": {
    what: "Decodes a hex/base64 blob as UTF-16 text (little- or big-endian), which is how Windows stores wide strings and how some config blobs are laid out.",
    when: "You have wide-character bytes (every other byte is 00) and want the readable string.",
    example: { data: "68006900", fmt: "Auto", endian: "Little-endian" },
  },
  "bi-decode-chain": {
    what: "Peels nested encodings off an obfuscated string, trying URL-decoding, hex and base64 at each step and showing every layer until it can go no further. Decode only.",
    when: "You have an inert config or command string that has been encoded several times and want to see the plain value.",
    example: { text: "aGVsbG8gd29ybGQh" },
  },
  "bi-b64-extract": {
    what: "Scans a block of text for long base64 runs and decodes each one that turns into mostly readable text, showing where it was found.",
    when: "You are reading a report, log or script and want to decode the base64 chunks buried in it.",
    example: { text: "run this: aGVsbG8gd29ybGQh then exit" },
  },
  "bi-powershell-decode": {
    what: "Decodes a PowerShell -EncodedCommand value (base64 of UTF-16LE text) back into the readable script, which is how encoded PowerShell appears in logs.",
    when: "You found a 'powershell -enc <base64>' command in a log and want to read what it would have run.",
    example: { b64: "VwByAGkAdABlAC0ASABvAHMAdAAgAGgAaQA=" },
  },
  "bi-url-deobfuscate": {
    what: "Recursively percent-decodes a URL or log value, peeling off double or triple encoding, and reports how many layers it removed.",
    when: "You see an over-encoded path in a web log (like %252e%252e%252f) and want the real request it hides.",
    example: { url: "%252e%252e%252fetc%252fpasswd" },
  },
  "bi-charcode-decode": {
    what: "Decodes text that was written as character codes: a String.fromCharCode(...) list, \\xHH or \\uHHHH escapes, or a plain list of decimal/hex codes, back into readable text.",
    when: "You have an inert obfuscated script fragment built from character codes and want the string it produces.",
    example: { text: "String.fromCharCode(104,101,108,108,111)" },
  },
  "bi-xor-bruteforce": {
    what: "Tries all 256 single-byte XOR keys against a byte blob and lists the keys that turn it into mostly readable text, optionally only the ones that contain a word you expect.",
    when: "You have a short string that was hidden with a single-byte XOR and want to recover it.",
    example: { data: "29242d2d2e", fmt: "Auto", crib: "hel" },
  },
  "bi-ioc-extract": {
    what: "Pulls indicators of compromise out of a pasted report or log: IPv4/IPv6 addresses, domains, URLs, email addresses and MD5/SHA-1/SHA-256 hashes, de-duplicated, with optional defanging.",
    when: "You have a threat report or log and want a clean, grouped list of the indicators in it.",
    example: { text: "C2 at 198.51.100.23 and http://bad.example.com/x, hash 44d88612fea8a8f36de82e1278abb02f, mail evil@example.com", defang: true },
  },
  "bi-defang-refang": {
    what: "Switches indicators between live and safe-to-share form: defang turns http://1.2.3.4 into hxxp[://]1[.]2[.]3[.]4 so it is not clickable, and refang turns it back.",
    when: "You are pasting indicators into a report or ticket and want them neutralised (or you received defanged ones and need the real values).",
    example: { text: "http://example.com/path", mode: "Defang" },
  },
  "bi-ioc-normalize": {
    what: "Cleans a list of indicators: it refangs them, lowercases, removes duplicates, sorts and groups them by type (IP, domain, URL, email, hash) with counts.",
    when: "You have a messy indicator list from several sources and want one tidy, de-duplicated set.",
    example: { text: "1[.]2[.]3[.]4\nEXAMPLE.com\nhxxp://bad.example/x\nexample.com" },
  },
  "bi-import-normalize": {
    what: "Sorts, lowercases and de-duplicates a list of imported DLLs/functions (or shared library names), grouped by module, so two samples' imports can be compared side by side.",
    when: "You want to diff the imports of two binaries and need both lists in the same normalised order.",
    example: { text: "KERNEL32.dll!LoadLibraryA\nkernel32.dll!GetProcAddress\nKERNEL32.dll!LoadLibraryA\nlibc.so.6" },
  },
  "bi-hashset-dedupe": {
    what: "Finds every MD5, SHA-1 and SHA-256 hash in messy pasted text, lowercases them, removes duplicates and sorts them by type.",
    when: "You have hashes scattered through notes or a report and want one clean, grouped list for comparison.",
    example: { text: "d41d8cd98f00b204e9800998ecf8427e file1\nDA39A3EE5E6B4B0D3255BFEF95601890AFD80709 file2\nd41d8cd98f00b204e9800998ecf8427e dup" },
  },
  "bi-yara-skeleton": {
    what: "Formats the strings you picked into a well-formed YARA rule template with meta, strings and condition sections. Text strings are quoted, {..} hex and /re/ regex are kept as-is. It is a scaffold, not generated detection logic.",
    when: "You have chosen a few strings from a sample and want a correctly structured YARA rule to fill in.",
    example: { name: "Suspicious_Sample", strings: "cmd.exe /c\nhxxp fragment\n{ 6A 40 68 00 30 }", author: "analyst", desc: "example detection", cond: "any of them" },
  },
  "bi-yara-hex": {
    what: "Turns a hex or base64 byte blob into a YARA hex string like { 6A 40 68 00 30 }, optionally wrapped across lines, ready to paste into a rule.",
    when: "You have some bytes to match and want them formatted as a YARA hex string.",
    example: { data: "6A40680030", fmt: "Auto", name: "$a", wrap: "16" },
  },
  "bi-sigma-skeleton": {
    what: "Formats a Sigma detection-rule scaffold (YAML) from a title, log source and field:value selection lines you provide. A template, not generated logic.",
    when: "You want a correctly structured Sigma rule skeleton to fill in for a SIEM detection.",
    example: { title: "Suspicious PowerShell EncodedCommand", product: "windows", category: "process_creation", selection: "Image|endswith: \\powershell.exe\nCommandLine|contains: -enc", level: "high" },
  },
  "bi-vt-url": {
    what: "Builds the VirusTotal web address for a hash, IP, domain or URL you paste, so you can open the report in your browser. It only formats a link; it does not contact VirusTotal.",
    when: "You have an indicator and want a ready-made VirusTotal report link.",
    example: { ioc: "44d88612fea8a8f36de82e1278abb02f" },
  },
  "bi-base64-inspect": {
    what: "Analyses one base64 string: whether it is valid (standard or URL-safe), its padding, the decoded length in bytes, how much of the result is printable, and any file signature of the decoded bytes.",
    when: "You have a base64 string and want to know what it decodes to before you trust it.",
    example: { b64: "TVqQAAMAAAAEAAAA" },
  },
  "bi-winapi-reference": {
    what: "Explains a Windows API function in plain language and says why malware analysts often flag it, for defensive context. Only functions verified correct are included.",
    when: "You see an unfamiliar Windows API in a sample's imports and want to know what it does and why it matters.",
    example: { q: "CreateRemoteThread" },
  },
  "bi-linux-syscall": {
    what: "Looks up a Linux x86-64 system call by its number or name (for example 59 is execve), using the x86_64 syscall table.",
    when: "You are reading x86-64 shellcode or a strace and want to turn a syscall number into its name.",
    example: { q: "59" },
  },
  "bi-syscall-convention": {
    what: "Shows how Linux system calls pass their number and arguments on each architecture (x86_64, i386, ARM, AArch64) - which register holds the number and which hold the arguments.",
    when: "You are reading assembly around a syscall and need to know which register is the call number and which are the arguments.",
    example: { q: "x86_64" },
  },
  "bi-x86-mnemonic": {
    what: "Explains what a common x86/x64 assembly instruction does (mov, lea, call, xor, syscall and so on). Leave it blank to list the ones covered.",
    when: "You are reading a disassembly and want a one-line reminder of what an instruction does.",
    example: { q: "lea" },
  },
  "bi-x86-opcode": {
    what: "Looks up well-known x86 opcode bytes (0x90 is NOP, 0xCC is INT3, 0xC3 is RET, 0xE8 is CALL) by byte or keyword.",
    when: "You are reading raw bytes of code and want to recognise the common opcodes.",
    example: { q: "CC" },
  },
  "bi-x86-registers": {
    what: "Shows the x86/x64 register size mapping (RAX/EAX/AX/AL and so on) and each register's usual role. Leave it blank for the whole table.",
    when: "You are reading assembly and want to recall how the 64/32/16/8-bit register names line up, or what a register is typically used for.",
    example: { q: "rsi" },
  },
  "bi-eflags": {
    what: "Decodes an x86 EFLAGS value into the status flags that are set (Carry, Zero, Sign, Overflow, Direction and so on).",
    when: "You have a flags value from a debugger and want to see which condition flags are on.",
    example: { val: "0x0246" },
  },
  "bi-abi-convention": {
    what: "Shows how function arguments and return values are passed for the common calling conventions (System V AMD64, Microsoft x64, cdecl, stdcall, fastcall, thiscall).",
    when: "You are reading a function in a disassembler and need to know where its arguments come from.",
    example: { q: "stdcall" },
  },
  "bi-win-memprotect": {
    what: "Decodes a Windows memory-protection value (PAGE_* constants) - for example 0x40 is PAGE_EXECUTE_READWRITE - including modifiers like PAGE_GUARD, and warns on executable+writable pages.",
    when: "You see a protection constant passed to VirtualAlloc/VirtualProtect and want to know what access it grants.",
    example: { val: "0x40" },
  },
  "bi-lolbas": {
    what: "Explains how a built-in Windows binary (certutil, mshta, rundll32, regsvr32 and others) can be abused to live off the land, as defensive reference. Leave blank to list them.",
    when: "You see a trusted Windows tool doing something odd in a log and want to know how attackers abuse it.",
    example: { q: "certutil" },
  },
  "bi-registry-autorun": {
    what: "Reference of common Windows registry autorun and persistence locations - Run keys, Winlogon entries, services and Image File Execution Options. Leave blank for the full list.",
    when: "You are hunting for persistence and want the usual registry locations to check.",
    example: { q: "winlogon" },
  },
  "bi-attack-lookup": {
    what: "Looks up a MITRE ATT&CK Enterprise technique by its T-number or by keyword and shows its name and tactic. A curated, accurate subset of techniques.",
    when: "You see an ATT&CK technique ID in a report (like T1055) and want its name and tactic, or you want the ID for a behaviour.",
    example: { q: "T1055" },
  },
  "bi-attack-tactics": {
    what: "Lists the 14 MITRE ATT&CK Enterprise tactics with their TA numbers, or looks one up by name or number.",
    when: "You need the official tactic names and TA IDs, for example to label a detection.",
    example: { q: "persistence" },
  },
  "bi-killchain": {
    what: "Reference for the seven phases of the Lockheed Martin Cyber Kill Chain, from Reconnaissance through to Actions on Objectives. Leave blank for all phases.",
    when: "You want to map an intrusion's steps onto the kill-chain phases.",
    example: { q: "delivery" },
  },
  "bi-diamond-model": {
    what: "Reference for the four core features of the Diamond Model of intrusion analysis: Adversary, Capability, Infrastructure and Victim.",
    when: "You are structuring an intrusion analysis around the Diamond Model and want the definitions.",
    example: { q: "infrastructure" },
  },
  "bi-pyramid-of-pain": {
    what: "Reference for the Pyramid of Pain, which ranks indicator types by how much blocking them hurts an attacker - hashes are easiest for them to change, TTPs the hardest.",
    when: "You want to explain why behaviour-based detections are more valuable than hash or IP blocks.",
    example: { q: "ttp" },
  },
  "bi-tlp": {
    what: "Explains the FIRST Traffic Light Protocol 2.0 sharing levels (RED, AMBER, AMBER+STRICT, GREEN, CLEAR) used to mark how widely threat intel may be shared.",
    when: "You are labelling or received intel with a TLP marking and want to know the sharing rules.",
    example: { q: "amber" },
  },
  "bi-dll-reference": {
    what: "Explains what a common Windows DLL provides (kernel32 for core OS calls, ws2_32 for sockets, advapi32 for registry and security, and so on). Leave blank to list them.",
    when: "You are reading a sample's imported DLLs and want to know what capability each one brings.",
    example: { q: "ws2_32" },
  },
  "bi-packer-sections": {
    what: "Maps a PE section name to the packer that usually produces it (UPX0/UPX1 for UPX, .aspack for ASPack, and so on). A hint toward packing, not proof.",
    when: "You see an unusual section name in a PE and want to know if a known packer created it.",
    example: { q: "UPX1" },
  },
};
