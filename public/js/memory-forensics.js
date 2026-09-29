// Memory Forensics — hex viewer, process tree, Volatility reference, YARA scanning, memory structures
// All analysis runs client-side. Nothing leaves the browser.
const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// ─── Volatility 2 & 3 plugin reference ───
const VOLATILITY_PLUGINS = [
  { name: "pslist", vol2: "pslist", vol3: "windows.pslist", desc: "List running processes via EPROCESS doubly-linked list traversal", output: "PID, PPID, name, threads, handles, start time", lookFor: "Unusual process names, orphaned processes, processes with many threads", category: "Process" },
  { name: "pstree", vol2: "pstree", vol3: "windows.pstree", desc: "Display process parent-child relationships as a tree", output: "Hierarchical PID/PPID/name tree", lookFor: "cmd.exe spawned from unusual parents, PowerShell under svchost, nested suspicious trees", category: "Process" },
  { name: "psscan", vol2: "psscan", vol3: "windows.psscan", desc: "Scan for EPROCESS objects in physical memory (catches hidden/unlinked processes)", output: "Same as pslist but includes terminated and hidden processes", lookFor: "Processes not in pslist output = DKOM (Direct Kernel Object Manipulation) rootkit", category: "Process" },
  { name: "psxview", vol2: "psxview", vol3: "N/A", desc: "Cross-reference process listings from multiple sources (pslist, psscan, thrdproc, csrss, session)", output: "Matrix of True/False per detection method per process", lookFor: "Processes visible in psscan but not pslist indicate DKOM hiding", category: "Process" },
  { name: "netscan", vol2: "netscan", vol3: "windows.netscan", desc: "Scan for network connections and listening sockets", output: "Protocol, local/remote addr:port, state, PID, owner", lookFor: "C2 connections, unusual ports (4444, 5555, 8080), connections to known bad IPs", category: "Network" },
  { name: "netstat", vol2: "connections/connscan", vol3: "windows.netstat", desc: "List active network connections (newer Windows)", output: "Protocol, addresses, state, PID", lookFor: "Same as netscan — established connections to suspicious destinations", category: "Network" },
  { name: "malfind", vol2: "malfind", vol3: "windows.malfind", desc: "Find injected/hidden code in process memory (PAGE_EXECUTE_READWRITE)", output: "Process, VAD address, protection flags, hex dump of first bytes", lookFor: "MZ headers in non-image VADs, PAGE_EXECUTE_READWRITE regions, shellcode patterns (FC E8, 4D 5A)", category: "Malware" },
  { name: "dlllist", vol2: "dlllist", vol3: "windows.dlllist", desc: "List loaded DLLs per process from PEB InLoadOrderModuleList", output: "PID, base address, size, path for each DLL", lookFor: "DLLs loaded from temp/user directories, misspelled system DLLs, unsigned DLLs", category: "Module" },
  { name: "ldrmodules", vol2: "ldrmodules", vol3: "N/A", desc: "Cross-reference DLLs from three PEB lists (InLoad, InInit, InMem)", output: "PID, base, InLoad, InInit, InMem, mapped path", lookFor: "False in one or more columns = DLL hiding/unlinking", category: "Module" },
  { name: "handles", vol2: "handles", vol3: "windows.handles", desc: "List open handles (files, registry keys, mutexes, events, etc.)", output: "PID, handle value, type, granted access, name", lookFor: "Handles to \\Device\\Afd (network), suspicious mutexes, named pipes", category: "Handle" },
  { name: "filescan", vol2: "filescan", vol3: "windows.filescan", desc: "Scan physical memory for FILE_OBJECT structures", output: "Physical offset, file name, pointers, handles", lookFor: "Temp files, files in recycle bin, suspicious executables, recently created files", category: "File" },
  { name: "dumpfiles", vol2: "dumpfiles", vol3: "windows.dumpfiles", desc: "Extract cached files from memory (data/image sections)", output: "Extracted files on disk", lookFor: "Recover malware binaries, documents, scripts from memory", category: "File" },
  { name: "hivelist", vol2: "hivelist", vol3: "windows.registry.hivelist", desc: "List registry hives loaded in memory", output: "Virtual/physical offsets, hive path", lookFor: "All standard hives present; additional hives may be malware persistence", category: "Registry" },
  { name: "printkey", vol2: "printkey", vol3: "windows.registry.printkey", desc: "Print a registry key and its subkeys/values", output: "Key name, last write time, subkeys, values", lookFor: "Run/RunOnce keys, Services, Image File Execution Options, Shell extensions", category: "Registry" },
  { name: "hashdump", vol2: "hashdump", vol3: "windows.hashdump", desc: "Dump password hashes from the SAM hive", output: "username:RID:LM:NTLM format", lookFor: "Credential harvesting evidence; crack with hashcat/john", category: "Credential" },
  { name: "lsadump", vol2: "lsadump", vol3: "windows.lsadump", desc: "Dump LSA secrets (service account passwords, cached credentials)", output: "Secret name, decrypted value", lookFor: "Plaintext service account passwords, VPN credentials, autologon passwords", category: "Credential" },
  { name: "cachedump", vol2: "cachedump", vol3: "windows.cachedump", desc: "Dump domain cached credentials (MSCash2)", output: "username:hash pairs", lookFor: "Cached domain credentials that can be cracked offline", category: "Credential" },
  { name: "timeliner", vol2: "timeliner", vol3: "timeliner", desc: "Create a timeline of all timestamped artifacts", output: "Timestamp, type, source, details", lookFor: "Cluster of activity around incident time, process creation/file access patterns", category: "Timeline" },
  { name: "mftparser", vol2: "mftparser", vol3: "windows.mftscan.MFTScan", desc: "Parse the $MFT for file metadata", output: "MFT entry, filename, timestamps (MACB), size, flags", lookFor: "Timestomping ($SI vs $FN mismatch), recently created executables, ADS", category: "File" },
  { name: "shimcache", vol2: "shimcachemem", vol3: "windows.shimcachemem", desc: "Parse the Application Compatibility Cache (ShimCache)", output: "Last modified time, path, execution flag", lookFor: "Evidence of program execution, lateral movement tools, renamed system utilities", category: "Artifact" },
  { name: "userassist", vol2: "userassist", vol3: "windows.registry.userassist", desc: "Parse UserAssist registry keys (ROT13 encoded program execution tracking)", output: "Program path (decoded), run count, last run time, focus time", lookFor: "What programs the user ran, how often, when — key for insider threat", category: "Artifact" },
  { name: "svcscan", vol2: "svcscan", vol3: "windows.svcscan", desc: "Scan for Windows service structures", output: "Service name, display name, type, state, binary path, PID", lookFor: "Services with unusual binary paths, services running from temp, disabled AV services", category: "Service" },
  { name: "driverirp", vol2: "driverirp", vol3: "windows.driverirp", desc: "List IRP (I/O Request Packet) handler addresses for drivers", output: "Driver name, IRP function, handler address, module", lookFor: "IRP handlers pointing outside the driver module = IRP hooking rootkit", category: "Rootkit" },
  { name: "ssdt", vol2: "ssdt", vol3: "windows.ssdt", desc: "Display System Service Descriptor Table entries", output: "Index, function address, owning module", lookFor: "SSDT entries pointing to non-ntoskrnl modules = SSDT hooking rootkit", category: "Rootkit" },
  { name: "callbacks", vol2: "callbacks", vol3: "windows.callbacks", desc: "List kernel notification callbacks (process, thread, image load, registry, shutdown)", output: "Type, callback address, owning module, detail", lookFor: "Callbacks in non-standard modules = rootkit monitoring", category: "Rootkit" },
  { name: "modules", vol2: "modules", vol3: "windows.modules", desc: "List loaded kernel modules via PsLoadedModuleList", output: "Base, size, name, path", lookFor: "Unknown drivers, drivers loaded from unusual paths", category: "Module" },
  { name: "modscan", vol2: "modscan", vol3: "windows.modscan", desc: "Scan for LDR_DATA_TABLE_ENTRY objects (catches unlinked modules)", output: "Same as modules but includes hidden/unlinked", lookFor: "Modules in modscan but not modules = hidden rootkit driver", category: "Module" },
  { name: "vadinfo", vol2: "vadinfo", vol3: "windows.vadinfo", desc: "Display detailed VAD (Virtual Address Descriptor) information per process", output: "Start/end address, tag, protection, flags, filename", lookFor: "PAGE_EXECUTE_READWRITE without a file backing, large anonymous regions", category: "Memory" },
  { name: "vadtree", vol2: "vadtree", vol3: "windows.vadtree", desc: "Display VAD tree in graphical/tree format", output: "AVL tree of virtual address descriptors", lookFor: "Visualize memory layout, find injected regions", category: "Memory" },
  { name: "cmdscan", vol2: "cmdscan", vol3: "windows.cmdscan", desc: "Scan for COMMAND_HISTORY structures (cmd.exe command history)", output: "Application, command count, commands typed", lookFor: "Attacker's commands in cmd.exe: whoami, net user, ipconfig, reconnaissance", category: "Artifact" },
  { name: "consoles", vol2: "consoles", vol3: "windows.consoles", desc: "Scan for CONSOLE_INFORMATION structures (full console I/O)", output: "Console title, input/output history", lookFor: "Full command input AND output — richer than cmdscan", category: "Artifact" },
  { name: "clipboard", vol2: "clipboard", vol3: "windows.clipboard", desc: "Extract clipboard contents", output: "Format, handle, data", lookFor: "Copied passwords, commands, sensitive data", category: "Artifact" },
  { name: "screenshot", vol2: "screenshot", vol3: "windows.screenshot", desc: "Reconstruct desktop screenshots from GDI bitmaps", output: "BMP files of each window/desktop", lookFor: "Visual evidence of what the user/attacker was doing", category: "Artifact" },
  { name: "mutantscan", vol2: "mutantscan", vol3: "windows.mutantscan", desc: "Scan for KMUTANT objects (named mutexes)", output: "Physical offset, name, thread, CID", lookFor: "Known malware mutexes (check VirusTotal, Malpedia for mutex names)", category: "Handle" },
  { name: "idt", vol2: "idt", vol3: "N/A", desc: "Display Interrupt Descriptor Table entries", output: "Index, GDT selector, address, module", lookFor: "IDT entries hooked by rootkits (pointing to non-standard code)", category: "Rootkit" },
  { name: "gdt", vol2: "gdt", vol3: "N/A", desc: "Display Global Descriptor Table", output: "Index, base, limit, type, DPL, flags", lookFor: "Call gate entries used for privilege escalation", category: "Rootkit" },
  { name: "envars", vol2: "envars", vol3: "windows.envars", desc: "Display process environment variables", output: "PID, variable name, value", lookFor: "Modified PATH, proxy settings, unusual variables set by malware", category: "Process" },
  { name: "cmdline", vol2: "cmdline", vol3: "windows.cmdline", desc: "Show command line arguments for each process", output: "PID, process name, command line", lookFor: "Encoded PowerShell (-EncodedCommand), suspicious arguments, living-off-the-land", category: "Process" },
  { name: "getsids", vol2: "getsids", vol3: "windows.getsids", desc: "List SIDs associated with each process", output: "PID, SID, name", lookFor: "Processes running under unexpected accounts, SYSTEM processes that should be user-level", category: "Process" },
  { name: "privs", vol2: "privs", vol3: "windows.privileges", desc: "List privileges for each process", output: "PID, privilege name, attributes (present, enabled, default)", lookFor: "SeDebugPrivilege enabled on unexpected processes, SeImpersonatePrivilege", category: "Process" },
  { name: "apihooks", vol2: "apihooks", vol3: "N/A", desc: "Detect API hooks (inline, IAT, EAT) in process memory", output: "Process, hook type, function, hook address, disassembly", lookFor: "IAT/inline hooks in standard DLLs = API hooking malware/rootkit", category: "Malware" },
  { name: "thrdscan", vol2: "thrdscan", vol3: "windows.thrdscan", desc: "Scan for ETHREAD objects", output: "Thread ID, PID, start address, create time, state", lookFor: "Threads with start addresses in non-module memory = injected code", category: "Process" },
  { name: "memmap", vol2: "memmap", vol3: "windows.memmap", desc: "Display memory map for a process (virtual to physical)", output: "Virtual address, physical address, size", lookFor: "Map entire address space for a process, useful for manual analysis", category: "Memory" },
  { name: "procdump", vol2: "procdump", vol3: "windows.dumpfiles", desc: "Dump a process executable from memory", output: "Reconstructed PE file on disk", lookFor: "Extract unpacked/decrypted malware from memory after it runs", category: "Extraction" },
  { name: "vaddump", vol2: "vaddump", vol3: "windows.vadyarascan", desc: "Dump individual VAD sections from a process", output: "Raw memory dumps per VAD region", lookFor: "Extract injected code regions for analysis", category: "Extraction" },
  { name: "yarascan", vol2: "yarascan", vol3: "yarascan", desc: "Scan memory with YARA rules", output: "Rule name, match offset, owning process/module, matched strings", lookFor: "Apply YARA rules for specific malware families, IOCs, shellcode patterns", category: "Scanning" },
  { name: "strings", vol2: "strings (external)", vol3: "strings (external)", desc: "Extract ASCII/Unicode strings and map to processes", output: "String, owning process, virtual address", lookFor: "URLs, IPs, file paths, error messages, C2 domains in process memory", category: "Scanning" },
];

// ─── Windows memory structures reference ───
const MEMORY_STRUCTURES = {
  "EPROCESS": {
    description: "Executive Process — kernel structure representing a Windows process. Contains all process metadata.",
    fields: [
      { offset: "0x000", name: "Pcb (KPROCESS)", type: "KPROCESS", desc: "Kernel process block — scheduling, affinity, base priority" },
      { offset: "0x0B8", name: "ProcessLock", type: "EX_PUSH_LOCK", desc: "Lock for process structure access" },
      { offset: "0x0C0", name: "UniqueProcessId", type: "HANDLE", desc: "Process ID (PID)" },
      { offset: "0x0C8", name: "ActiveProcessLinks", type: "LIST_ENTRY", desc: "Doubly-linked list connecting all active EPROCESS objects — what pslist walks. DKOM unlinks here." },
      { offset: "0x0E0", name: "RundownProtect", type: "EX_RUNDOWN_REF", desc: "Rundown protection reference" },
      { offset: "0x0F0", name: "Flags2", type: "ULONG", desc: "Process flags (protected process, etc.)" },
      { offset: "0x0F4", name: "Flags", type: "ULONG", desc: "Process flags (has been debugged, has address space, etc.)" },
      { offset: "0x100", name: "CreateTime", type: "LARGE_INTEGER", desc: "When the process was created" },
      { offset: "0x110", name: "ProcessQuotaUsage", type: "SIZE_T[2]", desc: "Current quota usage (non-paged, paged)" },
      { offset: "0x120", name: "ProcessQuotaPeak", type: "SIZE_T[2]", desc: "Peak quota usage" },
      { offset: "0x130", name: "PeakVirtualSize", type: "SIZE_T", desc: "Peak virtual memory size" },
      { offset: "0x138", name: "VirtualSize", type: "SIZE_T", desc: "Current virtual memory size" },
      { offset: "0x148", name: "SessionProcessLinks", type: "LIST_ENTRY", desc: "Links to other processes in the same session" },
      { offset: "0x170", name: "ExceptionPortData", type: "PVOID", desc: "Exception port" },
      { offset: "0x178", name: "Token", type: "EX_FAST_REF", desc: "Process token — security context, privileges, group memberships" },
      { offset: "0x1E0", name: "ObjectTable", type: "PHANDLE_TABLE", desc: "Handle table — all open handles" },
      { offset: "0x200", name: "InheritedFromUniqueProcessId", type: "HANDLE", desc: "Parent process ID (PPID)" },
      { offset: "0x2E0", name: "Peb", type: "PPEB", desc: "Pointer to Process Environment Block in user space" },
      { offset: "0x2E8", name: "Session", type: "PMM_SESSION_SPACE", desc: "Pointer to session object" },
      { offset: "0x300", name: "ImageFilePointer", type: "PFILE_OBJECT", desc: "File object for the process executable" },
      { offset: "0x338", name: "ThreadListHead", type: "LIST_ENTRY", desc: "List of all threads in the process" },
      { offset: "0x370", name: "ActiveThreads", type: "ULONG", desc: "Number of active threads" },
      { offset: "0x3F8", name: "ImageFileName", type: "UCHAR[15]", desc: "First 15 characters of the executable filename" },
      { offset: "0x448", name: "ExitStatus", type: "NTSTATUS", desc: "Exit status if process has terminated" },
      { offset: "0x450", name: "ExitTime", type: "LARGE_INTEGER", desc: "When the process exited" },
    ]
  },
  "PEB": {
    description: "Process Environment Block — user-mode structure containing process startup info, loaded modules, heap info.",
    fields: [
      { offset: "0x000", name: "InheritedAddressSpace", type: "BOOLEAN", desc: "Whether address space was inherited from parent" },
      { offset: "0x001", name: "ReadImageFileExecOptions", type: "BOOLEAN", desc: "Image File Execution Options checked" },
      { offset: "0x002", name: "BeingDebugged", type: "BOOLEAN", desc: "1 if process is being debugged — anti-debug check target" },
      { offset: "0x003", name: "BitField", type: "UCHAR", desc: "Bitfield flags" },
      { offset: "0x010", name: "ImageBaseAddress", type: "PVOID", desc: "Base address of the main executable" },
      { offset: "0x018", name: "Ldr", type: "PPEB_LDR_DATA", desc: "Pointer to loader data — contains three module lists" },
      { offset: "0x020", name: "ProcessParameters", type: "PRTL_USER_PROCESS_PARAMETERS", desc: "Command line, environment, current directory, DLL path" },
      { offset: "0x028", name: "SubSystemData", type: "PVOID", desc: "Subsystem-specific data" },
      { offset: "0x030", name: "ProcessHeap", type: "PVOID", desc: "Default process heap address" },
      { offset: "0x038", name: "FastPebLock", type: "PRTL_CRITICAL_SECTION", desc: "Lock for PEB access" },
      { offset: "0x060", name: "TlsBitmap", type: "PVOID", desc: "Thread Local Storage bitmap" },
      { offset: "0x078", name: "NumberOfProcessors", type: "ULONG", desc: "Number of processors" },
      { offset: "0x07C", name: "NtGlobalFlag", type: "ULONG", desc: "NT global flags — FLG_HEAP_ENABLE_* for debug detection" },
      { offset: "0x0BC", name: "NumberOfHeaps", type: "ULONG", desc: "Number of process heaps" },
      { offset: "0x0C0", name: "MaximumNumberOfHeaps", type: "ULONG", desc: "Maximum heap count" },
      { offset: "0x0C8", name: "ProcessHeaps", type: "PPVOID", desc: "Array of heap base addresses" },
    ]
  },
  "TEB": {
    description: "Thread Environment Block — per-thread structure in user mode containing thread-local data.",
    fields: [
      { offset: "0x000", name: "NtTib", type: "NT_TIB", desc: "NT Thread Information Block (SEH chain, stack base/limit, self-pointer)" },
      { offset: "0x030", name: "EnvironmentPointer", type: "PVOID", desc: "Environment data" },
      { offset: "0x038", name: "ClientId", type: "CLIENT_ID", desc: "PID and TID for this thread" },
      { offset: "0x050", name: "ThreadLocalStoragePointer", type: "PVOID", desc: "TLS slot array" },
      { offset: "0x060", name: "ProcessEnvironmentBlock", type: "PPEB", desc: "Pointer to PEB — gs:[0x60] on x64" },
      { offset: "0x068", name: "LastErrorValue", type: "ULONG", desc: "GetLastError() value" },
      { offset: "0x1250", name: "GdiTebBatch", type: "GDI_TEB_BATCH", desc: "GDI batching structure" },
    ]
  },
  "KTHREAD": {
    description: "Kernel Thread structure — scheduling state, priority, stack, wait information.",
    fields: [
      { offset: "0x000", name: "Header", type: "DISPATCHER_HEADER", desc: "Object header for synchronization" },
      { offset: "0x028", name: "InitialStack", type: "PVOID", desc: "Top of kernel stack" },
      { offset: "0x030", name: "StackLimit", type: "PVOID", desc: "Bottom of kernel stack" },
      { offset: "0x038", name: "StackBase", type: "PVOID", desc: "Stack base address" },
      { offset: "0x058", name: "KernelStack", type: "PVOID", desc: "Current kernel stack pointer" },
      { offset: "0x074", name: "Priority", type: "SCHAR", desc: "Current thread priority" },
      { offset: "0x078", name: "BasePriority", type: "SCHAR", desc: "Base thread priority" },
      { offset: "0x0B8", name: "State", type: "UCHAR", desc: "Thread state: 0=Init, 1=Ready, 2=Running, 3=Standby, 4=Terminated, 5=Waiting" },
      { offset: "0x100", name: "Teb", type: "PVOID", desc: "Pointer to Thread Environment Block" },
      { offset: "0x1A0", name: "StartAddress", type: "PVOID", desc: "Thread entry point — suspicious if in non-module memory" },
      { offset: "0x1B8", name: "Win32StartAddress", type: "PVOID", desc: "CreateThread start address" },
      { offset: "0x1C0", name: "CreateTime", type: "ULONGLONG", desc: "Thread creation time" },
    ]
  },
  "OBJECT_HEADER": {
    description: "Object Manager header — precedes every kernel object. Contains type index, reference count, security descriptor.",
    fields: [
      { offset: "-0x30", name: "SecurityDescriptor", type: "PVOID", desc: "Pointer to security descriptor" },
      { offset: "-0x18", name: "TypeIndex", type: "UCHAR", desc: "Index into ObTypeIndexTable — identifies object type" },
      { offset: "-0x17", name: "InfoMask", type: "UCHAR", desc: "Bitmask of optional headers present" },
      { offset: "-0x08", name: "HandleCount", type: "LONG", desc: "Number of open handles to this object" },
      { offset: "-0x04", name: "PointerCount", type: "LONG", desc: "Reference count" },
      { offset: "0x000", name: "Body", type: "varies", desc: "The actual object (EPROCESS, ETHREAD, FILE_OBJECT, etc.)" },
    ]
  },
};

// ─── Pool tags reference ───
const POOL_TAGS = [
  { tag: "Proc", desc: "EPROCESS objects — kernel process structures", module: "nt" },
  { tag: "Thre", desc: "ETHREAD objects — kernel thread structures", module: "nt" },
  { tag: "File", desc: "FILE_OBJECT — open file instances", module: "nt" },
  { tag: "Driv", desc: "DRIVER_OBJECT — loaded kernel drivers", module: "nt" },
  { tag: "Devi", desc: "DEVICE_OBJECT — device instances", module: "nt" },
  { tag: "ObDi", desc: "Object directory entries", module: "nt" },
  { tag: "MmCa", desc: "Memory Manager control areas (section objects)", module: "nt" },
  { tag: "MmSt", desc: "Memory Manager segment structures", module: "nt" },
  { tag: "MmPt", desc: "Memory Manager page table pages", module: "nt" },
  { tag: "CcSc", desc: "Cache Manager shared cache map", module: "nt" },
  { tag: "CcBc", desc: "Cache Manager BCB (Buffer Control Block)", module: "nt" },
  { tag: "Ica ", desc: "ICA connection/channel data — Terminal Services", module: "termdd" },
  { tag: "Irp ", desc: "IRP (I/O Request Packet) — I/O operation descriptor", module: "nt" },
  { tag: "TCPT", desc: "TCP/IP transport — TCP connection endpoints", module: "tcpip" },
  { tag: "UDPA", desc: "UDP/IP transport — UDP endpoints", module: "tcpip" },
  { tag: "IPXa", desc: "IPX/SPX transport", module: "nwlnkipx" },
  { tag: "NbtW", desc: "NetBT (NetBIOS over TCP) work context", module: "netbt" },
  { tag: "SmbW", desc: "SMB/CIFS work context", module: "mrxsmb" },
  { tag: "Ntfs", desc: "NTFS general allocation", module: "ntfs" },
  { tag: "FatF", desc: "FAT filesystem FCB (File Control Block)", module: "fastfat" },
  { tag: "Sect", desc: "Section objects (memory-mapped files)", module: "nt" },
  { tag: "Toke", desc: "Security token objects", module: "nt" },
  { tag: "Key ", desc: "Registry key objects (CM_KEY_BODY)", module: "nt" },
  { tag: "CM31", desc: "Registry Configuration Manager", module: "nt" },
  { tag: "Muta", desc: "KMUTANT — kernel mutex objects", module: "nt" },
  { tag: "Even", desc: "KEVENT — kernel event objects", module: "nt" },
  { tag: "Sema", desc: "KSEMAPHORE — kernel semaphore objects", module: "nt" },
  { tag: "Time", desc: "KTIMER — kernel timer objects", module: "nt" },
  { tag: "Port", desc: "LPC port objects (ALPC)", module: "nt" },
  { tag: "ALPC", desc: "ALPC (Advanced Local Procedure Call) structures", module: "nt" },
  { tag: "Symt", desc: "Symbolic link objects", module: "nt" },
  { tag: "FMfn", desc: "Filter Manager file name information", module: "fltmgr" },
  { tag: "FMic", desc: "Filter Manager instance context", module: "fltmgr" },
  { tag: "Usqm", desc: "USB hub queue management", module: "usbhub" },
  { tag: "HidC", desc: "HID class driver", module: "hidclass" },
  { tag: "Wndf", desc: "WDF (Windows Driver Framework) structures", module: "wdf01000" },
  { tag: "WfpA", desc: "Windows Filtering Platform — firewall allocation", module: "netio" },
  { tag: "NDnd", desc: "NDIS (Network Driver Interface) structures", module: "ndis" },
  { tag: "AfdE", desc: "AFD (Ancillary Function Driver) endpoint — socket structures", module: "afd" },
  { tag: "Powe", desc: "Power management IRP", module: "nt" },
];

// ─── Malware indicators in memory ───
const MALWARE_INDICATORS = {
  "Code Injection": [
    { name: "Process Hollowing", desc: "Create suspended process, unmap legitimate image, map malicious PE, resume. Memory shows: process with expected name but unexpected image base/size.", detection: "Compare PEB ImageBaseAddress with on-disk PE base. malfind shows MZ header in private memory.", mitre: "T1055.012" },
    { name: "Reflective DLL Injection", desc: "Load DLL from memory without touching disk — custom loader resolves imports and relocations.", detection: "malfind shows PE headers (MZ/PE signature) in non-image VAD regions. No corresponding file on disk.", mitre: "T1055.001" },
    { name: "Process Doppelganging", desc: "Uses NTFS transactions to create a process from a transacted (never-committed) file.", detection: "Process image file cannot be found on disk. Section object points to transacted file.", mitre: "T1055.013" },
    { name: "APC Injection", desc: "Queue an Asynchronous Procedure Call containing shellcode to a thread in a target process.", detection: "Unexpected executable memory in target process. Thread start address in unusual location.", mitre: "T1055.004" },
    { name: "Thread Execution Hijacking", desc: "Suspend a thread, modify its context (instruction pointer) to point to injected code.", detection: "Thread context shows start/current address in non-module memory.", mitre: "T1055.003" },
    { name: "Atom Bombing", desc: "Use the global atom table to write shellcode into a target process, then trigger execution via APC.", detection: "Unusual atom table entries containing binary data. Non-module code execution.", mitre: "T1055" },
    { name: "Module Stomping / DLL Hollowing", desc: "Load a legitimate DLL, then overwrite its .text section with malicious code.", detection: "DLL loaded normally but .text section hash differs from on-disk version.", mitre: "T1055.001" },
    { name: "Early Bird Injection", desc: "Inject code into a process before its entry point executes (before AV hooks).", detection: "Injected code present before process initialization completes.", mitre: "T1055" },
  ],
  "API Hooking": [
    { name: "IAT Hooking", desc: "Overwrite Import Address Table entries to redirect API calls to malicious code.", detection: "ldrmodules / dlllist shows IAT entries pointing to non-matching DLLs. apihooks detects.", mitre: "T1056" },
    { name: "EAT Hooking", desc: "Modify Export Address Table of a DLL to redirect function resolution.", detection: "EAT entries point to unexpected addresses.", mitre: "T1056" },
    { name: "Inline Hooking (Detour)", desc: "Overwrite first bytes of a function with a JMP to hook code.", detection: "apihooks shows modified function prologues (E9 xx xx xx xx = JMP). First 5+ bytes differ from on-disk.", mitre: "T1056" },
    { name: "SSDT Hooking", desc: "Replace System Service Descriptor Table entries to intercept syscalls.", detection: "ssdt plugin shows entries pointing outside ntoskrnl/win32k.", mitre: "T1014" },
  ],
  "Rootkit Techniques": [
    { name: "DKOM (Direct Kernel Object Manipulation)", desc: "Unlink process from ActiveProcessLinks to hide from task manager and pslist.", detection: "Process visible in psscan but not pslist. psxview shows discrepancy.", mitre: "T1014" },
    { name: "SSDT Hook", desc: "Replace system call handler addresses in the SSDT with rootkit functions.", detection: "ssdt plugin — entries should point to ntoskrnl.exe or win32k.sys only.", mitre: "T1014" },
    { name: "IDT Hook", desc: "Modify Interrupt Descriptor Table to intercept hardware/software interrupts.", detection: "idt plugin — all entries should point to nt/hal code.", mitre: "T1014" },
    { name: "IRP Hook", desc: "Replace I/O Request Packet handler function pointers in driver objects.", detection: "driverirp shows handler addresses outside the owning driver module.", mitre: "T1014" },
    { name: "Callback Manipulation", desc: "Register malicious kernel callbacks or modify legitimate callback lists.", detection: "callbacks plugin — unknown modules in callback list.", mitre: "T1014" },
    { name: "Filter Driver", desc: "Insert a minifilter or legacy filter driver to intercept I/O at the driver stack level.", detection: "Unexpected filter drivers in the device stack. Check with modules/modscan.", mitre: "T1014" },
  ]
};

// ─── Linux memory analysis reference ───
const LINUX_STRUCTURES = {
  "task_struct": {
    description: "Linux process descriptor — equivalent of Windows EPROCESS. Contains all process state.",
    fields: [
      { name: "state", desc: "Process state: TASK_RUNNING, TASK_INTERRUPTIBLE, TASK_ZOMBIE, etc." },
      { name: "pid", desc: "Process ID (kernel space PID, may differ from namespace PID)" },
      { name: "tgid", desc: "Thread Group ID (visible PID in userspace)" },
      { name: "real_parent", desc: "Pointer to real parent task_struct (biological parent)" },
      { name: "parent", desc: "Pointer to adoptive parent (may differ after ptrace)" },
      { name: "children", desc: "List head for child processes" },
      { name: "sibling", desc: "List entry for sibling processes" },
      { name: "comm[TASK_COMM_LEN]", desc: "Executable name (first 15 chars + null)" },
      { name: "mm", desc: "Pointer to mm_struct (memory descriptor) — NULL for kernel threads" },
      { name: "cred", desc: "Pointer to credentials (uid, gid, capabilities)" },
      { name: "fs", desc: "Filesystem information (root, pwd)" },
      { name: "files", desc: "Open file descriptor table" },
      { name: "nsproxy", desc: "Namespace proxy (PID, mount, network, IPC, UTS namespaces)" },
      { name: "signal", desc: "Signal handling information" },
      { name: "tasks", desc: "Linked list connecting all tasks — what pslist walks" },
    ]
  },
  "mm_struct": {
    description: "Memory descriptor — describes a process's virtual address space.",
    fields: [
      { name: "mmap", desc: "Linked list of vm_area_struct (VMAs) — each represents one mapped region" },
      { name: "pgd", desc: "Pointer to page global directory (page table root)" },
      { name: "map_count", desc: "Number of VMAs" },
      { name: "total_vm", desc: "Total number of pages mapped" },
      { name: "start_code / end_code", desc: "Text segment boundaries" },
      { name: "start_data / end_data", desc: "Data segment boundaries" },
      { name: "start_brk / brk", desc: "Heap boundaries" },
      { name: "start_stack", desc: "Stack start address" },
      { name: "arg_start / arg_end", desc: "Command line arguments location" },
      { name: "env_start / env_end", desc: "Environment variables location" },
    ]
  },
  "/proc filesystem": {
    description: "Virtual filesystem exposing kernel data structures — primary source for live forensics.",
    fields: [
      { name: "/proc/[pid]/maps", desc: "Memory mappings — addresses, permissions, backing files" },
      { name: "/proc/[pid]/status", desc: "Process status — name, state, UIDs, memory stats, capabilities" },
      { name: "/proc/[pid]/cmdline", desc: "Command line arguments (null-separated)" },
      { name: "/proc/[pid]/environ", desc: "Environment variables (null-separated)" },
      { name: "/proc/[pid]/fd/", desc: "Directory of open file descriptors (symlinks to files/sockets/pipes)" },
      { name: "/proc/[pid]/exe", desc: "Symlink to the executed binary" },
      { name: "/proc/[pid]/cwd", desc: "Symlink to current working directory" },
      { name: "/proc/[pid]/root", desc: "Symlink to root directory (chroot)" },
      { name: "/proc/[pid]/net/tcp", desc: "TCP connections (hex-encoded addresses)" },
      { name: "/proc/[pid]/net/udp", desc: "UDP sockets" },
      { name: "/proc/[pid]/smaps", desc: "Detailed memory map with RSS, PSS, shared/private pages" },
      { name: "/proc/[pid]/stack", desc: "Kernel stack trace for the process" },
      { name: "/proc/[pid]/task/", desc: "Per-thread information" },
      { name: "/proc/kcore", desc: "Physical memory in ELF core format — requires root" },
      { name: "/proc/kallsyms", desc: "Kernel symbol table with addresses" },
      { name: "/proc/modules", desc: "Loaded kernel modules" },
      { name: "/proc/iomem", desc: "I/O memory map" },
      { name: "/proc/version", desc: "Kernel version string" },
    ]
  }
};

// ─── Hex viewer functions ───
function formatHexView(bytes, startOffset) {
  startOffset = startOffset || 0;
  var lines = [];
  for (var i = 0; i < bytes.length; i += 16) {
    var offset = (startOffset + i).toString(16).toUpperCase().padStart(8, "0");
    var hexParts = [];
    var asciiParts = [];
    for (var j = 0; j < 16; j++) {
      if (i + j < bytes.length) {
        hexParts.push(bytes[i + j].toString(16).toUpperCase().padStart(2, "0"));
        var ch = bytes[i + j];
        asciiParts.push(ch >= 32 && ch < 127 ? String.fromCharCode(ch) : ".");
      } else {
        hexParts.push("  ");
        asciiParts.push(" ");
      }
    }
    var hex1 = hexParts.slice(0, 8).join(" ");
    var hex2 = hexParts.slice(8).join(" ");
    lines.push(offset + "  " + hex1 + "  " + hex2 + "  |" + asciiParts.join("") + "|");
  }
  return lines.join("\n");
}

function parseHexInput(input) {
  var clean = input.replace(/[^0-9a-fA-F]/g, "");
  if (clean.length % 2 !== 0) return null;
  var bytes = new Uint8Array(clean.length / 2);
  for (var i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
  }
  return bytes;
}

// ─── YARA rule parsing (simple) ───
function parseYaraRule(ruleText) {
  var nameMatch = ruleText.match(/rule\s+(\w+)/);
  if (!nameMatch) return null;
  var rule = { name: nameMatch[1], strings: [], condition: "" };
  var stringsSection = ruleText.match(/strings:\s*([\s\S]*?)(?:condition:|$)/);
  if (stringsSection) {
    var lines = stringsSection[1].split("\n");
    for (var line of lines) {
      line = line.trim();
      if (!line || line.startsWith("//")) continue;
      var hexMatch = line.match(/(\$\w+)\s*=\s*\{\s*([0-9a-fA-F\s?]+)\s*\}/);
      if (hexMatch) {
        rule.strings.push({ name: hexMatch[1], type: "hex", value: hexMatch[2].replace(/\s/g, "").toLowerCase() });
        continue;
      }
      var strMatch = line.match(/(\$\w+)\s*=\s*"([^"]+)"/);
      if (strMatch) {
        rule.strings.push({ name: strMatch[1], type: "text", value: strMatch[2] });
      }
    }
  }
  var condMatch = ruleText.match(/condition:\s*([\s\S]*?)$/);
  if (condMatch) rule.condition = condMatch[1].trim();
  return rule;
}

function yaraSearch(bytes, rule) {
  var matches = [];
  for (var s of rule.strings) {
    if (s.type === "hex") {
      var pattern = s.value.replace(/\?/g, ".");
      var hexStr = Array.from(bytes).map(function(b) { return b.toString(16).padStart(2, "0"); }).join("");
      var re = new RegExp(pattern, "gi");
      var m;
      while ((m = re.exec(hexStr)) !== null) {
        if (m.index % 2 !== 0) { re.lastIndex = m.index + 1; continue; }
        matches.push({ string: s.name, offset: m.index / 2, matchHex: m[0], length: m[0].length / 2 });
      }
    } else if (s.type === "text") {
      var textBytes = new TextEncoder().encode(s.value);
      for (var i = 0; i <= bytes.length - textBytes.length; i++) {
        var found = true;
        for (var j = 0; j < textBytes.length; j++) {
          if (bytes[i + j] !== textBytes[j]) { found = false; break; }
        }
        if (found) {
          matches.push({ string: s.name, offset: i, matchText: s.value, length: textBytes.length });
        }
      }
    }
  }
  return matches;
}

// ─── Process tree builder ───
function buildProcessTree(processes) {
  var map = {};
  for (var p of processes) map[p.pid] = { ...p, children: [] };
  var roots = [];
  for (var p of processes) {
    if (p.ppid && map[p.ppid]) {
      map[p.ppid].children.push(map[p.pid]);
    } else {
      roots.push(map[p.pid]);
    }
  }
  return roots;
}

function renderTreeHTML(node, depth) {
  depth = depth || 0;
  var indent = "&nbsp;".repeat(depth * 4);
  var prefix = depth > 0 ? "&#9492;&#9472; " : "";
  var html = '<div class="mf-tree-node">' +
    '<span class="mf-tree-indent">' + indent + prefix + '</span>' +
    '<span class="mf-tree-pid">[' + esc(String(node.pid)) + ']</span> ' +
    '<span class="mf-tree-name">' + esc(node.name) + '</span>';
  if (node.user) html += ' <span class="mf-tree-user">(' + esc(node.user) + ')</span>';
  if (node.cmdline) html += ' <span class="mf-tree-cmd">' + esc(node.cmdline) + '</span>';
  html += '</div>';
  if (node.children) {
    for (var child of node.children) {
      html += renderTreeHTML(child, depth + 1);
    }
  }
  return html;
}

// ─── Sample data for demos ───
var SAMPLE_PROCESSES = [
  { pid: 4, ppid: 0, name: "System", user: "SYSTEM", cmdline: "", mem: "140 KB", startTime: "2024-01-15 08:00:01" },
  { pid: 88, ppid: 4, name: "Registry", user: "SYSTEM", cmdline: "", mem: "72 MB", startTime: "2024-01-15 08:00:01" },
  { pid: 360, ppid: 4, name: "smss.exe", user: "SYSTEM", cmdline: "\\SystemRoot\\System32\\smss.exe", mem: "1.2 MB", startTime: "2024-01-15 08:00:02" },
  { pid: 476, ppid: 360, name: "csrss.exe", user: "SYSTEM", cmdline: "%SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows", mem: "5.8 MB", startTime: "2024-01-15 08:00:03" },
  { pid: 556, ppid: 360, name: "wininit.exe", user: "SYSTEM", cmdline: "wininit.exe", mem: "2.1 MB", startTime: "2024-01-15 08:00:03" },
  { pid: 580, ppid: 556, name: "services.exe", user: "SYSTEM", cmdline: "C:\\Windows\\system32\\services.exe", mem: "9.4 MB", startTime: "2024-01-15 08:00:03" },
  { pid: 592, ppid: 556, name: "lsass.exe", user: "SYSTEM", cmdline: "C:\\Windows\\system32\\lsass.exe", mem: "18.3 MB", startTime: "2024-01-15 08:00:03" },
  { pid: 700, ppid: 580, name: "svchost.exe", user: "SYSTEM", cmdline: "C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p", mem: "32.5 MB", startTime: "2024-01-15 08:00:04" },
  { pid: 756, ppid: 580, name: "svchost.exe", user: "NETWORK SERVICE", cmdline: "C:\\Windows\\system32\\svchost.exe -k RPCSS -p", mem: "11.2 MB", startTime: "2024-01-15 08:00:04" },
  { pid: 892, ppid: 580, name: "svchost.exe", user: "SYSTEM", cmdline: "C:\\Windows\\system32\\svchost.exe -k netsvcs -p", mem: "48.7 MB", startTime: "2024-01-15 08:00:04" },
  { pid: 1024, ppid: 580, name: "spoolsv.exe", user: "SYSTEM", cmdline: "C:\\Windows\\System32\\spoolsv.exe", mem: "8.1 MB", startTime: "2024-01-15 08:00:05" },
  { pid: 1200, ppid: 580, name: "svchost.exe", user: "LOCAL SERVICE", cmdline: "C:\\Windows\\system32\\svchost.exe -k LocalService -p", mem: "7.3 MB", startTime: "2024-01-15 08:00:05" },
  { pid: 2100, ppid: 892, name: "explorer.exe", user: "JohnDoe", cmdline: "C:\\Windows\\Explorer.EXE", mem: "98.5 MB", startTime: "2024-01-15 08:01:12" },
  { pid: 2456, ppid: 2100, name: "chrome.exe", user: "JohnDoe", cmdline: '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"', mem: "156 MB", startTime: "2024-01-15 08:02:30" },
  { pid: 3100, ppid: 2100, name: "cmd.exe", user: "JohnDoe", cmdline: "cmd.exe", mem: "4.2 MB", startTime: "2024-01-15 09:15:42" },
  { pid: 3200, ppid: 3100, name: "powershell.exe", user: "JohnDoe", cmdline: "powershell.exe -EncodedCommand JABjAGwAaQBlAG4AdAA=", mem: "87.3 MB", startTime: "2024-01-15 09:15:45" },
  { pid: 3312, ppid: 3200, name: "svchost.exe", user: "SYSTEM", cmdline: "C:\\Users\\JohnDoe\\AppData\\Local\\Temp\\svchost.exe", mem: "12.4 MB", startTime: "2024-01-15 09:15:50" },
];

// ─── Tab renderers ───
function renderHexViewerTab(container) {
  container.innerHTML =
    '<div class="mf-section">' +
      '<h3 class="mf-sh">Hex Viewer</h3>' +
      '<p class="mf-desc">Paste hex data or upload a binary file to view in standard hex editor format.</p>' +
      '<textarea id="mf-hex-input" class="mf-textarea" rows="4" placeholder="Paste hex bytes (e.g. 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00)..." spellcheck="false"></textarea>' +
      '<div class="mf-btn-row">' +
        '<button class="mf-btn" id="mf-hex-btn">View</button>' +
        '<label class="mf-btn mf-btn-sec">Upload <input type="file" id="mf-hex-file" hidden></label>' +
        '<button class="mf-btn mf-btn-sec" id="mf-hex-sample">Load PE Header Sample</button>' +
      '</div>' +
      '<pre id="mf-hex-output" class="mf-pre"></pre>' +
    '</div>';
  container.querySelector("#mf-hex-btn").onclick = function() {
    var input = container.querySelector("#mf-hex-input").value;
    var bytes = parseHexInput(input);
    if (!bytes || bytes.length === 0) { container.querySelector("#mf-hex-output").textContent = "Invalid hex input"; return; }
    container.querySelector("#mf-hex-output").textContent = formatHexView(bytes);
  };
  container.querySelector("#mf-hex-file").onchange = function(e) {
    var file = e.target.files[0];
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function(ev) {
      var bytes = new Uint8Array(ev.target.result);
      var display = bytes.slice(0, 4096);
      container.querySelector("#mf-hex-output").textContent = formatHexView(display) +
        (bytes.length > 4096 ? "\n\n... (" + (bytes.length - 4096) + " more bytes truncated)" : "");
    };
    reader.readAsArrayBuffer(file.slice(0, 65536));
  };
  container.querySelector("#mf-hex-sample").onclick = function() {
    var peHeader = "4D5A9000030000000400000000000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000F00000000E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A2400000000000000";
    container.querySelector("#mf-hex-input").value = peHeader;
    var bytes = parseHexInput(peHeader);
    container.querySelector("#mf-hex-output").textContent = formatHexView(bytes);
  };
}

function renderProcessTab(container) {
  container.innerHTML =
    '<div class="mf-section">' +
      '<h3 class="mf-sh">Process Tree Viewer</h3>' +
      '<p class="mf-desc">Visualize process parent-child relationships. Loaded with sample Windows process data — paste your own pslist output.</p>' +
      '<div class="mf-btn-row">' +
        '<button class="mf-btn" id="mf-proc-sample">Load Sample</button>' +
        '<button class="mf-btn mf-btn-sec" id="mf-proc-clear">Clear</button>' +
      '</div>' +
      '<div id="mf-proc-tree" class="mf-tree-container"></div>' +
      '<h4 class="mf-sh2">Suspicious Indicators</h4>' +
      '<div id="mf-proc-alerts" class="mf-alerts"></div>' +
    '</div>';
  function analyzeProcesses(procs) {
    var alerts = [];
    for (var p of procs) {
      if (p.name === "svchost.exe" && p.cmdline && p.cmdline.includes("Temp")) {
        alerts.push({ severity: "critical", msg: "PID " + p.pid + ": svchost.exe running from Temp directory — likely malware masquerading" });
      }
      if (p.name === "powershell.exe" && p.cmdline && p.cmdline.includes("EncodedCommand")) {
        alerts.push({ severity: "high", msg: "PID " + p.pid + ": PowerShell with -EncodedCommand — common in attacks. Decode the Base64." });
      }
      if (p.name === "cmd.exe" || p.name === "powershell.exe") {
        var parent = procs.find(function(pp) { return pp.pid === p.ppid; });
        if (parent && (parent.name === "winword.exe" || parent.name === "excel.exe" || parent.name === "outlook.exe")) {
          alerts.push({ severity: "critical", msg: "PID " + p.pid + ": " + p.name + " spawned from " + parent.name + " — macro/exploit execution" });
        }
      }
      if (p.name === "lsass.exe") {
        var lsassCount = procs.filter(function(pp) { return pp.name === "lsass.exe"; }).length;
        if (lsassCount > 1) {
          alerts.push({ severity: "critical", msg: "Multiple lsass.exe instances detected — only one should exist. PID " + p.pid + " may be malicious." });
        }
      }
    }
    return alerts;
  }
  function render(procs) {
    var tree = buildProcessTree(procs);
    var treeEl = container.querySelector("#mf-proc-tree");
    treeEl.innerHTML = tree.map(function(r) { return renderTreeHTML(r); }).join("");
    var alerts = analyzeProcesses(procs);
    var alertsEl = container.querySelector("#mf-proc-alerts");
    if (alerts.length === 0) {
      alertsEl.innerHTML = '<div class="mf-pass">No obvious suspicious indicators detected in process list.</div>';
    } else {
      alertsEl.innerHTML = alerts.map(function(a) {
        var cls = a.severity === "critical" ? "mf-alert-crit" : "mf-alert-high";
        return '<div class="mf-alert ' + cls + '">' + esc(a.msg) + '</div>';
      }).join("");
    }
  }
  container.querySelector("#mf-proc-sample").onclick = function() { render(SAMPLE_PROCESSES); };
  container.querySelector("#mf-proc-clear").onclick = function() {
    container.querySelector("#mf-proc-tree").innerHTML = "";
    container.querySelector("#mf-proc-alerts").innerHTML = "";
  };
  render(SAMPLE_PROCESSES);
}

function renderVolatilityTab(container) {
  var categories = [...new Set(VOLATILITY_PLUGINS.map(function(p) { return p.category; }))];
  container.innerHTML =
    '<div class="mf-section">' +
      '<h3 class="mf-sh">Volatility Plugin Reference</h3>' +
      '<p class="mf-desc">' + VOLATILITY_PLUGINS.length + ' plugins for Volatility 2 &amp; 3 memory forensics framework.</p>' +
      '<div class="mf-filter" id="mf-vol-filter">' +
        '<button class="mf-chip on" data-c="all">All</button>' +
        categories.map(function(c) { return '<button class="mf-chip" data-c="' + esc(c) + '">' + esc(c) + '</button>'; }).join("") +
      '</div>' +
      '<div class="mf-input-row"><input type="text" id="mf-vol-search" class="mf-input" placeholder="Search plugins..."></div>' +
      '<div id="mf-vol-list" class="mf-vol-list"></div>' +
    '</div>';
  function renderPlugins(filter, search) {
    var filtered = VOLATILITY_PLUGINS.filter(function(p) {
      if (filter !== "all" && p.category !== filter) return false;
      if (search) {
        var q = search.toLowerCase();
        return p.name.toLowerCase().includes(q) || p.desc.toLowerCase().includes(q);
      }
      return true;
    });
    var listEl = container.querySelector("#mf-vol-list");
    if (filtered.length === 0) {
      listEl.innerHTML = '<p class="mf-muted">No plugins match.</p>';
      return;
    }
    listEl.innerHTML = filtered.map(function(p) {
      return '<div class="mf-vol-card" data-cat="' + esc(p.category) + '">' +
        '<div class="mf-vol-header">' +
          '<span class="mf-vol-name">' + esc(p.name) + '</span>' +
          '<span class="mf-chip-sm">' + esc(p.category) + '</span>' +
        '</div>' +
        '<div class="mf-vol-desc">' + esc(p.desc) + '</div>' +
        '<div class="mf-vol-cmds">' +
          '<div><span class="mf-vol-label">Vol2:</span> <code>vol.py -f memdump.raw --profile=Win7SP1x64 ' + esc(p.vol2) + '</code></div>' +
          '<div><span class="mf-vol-label">Vol3:</span> <code>vol -f memdump.raw ' + esc(p.vol3) + '</code></div>' +
        '</div>' +
        '<div class="mf-vol-meta">' +
          '<div><span class="mf-vol-label">Output:</span> ' + esc(p.output) + '</div>' +
          '<div><span class="mf-vol-label">Look for:</span> ' + esc(p.lookFor) + '</div>' +
        '</div>' +
      '</div>';
    }).join("");
  }
  var currentFilter = "all";
  renderPlugins("all", "");
  container.querySelector("#mf-vol-filter").onclick = function(e) {
    var btn = e.target.closest(".mf-chip");
    if (!btn) return;
    currentFilter = btn.dataset.c;
    container.querySelectorAll("#mf-vol-filter .mf-chip").forEach(function(b) { b.classList.toggle("on", b === btn); });
    renderPlugins(currentFilter, container.querySelector("#mf-vol-search").value);
  };
  container.querySelector("#mf-vol-search").oninput = function() {
    renderPlugins(currentFilter, this.value);
  };
}

function renderStructuresTab(container) {
  var structs = Object.keys(MEMORY_STRUCTURES);
  container.innerHTML =
    '<div class="mf-section">' +
      '<h3 class="mf-sh">Windows Memory Structures</h3>' +
      '<p class="mf-desc">Key kernel and user-mode structures used in memory forensics (x64 offsets).</p>' +
      '<div class="mf-struct-tabs" id="mf-struct-tabs">' +
        structs.map(function(s, i) { return '<button class="mf-chip' + (i === 0 ? " on" : "") + '" data-s="' + esc(s) + '">' + esc(s) + '</button>'; }).join("") +
      '</div>' +
      '<div id="mf-struct-detail"></div>' +
    '</div>' +
    '<div class="mf-section">' +
      '<h3 class="mf-sh">Pool Tags</h3>' +
      '<p class="mf-desc">' + POOL_TAGS.length + ' common pool tags — use with pooltag scanning to identify kernel allocations.</p>' +
      '<div class="mf-table-wrap"><table class="mf-table">' +
        '<thead><tr><th>Tag</th><th>Description</th><th>Module</th></tr></thead><tbody>' +
        POOL_TAGS.map(function(t) { return '<tr><td><code>' + esc(t.tag) + '</code></td><td>' + esc(t.desc) + '</td><td>' + esc(t.module) + '</td></tr>'; }).join("") +
      '</tbody></table></div>' +
    '</div>';
  function showStruct(name) {
    var s = MEMORY_STRUCTURES[name];
    if (!s) return;
    var detail = container.querySelector("#mf-struct-detail");
    detail.innerHTML = '<div class="mf-struct-desc">' + esc(s.description) + '</div>' +
      '<div class="mf-table-wrap"><table class="mf-table">' +
        '<thead><tr><th>Offset</th><th>Field</th><th>Type</th><th>Description</th></tr></thead><tbody>' +
        s.fields.map(function(f) {
          return '<tr><td><code>' + esc(f.offset || "") + '</code></td><td><code>' + esc(f.name) + '</code></td>' +
            '<td>' + esc(f.type || "") + '</td><td>' + esc(f.desc) + '</td></tr>';
        }).join("") +
      '</tbody></table></div>';
  }
  showStruct(structs[0]);
  container.querySelector("#mf-struct-tabs").onclick = function(e) {
    var btn = e.target.closest(".mf-chip");
    if (!btn) return;
    container.querySelectorAll("#mf-struct-tabs .mf-chip").forEach(function(b) { b.classList.toggle("on", b === btn); });
    showStruct(btn.dataset.s);
  };
}

function renderLinuxTab(container) {
  var structs = Object.keys(LINUX_STRUCTURES);
  container.innerHTML =
    '<div class="mf-section">' +
      '<h3 class="mf-sh">Linux Memory Analysis</h3>' +
      '<p class="mf-desc">Key data structures and /proc filesystem references for Linux memory forensics.</p>' +
      '<div class="mf-struct-tabs" id="mf-linux-tabs">' +
        structs.map(function(s, i) { return '<button class="mf-chip' + (i === 0 ? " on" : "") + '" data-s="' + esc(s) + '">' + esc(s) + '</button>'; }).join("") +
      '</div>' +
      '<div id="mf-linux-detail"></div>' +
    '</div>';
  function showStruct(name) {
    var s = LINUX_STRUCTURES[name];
    if (!s) return;
    var detail = container.querySelector("#mf-linux-detail");
    detail.innerHTML = '<div class="mf-struct-desc">' + esc(s.description) + '</div>' +
      '<div class="mf-table-wrap"><table class="mf-table">' +
        '<thead><tr><th>Field / Path</th><th>Description</th></tr></thead><tbody>' +
        s.fields.map(function(f) {
          return '<tr><td><code>' + esc(f.name) + '</code></td><td>' + esc(f.desc) + '</td></tr>';
        }).join("") +
      '</tbody></table></div>';
  }
  showStruct(structs[0]);
  container.querySelector("#mf-linux-tabs").onclick = function(e) {
    var btn = e.target.closest(".mf-chip");
    if (!btn) return;
    container.querySelectorAll("#mf-linux-tabs .mf-chip").forEach(function(b) { b.classList.toggle("on", b === btn); });
    showStruct(btn.dataset.s);
  };
}

function renderMalwareTab(container) {
  var categories = Object.keys(MALWARE_INDICATORS);
  container.innerHTML =
    '<div class="mf-section">' +
      '<h3 class="mf-sh">Malware Indicators in Memory</h3>' +
      '<p class="mf-desc">Code injection patterns, API hooking, and rootkit techniques — what to look for in a memory dump.</p>' +
      '<div class="mf-struct-tabs" id="mf-malware-tabs">' +
        categories.map(function(c, i) { return '<button class="mf-chip' + (i === 0 ? " on" : "") + '" data-c="' + esc(c) + '">' + esc(c) + '</button>'; }).join("") +
      '</div>' +
      '<div id="mf-malware-list"></div>' +
    '</div>';
  function showCategory(cat) {
    var items = MALWARE_INDICATORS[cat] || [];
    var listEl = container.querySelector("#mf-malware-list");
    listEl.innerHTML = items.map(function(item) {
      return '<div class="mf-mal-card">' +
        '<div class="mf-mal-name">' + esc(item.name) + (item.mitre ? ' <span class="mf-chip-sm">' + esc(item.mitre) + '</span>' : '') + '</div>' +
        '<div class="mf-mal-desc">' + esc(item.desc) + '</div>' +
        '<div class="mf-mal-det"><strong>Detection:</strong> ' + esc(item.detection) + '</div>' +
      '</div>';
    }).join("");
  }
  showCategory(categories[0]);
  container.querySelector("#mf-malware-tabs").onclick = function(e) {
    var btn = e.target.closest(".mf-chip");
    if (!btn) return;
    container.querySelectorAll("#mf-malware-tabs .mf-chip").forEach(function(b) { b.classList.toggle("on", b === btn); });
    showCategory(btn.dataset.c);
  };
}

function renderYaraTab(container) {
  container.innerHTML =
    '<div class="mf-section">' +
      '<h3 class="mf-sh">YARA Scanner</h3>' +
      '<p class="mf-desc">Scan hex data against YARA rules (simplified client-side matcher for hex and text strings).</p>' +
      '<div class="mf-yara-split">' +
        '<div class="mf-yara-col">' +
          '<h4 class="mf-sh2">YARA Rule</h4>' +
          '<textarea id="mf-yara-rule" class="mf-textarea" rows="10" spellcheck="false" placeholder="rule example_pe {\n  strings:\n    $mz = { 4D 5A }\n    $dos = \"This program\"\n  condition:\n    $mz at 0 and $dos\n}"></textarea>' +
        '</div>' +
        '<div class="mf-yara-col">' +
          '<h4 class="mf-sh2">Hex Data to Scan</h4>' +
          '<textarea id="mf-yara-data" class="mf-textarea" rows="10" spellcheck="false" placeholder="4D5A9000030000000400..."></textarea>' +
        '</div>' +
      '</div>' +
      '<div class="mf-btn-row">' +
        '<button class="mf-btn" id="mf-yara-scan">Scan</button>' +
        '<button class="mf-btn mf-btn-sec" id="mf-yara-sample">Load Sample</button>' +
      '</div>' +
      '<div id="mf-yara-result" class="mf-result"></div>' +
    '</div>';
  container.querySelector("#mf-yara-sample").onclick = function() {
    container.querySelector("#mf-yara-rule").value = 'rule detect_pe_header {\n  strings:\n    $mz = { 4D 5A }\n    $dos_msg = "This program cannot be run in DOS mode"\n  condition:\n    $mz at 0 and $dos_msg\n}';
    container.querySelector("#mf-yara-data").value = "4D5A9000030000000400000000000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000F00000000E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A2400000000000000";
  };
  container.querySelector("#mf-yara-scan").onclick = function() {
    var ruleText = container.querySelector("#mf-yara-rule").value;
    var hexData = container.querySelector("#mf-yara-data").value;
    var resultEl = container.querySelector("#mf-yara-result");
    var rule = parseYaraRule(ruleText);
    if (!rule) { resultEl.innerHTML = '<div class="mf-err">Could not parse YARA rule. Check syntax.</div>'; return; }
    var bytes = parseHexInput(hexData);
    if (!bytes || bytes.length === 0) { resultEl.innerHTML = '<div class="mf-err">Invalid hex data.</div>'; return; }
    var matches = yaraSearch(bytes, rule);
    if (matches.length === 0) {
      resultEl.innerHTML = '<div class="mf-muted">Rule "' + esc(rule.name) + '" — no matches found.</div>';
      return;
    }
    var html = '<div class="mf-pass">Rule "' + esc(rule.name) + '" — ' + matches.length + ' match(es) found!</div>' +
      '<div class="mf-table-wrap"><table class="mf-table">' +
      '<thead><tr><th>String</th><th>Offset</th><th>Length</th><th>Match</th></tr></thead><tbody>';
    for (var m of matches) {
      html += '<tr><td>' + esc(m.string) + '</td><td>0x' + m.offset.toString(16).toUpperCase() + '</td>' +
        '<td>' + m.length + ' bytes</td><td><code>' + esc(m.matchHex || m.matchText || "") + '</code></td></tr>';
    }
    html += '</tbody></table></div>';
    resultEl.innerHTML = html;
  };
}

// ─── CSS ───
var MF_CSS = '<style>' +
  '.mf-section{margin-bottom:24px}' +
  '.mf-sh{font-size:1.1rem;margin:0 0 6px;color:var(--txt,#eee)}' +
  '.mf-sh2{font-size:.95rem;margin:16px 0 6px;color:var(--txt,#eee)}' +
  '.mf-desc{color:var(--mut,#888);font-size:.82rem;margin:0 0 12px}' +
  '.mf-input-row{display:flex;gap:8px;margin-bottom:8px}' +
  '.mf-input{flex:1;padding:8px 12px;background:var(--bg,#111);border:1px solid var(--line,#333);color:var(--txt,#eee);border-radius:4px;font-size:.85rem}' +
  '.mf-textarea{width:100%;padding:8px 12px;background:var(--bg,#111);border:1px solid var(--line,#333);color:var(--txt,#eee);border-radius:4px;font-family:monospace;font-size:.8rem;resize:vertical;box-sizing:border-box;margin-bottom:8px}' +
  '.mf-btn-row{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center}' +
  '.mf-btn{padding:8px 18px;background:var(--acc,#ffc107);color:#111;border:none;border-radius:4px;cursor:pointer;font-weight:600;font-size:.85rem;white-space:nowrap;display:inline-flex;align-items:center;justify-content:center;line-height:1.4;box-sizing:border-box}' +
  '.mf-btn:hover{opacity:.9}' +
  '.mf-btn-sec{background:var(--card,#1a1a1a);color:var(--txt,#eee);border:1px solid var(--line,#333)}' +
  '.mf-pre{background:var(--bg,#111);border:1px solid var(--line,#333);padding:12px;border-radius:4px;font-family:monospace;font-size:.75rem;overflow-x:auto;color:var(--txt,#eee);white-space:pre;line-height:1.5;max-height:400px;overflow-y:auto}' +
  '.mf-result{margin-top:12px}' +
  '.mf-muted{color:var(--mut,#888);font-size:.85rem}' +
  '.mf-pass{padding:8px 12px;background:rgba(76,175,80,.12);border:1px solid rgba(76,175,80,.3);border-radius:4px;color:#4caf50;font-size:.85rem;margin-bottom:8px}' +
  '.mf-err{padding:8px 12px;background:rgba(244,67,54,.12);border:1px solid rgba(244,67,54,.3);border-radius:4px;color:#f44336;font-size:.85rem}' +
  '.mf-filter{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:12px}' +
  '.mf-chip{padding:4px 12px;border:1px solid var(--line,#333);background:var(--card,#1a1a1a);color:var(--txt,#eee);cursor:pointer;font-size:.78rem;border-radius:4px;transition:all .15s}' +
  '.mf-chip:hover{background:var(--bg,#111)}' +
  '.mf-chip.on{background:var(--acc,#ffc107);color:#111;border-color:var(--acc,#ffc107);font-weight:600}' +
  '.mf-chip-sm{padding:2px 8px;background:var(--bg,#111);border:1px solid var(--line,#333);border-radius:3px;font-size:.7rem;color:var(--acc,#ffc107)}' +
  '.mf-table-wrap{overflow-x:auto;margin-bottom:12px}' +
  '.mf-table{width:100%;border-collapse:collapse;font-size:.8rem}' +
  '.mf-table th,.mf-table td{padding:6px 10px;border:1px solid var(--line,#333);text-align:left}' +
  '.mf-table th{background:var(--card,#1a1a1a);color:var(--mut,#888);font-weight:600;white-space:nowrap}' +
  '.mf-table td{color:var(--txt,#eee)}' +
  '.mf-table code{font-size:.78rem;color:var(--acc,#ffc107)}' +
  '.mf-tree-container{background:var(--bg,#111);border:1px solid var(--line,#333);padding:12px;border-radius:4px;font-family:monospace;font-size:.8rem;max-height:400px;overflow-y:auto;margin-bottom:12px}' +
  '.mf-tree-node{line-height:1.6}' +
  '.mf-tree-pid{color:var(--acc,#ffc107);font-weight:600}' +
  '.mf-tree-name{color:var(--txt,#eee)}' +
  '.mf-tree-user{color:var(--mut,#888);font-size:.75rem}' +
  '.mf-tree-cmd{color:var(--mut,#666);font-size:.72rem}' +
  '.mf-alerts{margin-bottom:12px}' +
  '.mf-alert{padding:8px 12px;border-radius:4px;font-size:.82rem;margin-bottom:4px}' +
  '.mf-alert-crit{background:rgba(244,67,54,.12);border:1px solid rgba(244,67,54,.3);color:#f44336}' +
  '.mf-alert-high{background:rgba(255,152,0,.12);border:1px solid rgba(255,152,0,.3);color:#ff9800}' +
  '.mf-vol-list{display:flex;flex-direction:column;gap:8px}' +
  '.mf-vol-card{background:var(--card,#1a1a1a);border:1px solid var(--line,#333);padding:12px;border-radius:4px}' +
  '.mf-vol-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}' +
  '.mf-vol-name{font-weight:700;color:var(--acc,#ffc107);font-size:.9rem}' +
  '.mf-vol-desc{color:var(--txt,#eee);font-size:.82rem;margin-bottom:8px}' +
  '.mf-vol-cmds{font-family:monospace;font-size:.78rem;color:var(--mut,#888);margin-bottom:6px}' +
  '.mf-vol-cmds code{color:var(--txt,#eee)}' +
  '.mf-vol-meta{font-size:.78rem;color:var(--mut,#888)}' +
  '.mf-vol-label{color:var(--acc,#ffc107);font-weight:600}' +
  '.mf-struct-tabs{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:12px}' +
  '.mf-struct-desc{color:var(--mut,#888);font-size:.82rem;margin-bottom:12px;padding:8px;background:var(--card,#1a1a1a);border-radius:4px}' +
  '.mf-mal-card{background:var(--card,#1a1a1a);border:1px solid var(--line,#333);padding:12px;border-radius:4px;margin-bottom:8px}' +
  '.mf-mal-name{font-weight:700;color:var(--txt,#eee);font-size:.9rem;margin-bottom:4px}' +
  '.mf-mal-desc{color:var(--mut,#888);font-size:.82rem;margin-bottom:6px}' +
  '.mf-mal-det{font-size:.82rem;color:var(--txt,#eee)}' +
  '.mf-yara-split{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:8px}' +
  '@media(max-width:600px){.mf-yara-split{grid-template-columns:1fr}.mf-vol-header{flex-direction:column;align-items:flex-start;gap:4px}}' +
  '</style>';

// ─── Main tabs ───
var MF_TABS = [
  { id: "hex", label: "Hex Viewer", render: renderHexViewerTab },
  { id: "process", label: "Process Tree", render: renderProcessTab },
  { id: "volatility", label: "Volatility", render: renderVolatilityTab },
  { id: "structures", label: "Structures", render: renderStructuresTab },
  { id: "linux", label: "Linux", render: renderLinuxTab },
  { id: "malware", label: "Malware", render: renderMalwareTab },
  { id: "yara", label: "YARA", render: renderYaraTab },
];

export function renderMemoryForensics(main) {
  main.innerHTML = MF_CSS +
    '<h1 class="pg-h1">Memory Forensics</h1>' +
    '<p class="muted pg-sub">Hex viewer, process tree analysis, Volatility reference, memory structures, YARA scanning. All client-side.</p>' +
    '<div class="mf-filter" id="mf-tabs">' +
      MF_TABS.map(function(t) { return '<button class="mf-chip' + (t.id === "hex" ? " on" : "") + '" data-tab="' + t.id + '">' + t.label + '</button>'; }).join("") +
    '</div>' +
    '<div id="mf-panel"></div>';
  var panel = main.querySelector("#mf-panel");
  renderHexViewerTab(panel);
  main.querySelector("#mf-tabs").onclick = function(e) {
    var btn = e.target.closest(".mf-chip");
    if (!btn) return;
    main.querySelectorAll("#mf-tabs .mf-chip").forEach(function(b) { b.classList.toggle("on", b === btn); });
    var tab = MF_TABS.find(function(t) { return t.id === btn.dataset.tab; });
    if (tab) tab.render(panel);
  };
}
