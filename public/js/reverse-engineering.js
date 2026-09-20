const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const PE_SECTIONS = [
  { name: ".text", vaddr: "0x00401000", vsize: "0x0002A400", rsize: "0x0002A400", flags: "CODE|EXECUTE|READ", entropy: 6.12 },
  { name: ".rdata", vaddr: "0x0042C000", vsize: "0x00008E00", rsize: "0x00009000", flags: "INITIALIZED|READ", entropy: 5.44 },
  { name: ".data", vaddr: "0x00435000", vsize: "0x00003200", rsize: "0x00001A00", flags: "INITIALIZED|READ|WRITE", entropy: 4.21 },
  { name: ".rsrc", vaddr: "0x00439000", vsize: "0x00001800", rsize: "0x00001800", flags: "INITIALIZED|READ", entropy: 3.87 },
  { name: ".reloc", vaddr: "0x0043B000", vsize: "0x00002400", rsize: "0x00002400", flags: "INITIALIZED|READ|DISCARDABLE", entropy: 5.98 },
  { name: ".upx0", vaddr: "0x0043E000", vsize: "0x00040000", rsize: "0x00000000", flags: "CODE|EXECUTE|READ|WRITE", entropy: 0.00 },
  { name: ".upx1", vaddr: "0x0047E000", vsize: "0x00020000", rsize: "0x0001F200", flags: "CODE|EXECUTE|READ|WRITE", entropy: 7.89 },
];

const IMPORTS_TABLE = [
  { dll: "KERNEL32.dll", funcs: ["CreateProcessA", "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "ReadProcessMemory", "GetProcAddress", "LoadLibraryA", "CreateRemoteThread", "OpenProcess", "NtQueryInformationProcess"] },
  { dll: "NTDLL.dll", funcs: ["NtUnmapViewOfSection", "RtlDecompressBuffer", "NtWriteVirtualMemory", "NtCreateThreadEx"] },
  { dll: "WS2_32.dll", funcs: ["WSAStartup", "socket", "connect", "send", "recv", "closesocket", "inet_addr", "htons"] },
  { dll: "ADVAPI32.dll", funcs: ["RegSetValueExA", "RegOpenKeyExA", "AdjustTokenPrivileges", "OpenProcessToken", "CryptAcquireContextA", "CryptEncrypt"] },
  { dll: "USER32.dll", funcs: ["GetAsyncKeyState", "GetForegroundWindow", "GetWindowTextA", "SetWindowsHookExA", "CallNextHookEx"] },
];

const SUSPICIOUS_INDICATORS = [
  { type: "Critical", indicator: "Process Hollowing APIs", detail: "CreateProcess + NtUnmapViewOfSection + WriteProcessMemory pattern", mitre: "T1055.012" },
  { type: "Critical", indicator: "Remote Thread Injection", detail: "OpenProcess + VirtualAllocEx + CreateRemoteThread pattern", mitre: "T1055.001" },
  { type: "High", indicator: "Keylogger APIs", detail: "GetAsyncKeyState + GetForegroundWindow + SetWindowsHookEx", mitre: "T1056.001" },
  { type: "High", indicator: "Network Communication", detail: "Raw socket API usage (WS2_32) for C2 communication", mitre: "T1071.001" },
  { type: "High", indicator: "Packed Binary (UPX)", detail: "UPX section headers detected, entropy 7.89 in .upx1", mitre: "T1027.002" },
  { type: "Medium", indicator: "Registry Persistence", detail: "RegSetValueExA used for Run key persistence", mitre: "T1547.001" },
  { type: "Medium", indicator: "Crypto API Usage", detail: "CryptAcquireContext + CryptEncrypt suggests file encryption", mitre: "T1486" },
  { type: "Low", indicator: "Anti-Debug Check", detail: "NtQueryInformationProcess for ProcessDebugPort", mitre: "T1622" },
];

const DISASSEMBLY = [
  { addr: "0x00401000", bytes: "55", asm: "push ebp", comment: "; function prologue" },
  { addr: "0x00401001", bytes: "8BEC", asm: "mov ebp, esp", comment: "" },
  { addr: "0x00401003", bytes: "83EC20", asm: "sub esp, 0x20", comment: "; allocate 32 bytes" },
  { addr: "0x00401006", bytes: "6A00", asm: "push 0", comment: "; dwCreationFlags = 0" },
  { addr: "0x00401008", bytes: "6A00", asm: "push 0", comment: "" },
  { addr: "0x0040100A", bytes: "6A00", asm: "push 0", comment: "" },
  { addr: "0x0040100C", bytes: "6A00", asm: "push 0", comment: "" },
  { addr: "0x0040100E", bytes: "6A04", asm: "push 4", comment: "; CREATE_SUSPENDED" },
  { addr: "0x00401010", bytes: "6A00", asm: "push 0", comment: "" },
  { addr: "0x00401012", bytes: "8D4DE0", asm: "lea ecx, [ebp-0x20]", comment: "; lpProcessInformation" },
  { addr: "0x00401015", bytes: "51", asm: "push ecx", comment: "" },
  { addr: "0x00401016", bytes: "8D45F0", asm: "lea eax, [ebp-0x10]", comment: "; lpStartupInfo" },
  { addr: "0x00401019", bytes: "50", asm: "push eax", comment: "" },
  { addr: "0x0040101A", bytes: "6800304200", asm: 'push 0x00423000', comment: '; "svchost.exe"' },
  { addr: "0x0040101F", bytes: "6A00", asm: "push 0", comment: "" },
  { addr: "0x00401021", bytes: "FF1508304200", asm: "call [CreateProcessA]", comment: "; CREATE_SUSPENDED" },
  { addr: "0x00401027", bytes: "85C0", asm: "test eax, eax", comment: "; check success" },
  { addr: "0x00401029", bytes: "7420", asm: "jz 0x0040104B", comment: "; bail on failure" },
  { addr: "0x0040102B", bytes: "8B45E0", asm: "mov eax, [ebp-0x20]", comment: "; hProcess" },
  { addr: "0x0040102E", bytes: "50", asm: "push eax", comment: "" },
  { addr: "0x0040102F", bytes: "FF150C304200", asm: "call [NtUnmapViewOfSection]", comment: "; hollow process" },
  { addr: "0x00401035", bytes: "6800100000", asm: "push 0x1000", comment: "; MEM_COMMIT" },
  { addr: "0x0040103A", bytes: "6800400000", asm: "push 0x4000", comment: "; size" },
  { addr: "0x0040103F", bytes: "6800004000", asm: "push 0x00400000", comment: "; base address" },
  { addr: "0x00401044", bytes: "8B4DE0", asm: "mov ecx, [ebp-0x20]", comment: "; hProcess" },
  { addr: "0x00401047", bytes: "51", asm: "push ecx", comment: "" },
  { addr: "0x00401048", bytes: "FF1510304200", asm: "call [VirtualAllocEx]", comment: "; allocate in target" },
];

const STRING_REFS = [
  { addr: "0x00423000", value: "svchost.exe", type: "ASCII", context: "Process hollowing target" },
  { addr: "0x00423010", value: "Software\\Microsoft\\Windows\\CurrentVersion\\Run", type: "ASCII", context: "Persistence registry key" },
  { addr: "0x00423050", value: "MalwareC2Service", type: "ASCII", context: "Registry value name" },
  { addr: "0x00423070", value: "http://192.168.1.100:8443/beacon", type: "ASCII", context: "C2 callback URL" },
  { addr: "0x004230A0", value: "Mozilla/5.0 (Windows NT 10.0; Win64)", type: "ASCII", context: "HTTP User-Agent" },
  { addr: "0x004230F0", value: "cmd.exe /c whoami", type: "ASCII", context: "Reconnaissance command" },
  { addr: "0x00423110", value: "\\\\%s\\C$\\Windows\\Temp\\payload.exe", type: "ASCII", context: "Lateral movement path" },
  { addr: "0x00423150", value: "AES-256-CBC", type: "ASCII", context: "Encryption algorithm" },
  { addr: "0x00423170", value: "%APPDATA%\\update.exe", type: "ASCII", context: "Dropped file path" },
  { addr: "0x00423190", value: "IsDebuggerPresent", type: "ASCII", context: "Anti-debug API name" },
  { addr: "0x004231B0", value: "VMwareService.exe", type: "ASCII", context: "VM detection string" },
  { addr: "0x004231D0", value: "SbieDll.dll", type: "ASCII", context: "Sandboxie detection" },
];

const YARA_RULES = [
  { name: "ProcessHollowing", match: true, desc: "Detects process hollowing technique via API pattern" },
  { name: "UPX_Packed", match: true, desc: "Identifies UPX packer signature in PE headers" },
  { name: "Keylogger_APIs", match: true, desc: "GetAsyncKeyState with window title capture" },
  { name: "C2_Communication", match: true, desc: "HTTP beacon pattern with suspicious User-Agent" },
  { name: "AntiDebug_Techniques", match: true, desc: "Multiple anti-analysis checks detected" },
  { name: "Ransomware_Behavior", match: false, desc: "File enumeration + encryption pattern" },
  { name: "Emotet_Payload", match: false, desc: "Emotet-specific string and API pattern" },
  { name: "Cobalt_Strike_Beacon", match: false, desc: "Cobalt Strike shellcode markers" },
];

const TABS = [
  { id: "headers", label: "PE Headers" },
  { id: "imports", label: "Imports" },
  { id: "strings", label: "Strings" },
  { id: "disasm", label: "Disassembly" },
  { id: "entropy", label: "Entropy" },
  { id: "indicators", label: "Indicators" },
  { id: "yara", label: "YARA Scan" },
  { id: "decompile", label: "Decompiler" },
];

export function renderReverseEngineering(main) {
  var tab = "headers";

  function render() {
    var tabsHTML = "";
    for (var i = 0; i < TABS.length; i++) {
      tabsHTML += '<button class="re-tab' + (TABS[i].id === tab ? " active" : "") + '" data-tab="' + esc(TABS[i].id) + '">' + esc(TABS[i].label) + '</button>';
    }

    var body = "";
    if (tab === "headers") body = renderHeaders();
    else if (tab === "imports") body = renderImports();
    else if (tab === "strings") body = renderStrings();
    else if (tab === "disasm") body = renderDisasm();
    else if (tab === "entropy") body = renderEntropy();
    else if (tab === "indicators") body = renderIndicators();
    else if (tab === "yara") body = renderYara();
    else if (tab === "decompile") body = renderDecompile();

    main.innerHTML =
      '<h1 class="pg-h1">Reverse Engineering Workbench</h1>' +
      '<p class="muted pg-sub">Static analysis, disassembly, and malware reverse engineering toolkit.</p>' +
      '<div class="re-file-info">' +
      '<span class="re-fname">sample_malware.exe</span>' +
      '<span class="re-fmeta">PE32 | 174 KB | MD5: a1b2c3d4e5f6...</span>' +
      '<span class="re-sev re-sev-crit">Malicious</span>' +
      '</div>' +
      '<div class="re-tabs">' + tabsHTML + '</div>' +
      '<div class="re-body">' + body + '</div>';

    main.querySelectorAll(".re-tab").forEach(function(btn) {
      btn.onclick = function() { tab = btn.dataset.tab; render(); };
    });

    if (tab === "entropy") drawEntropyChart();
  }

  function renderHeaders() {
    var sectionRows = "";
    for (var i = 0; i < PE_SECTIONS.length; i++) {
      var s = PE_SECTIONS[i];
      var entropyClass = s.entropy > 7 ? "re-ent-high" : s.entropy > 6 ? "re-ent-med" : "re-ent-low";
      sectionRows +=
        '<tr>' +
        '<td class="mono"><strong>' + esc(s.name) + '</strong></td>' +
        '<td class="mono">' + esc(s.vaddr) + '</td>' +
        '<td class="mono">' + esc(s.vsize) + '</td>' +
        '<td class="mono">' + esc(s.rsize) + '</td>' +
        '<td><span class="re-flags">' + esc(s.flags) + '</span></td>' +
        '<td><span class="' + entropyClass + '">' + s.entropy.toFixed(2) + '</span></td>' +
        '</tr>';
    }

    return '<div class="re-grid2">' +
      '<div class="re-panel">' +
      '<h3 class="re-panel-h">DOS Header</h3>' +
      '<div class="re-kv"><span>Magic</span><span class="mono">MZ (0x5A4D)</span></div>' +
      '<div class="re-kv"><span>e_lfanew</span><span class="mono">0x000000E0</span></div>' +
      '</div>' +
      '<div class="re-panel">' +
      '<h3 class="re-panel-h">PE Signature</h3>' +
      '<div class="re-kv"><span>Signature</span><span class="mono">PE\\0\\0 (0x00004550)</span></div>' +
      '<div class="re-kv"><span>Machine</span><span class="mono">0x014C (i386)</span></div>' +
      '<div class="re-kv"><span>Sections</span><span class="mono">' + PE_SECTIONS.length + '</span></div>' +
      '<div class="re-kv"><span>Timestamp</span><span class="mono">2024-03-15 08:42:11 UTC</span></div>' +
      '<div class="re-kv"><span>Characteristics</span><span class="mono">EXECUTABLE_IMAGE | 32BIT_MACHINE</span></div>' +
      '</div>' +
      '</div>' +
      '<div class="re-panel">' +
      '<h3 class="re-panel-h">Optional Header</h3>' +
      '<div class="re-kv-grid">' +
      '<div class="re-kv"><span>Magic</span><span class="mono">0x010B (PE32)</span></div>' +
      '<div class="re-kv"><span>Entry Point</span><span class="mono">0x00401000</span></div>' +
      '<div class="re-kv"><span>Image Base</span><span class="mono">0x00400000</span></div>' +
      '<div class="re-kv"><span>Section Alignment</span><span class="mono">0x1000</span></div>' +
      '<div class="re-kv"><span>File Alignment</span><span class="mono">0x200</span></div>' +
      '<div class="re-kv"><span>Subsystem</span><span class="mono">WINDOWS_GUI</span></div>' +
      '<div class="re-kv"><span>DLL Characteristics</span><span class="mono re-warn-text">NO_DEP | NO_ASLR</span></div>' +
      '<div class="re-kv"><span>Size of Image</span><span class="mono">0x0009E000</span></div>' +
      '</div></div>' +
      '<div class="re-panel">' +
      '<h3 class="re-panel-h">Section Table</h3>' +
      '<div class="re-table-wrap"><table class="re-table">' +
      '<thead><tr><th>Name</th><th>Virtual Addr</th><th>Virtual Size</th><th>Raw Size</th><th>Flags</th><th>Entropy</th></tr></thead>' +
      '<tbody>' + sectionRows + '</tbody>' +
      '</table></div></div>';
  }

  function renderImports() {
    var panels = "";
    for (var i = 0; i < IMPORTS_TABLE.length; i++) {
      var imp = IMPORTS_TABLE[i];
      var funcs = "";
      for (var f = 0; f < imp.funcs.length; f++) {
        var suspicious = ["CreateRemoteThread", "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
          "NtUnmapViewOfSection", "GetAsyncKeyState", "SetWindowsHookExA", "CryptEncrypt",
          "NtCreateThreadEx", "NtWriteVirtualMemory", "CreateProcessA", "OpenProcess",
          "AdjustTokenPrivileges"].indexOf(imp.funcs[f]) !== -1;
        funcs += '<div class="re-import-fn' + (suspicious ? " re-suspicious" : "") + '">' +
          esc(imp.funcs[f]) +
          (suspicious ? ' <span class="re-flag-icon">!</span>' : "") +
          '</div>';
      }
      panels +=
        '<div class="re-panel">' +
        '<h3 class="re-panel-h">' + esc(imp.dll) + ' <span class="re-count">' + imp.funcs.length + ' functions</span></h3>' +
        '<div class="re-import-list">' + funcs + '</div>' +
        '</div>';
    }
    return '<div class="re-import-summary">' +
      '<span class="re-pill">' + IMPORTS_TABLE.length + ' DLLs</span>' +
      '<span class="re-pill">' + IMPORTS_TABLE.reduce(function(s, d) { return s + d.funcs.length; }, 0) + ' Functions</span>' +
      '<span class="re-pill re-pill-warn">14 Suspicious APIs</span>' +
      '</div>' + panels;
  }

  function renderStrings() {
    var rows = "";
    for (var i = 0; i < STRING_REFS.length; i++) {
      var s = STRING_REFS[i];
      var suspicious = s.context.indexOf("C2") !== -1 || s.context.indexOf("hollowing") !== -1 ||
        s.context.indexOf("Lateral") !== -1 || s.context.indexOf("Anti-debug") !== -1 ||
        s.context.indexOf("detection") !== -1;
      rows +=
        '<tr class="' + (suspicious ? "re-row-warn" : "") + '">' +
        '<td class="mono">' + esc(s.addr) + '</td>' +
        '<td class="mono re-str-val">' + esc(s.value) + '</td>' +
        '<td>' + esc(s.type) + '</td>' +
        '<td>' + esc(s.context) + (suspicious ? ' <span class="re-flag-icon">!</span>' : '') + '</td>' +
        '</tr>';
    }
    return '<div class="re-str-controls">' +
      '<input class="re-input" id="re-str-filter" placeholder="Filter strings...">' +
      '<select class="re-select"><option>All Types</option><option>ASCII</option><option>Unicode</option><option>URLs</option><option>File Paths</option><option>IP Addresses</option></select>' +
      '<span class="re-str-count">' + STRING_REFS.length + ' strings extracted</span>' +
      '</div>' +
      '<div class="re-table-wrap"><table class="re-table">' +
      '<thead><tr><th>Address</th><th>String</th><th>Type</th><th>Context</th></tr></thead>' +
      '<tbody>' + rows + '</tbody>' +
      '</table></div>';
  }

  function renderDisasm() {
    var lines = "";
    for (var i = 0; i < DISASSEMBLY.length; i++) {
      var d = DISASSEMBLY[i];
      var isCall = d.asm.indexOf("call") !== -1;
      var isJump = d.asm.indexOf("jz") !== -1 || d.asm.indexOf("jnz") !== -1 || d.asm.indexOf("jmp") !== -1;
      var cls = isCall ? "re-asm-call" : isJump ? "re-asm-jump" : "";
      lines +=
        '<div class="re-asm-line ' + cls + '">' +
        '<span class="re-asm-addr">' + esc(d.addr) + '</span>' +
        '<span class="re-asm-bytes">' + esc(d.bytes) + '</span>' +
        '<span class="re-asm-inst">' + esc(d.asm) + '</span>' +
        '<span class="re-asm-comment">' + esc(d.comment) + '</span>' +
        '</div>';
    }
    return '<div class="re-asm-controls">' +
      '<input class="re-input" placeholder="Go to address (0x...)">' +
      '<select class="re-select"><option>x86 (32-bit)</option><option>x86-64</option><option>ARM</option><option>MIPS</option></select>' +
      '<select class="re-select"><option>Intel syntax</option><option>AT&amp;T syntax</option></select>' +
      '</div>' +
      '<div class="re-asm-title">sub_401000 &mdash; Process Hollowing Routine</div>' +
      '<div class="re-asm-view">' + lines + '</div>' +
      '<div class="re-xref-panel">' +
      '<h3 class="re-panel-h">Cross References</h3>' +
      '<div class="re-xref">sub_401000 called from: 0x004015A2 (main), 0x00401800 (thread_proc)</div>' +
      '<div class="re-xref">References: CreateProcessA, NtUnmapViewOfSection, VirtualAllocEx</div>' +
      '</div>';
  }

  function renderEntropy() {
    return '<div class="re-entropy-info">' +
      '<p>Entropy measures randomness in data (0 = uniform, 8 = maximum random). High entropy (&gt;7.0) in code sections strongly suggests packing, encryption, or compression.</p>' +
      '</div>' +
      '<canvas id="re-entropy-canvas" class="re-canvas" width="800" height="300"></canvas>' +
      '<div class="re-entropy-legend">' +
      '<span class="re-legend-item"><span class="re-legend-dot re-ent-low-bg"></span> Normal (0-6.0)</span>' +
      '<span class="re-legend-item"><span class="re-legend-dot re-ent-med-bg"></span> Suspicious (6.0-7.0)</span>' +
      '<span class="re-legend-item"><span class="re-legend-dot re-ent-high-bg"></span> Packed/Encrypted (7.0+)</span>' +
      '</div>' +
      '<div class="re-panel"><h3 class="re-panel-h">Packer Detection</h3>' +
      '<div class="re-kv"><span>Packer</span><span class="mono re-warn-text">UPX 3.96w</span></div>' +
      '<div class="re-kv"><span>Confidence</span><span>98%</span></div>' +
      '<div class="re-kv"><span>Original Size</span><span class="mono">~412 KB (estimated)</span></div>' +
      '<div class="re-kv"><span>Compression Ratio</span><span class="mono">2.37:1</span></div>' +
      '<div class="re-kv"><span>Unpack Command</span><span class="mono">upx -d sample_malware.exe</span></div>' +
      '</div>';
  }

  function renderIndicators() {
    var items = "";
    for (var i = 0; i < SUSPICIOUS_INDICATORS.length; i++) {
      var ind = SUSPICIOUS_INDICATORS[i];
      var cls = "re-ind ";
      if (ind.type === "Critical") cls += "re-ind-crit";
      else if (ind.type === "High") cls += "re-ind-high";
      else if (ind.type === "Medium") cls += "re-ind-med";
      else cls += "re-ind-low";
      items +=
        '<div class="' + cls + '">' +
        '<div class="re-ind-header">' +
        '<span class="re-ind-sev">' + esc(ind.type) + '</span>' +
        '<strong>' + esc(ind.indicator) + '</strong>' +
        '<span class="re-mitre">' + esc(ind.mitre) + '</span>' +
        '</div>' +
        '<p class="re-ind-detail">' + esc(ind.detail) + '</p>' +
        '</div>';
    }
    return '<div class="re-ind-summary">' +
      '<div class="re-ind-stat"><span class="re-ind-n re-bad">' + SUSPICIOUS_INDICATORS.filter(function(i) { return i.type === "Critical"; }).length + '</span><span>Critical</span></div>' +
      '<div class="re-ind-stat"><span class="re-ind-n re-warn-text">' + SUSPICIOUS_INDICATORS.filter(function(i) { return i.type === "High"; }).length + '</span><span>High</span></div>' +
      '<div class="re-ind-stat"><span class="re-ind-n">' + SUSPICIOUS_INDICATORS.filter(function(i) { return i.type === "Medium"; }).length + '</span><span>Medium</span></div>' +
      '<div class="re-ind-stat"><span class="re-ind-n">' + SUSPICIOUS_INDICATORS.filter(function(i) { return i.type === "Low"; }).length + '</span><span>Low</span></div>' +
      '</div>' +
      '<div class="re-ind-list">' + items + '</div>';
  }

  function renderYara() {
    var rules = "";
    for (var i = 0; i < YARA_RULES.length; i++) {
      var y = YARA_RULES[i];
      rules +=
        '<div class="re-yara-rule ' + (y.match ? "re-yara-match" : "re-yara-miss") + '">' +
        '<span class="re-yara-status">' + (y.match ? "MATCH" : "NO MATCH") + '</span>' +
        '<strong>' + esc(y.name) + '</strong>' +
        '<span class="re-yara-desc">' + esc(y.desc) + '</span>' +
        '</div>';
    }
    return '<div class="re-panel">' +
      '<h3 class="re-panel-h">YARA Rule Scan Results</h3>' +
      '<div class="re-yara-summary">' + YARA_RULES.filter(function(y) { return y.match; }).length + ' / ' + YARA_RULES.length + ' rules matched</div>' +
      '<div class="re-yara-list">' + rules + '</div>' +
      '</div>' +
      '<div class="re-panel">' +
      '<h3 class="re-panel-h">Custom YARA Rule</h3>' +
      '<textarea class="re-textarea" id="re-yara-custom" rows="10" placeholder="rule custom_rule {\n  strings:\n    $s1 = &quot;suspicious_string&quot;\n  condition:\n    $s1\n}"></textarea>' +
      '<button class="re-btn" id="re-yara-scan">Scan with Rule</button>' +
      '</div>';
  }

  function renderDecompile() {
    var pseudocode = '// Decompiled: sub_401000\n' +
      '// Process Hollowing implementation\n\n' +
      'int __cdecl inject_payload(void *payload, int payload_size) {\n' +
      '    STARTUPINFOA si;\n' +
      '    PROCESS_INFORMATION pi;\n' +
      '    CONTEXT ctx;\n' +
      '    \n' +
      '    memset(&si, 0, sizeof(si));\n' +
      '    si.cb = sizeof(si);\n' +
      '    \n' +
      '    // Create suspended svchost.exe process\n' +
      '    if (!CreateProcessA("svchost.exe", NULL, NULL, NULL,\n' +
      '                        FALSE, CREATE_SUSPENDED, NULL, NULL,\n' +
      '                        &si, &pi)) {\n' +
      '        return -1;\n' +
      '    }\n' +
      '    \n' +
      '    // Hollow out the target process\n' +
      '    NtUnmapViewOfSection(pi.hProcess, (PVOID)0x00400000);\n' +
      '    \n' +
      '    // Allocate memory at image base\n' +
      '    LPVOID base = VirtualAllocEx(pi.hProcess,\n' +
      '                                 (PVOID)0x00400000,\n' +
      '                                 payload_size,\n' +
      '                                 MEM_COMMIT | MEM_RESERVE,\n' +
      '                                 PAGE_EXECUTE_READWRITE);\n' +
      '    \n' +
      '    // Write payload to hollowed process\n' +
      '    WriteProcessMemory(pi.hProcess, base,\n' +
      '                       payload, payload_size, NULL);\n' +
      '    \n' +
      '    // Update entry point and resume\n' +
      '    ctx.ContextFlags = CONTEXT_FULL;\n' +
      '    GetThreadContext(pi.hThread, &ctx);\n' +
      '    ctx.Eax = (DWORD)0x00401000; // new EP\n' +
      '    SetThreadContext(pi.hThread, &ctx);\n' +
      '    ResumeThread(pi.hThread);\n' +
      '    \n' +
      '    return 0;\n' +
      '}';

    return '<div class="re-decompile-bar">' +
      '<select class="re-select"><option>sub_401000 (inject_payload)</option><option>sub_401200 (keylogger_main)</option><option>sub_401500 (c2_beacon)</option><option>sub_401800 (thread_proc)</option><option>sub_401A00 (anti_debug)</option></select>' +
      '</div>' +
      '<pre class="re-decompile-view">' + esc(pseudocode) + '</pre>' +
      '<div class="re-panel">' +
      '<h3 class="re-panel-h">Analysis Notes</h3>' +
      '<p class="muted">This function implements classic process hollowing (T1055.012). It creates a suspended svchost.exe process, unmaps its image, allocates new memory at the same base, writes the malicious payload, updates the thread context to point to the new entry point, and resumes execution. The malicious code now runs under the guise of a legitimate Windows service.</p>' +
      '</div>';
  }

  function drawEntropyChart() {
    var canvas = main.querySelector("#re-entropy-canvas");
    if (!canvas) return;
    var ctx = canvas.getContext("2d");
    var W = canvas.width, H = canvas.height;
    ctx.clearRect(0, 0, W, H);

    ctx.fillStyle = "rgba(0,0,0,0.3)";
    ctx.fillRect(0, 0, W, H);

    var ox = 60, oy = H - 40;
    var barW = (W - 100) / PE_SECTIONS.length - 8;

    for (var g = 0; g <= 8; g++) {
      var gy = oy - (oy - 20) * g / 8;
      ctx.strokeStyle = "rgba(255,255,255,0.08)";
      ctx.beginPath(); ctx.moveTo(ox, gy); ctx.lineTo(W - 30, gy); ctx.stroke();
      ctx.fillStyle = "rgba(255,255,255,0.4)";
      ctx.font = "10px monospace";
      ctx.textAlign = "right";
      ctx.fillText(g.toFixed(1), ox - 8, gy + 4);
    }

    var threshHigh = oy - (oy - 20) * 7 / 8;
    var threshMed = oy - (oy - 20) * 6 / 8;
    ctx.strokeStyle = "rgba(255,92,108,0.3)";
    ctx.setLineDash([4, 4]);
    ctx.beginPath(); ctx.moveTo(ox, threshHigh); ctx.lineTo(W - 30, threshHigh); ctx.stroke();
    ctx.strokeStyle = "rgba(255,200,50,0.3)";
    ctx.beginPath(); ctx.moveTo(ox, threshMed); ctx.lineTo(W - 30, threshMed); ctx.stroke();
    ctx.setLineDash([]);

    for (var i = 0; i < PE_SECTIONS.length; i++) {
      var s = PE_SECTIONS[i];
      var x = ox + i * ((W - 100) / PE_SECTIONS.length) + 4;
      var barH = (oy - 20) * s.entropy / 8;
      var y = oy - barH;

      var color = s.entropy > 7 ? "rgba(255,92,108," : s.entropy > 6 ? "rgba(255,200,50," : "rgba(0,255,200,";
      var grad = ctx.createLinearGradient(0, y, 0, oy);
      grad.addColorStop(0, color + "0.8)");
      grad.addColorStop(1, color + "0.2)");
      ctx.fillStyle = grad;
      ctx.fillRect(x, y, barW, barH);

      ctx.strokeStyle = color + "0.9)";
      ctx.lineWidth = 1;
      ctx.strokeRect(x, y, barW, barH);

      ctx.fillStyle = "rgba(255,255,255,0.7)";
      ctx.font = "10px monospace";
      ctx.textAlign = "center";
      ctx.fillText(s.name, x + barW / 2, oy + 14);
      ctx.fillText(s.entropy.toFixed(2), x + barW / 2, y - 6);
    }
  }

  render();
}
