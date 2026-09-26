// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Digital Forensics Toolkit — file header analysis, timestamp conversion, artifact reference, hash tools.

export function renderForensicsToolkit(container) {

  const FILE_SIGNATURES = [
    { hex: "89504E47", ext: "PNG", desc: "Portable Network Graphics image" },
    { hex: "FFD8FFE0", ext: "JPG", desc: "JPEG image (JFIF)" },
    { hex: "FFD8FFE1", ext: "JPG", desc: "JPEG image (EXIF)" },
    { hex: "FFD8FFDB", ext: "JPG", desc: "JPEG image" },
    { hex: "47494638", ext: "GIF", desc: "GIF image (87a/89a)" },
    { hex: "424D", ext: "BMP", desc: "Bitmap image" },
    { hex: "49492A00", ext: "TIFF", desc: "TIFF image (little-endian)" },
    { hex: "4D4D002A", ext: "TIFF", desc: "TIFF image (big-endian)" },
    { hex: "52494646", ext: "WEBP/AVI/WAV", desc: "RIFF container (check offset 8)" },
    { hex: "504B0304", ext: "ZIP/DOCX/XLSX/PPTX/APK/JAR", desc: "ZIP archive (or Office Open XML / Android APK / Java JAR)" },
    { hex: "504B0506", ext: "ZIP", desc: "ZIP archive (empty)" },
    { hex: "504B0708", ext: "ZIP", desc: "ZIP archive (spanned)" },
    { hex: "25504446", ext: "PDF", desc: "Adobe PDF document" },
    { hex: "D0CF11E0A1B11AE1", ext: "DOC/XLS/PPT/MSG", desc: "Microsoft Compound Document (Office 97-2003)" },
    { hex: "7F454C46", ext: "ELF", desc: "ELF executable (Linux/Unix)" },
    { hex: "4D5A", ext: "EXE/DLL", desc: "DOS/PE executable (Windows)" },
    { hex: "CAFEBABE", ext: "CLASS/JAR", desc: "Java class file" },
    { hex: "CEFAEDFE", ext: "Mach-O", desc: "Mach-O binary (32-bit, little-endian)" },
    { hex: "CFFAEDFE", ext: "Mach-O", desc: "Mach-O binary (64-bit, little-endian)" },
    { hex: "FEEDFACE", ext: "Mach-O", desc: "Mach-O binary (32-bit, big-endian)" },
    { hex: "FEEDFACF", ext: "Mach-O", desc: "Mach-O binary (64-bit, big-endian)" },
    { hex: "1F8B08", ext: "GZ", desc: "Gzip compressed" },
    { hex: "425A68", ext: "BZ2", desc: "Bzip2 compressed" },
    { hex: "FD377A585A00", ext: "XZ", desc: "XZ compressed" },
    { hex: "377ABCAF271C", ext: "7Z", desc: "7-Zip archive" },
    { hex: "526172211A07", ext: "RAR", desc: "RAR archive (v4)" },
    { hex: "526172211A0700", ext: "RAR", desc: "RAR archive (v5)" },
    { hex: "7573746172", ext: "TAR", desc: "TAR archive (offset 257)" },
    { hex: "213C617263683E", ext: "DEB/AR", desc: "Debian package / Unix AR archive" },
    { hex: "EDABEEDB", ext: "RPM", desc: "Red Hat RPM package" },
    { hex: "4F676753", ext: "OGG", desc: "Ogg Vorbis audio" },
    { hex: "664C6143", ext: "FLAC", desc: "Free Lossless Audio Codec" },
    { hex: "494433", ext: "MP3", desc: "MP3 audio (ID3 tag)" },
    { hex: "FFFB", ext: "MP3", desc: "MP3 audio (frame sync)" },
    { hex: "FFF3", ext: "MP3", desc: "MP3 audio (frame sync)" },
    { hex: "FFF2", ext: "MP3", desc: "MP3 audio (frame sync)" },
    { hex: "1A45DFA3", ext: "MKV/WEBM", desc: "Matroska/WebM video" },
    { hex: "000000186674797033677035", ext: "MP4", desc: "MPEG-4 video (3gp5)" },
    { hex: "0000001C667479704D534E56", ext: "MP4", desc: "MPEG-4 video (MSNV)" },
    { hex: "00000020667479706973", ext: "MP4", desc: "MPEG-4 video" },
    { hex: "667479704D534E56", ext: "MP4", desc: "MP4 video (ftyp at offset 4)" },
    { hex: "6674797069736F6D", ext: "MP4", desc: "MP4 video (isom)" },
    { hex: "000001BA", ext: "MPEG", desc: "MPEG video" },
    { hex: "000001B3", ext: "MPEG", desc: "MPEG video" },
    { hex: "3026B2758E66CF11", ext: "WMV/WMA/ASF", desc: "Windows Media" },
    { hex: "464C5601", ext: "FLV", desc: "Flash Video" },
    { hex: "53514C69746520666F726D6174203300", ext: "SQLite", desc: "SQLite database" },
    { hex: "00000100", ext: "ICO", desc: "Windows icon" },
    { hex: "00000200", ext: "CUR", desc: "Windows cursor" },
    { hex: "2321", ext: "Script", desc: "Unix shebang (#!)" },
    { hex: "3C3F786D6C", ext: "XML", desc: "XML document" },
    { hex: "3C21444F43545950", ext: "HTML", desc: "HTML document" },
    { hex: "3C68746D6C", ext: "HTML", desc: "HTML document" },
    { hex: "EFBBBF", ext: "UTF-8", desc: "UTF-8 BOM marker" },
    { hex: "FFFE", ext: "UTF-16LE", desc: "UTF-16 Little Endian BOM" },
    { hex: "FEFF", ext: "UTF-16BE", desc: "UTF-16 Big Endian BOM" },
    { hex: "255044462D", ext: "PDF", desc: "PDF document" },
    { hex: "7B5C72746631", ext: "RTF", desc: "Rich Text Format" },
    { hex: "38425053", ext: "PSD", desc: "Adobe Photoshop" },
    { hex: "000100005374616E64617264204A", ext: "MDB", desc: "MS Access database" },
    { hex: "4C000000011402", ext: "LNK", desc: "Windows shortcut" },
    { hex: "49545346", ext: "CHM", desc: "MS Compiled HTML Help" },
    { hex: "72656766", ext: "REG", desc: "Windows Registry hive" },
    { hex: "ACED0005", ext: "Java", desc: "Java serialized object" },
    { hex: "0061736D", ext: "WASM", desc: "WebAssembly binary" },
    { hex: "4C01", ext: "OBJ", desc: "MS COFF object file" },
    { hex: "2D2D2D2D2D424547494E", ext: "PEM", desc: "PEM certificate/key" },
    { hex: "30820", ext: "DER", desc: "DER encoded certificate" },
    { hex: "2D2D2D2D2D424547494E2050475020", ext: "PGP", desc: "PGP public key block" },
    { hex: "6D6473746F7265", ext: "Spotlight", desc: "macOS Spotlight index" },
    { hex: "4D444D5093A7", ext: "MDF", desc: "Alcohol 120% disk image" },
    { hex: "434F4E4543545258", ext: "VHD", desc: "Virtual hard disk" },
    { hex: "7F454C460201", ext: "ELF64", desc: "ELF 64-bit executable" },
    { hex: "7F454C460101", ext: "ELF32", desc: "ELF 32-bit executable" },
    { hex: "64657831", ext: "DEX", desc: "Dalvik Executable (Android)" },
    { hex: "78617221", ext: "XAR", desc: "macOS installer (xar archive)" },
    { hex: "494E4458", ext: "IDX", desc: "Index file" },
    { hex: "4C4E0200", ext: "GUL", desc: "Windows Help (GUL)" },
    { hex: "4D5448", ext: "MIDI", desc: "MIDI audio" },
    { hex: "23204D6963726F736F6674", ext: "MSI", desc: "Windows Installer" },
    { hex: "CECECECE", ext: "JCEKS", desc: "Java KeyStore" },
    { hex: "FEEDFEED", ext: "JKS", desc: "Java KeyStore" },
    { hex: "5061636B", ext: "PACK", desc: "Git pack file" },
    { hex: "44494346", ext: "DICF", desc: "Digital Imaging (DICF)" },
    { hex: "28B52FFD", ext: "ZSTD", desc: "Zstandard compressed" },
    { hex: "04224D18", ext: "LZ4", desc: "LZ4 compressed" },
    { hex: "4C5A4950", ext: "LZIP", desc: "Lzip compressed" },
    { hex: "EDEDED", ext: "LUAC", desc: "Lua compiled script" },
    { hex: "1B4C7561", ext: "LUAC", desc: "Lua bytecode" },
    { hex: "789C", ext: "ZLIB", desc: "Zlib compressed (default)" },
    { hex: "7801", ext: "ZLIB", desc: "Zlib compressed (no compression)" },
    { hex: "78DA", ext: "ZLIB", desc: "Zlib compressed (best)" },
  ];

  const WINDOWS_ARTIFACTS = [
    { path: "C:\\Windows\\Prefetch\\", desc: "Application execution evidence", tool: "PECmd", forensicValue: "Shows which programs ran, when, and how many times" },
    { path: "NTUSER.DAT", desc: "User registry hive", tool: "Registry Explorer", forensicValue: "User preferences, recent files, typed URLs, searches" },
    { path: "SYSTEM hive", desc: "System configuration", tool: "Registry Explorer", forensicValue: "Computer name, timezone, network interfaces, services, USB history" },
    { path: "SAM hive", desc: "Security Accounts Manager", tool: "mimikatz / Registry Explorer", forensicValue: "Local user accounts, password hashes (LM/NTLM)" },
    { path: "SOFTWARE hive", desc: "Installed software", tool: "Registry Explorer", forensicValue: "Installed programs, OS version, registered apps" },
    { path: "SECURITY hive", desc: "Security policies", tool: "Registry Explorer", forensicValue: "Security policies, cached domain credentials" },
    { path: "C:\\Windows\\System32\\winevt\\Logs\\", desc: "Windows Event Logs", tool: "Event Log Explorer / EvtxECmd", forensicValue: "Security, System, Application, PowerShell logs" },
    { path: "C:\\$MFT", desc: "Master File Table", tool: "MFTECmd / analyzeMFT", forensicValue: "All NTFS file metadata: timestamps, sizes, parent directories" },
    { path: "C:\\$UsnJrnl", desc: "USN Change Journal", tool: "MFTECmd", forensicValue: "File system change log — creates, deletes, renames" },
    { path: "C:\\$LogFile", desc: "NTFS Transaction Log", tool: "LogFileParser", forensicValue: "NTFS metadata changes for recovery" },
    { path: "C:\\Windows\\AppCompat\\Programs\\Amcache.hve", desc: "Amcache", tool: "AmcacheParser", forensicValue: "Application execution, SHA-1 hashes, install timestamps" },
    { path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache", desc: "ShimCache / AppCompatCache", tool: "AppCompatCacheParser", forensicValue: "Evidence of file existence and execution" },
    { path: "C:\\Windows\\System32\\sru\\SRUDB.dat", desc: "SRUM Database", tool: "SrumECmd", forensicValue: "Application resource usage: network bytes, CPU, energy" },
    { path: "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\", desc: "Recent files (LNK)", tool: "LECmd", forensicValue: "Recently accessed files with timestamps, target paths, MAC addresses" },
    { path: "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\", desc: "Jump Lists", tool: "JLECmd", forensicValue: "Recently/frequently used files per application" },
    { path: "C:\\Users\\*\\NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths", desc: "Typed Paths", tool: "Registry Explorer", forensicValue: "Paths manually typed in Explorer address bar" },
    { path: "C:\\Users\\*\\NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery", desc: "Explorer Searches", tool: "Registry Explorer", forensicValue: "Searches performed in Windows Explorer" },
    { path: "C:\\Users\\*\\NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", desc: "Run Dialog History", tool: "Registry Explorer", forensicValue: "Commands typed in Win+R Run dialog" },
    { path: "C:\\Users\\*\\NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist", desc: "UserAssist", tool: "UserAssist / Registry Explorer", forensicValue: "GUI program execution counts and last run times (ROT-13 encoded)" },
    { path: "C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat", desc: "IE/Edge Web Cache", tool: "ESEDatabaseView", forensicValue: "Browser history, cookies, downloads for IE/Edge Legacy" },
    { path: "C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", desc: "Chrome History", tool: "DB Browser for SQLite", forensicValue: "Chrome browsing history (SQLite database)" },
    { path: "C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\places.sqlite", desc: "Firefox History", tool: "DB Browser for SQLite", forensicValue: "Firefox browsing history and bookmarks" },
    { path: "C:\\Users\\*\\AppData\\Local\\ConnectedDevicesPlatform\\", desc: "Connected Devices", tool: "Manual parsing", forensicValue: "Bluetooth, companion devices, activity timeline" },
    { path: "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR", desc: "USB Device History", tool: "USBDeview / Registry Explorer", forensicValue: "Connected USB storage devices: vendor, product, serial, first/last connect" },
    { path: "HKLM\\SYSTEM\\MountedDevices", desc: "Mounted Devices", tool: "Registry Explorer", forensicValue: "Drive letter assignments for volumes" },
    { path: "C:\\Windows\\inf\\setupapi.dev.log", desc: "Device Install Log", tool: "Text editor", forensicValue: "First-time device installation timestamps" },
    { path: "C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\Explorer\\thumbcache_*.db", desc: "Thumbnail Cache", tool: "Thumbcache Viewer", forensicValue: "Thumbnails of viewed images (even deleted ones)" },
    { path: "C:\\$Recycle.Bin\\", desc: "Recycle Bin", tool: "RBCmd", forensicValue: "Deleted files with original path and deletion timestamp" },
    { path: "C:\\Windows\\System32\\Tasks\\", desc: "Scheduled Tasks", tool: "Text editor / TaskScheduler", forensicValue: "Persistence mechanism — scheduled tasks XML definitions" },
    { path: "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt", desc: "PowerShell History", tool: "Text editor", forensicValue: "PowerShell command history per user" },
    { path: "HKCU\\Software\\Microsoft\\Terminal Server Client\\Default", desc: "RDP Client MRU", tool: "Registry Explorer", forensicValue: "Remote Desktop targets the user connected to" },
    { path: "C:\\Windows\\System32\\LogFiles\\W3SVC*\\", desc: "IIS Logs", tool: "Log Parser / text editor", forensicValue: "Web server access logs" },
    { path: "Security.evtx Event ID 4624/4625", desc: "Logon Events", tool: "EvtxECmd", forensicValue: "Successful (4624) and failed (4625) logon attempts" },
    { path: "Security.evtx Event ID 4688", desc: "Process Creation", tool: "EvtxECmd", forensicValue: "New process created with command line (if auditing enabled)" },
    { path: "Security.evtx Event ID 4672", desc: "Special Privileges Assigned", tool: "EvtxECmd", forensicValue: "Admin/elevated logon" },
    { path: "Security.evtx Event ID 4720/4726", desc: "Account Created/Deleted", tool: "EvtxECmd", forensicValue: "User account management" },
    { path: "Microsoft-Windows-Sysmon/Operational.evtx", desc: "Sysmon Logs", tool: "EvtxECmd / Sysmon View", forensicValue: "Process creation (1), network connections (3), file creation (11), registry (12-14), DNS (22)" },
    { path: "Microsoft-Windows-PowerShell/Operational.evtx Event ID 4104", desc: "PowerShell ScriptBlock", tool: "EvtxECmd", forensicValue: "Full PowerShell script content (if ScriptBlock logging enabled)" },
    { path: "Microsoft-Windows-TaskScheduler/Operational.evtx", desc: "Task Scheduler Log", tool: "EvtxECmd", forensicValue: "Scheduled task registration, execution, completion" },
    { path: "C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\Notifications\\wpndatabase.db", desc: "Windows Notifications", tool: "DB Browser for SQLite", forensicValue: "Windows notification history" },
  ];

  const LINUX_ARTIFACTS = [
    { path: "/var/log/auth.log (Debian) or /var/log/secure (RHEL)", desc: "Authentication log", forensicValue: "Login attempts (success/fail), sudo usage, SSH access, su usage" },
    { path: "/var/log/syslog or /var/log/messages", desc: "System log", forensicValue: "General system events, service starts/stops, kernel messages" },
    { path: "/var/log/kern.log", desc: "Kernel log", forensicValue: "Kernel messages — hardware errors, module loads, firewall drops" },
    { path: "/var/log/daemon.log", desc: "Daemon log", forensicValue: "Background service events" },
    { path: "/var/log/cron or /var/log/cron.log", desc: "Cron log", forensicValue: "Scheduled task execution — persistence detection" },
    { path: "/var/log/apt/history.log", desc: "APT history", forensicValue: "Package installation/removal history with timestamps" },
    { path: "/var/log/dpkg.log", desc: "DPKG log", forensicValue: "Low-level package operations" },
    { path: "/var/log/yum.log or /var/log/dnf.log", desc: "RPM package log", forensicValue: "Package management on RHEL-based systems" },
    { path: "/var/log/apache2/ or /var/log/httpd/", desc: "Apache web server logs", forensicValue: "access.log (requests), error.log (errors)" },
    { path: "/var/log/nginx/", desc: "Nginx web server logs", forensicValue: "access.log, error.log" },
    { path: "/var/log/faillog", desc: "Failed login log", forensicValue: "Binary file — use 'faillog -a' to read" },
    { path: "/var/log/lastlog", desc: "Last login per user", forensicValue: "Binary file — use 'lastlog' to read" },
    { path: "/var/log/wtmp", desc: "Login/logout/reboot records", forensicValue: "Binary — use 'last' command. Shows login sessions." },
    { path: "/var/log/btmp", desc: "Failed login attempts", forensicValue: "Binary — use 'lastb' command. Brute force detection." },
    { path: "/var/log/utmp", desc: "Currently logged in users", forensicValue: "Binary — use 'who' or 'w' command" },
    { path: "/etc/passwd", desc: "User accounts", forensicValue: "All user accounts, UIDs, home dirs, shells — look for UID 0 backdoors" },
    { path: "/etc/shadow", desc: "Password hashes", forensicValue: "Password hashes, aging info — check for empty passwords" },
    { path: "/etc/group", desc: "Group memberships", forensicValue: "Who is in sudo/admin/wheel/docker groups" },
    { path: "/etc/sudoers + /etc/sudoers.d/", desc: "Sudo configuration", forensicValue: "Who can run what as root — NOPASSWD entries" },
    { path: "/etc/crontab + /etc/cron.d/ + /var/spool/cron/", desc: "Cron jobs", forensicValue: "Scheduled tasks — persistence mechanism" },
    { path: "/etc/systemd/system/ + /lib/systemd/system/", desc: "Systemd services", forensicValue: "Service definitions — persistence mechanism" },
    { path: "~/.bash_history (or .zsh_history)", desc: "Shell history", forensicValue: "Commands executed by user — may include passwords, curl commands, SSH" },
    { path: "~/.ssh/authorized_keys", desc: "SSH authorized keys", forensicValue: "Who can SSH in without a password — backdoor SSH keys" },
    { path: "~/.ssh/known_hosts", desc: "SSH known hosts", forensicValue: "Hosts the user has connected to via SSH" },
    { path: "~/.ssh/config", desc: "SSH client config", forensicValue: "Configured SSH aliases, hosts, tunnels" },
    { path: "/etc/ssh/sshd_config", desc: "SSH server config", forensicValue: "SSH configuration — PermitRootLogin, PasswordAuthentication" },
    { path: "~/.gnupg/", desc: "GPG keyring", forensicValue: "Encryption keys, trust database" },
    { path: "/tmp/ and /dev/shm/", desc: "Temporary directories", forensicValue: "Malware often stages here — world-writable, sometimes tmpfs" },
    { path: "~/.local/share/Trash/", desc: "User trash", forensicValue: "Deleted files and their original paths" },
    { path: "/etc/hosts", desc: "Static DNS mappings", forensicValue: "DNS redirects — C2 or ad-blocking evidence" },
    { path: "/etc/resolv.conf", desc: "DNS resolver config", forensicValue: "DNS servers in use — rogue DNS detection" },
    { path: "/proc/*/cmdline + /proc/*/maps + /proc/*/fd/", desc: "Process information", forensicValue: "Running processes, memory maps, open files (live system only)" },
    { path: "/etc/ld.so.preload", desc: "LD_PRELOAD config", forensicValue: "Rootkit detection — libraries loaded before all others" },
    { path: "~/.config/autostart/", desc: "XDG autostart", forensicValue: "Programs that auto-start on desktop login — persistence" },
    { path: "/etc/rc.local", desc: "Legacy boot script", forensicValue: "Commands run at boot — persistence mechanism" },
    { path: "~/.mozilla/firefox/*/places.sqlite", desc: "Firefox history", forensicValue: "Browsing history and bookmarks" },
    { path: "~/.config/google-chrome/Default/History", desc: "Chrome history", forensicValue: "Browsing history (SQLite)" },
  ];

  const VOLATILITY_PLUGINS = [
    { name: "windows.info", desc: "System information (OS version, architecture, DTB)", category: "Info" },
    { name: "windows.pslist", desc: "List running processes (from process list)", category: "Processes" },
    { name: "windows.psscan", desc: "Scan for process structures (finds hidden processes)", category: "Processes" },
    { name: "windows.pstree", desc: "Process tree — parent/child relationships", category: "Processes" },
    { name: "windows.cmdline", desc: "Command line arguments for each process", category: "Processes" },
    { name: "windows.dlllist", desc: "DLLs loaded by each process", category: "Processes" },
    { name: "windows.handles", desc: "Open handles (files, registry keys, mutexes) per process", category: "Processes" },
    { name: "windows.memmap", desc: "Memory mappings for a process", category: "Memory" },
    { name: "windows.vadinfo", desc: "Virtual Address Descriptor information", category: "Memory" },
    { name: "windows.malfind", desc: "Find injected code / suspicious memory regions (RWX pages)", category: "Malware" },
    { name: "windows.netscan", desc: "Network connections and listening sockets", category: "Network" },
    { name: "windows.netstat", desc: "Active network connections (like netstat)", category: "Network" },
    { name: "windows.registry.hivelist", desc: "List registry hives loaded in memory", category: "Registry" },
    { name: "windows.registry.printkey", desc: "Print registry key values", category: "Registry" },
    { name: "windows.registry.userassist", desc: "Parse UserAssist entries (program execution)", category: "Registry" },
    { name: "windows.filescan", desc: "Scan for file objects in memory", category: "Files" },
    { name: "windows.dumpfiles", desc: "Extract files from memory (by virtual address)", category: "Files" },
    { name: "windows.hashdump", desc: "Dump password hashes from SAM", category: "Credentials" },
    { name: "windows.cachedump", desc: "Dump cached domain credentials", category: "Credentials" },
    { name: "windows.lsadump", desc: "Dump LSA secrets", category: "Credentials" },
    { name: "windows.svcscan", desc: "Scan for Windows services", category: "Services" },
    { name: "windows.driverscan", desc: "Scan for loaded kernel drivers", category: "Drivers" },
    { name: "windows.modules", desc: "List loaded kernel modules", category: "Drivers" },
    { name: "windows.modscan", desc: "Scan for kernel modules (finds unlinked)", category: "Drivers" },
    { name: "windows.ssdt", desc: "System Service Descriptor Table — rootkit detection", category: "Rootkit" },
    { name: "windows.callbacks", desc: "Enumerate kernel callbacks — rootkit detection", category: "Rootkit" },
    { name: "windows.envars", desc: "Environment variables per process", category: "Info" },
    { name: "windows.getsids", desc: "SIDs associated with each process", category: "Info" },
    { name: "windows.privileges", desc: "Privileges enabled for each process", category: "Info" },
    { name: "timeliner.Timeliner", desc: "Create a combined timeline of all artifacts", category: "Timeline" },
    { name: "linux.pslist", desc: "List running processes (Linux)", category: "Linux" },
    { name: "linux.pstree", desc: "Process tree (Linux)", category: "Linux" },
    { name: "linux.bash", desc: "Recover bash history from memory (Linux)", category: "Linux" },
    { name: "linux.check_idt", desc: "Check IDT for hooks (Linux rootkit detection)", category: "Linux" },
    { name: "linux.check_syscall", desc: "Check syscall table for hooks (Linux)", category: "Linux" },
    { name: "linux.elfs", desc: "List ELF binaries in process memory (Linux)", category: "Linux" },
    { name: "linux.lsmod", desc: "List loaded kernel modules (Linux)", category: "Linux" },
    { name: "linux.lsof", desc: "List open files per process (Linux)", category: "Linux" },
    { name: "linux.mount", desc: "List mounted filesystems (Linux)", category: "Linux" },
    { name: "linux.sockstat", desc: "List network sockets (Linux)", category: "Linux" },
  ];

  const EXIF_TAGS = [
    { id: "0x010F", name: "Make", desc: "Camera manufacturer", forensicValue: "Identifies device" },
    { id: "0x0110", name: "Model", desc: "Camera model", forensicValue: "Narrows device identification" },
    { id: "0x0112", name: "Orientation", desc: "Image rotation", forensicValue: "How the device was held" },
    { id: "0x011A", name: "XResolution", desc: "Horizontal DPI", forensicValue: "Print vs screen intent" },
    { id: "0x0131", name: "Software", desc: "Software used", forensicValue: "Editing software identification" },
    { id: "0x0132", name: "DateTime", desc: "File modification date", forensicValue: "When image was last modified" },
    { id: "0x8769", name: "ExifIFDPointer", desc: "Pointer to Exif sub-IFD", forensicValue: "Contains detailed metadata" },
    { id: "0x8825", name: "GPSInfoIFDPointer", desc: "Pointer to GPS IFD", forensicValue: "Location data — critical for geolocation" },
    { id: "0x9000", name: "ExifVersion", desc: "EXIF version", forensicValue: "Metadata standard version" },
    { id: "0x9003", name: "DateTimeOriginal", desc: "Date photo was taken", forensicValue: "Original capture time — most reliable timestamp" },
    { id: "0x9004", name: "DateTimeDigitized", desc: "Date digitized", forensicValue: "When the image was digitized" },
    { id: "0x920A", name: "FocalLength", desc: "Lens focal length", forensicValue: "Zoom level — helps determine distance to subject" },
    { id: "0xA002", name: "PixelXDimension", desc: "Image width", forensicValue: "Original resolution" },
    { id: "0xA003", name: "PixelYDimension", desc: "Image height", forensicValue: "Original resolution" },
    { id: "0xA420", name: "ImageUniqueID", desc: "Unique image identifier", forensicValue: "Can link images across copies" },
    { id: "0x0001", name: "GPSLatitudeRef", desc: "N or S", forensicValue: "Latitude hemisphere" },
    { id: "0x0002", name: "GPSLatitude", desc: "Latitude degrees/minutes/seconds", forensicValue: "Exact latitude" },
    { id: "0x0003", name: "GPSLongitudeRef", desc: "E or W", forensicValue: "Longitude hemisphere" },
    { id: "0x0004", name: "GPSLongitude", desc: "Longitude degrees/minutes/seconds", forensicValue: "Exact longitude" },
    { id: "0x0005", name: "GPSAltitudeRef", desc: "Above/below sea level", forensicValue: "Altitude reference" },
    { id: "0x0006", name: "GPSAltitude", desc: "Altitude in meters", forensicValue: "Elevation" },
    { id: "0x0007", name: "GPSTimeStamp", desc: "UTC time from GPS", forensicValue: "GPS-based timestamp — very accurate" },
    { id: "0x001D", name: "GPSDateStamp", desc: "UTC date from GPS", forensicValue: "GPS-based date" },
    { id: "0xA430", name: "CameraOwnerName", desc: "Camera owner", forensicValue: "Directly identifies owner" },
    { id: "0xA431", name: "BodySerialNumber", desc: "Camera serial number", forensicValue: "Unique device identifier" },
    { id: "0xA432", name: "LensSpecification", desc: "Lens info", forensicValue: "Lens focal range and aperture" },
    { id: "0xA434", name: "LensModel", desc: "Lens model", forensicValue: "Specific lens identification" },
    { id: "0xA435", name: "LensSerialNumber", desc: "Lens serial", forensicValue: "Unique lens identifier" },
  ];

  let activeTab = "file-id";

  function identifyFile(hexStr) {
    const clean = hexStr.replace(/[\s\-:]/g, "").toUpperCase();
    const matches = [];
    for (const sig of FILE_SIGNATURES) {
      if (clean.startsWith(sig.hex.toUpperCase())) {
        matches.push(sig);
      }
    }
    return matches;
  }

  function convertTimestamp(value, fromFormat) {
    let ms;
    const n = Number(value);
    switch (fromFormat) {
      case "unix": ms = n * 1000; break;
      case "unix_ms": ms = n; break;
      case "filetime": ms = (n / 10000) - 11644473600000; break;
      case "mac_absolute": ms = (n + 978307200) * 1000; break;
      case "fat": {
        const date = (n >> 16) & 0xFFFF, time = n & 0xFFFF;
        const y = ((date >> 9) & 0x7F) + 1980, mo = (date >> 5) & 0x0F, d = date & 0x1F;
        const h = (time >> 11) & 0x1F, mi = (time >> 5) & 0x3F, s = (time & 0x1F) * 2;
        ms = Date.UTC(y, mo - 1, d, h, mi, s); break;
      }
      case "chrome": ms = (n / 1000) - 11644473600000; break;
      case "webkit": ms = (n + 978307200) * 1000; break;
      case "iso": ms = new Date(value).getTime(); break;
      default: ms = n * 1000;
    }
    if (isNaN(ms)) return null;
    const d = new Date(ms);
    const winFT = BigInt(ms + 11644473600000) * 10000n;
    const macAbs = Math.floor(ms / 1000) - 978307200;
    const chromeFT = (ms + 11644473600000) * 1000;
    return {
      iso: d.toISOString(),
      unix: Math.floor(ms / 1000),
      unix_ms: ms,
      filetime: winFT.toString(),
      mac_absolute: macAbs,
      chrome: chromeFT,
      webkit: Math.floor(ms / 1000) - 978307200,
      human: d.toLocaleString("en-US", { dateStyle: "full", timeStyle: "long", timeZone: "UTC" }) + " UTC",
      local: d.toLocaleString(),
    };
  }

  function extractStrings(hexStr, minLen) {
    const clean = hexStr.replace(/[\s\-:]/g, "");
    const results = [];
    let current = "", offset = 0;
    for (let i = 0; i < clean.length; i += 2) {
      const byte = parseInt(clean.substr(i, 2), 16);
      if (byte >= 32 && byte <= 126) {
        if (!current) offset = i / 2;
        current += String.fromCharCode(byte);
      } else {
        if (current.length >= minLen) results.push({ offset, string: current });
        current = "";
      }
    }
    if (current.length >= minLen) results.push({ offset, string: current });
    return results;
  }

  function render() {
    container.innerHTML = `
      <style>
        .ft-wrap{font-family:system-ui,sans-serif;color:#e0e0e0;max-width:1200px;margin:0 auto;padding:20px}
        .ft-h1{font-size:1.6rem;font-weight:700;color:#00d4ff;margin:0 0 6px}
        .ft-sub{color:#888;font-size:.85rem;margin:0 0 20px}
        .ft-tabs{display:flex;gap:4px;margin-bottom:20px;border-bottom:1px solid #333;flex-wrap:wrap}
        .ft-tab{padding:8px 14px;cursor:pointer;color:#888;border:none;background:none;font-size:.82rem;border-bottom:2px solid transparent;transition:all .2s}
        .ft-tab:hover{color:#ccc}
        .ft-tab.active{color:#00d4ff;border-bottom-color:#00d4ff}
        .ft-card{background:#111;border:1px solid #222;border-radius:8px;padding:16px;margin-bottom:16px}
        .ft-card h3{margin:0 0 12px;font-size:1rem;color:#00d4ff}
        .ft-input{background:#0a0a0a;border:1px solid #333;color:#e0e0e0;padding:8px 12px;border-radius:4px;font-family:monospace;font-size:.85rem;width:100%}
        .ft-input:focus{outline:none;border-color:#00d4ff}
        .ft-btn{background:#00d4ff;color:#000;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;font-size:.8rem;font-weight:600}
        .ft-table{width:100%;border-collapse:collapse;font-size:.8rem}
        .ft-table th{text-align:left;padding:6px 8px;border-bottom:1px solid #333;color:#888;font-weight:600;position:sticky;top:0;background:#111}
        .ft-table td{padding:5px 8px;border-bottom:1px solid #1a1a1a;vertical-align:top}
        .ft-mono{font-family:monospace;font-size:.8rem}
        .ft-badge{display:inline-block;padding:2px 6px;border-radius:3px;font-size:.7rem;font-weight:600}
        .ft-scroll{max-height:500px;overflow-y:auto}
        .ft-result{background:#0a0f14;border:1px solid #00d4ff33;border-radius:6px;padding:12px;margin:8px 0}
        .ft-row{display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #1a1a1a}
        .ft-label{color:#888;font-size:.82rem}
        .ft-val{font-family:monospace;color:#e0e0e0;font-size:.82rem}
        .ft-search{margin-bottom:12px}
      </style>
      <div class="ft-wrap">
        <h1 class="ft-h1">Forensics Toolkit</h1>
        <p class="ft-sub">File identification, timestamp conversion, artifact reference, and analysis tools</p>
        <div class="ft-tabs">
          ${["file-id", "timestamps", "strings", "win-artifacts", "linux-artifacts", "volatility", "exif"].map(t =>
            `<button class="ft-tab ${activeTab === t ? "active" : ""}" data-tab="${t}">${
              ({
                "file-id": "File ID",
                "timestamps": "Timestamps",
                "strings": "Strings",
                "win-artifacts": "Windows",
                "linux-artifacts": "Linux",
                "volatility": "Volatility3",
                "exif": "EXIF"
              })[t]
            }</button>`
          ).join("")}
        </div>
        <div id="ft-content"></div>
      </div>`;
    container.querySelectorAll(".ft-tab").forEach(tab => {
      tab.onclick = () => { activeTab = tab.dataset.tab; render(); };
    });
    const content = container.querySelector("#ft-content");
    if (activeTab === "file-id") renderFileId(content);
    else if (activeTab === "timestamps") renderTimestamps(content);
    else if (activeTab === "strings") renderStrings(content);
    else if (activeTab === "win-artifacts") renderArtifacts(content, WINDOWS_ARTIFACTS, "Windows Forensic Artifacts");
    else if (activeTab === "linux-artifacts") renderArtifacts(content, LINUX_ARTIFACTS, "Linux Forensic Artifacts");
    else if (activeTab === "volatility") renderVolatility(content);
    else if (activeTab === "exif") renderExif(content);
  }

  function renderFileId(el) {
    el.innerHTML = `
      <div class="ft-card">
        <h3>File Header / Magic Bytes Identifier</h3>
        <p style="color:#888;font-size:.82rem;margin:0 0 8px">Paste hex bytes from the start of a file to identify its type.</p>
        <input class="ft-input" id="ft-hex-input" placeholder="e.g. 89504E470D0A1A0A or 4D 5A 90 00" style="margin-bottom:8px">
        <button class="ft-btn" id="ft-identify-btn">Identify</button>
        <div id="ft-id-result"></div>
      </div>
      <div class="ft-card">
        <h3>Complete Signature Database (${FILE_SIGNATURES.length} signatures)</h3>
        <input class="ft-input ft-search" id="ft-sig-search" placeholder="Search by extension or description...">
        <div class="ft-scroll">
          <table class="ft-table" id="ft-sig-table">
            <tr><th>Hex</th><th>Extension</th><th>Description</th></tr>
            ${FILE_SIGNATURES.map(s => `<tr><td class="ft-mono" style="color:#00d4ff">${s.hex}</td><td><span class="ft-badge" style="background:#1a3a4a;color:#00d4ff">${s.ext}</span></td><td>${s.desc}</td></tr>`).join("")}
          </table>
        </div>
      </div>`;
    const input = el.querySelector("#ft-hex-input");
    const btn = el.querySelector("#ft-identify-btn");
    const result = el.querySelector("#ft-id-result");
    const search = el.querySelector("#ft-sig-search");
    const table = el.querySelector("#ft-sig-table");
    btn.onclick = () => {
      const matches = identifyFile(input.value);
      if (!matches.length) { result.innerHTML = `<div class="ft-result" style="border-color:#ef444433"><span style="color:#ef4444">No matching signature found.</span> The file may be text-based, corrupted, or use an uncommon format.</div>`; return; }
      result.innerHTML = matches.map(m => `<div class="ft-result"><span class="ft-badge" style="background:#0d4f2b;color:#17a34a">Match</span> <strong>${m.ext}</strong> — ${m.desc}<br><span class="ft-mono" style="color:#888">Signature: ${m.hex}</span></div>`).join("");
    };
    search.oninput = () => {
      const q = search.value.toLowerCase();
      const rows = table.querySelectorAll("tr");
      rows.forEach((r, i) => { if (i === 0) return; r.style.display = r.textContent.toLowerCase().includes(q) ? "" : "none"; });
    };
  }

  function renderTimestamps(el) {
    el.innerHTML = `
      <div class="ft-card">
        <h3>Timestamp Converter</h3>
        <div style="display:grid;grid-template-columns:1fr 200px auto;gap:8px;align-items:end">
          <div><label style="color:#888;font-size:.75rem;display:block;margin-bottom:4px">Value</label><input class="ft-input" id="ft-ts-input" placeholder="e.g. 1700000000"></div>
          <div><label style="color:#888;font-size:.75rem;display:block;margin-bottom:4px">Format</label><select class="ft-input" id="ft-ts-format">
            <option value="unix">Unix (seconds)</option>
            <option value="unix_ms">Unix (milliseconds)</option>
            <option value="filetime">Windows FILETIME</option>
            <option value="mac_absolute">Mac Absolute</option>
            <option value="fat">FAT timestamp</option>
            <option value="chrome">Chrome/WebKit</option>
            <option value="webkit">Cocoa/WebKit</option>
            <option value="iso">ISO 8601</option>
          </select></div>
          <button class="ft-btn" id="ft-ts-btn" style="height:36px">Convert</button>
        </div>
        <div id="ft-ts-result"></div>
      </div>
      <div class="ft-card">
        <h3>Current Time Reference</h3>
        <div id="ft-now"></div>
      </div>`;
    const btn = el.querySelector("#ft-ts-btn");
    const result = el.querySelector("#ft-ts-result");
    btn.onclick = () => {
      const val = el.querySelector("#ft-ts-input").value.trim();
      const fmt = el.querySelector("#ft-ts-format").value;
      const r = convertTimestamp(val, fmt);
      if (!r) { result.innerHTML = `<div class="ft-result" style="border-color:#ef444433;color:#ef4444">Invalid timestamp value</div>`; return; }
      result.innerHTML = `<div class="ft-result">
        ${Object.entries({ "Human Readable": r.human, "Local Time": r.local, "ISO 8601": r.iso, "Unix (s)": r.unix, "Unix (ms)": r.unix_ms, "Windows FILETIME": r.filetime, "Mac Absolute": r.mac_absolute, "Chrome": r.chrome, "WebKit/Cocoa": r.webkit })
          .map(([k, v]) => `<div class="ft-row"><span class="ft-label">${k}</span><span class="ft-val">${v}</span></div>`).join("")}
      </div>`;
    };
    const now = new Date();
    el.querySelector("#ft-now").innerHTML = [
      ["Now (ISO)", now.toISOString()],
      ["Unix", Math.floor(now.getTime() / 1000)],
      ["Unix ms", now.getTime()],
      ["FILETIME", (BigInt(now.getTime() + 11644473600000) * 10000n).toString()],
    ].map(([k, v]) => `<div class="ft-row"><span class="ft-label">${k}</span><span class="ft-val">${v}</span></div>`).join("");
  }

  function renderStrings(el) {
    el.innerHTML = `
      <div class="ft-card">
        <h3>String Extractor</h3>
        <p style="color:#888;font-size:.82rem;margin:0 0 8px">Paste a hex dump to extract ASCII strings (like the <code>strings</code> command).</p>
        <textarea class="ft-input" id="ft-str-input" rows="6" placeholder="Paste hex bytes here..."></textarea>
        <div style="display:flex;gap:8px;align-items:center;margin-top:8px">
          <label style="color:#888;font-size:.8rem">Min length:</label>
          <input class="ft-input" id="ft-str-min" type="number" min="3" max="50" value="4" style="width:60px">
          <button class="ft-btn" id="ft-str-btn">Extract</button>
        </div>
        <div id="ft-str-result"></div>
      </div>`;
    el.querySelector("#ft-str-btn").onclick = () => {
      const hex = el.querySelector("#ft-str-input").value;
      const min = parseInt(el.querySelector("#ft-str-min").value, 10) || 4;
      const strings = extractStrings(hex, min);
      const result = el.querySelector("#ft-str-result");
      if (!strings.length) { result.innerHTML = `<div class="ft-result" style="color:#888">No strings found (min length: ${min})</div>`; return; }
      result.innerHTML = `<div class="ft-result"><strong>${strings.length} strings found:</strong><div class="ft-scroll" style="max-height:300px;margin-top:8px"><table class="ft-table"><tr><th>Offset</th><th>String</th></tr>${strings.map(s => `<tr><td class="ft-mono" style="color:#00d4ff">0x${s.offset.toString(16).padStart(4, "0")}</td><td class="ft-mono">${s.string.replace(/</g, "&lt;")}</td></tr>`).join("")}</table></div></div>`;
    };
  }

  function renderArtifacts(el, artifacts, title) {
    el.innerHTML = `
      <div class="ft-card">
        <h3>${title} (${artifacts.length} locations)</h3>
        <input class="ft-input ft-search" id="ft-art-search" placeholder="Search artifacts...">
        <div class="ft-scroll">
          <table class="ft-table" id="ft-art-table">
            <tr><th>Path / Location</th><th>Description</th><th>${artifacts[0].tool ? "Tool" : ""}</th><th>Forensic Value</th></tr>
            ${artifacts.map(a => `<tr>
              <td class="ft-mono" style="font-size:.72rem;color:#00d4ff;max-width:300px;word-break:break-all">${a.path}</td>
              <td>${a.desc}</td>
              <td>${a.tool ? `<span class="ft-badge" style="background:#1a1a3a;color:#9f7aea">${a.tool}</span>` : ""}</td>
              <td style="color:#aaa;font-size:.78rem">${a.forensicValue}</td>
            </tr>`).join("")}
          </table>
        </div>
      </div>`;
    el.querySelector("#ft-art-search").oninput = function () {
      const q = this.value.toLowerCase();
      el.querySelectorAll("#ft-art-table tr").forEach((r, i) => { if (i === 0) return; r.style.display = r.textContent.toLowerCase().includes(q) ? "" : "none"; });
    };
  }

  function renderVolatility(el) {
    const cats = [...new Set(VOLATILITY_PLUGINS.map(p => p.category))];
    el.innerHTML = `
      <div class="ft-card">
        <h3>Volatility3 Plugin Reference (${VOLATILITY_PLUGINS.length} plugins)</h3>
        <p style="color:#888;font-size:.82rem;margin:0 0 8px">Usage: <code class="ft-mono" style="color:#00d4ff">vol -f memory.dmp &lt;plugin&gt;</code></p>
        <input class="ft-input ft-search" id="ft-vol-search" placeholder="Search plugins...">
        ${cats.map(cat => `
          <h4 style="color:#888;font-size:.85rem;margin:16px 0 6px;border-bottom:1px solid #222;padding-bottom:4px">${cat}</h4>
          <table class="ft-table">
            ${VOLATILITY_PLUGINS.filter(p => p.category === cat).map(p => `
              <tr><td class="ft-mono" style="color:#00d4ff;white-space:nowrap">${p.name}</td><td>${p.desc}</td></tr>
            `).join("")}
          </table>
        `).join("")}
      </div>`;
    el.querySelector("#ft-vol-search").oninput = function () {
      const q = this.value.toLowerCase();
      el.querySelectorAll(".ft-table tr").forEach(r => { r.style.display = r.textContent.toLowerCase().includes(q) ? "" : "none"; });
    };
  }

  function renderExif(el) {
    el.innerHTML = `
      <div class="ft-card">
        <h3>EXIF Tag Reference (${EXIF_TAGS.length} tags)</h3>
        <p style="color:#888;font-size:.82rem;margin:0 0 8px">EXIF metadata in photos can reveal device info, GPS location, timestamps, and more. Use <code class="ft-mono" style="color:#00d4ff">exiftool &lt;image&gt;</code> to extract.</p>
        <input class="ft-input ft-search" id="ft-exif-search" placeholder="Search tags...">
        <div class="ft-scroll">
          <table class="ft-table" id="ft-exif-table">
            <tr><th>Tag ID</th><th>Name</th><th>Description</th><th>Forensic Value</th></tr>
            ${EXIF_TAGS.map(t => `<tr>
              <td class="ft-mono" style="color:#888">${t.id}</td>
              <td style="color:#00d4ff;font-weight:600">${t.name}</td>
              <td>${t.desc}</td>
              <td style="color:#aaa;font-size:.78rem">${t.forensicValue}</td>
            </tr>`).join("")}
          </table>
        </div>
      </div>`;
    el.querySelector("#ft-exif-search").oninput = function () {
      const q = this.value.toLowerCase();
      el.querySelectorAll("#ft-exif-table tr").forEach((r, i) => { if (i === 0) return; r.style.display = r.textContent.toLowerCase().includes(q) ? "" : "none"; });
    };
  }

  render();
}
