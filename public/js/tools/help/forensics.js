// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
// Plain-English help for the forensics.js mini-tools. See help/README.md for the contract.
// Digital Forensics & Incident Response helpers for analysts and defenders.
export const HELP = {
  "fx-filetime": {
    what: "Converts a Windows FILETIME (a count of 100-nanosecond ticks since 1 January 1601) into a normal UTC date and time, or turns a date back into a FILETIME.",
    when: "You found a huge 18-digit number in an NTFS record, registry value or event log and need to know the real date it represents.",
    example: { mode: "Decode", val: "132537600000000000" },
  },
  "fx-chrome-time": {
    what: "Converts a Chrome/WebKit timestamp (microseconds since 1 January 1601) into a UTC date, or back. These appear in Chrome's History and Cookies databases.",
    when: "You are examining a Chrome SQLite database and see a 17-digit time value you need to read.",
    example: { mode: "Decode", val: "13350000000000000" },
  },
  "fx-cocoa-time": {
    what: "Converts an Apple Cocoa / Core Data timestamp (seconds since 1 January 2001) into a UTC date, or back. Used widely in macOS and iOS plists and databases.",
    when: "You see a number near 700 million in a macOS or iOS artifact and need the actual date.",
    example: { mode: "Decode", val: "726000000" },
  },
  "fx-hfs-time": {
    what: "Converts an HFS+/HFS filesystem timestamp (seconds since 1 January 1904) into a UTC date, or back.",
    when: "You are reading timestamps from an HFS+ Mac volume. Note: HFS+ stores UTC but old classic HFS stored local time.",
    example: { mode: "Decode", val: "3787000000" },
  },
  "fx-ole-time": {
    what: "Converts an OLE Automation date (a decimal number of days since 30 December 1899, used by VBA, Office and some registry values) into a UTC date.",
    when: "You find a value like 45292.5 in an Office document or macro and need the date and time it means.",
    example: { mode: "Decode", val: "45292.5" },
  },
  "fx-dos-time": {
    what: "Decodes the packed 16-bit DOS/FAT date word and time word (used in ZIP files and FAT disks) into a readable date. Resolution is 2 seconds and the time is local.",
    when: "You are parsing a ZIP or FAT entry by hand and have the raw date/time words in hex or decimal.",
    example: { date: "0x5821", time: "0x6000" },
  },
  "fx-gps-time": {
    what: "Converts a GPS week number and time-of-week (seconds) into a UTC date. GPS time has no leap seconds, so the current GPS-UTC offset (18 since 2017) is subtracted.",
    when: "You are analysing GPS log or tracker data that records time as a week number plus seconds.",
    example: { week: "2300", tow: "259200", leap: "18" },
  },
  "fx-epoch-multi": {
    what: "Takes one numeric timestamp and shows how it reads as Unix seconds, milliseconds, microseconds and nanoseconds, then guesses the most likely unit.",
    when: "You have a raw timestamp number but do not know whether it is in seconds, milliseconds or something smaller.",
    example: { val: "1700000000" },
  },
  "fx-ad-interval": {
    what: "Interprets an Active Directory time-interval value (counted in 100-nanosecond units, often stored as a negative number) as a human-readable duration like days and hours.",
    when: "You are reading AD attributes such as maxPwdAge or lockoutDuration and see a large negative number.",
    example: { val: "-36288000000000" },
  },
  "fx-generalized-time": {
    what: "Parses an LDAP / ASN.1 GeneralizedTime or UTCTime string (like 20240131235959.0Z) and shows the normalized UTC date.",
    when: "You see a timestamp string in an LDAP export or an X.509 certificate and need it as a readable date.",
    example: { val: "20240131235959.0Z" },
  },
  "fx-timeline": {
    what: "Takes many event lines, each starting with a timestamp (Unix seconds/ms, ISO 8601, or 'YYYY-MM-DD HH:MM:SS') and an optional label, normalizes them to UTC and sorts them in time order.",
    when: "You are building an incident timeline from events whose timestamps come in several different formats.",
    example: { text: "1700000000 user login\n2023-11-14T22:30:00Z file written\n1699999000 service restarted", order: "Ascending" },
  },
  "fx-magic-bytes": {
    what: "Takes the first bytes of a file as hex and tells you what kind of file it is by matching its signature (magic bytes), including container formats like WebP and MP4.",
    when: "You carved a file with no extension, or an extension looks wrong, and you need to confirm the true file type.",
    example: { hex: "89 50 4E 47 0D 0A 1A 0A" },
  },
  "fx-hexdump": {
    what: "Shows bytes as a classic hex dump: an offset column, the bytes in hex, and a side column of printable characters. Works from hex or plain text input.",
    when: "You want to inspect the exact bytes of a small blob the way xxd or hexdump -C would show them.",
    example: { data: "DFIR evidence", src: "Text" },
  },
  "fx-strings": {
    what: "Pulls readable text out of binary data, finding both ASCII and UTF-16LE strings at or above a minimum length. Like the Unix strings command.",
    when: "You have a binary sample (as hex) and want to spot URLs, file paths, commands or messages hidden in it.",
    example: { data: "68656C6C6F00320077006F0072006C006400", src: "Hex", mode: "Both" },
  },
  "fx-entropy-profile": {
    what: "Measures the randomness (Shannon entropy, 0 to 8 bits per byte) of each fixed-size block of a hex blob, so blocks near 8 that look encrypted or compressed stand out.",
    when: "You want to find packed, encrypted or compressed regions inside a binary without unpacking it.",
    example: { hex: "00010203040506070809101112131415", block: "8" },
  },
  "fx-base64-extract": {
    what: "Scans a block of text for base64-looking chunks, decodes each one and shows a printable preview. Helps surface hidden commands or data.",
    when: "You are triaging a script, macro or log that contains embedded base64 and want to see what it decodes to.",
    example: { text: "then it ran SGVsbG8gV29ybGQhIERGSVIgcm9ja3M= and exited", min: "16" },
  },
  "fx-png-chunks": {
    what: "Parses a PNG image from hex: checks its signature, lists every chunk with its type and size, and reads the image dimensions and colour type from the IHDR chunk.",
    when: "You are examining a suspicious or corrupt PNG and want to see its internal structure and any extra chunks.",
    example: { hex: "89504E470D0A1A0A0000000D49484452000000100000001008060000001FF3FF61" },
  },
  "fx-jpeg-markers": {
    what: "Parses a JPEG from hex and lists its markers (start of image, APP segments, tables, frame, scan, end of image), reading the width and height from the frame marker.",
    when: "You want to see the segment layout of a JPEG, for example to confirm it carries EXIF (APP1) data.",
    example: { hex: "FFD8FFE000104A46494600010100000100010000FFD9" },
  },
  "fx-zip-local-header": {
    what: "Parses a ZIP local file header from hex and shows the version, flags, compression method, modification date/time, CRC-32, sizes and file name.",
    when: "You are inspecting a ZIP (or an Office/APK/JAR) file byte by byte and want to decode one entry's header.",
    example: { hex: "504b030414000000080000602158785634120a000000140000000400000074657374" },
  },
  "fx-zip-eocd": {
    what: "Parses a ZIP End of Central Directory record from hex, showing how many entries the archive has, the size and offset of the central directory, and any comment.",
    when: "You are reconstructing or validating a ZIP and need the summary record at the end of the file.",
    example: { hex: "504b0506000000000100010032000000000000000000" },
  },
  "fx-gzip-header": {
    what: "Parses a gzip header from hex, showing the compression method, flags, the embedded modification time (as a date) and the operating system that created it.",
    when: "You have a .gz file (or a gzip stream) and want its metadata, especially the original timestamp.",
    example: { hex: "1F8B0800A1B2C3D4000003" },
  },
  "fx-tar-header": {
    what: "Parses a POSIX tar (ustar) 512-byte header block from hex, decoding the file name, octal mode, owner, size, modification time, type and link target.",
    when: "You are carving or examining a tar archive and want to read one member's header fields.",
    example: { hex: "746573742e747874000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030303036343420003030303030312000303030303031200030303030303030303031362031343031323334353637312020202020202020203000000000000000000000000000" },
  },
  "fx-ps-encodedcommand": {
    what: "Decodes a PowerShell -EncodedCommand (or -enc) value, which is base64 of UTF-16LE text, back to the original PowerShell command.",
    when: "You see powershell.exe -enc <long base64> in an event log or EDR alert and need to read the real command.",
    example: { b64: "SABlAGwAbABvACAAVwBvAHIAbABkAA==" },
  },
  "fx-sid-parse": {
    what: "Parses a Windows SID (security identifier). Give it the S-1-... text to break out its parts, or the raw binary as hex to turn it into the S-1-... string.",
    when: "You are reading a SID from an event, a registry value or a binary structure and need to understand or convert it.",
    example: { val: "S-1-5-21-1004336348-1177238915-682003330-512" },
  },
  "fx-well-known-sid": {
    what: "Looks up well-known Windows SIDs (like S-1-5-18) and domain relative IDs (like 512 = Domain Admins) by number or name.",
    when: "You see a SID or RID in a log and want to know which built-in account or group it refers to.",
    example: { q: "512" },
  },
  "fx-registry-explain": {
    what: "Explains a Windows registry path: it names the full root key (HKLM, HKCU, ...) and maps the registry hives to the files on disk that hold them, with their forensic value.",
    when: "You are deciding which registry hive file to pull from an image, or need to resolve a root-key abbreviation.",
    example: { path: "HKLM\\SYSTEM\\CurrentControlSet\\Services" },
  },
  "fx-persistence-keys": {
    what: "Lists common Windows autostart and persistence locations in the registry and filesystem that malware uses to survive reboots.",
    when: "You are hunting for persistence on a Windows host and want a checklist of the usual autostart spots.",
    example: { q: "run" },
  },
  "fx-reg-types": {
    what: "Looks up a Windows registry value type by its number (for example 4 = REG_DWORD) or name, and explains what each type stores.",
    when: "You are reading an exported registry value and see a type number you need to interpret.",
    example: { q: "dword" },
  },
  "fx-uuid-inspect": {
    what: "Decodes a UUID/GUID: reports its version and variant, and for a version-1 UUID pulls out the embedded creation time, clock sequence and node (MAC address).",
    when: "You found a GUID in an artifact and want to know how it was generated, or extract a time and MAC from a v1 UUID.",
    example: { uuid: "6ba7b810-9dad-11d1-80b4-00c04fd430c8" },
  },
  "fx-windows-event-id": {
    what: "Looks up a Windows Security, System or PowerShell event ID (such as 4624 or 7045) or searches event descriptions. Uses a small, accurate curated list.",
    when: "You see an event ID in a Windows log and need a quick, reliable reminder of what it means.",
    example: { q: "4624" },
  },
  "fx-logon-type": {
    what: "Explains the Windows logon type code from logon events 4624 and 4625, such as 3 for network and 10 for Remote Desktop.",
    when: "You are reading a 4624 logon event and need to know how the logon happened.",
    example: { q: "10" },
  },
  "fx-sysmon-event-id": {
    what: "Looks up a Sysmon event ID (1 to 29) and what it records, for example 1 is process creation and 3 is a network connection.",
    when: "You are reviewing Sysmon logs and need to know what a given event ID captures.",
    example: { q: "3" },
  },
  "fx-ntfs-attributes": {
    what: "Looks up an NTFS MFT attribute type by hex code (like 0x10 for $STANDARD_INFORMATION or 0x30 for $FILE_NAME) or by name.",
    when: "You are parsing an MFT record and need to identify which attribute a type code refers to.",
    example: { q: "0x30" },
  },
  "fx-file-attr-decode": {
    what: "Decodes a Windows file-attribute number into its named flags, such as HIDDEN, SYSTEM and ARCHIVE. Takes hex or decimal.",
    when: "You see a file attribute value like 0x22 in metadata and want to know which flags are set.",
    example: { val: "0x22" },
  },
  "fx-usn-reason": {
    what: "Decodes an NTFS USN change-journal reason value into the named changes it represents, such as FILE_CREATE or DATA_OVERWRITE. Takes hex or decimal.",
    when: "You are reading the USN journal and need to understand why a file record changed.",
    example: { val: "0x102" },
  },
  "fx-access-mask": {
    what: "Decodes a Windows access-mask value (seen in object-access events 4656/4663) into the specific and generic rights it grants. Takes hex or decimal.",
    when: "You are investigating a file or object access event and need to know what access was requested or granted.",
    example: { val: "0x120089" },
  },
  "fx-service-type": {
    what: "Decodes a Windows service type number into its flags and lists the service start-type codes (0 Boot through 4 Disabled).",
    when: "You are examining a newly installed service (event 7045) or the Services registry and need to read its type and start setting.",
    example: { type: "0x10" },
  },
  "fx-kerberos-etype": {
    what: "Looks up a Kerberos encryption type (etype) number, for example 23 is RC4-HMAC and 18 is AES-256.",
    when: "You are triaging Kerberos events (4768/4769) or checking for weak ticket encryption and see an etype number.",
    example: { q: "23" },
  },
  "fx-email-received": {
    what: "Reads the Received: headers of an email and lists the relay hops in delivery order (earliest first), with each hop's source and destination hosts and the delay between hops.",
    when: "You are tracing where an email really came from and how long it spent at each mail server.",
    example: { headers: "Received: from relay.example.net (relay.example.net [198.51.100.7]) by mx.example.com; Mon, 1 Jan 2024 10:00:05 +0000\nReceived: from sender.example.org (sender.example.org [203.0.113.9]) by relay.example.net; Mon, 1 Jan 2024 10:00:01 +0000" },
  },
  "fx-email-auth-results": {
    what: "Reads an Authentication-Results header and shows the SPF, DKIM and DMARC pass/fail results and the domains they checked.",
    when: "You are checking whether an email passed sender authentication to judge if it may be spoofed.",
    example: { header: "Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=example.org; dkim=pass header.d=example.org; dmarc=pass" },
  },
  "fx-email-headers": {
    what: "Pulls the key fields out of raw email headers (From, To, Subject, Date, Message-ID, Return-Path, Reply-To and more) and flags common mismatches that suggest spoofing.",
    when: "You are reviewing a suspicious email and want a quick summary of its important headers.",
    example: { headers: "From: Alice <alice@example.com>\nReturn-Path: <bounce@mailer.example>\nReply-To: billing@example.com\nSubject: Invoice\nDate: Mon, 1 Jan 2024 10:00:00 +0000\nMessage-ID: <abc123@example.com>" },
  },
  "fx-dkim-parse": {
    what: "Breaks a DKIM-Signature header into its tags and explains each one, including the signing domain, the selector and the signed header fields.",
    when: "You are analysing an email's DKIM signature and want to see which domain and selector signed it.",
    example: { header: "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel1; c=relaxed/relaxed; h=from:to:subject:date; bh=47DEQpj8HBSaTImW; b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSb" },
  },
  "fx-smtp-status": {
    what: "Looks up an SMTP reply code (like 550 or 421) and explains what it means.",
    when: "You are reading mail-server logs or a bounce (non-delivery) message and need to understand a status code.",
    example: { q: "550" },
  },
  "fx-auth-log": {
    what: "Reads Linux auth.log / secure lines from the SSH service and summarizes failed and successful logins: counts per source IP and per user, plus invalid-user attempts.",
    when: "You are checking a Linux host for SSH brute-force activity and want a quick breakdown of the log.",
    example: { text: "Jan  1 10:00:01 host sshd[111]: Failed password for root from 198.51.100.7 port 54321 ssh2\nJan  1 10:00:02 host sshd[112]: Failed password for invalid user admin from 198.51.100.7 port 54322 ssh2\nJan  1 10:05:00 host sshd[120]: Accepted publickey for deploy from 203.0.113.9 port 51000 ssh2" },
  },
  "fx-syslog-parse": {
    what: "Parses one syslog line in either the old BSD format (RFC 3164) or the newer IETF format (RFC 5424) into fields like priority, time, host, program and message.",
    when: "You have a single syslog line and want its parts separated out.",
    example: { line: "<34>1 2024-01-01T10:00:00Z host app 1234 ID47 - disk nearly full" },
  },
  "fx-syslog-pri": {
    what: "Decodes a syslog priority number (0 to 191, like <34>) into its facility and severity, or builds the number from a facility and severity you choose.",
    when: "You see a syslog PRI value and need to know which facility and severity it encodes.",
    example: { mode: "Decode PRI", pri: "34" },
  },
  "fx-journald-json": {
    what: "Parses a journald log entry in JSON form (from journalctl -o json) and decodes the key fields, including the microsecond timestamp, priority, command, PID and message.",
    when: "You exported systemd journal logs as JSON and want one entry's fields in a readable form.",
    example: { json: '{"__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"6","_HOSTNAME":"host","_COMM":"sshd","_PID":"1234","MESSAGE":"Accepted publickey for deploy"}' },
  },
  "fx-apache-log": {
    what: "Parses one Apache or Nginx access log line in Common or Combined format into fields: client IP, time, request method and path, status, size, referer and user agent.",
    when: "You have a single web access log line and want it split into readable fields.",
    example: { line: '198.51.100.7 - - [01/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "curl/8.0"' },
  },
  "fx-access-analyze": {
    what: "Analyses a whole block of web access log lines and reports the top client IPs, the spread of status codes, the most requested paths, and a list of requests that look like attacks.",
    when: "You have a chunk of web server logs and want a fast overview plus a flag on suspicious requests.",
    example: { text: '198.51.100.7 - - [01/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "curl/8.0"\n203.0.113.9 - - [01/Jan/2024:10:00:05 +0000] "GET /../../etc/passwd HTTP/1.1" 404 200 "-" "x"\n198.51.100.7 - - [01/Jan/2024:10:00:06 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "curl/8.0"' },
  },
  "fx-apache-error": {
    what: "Parses an Apache 2.4 error.log line into its fields: time, the module and level, the process/thread id, the client, and the message.",
    when: "You are reading Apache error logs and want one line separated into readable parts.",
    example: { line: "[Mon Jan 01 10:00:00.123456 2024] [core:error] [pid 1234:tid 5678] [client 198.51.100.7:54321] File does not exist: /var/www/missing" },
  },
  "fx-cef-parse": {
    what: "Parses an ArcSight CEF log line into its header fields (vendor, product, signature, name, severity) and the key=value extension pairs.",
    when: "You receive logs in CEF format and want to read one event's fields clearly.",
    example: { line: "CEF:0|Security|Firewall|1.0|100|Blocked connection|5|src=198.51.100.7 dst=192.0.2.9 spt=1234 dpt=443" },
  },
  "fx-leef-parse": {
    what: "Parses an IBM QRadar LEEF log line into its header (vendor, product, event id) and its key=value attributes, handling both LEEF 1.0 and 2.0 with custom delimiters.",
    when: "You receive logs in LEEF format and want to read one event's attributes.",
    example: { line: "LEEF:2.0|Vendor|Product|1.0|EventID|^|src=198.51.100.7^dst=192.0.2.9^sev=5" },
  },
  "fx-cloudtrail": {
    what: "Reads one AWS CloudTrail event record (JSON) and shows the fields that matter in an investigation: time, event name and source, region, source IP, who did it and any error.",
    when: "You are reviewing AWS activity and want the important parts of a CloudTrail record without wading through the JSON.",
    example: { json: '{"eventTime":"2024-01-01T10:00:00Z","eventName":"ConsoleLogin","eventSource":"signin.amazonaws.com","awsRegion":"us-east-1","sourceIPAddress":"198.51.100.7","userIdentity":{"type":"IAMUser","userName":"alice","accountId":"123456789012"}}' },
  },
  "fx-ioc-extract": {
    what: "Pulls indicators of compromise out of text: IP addresses, domains, URLs, email addresses, MD5/SHA-1/SHA-256 hashes and CVE IDs. It can first un-defang input like hxxp and [.].",
    when: "You have a report, email or log and want to quickly collect all the technical indicators from it.",
    example: { text: "beacon to hxxp://bad[.]example/c2 from 198.51.100.7, dropper md5 44d88612fea8a8f36de82e1278abb02f, see CVE-2021-44228", refang: true },
  },
  "fx-defang": {
    what: "Makes indicators safe to paste by neutralizing them: http becomes hxxp, dots become [.], and @ becomes [at], so links and addresses will not auto-activate.",
    when: "You are writing a report or ticket and need to include a malicious URL or address without it becoming clickable.",
    example: { text: "http://bad.example/path and attacker@bad.example" },
  },
  "fx-refang": {
    what: "Reverses common defanging so indicators work again: hxxp becomes http, [.] becomes a dot and [at] becomes @.",
    when: "You received defanged indicators and need them in normal form to look up or analyse. Only refang values you intend to handle safely.",
    example: { text: "hxxp://bad[.]example/path and attacker[at]bad[.]example" },
  },
  "fx-url-decode-recursive": {
    what: "Percent-decodes a URL or parameter over and over until it stops changing, revealing double or triple encoding, and shows each decoding pass.",
    when: "You suspect an attacker encoded a payload more than once to slip past a filter and want the final decoded value.",
    example: { text: "%252e%252e%252fetc%252fpasswd", max: "6" },
  },
  "fx-hash-manifest": {
    what: "Turns a list of 'hash  filename' or 'filename=hash' lines into a tidy evidence manifest, working out each hash's algorithm from its length and counting the items.",
    when: "You collected file hashes during an acquisition and want a clean, labelled manifest for your case notes.",
    example: { text: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  evidence1.bin\n44d88612fea8a8f36de82e1278abb02f  sample.exe", case: "CASE-2024-001" },
  },
  "fx-chain-of-custody": {
    what: "Builds a formatted chain-of-custody form from the case and evidence details you enter, with a transfer log ready to fill in. It is a documentation aid, not legal advice.",
    when: "You are seizing or handing over evidence and need a consistent custody record to start from.",
    example: { caseNo: "CASE-2024-001", item: "ITEM-01", desc: "Dell laptop, service tag ABC123", collectedBy: "J. Analyst", when: "2024-01-01T10:00:00Z", where: "Suite 400, example.com HQ", method: "Write-blocked dd image to external SSD", hash: "sha256: e3b0c442..." },
  },
  "fx-exif-tags": {
    what: "Looks up an EXIF metadata tag by its hex id (like 0x9003 for the original date taken) or by name.",
    when: "You are reading raw EXIF data from a photo and need to know what a tag id means.",
    example: { q: "0x9003" },
  },
  "fx-exif-orientation": {
    what: "Explains the EXIF Orientation value (1 to 8), which tells viewers how a photo should be rotated or flipped to look right.",
    when: "You see an orientation number in a photo's EXIF data and want to know how the camera was held.",
    example: { q: "6" },
  },
  "fx-gps-coord": {
    what: "Converts GPS coordinates between degrees/minutes/seconds with an N/S/E/W letter (as EXIF stores them) and plain signed decimal degrees.",
    when: "You pulled a GPS location from a photo's EXIF data and want it as a decimal you can drop onto a map, or the reverse.",
    example: { mode: "DMS to Decimal", deg: "37", min: "48", sec: "30", ref: "N" },
  },
  "fx-attack-tactics": {
    what: "Looks up the 14 MITRE ATT&CK enterprise tactics by their ID (like TA0001) or name, with a short note on each attacker goal.",
    when: "You are mapping observed activity to ATT&CK tactics and want the IDs and names handy.",
    example: { q: "persistence" },
  },
  "fx-stat-mode": {
    what: "Decodes a Unix file mode value (like 100755 from stat metadata) into the file type, an ls-style permission string, and any setuid, setgid or sticky bits.",
    when: "You see a numeric mode in filesystem metadata and want to read it the way ls -l would show it.",
    example: { val: "100755" },
  },
  "fx-volatility": {
    what: "Builds a Volatility memory-forensics command for version 3 or version 2, picking a common plugin (process list, network connections, malfind and so on) with the right syntax.",
    when: "You are about to analyse a RAM capture with Volatility and want the exact command for a plugin.",
    example: { ver: "Volatility 3", image: "/cases/mem.raw", plugin: "Process list" },
  },
  "fx-plaso": {
    what: "Builds a Plaso super-timeline command: collect events into a .plaso file with log2timeline, output them with psort, or do both in one pass with psteal.",
    when: "You are creating a forensic timeline from a disk image and want the correct Plaso command for your step.",
    example: { step: "Collect (log2timeline)", source: "/cases/disk.e01", store: "/cases/timeline.plaso", tz: "UTC" },
  },
  "fx-dd-builder": {
    what: "Builds a dd or dcfldd command to make a raw forensic image of a device, with block size and optional hashing. A reminder: always image through a write-blocker.",
    when: "You are acquiring a disk or drive and want a correct imaging command with hashing set up.",
    example: { tool: "dcfldd", src: "/dev/sdb", dst: "/cases/disk.img", bs: "4M", hash: "sha256" },
  },
  "fx-tsk-builder": {
    what: "Builds a common Sleuth Kit command (mmls, fsstat, fls, icat or istat) for examining a disk image, filling in the image, offset and inode.",
    when: "You are working a disk image with The Sleuth Kit and want the right command to list or extract files.",
    example: { tool: "fls (list files)", image: "/cases/disk.img", offset: "2048" },
  },
  "fx-yara-rule": {
    what: "Generates a valid YARA detection rule from the text and hex strings you provide, with a meta block and a match condition you choose.",
    when: "You identified strings that mark a malware sample and want a starting YARA rule to detect it.",
    example: { name: "Suspicious_Dropper", author: "analyst", textStrings: "cmd.exe /c\nInvoke-Expression", hexStrings: "4D 5A 90 00", cond: "any of them", nocase: true },
  },
};
