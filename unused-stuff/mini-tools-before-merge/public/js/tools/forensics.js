// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
// Digital Forensics & Incident Response (DFIR) mini-tools: timestamp decoders,
// file-signature and container parsers, Windows artifact references, log and email
// header parsers, IOC extraction, evidence helpers and DFIR command builders.
// Analyst/defender side. Pure, deterministic, client-side. See _schema.md.

const S = (v) => (v == null ? "" : String(v));

// ---- byte / int helpers (for hex-driven parsers) ----
function hexBytes(s) {
  const h = String(s || "").replace(/0x/gi, "").replace(/[^0-9a-fA-F]/g, "");
  const u = new Uint8Array(h.length >> 1);
  for (let i = 0; i < u.length; i++) u[i] = parseInt(h.substr(i * 2, 2), 16);
  return u;
}
function readLE(u, off, len) { let n = 0; for (let i = len - 1; i >= 0; i--) n = n * 256 + u[off + i]; return n; }
function readBE(u, off, len) { let n = 0; for (let i = 0; i < len; i++) n = n * 256 + u[off + i]; return n; }
function asciiOf(u, off, len) { let s = ""; for (let i = 0; i < len && off + i < u.length; i++) { const b = u[off + i]; s += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : "."; } return s; }

// ---- big-int parse (decimal or hex) for large timestamps ----
function parseBig(s) {
  let t = String(s || "").trim().replace(/[\s,_]/g, "");
  if (!t) return null;
  try {
    let neg = false;
    if (t[0] === "-") { neg = true; t = t.slice(1); }
    let b;
    if (/^0x[0-9a-f]+$/i.test(t)) b = BigInt(t);
    else if (/^[0-9a-f]+$/i.test(t) && /[a-f]/i.test(t) && !/^\d+$/.test(t)) b = BigInt("0x" + t);
    else if (/^\d+$/.test(t)) b = BigInt(t);
    else return null;
    return neg ? -b : b;
  } catch (e) { return null; }
}

// ---- epoch constants (ms) ----
const MS_1601_TO_1970 = 11644473600000;       // 1601-01-01 -> 1970-01-01
const SEC_1904_TO_1970 = 2082844800;           // 1904-01-01 -> 1970-01-01
const SEC_1970_TO_2001 = 978307200;            // 1970-01-01 -> 2001-01-01
const OLE_EPOCH_MS = Date.UTC(1899, 11, 30);   // 1899-12-30
const GPS_EPOCH_MS = Date.UTC(1980, 0, 6);     // 1980-01-06

function showTime(unixMs, extra) {
  if (!isFinite(unixMs)) return { error: "Value is out of range." };
  const d = new Date(unixMs);
  if (isNaN(d.getTime())) return { error: "Resulting date is out of range." };
  const secs = unixMs / 1000;
  return [
    `UTC (ISO 8601):  ${d.toISOString()}`,
    `UTC (readable):  ${d.toUTCString()}`,
    `Unix seconds:    ${Math.floor(secs)}`,
    `Unix millis:     ${Math.round(unixMs)}`,
    extra ? extra : "",
  ].filter(Boolean).join("\n");
}
function parseDate(s) {
  let t = String(s || "").trim();
  if (!t) return null;
  if (/^\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2})?(\.\d+)?)?$/.test(t)) {
    t = t.replace(" ", "T");
    if (!/[Zz]|[+-]\d{2}:?\d{2}$/.test(t)) t += "Z";
  }
  const ms = Date.parse(t);
  return isNaN(ms) ? null : ms;
}

// ---- generic reference-table renderer ----
function lookup(rows, q, cols) {
  const ql = String(q || "").trim().toLowerCase();
  const filtered = ql ? rows.filter((r) => r.some((c) => String(c).toLowerCase().includes(ql))) : rows;
  if (!filtered.length) return `No entry matches "${q}".`;
  const widths = cols.map((h, i) => Math.max(h.length, ...filtered.map((r) => String(r[i]).length)));
  const line = (r) => r.map((c, i) => String(c).padEnd(widths[i])).join("  ").replace(/\s+$/, "");
  return [line(cols), cols.map((_, i) => "-".repeat(widths[i])).join("  "), ...filtered.map(line)].join("\n");
}
// decode a bitmask against [value, name, note?] table
function decodeFlags(mask, table) {
  const m = typeof mask === "bigint" ? mask : BigInt(mask);
  const hit = [], unknown = [];
  let covered = 0n;
  for (const [val, name] of table) { const b = BigInt(val); if ((m & b) === b && b !== 0n) { hit.push(`0x${b.toString(16)}  ${name}`); covered |= b; } }
  const rem = m & ~covered;
  if (rem) unknown.push(`unknown bits: 0x${rem.toString(16)}`);
  if (m === 0n) return "0x0  (no flags set)";
  return hit.concat(unknown).join("\n") || "(no known flags matched)";
}

// =====================================================================
// REFERENCE TABLES
// =====================================================================
const WIN_EVENTS = [
  ["1102", "Security", "The audit log was cleared"],
  ["4624", "Security", "An account was successfully logged on"],
  ["4625", "Security", "An account failed to log on"],
  ["4634", "Security", "An account was logged off"],
  ["4647", "Security", "User initiated logoff"],
  ["4648", "Security", "A logon was attempted using explicit credentials"],
  ["4656", "Security", "A handle to an object was requested"],
  ["4663", "Security", "An attempt was made to access an object"],
  ["4670", "Security", "Permissions on an object were changed"],
  ["4672", "Security", "Special privileges assigned to new logon"],
  ["4688", "Security", "A new process has been created"],
  ["4689", "Security", "A process has exited"],
  ["4697", "Security", "A service was installed in the system"],
  ["4698", "Security", "A scheduled task was created"],
  ["4699", "Security", "A scheduled task was deleted"],
  ["4700", "Security", "A scheduled task was enabled"],
  ["4701", "Security", "A scheduled task was disabled"],
  ["4702", "Security", "A scheduled task was updated"],
  ["4719", "Security", "System audit policy was changed"],
  ["4720", "Security", "A user account was created"],
  ["4722", "Security", "A user account was enabled"],
  ["4723", "Security", "An attempt was made to change an account's password"],
  ["4724", "Security", "An attempt was made to reset an account's password"],
  ["4725", "Security", "A user account was disabled"],
  ["4726", "Security", "A user account was deleted"],
  ["4728", "Security", "A member was added to a security-enabled global group"],
  ["4732", "Security", "A member was added to a security-enabled local group"],
  ["4738", "Security", "A user account was changed"],
  ["4740", "Security", "A user account was locked out"],
  ["4756", "Security", "A member was added to a security-enabled universal group"],
  ["4767", "Security", "A user account was unlocked"],
  ["4768", "Security", "A Kerberos authentication ticket (TGT) was requested"],
  ["4769", "Security", "A Kerberos service ticket was requested"],
  ["4771", "Security", "Kerberos pre-authentication failed"],
  ["4776", "Security", "The DC attempted to validate credentials (NTLM)"],
  ["4778", "Security", "A session was reconnected to a window station (RDP)"],
  ["4779", "Security", "A session was disconnected from a window station (RDP)"],
  ["4798", "Security", "A user's local group membership was enumerated"],
  ["4799", "Security", "A security-enabled local group membership was enumerated"],
  ["5140", "Security", "A network share object was accessed"],
  ["5145", "Security", "A network share object was checked for access (detailed)"],
  ["5156", "Security", "The Windows Filtering Platform permitted a connection"],
  ["104", "System", "The event log file was cleared"],
  ["1074", "System", "System shutdown/restart was initiated"],
  ["6005", "System", "The Event Log service was started (boot)"],
  ["6006", "System", "The Event Log service was stopped (clean shutdown)"],
  ["6008", "System", "The previous system shutdown was unexpected"],
  ["7034", "System", "A service terminated unexpectedly"],
  ["7036", "System", "A service entered the running or stopped state"],
  ["7045", "System", "A new service was installed (Service Control Manager)"],
  ["400", "PowerShell", "Engine state changed to Available (PowerShell started)"],
  ["4103", "PowerShell-Op", "Module logging: pipeline execution details"],
  ["4104", "PowerShell-Op", "Script block logging: a block of code was executed"],
];
const LOGON_TYPES = [
  ["0", "System", "Used only by the System account"],
  ["2", "Interactive", "Logon at the console (keyboard)"],
  ["3", "Network", "Access from the network (SMB shares, IIS)"],
  ["4", "Batch", "Scheduled task / batch server"],
  ["5", "Service", "A service started by the SCM"],
  ["7", "Unlock", "Workstation unlock"],
  ["8", "NetworkCleartext", "Network logon with cleartext credentials (IIS basic auth)"],
  ["9", "NewCredentials", "RunAs with /netonly (different network credentials)"],
  ["10", "RemoteInteractive", "Terminal Services / Remote Desktop (RDP)"],
  ["11", "CachedInteractive", "Interactive logon using locally cached credentials"],
];
const SYSMON_EVENTS = [
  ["1", "Process creation"],
  ["2", "A process changed a file creation time (timestomp)"],
  ["3", "Network connection"],
  ["4", "Sysmon service state changed"],
  ["5", "Process terminated"],
  ["6", "Driver loaded"],
  ["7", "Image loaded (DLL)"],
  ["8", "CreateRemoteThread"],
  ["9", "RawAccessRead (raw disk read)"],
  ["10", "ProcessAccess (one process opened another)"],
  ["11", "FileCreate"],
  ["12", "RegistryEvent (key create and delete)"],
  ["13", "RegistryEvent (value set)"],
  ["14", "RegistryEvent (key and value rename)"],
  ["15", "FileCreateStreamHash (alternate data stream)"],
  ["16", "Sysmon configuration change"],
  ["17", "PipeEvent (named pipe created)"],
  ["18", "PipeEvent (named pipe connected)"],
  ["19", "WmiEvent (WMI event filter)"],
  ["20", "WmiEvent (WMI event consumer)"],
  ["21", "WmiEvent (WMI consumer-to-filter binding)"],
  ["22", "DNSEvent (DNS query)"],
  ["23", "FileDelete (file deleted and archived)"],
  ["24", "ClipboardChange"],
  ["25", "ProcessTampering (image replaced / hollowing)"],
  ["26", "FileDeleteDetected (logged, not archived)"],
  ["27", "FileBlockExecutable"],
  ["28", "FileBlockShredding"],
  ["29", "FileExecutableDetected"],
  ["255", "Sysmon error"],
];
const NTFS_ATTRS = [
  ["0x10", "$STANDARD_INFORMATION", "MACB timestamps, flags, owner"],
  ["0x20", "$ATTRIBUTE_LIST", "List of attributes when record overflows"],
  ["0x30", "$FILE_NAME", "Name + parent reference + a 2nd MACB set"],
  ["0x40", "$OBJECT_ID", "16-byte object/GUID id"],
  ["0x50", "$SECURITY_DESCRIPTOR", "ACL / ownership (legacy; now in $Secure)"],
  ["0x60", "$VOLUME_NAME", "Volume label"],
  ["0x70", "$VOLUME_INFORMATION", "NTFS version and dirty flag"],
  ["0x80", "$DATA", "File contents (default or named/ADS stream)"],
  ["0x90", "$INDEX_ROOT", "Root of a B-tree index (directory)"],
  ["0xA0", "$INDEX_ALLOCATION", "Index buffers for large directories"],
  ["0xB0", "$BITMAP", "Allocation bitmap for index/$MFT"],
  ["0xC0", "$REPARSE_POINT", "Junctions, symlinks, mount points"],
  ["0xD0", "$EA_INFORMATION", "Extended attribute info"],
  ["0xE0", "$EA", "Extended attributes"],
  ["0x100", "$LOGGED_UTILITY_STREAM", "EFS $EFS, TxF data"],
];
const FILE_ATTRS = [
  ["0x1", "READONLY"], ["0x2", "HIDDEN"], ["0x4", "SYSTEM"], ["0x10", "DIRECTORY"],
  ["0x20", "ARCHIVE"], ["0x40", "DEVICE"], ["0x80", "NORMAL"], ["0x100", "TEMPORARY"],
  ["0x200", "SPARSE_FILE"], ["0x400", "REPARSE_POINT"], ["0x800", "COMPRESSED"],
  ["0x1000", "OFFLINE"], ["0x2000", "NOT_CONTENT_INDEXED"], ["0x4000", "ENCRYPTED"],
  ["0x8000", "INTEGRITY_STREAM"], ["0x10000", "VIRTUAL"], ["0x20000", "NO_SCRUB_DATA"],
  ["0x40000", "EA"], ["0x80000", "PINNED"], ["0x100000", "UNPINNED"],
  ["0x400000", "RECALL_ON_DATA_ACCESS"],
];
const USN_REASONS = [
  ["0x1", "DATA_OVERWRITE"], ["0x2", "DATA_EXTEND"], ["0x4", "DATA_TRUNCATION"],
  ["0x10", "NAMED_DATA_OVERWRITE"], ["0x20", "NAMED_DATA_EXTEND"], ["0x40", "NAMED_DATA_TRUNCATION"],
  ["0x100", "FILE_CREATE"], ["0x200", "FILE_DELETE"], ["0x400", "EA_CHANGE"],
  ["0x800", "SECURITY_CHANGE"], ["0x1000", "RENAME_OLD_NAME"], ["0x2000", "RENAME_NEW_NAME"],
  ["0x4000", "INDEXABLE_CHANGE"], ["0x8000", "BASIC_INFO_CHANGE"], ["0x10000", "HARD_LINK_CHANGE"],
  ["0x20000", "COMPRESSION_CHANGE"], ["0x40000", "ENCRYPTION_CHANGE"], ["0x80000", "OBJECT_ID_CHANGE"],
  ["0x100000", "REPARSE_POINT_CHANGE"], ["0x200000", "STREAM_CHANGE"], ["0x400000", "TRANSACTED_CHANGE"],
  ["0x800000", "INTEGRITY_CHANGE"], ["0x80000000", "CLOSE"],
];
const ACCESS_MASK = [
  ["0x1", "FILE_READ_DATA / FILE_LIST_DIRECTORY"],
  ["0x2", "FILE_WRITE_DATA / FILE_ADD_FILE"],
  ["0x4", "FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY"],
  ["0x8", "FILE_READ_EA"],
  ["0x10", "FILE_WRITE_EA"],
  ["0x20", "FILE_EXECUTE / FILE_TRAVERSE"],
  ["0x40", "FILE_DELETE_CHILD"],
  ["0x80", "FILE_READ_ATTRIBUTES"],
  ["0x100", "FILE_WRITE_ATTRIBUTES"],
  ["0x10000", "DELETE"],
  ["0x20000", "READ_CONTROL"],
  ["0x40000", "WRITE_DAC"],
  ["0x80000", "WRITE_OWNER"],
  ["0x100000", "SYNCHRONIZE"],
  ["0x1000000", "ACCESS_SYSTEM_SECURITY"],
  ["0x10000000", "GENERIC_ALL"],
  ["0x20000000", "GENERIC_EXECUTE"],
  ["0x40000000", "GENERIC_WRITE"],
  ["0x80000000", "GENERIC_READ"],
];
const WELL_KNOWN_SIDS = [
  ["S-1-0-0", "Nobody", "A null/empty group"],
  ["S-1-1-0", "Everyone", "All users including anonymous (varies)"],
  ["S-1-2-0", "Local", "Users who log on locally"],
  ["S-1-3-0", "Creator Owner", "Placeholder for the object's creator"],
  ["S-1-3-1", "Creator Group", "Placeholder for the creator's primary group"],
  ["S-1-5-7", "Anonymous Logon", "Connections without credentials"],
  ["S-1-5-9", "Enterprise Domain Controllers", ""],
  ["S-1-5-11", "Authenticated Users", "Any authenticated identity"],
  ["S-1-5-18", "Local System", "The SYSTEM service account"],
  ["S-1-5-19", "Local Service", ""],
  ["S-1-5-20", "Network Service", ""],
  ["S-1-5-32-544", "Administrators", "Built-in local Administrators"],
  ["S-1-5-32-545", "Users", "Built-in local Users"],
  ["S-1-5-32-546", "Guests", "Built-in local Guests"],
  ["S-1-5-32-547", "Power Users", ""],
  ["S-1-5-32-551", "Backup Operators", ""],
  ["S-1-5-32-555", "Remote Desktop Users", ""],
  ["S-1-5-32-562", "Distributed COM Users", ""],
];
const SID_RIDS = [
  ["500", "Administrator", "Built-in domain/local administrator"],
  ["501", "Guest", "Built-in guest account"],
  ["502", "krbtgt", "Kerberos ticket-granting service account"],
  ["512", "Domain Admins", ""],
  ["513", "Domain Users", ""],
  ["514", "Domain Guests", ""],
  ["515", "Domain Computers", ""],
  ["516", "Domain Controllers", ""],
  ["518", "Schema Admins", ""],
  ["519", "Enterprise Admins", ""],
  ["520", "Group Policy Creator Owners", ""],
  ["526", "Key Admins", ""],
  ["527", "Enterprise Key Admins", ""],
];
const REG_TYPES = [
  ["0", "REG_NONE", "No defined type"],
  ["1", "REG_SZ", "Unicode string"],
  ["2", "REG_EXPAND_SZ", "String with %env% variables"],
  ["3", "REG_BINARY", "Raw binary data"],
  ["4", "REG_DWORD", "32-bit little-endian integer"],
  ["5", "REG_DWORD_BIG_ENDIAN", "32-bit big-endian integer"],
  ["6", "REG_LINK", "Symbolic link (Unicode)"],
  ["7", "REG_MULTI_SZ", "Array of null-terminated strings"],
  ["8", "REG_RESOURCE_LIST", "Device-driver resource list"],
  ["9", "REG_FULL_RESOURCE_DESCRIPTOR", ""],
  ["10", "REG_RESOURCE_REQUIREMENTS_LIST", ""],
  ["11", "REG_QWORD", "64-bit little-endian integer"],
];
const SERVICE_TYPE = [
  ["0x1", "KERNEL_DRIVER"], ["0x2", "FILE_SYSTEM_DRIVER"], ["0x4", "ADAPTER"],
  ["0x8", "RECOGNIZER_DRIVER"], ["0x10", "WIN32_OWN_PROCESS"], ["0x20", "WIN32_SHARE_PROCESS"],
  ["0x100", "INTERACTIVE_PROCESS"],
];
const SERVICE_START = [
  ["0", "BOOT_START", "Loaded by the boot loader"],
  ["1", "SYSTEM_START", "Loaded during kernel initialization"],
  ["2", "AUTO_START", "Started automatically at boot"],
  ["3", "DEMAND_START", "Started manually (on demand)"],
  ["4", "DISABLED", "Cannot be started"],
];
const KERBEROS_ETYPE = [
  ["1", "des-cbc-crc", "DES, weak/deprecated"],
  ["2", "des-cbc-md4", "DES, weak/deprecated"],
  ["3", "des-cbc-md5", "DES, weak/deprecated"],
  ["16", "des3-cbc-sha1-kd", "Triple DES"],
  ["17", "aes128-cts-hmac-sha1-96", "AES-128"],
  ["18", "aes256-cts-hmac-sha1-96", "AES-256 (preferred)"],
  ["23", "rc4-hmac", "RC4 (NTLM hash as key; Kerberoasting target)"],
  ["24", "rc4-hmac-exp", "RC4 export"],
  ["25", "camellia128-cts-cmac", "Camellia-128"],
  ["26", "camellia256-cts-cmac", "Camellia-256"],
];
const ATTACK_TACTICS = [
  ["TA0043", "Reconnaissance", "Gathering information to plan operations"],
  ["TA0042", "Resource Development", "Establishing resources to support operations"],
  ["TA0001", "Initial Access", "Getting into the network"],
  ["TA0002", "Execution", "Running malicious code"],
  ["TA0003", "Persistence", "Maintaining a foothold"],
  ["TA0004", "Privilege Escalation", "Gaining higher-level permissions"],
  ["TA0005", "Defense Evasion", "Avoiding detection"],
  ["TA0006", "Credential Access", "Stealing account names and passwords"],
  ["TA0007", "Discovery", "Learning about the environment"],
  ["TA0008", "Lateral Movement", "Moving through the environment"],
  ["TA0009", "Collection", "Gathering data of interest"],
  ["TA0011", "Command and Control", "Communicating with compromised systems"],
  ["TA0010", "Exfiltration", "Stealing data"],
  ["TA0040", "Impact", "Manipulate, interrupt or destroy systems and data"],
];
const EXIF_TAGS = [
  ["0x0100", "ImageWidth"], ["0x0101", "ImageLength (height)"], ["0x0102", "BitsPerSample"],
  ["0x0106", "PhotometricInterpretation"], ["0x010E", "ImageDescription"], ["0x010F", "Make"],
  ["0x0110", "Model"], ["0x0112", "Orientation"], ["0x011A", "XResolution"], ["0x011B", "YResolution"],
  ["0x0128", "ResolutionUnit"], ["0x0131", "Software"], ["0x0132", "DateTime (modified)"],
  ["0x013B", "Artist"], ["0x8298", "Copyright"], ["0x8769", "ExifIFDPointer"],
  ["0x8825", "GPSInfoIFDPointer"], ["0x829A", "ExposureTime"], ["0x829D", "FNumber"],
  ["0x8822", "ExposureProgram"], ["0x8827", "ISOSpeedRatings"], ["0x9000", "ExifVersion"],
  ["0x9003", "DateTimeOriginal"], ["0x9004", "DateTimeDigitized"], ["0x9201", "ShutterSpeedValue"],
  ["0x9202", "ApertureValue"], ["0x9204", "ExposureBiasValue"], ["0x9207", "MeteringMode"],
  ["0x9209", "Flash"], ["0x920A", "FocalLength"], ["0x927C", "MakerNote"], ["0x9286", "UserComment"],
  ["0xA002", "PixelXDimension"], ["0xA003", "PixelYDimension"], ["0xA005", "InteroperabilityIFDPointer"],
  ["0xA402", "ExposureMode"], ["0xA403", "WhiteBalance"], ["0xA406", "SceneCaptureType"],
  ["0xA430", "CameraOwnerName"], ["0xA431", "BodySerialNumber"], ["0xA433", "LensMake"],
  ["0xA434", "LensModel"], ["0xA435", "LensSerialNumber"],
];
const EXIF_GPS_TAGS = [
  ["0x0000", "GPSVersionID"], ["0x0001", "GPSLatitudeRef (N/S)"], ["0x0002", "GPSLatitude"],
  ["0x0003", "GPSLongitudeRef (E/W)"], ["0x0004", "GPSLongitude"], ["0x0005", "GPSAltitudeRef"],
  ["0x0006", "GPSAltitude"], ["0x0007", "GPSTimeStamp (UTC)"], ["0x0008", "GPSSatellites"],
  ["0x000B", "GPSDOP"], ["0x0010", "GPSImgDirectionRef"], ["0x0011", "GPSImgDirection"],
  ["0x001D", "GPSDateStamp (UTC)"],
];
const SMTP_CODES = [
  ["211", "System status / help reply"], ["214", "Help message"], ["220", "Service ready"],
  ["221", "Service closing transmission channel"], ["235", "Authentication successful"],
  ["250", "Requested action completed (OK)"], ["251", "User not local; will forward"],
  ["252", "Cannot verify user; will attempt delivery"], ["334", "Server AUTH challenge (base64)"],
  ["354", "Start mail input; end with <CRLF>.<CRLF>"], ["421", "Service not available, closing"],
  ["450", "Mailbox unavailable (busy); try again"], ["451", "Local error in processing"],
  ["452", "Insufficient system storage"], ["454", "Temporary authentication failure"],
  ["500", "Syntax error, command unrecognized"], ["501", "Syntax error in parameters"],
  ["502", "Command not implemented"], ["503", "Bad sequence of commands"],
  ["504", "Command parameter not implemented"], ["535", "Authentication credentials invalid"],
  ["550", "Mailbox unavailable / rejected (policy)"], ["551", "User not local"],
  ["552", "Exceeded storage allocation"], ["553", "Mailbox name not allowed"],
  ["554", "Transaction failed / no valid recipients"],
];
const SYSLOG_FAC = ["kernel", "user", "mail", "system daemons", "security/authorization", "syslogd", "line printer", "network news", "UUCP", "clock daemon", "security/authorization (private)", "FTP daemon", "NTP", "log audit", "log alert", "clock daemon (note 2)", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"];
const SYSLOG_SEV = ["Emergency (system unusable)", "Alert (act immediately)", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"];
const MAGIC = [
  ["89504E470D0A1A0A", 0, "PNG image"],
  ["FFD8FF", 0, "JPEG image"],
  ["474946383761", 0, "GIF image (GIF87a)"],
  ["474946383961", 0, "GIF image (GIF89a)"],
  ["25504446", 0, "PDF document (%PDF)"],
  ["504B0304", 0, "ZIP / OOXML / JAR / APK (local file header)"],
  ["504B0506", 0, "ZIP end-of-central-directory (empty archive)"],
  ["504B0708", 0, "ZIP spanned/data-descriptor header"],
  ["1F8B", 0, "gzip compressed data"],
  ["425A68", 0, "bzip2 compressed data (BZh)"],
  ["377ABCAF271C", 0, "7-Zip archive"],
  ["FD377A585A00", 0, "XZ compressed data"],
  ["28B52FFD", 0, "Zstandard compressed data"],
  ["04224D18", 0, "LZ4 frame"],
  ["526172211A0700", 0, "RAR archive v1.5-4.x"],
  ["526172211A070100", 0, "RAR archive v5+"],
  ["7F454C46", 0, "ELF executable / object"],
  ["4D5A", 0, "DOS/Windows PE executable (MZ)"],
  ["CAFEBABE", 0, "Java class file OR Mach-O universal (fat) binary"],
  ["FEEDFACE", 0, "Mach-O 32-bit"],
  ["FEEDFACF", 0, "Mach-O 64-bit"],
  ["CEFAEDFE", 0, "Mach-O 32-bit (byte-swapped)"],
  ["CFFAEDFE", 0, "Mach-O 64-bit (byte-swapped)"],
  ["D0CF11E0A1B11AE1", 0, "MS Compound File (legacy doc/xls/ppt/msi, OLE2)"],
  ["53514C69746520666F726D6174203300", 0, "SQLite 3 database"],
  ["4D534346", 0, "Microsoft Cabinet (CAB)"],
  ["252150532D41646F6265", 0, "PostScript document"],
  ["7B5C727466", 0, "Rich Text Format ({\\rtf)"],
  ["494433", 0, "MP3 audio with ID3v2 tag"],
  ["664C6143", 0, "FLAC audio (fLaC)"],
  ["4F676753", 0, "Ogg container (OggS)"],
  ["1A45DFA3", 0, "Matroska / WebM (EBML)"],
  ["464C56", 0, "Flash Video (FLV)"],
  ["0A0D0D0A", 0, "pcapng capture file"],
  ["D4C3B2A1", 0, "pcap capture (little-endian)"],
  ["A1B2C3D4", 0, "pcap capture (big-endian)"],
  ["4C000000011402", 0, "Windows shortcut (.lnk)"],
  ["0061736D", 0, "WebAssembly binary (wasm)"],
  ["6465780A", 0, "Android Dalvik DEX"],
  ["49492A00", 0, "TIFF image (little-endian)"],
  ["4D4D002A", 0, "TIFF image (big-endian)"],
  ["424D", 0, "BMP image"],
  ["00000100", 0, "Windows icon (ICO)"],
  ["00000200", 0, "Windows cursor (CUR)"],
  ["38425053", 0, "Adobe Photoshop document (PSD)"],
  ["774F4646", 0, "WOFF web font"],
  ["774F4632", 0, "WOFF2 web font"],
  ["000100000", 0, "TrueType font"],
  ["4F54544F", 0, "OpenType font (CFF)"],
  ["EDABEEDB", 0, "RPM package"],
  ["213C617263683E", 0, "Unix ar archive / .deb"],
];

// =====================================================================
// TOOLS
// =====================================================================
export const TOOLS = [
  // --------------------------- TIMESTAMPS ---------------------------
  { id: "fx-filetime", name: "Windows FILETIME Decoder / Encoder", cat: "forensics", desc: "Convert a Windows/NTFS FILETIME (100-nanosecond intervals since 1601-01-01 UTC) to a readable UTC date, or back. Accepts decimal or 0x-hex.", tags: ["filetime", "ntfs", "windows", "100ns", "1601"],
    inputs: [{ k: "mode", label: "Mode", type: "select", opts: ["Decode", "Encode"], value: "Decode" }, { k: "val", label: "FILETIME / Date", type: "text", placeholder: "132537600000000000 or 2021-01-01T00:00:00Z" }],
    run(v) {
      if (!v.val) return "";
      if (v.mode === "Encode") {
        const ms = parseDate(v.val); if (ms == null) return { error: "Enter an ISO date like 2021-01-01T00:00:00Z." };
        const ft = (BigInt(Math.round(ms)) + BigInt(MS_1601_TO_1970)) * 10000n;
        return `FILETIME (decimal): ${ft.toString()}\nFILETIME (hex):     0x${ft.toString(16).toUpperCase()}`;
      }
      const ft = parseBig(v.val); if (ft == null) return { error: "Enter a number (decimal or 0x-hex)." };
      const unixMs = Number(ft / 10000n) - MS_1601_TO_1970;
      return showTime(unixMs, `100ns intervals: ${ft.toString()}`);
    } },

  { id: "fx-chrome-time", name: "Chrome / WebKit Timestamp Decoder", cat: "forensics", desc: "Convert a Chrome/WebKit timestamp (microseconds since 1601-01-01 UTC, used in Chrome History/Cookies) to a readable UTC date, or back.", tags: ["chrome", "webkit", "cookies", "history", "microseconds"],
    inputs: [{ k: "mode", label: "Mode", type: "select", opts: ["Decode", "Encode"], value: "Decode" }, { k: "val", label: "WebKit time / Date", type: "text", placeholder: "13350000000000000 or 2024-01-01T00:00:00Z" }],
    run(v) {
      if (!v.val) return "";
      if (v.mode === "Encode") {
        const ms = parseDate(v.val); if (ms == null) return { error: "Enter an ISO date." };
        const wk = (BigInt(Math.round(ms)) + BigInt(MS_1601_TO_1970)) * 1000n;
        return `WebKit (microseconds): ${wk.toString()}`;
      }
      const wk = parseBig(v.val); if (wk == null) return { error: "Enter a number." };
      const unixMs = Number(wk / 1000n) - MS_1601_TO_1970;
      return showTime(unixMs, `microseconds since 1601: ${wk.toString()}`);
    } },

  { id: "fx-cocoa-time", name: "Apple Cocoa / Core Data Timestamp", cat: "forensics", desc: "Convert an Apple Cocoa / Core Data absolute time (seconds since 2001-01-01 UTC, used in macOS/iOS plists and SQLite) to a UTC date, or back.", tags: ["apple", "cocoa", "mac", "ios", "nsdate", "2001"],
    inputs: [{ k: "mode", label: "Mode", type: "select", opts: ["Decode", "Encode"], value: "Decode" }, { k: "val", label: "Cocoa seconds / Date", type: "text", placeholder: "726000000 or 2024-01-01T00:00:00Z" }],
    run(v) {
      if (!v.val) return "";
      if (v.mode === "Encode") { const ms = parseDate(v.val); if (ms == null) return { error: "Enter an ISO date." }; return `Cocoa seconds: ${ms / 1000 - SEC_1970_TO_2001}`; }
      const n = Number(String(v.val).trim()); if (!isFinite(n)) return { error: "Enter a number." };
      return showTime((n + SEC_1970_TO_2001) * 1000);
    } },

  { id: "fx-hfs-time", name: "HFS+ Timestamp Decoder", cat: "forensics", desc: "Convert an HFS+ / HFS timestamp (seconds since 1904-01-01) to a UTC date, or back. HFS+ stores UTC; classic HFS stored local time.", tags: ["hfs", "hfsplus", "mac", "1904"],
    inputs: [{ k: "mode", label: "Mode", type: "select", opts: ["Decode", "Encode"], value: "Decode" }, { k: "val", label: "HFS+ seconds / Date", type: "text", placeholder: "3787000000 or 2024-01-01T00:00:00Z" }],
    run(v) {
      if (!v.val) return "";
      if (v.mode === "Encode") { const ms = parseDate(v.val); if (ms == null) return { error: "Enter an ISO date." }; return `HFS+ seconds: ${ms / 1000 + SEC_1904_TO_1970}`; }
      const n = Number(String(v.val).trim()); if (!isFinite(n)) return { error: "Enter a number." };
      return showTime((n - SEC_1904_TO_1970) * 1000, "(HFS+ assumed UTC; classic HFS is local time)");
    } },

  { id: "fx-ole-time", name: "OLE Automation Date Decoder", cat: "forensics", desc: "Convert an OLE Automation date (floating-point days since 1899-12-30, used by VBA, Office and some registry values) to a UTC date.", tags: ["ole", "vba", "office", "oadate", "1899"],
    inputs: [{ k: "mode", label: "Mode", type: "select", opts: ["Decode", "Encode"], value: "Decode" }, { k: "val", label: "OLE days / Date", type: "text", placeholder: "45292.5 or 2024-01-01T12:00:00Z" }],
    run(v) {
      if (!v.val) return "";
      if (v.mode === "Encode") { const ms = parseDate(v.val); if (ms == null) return { error: "Enter an ISO date." }; return `OLE Automation date: ${(ms - OLE_EPOCH_MS) / 86400000}`; }
      const n = Number(String(v.val).trim()); if (!isFinite(n)) return { error: "Enter a number." };
      return showTime(n * 86400000 + OLE_EPOCH_MS);
    } },

  { id: "fx-dos-time", name: "DOS / FAT Date-Time Decoder", cat: "forensics", desc: "Decode a 16-bit DOS/FAT date word and time word (as used in ZIP local headers and FAT filesystems) into a date. 2-second resolution, local time.", tags: ["dos", "fat", "zip", "msdos"],
    inputs: [{ k: "date", label: "Date word (hex or dec)", type: "text", placeholder: "0x5821" }, { k: "time", label: "Time word (hex or dec)", type: "text", placeholder: "0x6000" }],
    run(v) {
      const d = v.date ? Number(parseBig(v.date)) : NaN, t = v.time ? Number(parseBig(v.time)) : NaN;
      if (!isFinite(d) && !isFinite(t)) return { error: "Enter a date and/or time word." };
      let out = [];
      if (isFinite(d)) { const y = 1980 + ((d >> 9) & 0x7f), mo = (d >> 5) & 0xf, day = d & 0x1f; out.push(`Date: ${y}-${String(mo).padStart(2, "0")}-${String(day).padStart(2, "0")}`); }
      if (isFinite(t)) { const h = (t >> 11) & 0x1f, mi = (t >> 5) & 0x3f, s = (t & 0x1f) * 2; out.push(`Time: ${String(h).padStart(2, "0")}:${String(mi).padStart(2, "0")}:${String(s).padStart(2, "0")} (local, 2s resolution)`); }
      return out.join("\n");
    } },

  { id: "fx-gps-time", name: "GPS Week/TOW to UTC", cat: "forensics", desc: "Convert a GPS week number and time-of-week (seconds) into a UTC date. GPS has no leap seconds; subtract the current GPS-UTC offset (18 since 2017).", tags: ["gps", "week", "tow", "leap"],
    inputs: [{ k: "week", label: "GPS week number", type: "text", placeholder: "2300" }, { k: "tow", label: "Time of week (seconds)", type: "text", placeholder: "259200" }, { k: "leap", label: "GPS-UTC leap seconds", type: "text", value: "18" }],
    run(v) {
      const w = Number(v.week), tow = Number(v.tow || 0), leap = Number(v.leap || 0);
      if (!isFinite(w)) return { error: "Enter a GPS week number." };
      const unixMs = GPS_EPOCH_MS + (w * 604800 + tow - leap) * 1000;
      return showTime(unixMs, `GPS week ${w}, TOW ${tow}s, leap ${leap}s`);
    } },

  { id: "fx-epoch-multi", name: "Unix Epoch Multi-Precision Decoder", cat: "forensics", desc: "Given one numeric timestamp, show how it decodes as Unix seconds, milliseconds, microseconds and nanoseconds, so an unknown-unit value can be disambiguated. Auto-guesses the most likely unit.", tags: ["epoch", "unix", "ms", "us", "ns", "ambiguous"],
    inputs: [{ k: "val", label: "Timestamp (number)", type: "text", placeholder: "1700000000" }],
    run(v) {
      const b = parseBig(v.val); if (b == null) return { error: "Enter a number." };
      const n = Number(b); if (!isFinite(n)) return { error: "Number too large." };
      const digits = String(Math.abs(n)).length;
      const guess = digits <= 11 ? "seconds" : digits <= 14 ? "milliseconds" : digits <= 17 ? "microseconds" : "nanoseconds";
      const rows = [["seconds", n * 1000], ["milliseconds", n], ["microseconds", n / 1000], ["nanoseconds", n / 1e6]];
      const lines = rows.map(([u, ms]) => { const d = new Date(ms); const iso = isNaN(d.getTime()) ? "(out of range)" : d.toISOString(); return `as ${u.padEnd(13)} -> ${iso}${u === guess ? "   <- most likely" : ""}`; });
      return `Value: ${b.toString()} (${digits} digits)\n\n${lines.join("\n")}`;
    } },

  { id: "fx-ad-interval", name: "Active Directory Time Interval", cat: "forensics", desc: "Interpret an AD time-interval attribute (100-nanosecond units, often negative, e.g. maxPwdAge, lockoutDuration) as a human-readable duration.", tags: ["ad", "ldap", "interval", "maxpwdage", "lockout"],
    inputs: [{ k: "val", label: "Interval (100ns units)", type: "text", placeholder: "-36288000000000" }],
    run(v) {
      const b = parseBig(v.val); if (b == null) return { error: "Enter a number." };
      if (b === 0n) return "0 = not set / none";
      if (b === -9223372036854775808n || b === 9223372036854775807n) return "This value means 'never' (no expiry).";
      let ns100 = b < 0n ? -b : b;
      let totalSec = Number(ns100) / 1e7;
      const days = Math.floor(totalSec / 86400); totalSec -= days * 86400;
      const h = Math.floor(totalSec / 3600); totalSec -= h * 3600;
      const m = Math.floor(totalSec / 60); const s = Math.round(totalSec - m * 60);
      return `${b < 0n ? "(negative = a duration) " : ""}${days} days, ${h} hours, ${m} minutes, ${s} seconds\nTotal seconds: ${(Number(ns100) / 1e7)}`;
    } },

  { id: "fx-generalized-time", name: "LDAP / ASN.1 GeneralizedTime Parser", cat: "forensics", desc: "Parse an LDAP/ASN.1 GeneralizedTime or UTCTime string (e.g. 20240131235959.0Z or 240131235959Z) into a normalized UTC date.", tags: ["ldap", "asn1", "generalizedtime", "utctime", "x509"],
    inputs: [{ k: "val", label: "GeneralizedTime / UTCTime", type: "text", placeholder: "20240131235959.0Z" }],
    run(v) {
      const t = String(v.val || "").trim(); if (!t) return "";
      let m = t.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:[.,](\d+))?(Z|[+-]\d{2}\d{2})?$/);
      let kind = "GeneralizedTime";
      if (!m) { m = t.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{2}\d{2})?$/); if (m) { kind = "UTCTime"; const yy = parseInt(m[1], 10); m[1] = String(yy >= 50 ? 1900 + yy : 2000 + yy); } }
      if (!m) return { error: "Not a valid GeneralizedTime/UTCTime string." };
      const [, Y, Mo, D, h, mi, s = "00", frac, tz = "Z"] = m;
      let iso = `${Y}-${Mo}-${D}T${h}:${mi}:${s}${frac ? "." + frac : ""}`;
      iso += tz === "Z" ? "Z" : `${tz.slice(0, 3)}:${tz.slice(3)}`;
      const ms = Date.parse(iso); if (isNaN(ms)) return { error: "Could not parse the components." };
      return `Type: ${kind}\n` + showTime(ms);
    } },

  { id: "fx-timeline", name: "Timeline Builder (Sort Mixed Timestamps)", cat: "forensics", desc: "Paste one event per line starting with a timestamp (Unix s/ms, ISO 8601, or 'YYYY-MM-DD HH:MM:SS'), optionally followed by a label. Normalizes to UTC and sorts chronologically.", tags: ["timeline", "sort", "events", "super-timeline"],
    inputs: [{ k: "text", label: "Events (one per line)", type: "textarea", rows: 8, placeholder: "1700000000 login\n2023-11-14T22:13:20Z file written" }, { k: "order", label: "Order", type: "select", opts: ["Ascending", "Descending"], value: "Ascending" }],
    run(v) {
      const lines = String(v.text || "").split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
      if (!lines.length) return "";
      const rows = [];
      for (const l of lines) {
        const sp = l.search(/\s/);
        const tok = sp < 0 ? l : l.slice(0, sp);
        const label = sp < 0 ? "" : l.slice(sp + 1).trim();
        let ms = null;
        if (/^\d+$/.test(tok)) { const n = Number(tok); ms = tok.length <= 11 ? n * 1000 : tok.length <= 14 ? n : tok.length <= 17 ? n / 1000 : n / 1e6; }
        else { const p = parseDate(l) ?? Date.parse(l); if (!isNaN(p)) ms = p; }
        if (ms == null || !isFinite(ms) || isNaN(new Date(ms).getTime())) rows.push({ ms: null, raw: l });
        else rows.push({ ms, iso: new Date(ms).toISOString(), label });
      }
      const ok = rows.filter((r) => r.ms != null).sort((a, b) => v.order === "Descending" ? b.ms - a.ms : a.ms - b.ms);
      const bad = rows.filter((r) => r.ms == null);
      let out = ok.map((r) => `${r.iso}  ${r.label}`.trimEnd()).join("\n");
      if (bad.length) out += `\n\nUnparsed lines (${bad.length}):\n` + bad.map((r) => "  " + r.raw).join("\n");
      return out;
    } },

  // --------------------------- BINARY / FILE FORMAT ---------------------------
  { id: "fx-magic-bytes", name: "File Signature (Magic Bytes) Identifier", cat: "forensics", desc: "Paste the first bytes of a file as hex and identify the file type from its signature. Includes container checks for RIFF (WEBP/WAVE/AVI) and ISO-BMFF (MP4/MOV).", tags: ["magic", "signature", "file type", "header", "hex"],
    inputs: [{ k: "hex", label: "First bytes (hex)", type: "textarea", rows: 3, placeholder: "89 50 4E 47 0D 0A 1A 0A" }],
    run(v) {
      const h = String(v.hex || "").replace(/0x/gi, "").replace(/[^0-9a-fA-F]/g, "").toUpperCase();
      if (!h) return "";
      const hits = [];
      for (const [sig, off, name] of MAGIC) { const at = off * 2; if (h.length >= at + sig.length && h.substr(at, sig.length) === sig) hits.push(`offset ${off}: ${name}  (${sig.match(/../g).join(" ")})`); }
      const u = hexBytes(h);
      if (asciiOf(u, 0, 4) === "RIFF" && u.length >= 12) { const f = asciiOf(u, 8, 4); const names = { WEBP: "WebP image", WAVE: "WAV audio", "AVI ": "AVI video" }; hits.push(`RIFF container, form "${f}": ${names[f] || "unknown RIFF type"}`); }
      if (u.length >= 8 && asciiOf(u, 4, 4) === "ftyp") hits.push(`ISO-BMFF container (MP4/MOV/HEIC), brand "${asciiOf(u, 8, 4)}"`);
      return hits.length ? hits.join("\n") : "No known signature matched these bytes.";
    } },

  { id: "fx-hexdump", name: "Hex Dump Formatter", cat: "forensics", desc: "Produce a canonical hex dump (offset, 16 hex bytes, ASCII column) from either hex input or raw text. Mirrors the layout of xxd / hexdump -C.", tags: ["hexdump", "xxd", "offset", "ascii"],
    inputs: [{ k: "data", label: "Input", type: "textarea", rows: 5, placeholder: "DFIR" }, { k: "src", label: "Treat input as", type: "select", opts: ["Text", "Hex"], value: "Text" }],
    run(v, H) {
      if (!v.data) return "";
      const u = v.src === "Hex" ? hexBytes(v.data) : H.bytes(v.data);
      if (!u.length) return { error: "No bytes to dump." };
      const lines = [];
      for (let i = 0; i < u.length; i += 16) {
        const chunk = u.subarray(i, i + 16);
        let hex = "", asc = "";
        for (let j = 0; j < 16; j++) { if (j < chunk.length) { hex += chunk[j].toString(16).padStart(2, "0") + " "; asc += chunk[j] >= 0x20 && chunk[j] <= 0x7e ? String.fromCharCode(chunk[j]) : "."; } else hex += "   "; if (j === 7) hex += " "; }
        lines.push(`${i.toString(16).padStart(8, "0")}  ${hex} |${asc}|`);
      }
      return lines.join("\n") + `\n\n${u.length} bytes`;
    } },

  { id: "fx-strings", name: "Printable Strings Extractor", cat: "forensics", desc: "Extract printable strings from binary (hex) or text input, ASCII and/or UTF-16LE, above a minimum length. Equivalent to the Unix strings command.", tags: ["strings", "ascii", "utf-16", "binary", "ioc"],
    inputs: [{ k: "data", label: "Input", type: "textarea", rows: 5, placeholder: "68656C6C6F00320077006F0072006C006400" }, { k: "src", label: "Treat input as", type: "select", opts: ["Hex", "Text"], value: "Hex" }, { k: "min", label: "Min length", type: "range", min: 1, max: 20, step: 1, value: 4 }, { k: "mode", label: "Encoding", type: "select", opts: ["ASCII", "UTF-16LE", "Both"], value: "Both" }],
    run(v, H) {
      if (!v.data) return "";
      const u = v.src === "Hex" ? hexBytes(v.data) : H.bytes(v.data);
      const min = Math.max(1, parseInt(v.min, 10) || 4);
      const out = [];
      if (v.mode === "ASCII" || v.mode === "Both") { let cur = ""; for (let i = 0; i < u.length; i++) { const b = u[i]; if (b >= 0x20 && b <= 0x7e) cur += String.fromCharCode(b); else { if (cur.length >= min) out.push(cur); cur = ""; } } if (cur.length >= min) out.push(cur); }
      if (v.mode === "UTF-16LE" || v.mode === "Both") { let cur = ""; for (let i = 0; i + 1 < u.length; i += 2) { const lo = u[i], hi = u[i + 1]; if (hi === 0 && lo >= 0x20 && lo <= 0x7e) cur += String.fromCharCode(lo); else { if (cur.length >= min) out.push("[u16] " + cur); cur = ""; } } if (cur.length >= min) out.push("[u16] " + cur); }
      return out.length ? out.join("\n") : "(no strings of that length found)";
    } },

  { id: "fx-entropy-profile", name: "Per-Block Shannon Entropy Profile", cat: "forensics", desc: "Compute Shannon entropy (0-8 bits/byte) for each fixed-size block of a hex blob, plus the overall value, to spot encrypted or compressed regions (entropy near 8).", tags: ["entropy", "shannon", "packed", "encrypted", "block"],
    inputs: [{ k: "hex", label: "Bytes (hex)", type: "textarea", rows: 4, placeholder: "00 11 22 33 ... (paste a hex blob)" }, { k: "block", label: "Block size (bytes)", type: "text", value: "256" }],
    run(v) {
      const u = hexBytes(v.hex); if (!u.length) return "";
      const bs = Math.max(1, parseInt(v.block, 10) || 256);
      const ent = (arr) => { const f = new Array(256).fill(0); for (const b of arr) f[b]++; let h = 0; for (const c of f) if (c) { const p = c / arr.length; h -= p * Math.log2(p); } return h; };
      const lines = [];
      for (let i = 0; i < u.length; i += bs) { const blk = u.subarray(i, i + bs); const e = ent(blk); const bar = "#".repeat(Math.round(e * 4)); const flag = e >= 7.5 ? "  <- high (encrypted/compressed?)" : e <= 1.0 ? "  <- very low" : ""; lines.push(`0x${i.toString(16).padStart(8, "0")} (${String(blk.length).padStart(4)}B): ${e.toFixed(3)} ${bar}${flag}`); }
      return `Overall entropy: ${ent(u).toFixed(4)} bits/byte over ${u.length} bytes\nBlock size: ${bs} bytes\n\n${lines.join("\n")}`;
    } },

  { id: "fx-base64-extract", name: "Base64 Blob Extractor & Decoder", cat: "forensics", desc: "Find base64-looking runs in a block of text (such as a script or log) and decode each one, showing a printable preview. Useful for triaging obfuscated payloads.", tags: ["base64", "extract", "decode", "obfuscation", "malware"],
    inputs: [{ k: "text", label: "Input text", type: "textarea", rows: 6, placeholder: "...powershell -enc SGVsbG8gd29ybGQ= ..." }, { k: "min", label: "Min length", type: "text", value: "16" }],
    run(v, H) {
      const text = String(v.text || ""); if (!text) return "";
      const min = Math.max(4, parseInt(v.min, 10) || 16);
      const re = new RegExp(`[A-Za-z0-9+/]{${min},}={0,2}`, "g");
      const seen = new Set(); const out = [];
      let m;
      while ((m = re.exec(text)) !== null) {
        const s = m[0]; if (seen.has(s)) continue; seen.add(s);
        if (s.length % 4 === 1) continue;
        try { const dec = H.b64decode(s); const printable = (dec.replace(/[^\x20-\x7e]/g, "").length / Math.max(1, dec.length)); out.push(`[${s.length} chars] ${s.slice(0, 48)}${s.length > 48 ? "..." : ""}\n  -> ${printable > 0.7 ? dec.slice(0, 200) : "(non-text, " + dec.length + " bytes; " + (printable * 100).toFixed(0) + "% printable)"}`); } catch (e) { /* skip */ }
      }
      return out.length ? out.join("\n\n") : "No decodable base64 runs found.";
    } },

  { id: "fx-png-chunks", name: "PNG Chunk Parser", cat: "forensics", desc: "Parse a PNG file from hex: verifies the 8-byte signature, lists every chunk (type, length, offset) and decodes the IHDR dimensions and color type.", tags: ["png", "chunk", "ihdr", "image", "parser"],
    inputs: [{ k: "hex", label: "PNG bytes (hex)", type: "textarea", rows: 4, placeholder: "89504E470D0A1A0A0000000D49484452..." }],
    run(v) {
      const u = hexBytes(v.hex); if (!u.length) return "";
      if (u.length < 8 || readBE(u, 0, 4) !== 0x89504e47) return { error: "Not a PNG (bad signature)." };
      const out = ["PNG signature OK"]; let i = 8;
      while (i + 8 <= u.length) {
        const len = readBE(u, i, 4); const type = asciiOf(u, i + 4, 4);
        out.push(`offset ${i}: ${type}  length ${len}`);
        if (type === "IHDR" && i + 8 + 13 <= u.length) { const w = readBE(u, i + 8, 4), ht = readBE(u, i + 12, 4), bd = u[i + 16], ct = u[i + 17], il = u[i + 20]; const colors = { 0: "Grayscale", 2: "Truecolor (RGB)", 3: "Indexed (palette)", 4: "Grayscale+Alpha", 6: "Truecolor+Alpha (RGBA)" }; out.push(`  IHDR: ${w} x ${ht}, bit depth ${bd}, color type ${ct} (${colors[ct] || "?"}), interlace ${il}`); }
        if (type === "IEND") break;
        i += 12 + len;
      }
      return out.join("\n");
    } },

  { id: "fx-jpeg-markers", name: "JPEG Marker / Segment Parser", cat: "forensics", desc: "Parse a JPEG from hex and list its markers (SOI, APPn, DQT, SOFn, DHT, SOS, EOI) with offsets, decoding frame dimensions from the SOF segment.", tags: ["jpeg", "jfif", "exif", "marker", "sof"],
    inputs: [{ k: "hex", label: "JPEG bytes (hex)", type: "textarea", rows: 4, placeholder: "FFD8FFE000104A464946..." }],
    run(v) {
      const u = hexBytes(v.hex); if (!u.length) return "";
      if (u[0] !== 0xff || u[1] !== 0xd8) return { error: "Not a JPEG (missing SOI FFD8)." };
      const names = { 0xd8: "SOI (start of image)", 0xd9: "EOI (end of image)", 0xda: "SOS (start of scan)", 0xdb: "DQT (quantization table)", 0xc4: "DHT (Huffman table)", 0xdd: "DRI (restart interval)", 0xe0: "APP0 (JFIF)", 0xe1: "APP1 (EXIF/XMP)", 0xee: "APP14 (Adobe)", 0xfe: "COM (comment)" };
      for (let n = 0; n <= 15; n++) names[0xe0 + n] = names[0xe0 + n] || `APP${n}`;
      for (let n = 0; n <= 15; n++) names[0xc0 + n] = names[0xc0 + n] || `SOF${n} (frame)`;
      const out = []; let i = 0;
      while (i + 1 < u.length) {
        if (u[i] !== 0xff) { i++; continue; }
        let mk = u[i + 1]; if (mk === 0xff) { i++; continue; } if (mk === 0x00 || (mk >= 0xd0 && mk <= 0xd7)) { i += 2; continue; }
        const label = names[mk] || `marker FF${mk.toString(16).toUpperCase()}`;
        if (mk === 0xd8 || mk === 0xd9) { out.push(`offset ${i}: ${label}`); i += 2; if (mk === 0xd9) break; continue; }
        const len = readBE(u, i + 2, 2);
        let extra = "";
        if (mk >= 0xc0 && mk <= 0xcf && mk !== 0xc4 && mk !== 0xc8 && mk !== 0xcc) { const prec = u[i + 4], hh = readBE(u, i + 5, 2), ww = readBE(u, i + 7, 2), comp = u[i + 9]; extra = `  -> ${ww} x ${hh}, ${prec}-bit, ${comp} components`; }
        out.push(`offset ${i}: ${label}  length ${len}${extra}`);
        if (mk === 0xda) { out.push("  (entropy-coded scan data follows)"); break; }
        i += 2 + len;
      }
      return out.join("\n");
    } },

  { id: "fx-zip-local-header", name: "ZIP Local File Header Parser", cat: "forensics", desc: "Parse a ZIP local file header from hex (signature PK\\x03\\x04): version, flags, compression method, DOS mod time, CRC-32, sizes and file name.", tags: ["zip", "pk", "local header", "crc32", "parser"],
    inputs: [{ k: "hex", label: "Header bytes (hex)", type: "textarea", rows: 4, placeholder: "504B0304140000000800..." }],
    run(v) {
      const u = hexBytes(v.hex); if (u.length < 30) return u.length ? { error: "Need at least 30 bytes." } : "";
      if (!(u[0] === 0x50 && u[1] === 0x4b && u[2] === 0x03 && u[3] === 0x04)) return { error: "Not a ZIP local file header (expected 50 4B 03 04)." };
      const methods = { 0: "stored (no compression)", 8: "deflate", 9: "deflate64", 12: "bzip2", 14: "LZMA", 93: "zstd", 95: "xz", 99: "AES" };
      const flags = readLE(u, 6, 2), method = readLE(u, 8, 2), nlen = readLE(u, 26, 2);
      const dosT = readLE(u, 10, 2), dosD = readLE(u, 12, 2);
      const h = (dosT >> 11) & 0x1f, mi = (dosT >> 5) & 0x3f, s = (dosT & 0x1f) * 2;
      const y = 1980 + ((dosD >> 9) & 0x7f), mo = (dosD >> 5) & 0xf, day = dosD & 0x1f;
      const name = nlen && u.length >= 30 + nlen ? asciiOf(u, 30, nlen) : "(name beyond provided bytes)";
      return [
        `Signature:        PK\\x03\\x04 OK`,
        `Version needed:   ${readLE(u, 4, 2) / 10}`,
        `Flags:            0x${flags.toString(16).padStart(4, "0")}${flags & 1 ? " (encrypted)" : ""}${flags & 8 ? " (data descriptor)" : ""}`,
        `Compression:      ${method} (${methods[method] || "?"})`,
        `Mod date/time:    ${y}-${String(mo).padStart(2, "0")}-${String(day).padStart(2, "0")} ${String(h).padStart(2, "0")}:${String(mi).padStart(2, "0")}:${String(s).padStart(2, "0")} (local)`,
        `CRC-32:           0x${readLE(u, 14, 4).toString(16).padStart(8, "0")}`,
        `Compressed size:  ${readLE(u, 18, 4)}`,
        `Uncompressed:     ${readLE(u, 22, 4)}`,
        `File name length: ${nlen}`,
        `Extra field len:  ${readLE(u, 28, 2)}`,
        `File name:        ${name}`,
      ].join("\n");
    } },

  { id: "fx-zip-eocd", name: "ZIP End-of-Central-Directory Parser", cat: "forensics", desc: "Parse a ZIP End of Central Directory record from hex (signature PK\\x05\\x06): entry counts, central-directory size and offset, and comment length.", tags: ["zip", "eocd", "central directory", "parser"],
    inputs: [{ k: "hex", label: "EOCD bytes (hex)", type: "textarea", rows: 3, placeholder: "504B0506000000000100010..." }],
    run(v) {
      const u = hexBytes(v.hex); if (u.length < 22) return u.length ? { error: "Need at least 22 bytes." } : "";
      if (!(u[0] === 0x50 && u[1] === 0x4b && u[2] === 0x05 && u[3] === 0x06)) return { error: "Not an EOCD record (expected 50 4B 05 06)." };
      const clen = readLE(u, 20, 2);
      return [
        `Signature:              PK\\x05\\x06 OK`,
        `Disk number:            ${readLE(u, 4, 2)}`,
        `Disk with CD start:     ${readLE(u, 6, 2)}`,
        `CD entries on disk:     ${readLE(u, 8, 2)}`,
        `Total CD entries:       ${readLE(u, 10, 2)}`,
        `Central directory size: ${readLE(u, 12, 4)} bytes`,
        `CD offset:              ${readLE(u, 16, 4)}`,
        `Comment length:         ${clen}`,
        clen && u.length >= 22 + clen ? `Comment:                ${asciiOf(u, 22, clen)}` : "",
      ].filter(Boolean).join("\n");
    } },

  { id: "fx-gzip-header", name: "gzip Header Parser", cat: "forensics", desc: "Parse a gzip member header from hex (magic 1F 8B): compression method, flags, the embedded modification time (Unix seconds) and the originating OS.", tags: ["gzip", "gz", "mtime", "header", "parser"],
    inputs: [{ k: "hex", label: "gzip bytes (hex)", type: "textarea", rows: 3, placeholder: "1F8B0800A1B2C3D4000003..." }],
    run(v) {
      const u = hexBytes(v.hex); if (u.length < 10) return u.length ? { error: "Need at least 10 bytes." } : "";
      if (!(u[0] === 0x1f && u[1] === 0x8b)) return { error: "Not gzip (expected 1F 8B)." };
      const oslist = { 0: "FAT (MS-DOS)", 1: "Amiga", 2: "VMS", 3: "Unix", 6: "HPFS", 7: "Macintosh", 11: "NTFS", 255: "unknown" };
      const flg = u[3], mtime = readLE(u, 4, 4);
      const fl = []; if (flg & 1) fl.push("FTEXT"); if (flg & 2) fl.push("FHCRC"); if (flg & 4) fl.push("FEXTRA"); if (flg & 8) fl.push("FNAME"); if (flg & 16) fl.push("FCOMMENT");
      return [
        `Magic:        1F 8B OK`,
        `Method:       ${u[2]}${u[2] === 8 ? " (deflate)" : ""}`,
        `Flags:        0x${flg.toString(16).padStart(2, "0")}${fl.length ? " (" + fl.join(", ") + ")" : ""}`,
        `MTIME:        ${mtime}${mtime ? " -> " + new Date(mtime * 1000).toISOString() : " (not set)"}`,
        `Extra flags:  0x${u[8].toString(16).padStart(2, "0")}`,
        `OS:           ${u[9]} (${oslist[u[9]] || "?"})`,
      ].join("\n");
    } },

  { id: "fx-tar-header", name: "TAR (ustar) Header Parser", cat: "forensics", desc: "Parse a 512-byte POSIX tar (ustar) header block from hex: file name, octal mode, size and mtime, type flag and link target.", tags: ["tar", "ustar", "posix", "archive", "parser"],
    inputs: [{ k: "hex", label: "Header block (hex)", type: "textarea", rows: 4, placeholder: "7465737400...(512 bytes)" }],
    run(v) {
      const u = hexBytes(v.hex); if (u.length < 157) return u.length ? { error: "Need at least ~157 bytes of a tar header." } : "";
      const str = (o, l) => { let s = ""; for (let i = 0; i < l && u[o + i]; i++) s += String.fromCharCode(u[o + i]); return s.trim(); };
      const oct = (o, l) => { const t = str(o, l).replace(/[^0-7]/g, ""); return t ? parseInt(t, 8) : 0; };
      const types = { "0": "regular file", "\0": "regular file", "1": "hard link", "2": "symbolic link", "3": "char device", "4": "block device", "5": "directory", "6": "FIFO", "7": "contiguous", "g": "pax global header", "x": "pax extended header", "L": "GNU long name" };
      const tf = String.fromCharCode(u[156] || 0);
      const mtime = oct(136, 12);
      return [
        `Name:      ${str(0, 100)}`,
        `Mode:      ${oct(100, 8).toString(8).padStart(4, "0")} (octal)`,
        `UID/GID:   ${oct(108, 8)} / ${oct(116, 8)}`,
        `Size:      ${oct(124, 12)} bytes`,
        `MTime:     ${mtime} -> ${new Date(mtime * 1000).toISOString()}`,
        `Type flag: '${tf === "\0" ? "0" : tf}' (${types[tf] || "unknown"})`,
        `Link name: ${str(157, 100) || "(none)"}`,
        `Magic:     ${str(257, 6) || "(pre-POSIX / v7)"}`,
        `Uname/Gname: ${str(265, 32)} / ${str(297, 32)}`,
      ].join("\n");
    } },

  { id: "fx-ps-encodedcommand", name: "PowerShell -EncodedCommand Decoder", cat: "forensics", desc: "Decode a PowerShell -EncodedCommand / -enc value (base64 of UTF-16LE) back to the original command text. Common in incident logs and EDR alerts.", tags: ["powershell", "encodedcommand", "enc", "utf-16", "base64"],
    inputs: [{ k: "b64", label: "Base64 payload", type: "textarea", rows: 4, placeholder: "SABlAGwAbABvACAAVwBvAHIAbABkAA==" }],
    run(v, H) {
      let s = String(v.b64 || "").trim(); if (!s) return "";
      const m = s.match(/(?:-e(?:nc|ncodedcommand)?\s+)?([A-Za-z0-9+/_-]+={0,2})\s*$/i); if (m) s = m[1];
      try {
        const norm = s.replace(/-/g, "+").replace(/_/g, "/");
        const raw = atob(norm + "===".slice((norm.length + 3) % 4));
        // PowerShell -EncodedCommand is base64 of UTF-16LE
        let out = ""; for (let i = 0; i + 1 < raw.length; i += 2) out += String.fromCharCode(raw.charCodeAt(i) | (raw.charCodeAt(i + 1) << 8));
        return out || "(decoded to empty text)";
      } catch (e) { return { error: "Not valid base64." }; }
    } },

  // --------------------------- WINDOWS ARTIFACTS ---------------------------
  { id: "fx-sid-parse", name: "Windows SID Parser", cat: "forensics", desc: "Parse a Windows SID either from its binary form (hex) into the S-1-... string, or from the string form into its revision, identifier authority, sub-authorities and RID.", tags: ["sid", "windows", "security identifier", "rid"],
    inputs: [{ k: "val", label: "SID (hex binary or S-1-... string)", type: "text", placeholder: "S-1-5-21-1004336348-1177238915-682003330-512" }],
    run(v) {
      const t = String(v.val || "").trim(); if (!t) return "";
      if (/^s-/i.test(t)) {
        const parts = t.split("-"); if (parts.length < 3) return { error: "Malformed SID string." };
        const rev = parts[1], auth = parts[2], subs = parts.slice(3);
        const rid = subs.length ? subs[subs.length - 1] : "(none)";
        return [`Revision:        ${rev}`, `Authority:       ${auth}`, `Sub-authorities: ${subs.join(", ") || "(none)"}`, `RID (last):      ${rid}`, `Sub count:       ${subs.length}`].join("\n");
      }
      const u = hexBytes(t); if (u.length < 8) return { error: "Need the S-1-... string or at least 8 bytes of binary SID." };
      const rev = u[0], count = u[1]; let authority = 0; for (let i = 2; i < 8; i++) authority = authority * 256 + u[i];
      const subs = []; for (let i = 0; i < count && 8 + i * 4 + 4 <= u.length; i++) subs.push(readLE(u, 8 + i * 4, 4));
      return `Binary -> S-${rev}-${authority}${subs.length ? "-" + subs.join("-") : ""}\nRevision ${rev}, ${count} sub-authorities`;
    } },

  { id: "fx-well-known-sid", name: "Well-Known SID & RID Lookup", cat: "forensics", desc: "Look up a well-known Windows SID (e.g. S-1-5-18) or a domain RID (e.g. 512 = Domain Admins) by number or name. Filter with any text.", tags: ["sid", "rid", "well-known", "reference", "windows"],
    inputs: [{ k: "q", label: "Filter (SID, RID or name)", type: "text", placeholder: "512" }],
    run(v) {
      const a = lookup(WELL_KNOWN_SIDS, v.q, ["SID", "Name", "Note"]);
      const b = lookup(SID_RIDS, v.q, ["RID", "Name", "Note"]);
      const q = String(v.q || "").trim().toLowerCase();
      const aHit = !q || WELL_KNOWN_SIDS.some((r) => r.some((c) => String(c).toLowerCase().includes(q)));
      const bHit = !q || SID_RIDS.some((r) => r.some((c) => String(c).toLowerCase().includes(q)));
      return [aHit ? "WELL-KNOWN SIDs\n" + a : "", bHit ? "\nDOMAIN RELATIVE IDs (append to S-1-5-21-<domain>-)\n" + b : ""].filter(Boolean).join("\n").trim() || `No entry matches "${v.q}".`;
    } },

  { id: "fx-registry-explain", name: "Registry Hive & Path Explainer", cat: "forensics", desc: "Explain a Windows registry path: resolve its root key (HKLM/HKCU/etc.), and map registry hives to the files that back them on disk (SYSTEM, SOFTWARE, SAM, NTUSER.DAT, ...).", tags: ["registry", "hive", "hklm", "ntuser", "windows"],
    inputs: [{ k: "path", label: "Registry path", type: "text", placeholder: "HKLM\\SYSTEM\\CurrentControlSet\\Services" }],
    run(v) {
      const roots = { HKLM: "HKEY_LOCAL_MACHINE", "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE", HKCU: "HKEY_CURRENT_USER", "HKEY_CURRENT_USER": "HKEY_CURRENT_USER", HKU: "HKEY_USERS", "HKEY_USERS": "HKEY_USERS", HKCR: "HKEY_CLASSES_ROOT", "HKEY_CLASSES_ROOT": "HKEY_CLASSES_ROOT", HKCC: "HKEY_CURRENT_CONFIG", "HKEY_CURRENT_CONFIG": "HKEY_CURRENT_CONFIG" };
      const hives = [
        ["HKLM\\SYSTEM", "%SystemRoot%\\System32\\config\\SYSTEM", "Services, CurrentControlSet, mounted devices, USB history"],
        ["HKLM\\SOFTWARE", "%SystemRoot%\\System32\\config\\SOFTWARE", "Installed software, Run keys, OS version, network profiles"],
        ["HKLM\\SAM", "%SystemRoot%\\System32\\config\\SAM", "Local accounts and password hashes"],
        ["HKLM\\SECURITY", "%SystemRoot%\\System32\\config\\SECURITY", "LSA secrets, cached domain policy"],
        ["HKCU", "%UserProfile%\\NTUSER.DAT", "Per-user settings, user Run keys, RecentDocs, TypedURLs, UserAssist"],
        ["HKCR / per-user classes", "%UserProfile%\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat", "Shellbags, file associations"],
        ["Amcache", "%SystemRoot%\\AppCompat\\Programs\\Amcache.hve", "Executed program metadata (SHA-1, paths)"],
      ];
      const p = String(v.path || "").trim();
      let head = "";
      if (p) { const first = p.replace(/^\\+/, "").split(/[\\/]/)[0].toUpperCase(); if (roots[first]) head = `Root key: ${first} = ${roots[first]}\n\n`; }
      return head + "HIVE -> BACKING FILE\n" + lookup(hives, p && roots[p.split(/[\\/]/)[0].toUpperCase()] ? "" : p, ["Hive", "File", "Forensic value"]);
    } },

  { id: "fx-persistence-keys", name: "Autostart / Persistence Registry Reference", cat: "forensics", desc: "Reference of common Windows autostart extensibility points (ASEPs) and persistence registry locations that malware abuses. Filter by keyword.", tags: ["persistence", "asep", "autoruns", "run keys", "registry"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "run" }],
    run(v) {
      const rows = [
        ["Run (per-machine)", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"],
        ["Run (per-user)", "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"],
        ["RunOnce", "HKLM or HKCU ...\\CurrentVersion\\RunOnce"],
        ["Winlogon Shell", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon (Shell/Userinit)"],
        ["Services", "HKLM\\SYSTEM\\CurrentControlSet\\Services"],
        ["IFEO (debugger hijack)", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"],
        ["AppInit_DLLs", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs"],
        ["Startup folder", "%AppData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"],
        ["Scheduled Tasks", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks"],
        ["COM hijack (CLSID)", "HKCU\\SOFTWARE\\Classes\\CLSID\\{...}\\InprocServer32"],
        ["Winlogon Notify (legacy)", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify"],
        ["LSA Security Packages", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa (Security Packages)"],
        ["Explorer Run", "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"],
      ];
      return lookup(rows, v.q, ["Technique", "Location"]);
    } },

  { id: "fx-reg-types", name: "Registry Value Type Reference", cat: "forensics", desc: "Look up a Windows registry value type by number (e.g. 4 = REG_DWORD) or name. Filter with any text.", tags: ["registry", "reg_sz", "reg_dword", "type", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "dword" }],
    run(v) { return lookup(REG_TYPES, v.q, ["ID", "Name", "Meaning"]); } },

  { id: "fx-uuid-inspect", name: "GUID / UUID Version Decoder", cat: "forensics", desc: "Decode a UUID/GUID: report its version and variant, and for a version-1 (time-based) UUID extract the embedded timestamp, clock sequence and node (MAC).", tags: ["uuid", "guid", "version", "v1", "timestamp"],
    inputs: [{ k: "uuid", label: "UUID / GUID", type: "text", placeholder: "6ba7b810-9dad-11d1-80b4-00c04fd430c8" }],
    run(v) {
      const t = String(v.uuid || "").trim().replace(/[{}]/g, "");
      if (!t) return "";
      const m = t.match(/^([0-9a-f]{8})-?([0-9a-f]{4})-?([0-9a-f]{4})-?([0-9a-f]{4})-?([0-9a-f]{12})$/i);
      if (!m) return { error: "Not a valid UUID (expected 32 hex digits)." };
      const hex = (m[1] + m[2] + m[3] + m[4] + m[5]).toLowerCase();
      const ver = parseInt(hex[12], 16);
      const vbits = parseInt(hex[16], 16);
      let variant = "reserved";
      if (vbits < 8) variant = "NCS (legacy)"; else if (vbits < 12) variant = "RFC 4122"; else if (vbits < 14) variant = "Microsoft GUID"; else variant = "reserved (future)";
      const out = [`Version: ${ver}`, `Variant: ${variant}`];
      if (ver === 1) {
        const timeLow = BigInt("0x" + hex.slice(0, 8)), timeMid = BigInt("0x" + hex.slice(8, 12)), timeHi = BigInt("0x" + hex.slice(13, 16));
        const ts = (timeHi << 48n) | (timeMid << 32n) | timeLow; // 100ns since 1582-10-15
        const unixMs = Number(ts / 10000n) - 12219292800000;
        const node = hex.slice(20); const clock = parseInt(hex.slice(16, 20), 16) & 0x3fff;
        const d = new Date(unixMs);
        out.push(`Timestamp: ${isNaN(d.getTime()) ? "(out of range)" : d.toISOString()} (100ns since 1582-10-15)`);
        out.push(`Clock seq: ${clock}`);
        out.push(`Node (MAC): ${node.match(/../g).join(":")}${(parseInt(node.slice(0, 2), 16) & 1) ? " (multicast bit set - likely random)" : ""}`);
      } else if (ver === 4) out.push("Random UUID: no embedded timestamp.");
      else if (ver === 7) { const ms = BigInt("0x" + hex.slice(0, 12)); const d = new Date(Number(ms)); out.push(`Timestamp: ${isNaN(d.getTime()) ? "(out of range)" : d.toISOString()} (Unix ms, UUIDv7)`); }
      return out.join("\n");
    } },

  { id: "fx-windows-event-id", name: "Windows Event ID Reference", cat: "forensics", desc: "Look up a Windows Security/System/PowerShell event ID (e.g. 4624, 7045, 4104) or search event descriptions. Curated, accurate entries only.", tags: ["event id", "windows", "security log", "4624", "reference"],
    inputs: [{ k: "q", label: "Filter (ID or keyword)", type: "text", placeholder: "4624" }],
    run(v) { return lookup(WIN_EVENTS, v.q, ["ID", "Log", "Event"]); } },

  { id: "fx-logon-type", name: "Windows Logon Type Reference", cat: "forensics", desc: "Explain a Windows logon type code from events 4624/4625 (e.g. 3 = Network, 10 = RDP). Filter by number or keyword.", tags: ["logon type", "4624", "rdp", "network", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "10" }],
    run(v) { return lookup(LOGON_TYPES, v.q, ["Type", "Name", "Meaning"]); } },

  { id: "fx-sysmon-event-id", name: "Sysmon Event ID Reference", cat: "forensics", desc: "Look up a Sysmon event ID (1-29) and its meaning, e.g. 1 = Process creation, 3 = Network connection, 11 = FileCreate. Filter by number or keyword.", tags: ["sysmon", "event id", "process create", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "3" }],
    run(v) { return lookup(SYSMON_EVENTS, v.q, ["ID", "Event"]); } },

  { id: "fx-ntfs-attributes", name: "NTFS Attribute Type Reference", cat: "forensics", desc: "Look up an NTFS MFT attribute type by hex code (e.g. 0x10 = $STANDARD_INFORMATION, 0x30 = $FILE_NAME) or name. Filter with any text.", tags: ["ntfs", "mft", "attribute", "file_name", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "0x30" }],
    run(v) { return lookup(NTFS_ATTRS, v.q, ["Type", "Name", "Contains"]); } },

  { id: "fx-file-attr-decode", name: "Windows File Attribute Decoder", cat: "forensics", desc: "Decode a Windows file-attribute bitmask (e.g. 0x22) into its flags (HIDDEN, SYSTEM, ARCHIVE, ...). Accepts hex or decimal.", tags: ["file attributes", "hidden", "system", "bitmask", "windows"],
    inputs: [{ k: "val", label: "Attribute value (hex or dec)", type: "text", placeholder: "0x22" }],
    run(v) { const b = parseBig(v.val); if (b == null) return v.val ? { error: "Enter a number." } : ""; return `Value: 0x${b.toString(16)} (${b.toString()})\n\n${decodeFlags(b, FILE_ATTRS)}`; } },

  { id: "fx-usn-reason", name: "NTFS USN Journal Reason Decoder", cat: "forensics", desc: "Decode an NTFS USN Journal (change journal) reason bitmask into its flags (FILE_CREATE, DATA_OVERWRITE, RENAME_NEW_NAME, ...). Accepts hex or decimal.", tags: ["usn", "journal", "ntfs", "reason", "bitmask"],
    inputs: [{ k: "val", label: "Reason value (hex or dec)", type: "text", placeholder: "0x102" }],
    run(v) { const b = parseBig(v.val); if (b == null) return v.val ? { error: "Enter a number." } : ""; return `Value: 0x${b.toString(16)}\n\n${decodeFlags(b, USN_REASONS)}`; } },

  { id: "fx-access-mask", name: "Windows Access Mask Decoder", cat: "forensics", desc: "Decode a Windows access-mask value (as seen in object-access events 4656/4663) into the specific and generic rights it grants. Accepts hex or decimal.", tags: ["access mask", "4663", "rights", "acl", "bitmask"],
    inputs: [{ k: "val", label: "Access mask (hex or dec)", type: "text", placeholder: "0x120089" }],
    run(v) { const b = parseBig(v.val); if (b == null) return v.val ? { error: "Enter a number." } : ""; return `Value: 0x${b.toString(16)}\n\n${decodeFlags(b, ACCESS_MASK)}`; } },

  { id: "fx-service-type", name: "Windows Service Type & Start Reference", cat: "forensics", desc: "Decode a Windows service type bitmask and look up service start-type codes (0=Boot ... 4=Disabled), as found in event 7045 and the Services registry.", tags: ["service", "7045", "start type", "scm", "reference"],
    inputs: [{ k: "type", label: "Service type (hex/dec, optional)", type: "text", placeholder: "0x10" }, { k: "q", label: "Start-type filter (optional)", type: "text", placeholder: "auto" }],
    run(v) {
      const out = [];
      if (v.type) { const b = parseBig(v.type); if (b == null) return { error: "Service type must be a number." }; out.push(`Service type 0x${b.toString(16)}:\n${decodeFlags(b, SERVICE_TYPE)}`); }
      out.push("START TYPES\n" + lookup(SERVICE_START, v.q, ["Code", "Name", "Meaning"]));
      return out.join("\n\n");
    } },

  { id: "fx-kerberos-etype", name: "Kerberos Encryption Type Reference", cat: "forensics", desc: "Look up a Kerberos encryption type (etype) number, e.g. 23 = rc4-hmac, 18 = aes256. Useful when triaging 4768/4769 events and Kerberoasting. Filter by number or name.", tags: ["kerberos", "etype", "rc4", "aes", "kerberoasting"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "23" }],
    run(v) { return lookup(KERBEROS_ETYPE, v.q, ["etype", "Name", "Note"]); } },

  // --------------------------- EMAIL ---------------------------
  { id: "fx-email-received", name: "Email Received-Header Hop Parser", cat: "forensics", desc: "Paste the Received: headers from an email and get the relay hops in delivery order (earliest first), each with its from/by hosts and the per-hop delay.", tags: ["email", "received", "hops", "headers", "smtp"],
    inputs: [{ k: "headers", label: "Raw headers", type: "textarea", rows: 10, placeholder: "Received: from mail.example.com (...) by mx.example.net; Mon, 1 Jan 2024 10:00:01 +0000" }],
    run(v) {
      const text = String(v.headers || ""); if (!text.trim()) return "";
      // unfold then split into Received blocks
      const unfolded = text.replace(/\r?\n[ \t]+/g, " ");
      const recs = unfolded.split(/\r?\n/).filter((l) => /^received:/i.test(l)).map((l) => l.replace(/^received:\s*/i, ""));
      if (!recs.length) return { error: "No Received: headers found." };
      // Received headers are prepended, so reverse for chronological order
      const hops = recs.slice().reverse().map((r, idx) => {
        const from = (r.match(/\bfrom\s+([^\s(;]+)/i) || [])[1] || "?";
        const by = (r.match(/\bby\s+([^\s(;]+)/i) || [])[1] || "?";
        const ip = (r.match(/\[?(\d{1,3}(?:\.\d{1,3}){3})\]?/) || [])[1] || "";
        const dm = r.match(/;\s*(.+)$/); const date = dm ? Date.parse(dm[1].trim()) : NaN;
        return { idx: idx + 1, from, by, ip, date };
      });
      const lines = hops.map((h, i) => { let delay = ""; if (i > 0 && !isNaN(h.date) && !isNaN(hops[i - 1].date)) { const d = (h.date - hops[i - 1].date) / 1000; delay = `  (+${d >= 0 ? d : "?"}s)`; } return `${h.idx}. from ${h.from}${h.ip ? " [" + h.ip + "]" : ""} by ${h.by}${isNaN(h.date) ? "" : "  " + new Date(h.date).toISOString()}${delay}`; });
      return `Delivery path (earliest first), ${hops.length} hop(s):\n\n${lines.join("\n")}`;
    } },

  { id: "fx-email-auth-results", name: "Authentication-Results Reader", cat: "forensics", desc: "Parse an Authentication-Results (or ARC-Authentication-Results) header and show the SPF, DKIM and DMARC verdicts plus the domains they covered.", tags: ["email", "spf", "dkim", "dmarc", "authentication-results"],
    inputs: [{ k: "header", label: "Authentication-Results header", type: "textarea", rows: 5, placeholder: "Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=example.org; dkim=pass header.d=example.org; dmarc=pass" }],
    run(v) {
      const t = String(v.header || "").replace(/\r?\n[ \t]+/g, " ").trim(); if (!t) return "";
      const body = t.replace(/^(arc-)?authentication-results:\s*/i, "");
      const out = [];
      for (const method of ["spf", "dkim", "dmarc", "arc", "compauth"]) {
        const re = new RegExp(`\\b${method}=([a-z]+)([^;]*)`, "i"); const m = body.match(re);
        if (m) { const detail = m[2].trim().replace(/^\(/, "").replace(/\)$/, ""); out.push(`${method.toUpperCase().padEnd(8)} ${m[1]}${detail ? "   " + detail : ""}`); }
      }
      const mx = (body.split(";")[0] || "").trim();
      return out.length ? `Verifier: ${mx}\n\n${out.join("\n")}` : "No spf/dkim/dmarc results found in the header.";
    } },

  { id: "fx-email-headers", name: "Email Header Overview", cat: "forensics", desc: "Extract the key fields from a raw email header block (From, To, Subject, Date, Message-ID, Return-Path, Reply-To, X-Originating-IP) and flag common mismatches.", tags: ["email", "headers", "message-id", "return-path", "phishing"],
    inputs: [{ k: "headers", label: "Raw headers", type: "textarea", rows: 10, placeholder: "From: Alice <alice@example.com>\nReturn-Path: <bounce@evil.example>\nSubject: Hi" }],
    run(v) {
      const text = String(v.headers || "").replace(/\r?\n[ \t]+/g, " "); if (!text.trim()) return "";
      const get = (name) => { const m = text.match(new RegExp("^" + name + ":\\s*(.+)$", "im")); return m ? m[1].trim() : ""; };
      const fields = ["From", "To", "Cc", "Reply-To", "Return-Path", "Sender", "Subject", "Date", "Message-ID", "X-Originating-IP", "X-Mailer", "Content-Type"];
      const got = fields.map((f) => [f, get(f)]).filter(([, val]) => val);
      if (!got.length) return { error: "No recognizable headers found." };
      const out = got.map(([f, val]) => `${f}: ${val}`);
      const fromDom = (get("From").match(/@([^\s>]+)/) || [])[1];
      const rpDom = (get("Return-Path").match(/@([^\s>]+)/) || [])[1];
      const notes = [];
      if (fromDom && rpDom && fromDom.toLowerCase() !== rpDom.toLowerCase()) notes.push(`From domain (${fromDom}) != Return-Path domain (${rpDom}) - check SPF alignment.`);
      const replyDom = (get("Reply-To").match(/@([^\s>]+)/) || [])[1];
      if (fromDom && replyDom && fromDom.toLowerCase() !== replyDom.toLowerCase()) notes.push(`Reply-To domain (${replyDom}) differs from From (${fromDom}).`);
      return out.join("\n") + (notes.length ? "\n\nNOTES:\n" + notes.map((n) => "- " + n).join("\n") : "");
    } },

  { id: "fx-dkim-parse", name: "DKIM-Signature Tag Parser", cat: "forensics", desc: "Break a DKIM-Signature header into its tags and explain them (v, a, d, s, c, bh, b, h, t, x), including the signing domain and selector.", tags: ["dkim", "signature", "selector", "email", "parser"],
    inputs: [{ k: "header", label: "DKIM-Signature", type: "textarea", rows: 5, placeholder: "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel1; h=from:to:subject; bh=...; b=..." }],
    run(v) {
      const t = String(v.header || "").replace(/\r?\n[ \t]+/g, " ").replace(/^dkim-signature:\s*/i, "").trim(); if (!t) return "";
      const names = { v: "Version", a: "Signing algorithm", d: "Signing domain (d=)", s: "Selector (DNS: <s>._domainkey.<d>)", c: "Canonicalization (header/body)", q: "Query method", bh: "Body hash", b: "Signature", h: "Signed header fields", t: "Signature timestamp (Unix)", x: "Expiration (Unix)", i: "Identity (AUID)", l: "Body length" };
      const tags = {};
      t.split(";").forEach((p) => { const m = p.trim().match(/^(\w+)=([\s\S]*)$/); if (m) tags[m[1]] = m[2].trim(); });
      if (!Object.keys(tags).length) return { error: "No DKIM tags found." };
      const out = Object.entries(tags).map(([k, val]) => { let shown = val; if ((k === "b" || k === "bh") && val.length > 24) shown = val.slice(0, 24) + "...(" + val.length + " chars)"; let x = ""; if ((k === "t" || k === "x") && /^\d+$/.test(val)) x = " -> " + new Date(Number(val) * 1000).toISOString(); return `${k.padEnd(3)} ${(names[k] || "?").padEnd(28)} ${shown}${x}`; });
      return out.join("\n");
    } },

  { id: "fx-smtp-status", name: "SMTP Status Code Reference", cat: "forensics", desc: "Look up an SMTP reply code (e.g. 550, 421, 250) and its meaning. Useful when reading mail logs and bounce (NDR) messages. Filter by code or keyword.", tags: ["smtp", "status", "550", "bounce", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "550" }],
    run(v) { return lookup(SMTP_CODES, v.q, ["Code", "Meaning"]); } },

  // --------------------------- LOGS ---------------------------
  { id: "fx-auth-log", name: "Linux auth.log (sshd) Parser", cat: "forensics", desc: "Parse Linux auth.log / secure lines from sshd and summarize failed and accepted logins: counts per source IP and per user, and invalid-user attempts.", tags: ["auth.log", "sshd", "linux", "bruteforce", "secure"],
    inputs: [{ k: "text", label: "auth.log lines", type: "textarea", rows: 10, placeholder: "Jan  1 10:00:01 host sshd[123]: Failed password for root from 198.51.100.7 port 54321 ssh2" }],
    run(v) {
      const lines = String(v.text || "").split(/\r?\n/).filter((l) => /sshd/i.test(l)); if (!lines.length) return String(v.text || "").trim() ? { error: "No sshd lines found." } : "";
      const failByIp = {}, failByUser = {}, accepted = []; let invalid = 0, failTotal = 0;
      for (const l of lines) {
        const ipm = l.match(/from\s+(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]+)/i); const ip = ipm ? ipm[1] : "?";
        if (/Failed password|authentication failure/i.test(l)) { failTotal++; failByIp[ip] = (failByIp[ip] || 0) + 1; const um = l.match(/for (?:invalid user )?(\S+) from/i); if (um) failByUser[um[1]] = (failByUser[um[1]] || 0) + 1; if (/invalid user/i.test(l)) invalid++; }
        else if (/Accepted (?:password|publickey)/i.test(l)) { const um = l.match(/for (\S+) from/i); accepted.push(`${um ? um[1] : "?"}@${ip} (${/publickey/i.test(l) ? "publickey" : "password"})`); }
      }
      const top = (o) => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([k, n]) => `  ${String(n).padStart(5)}  ${k}`).join("\n") || "  (none)";
      return [`Failed attempts: ${failTotal} (invalid user: ${invalid})`, `Accepted logins: ${accepted.length}`, ``, `Top source IPs (failed):`, top(failByIp), ``, `Top targeted users (failed):`, top(failByUser), ``, `Accepted logins:`, accepted.length ? accepted.map((a) => "  " + a).join("\n") : "  (none)"].join("\n");
    } },

  { id: "fx-syslog-parse", name: "Syslog Line Parser (RFC 3164 / 5424)", cat: "forensics", desc: "Parse a single syslog line in BSD (RFC 3164) or IETF (RFC 5424) format into its fields: priority, timestamp, host, app/tag, PID and message.", tags: ["syslog", "rfc3164", "rfc5424", "parser", "linux"],
    inputs: [{ k: "line", label: "Syslog line", type: "textarea", rows: 3, placeholder: "<34>1 2024-01-01T10:00:00Z host app 1234 ID47 - message" }],
    run(v) {
      let l = String(v.line || "").trim(); if (!l) return "";
      const out = [];
      const pm = l.match(/^<(\d{1,3})>/); if (pm) { const pri = parseInt(pm[1], 10); out.push(`PRI: ${pri}  (facility ${pri >> 3} = ${SYSLOG_FAC[pri >> 3] || "?"}, severity ${pri & 7} = ${SYSLOG_SEV[pri & 7] || "?"})`); l = l.slice(pm[0].length); }
      const v5 = l.match(/^(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:(\S+)\s+)?(.*)$/);
      if (v5 && v5[1] === "1") { out.push("Format: RFC 5424", `Timestamp: ${v5[2]}`, `Host: ${v5[3]}`, `App: ${v5[4]}`, `PID: ${v5[5]}`, `MsgID: ${v5[6]}`, `Message: ${v5[8] || ""}`); return out.join("\n"); }
      const v3 = l.match(/^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[\s]+)(?:\[(\d+)\])?:?\s*(.*)$/);
      if (v3) { out.push("Format: RFC 3164 (BSD)", `Timestamp: ${v3[1]}`, `Host: ${v3[2]}`, `Tag: ${v3[3]}`, `PID: ${v3[4] || "(none)"}`, `Message: ${v3[5]}`); return out.join("\n"); }
      out.push("Format: unrecognized; raw message:", l);
      return out.join("\n");
    } },

  { id: "fx-syslog-pri", name: "Syslog Priority (PRI) Decoder", cat: "forensics", desc: "Decode a syslog PRI value (0-191, e.g. <34>) into its facility and severity, or build the PRI from a facility and severity number.", tags: ["syslog", "pri", "facility", "severity", "decoder"],
    inputs: [{ k: "mode", label: "Mode", type: "select", opts: ["Decode PRI", "Build PRI"], value: "Decode PRI" }, { k: "pri", label: "PRI (decode)", type: "text", placeholder: "34" }, { k: "fac", label: "Facility (build, 0-23)", type: "text", placeholder: "4" }, { k: "sev", label: "Severity (build, 0-7)", type: "text", placeholder: "2" }],
    run(v) {
      if (v.mode === "Build PRI") { const f = parseInt(v.fac, 10), s = parseInt(v.sev, 10); if (!(f >= 0 && f <= 23) || !(s >= 0 && s <= 7)) return { error: "Facility 0-23 and severity 0-7." }; return `PRI = ${f * 8 + s}  (<${f * 8 + s}>)\nFacility ${f} = ${SYSLOG_FAC[f]}\nSeverity ${s} = ${SYSLOG_SEV[s]}`; }
      const p = parseInt(String(v.pri || "").replace(/[<>]/g, ""), 10); if (!(p >= 0 && p <= 191)) return v.pri ? { error: "PRI must be 0-191." } : "";
      return `PRI ${p}\nFacility ${p >> 3} = ${SYSLOG_FAC[p >> 3]}\nSeverity ${p & 7} = ${SYSLOG_SEV[p & 7]}`;
    } },

  { id: "fx-journald-json", name: "journald JSON Entry Parser", cat: "forensics", desc: "Parse a journald log entry in JSON format (journalctl -o json) and decode its key fields: __REALTIME_TIMESTAMP (microseconds), PRIORITY, _PID, _COMM, unit and MESSAGE.", tags: ["journald", "systemd", "journalctl", "json", "linux"],
    inputs: [{ k: "json", label: "journald JSON line", type: "textarea", rows: 5, placeholder: '{"__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"6","_COMM":"sshd","MESSAGE":"Accepted publickey"}' }],
    run(v) {
      const t = String(v.json || "").trim(); if (!t) return "";
      let o; try { o = JSON.parse(t); } catch (e) { return { error: "Not valid JSON." }; }
      const out = [];
      if (o.__REALTIME_TIMESTAMP) { const us = Number(o.__REALTIME_TIMESTAMP); const d = new Date(us / 1000); out.push(`Time: ${isNaN(d.getTime()) ? o.__REALTIME_TIMESTAMP : d.toISOString()} (realtime)`); }
      if (o.PRIORITY != null) { const p = parseInt(o.PRIORITY, 10); out.push(`Priority: ${p} = ${SYSLOG_SEV[p] || "?"}`); }
      for (const [k, label] of [["_HOSTNAME", "Host"], ["_COMM", "Command"], ["_PID", "PID"], ["_UID", "UID"], ["_SYSTEMD_UNIT", "Unit"], ["SYSLOG_IDENTIFIER", "Identifier"], ["_EXE", "Executable"]]) if (o[k] != null) out.push(`${label}: ${o[k]}`);
      if (o.MESSAGE != null) out.push(`Message: ${Array.isArray(o.MESSAGE) ? o.MESSAGE.join("") : o.MESSAGE}`);
      return out.length ? out.join("\n") : "No recognized journald fields in that object.";
    } },

  { id: "fx-apache-log", name: "Access Log Line Parser (Combined/Common)", cat: "forensics", desc: "Parse one Apache/Nginx access log line in Common or Combined Log Format into fields: client IP, user, timestamp, method, path, protocol, status, size, referer and user agent.", tags: ["apache", "nginx", "access log", "combined", "clf"],
    inputs: [{ k: "line", label: "Access log line", type: "textarea", rows: 3, placeholder: '198.51.100.7 - - [01/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "curl/8.0"' }],
    run(v) {
      const l = String(v.line || "").trim(); if (!l) return "";
      const m = l.match(/^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?/);
      if (!m) return { error: "Line does not match Common/Combined Log Format." };
      const req = m[5].split(/\s+/);
      return [`Client IP:  ${m[1]}`, `Ident/User: ${m[2]} / ${m[3]}`, `Time:       ${m[4]}`, `Method:     ${req[0] || "?"}`, `Path:       ${req[1] || "?"}`, `Protocol:   ${req[2] || "?"}`, `Status:     ${m[6]}`, `Size:       ${m[7]} bytes`, `Referer:    ${m[8] || "(not logged)"}`, `User-Agent: ${m[9] || "(not logged)"}`].join("\n");
    } },

  { id: "fx-access-analyze", name: "Access Log Analyzer", cat: "forensics", desc: "Analyze a whole block of Apache/Nginx access log lines: top client IPs, status-code distribution, top requested paths, and a heuristic scan for suspicious requests (traversal, SQLi, common shells).", tags: ["access log", "analyze", "top ips", "status", "suspicious"],
    inputs: [{ k: "text", label: "Access log", type: "textarea", rows: 12, placeholder: "paste many access log lines..." }],
    run(v) {
      const lines = String(v.text || "").split(/\r?\n/).filter((l) => l.trim()); if (!lines.length) return "";
      const ips = {}, status = {}, paths = {}, susp = [];
      const suspRe = /(\.\.(?:\/|%2f)|\/etc\/passwd|union(?:\s|\+|%20)+select|<script|\betc\b.*\bpasswd\b|cmd\.exe|\/bin\/sh|\bselect\b.*\bfrom\b|%00|\bbase64_decode\b|wp-login|phpmyadmin|\.env\b|\/\.git)/i;
      let parsed = 0;
      for (const l of lines) {
        const m = l.match(/^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)/); if (!m) continue; parsed++;
        ips[m[1]] = (ips[m[1]] || 0) + 1; status[m[4]] = (status[m[4]] || 0) + 1;
        const path = (m[3].split(/\s+/)[1] || "").split("?")[0]; if (path) paths[path] = (paths[path] || 0) + 1;
        if (suspRe.test(m[3])) susp.push(`${m[1]}  ${m[4]}  ${m[3].slice(0, 100)}`);
      }
      if (!parsed) return { error: "No parseable access log lines found." };
      const top = (o, n) => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, n).map(([k, c]) => `  ${String(c).padStart(6)}  ${k}`).join("\n");
      return [`Parsed ${parsed} of ${lines.length} lines`, ``, `Top client IPs:`, top(ips, 10), ``, `Status codes:`, top(status, 20), ``, `Top paths:`, top(paths, 15), ``, `Suspicious requests (${susp.length}):`, susp.length ? susp.slice(0, 30).map((s) => "  " + s).join("\n") : "  (none matched the heuristics)"].join("\n");
    } },

  { id: "fx-apache-error", name: "Apache error.log Parser", cat: "forensics", desc: "Parse an Apache 2.4 error.log line into fields: timestamp, module:level, process/thread id, client, and message.", tags: ["apache", "error log", "httpd", "parser"],
    inputs: [{ k: "line", label: "error.log line", type: "textarea", rows: 3, placeholder: "[Mon Jan 01 10:00:00.123456 2024] [core:error] [pid 1234:tid 5678] [client 198.51.100.7:54321] File does not exist: /var/www/x" }],
    run(v) {
      const l = String(v.line || "").trim(); if (!l) return "";
      const m = l.match(/^\[([^\]]+)\]\s+\[([^\]]+)\]\s+(?:\[pid\s+([^\]]+)\]\s+)?(?:\[client\s+([^\]]+)\]\s+)?(.*)$/);
      if (!m) return { error: "Does not look like an Apache 2.4 error.log line." };
      const ml = m[2].split(":");
      return [`Timestamp: ${m[1]}`, `Module:    ${ml[0]}`, `Level:     ${ml[1] || "(none)"}`, `PID/TID:   ${m[3] || "(not logged)"}`, `Client:    ${m[4] || "(not logged)"}`, `Message:   ${m[5]}`].join("\n");
    } },

  { id: "fx-cef-parse", name: "CEF (Common Event Format) Parser", cat: "forensics", desc: "Parse an ArcSight CEF log line into its header fields (version, vendor, product, signature, name, severity) and the key=value extension pairs.", tags: ["cef", "arcsight", "siem", "log", "parser"],
    inputs: [{ k: "line", label: "CEF line", type: "textarea", rows: 4, placeholder: "CEF:0|Security|Firewall|1.0|100|Blocked connection|5|src=198.51.100.7 dst=192.0.2.9 spt=1234" }],
    run(v) {
      const l = String(v.line || "").trim(); if (!l) return "";
      const idx = l.indexOf("CEF:"); if (idx < 0) return { error: "No CEF: prefix found." };
      const body = l.slice(idx + 4);
      // split header on unescaped pipes (max 7 parts, 8th = extension)
      const parts = []; let cur = "";
      for (let i = 0; i < body.length; i++) { if (body[i] === "\\" && i + 1 < body.length) { cur += body[i] + body[i + 1]; i++; } else if (body[i] === "|" && parts.length < 7) { parts.push(cur); cur = ""; } else cur += body[i]; }
      parts.push(cur);
      if (parts.length < 7) return { error: "CEF header incomplete (need 7 pipe-separated fields)." };
      const [ver, vendor, product, pver, sig, name, sev] = parts;
      const ext = parts[7] || "";
      const pairs = [];
      const re = /([A-Za-z][A-Za-z0-9]*)=((?:[^\\]|\\.)*?)(?=\s+[A-Za-z][A-Za-z0-9]*=|$)/g; let mm;
      while ((mm = re.exec(ext)) !== null) pairs.push(`  ${mm[1]} = ${mm[2].trim()}`);
      return [`CEF version:   ${ver}`, `Device vendor: ${vendor}`, `Device product:${product}`, `Device version:${pver}`, `Signature ID:  ${sig}`, `Name:          ${name}`, `Severity:      ${sev}`, ``, `Extensions:`, pairs.length ? pairs.join("\n") : "  (none)"].join("\n");
    } },

  { id: "fx-leef-parse", name: "LEEF (Log Event Extended Format) Parser", cat: "forensics", desc: "Parse an IBM QRadar LEEF log line into its header (version, vendor, product, event id) and the key=value attributes, handling both LEEF 1.0 and 2.0 (custom delimiter).", tags: ["leef", "qradar", "ibm", "siem", "parser"],
    inputs: [{ k: "line", label: "LEEF line", type: "textarea", rows: 4, placeholder: "LEEF:2.0|Vendor|Product|1.0|EventID|^|src=198.51.100.7^dst=192.0.2.9^sev=5" }],
    run(v) {
      const l = String(v.line || "").trim(); if (!l) return "";
      const idx = l.indexOf("LEEF:"); if (idx < 0) return { error: "No LEEF: prefix found." };
      const parts = l.slice(idx + 5).split("|");
      const ver = parts[0];
      let delim = "\t", headerCount = 4;
      if (ver.startsWith("2")) { headerCount = 5; if (parts[5] != null && parts[5].length) { let d = parts[5]; if (/^0x[0-9a-f]+$/i.test(d)) d = String.fromCharCode(parseInt(d, 16)); delim = d; } }
      const ext = parts.slice(headerCount + (ver.startsWith("2") ? 1 : 0)).join("|");
      const pairs = ext.split(delim).filter(Boolean).map((p) => { const e = p.indexOf("="); return e < 0 ? "  " + p : `  ${p.slice(0, e)} = ${p.slice(e + 1)}`; });
      return [`LEEF version:  ${ver}`, `Vendor:        ${parts[1] || ""}`, `Product:       ${parts[2] || ""}`, `Version:       ${parts[3] || ""}`, `Event ID:      ${parts[4] || ""}`, ver.startsWith("2") ? `Delimiter:     ${JSON.stringify(delim)}` : "", ``, `Attributes:`, pairs.length ? pairs.join("\n") : "  (none)"].filter((x) => x !== "").join("\n");
    } },

  { id: "fx-cloudtrail", name: "AWS CloudTrail Record Reader", cat: "forensics", desc: "Parse a single AWS CloudTrail event record (JSON) and surface the key investigative fields: time, event name/source, region, source IP, user identity and any error code.", tags: ["cloudtrail", "aws", "cloud", "json", "iam"],
    inputs: [{ k: "json", label: "CloudTrail record (JSON)", type: "textarea", rows: 8, placeholder: '{"eventTime":"2024-01-01T10:00:00Z","eventName":"ConsoleLogin","eventSource":"signin.amazonaws.com","sourceIPAddress":"198.51.100.7","userIdentity":{"type":"IAMUser","userName":"alice","accountId":"123456789012"}}' }],
    run(v) {
      const t = String(v.json || "").trim(); if (!t) return "";
      let o; try { o = JSON.parse(t); } catch (e) { return { error: "Not valid JSON." }; }
      const ui = o.userIdentity || {};
      const out = [
        `Event time:   ${o.eventTime || "?"}`,
        `Event name:   ${o.eventName || "?"}`,
        `Event source: ${o.eventSource || "?"}`,
        `Region:       ${o.awsRegion || "?"}`,
        `Source IP:    ${o.sourceIPAddress || "?"}`,
        `User agent:   ${o.userAgent || "?"}`,
        `Identity:     ${ui.type || "?"}${ui.userName ? " / " + ui.userName : ""}${ui.arn ? "\n  ARN: " + ui.arn : ""}${ui.accountId ? "\n  Account: " + ui.accountId : ""}`,
        o.errorCode ? `Error:        ${o.errorCode} - ${o.errorMessage || ""}` : "",
        o.requestParameters ? `Request params: ${Object.keys(o.requestParameters).join(", ")}` : "",
        o.readOnly != null ? `Read only:    ${o.readOnly}` : "",
      ].filter(Boolean);
      return out.join("\n");
    } },

  // --------------------------- IOC ---------------------------
  { id: "fx-ioc-extract", name: "IOC Extractor", cat: "forensics", desc: "Pull indicators of compromise from a block of text: IPv4/IPv6 addresses, domains, URLs, email addresses, MD5/SHA-1/SHA-256 hashes and CVE IDs. Understands defanged input (hxxp, [.]).", tags: ["ioc", "extract", "indicators", "hashes", "domains"],
    inputs: [{ k: "text", label: "Input text", type: "textarea", rows: 8, placeholder: "contacted hxxp://evil[.]example/a from 198.51.100.7, hash 44d88612fea8a8f36de82e1278abb02f" }, { k: "refang", label: "Refang before extracting", type: "checkbox", value: true }],
    run(v) {
      let text = String(v.text || ""); if (!text.trim()) return "";
      if (v.refang) text = text.replace(/\[\.\]|\(\.\)|\{\.\}/g, ".").replace(/\[:\]/g, ":").replace(/h(?:xx|XX)p(s?):\/\//gi, "http$1://").replace(/\[(dot)\]/gi, ".").replace(/\[(at)\]/gi, "@");
      const uniq = (arr) => Array.from(new Set(arr));
      const find = (re) => uniq((text.match(re) || []));
      const ipv4 = find(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g);
      const sha256 = find(/\b[a-fA-F0-9]{64}\b/g), sha1 = find(/\b[a-fA-F0-9]{40}\b/g), md5 = find(/\b[a-fA-F0-9]{32}\b/g);
      const urls = find(/\bhttps?:\/\/[^\s"'<>]+/gi);
      const emails = find(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g);
      const cves = find(/\bCVE-\d{4}-\d{4,7}\b/gi);
      const ipv6 = find(/\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b/g).filter((x) => x.includes("::") || x.split(":").length >= 4);
      const domains = uniq((text.match(/\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g) || []).filter((d) => !emails.some((e) => e.endsWith(d)) && !ipv4.includes(d)));
      const sect = (name, arr) => arr.length ? `${name} (${arr.length}):\n` + arr.map((x) => "  " + x).join("\n") : "";
      const parts = [sect("URLs", urls), sect("IPv4", ipv4), sect("IPv6", ipv6), sect("Domains", domains), sect("Emails", emails), sect("MD5", md5), sect("SHA-1", sha1), sect("SHA-256", sha256), sect("CVEs", cves)].filter(Boolean);
      return parts.length ? parts.join("\n\n") : "No indicators found.";
    } },

  { id: "fx-defang", name: "IOC Defanger", cat: "forensics", desc: "Defang indicators so they cannot be accidentally clicked or auto-linked: http -> hxxp, dots -> [.], @ -> [at]. Safe to paste into reports and tickets.", tags: ["defang", "ioc", "safe", "report", "neutralize"],
    inputs: [{ k: "text", label: "Input", type: "textarea", rows: 5, placeholder: "http://evil.example/path and bad@evil.example" }],
    run(v) {
      let t = String(v.text || ""); if (!t) return "";
      return t.replace(/https?:\/\//gi, (m) => m.replace(/^http/i, "hxxp")).replace(/\./g, "[.]").replace(/@/g, "[at]");
    } },

  { id: "fx-refang", name: "IOC Refanger", cat: "forensics", desc: "Reverse common defanging so indicators become real again for analysis: hxxp -> http, [.] -> dot, [at] -> @. Only run on values you intend to resolve.", tags: ["refang", "ioc", "unfang", "restore"],
    inputs: [{ k: "text", label: "Input", type: "textarea", rows: 5, placeholder: "hxxp://evil[.]example/path and bad[at]evil[.]example" }],
    run(v) {
      let t = String(v.text || ""); if (!t) return "";
      return t.replace(/\[:\/\/\]|\(:\/\/\)/g, "://").replace(/h(?:xx|XX)p(s?)/gi, "http$1").replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, ".").replace(/\[at\]|\(at\)/gi, "@").replace(/\[:\]/g, ":");
    } },

  { id: "fx-url-decode-recursive", name: "Recursive URL Decoder", cat: "forensics", desc: "Repeatedly percent-decode a URL or parameter until it stops changing, revealing multi-layer (double/triple) encoding often used to evade filters. Shows each pass.", tags: ["url decode", "recursive", "double encode", "evasion", "percent"],
    inputs: [{ k: "text", label: "Encoded input", type: "textarea", rows: 3, placeholder: "%252e%252e%252fetc%252fpasswd" }, { k: "max", label: "Max passes", type: "text", value: "6" }],
    run(v) {
      let s = String(v.text || ""); if (!s) return "";
      const max = Math.min(20, Math.max(1, parseInt(v.max, 10) || 6));
      const steps = [s]; let cur = s;
      for (let i = 0; i < max; i++) { let next; try { next = decodeURIComponent(cur.replace(/\+/g, "%20")); } catch (e) { break; } if (next === cur) break; steps.push(next); cur = next; }
      if (steps.length === 1) return `(no percent-encoding to decode)\n${s}`;
      return steps.map((v2, i) => `pass ${i}: ${v2}`).join("\n") + `\n\nFully decoded:\n${cur}`;
    } },

  // --------------------------- EVIDENCE ---------------------------
  { id: "fx-hash-manifest", name: "Evidence Hash Manifest Builder", cat: "forensics", desc: "Turn a list of 'hash  filename' (sha256sum style) or 'filename=hash' lines into a tidy evidence manifest, auto-identifying each hash algorithm by length and counting entries.", tags: ["manifest", "hashes", "evidence", "sha256sum", "integrity"],
    inputs: [{ k: "text", label: "Hash lines", type: "textarea", rows: 8, placeholder: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  evidence1.bin" }, { k: "case", label: "Case / label (optional)", type: "text", placeholder: "CASE-2024-001" }],
    run(v) {
      const lines = String(v.text || "").split(/\r?\n/).map((l) => l.trim()).filter(Boolean); if (!lines.length) return "";
      const byLen = { 8: "CRC32", 32: "MD5", 40: "SHA-1", 56: "SHA-224", 64: "SHA-256", 96: "SHA-384", 128: "SHA-512" };
      const rows = [];
      for (const l of lines) {
        let hash = "", file = "";
        let m = l.match(/^([0-9a-fA-F]{8,128})[\s*]+(.+)$/);
        if (m) { hash = m[1]; file = m[2].trim(); }
        else { m = l.match(/^(.+?)\s*[=:]\s*([0-9a-fA-F]{8,128})$/); if (m) { file = m[1].trim(); hash = m[2]; } }
        if (!hash) { rows.push(["?", "(unparsed)", l]); continue; }
        rows.push([byLen[hash.length] || `${hash.length * 4}-bit`, file.replace(/^[*]/, ""), hash.toLowerCase()]);
      }
      const head = v.case ? `Evidence Hash Manifest - ${v.case}\nGenerated (UTC): ${new Date().toISOString()}\nItems: ${rows.length}\n` : `Evidence Hash Manifest\nItems: ${rows.length}\n`;
      return head + "\n" + lookup(rows, "", ["Algorithm", "File", "Hash"]);
    } },

  { id: "fx-chain-of-custody", name: "Chain-of-Custody Record Generator", cat: "forensics", desc: "Produce a formatted chain-of-custody form from the case and evidence details you provide (item, description, collector, date/time, location, acquisition method and hash). A documentation aid, not legal advice.", tags: ["chain of custody", "evidence", "coc", "documentation"],
    inputs: [
      { k: "caseNo", label: "Case number", type: "text", placeholder: "CASE-2024-001" },
      { k: "item", label: "Evidence item ID", type: "text", placeholder: "ITEM-01" },
      { k: "desc", label: "Description", type: "text", placeholder: "Dell laptop, service tag ABC123" },
      { k: "collectedBy", label: "Collected by", type: "text", placeholder: "J. Analyst" },
      { k: "when", label: "Collected (UTC)", type: "text", placeholder: "2024-01-01T10:00:00Z" },
      { k: "where", label: "Location", type: "text", placeholder: "Suite 400, example.com HQ" },
      { k: "method", label: "Acquisition method", type: "text", placeholder: "Write-blocked dd image to external SSD" },
      { k: "hash", label: "Image hash", type: "text", placeholder: "sha256: e3b0c442..." },
      { k: "notes", label: "Notes", type: "textarea", rows: 2, placeholder: "Powered off at seizure." },
    ],
    run(v) {
      if (!v.caseNo && !v.item && !v.desc) return "";
      const row = (k, val) => `${(k + ":").padEnd(22)}${val || "________________________"}`;
      return [
        "CHAIN OF CUSTODY RECORD",
        "=======================",
        row("Case number", v.caseNo),
        row("Evidence item ID", v.item),
        row("Description", v.desc),
        row("Collected by", v.collectedBy),
        row("Date/Time (UTC)", v.when),
        row("Location", v.where),
        row("Acquisition method", v.method),
        row("Integrity hash", v.hash),
        row("Notes", v.notes),
        "",
        "TRANSFER LOG",
        "Date/Time (UTC)      Released by            Received by            Purpose",
        "-------------------  ---------------------  ---------------------  --------------------",
        "____________________  _____________________  _____________________  ____________________",
        "____________________  _____________________  _____________________  ____________________",
        "____________________  _____________________  _____________________  ____________________",
      ].join("\n");
    } },

  // --------------------------- REFERENCE ---------------------------
  { id: "fx-exif-tags", name: "EXIF Tag Reference", cat: "forensics", desc: "Look up an EXIF tag by its hex id (e.g. 0x9003 = DateTimeOriginal) or by name. Covers the common image/camera tags. Filter with any text.", tags: ["exif", "tag", "metadata", "camera", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "0x9003" }],
    run(v) { return lookup(EXIF_TAGS, v.q, ["Tag ID", "Name"]); } },

  { id: "fx-exif-orientation", name: "EXIF Orientation Decoder", cat: "forensics", desc: "Explain an EXIF Orientation value (1-8), which tells software how to rotate/flip a photo for correct display. Enter a value or list all.", tags: ["exif", "orientation", "rotate", "photo", "reference"],
    inputs: [{ k: "q", label: "Value (1-8) or blank for all", type: "text", placeholder: "6" }],
    run(v) {
      const rows = [
        ["1", "0 degrees (normal)", "No transform"],
        ["2", "Mirrored horizontally", "Flip left-right"],
        ["3", "Rotated 180 degrees", ""],
        ["4", "Mirrored vertically", "Flip top-bottom"],
        ["5", "Mirror horizontal + rotate 270 CW", ""],
        ["6", "Rotate 90 CW", "Camera held rotated clockwise"],
        ["7", "Mirror horizontal + rotate 90 CW", ""],
        ["8", "Rotate 270 CW (90 CCW)", "Camera held rotated counter-clockwise"],
      ];
      return lookup(rows, v.q, ["Value", "Display orientation", "Note"]);
    } },

  { id: "fx-gps-coord", name: "EXIF GPS Coordinate Converter", cat: "forensics", desc: "Convert between EXIF-style degrees/minutes/seconds (with N/S/E/W reference) and signed decimal degrees, to map a photo's recorded location.", tags: ["gps", "exif", "coordinates", "dms", "geolocation"],
    inputs: [
      { k: "mode", label: "Mode", type: "select", opts: ["DMS to Decimal", "Decimal to DMS"], value: "DMS to Decimal" },
      { k: "deg", label: "Degrees (DMS)", type: "text", placeholder: "37" },
      { k: "min", label: "Minutes (DMS)", type: "text", placeholder: "48" },
      { k: "sec", label: "Seconds (DMS)", type: "text", placeholder: "30" },
      { k: "ref", label: "Reference", type: "select", opts: ["N", "S", "E", "W"], value: "N" },
      { k: "dec", label: "Decimal degrees", type: "text", placeholder: "-37.808333" },
      { k: "axis", label: "Axis (for decimal input)", type: "select", opts: ["Latitude", "Longitude"], value: "Latitude" },
    ],
    run(v) {
      if (v.mode === "DMS to Decimal") {
        const d = Number(v.deg || 0), m = Number(v.min || 0), s = Number(v.sec || 0);
        if ([d, m, s].some((x) => !isFinite(x))) return { error: "Enter numeric degrees/minutes/seconds." };
        let dec = d + m / 60 + s / 3600; if (v.ref === "S" || v.ref === "W") dec = -dec;
        return `Decimal: ${dec.toFixed(6)} (${v.ref})`;
      }
      const dec = Number(v.dec); if (!isFinite(dec)) return v.dec ? { error: "Enter a decimal number." } : "";
      const abs = Math.abs(dec); const d = Math.floor(abs); const mF = (abs - d) * 60; const m = Math.floor(mF); const s = (mF - m) * 60;
      const ref = v.axis === "Latitude" ? (dec < 0 ? "S" : "N") : (dec < 0 ? "W" : "E");
      return `${d} deg ${m}' ${s.toFixed(3)}" ${ref}`;
    } },

  { id: "fx-attack-tactics", name: "MITRE ATT&CK Tactics Reference", cat: "forensics", desc: "Look up the 14 MITRE ATT&CK (Enterprise) tactics by ID (e.g. TA0001) or name, with a short description of each attacker goal. Filter with any text.", tags: ["mitre", "att&ck", "tactics", "ttps", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "persistence" }],
    run(v) { return lookup(ATTACK_TACTICS, v.q, ["ID", "Tactic", "Goal"]); } },

  { id: "fx-stat-mode", name: "Unix File Mode (st_mode) Decoder", cat: "forensics", desc: "Decode a Unix st_mode value (e.g. 100755 or 0o40755 from stat metadata) into the file type, an ls-style permission string, and the setuid/setgid/sticky bits.", tags: ["stat", "st_mode", "permissions", "unix", "inode"],
    inputs: [{ k: "val", label: "Mode (octal)", type: "text", placeholder: "100755" }],
    run(v) {
      let t = String(v.val || "").trim().replace(/^0o/i, ""); if (!t) return "";
      if (!/^[0-7]+$/.test(t)) return { error: "Enter an octal number (e.g. 100755)." };
      const mode = parseInt(t, 8);
      const types = { 0o140000: ["socket", "s"], 0o120000: ["symbolic link", "l"], 0o100000: ["regular file", "-"], 0o060000: ["block device", "b"], 0o040000: ["directory", "d"], 0o020000: ["character device", "c"], 0o010000: ["FIFO/pipe", "p"] };
      const tbits = mode & 0o170000; const ty = types[tbits] || ["unknown", "?"];
      const perm = mode & 0o777; const special = mode & 0o7000;
      let str = ""; const rwx = ["---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"];
      str = rwx[(perm >> 6) & 7] + rwx[(perm >> 3) & 7] + rwx[perm & 7];
      let arr = str.split("");
      if (special & 0o4000) arr[2] = arr[2] === "x" ? "s" : "S";
      if (special & 0o2000) arr[5] = arr[5] === "x" ? "s" : "S";
      if (special & 0o1000) arr[8] = arr[8] === "x" ? "t" : "T";
      const specialNames = []; if (special & 0o4000) specialNames.push("setuid"); if (special & 0o2000) specialNames.push("setgid"); if (special & 0o1000) specialNames.push("sticky");
      return [`File type:   ${ty[0]}`, `ls -l form:  ${ty[1]}${arr.join("")}`, `Permissions: ${perm.toString(8).padStart(3, "0")} (octal)`, `Special:     ${specialNames.length ? specialNames.join(", ") : "(none)"}`].join("\n");
    } },

  // --------------------------- DFIR COMMAND BUILDERS ---------------------------
  { id: "fx-volatility", name: "Volatility Command Builder", cat: "forensics", desc: "Build a Volatility memory-analysis command for Volatility 3 or 2, choosing a common plugin (pslist, netscan, malfind, etc.) with the right syntax for the version.", tags: ["volatility", "memory", "forensics", "plugin", "builder"],
    inputs: [
      { k: "ver", label: "Version", type: "select", opts: ["Volatility 3", "Volatility 2"], value: "Volatility 3" },
      { k: "image", label: "Memory image path", type: "text", placeholder: "/cases/mem.raw" },
      { k: "plugin", label: "Plugin", type: "select", opts: ["Process list", "Process tree", "Command line", "Network connections", "Loaded DLLs", "Injected code (malfind)", "Handles", "Registry hive list", "Hashdump (SAM)", "File scan", "Services"], value: "Process list" },
      { k: "profile", label: "Profile (Vol2 only)", type: "text", placeholder: "Win7SP1x64" },
    ],
    run(v) {
      const img = v.image || "<image>";
      const map3 = { "Process list": "windows.pslist.PsList", "Process tree": "windows.pstree.PsTree", "Command line": "windows.cmdline.CmdLine", "Network connections": "windows.netscan.NetScan", "Loaded DLLs": "windows.dlllist.DllList", "Injected code (malfind)": "windows.malfind.Malfind", "Handles": "windows.handles.Handles", "Registry hive list": "windows.registry.hivelist.HiveList", "Hashdump (SAM)": "windows.hashdump.Hashdump", "File scan": "windows.filescan.FileScan", "Services": "windows.svcscan.SvcScan" };
      const map2 = { "Process list": "pslist", "Process tree": "pstree", "Command line": "cmdline", "Network connections": "netscan", "Loaded DLLs": "dlllist", "Injected code (malfind)": "malfind", "Handles": "handles", "Registry hive list": "hivelist", "Hashdump (SAM)": "hashdump", "File scan": "filescan", "Services": "svcscan" };
      if (v.ver === "Volatility 3") return `vol -f ${img} ${map3[v.plugin]}`;
      const prof = v.profile || "<profile>";
      return `vol.py -f ${img} --profile=${prof} ${map2[v.plugin]}\n\n(Tip: run 'vol.py -f ${img} imageinfo' first to find the profile.)`;
    } },

  { id: "fx-plaso", name: "Plaso / log2timeline Command Builder", cat: "forensics", desc: "Build a Plaso super-timeline command: collect events with log2timeline.py into a .plaso store, filter and output with psort.py, or do it all in one pass with psteal.py.", tags: ["plaso", "log2timeline", "psort", "psteal", "timeline"],
    inputs: [
      { k: "step", label: "Step", type: "select", opts: ["Collect (log2timeline)", "Output (psort)", "All-in-one (psteal)"], value: "Collect (log2timeline)" },
      { k: "source", label: "Source (image/dir)", type: "text", placeholder: "/cases/disk.e01" },
      { k: "store", label: ".plaso storage file", type: "text", placeholder: "/cases/timeline.plaso" },
      { k: "out", label: "Output format (psort/psteal)", type: "select", opts: ["l2tcsv", "dynamic", "json_line", "elastic"], value: "l2tcsv" },
      { k: "tz", label: "Timezone", type: "text", value: "UTC" },
    ],
    run(v) {
      const store = v.store || "timeline.plaso", src = v.source || "<source>";
      if (v.step === "Collect (log2timeline)") return `log2timeline.py --storage-file ${store} --timezone ${v.tz || "UTC"} ${src}`;
      if (v.step === "Output (psort)") return `psort.py -o ${v.out} -w timeline.${v.out === "l2tcsv" ? "csv" : "txt"} ${store}`;
      return `psteal.py --source ${src} -o ${v.out} -w timeline.${v.out === "l2tcsv" ? "csv" : "txt"} --timezone ${v.tz || "UTC"}`;
    } },

  { id: "fx-dd-builder", name: "Forensic Imaging (dd) Command Builder", cat: "forensics", desc: "Build a dd or dcfldd command to image a device to a raw file for forensic analysis, with block size and optional hashing/progress. Always image through a write-blocker.", tags: ["dd", "dcfldd", "imaging", "acquisition", "builder"],
    inputs: [
      { k: "tool", label: "Tool", type: "select", opts: ["dd", "dcfldd"], value: "dcfldd" },
      { k: "src", label: "Source device", type: "text", placeholder: "/dev/sdb" },
      { k: "dst", label: "Output image", type: "text", placeholder: "/cases/disk.img" },
      { k: "bs", label: "Block size", type: "text", value: "4M" },
      { k: "hash", label: "Hash while imaging", type: "select", opts: ["none", "md5", "sha256", "md5,sha256"], value: "sha256" },
    ],
    run(v) {
      const src = v.src || "/dev/<src>", dst = v.dst || "<image>";
      if (v.tool === "dcfldd") { let c = `dcfldd if=${src} of=${dst} bs=${v.bs || "4M"}`; if (v.hash !== "none") c += ` hash=${v.hash} hashlog=${dst}.hashlog`; return c + `\n\n(dcfldd shows progress and logs hashes automatically.)`; }
      let c = `dd if=${src} of=${dst} bs=${v.bs || "4M"} conv=noerror,sync status=progress`;
      const post = v.hash === "none" ? "" : "\n\nThen verify:\n" + v.hash.split(",").map((h) => `${h}sum ${dst}`).join("\n");
      return c + post;
    } },

  { id: "fx-tsk-builder", name: "Sleuth Kit Command Builder", cat: "forensics", desc: "Build a common Sleuth Kit command (mmls, fsstat, fls, icat, istat) for examining a disk image, filling in the image, offset and inode as needed.", tags: ["sleuthkit", "tsk", "fls", "icat", "mmls"],
    inputs: [
      { k: "tool", label: "Tool", type: "select", opts: ["mmls (partitions)", "fsstat (fs details)", "fls (list files)", "icat (extract by inode)", "istat (inode details)"], value: "fls (list files)" },
      { k: "image", label: "Image path", type: "text", placeholder: "/cases/disk.img" },
      { k: "offset", label: "Partition offset (sectors)", type: "text", placeholder: "2048" },
      { k: "inode", label: "Inode (icat/istat)", type: "text", placeholder: "64-128-1" },
    ],
    run(v) {
      const img = v.image || "<image>"; const off = v.offset ? ` -o ${v.offset}` : "";
      switch (v.tool) {
        case "mmls (partitions)": return `mmls ${img}`;
        case "fsstat (fs details)": return `fsstat${off} ${img}`;
        case "fls (list files)": return `fls -r -p${off} ${img}\n\n(-r recursive, -p full paths; add -d for deleted only.)`;
        case "icat (extract by inode)": return `icat${off} ${img} ${v.inode || "<inode>"} > extracted.bin`;
        case "istat (inode details)": return `istat${off} ${img} ${v.inode || "<inode>"}`;
        default: return "";
      }
    } },

  { id: "fx-yara-rule", name: "YARA Rule Builder", cat: "forensics", desc: "Generate a well-formed YARA detection rule from text and/or hex strings you supply, with a meta block and a configurable match condition (any/all).", tags: ["yara", "detection", "rule", "strings", "builder"],
    inputs: [
      { k: "name", label: "Rule name", type: "text", placeholder: "Suspicious_Dropper" },
      { k: "author", label: "Author", type: "text", placeholder: "analyst" },
      { k: "textStrings", label: "Text strings (one per line)", type: "textarea", rows: 4, placeholder: "cmd.exe /c\nInvoke-Expression" },
      { k: "hexStrings", label: "Hex strings (one per line)", type: "textarea", rows: 2, placeholder: "4D 5A 90 00" },
      { k: "cond", label: "Condition", type: "select", opts: ["any of them", "all of them", "2 of them"], value: "any of them" },
      { k: "nocase", label: "Text case-insensitive", type: "checkbox", value: true },
    ],
    run(v) {
      const name = (v.name || "rule_name").replace(/[^A-Za-z0-9_]/g, "_").replace(/^(\d)/, "_$1");
      const strs = [];
      let i = 0;
      String(v.textStrings || "").split(/\r?\n/).map((s) => s.trim()).filter(Boolean).forEach((s) => { strs.push(`        $s${i++} = "${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"${v.nocase ? " nocase" : ""} ascii wide`); });
      String(v.hexStrings || "").split(/\r?\n/).map((s) => s.trim()).filter(Boolean).forEach((s) => { const h = s.replace(/[^0-9a-fA-F?]/g, " ").trim().replace(/\s+/g, " "); if (h) strs.push(`        $h${i++} = { ${h} }`); });
      if (!strs.length) return v.name ? { error: "Add at least one text or hex string." } : "";
      return [
        `rule ${name}`,
        `{`,
        `    meta:`,
        `        author = "${(v.author || "unknown").replace(/"/g, "'")}"`,
        `        date = "${new Date().toISOString().slice(0, 10)}"`,
        `        description = "Auto-generated YARA rule"`,
        ``,
        `    strings:`,
        strs.join("\n"),
        ``,
        `    condition:`,
        `        ${v.cond}`,
        `}`,
      ].join("\n");
    } },
];
