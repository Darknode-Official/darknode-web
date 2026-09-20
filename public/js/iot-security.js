// IoT & Industrial Control System Security Engine
// Protocol analyzers, firmware analysis, vulnerability database, default credentials
// All functions are pure browser-compatible ES modules.

// ═══════════════════════════════════════════════════════════════════
// MQTT PACKET PARSER
// ═══════════════════════════════════════════════════════════════════

export const MQTT_PACKET_TYPES = {
  1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK",
  5: "PUBREC", 6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE",
  9: "SUBACK", 10: "UNSUBSCRIBE", 11: "UNSUBACK",
  12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT"
};

export function parseMQTT(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 2) return { error: "Too short" };
  const type = (bytes[0] >> 4) & 0x0F;
  const flags = bytes[0] & 0x0F;
  const dup = !!(flags & 0x08);
  const qos = (flags >> 1) & 0x03;
  const retain = !!(flags & 0x01);
  let multiplier = 1, length = 0, pos = 1;
  do {
    if (pos >= bytes.length) return { error: "Incomplete length" };
    length += (bytes[pos] & 0x7F) * multiplier;
    multiplier *= 128;
  } while (bytes[pos++] & 0x80);
  const result = { type: MQTT_PACKET_TYPES[type] || `UNKNOWN(${type})`, typeId: type, flags: { dup, qos, retain }, remainingLength: length, headerSize: pos };
  if (type === 1) {
    let i = pos;
    const protoLen = (bytes[i] << 8) | bytes[i + 1]; i += 2;
    const proto = new TextDecoder().decode(bytes.slice(i, i + protoLen)); i += protoLen;
    const version = bytes[i++];
    const connectFlags = bytes[i++];
    const keepAlive = (bytes[i] << 8) | bytes[i + 1]; i += 2;
    const clientIdLen = (bytes[i] << 8) | bytes[i + 1]; i += 2;
    const clientId = new TextDecoder().decode(bytes.slice(i, i + clientIdLen)); i += clientIdLen;
    result.connect = { protocol: proto, version, keepAlive, clientId, cleanSession: !!(connectFlags & 0x02), hasWill: !!(connectFlags & 0x04), willQoS: (connectFlags >> 3) & 0x03, willRetain: !!(connectFlags & 0x20), hasPassword: !!(connectFlags & 0x40), hasUsername: !!(connectFlags & 0x80) };
    if (result.connect.hasUsername && i + 2 <= bytes.length) {
      const uLen = (bytes[i] << 8) | bytes[i + 1]; i += 2;
      result.connect.username = new TextDecoder().decode(bytes.slice(i, i + uLen)); i += uLen;
    }
  }
  if (type === 3) {
    let i = pos;
    const topicLen = (bytes[i] << 8) | bytes[i + 1]; i += 2;
    const topic = new TextDecoder().decode(bytes.slice(i, i + topicLen)); i += topicLen;
    let packetId = null;
    if (qos > 0) { packetId = (bytes[i] << 8) | bytes[i + 1]; i += 2; }
    const payload = new TextDecoder().decode(bytes.slice(i, pos + length));
    result.publish = { topic, packetId, payload };
  }
  return result;
}

export const MQTT_SECURITY_CHECKS = [
  { id: "MQTT-001", check: "Authentication", desc: "MQTT broker requires username/password or certificate authentication", severity: "critical", test: "Attempt anonymous CONNECT without credentials" },
  { id: "MQTT-002", check: "Encryption", desc: "MQTT uses TLS (port 8883) instead of plaintext (port 1883)", severity: "critical", test: "Check if broker accepts connections on port 1883" },
  { id: "MQTT-003", check: "Authorization", desc: "Topic-level ACLs restrict which clients can publish/subscribe to which topics", severity: "high", test: "Subscribe to # (wildcard all topics) and check if data is returned" },
  { id: "MQTT-004", check: "Wildcard Subscriptions", desc: "Broker restricts wildcard subscriptions (# and +)", severity: "medium", test: "Subscribe to # and $SYS/# topics" },
  { id: "MQTT-005", check: "$SYS Topics", desc: "System topics ($SYS/#) are restricted to admin clients only", severity: "medium", test: "Subscribe to $SYS/# for broker internal info (clients, messages, uptime)" },
  { id: "MQTT-006", check: "Client ID Spoofing", desc: "Broker prevents client ID collision/takeover", severity: "medium", test: "Connect with a known client ID to see if it disconnects the original" },
  { id: "MQTT-007", check: "Message Size Limits", desc: "Broker enforces maximum message size to prevent DoS", severity: "low", test: "Send oversized PUBLISH message" },
  { id: "MQTT-008", check: "Rate Limiting", desc: "Broker limits connection and message rates per client", severity: "medium", test: "Rapid-fire PUBLISH messages to test rate limits" },
  { id: "MQTT-009", check: "Retained Messages", desc: "Sensitive data not stored as retained messages", severity: "medium", test: "Subscribe with clean session and check for retained messages with credentials" },
  { id: "MQTT-010", check: "Will Messages", desc: "Last Will and Testament messages don't leak sensitive info", severity: "low", test: "Connect with will message, check content upon disconnection" },
];

// ═══════════════════════════════════════════════════════════════════
// CoAP MESSAGE PARSER
// ═══════════════════════════════════════════════════════════════════

export const COAP_METHODS = { 1: "GET", 2: "POST", 3: "PUT", 4: "DELETE" };
export const COAP_TYPES = { 0: "CON", 1: "NON", 2: "ACK", 3: "RST" };

export function parseCoAP(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 4) return { error: "Too short for CoAP" };
  const ver = (bytes[0] >> 6) & 0x03;
  const type = (bytes[0] >> 4) & 0x03;
  const tokenLen = bytes[0] & 0x0F;
  const code = bytes[1];
  const codeClass = (code >> 5) & 0x07;
  const codeDetail = code & 0x1F;
  const msgId = (bytes[2] << 8) | bytes[3];
  const token = bytes.slice(4, 4 + tokenLen);
  let optPos = 4 + tokenLen;
  const options = [];
  let optNum = 0;
  while (optPos < bytes.length && bytes[optPos] !== 0xFF) {
    const delta = (bytes[optPos] >> 4) & 0x0F;
    const len = bytes[optPos] & 0x0F;
    optPos++;
    let actualDelta = delta, actualLen = len;
    if (delta === 13) { actualDelta = bytes[optPos++] + 13; }
    else if (delta === 14) { actualDelta = ((bytes[optPos] << 8) | bytes[optPos + 1]) + 269; optPos += 2; }
    if (len === 13) { actualLen = bytes[optPos++] + 13; }
    else if (len === 14) { actualLen = ((bytes[optPos] << 8) | bytes[optPos + 1]) + 269; optPos += 2; }
    optNum += actualDelta;
    const value = bytes.slice(optPos, optPos + actualLen);
    options.push({ number: optNum, value });
    optPos += actualLen;
  }
  let payload = null;
  if (optPos < bytes.length && bytes[optPos] === 0xFF) {
    payload = new TextDecoder().decode(bytes.slice(optPos + 1));
  }
  return { version: ver, type: COAP_TYPES[type] || type, code: `${codeClass}.${String(codeDetail).padStart(2, "0")}`, method: codeClass === 0 ? (COAP_METHODS[codeDetail] || `0.${codeDetail}`) : null, messageId: msgId, token: Array.from(token).map(b => b.toString(16).padStart(2, "0")).join(""), options, payload };
}

// ═══════════════════════════════════════════════════════════════════
// MODBUS TCP PARSER
// ═══════════════════════════════════════════════════════════════════

export const MODBUS_FUNCTIONS = {
  1: { name: "Read Coils", access: "read", desc: "Read status of discrete output coils" },
  2: { name: "Read Discrete Inputs", access: "read", desc: "Read status of discrete input contacts" },
  3: { name: "Read Holding Registers", access: "read", desc: "Read contents of holding registers" },
  4: { name: "Read Input Registers", access: "read", desc: "Read contents of input registers" },
  5: { name: "Write Single Coil", access: "write", desc: "Write a single discrete output coil" },
  6: { name: "Write Single Register", access: "write", desc: "Write a single holding register" },
  7: { name: "Read Exception Status", access: "read", desc: "Read exception status outputs" },
  8: { name: "Diagnostics", access: "diag", desc: "Diagnostic functions for serial line communication" },
  11: { name: "Get Comm Event Counter", access: "read", desc: "Get communication event counter" },
  12: { name: "Get Comm Event Log", access: "read", desc: "Get communication event log" },
  15: { name: "Write Multiple Coils", access: "write", desc: "Write multiple discrete output coils" },
  16: { name: "Write Multiple Registers", access: "write", desc: "Write multiple holding registers" },
  17: { name: "Report Server ID", access: "read", desc: "Report device identification and status" },
  20: { name: "Read File Record", access: "read", desc: "Read from file record" },
  21: { name: "Write File Record", access: "write", desc: "Write to file record" },
  22: { name: "Mask Write Register", access: "write", desc: "Modify register using AND/OR masks" },
  23: { name: "Read/Write Multiple Registers", access: "write", desc: "Read and write multiple registers in one transaction" },
  24: { name: "Read FIFO Queue", access: "read", desc: "Read contents of a FIFO queue of registers" },
  43: { name: "Encapsulated Interface Transport", access: "read", desc: "MEI transport for device identification" },
};

export function parseModbusTCP(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 8) return { error: "Too short for Modbus TCP" };
  const transactionId = (bytes[0] << 8) | bytes[1];
  const protocolId = (bytes[2] << 8) | bytes[3];
  const length = (bytes[4] << 8) | bytes[5];
  const unitId = bytes[6];
  const functionCode = bytes[7];
  const isException = !!(functionCode & 0x80);
  const actualFC = functionCode & 0x7F;
  const funcInfo = MODBUS_FUNCTIONS[actualFC] || { name: `Unknown(${actualFC})`, access: "unknown" };
  const result = { transactionId, protocolId, length, unitId, functionCode: actualFC, functionName: funcInfo.name, isException, access: funcInfo.access };
  if (isException && bytes.length > 8) {
    const exCodes = { 1: "Illegal Function", 2: "Illegal Data Address", 3: "Illegal Data Value", 4: "Server Device Failure", 5: "Acknowledge", 6: "Server Device Busy", 8: "Memory Parity Error", 10: "Gateway Path Unavailable", 11: "Gateway Target Failed to Respond" };
    result.exceptionCode = bytes[8];
    result.exceptionName = exCodes[bytes[8]] || `Unknown(${bytes[8]})`;
  } else if (!isException && bytes.length > 8) {
    if (actualFC === 1 || actualFC === 2) {
      const byteCount = bytes[8];
      result.data = { byteCount, coils: Array.from(bytes.slice(9, 9 + byteCount)) };
    } else if (actualFC === 3 || actualFC === 4) {
      const byteCount = bytes[8];
      const registers = [];
      for (let i = 9; i < 9 + byteCount; i += 2) {
        registers.push((bytes[i] << 8) | bytes[i + 1]);
      }
      result.data = { byteCount, registers };
    } else if (actualFC === 5 || actualFC === 6) {
      result.data = { address: (bytes[8] << 8) | bytes[9], value: (bytes[10] << 8) | bytes[11] };
    } else if (actualFC === 15 || actualFC === 16) {
      result.data = { startAddress: (bytes[8] << 8) | bytes[9], quantity: (bytes[10] << 8) | bytes[11] };
    }
  }
  return result;
}

// ═══════════════════════════════════════════════════════════════════
// DNP3 PARSER (Distributed Network Protocol)
// ═══════════════════════════════════════════════════════════════════

export const DNP3_FUNCTION_CODES = {
  0: "Confirm", 1: "Read", 2: "Write", 3: "Select",
  4: "Operate", 5: "Direct Operate", 6: "Direct Operate No Ack",
  7: "Immediate Freeze", 8: "Immediate Freeze No Ack",
  9: "Freeze and Clear", 10: "Freeze and Clear No Ack",
  11: "Freeze at Time", 12: "Freeze at Time No Ack",
  13: "Cold Restart", 14: "Warm Restart",
  15: "Initialize Data", 16: "Initialize Application",
  17: "Start Application", 18: "Stop Application",
  19: "Save Configuration", 20: "Enable Unsolicited",
  21: "Disable Unsolicited", 22: "Assign Class",
  23: "Delay Measurement", 24: "Record Current Time",
  25: "Open File", 26: "Close File", 27: "Delete File",
  28: "Get File Info", 29: "Authenticate File",
  30: "Abort File", 129: "Response", 130: "Unsolicited Response",
  131: "Authentication Response"
};

export const DNP3_OBJECT_GROUPS = {
  1: "Binary Input", 2: "Binary Input Event", 3: "Double-bit Binary Input",
  4: "Double-bit Binary Input Event", 10: "Binary Output", 11: "Binary Output Event",
  12: "Control Relay Output Block", 20: "Counter", 21: "Frozen Counter",
  22: "Counter Event", 23: "Frozen Counter Event", 30: "Analog Input",
  31: "Frozen Analog Input", 32: "Analog Input Event", 33: "Frozen Analog Input Event",
  40: "Analog Output Status", 41: "Analog Output", 42: "Analog Output Event",
  43: "Analog Output Command Event", 50: "Time and Date",
  51: "Time and Date CTO", 52: "Time Delay", 60: "Class Data",
  70: "File Identification", 80: "Internal Indications", 81: "Storage",
  83: "Data Set Prototype", 85: "Data Set Descriptor",
  86: "Data Set Present Value", 87: "Data Set Snapshot",
  90: "Application Identification", 91: "Status of Requested Operations",
  110: "Octet String", 111: "Octet String Event",
  112: "Virtual Terminal Output", 113: "Virtual Terminal Event",
  120: "Authentication"
};

export function parseDNP3(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 10) return { error: "Too short for DNP3" };
  if (bytes[0] !== 0x05 || bytes[1] !== 0x64) return { error: "Invalid DNP3 start bytes (expected 0x0564)" };
  const length = bytes[2];
  const control = bytes[3];
  const dir = !!(control & 0x80);
  const prm = !!(control & 0x40);
  const fcb = !!(control & 0x20);
  const fcv = !!(control & 0x10);
  const funcCode = control & 0x0F;
  const destination = (bytes[5] << 8) | bytes[4];
  const source = (bytes[7] << 8) | bytes[6];
  const crc = (bytes[9] << 8) | bytes[8];
  const result = { startBytes: "0564", length, control: { dir, prm, fcb, fcv, functionCode: funcCode }, destination, source, headerCRC: crc };
  if (bytes.length > 10) {
    const transportHeader = bytes[10];
    result.transport = { fin: !!(transportHeader & 0x80), fir: !!(transportHeader & 0x40), sequence: transportHeader & 0x3F };
    if (bytes.length > 11) {
      const appControl = bytes[11];
      result.application = { fir: !!(appControl & 0x80), fin: !!(appControl & 0x40), con: !!(appControl & 0x20), uns: !!(appControl & 0x10), sequence: appControl & 0x0F };
      if (bytes.length > 12) {
        const fc = bytes[12];
        result.application.functionCode = fc;
        result.application.functionName = DNP3_FUNCTION_CODES[fc] || `Unknown(${fc})`;
      }
    }
  }
  return result;
}

// ═══════════════════════════════════════════════════════════════════
// BLE ADVERTISEMENT PARSER
// ═══════════════════════════════════════════════════════════════════

export const BLE_AD_TYPES = {
  0x01: "Flags", 0x02: "Incomplete 16-bit UUIDs", 0x03: "Complete 16-bit UUIDs",
  0x04: "Incomplete 32-bit UUIDs", 0x05: "Complete 32-bit UUIDs",
  0x06: "Incomplete 128-bit UUIDs", 0x07: "Complete 128-bit UUIDs",
  0x08: "Shortened Local Name", 0x09: "Complete Local Name",
  0x0A: "Tx Power Level", 0x0D: "Class of Device",
  0x0E: "Simple Pairing Hash", 0x0F: "Simple Pairing Randomizer",
  0x10: "TK Value", 0x11: "Security Manager OOB Flags",
  0x12: "Peripheral Connection Interval Range",
  0x14: "16-bit Solicitation UUIDs", 0x15: "128-bit Solicitation UUIDs",
  0x16: "Service Data (16-bit UUID)", 0x17: "Public Target Address",
  0x18: "Random Target Address", 0x19: "Appearance",
  0x1A: "Advertising Interval", 0x1B: "LE Bluetooth Device Address",
  0x1C: "LE Role", 0x20: "Service Data (32-bit UUID)",
  0x21: "Service Data (128-bit UUID)", 0xFF: "Manufacturer Specific Data"
};

export function parseBLEAdvertisement(bytes) {
  if (!(bytes instanceof Uint8Array)) return { error: "Expected Uint8Array" };
  const structures = [];
  let i = 0;
  while (i < bytes.length) {
    const len = bytes[i]; i++;
    if (len === 0 || i + len > bytes.length) break;
    const type = bytes[i];
    const data = bytes.slice(i + 1, i + len);
    const typeName = BLE_AD_TYPES[type] || `Unknown(0x${type.toString(16)})`;
    const entry = { type, typeName, data };
    if (type === 0x09 || type === 0x08) {
      entry.name = new TextDecoder().decode(data);
    } else if (type === 0x01) {
      entry.flags = { leLimited: !!(data[0] & 0x01), leGeneral: !!(data[0] & 0x02), brEdrNotSupported: !!(data[0] & 0x04), leBrEdrController: !!(data[0] & 0x08), leBrEdrHost: !!(data[0] & 0x10) };
    } else if (type === 0x0A) {
      entry.txPower = (data[0] > 127) ? data[0] - 256 : data[0];
    } else if (type === 0xFF && data.length >= 2) {
      entry.companyId = (data[1] << 8) | data[0];
      entry.companyData = data.slice(2);
    }
    structures.push(entry);
    i += len;
  }
  return { structures, deviceName: structures.find(s => s.name)?.name || null };
}

// ═══════════════════════════════════════════════════════════════════
// ICS/SCADA VULNERABILITY DATABASE
// ═══════════════════════════════════════════════════════════════════

export const ICS_VULNERABILITIES = [
  { cve: "CVE-2015-1778", vendor: "Siemens", product: "SIMATIC S7-300/400", severity: "critical", cvss: 10.0, desc: "Hardcoded cryptographic key allows authentication bypass on Siemens S7 PLCs", impact: "Complete control of PLC — can modify ladder logic, stop processes", mitigation: "Network segmentation, firewall rules, update firmware" },
  { cve: "CVE-2017-6034", vendor: "Schneider Electric", product: "Modicon M340", severity: "critical", cvss: 9.8, desc: "Unauthenticated Modbus write allows arbitrary register modification", impact: "Manipulate industrial process values, disable safety systems", mitigation: "Enable Modbus authentication, network segmentation, IDS monitoring" },
  { cve: "CVE-2019-13945", vendor: "Siemens", product: "SIMATIC S7-1200/1500", severity: "high", cvss: 8.1, desc: "Session fixation allows replay attacks against S7comm protocol", impact: "Replay legitimate commands to manipulate PLC state", mitigation: "Enable TLS for S7comm, firmware update, network monitoring" },
  { cve: "CVE-2020-15782", vendor: "Siemens", product: "SIMATIC S7-1200/1500", severity: "critical", cvss: 10.0, desc: "Memory protection bypass allows arbitrary code execution on PLC", impact: "Execute native code on PLC, bypass sandbox, persistent backdoor", mitigation: "Firmware update, network isolation, access control" },
  { cve: "CVE-2018-7762", vendor: "Schneider Electric", product: "Modicon M221", severity: "critical", cvss: 9.8, desc: "Hardcoded FTP credentials allow firmware extraction and modification", impact: "Extract and modify PLC firmware, install backdoor", mitigation: "Disable FTP, firmware update, network segmentation" },
  { cve: "CVE-2017-14462", vendor: "Rockwell Automation", product: "MicroLogix 1400", severity: "high", cvss: 8.6, desc: "Denial of service via crafted EtherNet/IP packet causes PLC reboot", impact: "Process disruption, safety system failure", mitigation: "Firmware update, IDS rules for malformed EtherNet/IP" },
  { cve: "CVE-2019-6553", vendor: "GE", product: "Mark VIe Controller", severity: "critical", cvss: 10.0, desc: "Unauthenticated access to engineering workstation service", impact: "Full control of turbine/generator control system", mitigation: "Network segmentation, access control, monitoring" },
  { cve: "CVE-2020-10054", vendor: "Siemens", product: "SCALANCE X switches", severity: "high", cvss: 7.5, desc: "Web interface authentication bypass allows configuration changes", impact: "Network reconfiguration, VLAN hopping, traffic interception", mitigation: "Firmware update, disable web interface, use CLI only" },
  { cve: "CVE-2021-22779", vendor: "Schneider Electric", product: "EcoStruxure", severity: "critical", cvss: 9.8, desc: "Authentication bypass in Modbus service allows unauthorized access", impact: "Modify energy management system configurations", mitigation: "Network segmentation, Modbus firewall rules" },
  { cve: "CVE-2018-10730", vendor: "ABB", product: "eSOMS", severity: "high", cvss: 8.1, desc: "SQL injection in operations management system", impact: "Access to safety management data, procedure modification", mitigation: "Input validation, WAF, database access controls" },
  { cve: "CVE-2019-18255", vendor: "Omron", product: "CJ/CS Series PLC", severity: "critical", cvss: 9.8, desc: "FINS protocol allows unauthenticated memory read/write", impact: "Read/write PLC memory, modify program, control outputs", mitigation: "FINS protocol firewall rules, network segmentation" },
  { cve: "CVE-2020-25159", vendor: "Real Time Automation", product: "499ES EtherNet/IP Adapter", severity: "critical", cvss: 9.8, desc: "Stack overflow in EtherNet/IP implementation allows RCE", impact: "Remote code execution on embedded device", mitigation: "Firmware update, network isolation" },
  { cve: "CVE-2015-3935", vendor: "Honeywell", product: "Experion PKS", severity: "critical", cvss: 10.0, desc: "Unauthenticated access to DCS controller service", impact: "Control of distributed control system, process manipulation", mitigation: "Network segmentation, access control lists" },
  { cve: "CVE-2022-22965", vendor: "Multiple", product: "Spring Framework (used in SCADA HMIs)", severity: "critical", cvss: 9.8, desc: "Spring4Shell RCE affecting Java-based HMI applications", impact: "Remote code execution on HMI servers", mitigation: "Patch Spring Framework, WAF rules, network isolation" },
  { cve: "CVE-2021-27421", vendor: "AVEVA", product: "InTouch HMI", severity: "high", cvss: 8.8, desc: "Buffer overflow in InTouch HMI allows code execution", impact: "Compromise HMI, pivot to control network", mitigation: "Patch InTouch, application whitelisting, host IDS" },
];

export const ICS_ATTACK_VECTORS = [
  { name: "Modbus TCP Manipulation", protocol: "Modbus", desc: "Modbus has no built-in authentication or encryption. Attackers on the network can read registers (function 3/4), write registers (function 6/16), and control outputs (function 5/15) without credentials.", impact: "Direct physical process manipulation — change setpoints, open/close valves, start/stop motors", mitigation: ["Network segmentation (IT/OT boundary)", "Modbus-aware firewall (e.g., Tofino)", "Read-only Modbus gateway", "Deep packet inspection IDS"] },
  { name: "S7comm Replay Attack", protocol: "S7comm", desc: "Siemens S7 communication protocol uses weak session handling. Captured packets can be replayed to execute PLC commands.", impact: "Replay legitimate commands to change PLC behavior", mitigation: ["S7comm-Plus with TLS (S7-1500)", "Network monitoring for replay patterns", "Session token rotation"] },
  { name: "EtherNet/IP CIP Exploitation", protocol: "EtherNet/IP", desc: "Common Industrial Protocol (CIP) over EtherNet/IP allows device configuration, firmware upload, and program modification.", impact: "Firmware replacement, program modification, device DoS", mitigation: ["CIP Security (TLS + authentication)", "Restrict CIP access to engineering workstations", "IDS rules for CIP anomalies"] },
  { name: "DNP3 Man-in-the-Middle", protocol: "DNP3", desc: "DNP3 without Secure Authentication (SA) is vulnerable to packet injection and modification between master and outstation.", impact: "False data injection, command spoofing, measurement manipulation", mitigation: ["Enable DNP3 Secure Authentication v5", "TLS wrapping for DNP3", "Challenge-response authentication"] },
  { name: "OPC UA Exploitation", protocol: "OPC UA", desc: "OPC UA servers may use insecure configurations — no encryption, anonymous access, or weak certificates.", impact: "Read/write process data, historical data exfiltration, method calls", mitigation: ["Require SignAndEncrypt security mode", "Certificate-based authentication", "Application whitelisting"] },
  { name: "HMI Web Interface Attack", protocol: "HTTP/HTTPS", desc: "Web-based HMI interfaces often have default credentials, SQL injection, XSS, or CSRF vulnerabilities.", impact: "Process visualization manipulation, setpoint changes, operator confusion", mitigation: ["Change default credentials", "Input validation", "CSP headers", "Authentication and session management"] },
  { name: "Engineering Workstation Compromise", protocol: "Multiple", desc: "Compromise the engineering workstation (EWS) to gain access to PLC programming software and project files.", impact: "Modify PLC programs, upload malicious logic, extract proprietary processes", mitigation: ["Dedicated EWS with application whitelisting", "Two-person rule for program changes", "Offline project file backup and comparison"] },
  { name: "Firmware Update Hijacking", protocol: "TFTP/FTP/HTTP", desc: "Intercept or replace firmware update files for PLCs, RTUs, or IEDs using insecure update mechanisms.", impact: "Install backdoored firmware, persistent access, process manipulation", mitigation: ["Signed firmware updates", "Secure update channels (HTTPS)", "Firmware integrity verification"] },
];

// ═══════════════════════════════════════════════════════════════════
// FIRMWARE ANALYSIS
// ═══════════════════════════════════════════════════════════════════

export const FIRMWARE_SIGNATURES = [
  { offset: 0, magic: [0x27, 0x05, 0x19, 0x56], name: "U-Boot image (uImage)", desc: "Das U-Boot bootloader image format" },
  { offset: 0, magic: [0xD0, 0x0D, 0xFE, 0xED], name: "Device Tree Blob (DTB)", desc: "Flattened device tree for hardware description" },
  { offset: 0, magic: [0x68, 0x73, 0x71, 0x73], name: "SquashFS (little-endian)", desc: "Compressed read-only filesystem, common in routers" },
  { offset: 0, magic: [0x73, 0x71, 0x73, 0x68], name: "SquashFS (big-endian)", desc: "Compressed read-only filesystem, big-endian variant" },
  { offset: 0, magic: [0x85, 0x19, 0x01, 0xE0], name: "JFFS2 (little-endian)", desc: "Journaling Flash File System v2" },
  { offset: 0, magic: [0x19, 0x85, 0x20, 0x03], name: "JFFS2 (big-endian)", desc: "JFFS2 big-endian, common in ARM devices" },
  { offset: 0, magic: [0x59, 0x41, 0x46, 0x46], name: "YAFFS", desc: "Yet Another Flash File System" },
  { offset: 0, magic: [0x28, 0xB5, 0x2F, 0xFD], name: "Zstandard compressed", desc: "Zstd compression, newer firmware packaging" },
  { offset: 0, magic: [0x1F, 0x8B], name: "Gzip compressed", desc: "Gzip-compressed data (kernel, rootfs)" },
  { offset: 0, magic: [0x42, 0x5A, 0x68], name: "Bzip2 compressed", desc: "Bzip2-compressed data" },
  { offset: 0, magic: [0xFD, 0x37, 0x7A, 0x58, 0x5A], name: "XZ compressed", desc: "XZ/LZMA2-compressed data" },
  { offset: 0, magic: [0x5D, 0x00, 0x00], name: "LZMA compressed", desc: "LZMA-compressed data" },
  { offset: 0, magic: [0x30, 0x37, 0x30, 0x37, 0x30, 0x31], name: "CPIO archive", desc: "CPIO archive (used in initramfs)" },
  { offset: 0, magic: [0x89, 0x50, 0x4E, 0x47], name: "PNG image", desc: "PNG image (splash screen, logo)" },
  { offset: 0, magic: [0x43, 0x72, 0x34, 0x38], name: "CramFS", desc: "Compressed ROM filesystem" },
  { offset: 0, magic: [0x3C, 0xD2, 0xE5, 0x23], name: "UBIFS superblock", desc: "Unsorted Block Image File System" },
  { offset: 0, magic: [0x55, 0x42, 0x49, 0x23], name: "UBI image", desc: "Unsorted Block Images volume" },
  { offset: 257, magic: [0x75, 0x73, 0x74, 0x61, 0x72], name: "TAR archive", desc: "POSIX tar archive (at offset 257)" },
  { offset: 0, magic: [0x7F, 0x45, 0x4C, 0x46], name: "ELF binary", desc: "Executable and Linkable Format" },
];

export function identifyFirmware(bytes) {
  if (!(bytes instanceof Uint8Array)) return [];
  const matches = [];
  for (const sig of FIRMWARE_SIGNATURES) {
    if (sig.offset + sig.magic.length > bytes.length) continue;
    let match = true;
    for (let i = 0; i < sig.magic.length; i++) {
      if (bytes[sig.offset + i] !== sig.magic[i]) { match = false; break; }
    }
    if (match) matches.push({ ...sig, offset: sig.offset });
  }
  // Scan for embedded signatures throughout the binary
  const scanSigs = FIRMWARE_SIGNATURES.filter(s => s.offset === 0 && s.magic.length >= 3);
  for (let pos = 1; pos < Math.min(bytes.length, 16 * 1024 * 1024); pos++) {
    for (const sig of scanSigs) {
      if (pos + sig.magic.length > bytes.length) continue;
      let match = true;
      for (let i = 0; i < sig.magic.length; i++) {
        if (bytes[pos + i] !== sig.magic[i]) { match = false; break; }
      }
      if (match && !matches.some(m => m.name === sig.name && m.offset === pos)) {
        matches.push({ ...sig, offset: pos });
      }
    }
  }
  return matches.sort((a, b) => a.offset - b.offset);
}

export function firmwareEntropy(bytes, blockSize = 256) {
  if (!(bytes instanceof Uint8Array)) return [];
  const blocks = [];
  for (let i = 0; i < bytes.length; i += blockSize) {
    const block = bytes.slice(i, Math.min(i + blockSize, bytes.length));
    const freq = new Uint32Array(256);
    for (const b of block) freq[b]++;
    let entropy = 0;
    for (let j = 0; j < 256; j++) {
      if (freq[j] === 0) continue;
      const p = freq[j] / block.length;
      entropy -= p * Math.log2(p);
    }
    blocks.push({ offset: i, size: block.length, entropy: Math.round(entropy * 1000) / 1000 });
  }
  return blocks;
}

// ═══════════════════════════════════════════════════════════════════
// DEFAULT CREDENTIALS DATABASE
// ═══════════════════════════════════════════════════════════════════

export const DEFAULT_CREDENTIALS = [
  // Routers
  { vendor: "Cisco", product: "IOS Router", username: "admin", password: "admin", service: "HTTP/SSH", category: "router" },
  { vendor: "Cisco", product: "IOS Router", username: "cisco", password: "cisco", service: "SSH/Telnet", category: "router" },
  { vendor: "Cisco", product: "RV Series", username: "admin", password: "admin", service: "HTTP", category: "router" },
  { vendor: "MikroTik", product: "RouterOS", username: "admin", password: "", service: "SSH/HTTP", category: "router" },
  { vendor: "Ubiquiti", product: "EdgeRouter", username: "ubnt", password: "ubnt", service: "SSH", category: "router" },
  { vendor: "Juniper", product: "SRX/EX", username: "root", password: "", service: "Console", category: "router" },
  { vendor: "TP-Link", product: "Router", username: "admin", password: "admin", service: "HTTP", category: "router" },
  { vendor: "Netgear", product: "Router", username: "admin", password: "password", service: "HTTP", category: "router" },
  { vendor: "D-Link", product: "Router", username: "admin", password: "", service: "HTTP", category: "router" },
  { vendor: "Linksys", product: "Router", username: "admin", password: "admin", service: "HTTP", category: "router" },
  { vendor: "ASUS", product: "Router", username: "admin", password: "admin", service: "HTTP", category: "router" },
  { vendor: "Huawei", product: "Router", username: "admin", password: "Admin@huawei", service: "HTTP", category: "router" },
  { vendor: "ZTE", product: "Router", username: "admin", password: "admin", service: "HTTP/Telnet", category: "router" },
  { vendor: "Aruba", product: "Controller", username: "admin", password: "admin", service: "HTTPS", category: "router" },
  { vendor: "Fortinet", product: "FortiGate", username: "admin", password: "", service: "HTTPS", category: "router" },
  { vendor: "Palo Alto", product: "Firewall", username: "admin", password: "admin", service: "HTTPS", category: "router" },
  { vendor: "pfSense", product: "Firewall", username: "admin", password: "pfsense", service: "HTTPS", category: "router" },
  { vendor: "OPNsense", product: "Firewall", username: "root", password: "opnsense", service: "HTTPS", category: "router" },
  { vendor: "Sophos", product: "XG Firewall", username: "admin", password: "admin", service: "HTTPS", category: "router" },
  { vendor: "Ruckus", product: "ZoneDirector", username: "super", password: "sp-admin", service: "HTTPS", category: "router" },
  // Cameras
  { vendor: "Hikvision", product: "IP Camera", username: "admin", password: "12345", service: "HTTP/RTSP", category: "camera" },
  { vendor: "Dahua", product: "IP Camera", username: "admin", password: "admin", service: "HTTP/RTSP", category: "camera" },
  { vendor: "Axis", product: "IP Camera", username: "root", password: "pass", service: "HTTP", category: "camera" },
  { vendor: "Foscam", product: "IP Camera", username: "admin", password: "", service: "HTTP", category: "camera" },
  { vendor: "Samsung", product: "IP Camera", username: "admin", password: "4321", service: "HTTP", category: "camera" },
  { vendor: "Vivotek", product: "IP Camera", username: "root", password: "", service: "HTTP", category: "camera" },
  { vendor: "Amcrest", product: "IP Camera", username: "admin", password: "admin", service: "HTTP", category: "camera" },
  { vendor: "Reolink", product: "IP Camera", username: "admin", password: "", service: "HTTP", category: "camera" },
  { vendor: "Uniview", product: "IP Camera", username: "admin", password: "123456", service: "HTTP", category: "camera" },
  { vendor: "Bosch", product: "IP Camera", username: "service", password: "", service: "HTTP", category: "camera" },
  // Databases
  { vendor: "MySQL", product: "MySQL Server", username: "root", password: "", service: "3306", category: "database" },
  { vendor: "PostgreSQL", product: "PostgreSQL", username: "postgres", password: "postgres", service: "5432", category: "database" },
  { vendor: "MongoDB", product: "MongoDB", username: "", password: "", service: "27017", category: "database" },
  { vendor: "Redis", product: "Redis Server", username: "", password: "", service: "6379", category: "database" },
  { vendor: "Microsoft", product: "SQL Server", username: "sa", password: "", service: "1433", category: "database" },
  { vendor: "Oracle", product: "Database", username: "system", password: "manager", service: "1521", category: "database" },
  { vendor: "Oracle", product: "Database", username: "scott", password: "tiger", service: "1521", category: "database" },
  { vendor: "CouchDB", product: "CouchDB", username: "admin", password: "admin", service: "5984", category: "database" },
  { vendor: "Elasticsearch", product: "Elasticsearch", username: "elastic", password: "changeme", service: "9200", category: "database" },
  { vendor: "Cassandra", product: "Cassandra", username: "cassandra", password: "cassandra", service: "9042", category: "database" },
  // IoT/Smart Home
  { vendor: "Raspberry Pi", product: "Raspbian/Pi OS", username: "pi", password: "raspberry", service: "SSH", category: "iot" },
  { vendor: "Arduino", product: "Yun", username: "root", password: "arduino", service: "SSH", category: "iot" },
  { vendor: "Samsung", product: "SmartThings Hub", username: "root", password: "", service: "Serial", category: "iot" },
  { vendor: "Philips", product: "Hue Bridge", username: "", password: "", service: "HTTP API", category: "iot" },
  { vendor: "Sonos", product: "Speaker", username: "", password: "", service: "HTTP/1400", category: "iot" },
  { vendor: "Ring", product: "Doorbell", username: "", password: "", service: "Cloud API", category: "iot" },
  // Industrial
  { vendor: "Siemens", product: "SIMATIC S7", username: "", password: "", service: "102/TCP", category: "ics" },
  { vendor: "Schneider", product: "Modicon", username: "", password: "", service: "502/TCP (Modbus)", category: "ics" },
  { vendor: "Allen-Bradley", product: "ControlLogix", username: "", password: "", service: "44818/TCP (EtherNet/IP)", category: "ics" },
  { vendor: "ABB", product: "AC500 PLC", username: "admin", password: "admin", service: "HTTP", category: "ics" },
  { vendor: "Emerson", product: "DeltaV DCS", username: "DeltaVAdmin", password: "DeltaVAdmin", service: "HTTPS", category: "ics" },
  { vendor: "Yokogawa", product: "CENTUM VP", username: "admin", password: "", service: "HTTP", category: "ics" },
  { vendor: "Honeywell", product: "Experion PKS", username: "Engineer", password: "", service: "HTTP", category: "ics" },
  { vendor: "GE", product: "MarkVIe Controller", username: "admin", password: "admin", service: "HTTP", category: "ics" },
  // Network Equipment
  { vendor: "HP/Aruba", product: "ProCurve Switch", username: "admin", password: "", service: "SSH/Telnet", category: "network" },
  { vendor: "Dell", product: "PowerConnect", username: "admin", password: "", service: "SSH/Telnet", category: "network" },
  { vendor: "Brocade", product: "Fibre Channel", username: "admin", password: "password", service: "SSH/HTTP", category: "network" },
  { vendor: "Avaya", product: "IP Phone", username: "admin", password: "admin", service: "HTTP", category: "network" },
  { vendor: "Polycom", product: "IP Phone", username: "Polycom", password: "456", service: "HTTP", category: "network" },
  { vendor: "Cisco", product: "IP Phone", username: "admin", password: "admin", service: "HTTP", category: "network" },
  // CMS/Web Apps
  { vendor: "WordPress", product: "WordPress", username: "admin", password: "admin", service: "HTTP", category: "webapp" },
  { vendor: "Joomla", product: "Joomla", username: "admin", password: "admin", service: "HTTP", category: "webapp" },
  { vendor: "Drupal", product: "Drupal", username: "admin", password: "admin", service: "HTTP", category: "webapp" },
  { vendor: "Apache", product: "Tomcat Manager", username: "tomcat", password: "tomcat", service: "HTTP/8080", category: "webapp" },
  { vendor: "Apache", product: "Tomcat Manager", username: "admin", password: "admin", service: "HTTP/8080", category: "webapp" },
  { vendor: "Jenkins", product: "Jenkins CI", username: "admin", password: "admin", service: "HTTP/8080", category: "webapp" },
  { vendor: "Grafana", product: "Grafana", username: "admin", password: "admin", service: "HTTP/3000", category: "webapp" },
  { vendor: "Zabbix", product: "Zabbix", username: "Admin", password: "zabbix", service: "HTTP", category: "webapp" },
  { vendor: "Nagios", product: "Nagios", username: "nagiosadmin", password: "nagiosadmin", service: "HTTP", category: "webapp" },
  { vendor: "phpMyAdmin", product: "phpMyAdmin", username: "root", password: "", service: "HTTP", category: "webapp" },
  { vendor: "Webmin", product: "Webmin", username: "root", password: "", service: "HTTPS/10000", category: "webapp" },
  { vendor: "Portainer", product: "Portainer", username: "admin", password: "admin", service: "HTTPS/9443", category: "webapp" },
  { vendor: "Minio", product: "MinIO", username: "minioadmin", password: "minioadmin", service: "HTTP/9000", category: "webapp" },
  { vendor: "GitLab", product: "GitLab CE", username: "root", password: "5iveL!fe", service: "HTTP", category: "webapp" },
  { vendor: "SonarQube", product: "SonarQube", username: "admin", password: "admin", service: "HTTP/9000", category: "webapp" },
  { vendor: "RabbitMQ", product: "RabbitMQ", username: "guest", password: "guest", service: "HTTP/15672", category: "webapp" },
  { vendor: "Kibana", product: "Kibana", username: "elastic", password: "changeme", service: "HTTP/5601", category: "webapp" },
  { vendor: "Consul", product: "HashiCorp Consul", username: "", password: "", service: "HTTP/8500", category: "webapp" },
  { vendor: "Vault", product: "HashiCorp Vault", username: "", password: "", service: "HTTP/8200", category: "webapp" },
  // Printers
  { vendor: "HP", product: "LaserJet", username: "admin", password: "", service: "HTTP/HTTPS", category: "printer" },
  { vendor: "Canon", product: "imageRUNNER", username: "7654321", password: "7654321", service: "HTTP", category: "printer" },
  { vendor: "Xerox", product: "WorkCentre", username: "admin", password: "1111", service: "HTTP", category: "printer" },
  { vendor: "Brother", product: "Printer", username: "admin", password: "access", service: "HTTP", category: "printer" },
  { vendor: "Ricoh", product: "Printer", username: "admin", password: "", service: "HTTP", category: "printer" },
  { vendor: "Epson", product: "Printer", username: "epson", password: "epson", service: "HTTP", category: "printer" },
  { vendor: "Lexmark", product: "Printer", username: "", password: "", service: "HTTP", category: "printer" },
  { vendor: "Samsung", product: "Printer", username: "admin", password: "sec00000", service: "HTTP", category: "printer" },
  // Virtualization
  { vendor: "VMware", product: "ESXi", username: "root", password: "", service: "HTTPS/443", category: "virtualization" },
  { vendor: "VMware", product: "vCenter", username: "administrator@vsphere.local", password: "", service: "HTTPS/443", category: "virtualization" },
  { vendor: "Proxmox", product: "Proxmox VE", username: "root", password: "", service: "HTTPS/8006", category: "virtualization" },
  { vendor: "Citrix", product: "XenServer", username: "root", password: "", service: "HTTPS", category: "virtualization" },
  // Storage
  { vendor: "Synology", product: "DiskStation", username: "admin", password: "", service: "HTTPS/5001", category: "storage" },
  { vendor: "QNAP", product: "NAS", username: "admin", password: "admin", service: "HTTPS/8080", category: "storage" },
  { vendor: "NetApp", product: "ONTAP", username: "admin", password: "", service: "HTTPS", category: "storage" },
  { vendor: "EMC", product: "Isilon", username: "root", password: "a", service: "SSH", category: "storage" },
  { vendor: "FreeNAS", product: "TrueNAS", username: "root", password: "", service: "HTTPS", category: "storage" },
];

export function searchCredentials(query) {
  const q = query.toLowerCase();
  return DEFAULT_CREDENTIALS.filter(c =>
    c.vendor.toLowerCase().includes(q) ||
    c.product.toLowerCase().includes(q) ||
    c.category.toLowerCase().includes(q) ||
    c.service.toLowerCase().includes(q)
  );
}

export function credentialsByCategory(category) {
  return DEFAULT_CREDENTIALS.filter(c => c.category === category);
}

// ═══════════════════════════════════════════════════════════════════
// RADIO FREQUENCY REFERENCE
// ═══════════════════════════════════════════════════════════════════

export const RF_BANDS = [
  { name: "WiFi 2.4 GHz", freq: "2.400–2.4835 GHz", channels: 14, bandwidth: "20/40 MHz", range: "50–100m indoor", protocol: "802.11b/g/n/ax", security: ["WPA3-Personal", "WPA3-Enterprise", "WPA2"], attacks: ["Deauthentication", "Evil Twin", "PMKID capture", "Handshake capture", "Karma attack"] },
  { name: "WiFi 5 GHz", freq: "5.150–5.825 GHz", channels: 25, bandwidth: "20/40/80/160 MHz", range: "30–50m indoor", protocol: "802.11a/n/ac/ax", security: ["WPA3", "WPA2", "802.1X"], attacks: ["Channel hopping deauth", "Rogue AP", "KRACK (patched)"] },
  { name: "WiFi 6 GHz", freq: "5.925–7.125 GHz", channels: 59, bandwidth: "20–320 MHz", range: "20–40m indoor", protocol: "802.11ax (Wi-Fi 6E)", security: ["WPA3 required", "SAE", "OWE"], attacks: ["Limited — WPA3 required by spec"] },
  { name: "Bluetooth Classic", freq: "2.402–2.480 GHz", channels: 79, bandwidth: "1 MHz", range: "10–100m", protocol: "BR/EDR", security: ["SSP", "Secure Connections"], attacks: ["BlueBorne", "KNOB", "BIAS", "PIN brute-force", "Bluesnarfing", "Bluebugging"] },
  { name: "Bluetooth Low Energy", freq: "2.402–2.480 GHz", channels: 40, bandwidth: "2 MHz", range: "10–50m", protocol: "BLE 4.0–5.3", security: ["LE Secure Connections", "LESC"], attacks: ["GATT enumeration", "Pairing MitM", "Replay attacks", "Tracking via advertising"] },
  { name: "Zigbee", freq: "2.405–2.480 GHz", channels: 16, bandwidth: "2 MHz", range: "10–100m", protocol: "IEEE 802.15.4 / Zigbee 3.0", security: ["AES-128 CCM*", "Network key", "Link key"], attacks: ["Key sniffing (during join)", "Replay attacks", "Insecure rejoin", "Firmware OTA hijack"] },
  { name: "Z-Wave", freq: "908.42 MHz (US) / 868.42 MHz (EU)", channels: 3, bandwidth: "Various", range: "30–100m", protocol: "Z-Wave Plus / S2", security: ["S2 framework", "AES-128 CCM"], attacks: ["Downgrade to S0 (known key)", "Signal jamming", "Replay (legacy S0)"] },
  { name: "LoRa", freq: "868 MHz (EU) / 915 MHz (US) / 923 MHz (AS)", channels: "Variable", bandwidth: "125–500 kHz", range: "2–15 km", protocol: "LoRaWAN 1.0/1.1", security: ["AES-128 (NwkSKey + AppSKey)", "Join handshake"], attacks: ["Replay attacks (LoRaWAN 1.0)", "Bit-flipping", "ACK spoofing", "Join accept replay"] },
  { name: "NFC", freq: "13.56 MHz", channels: 1, bandwidth: "Various", range: "1–10 cm", protocol: "ISO 14443/15693, NFC Forum", security: ["Varies by application"], attacks: ["Relay attack", "Eavesdropping", "Data modification", "Cloning (MIFARE Classic)"] },
  { name: "RFID LF", freq: "125–134.2 kHz", channels: 1, bandwidth: "N/A", range: "1–10 cm", protocol: "EM4100, HID ProxCard", security: ["Minimal — fixed ID", "No encryption"], attacks: ["Cloning (Proxmark3)", "Replay", "Brute-force"] },
  { name: "RFID HF", freq: "13.56 MHz", channels: 1, bandwidth: "N/A", range: "1–30 cm", protocol: "MIFARE, iCLASS, DESFire", security: ["MIFARE Classic: Crypto-1 (broken)", "DESFire: AES/3DES"], attacks: ["MIFARE Classic: key recovery", "Relay attack", "Side-channel"] },
  { name: "Cellular 4G LTE", freq: "Various (600 MHz–6 GHz)", channels: "Many", bandwidth: "1.4–20 MHz", range: "1–30 km", protocol: "LTE/LTE-A", security: ["AKA protocol", "AES encryption"], attacks: ["IMSI catcher (Stingray)", "Downgrade to 2G", "aLTEr attack"] },
  { name: "Cellular 5G NR", freq: "Sub-6 GHz + mmWave (24–100 GHz)", channels: "Many", bandwidth: "5–400 MHz", range: "100m–10 km", protocol: "5G NR", security: ["5G-AKA", "SUCI (encrypted IMSI)", "256-bit keys"], attacks: ["Bidding-down to 4G", "False base station (limited)", "SUPI leakage in roaming"] },
];

// ═══════════════════════════════════════════════════════════════════
// CAN BUS PROTOCOL (AUTOMOTIVE)
// ═══════════════════════════════════════════════════════════════════

export function parseCANFrame(id, data) {
  const frame = { id: typeof id === "number" ? id : parseInt(id, 16), data: data instanceof Uint8Array ? data : new Uint8Array(data), isExtended: id > 0x7FF };
  const stdPIDs = {
    0x7DF: "OBD-II broadcast request",
    0x7E0: "ECU #1 request", 0x7E8: "ECU #1 response",
    0x7E1: "ECU #2 request", 0x7E9: "ECU #2 response",
    0x7E2: "ECU #3 request", 0x7EA: "ECU #3 response",
  };
  frame.description = stdPIDs[frame.id] || `CAN ID 0x${frame.id.toString(16).toUpperCase()}`;
  if (frame.data.length >= 3 && (frame.id >= 0x7E8 && frame.id <= 0x7EF)) {
    const mode = frame.data[1];
    const pid = frame.data[2];
    frame.obd = { mode, pid };
    if (mode === 0x41) {
      const obdPIDs = {
        0x04: { name: "Engine Load", unit: "%", calc: (d) => (d[3] * 100 / 255).toFixed(1) },
        0x05: { name: "Coolant Temp", unit: "°C", calc: (d) => d[3] - 40 },
        0x0C: { name: "Engine RPM", unit: "rpm", calc: (d) => ((d[3] * 256 + d[4]) / 4).toFixed(0) },
        0x0D: { name: "Vehicle Speed", unit: "km/h", calc: (d) => d[3] },
        0x0F: { name: "Intake Air Temp", unit: "°C", calc: (d) => d[3] - 40 },
        0x10: { name: "MAF Air Flow", unit: "g/s", calc: (d) => ((d[3] * 256 + d[4]) / 100).toFixed(2) },
        0x11: { name: "Throttle Position", unit: "%", calc: (d) => (d[3] * 100 / 255).toFixed(1) },
        0x1F: { name: "Run Time", unit: "sec", calc: (d) => d[3] * 256 + d[4] },
        0x2F: { name: "Fuel Level", unit: "%", calc: (d) => (d[3] * 100 / 255).toFixed(1) },
        0x46: { name: "Ambient Air Temp", unit: "°C", calc: (d) => d[3] - 40 },
        0x5C: { name: "Oil Temp", unit: "°C", calc: (d) => d[3] - 40 },
      };
      if (obdPIDs[pid]) {
        const p = obdPIDs[pid];
        frame.obd.name = p.name;
        frame.obd.value = p.calc(frame.data);
        frame.obd.unit = p.unit;
      }
    }
  }
  return frame;
}

export const AUTOMOTIVE_ATTACK_SURFACES = [
  { surface: "OBD-II Port", access: "Physical", risk: "high", desc: "Direct CAN bus access via diagnostic port under dashboard. Allows reading/writing ECU data, injecting CAN frames.", attacks: ["ECU reprogramming", "Speedometer manipulation", "Engine control modification", "Diagnostic data extraction"] },
  { surface: "Infotainment System", access: "Bluetooth/WiFi/USB", risk: "high", desc: "Head unit often connected to CAN bus. Compromise via Bluetooth, USB firmware update, or connected phone.", attacks: ["RCE via media file parsing", "Bluetooth pairing exploit", "USB firmware injection", "WiFi AP compromise"] },
  { surface: "Telematics (TCU)", access: "Cellular", risk: "critical", desc: "Cellular-connected module for remote diagnostics, OTA updates, and connected services. Remote attack surface.", attacks: ["Remote code execution via cellular", "Man-in-the-middle on data channel", "GPS spoofing", "Remote unlock/start"] },
  { surface: "Key Fob (RKE)", access: "RF (315/433 MHz)", risk: "high", desc: "Remote Keyless Entry uses rolling codes. Vulnerable to relay attacks, signal amplification, and code grabbing.", attacks: ["Relay attack (amplify key signal)", "RollJam (block + capture rolling code)", "Brute-force (older fixed codes)"] },
  { surface: "Tire Pressure Monitoring (TPMS)", access: "RF (315/433 MHz)", risk: "low", desc: "TPMS sensors transmit tire data wirelessly. Can be spoofed to trigger warnings.", attacks: ["Spoof tire pressure alerts", "Vehicle tracking via TPMS IDs"] },
  { surface: "Vehicle-to-Everything (V2X)", access: "DSRC/C-V2X", risk: "medium", desc: "Vehicle communication with infrastructure, other vehicles, and pedestrians.", attacks: ["Message spoofing", "Denial of service", "Privacy tracking", "False traffic signal injection"] },
  { surface: "OTA Update Channel", access: "Cellular/WiFi", risk: "critical", desc: "Over-the-air firmware update mechanism. If compromised, allows fleet-wide code execution.", attacks: ["Firmware image replacement", "Downgrade attack", "Man-in-the-middle during update", "Signing key compromise"] },
];

// ═══════════════════════════════════════════════════════════════════
// SMART HOME SECURITY ASSESSMENT
// ═══════════════════════════════════════════════════════════════════

export const SMART_HOME_CHECKLIST = [
  { category: "Network", checks: [
    { id: "SH-NET-01", check: "IoT devices on separate VLAN/subnet", severity: "high", desc: "Isolate IoT devices from computers and phones to limit lateral movement" },
    { id: "SH-NET-02", check: "WiFi uses WPA3 or WPA2 with strong passphrase", severity: "critical", desc: "Weak WiFi security exposes all connected devices" },
    { id: "SH-NET-03", check: "Guest network for untrusted devices", severity: "medium", desc: "Visitors and temporary devices should use a separate network" },
    { id: "SH-NET-04", check: "UPnP disabled on router", severity: "high", desc: "UPnP allows devices to open firewall ports automatically — disable it" },
    { id: "SH-NET-05", check: "DNS filtering enabled (Pi-hole, NextDNS, etc.)", severity: "medium", desc: "Block IoT telemetry and known malicious domains at DNS level" },
    { id: "SH-NET-06", check: "Router firmware up to date", severity: "critical", desc: "Router vulnerabilities give attackers network-wide access" },
    { id: "SH-NET-07", check: "Remote management disabled", severity: "high", desc: "Disable WAN-side management interface on router" },
  ]},
  { category: "Devices", checks: [
    { id: "SH-DEV-01", check: "Default credentials changed on all devices", severity: "critical", desc: "Default passwords are publicly known — change them immediately" },
    { id: "SH-DEV-02", check: "Firmware up to date on all IoT devices", severity: "high", desc: "Unpatched devices are vulnerable to known exploits" },
    { id: "SH-DEV-03", check: "Unused features disabled (Telnet, FTP, SSH)", severity: "medium", desc: "Disable unnecessary services to reduce attack surface" },
    { id: "SH-DEV-04", check: "Device inventory maintained", severity: "medium", desc: "Know what's on your network — forgotten devices are common entry points" },
    { id: "SH-DEV-05", check: "Cloud account MFA enabled for device management", severity: "high", desc: "If someone compromises your SmartThings/Alexa/Google account, they control your home" },
    { id: "SH-DEV-06", check: "Camera feeds encrypted and not publicly accessible", severity: "critical", desc: "Check if cameras are accessible from the internet without authentication" },
    { id: "SH-DEV-07", check: "Voice assistants configured for voice match", severity: "medium", desc: "Prevent unauthorized voice commands to smart speakers" },
  ]},
  { category: "Privacy", checks: [
    { id: "SH-PRV-01", check: "Review and limit cloud data sharing per device", severity: "medium", desc: "Many IoT devices send usage data to manufacturer clouds" },
    { id: "SH-PRV-02", check: "Disable unnecessary microphone/camera access", severity: "high", desc: "Smart speakers and displays are always-on microphones" },
    { id: "SH-PRV-03", check: "Review third-party app integrations (IFTTT, Alexa Skills)", severity: "medium", desc: "Third-party integrations may have excessive permissions" },
    { id: "SH-PRV-04", check: "Location sharing and tracking disabled where not needed", severity: "medium", desc: "Smart devices may reveal your presence/absence patterns" },
  ]},
  { category: "Physical", checks: [
    { id: "SH-PHY-01", check: "Smart locks have physical key backup", severity: "high", desc: "Electronic locks can fail — always have a manual override" },
    { id: "SH-PHY-02", check: "Critical systems (locks, alarm) don't rely solely on WiFi", severity: "high", desc: "WiFi jamming can disable WiFi-only security systems. Use Z-Wave or wired backup." },
    { id: "SH-PHY-03", check: "Hub/controller in a secured location", severity: "medium", desc: "Physical access to the hub means control of all connected devices" },
  ]},
];

// ═══════════════════════════════════════════════════════════════════
// MEDICAL DEVICE SECURITY
// ═══════════════════════════════════════════════════════════════════

export const MEDICAL_SECURITY = {
  fdaGuidance: [
    { name: "Premarket Submissions", desc: "FDA requires cybersecurity information in premarket submissions for medical devices", doc: "Guidance for the Content of Premarket Submissions for Cybersecurity in Medical Devices (2023)" },
    { name: "Postmarket Management", desc: "Ongoing monitoring, vulnerability disclosure, patching throughout device lifecycle", doc: "Postmarket Management of Cybersecurity in Medical Devices (2016)" },
    { name: "SBOM Requirement", desc: "Software Bill of Materials required for all new device submissions", doc: "Section 524B of FD&C Act (2023)" },
  ],
  commonVulnerabilities: [
    { type: "Infusion Pump", vuln: "Unauthenticated firmware update over HTTP", impact: "Modify drug delivery dosage", severity: "critical" },
    { type: "Patient Monitor", vuln: "Default credentials on management interface", impact: "Alter alarm thresholds, suppress alerts", severity: "critical" },
    { type: "MRI/CT Scanner", vuln: "Unsupported Windows OS (XP/7) running control software", impact: "Remote code execution, ransomware target", severity: "high" },
    { type: "PACS Server", vuln: "DICOM service without authentication", impact: "Access/modify medical images, patient data breach", severity: "critical" },
    { type: "Implantable Device", vuln: "Wireless programming interface without encryption", impact: "Reprogram pacemaker/ICD settings", severity: "critical" },
    { type: "Lab Equipment", vuln: "HL7 messages transmitted in cleartext", impact: "Intercept/modify lab results", severity: "high" },
    { type: "Surgical Robot", vuln: "Telemetry channel without integrity checks", impact: "Manipulate robotic arm movements", severity: "critical" },
    { type: "Wearable Monitor", vuln: "BLE pairing without MITM protection", impact: "Intercept health data, inject false readings", severity: "medium" },
  ],
  dicomPorts: [
    { port: 104, service: "DICOM", desc: "Standard DICOM port for medical image transfer" },
    { port: 2761, service: "DICOM-TLS", desc: "DICOM over TLS" },
    { port: 2762, service: "DICOM-ISCL", desc: "DICOM over ISCL" },
    { port: 11112, service: "DICOM", desc: "Common alternative DICOM port" },
  ]
};
