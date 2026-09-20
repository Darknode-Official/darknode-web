// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
(function(){var _h=location.hostname,_a=["darknode.ai","www.darknode.ai","localhost","127.0.0.1"];if(!_a.some(function(d){return _h===d}))throw document.body.innerHTML="",new Error("unlicensed")}());

// ============================================================================
// DARKNODE IP TOOLS — Network Calculation Toolkit
// IPv4/IPv6 subnet calculator, CIDR, wildcard masks, binary conversion,
// private IP detection, MAC OUI lookup, port reference.
// ============================================================================

function ipv4ToBinary(ip) {
  return ip.split(".").map(o => parseInt(o,10).toString(2).padStart(8,"0")).join(".");
}
function ipv4ToInt(ip) {
  const p = ip.split(".").map(Number);
  return ((p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3])>>>0;
}
function intToIpv4(n) {
  return [(n>>>24)&255,(n>>>16)&255,(n>>>8)&255,n&255].join(".");
}
function isValidIPv4(ip) {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  return m && m.slice(1).every(o => { const n=parseInt(o,10); return n>=0&&n<=255; });
}
function subnetCalc(ip, prefix) {
  if (!isValidIPv4(ip)) return { error: "Invalid IPv4 address" };
  prefix = parseInt(prefix,10);
  if (isNaN(prefix)||prefix<0||prefix>32) return { error: "CIDR prefix must be 0-32" };
  const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  const wildcard = (~mask) >>> 0;
  const ipInt = ipv4ToInt(ip);
  const network = (ipInt & mask) >>> 0;
  const broadcast = (network | wildcard) >>> 0;
  const firstHost = prefix >= 31 ? network : (network + 1) >>> 0;
  const lastHost = prefix >= 31 ? broadcast : (broadcast - 1) >>> 0;
  const totalHosts = prefix >= 31 ? (prefix === 32 ? 1 : 2) : Math.pow(2, 32 - prefix) - 2;
  return {
    ip, prefix, cidr: intToIpv4(network) + "/" + prefix,
    network: intToIpv4(network), broadcast: intToIpv4(broadcast),
    mask: intToIpv4(mask), wildcard: intToIpv4(wildcard),
    firstHost: intToIpv4(firstHost), lastHost: intToIpv4(lastHost),
    totalHosts, totalAddresses: Math.pow(2, 32 - prefix),
    ipBinary: ipv4ToBinary(ip), maskBinary: ipv4ToBinary(intToIpv4(mask)),
    networkBinary: ipv4ToBinary(intToIpv4(network)),
    ipClass: classifyIP(ip), isPrivate: isPrivateIP(ip),
    mapv6: "::ffff:" + ip
  };
}
function classifyIP(ip) {
  const first = parseInt(ip.split(".")[0],10);
  if (first<128) return { class:"A", range:"0.0.0.0 – 127.255.255.255", defaultMask:"/8" };
  if (first<192) return { class:"B", range:"128.0.0.0 – 191.255.255.255", defaultMask:"/16" };
  if (first<224) return { class:"C", range:"192.0.0.0 – 223.255.255.255", defaultMask:"/24" };
  if (first<240) return { class:"D", range:"224.0.0.0 – 239.255.255.255", defaultMask:"Multicast" };
  return { class:"E", range:"240.0.0.0 – 255.255.255.255", defaultMask:"Reserved" };
}
function isPrivateIP(ip) {
  const n = ipv4ToInt(ip);
  if ((n>>>24)===10) return { private:true, range:"10.0.0.0/8 (Class A private)" };
  if ((n>>>20)===0xAC1) return { private:true, range:"172.16.0.0/12 (Class B private)" };
  if ((n>>>16)===0xC0A8) return { private:true, range:"192.168.0.0/16 (Class C private)" };
  if ((n>>>24)===127) return { private:true, range:"127.0.0.0/8 (Loopback)" };
  if ((n>>>16)===0xA9FE) return { private:true, range:"169.254.0.0/16 (Link-local)" };
  return { private:false, range:"Public" };
}
function ipRange(startIP, endIP) {
  if (!isValidIPv4(startIP)||!isValidIPv4(endIP)) return { error:"Invalid IP" };
  const s = ipv4ToInt(startIP), e = ipv4ToInt(endIP);
  if (s>e) return { error:"Start IP must be <= End IP" };
  return { start:startIP, end:endIP, count:e-s+1 };
}

const OUI_DB = [
  {prefix:"00:00:0C",vendor:"Cisco Systems"},{prefix:"00:01:42",vendor:"Cisco Systems"},{prefix:"00:1A:A1",vendor:"Cisco Systems"},
  {prefix:"00:50:56",vendor:"VMware"},{prefix:"00:0C:29",vendor:"VMware"},{prefix:"00:05:69",vendor:"VMware"},
  {prefix:"00:1B:21",vendor:"Intel"},{prefix:"00:1E:67",vendor:"Intel"},{prefix:"3C:97:0E",vendor:"Intel"},
  {prefix:"A4:C3:F0",vendor:"Intel"},{prefix:"8C:EC:4B",vendor:"Intel"},{prefix:"DC:71:96",vendor:"Intel"},
  {prefix:"00:1A:11",vendor:"Google"},{prefix:"3C:5A:B4",vendor:"Google"},{prefix:"F4:F5:D8",vendor:"Google"},
  {prefix:"94:EB:2C",vendor:"Google"},{prefix:"54:60:09",vendor:"Google"},
  {prefix:"00:1E:C2",vendor:"Apple"},{prefix:"A8:20:66",vendor:"Apple"},{prefix:"3C:22:FB",vendor:"Apple"},
  {prefix:"F0:18:98",vendor:"Apple"},{prefix:"AC:DE:48",vendor:"Apple"},{prefix:"14:98:77",vendor:"Apple"},
  {prefix:"D0:03:4B",vendor:"Apple"},{prefix:"78:7B:8A",vendor:"Apple"},
  {prefix:"00:15:5D",vendor:"Microsoft (Hyper-V)"},{prefix:"00:0D:3A",vendor:"Microsoft Azure"},
  {prefix:"00:17:FA",vendor:"Microsoft"},{prefix:"28:18:78",vendor:"Microsoft"},
  {prefix:"00:04:4B",vendor:"Nvidia"},{prefix:"04:D4:C4",vendor:"Nvidia"},
  {prefix:"00:25:90",vendor:"SuperMicro"},{prefix:"AC:1F:6B",vendor:"SuperMicro"},
  {prefix:"00:1A:4A",vendor:"Qumranet (KVM)"},{prefix:"52:54:00",vendor:"QEMU/KVM Virtual NIC"},
  {prefix:"08:00:27",vendor:"Oracle VirtualBox"},
  {prefix:"B8:27:EB",vendor:"Raspberry Pi Foundation"},{prefix:"DC:A6:32",vendor:"Raspberry Pi Foundation"},
  {prefix:"E4:5F:01",vendor:"Raspberry Pi Foundation"},
  {prefix:"00:1F:1F",vendor:"Edimax"},{prefix:"00:1D:7E",vendor:"Linksys"},
  {prefix:"00:14:BF",vendor:"Linksys"},{prefix:"C0:56:27",vendor:"Belkin/Linksys"},
  {prefix:"00:24:01",vendor:"D-Link"},{prefix:"1C:AF:F7",vendor:"D-Link"},
  {prefix:"00:0F:B5",vendor:"Netgear"},{prefix:"C4:3D:C7",vendor:"Netgear"},
  {prefix:"20:CF:30",vendor:"Netgear"},{prefix:"A4:2B:8C",vendor:"Netgear"},
  {prefix:"00:1E:58",vendor:"D-Link"},{prefix:"FC:75:16",vendor:"D-Link"},
  {prefix:"00:18:E7",vendor:"Aruba/HPE"},{prefix:"24:DE:C6",vendor:"Aruba/HPE"},
  {prefix:"00:0B:86",vendor:"Aruba/HPE"},{prefix:"9C:1C:12",vendor:"Aruba/HPE"},
  {prefix:"E8:04:62",vendor:"Cisco Meraki"},{prefix:"00:18:0A",vendor:"Cisco Meraki"},
  {prefix:"00:11:32",vendor:"Synology"},{prefix:"00:1D:09",vendor:"Dell"},
  {prefix:"00:14:22",vendor:"Dell"},{prefix:"F8:DB:88",vendor:"Dell"},
  {prefix:"B4:99:BA",vendor:"Hewlett-Packard"},{prefix:"3C:D9:2B",vendor:"Hewlett-Packard"},
  {prefix:"00:21:5A",vendor:"Hewlett-Packard"},{prefix:"A0:D3:C1",vendor:"Hewlett-Packard"},
  {prefix:"00:1C:C4",vendor:"Hewlett-Packard"},
  {prefix:"00:0A:27",vendor:"Apple (AirPort)"},{prefix:"08:6D:41",vendor:"Samsung"},
  {prefix:"00:21:19",vendor:"Samsung"},{prefix:"C4:73:1E",vendor:"Samsung"},
  {prefix:"FC:F8:AE",vendor:"Samsung"},{prefix:"E4:B3:18",vendor:"Samsung"},
  {prefix:"A0:CC:2B",vendor:"Murata/Sony"},{prefix:"00:1A:80",vendor:"Sony"},
  {prefix:"00:04:5A",vendor:"Linksys"},
  {prefix:"44:D9:E7",vendor:"Ubiquiti"},{prefix:"80:2A:A8",vendor:"Ubiquiti"},
  {prefix:"FC:EC:DA",vendor:"Ubiquiti"},{prefix:"24:5A:4C",vendor:"Ubiquiti"},
  {prefix:"18:E8:29",vendor:"Ubiquiti"},
  {prefix:"B0:B9:8A",vendor:"Netgear"},{prefix:"E0:91:F5",vendor:"Netgear"},
  {prefix:"00:24:B2",vendor:"Netgear"},
  {prefix:"00:26:F2",vendor:"Netgear"},
  {prefix:"60:38:E0",vendor:"Belkin"},{prefix:"94:10:3E",vendor:"Belkin"},
  {prefix:"30:23:03",vendor:"Belkin"},
  {prefix:"00:1B:11",vendor:"D-Link"},{prefix:"28:10:7B",vendor:"D-Link"},
  {prefix:"1C:7E:E5",vendor:"D-Link"},
  {prefix:"00:11:24",vendor:"Apple"},{prefix:"00:1B:63",vendor:"Apple"},
  {prefix:"B8:E8:56",vendor:"Apple"},{prefix:"70:56:81",vendor:"Apple"},
  {prefix:"A8:5C:2C",vendor:"Apple"},
  {prefix:"00:1A:2B",vendor:"Ayecom"},
  {prefix:"F0:9F:C2",vendor:"Ubiquiti"},{prefix:"78:8A:20",vendor:"Ubiquiti"},
  {prefix:"00:27:22",vendor:"Ubiquiti"},
  {prefix:"00:17:88",vendor:"Philips Hue"},{prefix:"EC:B5:FA",vendor:"Philips Hue"},
  {prefix:"00:0E:8F",vendor:"Cisco"},
  {prefix:"70:B3:D5",vendor:"IEEE Registration Authority (IoT)"},
  {prefix:"00:1B:44",vendor:"SanDisk"},{prefix:"00:26:AB",vendor:"Seiko Epson"},
  {prefix:"00:1E:8C",vendor:"ASUSTek"},{prefix:"2C:56:DC",vendor:"ASUSTek"},
  {prefix:"00:04:25",vendor:"Atari"},
  {prefix:"F8:1A:67",vendor:"TP-Link"},{prefix:"50:C7:BF",vendor:"TP-Link"},
  {prefix:"60:E3:27",vendor:"TP-Link"},{prefix:"30:DE:4B",vendor:"TP-Link"},
  {prefix:"EC:08:6B",vendor:"TP-Link"},{prefix:"30:B5:C2",vendor:"TP-Link"},
  {prefix:"A0:F3:C1",vendor:"TP-Link"},
  {prefix:"00:22:6B",vendor:"Cisco"},
  {prefix:"00:17:C8",vendor:"Kyocera"},{prefix:"00:21:E1",vendor:"Nortel"},
  {prefix:"00:24:D7",vendor:"Intel"},
  {prefix:"00:03:93",vendor:"Apple"},{prefix:"00:05:02",vendor:"Apple"},
  {prefix:"AC:BC:32",vendor:"Apple"},{prefix:"88:66:A5",vendor:"Apple"},
  {prefix:"7C:D1:C3",vendor:"Apple"},
  {prefix:"9C:B6:D0",vendor:"Rivet Networks (Killer)"},{prefix:"00:13:3B",vendor:"Speed Dragon/Realtek"},
  {prefix:"54:B2:03",vendor:"Huawei"},{prefix:"00:E0:FC",vendor:"Huawei"},
  {prefix:"48:46:FB",vendor:"Huawei"},{prefix:"CC:A2:23",vendor:"Huawei"},
  {prefix:"4C:B1:6C",vendor:"Huawei"},{prefix:"00:18:82",vendor:"Huawei"},
  {prefix:"88:28:B3",vendor:"Huawei"},
  {prefix:"34:97:F6",vendor:"ASUSTek"},{prefix:"04:D4:C4",vendor:"ASUSTek"},
  {prefix:"B0:6E:BF",vendor:"ASUSTek"},
  {prefix:"00:25:00",vendor:"Apple"},
  {prefix:"00:0D:93",vendor:"Apple"},{prefix:"64:A5:C3",vendor:"Apple"},
  {prefix:"2C:BE:08",vendor:"Apple"},{prefix:"B8:53:AC",vendor:"Apple"},
  {prefix:"84:FC:FE",vendor:"Apple"},{prefix:"10:DD:B1",vendor:"Apple"},
  {prefix:"D8:00:4D",vendor:"Apple"},{prefix:"18:AF:61",vendor:"Apple"},
  {prefix:"E0:C7:67",vendor:"Apple"},
  {prefix:"00:1C:B3",vendor:"Apple"},{prefix:"58:55:CA",vendor:"Apple"},
  {prefix:"E8:6D:52",vendor:"Juniper"},
  {prefix:"F4:CC:55",vendor:"Juniper"},
  {prefix:"64:87:88",vendor:"Juniper"},
  {prefix:"00:23:9C",vendor:"Juniper"},
  {prefix:"48:2C:6A",vendor:"Cisco"},
  {prefix:"C8:9C:1D",vendor:"Cisco"},
  {prefix:"58:AC:78",vendor:"Cisco"},
  {prefix:"D4:AD:71",vendor:"Cisco"},
  {prefix:"B0:7D:47",vendor:"Cisco"},
  {prefix:"70:DB:98",vendor:"Cisco"},
  {prefix:"5C:FC:66",vendor:"Cisco"},
  {prefix:"00:40:96",vendor:"Cisco"},
  {prefix:"00:60:47",vendor:"Cisco"},
  {prefix:"00:E0:1E",vendor:"Cisco"},
  {prefix:"7C:69:F6",vendor:"Cisco"},
  {prefix:"34:DB:FD",vendor:"Cisco"},
  {prefix:"BC:67:78",vendor:"Cisco"},
  {prefix:"00:1B:D4",vendor:"Cisco"},
  {prefix:"F4:4E:05",vendor:"Cisco"},
  {prefix:"68:BC:0C",vendor:"Cisco"},
  {prefix:"20:37:06",vendor:"Cisco"},
  {prefix:"00:14:F2",vendor:"Cisco"},
  {prefix:"5C:A4:8A",vendor:"Cisco"},
  {prefix:"00:13:1A",vendor:"Cisco"},
];

function lookupMAC(mac) {
  const clean = mac.replace(/[^0-9a-fA-F]/g,"").toUpperCase();
  if (clean.length < 6) return { error:"Need at least 6 hex digits" };
  const oui = clean.slice(0,2)+":"+clean.slice(2,4)+":"+clean.slice(4,6);
  const match = OUI_DB.find(e => e.prefix.toUpperCase() === oui);
  return match ? { mac, oui, vendor:match.vendor } : { mac, oui, vendor:"Unknown (not in local DB)" };
}

const COMMON_PORTS = [
  {port:20,proto:"TCP",service:"FTP Data",desc:"File Transfer Protocol data transfer"},
  {port:21,proto:"TCP",service:"FTP",desc:"File Transfer Protocol control"},
  {port:22,proto:"TCP",service:"SSH",desc:"Secure Shell — encrypted remote login"},
  {port:23,proto:"TCP",service:"Telnet",desc:"Unencrypted remote login (insecure)"},
  {port:25,proto:"TCP",service:"SMTP",desc:"Simple Mail Transfer Protocol"},
  {port:53,proto:"TCP/UDP",service:"DNS",desc:"Domain Name System"},
  {port:67,proto:"UDP",service:"DHCP Server",desc:"Dynamic Host Configuration Protocol"},
  {port:68,proto:"UDP",service:"DHCP Client",desc:"Dynamic Host Configuration Protocol"},
  {port:69,proto:"UDP",service:"TFTP",desc:"Trivial File Transfer Protocol"},
  {port:80,proto:"TCP",service:"HTTP",desc:"HyperText Transfer Protocol"},
  {port:88,proto:"TCP/UDP",service:"Kerberos",desc:"Network authentication protocol"},
  {port:110,proto:"TCP",service:"POP3",desc:"Post Office Protocol v3"},
  {port:111,proto:"TCP/UDP",service:"RPCbind",desc:"Open Network Computing Remote Procedure Call"},
  {port:119,proto:"TCP",service:"NNTP",desc:"Network News Transfer Protocol"},
  {port:123,proto:"UDP",service:"NTP",desc:"Network Time Protocol"},
  {port:135,proto:"TCP",service:"MS-RPC",desc:"Microsoft RPC / DCOM endpoint mapper"},
  {port:137,proto:"UDP",service:"NetBIOS-NS",desc:"NetBIOS Name Service"},
  {port:138,proto:"UDP",service:"NetBIOS-DGM",desc:"NetBIOS Datagram Service"},
  {port:139,proto:"TCP",service:"NetBIOS-SSN",desc:"NetBIOS Session Service / SMBv1"},
  {port:143,proto:"TCP",service:"IMAP",desc:"Internet Message Access Protocol"},
  {port:161,proto:"UDP",service:"SNMP",desc:"Simple Network Management Protocol"},
  {port:162,proto:"UDP",service:"SNMP Trap",desc:"SNMP trap notifications"},
  {port:179,proto:"TCP",service:"BGP",desc:"Border Gateway Protocol"},
  {port:389,proto:"TCP",service:"LDAP",desc:"Lightweight Directory Access Protocol"},
  {port:443,proto:"TCP",service:"HTTPS",desc:"HTTP over TLS/SSL"},
  {port:445,proto:"TCP",service:"SMB",desc:"Server Message Block (file sharing)"},
  {port:464,proto:"TCP",service:"Kerberos changepw",desc:"Kerberos password change"},
  {port:465,proto:"TCP",service:"SMTPS",desc:"SMTP over TLS (submission)"},
  {port:500,proto:"UDP",service:"ISAKMP",desc:"IKE for IPsec VPN"},
  {port:514,proto:"UDP",service:"Syslog",desc:"System logging"},
  {port:515,proto:"TCP",service:"LPD",desc:"Line Printer Daemon"},
  {port:520,proto:"UDP",service:"RIP",desc:"Routing Information Protocol"},
  {port:523,proto:"TCP",service:"IBM DB2",desc:"IBM DB2 database"},
  {port:587,proto:"TCP",service:"SMTP Submission",desc:"Email message submission"},
  {port:593,proto:"TCP",service:"MS-RPC HTTP",desc:"Microsoft RPC over HTTP"},
  {port:636,proto:"TCP",service:"LDAPS",desc:"LDAP over SSL"},
  {port:873,proto:"TCP",service:"rsync",desc:"Fast file synchronization"},
  {port:993,proto:"TCP",service:"IMAPS",desc:"IMAP over SSL"},
  {port:995,proto:"TCP",service:"POP3S",desc:"POP3 over SSL"},
  {port:1080,proto:"TCP",service:"SOCKS",desc:"SOCKS proxy"},
  {port:1433,proto:"TCP",service:"MSSQL",desc:"Microsoft SQL Server"},
  {port:1434,proto:"UDP",service:"MSSQL Browser",desc:"MS SQL Server browser service"},
  {port:1521,proto:"TCP",service:"Oracle DB",desc:"Oracle database listener"},
  {port:1723,proto:"TCP",service:"PPTP",desc:"Point-to-Point Tunneling Protocol VPN"},
  {port:2049,proto:"TCP/UDP",service:"NFS",desc:"Network File System"},
  {port:2082,proto:"TCP",service:"cPanel",desc:"cPanel web hosting control panel"},
  {port:2083,proto:"TCP",service:"cPanel SSL",desc:"cPanel over SSL"},
  {port:2181,proto:"TCP",service:"ZooKeeper",desc:"Apache ZooKeeper coordination service"},
  {port:2375,proto:"TCP",service:"Docker",desc:"Docker daemon (unencrypted)"},
  {port:2376,proto:"TCP",service:"Docker TLS",desc:"Docker daemon (TLS)"},
  {port:3000,proto:"TCP",service:"Dev Server",desc:"Common dev server (Grafana, Node)"},
  {port:3306,proto:"TCP",service:"MySQL",desc:"MySQL / MariaDB database"},
  {port:3389,proto:"TCP",service:"RDP",desc:"Remote Desktop Protocol (Windows)"},
  {port:4443,proto:"TCP",service:"Pharos",desc:"Web management / alt HTTPS"},
  {port:4444,proto:"TCP",service:"Metasploit",desc:"Metasploit default listener"},
  {port:5060,proto:"TCP/UDP",service:"SIP",desc:"Session Initiation Protocol (VoIP)"},
  {port:5432,proto:"TCP",service:"PostgreSQL",desc:"PostgreSQL database"},
  {port:5555,proto:"TCP",service:"ADB",desc:"Android Debug Bridge"},
  {port:5672,proto:"TCP",service:"AMQP",desc:"RabbitMQ message broker"},
  {port:5900,proto:"TCP",service:"VNC",desc:"Virtual Network Computing"},
  {port:5984,proto:"TCP",service:"CouchDB",desc:"Apache CouchDB"},
  {port:6379,proto:"TCP",service:"Redis",desc:"Redis in-memory data store"},
  {port:6443,proto:"TCP",service:"K8s API",desc:"Kubernetes API server"},
  {port:6667,proto:"TCP",service:"IRC",desc:"Internet Relay Chat"},
  {port:8000,proto:"TCP",service:"HTTP Alt",desc:"Alternative HTTP / dev server"},
  {port:8080,proto:"TCP",service:"HTTP Proxy",desc:"HTTP proxy / alternative HTTP"},
  {port:8443,proto:"TCP",service:"HTTPS Alt",desc:"Alternative HTTPS"},
  {port:8888,proto:"TCP",service:"HTTP Alt",desc:"Alternative HTTP / Jupyter"},
  {port:9090,proto:"TCP",service:"Prometheus",desc:"Prometheus monitoring"},
  {port:9200,proto:"TCP",service:"Elasticsearch",desc:"Elasticsearch REST API"},
  {port:9418,proto:"TCP",service:"Git",desc:"Git protocol"},
  {port:11211,proto:"TCP",service:"Memcached",desc:"Memcached caching system"},
  {port:27017,proto:"TCP",service:"MongoDB",desc:"MongoDB database"},
  {port:27018,proto:"TCP",service:"MongoDB Shard",desc:"MongoDB shard server"},
  {port:50000,proto:"TCP",service:"SAP",desc:"SAP management console"},
  {port:50070,proto:"TCP",service:"HDFS NameNode",desc:"Hadoop HDFS NameNode web UI"},
];

const IP_STYLES = `
  .ip-wrap { font-family: var(--mono, 'JetBrains Mono', monospace); color: var(--txt, #e0e6ed); max-width: 1100px; margin: 0 auto; padding: 24px; }
  .ip-title { font-family: var(--sans, 'Sora', system-ui, sans-serif); font-size: 1.75rem; font-weight: 700; margin-bottom: 8px; background: linear-gradient(135deg, #ff9800, #f44336); -webkit-background-clip: text; background-clip: text; color: transparent; }
  .ip-sub { color: var(--txt-2, #8899aa); font-size: 0.85rem; margin-bottom: 24px; font-family: var(--sans, 'Sora', system-ui, sans-serif); }
  .ip-tabs { display: flex; gap: 4px; border-bottom: 1px solid var(--border, #1a2233); margin-bottom: 20px; flex-wrap: wrap; }
  .ip-tab { padding: 8px 14px; cursor: pointer; font-size: 0.78rem; border: none; background: transparent; color: var(--txt-2, #8899aa); border-bottom: 2px solid transparent; transition: all 0.15s; font-family: inherit; }
  .ip-tab:hover { color: var(--txt, #e0e6ed); }
  .ip-tab.active { color: #ff9800; border-bottom-color: #ff9800; }
  .ip-panel { display: none; }
  .ip-panel.active { display: block; }
  .ip-card { background: var(--card, #0d1117); border: 1px solid var(--border, #1a2233); border-radius: 8px; padding: 20px; margin-bottom: 16px; }
  .ip-card h3 { font-size: 1rem; font-weight: 600; margin: 0 0 12px; color: var(--txt, #e0e6ed); font-family: var(--sans, 'Sora', system-ui, sans-serif); }
  .ip-label { display: block; font-size: 0.73rem; color: var(--txt-2, #8899aa); margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.05em; }
  .ip-input { width: 100%; box-sizing: border-box; padding: 10px 12px; background: var(--input-bg, #161b22); border: 1px solid var(--border, #1a2233); border-radius: 6px; color: var(--txt, #e0e6ed); font-family: inherit; font-size: 0.85rem; outline: none; }
  .ip-input:focus { border-color: #ff9800; }
  .ip-btn { padding: 8px 18px; border: none; border-radius: 6px; cursor: pointer; font-family: inherit; font-size: 0.8rem; font-weight: 600; background: linear-gradient(135deg, #ff9800, #e65100); color: #fff; transition: all 0.15s; }
  .ip-btn:hover { filter: brightness(1.15); }
  .ip-row { display: flex; justify-content: space-between; align-items: center; padding: 8px 0; border-bottom: 1px solid rgba(26,34,51,0.3); }
  .ip-row-label { color: var(--txt-2, #8899aa); font-size: 0.8rem; }
  .ip-row-value { color: var(--txt, #e0e6ed); font-size: 0.85rem; font-weight: 500; }
  .ip-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; }
  .ip-badge-orange { background: rgba(255,152,0,0.15); color: #ff9800; }
  .ip-badge-green { background: rgba(0,200,83,0.15); color: #00c853; }
  .ip-badge-red { background: rgba(244,67,54,0.15); color: #f44336; }
  .ip-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 16px; }
  .ip-table { width: 100%; border-collapse: collapse; font-size: 0.78rem; }
  .ip-table th { text-align: left; padding: 8px 10px; background: #0a0e16; color: var(--txt-2, #8899aa); font-weight: 500; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .ip-table td { padding: 8px 10px; border-bottom: 1px solid rgba(26,34,51,0.3); }
  .ip-port-search { margin-bottom: 12px; }
  @media (max-width: 700px) { .ip-grid { grid-template-columns: 1fr; } }
`;

export function renderIPTools(container) {
  const s = document.createElement("style"); s.textContent = IP_STYLES; document.head.appendChild(s);
  container.innerHTML = `
    <div class="ip-wrap">
      <div class="ip-title">IP Tools</div>
      <div class="ip-sub">Subnet calculator, CIDR converter, MAC lookup, port reference — entirely in your browser</div>
      <div class="ip-tabs">
        <button class="ip-tab active" data-p="subnet">Subnet Calc</button>
        <button class="ip-tab" data-p="range">IP Range</button>
        <button class="ip-tab" data-p="mac">MAC Lookup</button>
        <button class="ip-tab" data-p="ports">Port Reference</button>
      </div>
      <div class="ip-panel active" id="ipp-subnet">
        <div class="ip-card">
          <h3>IPv4 Subnet Calculator</h3>
          <div style="display:flex;gap:8px;align-items:end;flex-wrap:wrap;">
            <div style="flex:1;min-width:180px;"><label class="ip-label">IPv4 Address</label><input class="ip-input" id="sub-ip" placeholder="192.168.1.0" value="192.168.1.100"></div>
            <div style="width:100px;"><label class="ip-label">CIDR (/)</label><input class="ip-input" id="sub-cidr" placeholder="24" value="24" type="number" min="0" max="32"></div>
            <button class="ip-btn" id="sub-calc">Calculate</button>
          </div>
          <div id="sub-output"></div>
        </div>
      </div>
      <div class="ip-panel" id="ipp-range">
        <div class="ip-card">
          <h3>IP Range Calculator</h3>
          <div style="display:flex;gap:8px;align-items:end;flex-wrap:wrap;">
            <div style="flex:1;"><label class="ip-label">Start IP</label><input class="ip-input" id="range-start" placeholder="192.168.1.1"></div>
            <div style="flex:1;"><label class="ip-label">End IP</label><input class="ip-input" id="range-end" placeholder="192.168.1.254"></div>
            <button class="ip-btn" id="range-calc">Calculate</button>
          </div>
          <div id="range-output"></div>
        </div>
      </div>
      <div class="ip-panel" id="ipp-mac">
        <div class="ip-card">
          <h3>MAC Address OUI Lookup</h3>
          <div style="display:flex;gap:8px;align-items:end;flex-wrap:wrap;">
            <div style="flex:1;"><label class="ip-label">MAC Address</label><input class="ip-input" id="mac-input" placeholder="00:50:56:XX:XX:XX"></div>
            <button class="ip-btn" id="mac-btn">Lookup</button>
          </div>
          <div id="mac-output"></div>
        </div>
      </div>
      <div class="ip-panel" id="ipp-ports">
        <div class="ip-card">
          <h3>Common Ports Reference</h3>
          <div class="ip-port-search"><input class="ip-input" id="port-search" placeholder="Search by port number, service name, or protocol..."></div>
          <div style="max-height:600px;overflow-y:auto;"><table class="ip-table"><thead><tr><th>Port</th><th>Proto</th><th>Service</th><th>Description</th></tr></thead><tbody id="port-tbody"></tbody></table></div>
        </div>
      </div>
    </div>`;

  // Tabs
  container.querySelectorAll(".ip-tab").forEach(t => t.addEventListener("click", () => {
    container.querySelectorAll(".ip-tab").forEach(x=>x.classList.remove("active"));
    container.querySelectorAll(".ip-panel").forEach(x=>x.classList.remove("active"));
    t.classList.add("active");
    container.querySelector("#ipp-"+t.dataset.p).classList.add("active");
  }));

  // Subnet calc
  container.querySelector("#sub-calc").addEventListener("click", () => {
    const r = subnetCalc(container.querySelector("#sub-ip").value.trim(), container.querySelector("#sub-cidr").value);
    const o = container.querySelector("#sub-output");
    if (r.error) { o.innerHTML = `<div style="color:#f44336;margin-top:12px;">${r.error}</div>`; return; }
    o.innerHTML = `<div class="ip-grid" style="margin-top:16px;">
      <div class="ip-card"><h3>Network Details</h3>
        <div class="ip-row"><span class="ip-row-label">CIDR</span><span class="ip-row-value">${r.cidr}</span></div>
        <div class="ip-row"><span class="ip-row-label">Network</span><span class="ip-row-value">${r.network}</span></div>
        <div class="ip-row"><span class="ip-row-label">Broadcast</span><span class="ip-row-value">${r.broadcast}</span></div>
        <div class="ip-row"><span class="ip-row-label">Subnet mask</span><span class="ip-row-value">${r.mask}</span></div>
        <div class="ip-row"><span class="ip-row-label">Wildcard</span><span class="ip-row-value">${r.wildcard}</span></div>
        <div class="ip-row"><span class="ip-row-label">First host</span><span class="ip-row-value">${r.firstHost}</span></div>
        <div class="ip-row"><span class="ip-row-label">Last host</span><span class="ip-row-value">${r.lastHost}</span></div>
        <div class="ip-row"><span class="ip-row-label">Usable hosts</span><span class="ip-row-value" style="color:#ff9800;font-weight:700;">${r.totalHosts.toLocaleString()}</span></div>
        <div class="ip-row"><span class="ip-row-label">Total addresses</span><span class="ip-row-value">${r.totalAddresses.toLocaleString()}</span></div>
      </div>
      <div class="ip-card"><h3>Classification</h3>
        <div class="ip-row"><span class="ip-row-label">IP class</span><span class="ip-row-value"><span class="ip-badge ip-badge-orange">Class ${r.ipClass.class}</span></span></div>
        <div class="ip-row"><span class="ip-row-label">Class range</span><span class="ip-row-value" style="font-size:0.78rem;">${r.ipClass.range}</span></div>
        <div class="ip-row"><span class="ip-row-label">Default mask</span><span class="ip-row-value">${r.ipClass.defaultMask}</span></div>
        <div class="ip-row"><span class="ip-row-label">Private?</span><span class="ip-row-value"><span class="ip-badge ${r.isPrivate.private?"ip-badge-green":"ip-badge-red"}">${r.isPrivate.private?"Yes":"No"}</span> ${r.isPrivate.range}</span></div>
        <div class="ip-row"><span class="ip-row-label">IPv4-mapped IPv6</span><span class="ip-row-value" style="font-size:0.78rem;">${r.mapv6}</span></div>
      </div></div>
      <div class="ip-card" style="margin-top:8px;"><h3>Binary</h3>
        <div class="ip-row"><span class="ip-row-label">IP</span><span class="ip-row-value" style="font-size:0.78rem;">${r.ipBinary}</span></div>
        <div class="ip-row"><span class="ip-row-label">Mask</span><span class="ip-row-value" style="font-size:0.78rem;">${r.maskBinary}</span></div>
        <div class="ip-row"><span class="ip-row-label">Network</span><span class="ip-row-value" style="font-size:0.78rem;">${r.networkBinary}</span></div>
      </div>`;
  });

  // Range calc
  container.querySelector("#range-calc").addEventListener("click", () => {
    const r = ipRange(container.querySelector("#range-start").value.trim(), container.querySelector("#range-end").value.trim());
    const o = container.querySelector("#range-output");
    if (r.error) { o.innerHTML = `<div style="color:#f44336;margin-top:12px;">${r.error}</div>`; return; }
    o.innerHTML = `<div class="ip-card" style="margin-top:12px;"><div class="ip-row"><span class="ip-row-label">Start</span><span class="ip-row-value">${r.start}</span></div><div class="ip-row"><span class="ip-row-label">End</span><span class="ip-row-value">${r.end}</span></div><div class="ip-row"><span class="ip-row-label">Total IPs</span><span class="ip-row-value" style="color:#ff9800;font-weight:700;">${r.count.toLocaleString()}</span></div></div>`;
  });

  // MAC lookup
  container.querySelector("#mac-btn").addEventListener("click", () => {
    const r = lookupMAC(container.querySelector("#mac-input").value.trim());
    const o = container.querySelector("#mac-output");
    if (r.error) { o.innerHTML = `<div style="color:#f44336;margin-top:12px;">${r.error}</div>`; return; }
    o.innerHTML = `<div class="ip-card" style="margin-top:12px;"><div class="ip-row"><span class="ip-row-label">MAC</span><span class="ip-row-value">${r.mac}</span></div><div class="ip-row"><span class="ip-row-label">OUI Prefix</span><span class="ip-row-value">${r.oui}</span></div><div class="ip-row"><span class="ip-row-label">Vendor</span><span class="ip-row-value" style="color:#ff9800;font-weight:700;">${r.vendor}</span></div></div>`;
  });

  // Ports
  function renderPorts(filter) {
    const f = (filter||"").toLowerCase();
    const filtered = f ? COMMON_PORTS.filter(p => p.port.toString().includes(f)||p.service.toLowerCase().includes(f)||p.proto.toLowerCase().includes(f)||p.desc.toLowerCase().includes(f)) : COMMON_PORTS;
    const tbody = container.querySelector("#port-tbody");
    tbody.innerHTML = filtered.map(p => `<tr><td style="font-weight:600;color:#ff9800;">${p.port}</td><td>${p.proto}</td><td style="font-weight:600;">${p.service}</td><td style="color:var(--txt-2,#8899aa);font-size:0.75rem;">${p.desc}</td></tr>`).join("");
  }
  container.querySelector("#port-search").addEventListener("input", (e) => renderPorts(e.target.value));
  renderPorts();
}
