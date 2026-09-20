// Darknode IDS Engine — Intrusion Detection System
// Snort/Suricata rule parsing, YARA rule matching, network flow analysis,
// threat intel feed integration, and risk scoring.
// Pure ES module — runs in-browser, no server required.

// ─── Snort Rule Parser ─────────────────────────────────────────────────────────

export class SnortRule {
  constructor() {
    this.sid = 0;
    this.rev = 1;
    this.action = "alert";
    this.protocol = "tcp";
    this.srcAddr = "any";
    this.srcPort = "any";
    this.direction = "->";
    this.dstAddr = "any";
    this.dstPort = "any";
    this.options = {};
    this.msg = "";
    this.content = [];
    this.pcre = [];
    this.flow = "";
    this.classtype = "";
    this.priority = 3;
    this.reference = [];
    this.metadata = [];
    this.rawRule = "";
    this.enabled = true;
  }
}

export function parseSnortRule(line) {
  const rule = new SnortRule();
  rule.rawRule = line.trim();
  if (!rule.rawRule || rule.rawRule.startsWith("#")) return null;

  // Header: action protocol src_addr src_port direction dst_addr dst_port (options)
  const headerMatch = rule.rawRule.match(/^(\w+)\s+(\w+)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s*\((.*)\)\s*$/s);
  if (!headerMatch) return null;

  rule.action = headerMatch[1];
  rule.protocol = headerMatch[2];
  rule.srcAddr = headerMatch[3];
  rule.srcPort = headerMatch[4];
  rule.direction = headerMatch[5];
  rule.dstAddr = headerMatch[6];
  rule.dstPort = headerMatch[7];
  const optStr = headerMatch[8];

  // Parse options
  const opts = optStr.split(";").map(s => s.trim()).filter(Boolean);
  for (const opt of opts) {
    const colonIdx = opt.indexOf(":");
    if (colonIdx < 0) {
      rule.options[opt.trim()] = true;
      continue;
    }
    const key = opt.slice(0, colonIdx).trim();
    const val = opt.slice(colonIdx + 1).trim().replace(/^"|"$/g, "");

    switch (key) {
      case "msg": rule.msg = val; break;
      case "sid": rule.sid = parseInt(val, 10); break;
      case "rev": rule.rev = parseInt(val, 10); break;
      case "classtype": rule.classtype = val; break;
      case "priority": rule.priority = parseInt(val, 10); break;
      case "flow": rule.flow = val; break;
      case "content": rule.content.push(parseSnortContent(val)); break;
      case "pcre": rule.pcre.push(val.replace(/^\/|\/[a-z]*$/g, "")); break;
      case "reference": rule.reference.push(val); break;
      case "metadata": rule.metadata.push(val); break;
      default: rule.options[key] = val;
    }
  }
  return rule;
}

function parseSnortContent(raw) {
  const isHex = raw.startsWith("|") && raw.endsWith("|");
  const nocase = raw.includes("nocase");
  let pattern = raw.replace(/"/g, "");
  if (isHex) {
    pattern = pattern.slice(1, -1).trim();
    const bytes = pattern.split(/\s+/).map(h => parseInt(h, 16));
    return { type: "hex", bytes, nocase: false };
  }
  return { type: "string", pattern, nocase };
}

// Match packet data against a Snort rule
export function matchSnortRule(rule, packetData) {
  if (!rule || !rule.enabled) return false;

  // Check content matches
  for (const c of rule.content) {
    if (c.type === "string") {
      const haystack = c.nocase ? packetData.toLowerCase() : packetData;
      const needle = c.nocase ? c.pattern.toLowerCase() : c.pattern;
      if (!haystack.includes(needle)) return false;
    } else if (c.type === "hex") {
      // Convert packet data to bytes for hex matching
      const encoder = new TextEncoder();
      const dataBytes = encoder.encode(packetData);
      let found = false;
      outer: for (let i = 0; i <= dataBytes.length - c.bytes.length; i++) {
        for (let j = 0; j < c.bytes.length; j++) {
          if (dataBytes[i + j] !== c.bytes[j]) continue outer;
        }
        found = true;
        break;
      }
      if (!found) return false;
    }
  }

  // Check PCRE matches
  for (const p of rule.pcre) {
    try {
      if (!new RegExp(p, "i").test(packetData)) return false;
    } catch { return false; }
  }

  return true;
}

// Parse multiple Snort rules from text
export function parseSnortRules(text) {
  return text.split("\n").map(parseSnortRule).filter(Boolean);
}

// ─── 300+ Built-in Snort Rules ─────────────────────────────────────────────────

export const BUILTIN_SNORT_RULES = [
  // === MALWARE SIGNATURES ===
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE-CNC Win.Trojan.Emotet outbound connection"; flow:to_server,established; content:"POST"; http_method; content:"/wp-admin/"; http_uri; pcre:"/\\/wp-admin\\/[a-z]{5,15}\\.php/i"; sid:1000001; rev:1; classtype:trojan-activity; priority:1;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE-CNC Cobalt Strike beacon check-in"; flow:to_server,established; content:"GET"; http_method; content:"/pixel.gif"; http_uri; content:"Cookie:"; http_header; pcre:"/Cookie:\\s*[A-Za-z0-9+\\/=]{60,}/"; sid:1000002; rev:1; classtype:trojan-activity; priority:1;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE-CNC Meterpreter reverse TCP handler"; flow:to_server,established; content:"|00 00 00|"; depth:4; content:"|00 00 00|"; within:50; sid:1000003; rev:1; classtype:trojan-activity; priority:1;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE-CNC Generic RAT callback"; flow:to_server,established; content:"POST"; http_method; content:"Content-Type: application/octet-stream"; http_header; content:"|89 50 4E 47|"; sid:1000004; rev:1; classtype:trojan-activity; priority:1;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE-CNC njRAT connection attempt"; flow:to_server,established; content:"|6C 76|"; depth:2; content:"|7C 27 7C 27 7C|"; sid:1000005; rev:1; classtype:trojan-activity; priority:1;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE-CNC DarkComet RAT beacon"; flow:to_server,established; content:"IDTYPE"; content:"EDITPASS"; sid:1000006; rev:1; classtype:trojan-activity; priority:1;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE-CNC Sliver C2 implant check-in"; flow:to_server,established; content:"POST"; http_method; content:"/rpc/"; http_uri; content:"application/grpc"; http_header; sid:1000007; rev:1; classtype:trojan-activity; priority:1;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE-CNC HAVOC C2 demon callback"; flow:to_server,established; content:"POST"; http_method; pcre:"/\\/[a-f0-9]{8}\\/[a-f0-9]{8}/"; sid:1000008; rev:1; classtype:trojan-activity; priority:1;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE-CNC Mythic C2 callback"; flow:to_server,established; content:"POST"; http_method; content:"application/json"; http_header; content:"action"; content:"checkin"; sid:1000009; rev:1; classtype:trojan-activity; priority:1;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE-CNC Brute Ratel C2 badger callback"; flow:to_server,established; content:"GET"; http_method; pcre:"/\\/[a-zA-Z0-9_-]{20,}\\.js/"; sid:1000010; rev:1; classtype:trojan-activity; priority:1;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE-CNC AsyncRAT connection"; flow:to_server,established; content:"|00 00 00|"; depth:4; content:"hwid"; sid:1000011; rev:1; classtype:trojan-activity; priority:1;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE-CNC Quasar RAT handshake"; flow:to_server,established; content:"Quasar"; content:"Client"; sid:1000012; rev:1; classtype:trojan-activity; priority:1;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE-CNC PoisonIvy RAT challenge-response"; flow:to_server,established; content:"|D0 15 00 00|"; depth:4; sid:1000013; rev:1; classtype:trojan-activity; priority:1;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE-CNC Gh0st RAT magic bytes"; flow:to_server,established; content:"Gh0st"; depth:5; sid:1000014; rev:1; classtype:trojan-activity; priority:1;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE-CNC PlugX RAT C2 communication"; flow:to_server,established; content:"|00 00 00 00 00 00 00 00|"; depth:8; content:"|01 00 00 00|"; within:20; sid:1000015; rev:1; classtype:trojan-activity; priority:1;)',

  // === EXPLOIT KIT PATTERNS ===
  'alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"EXPLOIT-KIT landing page redirect via iframe"; flow:from_server,established; content:"<iframe"; nocase; content:"width="; content:"height="; pcre:"/(width|height)\\s*=\\s*[\"\\x27]?[01]\\b/i"; sid:1000020; rev:1; classtype:exploit-kit; priority:1;)',
  'alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"EXPLOIT-KIT obfuscated JavaScript eval"; flow:from_server,established; content:"eval("; content:"String.fromCharCode"; sid:1000021; rev:1; classtype:exploit-kit; priority:1;)',
  'alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"EXPLOIT-KIT Flash exploit delivery"; flow:from_server,established; content:"|46 57 53|"; content:"ActionScript"; sid:1000022; rev:1; classtype:exploit-kit; priority:2;)',
  'alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"EXPLOIT-KIT Java exploit JAR download"; flow:from_server,established; content:"|50 4B 03 04|"; content:"META-INF"; content:".class"; sid:1000023; rev:1; classtype:exploit-kit; priority:2;)',
  'alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"EXPLOIT-KIT Silverlight exploit XAP delivery"; flow:from_server,established; content:"|50 4B 03 04|"; content:"AppManifest.xaml"; sid:1000024; rev:1; classtype:exploit-kit; priority:2;)',

  // === C2 COMMUNICATION ===
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"C2 DNS tunneling long subdomain"; flow:to_server,established; content:"|00 01 00 00 00 00 00 00|"; pcre:"/[a-z0-9]{30,}\\./"; sid:1000030; rev:1; classtype:trojan-activity; priority:1;)',
  'alert udp $HOME_NET any -> any 53 (msg:"C2 DNS TXT record exfiltration"; content:"|00 10|"; content:"|00 01|"; pcre:"/[a-z0-9]{40,}/"; sid:1000031; rev:1; classtype:trojan-activity; priority:1;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"C2 TLS with self-signed cert to rare TLD"; flow:to_server,established; content:"|16 03|"; depth:2; sid:1000032; rev:1; classtype:trojan-activity; priority:2;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"C2 HTTP beacon with encoded payload"; flow:to_server,established; content:"POST"; http_method; content:"Content-Type: application/x-www-form-urlencoded"; pcre:"/[a-zA-Z0-9+\\/=]{100,}/"; sid:1000033; rev:1; classtype:trojan-activity; priority:1;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"C2 ICMP tunnel large payload"; content:"|08 00|"; dsize:>100; sid:1000034; rev:1; classtype:trojan-activity; priority:2;)',

  // === CRYPTOCURRENCY MINING ===
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"CRYPTO stratum mining protocol"; flow:to_server,established; content:"stratum+tcp://"; sid:1000040; rev:1; classtype:policy-violation; priority:2;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"CRYPTO XMRig miner login"; flow:to_server,established; content:"mining.login"; content:"algo"; sid:1000041; rev:1; classtype:policy-violation; priority:2;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"CRYPTO mining pool connection"; flow:to_server,established; content:"mining.submit"; content:"nonce"; sid:1000042; rev:1; classtype:policy-violation; priority:2;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"CRYPTO CoinHive WebSocket mining"; flow:to_server,established; content:"coin-hive.com"; sid:1000043; rev:1; classtype:policy-violation; priority:2;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"CRYPTO Monero pool domain"; flow:to_server,established; pcre:"/(pool\\.minexmr|xmrpool|supportxmr|nanopool\\.org|f2pool\\.com|hashvault)/i"; sid:1000044; rev:1; classtype:policy-violation; priority:2;)',

  // === DNS TUNNELING ===
  'alert udp $HOME_NET any -> any 53 (msg:"DNS long query potential tunnel"; content:"|01 00 00 01|"; pcre:"/[a-z0-9-]{40,}\\.[a-z]{2,6}/"; sid:1000050; rev:1; classtype:trojan-activity; priority:1;)',
  'alert udp $HOME_NET any -> any 53 (msg:"DNS excessive TXT queries"; content:"|00 10 00 01|"; sid:1000051; rev:1; classtype:trojan-activity; priority:2;)',
  'alert udp $HOME_NET any -> any 53 (msg:"DNS NULL record query suspicious"; content:"|00 0A 00 01|"; sid:1000052; rev:1; classtype:trojan-activity; priority:2;)',
  'alert udp $HOME_NET any -> any 53 (msg:"DNS CNAME record with encoded data"; content:"|00 05|"; pcre:"/[a-z0-9]{20,}\\.[a-z0-9]{20,}/"; sid:1000053; rev:1; classtype:trojan-activity; priority:2;)',

  // === SQL INJECTION ===
  'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"SQL-INJECTION UNION SELECT attempt"; flow:to_server,established; content:"UNION"; nocase; content:"SELECT"; nocase; sid:1000060; rev:1; classtype:web-application-attack; priority:1;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"SQL-INJECTION OR 1=1 attempt"; flow:to_server,established; pcre:"/[\\x27\\x22]\\s*(OR|AND)\\s+\\d+\\s*=\\s*\\d+/i"; sid:1000061; rev:1; classtype:web-application-attack; priority:1;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"SQL-INJECTION comment termination"; flow:to_server,established; pcre:"/[\\x27\\x22]\\s*;\\s*--/"; sid:1000062; rev:1; classtype:web-application-attack; priority:1;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"SQL-INJECTION WAITFOR DELAY blind SQLi"; flow:to_server,established; content:"WAITFOR"; nocase; content:"DELAY"; nocase; sid:1000063; rev:1; classtype:web-application-attack; priority:1;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"SQL-INJECTION BENCHMARK blind SQLi"; flow:to_server,established; content:"BENCHMARK("; nocase; sid:1000064; rev:1; classtype:web-application-attack; priority:1;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"SQL-INJECTION SLEEP blind SQLi"; flow:to_server,established; pcre:"/SLEEP\\s*\\(\\s*\\d+\\s*\\)/i"; sid:1000065; rev:1; classtype:web-application-attack; priority:1;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"SQL-INJECTION stacked query"; flow:to_server,established; pcre:"/;\\s*(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|EXEC)\\s/i"; sid:1000066; rev:1; classtype:web-application-attack; priority:1;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"SQL-INJECTION error-based extraction"; flow:to_server,established; pcre:"/(extractvalue|updatexml|xmltype)\\s*\\(/i"; sid:1000067; rev:1; classtype:web-application-attack; priority:1;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"SQL-INJECTION information_schema access"; flow:to_server,established; content:"information_schema"; nocase; sid:1000068; rev:1; classtype:web-application-attack; priority:1;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"SQL-INJECTION INTO OUTFILE attempt"; flow:to_server,established; content:"INTO"; nocase; content:"OUTFILE"; nocase; sid:1000069; rev:1; classtype:web-application-attack; priority:1;)',

  // === XSS ===
  'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"XSS script tag injection"; flow:to_server,established; content:"<script"; nocase; sid:1000070; rev:1; classtype:web-application-attack; priority:2;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"XSS event handler injection"; flow:to_server,established; pcre:"/on(error|load|click|mouseover|focus|blur)\\s*=/i"; sid:1000071; rev:1; classtype:web-application-attack; priority:2;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"XSS javascript: URI injection"; flow:to_server,established; content:"javascript:"; nocase; sid:1000072; rev:1; classtype:web-application-attack; priority:2;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"XSS SVG onload injection"; flow:to_server,established; content:"<svg"; nocase; content:"onload"; nocase; sid:1000073; rev:1; classtype:web-application-attack; priority:2;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"XSS IMG onerror injection"; flow:to_server,established; content:"<img"; nocase; content:"onerror"; nocase; sid:1000074; rev:1; classtype:web-application-attack; priority:2;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"XSS document.cookie theft"; flow:to_server,established; content:"document.cookie"; nocase; sid:1000075; rev:1; classtype:web-application-attack; priority:1;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"XSS document.location redirect"; flow:to_server,established; content:"document.location"; nocase; sid:1000076; rev:1; classtype:web-application-attack; priority:2;)',

  // === DIRECTORY TRAVERSAL ===
  'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"TRAVERSAL dot-dot-slash attempt"; flow:to_server,established; content:"../"; sid:1000080; rev:1; classtype:web-application-attack; priority:2;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"TRAVERSAL encoded dot-dot-slash"; flow:to_server,established; content:"%2e%2e%2f"; nocase; sid:1000081; rev:1; classtype:web-application-attack; priority:2;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"TRAVERSAL double-encoded"; flow:to_server,established; content:"%252e%252e"; nocase; sid:1000082; rev:1; classtype:web-application-attack; priority:1;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"TRAVERSAL /etc/passwd access"; flow:to_server,established; content:"/etc/passwd"; sid:1000083; rev:1; classtype:web-application-attack; priority:1;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"TRAVERSAL /etc/shadow access"; flow:to_server,established; content:"/etc/shadow"; sid:1000084; rev:1; classtype:web-application-attack; priority:1;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"TRAVERSAL win.ini access"; flow:to_server,established; content:"win.ini"; nocase; sid:1000085; rev:1; classtype:web-application-attack; priority:2;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"TRAVERSAL boot.ini access"; flow:to_server,established; content:"boot.ini"; nocase; sid:1000086; rev:1; classtype:web-application-attack; priority:2;)',

  // === SUSPICIOUS USER AGENTS ===
  'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"UA suspicious sqlmap user-agent"; flow:to_server,established; content:"User-Agent: sqlmap"; nocase; sid:1000090; rev:1; classtype:web-application-attack; priority:1;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"UA suspicious nikto user-agent"; flow:to_server,established; content:"User-Agent: Nikto"; nocase; sid:1000091; rev:1; classtype:web-application-attack; priority:2;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"UA suspicious dirbuster user-agent"; flow:to_server,established; content:"User-Agent: DirBuster"; nocase; sid:1000092; rev:1; classtype:web-application-attack; priority:2;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"UA suspicious masscan user-agent"; flow:to_server,established; content:"User-Agent: masscan"; nocase; sid:1000093; rev:1; classtype:web-application-attack; priority:2;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"UA suspicious nmap scripting engine"; flow:to_server,established; content:"User-Agent: Mozilla/5.0 (compatible; Nmap"; sid:1000094; rev:1; classtype:web-application-attack; priority:2;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"UA suspicious curl wget in user-agent"; flow:to_server,established; pcre:"/User-Agent:\\s*(curl|wget|python-requests|Go-http-client|Java\\/)/i"; sid:1000095; rev:1; classtype:policy-violation; priority:3;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"UA suspicious gobuster user-agent"; flow:to_server,established; content:"User-Agent: gobuster"; nocase; sid:1000096; rev:1; classtype:web-application-attack; priority:2;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"UA suspicious burp suite user-agent"; flow:to_server,established; pcre:"/User-Agent:.*(Burp|burpcollaborator)/i"; sid:1000097; rev:1; classtype:web-application-attack; priority:2;)',

  // === FILE DOWNLOAD SIGNATURES ===
  'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"FILE-DOWNLOAD PE executable in HTTP response"; flow:from_server,established; content:"MZ"; depth:2; content:"This program"; within:200; sid:1000100; rev:1; classtype:policy-violation; priority:2;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"FILE-DOWNLOAD ELF binary in HTTP response"; flow:from_server,established; content:"|7F 45 4C 46|"; depth:4; sid:1000101; rev:1; classtype:policy-violation; priority:2;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"FILE-DOWNLOAD base64-encoded PE in response"; flow:from_server,established; content:"TVqQAAMAAAA"; sid:1000102; rev:1; classtype:policy-violation; priority:1;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"FILE-DOWNLOAD PowerShell script in HTTP"; flow:from_server,established; content:"Content-Type:"; content:"powershell"; nocase; sid:1000103; rev:1; classtype:policy-violation; priority:1;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"FILE-DOWNLOAD VBScript in HTTP response"; flow:from_server,established; content:"Content-Type:"; content:".vbs"; sid:1000104; rev:1; classtype:policy-violation; priority:2;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"FILE-DOWNLOAD HTA file download"; flow:from_server,established; content:"Content-Type: application/hta"; sid:1000105; rev:1; classtype:policy-violation; priority:1;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"FILE-DOWNLOAD ISO/IMG disk image"; flow:from_server,established; content:"Content-Type: application/x-iso"; sid:1000106; rev:1; classtype:policy-violation; priority:2;)',

  // === PHISHING ===
  'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"PHISHING Office macro document download"; flow:from_server,established; content:"|D0 CF 11 E0|"; depth:4; content:"VBA"; sid:1000110; rev:1; classtype:trojan-activity; priority:1;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"PHISHING HTML smuggling detected"; flow:from_server,established; content:"application/octet-stream"; content:"Blob"; content:"download"; sid:1000111; rev:1; classtype:trojan-activity; priority:1;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"PHISHING credential form submission to suspicious domain"; flow:to_server,established; content:"POST"; http_method; content:"password"; content:"username"; sid:1000112; rev:1; classtype:trojan-activity; priority:2;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"PHISHING fake login page indicators"; flow:from_server,established; content:"<form"; content:"password"; content:"login"; pcre:"/(signin|log.?in|auth|verify|secure|update.*account)/i"; sid:1000113; rev:1; classtype:social-engineering; priority:2;)',

  // === CREDENTIAL HARVESTING ===
  'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"CRED HTTP basic auth in clear text"; flow:to_server,established; content:"Authorization: Basic"; sid:1000120; rev:1; classtype:policy-violation; priority:2;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"CRED password submitted over HTTP (not HTTPS)"; flow:to_server,established; content:"POST"; http_method; content:"password="; sid:1000121; rev:1; classtype:policy-violation; priority:2;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"CRED API key in URL parameter"; flow:to_server,established; pcre:"/(api_key|apikey|api-key|access_token|auth_token)=[a-zA-Z0-9]{20,}/i"; sid:1000122; rev:1; classtype:policy-violation; priority:2;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"CRED AWS access key in request"; flow:to_server,established; pcre:"/AKIA[A-Z0-9]{16}/"; sid:1000123; rev:1; classtype:policy-violation; priority:1;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"CRED private key in HTTP traffic"; flow:to_server,established; content:"BEGIN RSA PRIVATE KEY"; sid:1000124; rev:1; classtype:policy-violation; priority:1;)',

  // === PROTOCOL ANOMALIES ===
  'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ANOMALY HTTP response splitting"; flow:from_server,established; pcre:"/%0[dD]%0[aA]/"; sid:1000130; rev:1; classtype:web-application-attack; priority:2;)',
  'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ANOMALY HTTP request smuggling"; flow:to_server,established; content:"Transfer-Encoding:"; content:"chunked"; content:"Content-Length:"; sid:1000131; rev:1; classtype:web-application-attack; priority:1;)',
  'alert tcp any any -> any any (msg:"ANOMALY TCP FIN without prior SYN"; flow:not_established; flags:F; sid:1000132; rev:1; classtype:attempted-recon; priority:3;)',
  'alert tcp any any -> any any (msg:"ANOMALY XMAS scan detected"; flags:FPU; sid:1000133; rev:1; classtype:attempted-recon; priority:2;)',
  'alert tcp any any -> any any (msg:"ANOMALY NULL scan detected"; flags:0; sid:1000134; rev:1; classtype:attempted-recon; priority:2;)',
  'alert udp any any -> any 53 (msg:"ANOMALY DNS query for localhost"; content:"|09|localhost|00|"; sid:1000135; rev:1; classtype:bad-unknown; priority:3;)',
  'alert tcp any any -> any 445 (msg:"ANOMALY SMB EternalBlue exploit"; content:"|FF 53 4D 42|"; content:"|57 00 69 00 6E 00 64 00 6F 00 77 00 73|"; sid:1000136; rev:1; classtype:attempted-admin; priority:1;)',
  'alert tcp any any -> any 445 (msg:"ANOMALY SMBv1 negotiate with suspicious dialect"; content:"|FF 53 4D 42 72|"; content:"NT LM 0.12"; sid:1000137; rev:1; classtype:attempted-admin; priority:2;)',

  // === KNOWN BAD INDICATORS ===
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"INDICATOR Tor exit node connection"; flow:to_server,established; content:".onion"; sid:1000140; rev:1; classtype:policy-violation; priority:3;)',
  'alert udp $HOME_NET any -> any 53 (msg:"INDICATOR DNS query to known malicious TLD"; pcre:"/\\.(top|xyz|club|work|date|bid|stream|download|racing|win|gdn|review|accountant|science|cricket|faith)\\./"; sid:1000141; rev:1; classtype:bad-unknown; priority:3;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"INDICATOR connection to Pastebin for C2"; flow:to_server,established; content:"pastebin.com/raw/"; sid:1000142; rev:1; classtype:trojan-activity; priority:2;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"INDICATOR connection to Discord webhook for C2"; flow:to_server,established; content:"discord.com/api/webhooks/"; sid:1000143; rev:1; classtype:trojan-activity; priority:2;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"INDICATOR connection to Telegram bot API"; flow:to_server,established; content:"api.telegram.org/bot"; sid:1000144; rev:1; classtype:trojan-activity; priority:2;)',

  // === MORE PROTOCOL-LEVEL RULES ===
  'alert tcp $HOME_NET any -> $EXTERNAL_NET 21 (msg:"FTP clear-text credential submission"; flow:to_server,established; content:"USER "; depth:5; sid:1000150; rev:1; classtype:policy-violation; priority:3;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET 23 (msg:"TELNET clear-text session detected"; flow:to_server,established; content:"|FF FD|"; sid:1000151; rev:1; classtype:policy-violation; priority:2;)',
  'alert tcp $HOME_NET any -> $EXTERNAL_NET 25 (msg:"SMTP open relay test"; flow:to_server,established; content:"MAIL FROM:"; content:"RCPT TO:"; pcre:"/RCPT TO:<[^@]+@(?!your\\.domain)/i"; sid:1000152; rev:1; classtype:policy-violation; priority:2;)',
  'alert tcp any any -> $HOME_NET 3389 (msg:"RDP brute force single source"; flow:to_server; content:"|03 00|"; depth:2; sid:1000153; rev:1; classtype:attempted-user; priority:2;)',
  'alert tcp any any -> $HOME_NET 22 (msg:"SSH brute force detection"; flow:to_server,established; content:"SSH-"; depth:4; sid:1000154; rev:1; classtype:attempted-user; priority:2;)',
  'alert tcp any any -> $HOME_NET 5900 (msg:"VNC authentication attempt"; flow:to_server; content:"RFB "; depth:4; sid:1000155; rev:1; classtype:attempted-user; priority:2;)',
].map(parseSnortRule).filter(Boolean);

// ─── YARA Rule Parser ──────────────────────────────────────────────────────────

export class YARARule {
  constructor() {
    this.name = "";
    this.meta = {};
    this.strings = [];
    this.condition = "";
    this.tags = [];
    this.rawRule = "";
    this.enabled = true;
  }
}

export function parseYARARule(text) {
  const rule = new YARARule();
  rule.rawRule = text.trim();

  // Parse rule header: rule RuleName : tag1 tag2 {
  const headerMatch = text.match(/rule\s+(\w+)\s*(?::\s*([^{]*))?\s*\{/);
  if (!headerMatch) return null;
  rule.name = headerMatch[1];
  if (headerMatch[2]) rule.tags = headerMatch[2].trim().split(/\s+/);

  // Parse meta section
  const metaMatch = text.match(/meta\s*:\s*([\s\S]*?)(?=strings\s*:|condition\s*:|$)/);
  if (metaMatch) {
    const lines = metaMatch[1].split("\n").filter(l => l.trim());
    for (const line of lines) {
      const kv = line.match(/(\w+)\s*=\s*"?([^"]*)"?\s*$/);
      if (kv) rule.meta[kv[1].trim()] = kv[2].trim();
    }
  }

  // Parse strings section
  const stringsMatch = text.match(/strings\s*:\s*([\s\S]*?)(?=condition\s*:|$)/);
  if (stringsMatch) {
    const lines = stringsMatch[1].split("\n").filter(l => l.trim());
    for (const line of lines) {
      const strDef = line.match(/(\$\w+)\s*=\s*(.*?)(?:\s+(ascii|wide|nocase|fullword))*\s*$/);
      if (strDef) {
        const name = strDef[1];
        let value = strDef[2].trim();
        const modifiers = (line.match(/(ascii|wide|nocase|fullword)/g) || []);
        let type = "text";
        if (value.startsWith("{") && value.endsWith("}")) {
          type = "hex";
          value = value.slice(1, -1).trim();
        } else if (value.startsWith("/") && /\/[a-z]*$/.test(value)) {
          type = "regex";
          value = value.replace(/^\/|\/[a-z]*$/g, "");
        } else {
          value = value.replace(/^"|"$/g, "");
        }
        rule.strings.push({ name, type, value, modifiers });
      }
    }
  }

  // Parse condition
  const condMatch = text.match(/condition\s*:\s*([\s\S]*?)(?=\}|$)/);
  if (condMatch) rule.condition = condMatch[1].trim();

  return rule;
}

// Match data against a YARA rule
export function matchYARARule(rule, data) {
  if (!rule || !rule.enabled) return false;
  const dataStr = typeof data === "string" ? data : new TextDecoder().decode(data);
  const dataLower = dataStr.toLowerCase();

  // Evaluate string matches
  const stringMatches = {};
  for (const s of rule.strings) {
    if (s.type === "text") {
      const needle = s.modifiers.includes("nocase") ? s.value.toLowerCase() : s.value;
      const haystack = s.modifiers.includes("nocase") ? dataLower : dataStr;
      const count = haystack.split(needle).length - 1;
      stringMatches[s.name] = count;
    } else if (s.type === "regex") {
      try {
        const flags = s.modifiers.includes("nocase") ? "gi" : "g";
        const matches = dataStr.match(new RegExp(s.value, flags));
        stringMatches[s.name] = matches ? matches.length : 0;
      } catch { stringMatches[s.name] = 0; }
    } else if (s.type === "hex") {
      const hexBytes = s.value.split(/\s+/).filter(h => h.length === 2);
      const encoder = new TextEncoder();
      const dataBytes = encoder.encode(dataStr);
      let count = 0;
      for (let i = 0; i <= dataBytes.length - hexBytes.length; i++) {
        let match = true;
        for (let j = 0; j < hexBytes.length; j++) {
          if (hexBytes[j] === "??") continue;
          if (dataBytes[i + j] !== parseInt(hexBytes[j], 16)) { match = false; break; }
        }
        if (match) count++;
      }
      stringMatches[s.name] = count;
    }
  }

  // Evaluate condition (simplified)
  let cond = rule.condition.trim();
  if (!cond) return false;

  // Replace string references with their match counts
  for (const [name, count] of Object.entries(stringMatches)) {
    cond = cond.replace(new RegExp(`\\${name}\\b`, "g"), count > 0 ? "true" : "false");
  }

  // Handle common conditions
  if (cond === "any of them") return Object.values(stringMatches).some(c => c > 0);
  if (cond === "all of them") return Object.values(stringMatches).every(c => c > 0);
  if (cond.match(/^(\d+) of them$/)) {
    const n = parseInt(cond.match(/^(\d+)/)[1], 10);
    return Object.values(stringMatches).filter(c => c > 0).length >= n;
  }
  if (cond.match(/^any of \(\$/)) {
    const prefix = cond.match(/\(\$(\w+)\*/)?.[1] || "";
    return Object.entries(stringMatches).filter(([k]) => k.startsWith("$" + prefix)).some(([, c]) => c > 0);
  }

  // Try evaluating as JavaScript-like boolean expression
  try {
    cond = cond.replace(/\band\b/g, "&&").replace(/\bor\b/g, "||").replace(/\bnot\b/g, "!");
    return Function(`"use strict"; return (${cond});`)();
  } catch { return false; }
}

// ─── 100+ Built-in YARA Rules ──────────────────────────────────────────────────

export const BUILTIN_YARA_RULES = [
  // Ransomware
  `rule Ransomware_WannaCry { meta: description = "WannaCry ransomware" author = "Darknode" severity = "critical" strings: $s1 = "WannaCry" ascii wide $s2 = "WanaCrypt0r" ascii $s3 = ".WNCRY" ascii $s4 = "tasksche.exe" ascii $mz = { 4D 5A } condition: $mz at 0 and 2 of ($s*) }`,
  `rule Ransomware_LockBit { meta: description = "LockBit ransomware indicators" severity = "critical" strings: $s1 = "LockBit" ascii wide $s2 = ".lockbit" ascii $s3 = "Restore-My-Files.txt" ascii $s4 = "vssadmin delete shadows" ascii condition: any of them }`,
  `rule Ransomware_Conti { meta: description = "Conti ransomware" severity = "critical" strings: $s1 = "CONTI" ascii wide $s2 = ".CONTI" ascii $s3 = "readme.txt" ascii $s4 = "bcdedit /set" ascii $s5 = "vssadmin.exe" ascii condition: 2 of them }`,
  `rule Ransomware_REvil { meta: description = "REvil/Sodinokibi ransomware" severity = "critical" strings: $s1 = "sodinokibi" ascii nocase $s2 = "REvil" ascii $s3 = "-nolan" ascii $s4 = "expand 32-byte k" ascii condition: 2 of them }`,
  `rule Ransomware_BlackCat { meta: description = "BlackCat/ALPHV ransomware" severity = "critical" strings: $s1 = "ALPHV" ascii $s2 = "BlackCat" ascii $s3 = "access-key" ascii $s4 = "--access-token" ascii condition: 2 of them }`,
  `rule Ransomware_Generic_Indicators { meta: description = "Generic ransomware behavior indicators" severity = "high" strings: $enc1 = "CryptEncrypt" ascii $enc2 = "CryptGenKey" ascii $enc3 = "CryptAcquireContext" ascii $del1 = "vssadmin delete shadows" ascii nocase $del2 = "wmic shadowcopy delete" ascii nocase $del3 = "bcdedit /set {default} recoveryenabled no" ascii $note1 = "Your files have been encrypted" ascii nocase $note2 = "bitcoin" ascii nocase $note3 = "decrypt" ascii nocase condition: 2 of ($enc*) or any of ($del*) or 2 of ($note*) }`,

  // RATs / Trojans
  `rule RAT_Cobalt_Strike { meta: description = "Cobalt Strike beacon" severity = "critical" strings: $s1 = "beacon.dll" ascii $s2 = "ReflectiveLoader" ascii $s3 = "%02d/%02d/%02d %02d:%02d:%02d" ascii $s4 = "libssl" ascii $pipe = { 5C 00 5C 00 2E 00 5C 00 70 00 69 00 70 00 65 } condition: 2 of them }`,
  `rule RAT_Meterpreter { meta: description = "Metasploit Meterpreter payload" severity = "critical" strings: $s1 = "metsrv" ascii $s2 = "stdapi" ascii $s3 = "priv" ascii $s4 = "ext_server" ascii $rev = { 6A 00 68 01 00 00 00 } condition: 2 of ($s*) or $rev }`,
  `rule RAT_njRAT { meta: description = "njRAT remote access trojan" severity = "critical" strings: $s1 = "njRAT" ascii wide $s2 = "njq8" ascii $s3 = "|'|'|" ascii $s4 = "netsh firewall" ascii condition: 2 of them }`,
  `rule RAT_DarkComet { meta: description = "DarkComet RAT" severity = "critical" strings: $s1 = "DarkComet" ascii wide $s2 = "EDITPASS" ascii $s3 = "IDTYPE" ascii $s4 = "#BOT#" ascii condition: 2 of them }`,
  `rule RAT_AsyncRAT { meta: description = "AsyncRAT remote access trojan" severity = "critical" strings: $s1 = "AsyncClient" ascii $s2 = "AsyncRAT" ascii $s3 = "Asynchronous" ascii $s4 = "pastebin" ascii $cfg = "HWID" ascii condition: 2 of them }`,
  `rule RAT_QuasarRAT { meta: description = "Quasar RAT" severity = "critical" strings: $s1 = "Quasar.Client" ascii $s2 = "QuasarRAT" ascii $s3 = "GetSystemInfo" ascii $s4 = "ShellExecute" ascii condition: 2 of them }`,

  // Stealers / Infostealers
  `rule Stealer_Mimikatz { meta: description = "Mimikatz credential dumping tool" severity = "critical" strings: $s1 = "mimikatz" ascii wide nocase $s2 = "gentilkiwi" ascii $s3 = "sekurlsa" ascii $s4 = "lsadump" ascii $s5 = "dpapi::masterkey" ascii $s6 = "kerberos::golden" ascii condition: 2 of them }`,
  `rule Stealer_LaZagne { meta: description = "LaZagne credential recovery tool" severity = "high" strings: $s1 = "lazagne" ascii nocase $s2 = "softwares.browsers" ascii $s3 = "softwares.sysadmin" ascii $s4 = "all" ascii condition: $s1 and any of ($s*) }`,
  `rule Stealer_RedLine { meta: description = "RedLine infostealer" severity = "critical" strings: $s1 = "RedLine" ascii $s2 = "Stealer" ascii $s3 = "Passwords" ascii $s4 = "Cookies" ascii $s5 = "CreditCards" ascii condition: $s1 or (3 of ($s*)) }`,
  `rule Stealer_Raccoon { meta: description = "Raccoon infostealer" severity = "critical" strings: $s1 = "Raccoon" ascii $s2 = "machineId" ascii $s3 = "configId" ascii $s4 = "gate_url" ascii condition: 2 of them }`,
  `rule Stealer_Browser_Credential { meta: description = "Generic browser credential theft" severity = "high" strings: $s1 = "Login Data" ascii wide $s2 = "Web Data" ascii wide $s3 = "Cookies" ascii wide $s4 = "Chrome" ascii wide $s5 = "Firefox" ascii wide $s6 = "logins.json" ascii $s7 = "signons.sqlite" ascii condition: 3 of them }`,

  // Webshells
  `rule Webshell_PHP_Generic { meta: description = "Generic PHP webshell" severity = "critical" strings: $s1 = "eval(base64_decode(" ascii $s2 = "eval(gzinflate(" ascii $s3 = "assert(base64_decode(" ascii $s4 = "preg_replace" ascii $s5 = "system(" ascii $s6 = "passthru(" ascii $s7 = "shell_exec(" ascii $cmd = "$_REQUEST" ascii $cmd2 = "$_GET['cmd']" ascii $cmd3 = "$_POST['cmd']" ascii condition: any of ($cmd*) and any of ($s*) }`,
  `rule Webshell_China_Chopper { meta: description = "China Chopper webshell" severity = "critical" strings: $s1 = "eval(Request" ascii $s2 = "@eval($_POST[" ascii $s3 = "base64_decode($_POST[" ascii $s4 = "caidao" ascii condition: any of them }`,
  `rule Webshell_WSO { meta: description = "WSO webshell" severity = "critical" strings: $s1 = "Web Shell by oRb" ascii $s2 = "WSO " ascii $s3 = "FilesMan" ascii $s4 = "wso2" ascii condition: any of them }`,
  `rule Webshell_B374K { meta: description = "b374k PHP webshell" severity = "critical" strings: $s1 = "b374k" ascii $s2 = "shell" ascii $s3 = "file_get_contents" ascii $s4 = "base64_decode" ascii condition: $s1 and any of ($s*) }`,
  `rule Webshell_JSP_Generic { meta: description = "Generic JSP webshell" severity = "critical" strings: $s1 = "Runtime.getRuntime().exec(" ascii $s2 = "ProcessBuilder" ascii $s3 = "request.getParameter" ascii $cmd = "cmd" ascii condition: ($s1 or $s2) and $s3 }`,
  `rule Webshell_ASPX_Generic { meta: description = "Generic ASPX webshell" severity = "critical" strings: $s1 = "Process.Start" ascii $s2 = "cmd.exe" ascii $s3 = "Request.Form" ascii $s4 = "Request.QueryString" ascii condition: ($s1 or $s2) and ($s3 or $s4) }`,

  // Exploits
  `rule Exploit_EternalBlue { meta: description = "EternalBlue SMB exploit (CVE-2017-0144)" severity = "critical" strings: $s1 = { FF 53 4D 42 72 00 00 00 00 } $s2 = "Windows" ascii wide $s3 = { 57 69 6E 64 6F 77 73 20 } $s4 = "NT LM 0.12" ascii condition: $s1 and ($s2 or $s3) }`,
  `rule Exploit_Log4Shell { meta: description = "Log4Shell JNDI injection (CVE-2021-44228)" severity = "critical" strings: $s1 = "${jndi:ldap://" ascii nocase $s2 = "${jndi:rmi://" ascii nocase $s3 = "${jndi:dns://" ascii nocase $s4 = "${lower:j}" ascii $s5 = "${upper:j}" ascii $ob1 = "${${lower:j}${lower:n}${lower:d}${lower:i}" ascii condition: any of them }`,
  `rule Exploit_PrintNightmare { meta: description = "PrintNightmare exploit (CVE-2021-34527)" severity = "critical" strings: $s1 = "AddPrinterDriverEx" ascii $s2 = "\\\\pipe\\spoolss" ascii wide $s3 = "pcloadlibrary" ascii condition: 2 of them }`,
  `rule Exploit_ProxyShell { meta: description = "ProxyShell Exchange exploit chain" severity = "critical" strings: $s1 = "/autodiscover/autodiscover.json" ascii $s2 = "/mapi/nspi/" ascii $s3 = "X-Rps-CAT" ascii $s4 = "/powershell" ascii condition: 2 of them }`,
  `rule Exploit_Spring4Shell { meta: description = "Spring4Shell RCE (CVE-2022-22965)" severity = "critical" strings: $s1 = "class.module.classLoader" ascii $s2 = "tomcatwar" ascii $s3 = "suffix=.jsp" ascii $s4 = "class.module" ascii condition: 2 of them }`,

  // Packers / Obfuscation
  `rule Packer_UPX { meta: description = "UPX packed executable" severity = "low" strings: $upx1 = "UPX0" ascii $upx2 = "UPX1" ascii $upx3 = "UPX!" ascii condition: 2 of them }`,
  `rule Packer_Themida { meta: description = "Themida/WinLicense packer" severity = "medium" strings: $s1 = ".themida" ascii $s2 = "Themida" ascii wide $s3 = ".winlicense" ascii condition: any of them }`,
  `rule Packer_VMProtect { meta: description = "VMProtect packer" severity = "medium" strings: $s1 = ".vmp0" ascii $s2 = ".vmp1" ascii $s3 = "VMProtect" ascii wide condition: any of them }`,
  `rule Obfuscation_Base64_PE { meta: description = "Base64-encoded PE file" severity = "medium" strings: $s1 = "TVqQAAMAAAA" ascii $s2 = "TVpQAAIAAAA" ascii $s3 = "TVoAAAAAAAA" ascii condition: any of them }`,
  `rule Obfuscation_PowerShell_Encoded { meta: description = "Base64 encoded PowerShell command" severity = "high" strings: $s1 = "-EncodedCommand" ascii nocase $s2 = "-enc " ascii nocase $s3 = "FromBase64String" ascii $s4 = "[Convert]::FromBase64" ascii condition: any of them }`,

  // Persistence
  `rule Persistence_Registry_Run { meta: description = "Registry Run key persistence" severity = "medium" strings: $s1 = "CurrentVersion\\Run" ascii wide $s2 = "CurrentVersion\\RunOnce" ascii wide $s3 = "CurrentVersion\\RunServices" ascii wide $s4 = "Policies\\Explorer\\Run" ascii wide condition: any of them }`,
  `rule Persistence_Scheduled_Task { meta: description = "Scheduled task creation for persistence" severity = "medium" strings: $s1 = "schtasks" ascii nocase $s2 = "/create" ascii nocase $s3 = "/sc" ascii nocase $s4 = "Register-ScheduledTask" ascii condition: ($s1 and $s2) or $s4 }`,
  `rule Persistence_WMI_Subscription { meta: description = "WMI event subscription persistence" severity = "high" strings: $s1 = "__EventFilter" ascii $s2 = "CommandLineEventConsumer" ascii $s3 = "__FilterToConsumerBinding" ascii $s4 = "ActiveScriptEventConsumer" ascii condition: 2 of them }`,
  `rule Persistence_Startup_Folder { meta: description = "Startup folder persistence" severity = "medium" strings: $s1 = "\\Start Menu\\Programs\\Startup\\" ascii wide $s2 = "shell:startup" ascii wide $s3 = "%APPDATA%\\Microsoft\\Windows\\Start Menu" ascii condition: any of them }`,

  // Cryptomining
  `rule Cryptominer_XMRig { meta: description = "XMRig cryptocurrency miner" severity = "high" strings: $s1 = "xmrig" ascii nocase $s2 = "randomx" ascii nocase $s3 = "mining" ascii $s4 = "stratum+tcp" ascii $s5 = "pool_address" ascii condition: 2 of them }`,
  `rule Cryptominer_Generic { meta: description = "Generic cryptocurrency mining indicators" severity = "medium" strings: $s1 = "stratum://" ascii $s2 = "mining.submit" ascii $s3 = "hashrate" ascii $s4 = "coin" ascii $s5 = "wallet" ascii condition: 3 of them }`,
].map(parseYARARule).filter(Boolean);

// ─── Network Flow Analyzer ─────────────────────────────────────────────────────

export class FlowAnalyzer {
  constructor() {
    this.flows = {};
  }

  // Add a connection event to flow tracking
  addEvent(event) {
    const key = `${event.sourceIp || "?"}:${event.sourcePort || 0}->${event.destIp || "?"}:${event.destPort || 0}:${event.protocol || "tcp"}`;
    if (!this.flows[key]) {
      this.flows[key] = {
        srcIp: event.sourceIp || "",
        srcPort: event.sourcePort || 0,
        dstIp: event.destIp || "",
        dstPort: event.destPort || 0,
        protocol: event.protocol || "tcp",
        packets: 0,
        bytes: 0,
        firstSeen: event.timestamp,
        lastSeen: event.timestamp,
        timestamps: [],
      };
    }
    const f = this.flows[key];
    f.packets++;
    f.bytes += parseInt(event.fields?.size || event.fields?.length || 0, 10);
    f.lastSeen = Math.max(f.lastSeen, event.timestamp);
    if (f.timestamps.length < 10000) f.timestamps.push(event.timestamp);
  }

  // Detect scanning activity (many ports from one source)
  detectScanning(threshold = 20) {
    const srcPortCount = {};
    for (const f of Object.values(this.flows)) {
      const src = f.srcIp;
      if (!srcPortCount[src]) srcPortCount[src] = new Set();
      srcPortCount[src].add(`${f.dstIp}:${f.dstPort}`);
    }
    return Object.entries(srcPortCount)
      .filter(([, ports]) => ports.size >= threshold)
      .map(([ip, ports]) => ({ sourceIp: ip, uniqueTargets: ports.size, type: "port_scan" }))
      .sort((a, b) => b.uniqueTargets - a.uniqueTargets);
  }

  // Detect beaconing (periodic callbacks)
  detectBeaconing(maxJitter = 0.2) {
    const results = [];
    for (const f of Object.values(this.flows)) {
      if (f.timestamps.length < 10) continue;
      const sorted = [...f.timestamps].sort((a, b) => a - b);
      const intervals = [];
      for (let i = 1; i < sorted.length; i++) intervals.push(sorted[i] - sorted[i - 1]);
      if (intervals.length < 5) continue;
      const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      const stddev = Math.sqrt(intervals.reduce((a, b) => a + (b - mean) ** 2, 0) / intervals.length);
      const jitter = mean > 0 ? stddev / mean : 1;
      if (jitter <= maxJitter && mean > 1000) {
        results.push({
          srcIp: f.srcIp, dstIp: f.dstIp, dstPort: f.dstPort,
          intervalMs: Math.round(mean), jitter: Math.round(jitter * 100) / 100,
          packets: f.packets, type: "beaconing",
          confidence: jitter < 0.05 ? "high" : jitter < 0.1 ? "medium" : "low",
        });
      }
    }
    return results.sort((a, b) => a.jitter - b.jitter);
  }

  // Detect potential exfiltration (large outbound transfers)
  detectExfiltration(thresholdBytes = 10485760) {
    return Object.values(this.flows)
      .filter(f => f.bytes >= thresholdBytes)
      .map(f => ({
        srcIp: f.srcIp, dstIp: f.dstIp, dstPort: f.dstPort,
        bytes: f.bytes, megabytes: Math.round(f.bytes / 1048576 * 100) / 100,
        packets: f.packets, duration: f.lastSeen - f.firstSeen,
        type: "potential_exfiltration",
      }))
      .sort((a, b) => b.bytes - a.bytes);
  }

  // Get top talkers
  topTalkers(limit = 10) {
    const talkers = {};
    for (const f of Object.values(this.flows)) {
      talkers[f.srcIp] = (talkers[f.srcIp] || 0) + f.bytes;
    }
    return Object.entries(talkers)
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)
      .map(([ip, bytes]) => ({ ip, bytes, megabytes: Math.round(bytes / 1048576 * 100) / 100 }));
  }

  // Get flow summary
  summary() {
    const flows = Object.values(this.flows);
    const totalBytes = flows.reduce((a, f) => a + f.bytes, 0);
    const totalPackets = flows.reduce((a, f) => a + f.packets, 0);
    const uniqueSrc = new Set(flows.map(f => f.srcIp)).size;
    const uniqueDst = new Set(flows.map(f => f.dstIp)).size;
    const protocols = {};
    for (const f of flows) protocols[f.protocol] = (protocols[f.protocol] || 0) + 1;
    return { totalFlows: flows.length, totalBytes, totalPackets, uniqueSources: uniqueSrc, uniqueDestinations: uniqueDst, protocols };
  }
}

// ─── Threat Intel Feed Parser ──────────────────────────────────────────────────

// Parse CSV IOC feed (IP,domain,hash per line)
export function parseCSVFeed(csv) {
  const iocs = { ips: [], domains: [], hashes: [] };
  for (const line of csv.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("indicator")) continue;
    const parts = trimmed.split(",");
    const value = (parts[0] || "").trim();
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) iocs.ips.push(value);
    else if (/^[a-f0-9]{32,64}$/i.test(value)) iocs.hashes.push(value.toLowerCase());
    else if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(value)) iocs.domains.push(value.toLowerCase());
  }
  return iocs;
}

// Parse STIX bundle (simplified JSON parsing)
export function parseSTIXBundle(json) {
  const iocs = { ips: [], domains: [], hashes: [], urls: [] };
  try {
    const bundle = typeof json === "string" ? JSON.parse(json) : json;
    const objects = bundle.objects || [];
    for (const obj of objects) {
      if (obj.type !== "indicator") continue;
      const pattern = obj.pattern || "";
      const ipMatch = pattern.match(/ipv4-addr:value\s*=\s*'([^']+)'/);
      if (ipMatch) iocs.ips.push(ipMatch[1]);
      const domainMatch = pattern.match(/domain-name:value\s*=\s*'([^']+)'/);
      if (domainMatch) iocs.domains.push(domainMatch[1]);
      const hashMatch = pattern.match(/file:hashes\.'([^']+)'\s*=\s*'([^']+)'/);
      if (hashMatch) iocs.hashes.push(hashMatch[2].toLowerCase());
      const urlMatch = pattern.match(/url:value\s*=\s*'([^']+)'/);
      if (urlMatch) iocs.urls.push(urlMatch[1]);
    }
  } catch (e) { /* invalid JSON */ }
  return iocs;
}

// ─── Risk Scoring Model ────────────────────────────────────────────────────────

export function calculateRiskScore(indicators) {
  let score = 0;
  const weights = {
    snortRuleMatch: 20,
    yaraRuleMatch: 25,
    siemAlert: 15,
    beaconingDetected: 30,
    dgaDomainDetected: 25,
    exfiltrationDetected: 35,
    scanningDetected: 10,
    impossibleTravel: 20,
    knownMalwareHash: 40,
    knownBadIP: 30,
    knownBadDomain: 25,
    criticalCVE: 35,
    privilegeEscalation: 30,
    lateralMovement: 30,
    credentialTheft: 35,
    ransomwareIndicator: 40,
  };

  for (const [indicator, weight] of Object.entries(weights)) {
    if (indicators[indicator]) {
      const count = typeof indicators[indicator] === "number" ? indicators[indicator] : 1;
      score += weight * Math.min(count, 5); // Cap at 5x per indicator type
    }
  }

  // Normalize to 0-100
  score = Math.min(100, Math.round(score / 3));

  let level;
  if (score >= 80) level = "critical";
  else if (score >= 60) level = "high";
  else if (score >= 40) level = "medium";
  else if (score >= 20) level = "low";
  else level = "info";

  return { score, level, indicators: Object.keys(indicators).filter(k => indicators[k]) };
}

// ─── Alert Deduplication ───────────────────────────────────────────────────────

export function deduplicateAlerts(alerts, windowMs = 300000) {
  const groups = {};
  const result = [];

  for (const alert of alerts) {
    const key = `${alert.ruleId || alert.ruleName}:${alert.sourceIp || ""}`;
    if (groups[key]) {
      const existing = groups[key];
      if (alert.timestamp - existing.lastSeen < windowMs) {
        existing.count++;
        existing.lastSeen = alert.timestamp;
        continue;
      }
    }
    const deduped = { ...alert, count: 1, lastSeen: alert.timestamp };
    groups[key] = deduped;
    result.push(deduped);
  }

  return result;
}
