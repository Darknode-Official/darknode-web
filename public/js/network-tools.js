// Darknode Network Tools -- a self-contained suite of network-engineering and
// network-security reference calculators and lookups. Everything here runs
// entirely client-side: no network calls, no backend. Pure vanilla JS + DOM.
//
// export function renderNetworkTools(main) mounts a tab bar + active tool
// panel into the given container element. Each tool is implemented as an
// independent render(root) function that owns its own markup and events.

// ---------------------------------------------------------------------------
//  Small shared helpers
// ---------------------------------------------------------------------------

function el(tag, attrs = {}, html = "") {
  const e = document.createElement(tag);
  for (const k in attrs) {
    if (k === "class") e.className = attrs[k];
    else if (k === "style") e.style.cssText = attrs[k];
    else e.setAttribute(k, attrs[k]);
  }
  if (html) e.innerHTML = html;
  return e;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function pad(n, w) { return String(n).padStart(w, "0"); }

// Standard input -> transform -> output tool, matching the toolkit.js pattern.
function io(root, ops, ph = "Input") {
  root.innerHTML = `<textarea class="tk-in" rows="4" placeholder="${ph}"></textarea>
    <div class="tk-btns">${ops.map((o, i) => `<button class="btn sm" data-i="${i}">${o.label}</button>`).join("")}</div>
    <pre class="tk-out"></pre>`;
  const inp = root.querySelector(".tk-in"), out = root.querySelector(".tk-out");
  root.querySelector(".tk-btns").onclick = async (e) => {
    const b = e.target.closest("button[data-i]"); if (!b) return;
    try { out.textContent = await ops[+b.dataset.i].fn(inp.value); }
    catch (err) { out.textContent = "Error: " + err.message; }
  };
}

// Single-line labeled text field row, used by several calculators below.
function field(label, id, value = "", placeholder = "", type = "text") {
  return `<div class="tk-row"><label style="min-width:150px;display:inline-block">${label}</label>
    <input class="tk-f" id="${id}" type="${type}" value="${value}" placeholder="${placeholder}"></div>`;
}

function selectField(label, id, options, selected) {
  return `<div class="tk-row"><label style="min-width:150px;display:inline-block">${label}</label>
    <select class="tk-f" id="${id}">${options.map((o) => `<option value="${o.value}" ${o.value === selected ? "selected" : ""}>${o.label}</option>`).join("")}</select></div>`;
}

// ---------------------------------------------------------------------------
//  IPv4 bit-level helpers, shared by subnet / IP-info / CIDR-range tools
// ---------------------------------------------------------------------------

function parseIPv4(s) {
  const parts = String(s).trim().split(".");
  if (parts.length !== 4) throw new Error("expected 4 octets, e.g. 192.168.1.1");
  const oct = parts.map((p) => {
    if (!/^\d{1,3}$/.test(p)) throw new Error(`invalid octet: "${p}"`);
    const n = Number(p);
    if (n < 0 || n > 255) throw new Error(`octet out of range: "${p}"`);
    return n;
  });
  return oct;
}

function ipToInt(oct) {
  return (oct[0] * 16777216 + oct[1] * 65536 + oct[2] * 256 + oct[3]) >>> 0;
}

function intToIp(n) {
  return [24, 16, 8, 0].map((s) => (n >>> s) & 255).join(".");
}

function octetBinary(oct) {
  return oct.map((o) => pad(o.toString(2), 8));
}

function maskFromBits(bits) {
  if (bits === 0) return 0;
  return (0xFFFFFFFF << (32 - bits)) >>> 0;
}

function ipClass(firstOctet) {
  if (firstOctet >= 1 && firstOctet <= 126) return "A";
  if (firstOctet === 127) return "A (loopback range)";
  if (firstOctet >= 128 && firstOctet <= 191) return "B";
  if (firstOctet >= 192 && firstOctet <= 223) return "C";
  if (firstOctet >= 224 && firstOctet <= 239) return "D (multicast)";
  if (firstOctet >= 240 && firstOctet <= 255) return "E (experimental/reserved)";
  return "0 (this network / reserved)";
}

function classDefaultMaskBits(firstOctet) {
  if (firstOctet >= 1 && firstOctet <= 126) return 8;
  if (firstOctet >= 128 && firstOctet <= 191) return 16;
  if (firstOctet >= 192 && firstOctet <= 223) return 24;
  return null;
}

function isPrivateIPv4(oct) {
  const [a, b] = oct;
  if (a === 10) return "Private (RFC 1918) -- 10.0.0.0/8";
  if (a === 172 && b >= 16 && b <= 31) return "Private (RFC 1918) -- 172.16.0.0/12";
  if (a === 192 && b === 168) return "Private (RFC 1918) -- 192.168.0.0/16";
  if (a === 127) return "Loopback (RFC 5735) -- 127.0.0.0/8";
  if (a === 169 && b === 254) return "Link-local (RFC 3927) -- 169.254.0.0/16";
  if (a === 100 && b >= 64 && b <= 127) return "Carrier-grade NAT (RFC 6598) -- 100.64.0.0/10";
  if (a === 0) return "\"This\" network (RFC 791) -- 0.0.0.0/8";
  if (a === 192 && b === 0 && oct[2] === 0) return "IETF protocol assignments (RFC 6890) -- 192.0.0.0/24";
  if (a === 192 && b === 0 && oct[2] === 2) return "Documentation/TEST-NET-1 (RFC 5737) -- 192.0.2.0/24";
  if (a === 198 && b === 51 && oct[2] === 100) return "Documentation/TEST-NET-2 (RFC 5737) -- 198.51.100.0/24";
  if (a === 203 && b === 0 && oct[2] === 113) return "Documentation/TEST-NET-3 (RFC 5737) -- 203.0.113.0/24";
  if (a === 198 && b >= 18 && b <= 19) return "Benchmark testing (RFC 2544) -- 198.18.0.0/15";
  if (a >= 224 && a <= 239) return "Multicast (RFC 5771)";
  if (a === 255 && b === 255 && oct[2] === 255 && oct[3] === 255) return "Limited broadcast (RFC 919)";
  if (a >= 240) return "Reserved for future use (RFC 1112)";
  return "Public / globally routable";
}

// ---------------------------------------------------------------------------
//  Tool 1 -- Subnet Calculator
// ---------------------------------------------------------------------------

function renderSubnetCalculator(root) {
  root.innerHTML = `
    <div class="panel">
      <p class="muted">Enter an address in CIDR notation (e.g. <span class="mono">192.168.1.0/24</span>) to get
      the network address, broadcast address, usable host range, wildcard mask, binary breakdown, and class info.</p>
      ${field("CIDR", "sn-cidr", "192.168.1.0/24", "e.g. 10.0.0.0/8")}
      <div class="tk-btns"><button class="btn sm" id="sn-go">Calculate</button>
      <button class="btn ghost sm" id="sn-clear">Clear</button></div>
      <div id="sn-out"></div>

      <p class="pg-sub" style="margin-top:26px">VLSM planner</p>
      <p class="muted">Variable Length Subnet Masking splits one base network into differently-sized subnets to
      match each segment's actual host requirement, rather than wasting addresses on a uniform prefix length.
      Enter a base network and a list of required host counts (one per line, largest first is not required --
      the planner sorts automatically) to get an allocation plan.</p>
      ${field("Base network", "vlsm-base", "10.0.0.0/24", "e.g. 10.0.0.0/24")}
      <textarea class="tk-in" id="vlsm-hosts" rows="5" placeholder="Required host counts, one per line, e.g.&#10;50&#10;20&#10;10&#10;2">50
20
10
2</textarea>
      <div class="tk-btns"><button class="btn sm" id="vlsm-go">Plan subnets</button></div>
      <div id="vlsm-out"></div>

      <p class="pg-sub" style="margin-top:26px">CIDR aggregator (route summarization)</p>
      <p class="muted">Given a list of networks, find the smallest set of supernets that covers them all --
      useful for summarizing routes to reduce routing-table size. Enter one CIDR block per line.</p>
      <textarea class="tk-in" id="agg-in" rows="5" placeholder="One CIDR per line, e.g.&#10;192.168.0.0/24&#10;192.168.1.0/24&#10;192.168.2.0/24&#10;192.168.3.0/24">192.168.0.0/24
192.168.1.0/24
192.168.2.0/24
192.168.3.0/24</textarea>
      <div class="tk-btns"><button class="btn sm" id="agg-go">Aggregate</button></div>
      <div id="agg-out"></div>
    </div>`;

  const calc = () => {
    const raw = root.querySelector("#sn-cidr").value.trim();
    const out = root.querySelector("#sn-out");
    try {
      const [ipStr, bitsStr] = raw.split("/");
      if (bitsStr === undefined) throw new Error("missing prefix length, e.g. /24");
      const bits = Number(bitsStr);
      if (!Number.isInteger(bits) || bits < 0 || bits > 32) throw new Error("prefix length must be 0-32");
      const oct = parseIPv4(ipStr);
      const ipInt = ipToInt(oct);
      const mask = maskFromBits(bits);
      const wildcard = (~mask) >>> 0;
      const network = (ipInt & mask) >>> 0;
      const broadcast = (network | wildcard) >>> 0;
      const totalAddrs = Math.pow(2, 32 - bits);
      const usable = bits >= 31 ? (bits === 32 ? 1 : 2) : totalAddrs - 2;
      const firstHost = bits >= 31 ? network : network + 1;
      const lastHost = bits >= 31 ? broadcast : broadcast - 1;
      const cls = ipClass(oct[0]);
      const netOct = intToIp(network).split(".").map(Number);
      const bcOct = intToIp(broadcast).split(".").map(Number);
      const maskOct = intToIp(mask).split(".").map(Number);
      const wcOct = intToIp(wildcard).split(".").map(Number);

      const binRow = (label, octets) => `<tr><td class="mono">${label}</td>${octets.map((o) => `<td class="mono">${pad(o.toString(2), 8)}</td>`).join("")}<td class="mono">${octets.join(".")}</td></tr>`;

      // Supernet: the /n-1 aggregate that contains this network, when possible.
      let supernetInfo = "n/a (already /0)";
      if (bits > 0) {
        const superBits = bits - 1;
        const superMask = maskFromBits(superBits);
        const superNet = (ipInt & superMask) >>> 0;
        supernetInfo = `${intToIp(superNet)}/${superBits}`;
      }

      // Next / previous adjacent subnets of the same size.
      const blockSize = totalAddrs;
      const nextSubnet = network + blockSize <= 0xFFFFFFFF ? `${intToIp((network + blockSize) >>> 0)}/${bits}` : "n/a (end of address space)";
      const prevSubnet = network - blockSize >= 0 ? `${intToIp((network - blockSize) >>> 0)}/${bits}` : "n/a (start of address space)";

      out.innerHTML = `
        <div class="dl-cmd" style="margin-top:14px">
          <div class="stat-l">Network</div><div class="mono">${intToIp(network)}</div>
          <div class="stat-l">Broadcast</div><div class="mono">${intToIp(broadcast)}</div>
          <div class="stat-l">Netmask</div><div class="mono">${intToIp(mask)} (/${bits})</div>
          <div class="stat-l">Wildcard mask</div><div class="mono">${intToIp(wildcard)}</div>
          <div class="stat-l">First usable host</div><div class="mono">${bits === 32 ? "n/a" : intToIp(firstHost)}</div>
          <div class="stat-l">Last usable host</div><div class="mono">${bits === 32 ? "n/a" : intToIp(lastHost)}</div>
          <div class="stat-l">Usable hosts</div><div class="mono">${usable.toLocaleString()}</div>
          <div class="stat-l">Total addresses</div><div class="mono">${totalAddrs.toLocaleString()}</div>
          <div class="stat-l">Address class</div><div class="mono">${cls}</div>
          <div class="stat-l">Supernet (/${bits - 1 >= 0 ? bits - 1 : 0})</div><div class="mono">${supernetInfo}</div>
          <div class="stat-l">Next adjacent /${bits}</div><div class="mono">${nextSubnet}</div>
          <div class="stat-l">Previous adjacent /${bits}</div><div class="mono">${prevSubnet}</div>
          <div class="stat-l">Private / public</div><div class="mono">${isPrivateIPv4(oct)}</div>
        </div>
        <p class="pg-sub" style="margin-top:16px">Binary breakdown</p>
        <table class="mono" style="width:100%;border-collapse:collapse;font-size:.82rem">
          <tr><td></td><td>Octet 1</td><td>Octet 2</td><td>Octet 3</td><td>Octet 4</td><td>Dotted</td></tr>
          ${binRow("Address", oct)}
          ${binRow("Netmask", maskOct)}
          ${binRow("Network", netOct)}
          ${binRow("Broadcast", bcOct)}
          ${binRow("Wildcard", wcOct)}
        </table>
        <p class="muted" style="margin-top:10px">CIDR /${bits} covers ${bits} network bits and ${32 - bits} host bits.
        Each step down in prefix length (e.g. /24 -> /23) doubles the address block size.</p>`;
    } catch (err) {
      out.innerHTML = `<pre class="tk-out">Error: ${escapeHtml(err.message)}</pre>`;
    }
  };

  root.querySelector("#sn-go").onclick = calc;
  root.querySelector("#sn-cidr").addEventListener("keydown", (e) => { if (e.key === "Enter") calc(); });
  root.querySelector("#sn-clear").onclick = () => { root.querySelector("#sn-cidr").value = ""; root.querySelector("#sn-out").innerHTML = ""; };
  calc();

  // -- VLSM planner --------------------------------------------------------
  const bitsNeededForHosts = (hosts) => {
    // Smallest number of host bits h such that 2^h - 2 >= hosts (2^h for the /31, /32 edge cases).
    if (hosts <= 0) return 0;
    let h = 0;
    while (Math.pow(2, h) - 2 < hosts) h++;
    return h;
  };

  const planVlsm = () => {
    const out = root.querySelector("#vlsm-out");
    try {
      const [ipStr, bitsStr] = root.querySelector("#vlsm-base").value.trim().split("/");
      const baseBits = Number(bitsStr);
      if (!Number.isInteger(baseBits) || baseBits < 0 || baseBits > 32) throw new Error("base network needs a valid /prefix");
      const baseOct = parseIPv4(ipStr);
      const baseNet = (ipToInt(baseOct) & maskFromBits(baseBits)) >>> 0;
      const baseSize = Math.pow(2, 32 - baseBits);

      const reqs = root.querySelector("#vlsm-hosts").value.split("\n").map((l) => l.trim()).filter(Boolean).map(Number);
      if (!reqs.length) throw new Error("enter at least one required host count");
      if (reqs.some((n) => !Number.isFinite(n) || n <= 0)) throw new Error("host counts must be positive numbers");

      // Sort largest-first (classic VLSM allocation strategy) but remember original order for output.
      const withIndex = reqs.map((hosts, i) => ({ hosts, i, hostBits: bitsNeededForHosts(hosts) }));
      withIndex.sort((a, b) => b.hosts - a.hosts);

      let cursor = baseNet;
      const rows = [];
      let overflow = false;
      for (const r of withIndex) {
        const prefixBits = 32 - r.hostBits;
        const blockSize = Math.pow(2, r.hostBits);
        // Align cursor up to a boundary for this block size.
        const aligned = Math.ceil(cursor / blockSize) * blockSize;
        if (aligned + blockSize > baseNet + baseSize) { overflow = true; break; }
        const net = aligned >>> 0;
        const bc = (net + blockSize - 1) >>> 0;
        rows.push({
          reqIndex: r.i, hostsNeeded: r.hosts, prefixBits, blockSize,
          network: `${intToIp(net)}/${prefixBits}`, mask: intToIp(maskFromBits(prefixBits)),
          firstHost: prefixBits >= 31 ? intToIp(net) : intToIp(net + 1),
          lastHost: prefixBits >= 31 ? intToIp(bc) : intToIp(bc - 1),
          broadcast: intToIp(bc), usable: prefixBits >= 31 ? blockSize : blockSize - 2,
        });
        cursor = aligned + blockSize;
      }
      rows.sort((a, b) => a.reqIndex - b.reqIndex);

      const usedAddrs = rows.reduce((sum, r) => sum + r.blockSize, 0);
      out.innerHTML = `
        <div class="dl-cmd" style="margin-top:10px">
          <div class="stat-l">Base network</div><div class="mono">${intToIp(baseNet)}/${baseBits} (${baseSize.toLocaleString()} addresses)</div>
          <div class="stat-l">Subnets requested</div><div class="mono">${reqs.length}</div>
          <div class="stat-l">Addresses allocated</div><div class="mono">${usedAddrs.toLocaleString()} / ${baseSize.toLocaleString()} (${((usedAddrs / baseSize) * 100).toFixed(1)}%)</div>
        </div>
        <table class="mono" style="width:100%;border-collapse:collapse;font-size:.8rem;margin-top:10px">
          <tr><td><strong>#</strong></td><td><strong>Hosts needed</strong></td><td><strong>Network</strong></td><td><strong>Mask</strong></td>
              <td><strong>Usable range</strong></td><td><strong>Broadcast</strong></td><td><strong>Usable hosts</strong></td></tr>
          ${rows.map((r, i) => `<tr><td>${i + 1}</td><td>${r.hostsNeeded}</td><td>${r.network}</td><td>${r.mask}</td>
            <td>${r.firstHost} - ${r.lastHost}</td><td>${r.broadcast}</td><td>${r.usable}</td></tr>`).join("")}
        </table>
        ${overflow ? `<p class="muted" style="margin-top:10px;color:var(--danger,#ff5566)">Warning: the base network is not large enough to fit all requested subnets -- only ${rows.length} of ${reqs.length} were allocated. Use a larger base network or fewer/smaller subnets.</p>` : ""}
        <p class="muted" style="margin-top:10px">Subnets are allocated largest-requirement-first to minimize fragmentation,
        then displayed back in your original input order.</p>`;
    } catch (err) {
      out.innerHTML = `<pre class="tk-out">Error: ${escapeHtml(err.message)}</pre>`;
    }
  };
  root.querySelector("#vlsm-go").onclick = planVlsm;
  planVlsm();

  // -- CIDR aggregator (route summarization) -------------------------------
  const aggregate = () => {
    const out = root.querySelector("#agg-out");
    try {
      const lines = root.querySelector("#agg-in").value.split("\n").map((l) => l.trim()).filter(Boolean);
      if (!lines.length) throw new Error("enter at least one CIDR block");
      const blocks = lines.map((line) => {
        const [ipStr, bitsStr] = line.split("/");
        const bits = Number(bitsStr);
        if (!Number.isInteger(bits) || bits < 0 || bits > 32) throw new Error(`invalid CIDR: "${line}"`);
        const oct = parseIPv4(ipStr);
        const net = (ipToInt(oct) & maskFromBits(bits)) >>> 0;
        return { net, bits, size: Math.pow(2, 32 - bits) };
      });

      // Iteratively merge adjacent equal-size blocks that share a common supernet.
      let current = blocks.map((b) => ({ start: b.net, end: b.net + b.size - 1, bits: b.bits }));
      let merged = true;
      while (merged) {
        merged = false;
        current.sort((a, b) => a.start - b.start);
        const next = [];
        let i = 0;
        while (i < current.length) {
          const a = current[i];
          const b = current[i + 1];
          if (b && a.bits === b.bits && a.end + 1 === b.start) {
            const superBits = a.bits - 1;
            const superSize = Math.pow(2, 32 - superBits);
            const superStart = (a.start & maskFromBits(superBits)) >>> 0;
            if (superBits >= 0 && superStart === a.start && (a.end - a.start + 1) * 2 === superSize) {
              next.push({ start: superStart, end: superStart + superSize - 1, bits: superBits });
              i += 2; merged = true; continue;
            }
          }
          next.push(a); i++;
        }
        current = next;
      }
      current.sort((a, b) => a.start - b.start);

      out.innerHTML = `
        <div class="dl-cmd" style="margin-top:10px">
          <div class="stat-l">Input networks</div><div class="mono">${blocks.length}</div>
          <div class="stat-l">Aggregated into</div><div class="mono">${current.length} supernet${current.length === 1 ? "" : "s"}</div>
        </div>
        <pre class="tk-out">${current.map((c) => `${intToIp(c.start)}/${c.bits}`).join("\n")}</pre>
        <p class="muted" style="margin-top:8px">Aggregation only merges blocks that are exact power-of-two-aligned
        siblings (e.g. two /24s sharing a /23 parent). Gaps, overlaps, or misaligned blocks are left unmerged and
        listed individually.</p>`;
    } catch (err) {
      out.innerHTML = `<pre class="tk-out">Error: ${escapeHtml(err.message)}</pre>`;
    }
  };
  root.querySelector("#agg-go").onclick = aggregate;
  aggregate();
}

// ---------------------------------------------------------------------------
//  Tool 2 -- IP Address Info
// ---------------------------------------------------------------------------

const IANA_SPECIAL_IPV4 = [
  { block: "0.0.0.0/8", name: '"This" network', rfc: "RFC 791", purpose: "Source address meaning \"this host, this network\" at boot before an address is configured." },
  { block: "10.0.0.0/8", name: "Private-use", rfc: "RFC 1918", purpose: "Not routed on the public internet; the largest private block, common in enterprise networks." },
  { block: "100.64.0.0/10", name: "Shared address space (CGNAT)", rfc: "RFC 6598", purpose: "Used by ISPs for carrier-grade NAT between customer devices and the ISP's NAT layer." },
  { block: "127.0.0.0/8", name: "Loopback", rfc: "RFC 1122", purpose: "Reserved for a host to address itself; 127.0.0.1 is the most common loopback address." },
  { block: "169.254.0.0/16", name: "Link-local (APIPA)", rfc: "RFC 3927", purpose: "Auto-assigned when DHCP fails; valid only on the local link, never routed." },
  { block: "172.16.0.0/12", name: "Private-use", rfc: "RFC 1918", purpose: "Second RFC 1918 private block, common in medium-sized networks and Docker default bridges." },
  { block: "192.0.0.0/24", name: "IETF protocol assignments", rfc: "RFC 6890", purpose: "Reserved for IETF protocols; includes the DS-Lite (192.0.0.0/29) and NAT64 discovery ranges." },
  { block: "192.0.2.0/24", name: "TEST-NET-1", rfc: "RFC 5737", purpose: "Reserved for documentation and examples -- never assigned to real hosts." },
  { block: "192.88.99.0/24", name: "6to4 relay anycast", rfc: "RFC 3068", purpose: "Formerly used for 6to4 IPv6 transition relays; deprecated, since reclaimed for other uses." },
  { block: "192.168.0.0/16", name: "Private-use", rfc: "RFC 1918", purpose: "Third RFC 1918 block, by far the most common default for home routers and small networks." },
  { block: "198.18.0.0/15", name: "Benchmark testing", rfc: "RFC 2544", purpose: "Reserved for network device benchmarking to avoid interference with real production traffic." },
  { block: "198.51.100.0/24", name: "TEST-NET-2", rfc: "RFC 5737", purpose: "Second documentation/example range." },
  { block: "203.0.113.0/24", name: "TEST-NET-3", rfc: "RFC 5737", purpose: "Third documentation/example range." },
  { block: "224.0.0.0/4", name: "Multicast", rfc: "RFC 5771", purpose: "Class D multicast address space, subdivided into local, internetwork, and administratively scoped ranges." },
  { block: "240.0.0.0/4", name: "Reserved for future use", rfc: "RFC 1112", purpose: "Class E; reserved and not assigned for general internet use (with minor exceptions)." },
  { block: "255.255.255.255/32", name: "Limited broadcast", rfc: "RFC 919", purpose: "Broadcasts to all hosts on the local network segment only; never forwarded by routers." },
];

const DIAG_COMMANDS = [
  { task: "Ping a host", linux: "ping -c 4 host", macos: "ping -c 4 host", windows: "ping host" },
  { task: "Trace the route", linux: "traceroute host", macos: "traceroute host", windows: "tracert host" },
  { task: "DNS lookup", linux: "dig host / nslookup host", macos: "dig host / nslookup host", windows: "nslookup host" },
  { task: "Show interfaces/IPs", linux: "ip addr show", macos: "ifconfig", windows: "ipconfig /all" },
  { task: "Show routing table", linux: "ip route show", macos: "netstat -rn", windows: "route print" },
  { task: "Show ARP table", linux: "ip neigh show", macos: "arp -a", windows: "arp -a" },
  { task: "Show open sockets/ports", linux: "ss -tulpn", macos: "netstat -an", windows: "netstat -ano" },
  { task: "Test a TCP port", linux: "nc -zv host port", macos: "nc -zv host port", windows: "Test-NetConnection host -Port port" },
  { task: "Release/renew DHCP lease", linux: "sudo dhclient -r && sudo dhclient", macos: "sudo ipconfig set en0 DHCP", windows: "ipconfig /release && ipconfig /renew" },
  { task: "Flush DNS cache", linux: "sudo systemd-resolve --flush-caches", macos: "sudo dscacheutil -flushcache", windows: "ipconfig /flushdns" },
  { task: "Capture packets", linux: "sudo tcpdump -i eth0", macos: "sudo tcpdump -i en0", windows: "(use Wireshark GUI or pktmon)" },
  { task: "Show current MTU", linux: "ip link show eth0", macos: "ifconfig en0", windows: "netsh interface ipv4 show subinterfaces" },
];

function renderIpInfo(root) {
  root.innerHTML = `
    <div class="panel">
      <p class="muted">Enter any IPv4 address to see its class, scope (private/public/reserved), binary and hex
      forms, integer representation, and IPv4-mapped IPv6 address.</p>
      ${field("IPv4 address", "ii-ip", "8.8.8.8", "e.g. 192.168.1.1")}
      <div class="tk-btns"><button class="btn sm" id="ii-go">Look up</button></div>
      <div id="ii-out"></div>

      <p class="pg-sub" style="margin-top:24px">IANA special-purpose IPv4 address registry</p>
      <p class="muted">The complete set of reserved/special-use IPv4 blocks defined by IANA (RFC 6890 and its
      successors), beyond the common private ranges shown above.</p>
      <table class="mono" style="width:100%;border-collapse:collapse;font-size:.8rem">
        <tr><td><strong>Block</strong></td><td><strong>Name</strong></td><td><strong>RFC</strong></td><td><strong>Purpose</strong></td></tr>
        ${IANA_SPECIAL_IPV4.map((r) => `<tr><td>${r.block}</td><td style="font-family:inherit">${r.name}</td><td>${r.rfc}</td><td style="font-family:inherit">${r.purpose}</td></tr>`).join("")}
      </table>

      <p class="pg-sub" style="margin-top:24px">Cross-platform network diagnostic commands</p>
      <p class="muted">The commands you'd actually run at a terminal to investigate whatever this tool just told you.</p>
      <table class="mono" style="width:100%;border-collapse:collapse;font-size:.8rem">
        <tr><td><strong>Task</strong></td><td><strong>Linux</strong></td><td><strong>macOS</strong></td><td><strong>Windows</strong></td></tr>
        ${DIAG_COMMANDS.map((r) => `<tr><td style="font-family:inherit">${r.task}</td><td>${r.linux}</td><td>${r.macos}</td><td>${r.windows}</td></tr>`).join("")}
      </table>
    </div>`;

  const calc = () => {
    const raw = root.querySelector("#ii-ip").value.trim();
    const out = root.querySelector("#ii-out");
    try {
      const oct = parseIPv4(raw);
      const n = ipToInt(oct);
      const bin = octetBinary(oct);
      const hex = oct.map((o) => pad(o.toString(16).toUpperCase(), 2));
      const cls = ipClass(oct[0]);
      const defBits = classDefaultMaskBits(oct[0]);
      const scope = isPrivateIPv4(oct);
      const mappedV6 = `::ffff:${hex[0]}${hex[1]}:${hex[2]}${hex[3]}`.toLowerCase();
      const mappedV6Dotted = `::ffff:${oct.join(".")}`;
      const reversedDns = `${[...oct].reverse().join(".")}.in-addr.arpa`;
      const isLoopback = oct[0] === 127;
      const isLinkLocal = oct[0] === 169 && oct[1] === 254;
      const isMulticast = oct[0] >= 224 && oct[0] <= 239;
      let multicastType = "";
      if (isMulticast) {
        const n2 = ipToInt(oct);
        if (n2 >= ipToInt([224, 0, 0, 0]) && n2 <= ipToInt([224, 0, 0, 255])) multicastType = "Local network control block";
        else if (n2 >= ipToInt([224, 0, 1, 0]) && n2 <= ipToInt([224, 0, 1, 255])) multicastType = "Internetwork control block";
        else if (n2 >= ipToInt([232, 0, 0, 0]) && n2 <= ipToInt([232, 255, 255, 255])) multicastType = "Source-specific multicast (SSM)";
        else if (n2 >= ipToInt([239, 0, 0, 0]) && n2 <= ipToInt([239, 255, 255, 255])) multicastType = "Administratively scoped (RFC 2365)";
        else multicastType = "Global multicast";
      }

      out.innerHTML = `
        <div class="dl-cmd" style="margin-top:14px">
          <div class="stat-l">Address</div><div class="mono">${oct.join(".")}</div>
          <div class="stat-l">Class</div><div class="mono">${cls}</div>
          <div class="stat-l">Default mask (classful)</div><div class="mono">${defBits ? `/${defBits}` : "n/a"}</div>
          <div class="stat-l">Scope</div><div class="mono">${scope}</div>
          <div class="stat-l">32-bit integer</div><div class="mono">${n.toLocaleString()} (0x${n.toString(16).toUpperCase()})</div>
          <div class="stat-l">Hexadecimal</div><div class="mono">${hex.join(":")}</div>
          <div class="stat-l">Binary</div><div class="mono">${bin.join(".")}</div>
          <div class="stat-l">Binary (32-bit)</div><div class="mono">${bin.join("")}</div>
          <div class="stat-l">IPv4-mapped IPv6</div><div class="mono">${mappedV6Dotted}</div>
          <div class="stat-l">IPv4-mapped IPv6 (hex)</div><div class="mono">${mappedV6}</div>
          <div class="stat-l">Reverse DNS (PTR) name</div><div class="mono">${reversedDns}</div>
          <div class="stat-l">Loopback</div><div class="mono">${isLoopback ? "Yes" : "No"}</div>
          <div class="stat-l">Link-local (APIPA)</div><div class="mono">${isLinkLocal ? "Yes" : "No"}</div>
          <div class="stat-l">Multicast</div><div class="mono">${isMulticast ? `Yes -- ${multicastType}` : "No"}</div>
        </div>
        <p class="muted" style="margin-top:10px">Classful addressing (class A/B/C/D/E) was replaced by CIDR in 1993,
        but class ranges are still useful shorthand: A = 1-126, B = 128-191, C = 192-223, D = 224-239 (multicast),
        E = 240-255 (reserved/experimental).</p>`;
    } catch (err) {
      out.innerHTML = `<pre class="tk-out">Error: ${escapeHtml(err.message)}</pre>`;
    }
  };

  root.querySelector("#ii-go").onclick = calc;
  root.querySelector("#ii-ip").addEventListener("keydown", (e) => { if (e.key === "Enter") calc(); });
  calc();
}

// ---------------------------------------------------------------------------
//  Tool 3 -- CIDR to IP Range
// ---------------------------------------------------------------------------

function renderCidrRange(root) {
  root.innerHTML = `
    <div class="panel">
      <p class="muted">Enter a CIDR block to see its full first/last address range, host count, and (for small
      blocks) an enumerated address list.</p>
      ${field("CIDR", "cr-cidr", "192.168.1.0/28", "e.g. 10.10.10.0/30")}
      <div class="tk-row"><label><input type="checkbox" id="cr-list" checked> List individual addresses (blocks up to /20, max 4096 shown)</label></div>
      <div class="tk-btns"><button class="btn sm" id="cr-go">Calculate</button></div>
      <div id="cr-out"></div>
    </div>`;

  const calc = () => {
    const raw = root.querySelector("#cr-cidr").value.trim();
    const out = root.querySelector("#cr-out");
    try {
      const [ipStr, bitsStr] = raw.split("/");
      const bits = Number(bitsStr);
      if (!Number.isInteger(bits) || bits < 0 || bits > 32) throw new Error("prefix length must be 0-32");
      const oct = parseIPv4(ipStr);
      const ipInt = ipToInt(oct);
      const mask = maskFromBits(bits);
      const network = (ipInt & mask) >>> 0;
      const broadcast = (network | (~mask >>> 0)) >>> 0;
      const total = Math.pow(2, 32 - bits);

      let listHtml = "";
      const doList = root.querySelector("#cr-list").checked;
      if (doList && bits >= 20) {
        const cap = Math.min(total, 4096);
        const addrs = [];
        for (let i = 0; i < cap; i++) addrs.push(intToIp((network + i) >>> 0));
        listHtml = `<p class="pg-sub" style="margin-top:14px">Addresses ${cap < total ? `(first ${cap.toLocaleString()} of ${total.toLocaleString()})` : `(all ${total.toLocaleString()})`}</p>
          <pre class="tk-out" style="max-height:340px;overflow:auto">${addrs.join("\n")}</pre>`;
      } else if (doList) {
        listHtml = `<p class="muted" style="margin-top:14px">Block too large to list individually (limit is /20 = 4,096 addresses). Narrow the prefix or uncheck listing.</p>`;
      }

      out.innerHTML = `
        <div class="dl-cmd" style="margin-top:14px">
          <div class="stat-l">Range start (network)</div><div class="mono">${intToIp(network)}</div>
          <div class="stat-l">Range end (broadcast)</div><div class="mono">${intToIp(broadcast)}</div>
          <div class="stat-l">First usable</div><div class="mono">${bits >= 31 ? intToIp(network) : intToIp(network + 1)}</div>
          <div class="stat-l">Last usable</div><div class="mono">${bits >= 31 ? intToIp(broadcast) : intToIp(broadcast - 1)}</div>
          <div class="stat-l">Total addresses</div><div class="mono">${total.toLocaleString()}</div>
          <div class="stat-l">Usable hosts</div><div class="mono">${(bits >= 31 ? total : total - 2).toLocaleString()}</div>
          <div class="stat-l">Range notation</div><div class="mono">${intToIp(network)} - ${intToIp(broadcast)}</div>
        </div>
        ${listHtml}`;
    } catch (err) {
      out.innerHTML = `<pre class="tk-out">Error: ${escapeHtml(err.message)}</pre>`;
    }
  };

  root.querySelector("#cr-go").onclick = calc;
  root.querySelector("#cr-list").onchange = calc;
  root.querySelector("#cr-cidr").addEventListener("keydown", (e) => { if (e.key === "Enter") calc(); });
  calc();
}

// ---------------------------------------------------------------------------
//  Tool 4 -- IPv4 to IPv6 Converter
// ---------------------------------------------------------------------------

function compressIPv6(hextets) {
  // hextets: array of 8 numbers (0-65535). Find longest run of zeros to compress with "::".
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (hextets[i] === 0) {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
    } else { curStart = -1; curLen = 0; }
  }
  const parts = hextets.map((h) => h.toString(16));
  if (bestLen > 1) {
    const before = parts.slice(0, bestStart);
    const after = parts.slice(bestStart + bestLen);
    return (before.length ? before.join(":") : "") + "::" + (after.length ? after.join(":") : "");
  }
  return parts.join(":");
}

// Parse a (possibly compressed) IPv6 address string into 8 hextet numbers (0-65535).
function parseIPv6(input) {
  let s = input.trim();
  if (!s) throw new Error("empty address");
  if ((s.match(/::/g) || []).length > 1) throw new Error("only one \"::\" is allowed");
  let head = s, tail = "";
  const hasCompression = s.includes("::");
  if (hasCompression) {
    const parts = s.split("::");
    head = parts[0]; tail = parts[1] || "";
  }
  const headParts = head ? head.split(":").filter((p) => p !== "") : [];
  const tailParts = tail ? tail.split(":").filter((p) => p !== "") : [];
  const total = headParts.length + tailParts.length;
  if (!hasCompression && total !== 8) throw new Error(`expected 8 groups, got ${total}`);
  if (hasCompression && total >= 8) throw new Error(`"::" implies missing groups, but ${total} were given`);
  const fillCount = hasCompression ? 8 - total : 0;
  const allParts = [...headParts, ...Array(fillCount).fill("0"), ...tailParts];
  if (allParts.length !== 8) throw new Error("could not parse address into 8 groups");
  return allParts.map((p) => {
    if (!/^[0-9a-fA-F]{1,4}$/.test(p)) throw new Error(`invalid hextet: "${p}"`);
    return parseInt(p, 16);
  });
}

function ipv6ToBigInt(hextets) {
  return hextets.reduce((acc, h) => (acc << 16n) | BigInt(h), 0n);
}

function bigIntToHextets(big) {
  const out = [];
  let n = big;
  for (let i = 0; i < 8; i++) {
    out.unshift(Number(n & 0xffffn));
    n >>= 16n;
  }
  return out;
}

function ipv6MaskFromBits(bits) {
  if (bits === 0) return 0n;
  return ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - bits)) - 1n);
}

function renderIpv6Converter(root) {
  root.innerHTML = `
    <div class="panel">
      <p class="muted">Convert an IPv4 address into its various IPv6 transition representations: IPv4-mapped,
      IPv4-compatible (deprecated), 6to4, and NAT64 well-known prefix.</p>
      ${field("IPv4 address", "v6-ip", "203.0.113.25", "e.g. 192.0.2.1")}
      <div class="tk-btns"><button class="btn sm" id="v6-go">Convert</button></div>
      <div id="v6-out"></div>

      <p class="pg-sub" style="margin-top:26px">IPv6 subnet calculator</p>
      <p class="muted">Enter a native IPv6 address in CIDR notation (compressed or expanded) to get its network
      prefix, address range, and both compressed and fully-expanded forms.</p>
      ${field("IPv6 CIDR", "v6sub-cidr", "2001:db8:acad::/48", "e.g. 2001:db8::/32")}
      <div class="tk-btns"><button class="btn sm" id="v6sub-go">Calculate</button></div>
      <div id="v6sub-out"></div>
    </div>`;

  const calc = () => {
    const raw = root.querySelector("#v6-ip").value.trim();
    const out = root.querySelector("#v6-out");
    try {
      const oct = parseIPv4(raw);
      const hex = oct.map((o) => pad(o.toString(16), 2));
      const hi = parseInt(hex[0] + hex[1], 16), lo = parseInt(hex[2] + hex[3], 16);

      const mapped = `::ffff:${hex[0]}${hex[1]}:${hex[2]}${hex[3]}`;
      const mappedDotted = `::ffff:${oct.join(".")}`;
      const compatible = `::${oct.join(".")}`;
      const sixToFour = `2002:${pad(hi.toString(16), 4)}:${pad(lo.toString(16), 4)}::/48`;
      const nat64 = `64:ff9b::${hex[0]}${hex[1]}:${hex[2]}${hex[3]}`;
      const nat64Dotted = `64:ff9b::${oct.join(".")}`;
      const fullHextets = [0, 0, 0, 0, 0, 0xffff, hi, lo];
      const fullExpanded = fullHextets.map((h) => pad(h.toString(16), 4)).join(":");
      const compressed = compressIPv6(fullHextets);

      out.innerHTML = `
        <div class="dl-cmd" style="margin-top:14px">
          <div class="stat-l">IPv4-mapped IPv6</div><div class="mono">${mapped}</div>
          <div class="stat-l">IPv4-mapped (dotted quad tail)</div><div class="mono">${mappedDotted}</div>
          <div class="stat-l">Fully expanded</div><div class="mono">${fullExpanded}</div>
          <div class="stat-l">Compressed form</div><div class="mono">${compressed}</div>
          <div class="stat-l">IPv4-compatible (deprecated, RFC 4291)</div><div class="mono">${compatible}</div>
          <div class="stat-l">6to4 prefix (RFC 3056)</div><div class="mono">${sixToFour}</div>
          <div class="stat-l">NAT64 well-known prefix</div><div class="mono">${nat64}</div>
          <div class="stat-l">NAT64 (dotted tail)</div><div class="mono">${nat64Dotted}</div>
        </div>
        <p class="muted" style="margin-top:10px">IPv4-mapped addresses (::ffff:0:0/96) let a dual-stack IPv6 socket
        accept IPv4 connections. 6to4 (2002::/16) and the NAT64 well-known prefix (64:ff9b::/96) are transition
        mechanisms for routing IPv4 traffic across IPv6-only infrastructure.</p>`;
    } catch (err) {
      out.innerHTML = `<pre class="tk-out">Error: ${escapeHtml(err.message)}</pre>`;
    }
  };

  root.querySelector("#v6-go").onclick = calc;
  root.querySelector("#v6-ip").addEventListener("keydown", (e) => { if (e.key === "Enter") calc(); });
  calc();

  // -- Native IPv6 subnet calculator ---------------------------------------
  const calcV6Subnet = () => {
    const out = root.querySelector("#v6sub-out");
    const raw = root.querySelector("#v6sub-cidr").value.trim();
    try {
      const [addrStr, bitsStr] = raw.split("/");
      const bits = Number(bitsStr);
      if (!Number.isInteger(bits) || bits < 0 || bits > 128) throw new Error("prefix length must be 0-128");
      const hextets = parseIPv6(addrStr);
      const addrInt = ipv6ToBigInt(hextets);
      const mask = ipv6MaskFromBits(bits);
      const network = addrInt & mask;
      const hostMask = ((1n << 128n) - 1n) ^ mask;
      const lastAddr = network | hostMask;
      const networkHextets = bigIntToHextets(network);
      const lastHextets = bigIntToHextets(lastAddr);

      const expand = (hx) => hx.map((h) => pad(h.toString(16), 4)).join(":");
      const totalAddrs = 2n ** BigInt(128 - bits);

      // Common IPv6 well-known prefixes for context.
      const notes = [];
      if (networkHextets[0] === 0x2001 && networkHextets[1] === 0x0db8) notes.push("2001:db8::/32 is the reserved documentation prefix (RFC 3849) -- never used on the real internet.");
      if ((networkHextets[0] & 0xffc0) === 0xfe80) notes.push("fe80::/10 is the link-local prefix -- valid only on the local link, never routed.");
      if ((networkHextets[0] & 0xfe00) === 0xfc00) notes.push("fc00::/7 is Unique Local Address (ULA) space (RFC 4193) -- IPv6's equivalent of RFC 1918 private addressing.");
      if ((networkHextets[0] & 0xe000) === 0x2000) notes.push("2000::/3 is the current global unicast address range.");
      if (networkHextets.every((h) => h === 0) && network === 0n) notes.push(":: is the unspecified address (equivalent to IPv4's 0.0.0.0).");

      out.innerHTML = `
        <div class="dl-cmd" style="margin-top:14px">
          <div class="stat-l">Network (compressed)</div><div class="mono">${compressIPv6(networkHextets)}/${bits}</div>
          <div class="stat-l">Network (expanded)</div><div class="mono">${expand(networkHextets)}</div>
          <div class="stat-l">Last address (compressed)</div><div class="mono">${compressIPv6(lastHextets)}</div>
          <div class="stat-l">Last address (expanded)</div><div class="mono">${expand(lastHextets)}</div>
          <div class="stat-l">Total addresses in block</div><div class="mono">${totalAddrs.toLocaleString()}</div>
          <div class="stat-l">Prefix length</div><div class="mono">/${bits} (${128 - bits} host bits)</div>
        </div>
        ${notes.length ? `<p class="muted" style="margin-top:10px">${notes.map(escapeHtml).join(" ")}</p>` : ""}
        <p class="muted" style="margin-top:10px">Unlike IPv4, IPv6 has no broadcast address -- the "last address"
        above is simply the top of the range, and per-subnet host counts are typically astronomically large
        (a /64, the standard LAN subnet size, holds 2^64 addresses).</p>`;
    } catch (err) {
      out.innerHTML = `<pre class="tk-out">Error: ${escapeHtml(err.message)}</pre>`;
    }
  };
  root.querySelector("#v6sub-go").onclick = calcV6Subnet;
  root.querySelector("#v6sub-cidr").addEventListener("keydown", (e) => { if (e.key === "Enter") calcV6Subnet(); });
  calcV6Subnet();
}

// ---------------------------------------------------------------------------
//  Tool 5 -- MAC Address Lookup (OUI vendor database)
// ---------------------------------------------------------------------------
//
// The IEEE assigns each hardware manufacturer one or more 24-bit OUI
// (Organizationally Unique Identifier) blocks -- the first three octets of
// a MAC address. Large vendors hold dozens of blocks. This table groups
// blocks by vendor for readability and flattens into a single lookup map.

const VENDOR_BLOCKS = [
  { vendor: "Cisco Systems, Inc", prefixes: [
    "00:00:0C", "00:01:42", "00:01:43", "00:01:63", "00:01:64", "00:01:96", "00:01:97", "00:02:16",
    "00:02:17", "00:02:4A", "00:02:4B", "00:02:7D", "00:02:7E", "00:02:B9", "00:02:BA", "00:02:FC",
    "00:02:FD", "00:03:31", "00:03:32", "00:03:6B", "00:03:9E", "00:03:9F", "00:03:A0", "00:03:E3",
    "00:03:E4", "00:03:FD", "00:03:FE", "00:04:27", "00:04:28", "00:04:6D", "00:04:6E", "00:04:9A",
    "00:04:9B", "00:04:C0", "00:04:C1", "00:04:DD", "00:04:DE", "00:05:00", "00:05:01", "00:05:31",
    "00:05:32", "00:05:5E", "00:05:5F", "00:05:73", "00:05:74", "00:05:9A", "00:05:9B", "00:05:DC",
    "00:05:DD", "00:06:28", "00:06:2A", "00:06:52", "00:06:53", "00:06:7C", "00:06:7D", "00:06:C1",
    "00:06:D6", "00:06:D7", "00:07:0D", "00:07:0E", "00:07:4F", "00:07:50", "00:07:7D", "00:07:84",
    "00:07:85", "00:07:B3", "00:07:B4", "00:07:EB", "00:07:EC", "00:08:20", "00:08:21", "00:08:7C",
    "00:08:A3", "00:08:A4", "00:08:C2", "00:08:E2", "00:08:E3", "00:09:11", "00:09:12", "00:09:43",
    "00:09:44", "00:09:7B", "00:09:7C", "00:09:B6", "00:09:B7", "00:09:E8", "00:09:E9", "00:0A:41",
    "00:0A:42", "00:0A:8A", "00:0A:8B", "00:0A:B7", "00:0A:B8", "00:0A:F3", "00:0A:F4", "00:0B:45",
    "00:0B:46", "00:0B:5F", "00:0B:60", "00:0B:BE", "00:0B:BF", "00:0B:FC", "00:0B:FD", "00:0C:30",
    "00:0C:31", "00:0C:85", "00:0C:86", "00:0C:CE", "00:0C:CF", "00:0D:28", "00:0D:29", "00:0D:65",
    "00:0D:66", "00:0D:BC", "00:0D:BD", "00:0D:ED", "00:0D:EE", "00:0E:08", "00:0E:38", "00:0E:39",
    "00:0E:83", "00:0E:84", "00:0E:D6", "00:0E:D7", "00:0F:23", "00:0F:24", "00:0F:34", "00:0F:35",
    "00:0F:8F", "00:0F:90", "00:0F:F7", "00:0F:F8", "00:10:07", "00:10:11", "00:10:14", "00:10:1F",
    "00:10:29", "00:10:2F", "00:10:54", "00:10:79", "00:10:7B", "00:10:A6", "00:10:F6", "00:10:FF",
  ]},
  { vendor: "Apple, Inc", prefixes: [
    "00:03:93", "00:05:02", "00:0A:27", "00:0A:95", "00:0D:93", "00:11:24", "00:14:51", "00:16:CB",
    "00:17:F2", "00:19:E3", "00:1B:63", "00:1C:B3", "00:1D:4F", "00:1E:52", "00:1E:C2", "00:1F:5B",
    "00:1F:F3", "00:21:E9", "00:22:41", "00:23:12", "00:23:32", "00:23:6C", "00:23:DF", "00:24:36",
    "00:25:00", "00:25:4B", "00:25:BC", "00:26:08", "00:26:4A", "00:26:B0", "00:26:BB", "00:30:65",
    "00:3E:E1", "00:50:E4", "00:56:CD", "00:61:71", "00:6D:52", "00:88:65", "00:A0:40", "04:0C:CE",
    "04:15:52", "04:1E:64", "04:26:65", "04:52:F3", "04:54:53", "04:69:F8", "04:D3:CF", "04:DB:56",
    "04:E5:36", "04:F1:3E", "04:F7:E4", "08:00:07", "08:66:98", "08:6D:41", "08:70:45", "0C:30:21",
    "0C:3E:9F", "0C:4D:E9", "0C:51:01", "0C:74:C2", "0C:77:1A", "0C:BC:9F", "0C:D7:46", "10:1C:0C",
    "10:40:F3", "10:41:7F", "10:93:E9", "10:9A:DD", "10:DD:B1", "14:10:9F", "14:5A:05", "14:7D:DA",
    "14:8F:C6", "14:99:E2", "14:BD:61", "18:20:32", "18:34:51", "18:38:F0", "18:65:90", "18:9E:FC",
    "18:AF:61", "18:AF:8F", "18:E7:F4", "18:F1:D8", "18:F6:43", "1C:1A:C0", "1C:36:BB", "1C:5C:F2",
    "1C:91:48", "1C:9E:46", "1C:AB:A7", "1C:E6:2B", "20:3C:AE", "20:78:F0", "20:7D:74", "20:9B:CD",
    "20:A2:E4", "20:AB:37", "20:C9:D0", "24:24:0E", "24:A2:E1", "24:A0:74", "24:AB:81", "24:E3:14",
    "24:F0:94", "28:37:37", "28:6A:B8", "28:6A:BA", "28:CF:DA", "28:CF:E9", "28:E0:2C", "28:E1:4C",
    "28:E7:CF", "28:F0:76", "2C:1F:23", "2C:20:0B", "2C:33:61", "2C:B4:3A", "2C:BE:08", "30:35:AD",
    "30:63:6B", "30:90:AB", "30:F7:C5", "34:12:98", "34:15:9E", "34:36:3B", "34:51:C9", "34:A3:95",
    "34:C0:59", "34:E2:FD", "38:0F:4A", "38:48:4C", "38:C9:86", "3C:07:54", "3C:15:C2", "3C:2E:F9",
    "3C:E0:72", "40:30:04", "40:33:1A", "40:3C:FC", "40:6C:8F", "40:A6:D9", "40:B3:95", "40:D3:2D",
  ]},
  { vendor: "Samsung Electronics Co, Ltd", prefixes: [
    "00:00:F0", "00:07:AB", "00:12:47", "00:12:FB", "00:15:99", "00:15:B9", "00:16:32", "00:16:6B",
    "00:17:C9", "00:17:D5", "00:18:AF", "00:1A:8A", "00:1B:98", "00:1C:43", "00:1D:25", "00:1E:7D",
    "00:1F:CC", "00:1F:CD", "00:21:19", "00:21:D1", "00:21:D2", "00:23:39", "00:23:99", "00:23:C2",
    "00:23:D6", "00:23:D7", "00:24:54", "00:24:90", "00:24:91", "00:25:38", "00:25:66", "00:25:67",
    "00:26:37", "00:26:5D", "00:26:5F", "08:08:C2", "08:37:3D", "08:3D:88", "08:78:C0", "08:D4:2B",
    "08:EC:A9", "0C:14:20", "0C:71:5D", "0C:89:10", "0C:9D:92", "10:1D:C0", "10:30:47", "10:3B:59",
    "10:77:B1", "14:1F:BA", "14:49:E0", "14:56:8E", "14:89:FD", "14:B4:84", "18:16:C9", "18:26:66",
    "18:3A:2D", "18:67:B0", "18:83:31", "1C:23:2C", "1C:5A:0B", "1C:66:AA", "20:13:E0", "20:64:32",
    "20:D5:BF", "24:4B:03", "24:4B:81", "24:C6:96", "28:27:BF", "28:39:5E", "28:98:7B", "2C:44:01",
  ]},
  { vendor: "Dell Inc", prefixes: [
    "00:06:5B", "00:08:74", "00:0B:DB", "00:0D:56", "00:0F:1F", "00:11:43", "00:12:3F", "00:13:72",
    "00:14:22", "00:15:C5", "00:18:8B", "00:19:B9", "00:1A:A0", "00:1C:23", "00:1D:09", "00:1E:4F",
    "00:1E:C9", "00:21:70", "00:21:9B", "00:22:19", "00:23:AE", "00:24:E8", "00:25:64", "00:26:B9",
    "18:03:73", "18:66:DA", "18:A9:9B", "18:DB:F2", "1C:40:24", "20:47:47", "24:6E:96", "28:F1:0E",
    "34:17:EB", "34:E6:D7", "3C:2C:30", "44:A8:42", "48:4D:7E", "4C:76:25", "50:9A:4C", "54:9F:35",
    "54:BF:64", "5C:26:0A", "5C:F9:DD", "64:00:6A", "74:86:7A", "78:2B:CB", "84:2B:2B", "8C:EC:4B",
  ]},
  { vendor: "Hewlett Packard Enterprise", prefixes: [
    "00:01:E6", "00:01:E7", "00:02:A5", "00:04:EA", "00:08:02", "00:08:C7", "00:0A:57", "00:0B:CD",
    "00:0D:9D", "00:0E:7F", "00:0F:20", "00:10:83", "00:11:0A", "00:11:85", "00:12:79", "00:13:21",
    "00:14:38", "00:14:C2", "00:15:60", "00:16:35", "00:17:08", "00:18:71", "00:18:FE", "00:19:BB",
    "00:1A:4B", "00:1B:78", "00:1C:C4", "00:1E:0B", "00:1F:29", "00:21:5A", "00:22:64", "00:23:7D",
    "00:24:81", "00:25:B3", "00:26:55", "10:1F:74", "18:A9:05", "1C:C1:DE", "24:BE:05", "28:80:23",
    "2C:23:3A", "2C:41:38", "30:E1:71", "34:64:A9", "38:63:BB", "3C:52:82", "40:A8:F0", "44:31:92",
  ]},
  { vendor: "Intel Corporate", prefixes: [
    "00:02:B3", "00:03:47", "00:04:23", "00:07:E9", "00:0C:F1", "00:0E:0C", "00:0E:35", "00:11:11",
    "00:12:F0", "00:13:02", "00:13:20", "00:13:CE", "00:15:00", "00:15:17", "00:16:6F", "00:16:76",
    "00:16:EA", "00:16:EB", "00:18:DE", "00:19:D1", "00:19:D2", "00:1B:21", "00:1B:77", "00:1C:BF",
    "00:1C:C0", "00:1D:E0", "00:1D:E1", "00:1E:64", "00:1E:65", "00:1E:67", "00:1F:3A", "00:1F:3B",
    "00:1F:3C", "00:20:7B", "00:21:5C", "00:21:5D", "00:21:6A", "00:21:6B", "00:22:FA", "00:22:FB",
    "00:23:14", "00:23:15", "00:24:D6", "00:24:D7", "00:26:C6", "00:26:C7", "3C:A9:F4", "3C:FD:FE",
    "44:85:00", "48:51:B7", "4C:34:88", "4C:80:93", "50:2D:A2", "5C:51:4F", "5C:C5:D4", "60:36:DD",
  ]},
  { vendor: "Huawei Technologies Co, Ltd", prefixes: [
    "00:18:82", "00:1E:10", "00:22:A1", "00:25:68", "00:25:9E", "00:34:FE", "00:46:4B", "00:5A:13",
    "00:66:4B", "00:9A:CD", "00:E0:FC", "04:25:C5", "04:33:89", "04:9F:CA", "04:BD:88", "04:C0:6F",
    "08:19:A6", "08:63:61", "08:7A:4C", "0C:37:DC", "0C:96:BF", "10:1B:54", "10:47:80", "10:51:72",
    "10:C6:1F", "18:C5:8A", "1C:59:9D", "20:0B:C7", "20:F3:A3", "24:09:95", "24:69:A5", "28:31:52",
    "28:6E:D4", "2C:AB:00", "30:87:30", "34:6B:D3", "38:F8:87", "3C:DF:1E", "40:4D:8E", "44:6A:20",
  ]},
  { vendor: "Google, Inc", prefixes: [
    "00:1A:11", "08:9E:08", "1C:F2:9A", "20:DF:B9", "24:F5:AA", "3C:5A:B4", "40:75:20", "44:07:0B",
    "48:D6:D5", "54:60:09", "6C:AD:F8", "70:3A:CB", "78:B8:D6", "94:EB:2C", "A4:77:33", "F4:03:2E",
    "F4:F5:D8", "F4:F5:E8", "D8:6C:63",
  ]},
  { vendor: "Amazon Technologies Inc", prefixes: [
    "00:FC:8B", "0C:47:C9", "10:AE:60", "18:74:2E", "34:D2:70", "40:B4:CD", "44:65:0D", "50:F5:DA",
    "50:DC:E7", "68:37:E9", "68:54:FD", "74:75:48", "84:D6:D0", "88:71:E5", "A0:02:DC", "AC:63:BE",
    "B4:7C:9C", "F0:27:2D", "FC:65:DE", "F0:81:73",
  ]},
  { vendor: "Microsoft Corporation", prefixes: [
    "00:03:FF", "00:0D:3A", "00:12:5A", "00:15:5D", "00:17:FA", "00:1D:D8", "00:22:48", "00:25:AE",
    "00:50:F2", "28:18:78", "2C:F5:D3", "30:59:B7", "48:50:73", "50:1A:C5", "58:82:A8", "60:45:BD",
    "6C:5E:3B", "7C:1E:52", "7C:ED:8D", "94:65:2D",
  ]},
  { vendor: "Sony Corporation", prefixes: [
    "00:01:4A", "00:04:1F", "00:0A:D9", "00:0E:07", "00:13:15", "00:16:20", "00:19:63", "00:1A:80",
    "00:1D:0D", "00:1D:BA", "00:1E:DC", "00:21:97", "00:24:BE", "08:00:46", "10:4F:A8", "18:00:2D",
    "20:54:76", "28:0D:FC", "30:F9:ED", "3C:07:71", "40:2B:A1", "4C:0F:6E", "5C:B5:24", "70:9E:29",
  ]},
  { vendor: "LG Electronics", prefixes: [
    "00:1C:62", "00:1E:75", "00:1F:6B", "00:1F:E3", "00:24:83", "00:25:E5", "00:26:E2", "00:AA:70",
    "10:68:3F", "10:F1:F2", "14:B4:C4", "1C:CE:26", "20:21:A5", "2C:54:CF", "34:4D:F7", "38:8C:50",
    "3C:BD:D8", "48:59:29", "4C:61:0D", "5C:A3:9D", "64:99:5D", "6C:DD:BC", "74:A5:28", "88:C9:D0",
  ]},
  { vendor: "Xiaomi Communications Co Ltd", prefixes: [
    "00:9E:C8", "04:CF:8C", "08:35:71", "0C:1D:AF", "10:2A:B3", "14:F6:5A", "18:59:36", "20:82:C0",
    "28:6C:07", "28:E3:1F", "34:80:B3", "34:CE:00", "38:A4:ED", "3C:BF:1C", "50:64:2B", "50:8F:4C",
    "58:44:98", "64:09:80", "64:B4:73", "68:DF:DD", "74:23:44", "78:02:F8", "7C:1D:D9", "7C:49:EB",
  ]},
  { vendor: "NETGEAR", prefixes: [
    "00:09:5B", "00:0F:B5", "00:14:6C", "00:18:4D", "00:1B:2F", "00:1E:2A", "00:1F:33", "00:22:3F",
    "00:24:B2", "00:26:F2", "04:A1:51", "08:BD:43", "20:0C:C8", "20:4E:7F", "28:80:88", "2C:30:33",
    "30:46:9A", "44:94:FC", "6C:B0:CE", "84:1B:5E", "9C:3D:CF", "A0:04:60", "A0:21:B7", "B0:39:56",
  ]},
  { vendor: "D-Link International", prefixes: [
    "00:05:5D", "00:0D:88", "00:0F:3D", "00:11:95", "00:13:46", "00:15:E9", "00:17:9A", "00:19:5B",
    "00:1B:11", "00:1C:F0", "00:1E:58", "00:21:91", "00:22:B0", "00:24:01", "00:26:5A", "14:D6:4D",
    "1C:7E:E5", "1C:AF:F7", "28:10:7B", "34:08:04", "5C:D9:98", "84:C9:B2", "90:94:E4", "AC:F1:DF",
  ]},
  { vendor: "TP-Link Technologies Co, Ltd", prefixes: [
    "00:0A:EB", "00:14:78", "00:19:E0", "00:1D:0F", "00:21:27", "00:23:CD", "00:25:86", "00:27:19",
    "10:FE:ED", "14:CC:20", "18:A6:F7", "1C:3B:F3", "1C:FA:68", "30:B5:C2", "34:60:F9", "3C:84:6A",
    "40:16:9F", "4C:E1:73", "50:C7:BF", "54:AF:97", "5C:63:BF", "60:32:B1", "64:66:B3", "6C:5A:B0",
  ]},
  { vendor: "Ubiquiti Networks Inc", prefixes: [
    "00:15:6D", "00:27:22", "04:18:D6", "18:E8:29", "24:5A:4C", "24:A4:3C", "28:70:4E", "2C:26:17",
    "44:D9:E7", "68:72:51", "70:A7:41", "74:83:C2", "78:8A:20", "80:2A:A8", "B4:FB:E4", "DC:9F:DB",
    "F0:9F:C2", "FC:EC:DA",
  ]},
  { vendor: "Belkin International Inc", prefixes: [
    "00:11:50", "00:17:3F", "00:1C:DF", "00:22:75", "00:30:BD", "08:86:3B", "14:91:82", "24:F5:A2",
    "58:EF:68", "80:69:1A", "94:10:3E", "B4:75:0E", "C0:56:27", "EC:1A:59", "F4:BF:80",
  ]},
  { vendor: "ASUSTek Computer Inc", prefixes: [
    "00:0C:6E", "00:0E:A6", "00:11:2F", "00:13:D4", "00:15:F2", "00:17:31", "00:1A:92", "00:1D:60",
    "00:1E:8C", "00:22:15", "00:23:54", "00:24:8C", "00:26:18", "10:7B:44", "14:DA:E9", "1C:87:2C",
    "20:CF:30", "2C:56:DC", "30:5A:3A", "38:2C:4A", "40:16:7E", "50:46:5D", "54:04:A6", "5C:AC:4C",
  ]},
  { vendor: "Realtek Semiconductor Corp", prefixes: [
    "00:E0:4C", "52:54:00", "00:16:6C", "00:1E:07", "00:22:26", "00:23:CA", "00:26:E1", "24:0A:64",
    "40:5E:D5", "48:8A:D2", "52:54:AB", "94:39:E5",
  ]},
  { vendor: "Texas Instruments", prefixes: [
    "00:04:0B", "00:0B:AB", "00:12:B0", "00:17:E9", "00:1A:B6", "00:1E:C0", "00:22:56", "20:C3:8F",
    "28:6D:CD", "34:B1:F7", "50:5A:65", "6C:EC:EB", "84:2F:5C", "A0:A3:B3",
  ]},
  { vendor: "Nokia", prefixes: [
    "00:02:EE", "00:0E:ED", "00:12:62", "00:16:BC", "00:1A:89", "00:1E:C8", "00:21:1B", "00:23:D5",
    "00:26:CC", "24:77:03", "3C:75:4A", "58:60:24", "70:2E:D9", "88:83:22",
  ]},
  { vendor: "Juniper Networks", prefixes: [
    "00:05:85", "00:10:DB", "00:12:1E", "00:14:F6", "00:17:CB", "00:19:E2", "00:1B:C0", "00:1D:B5",
    "00:1F:12", "00:21:59", "00:23:9C", "00:26:88", "2C:21:31", "2C:6B:F5", "3C:8A:B0", "5C:5E:AB",
  ]},
  { vendor: "Arista Networks", prefixes: [
    "00:1C:73", "44:4C:A8", "74:83:EF", "DC:A6:32", "F0:2F:74", "20:A6:CD", "28:99:3A", "6C:64:1A",
  ]},
  { vendor: "VMware, Inc", prefixes: [
    "00:0C:29", "00:05:69", "00:1C:14", "00:50:56",
  ]},
  { vendor: "Aruba Networks (HPE)", prefixes: [
    "00:0B:86", "00:1A:1E", "00:24:6C", "18:64:72", "20:4C:03", "24:DE:C6", "6C:F3:7F", "94:B4:0F",
  ]},
  { vendor: "Ruckus Wireless", prefixes: [
    "00:13:92", "00:24:82", "2C:B0:5D", "58:93:96", "8C:0C:90", "C4:01:7C",
  ]},
  { vendor: "Raspberry Pi Foundation", prefixes: [
    "28:CD:C1", "B8:27:EB", "D8:3A:DD", "DC:A6:32", "E4:5F:01",
  ]},
  { vendor: "Espressif Inc", prefixes: [
    "18:FE:34", "24:0A:C4", "2C:3A:E8", "30:AE:A4", "3C:71:BF", "5C:CF:7F", "84:0D:8E", "A0:20:A6",
    "AC:D0:74", "B4:E6:2D", "CC:50:E3", "DC:4F:22",
  ]},
  { vendor: "Nest Labs Inc (Google)", prefixes: [
    "18:B4:30", "64:16:66", "D0:52:A8",
  ]},
  { vendor: "Roku Inc", prefixes: [
    "00:0D:4B", "08:05:81", "AC:3A:7A", "B0:A7:37", "B8:3E:59", "CC:6D:A0", "D8:31:34",
  ]},
  { vendor: "Sonos, Inc", prefixes: [
    "00:0E:58", "34:7E:5C", "5C:AA:FD", "78:28:CA", "94:9F:3E", "B8:E9:37",
  ]},
  { vendor: "Philips Electronics", prefixes: [
    "00:0F:D3", "00:17:88", "00:22:F4", "EC:B5:FA",
  ]},
  { vendor: "Bose Corporation", prefixes: [
    "08:DF:1F", "28:D0:CA", "B0:34:95",
  ]},
  { vendor: "GoPro Inc", prefixes: [
    "A0:F1:EC", "D0:2E:AB", "F8:AF:05",
  ]},
  { vendor: "Zebra Technologies", prefixes: [
    "00:07:4D", "00:15:70", "00:23:68", "38:1B:C4", "68:82:F5",
  ]},
  { vendor: "Honeywell International", prefixes: [
    "00:04:F8", "00:26:D4", "8C:F2:28",
  ]},
  { vendor: "Cisco Meraki", prefixes: [
    "00:18:0A", "88:15:44", "AC:17:C8", "E0:55:3D", "F8:A9:6E",
  ]},
  { vendor: "Fortinet, Inc", prefixes: [
    "00:09:0F", "00:1F:AA", "08:5B:0E", "70:4C:A5", "90:6C:AC",
  ]},
  { vendor: "Palo Alto Networks", prefixes: [
    "00:1B:17", "28:16:AD", "94:B2:CC", "BC:24:11",
  ]},
  { vendor: "F5 Networks, Inc", prefixes: [
    "00:01:D7", "0C:C4:7A",
  ]},
  { vendor: "Check Point Software Technologies", prefixes: [
    "00:1C:7F", "F8:2D:2C",
  ]},
  { vendor: "SonicWall", prefixes: [
    "00:06:B1", "00:17:C5", "0C:9D:12",
  ]},
  { vendor: "WatchGuard Technologies", prefixes: [
    "00:90:7F", "00:1A:3D",
  ]},
  { vendor: "ARRIS Group, Inc", prefixes: [
    "00:04:BD", "00:0F:CA", "00:1D:CD", "00:23:5A", "00:26:F1", "18:2A:D3", "34:BD:C8", "58:23:8C",
    "68:6F:8E", "70:F1:1C", "84:E0:6E", "9C:34:26",
  ]},
  { vendor: "Motorola Mobility LLC", prefixes: [
    "00:0C:E5", "00:0E:5C", "00:1B:C6", "00:26:E8", "40:83:DE", "5C:0E:8B", "88:C6:26",
  ]},
  { vendor: "Nintendo Co, Ltd", prefixes: [
    "00:09:BF", "00:16:56", "00:19:1D", "00:1A:E9", "00:1B:7A", "00:1E:35", "00:1F:32", "00:21:47",
    "00:22:AA", "00:23:31", "00:24:1E", "00:24:F3", "00:25:A0", "18:2A:7B", "40:D2:8A",
  ]},
  { vendor: "Sony Interactive Entertainment", prefixes: [
    "00:04:1F", "00:13:15", "00:15:C1", "00:1F:A7", "28:0D:FC", "70:9E:29", "BC:60:A7",
  ]},
  { vendor: "Logitech, Inc", prefixes: [
    "00:07:61", "00:1F:20", "88:C6:26", "C8:0A:A9",
  ]},
  { vendor: "Buffalo Inc", prefixes: [
    "00:16:01", "00:1D:73", "00:24:A5", "10:6F:3F", "34:76:C5", "70:5D:CC",
  ]},
  { vendor: "Lenovo", prefixes: [
    "00:26:BE", "10:7B:EF", "28:D2:44", "3C:A8:2A", "54:EE:75", "6C:0B:84", "88:70:8C",
  ]},
  { vendor: "Acer Inc", prefixes: [
    "00:0B:CD", "00:1D:72", "00:24:8C", "10:BF:48", "38:D5:47",
  ]},
  { vendor: "Toshiba Corporation", prefixes: [
    "00:0B:97", "00:16:6E", "00:23:F1", "10:1F:F1", "3C:F7:A4",
  ]},
  { vendor: "Fujitsu Limited", prefixes: [
    "00:00:0B", "00:0B:5D", "00:11:88", "00:17:42", "00:19:99",
  ]},
  { vendor: "NEC Corporation", prefixes: [
    "00:00:4C", "00:04:5A", "00:0B:97", "00:12:88", "00:1F:23",
  ]},
  { vendor: "Panasonic Corporation", prefixes: [
    "00:0B:B7", "00:1C:5A", "00:23:CB", "18:E8:2A", "AC:E2:D3",
  ]},
  { vendor: "Canon Inc", prefixes: [
    "00:00:85", "00:1E:8F", "00:26:AB", "3C:A8:2A",
  ]},
  { vendor: "Seiko Epson Corporation", prefixes: [
    "00:00:48", "00:26:AB", "64:EB:8C",
  ]},
  { vendor: "Brother Industries, Ltd", prefixes: [
    "00:1B:A9", "00:80:77", "30:05:5C", "9C:93:4E",
  ]},
  { vendor: "Xerox Corporation", prefixes: [
    "00:00:AA", "00:01:AF", "00:04:79",
  ]},
  { vendor: "HTC Corporation", prefixes: [
    "00:23:76", "38:E7:D8", "7C:61:93", "90:21:55",
  ]},
  { vendor: "BlackBerry Limited", prefixes: [
    "00:1B:98", "20:B1:5C", "2C:8A:72",
  ]},
  { vendor: "Garmin International", prefixes: [
    "00:21:6A", "5C:F9:38", "A8:BE:27",
  ]},
  { vendor: "Fitbit, Inc", prefixes: [
    "AC:9E:17", "C8:69:CD", "D0:B5:C2",
  ]},
  { vendor: "iRobot Corporation", prefixes: [
    "50:14:79", "40:7A:66",
  ]},
  { vendor: "Ring LLC (Amazon)", prefixes: [
    "0C:47:C9", "3C:29:9F",
  ]},
  { vendor: "Wyze Labs, Inc", prefixes: [
    "2C:AA:8E", "7C:78:B2",
  ]},
  { vendor: "Ecobee Inc", prefixes: [
    "44:61:32", "5C:E0:C8",
  ]},
  { vendor: "Western Digital Technologies", prefixes: [
    "00:90:A9", "94:EB:CD",
  ]},
  { vendor: "Synology Incorporated", prefixes: [
    "00:11:32", "90:09:D0",
  ]},
  { vendor: "QNAP Systems, Inc", prefixes: [
    "00:08:9B", "24:5E:BE",
  ]},
  { vendor: "Extreme Networks", prefixes: [
    "00:01:30", "00:04:96", "5C:0E:8B",
  ]},
  { vendor: "Alcatel-Lucent", prefixes: [
    "00:80:9F", "00:0F:CB",
  ]},
  { vendor: "Ericsson AB", prefixes: [
    "00:01:EC", "00:0E:6D",
  ]},
  { vendor: "ZTE Corporation", prefixes: [
    "00:19:C6", "18:68:6A", "C8:9F:42",
  ]},
  { vendor: "Vizio, Inc", prefixes: [
    "00:19:D1", "D8:5D:E2",
  ]},
];

const OUI_DB = {};
for (const { vendor, prefixes } of VENDOR_BLOCKS) {
  for (const p of prefixes) OUI_DB[p.toUpperCase()] = vendor;
}
const OUI_TOTAL = Object.keys(OUI_DB).length;

function renderMacLookup(root) {
  root.innerHTML = `
    <div class="panel">
      <p class="muted">Look up the manufacturer of a network interface from its MAC address OUI (first 3 octets).
      Database covers ${OUI_TOTAL.toLocaleString()} OUI blocks across ${VENDOR_BLOCKS.length} vendors.</p>
      ${field("MAC address", "mc-mac", "3C:5A:B4:12:34:56", "e.g. AA:BB:CC:DD:EE:FF")}
      <div class="tk-btns"><button class="btn sm" id="mc-go">Look up</button></div>
      <div id="mc-out"></div>
      <p class="pg-sub" style="margin-top:20px">Browse vendor list</p>
      ${field("Filter vendors", "mc-filter", "", "type to filter, e.g. cisco")}
      <div id="mc-list" class="tk-out" style="max-height:280px;overflow:auto"></div>
    </div>`;

  const normalizeMac = (s) => {
    const hex = s.replace(/[^0-9a-fA-F]/g, "").toUpperCase();
    if (hex.length < 6) throw new Error("need at least 6 hex digits (the OUI)");
    return hex;
  };

  const calc = () => {
    const raw = root.querySelector("#mc-mac").value.trim();
    const out = root.querySelector("#mc-out");
    try {
      const hex = normalizeMac(raw);
      const oui = hex.slice(0, 6);
      const ouiFormatted = `${oui.slice(0, 2)}:${oui.slice(2, 4)}:${oui.slice(4, 6)}`;
      const vendor = OUI_DB[ouiFormatted] || null;
      const full = hex.padEnd(12, "0").slice(0, 12);
      const colonForm = full.match(/.{1,2}/g).join(":");
      const dashForm = full.match(/.{1,2}/g).join("-");
      const ciscoForm = full.match(/.{1,4}/g).join(".").toLowerCase();
      const bareForm = full.toLowerCase();
      const isUnicast = (parseInt(full[1], 16) & 1) === 0;
      const isUniversal = (parseInt(full[1], 16) & 2) === 0;
      const isBroadcast = full === "FFFFFFFFFFFF";

      out.innerHTML = `
        <div class="dl-cmd" style="margin-top:14px">
          <div class="stat-l">Vendor (OUI ${ouiFormatted})</div><div class="mono">${vendor ? escapeHtml(vendor) : "Unknown -- not in local database"}</div>
          <div class="stat-l">Colon form</div><div class="mono">${colonForm}</div>
          <div class="stat-l">Dash form</div><div class="mono">${dashForm}</div>
          <div class="stat-l">Cisco dotted form</div><div class="mono">${ciscoForm}</div>
          <div class="stat-l">Bare hex</div><div class="mono">${bareForm}</div>
          <div class="stat-l">Address type</div><div class="mono">${isBroadcast ? "Broadcast" : isUnicast ? "Unicast" : "Multicast"}</div>
          <div class="stat-l">Administration</div><div class="mono">${isUniversal ? "Universally administered (burned-in, vendor assigned)" : "Locally administered (software-assigned/randomized)"}</div>
        </div>
        <p class="muted" style="margin-top:10px">The U/L bit (2nd least-significant bit of the first octet) marks
        locally administered addresses -- common with MAC randomization on modern phones/laptops for privacy.
        The I/G bit (least-significant bit of the first octet) distinguishes unicast from multicast/broadcast.</p>`;
    } catch (err) {
      out.innerHTML = `<pre class="tk-out">Error: ${escapeHtml(err.message)}</pre>`;
    }
  };

  const renderList = () => {
    const filter = root.querySelector("#mc-filter").value.trim().toLowerCase();
    const list = root.querySelector("#mc-list");
    const rows = VENDOR_BLOCKS
      .filter((v) => !filter || v.vendor.toLowerCase().includes(filter) || v.prefixes.some((p) => p.toLowerCase().includes(filter)))
      .map((v) => `${v.vendor} (${v.prefixes.length} block${v.prefixes.length > 1 ? "s" : ""}): ${v.prefixes.join(", ")}`);
    list.textContent = rows.length ? rows.join("\n\n") : "No vendors match that filter.";
  };

  root.querySelector("#mc-go").onclick = calc;
  root.querySelector("#mc-mac").addEventListener("keydown", (e) => { if (e.key === "Enter") calc(); });
  root.querySelector("#mc-filter").addEventListener("input", renderList);
  calc();
  renderList();
}

// ---------------------------------------------------------------------------
//  Tool 6 -- DNS Record Type Reference
// ---------------------------------------------------------------------------

const DNS_RECORDS = [
  { type: "A", rfc: "RFC 1035", name: "Address record", desc: "Maps a hostname to a 32-bit IPv4 address. The most fundamental DNS record type -- almost every domain has at least one.", example: "example.com.  3600  IN  A  93.184.216.34" },
  { type: "AAAA", rfc: "RFC 3596", name: "IPv6 address record", desc: "Maps a hostname to a 128-bit IPv6 address. The IPv6 equivalent of an A record.", example: "example.com.  3600  IN  AAAA  2606:2800:220:1:248:1893:25c8:1946" },
  { type: "CNAME", rfc: "RFC 1035", name: "Canonical name record", desc: "Aliases one name to another (the canonical name). The resolver restarts the lookup using the target name. A CNAME cannot coexist with other records at the same name.", example: "www.example.com.  3600  IN  CNAME  example.com." },
  { type: "MX", rfc: "RFC 1035 / RFC 5321", name: "Mail exchange record", desc: "Specifies the mail server(s) responsible for accepting email for the domain, along with a priority (lower value = higher priority).", example: "example.com.  3600  IN  MX  10 mail.example.com." },
  { type: "TXT", rfc: "RFC 1035", name: "Text record", desc: "Holds arbitrary free-form text. Widely repurposed for SPF, DKIM, DMARC, domain verification (Google, Microsoft, etc.), and other machine-readable metadata.", example: 'example.com.  3600  IN  TXT  "v=spf1 include:_spf.google.com ~all"' },
  { type: "NS", rfc: "RFC 1035", name: "Name server record", desc: "Delegates a DNS zone to a set of authoritative name servers. Every zone must have at least one NS record at its apex.", example: "example.com.  86400  IN  NS  ns1.example.com." },
  { type: "SOA", rfc: "RFC 1035 / RFC 2308", name: "Start of authority", desc: "Marks the start of a zone and holds administrative info: primary NS, admin email, serial number, and refresh/retry/expire/minimum-TTL timers used for zone transfers and negative caching.", example: "example.com.  86400  IN  SOA  ns1.example.com. admin.example.com. 2024010100 7200 3600 1209600 3600" },
  { type: "PTR", rfc: "RFC 1035", name: "Pointer record", desc: "Maps an IP address to a hostname -- used for reverse DNS lookups, stored under the special in-addr.arpa (IPv4) or ip6.arpa (IPv6) zones.", example: "34.216.184.93.in-addr.arpa.  3600  IN  PTR  example.com." },
  { type: "SRV", rfc: "RFC 2782", name: "Service locator record", desc: "Specifies host, port, priority, and weight for a specific service (e.g. SIP, XMPP, LDAP), enabling service discovery without hardcoded hostnames/ports.", example: "_sip._tcp.example.com.  3600  IN  SRV  10 60 5060 sipserver.example.com." },
  { type: "CAA", rfc: "RFC 8659", name: "Certification authority authorization", desc: "Restricts which certificate authorities are allowed to issue TLS certificates for the domain, mitigating unauthorized cert issuance.", example: 'example.com.  3600  IN  CAA  0 issue "letsencrypt.org"' },
  { type: "NAPTR", rfc: "RFC 3403", name: "Naming authority pointer", desc: "Used for dynamic delegation discovery (DDDS), commonly for ENUM (mapping telephone numbers to URIs) and SIP routing.", example: 'example.com.  3600  IN  NAPTR  100 10 "U" "E2U+sip" "!^.*$!sip:info@example.com!" .' },
  { type: "DNSKEY", rfc: "RFC 4034", name: "DNSSEC public key", desc: "Publishes the public key used to verify DNSSEC RRSIG signatures for the zone. Zone-signing keys (ZSK) and key-signing keys (KSK) both use this record type.", example: "example.com.  3600  IN  DNSKEY  256 3 8 AwEAAcaVGJVpjF..." },
  { type: "DS", rfc: "RFC 4034", name: "Delegation signer", desc: "Placed in a parent zone to establish a DNSSEC chain of trust down to the child zone -- a hash of the child zone's DNSKEY.", example: "example.com.  3600  IN  DS  2371 8 2 3F7A1DF3688..." },
  { type: "RRSIG", rfc: "RFC 4034", name: "DNSSEC signature", desc: "Holds the digital signature covering an RRset, produced with the zone's private key and verified against the published DNSKEY.", example: "example.com.  3600  IN  RRSIG  A 8 2 3600 20240201000000 20240101000000 2371 example.com. sig..." },
  { type: "NSEC", rfc: "RFC 4034", name: "Next secure record", desc: "Provides authenticated denial of existence in DNSSEC -- lists the next owner name in canonical order and which record types exist at the current name. Allows zone enumeration (walking).", example: "a.example.com.  3600  IN  NSEC  b.example.com. A RRSIG NSEC" },
  { type: "NSEC3", rfc: "RFC 5155", name: "Hashed next secure record", desc: "Like NSEC but hashes owner names before ordering them, preventing trivial zone enumeration by walking NSEC records.", example: "q04j...  3600  IN  NSEC3  1 0 10 AABBCCDD q05k... A RRSIG" },
  { type: "TLSA", rfc: "RFC 6698", name: "TLSA certificate association (DANE)", desc: "Associates a TLS certificate or public key with a hostname/port, used by DANE to pin certificates independent of the public CA system.", example: "_443._tcp.example.com.  3600  IN  TLSA  3 1 1 92003ba34942dc74152..." },
  { type: "SSHFP", rfc: "RFC 4255", name: "SSH fingerprint record", desc: "Publishes the fingerprint of an SSH host key in DNS so clients can verify a server's identity via DNSSEC instead of trust-on-first-use.", example: "example.com.  3600  IN  SSHFP  2 1 123456789abcdef67890123456789abcdef67890" },
  { type: "LOC", rfc: "RFC 1876", name: "Location record", desc: "Encodes geographic location (latitude, longitude, altitude, precision) for a host or domain. Rarely used in production.", example: "example.com.  3600  IN  LOC  37 48 48.0 N 122 25 48.0 W 10m" },
  { type: "HINFO", rfc: "RFC 1035", name: "Host information record", desc: "Describes host CPU and OS type as free text. Largely obsolete and considered an information-disclosure risk if published.", example: 'host.example.com.  3600  IN  HINFO  "INTEL-X64" "LINUX"' },
  { type: "RP", rfc: "RFC 1183", name: "Responsible person record", desc: "Identifies the person responsible for a host or domain, with an email (mailbox) name and a pointer to a TXT record with more detail.", example: "example.com.  3600  IN  RP  admin.example.com. admin-info.example.com." },
  { type: "AFSDB", rfc: "RFC 1183", name: "AFS database record", desc: "Locates servers for AFS (Andrew File System) cells or DCE authenticated-naming-system servers. Legacy, niche usage.", example: "example.com.  3600  IN  AFSDB  1 afsdb.example.com." },
  { type: "CERT", rfc: "RFC 4398", name: "Certificate record", desc: "Stores PKIX, SPKI, PGP, or other certificates directly in DNS for retrieval by name.", example: "example.com.  3600  IN  CERT  PKIX 0 0 MIIC..." },
  { type: "DNAME", rfc: "RFC 6672", name: "Delegation name record", desc: "Redirects an entire subtree of the DNS namespace to another domain, unlike CNAME which only redirects a single name.", example: "old.example.com.  3600  IN  DNAME  new.example.com." },
  { type: "SPF", rfc: "RFC 7208 (obsoleted as own type)", name: "Sender Policy Framework (legacy)", desc: "Originally a dedicated record type for SPF; RFC 7208 deprecated it in favor of publishing SPF policy as a TXT record instead.", example: 'example.com.  3600  IN  TXT  "v=spf1 mx a ip4:203.0.113.0/24 -all"' },
  { type: "DHCID", rfc: "RFC 4701", name: "DHCP identifier record", desc: "Used with DNS updates from DHCP servers to associate a DHCP client with a DNS name without conflicts between clients.", example: "host.example.com.  3600  IN  DHCID  AAIBY2/AuCccgoSwXwaTNCS1MP..." },
  { type: "IPSECKEY", rfc: "RFC 4025", name: "IPsec key record", desc: "Publishes public keys for use with IPsec, along with the associated gateway information, enabling opportunistic IPsec.", example: "example.com.  3600  IN  IPSECKEY  10 1 2 192.0.2.38 AQNRU3mG7TVTO2BkR..." },
  { type: "OPENPGPKEY", rfc: "RFC 7929", name: "OpenPGP public key record", desc: "Publishes an OpenPGP public key for an email address at a hashed local-part name, part of the DANE-for-email-encryption ecosystem.", example: "abcdef0123456789._openpgpkey.example.com.  3600  IN  OPENPGPKEY  mQINBFj..." },
  { type: "URI", rfc: "RFC 7553", name: "Uniform resource identifier record", desc: "Publishes a URI associated with a target name, along with priority and weight, similar in spirit to SRV but for arbitrary URIs.", example: '_ftp._tcp.example.com.  3600  IN  URI  10 1 "ftp://ftp.example.com/"' },
  { type: "SVCB", rfc: "RFC 9460", name: "Service binding record", desc: "General-purpose record for advertising how to reach a service, including ALPN protocols and connection parameters, used as the basis for HTTPS records.", example: "example.com.  3600  IN  SVCB  1 svc1.example.net. alpn=h2,h3" },
  { type: "HTTPS", rfc: "RFC 9460", name: "HTTPS service binding record", desc: "Specialized SVCB record for HTTPS origins -- lets clients discover HTTP/2, HTTP/3, and ECH parameters without an extra round trip.", example: "example.com.  3600  IN  HTTPS  1 . alpn=h3,h2 ipv4hint=93.184.216.34" },
  { type: "CSYNC", rfc: "RFC 7477", name: "Child-to-parent synchronization record", desc: "Lets a child zone signal the parent zone to synchronize NS and glue records automatically, reducing manual delegation updates.", example: "example.com.  3600  IN  CSYNC  2024010100 3 A NS AAAA" },
  { type: "ZONEMD", rfc: "RFC 8976", name: "Zone message digest record", desc: "Provides a cryptographic digest of zone contents so the entire zone can be verified for integrity when transferred out-of-band.", example: "example.com.  86400  IN  ZONEMD  2024010100 1 1 c68090d90a7aed71..." },
  { type: "ANY / *", rfc: "RFC 1035 (qtype)", name: "Wildcard query type", desc: "A query type (not a stored record type) requesting all available record types for a name. Many resolvers now refuse or minimize ANY responses to reduce DNS amplification abuse.", example: "dig example.com ANY" },
  { type: "AXFR", rfc: "RFC 5936", name: "Full zone transfer (qtype)", desc: "A special query type requesting a complete copy of a zone from an authoritative server -- should be restricted to trusted secondary servers only, since an open AXFR leaks the entire zone.", example: "dig axfr example.com @ns1.example.com" },
  { type: "IXFR", rfc: "RFC 1995", name: "Incremental zone transfer (qtype)", desc: "Requests only the changes to a zone since a given serial number, reducing bandwidth compared to a full AXFR for large zones.", example: "dig ixfr=2024010100 example.com @ns1.example.com" },
];

function renderDnsReference(root) {
  root.innerHTML = `
    <div class="panel">
      <p class="muted">Reference for ${DNS_RECORDS.length} DNS resource record types: purpose, defining RFC, and an
      example zone-file line.</p>
      ${field("Filter", "dns-filter", "", "type, RFC number, or keyword")}
      <div id="dns-count" class="muted" style="margin:8px 0"></div>
      <div id="dns-list"></div>
    </div>`;

  const renderList = () => {
    const filter = root.querySelector("#dns-filter").value.trim().toLowerCase();
    const rows = DNS_RECORDS.filter((r) =>
      !filter || r.type.toLowerCase().includes(filter) || r.name.toLowerCase().includes(filter) ||
      r.desc.toLowerCase().includes(filter) || r.rfc.toLowerCase().includes(filter));
    root.querySelector("#dns-count").textContent = `${rows.length} of ${DNS_RECORDS.length} record types`;
    root.querySelector("#dns-list").innerHTML = rows.map((r) => `
      <div class="card" style="margin-bottom:10px;padding:14px">
        <div style="display:flex;justify-content:space-between;align-items:baseline;flex-wrap:wrap;gap:8px">
          <strong class="mono" style="font-size:1.05rem">${escapeHtml(r.type)}</strong>
          <span class="muted" style="font-size:.8rem">${escapeHtml(r.rfc)}</span>
        </div>
        <div class="pg-sub" style="margin:4px 0">${escapeHtml(r.name)}</div>
        <p class="muted" style="margin:6px 0">${escapeHtml(r.desc)}</p>
        <pre class="tk-out" style="margin:0">${escapeHtml(r.example)}</pre>
      </div>`).join("") || `<p class="muted">No record types match that filter.</p>`;
  };

  root.querySelector("#dns-filter").addEventListener("input", renderList);
  renderList();
}

// ---------------------------------------------------------------------------
//  Tool 7 -- HTTP Status Code Reference
// ---------------------------------------------------------------------------

const HTTP_STATUS = [
  // 1xx Informational
  { code: 100, name: "Continue", cat: "1xx Informational", desc: "The initial part of a request has been received and the client should continue sending the rest, or ignore this response if the request is already finished.", causes: "Sent by servers in response to an Expect: 100-continue header on large request bodies." },
  { code: 101, name: "Switching Protocols", cat: "1xx Informational", desc: "The server is complying with a client's Upgrade request header and switching to a different protocol (e.g. from HTTP/1.1 to WebSocket).", causes: "WebSocket handshake completion, HTTP/2 upgrade over cleartext." },
  { code: 102, name: "Processing", cat: "1xx Informational", desc: "WebDAV: the server has received and is processing the request, but no response is available yet -- prevents client timeout.", causes: "Long-running WebDAV operations (COPY, MOVE across large collections)." },
  { code: 103, name: "Early Hints", cat: "1xx Informational", desc: "Allows the server to send preliminary headers (e.g. Link: preload) before the final response is ready, letting the browser start fetching resources early.", causes: "Used by CDNs/servers to speed up page load via early resource hints." },

  // 2xx Success
  { code: 200, name: "OK", cat: "2xx Success", desc: "The request succeeded. The meaning depends on the method: GET returns a representation, POST returns the result of the action, HEAD returns only headers.", causes: "Standard successful response for nearly any request." },
  { code: 201, name: "Created", cat: "2xx Success", desc: "The request succeeded and a new resource was created as a result, typically returned by POST or PUT, usually with a Location header pointing to the new resource.", causes: "Successful resource creation via a REST API." },
  { code: 202, name: "Accepted", cat: "2xx Success", desc: "The request has been accepted for processing, but processing is not complete -- there is no guarantee it will ultimately be acted upon.", causes: "Asynchronous job queues, batch processing APIs." },
  { code: 203, name: "Non-Authoritative Information", cat: "2xx Success", desc: "The returned metadata is not exactly the same as available from the origin server, typically because a transforming proxy modified it.", causes: "Proxies or CDNs that rewrite response headers." },
  { code: 204, name: "No Content", cat: "2xx Success", desc: "The request succeeded but there is no content to send in the response body. Often used after a DELETE or a successful PUT that returns nothing.", causes: "Successful DELETE, form submissions that shouldn't navigate away." },
  { code: 205, name: "Reset Content", cat: "2xx Success", desc: "Tells the client to reset the document view that sent this request, e.g. clear a form after successful submission.", causes: "Form submission handlers signalling the UI to reset." },
  { code: 206, name: "Partial Content", cat: "2xx Success", desc: "Used when the Range header was sent to request only part of a resource; this response contains only that requested part.", causes: "Video/audio streaming, resumable downloads." },
  { code: 207, name: "Multi-Status", cat: "2xx Success", desc: "WebDAV: conveys multiple independent status codes for sub-operations of a single request, encoded in the XML body.", causes: "WebDAV PROPFIND/PROPPATCH operating on multiple resources." },
  { code: 208, name: "Already Reported", cat: "2xx Success", desc: "WebDAV: used inside a DAV binding to avoid enumerating the members of a collection more than once.", causes: "WebDAV bindings referencing the same resource multiple times." },
  { code: 226, name: "IM Used", cat: "2xx Success", desc: "The server fulfilled the request and the response is a representation of the result of one or more instance manipulations applied to the current instance.", causes: "Delta encoding responses (RFC 3229)." },

  // 3xx Redirection
  { code: 300, name: "Multiple Choices", cat: "3xx Redirection", desc: "The request has more than one possible response; the user or user-agent should choose one, often listed in the body or via Location.", causes: "Content negotiation with multiple representations available." },
  { code: 301, name: "Moved Permanently", cat: "3xx Redirection", desc: "The resource has been permanently moved to a new URL given in the Location header; search engines and clients should update bookmarks/links.", causes: "Domain migrations, HTTP to HTTPS redirects, URL restructuring." },
  { code: 302, name: "Found", cat: "3xx Redirection", desc: "The resource temporarily resides at a different URL. Historically often misused where 303 or 307 were more correct; most clients treat it as 303 in practice.", causes: "Temporary redirects, legacy PHP/ASP redirect() calls." },
  { code: 303, name: "See Other", cat: "3xx Redirection", desc: "The response to the request can be found at another URL using GET, regardless of the original request method -- the classic Post/Redirect/Get pattern.", causes: "Redirecting after a successful form POST to prevent duplicate submissions." },
  { code: 304, name: "Not Modified", cat: "3xx Redirection", desc: "Indicates the cached version of the resource is still valid; sent in response to a conditional GET with If-None-Match or If-Modified-Since.", causes: "Browser cache validation, saves bandwidth by not resending unchanged content." },
  { code: 305, name: "Use Proxy", cat: "3xx Redirection", desc: "Deprecated: the requested resource must be accessed through the proxy given in the Location header. Deprecated due to security concerns.", causes: "Legacy proxy configuration directives; not used in modern APIs." },
  { code: 306, name: "Switch Proxy", cat: "3xx Redirection", desc: "Reserved but no longer used -- was defined in a draft of the HTTP/1.1 spec and never standardized.", causes: "Not used in modern HTTP; reserved for historical reasons." },
  { code: 307, name: "Temporary Redirect", cat: "3xx Redirection", desc: "Like 302 but guarantees the request method and body will not change when the redirected request is made -- safe for non-GET requests.", causes: "APIs redirecting POST/PUT requests without changing the method." },
  { code: 308, name: "Permanent Redirect", cat: "3xx Redirection", desc: "Like 301 but guarantees the request method and body will not change on the redirected request.", causes: "Permanent API endpoint moves that must preserve the HTTP method." },

  // 4xx Client Error
  { code: 400, name: "Bad Request", cat: "4xx Client Error", desc: "The server cannot process the request due to a client error: malformed syntax, invalid request framing, or deceptive routing.", causes: "Malformed JSON body, missing required fields, invalid query parameters." },
  { code: 401, name: "Unauthorized", cat: "4xx Client Error", desc: "Authentication is required and has failed or has not been provided. Despite the name, this is about authentication, not authorization.", causes: "Missing or invalid API token, expired session, missing Authorization header." },
  { code: 402, name: "Payment Required", cat: "4xx Client Error", desc: "Reserved for future use; originally envisioned for digital payment systems. Some APIs repurpose it for subscription/quota-exceeded errors.", causes: "APIs signaling exhausted paid quota or unpaid invoices (non-standard usage)." },
  { code: 403, name: "Forbidden", cat: "4xx Client Error", desc: "The client's identity is known but it does not have permission to access the resource -- unlike 401, re-authenticating will not help.", causes: "Insufficient role/permissions, IP allowlist blocks, WAF rule matches." },
  { code: 404, name: "Not Found", cat: "4xx Client Error", desc: "The server cannot find the requested resource. Also used to disguise a 403 without revealing that the resource exists.", causes: "Broken links, mistyped URLs, deleted resources, deliberate obfuscation of 403s." },
  { code: 405, name: "Method Not Allowed", cat: "4xx Client Error", desc: "The request method is known by the server but is not supported by the target resource, e.g. sending DELETE to a read-only endpoint.", causes: "Calling a REST endpoint with the wrong HTTP verb." },
  { code: 406, name: "Not Acceptable", cat: "4xx Client Error", desc: "No content matching the criteria given in the request's Accept headers is available and the server is unwilling to supply a default representation.", causes: "Strict content negotiation with unsupported Accept/Accept-Language headers." },
  { code: 407, name: "Proxy Authentication Required", cat: "4xx Client Error", desc: "Similar to 401 but authentication must be done via a proxy, indicated by the Proxy-Authenticate response header.", causes: "Corporate/forward proxies requiring credentials before forwarding traffic." },
  { code: 408, name: "Request Timeout", cat: "4xx Client Error", desc: "The server timed out waiting for the request; the client did not produce a complete request within the time the server was prepared to wait.", causes: "Slow clients, idle keep-alive connections, slowloris-style attacks." },
  { code: 409, name: "Conflict", cat: "4xx Client Error", desc: "The request conflicts with the current state of the target resource, e.g. two edits to the same resource, or a duplicate unique key.", causes: "Concurrent edit conflicts, version mismatches, duplicate resource creation." },
  { code: 410, name: "Gone", cat: "4xx Client Error", desc: "The resource requested is permanently unavailable and will not be available again -- a more definitive signal than 404 for cleanup/deindexing.", causes: "Deliberately decommissioned resources/endpoints." },
  { code: 411, name: "Length Required", cat: "4xx Client Error", desc: "The server refuses to accept the request without a defined Content-Length header.", causes: "Chunked-encoding-only clients hitting servers that require an explicit length." },
  { code: 412, name: "Precondition Failed", cat: "4xx Client Error", desc: "One or more conditions in the request header fields (If-Match, If-Unmodified-Since, etc.) evaluated to false.", causes: "Optimistic concurrency control -- resource changed since the client last read it." },
  { code: 413, name: "Content Too Large", cat: "4xx Client Error", desc: "The request body is larger than limits defined by the server; formerly known as Payload Too Large / Request Entity Too Large.", causes: "Oversized file uploads, large JSON payloads exceeding server limits." },
  { code: 414, name: "URI Too Long", cat: "4xx Client Error", desc: "The URI requested by the client is longer than the server is willing to interpret.", causes: "Excessively long query strings, GET requests used to pass large data sets." },
  { code: 415, name: "Unsupported Media Type", cat: "4xx Client Error", desc: "The media format of the requested data (Content-Type) is not supported by the server.", causes: "Sending XML to a JSON-only API, missing/incorrect Content-Type header." },
  { code: 416, name: "Range Not Satisfiable", cat: "4xx Client Error", desc: "The range specified by the Range header cannot be fulfilled -- it may be outside the size of the target resource.", causes: "Resumable download client requesting bytes beyond the file's end." },
  { code: 417, name: "Expectation Failed", cat: "4xx Client Error", desc: "The expectation given in the request's Expect header could not be met by the server.", causes: "Sending Expect: 100-continue to a server/proxy that doesn't support it." },
  { code: 418, name: "I'm a Teapot", cat: "4xx Client Error", desc: "An April Fools' joke from RFC 2324 (Hyper Text Coffee Pot Control Protocol) -- a teapot receiving a request to brew coffee. Kept alive in some frameworks as an easter egg.", causes: "Deliberately implemented as a joke; occasionally used to detect naive bots that don't handle unusual codes." },
  { code: 421, name: "Misdirected Request", cat: "4xx Client Error", desc: "The request was directed at a server that is not able to produce a response, e.g. sent to the wrong origin via connection reuse/coalescing.", causes: "HTTP/2 connection coalescing routing a request to the wrong virtual host." },
  { code: 422, name: "Unprocessable Content", cat: "4xx Client Error", desc: "The request was well-formed but contains semantic errors -- e.g. valid JSON that fails schema/business-rule validation.", causes: "Failed validation rules in REST APIs (invalid email format, out-of-range values)." },
  { code: 423, name: "Locked", cat: "4xx Client Error", desc: "WebDAV: the resource being accessed is locked.", causes: "WebDAV collaborative editing locks preventing concurrent writes." },
  { code: 424, name: "Failed Dependency", cat: "4xx Client Error", desc: "WebDAV: the request failed because it depended on another request that failed.", causes: "Chained WebDAV operations where an earlier step failed." },
  { code: 425, name: "Too Early", cat: "4xx Client Error", desc: "The server is unwilling to risk processing a request that might be replayed, used to protect against replay attacks on TLS 1.3 0-RTT data.", causes: "TLS 1.3 early-data requests that are unsafe to process before the handshake completes." },
  { code: 426, name: "Upgrade Required", cat: "4xx Client Error", desc: "The server refuses to perform the request using the current protocol but might be willing to after the client upgrades, indicated via the Upgrade header.", causes: "Servers requiring TLS or a newer HTTP version before proceeding." },
  { code: 428, name: "Precondition Required", cat: "4xx Client Error", desc: "The origin server requires the request to be conditional, to prevent the 'lost update' problem where a client overwrites a resource without knowledge of prior changes.", causes: "APIs mandating If-Match headers for update operations." },
  { code: 429, name: "Too Many Requests", cat: "4xx Client Error", desc: "The user has sent too many requests in a given amount of time (rate limiting). Often includes a Retry-After header.", causes: "API rate limits, brute-force login protections, abuse mitigation." },
  { code: 431, name: "Request Header Fields Too Large", cat: "4xx Client Error", desc: "The server is unwilling to process the request because its header fields are too large.", causes: "Oversized cookies, excessive custom headers, malformed proxied headers." },
  { code: 451, name: "Unavailable For Legal Reasons", cat: "4xx Client Error", desc: "The server operator has received a legal demand to deny access to the resource, e.g. censorship or DMCA takedowns. Named after Ray Bradbury's Fahrenheit 451.", causes: "Government-ordered content blocking, court-ordered takedowns." },

  // 5xx Server Error
  { code: 500, name: "Internal Server Error", cat: "5xx Server Error", desc: "A generic catch-all response indicating an unexpected condition was encountered on the server and no more specific message is suitable.", causes: "Unhandled exceptions, application bugs, misconfiguration." },
  { code: 501, name: "Not Implemented", cat: "5xx Server Error", desc: "The request method is not supported by the server and cannot be handled -- the only methods servers are required to support are GET and HEAD.", causes: "Calling an HTTP method the server/framework has not implemented." },
  { code: 502, name: "Bad Gateway", cat: "5xx Server Error", desc: "The server, while acting as a gateway or proxy, received an invalid response from the upstream server it accessed.", causes: "Backend application crashed or is unreachable from a reverse proxy/load balancer." },
  { code: 503, name: "Service Unavailable", cat: "5xx Server Error", desc: "The server is not ready to handle the request, often due to maintenance or overload. Should ideally include a Retry-After header.", causes: "Planned maintenance windows, overloaded backend, health-check failures behind a load balancer." },
  { code: 504, name: "Gateway Timeout", cat: "5xx Server Error", desc: "The server, while acting as a gateway or proxy, did not get a response in time from the upstream server.", causes: "Slow database queries, backend timeouts, network issues between proxy and origin." },
  { code: 505, name: "HTTP Version Not Supported", cat: "5xx Server Error", desc: "The HTTP version used in the request is not supported by the server.", causes: "Legacy or experimental HTTP versions hitting servers that only support HTTP/1.1 or HTTP/2." },
  { code: 506, name: "Variant Also Negotiates", cat: "5xx Server Error", desc: "The server has an internal configuration error: transparent content negotiation results in a circular reference.", causes: "Misconfigured Apache content-negotiation (mod_negotiation) setups." },
  { code: 507, name: "Insufficient Storage", cat: "5xx Server Error", desc: "WebDAV: the method could not be performed because the server is unable to store the representation needed to complete the request.", causes: "WebDAV/CalDAV server disk space exhaustion." },
  { code: 508, name: "Loop Detected", cat: "5xx Server Error", desc: "WebDAV: the server detected an infinite loop while processing a request (e.g. via DAV bindings).", causes: "Circular WebDAV collection bindings." },
  { code: 510, name: "Not Extended", cat: "5xx Server Error", desc: "Further extensions to the request are required for the server to fulfil it, as described by the HTTP Extension Framework.", causes: "Rarely used; niche extension-negotiation scenarios." },
  { code: 511, name: "Network Authentication Required", cat: "5xx Server Error", desc: "The client needs to authenticate to gain network access, typically returned by captive portals (hotel/airport Wi-Fi) instead of the actual target.", causes: "Captive portal login pages intercepting traffic before granting internet access." },
];

function renderHttpReference(root) {
  const cats = [...new Set(HTTP_STATUS.map((s) => s.cat))];
  root.innerHTML = `
    <div class="panel">
      <p class="muted">Complete reference for all ${HTTP_STATUS.length} standard HTTP status codes (1xx-5xx):
      meaning, category, and common real-world causes.</p>
      <div class="tk-row">
        <input class="tk-f" id="http-filter" placeholder="Filter by code, name, or keyword">
        <select class="tk-f" id="http-cat" style="max-width:220px">
          <option value="">All categories</option>
          ${cats.map((c) => `<option value="${c}">${c}</option>`).join("")}
        </select>
      </div>
      <div id="http-count" class="muted" style="margin:8px 0"></div>
      <div id="http-list"></div>
    </div>`;

  const renderList = () => {
    const filter = root.querySelector("#http-filter").value.trim().toLowerCase();
    const cat = root.querySelector("#http-cat").value;
    const rows = HTTP_STATUS.filter((s) =>
      (!cat || s.cat === cat) &&
      (!filter || String(s.code).includes(filter) || s.name.toLowerCase().includes(filter) || s.desc.toLowerCase().includes(filter)));
    root.querySelector("#http-count").textContent = `${rows.length} of ${HTTP_STATUS.length} status codes`;
    root.querySelector("#http-list").innerHTML = rows.map((s) => `
      <div class="card" style="margin-bottom:10px;padding:14px">
        <div style="display:flex;justify-content:space-between;align-items:baseline;flex-wrap:wrap;gap:8px">
          <strong class="mono" style="font-size:1.1rem">${s.code} ${escapeHtml(s.name)}</strong>
          <span class="muted" style="font-size:.8rem">${escapeHtml(s.cat)}</span>
        </div>
        <p class="muted" style="margin:6px 0">${escapeHtml(s.desc)}</p>
        <p style="margin:0;font-size:.85rem"><strong>Common causes:</strong> ${escapeHtml(s.causes)}</p>
      </div>`).join("") || `<p class="muted">No status codes match that filter.</p>`;
  };

  root.querySelector("#http-filter").addEventListener("input", renderList);
  root.querySelector("#http-cat").addEventListener("change", renderList);
  renderList();
}

// ---------------------------------------------------------------------------
//  Tool 8 -- Port Scanner Reference (well-known + registered ports)
// ---------------------------------------------------------------------------
//
// Each row: [port, protocol ("TCP", "UDP", or "TCP/UDP"), service name, description, security note]

const PORT_ROWS = [
  [1, "TCP/UDP", "TCPMUX", "TCP Port Service Multiplexer -- historic protocol for multiplexing services on one port.", "Rarely seen; unexpected activity may indicate legacy or misconfigured software."],
  [5, "TCP/UDP", "RJE", "Remote Job Entry -- legacy mainframe batch job submission protocol.", "Obsolete; presence suggests very old infrastructure."],
  [7, "TCP/UDP", "Echo", "Echoes back any data received; used historically for connectivity testing.", "Abused for UDP reflection/amplification DDoS; should be disabled."],
  [9, "TCP/UDP", "Discard", "Silently discards any data received -- a network null device.", "Low risk but unnecessary; disable if not needed."],
  [11, "TCP", "SYSTAT", "Reports active users/processes on a system -- an early systat service.", "Information disclosure if exposed externally."],
  [13, "TCP/UDP", "Daytime", "Returns the current date and time as readable text.", "Minor info disclosure; can aid time-based attacks."],
  [17, "TCP/UDP", "QOTD", "Quote of the Day -- returns a short text message.", "Can be abused for UDP amplification DDoS."],
  [19, "TCP/UDP", "Chargen", "Character Generator -- streams a repeating character sequence for testing.", "Classic UDP amplification/DoS vector; should never be enabled."],
  [20, "TCP", "FTP-DATA", "File Transfer Protocol data channel used for the actual file transfer in active mode.", "Cleartext data; can be sniffed on the wire."],
  [21, "TCP", "FTP", "File Transfer Protocol control channel -- authentication and command exchange.", "Cleartext credentials; prefer FTPS or SFTP. Frequent target for anonymous-login and brute-force attacks."],
  [22, "TCP", "SSH", "Secure Shell -- encrypted remote administration, tunneling, and file transfer (SFTP/SCP).", "High-value target for credential brute-forcing; disable password auth and use key-based auth."],
  [23, "TCP", "Telnet", "Unencrypted remote terminal access.", "Cleartext credentials and session data; should be disabled in favor of SSH."],
  [25, "TCP", "SMTP", "Simple Mail Transfer Protocol -- server-to-server mail relay.", "Open relays are abused for spam; restrict relay to authenticated/authorized hosts."],
  [26, "TCP", "RSFTP", "Alternate FTP-like service sometimes used to avoid ISP blocks on port 21.", "Same risks as standard FTP if unencrypted."],
  [37, "TCP/UDP", "Time", "Returns the current time as a 32-bit binary value (RFC 868).", "Legacy; largely superseded by NTP."],
  [39, "UDP", "RLP", "Resource Location Protocol -- legacy resource discovery.", "Rarely used; unexpected traffic may indicate misconfiguration."],
  [42, "TCP/UDP", "WINS / Nameserv", "Host Name Server / WINS replication.", "Legacy NetBIOS name resolution; internal use only."],
  [43, "TCP", "WHOIS", "Queries domain/IP registration ownership databases.", "Can leak registrant PII if not privacy-protected; used heavily in recon."],
  [49, "TCP/UDP", "TACACS", "Terminal Access Controller Access-Control System -- legacy AAA protocol for network devices.", "Superseded by TACACS+; weak/no encryption in original spec."],
  [53, "TCP/UDP", "DNS", "Domain Name System -- resolves hostnames to IP addresses; TCP used for zone transfers and large responses.", "Cache poisoning, DNS tunneling for data exfiltration/C2, and amplification DDoS via open resolvers."],
  [67, "UDP", "DHCP (server)", "Dynamic Host Configuration Protocol -- server listens here for client requests.", "Rogue DHCP servers can redirect clients to malicious gateways/DNS."],
  [68, "UDP", "DHCP (client)", "DHCP client listens here for server offers/acknowledgments.", "Susceptible to DHCP starvation and spoofing attacks."],
  [69, "UDP", "TFTP", "Trivial File Transfer Protocol -- simple, unauthenticated file transfer.", "No authentication or encryption; widely used to bootstrap network devices/firmware, a common pivot target."],
  [70, "TCP", "Gopher", "Pre-web hierarchical document retrieval protocol.", "Largely historical; rarely seen today."],
  [79, "TCP", "Finger", "Returns information about users on a remote system.", "User enumeration and information disclosure; should be disabled."],
  [80, "TCP", "HTTP", "Hypertext Transfer Protocol -- unencrypted web traffic.", "All traffic is cleartext; susceptible to MITM, should redirect to HTTPS."],
  [81, "TCP", "HTTP-Alt", "Alternate HTTP port, often used by proxies, cameras, or embedded devices.", "Frequently exposed IoT/router admin panels with weak default credentials."],
  [82, "TCP", "HTTP-Alt", "Secondary alternate HTTP port used by some web admin interfaces.", "Often overlooked in scans; check for exposed management UIs."],
  [88, "TCP/UDP", "Kerberos", "Network authentication protocol using tickets to avoid transmitting passwords.", "Kerberoasting and AS-REP roasting attacks target this service in Active Directory environments."],
  [102, "TCP", "ISO-TSAP", "ISO Transport Service Access Point -- used by Siemens S7 industrial PLCs.", "Common ICS/SCADA attack surface; often unauthenticated."],
  [110, "TCP", "POP3", "Post Office Protocol v3 -- downloads email from a mail server.", "Cleartext credentials by default; use POP3S (995) instead."],
  [111, "TCP/UDP", "RPCbind / Portmapper", "Maps RPC program numbers to network port numbers for services like NFS.", "Information disclosure of running RPC services; historically exploited for DoS/enumeration."],
  [113, "TCP", "Ident", "Identification Protocol -- identifies the user of a TCP connection.", "Minor information disclosure; occasionally required by IRC networks."],
  [119, "TCP", "NNTP", "Network News Transfer Protocol -- Usenet article distribution.", "Cleartext; largely legacy today."],
  [123, "UDP", "NTP", "Network Time Protocol -- synchronizes system clocks.", "monlist command abused for large-scale UDP amplification DDoS attacks."],
  [135, "TCP/UDP", "MSRPC", "Microsoft RPC endpoint mapper, used by many Windows services (DCOM, etc.).", "Historic target of major worms (Blaster); exposes internal service enumeration."],
  [137, "UDP", "NetBIOS Name Service", "Resolves NetBIOS names to IP addresses on a local network.", "NBT-NS poisoning (Responder) used to capture credential hashes."],
  [138, "UDP", "NetBIOS Datagram Service", "Connectionless NetBIOS communication.", "Legacy Windows networking; internal use only, should not face the internet."],
  [139, "TCP", "NetBIOS Session Service", "Supports file/printer sharing (SMB) over NetBIOS.", "Historic target of worms; SMB relay attacks; should never be internet-exposed."],
  [143, "TCP", "IMAP", "Internet Message Access Protocol -- retrieves and manages email on the server.", "Cleartext credentials by default; use IMAPS (993) instead."],
  [161, "UDP", "SNMP", "Simple Network Management Protocol -- device monitoring and configuration.", "Default community strings (public/private) allow full device enumeration or reconfiguration."],
  [162, "UDP", "SNMP Trap", "Receives asynchronous notification (trap) messages from SNMP agents.", "Spoofed traps can be used to inject false monitoring data."],
  [177, "TCP/UDP", "XDMCP", "X Display Manager Control Protocol -- remote X11 login sessions.", "Unencrypted; exposes GUI login to the network."],
  [179, "TCP", "BGP", "Border Gateway Protocol -- exchanges routing information between autonomous systems on the internet.", "BGP hijacking/leaks can reroute or blackhole global traffic; sessions should use TCP-MD5 or TTL security."],
  [194, "TCP/UDP", "IRC", "Internet Relay Chat -- text-based real-time messaging.", "Historically used as a botnet C2 channel."],
  [201, "TCP/UDP", "AppleTalk", "AppleTalk Routing Maintenance Protocol.", "Legacy Apple networking; rarely seen today."],
  [264, "TCP/UDP", "BGMP", "Border Gateway Multicast Protocol.", "Rare; multicast routing infrastructure."],
  [318, "TCP/UDP", "PKIX-TSP", "Time Stamp Protocol used in PKI to prove data existed at a point in time.", "Used in digital signature/document timestamping infrastructure."],
  [381, "TCP/UDP", "HP Openview", "HP OpenView network management alarm manager.", "Legacy enterprise NMS; check for default credentials."],
  [389, "TCP/UDP", "LDAP", "Lightweight Directory Access Protocol -- directory services (users, groups, computers).", "Cleartext binds leak credentials; anonymous binds can enumerate the entire directory (esp. Active Directory)."],
  [411, "TCP", "Direct Connect Hub", "Peer discovery for the Direct Connect P2P file-sharing protocol.", "P2P file sharing risk; possible malware distribution vector."],
  [412, "TCP", "Direct Connect Client-Client", "Client-to-client transfer channel for Direct Connect.", "Same risks as the hub port -- unauthenticated file transfer."],
  [443, "TCP", "HTTPS", "HTTP over TLS/SSL -- encrypted web traffic.", "Weak/outdated TLS configs, expired certs, or vulnerable cipher suites remain common findings."],
  [444, "TCP", "SNPP", "Simple Network Paging Protocol.", "Legacy paging systems; rarely seen."],
  [445, "TCP", "SMB (Microsoft-DS)", "Server Message Block over TCP -- Windows file/printer sharing without NetBIOS.", "EternalBlue (MS17-010), ransomware propagation, and relay attacks; should never face the internet."],
  [464, "TCP/UDP", "Kerberos Change/Set Password", "Allows users to change their Kerberos password.", "Should be restricted and monitored for password-spray activity."],
  [465, "TCP", "SMTPS", "SMTP submission encrypted with implicit TLS.", "Properly configured, this is the secure alternative to cleartext SMTP submission."],
  [497, "TCP", "Retrospect", "Backup software client-server communication (Retrospect).", "Older versions had known authentication weaknesses."],
  [500, "UDP", "ISAKMP/IKE", "Internet Key Exchange -- negotiates IPsec VPN security associations.", "Aggressive mode PSK cracking; commonly scanned/fingerprinted for VPN gateway discovery."],
  [502, "TCP", "Modbus", "Industrial control protocol for PLCs and SCADA devices.", "No built-in authentication or encryption; a primary ICS/OT attack surface."],
  [512, "TCP", "Rexec", "Remote Execution Protocol -- runs a command on a remote host.", "Cleartext credentials; legacy Unix r-command, should be disabled."],
  [513, "TCP", "Rlogin", "Remote login protocol, cleartext, trust-based via .rhosts.", "Weak host-based trust model; superseded entirely by SSH."],
  [513, "UDP", "Who", "Displays who is logged into machines on the local network.", "Information disclosure of logged-in users."],
  [514, "TCP", "Shell (rsh)", "Remote Shell -- executes commands on a remote host without a password prompt.", "No encryption or strong authentication; classic lateral-movement target."],
  [514, "UDP", "Syslog", "Standard protocol for forwarding log messages.", "Unauthenticated by default; spoofed messages can pollute or hide log evidence."],
  [515, "TCP", "LPD", "Line Printer Daemon -- legacy Unix printing protocol.", "Historically exploited for buffer overflow / RCE in older daemons."],
  [520, "UDP", "RIP", "Routing Information Protocol -- distance-vector interior routing.", "No authentication in RIPv1; route poisoning/spoofing possible."],
  [521, "UDP", "RIPng", "RIP for IPv6.", "Same trust/authentication weaknesses as RIPv1/v2."],
  [523, "TCP/UDP", "IBM DB2", "IBM DB2 database connection port.", "Should never be directly internet-facing; brute-force/enumeration target."],
  [540, "TCP", "UUCP", "Unix-to-Unix Copy Protocol -- legacy file transfer/mail relay.", "Historic; essentially unused today."],
  [543, "TCP", "Klogin", "Kerberos-authenticated rlogin.", "Legacy; superseded by SSH with Kerberos/GSSAPI."],
  [544, "TCP", "Kshell", "Kerberos-authenticated remote shell.", "Legacy; superseded by SSH."],
  [546, "UDP", "DHCPv6 (client)", "DHCPv6 client listens here for server messages.", "Rogue DHCPv6 servers can redirect IPv6 clients (see mitm6-style attacks)."],
  [547, "UDP", "DHCPv6 (server)", "DHCPv6 server listens here for client requests.", "Should be tightly controlled to prevent rogue server injection."],
  [548, "TCP", "AFP", "Apple Filing Protocol -- macOS file sharing.", "Older AFP versions transmitted credentials weakly; prefer SMB3 today."],
  [554, "TCP/UDP", "RTSP", "Real Time Streaming Protocol -- controls media streaming sessions (IP cameras, DVRs).", "Frequently exposed IP camera streams with default/no credentials."],
  [563, "TCP", "NNTPS", "NNTP over TLS/SSL.", "Encrypted Usenet access; low risk when properly configured."],
  [587, "TCP", "SMTP Submission", "Authenticated mail submission port for MUAs (mail clients) with STARTTLS.", "Should require authentication and TLS; open relays here are heavily abused."],
  [591, "TCP", "FileMaker", "FileMaker Server web publishing port.", "Older versions had notable RCE and auth-bypass vulnerabilities."],
  [593, "TCP/UDP", "MSRPC over HTTP", "Microsoft RPC tunneled over HTTP.", "Used by Outlook Anywhere/Exchange; exposes internal RPC services externally if misconfigured."],
  [601, "TCP", "Reliable Syslog", "Syslog over reliable (TCP) transport.", "Same trust issues as UDP syslog unless combined with TLS (syslog-TLS, port 6514)."],
  [623, "UDP", "IPMI", "Intelligent Platform Management Interface -- out-of-band server management.", "Cipher zero authentication bypass, weak default credentials; a top target for full server compromise."],
  [625, "TCP", "OpenDirectory/DALS", "Apple Open Directory Proxy / DALS.", "macOS directory services; internal use."],
  [631, "TCP/UDP", "IPP / CUPS", "Internet Printing Protocol -- manages print jobs and printer discovery.", "CUPS remote code execution and info-disclosure CVEs; printers often overlooked in patching."],
  [636, "TCP", "LDAPS", "LDAP over TLS/SSL -- encrypted directory access.", "Preferred secure alternative to plaintext LDAP; verify certificate validation is enforced."],
  [639, "TCP/UDP", "MSDP", "Multicast Source Discovery Protocol.", "Used between multicast rendezvous points; internal routing infrastructure."],
  [646, "TCP", "LDP", "Label Distribution Protocol for MPLS.", "Service provider core network protocol; should never be customer-facing."],
  [647, "TCP", "DHCP Failover", "Synchronizes state between redundant DHCP servers.", "Internal infrastructure protocol; should be isolated from clients."],
  [666, "TCP", "Doom", "Original id Software Doom multiplayer port.", "Historical/novelty; occasionally repurposed by malware for its notoriety."],
  [691, "TCP", "MS Exchange Routing", "Microsoft Exchange link-state routing protocol.", "Legacy Exchange infrastructure; internal use only."],
  [750, "TCP/UDP", "Kerberos (legacy)", "Older Kerberos v4 port before standardizing on 88.", "Legacy; modern Kerberos uses port 88."],
  [873, "TCP", "Rsync", "Efficient file synchronization protocol.", "Anonymous/misconfigured rsync daemons can leak or allow overwrite of files."],
  [902, "TCP", "VMware Server", "VMware ESXi/Server management console access.", "Hypervisor compromise here can affect every hosted VM; must be tightly access-controlled."],
  [989, "TCP", "FTPS (data)", "FTP data channel secured with implicit TLS.", "Encrypted alternative to cleartext FTP-DATA."],
  [990, "TCP", "FTPS (control)", "FTP control channel secured with implicit TLS.", "Encrypted alternative to cleartext FTP control channel."],
  [993, "TCP", "IMAPS", "IMAP over TLS/SSL.", "Preferred secure alternative to plaintext IMAP (143)."],
  [995, "TCP", "POP3S", "POP3 over TLS/SSL.", "Preferred secure alternative to plaintext POP3 (110)."],
  [1025, "TCP", "NFS or MSRPC (Windows)", "Often used as a secondary MSRPC port on Windows, or NFS on some Unix systems.", "Frequently open by default on Windows; can expose internal RPC services."],
  [1080, "TCP", "SOCKS Proxy", "Generic circuit-level proxy protocol used to tunnel arbitrary TCP/UDP traffic.", "Open SOCKS proxies are abused to anonymize attack traffic or bypass egress controls."],
  [1099, "TCP", "Java RMI Registry", "Java Remote Method Invocation registry.", "Deserialization RCE vulnerabilities are common when RMI is exposed without hardening."],
  [1155, "TCP/UDP", "Network File Access", "Legacy NFA / OracleAS Discoverer.", "Legacy Oracle application server component."],
  [1194, "UDP", "OpenVPN", "Widely used open-source VPN tunnel protocol.", "Weak PSK/certs or outdated OpenSSL versions are the main risk vectors."],
  [1214, "TCP", "Kazaa", "Legacy P2P file-sharing protocol.", "Historical malware/adware distribution vector."],
  [1241, "TCP/UDP", "Nessus", "Legacy default port for the Nessus vulnerability scanner.", "Exposure could allow scan-result tampering or unauthorized scanning."],
  [1311, "TCP", "Dell OpenManage", "Dell server management web console.", "Default credentials and known RCE CVEs in various versions."],
  [1337, "TCP", "WASTE / Menandmice", "Historically associated with the WASTE encrypted P2P chat/file-sharing tool; also a popular 'leet' port for backdoors.", "Commonly chosen by malware authors for its symbolic 'leet' value; unusual traffic here warrants investigation."],
  [1352, "TCP", "Lotus Notes / Domino", "IBM/HCL Notes RPC communication.", "Numerous historical CVEs; often exposed on legacy enterprise mail deployments."],
  [1414, "TCP", "IBM MQSeries", "IBM MQ message queue listener port.", "Unauthenticated queue managers can allow message injection/interception."],
  [1417, "TCP", "Timbuktu", "Legacy remote-control software (Timbuktu Pro).", "Old remote access tool with known vulnerabilities; rarely seen today."],
  [1433, "TCP", "MS-SQL Server", "Microsoft SQL Server database engine.", "SQL Server brute-force, xp_cmdshell abuse for RCE, and weak sa account passwords are common findings."],
  [1434, "UDP", "MS-SQL Monitor", "SQL Server Browser service -- resolves named instances to dynamic ports.", "SQL Slammer worm exploited this service via a stack buffer overflow."],
  [1471, "TCP/UDP", "Csdmbase", "Legacy CSD database access.", "Rare legacy service."],
  [1512, "TCP/UDP", "WINS", "Windows Internet Name Service -- NetBIOS name resolution.", "Legacy internal name resolution; should not be internet-facing."],
  [1521, "TCP", "Oracle DB Listener", "Oracle database TNS listener -- brokers client connections to database instances.", "TNS poisoning, default accounts, and listener misconfig are classic Oracle pentest findings."],
  [1524, "TCP", "Ingreslock", "Historic backdoor port left by several worms (e.g. lion worm) providing a root shell.", "Presence of an open listener here is a strong indicator of prior compromise."],
  [1526, "TCP", "Oracle DB (alt)", "Alternate Oracle TNS listener port used in some multi-instance deployments.", "Same risk profile as the standard Oracle listener port."],
  [1589, "TCP/UDP", "Cisco VQP", "Cisco VLAN Query Protocol, used with VMPS.", "Legacy Cisco VLAN management protocol."],
  [1604, "TCP/UDP", "Citrix ICA", "Citrix Independent Computing Architecture -- legacy remote application delivery.", "Older ICA implementations had weak encryption; verify TLS is enforced."],
  [1701, "UDP", "L2TP", "Layer 2 Tunneling Protocol -- VPN tunneling, usually paired with IPsec for encryption.", "L2TP alone provides no encryption; must be combined with IPsec (L2TP/IPsec)."],
  [1723, "TCP", "PPTP", "Point-to-Point Tunneling Protocol -- legacy VPN protocol.", "MS-CHAPv2 authentication is cryptographically broken; PPTP should be retired in favor of modern VPNs."],
  [1755, "TCP/UDP", "MS Media Services", "Windows Media Services streaming control.", "Legacy streaming media infrastructure."],
  [1801, "TCP/UDP", "MSMQ", "Microsoft Message Queuing.", "Known deserialization and RCE CVEs (e.g. QueueJumper) when exposed."],
  [1812, "UDP", "RADIUS Authentication", "Remote Authentication Dial-In User Service -- centralized AAA for network access.", "Shared-secret brute-forcing and legacy MD5-based packet integrity are known weak points."],
  [1813, "UDP", "RADIUS Accounting", "Carries usage/accounting data for RADIUS sessions.", "Same shared-secret trust model risks as RADIUS authentication."],
  [1863, "TCP", "MSNP", "MSN Messenger Protocol.", "Legacy IM protocol; discontinued service."],
  [1900, "UDP", "SSDP / UPnP", "Simple Service Discovery Protocol -- discovers UPnP devices on a LAN.", "Major UDP amplification DDoS vector; UPnP can also allow unauthenticated port-forwarding changes on routers."],
  [1935, "TCP", "RTMP", "Real-Time Messaging Protocol -- legacy Flash-based media streaming.", "Deprecated alongside Flash; still used by some streaming ingest pipelines (e.g. OBS to media servers)."],
  [1985, "UDP", "HSRP", "Hot Standby Router Protocol -- Cisco first-hop router redundancy.", "Spoofed HSRP hello packets can hijack the virtual gateway IP (MITM)."],
  [2000, "TCP", "Cisco SCCP", "Skinny Client Control Protocol -- Cisco VoIP phone signaling.", "Unencrypted signaling can leak call metadata; SCCP has known DoS vulnerabilities."],
  [2002, "TCP", "Cisco ACS", "Cisco Secure Access Control Server management.", "Legacy AAA management interface; check for default credentials."],
  [2049, "TCP/UDP", "NFS", "Network File System -- Unix/Linux network file sharing.", "Weak export permissions (no_root_squash, world-exported shares) are a classic privilege-escalation path."],
  [2082, "TCP", "cPanel", "Default cPanel web hosting control panel port (unencrypted).", "Common brute-force/credential-stuffing target on shared hosting."],
  [2083, "TCP", "cPanel (SSL)", "Encrypted cPanel web hosting control panel port.", "Preferred over 2082; still a brute-force target."],
  [2086, "TCP", "WHM", "Web Host Manager -- cPanel's reseller/admin interface (unencrypted).", "Full-server compromise possible if credentials are weak."],
  [2087, "TCP", "WHM (SSL)", "Encrypted Web Host Manager interface.", "Preferred over 2086; still a high-value target for hosting compromise."],
  [2095, "TCP", "cPanel Webmail", "cPanel webmail interface (unencrypted).", "Credential-stuffing target; should redirect to 2096."],
  [2096, "TCP", "cPanel Webmail (SSL)", "Encrypted cPanel webmail interface.", "Preferred secure alternative to port 2095."],
  [2100, "TCP", "Oracle XDB FTP", "Oracle XML database FTP service.", "Legacy Oracle component; check for default credentials."],
  [2181, "TCP", "ZooKeeper", "Apache ZooKeeper client port -- distributed coordination service for Kafka, Hadoop, etc.", "Unauthenticated ZooKeeper instances allow full read/write of cluster configuration and can leak secrets."],
  [2222, "TCP", "SSH (alt) / DirectAdmin", "Common alternate SSH port; also default for the DirectAdmin control panel.", "Same brute-force exposure as standard SSH if used for shell access."],
  [2375, "TCP", "Docker (unencrypted)", "Docker Engine API without TLS.", "Unauthenticated access equals full host compromise -- allows launching privileged containers to escape to the host."],
  [2376, "TCP", "Docker (TLS)", "Docker Engine API with TLS client-certificate authentication.", "Properly configured, this is the secure alternative to port 2375; misissued certs remain a risk."],
  [2379, "TCP", "etcd client", "Client API for etcd, the distributed key-value store used by Kubernetes.", "Unauthenticated etcd exposes cluster secrets, service account tokens, and full config."],
  [2380, "TCP", "etcd peer", "Peer communication port between etcd cluster members.", "Should be isolated to the cluster network; peer traffic exposure risks cluster integrity."],
  [2401, "TCP", "CVS", "Concurrent Versions System -- legacy version control server.", "Cleartext protocol; largely superseded by Git/SVN over SSH."],
  [2483, "TCP/UDP", "Oracle DB (unencrypted)", "Oracle database listener without SSL.", "Same TNS risks as port 1521 without transport encryption."],
  [2484, "TCP/UDP", "Oracle DB (SSL)", "Oracle database listener with SSL.", "Preferred encrypted alternative to port 2483."],
  [2601, "TCP", "Zebra/Quagga (RIP)", "Routing daemon management console (Quagga/FRR suite).", "Cleartext console access to routing configuration if exposed."],
  [2604, "TCP", "Zebra/Quagga (OSPF)", "OSPF daemon management console.", "Same exposure risk as other Zebra/Quagga management ports."],
  [2701, "TCP", "SMS Xfer", "Systems Management Server data transfer.", "Legacy Microsoft SMS/SCCM component."],
  [2717, "TCP", "PN Requester", "Legacy Microsoft messaging component.", "Rarely encountered in modern environments."],
  [2967, "TCP", "Symantec AV", "Symantec Endpoint Protection management communication.", "Endpoint security infrastructure; compromise here can disable AV fleet-wide."],
  [3000, "TCP", "Node.js / dev servers", "Extremely common default port for Node.js, Grafana, and many web dev frameworks.", "Development servers left running in production often lack hardening and expose debug info."],
  [3020, "TCP", "CIFS", "Common Internet File System, an SMB dialect.", "Same risk profile as standard SMB (445)."],
  [3050, "TCP", "Firebird/InterBase DB", "Firebird and InterBase relational database default port.", "Weak default credentials and known RCE CVEs in older versions."],
  [3074, "TCP/UDP", "Xbox Live", "Microsoft Xbox Live gaming and voice service.", "Consumer gaming traffic; rarely a security concern outside DDoS 'booter' abuse."],
  [3128, "TCP", "Squid Proxy", "Default port for the Squid caching HTTP proxy.", "Open/misconfigured proxies enable anonymized attack traffic and internal network pivoting."],
  [3260, "TCP", "iSCSI", "Internet Small Computer Systems Interface -- block storage over IP.", "Unauthenticated iSCSI targets expose raw disk volumes to any client on the network."],
  [3268, "TCP", "MS Global Catalog", "Active Directory Global Catalog -- forest-wide directory search.", "Same LDAP-style enumeration risks as port 389, but forest-wide in scope."],
  [3269, "TCP", "MS Global Catalog (SSL)", "Encrypted Global Catalog access.", "Preferred secure alternative to port 3268."],
  [3283, "TCP/UDP", "Apple Remote Desktop", "Apple Remote Desktop management/reporting channel.", "Weak credentials allow full remote control of managed Macs."],
  [3306, "TCP", "MySQL / MariaDB", "MySQL/MariaDB relational database default port.", "Extremely common brute-force target; should never be directly internet-exposed."],
  [3389, "TCP", "RDP", "Remote Desktop Protocol -- Windows remote GUI access.", "One of the highest-value ransomware entry points; BlueKeep and brute-force campaigns are constant threats."],
  [3390, "TCP", "DSC / RDP (alt)", "Alternate RDP port used to reduce automated scanning noise.", "Same underlying protocol risk as 3389, security-by-obscurity only."],
  [3396, "TCP", "Novell NDPS", "Novell Distributed Print Services.", "Legacy Novell infrastructure; rarely seen today."],
  [3689, "TCP", "DAAP", "Digital Audio Access Protocol -- iTunes music sharing.", "Consumer media-sharing protocol; low security relevance."],
  [3690, "TCP", "SVN", "Apache Subversion version control server protocol.", "Anonymous read access can leak proprietary source code and secrets committed to history."],
  [3703, "TCP", "Adobe Marketing Cloud", "Adobe Experience/Marketing Cloud service communication.", "SaaS integration channel; check for outdated agent versions."],
  [3724, "TCP/UDP", "World of Warcraft", "Blizzard's WoW game client-server communication.", "Consumer gaming traffic; DDoS booter abuse is the main relevant risk."],
  [3784, "TCP/UDP", "BFD Control", "Bidirectional Forwarding Detection -- fast link-failure detection for routing protocols.", "Spoofed BFD packets can be used to force route flapping/DoS."],
  [3785, "UDP", "BFD Echo", "BFD echo function port.", "Same risk class as BFD control."],
  [4000, "TCP", "ICQ / Diablo II", "Legacy ICQ instant messaging; also used by Diablo II battle.net.", "Legacy consumer protocols; low modern relevance."],
  [4045, "TCP/UDP", "NFS Lock Manager", "Manages file locks for NFS.", "Historic buffer overflow CVEs (e.g. Solaris lockd); should be firewalled with NFS itself."],
  [4070, "TCP", "Spotify", "Legacy Spotify client-server protocol port.", "Consumer streaming traffic; low security relevance."],
  [4111, "TCP", "Xgrid", "Apple Xgrid distributed computing.", "Legacy macOS distributed-computing framework."],
  [4190, "TCP", "ManageSieve", "Protocol for remotely managing Sieve mail-filtering scripts.", "Weak auth allows filter tampering (e.g. silently forwarding/deleting mail)."],
  [4200, "TCP", "Dev servers (Angular, etc.)", "Common default port for Angular CLI and similar dev servers.", "Development servers should never be exposed to untrusted networks."],
  [4369, "TCP", "EPMD", "Erlang Port Mapper Daemon -- used by RabbitMQ, CouchDB, and other Erlang/OTP apps.", "Can leak node names and facilitate unauthorized Erlang distribution connections."],
  [4443, "TCP", "HTTPS (alt) / Pharos", "Common alternate HTTPS port used by admin panels and appliances.", "Same TLS configuration risks as standard 443."],
  [4444, "TCP", "Metasploit / krb524", "Default Metasploit Framework handler port for reverse shells; also legacy Kerberos 524.", "Extremely strong indicator of active exploitation when seen unexpectedly on outbound connections."],
  [4500, "UDP", "IPsec NAT-T", "IPsec NAT Traversal -- encapsulates ESP inside UDP for clients behind NAT.", "Same IKE/PSK cracking risks as port 500 apply to the encapsulated traffic."],
  [4664, "TCP", "Google Desktop", "Legacy Google Desktop Search local API.", "Discontinued product; historical relevance only."],
  [4672, "UDP", "eMule", "eDonkey/eMule P2P file-sharing protocol.", "P2P traffic often violates corporate policy and is a malware distribution vector."],
  [4899, "TCP", "Radmin", "Remote Administrator -- Windows remote control software.", "Extremely popular post-exploitation persistence tool; unexpected listeners are a strong compromise indicator."],
  [5000, "TCP", "UPnP / Flask / Synology", "Common default for UPnP control, Python Flask dev servers, and Synology DSM.", "Very frequently left open with weak/default credentials on consumer NAS devices."],
  [5001, "TCP", "Synology DSM (SSL)", "Encrypted Synology DiskStation Manager web interface.", "Preferred over port 5000; still a common ransomware target when exposed to the internet."],
  [5004, "TCP/UDP", "RTP", "Real-time Transport Protocol -- carries audio/video media streams (often paired with RTCP on 5005).", "Unencrypted media can be intercepted; use SRTP for confidentiality."],
  [5050, "TCP", "Yahoo Messenger", "Legacy Yahoo Messenger client-server protocol.", "Discontinued consumer IM service."],
  [5060, "TCP/UDP", "SIP", "Session Initiation Protocol -- VoIP call signaling.", "SIP scanning/brute-forcing for toll fraud (PBX hacking) is extremely common on exposed systems."],
  [5061, "TCP", "SIP-TLS", "SIP signaling encrypted with TLS.", "Preferred secure alternative to plaintext SIP."],
  [5222, "TCP", "XMPP (client)", "Extensible Messaging and Presence Protocol -- client-to-server chat/presence.", "Weak TLS enforcement can allow message interception/downgrade attacks."],
  [5223, "TCP", "XMPP (SSL)", "Legacy implicit-TLS XMPP client port.", "Older encrypted XMPP alternative."],
  [5228, "TCP", "Google Cloud Messaging", "Android/Google push-notification transport (FCM/GCM).", "Mobile push infrastructure; low direct exploitation surface for typical networks."],
  [5269, "TCP", "XMPP (server)", "Server-to-server XMPP federation.", "Misconfigured federation can allow message spoofing between domains."],
  [5353, "UDP", "mDNS", "Multicast DNS -- zero-configuration name resolution (Bonjour/Avahi).", "Information disclosure of device/service names; can be leveraged for local network reconnaissance."],
  [5355, "UDP", "LLMNR", "Link-Local Multicast Name Resolution -- Windows fallback name resolution.", "LLMNR poisoning (Responder) is one of the most common internal-network credential-capture techniques."],
  [5432, "TCP", "PostgreSQL", "PostgreSQL relational database default port.", "Weak pg_hba.conf rules or default credentials can expose the entire database to the network."],
  [5555, "TCP", "Android Debug Bridge", "ADB over TCP/IP -- Android device debugging.", "Unauthenticated ADB grants full shell access; actively scanned and exploited on exposed devices/emulators."],
  [5601, "TCP", "Kibana", "Web UI for visualizing and exploring Elasticsearch data.", "Unauthenticated Kibana instances expose all indexed data, including logs that may contain secrets."],
  [5631, "TCP", "pcAnywhere (data)", "Symantec pcAnywhere remote control data channel.", "Legacy remote-control tool with multiple critical historical CVEs."],
  [5632, "UDP", "pcAnywhere (status)", "pcAnywhere status/discovery channel.", "Same risk profile as the pcAnywhere data channel."],
  [5666, "TCP", "NRPE", "Nagios Remote Plugin Executor -- runs monitoring checks on remote hosts.", "Historically vulnerable to command injection if check arguments aren't sanitized."],
  [5672, "TCP", "AMQP", "Advanced Message Queuing Protocol -- used by RabbitMQ and other brokers.", "Unauthenticated brokers allow message interception, injection, and queue manipulation."],
  [5683, "UDP", "CoAP", "Constrained Application Protocol -- lightweight IoT device communication.", "Growing UDP amplification DDoS vector; many IoT stacks lack authentication."],
  [5900, "TCP", "VNC", "Virtual Network Computing -- remote desktop framebuffer sharing.", "Weak/no authentication is extremely common; internet-exposed VNC is a top target for opportunistic compromise."],
  [5901, "TCP", "VNC (display :1)", "VNC server for the second display/session.", "Same risk profile as the primary VNC port."],
  [5938, "TCP", "TeamViewer", "TeamViewer remote-access relay/direct connection port.", "Legitimate remote-support tool frequently abused by scammers and post-exploitation actors."],
  [5984, "TCP", "CouchDB", "Apache CouchDB HTTP API.", "Historic default-open admin party mode allowed unauthenticated full database control (CVE-2017-12635/36)."],
  [5985, "TCP", "WinRM (HTTP)", "Windows Remote Management over HTTP -- PowerShell remoting.", "Cleartext transport by default; common lateral-movement channel using stolen credentials."],
  [5986, "TCP", "WinRM (HTTPS)", "Windows Remote Management over HTTPS.", "Preferred encrypted alternative to 5985; still a lateral-movement target with valid credentials."],
  [6000, "TCP", "X11", "X Window System display server protocol.", "Unauthenticated X11 servers (xhost +) allow full desktop control, keystroke logging, and screen capture."],
  [6379, "TCP", "Redis", "In-memory key-value data store, widely used for caching and queues.", "Historically shipped with no authentication by default; unauthenticated Redis enables RCE via module loading or cron/SSH-key writes."],
  [6443, "TCP", "Kubernetes API", "Kubernetes API server -- the control plane's primary management interface.", "Misconfigured RBAC or anonymous access grants full cluster control, a critical container-security finding."],
  [6514, "TCP", "Syslog-TLS", "Syslog transported over TLS for confidentiality/integrity.", "Preferred secure alternative to plaintext syslog."],
  [6566, "TCP", "SANE", "Scanner Access Now Easy -- network scanner sharing daemon.", "Unauthenticated access can allow triggering scans or accessing scanned documents."],
  [6588, "TCP", "AnalogX Proxy", "Legacy lightweight HTTP/SOCKS proxy software.", "Older proxy software with limited access controls by default."],
  [6600, "TCP", "MPD", "Music Player Daemon control protocol.", "Unauthenticated MPD instances allow arbitrary playback/library control."],
  [6660, "TCP", "IRC (alt range start)", "Alternate IRC server port range (6660-6669).", "Historic malware C2 channel; unusual IRC traffic warrants investigation."],
  [6666, "TCP", "IRC (alt) / malware", "Commonly used alternate IRC port, and a very common malware/backdoor default.", "Frequently seen as a C2 callback port in botnet malware families."],
  [6667, "TCP", "IRC", "Standard Internet Relay Chat port.", "Historic botnet C2 channel; also legitimate chat traffic -- context matters."],
  [6697, "TCP", "IRC-TLS", "IRC encrypted with TLS.", "Preferred secure alternative to plaintext IRC."],
  [6881, "TCP/UDP", "BitTorrent", "Peer-to-peer file distribution protocol (part of the 6881-6889 range).", "Bandwidth/legal risk from unauthorized file sharing; also a malware distribution vector."],
  [6969, "TCP/UDP", "BitTorrent Tracker", "Coordinates peers for BitTorrent swarms.", "Same P2P policy/malware risks as BitTorrent data ports."],
  [7000, "TCP", "Cassandra (inter-node)", "Apache Cassandra internal node-to-node communication.", "Should be isolated to the cluster network; exposure risks data-plane compromise."],
  [7001, "TCP", "Cassandra (SSL) / WebLogic", "Cassandra encrypted inter-node port; also a common WebLogic admin console port.", "WebLogic admin consoles are frequently targeted for deserialization RCEs."],
  [7070, "TCP", "RealServer / ARCP", "RealNetworks streaming server control port.", "Legacy streaming infrastructure; rarely seen today."],
  [7077, "TCP", "Apache Spark", "Spark standalone cluster manager communication.", "Unauthenticated Spark clusters allow arbitrary job submission -- effective RCE on the cluster."],
  [7199, "TCP", "Cassandra JMX", "Java Management Extensions monitoring port for Cassandra.", "Unauthenticated JMX is a well-known RCE vector via MBean deserialization."],
  [7443, "TCP", "Cisco/VMware alt HTTPS", "Common alternate HTTPS port for appliance management UIs.", "Same TLS/credential risks as standard HTTPS admin interfaces."],
  [7474, "TCP", "Neo4j (HTTP)", "Neo4j graph database web interface and REST API.", "Default credentials (neo4j/neo4j) were a widespread historical finding; also Cypher injection risks."],
  [7473, "TCP", "Neo4j (HTTPS)", "Encrypted Neo4j web interface.", "Preferred secure alternative to the plaintext Neo4j HTTP port."],
  [7687, "TCP", "Neo4j Bolt", "Neo4j's binary protocol for driver connections.", "Same authentication risks as the HTTP interface, but for the native driver protocol."],
  [7777, "TCP/UDP", "Oracle iAS / game servers", "Used by Oracle Application Server clustering and many game server platforms.", "Context-dependent; verify service identity before assuming risk level."],
  [8000, "TCP", "HTTP-Alt / dev servers", "Extremely common alternate HTTP port for development servers and admin panels.", "Frequently hosts unhardened debug/dev builds directly reachable from the internet."],
  [8008, "TCP", "HTTP-Alt", "Alternate HTTP port used by various application servers and IoT devices.", "Same general risks as other alternate HTTP ports -- verify what's actually listening."],
  [8009, "TCP", "AJP13", "Apache JServ Protocol -- binary protocol between Apache HTTPD and Tomcat.", "Ghostcat (CVE-2020-1938) allowed file read/inclusion via exposed AJP connectors."],
  [8020, "TCP", "Hadoop NameNode", "HDFS NameNode RPC port for metadata operations.", "Unauthenticated Hadoop clusters allow full filesystem read/write/delete."],
  [8021, "TCP", "FTP-Proxy / Asterisk", "Common alternate FTP proxy port; also used by Asterisk manager in some configs.", "Verify actual service before assessing risk -- port is heavily reused."],
  [8025, "TCP", "SMTP (alt) / MailCatcher", "Alternate SMTP port used by dev mail-catching tools like MailHog/MailCatcher.", "Dev tooling; should never be reachable outside the local development environment."],
  [8069, "TCP", "Odoo", "Odoo ERP/CRM web application default port.", "Default admin credentials and known XML-RPC RCE issues in older versions."],
  [8080, "TCP", "HTTP-Alt / Proxy", "Extremely common alternate HTTP port -- used by Tomcat, Jenkins, proxies, and countless apps.", "One of the most heavily scanned ports on the internet; often hosts unauthenticated admin consoles."],
  [8081, "TCP", "HTTP-Alt", "Another very common alternate HTTP port, often a secondary app or reverse-proxy target.", "Same exposure risk class as 8080; check for exposed admin/debug endpoints."],
  [8086, "TCP", "InfluxDB", "InfluxDB time-series database HTTP API.", "Historically allowed unauthenticated read/write access to all stored metrics by default."],
  [8087, "TCP", "Riak", "Riak distributed NoSQL database HTTP API.", "Unauthenticated access allows full data-store read/write."],
  [8089, "TCP", "Splunk Management", "Splunk's management/REST API port.", "Default credentials historically widespread; grants access to indexed logs (often containing secrets)."],
  [8091, "TCP", "Couchbase", "Couchbase Server administration console.", "Default/no authentication exposes the entire NoSQL cluster."],
  [8095, "TCP", "TFS / Riak Search", "Various application-specific web services.", "Verify actual service; commonly reused port number."],
  [8096, "TCP", "Emby / Jellyfin", "Media server web interface (Emby/Jellyfin).", "Media servers are frequently exposed with weak credentials for remote access convenience."],
  [8140, "TCP", "Puppet", "Puppet master certificate/catalog service.", "Compromise here can push malicious configuration to every managed node (\"config management as C2\")."],
  [8161, "TCP", "ActiveMQ Web Console", "Apache ActiveMQ web management console.", "Default admin/admin credentials and known RCE CVEs (CVE-2023-46604) are frequent findings."],
  [8180, "TCP", "Tomcat (alt)", "Alternate Apache Tomcat HTTP port.", "Same risks as 8080 for Tomcat -- default manager app credentials enable WAR-upload RCE."],
  [8200, "TCP", "GoToMyPC / Vault", "Legacy GoToMyPC remote access; also common for HashiCorp Vault.", "Vault exposure risks secrets-management compromise if not properly sealed/authenticated."],
  [8222, "TCP", "VMware Server console", "VMware Server management console (legacy).", "Legacy hypervisor management; superseded by vCenter/ESXi ports."],
  [8291, "TCP", "MikroTik Winbox", "MikroTik RouterOS Winbox configuration protocol.", "Multiple critical RCE/credential-disclosure CVEs (CVE-2018-14847) actively exploited in botnets."],
  [8332, "TCP", "Bitcoin RPC", "Bitcoin Core JSON-RPC interface.", "Unauthenticated/weakly authenticated RPC exposes wallet control -- direct financial risk."],
  [8333, "TCP", "Bitcoin P2P", "Bitcoin peer-to-peer network protocol.", "Normal blockchain P2P traffic; DoS and eclipse-attack considerations for node operators."],
  [8443, "TCP", "HTTPS-Alt", "Extremely common alternate HTTPS port for admin consoles and application servers.", "Same TLS/config risks as 443; frequently fronts management interfaces (vCenter, Jenkins, etc.)."],
  [8500, "TCP", "Consul", "HashiCorp Consul HTTP API and UI.", "Unauthenticated Consul exposes service catalog, health checks, and can allow KV store tampering."],
  [8530, "TCP", "WSUS (HTTP)", "Windows Server Update Services client communication.", "Unsigned/unencrypted WSUS traffic historically allowed malicious update injection (WSUXploit)."],
  [8531, "TCP", "WSUS (HTTPS)", "Encrypted WSUS client communication.", "Preferred secure alternative to plaintext WSUS."],
  [8545, "TCP", "Ethereum JSON-RPC", "Ethereum node JSON-RPC interface (geth, etc.).", "Unauthenticated RPC can expose wallet operations and node control -- direct financial risk."],
  [8600, "TCP/UDP", "Consul DNS", "Consul's built-in DNS interface for service discovery.", "Information disclosure of internal service topology if exposed externally."],
  [8686, "TCP", "JMX (generic)", "Generic Java Management Extensions RMI connector port.", "Unauthenticated JMX is a reliable RCE vector across many Java applications."],
  [8834, "TCP", "Nessus", "Tenable Nessus vulnerability scanner web interface.", "Compromise exposes scan results (a roadmap of every vulnerability in the environment)."],
  [8880, "TCP", "IBM WebSphere Admin", "IBM WebSphere administrative console (alt).", "Legacy enterprise Java app server; default credentials are a common finding."],
  [8888, "TCP", "HTTP-Alt / Jupyter", "Common alternate HTTP port, notably the Jupyter Notebook default.", "Jupyter without a token/password grants arbitrary code execution via notebook cells."],
  [9000, "TCP", "PHP-FPM / SonarQube / Portainer", "Reused across many stacks: PHP-FPM FastCGI, SonarQube, Portainer, and more.", "PHP-FPM exposed directly to the internet (bypassing the web server) allows arbitrary FastCGI requests."],
  [9001, "TCP", "Tor ORPort / Supervisor", "Tor relay OR port; also the Supervisor process-control web UI.", "Context-dependent; Supervisor without auth allows arbitrary process control."],
  [9042, "TCP", "Cassandra (CQL)", "Cassandra Query Language native client port.", "Unauthenticated access allows full read/write of cluster data."],
  [9092, "TCP", "Kafka", "Apache Kafka broker client port.", "Unauthenticated brokers allow topic read/write/delete -- data integrity and confidentiality risk."],
  [9100, "TCP", "JetDirect / Raw Printing", "HP JetDirect raw TCP printing (also used by many other printer brands).", "PostScript/PJL injection can cause DoS, firmware tampering, or document/credential disclosure (PRET tool)."],
  [9160, "TCP", "Cassandra (Thrift)", "Legacy Cassandra Thrift RPC client port.", "Same unauthenticated-access risk as the CQL native port."],
  [9200, "TCP", "Elasticsearch (HTTP)", "Elasticsearch REST API for indexing and querying data.", "Long history of unauthenticated instances leaking massive datasets; also scripting-engine RCE CVEs."],
  [9300, "TCP", "Elasticsearch (transport)", "Elasticsearch inter-node cluster communication.", "Should never be exposed outside the cluster network; historic deserialization RCEs (CVE-2015-1427)."],
  [9418, "TCP", "Git", "Git's native, unauthenticated transfer protocol.", "No authentication or encryption; anonymous read access to repository contents."],
  [9999, "TCP", "Common admin/backdoor", "Frequently reused for admin panels, ODBC, and unfortunately also common in malware.", "Unusual/unexpected listeners here warrant closer investigation."],
  [10000, "TCP", "Webmin / BackupExec", "Webmin server administration web UI; also Veritas BackupExec.", "Historic Webmin RCE (CVE-2019-15107) via password-reset backdoor; verify patch level."],
  [10050, "TCP", "Zabbix Agent", "Zabbix monitoring agent listener.", "Weak agent configuration can allow arbitrary command execution via user parameters."],
  [10051, "TCP", "Zabbix Server", "Zabbix server trapper communication port.", "Unauthenticated trapper items can allow data injection into monitoring."],
  [10250, "TCP", "Kubelet API", "Kubernetes node agent (kubelet) API.", "Anonymous/unauthenticated kubelet access allows arbitrary pod exec -- full node compromise."],
  [10255, "TCP", "Kubelet (read-only, deprecated)", "Legacy unauthenticated read-only kubelet API.", "Even read-only access leaks secrets/env vars from every pod on the node; deprecated for this reason."],
  [11211, "TCP/UDP", "Memcached", "Distributed memory object caching system.", "No authentication by default; both a data-leak vector and one of the largest UDP amplification DDoS multipliers ever recorded."],
  [11214, "TCP", "Sybase/SQL Anywhere", "SQL Anywhere database engine port.", "Legacy embedded database; check for default credentials."],
  [12345, "TCP", "NetBus (malware)", "Classic Windows backdoor trojan (NetBus) default port.", "Strong historical indicator of compromise if seen listening unexpectedly."],
  [13720, "TCP", "NetBackup", "Veritas NetBackup client-server communication.", "Backup infrastructure compromise can enable data theft or destruction of all backed-up data."],
  [15672, "TCP", "RabbitMQ Management", "RabbitMQ web-based management UI and HTTP API.", "Default guest/guest credentials historically allowed full broker control from localhost-only, but misconfig can expose it externally."],
  [16379, "TCP", "Redis Cluster (bus)", "Redis Cluster bus port for inter-node gossip (offset +10000 from client port).", "Same unauthenticated-access risk profile as standard Redis, cluster-wide."],
  [16992, "TCP", "Intel AMT (HTTP)", "Intel Active Management Technology out-of-band web interface.", "Critical AMT authentication-bypass CVEs (INTEL-SA-00075) allow full remote hardware control below the OS."],
  [16993, "TCP", "Intel AMT (HTTPS)", "Encrypted Intel AMT web interface.", "Same critical firmware-level compromise risk as the unencrypted AMT port."],
  [17500, "TCP/UDP", "Dropbox LAN Sync", "Dropbox's local network sync discovery protocol.", "Information disclosure of Dropbox account/device metadata on the local network."],
  [18080, "TCP", "Monero P2P (alt)", "Common alternate port for Monero and other cryptocurrency node P2P traffic.", "Unexpected mining/coin traffic can indicate cryptojacking malware on compromised hosts."],
  [19132, "UDP", "Minecraft Bedrock", "Minecraft Bedrock Edition (Raknet) server port.", "Consumer gaming traffic; DDoS booter abuse is the main relevant risk."],
  [20000, "TCP", "DNP3 / Usermin", "Distributed Network Protocol 3 (SCADA); also the Usermin web UI.", "DNP3 has no built-in authentication in its base spec -- a core ICS/OT attack surface."],
  [22222, "TCP", "EasyEngine / DirectAdmin (alt)", "Alternate SSH/control-panel port used to reduce automated scan noise.", "Same underlying service risk as the standard port, security-by-obscurity only."],
  [23023, "TCP", "Malware C2 (generic)", "No standard service; occasionally observed as a custom malware callback port.", "Unexpected listeners here should be treated as a potential indicator of compromise."],
  [25565, "TCP", "Minecraft (Java)", "Minecraft Java Edition default server port.", "Older server versions had RCE plugins/exploits; DDoS booter abuse is common against public servers."],
  [27015, "TCP/UDP", "Source Engine (Steam)", "Valve Source engine game server and Steam client port.", "Consumer gaming traffic; historic Source engine RCE vulnerabilities exist in some titles."],
  [27017, "TCP", "MongoDB", "MongoDB default client connection port.", "Historically shipped with no authentication by default; a leading cause of large-scale public database leaks and ransom-note wipes."],
  [27018, "TCP", "MongoDB (shard)", "MongoDB shard server port in a sharded cluster.", "Same unauthenticated-access risk as the standard MongoDB port."],
  [27019, "TCP", "MongoDB (config server)", "MongoDB config server port for sharded cluster metadata.", "Compromise here can affect routing/metadata for an entire sharded cluster."],
  [28015, "TCP/UDP", "Rust (game)", "Rust game server default port.", "Consumer gaming traffic; DDoS booter abuse against public servers is common."],
  [28017, "TCP", "MongoDB (HTTP status)", "Legacy MongoDB HTTP status/diagnostic interface.", "Deprecated but when present exposes server statistics without authentication."],
  [31337, "TCP", "Back Orifice (malware)", "Classic Windows backdoor trojan (Back Orifice), the numeral spelling of 'eleet'.", "Extremely strong historical indicator of compromise if seen listening unexpectedly."],
  [33060, "TCP", "MySQL X Protocol", "MySQL's newer document-store/X DevAPI protocol port.", "Same credential/exposure risks as classic MySQL, for the newer protocol."],
  [37777, "TCP", "Dahua DVR", "Dahua/many white-label DVR and IP camera proprietary protocol.", "Widely exploited by IoT botnets (Mirai variants) via default credentials and firmware RCEs."],
  [44818, "TCP/UDP", "EtherNet/IP", "Industrial automation protocol (CIP over Ethernet) used by Allen-Bradley/Rockwell PLCs.", "No built-in authentication; direct PLC read/write access if exposed -- critical OT risk."],
  [47808, "TCP/UDP", "BACnet", "Building Automation and Control Networking protocol -- HVAC, access control, lighting.", "Unauthenticated by design; exposed BACnet devices allow building-system manipulation."],
  [49152, "TCP", "Windows RPC (dynamic)", "Start of the modern Windows ephemeral RPC port range (49152-65535).", "Dynamic RPC endpoints here back many Windows services; firewall the whole range from untrusted networks."],
  [50000, "TCP", "SAP / DB2", "Common SAP application server port; also IBM DB2 in some configs.", "ERP systems are high-value targets; verify authentication and patch level."],
  [50070, "TCP", "Hadoop NameNode (Web UI)", "HDFS NameNode web UI for cluster status and browsing.", "Unauthenticated web UI allows browsing (and sometimes downloading) the entire HDFS filesystem."],
  [54321, "TCP", "Check Point FireWall-1", "Check Point FireWall-1 management/topology port.", "Firewall management-plane exposure is a critical finding -- can allow rule tampering."],
  [61616, "TCP", "ActiveMQ (OpenWire)", "Apache ActiveMQ's native OpenWire protocol port.", "OpenWire deserialization RCE (CVE-2023-46604) is actively exploited in the wild; patch immediately if exposed."],
  [1027, "TCP", "MSRPC (dynamic)", "Commonly allocated Windows dynamic RPC endpoint.", "Backs many built-in Windows services; unexpected external exposure aids service enumeration."],
  [1234, "TCP/UDP", "VLC HTTP Interface", "VLC media player's built-in HTTP remote-control interface.", "No authentication by default in older versions; allows remote playback/control."],
  [1494, "TCP", "Citrix ICA", "Independent Computing Architecture -- legacy Citrix published-application protocol.", "Older ICA sessions may lack strong encryption; verify Secure Gateway/TLS is enforced."],
  [1720, "TCP", "H.323", "ITU-T call-signaling protocol for VoIP and videoconferencing.", "Complex protocol with a history of parser vulnerabilities in gateways/gatekeepers."],
  [2121, "TCP", "FTP (alt/proxy)", "Common alternate FTP port used by proxies and some FTP daemons (e.g. ProFTPD default alt).", "Same cleartext-credential risk as standard FTP if unencrypted."],
  [2323, "TCP", "Telnet (alt)", "Alternate Telnet port, notably the default target of the original Mirai IoT botnet scanner.", "Actively scanned by IoT botnets for default credential brute-forcing."],
  [2404, "TCP", "IEC 60870-5-104", "SCADA protocol for power-grid telecontrol (electric utility automation).", "No built-in authentication or encryption in the base standard; critical infrastructure exposure risk."],
  [2598, "TCP", "Citrix Session Reliability", "Maintains Citrix ICA sessions across network interruptions.", "Same session-hijacking considerations as the primary ICA channel."],
  [2638, "TCP", "Sybase SQL Anywhere", "Sybase/SAP SQL Anywhere database default port.", "Default credentials and unpatched instances are common in embedded/legacy deployments."],
  [2809, "TCP", "CORBA / IBM WebSphere", "CORBA naming service, also used by IBM WebSphere Application Server.", "Unauthenticated CORBA naming lookups can expose internal object references."],
  [3221, "TCP", "Juniper XNM (cleartext)", "Juniper Networks XML management protocol, unencrypted.", "Cleartext device configuration channel; use NETCONF over SSH instead."],
  [3300, "TCP", "Ceph Monitor (msgr2)", "Ceph distributed storage cluster monitor daemon (msgr2 protocol).", "Should be isolated to the storage cluster network; exposure risks cluster-wide compromise."],
  [3310, "TCP", "ClamAV (clamd)", "ClamAV antivirus daemon's network scanning interface.", "Unauthenticated clamd instances can be abused to scan/probe arbitrary files if reachable."],
  [3333, "TCP", "Generic dev / mining pool", "Frequently reused for development servers, database GUIs, and cryptocurrency mining pool stratum ports.", "Unexpected outbound connections here can indicate cryptojacking malware."],
  [3478, "UDP", "STUN/TURN", "Session Traversal Utilities for NAT / Traversal Using Relays around NAT -- used by WebRTC and VoIP for NAT traversal.", "Open TURN relays can be abused to proxy/anonymize traffic if not access-controlled."],
  [4040, "TCP", "Apache Spark Web UI", "Web UI for monitoring running Spark applications and jobs.", "Can leak application configuration, environment variables, and sometimes credentials if exposed."],
  [4321, "TCP", "RWhois", "Referral Whois -- distributed extension of the WHOIS protocol.", "Information disclosure of registration data similar to standard WHOIS."],
  [4333, "TCP", "mSQL", "Mini SQL lightweight database engine default port.", "Legacy database with a history of authentication-bypass CVEs."],
  [5190, "TCP", "AIM/ICQ (OSCAR)", "AOL Instant Messenger / ICQ's OSCAR protocol.", "Legacy consumer IM protocol; discontinued service."],
  [5349, "TCP", "STUN/TURN over TLS", "Encrypted STUN/TURN NAT-traversal signaling.", "Preferred secure alternative to plaintext STUN/TURN on port 3478."],
  [5351, "UDP", "NAT-PMP", "NAT Port Mapping Protocol -- lets devices behind NAT request port forwards automatically.", "Similar unauthenticated port-forwarding risk profile to UPnP."],
  [5357, "TCP", "WSDAPI", "Web Services for Devices API -- Windows network device discovery.", "Information disclosure of device metadata; part of the SSDP/WS-Discovery ecosystem."],
  [5500, "TCP", "VNC (HTTP listen)", "VNC's reverse-connection listener, or a Java-applet VNC viewer over HTTP.", "Same authentication weaknesses as standard VNC apply."],
  [5800, "TCP", "VNC over HTTP (Java viewer)", "Serves a Java VNC viewer applet so clients can connect via a browser.", "Adds a web attack surface on top of standard VNC authentication risks."],
  [6002, "TCP", "X11 (display :2)", "X Window System server for the third local display.", "Same unauthenticated-access risk as the base X11 port (6000)."],
  [6050, "TCP", "Arcserve Backup", "CA/Arcserve backup agent communication port.", "Backup infrastructure compromise can enable data theft or destruction."],
  [6060, "TCP", "X11 (alt)", "Alternate X Window System display port used by some configurations.", "Same risk profile as standard X11."],
  [6112, "TCP/UDP", "Battle.net / dtspcd", "Blizzard Battle.net matchmaking; also the legacy CDE subprocess control daemon.", "dtspcd had critical historical RCE CVEs on Unix systems (CVE-2001-0803)."],
  [6129, "TCP", "DameWare Mini Remote Control", "DameWare remote administration agent port.", "Historic authentication-bypass CVE (CVE-2019-9202-class issues); popular lateral-movement target."],
  [6346, "TCP/UDP", "Gnutella", "Peer-to-peer file-sharing network protocol.", "P2P policy violations and malware distribution vector, similar to BitTorrent."],
  [6347, "TCP/UDP", "Gnutella2", "Second-generation Gnutella P2P protocol.", "Same risk profile as the original Gnutella network."],
  [6400, "TCP", "CVSup", "Software/file distribution and mirroring protocol (historically used by FreeBSD ports).", "Legacy protocol; largely superseded by rsync/git-based mirroring."],
  [6547, "TCP", "APC PowerChute", "APC UPS PowerChute Network Shutdown management.", "Compromise can trigger unauthorized shutdown of protected infrastructure."],
  [6699, "TCP", "Napster", "Legacy Napster P2P music-sharing protocol.", "Historical significance only; service long discontinued."],
  [7100, "TCP", "X Font Server (xfs)", "Serves fonts to X11 clients over the network.", "Historic buffer overflow CVEs in older xfs implementations."],
  [8065, "TCP", "Mattermost", "Mattermost team-chat application default web port.", "Self-hosted chat platform; verify authentication and TLS termination are properly configured."],
  [8082, "TCP", "HTTP-Alt", "Generic alternate HTTP port reused by many applications and appliances.", "Verify the actual service; frequently fronts unauthenticated admin panels."],
  [8118, "TCP", "Privoxy", "Privacy-enhancing non-caching HTTP proxy with filtering.", "Misconfigured proxy ACLs can turn it into an open relay for anonymized abuse."],
  [8123, "TCP", "Home Assistant", "Popular open-source home automation platform's web interface.", "Exposes control over connected smart-home devices; weak auth enables physical-world impact."],
  [8649, "TCP/UDP", "Ganglia", "Distributed system monitoring tool (gmond/gmetad) default port.", "Historically unauthenticated XML data feed can leak detailed cluster performance/topology data."],
  [8983, "TCP", "Apache Solr", "Solr search platform's admin UI and API.", "Unauthenticated Solr instances have known RCE via VelocityResponseWriter and config API abuse."],
  [9050, "TCP", "Tor SOCKS Proxy", "Local SOCKS5 proxy endpoint for routing traffic through the Tor network.", "Should only be bound to localhost; exposing it network-wide lets others anonymize traffic through your node."],
  [9051, "TCP", "Tor Control Port", "Administrative control port for a Tor client/relay, used by tools like Nyx.", "Unauthenticated or weakly authenticated control ports allow full control of the Tor process."],
  [9060, "TCP", "IBM WebSphere Admin", "WebSphere Application Server administrative console (unencrypted).", "Legacy Java EE admin interface; default credentials are a common finding."],
  [9080, "TCP", "IBM WebSphere HTTP", "WebSphere Application Server default HTTP transport port.", "Same general Java EE application risks as other WebSphere ports."],
  [9090, "TCP", "HTTP-Alt / Openfire Admin", "Common alternate HTTP port; default Openfire XMPP server admin console.", "Admin consoles here are frequently left with default credentials."],
  [9091, "TCP", "Transmission RPC", "Transmission BitTorrent client's remote-control web API.", "Weak/no authentication allows remote control of downloads, including malicious torrents."],
  [9389, "TCP", "AD Web Services", "Active Directory Web Services -- used by PowerShell AD cmdlets and AD Administrative Center.", "Exposes directory query capability; should remain internal to the domain network."],
  [9443, "TCP", "HTTPS-Alt (vCenter/Portainer)", "Common alternate HTTPS port for vCenter, Portainer, and other management consoles.", "Same TLS/credential risks as other admin-console HTTPS ports."],
  [9800, "TCP", "WebDAV Source", "WebDAV source-control integration port used by some CMS/authoring tools.", "Weak WebDAV ACLs can allow unauthorized content modification."],
  [9993, "TCP/UDP", "ZeroTier", "ZeroTier SDN/virtual-network client communication.", "Compromise of the ZeroTier controller/network can expose the entire virtual LAN."],
  [9997, "TCP", "Splunk Forwarder", "Receives data from Splunk universal/heavy forwarders on indexers.", "Unauthenticated forwarder input can allow log injection or unauthorized data ingestion."],
  [10001, "TCP/UDP", "Ubiquiti Device Discovery", "Ubiquiti's proprietary device discovery protocol.", "Information disclosure of device model/firmware; part of several UBNT CVEs."],
  [10161, "TCP", "SNMP over TLS (agent)", "Encrypted SNMP agent transport per RFC 6353.", "Preferred secure alternative to plaintext SNMP; still requires strong auth credentials."],
  [10162, "TCP", "SNMP-Trap over TLS", "Encrypted SNMP trap transport per RFC 6353.", "Preferred secure alternative to plaintext SNMP traps."],
  [13782, "TCP", "NetBackup (alt)", "Veritas NetBackup client-daemon communication (alternate).", "Same backup-infrastructure compromise risk as port 13720."],
  [13783, "TCP", "NetBackup (alt2)", "Veritas NetBackup volume manager communication.", "Same backup-infrastructure compromise risk as other NetBackup ports."],
  [18081, "TCP", "Monero Daemon RPC", "Monero (XMR) full-node JSON-RPC interface.", "Unauthenticated RPC can expose node control and, on wallet RPC, funds."],
  [18082, "TCP", "Monero Wallet RPC", "Monero wallet daemon's JSON-RPC interface.", "Direct financial risk if exposed without strong authentication."],
  [19999, "TCP", "Netdata", "Real-time system performance monitoring dashboard.", "Historically exposed detailed system/process metrics without authentication by default."],
  [20048, "TCP/UDP", "NFS Mountd", "NFS mount protocol -- handles initial mount requests before NFS traffic on port 2049.", "Weak export ACLs here mirror the same risk as the main NFS service."],
  [24444, "TCP", "NoMachine NX", "NoMachine remote desktop protocol port.", "Historic authentication-bypass and privilege-escalation CVEs; keep patched and firewalled."],
  [24800, "TCP", "Synergy", "Software KVM -- shares one keyboard/mouse across multiple computers over the network.", "Unencrypted versions transmit every keystroke (including passwords) in cleartext."],
  [26000, "TCP/UDP", "Quake", "id Software Quake game server default port.", "Consumer gaming traffic; DDoS booter abuse against public servers is common."],
  [27000, "TCP", "FlexLM License Manager", "FlexNet/FlexLM software license server default port.", "Historic buffer overflow CVEs; license servers are often unpatched for years."],
  [27374, "TCP", "SubSeven (malware)", "Classic Windows backdoor trojan (SubSeven) default port.", "Strong historical indicator of compromise if seen listening unexpectedly."],
  [30718, "UDP", "Lantronix Discovery", "Discovery protocol for Lantronix device servers.", "Information disclosure of embedded device presence/configuration."],
  [31335, "UDP", "Trin00 (malware)", "Classic DDoS agent/handler communication port for the Trin00 botnet tool.", "Strong historical indicator of compromise if seen in unexpected traffic."],
  [32400, "TCP", "Plex Media Server", "Plex's web management and streaming interface.", "Internet-exposed servers have had SSRF and RCE CVEs; keep patched and behind authentication."],
  [32764, "TCP", "Router backdoor (Sercomm)", "Undocumented backdoor found in several Sercomm-based consumer router/modem firmwares.", "Confirmed unauthenticated remote root-shell backdoor; a critical finding if present."],
  [33389, "TCP", "RDP (alt)", "Alternate RDP port used to reduce automated scan noise.", "Same underlying protocol risk as standard RDP (3389)."],
  [34567, "TCP", "Dahua DVR (alt)", "Alternate proprietary protocol port used by Dahua and rebadged DVR/NVR devices.", "Same IoT-botnet exploitation risk profile as port 37777."],
  [47001, "TCP", "WinRM Redirector", "Windows Remote Management HTTP redirect listener.", "Part of the WinRM lateral-movement surface alongside 5985/5986."],
  [49664, "TCP", "Windows RPC (dynamic, example)", "Representative port from the modern Windows ephemeral RPC range.", "Backs arbitrary RPC-based services; the entire 49152-65535 range should be firewalled externally."],
  [50030, "TCP", "Hadoop JobTracker (Web UI)", "Legacy Hadoop 1.x JobTracker web interface.", "Unauthenticated access can expose job details, configuration, and cluster data."],
  [50060, "TCP", "Hadoop TaskTracker (Web UI)", "Legacy Hadoop 1.x TaskTracker web interface.", "Same information-disclosure risk as the JobTracker web UI."],
  [50075, "TCP", "Hadoop DataNode (HTTP)", "HDFS DataNode web interface for browsing block data.", "Unauthenticated access can allow direct reading of raw HDFS block data."],
  [51413, "TCP/UDP", "Transmission (peer)", "Default BitTorrent peer-communication port for the Transmission client.", "Same P2P policy/malware-distribution risk as other BitTorrent ports."],
  [52869, "TCP", "UPnP (SOAP)", "UPnP SOAP control endpoint on many consumer routers/IoT devices.", "Actively exploited by Mirai-family botnets via command-injection vulnerabilities."],
  [55553, "TCP", "Meterpreter (alt handler)", "Commonly used alternate Metasploit Meterpreter handler port.", "Strong indicator of active exploitation when seen unexpectedly."],
  [62078, "TCP", "Apple lockdownd", "iOS lockdown service used for device pairing/sync over Wi-Fi.", "Historic authentication weaknesses allowed unauthorized pairing (\"SSL iOS pairing\" issues)."],
  [64738, "TCP/UDP", "Mumble", "Low-latency voice-chat server (Murmur) default port.", "Weak server passwords allow unauthorized listening/participation in voice channels."],
  [989, "TCP", "FTPS Data (explicit)", "Alternate reference to the FTPS data channel used with explicit TLS negotiation.", "Encrypted alternative to plain FTP data; verify certificate validation on clients."],
  [1029, "TCP", "MS-RPC (dynamic, legacy)", "Commonly allocated legacy Windows dynamic RPC endpoint (pre-Vista range).", "Same RPC service-enumeration risk as other dynamic endpoint ports."],
  [1080, "UDP", "SOCKS (UDP associate)", "UDP associate channel used by SOCKS5 for relaying UDP datagrams.", "Same open-relay abuse risk as the TCP SOCKS control channel."],
  [1500, "TCP", "VLSI License Manager", "License manager used by some EDA/VLSI design tools.", "Legacy engineering-software licensing infrastructure; check for default credentials."],
  [1723, "UDP", "PPTP (GRE control)", "Control-channel companion to PPTP's GRE-encapsulated data tunnel.", "Same MS-CHAPv2 weaknesses as the TCP PPTP control port."],
  [2003, "TCP", "Graphite (Carbon)", "Graphite/Carbon metrics ingestion port for time-series monitoring.", "Unauthenticated ingestion allows arbitrary metric injection or data exhaustion."],
  [2004, "TCP", "Graphite (Carbon pickle)", "Carbon's pickle-protocol metrics ingestion port.", "Same injection risk as the plaintext line-protocol port, plus pickle deserialization concerns in older setups."],
  [2601, "UDP", "Zebra RIP (data)", "Data-plane companion to the Zebra/Quagga RIP management console.", "Same routing-integrity risk as unauthenticated RIP in general."],
  [3690, "UDP", "SVN (alt)", "Occasionally referenced UDP companion for Subversion tooling in embedded contexts.", "Rare; verify actual protocol before assuming standard SVN semantics."],
  [4200, "UDP", "Dev server discovery", "Some development tool suites broadcast presence/discovery on this port alongside their TCP dev server.", "Development-only traffic; should never appear on a production network segment."],
  [4712, "TCP", "PulseAudio (native)", "PulseAudio sound server's native network protocol.", "Unauthenticated PulseAudio servers can allow remote audio capture/playback."],
  [4713, "TCP", "PulseAudio (ESD compat)", "PulseAudio's Enlightened Sound Daemon compatibility port.", "Same remote-audio exposure risk as the native PulseAudio port."],
  [5405, "TCP/UDP", "NetSupport Manager", "NetSupport remote-control software communication port.", "Legitimate remote-support tool frequently abused for post-exploitation persistence, similar to TeamViewer."],
  [5560, "TCP", "iSQL*Plus", "Oracle's web-based SQL*Plus interface (legacy).", "Deprecated Oracle component; check for default credentials if still running."],
  [6081, "TCP/UDP", "Geneve", "Generic Network Virtualization Encapsulation -- overlay tunneling for SDN/cloud networking.", "Should be restricted to the underlay management network; exposure risks overlay traffic injection."],
  [6444, "TCP", "Kubernetes API (alt)", "Alternate Kubernetes API server port used in some managed/HA control-plane setups.", "Same critical RBAC/anonymous-access risk as the standard API server port (6443)."],
  [7473, "TCP", "Neo4j (Bolt+routing)", "Neo4j cluster routing variant of the Bolt protocol port.", "Same authentication risk profile as the standard Bolt port."],
  [7911, "TCP", "Secure Data Replicator", "Cambium/various vendor secure data replication service.", "Verify actual vendor/service; replication channels should be encrypted and access-controlled."],
  [8006, "TCP", "Proxmox VE (HTTP)", "Proxmox Virtual Environment web management (unencrypted variant).", "Hypervisor management compromise can affect every hosted VM/container."],
  [8007, "TCP", "Apache Tomcat (AJP alt)", "Alternate Tomcat AJP connector port in some multi-instance deployments.", "Same Ghostcat-class exposure risk as the standard AJP port (8009)."],
  [8291, "UDP", "MikroTik Neighbor Discovery", "MikroTik's UDP neighbor/discovery broadcast companion to Winbox.", "Information disclosure of device identity/model on the local network."],
  [8447, "TCP", "HTTPS-Alt (Java apps)", "Common alternate HTTPS port for Java application servers and management consoles.", "Same TLS/credential risk class as other alternate HTTPS admin ports."],
  [9091, "UDP", "Transmission (LPD)", "Local peer discovery companion to the Transmission BitTorrent client.", "Same P2P discovery/policy risk as other BitTorrent-related ports."],
  [9997, "UDP", "Splunk Forwarder (legacy UDP)", "Legacy UDP variant occasionally used for lightweight forwarder input.", "Same unauthenticated-ingestion risk as the standard TCP forwarder port."],
  [10250, "UDP", "Kubelet (health probes)", "UDP-based health-check traffic associated with kubelet node agents in some CNI plugins.", "Should remain internal to the cluster network alongside the primary TCP kubelet API."],
  [16384, "UDP", "RTP (dynamic range start)", "Start of a commonly used dynamic RTP/RTCP media port range for VoIP/video.", "Unencrypted media in this range can be intercepted; pair with SRTP where possible."],
  [33434, "UDP", "Traceroute (default probe)", "Default destination port range used by Unix traceroute for UDP probe packets.", "Not a real service -- seeing traffic here is normal traceroute activity, not an attack."],
];

const PORTS = PORT_ROWS.map(([port, proto, name, desc, risk]) => ({ port, proto, name, desc, risk }));

const PORT_MIN = Math.min(...PORTS.map((p) => p.port));
const PORT_MAX = Math.max(...PORTS.map((p) => p.port));

function renderPortReference(root) {
  root.innerHTML = `
    <div class="panel">
      <p class="muted">Database of ${PORTS.length} well-known and registered ports (${PORT_MIN}-${PORT_MAX}):
      service name, protocol, description, and a security note for each.</p>
      <div class="tk-row">
        <input class="tk-f" id="pt-filter" placeholder="Filter by port, service, or keyword">
        <select class="tk-f" id="pt-proto" style="max-width:160px">
          <option value="">Any protocol</option>
          <option value="TCP">TCP only</option>
          <option value="UDP">UDP only</option>
        </select>
      </div>
      <div class="tk-row">
        <input class="tk-f" id="pt-min" type="number" placeholder="Range min" style="max-width:120px">
        <input class="tk-f" id="pt-max" type="number" placeholder="Range max" style="max-width:120px">
        <button class="btn ghost sm" id="pt-reset">Reset filters</button>
      </div>
      <div id="pt-count" class="muted" style="margin:8px 0"></div>
      <div id="pt-list" style="max-height:520px;overflow:auto"></div>
    </div>`;

  const renderList = () => {
    const filter = root.querySelector("#pt-filter").value.trim().toLowerCase();
    const proto = root.querySelector("#pt-proto").value;
    const min = Number(root.querySelector("#pt-min").value) || -Infinity;
    const max = Number(root.querySelector("#pt-max").value) || Infinity;
    const rows = PORTS.filter((p) =>
      p.port >= min && p.port <= max &&
      (!proto || p.proto.includes(proto)) &&
      (!filter || String(p.port).includes(filter) || p.name.toLowerCase().includes(filter) || p.desc.toLowerCase().includes(filter)));
    root.querySelector("#pt-count").textContent = `${rows.length} of ${PORTS.length} ports`;
    root.querySelector("#pt-list").innerHTML = rows.map((p) => `
      <div class="card" style="margin-bottom:8px;padding:12px">
        <div style="display:flex;justify-content:space-between;align-items:baseline;flex-wrap:wrap;gap:8px">
          <strong class="mono" style="font-size:1rem">${p.port}/${escapeHtml(p.proto)} -- ${escapeHtml(p.name)}</strong>
        </div>
        <p class="muted" style="margin:4px 0;font-size:.85rem">${escapeHtml(p.desc)}</p>
        <p style="margin:0;font-size:.82rem"><strong>Security note:</strong> ${escapeHtml(p.risk)}</p>
      </div>`).join("") || `<p class="muted">No ports match those filters.</p>`;
  };

  root.querySelector("#pt-filter").addEventListener("input", renderList);
  root.querySelector("#pt-proto").addEventListener("change", renderList);
  root.querySelector("#pt-min").addEventListener("input", renderList);
  root.querySelector("#pt-max").addEventListener("input", renderList);
  root.querySelector("#pt-reset").onclick = () => {
    root.querySelector("#pt-filter").value = "";
    root.querySelector("#pt-proto").value = "";
    root.querySelector("#pt-min").value = "";
    root.querySelector("#pt-max").value = "";
    renderList();
  };
  renderList();
}

// ---------------------------------------------------------------------------
//  Tool 9 -- Network Protocol Analyzer (OSI model + TCP/IP model)
// ---------------------------------------------------------------------------

const OSI_LAYERS = [
  {
    n: 7, name: "Application", pdu: "Data",
    desc: "Provides network services directly to end-user applications -- the layer users and programs actually interact with.",
    protocols: ["HTTP/HTTPS", "FTP", "SMTP", "IMAP/POP3", "DNS", "SSH", "Telnet", "SNMP", "LDAP", "RDP"],
    example: "A browser issuing an HTTP GET request to fetch a web page.",
    tcpip: "Application",
  },
  {
    n: 6, name: "Presentation", pdu: "Data",
    desc: "Translates, encrypts, and compresses data between the application and network formats -- handles character encoding, serialization, and TLS/SSL.",
    protocols: ["TLS/SSL", "JPEG", "MPEG", "ASCII/EBCDIC", "XDR", "MIME"],
    example: "TLS encrypting an HTTP payload before it is handed to the session layer.",
    tcpip: "Application",
  },
  {
    n: 5, name: "Session", pdu: "Data",
    desc: "Establishes, manages, and terminates sessions (dialogues) between two communicating hosts, including checkpointing and synchronization.",
    protocols: ["NetBIOS", "RPC", "PPTP", "SMB (session mgmt)", "SIP (signaling)"],
    example: "A NetBIOS session being established between two Windows hosts for file sharing.",
    tcpip: "Application",
  },
  {
    n: 4, name: "Transport", pdu: "Segment (TCP) / Datagram (UDP)",
    desc: "Provides end-to-end communication, segmentation/reassembly, flow control, and (for TCP) reliable, ordered delivery with error recovery.",
    protocols: ["TCP", "UDP", "SCTP", "QUIC (transport-layer over UDP)"],
    example: "TCP's three-way handshake establishing a reliable connection before data transfer.",
    tcpip: "Transport",
  },
  {
    n: 3, name: "Network", pdu: "Packet",
    desc: "Handles logical addressing and routing -- determines the best path for packets to travel across interconnected networks.",
    protocols: ["IPv4", "IPv6", "ICMP", "IGMP", "IPsec (AH/ESP)", "OSPF", "BGP"],
    example: "A router examining the destination IP address and forwarding the packet toward the next hop.",
    tcpip: "Internet",
  },
  {
    n: 2, name: "Data Link", pdu: "Frame",
    desc: "Provides node-to-node data transfer on the same physical segment, handling MAC addressing, framing, and error detection (not correction).",
    protocols: ["Ethernet (802.3)", "Wi-Fi (802.11)", "PPP", "VLAN (802.1Q)", "ARP", "STP (802.1D)", "MPLS"],
    example: "A switch forwarding a frame based on its destination MAC address.",
    tcpip: "Network Access (Link)",
  },
  {
    n: 1, name: "Physical", pdu: "Bit",
    desc: "Transmits raw, unstructured bit streams over a physical medium -- defines voltage levels, cable types, connectors, and radio frequencies.",
    protocols: ["Ethernet (electrical/optical)", "DSL", "Bluetooth (radio)", "USB", "Fiber optics (SFP/SFP+)"],
    example: "An electrical signal representing a 1 or 0 travelling over a copper Ethernet cable.",
    tcpip: "Network Access (Link)",
  },
];

function renderProtocolAnalyzer(root) {
  root.innerHTML = `
    <div class="panel">
      <p class="pg-sub">OSI 7-layer model, mapped to the practical 4-layer TCP/IP model</p>
      <p class="muted">Click a layer for protocols, PDU name, and a real-world example. Data flows down the stack
      (encapsulation) on the sending host and up the stack (decapsulation) on the receiving host.</p>
      <div id="osi-stack"></div>
      <div id="osi-detail" style="margin-top:16px"></div>
      <p class="pg-sub" style="margin-top:20px">TCP/IP model (practical, 4-layer)</p>
      <table class="mono" style="width:100%;border-collapse:collapse;font-size:.82rem" id="tcpip-table"></table>
    </div>`;

  const stack = root.querySelector("#osi-stack");
  stack.innerHTML = OSI_LAYERS.map((l) => `
    <div class="card osi-layer" data-n="${l.n}" style="margin-bottom:4px;padding:10px 14px;cursor:pointer;display:flex;justify-content:space-between;align-items:center">
      <span><strong class="mono">L${l.n}</strong> -- ${escapeHtml(l.name)}</span>
      <span class="muted" style="font-size:.8rem">${escapeHtml(l.pdu)}</span>
    </div>`).join("");

  const showDetail = (n) => {
    const l = OSI_LAYERS.find((x) => x.n === n);
    root.querySelector("#osi-detail").innerHTML = `
      <div class="dl-cmd">
        <div class="stat-l">Layer</div><div class="mono">L${l.n} -- ${escapeHtml(l.name)}</div>
        <div class="stat-l">PDU (data unit name)</div><div class="mono">${escapeHtml(l.pdu)}</div>
        <div class="stat-l">TCP/IP mapping</div><div class="mono">${escapeHtml(l.tcpip)}</div>
        <div class="stat-l">Description</div><div>${escapeHtml(l.desc)}</div>
        <div class="stat-l">Common protocols</div><div class="mono">${l.protocols.join(", ")}</div>
        <div class="stat-l">Example</div><div>${escapeHtml(l.example)}</div>
      </div>`;
  };

  stack.onclick = (e) => {
    const card = e.target.closest(".osi-layer"); if (!card) return;
    showDetail(Number(card.dataset.n));
  };
  showDetail(7);

  const tcpipGroups = [
    { name: "Application", layers: "OSI L5-L7", protocols: "HTTP, HTTPS, FTP, SMTP, DNS, SSH, TLS" },
    { name: "Transport", layers: "OSI L4", protocols: "TCP, UDP, QUIC" },
    { name: "Internet", layers: "OSI L3", protocols: "IPv4, IPv6, ICMP, IPsec" },
    { name: "Network Access (Link)", layers: "OSI L1-L2", protocols: "Ethernet, Wi-Fi, ARP, PPP" },
  ];
  root.querySelector("#tcpip-table").innerHTML = `
    <tr><td><strong>TCP/IP Layer</strong></td><td><strong>Maps to</strong></td><td><strong>Key protocols</strong></td></tr>
    ${tcpipGroups.map((g) => `<tr><td>${g.name}</td><td>${g.layers}</td><td>${g.protocols}</td></tr>`).join("")}`;
}

// ---------------------------------------------------------------------------
//  Tool 10 -- Bandwidth Calculator
// ---------------------------------------------------------------------------

const CONNECTION_SPEEDS = [
  { name: "Dial-up (56k modem)", mbps: 0.056 },
  { name: "ISDN", mbps: 0.128 },
  { name: "DSL (basic)", mbps: 8 },
  { name: "DSL (VDSL2)", mbps: 100 },
  { name: "Cable (DOCSIS 3.0)", mbps: 300 },
  { name: "Cable (DOCSIS 3.1)", mbps: 1000 },
  { name: "T1 line", mbps: 1.544 },
  { name: "T3 line", mbps: 44.736 },
  { name: "Fiber (FTTH, basic)", mbps: 300 },
  { name: "Fiber (FTTH, gigabit)", mbps: 1000 },
  { name: "Fiber (multi-gig)", mbps: 2500 },
  { name: "4G LTE (typical)", mbps: 30 },
  { name: "5G (sub-6GHz, typical)", mbps: 200 },
  { name: "5G (mmWave, peak)", mbps: 1000 },
  { name: "Wi-Fi 5 (802.11ac, typical)", mbps: 400 },
  { name: "Wi-Fi 6 (802.11ax, typical)", mbps: 600 },
  { name: "Fast Ethernet (100BASE-T)", mbps: 100 },
  { name: "Gigabit Ethernet", mbps: 1000 },
  { name: "10 Gigabit Ethernet", mbps: 10000 },
  { name: "40 Gigabit Ethernet", mbps: 40000 },
  { name: "100 Gigabit Ethernet", mbps: 100000 },
];

function formatBytes(bytes) {
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let i = 0, n = bytes;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(2)} ${units[i]}`;
}

function formatDuration(seconds) {
  if (!isFinite(seconds)) return "n/a";
  if (seconds < 1) return `${(seconds * 1000).toFixed(1)} ms`;
  if (seconds < 60) return `${seconds.toFixed(2)} sec`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ${Math.round(seconds % 60)} sec`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hr ${Math.floor((seconds % 3600) / 60)} min`;
  return `${Math.floor(seconds / 86400)} days ${Math.floor((seconds % 86400) / 3600)} hr`;
}

function renderBandwidthCalculator(root) {
  root.innerHTML = `
    <div class="panel">
      <p class="muted">Convert between bits and bytes, and calculate transfer time for a file size at a given
      connection speed. Remember: connection speeds are almost always advertised in <strong>bits</strong> per
      second, while file sizes are almost always shown in <strong>bytes</strong>.</p>

      <p class="pg-sub">Unit converter</p>
      ${field("Value", "bw-val", "100", "e.g. 100")}
      ${selectField("From unit", "bw-from", [
        { value: "bit", label: "bits" }, { value: "byte", label: "bytes" },
        { value: "Kb", label: "kilobits (Kb)" }, { value: "KB", label: "kilobytes (KB)" },
        { value: "Mb", label: "megabits (Mb)" }, { value: "MB", label: "megabytes (MB)" },
        { value: "Gb", label: "gigabits (Gb)" }, { value: "GB", label: "gigabytes (GB)" },
        { value: "Tb", label: "terabits (Tb)" }, { value: "TB", label: "terabytes (TB)" },
      ], "MB")}
      <div class="tk-btns"><button class="btn sm" id="bw-conv-go">Convert to all units</button></div>
      <div id="bw-conv-out"></div>

      <p class="pg-sub" style="margin-top:22px">Transfer time calculator</p>
      ${field("File size", "bw-size", "10", "e.g. 10")}
      ${selectField("Size unit", "bw-size-unit", [
        { value: "MB", label: "MB" }, { value: "GB", label: "GB" }, { value: "TB", label: "TB" }, { value: "KB", label: "KB" },
      ], "GB")}
      ${selectField("Connection speed", "bw-speed-preset", [
        { value: "custom", label: "Custom (enter Mbps below)" },
        ...CONNECTION_SPEEDS.map((s) => ({ value: String(s.mbps), label: `${s.name} (${s.mbps} Mbps)` })),
      ], "custom")}
      ${field("Speed (Mbps)", "bw-speed", "100", "e.g. 100")}
      <div class="tk-btns"><button class="btn sm" id="bw-time-go">Calculate transfer time</button></div>
      <div id="bw-time-out"></div>

      <p class="pg-sub" style="margin-top:22px">Common connection speed reference</p>
      <table class="mono" style="width:100%;border-collapse:collapse;font-size:.82rem">
        <tr><td><strong>Connection</strong></td><td><strong>Typical speed</strong></td><td><strong>1 GB transfer time</strong></td></tr>
        ${CONNECTION_SPEEDS.map((s) => `<tr><td>${s.name}</td><td>${s.mbps.toLocaleString()} Mbps</td><td>${formatDuration((1024 * 8) / s.mbps)}</td></tr>`).join("")}
      </table>
    </div>`;

  const BIT_FACTORS = { bit: 1, Kb: 1e3, Mb: 1e6, Gb: 1e9, Tb: 1e12, byte: 8, KB: 8e3, MB: 8e6, GB: 8e9, TB: 8e12 };

  root.querySelector("#bw-conv-go").onclick = () => {
    const val = Number(root.querySelector("#bw-val").value);
    const from = root.querySelector("#bw-from").value;
    const out = root.querySelector("#bw-conv-out");
    if (!isFinite(val)) { out.innerHTML = `<pre class="tk-out">Error: enter a numeric value</pre>`; return; }
    const bits = val * BIT_FACTORS[from];
    const rows = [
      ["bits", bits], ["bytes", bits / 8],
      ["kilobits (Kb)", bits / 1e3], ["kilobytes (KB)", bits / 8e3],
      ["megabits (Mb)", bits / 1e6], ["megabytes (MB)", bits / 8e6],
      ["gigabits (Gb)", bits / 1e9], ["gigabytes (GB)", bits / 8e9],
      ["terabits (Tb)", bits / 1e12], ["terabytes (TB)", bits / 8e12],
    ];
    out.innerHTML = `<div class="dl-cmd" style="margin-top:14px">
      ${rows.map(([label, v]) => `<div class="stat-l">${label}</div><div class="mono">${v.toLocaleString(undefined, { maximumFractionDigits: 6 })}</div>`).join("")}
    </div>`;
  };

  root.querySelector("#bw-speed-preset").onchange = (e) => {
    if (e.target.value !== "custom") root.querySelector("#bw-speed").value = e.target.value;
  };

  root.querySelector("#bw-time-go").onclick = () => {
    const size = Number(root.querySelector("#bw-size").value);
    const sizeUnit = root.querySelector("#bw-size-unit").value;
    const mbps = Number(root.querySelector("#bw-speed").value);
    const out = root.querySelector("#bw-time-out");
    if (!isFinite(size) || !isFinite(mbps) || mbps <= 0) { out.innerHTML = `<pre class="tk-out">Error: enter valid file size and speed</pre>`; return; }
    const sizeBytesFactor = { KB: 1024, MB: 1024 ** 2, GB: 1024 ** 3, TB: 1024 ** 4 };
    const totalBytes = size * sizeBytesFactor[sizeUnit];
    const totalBits = totalBytes * 8;
    const bps = mbps * 1e6;
    const seconds = totalBits / bps;
    const effectiveSeconds80 = seconds / 0.8; // real-world ~80% throughput efficiency
    out.innerHTML = `<div class="dl-cmd" style="margin-top:14px">
      <div class="stat-l">File size</div><div class="mono">${formatBytes(totalBytes)}</div>
      <div class="stat-l">Connection speed</div><div class="mono">${mbps.toLocaleString()} Mbps (${(mbps / 8).toFixed(2)} MB/s theoretical)</div>
      <div class="stat-l">Transfer time (theoretical)</div><div class="mono">${formatDuration(seconds)}</div>
      <div class="stat-l">Transfer time (~80% real-world efficiency)</div><div class="mono">${formatDuration(effectiveSeconds80)}</div>
    </div>
    <p class="muted" style="margin-top:8px">Real-world throughput is typically 70-90% of the advertised link speed
    due to protocol overhead (TCP/IP headers, retransmissions), other traffic sharing the link, and Wi-Fi contention.</p>`;
  };
}

// ---------------------------------------------------------------------------
//  Tool 11 -- MTU Calculator
// ---------------------------------------------------------------------------

const MTU_OVERHEADS = [
  { name: "Ethernet II header", bytes: 14, desc: "Destination MAC (6) + Source MAC (6) + EtherType (2)." },
  { name: "Ethernet FCS (trailer)", bytes: 4, desc: "Frame Check Sequence -- CRC32 for error detection (not usually counted against MTU)." },
  { name: "802.1Q VLAN tag", bytes: 4, desc: "Adds a VLAN tag (TPID + TCI) between the source MAC and EtherType." },
  { name: "802.1ad Q-in-Q (double tag)", bytes: 8, desc: "Two stacked 802.1Q tags for service-provider VLAN stacking." },
  { name: "PPPoE header", bytes: 8, desc: "PPPoE session header (6) + PPP protocol ID (2), common on DSL connections." },
  { name: "PPP header", bytes: 4, desc: "Point-to-Point Protocol framing overhead." },
  { name: "GRE header", bytes: 24, desc: "Generic Routing Encapsulation: base header (4) plus outer IP header (20) for the tunnel." },
  { name: "IPsec ESP (transport, AES-CBC)", bytes: 38, desc: "ESP header/trailer/ICV plus padding -- varies by cipher/mode; this is a typical figure." },
  { name: "IPsec ESP (tunnel, AES-CBC)", bytes: 58, desc: "Transport-mode ESP overhead plus an additional outer IP header (20 bytes) for tunnel mode." },
  { name: "IPsec AH", bytes: 24, desc: "Authentication Header -- integrity only, no encryption, smaller overhead than ESP." },
  { name: "L2TP header", bytes: 8, desc: "Layer 2 Tunneling Protocol header (varies slightly with optional fields)." },
  { name: "VXLAN header", bytes: 50, desc: "Outer Ethernet (14) + outer IP (20) + outer UDP (8) + VXLAN header (8) encapsulating the inner frame." },
  { name: "GENEVE header", bytes: 50, desc: "Similar overlay overhead profile to VXLAN: outer Ethernet + IP + UDP + Geneve base header." },
  { name: "MPLS label (per label)", bytes: 4, desc: "Each MPLS label adds 4 bytes; stacked labels (e.g. for VPN + TE) multiply this." },
  { name: "GTP-U header (mobile/5G)", bytes: 36, desc: "Outer IP (20) + outer UDP (8) + GTP-U header (8) used to tunnel user traffic in mobile core networks." },
  { name: "WireGuard header", bytes: 60, desc: "Outer IP/UDP (28) + WireGuard header and Poly1305 auth tag (~32), approximate typical overhead." },
  { name: "OpenVPN (UDP, AES-256-GCM)", bytes: 56, desc: "Outer IP/UDP plus OpenVPN framing and AEAD tag -- approximate, varies with cipher and options." },
];

function renderMtuCalculator(root) {
  root.innerHTML = `
    <div class="panel">
      <p class="muted">Calculate the effective/maximum payload MTU after subtracting one or more encapsulation
      overheads from a base link MTU. Useful for sizing tunnels (VPN, GRE, VXLAN) so packets don't get fragmented
      or dropped by devices with Don't-Fragment set.</p>
      ${field("Base link MTU (bytes)", "mtu-base", "1500", "e.g. 1500 for standard Ethernet")}
      <p class="pg-sub" style="margin-top:14px">Select overhead(s) to subtract</p>
      <div id="mtu-checks" class="tk-row" style="flex-wrap:wrap;gap:10px"></div>
      <div class="tk-btns" style="margin-top:10px"><button class="btn sm" id="mtu-go">Calculate</button>
      <button class="btn ghost sm" id="mtu-clear">Clear selections</button></div>
      <div id="mtu-out"></div>
      <p class="pg-sub" style="margin-top:20px">Overhead reference table</p>
      <table class="mono" style="width:100%;border-collapse:collapse;font-size:.82rem">
        <tr><td><strong>Encapsulation</strong></td><td><strong>Overhead</strong></td><td><strong>Notes</strong></td></tr>
        ${MTU_OVERHEADS.map((o) => `<tr><td>${o.name}</td><td>${o.bytes} bytes</td><td style="font-family:inherit">${o.desc}</td></tr>`).join("")}
      </table>
      <p class="muted" style="margin-top:10px">Common baseline MTUs: standard Ethernet 1500, Jumbo frames 9000,
      PPPoE-constrained DSL links often 1492, IPv6 minimum required MTU 1280, dial-up/PPP often 576.</p>
    </div>`;

  root.querySelector("#mtu-checks").innerHTML = MTU_OVERHEADS.map((o, i) => `
    <label style="display:flex;align-items:center;gap:6px;font-size:.85rem">
      <input type="checkbox" class="mtu-chk" data-i="${i}"> ${escapeHtml(o.name)} (${o.bytes}B)
    </label>`).join("");

  const calc = () => {
    const base = Number(root.querySelector("#mtu-base").value);
    const out = root.querySelector("#mtu-out");
    if (!isFinite(base) || base <= 0) { out.innerHTML = `<pre class="tk-out">Error: enter a valid base MTU</pre>`; return; }
    const checked = [...root.querySelectorAll(".mtu-chk:checked")].map((c) => MTU_OVERHEADS[+c.dataset.i]);
    const totalOverhead = checked.reduce((sum, o) => sum + o.bytes, 0);
    const effective = base - totalOverhead;
    out.innerHTML = `<div class="dl-cmd" style="margin-top:14px">
      <div class="stat-l">Base MTU</div><div class="mono">${base} bytes</div>
      <div class="stat-l">Selected overhead</div><div class="mono">${checked.length ? checked.map((o) => o.name).join(" + ") : "none"}</div>
      <div class="stat-l">Total overhead</div><div class="mono">${totalOverhead} bytes</div>
      <div class="stat-l">Effective MTU</div><div class="mono">${effective} bytes${effective < 0 ? " (invalid -- overhead exceeds base MTU)" : ""}</div>
      <div class="stat-l">Effective MSS (TCP, IPv4)</div><div class="mono">${effective - 40 > 0 ? effective - 40 : "n/a"} bytes (MTU - 20 IP - 20 TCP)</div>
      <div class="stat-l">Effective MSS (TCP, IPv6)</div><div class="mono">${effective - 60 > 0 ? effective - 60 : "n/a"} bytes (MTU - 40 IPv6 - 20 TCP)</div>
    </div>`;
  };

  root.querySelector("#mtu-go").onclick = calc;
  root.querySelector("#mtu-base").addEventListener("input", calc);
  root.querySelector("#mtu-checks").addEventListener("change", calc);
  root.querySelector("#mtu-clear").onclick = () => {
    root.querySelectorAll(".mtu-chk").forEach((c) => { c.checked = false; });
    calc();
  };
  calc();
}

// ---------------------------------------------------------------------------
//  Tool 12 -- TCP Flag Reference
// ---------------------------------------------------------------------------

const TCP_FLAGS = [
  { flag: "SYN", bit: 1, name: "Synchronize", desc: "Initiates a connection and synchronizes sequence numbers between two hosts. Set on the first and second packets of the three-way handshake." },
  { flag: "ACK", bit: 4, name: "Acknowledgment", desc: "Indicates the Acknowledgment Number field is significant -- confirms receipt of data. Set on almost every packet after the handshake." },
  { flag: "FIN", bit: 0, name: "Finish", desc: "Signals that the sender has no more data to send, beginning a graceful connection teardown." },
  { flag: "RST", bit: 2, name: "Reset", desc: "Abruptly terminates a connection, typically sent in response to a packet for a connection that doesn't exist or after an error." },
  { flag: "PSH", bit: 3, name: "Push", desc: "Asks the receiving stack to push buffered data up to the application immediately rather than waiting to fill a buffer." },
  { flag: "URG", bit: 5, name: "Urgent", desc: "Indicates the Urgent Pointer field is significant, marking data that should be processed out-of-band/ahead of the stream. Rarely used today." },
  { flag: "ECE", bit: 6, name: "ECN-Echo", desc: "Explicit Congestion Notification Echo -- indicates the sender received a congestion-marked packet (part of ECN, RFC 3168)." },
  { flag: "CWR", bit: 7, name: "Congestion Window Reduced", desc: "Sent by a sender to indicate it received an ECE and has reduced its congestion window in response." },
  { flag: "NS", bit: 8, name: "Nonce Sum", desc: "ECN-nonce concealment protection to guard against accidental or malicious concealment of congestion markings (RFC 3540, experimental)." },
];

const TCP_FLAG_COMBOS = [
  { combo: "SYN", meaning: "Connection request (handshake step 1). Client -> server, proposing initial sequence number." },
  { combo: "SYN, ACK", meaning: "Connection request acknowledged (handshake step 2). Server -> client, acknowledging the client's SYN and proposing its own." },
  { combo: "ACK", meaning: "Connection established / general data acknowledgment (handshake step 3, and virtually every packet afterward)." },
  { combo: "PSH, ACK", meaning: "Data segment being pushed to the application immediately, with acknowledgment of previously received data -- typical during active data transfer." },
  { combo: "FIN, ACK", meaning: "Graceful close of one direction of the connection, acknowledging prior data. Part of the standard four-way close." },
  { combo: "RST", meaning: "Abrupt termination, e.g. connecting to a closed port -- no listener responds with SYN-ACK, instead sending RST." },
  { combo: "RST, ACK", meaning: "Reset in response to an established connection, acknowledging received data before tearing down abruptly." },
  { combo: "SYN, RST", meaning: "Anomalous/malformed combination -- often seen in crafted packets used for OS fingerprinting or firewall evasion, or in scan responses." },
  { combo: "SYN, FIN", meaning: "Invalid combination that should never occur in normal traffic -- a classic IDS-evasion / stealth-scan signature (SYN+FIN scans)." },
  { combo: "All flags set (\"Christmas tree\")", meaning: "SYN, FIN, PSH, URG all set -- an Xmas scan technique used to probe firewall/IDS behavior since it violates normal TCP semantics." },
  { combo: "No flags set (\"Null scan\")", meaning: "A packet with no flags at all -- used in null scans to elicit RST responses from closed ports on some stacks while open ports stay silent." },
];

const TCP_STATES = [
  { state: "CLOSED", desc: "No connection exists; the default starting and ending state." },
  { state: "LISTEN", desc: "A server socket is waiting for incoming connection requests (after bind + listen)." },
  { state: "SYN_SENT", desc: "A client has sent a SYN and is waiting for a matching SYN-ACK." },
  { state: "SYN_RECEIVED", desc: "A server received a SYN, replied with SYN-ACK, and is waiting for the final ACK." },
  { state: "ESTABLISHED", desc: "The three-way handshake completed; data can flow in both directions." },
  { state: "FIN_WAIT_1", desc: "A host has sent a FIN to begin closing its side and is waiting for an ACK or a simultaneous FIN." },
  { state: "FIN_WAIT_2", desc: "A host's FIN was acknowledged; it is now waiting for the remote side's FIN." },
  { state: "CLOSE_WAIT", desc: "A host received a FIN from the remote side and has acknowledged it, but hasn't yet sent its own FIN (waiting on the local application to close)." },
  { state: "CLOSING", desc: "Both sides sent FINs roughly simultaneously, and each is waiting for the other's ACK." },
  { state: "LAST_ACK", desc: "A host that received a FIN and sent its own FIN is now waiting for the final ACK." },
  { state: "TIME_WAIT", desc: "A host waits (typically 2x Maximum Segment Lifetime) after closing to ensure the remote side received the final ACK and to let stray duplicate segments expire." },
];

function renderTcpFlags(root) {
  root.innerHTML = `
    <div class="panel">
      <p class="pg-sub">TCP header flags (control bits)</p>
      <table class="mono" style="width:100%;border-collapse:collapse;font-size:.82rem">
        <tr><td><strong>Flag</strong></td><td><strong>Bit</strong></td><td><strong>Name</strong></td><td><strong>Meaning</strong></td></tr>
        ${TCP_FLAGS.map((f) => `<tr><td>${f.flag}</td><td>${f.bit}</td><td style="font-family:inherit">${f.name}</td><td style="font-family:inherit">${escapeHtml(f.desc)}</td></tr>`).join("")}
      </table>

      <p class="pg-sub" style="margin-top:22px">The three-way handshake</p>
      <pre class="tk-out">Client                                   Server
  |                                        |
  |  ---------  SYN (seq=x)  ------------> |   1. Client proposes seq x
  |                                        |
  |  <----  SYN, ACK (seq=y, ack=x+1) ---- |   2. Server proposes seq y, acks x
  |                                        |
  |  ---------  ACK (ack=y+1)  ----------> |   3. Client acks y; connection ESTABLISHED
  |                                        |</pre>

      <p class="pg-sub" style="margin-top:22px">The four-way close</p>
      <pre class="tk-out">Client                                   Server
  |  ---------  FIN  --------------------> |   Client done sending
  |  <--------  ACK  --------------------- |   Server acks
  |  <--------  FIN  --------------------- |   Server done sending
  |  ---------  ACK  --------------------> |   Client acks; enters TIME_WAIT</pre>

      <p class="pg-sub" style="margin-top:22px">Common flag combinations and their meaning</p>
      <div id="combo-list"></div>

      <p class="pg-sub" style="margin-top:22px">TCP state machine</p>
      <div id="state-list"></div>
    </div>`;

  root.querySelector("#combo-list").innerHTML = TCP_FLAG_COMBOS.map((c) => `
    <div class="card" style="margin-bottom:8px;padding:10px 14px">
      <strong class="mono">${escapeHtml(c.combo)}</strong>
      <p class="muted" style="margin:4px 0 0">${escapeHtml(c.meaning)}</p>
    </div>`).join("");

  root.querySelector("#state-list").innerHTML = TCP_STATES.map((s) => `
    <div class="card" style="margin-bottom:6px;padding:8px 14px;display:flex;gap:14px">
      <strong class="mono" style="min-width:130px">${s.state}</strong>
      <span class="muted" style="font-size:.85rem">${escapeHtml(s.desc)}</span>
    </div>`).join("");
}

// ---------------------------------------------------------------------------
//  Tool 13 -- Packet Header Visualizer
// ---------------------------------------------------------------------------

const PACKET_HEADERS = {
  tcp: {
    label: "TCP Header (RFC 9293)",
    diagram: `
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port         |       Destination Port       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |N|C|E|U|A|P|R|S|F|                                    |
| Offset|S|W|C|R|C|S|S|Y|I|            Window Size             |
|       | |R|E|G|K|H|T|N|N|                                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum           |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options (if Data Offset > 5)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+`,
    fields: [
      { name: "Source Port", offset: "0-1", size: "2 bytes", desc: "Port number of the sending application." },
      { name: "Destination Port", offset: "2-3", size: "2 bytes", desc: "Port number of the receiving application." },
      { name: "Sequence Number", offset: "4-7", size: "4 bytes", desc: "Position of this segment's first data byte in the overall stream (or the ISN if SYN is set)." },
      { name: "Acknowledgment Number", offset: "8-11", size: "4 bytes", desc: "Next sequence number the sender expects to receive, valid when ACK is set." },
      { name: "Data Offset", offset: "12 (bits 0-3)", size: "4 bits", desc: "Length of the TCP header in 32-bit words; indicates where the data begins." },
      { name: "Flags (control bits)", offset: "12-13", size: "9 bits", desc: "NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN control flags." },
      { name: "Window Size", offset: "14-15", size: "2 bytes", desc: "Number of bytes the sender is willing to receive, for flow control." },
      { name: "Checksum", offset: "16-17", size: "2 bytes", desc: "Error-checking checksum covering the header, data, and a pseudo-header." },
      { name: "Urgent Pointer", offset: "18-19", size: "2 bytes", desc: "Offset from the sequence number indicating urgent data, valid when URG is set." },
      { name: "Options", offset: "20+", size: "variable (0-40 bytes)", desc: "Optional fields: MSS, window scale, SACK permitted, timestamps, etc." },
    ],
  },
  udp: {
    label: "UDP Header (RFC 768)",
    diagram: `
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port         |       Destination Port       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Length            |           Checksum           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+`,
    fields: [
      { name: "Source Port", offset: "0-1", size: "2 bytes", desc: "Port of the sending application (may be zero if unused)." },
      { name: "Destination Port", offset: "2-3", size: "2 bytes", desc: "Port of the receiving application." },
      { name: "Length", offset: "4-5", size: "2 bytes", desc: "Length in bytes of the UDP header plus data (minimum value 8)." },
      { name: "Checksum", offset: "6-7", size: "2 bytes", desc: "Error-checking value covering header, data, and pseudo-header; optional in IPv4, mandatory in IPv6." },
      { name: "Data", offset: "8+", size: "variable", desc: "The payload -- UDP has no built-in fragmentation, ordering, or retransmission." },
    ],
  },
  ipv4: {
    label: "IPv4 Header (RFC 791)",
    diagram: `
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|     Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |        Header Checksum        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options (if IHL > 5)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+`,
    fields: [
      { name: "Version", offset: "0 (bits 0-3)", size: "4 bits", desc: "IP version -- always 4 for IPv4." },
      { name: "IHL", offset: "0 (bits 4-7)", size: "4 bits", desc: "Internet Header Length in 32-bit words (minimum 5 = 20 bytes)." },
      { name: "Type of Service / DSCP+ECN", offset: "1", size: "1 byte", desc: "Differentiated Services Code Point (QoS priority) and Explicit Congestion Notification bits." },
      { name: "Total Length", offset: "2-3", size: "2 bytes", desc: "Total packet length (header + data) in bytes, max 65,535." },
      { name: "Identification", offset: "4-5", size: "2 bytes", desc: "Identifies fragments belonging to the same original datagram." },
      { name: "Flags", offset: "6 (bits 0-2)", size: "3 bits", desc: "Reserved, Don't Fragment (DF), More Fragments (MF)." },
      { name: "Fragment Offset", offset: "6-7 (bits 3-15)", size: "13 bits", desc: "Position of this fragment within the original datagram, in 8-byte units." },
      { name: "Time to Live (TTL)", offset: "8", size: "1 byte", desc: "Decremented by each router hop; packet is discarded when it reaches zero, preventing routing loops." },
      { name: "Protocol", offset: "9", size: "1 byte", desc: "Identifies the encapsulated protocol -- 6 = TCP, 17 = UDP, 1 = ICMP." },
      { name: "Header Checksum", offset: "10-11", size: "2 bytes", desc: "Error-checking value covering only the IP header, recalculated at every hop." },
      { name: "Source Address", offset: "12-15", size: "4 bytes", desc: "IPv4 address of the sender." },
      { name: "Destination Address", offset: "16-19", size: "4 bytes", desc: "IPv4 address of the intended recipient." },
      { name: "Options", offset: "20+", size: "variable (0-40 bytes)", desc: "Optional fields: record route, timestamp, source routing (rarely used, often stripped by routers)." },
    ],
  },
  icmp: {
    label: "ICMP Header (RFC 792)",
    diagram: `
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Rest of Header (type-specific)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+`,
    fields: [
      { name: "Type", offset: "0", size: "1 byte", desc: "Message type -- 8 = Echo Request, 0 = Echo Reply, 3 = Destination Unreachable, 11 = Time Exceeded, 5 = Redirect." },
      { name: "Code", offset: "1", size: "1 byte", desc: "Sub-classification of the Type, e.g. Type 3 Code 1 = Host Unreachable, Code 3 = Port Unreachable." },
      { name: "Checksum", offset: "2-3", size: "2 bytes", desc: "Error-checking value covering the entire ICMP message." },
      { name: "Rest of Header", offset: "4-7", size: "4 bytes", desc: "Meaning depends on Type -- e.g. Identifier + Sequence Number for Echo Request/Reply." },
      { name: "Data", offset: "8+", size: "variable", desc: "Echo payload, or the original IP header + first 8 bytes of the offending packet for error messages." },
    ],
    typeTable: [
      { type: 0, name: "Echo Reply", note: "Response to a ping request." },
      { type: 3, name: "Destination Unreachable", note: "Codes 0-15 specify network/host/protocol/port unreachable, fragmentation needed, etc." },
      { type: 4, name: "Source Quench", note: "Deprecated congestion-control signal." },
      { type: 5, name: "Redirect", note: "Informs a host of a better route; spoofable and often filtered for security." },
      { type: 8, name: "Echo Request", note: "The ping request." },
      { type: 9, name: "Router Advertisement", note: "Advertises the addresses of routers on a network." },
      { type: 10, name: "Router Solicitation", note: "Requests router advertisements." },
      { type: 11, name: "Time Exceeded", note: "TTL reached zero (used by traceroute) or fragment reassembly timed out." },
      { type: 12, name: "Parameter Problem", note: "Indicates a malformed IP header field." },
      { type: 13, name: "Timestamp", note: "Requests the remote system's current time (legacy)." },
      { type: 14, name: "Timestamp Reply", note: "Response to a Timestamp request." },
    ],
  },
  arp: {
    label: "ARP Header (RFC 826)",
    diagram: `
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Hardware Type         |         Protocol Type         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Hw Addr Len   | Proto Addr Len|          Operation            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Sender Hardware Address (6B)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Sender Hardware Address (cont.)  | Sender Proto... |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Sender Protocol Address (cont.)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Target Hardware Address (6B)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Target Protocol Address (4B)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+`,
    fields: [
      { name: "Hardware Type", offset: "0-1", size: "2 bytes", desc: "Link-layer type -- 1 = Ethernet." },
      { name: "Protocol Type", offset: "2-3", size: "2 bytes", desc: "Upper-layer protocol -- 0x0800 = IPv4." },
      { name: "Hardware Address Length", offset: "4", size: "1 byte", desc: "Length of hardware (MAC) addresses -- 6 for Ethernet." },
      { name: "Protocol Address Length", offset: "5", size: "1 byte", desc: "Length of protocol (IP) addresses -- 4 for IPv4." },
      { name: "Operation", offset: "6-7", size: "2 bytes", desc: "1 = Request, 2 = Reply." },
      { name: "Sender Hardware Address", offset: "8-13", size: "6 bytes", desc: "MAC address of the sender." },
      { name: "Sender Protocol Address", offset: "14-17", size: "4 bytes", desc: "IP address of the sender." },
      { name: "Target Hardware Address", offset: "18-23", size: "6 bytes", desc: "MAC address of the target (all zeros in a request)." },
      { name: "Target Protocol Address", offset: "24-27", size: "4 bytes", desc: "IP address of the target." },
    ],
  },
};

function renderPacketVisualizer(root) {
  const keys = Object.keys(PACKET_HEADERS);
  root.innerHTML = `
    <div class="panel">
      <p class="muted">ASCII byte-layout diagrams for the most common packet headers, with a field-by-field
      breakdown of offsets and meanings.</p>
      <div class="tab-bar" id="pkt-tabs">
        ${keys.map((k, i) => `<button class="tab${i === 0 ? " active" : ""}" data-k="${k}">${PACKET_HEADERS[k].label.split(" (")[0]}</button>`).join("")}
      </div>
      <div id="pkt-content" style="margin-top:14px"></div>
    </div>`;

  const show = (key) => {
    const h = PACKET_HEADERS[key];
    let extra = "";
    if (h.typeTable) {
      extra = `<p class="pg-sub" style="margin-top:16px">Common ICMP types</p>
        <table class="mono" style="width:100%;border-collapse:collapse;font-size:.82rem">
          <tr><td><strong>Type</strong></td><td><strong>Name</strong></td><td><strong>Note</strong></td></tr>
          ${h.typeTable.map((t) => `<tr><td>${t.type}</td><td>${t.name}</td><td style="font-family:inherit">${t.note}</td></tr>`).join("")}
        </table>`;
    }
    root.querySelector("#pkt-content").innerHTML = `
      <p class="pg-sub">${h.label}</p>
      <pre class="tk-out" style="overflow-x:auto;font-size:.72rem;line-height:1.35">${escapeHtml(h.diagram.trim())}</pre>
      <p class="pg-sub" style="margin-top:16px">Field reference</p>
      <table class="mono" style="width:100%;border-collapse:collapse;font-size:.82rem">
        <tr><td><strong>Field</strong></td><td><strong>Byte offset</strong></td><td><strong>Size</strong></td><td><strong>Description</strong></td></tr>
        ${h.fields.map((f) => `<tr><td>${f.name}</td><td>${f.offset}</td><td>${f.size}</td><td style="font-family:inherit">${f.desc}</td></tr>`).join("")}
      </table>
      ${extra}`;
  };

  root.querySelector("#pkt-tabs").onclick = (e) => {
    const btn = e.target.closest("button[data-k]"); if (!btn) return;
    root.querySelectorAll("#pkt-tabs .tab").forEach((t) => t.classList.remove("active"));
    btn.classList.add("active");
    show(btn.dataset.k);
  };
  show(keys[0]);
}

// ---------------------------------------------------------------------------
//  Tool 14 -- VLAN Reference
// ---------------------------------------------------------------------------

const VLAN_TYPES = [
  { name: "Default VLAN", desc: "VLAN 1 on most switches -- exists automatically and cannot be deleted. Best practice is to avoid using it for production traffic since it's a predictable target and often carries control-plane traffic (CDP, STP, VTP) by default." },
  { name: "Data VLAN", desc: "Carries regular user-generated traffic -- workstations, printers, general business applications. Typically the majority of configured VLANs." },
  { name: "Voice VLAN", desc: "Dedicated VLAN for VoIP traffic, separated from data VLANs to allow QoS prioritization and to keep phone traffic isolated from potentially compromised workstations." },
  { name: "Management VLAN", desc: "Carries traffic for administering network devices (SSH, HTTPS, SNMP to switches/routers/APs). Should be strictly isolated from user-accessible VLANs." },
  { name: "Native VLAN", desc: "On an 802.1Q trunk, the one VLAN whose traffic is sent untagged. Mismatched native VLANs between switches cause VLAN leakage and are a classic misconfiguration/attack vector (VLAN hopping)." },
  { name: "Black hole / Unused VLAN", desc: "An unused VLAN assigned to all switch ports that are administratively down or not in active use, preventing accidental or malicious use of default VLAN 1." },
  { name: "Guest VLAN", desc: "Isolated VLAN for visitor/BYOD devices, typically routed only to the internet with no access to internal resources." },
  { name: "Private VLAN (PVLAN)", desc: "Subdivides a VLAN into isolated, community, and promiscuous port types to restrict peer-to-peer communication within the same broadcast domain, e.g. in hosting/DMZ environments." },
];

const VLAN_TRUNKING = [
  { name: "802.1Q", desc: "IEEE standard VLAN tagging -- inserts a 4-byte tag (12-bit VLAN ID, supporting 4,094 usable VLANs) between the source MAC and EtherType fields of an Ethernet frame." },
  { name: "ISL (Inter-Switch Link)", desc: "Cisco's legacy proprietary trunking protocol that encapsulates the entire frame rather than inserting a tag. Deprecated in favor of the open 802.1Q standard." },
  { name: "VTP (VLAN Trunking Protocol)", desc: "Cisco proprietary protocol that propagates VLAN configuration across a switched domain. A misconfigured VTP server with a higher revision number can wipe VLAN databases network-wide -- a well-known operational hazard." },
  { name: "MVRP (Multiple VLAN Registration Protocol)", desc: "Open standard (802.1ak) alternative to VTP for dynamically registering and propagating VLAN membership across a bridged network." },
  { name: "802.1ad (Q-in-Q)", desc: "Double VLAN tagging used by service providers to tunnel customer VLANs transparently across a provider network by wrapping an outer service-provider tag around the customer's own 802.1Q tag." },
];

const VLAN_COMMON_IDS = [
  { id: "1", use: "Default VLAN on most switches -- avoid using for production traffic." },
  { id: "2-1001", use: "Normal-range VLANs available for general assignment (Ethernet VLANs)." },
  { id: "1002-1005", use: "Reserved for legacy Token Ring / FDDI VLANs on Cisco switches -- cannot be deleted on some platforms." },
  { id: "1006-4094", use: "Extended-range VLANs, usable on modern switches for large-scale segmentation." },
  { id: "4095", use: "Reserved -- typically not usable/configurable." },
  { id: "0 and 4096+", use: "Invalid/out of range for standard 802.1Q (12-bit ID field)." },
];

function renderVlanReference(root) {
  root.innerHTML = `
    <div class="panel">
      <p class="pg-sub">What is a VLAN?</p>
      <p class="muted">A Virtual LAN (VLAN) logically segments a single physical switched network into multiple
      independent broadcast domains. Devices in different VLANs cannot communicate without a router or Layer 3
      switch, even if they're plugged into the same physical switch. VLANs improve security (isolating sensitive
      traffic), reduce broadcast domain size (improving performance), and simplify logical network organization
      independent of physical topology.</p>

      <p class="pg-sub" style="margin-top:20px">802.1Q frame format</p>
      <pre class="tk-out" style="overflow-x:auto">
Untagged Ethernet II frame:
+-------------+-------------+-----------+------+-----+
| Dest MAC(6) | Src MAC (6) | EtherType |  Data | FCS |
+-------------+-------------+-----------+------+-----+

802.1Q tagged frame (adds a 4-byte tag after the source MAC):
+-------------+-------------+-----------+-----------+------+-----+
| Dest MAC(6) | Src MAC (6) | 802.1Q Tag| EtherType | Data | FCS |
+-------------+-------------+-----------+-----------+------+-----+
                              (4 bytes)

802.1Q Tag breakdown (32 bits):
+------------------+-----+----------------------+
| TPID (16 bits)   | PCP | DEI |  VLAN ID (12b)  |
| always 0x8100    | (3) | (1) |  0-4095         |
+------------------+-----+----------------------+
  TPID: Tag Protocol Identifier, marks this as an 802.1Q tag
  PCP:  Priority Code Point -- 802.1p QoS priority (0-7)
  DEI:  Drop Eligible Indicator -- congestion-management hint
  VLAN ID: identifies which of up to 4,094 usable VLANs (0 and 4095 reserved)</pre>

      <p class="pg-sub" style="margin-top:20px">VLAN types</p>
      <div id="vlan-types"></div>

      <p class="pg-sub" style="margin-top:20px">Trunking and propagation protocols</p>
      <div id="vlan-trunk"></div>

      <p class="pg-sub" style="margin-top:20px">Common VLAN ID ranges</p>
      <table class="mono" style="width:100%;border-collapse:collapse;font-size:.82rem">
        <tr><td><strong>VLAN ID</strong></td><td><strong>Usage</strong></td></tr>
        ${VLAN_COMMON_IDS.map((v) => `<tr><td>${v.id}</td><td style="font-family:inherit">${v.use}</td></tr>`).join("")}
      </table>

      <p class="pg-sub" style="margin-top:20px">Best practices</p>
      <ul class="muted" style="line-height:1.8">
        <li>Never use VLAN 1 for user or management traffic -- change the native VLAN on trunks to an unused ID.</li>
        <li>Disable unused switch ports and assign them to a dedicated "black hole" VLAN.</li>
        <li>Keep management traffic on a VLAN that's inaccessible from user/guest VLANs.</li>
        <li>Explicitly prune VLANs from trunks that don't need them, rather than allowing all VLANs by default.</li>
        <li>Disable Dynamic Trunking Protocol (DTP) on access ports to prevent VLAN hopping via switch spoofing.</li>
        <li>Use Private VLANs or ACLs to restrict lateral movement within large flat VLANs (e.g. guest Wi-Fi, DMZ hosts).</li>
        <li>Document a consistent VLAN numbering scheme (e.g. matching VLAN ID to subnet third octet) to reduce operational error.</li>
      </ul>
    </div>`;

  root.querySelector("#vlan-types").innerHTML = VLAN_TYPES.map((v) => `
    <div class="card" style="margin-bottom:8px;padding:12px 14px">
      <strong>${escapeHtml(v.name)}</strong>
      <p class="muted" style="margin:4px 0 0">${escapeHtml(v.desc)}</p>
    </div>`).join("");

  root.querySelector("#vlan-trunk").innerHTML = VLAN_TRUNKING.map((v) => `
    <div class="card" style="margin-bottom:8px;padding:12px 14px">
      <strong>${escapeHtml(v.name)}</strong>
      <p class="muted" style="margin:4px 0 0">${escapeHtml(v.desc)}</p>
    </div>`).join("");
}

// ---------------------------------------------------------------------------
//  Tool 15 -- Routing Protocol Comparison
// ---------------------------------------------------------------------------

const ROUTING_PROTOCOLS = [
  {
    name: "RIP (v1/v2)", type: "Interior Gateway Protocol (IGP)", algorithm: "Distance-vector",
    metric: "Hop count (max 15 hops -- 16 = unreachable)", convergence: "Slow (periodic updates every 30s, minutes to converge)",
    scalability: "Small networks only (hop-count limit)", authentication: "None (v1); plaintext or MD5 (v2)",
    adminDistance: "120", notes: "Simple to configure but limited by the 15-hop maximum and slow convergence via periodic full-table broadcasts. Largely obsolete in enterprise networks, though still seen in small/legacy environments and some labs.",
  },
  {
    name: "OSPF", type: "Interior Gateway Protocol (IGP)", algorithm: "Link-state (Dijkstra SPF)",
    metric: "Cost (based on interface bandwidth)", convergence: "Fast (event-driven, sub-second to seconds with tuning)",
    scalability: "Large networks via hierarchical areas (Area 0 backbone + non-backbone areas)", authentication: "None, plaintext, or MD5/SHA (v2); IPsec (v3 for IPv6)",
    adminDistance: "110", notes: "The dominant open-standard IGP for enterprise and service-provider networks. Uses areas to control LSA flooding scope and improve scalability; supports equal-cost multi-path (ECMP) load balancing.",
  },
  {
    name: "EIGRP", type: "Interior Gateway Protocol (IGP)", algorithm: "Advanced distance-vector (DUAL algorithm)",
    metric: "Composite (bandwidth, delay, reliability, load)", convergence: "Very fast (DUAL pre-computes backup feasible successors)",
    scalability: "Large networks, especially Cisco-centric", authentication: "MD5 or HMAC-SHA2",
    adminDistance: "90 (internal) / 170 (external)", notes: "Originally Cisco-proprietary, opened as an IETF informational RFC (7868) in 2016 but remains almost exclusively deployed on Cisco gear. Combines distance-vector simplicity with near-link-state convergence speed via DUAL's feasible successor concept.",
  },
  {
    name: "IS-IS", type: "Interior Gateway Protocol (IGP)", algorithm: "Link-state (Dijkstra SPF)",
    metric: "Cost (configurable, default often based on bandwidth)", convergence: "Fast (event-driven, similar to OSPF)",
    scalability: "Very large networks, hierarchical Level 1/Level 2 areas", authentication: "Plaintext, MD5, or HMAC-SHA",
    adminDistance: "115", notes: "Protocol-agnostic at Layer 2 (runs directly over the data link layer, not IP), making it naturally dual-stack for IPv4/IPv6. Heavily used by large service providers and carriers for its scalability and stability; less common in typical enterprise networks than OSPF.",
  },
  {
    name: "BGP (BGP-4)", type: "Exterior Gateway Protocol (EGP)", algorithm: "Path-vector",
    metric: "Path attributes (AS-path length, local preference, MED, origin, etc.)", convergence: "Slow relative to IGPs (can take minutes across the global internet)",
    scalability: "Internet-scale (900,000+ routes in the global routing table)", authentication: "TCP-MD5 (RFC 2385) or TCP-AO (RFC 5925)",
    adminDistance: "20 (eBGP) / 200 (iBGP)", notes: "The routing protocol that holds the internet together, exchanging reachability information between autonomous systems. Policy-driven rather than purely metric-driven -- routing decisions are heavily influenced by business relationships (peering, transit, customer routes) expressed through path attributes and route filtering.",
  },
];

function renderRoutingComparison(root) {
  root.innerHTML = `
    <div class="panel">
      <p class="muted">Side-by-side comparison of the major interior (IGP) and exterior (EGP) routing protocols:
      algorithm type, metric, convergence behavior, scalability, and administrative distance (Cisco default
      values, used to arbitrate between multiple protocols advertising a route to the same destination).</p>
      <div style="overflow-x:auto">
        <table class="mono" style="width:100%;border-collapse:collapse;font-size:.78rem;min-width:900px">
          <tr>
            <td><strong>Protocol</strong></td><td><strong>Type</strong></td><td><strong>Algorithm</strong></td>
            <td><strong>Metric</strong></td><td><strong>Convergence</strong></td><td><strong>Scalability</strong></td>
            <td><strong>Authentication</strong></td><td><strong>Admin Distance</strong></td>
          </tr>
          ${ROUTING_PROTOCOLS.map((p) => `
            <tr>
              <td><strong>${p.name}</strong></td><td style="font-family:inherit">${p.type}</td><td style="font-family:inherit">${p.algorithm}</td>
              <td style="font-family:inherit">${p.metric}</td><td style="font-family:inherit">${p.convergence}</td><td style="font-family:inherit">${p.scalability}</td>
              <td style="font-family:inherit">${p.authentication}</td><td>${p.adminDistance}</td>
            </tr>`).join("")}
        </table>
      </div>

      <p class="pg-sub" style="margin-top:22px">Protocol details</p>
      <div id="routing-detail"></div>

      <p class="pg-sub" style="margin-top:22px">Administrative distance reference (Cisco defaults)</p>
      <p class="muted">When a router learns a route to the same destination from multiple sources, it prefers the
      route with the lowest administrative distance, regardless of the metric within that protocol.</p>
      <table class="mono" style="width:100%;border-collapse:collapse;font-size:.82rem">
        <tr><td><strong>Source</strong></td><td><strong>Default AD</strong></td></tr>
        <tr><td>Connected interface</td><td>0</td></tr>
        <tr><td>Static route</td><td>1</td></tr>
        <tr><td>eBGP</td><td>20</td></tr>
        <tr><td>EIGRP (internal)</td><td>90</td></tr>
        <tr><td>OSPF</td><td>110</td></tr>
        <tr><td>IS-IS</td><td>115</td></tr>
        <tr><td>RIP</td><td>120</td></tr>
        <tr><td>EIGRP (external)</td><td>170</td></tr>
        <tr><td>iBGP</td><td>200</td></tr>
        <tr><td>Unreachable / unknown</td><td>255 (never used)</td></tr>
      </table>

      <p class="pg-sub" style="margin-top:22px">Distance-vector vs link-state vs path-vector</p>
      <ul class="muted" style="line-height:1.8">
        <li><strong>Distance-vector</strong> (RIP): routers share their entire routing table with directly connected neighbors periodically -- "routing by rumor." Simple but slow to converge and prone to routing loops without countermeasures (split horizon, route poisoning, holddown timers).</li>
        <li><strong>Link-state</strong> (OSPF, IS-IS): each router builds a complete map of the network topology by flooding link-state advertisements, then independently computes shortest paths via Dijkstra's algorithm. Faster convergence, more CPU/memory intensive.</li>
        <li><strong>Advanced distance-vector / hybrid</strong> (EIGRP): retains distance-vector's simplicity but pre-computes backup routes (feasible successors) for near-instant failover, approaching link-state convergence speed.</li>
        <li><strong>Path-vector</strong> (BGP): similar to distance-vector but tracks the entire AS-path traversed, enabling loop prevention at the autonomous-system level and rich policy-based route selection.</li>
      </ul>
    </div>`;

  root.querySelector("#routing-detail").innerHTML = ROUTING_PROTOCOLS.map((p) => `
    <div class="card" style="margin-bottom:8px;padding:12px 14px">
      <strong>${escapeHtml(p.name)}</strong>
      <p class="muted" style="margin:4px 0 0">${escapeHtml(p.notes)}</p>
    </div>`).join("");
}

// ---------------------------------------------------------------------------
//  Tab registry + main entry point
// ---------------------------------------------------------------------------

const TABS = [
  { id: "subnet", label: "Subnet Calculator", render: renderSubnetCalculator },
  { id: "ipinfo", label: "IP Address Info", render: renderIpInfo },
  { id: "cidrrange", label: "CIDR to IP Range", render: renderCidrRange },
  { id: "ipv6", label: "IPv4 to IPv6", render: renderIpv6Converter },
  { id: "mac", label: "MAC Address Lookup", render: renderMacLookup },
  { id: "dns", label: "DNS Record Reference", render: renderDnsReference },
  { id: "http", label: "HTTP Status Codes", render: renderHttpReference },
  { id: "ports", label: "Port Reference", render: renderPortReference },
  { id: "osi", label: "Protocol Analyzer", render: renderProtocolAnalyzer },
  { id: "bandwidth", label: "Bandwidth Calculator", render: renderBandwidthCalculator },
  { id: "mtu", label: "MTU Calculator", render: renderMtuCalculator },
  { id: "tcpflags", label: "TCP Flags", render: renderTcpFlags },
  { id: "packets", label: "Packet Headers", render: renderPacketVisualizer },
  { id: "vlan", label: "VLAN Reference", render: renderVlanReference },
  { id: "routing", label: "Routing Protocols", render: renderRoutingComparison },
];

/**
 * Mounts the full Network Tools suite into `main`.
 * Builds a tab bar across the top and renders exactly one tool's panel below it
 * at a time. Each tool owns its own DOM subtree and event listeners, torn down
 * and rebuilt fresh whenever the active tab changes.
 */
export function renderNetworkTools(main) {
  main.innerHTML = `
    <div class="dash-hero">
      <div class="eyebrow">Darknode / Reference</div>
      <h1 class="pg-h1">Network Tools</h1>
      <p class="pg-sub">Subnet math, protocol references, and packet-level reference material -- all computed
      locally in your browser. ${TABS.length} tools covering IPv4/IPv6 addressing, DNS, HTTP, ports, OSI/TCP-IP
      layering, bandwidth and MTU math, TCP internals, and routing protocols.</p>
    </div>
    <div class="tab-bar" id="nt-tabs"></div>
    <div id="nt-content" class="card" style="padding:20px;margin-top:14px"></div>`;

  const tabBar = main.querySelector("#nt-tabs");
  const content = main.querySelector("#nt-content");

  tabBar.innerHTML = TABS.map((t, i) => `<button class="tab${i === 0 ? " active" : ""}" data-id="${t.id}">${t.label}</button>`).join("");

  const activate = (id) => {
    const tab = TABS.find((t) => t.id === id) || TABS[0];
    tabBar.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b.dataset.id === tab.id));
    content.innerHTML = "";
    tab.render(content);
    if (history.replaceState) {
      const url = new URL(location.href);
      url.hash = `network-tools/${tab.id}`;
      history.replaceState(null, "", url);
    }
  };

  tabBar.onclick = (e) => {
    const btn = e.target.closest("button[data-id]"); if (!btn) return;
    activate(btn.dataset.id);
  };

  // Deep-link support: #network-tools/<tab-id>
  const hashTab = (location.hash || "").split("/")[1];
  activate(hashTab && TABS.some((t) => t.id === hashTab) ? hashTab : TABS[0].id);
}
