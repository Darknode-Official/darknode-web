import { esc } from '/js/shared.js';

const DE_RECORD_TYPES = ['A','AAAA','MX','NS','TXT','CNAME','SOA','SRV','PTR','CAA'];

// Real lookups over DNS-over-HTTPS (JSON API). Google first, Cloudflare as fallback.
const DE_DOH = [
  (n, t, extra) => `https://dns.google/resolve?name=${encodeURIComponent(n)}&type=${t}${extra || ''}`,
  (n, t, extra) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=${t}${extra || ''}`
];
const DE_TYPE_NUM = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33, DS: 43, RRSIG: 46, DNSKEY: 48, CAA: 257 };
const DE_ALGOS = { 5: 'RSASHA1', 7: 'RSASHA1-NSEC3-SHA1', 8: 'RSASHA256', 10: 'RSASHA512', 13: 'ECDSAP256SHA256', 14: 'ECDSAP384SHA384', 15: 'ED25519', 16: 'ED448' };
const DE_DIGESTS = { 1: 'SHA-1', 2: 'SHA-256', 4: 'SHA-384' };

async function _deDoh(name, type, extra) {
  let lastErr = null;
  for (const u of DE_DOH) {
    try {
      const r = await fetch(u(name, type, extra), { headers: { accept: 'application/dns-json' } });
      if (!r.ok) { lastErr = new Error('HTTP ' + r.status); continue; }
      return await r.json();
    } catch (e) { lastErr = e; }
  }
  throw lastErr || new Error('DoH lookup failed');
}

function _deAnswers(json, type) {
  const num = DE_TYPE_NUM[type];
  return ((json && json.Answer) || []).filter(a => a.type === num);
}

function _deStripDot(s) { return String(s || '').replace(/\.$/, ''); }

function _deParseAnswer(type, a) {
  const name = _deStripDot(a.name);
  const ttl = a.TTL;
  const d = String(a.data || '');
  if (type === 'MX') { const p = d.split(/\s+/); return { name, ttl, priority: parseInt(p[0], 10), value: _deStripDot(p[1] || d) }; }
  if (type === 'SRV') { const p = d.split(/\s+/); return { name, ttl, priority: parseInt(p[0], 10), weight: p[1], port: p[2], value: _deStripDot(p[3] || d) }; }
  if (type === 'CAA') { const m = d.match(/^(\d+)\s+(\S+)\s+"?(.*?)"?$/); return m ? { name, ttl, flag: m[1], tag: m[2], value: m[3] } : { name, ttl, value: d }; }
  if (type === 'TXT') return { name, ttl, value: d.replace(/^"|"$/g, '').replace(/"\s*"/g, '') };
  return { name, ttl, value: _deStripDot(d) };
}

async function _deDohRecords(domain) {
  const records = {};
  const q = async (name, type) => {
    try { return _deAnswers(await _deDoh(name, type), type).map(a => _deParseAnswer(type, a)); }
    catch { return []; }
  };
  const [A, AAAA, MX, NS, TXT, SOA, CAA, dmarc, cnApex, cnWww] = await Promise.all([
    q(domain, 'A'), q(domain, 'AAAA'), q(domain, 'MX'), q(domain, 'NS'), q(domain, 'TXT'),
    q(domain, 'SOA'), q(domain, 'CAA'), q('_dmarc.' + domain, 'TXT'), q(domain, 'CNAME'), q('www.' + domain, 'CNAME')
  ]);
  const srvNames = ['_sip._tcp', '_sips._tcp', '_xmpp-server._tcp', '_xmpp-client._tcp', '_ldap._tcp', '_autodiscover._tcp', '_caldavs._tcp'];
  const srv = (await Promise.all(srvNames.map(s => q(s + '.' + domain, 'SRV')))).flat();
  let PTR = [];
  if (A.length) {
    const rev = A[0].value.split('.').reverse().join('.') + '.in-addr.arpa';
    PTR = await q(rev, 'PTR');
  }
  Object.assign(records, { A, AAAA, MX, NS, TXT: TXT.concat(dmarc), CNAME: cnApex.concat(cnWww), SOA, SRV: srv, PTR, CAA });
  return records;
}

async function _deDohSubdomains(domain) {
  const prefixes = ['www','mail','ftp','api','dev','staging','admin','vpn','remote','portal','app','blog','cdn','docs','m','shop','status','support','test','webmail','smtp','git','sso','login','beta'];
  const out = await Promise.all(prefixes.map(async p => {
    const full = p + '.' + domain;
    try {
      const j = await _deDoh(full, 'A');
      const a = _deAnswers(j, 'A');
      if (a.length) return { subdomain: full, status: 'FOUND', ip: a[0].data, ports: [], headers: null };
      return { subdomain: full, status: j.Status === 3 ? 'NXDOMAIN' : 'NO A RECORD', ip: null, ports: [], headers: null };
    } catch { return { subdomain: full, status: 'LOOKUP FAILED', ip: null, ports: [], headers: null }; }
  }));
  return out.sort((a,b) => (b.status==='FOUND'?1:0)-(a.status==='FOUND'?1:0) || a.subdomain.localeCompare(b.subdomain));
}

// A browser cannot open raw TCP/53 connections, so AXFR is not attempted here.
function _deZoneTransferInfo(domain, nsRecords) {
  const ns = (nsRecords || []).map(r => r.value).filter(Boolean);
  return {
    tested: false,
    success: false,
    records: [],
    nameservers: ns,
    server: ns[0] || '',
    message: 'Not tested. A zone transfer (AXFR) needs a raw TCP connection to port 53 on each nameserver, which a web browser cannot open. Run the commands below from a terminal, or connect the local agent.'
  };
}

// Real DNSSEC check: DS (parent) and DNSKEY (zone) via validating DoH resolvers, reading the AD flag.
async function _deDNSSECReal(domain) {
  try {
    const [ds, dk, a] = await Promise.all([
      _deDoh(domain, 'DS', '&do=1&cd=0'),
      _deDoh(domain, 'DNSKEY', '&do=1&cd=0'),
      _deDoh(domain, 'SOA', '&do=1&cd=0')
    ]);
    const dsAns = _deAnswers(ds, 'DS');
    const dkAns = _deAnswers(dk, 'DNSKEY');
    const rrsig = _deAnswers(a, 'RRSIG').length > 0 || _deAnswers(dk, 'RRSIG').length > 0;
    const ad = !!(a.AD || dk.AD);
    const servfail = a.Status === 2 || dk.Status === 2;
    const hasDS = dsAns.length > 0, hasKey = dkAns.length > 0;
    let status, message, recommendation;
    if (servfail && hasDS) {
      status = 'BOGUS';
      message = 'The validating resolver returned SERVFAIL while a DS record exists at the parent. This usually means the DNSSEC chain is broken (validation failure).';
      recommendation = 'Check that the DNSKEY published in the zone matches the DS record at the registrar, and that signatures (RRSIG) have not expired.';
    } else if (ad && hasDS && hasKey) {
      status = 'SECURE';
      message = 'The resolver validated the answer (AD flag set). DS is published at the parent and DNSKEY records are present.';
      recommendation = 'DNSSEC is working. Monitor key rollovers and signature expiry.';
    } else if (hasKey && !hasDS) {
      status = 'INSECURE';
      message = 'The zone publishes DNSKEY records but no DS record exists at the parent, so resolvers cannot validate it (island of security).';
      recommendation = 'Publish the DS record for your key-signing key at your registrar to complete the chain of trust.';
    } else if (!hasDS && !hasKey) {
      status = 'UNSIGNED';
      message = 'No DS or DNSKEY records found. The domain is not signed with DNSSEC.';
      recommendation = 'Enable DNSSEC signing with your DNS provider, then publish the DS record at your registrar.';
    } else {
      status = 'INDETERMINATE';
      message = 'DNSSEC records were found but the resolver did not set the AD flag. Validation could not be confirmed from here.';
      recommendation = 'Verify with a local validating resolver: dig +dnssec ' + domain + ' SOA, or use dnsviz.net.';
    }
    const firstDS = dsAns[0] ? String(dsAns[0].data).split(/\s+/) : null;
    const ksk = dkAns.map(k => String(k.data).split(/\s+/)).find(p => p[0] === '257') || (dkAns[0] ? String(dkAns[0].data).split(/\s+/) : null);
    return {
      checked: true,
      signed: hasDS || hasKey,
      status, message, recommendation, ad,
      algorithm: firstDS ? (DE_ALGOS[firstDS[1]] || 'alg ' + firstDS[1]) : ksk ? (DE_ALGOS[ksk[2]] || 'alg ' + ksk[2]) : '-',
      keyTag: firstDS ? firstDS[0] : '-',
      digestType: firstDS ? (DE_DIGESTS[firstDS[2]] || 'type ' + firstDS[2]) : '-',
      dsCount: dsAns.length, dnskeyCount: dkAns.length,
      chain: [
        { zone: domain + '.', status, ds: hasDS, dnskey: hasKey, rrsig }
      ]
    };
  } catch (e) {
    return {
      checked: false, signed: false, status: 'ERROR', chain: [],
      message: 'DNSSEC lookup failed: ' + (e && e.message ? e.message : 'network error') + '. No verdict is shown.',
      recommendation: 'Retry, or check from a terminal: dig +dnssec ' + domain + ' DNSKEY'
    };
  }
}

function _deFormatTTL(ttl) {
  if (ttl >= 86400) return `${ttl} (${(ttl/86400).toFixed(0)}d)`;
  if (ttl >= 3600) return `${ttl} (${(ttl/3600).toFixed(0)}h)`;
  if (ttl >= 60) return `${ttl} (${(ttl/60).toFixed(0)}m)`;
  return `${ttl}s`;
}

function _deExportJSON(data, filename) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

function _deExportCSV(rows, headers, filename) {
  let csv = headers.join(',') + '\n';
  for (const r of rows) csv += headers.map(h => `"${String(r[h]||'').replace(/"/g,'""')}"`).join(',') + '\n';
  const blob = new Blob([csv], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

export function renderDNSEnum(container) {
  let activeTab = 'records';
  let currentDomain = '';
  let recordsData = null;
  let subdomainData = null;
  let zoneData = null;
  let dnssecData = null;
  let scanLive = false;

  container.innerHTML = `<style>
.de-wrap{font-family:'JetBrains Mono','Fira Code',monospace;background:#0a0e14;color:#c8d6e5;min-height:100vh;padding:24px}
.de-header{display:flex;align-items:center;gap:16px;margin-bottom:24px;padding:20px 24px;background:linear-gradient(135deg,#0c1220 0%,#0f1a2e 100%);border:1px solid #1a2a44;border-radius:10px}
.de-logo{width:48px;height:48px;border-radius:10px;background:linear-gradient(135deg,#00aaff,#0066cc);display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:700;color:#fff}
.de-title{font-size:22px;font-weight:700;color:#e2e8f0}
.de-subtitle{font-size:13px;color:#4a7a9b;margin-top:2px}
.de-input-row{display:flex;gap:12px;margin-bottom:20px;align-items:center;flex-wrap:wrap}
.de-input{flex:1;min-width:240px;background:#0c1220;border:1px solid #1a2a44;color:#e2e8f0;padding:10px 16px;border-radius:8px;font-family:inherit;font-size:14px;outline:none;transition:border-color .2s}
.de-input:focus{border-color:#00aaff}
.de-input::placeholder{color:#3a5a7a}
.de-btn{padding:10px 20px;border:none;border-radius:4px;font-family:inherit;font-size:13px;font-weight:600;cursor:pointer;transition:all .2s}
.de-btn-primary{background:#00aaff;color:#0a0e14}
.de-btn-primary:hover{background:#33bbff;transform:translateY(-1px)}
.de-btn-secondary{background:#1a2a44;color:#c8d6e5;border:1px solid #283a5a}
.de-btn-secondary:hover{background:#243448}
.de-tabs{display:flex;gap:4px;margin-bottom:20px;background:#0c1220;padding:4px;border-radius:10px;border:1px solid #1a2a44;flex-wrap:wrap}
.de-tab{padding:10px 20px;border:none;background:transparent;color:#4a7a9b;font-family:inherit;font-size:13px;font-weight:600;cursor:pointer;border-radius:4px;transition:all .2s}
.de-tab:hover{color:#c8d6e5;background:#111828}
.de-tab.active{background:#00aaff;color:#0a0e14}
.de-panel{background:#0c1220;border:1px solid #1a2a44;border-radius:10px;padding:20px;margin-bottom:16px}
.de-panel-title{font-size:15px;font-weight:700;color:#e2e8f0;margin-bottom:14px;display:flex;align-items:center;gap:8px}
.de-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700}
.de-badge-ok{background:#00ff8820;color:#00ff88;border:1px solid #00ff8840}
.de-badge-warn{background:#ffaa0020;color:#ffaa00;border:1px solid #ffaa0040}
.de-badge-err{background:#ff444420;color:#ff4444;border:1px solid #ff444440}
.de-badge-info{background:#00aaff20;color:#00aaff;border:1px solid #00aaff40}
.de-table{width:100%;border-collapse:collapse;font-size:13px}
.de-table th{text-align:left;padding:10px 14px;background:#111828;color:#00aaff;font-weight:600;border-bottom:2px solid #1a2a44;white-space:nowrap}
.de-table td{padding:9px 14px;border-bottom:1px solid #1a2a4480;color:#c8d6e5;word-break:break-all}
.de-table tr:hover td{background:#111828}
.de-record-type{display:inline-block;min-width:52px;text-align:center;padding:2px 8px;border-radius:4px;font-weight:700;font-size:11px;background:#00aaff15;color:#00aaff;border:1px solid #00aaff30}
.de-type-A{color:#00ff88;background:#00ff8815;border-color:#00ff8830}
.de-type-AAAA{color:#00ddff;background:#00ddff15;border-color:#00ddff30}
.de-type-MX{color:#ff9f43;background:#ff9f4315;border-color:#ff9f4330}
.de-type-NS{color:#a29bfe;background:#a29bfe15;border-color:#a29bfe30}
.de-type-TXT{color:#ffeaa7;background:#ffeaa715;border-color:#ffeaa730}
.de-type-CNAME{color:#fd79a8;background:#fd79a815;border-color:#fd79a830}
.de-type-SOA{color:#636e72;background:#636e7215;border-color:#636e7230}
.de-type-SRV{color:#e17055;background:#e1705515;border-color:#e1705530}
.de-type-PTR{color:#74b9ff;background:#74b9ff15;border-color:#74b9ff30}
.de-type-CAA{color:#55efc4;background:#55efc415;border-color:#55efc430}
.de-found{color:#00ff88}
.de-notfound{color:#ff4444}
.de-progress{width:100%;height:6px;background:#1a2a44;border-radius:3px;margin:12px 0;overflow:hidden}
.de-progress-bar{height:100%;background:linear-gradient(90deg,#00aaff,#00ff88);border-radius:3px;transition:width .3s}
.de-status-line{font-size:12px;color:#4a7a9b;margin:8px 0}
.de-chain{display:flex;flex-direction:column;gap:8px;margin-top:12px}
.de-chain-node{display:flex;align-items:center;gap:12px;padding:12px 16px;background:#111828;border-radius:8px;border-left:3px solid #1a2a44}
.de-chain-node.secure{border-left-color:#00ff88}
.de-chain-node.insecure{border-left-color:#ff4444}
.de-chain-node.bogus{border-left-color:#ffaa00}
.de-chain-zone{font-weight:700;color:#e2e8f0;min-width:140px}
.de-chain-checks{display:flex;gap:8px;flex-wrap:wrap}
.de-chain-check{font-size:11px;padding:2px 8px;border-radius:4px}
.de-chain-check.pass{background:#00ff8815;color:#00ff88}
.de-chain-check.fail{background:#ff444415;color:#ff4444}
.de-zone-record{padding:6px 12px;background:#111828;border-radius:6px;margin-bottom:4px;font-size:13px;display:flex;gap:12px;align-items:center;border-left:2px solid #1a2a44}
.de-zone-name{color:#00aaff;min-width:200px;word-break:break-all}
.de-zone-type{min-width:50px;font-weight:700}
.de-zone-ttl{color:#4a7a9b;min-width:60px}
.de-zone-value{color:#c8d6e5;word-break:break-all}
.de-ref-section{margin-bottom:20px}
.de-ref-title{font-size:14px;font-weight:700;color:#00aaff;margin-bottom:10px}
.de-ref-item{padding:10px 14px;background:#111828;border-radius:6px;margin-bottom:6px;border-left:3px solid #00aaff30}
.de-ref-item-title{font-weight:600;color:#e2e8f0;margin-bottom:4px}
.de-ref-item-desc{font-size:12px;color:#8ab4d0;line-height:1.6}
.de-ref-code{font-family:inherit;background:#0a0e14;color:#00ff88;padding:2px 6px;border-radius:3px;font-size:12px}
.de-empty{text-align:center;padding:40px 20px;color:#3a5a7a;font-size:14px}
.de-filter-row{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px}
.de-filter{padding:4px 12px;border:1px solid #1a2a44;background:#0c1220;color:#4a7a9b;border-radius:4px;font-family:inherit;font-size:11px;cursor:pointer;transition:all .2s}
.de-filter.active{background:#00aaff;color:#0a0e14;border-color:#00aaff}
.de-filter:hover{border-color:#00aaff}
.de-stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px}
.de-stat{background:#111828;padding:12px 18px;border-radius:8px;border:1px solid #1a2a44;min-width:120px}
.de-stat-val{font-size:22px;font-weight:700;color:#00ff88}
.de-stat-label{font-size:11px;color:#4a7a9b;margin-top:2px}
.de-export-row{display:flex;gap:8px;justify-content:flex-end;margin-top:14px;flex-wrap:wrap}
.de-vuln-banner{padding:14px 18px;border-radius:8px;margin-bottom:14px;display:flex;align-items:center;gap:12px;font-size:13px;font-weight:600}
.de-vuln-banner.danger{background:#ff444418;border:1px solid #ff444440;color:#ff6b6b}
.de-vuln-banner.safe{background:#00ff8818;border:1px solid #00ff8840;color:#00ff88}
@media(max-width:768px){.de-wrap{padding:12px}.de-header{flex-direction:column;text-align:center}.de-input-row{flex-direction:column}.de-input{min-width:auto}.de-table td,.de-table th{padding:6px 8px;font-size:12px}.de-zone-record{flex-direction:column;gap:4px}.de-zone-name{min-width:auto}}
</style>
<div class="de-wrap">
  <div class="de-header">
    <div class="de-logo">DNS</div>
    <div>
      <div class="de-title">DNS Enumeration Toolkit</div>
      <div class="de-subtitle">Live DNS record lookup over DNS-over-HTTPS, common-subdomain check &amp; DNSSEC check</div>
    </div>
  </div>
  <div class="de-input-row">
    <input class="de-input" id="deTarget" placeholder="Enter domain (e.g. example.com)" spellcheck="false">
    <button class="de-btn de-btn-primary" id="deScan">Enumerate</button>
  </div>
  <div class="de-tabs" id="deTabs">
    <button class="de-tab active" data-tab="records">Records</button>
    <button class="de-tab" data-tab="subdomains">Subdomains</button>
    <button class="de-tab" data-tab="zonetransfer">Zone Transfer</button>
    <button class="de-tab" data-tab="dnssec">DNSSEC</button>
    <button class="de-tab" data-tab="reference">Reference</button>
  </div>
  <div id="deContent"><div class="de-empty">Enter a domain above and click Enumerate to begin DNS analysis</div></div>
</div>`;

  const wrap = container.querySelector('.de-wrap');
  const inp = wrap.querySelector('#deTarget');
  const scanBtn = wrap.querySelector('#deScan');
  const tabBar = wrap.querySelector('#deTabs');
  const content = wrap.querySelector('#deContent');

  function switchTab(tab) {
    activeTab = tab;
    tabBar.querySelectorAll('.de-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
    renderContent();
  }

  tabBar.addEventListener('click', e => {
    const t = e.target.closest('.de-tab');
    if (t) switchTab(t.dataset.tab);
  });

  inp.addEventListener('keydown', e => { if (e.key === 'Enter') runScan(); });
  scanBtn.addEventListener('click', runScan);

  function _deSafe(s) { return String(s).replace(/[^a-zA-Z0-9.\-]/g, ''); }

  async function _deLiveRecords(domain) {
    const b = window._bridge;
    const records = {};
    const types = ['A','AAAA','MX','NS','TXT','CNAME','SOA','SRV','CAA'];
    for (const t of types) {
      try {
        const r = await b.exec('dig +short ' + t + ' ' + _deSafe(domain));
        const lines = (r.stdout || '').trim().split('\n').filter(l => l.trim());
        if (!lines.length) { records[t] = []; continue; }
        records[t] = lines.map(l => {
          if (t === 'MX') { const p = l.split(/\s+/); return { name: domain, ttl: 300, priority: parseInt(p[0])||10, value: p[1]||l }; }
          return { name: domain, ttl: 300, value: l.trim().replace(/\.$/,'') };
        });
      } catch { records[t] = []; }
    }
    return records;
  }

  async function _deLiveSubs(domain) {
    const b = window._bridge;
    const found = [];
    if (b.hasTool('subfinder')) {
      try {
        const r = await b.exec('subfinder -d ' + _deSafe(domain) + ' -silent 2>/dev/null | head -50');
        (r.stdout || '').trim().split('\n').filter(l => l.trim()).forEach(s => found.push({ name: s.trim(), ip: '-', status: 'found' }));
      } catch {}
    }
    if (!found.length) {
      const prefixes = ['www','mail','ftp','api','dev','admin','vpn','app','cdn','blog','portal','staging','test','docs','m'];
      for (const p of prefixes) {
        try {
          const r = await b.exec('dig +short A ' + _deSafe(p + '.' + domain));
          const ip = (r.stdout || '').trim().split('\n').map(function(l) { return l.trim(); }).find(function(l) { return /^\d+\.\d+\.\d+\.\d+$/.test(l); });
          if (ip) found.push({ name: p + '.' + domain, ip, status: 'resolved' });
        } catch {}
      }
    }
    return found;
  }

  async function _deLiveAXFR(domain, nsRecords) {
    const b = window._bridge;
    const ns = (nsRecords || []).map(r => r.value).filter(Boolean).slice(0, 4);
    if (!ns.length) return _deZoneTransferInfo(domain, nsRecords);
    for (const server of ns) {
      try {
        const r = await b.exec('dig axfr @' + _deSafe(server) + ' ' + _deSafe(domain) + ' +time=5 +tries=1');
        const out = r.stdout || '';
        const lines = out.split('\n').filter(l => l.trim() && !l.startsWith(';'));
        if (lines.length > 2 && !/Transfer failed/i.test(out)) {
          const records = lines.map(l => {
            const p = l.split(/\s+/);
            return { name: _deStripDot(p[0]), ttl: parseInt(p[1], 10) || 0, type: p[3] || '?', value: p.slice(4).join(' ') };
          });
          return { tested: true, success: true, server, nameservers: ns, records, message: 'Zone transfer succeeded from ' + server + ': ' + records.length + ' records retrieved.' };
        }
      } catch {}
    }
    return { tested: true, success: false, server: ns.join(', '), nameservers: ns, records: [], message: 'Transfer refused or failed on all tested nameservers (' + ns.join(', ') + ').' };
  }

  async function runScan() {
    const domain = inp.value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*/, '');
    if (!domain || !domain.includes('.')) return;
    currentDomain = domain;

    const isLive = window._bridge && window._bridge.connected && window._bridge.hasTool('dig');
    scanLive = true;
    const modeTag = isLive
      ? '<span style="color:#22c55e;font-size:11px;font-weight:700;margin-left:8px">[LOCAL AGENT]</span>'
      : '<span style="color:#22c55e;font-size:11px;font-weight:700;margin-left:8px">[DNS-over-HTTPS]</span>';

    content.innerHTML = `<div class="de-panel"><div class="de-panel-title">Scanning ${esc(domain)}...${modeTag}</div><div class="de-progress"><div class="de-progress-bar" style="width:0%"></div></div><div class="de-status-line" id="deStatusLine">Initializing...</div></div>`;
    const bar = content.querySelector('.de-progress-bar');
    const status = content.querySelector('#deStatusLine');

    if (isLive) {
      status.textContent = 'Querying DNS records (local agent)...';
      bar.style.width = '20%';
      recordsData = await _deLiveRecords(domain);
      bar.style.width = '45%';
      status.textContent = 'Enumerating subdomains (local agent)...';
      subdomainData = (await _deLiveSubs(domain)).map(s => ({ subdomain: s.name, status: 'FOUND', ip: s.ip && s.ip !== '-' ? s.ip : null, ports: [], headers: null }));
      bar.style.width = '70%';
      status.textContent = 'Attempting zone transfer (dig axfr)...';
      zoneData = await _deLiveAXFR(domain, recordsData.NS);
    } else {
      status.textContent = 'Querying DNS records over DNS-over-HTTPS...';
      bar.style.width = '20%';
      recordsData = await _deDohRecords(domain);
      bar.style.width = '50%';
      status.textContent = 'Checking common subdomain names...';
      subdomainData = await _deDohSubdomains(domain);
      bar.style.width = '75%';
      zoneData = _deZoneTransferInfo(domain, recordsData.NS);
    }
    status.textContent = 'Checking DNSSEC (DS / DNSKEY / AD flag)...';
    dnssecData = await _deDNSSECReal(domain);
    bar.style.width = '100%';
    status.textContent = 'Complete';

    renderContent();
  }

  function renderContent() {
    if (!currentDomain) {
      if (activeTab === 'reference') { renderReference(); return; }
      content.innerHTML = '<div class="de-empty">Enter a domain above and click Enumerate to begin DNS analysis</div>';
      return;
    }
    switch (activeTab) {
      case 'records': renderRecords(); break;
      case 'subdomains': renderSubdomains(); break;
      case 'zonetransfer': renderZoneTransfer(); break;
      case 'dnssec': renderDNSSECTab(); break;
      case 'reference': renderReference(); break;
    }
  }

  let activeFilter = 'ALL';

  function sendDnsToGraph(btn) {
    const tags = ['dns', scanLive ? 'live' : 'simulated'];
    const meta = { simulated: !scanLive, scannedAt: new Date().toISOString() };
    const items = [];
    for (const r of (recordsData?.A || []).concat(recordsData?.AAAA || [])) {
      items.push({ type: 'IP', name: r.value, data: { ...meta, record: r.name }, opts: { tags } });
    }
    for (const sd of (subdomainData || []).filter(x => x.status === 'FOUND')) {
      items.push({ type: 'DOMAIN', name: sd.subdomain, data: { ...meta, ip: sd.ip || '', ports: (sd.ports || []).join(',') }, opts: { tags: tags.concat('subdomain') } });
      if (sd.ip) items.push({ type: 'IP', name: sd.ip, data: { ...meta, record: sd.subdomain }, opts: { tags } });
    }
    const axfrOpen = zoneData && zoneData.success && zoneData.records.length;
    btn.disabled = true;
    import('/js/graph-bridge.js?v=20260923c').then(gb => {
      const root = gb.sendToGraph('DNS Enum', [{ type: 'DOMAIN', name: currentDomain, data: { ...meta, axfrOpen: !!axfrOpen }, opts: { tags, severity: axfrOpen ? 'high' : null } }], undefined, true).entities[0];
      const r = gb.sendToGraph('DNS Enum', items, undefined, true);
      if (root) {
        for (const e of r.entities) if (e.id !== root.id) gb.linkEntities(root.id, e.id, 'related_to');
        if (axfrOpen) {
          const f = gb.sendToGraph('DNS Enum', [{ type: 'FINDING', name: 'Zone transfer (AXFR) permitted on ' + currentDomain, data: { ...meta, server: zoneData.server, recordsExposed: zoneData.records.length }, opts: { tags, severity: 'high' } }], undefined, true).entities[0];
          if (f) gb.linkEntities(f.id, root.id, 'affects');
        }
      }
      btn.textContent = 'Sent ' + (r.entities.length + 1) + ' entities' + (scanLive ? '' : ' (tagged simulated)');
      gb.showGraphToast('Security Graph: ' + (r.created + (root ? 1 : 0)) + ' entities from ' + currentDomain + (axfrOpen ? ', 1 finding' : ''));
    }).catch(() => { btn.textContent = 'Security Graph unavailable'; btn.disabled = false; });
  }

  function graphBtnHTML() {
    return `<button class="de-btn de-btn-primary" id="deToGraph" title="Live DNS results">Send to Security Graph</button>`;
  }

  function renderRecords() {
    if (!recordsData) { content.innerHTML = '<div class="de-empty">No data — run a scan first</div>'; return; }
    let totalRecords = 0;
    for (const t of DE_RECORD_TYPES) totalRecords += (recordsData[t]||[]).length;

    let html = `<div class="de-stats">
      <div class="de-stat"><div class="de-stat-val">${totalRecords}</div><div class="de-stat-label">Total Records</div></div>
      <div class="de-stat"><div class="de-stat-val">${DE_RECORD_TYPES.filter(t=>(recordsData[t]||[]).length>0).length}</div><div class="de-stat-label">Record Types</div></div>
      <div class="de-stat"><div class="de-stat-val">${(recordsData.TXT||[]).length}</div><div class="de-stat-label">TXT Entries</div></div>
    </div>`;

    html += `<div class="de-filter-row">
      <button class="de-filter ${activeFilter==='ALL'?'active':''}" data-f="ALL">All</button>
      ${DE_RECORD_TYPES.map(t => `<button class="de-filter ${activeFilter===t?'active':''}" data-f="${t}">${t} (${(recordsData[t]||[]).length})</button>`).join('')}
    </div>`;

    html += `<div class="de-panel"><table class="de-table"><thead><tr><th>Type</th><th>Name</th><th>TTL</th><th>Value</th></tr></thead><tbody>`;
    for (const type of DE_RECORD_TYPES) {
      if (activeFilter !== 'ALL' && activeFilter !== type) continue;
      for (const r of (recordsData[type]||[])) {
        let val = esc(r.value);
        if (r.priority !== undefined) val = `<span style="color:#ff9f43">${r.priority}</span> ${val}`;
        if (r.port !== undefined) val = `<span style="color:#4a7a9b">w:${r.weight} p:${r.port}</span> ${val}`;
        if (r.tag) val = `<span style="color:#4a7a9b">${r.flag} ${esc(r.tag)}</span> ${esc(r.value)}`;
        html += `<tr><td><span class="de-record-type de-type-${type}">${type}</span></td><td>${esc(r.name)}</td><td style="color:#4a7a9b">${_deFormatTTL(r.ttl)}</td><td>${val}</td></tr>`;
      }
    }
    html += `</tbody></table></div>`;

    html += `<div class="de-export-row">
      <button class="de-btn de-btn-secondary" id="deExportRecJSON">Export JSON</button>
      <button class="de-btn de-btn-secondary" id="deExportRecCSV">Export CSV</button>
      ${graphBtnHTML()}
    </div>`;

    content.innerHTML = html;
    content.querySelector('#deToGraph')?.addEventListener('click', e => sendDnsToGraph(e.currentTarget));

    content.querySelectorAll('.de-filter').forEach(f => f.addEventListener('click', () => {
      activeFilter = f.dataset.f;
      renderRecords();
    }));

    content.querySelector('#deExportRecJSON')?.addEventListener('click', () => {
      _deExportJSON({ domain: currentDomain, records: recordsData }, `dns-records-${currentDomain}.json`);
    });
    content.querySelector('#deExportRecCSV')?.addEventListener('click', () => {
      const rows = [];
      for (const type of DE_RECORD_TYPES) for (const r of (recordsData[type]||[])) rows.push({ type, name: r.name, ttl: r.ttl, value: r.value, priority: r.priority||'' });
      _deExportCSV(rows, ['type','name','ttl','value','priority'], `dns-records-${currentDomain}.csv`);
    });
  }

  function renderSubdomains() {
    if (!subdomainData) { content.innerHTML = '<div class="de-empty">No data — run a scan first</div>'; return; }
    const found = subdomainData.filter(s => s.status === 'FOUND');
    const nf = subdomainData.filter(s => s.status !== 'FOUND');

    let html = `<div class="de-stats">
      <div class="de-stat"><div class="de-stat-val">${subdomainData.length}</div><div class="de-stat-label">Tested</div></div>
      <div class="de-stat"><div class="de-stat-val" style="color:#00ff88">${found.length}</div><div class="de-stat-label">Found</div></div>
      <div class="de-stat"><div class="de-stat-val" style="color:#ff4444">${nf.length}</div><div class="de-stat-label">Not Found</div></div>
    </div>`;

    html += `<div class="de-panel"><div class="de-panel-title">Discovered Subdomains <span class="de-badge de-badge-ok">${found.length} alive</span></div>
    <div class="de-status-line" style="margin-bottom:10px">Checks a short list of common names by DNS lookup only. Ports and web servers are not probed.</div>
    <table class="de-table"><thead><tr><th>Subdomain</th><th>Status</th><th>IP</th></tr></thead><tbody>`;
    for (const s of subdomainData) {
      const cls = s.status === 'FOUND' ? 'de-found' : 'de-notfound';
      html += `<tr>
        <td>${esc(s.subdomain)}</td>
        <td><span class="${cls}">${esc(s.status)}</span></td>
        <td>${s.ip ? esc(s.ip) : '-'}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;

    html += `<div class="de-export-row">
      <button class="de-btn de-btn-secondary" id="deExportSubJSON">Export JSON</button>
      <button class="de-btn de-btn-secondary" id="deExportSubCSV">Export CSV</button>
      ${graphBtnHTML()}
    </div>`;

    content.innerHTML = html;
    content.querySelector('#deToGraph')?.addEventListener('click', e => sendDnsToGraph(e.currentTarget));
    content.querySelector('#deExportSubJSON')?.addEventListener('click', () => {
      _deExportJSON({ domain: currentDomain, subdomains: subdomainData }, `subdomains-${currentDomain}.json`);
    });
    content.querySelector('#deExportSubCSV')?.addEventListener('click', () => {
      const rows = subdomainData.map(s => ({ subdomain: s.subdomain, status: s.status, ip: s.ip||'' }));
      _deExportCSV(rows, ['subdomain','status','ip'], `subdomains-${currentDomain}.csv`);
    });
  }

  function renderZoneTransfer() {
    if (!zoneData) { content.innerHTML = '<div class="de-empty">No data — run a scan first</div>'; return; }

    let html = '';
    if (!zoneData.tested) {
      html += `<div class="de-panel"><div class="de-panel-title">AXFR <span class="de-badge de-badge-warn">NOT TESTED</span></div>
      <div class="de-status-line">${esc(zoneData.message)}</div>`;
      if (zoneData.nameservers.length) {
        html += `<div class="de-panel-title" style="margin-top:14px">Nameservers found (${zoneData.nameservers.length})</div>`;
        for (const ns of zoneData.nameservers) {
          html += `<div class="de-zone-record"><span class="de-zone-name">${esc(ns)}</span><span class="de-zone-value"><span class="de-ref-code">dig axfr @${esc(ns)} ${esc(currentDomain)}</span></span></div>`;
        }
      } else {
        html += `<div class="de-status-line" style="margin-top:10px">No NS records were returned for ${esc(currentDomain)}. Try the parent zone or check the domain name.</div>`;
      }
      html += `</div>`;
    } else {
      if (zoneData.success) {
        html += `<div class="de-vuln-banner danger">VULNERABILITY: Zone transfer (AXFR) permitted on ${esc(zoneData.server)}: ${zoneData.records.length} records exposed</div>`;
      } else {
        html += `<div class="de-vuln-banner safe">Zone transfer refused by the tested nameservers</div>`;
      }
      html += `<div class="de-panel"><div class="de-panel-title">AXFR Query (local agent) <span class="de-badge ${zoneData.success?'de-badge-err':'de-badge-ok'}">${zoneData.success?'VULNERABLE':'REFUSED'}</span></div>
      <div class="de-status-line">${esc(zoneData.message)}</div>`;
      if (zoneData.success && zoneData.records.length) {
        html += `<div style="margin-top:14px">`;
        for (const r of zoneData.records) {
          html += `<div class="de-zone-record">
            <span class="de-zone-name">${esc(r.name)}</span>
            <span class="de-zone-type"><span class="de-record-type de-type-${esc(r.type)}">${esc(r.type)}</span></span>
            <span class="de-zone-ttl">${_deFormatTTL(r.ttl)}</span>
            <span class="de-zone-value">${esc(r.value)}</span>
          </div>`;
        }
        html += `</div>`;
      }
      html += `</div>`;
    }

    html += `<div class="de-panel"><div class="de-panel-title">Remediation</div>
    <div class="de-ref-item"><div class="de-ref-item-title">Restrict AXFR</div><div class="de-ref-item-desc">Configure your DNS server to allow zone transfers only to authorized secondary nameservers:<br><span class="de-ref-code">allow-transfer { 192.168.1.2; 10.0.0.5; };</span> (BIND9)<br><span class="de-ref-code">Set-DnsServerPrimaryZone -Name domain.com -SecureSecondaries TransferToSecureServers</span> (Windows DNS)</div></div>
    <div class="de-ref-item"><div class="de-ref-item-title">Use TSIG</div><div class="de-ref-item-desc">Authenticate zone transfers with Transaction SIGnatures (TSIG) to prevent unauthorized AXFR even from allowed IPs.</div></div>
    </div>`;

    content.innerHTML = html;
  }

  function renderDNSSECTab() {
    if (!dnssecData) { content.innerHTML = '<div class="de-empty">No data — run a scan first</div>'; return; }

    const statusBadge = dnssecData.status === 'SECURE' ? 'de-badge-ok' : (dnssecData.status === 'BOGUS' || dnssecData.status === 'ERROR') ? 'de-badge-err' : 'de-badge-warn';

    let html = `<div class="de-panel"><div class="de-panel-title">DNSSEC Check <span class="de-badge ${statusBadge}">${esc(dnssecData.status)}</span></div>
    <div class="de-status-line" style="margin-bottom:14px">${esc(dnssecData.message)}</div>`;

    if (dnssecData.checked) {
      html += `<div class="de-stats">
        <div class="de-stat"><div class="de-stat-val" style="font-size:14px;color:${dnssecData.ad?'#00ff88':'#ff9f43'}">${dnssecData.ad?'SET':'NOT SET'}</div><div class="de-stat-label">AD flag</div></div>
        <div class="de-stat"><div class="de-stat-val" style="font-size:14px;color:#00aaff">${dnssecData.dsCount}</div><div class="de-stat-label">DS records</div></div>
        <div class="de-stat"><div class="de-stat-val" style="font-size:14px;color:#00aaff">${dnssecData.dnskeyCount}</div><div class="de-stat-label">DNSKEY records</div></div>
      </div>`;
      if (dnssecData.signed) {
        html += `<div class="de-stats">
          <div class="de-stat"><div class="de-stat-val" style="font-size:14px;color:#00aaff">${esc(dnssecData.algorithm)}</div><div class="de-stat-label">Algorithm</div></div>
          <div class="de-stat"><div class="de-stat-val" style="font-size:14px;color:#00aaff">${esc(dnssecData.keyTag)}</div><div class="de-stat-label">DS Key Tag</div></div>
          <div class="de-stat"><div class="de-stat-val" style="font-size:14px;color:#00aaff">${esc(dnssecData.digestType)}</div><div class="de-stat-label">DS Digest</div></div>
        </div>`;
      }
      html += `<div class="de-panel-title" style="margin-top:16px">Zone</div><div class="de-chain">`;
      for (const node of dnssecData.chain) {
        const cls = node.status === 'SECURE' ? 'secure' : node.status === 'BOGUS' ? 'bogus' : 'insecure';
        html += `<div class="de-chain-node ${cls}">
          <span class="de-chain-zone">${esc(node.zone)}</span>
          <span class="de-badge ${statusBadge}">${esc(node.status)}</span>
          <div class="de-chain-checks">
            <span class="de-chain-check ${node.ds?'pass':'fail'}">DS ${node.ds?'Y':'N'}</span>
            <span class="de-chain-check ${node.dnskey?'pass':'fail'}">DNSKEY ${node.dnskey?'Y':'N'}</span>
            <span class="de-chain-check ${node.rrsig?'pass':'fail'}">RRSIG ${node.rrsig?'Y':'N'}</span>
          </div>
        </div>`;
      }
      html += `</div><div class="de-status-line" style="margin-top:10px">Checked through public validating DNS-over-HTTPS resolvers (dns.google, cloudflare-dns.com).</div>`;
    }
    html += `</div>`;

    html += `<div class="de-panel"><div class="de-panel-title">Recommendation</div>
    <div class="de-ref-item"><div class="de-ref-item-desc">${esc(dnssecData.recommendation)}</div></div></div>`;

    content.innerHTML = html;
  }

  function renderReference() {
    content.innerHTML = `
    <div class="de-panel">
      <div class="de-panel-title">DNS Record Types Reference</div>
      <div class="de-ref-section">
        <div class="de-ref-item"><div class="de-ref-item-title"><span class="de-record-type de-type-A">A</span> Address Record</div><div class="de-ref-item-desc">Maps a domain name to an IPv4 address. The most fundamental DNS record type. Example: <span class="de-ref-code">example.com. 300 IN A 93.184.216.34</span></div></div>
        <div class="de-ref-item"><div class="de-ref-item-title"><span class="de-record-type de-type-AAAA">AAAA</span> IPv6 Address</div><div class="de-ref-item-desc">Maps a domain to an IPv6 address. Essential for IPv6-enabled infrastructure. Example: <span class="de-ref-code">example.com. 300 IN AAAA 2606:2800:220:1:248:1893:25c8:1946</span></div></div>
        <div class="de-ref-item"><div class="de-ref-item-title"><span class="de-record-type de-type-MX">MX</span> Mail Exchange</div><div class="de-ref-item-desc">Specifies mail servers for the domain, with priority values (lower = preferred). Example: <span class="de-ref-code">example.com. 3600 IN MX 10 mail.example.com.</span></div></div>
        <div class="de-ref-item"><div class="de-ref-item-title"><span class="de-record-type de-type-NS">NS</span> Name Server</div><div class="de-ref-item-desc">Delegates a DNS zone to authoritative name servers. Critical for DNS infrastructure. Example: <span class="de-ref-code">example.com. 86400 IN NS ns1.example.com.</span></div></div>
        <div class="de-ref-item"><div class="de-ref-item-title"><span class="de-record-type de-type-TXT">TXT</span> Text Record</div><div class="de-ref-item-desc">Stores arbitrary text. Commonly used for SPF, DKIM, DMARC, domain verification, and security policies. Example: <span class="de-ref-code">example.com. 3600 IN TXT "v=spf1 include:_spf.google.com ~all"</span></div></div>
        <div class="de-ref-item"><div class="de-ref-item-title"><span class="de-record-type de-type-CNAME">CNAME</span> Canonical Name</div><div class="de-ref-item-desc">Creates an alias pointing one domain to another. Cannot coexist with other records at the same name. Example: <span class="de-ref-code">www.example.com. 3600 IN CNAME example.com.</span></div></div>
        <div class="de-ref-item"><div class="de-ref-item-title"><span class="de-record-type de-type-SOA">SOA</span> Start of Authority</div><div class="de-ref-item-desc">Contains administrative information about the zone: primary NS, admin email, serial number, refresh/retry/expire timers.</div></div>
        <div class="de-ref-item"><div class="de-ref-item-title"><span class="de-record-type de-type-SRV">SRV</span> Service Locator</div><div class="de-ref-item-desc">Specifies hostname and port for specific services (SIP, XMPP, LDAP). Format: <span class="de-ref-code">_service._proto.name TTL IN SRV priority weight port target</span></div></div>
        <div class="de-ref-item"><div class="de-ref-item-title"><span class="de-record-type de-type-PTR">PTR</span> Pointer Record</div><div class="de-ref-item-desc">Reverse DNS lookup — maps an IP address back to a hostname. Used for email verification and security auditing.</div></div>
        <div class="de-ref-item"><div class="de-ref-item-title"><span class="de-record-type de-type-CAA">CAA</span> Certification Authority Authorization</div><div class="de-ref-item-desc">Specifies which CAs are allowed to issue certificates for the domain. Helps prevent unauthorized certificate issuance.</div></div>
      </div>
    </div>
    <div class="de-panel">
      <div class="de-panel-title">DNS over HTTPS (DoH)</div>
      <div class="de-ref-section">
        <div class="de-ref-item"><div class="de-ref-item-title">What is DoH?</div><div class="de-ref-item-desc">DNS over HTTPS encrypts DNS queries inside HTTPS connections to port 443, preventing eavesdropping and manipulation of DNS traffic. Queries use the <span class="de-ref-code">application/dns-message</span> or <span class="de-ref-code">application/dns-json</span> content type.</div></div>
        <div class="de-ref-item"><div class="de-ref-item-title">Public DoH Resolvers</div><div class="de-ref-item-desc">
          <span class="de-ref-code">https://cloudflare-dns.com/dns-query</span> — Cloudflare (1.1.1.1)<br>
          <span class="de-ref-code">https://dns.google/dns-query</span> — Google (8.8.8.8)<br>
          <span class="de-ref-code">https://dns.quad9.net/dns-query</span> — Quad9 (9.9.9.9)<br>
          <span class="de-ref-code">https://doh.opendns.com/dns-query</span> — OpenDNS (Cisco)
        </div></div>
        <div class="de-ref-item"><div class="de-ref-item-title">DoH Query Example</div><div class="de-ref-item-desc">
          <span class="de-ref-code">curl -s "https://cloudflare-dns.com/dns-query?name=example.com&type=A" -H "Accept: application/dns-json" | jq</span><br><br>
          Or with the wire format:<br>
          <span class="de-ref-code">curl -s "https://dns.google/resolve?name=example.com&type=MX" | jq '.Answer[]'</span>
        </div></div>
        <div class="de-ref-item"><div class="de-ref-item-title">Security Implications</div><div class="de-ref-item-desc">
          <strong>Pros:</strong> Encrypts DNS queries, prevents ISP/network-level DNS monitoring, blocks DNS spoofing attacks.<br>
          <strong>Cons:</strong> Centralizes DNS to a few providers, can bypass enterprise DNS policies, harder to monitor for threat hunting.
        </div></div>
      </div>
    </div>
    <div class="de-panel">
      <div class="de-panel-title">Common Enumeration Commands</div>
      <div class="de-ref-section">
        <div class="de-ref-item"><div class="de-ref-item-title">dig</div><div class="de-ref-item-desc">
          <span class="de-ref-code">dig example.com ANY +noall +answer</span> — Query all record types<br>
          <span class="de-ref-code">dig @ns1.example.com example.com AXFR</span> — Attempt zone transfer<br>
          <span class="de-ref-code">dig +dnssec example.com</span> — Query with DNSSEC validation<br>
          <span class="de-ref-code">dig +trace example.com</span> — Trace full resolution path
        </div></div>
        <div class="de-ref-item"><div class="de-ref-item-title">nslookup</div><div class="de-ref-item-desc">
          <span class="de-ref-code">nslookup -type=any example.com</span> — All records<br>
          <span class="de-ref-code">nslookup -type=mx example.com 8.8.8.8</span> — MX via Google DNS
        </div></div>
        <div class="de-ref-item"><div class="de-ref-item-title">host</div><div class="de-ref-item-desc">
          <span class="de-ref-code">host -a example.com</span> — Verbose all records<br>
          <span class="de-ref-code">host -t axfr example.com ns1.example.com</span> — Zone transfer attempt
        </div></div>
        <div class="de-ref-item"><div class="de-ref-item-title">dnsrecon</div><div class="de-ref-item-desc">
          <span class="de-ref-code">dnsrecon -d example.com -t std</span> — Standard enumeration<br>
          <span class="de-ref-code">dnsrecon -d example.com -t brt -D subdomains.txt</span> — Brute force subdomains
        </div></div>
      </div>
    </div>`;
  }
}
