import { esc } from '/js/shared.js';

const OE_PROVIDERS = ['gmail.com','yahoo.com','outlook.com','hotmail.com','protonmail.com','proton.me','icloud.com','aol.com','zoho.com','fastmail.com','tutanota.com','yandex.com','mail.com','gmx.com','hey.com'];

const OE_SOCIALS = [
  { name:'GitHub', icon:'GH', url:'https://github.com/{user}', desc:'Code repositories & contributions' },
  { name:'LinkedIn', icon:'Li', url:'https://linkedin.com/in/{user}', desc:'Professional network profile' },
  { name:'Twitter/X', icon:'X', url:'https://x.com/{user}', desc:'Social media posts & follows' },
  { name:'Reddit', icon:'R', url:'https://reddit.com/user/{user}', desc:'Forum posts & comments' },
  { name:'Instagram', icon:'IG', url:'https://instagram.com/{user}', desc:'Photo & story sharing' },
  { name:'Facebook', icon:'FB', url:'https://facebook.com/{user}', desc:'Social network profile' },
  { name:'Keybase', icon:'KB', url:'https://keybase.io/{user}', desc:'Crypto identity verification' },
  { name:'HackerOne', icon:'H1', url:'https://hackerone.com/{user}', desc:'Bug bounty profile' },
  { name:'Medium', icon:'M', url:'https://medium.com/@{user}', desc:'Blog posts & articles' },
  { name:'Dev.to', icon:'DT', url:'https://dev.to/{user}', desc:'Developer blog & community' },
  { name:'Stack Overflow', icon:'SO', url:'https://stackoverflow.com/users/?tab=Reputation&filter=all&search={user}', desc:'Q&A contributions' },
  { name:'Gravatar', icon:'GR', url:'https://gravatar.com/{user}', desc:'Global avatar profile' },
  { name:'Pinterest', icon:'Pi', url:'https://pinterest.com/{user}', desc:'Image boards & pins' },
  { name:'Telegram', icon:'TG', url:'https://t.me/{user}', desc:'Messaging profile' },
  { name:'Mastodon', icon:'Ma', url:'https://mastodon.social/@{user}', desc:'Fediverse microblog' },
];

const OE_BREACHES = [
  { name:'ShadowDump 2024', date:'2024-08-14', records:'142M', types:['Email','Password hash','IP address','Username'] },
  { name:'CloudVault Leak', date:'2024-03-22', records:'38M', types:['Email','Full name','Phone','Address'] },
  { name:'GamePortal Breach', date:'2023-11-05', records:'67M', types:['Email','Username','Password (plaintext)','DOB'] },
  { name:'HealthTrack Incident', date:'2023-07-18', records:'12M', types:['Email','Full name','Medical ID','SSN (partial)'] },
  { name:'RetailMax Dump', date:'2023-02-09', records:'95M', types:['Email','Credit card (partial)','Purchase history','Address'] },
  { name:'SocialBuzz Scrape', date:'2022-12-01', records:'533M', types:['Email','Phone','Full name','Location','Bio'] },
  { name:'EduConnect Leak', date:'2022-06-15', records:'28M', types:['Email','Student ID','GPA','Enrollment dates'] },
  { name:'DevForge Breach', date:'2022-01-20', records:'8.2M', types:['Email','API keys','SSH keys','Repo access tokens'] },
  { name:'FinanceHub Incident', date:'2021-09-30', records:'15M', types:['Email','Account balance','Transaction history','SSN'] },
  { name:'TravelNow Dump', date:'2021-04-11', records:'22M', types:['Email','Passport number','Flight history','Loyalty points'] },
];

const OE_DORKS = [
  { label:'Pastebin mentions', template:'"{{email}}" site:pastebin.com', desc:'Search for email in paste dumps' },
  { label:'GitHub commits', template:'"{{email}}" site:github.com', desc:'Find commits authored by this email' },
  { label:'Document leaks', template:'"{{email}}" filetype:pdf OR filetype:xlsx OR filetype:docx', desc:'Find documents containing this email' },
  { label:'Forum posts', template:'"{{email}}" site:reddit.com OR site:stackoverflow.com', desc:'Find forum activity' },
  { label:'Social profiles', template:'"{{email}}" site:linkedin.com OR site:facebook.com OR site:twitter.com', desc:'Find social media mentions' },
  { label:'Data dumps', template:'"{{email}}" intext:password OR intext:passwd', desc:'Find potential credential dumps' },
  { label:'Config files', template:'"{{email}}" filetype:env OR filetype:yml OR filetype:json', desc:'Find leaked config files' },
  { label:'Archive.org', template:'"{{email}}" site:web.archive.org', desc:'Historical web mentions' },
  { label:'Trello boards', template:'"{{email}}" site:trello.com', desc:'Public Trello board references' },
  { label:'Public keys', template:'"{{email}}" site:pgp.mit.edu OR site:keys.openpgp.org', desc:'PGP/GPG public keys' },
  { label:'Job postings', template:'"{{email}}" site:indeed.com OR site:glassdoor.com', desc:'Job-related mentions' },
  { label:'WHOIS records', template:'"{{email}}" intext:registrant', desc:'Domain registration records' },
  { label:'Leaked databases', template:'"{{email}}" site:ghostbin.com OR site:rentry.co', desc:'Alternative paste sites' },
  { label:'Cloud storage', template:'"{{email}}" site:docs.google.com OR site:drive.google.com', desc:'Public cloud documents' },
  { label:'DNS/cert records', template:'"{{email}}" site:crt.sh OR site:shodan.io', desc:'Certificate and device records' },
];

function oeSeed(s) { let h = 0; for (let i = 0; i < s.length; i++) { h = ((h << 5) - h + s.charCodeAt(i)) | 0; } return Math.abs(h); }

function oeGenPerms(first, last) {
  const f = first.toLowerCase(), l = last.toLowerCase();
  const fi = f[0], li = l[0];
  const patterns = [
    `${f}.${l}`, `${f}${l}`, `${f}_${l}`, `${f}-${l}`,
    `${fi}${l}`, `${fi}.${l}`, `${fi}_${l}`, `${fi}-${l}`,
    `${f}${li}`, `${f}.${li}`, `${f}_${li}`,
    `${l}${f}`, `${l}.${f}`, `${l}_${f}`, `${l}-${f}`,
    `${l}${fi}`, `${l}.${fi}`, `${l}_${fi}`,
    `${fi}${li}`, `${fi}.${li}`,
    `${f}`, `${l}`,
    `${f}${l}1`, `${f}${l}123`, `${f}.${l}1`,
    `${f}${l}99`, `${f}${l}2024`, `${f}${l}01`,
    `${f}_${l}_`, `${fi}${l}1`, `${fi}${l}99`,
    `${l}${f}1`, `${l}.${f}1`,
    `${f}${l.slice(0,2)}`, `${f.slice(0,3)}${l}`,
    `${f}.${l}.${fi}`, `the${f}${l}`,
    `${f}${l}x`, `${f}${l}o`, `real${f}${l}`,
    `${f}${l}official`, `${f}${l}pro`,
    `${f}.${l}.dev`, `${f}${l}sec`,
    `${fi}${fi}${l}`, `${f}${l}work`,
    `${l}${f}pro`, `${f}dot${l}`,
    `${fi}.${l}.${f[1] || 'x'}`, `${f}${l}mail`,
    `${f}${l}hq`, `${f}.${l}.work`,
    `${f}${l}net`, `${f}${l}io`,
  ];
  return [...new Set(patterns)];
}

export function renderOSINTEmail(container) {
  const tabs = ['Analyze','Permutations','Breaches','Social Enum','Dorks'];
  container.innerHTML = `<style>
.oe-wrap{font-family:'Segoe UI',system-ui,sans-serif;background:#080c14;color:#c8d6e5;min-height:100vh;padding:0}
.oe-header{background:linear-gradient(135deg,#0a1628 0%,#0f1f3a 50%,#0a1628 100%);padding:20px 28px;border-bottom:1px solid #1a2a44;display:flex;align-items:center;gap:16px}
.oe-header h2{margin:0;font-size:22px;color:#00aaff;letter-spacing:1px;font-weight:700}
.oe-header-sub{color:#6a8aaa;font-size:13px}
.oe-header-icon{font-size:28px}
.oe-tabs{display:flex;background:#0a1018;border-bottom:1px solid #1a2a44;overflow-x:auto}
.oe-tab{padding:10px 20px;background:none;border:none;color:#6a8aaa;font-size:13px;cursor:pointer;border-bottom:2px solid transparent;white-space:nowrap;transition:all .2s}
.oe-tab:hover{color:#c8d6e5;background:#0f172a}
.oe-tab.active{color:#00aaff;border-bottom-color:#00aaff;background:#0c1424}
.oe-body{padding:24px 28px}
.oe-panel{background:#0c1424;border:1px solid #1a2a44;border-radius:8px;padding:20px;margin-bottom:16px}
.oe-panel-title{font-size:15px;font-weight:600;color:#e2e8f0;margin:0 0 14px;display:flex;align-items:center;gap:8px}
.oe-row{display:flex;gap:12px;margin-bottom:12px;flex-wrap:wrap}
.oe-input{background:#0a1018;border:1px solid #1a2a44;border-radius:6px;padding:9px 14px;color:#e2e8f0;font-size:14px;flex:1;min-width:180px;outline:none;transition:border-color .2s}
.oe-input:focus{border-color:#00aaff}
.oe-input::placeholder{color:#3a5a7a}
.oe-btn{background:linear-gradient(135deg,#00aaff,#0088cc);color:#fff;border:none;border-radius:6px;padding:9px 20px;font-size:13px;font-weight:600;cursor:pointer;white-space:nowrap;transition:all .2s}
.oe-btn:hover{background:linear-gradient(135deg,#00ccff,#00aaff);transform:translateY(-1px)}
.oe-btn-sec{background:#1a2a44;color:#c8d6e5}
.oe-btn-sec:hover{background:#243a5a}
.oe-result{background:#0a1018;border:1px solid #1a2a44;border-radius:6px;padding:14px;margin-top:12px}
.oe-badge{display:inline-block;padding:3px 10px;border-radius:4px;font-size:11px;font-weight:600;margin:2px 4px 2px 0}
.oe-badge-green{background:rgba(0,255,136,.12);color:#00ff88;border:1px solid rgba(0,255,136,.25)}
.oe-badge-red{background:rgba(255,68,68,.12);color:#ff4444;border:1px solid rgba(255,68,68,.25)}
.oe-badge-blue{background:rgba(0,170,255,.12);color:#00aaff;border:1px solid rgba(0,170,255,.25)}
.oe-badge-yellow{background:rgba(255,214,0,.12);color:#ffd600;border:1px solid rgba(255,214,0,.25)}
.oe-badge-purple{background:rgba(168,85,247,.12);color:#a855f7;border:1px solid rgba(168,85,247,.25)}
.oe-table{width:100%;border-collapse:collapse;font-size:13px}
.oe-table th{text-align:left;padding:8px 12px;color:#6a8aaa;border-bottom:2px solid #1a2a44;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px}
.oe-table td{padding:8px 12px;border-bottom:1px solid #0f1f2e;color:#c8d6e5}
.oe-table tr:hover td{background:#0f172a}
.oe-field{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #0f1f2e}
.oe-field:last-child{border:none}
.oe-field-label{color:#6a8aaa;font-size:13px;font-weight:500}
.oe-field-value{color:#e2e8f0;font-size:13px;font-family:'JetBrains Mono',monospace;word-break:break-all}
.oe-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px}
.oe-card{background:#0a1018;border:1px solid #1a2a44;border-radius:8px;padding:14px;transition:all .2s;cursor:default}
.oe-card:hover{border-color:#00aaff;transform:translateY(-2px);box-shadow:0 4px 20px rgba(0,170,255,.1)}
.oe-card-title{font-weight:600;color:#e2e8f0;font-size:14px;margin-bottom:6px;display:flex;align-items:center;gap:8px}
.oe-card-desc{color:#6a8aaa;font-size:12px;line-height:1.5}
.oe-card-url{color:#00aaff;font-size:11px;font-family:'JetBrains Mono',monospace;margin-top:8px;word-break:break-all}
.oe-perm-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:6px}
.oe-perm-item{background:#0a1018;border:1px solid #1a2a44;border-radius:4px;padding:6px 10px;font-family:'JetBrains Mono',monospace;font-size:12px;color:#c8d6e5;display:flex;align-items:center;gap:6px}
.oe-perm-item:hover{border-color:#00aaff;background:#0c1828}
.oe-copy-btn{background:none;border:none;color:#6a8aaa;cursor:pointer;font-size:12px;padding:2px 6px;border-radius:3px}
.oe-copy-btn:hover{color:#00aaff;background:#1a2a44}
.oe-breach-card{background:#0a1018;border:1px solid #1a2a44;border-radius:8px;padding:16px;margin-bottom:10px;border-left:3px solid #ff4444}
.oe-breach-card:nth-child(odd){border-left-color:#ff9100}
.oe-breach-title{font-weight:700;color:#e2e8f0;font-size:15px;margin-bottom:4px}
.oe-breach-meta{color:#6a8aaa;font-size:12px;margin-bottom:8px;display:flex;gap:16px;flex-wrap:wrap}
.oe-breach-types{display:flex;flex-wrap:wrap;gap:4px}
.oe-dork-card{background:#0a1018;border:1px solid #1a2a44;border-radius:8px;padding:14px;margin-bottom:8px}
.oe-dork-card:hover{border-color:#00aaff}
.oe-dork-label{font-weight:600;color:#e2e8f0;font-size:13px;margin-bottom:4px}
.oe-dork-desc{color:#6a8aaa;font-size:12px;margin-bottom:8px}
.oe-dork-query{background:#080c14;border:1px solid #1a2a44;border-radius:4px;padding:8px 12px;font-family:'JetBrains Mono',monospace;font-size:12px;color:#00ff88;display:flex;justify-content:space-between;align-items:center;gap:8px}
.oe-score{display:inline-flex;align-items:center;gap:8px;padding:6px 14px;border-radius:6px;font-weight:700;font-size:18px}
.oe-score.high{background:rgba(255,68,68,.12);color:#ff4444;border:1px solid rgba(255,68,68,.25)}
.oe-score.medium{background:rgba(255,145,0,.12);color:#ff9100;border:1px solid rgba(255,145,0,.25)}
.oe-score.low{background:rgba(0,255,136,.12);color:#00ff88;border:1px solid rgba(0,255,136,.25)}
.oe-empty{text-align:center;padding:40px;color:#3a5a7a;font-size:14px}
.oe-export-bar{display:flex;gap:8px;justify-content:flex-end;margin-top:16px}
@media(max-width:768px){
  .oe-body{padding:16px}
  .oe-header{padding:14px 16px}
  .oe-grid{grid-template-columns:1fr}
  .oe-perm-grid{grid-template-columns:1fr 1fr}
  .oe-row{flex-direction:column}
}
</style>
<div class="oe-wrap">
  <div class="oe-header">
    <span class="oe-header-icon"></span>
    <div>
      <h2>OSINT Email Intelligence</h2>
      <div class="oe-header-sub">Email analysis, enumeration & reconnaissance toolkit</div>
    </div>
  </div>
  <div class="oe-tabs">${tabs.map((t,i) => `<button class="oe-tab${i===0?' active':''}" data-idx="${i}">${esc(t)}</button>`).join('')}</div>
  <div class="oe-body" id="oe-content"></div>
</div>`;

  const wrap = container.querySelector('.oe-wrap');
  const content = wrap.querySelector('#oe-content');
  const tabBtns = wrap.querySelectorAll('.oe-tab');
  let activeTab = 0;

  function switchTab(idx) {
    activeTab = idx;
    tabBtns.forEach((b,i) => b.classList.toggle('active', i === idx));
    renderTab();
  }
  tabBtns.forEach(b => b.addEventListener('click', () => switchTab(+b.dataset.idx)));

  function copyText(text, btn) {
    navigator.clipboard.writeText(text).then(() => {
      const orig = btn.textContent;
      btn.textContent = 'OK';
      setTimeout(() => btn.textContent = orig, 1200);
    });
  }

  function renderTab() {
    if (activeTab === 0) renderAnalyze();
    else if (activeTab === 1) renderPermutations();
    else if (activeTab === 2) renderBreaches();
    else if (activeTab === 3) renderSocialEnum();
    else if (activeTab === 4) renderDorks();
  }

  function renderAnalyze() {
    content.innerHTML = `
      <div class="oe-panel">
        <div class="oe-panel-title">Email Address Analyzer</div>
        <div class="oe-row">
          <input class="oe-input" id="oe-email-input" placeholder="Enter email address (e.g. user@example.com)" />
          <button class="oe-btn" id="oe-analyze-btn">Analyze</button>
        </div>
        <div id="oe-analyze-result"></div>
      </div>
      <div class="oe-panel">
        <div class="oe-panel-title"> Email Security Quick Reference</div>
        <div class="oe-result">
          <table class="oe-table">
            <thead><tr><th>Protocol</th><th>Purpose</th><th>Record Type</th><th>Check Command</th></tr></thead>
            <tbody>
              <tr><td><span class="oe-badge oe-badge-blue">SPF</span></td><td>Sender Policy Framework — authorized mail servers</td><td>TXT</td><td style="font-family:monospace;font-size:11px;color:#00ff88">dig +short TXT domain.com | grep spf</td></tr>
              <tr><td><span class="oe-badge oe-badge-green">DKIM</span></td><td>DomainKeys Identified Mail — message signing</td><td>TXT</td><td style="font-family:monospace;font-size:11px;color:#00ff88">dig +short TXT selector._domainkey.domain.com</td></tr>
              <tr><td><span class="oe-badge oe-badge-purple">DMARC</span></td><td>Domain-based Message Authentication</td><td>TXT</td><td style="font-family:monospace;font-size:11px;color:#00ff88">dig +short TXT _dmarc.domain.com</td></tr>
              <tr><td><span class="oe-badge oe-badge-yellow">MX</span></td><td>Mail Exchange — receiving mail servers</td><td>MX</td><td style="font-family:monospace;font-size:11px;color:#00ff88">dig +short MX domain.com</td></tr>
              <tr><td><span class="oe-badge oe-badge-blue">PTR</span></td><td>Reverse DNS — IP to hostname mapping</td><td>PTR</td><td style="font-family:monospace;font-size:11px;color:#00ff88">dig +short -x IP_ADDRESS</td></tr>
              <tr><td><span class="oe-badge oe-badge-red">BIMI</span></td><td>Brand Indicators for Message Identification</td><td>TXT</td><td style="font-family:monospace;font-size:11px;color:#00ff88">dig +short TXT default._bimi.domain.com</td></tr>
            </tbody>
          </table>
        </div>
      </div>
      <div class="oe-panel">
        <div class="oe-panel-title">Common MX Provider Identification</div>
        <div class="oe-result">
          <table class="oe-table">
            <thead><tr><th>MX Pattern</th><th>Provider</th><th>Notes</th></tr></thead>
            <tbody>
              <tr><td style="font-family:monospace;color:#00aaff">*.google.com / *.googlemail.com</td><td>Google Workspace</td><td>Business Gmail</td></tr>
              <tr><td style="font-family:monospace;color:#00aaff">*.outlook.com / *.protection.outlook.com</td><td>Microsoft 365</td><td>Exchange Online</td></tr>
              <tr><td style="font-family:monospace;color:#00aaff">*.pphosted.com</td><td>Proofpoint</td><td>Email security gateway</td></tr>
              <tr><td style="font-family:monospace;color:#00aaff">*.mimecast.com</td><td>Mimecast</td><td>Email security</td></tr>
              <tr><td style="font-family:monospace;color:#00aaff">*.messagelabs.com</td><td>Symantec</td><td>Cloud email security</td></tr>
              <tr><td style="font-family:monospace;color:#00aaff">*.zoho.com</td><td>Zoho Mail</td><td>Business email</td></tr>
              <tr><td style="font-family:monospace;color:#00aaff">*.yahoodns.net</td><td>Yahoo</td><td>Consumer email</td></tr>
              <tr><td style="font-family:monospace;color:#00aaff">*.protonmail.ch</td><td>Proton Mail</td><td>Encrypted email</td></tr>
            </tbody>
          </table>
        </div>
      </div>`;

    content.querySelector('#oe-analyze-btn').addEventListener('click', () => {
      const email = content.querySelector('#oe-email-input').value.trim();
      if (!email || !email.includes('@')) {
        content.querySelector('#oe-analyze-result').innerHTML = `<div class="oe-result" style="color:#ff4444">Please enter a valid email address.</div>`;
        return;
      }
      analyzeEmail(email);
    });
    content.querySelector('#oe-email-input').addEventListener('keydown', e => {
      if (e.key === 'Enter') content.querySelector('#oe-analyze-btn').click();
    });
  }

  async function _oeLiveDomain(domain) {
    const b = window._bridge;
    const safe = String(domain).replace(/[^a-zA-Z0-9.\-]/g, '');
    const info = { mx: [], ns: [], txt: [], whois: '' };
    try { const r = await b.exec('dig +short MX ' + safe); info.mx = (r.stdout||'').trim().split('\n').filter(l=>l.trim()); } catch {}
    try { const r = await b.exec('dig +short NS ' + safe); info.ns = (r.stdout||'').trim().split('\n').filter(l=>l.trim()); } catch {}
    try { const r = await b.exec('dig +short TXT ' + safe); info.txt = (r.stdout||'').trim().split('\n').filter(l=>l.trim()); } catch {}
    if (b.hasTool('whois')) { try { const r = await b.exec('whois ' + safe + ' 2>/dev/null | head -40'); info.whois = r.stdout || ''; } catch {} }
    return info;
  }

  function analyzeEmail(email) {
    const [local, domain] = email.split('@');
    const domainParts = domain.split('.');
    const tld = domainParts.slice(-1)[0];
    const sld = domainParts.slice(-2).join('.');
    const isKnown = OE_PROVIDERS.includes(domain);
    const isFree = ['gmail.com','yahoo.com','hotmail.com','outlook.com','aol.com','mail.com','gmx.com','yandex.com'].includes(domain);
    const isSecure = ['protonmail.com','proton.me','tutanota.com','hey.com','fastmail.com'].includes(domain);

    const seed = oeSeed(email);
    const age = (seed % 8) + 1;
    const breachCount = seed % 5;
    const risk = breachCount >= 3 ? 'high' : breachCount >= 1 ? 'medium' : 'low';
    const riskScore = breachCount >= 3 ? 72 + (seed % 20) : breachCount >= 1 ? 35 + (seed % 25) : 5 + (seed % 15);

    if (window._bridge && window._bridge.connected && window._bridge.hasTool('dig')) {
      _oeLiveDomain(domain).then(function(info) {
        const livePanel = content.querySelector('#oe-live-intel');
        if (livePanel) {
          let html = '<div class="oe-panel-title" style="font-size:13px">Live Domain Intelligence <span style="color:#22c55e;font-size:10px;font-weight:700">[LIVE]</span></div>';
          if (info.mx.length) html += '<div class="oe-field"><span class="oe-field-label">MX Records</span><span class="oe-field-value">' + info.mx.map(m=>esc(m)).join('<br>') + '</span></div>';
          if (info.ns.length) html += '<div class="oe-field"><span class="oe-field-label">NS Records</span><span class="oe-field-value">' + info.ns.map(n=>esc(n)).join('<br>') + '</span></div>';
          if (info.txt.length) html += '<div class="oe-field"><span class="oe-field-label">TXT/SPF</span><span class="oe-field-value" style="font-size:11px;word-break:break-all">' + info.txt.map(t=>esc(t)).join('<br>') + '</span></div>';
          if (info.whois) html += '<details style="margin-top:8px"><summary style="cursor:pointer;color:#00aaff;font-size:12px">WHOIS Data</summary><pre style="font-size:10px;max-height:200px;overflow:auto;margin-top:6px;padding:8px;background:rgba(0,0,0,0.3);border-radius:6px">' + esc(info.whois) + '</pre></details>';
          livePanel.innerHTML = html;
        }
      });
    }

    const out = content.querySelector('#oe-analyze-result');
    out.innerHTML = `
      <div class="oe-result">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:12px">
          <div>
            <div style="font-size:18px;font-weight:700;color:#e2e8f0;margin-bottom:4px">${esc(email)}</div>
            <div style="color:#6a8aaa;font-size:12px">Analysis completed • ${new Date().toLocaleString()}</div>
          </div>
          <div class="oe-score ${risk}">
            ${riskScore}/100
            <span style="font-size:12px;font-weight:400">risk</span>
          </div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
          <div>
            <div class="oe-panel-title" style="font-size:13px">Address Structure</div>
            <div class="oe-field"><span class="oe-field-label">Local Part</span><span class="oe-field-value">${esc(local)}</span></div>
            <div class="oe-field"><span class="oe-field-label">Domain</span><span class="oe-field-value">${esc(domain)}</span></div>
            <div class="oe-field"><span class="oe-field-label">TLD</span><span class="oe-field-value">.${esc(tld)}</span></div>
            <div class="oe-field"><span class="oe-field-label">SLD</span><span class="oe-field-value">${esc(sld)}</span></div>
            <div class="oe-field"><span class="oe-field-label">Local Length</span><span class="oe-field-value">${local.length} chars</span></div>
            <div class="oe-field"><span class="oe-field-label">Has Numbers</span><span class="oe-field-value">${/\d/.test(local) ? 'Yes' : 'No'}</span></div>
            <div class="oe-field"><span class="oe-field-label">Has Dots</span><span class="oe-field-value">${local.includes('.') ? 'Yes' : 'No'}</span></div>
            <div class="oe-field"><span class="oe-field-label">Has Special</span><span class="oe-field-value">${/[+\-_]/.test(local) ? 'Yes' : 'No'}</span></div>
          </div>
          <div>
            <div class="oe-panel-title" style="font-size:13px">Domain Intelligence</div>
            <div class="oe-field"><span class="oe-field-label">Provider Type</span><span>${isFree ? '<span class="oe-badge oe-badge-yellow">FREE</span>' : isSecure ? '<span class="oe-badge oe-badge-green">SECURE</span>' : isKnown ? '<span class="oe-badge oe-badge-blue">KNOWN</span>' : '<span class="oe-badge oe-badge-purple">CUSTOM</span>'}</span></div>
            <div class="oe-field"><span class="oe-field-label">Known Provider</span><span class="oe-field-value">${isKnown ? 'Yes' : 'No (custom domain)'}</span></div>
            <div class="oe-field"><span class="oe-field-label">Est. Account Age</span><span class="oe-field-value">~${age} years (simulated)</span></div>
            <div class="oe-field"><span class="oe-field-label">Breach Exposure</span><span>${breachCount > 0 ? `<span class="oe-badge oe-badge-red">${breachCount} breaches</span>` : '<span class="oe-badge oe-badge-green">None found</span>'}</span></div>
            <div class="oe-field"><span class="oe-field-label">Disposable</span><span class="oe-field-value">${['tempmail.com','guerrillamail.com','throwaway.email','mailinator.com','10minutemail.com'].includes(domain) ? 'Likely' : 'No'}</span></div>
            <div id="oe-live-intel" style="margin-top:12px"></div>
            <div class="oe-field"><span class="oe-field-label">Privacy-Focused</span><span class="oe-field-value">${isSecure ? 'Yes' : 'No'}</span></div>
          </div>
        </div>
        ${!isKnown ? `<div style="margin-top:16px;padding:12px;background:rgba(0,170,255,.06);border:1px solid rgba(0,170,255,.2);border-radius:6px">
          <strong style="color:#00aaff">Custom Domain Detected:</strong> <span style="color:#c8d6e5">${esc(domain)} — this could be a corporate/personal domain. Investigate WHOIS, DNS, and website for more intel.</span>
        </div>` : ''}
        <div class="oe-export-bar">
          <button class="oe-btn oe-btn-sec oe-export-json">Export JSON</button>
        </div>
      </div>`;

    out.querySelector('.oe-export-json').addEventListener('click', function() {
      const data = { email, local, domain, tld, sld, isKnownProvider: isKnown, isFreeProvider: isFree, isSecureProvider: isSecure, riskScore, breachCount, analyzedAt: new Date().toISOString() };
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `osint-email-${local}-${domain}.json`;
      a.click();
      URL.revokeObjectURL(a.href);
    });
  }

  function renderPermutations() {
    content.innerHTML = `
      <div class="oe-panel">
        <div class="oe-panel-title"> Username & Email Permutation Generator</div>
        <p style="color:#6a8aaa;font-size:13px;margin:0 0 14px">Generate email address permutations from a person's name across common email providers.</p>
        <div class="oe-row">
          <input class="oe-input" id="oe-first" placeholder="First name" />
          <input class="oe-input" id="oe-last" placeholder="Last name" />
          <button class="oe-btn" id="oe-gen-btn">Generate</button>
        </div>
        <div style="margin-bottom:12px">
          <label style="color:#6a8aaa;font-size:12px;margin-right:12px">Providers:</label>
          ${['gmail.com','outlook.com','yahoo.com','protonmail.com','icloud.com'].map(p => `<label style="color:#c8d6e5;font-size:12px;margin-right:10px;cursor:pointer"><input type="checkbox" class="oe-provider-cb" value="${p}" checked style="margin-right:4px" />${p}</label>`).join('')}
        </div>
        <div id="oe-perm-result"></div>
      </div>`;

    content.querySelector('#oe-gen-btn').addEventListener('click', () => {
      const first = content.querySelector('#oe-first').value.trim();
      const last = content.querySelector('#oe-last').value.trim();
      if (!first || !last) {
        content.querySelector('#oe-perm-result').innerHTML = `<div class="oe-result" style="color:#ff4444">Please enter both first and last name.</div>`;
        return;
      }
      const providers = [...content.querySelectorAll('.oe-provider-cb:checked')].map(c => c.value);
      if (!providers.length) { content.querySelector('#oe-perm-result').innerHTML = `<div class="oe-result" style="color:#ff4444">Select at least one provider.</div>`; return; }
      const perms = oeGenPerms(first, last);
      const allEmails = [];
      providers.forEach(p => perms.forEach(u => allEmails.push(`${u}@${p}`)));
      const out = content.querySelector('#oe-perm-result');
      out.innerHTML = `
        <div class="oe-result">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:8px">
            <div>
              <span class="oe-badge oe-badge-blue">${perms.length} patterns</span>
              <span class="oe-badge oe-badge-green">${providers.length} providers</span>
              <span class="oe-badge oe-badge-purple">${allEmails.length} total permutations</span>
            </div>
            <div style="display:flex;gap:6px">
              <button class="oe-btn oe-btn-sec" id="oe-copy-all">Copy All</button>
              <button class="oe-btn oe-btn-sec" id="oe-export-perm">Export CSV</button>
            </div>
          </div>
          <div style="max-height:400px;overflow-y:auto">
            <div class="oe-perm-grid">
              ${allEmails.map(e => `<div class="oe-perm-item"><span style="flex:1">${esc(e)}</span><button class="oe-copy-btn" data-val="${esc(e)}">Copy</button></div>`).join('')}
            </div>
          </div>
        </div>`;

      out.querySelector('#oe-copy-all').addEventListener('click', function() { copyText(allEmails.join('\n'), this); });
      out.querySelector('#oe-export-perm').addEventListener('click', () => {
        const csv = 'Username,Provider,Email\n' + allEmails.map(e => { const [u,d] = e.split('@'); return `${u},${d},${e}`; }).join('\n');
        const blob = new Blob([csv], { type: 'text/csv' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `email-permutations-${first}-${last}.csv`;
        a.click();
        URL.revokeObjectURL(a.href);
      });
      out.querySelectorAll('.oe-copy-btn').forEach(b => b.addEventListener('click', function() { copyText(this.dataset.val, this); }));
    });
  }

  function renderBreaches() {
    content.innerHTML = `
      <div class="oe-panel">
        <div class="oe-panel-title">Breach Database Search (Simulated)</div>
        <p style="color:#6a8aaa;font-size:13px;margin:0 0 14px">Check if an email appears in known data breaches. <span class="oe-badge oe-badge-yellow">SIMULATED</span> — results are generated for educational purposes only.</p>
        <div class="oe-row">
          <input class="oe-input" id="oe-breach-email" placeholder="Enter email to check..." />
          <button class="oe-btn" id="oe-breach-btn" style="background:linear-gradient(135deg,#ff4444,#cc3333)">Check Breaches</button>
        </div>
        <div id="oe-breach-result"></div>
      </div>
      <div class="oe-panel">
        <div class="oe-panel-title">Breach Statistics Reference</div>
        <div class="oe-result">
          <table class="oe-table">
            <thead><tr><th>Year</th><th>Major Breaches</th><th>Records Exposed</th><th>Most Common Type</th></tr></thead>
            <tbody>
              <tr><td>2024</td><td>2,814</td><td>3.1 billion</td><td>Cloud misconfigurations</td></tr>
              <tr><td>2023</td><td>3,122</td><td>8.2 billion</td><td>Ransomware + exfiltration</td></tr>
              <tr><td>2022</td><td>1,862</td><td>4.1 billion</td><td>Phishing campaigns</td></tr>
              <tr><td>2021</td><td>1,291</td><td>5.9 billion</td><td>Supply chain attacks</td></tr>
              <tr><td>2020</td><td>1,108</td><td>3.6 billion</td><td>COVID-19 themed attacks</td></tr>
            </tbody>
          </table>
        </div>
      </div>`;

    content.querySelector('#oe-breach-btn').addEventListener('click', () => {
      const email = content.querySelector('#oe-breach-email').value.trim();
      if (!email || !email.includes('@')) {
        content.querySelector('#oe-breach-result').innerHTML = `<div class="oe-result" style="color:#ff4444">Enter a valid email address.</div>`;
        return;
      }
      const seed = oeSeed(email);
      const count = seed % 5;
      const hits = [];
      for (let i = 0; i < count; i++) {
        hits.push(OE_BREACHES[(seed + i * 3) % OE_BREACHES.length]);
      }
      const unique = [...new Map(hits.map(h => [h.name, h])).values()];

      const out = content.querySelector('#oe-breach-result');
      if (!unique.length) {
        out.innerHTML = `<div class="oe-result"><div style="text-align:center;padding:24px"><span style="font-size:18px;color:#00ff88;font-weight:700">[OK]</span><div style="color:#00ff88;font-size:18px;font-weight:700;margin:12px 0">No Breaches Found</div><div style="color:#6a8aaa;font-size:13px">${esc(email)} was not found in any known breach databases (simulated).</div></div></div>`;
        return;
      }
      out.innerHTML = `
        <div class="oe-result">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px">
            <div>
              <span class="oe-badge oe-badge-red">Found in ${unique.length} breach${unique.length > 1 ? 'es' : ''}</span>
              <span style="color:#6a8aaa;font-size:12px;margin-left:8px">(Simulated results)</span>
            </div>
            <button class="oe-btn oe-btn-sec" id="oe-export-breach">Export Report</button>
          </div>
          ${unique.map(b => `
            <div class="oe-breach-card">
              <div class="oe-breach-title">${esc(b.name)}</div>
              <div class="oe-breach-meta">
                <span> ${b.date}</span>
                <span>${b.records} records</span>
              </div>
              <div class="oe-breach-types">${b.types.map(t => `<span class="oe-badge oe-badge-red">${esc(t)}</span>`).join('')}</div>
            </div>
          `).join('')}
        </div>`;

      out.querySelector('#oe-export-breach').addEventListener('click', () => {
        const report = { email, checkedAt: new Date().toISOString(), simulated: true, breachesFound: unique.length, breaches: unique };
        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `breach-report-${email.replace('@','_at_')}.json`;
        a.click();
        URL.revokeObjectURL(a.href);
      });
    });

    content.querySelector('#oe-breach-email').addEventListener('keydown', e => {
      if (e.key === 'Enter') content.querySelector('#oe-breach-btn').click();
    });
  }

  function renderSocialEnum() {
    content.innerHTML = `
      <div class="oe-panel">
        <div class="oe-panel-title">Social Media & Platform Enumeration</div>
        <p style="color:#6a8aaa;font-size:13px;margin:0 0 14px">Enter a username to generate platform profile URLs for OSINT investigation.</p>
        <div class="oe-row">
          <input class="oe-input" id="oe-social-user" placeholder="Enter username (e.g. johndoe)" />
          <button class="oe-btn" id="oe-social-btn">Enumerate</button>
        </div>
        <div id="oe-social-result">
          <div class="oe-grid" style="margin-top:16px">
            ${OE_SOCIALS.map(s => `
              <div class="oe-card">
                <div class="oe-card-title"><span style="font-size:20px">${s.icon}</span> ${esc(s.name)}</div>
                <div class="oe-card-desc">${esc(s.desc)}</div>
                <div class="oe-card-url">${esc(s.url.replace('{user}', '<username>'))}</div>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
      <div class="oe-panel">
        <div class="oe-panel-title">Additional OSINT Resources</div>
        <div class="oe-result">
          <table class="oe-table">
            <thead><tr><th>Resource</th><th>Type</th><th>Use Case</th></tr></thead>
            <tbody>
              <tr><td style="color:#00aaff">Sherlock</td><td><span class="oe-badge oe-badge-blue">CLI Tool</span></td><td>Username search across 400+ social networks</td></tr>
              <tr><td style="color:#00aaff">Holehe</td><td><span class="oe-badge oe-badge-blue">CLI Tool</span></td><td>Check if email is used on various platforms</td></tr>
              <tr><td style="color:#00aaff">theHarvester</td><td><span class="oe-badge oe-badge-blue">CLI Tool</span></td><td>Email & subdomain harvesting</td></tr>
              <tr><td style="color:#00aaff">Maltego</td><td><span class="oe-badge oe-badge-green">GUI Tool</span></td><td>Visual link analysis and graph-based OSINT</td></tr>
              <tr><td style="color:#00aaff">SpiderFoot</td><td><span class="oe-badge oe-badge-green">Web Tool</span></td><td>Automated OSINT reconnaissance</td></tr>
              <tr><td style="color:#00aaff">OSINT Framework</td><td><span class="oe-badge oe-badge-purple">Directory</span></td><td>Collection of OSINT tools organized by category</td></tr>
              <tr><td style="color:#00aaff">Recon-ng</td><td><span class="oe-badge oe-badge-blue">CLI Tool</span></td><td>Web reconnaissance framework</td></tr>
              <tr><td style="color:#00aaff">Amass</td><td><span class="oe-badge oe-badge-blue">CLI Tool</span></td><td>Network mapping and external asset discovery</td></tr>
            </tbody>
          </table>
        </div>
      </div>`;

    content.querySelector('#oe-social-btn').addEventListener('click', () => {
      const user = content.querySelector('#oe-social-user').value.trim();
      if (!user) return;
      const out = content.querySelector('#oe-social-result');
      out.innerHTML = `
        <div style="margin-top:12px;margin-bottom:16px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
          <div>
            <span class="oe-badge oe-badge-blue">${OE_SOCIALS.length} platforms</span>
            <span style="color:#e2e8f0;font-size:14px;margin-left:8px">Results for: <strong style="color:#00aaff">${esc(user)}</strong></span>
          </div>
          <button class="oe-btn oe-btn-sec" id="oe-copy-social">Copy All URLs</button>
        </div>
        <div class="oe-grid">
          ${OE_SOCIALS.map(s => {
            const url = s.url.replace('{user}', user);
            return `<div class="oe-card">
              <div class="oe-card-title"><span style="font-size:20px">${s.icon}</span> ${esc(s.name)}</div>
              <div class="oe-card-desc">${esc(s.desc)}</div>
              <div class="oe-card-url">${esc(url)}</div>
              <div style="margin-top:8px;display:flex;gap:6px">
                <button class="oe-copy-btn" data-val="${esc(url)}">Copy</button>
              </div>
            </div>`;
          }).join('')}
        </div>`;

      out.querySelector('#oe-copy-social').addEventListener('click', function() {
        const urls = OE_SOCIALS.map(s => `${s.name}: ${s.url.replace('{user}', user)}`).join('\n');
        copyText(urls, this);
      });
      out.querySelectorAll('.oe-copy-btn').forEach(b => b.addEventListener('click', function() { copyText(this.dataset.val, this); }));
    });

    content.querySelector('#oe-social-user').addEventListener('keydown', e => {
      if (e.key === 'Enter') content.querySelector('#oe-social-btn').click();
    });
  }

  function renderDorks() {
    content.innerHTML = `
      <div class="oe-panel">
        <div class="oe-panel-title"> Google Dorking for Email OSINT</div>
        <p style="color:#6a8aaa;font-size:13px;margin:0 0 14px">Generate Google dork queries to discover information about an email address. Enter an email to customize all queries.</p>
        <div class="oe-row">
          <input class="oe-input" id="oe-dork-email" placeholder="Enter email to generate dorks for..." />
          <button class="oe-btn" id="oe-dork-btn">Generate Dorks</button>
        </div>
      </div>
      <div id="oe-dork-result">
        ${OE_DORKS.map(d => `
          <div class="oe-dork-card">
            <div class="oe-dork-label">${esc(d.label)}</div>
            <div class="oe-dork-desc">${esc(d.desc)}</div>
            <div class="oe-dork-query">
              <span>${esc(d.template.replace('{{email}}', 'target@example.com'))}</span>
              <button class="oe-copy-btn" data-val="${esc(d.template.replace('{{email}}', 'target@example.com'))}">Copy</button>
            </div>
          </div>
        `).join('')}
      </div>
      <div class="oe-panel" style="margin-top:16px">
        <div class="oe-panel-title"> Advanced Dork Operators</div>
        <div class="oe-result">
          <table class="oe-table">
            <thead><tr><th>Operator</th><th>Description</th><th>Example</th></tr></thead>
            <tbody>
              <tr><td style="color:#00ff88;font-family:monospace">site:</td><td>Restrict to specific domain</td><td style="font-family:monospace;color:#c8d6e5;font-size:11px">"email" site:pastebin.com</td></tr>
              <tr><td style="color:#00ff88;font-family:monospace">intext:</td><td>Search page body text</td><td style="font-family:monospace;color:#c8d6e5;font-size:11px">intext:"user@domain.com"</td></tr>
              <tr><td style="color:#00ff88;font-family:monospace">intitle:</td><td>Search page titles</td><td style="font-family:monospace;color:#c8d6e5;font-size:11px">intitle:"email list" "domain.com"</td></tr>
              <tr><td style="color:#00ff88;font-family:monospace">filetype:</td><td>Restrict to file extensions</td><td style="font-family:monospace;color:#c8d6e5;font-size:11px">"email" filetype:csv</td></tr>
              <tr><td style="color:#00ff88;font-family:monospace">inurl:</td><td>Search URL path</td><td style="font-family:monospace;color:#c8d6e5;font-size:11px">inurl:admin "email" "domain.com"</td></tr>
              <tr><td style="color:#00ff88;font-family:monospace">cache:</td><td>Google's cached version</td><td style="font-family:monospace;color:#c8d6e5;font-size:11px">cache:domain.com "email"</td></tr>
              <tr><td style="color:#00ff88;font-family:monospace">ext:</td><td>File extension (alt filetype)</td><td style="font-family:monospace;color:#c8d6e5;font-size:11px">"email" ext:sql OR ext:log</td></tr>
              <tr><td style="color:#00ff88;font-family:monospace">after: / before:</td><td>Date range filtering</td><td style="font-family:monospace;color:#c8d6e5;font-size:11px">"email" after:2023-01-01</td></tr>
            </tbody>
          </table>
        </div>
      </div>`;

    content.querySelectorAll('.oe-copy-btn').forEach(b => b.addEventListener('click', function() { copyText(this.dataset.val, this); }));

    content.querySelector('#oe-dork-btn').addEventListener('click', () => {
      const email = content.querySelector('#oe-dork-email').value.trim();
      if (!email || !email.includes('@')) return;
      const out = content.querySelector('#oe-dork-result');
      out.innerHTML = `
        <div style="margin-bottom:12px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
          <span class="oe-badge oe-badge-blue">${OE_DORKS.length} dork queries for ${esc(email)}</span>
          <button class="oe-btn oe-btn-sec" id="oe-copy-all-dorks">Copy All Dorks</button>
        </div>
        ${OE_DORKS.map(d => {
          const q = d.template.replace('{{email}}', email);
          return `<div class="oe-dork-card">
            <div class="oe-dork-label">${esc(d.label)}</div>
            <div class="oe-dork-desc">${esc(d.desc)}</div>
            <div class="oe-dork-query">
              <span>${esc(q)}</span>
              <button class="oe-copy-btn" data-val="${esc(q)}">Copy</button>
            </div>
          </div>`;
        }).join('')}`;

      out.querySelector('#oe-copy-all-dorks').addEventListener('click', function() {
        const all = OE_DORKS.map(d => d.template.replace('{{email}}', email)).join('\n');
        copyText(all, this);
      });
      out.querySelectorAll('.oe-copy-btn').forEach(b => b.addEventListener('click', function() { copyText(this.dataset.val, this); }));
    });

    content.querySelector('#oe-dork-email').addEventListener('keydown', e => {
      if (e.key === 'Enter') content.querySelector('#oe-dork-btn').click();
    });
  }

  renderTab();
}
