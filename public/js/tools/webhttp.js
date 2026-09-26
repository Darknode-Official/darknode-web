// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Web & HTTP mini-tools.

const S = x => (x == null ? '' : String(x));

const STATUS = {
  100: ['Continue', 'The client should continue with its request.'],
  101: ['Switching Protocols', 'The server is switching protocols per the Upgrade header.'],
  102: ['Processing', 'The server has accepted the request but not yet completed it (WebDAV).'],
  103: ['Early Hints', 'Return some response headers before the final response (preload hints).'],
  200: ['OK', 'The request succeeded; meaning depends on the method.'],
  201: ['Created', 'The request succeeded and a new resource was created.'],
  202: ['Accepted', 'The request was accepted for processing but is not complete.'],
  203: ['Non-Authoritative Information', 'Returned metadata was modified by a proxy.'],
  204: ['No Content', 'Success with no body to return.'],
  205: ['Reset Content', 'The client should reset the document view.'],
  206: ['Partial Content', 'Body is a range of the resource per the Range header.'],
  207: ['Multi-Status', 'Conveys multiple statuses for a WebDAV request.'],
  208: ['Already Reported', 'Members already enumerated in a prior multistatus (WebDAV).'],
  226: ['IM Used', 'The response is a result of instance manipulations.'],
  300: ['Multiple Choices', 'The request has more than one possible response.'],
  301: ['Moved Permanently', 'The resource has a new permanent URI.'],
  302: ['Found', 'The resource resides temporarily at a different URI.'],
  303: ['See Other', 'Fetch the resource at another URI using GET.'],
  304: ['Not Modified', 'The cached copy is still valid; no body sent.'],
  305: ['Use Proxy', 'The resource must be accessed through a proxy (deprecated).'],
  307: ['Temporary Redirect', 'Temporary redirect that preserves the method.'],
  308: ['Permanent Redirect', 'Permanent redirect that preserves the method.'],
  400: ['Bad Request', 'The server cannot process the request due to a client error.'],
  401: ['Unauthorized', 'Authentication is required and has failed or not been provided.'],
  402: ['Payment Required', 'Reserved for future use; used by some payment APIs.'],
  403: ['Forbidden', 'The server understood the request but refuses to authorize it.'],
  404: ['Not Found', 'The server cannot find the requested resource.'],
  405: ['Method Not Allowed', 'The method is not supported for this resource.'],
  406: ['Not Acceptable', 'No representation matches the Accept headers.'],
  407: ['Proxy Authentication Required', 'Authenticate with the proxy first.'],
  408: ['Request Timeout', 'The server timed out waiting for the request.'],
  409: ['Conflict', 'The request conflicts with the current state of the resource.'],
  410: ['Gone', 'The resource is permanently gone with no forwarding address.'],
  411: ['Length Required', 'A Content-Length header is required.'],
  412: ['Precondition Failed', 'A precondition in the request headers failed.'],
  413: ['Payload Too Large', 'The request body is larger than the server will process.'],
  414: ['URI Too Long', 'The request URI is longer than the server will interpret.'],
  415: ['Unsupported Media Type', 'The payload media type is not supported.'],
  416: ['Range Not Satisfiable', 'The requested range cannot be fulfilled.'],
  417: ['Expectation Failed', 'The Expect request header could not be met.'],
  418: ["I'm a Teapot", 'The server refuses to brew coffee (RFC 2324 joke).'],
  421: ['Misdirected Request', 'The request was directed at a server that cannot respond.'],
  422: ['Unprocessable Entity', 'Semantic errors prevent processing (WebDAV).'],
  423: ['Locked', 'The resource is locked (WebDAV).'],
  424: ['Failed Dependency', 'A prior request failed so this one cannot proceed (WebDAV).'],
  425: ['Too Early', 'The server is unwilling to risk processing a replayed request.'],
  426: ['Upgrade Required', 'The client must switch to a different protocol.'],
  428: ['Precondition Required', 'The origin server requires a conditional request.'],
  429: ['Too Many Requests', 'The client has sent too many requests (rate limited).'],
  431: ['Request Header Fields Too Large', 'Headers are too large to process.'],
  451: ['Unavailable For Legal Reasons', 'Access denied for legal reasons.'],
  500: ['Internal Server Error', 'A generic server-side error occurred.'],
  501: ['Not Implemented', 'The server does not support the functionality required.'],
  502: ['Bad Gateway', 'An upstream server returned an invalid response.'],
  503: ['Service Unavailable', 'The server is not ready (overloaded or down for maintenance).'],
  504: ['Gateway Timeout', 'An upstream server did not respond in time.'],
  505: ['HTTP Version Not Supported', 'The HTTP version is not supported.'],
  506: ['Variant Also Negotiates', 'Internal content negotiation configuration error.'],
  507: ['Insufficient Storage', 'The server cannot store the representation (WebDAV).'],
  508: ['Loop Detected', 'An infinite loop was detected (WebDAV).'],
  510: ['Not Extended', 'Further extensions to the request are required.'],
  511: ['Network Authentication Required', 'The client must authenticate to gain network access.'],
};

const METHODS = {
  GET: { safe: true, idempotent: true, body: false, desc: 'Retrieve a representation of a resource.' },
  HEAD: { safe: true, idempotent: true, body: false, desc: 'Like GET but returns headers only, no body.' },
  POST: { safe: false, idempotent: false, body: true, desc: 'Submit data; may create a resource or trigger processing.' },
  PUT: { safe: false, idempotent: true, body: true, desc: 'Replace the target resource with the request payload.' },
  PATCH: { safe: false, idempotent: false, body: true, desc: 'Apply a partial modification to a resource.' },
  DELETE: { safe: false, idempotent: true, body: false, desc: 'Remove the target resource.' },
  OPTIONS: { safe: true, idempotent: true, body: false, desc: 'Describe communication options (used for CORS preflight).' },
  CONNECT: { safe: false, idempotent: false, body: false, desc: 'Establish a tunnel to the server (used by proxies).' },
  TRACE: { safe: true, idempotent: true, body: false, desc: 'Perform a loop-back test along the request path.' },
};

const REQ_HEADERS = {
  'accept': 'Media types the client can process.',
  'accept-encoding': 'Content encodings (e.g. gzip, br) the client accepts.',
  'accept-language': 'Preferred natural languages for the response.',
  'authorization': 'Credentials to authenticate the user agent.',
  'cache-control': 'Directives for caches along the request/response chain.',
  'connection': 'Control options for the current connection.',
  'content-length': 'Size of the request body in bytes.',
  'content-type': 'Media type of the request body.',
  'cookie': 'HTTP cookies previously sent by the server.',
  'host': 'Domain name and optional port of the server.',
  'if-modified-since': 'Return the resource only if changed since this date.',
  'if-none-match': 'Return the resource only if the ETag does not match.',
  'origin': 'Origin that caused the request (CORS and fetch).',
  'range': 'Request only part of a resource.',
  'referer': 'Address of the page that linked to the resource.',
  'user-agent': 'Product tokens identifying the client software.',
  'x-requested-with': 'Convention marking an AJAX/XHR request.',
  'x-forwarded-for': 'Originating client IP through proxies.',
};

const RES_HEADERS = {
  'access-control-allow-origin': 'Origins allowed to read the response (CORS).',
  'age': 'Time in seconds the object has been in a proxy cache.',
  'cache-control': 'Caching directives for the response.',
  'content-disposition': 'How to display the body (inline or attachment).',
  'content-encoding': 'Encoding applied to the body (gzip, br, ...).',
  'content-length': 'Size of the body in bytes.',
  'content-type': 'Media type of the body.',
  'etag': 'Version identifier for the resource.',
  'expires': 'Date/time after which the response is stale.',
  'last-modified': 'Date the resource was last changed.',
  'location': 'URL to redirect to, or the URI of a new resource.',
  'retry-after': 'When to retry after a 503 or 429.',
  'server': 'Software used by the origin server.',
  'set-cookie': 'Send a cookie from the server to the client.',
  'strict-transport-security': 'Force HTTPS for a period (HSTS).',
  'vary': 'Request headers that affect content negotiation.',
  'www-authenticate': 'Authentication scheme required for access.',
  'x-content-type-options': 'nosniff disables MIME sniffing.',
  'x-frame-options': 'Whether the page may be framed (clickjacking guard).',
};

const MIME_EXT = {
  html: 'text/html', htm: 'text/html', xhtml: 'application/xhtml+xml',
  css: 'text/css', js: 'text/javascript', mjs: 'text/javascript', json: 'application/json',
  jsonld: 'application/ld+json', xml: 'application/xml', txt: 'text/plain', csv: 'text/csv',
  md: 'text/markdown', ics: 'text/calendar', rtf: 'application/rtf',
  pdf: 'application/pdf', doc: 'application/msword',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xls: 'application/vnd.ms-excel',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  ppt: 'application/vnd.ms-powerpoint',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  odt: 'application/vnd.oasis.opendocument.text',
  ods: 'application/vnd.oasis.opendocument.spreadsheet',
  odp: 'application/vnd.oasis.opendocument.presentation',
  zip: 'application/zip', gz: 'application/gzip', tar: 'application/x-tar',
  rar: 'application/vnd.rar', '7z': 'application/x-7z-compressed', bz2: 'application/x-bzip2',
  png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif',
  webp: 'image/webp', svg: 'image/svg+xml', ico: 'image/vnd.microsoft.icon',
  bmp: 'image/bmp', tif: 'image/tiff', tiff: 'image/tiff', avif: 'image/avif', heic: 'image/heic',
  mp3: 'audio/mpeg', wav: 'audio/wav', ogg: 'audio/ogg', oga: 'audio/ogg',
  m4a: 'audio/mp4', aac: 'audio/aac', flac: 'audio/flac', weba: 'audio/webm', mid: 'audio/midi',
  mp4: 'video/mp4', m4v: 'video/mp4', webm: 'video/webm', ogv: 'video/ogg',
  avi: 'video/x-msvideo', mov: 'video/quicktime', mpeg: 'video/mpeg', mkv: 'video/x-matroska', ts: 'video/mp2t',
  woff: 'font/woff', woff2: 'font/woff2', ttf: 'font/ttf', otf: 'font/otf', eot: 'application/vnd.ms-fontobject',
  wasm: 'application/wasm', bin: 'application/octet-stream',
  exe: 'application/vnd.microsoft.portable-executable',
  apk: 'application/vnd.android.package-archive',
  dmg: 'application/x-apple-diskimage',
  sh: 'application/x-sh', py: 'text/x-python', c: 'text/x-c', cpp: 'text/x-c',
  java: 'text/x-java-source', php: 'application/x-httpd-php',
  yaml: 'application/yaml', yml: 'application/yaml', toml: 'application/toml',
  epub: 'application/epub+zip',
};

const PORTS = {
  20: 'FTP data', 21: 'FTP control', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
  67: 'DHCP server', 68: 'DHCP client', 69: 'TFTP', 80: 'HTTP', 110: 'POP3', 119: 'NNTP',
  123: 'NTP', 143: 'IMAP', 161: 'SNMP', 179: 'BGP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB',
  465: 'SMTPS', 514: 'Syslog', 587: 'SMTP submission', 631: 'IPP', 636: 'LDAPS', 873: 'rsync',
  989: 'FTPS data', 990: 'FTPS control', 993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS proxy',
  1194: 'OpenVPN', 1433: 'MS SQL Server', 1521: 'Oracle DB', 1723: 'PPTP', 2049: 'NFS',
  3128: 'Squid proxy', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5672: 'AMQP',
  5900: 'VNC', 6379: 'Redis', 6667: 'IRC', 8080: 'HTTP alt', 8443: 'HTTPS alt',
  9092: 'Kafka', 9200: 'Elasticsearch', 11211: 'Memcached', 27017: 'MongoDB',
};

const REFERRER_POLICY = {
  'no-referrer': 'Never send the Referer header.',
  'no-referrer-when-downgrade': 'Send full URL except when going HTTPS to HTTP.',
  'origin': 'Send only the origin (scheme, host, port).',
  'origin-when-cross-origin': 'Full URL for same-origin, only origin cross-origin.',
  'same-origin': 'Send referrer for same-origin requests only.',
  'strict-origin': 'Send origin, but not on HTTPS to HTTP downgrade.',
  'strict-origin-when-cross-origin': 'Default: full URL same-origin, origin cross-origin, nothing on downgrade.',
  'unsafe-url': 'Always send the full URL (not recommended).',
};

function statusClassName(code) {
  return { 1: 'Informational', 2: 'Success', 3: 'Redirection', 4: 'Client Error', 5: 'Server Error' }[Math.floor(code / 100)] || 'Unknown';
}

function parseQList(s) {
  return S(s).split(',').map(x => x.trim()).filter(Boolean).map(item => {
    const parts = item.split(';').map(p => p.trim());
    let q = 1;
    for (const p of parts.slice(1)) {
      const m = p.match(/^q=([0-9.]+)$/i);
      if (m) q = parseFloat(m[1]);
    }
    return { val: parts[0], q: isNaN(q) ? 1 : q };
  }).sort((a, b) => b.q - a.q);
}

function robotMatch(pattern, path) {
  if (pattern === '') return { m: false, len: 0 };
  let end = false, p = pattern;
  if (p.endsWith('$')) { end = true; p = p.slice(0, -1); }
  const parts = p.split('*').map(x => x.replace(/[.+?^${}()|[\]\\]/g, '\\$&'));
  const re = new RegExp('^' + parts.join('.*') + (end ? '$' : ''));
  return { m: re.test(path), len: pattern.length };
}

export const TOOLS = [
  {
    id: 'wb-status-explain', name: 'HTTP Status Code Explainer', cat: 'web',
    desc: 'Look up an HTTP status code and get its name, class, and meaning.',
    tags: ['http', 'status', 'reference'],
    inputs: [{ k: 'code', type: 'text', label: 'Status code', ph: '404', def: '' }],
    run(v) {
      const code = parseInt(S(v.code).trim(), 10);
      if (!S(v.code).trim()) return '';
      if (isNaN(code)) return { error: 'Enter a numeric status code.' };
      const e = STATUS[code];
      if (!e) return { error: `${code} is not a standard HTTP status code.` };
      return { out: `${code} ${e[0]}\nClass: ${Math.floor(code / 100)}xx ${statusClassName(code)}\n${e[1]}` };
    },
  },
  {
    id: 'wb-status-by-class', name: 'HTTP Status Codes by Class', cat: 'web',
    desc: 'List every standard status code within a chosen class (1xx to 5xx).',
    tags: ['http', 'status', 'reference'],
    inputs: [{ k: 'cls', type: 'select', label: 'Class', opts: ['1xx', '2xx', '3xx', '4xx', '5xx'], def: '2xx' }],
    run(v) {
      const d = S(v.cls || '2xx')[0];
      const lines = Object.keys(STATUS).map(Number).filter(c => String(c)[0] === d)
        .map(c => `${c} ${STATUS[c][0]}`);
      return { out: lines.join('\n') };
    },
  },
  {
    id: 'wb-methods-ref', name: 'HTTP Methods Reference', cat: 'web',
    desc: 'Show HTTP methods with safe / idempotent flags and descriptions.',
    tags: ['http', 'methods', 'reference'],
    inputs: [{ k: 'm', type: 'select', label: 'Method', opts: ['(all)', 'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'CONNECT', 'TRACE'], def: '(all)' }],
    run(v) {
      const sel = S(v.m || '(all)');
      const names = sel === '(all)' ? Object.keys(METHODS) : [sel];
      const lines = names.map(n => {
        const m = METHODS[n];
        if (!m) return `${n}: unknown method`;
        return `${n}\n  safe: ${m.safe}  idempotent: ${m.idempotent}  has body: ${m.body}\n  ${m.desc}`;
      });
      return { out: lines.join('\n\n') };
    },
  },
  {
    id: 'wb-req-headers', name: 'Request Headers Reference', cat: 'web',
    desc: 'Look up a common HTTP request header by name, or list them all.',
    tags: ['http', 'headers', 'request'],
    inputs: [{ k: 'name', type: 'text', label: 'Header name (blank = all)', ph: 'Authorization', def: '' }],
    run(v) {
      const q = S(v.name).trim().toLowerCase();
      if (!q) return { out: Object.keys(REQ_HEADERS).map(h => `${h}: ${REQ_HEADERS[h]}`).join('\n') };
      const d = REQ_HEADERS[q];
      return d ? { out: `${q}\n${d}` } : { error: `No reference entry for request header "${v.name}".` };
    },
  },
  {
    id: 'wb-res-headers', name: 'Response Headers Reference', cat: 'web',
    desc: 'Look up a common HTTP response header by name, or list them all.',
    tags: ['http', 'headers', 'response'],
    inputs: [{ k: 'name', type: 'text', label: 'Header name (blank = all)', ph: 'ETag', def: '' }],
    run(v) {
      const q = S(v.name).trim().toLowerCase();
      if (!q) return { out: Object.keys(RES_HEADERS).map(h => `${h}: ${RES_HEADERS[h]}`).join('\n') };
      const d = RES_HEADERS[q];
      return d ? { out: `${q}\n${d}` } : { error: `No reference entry for response header "${v.name}".` };
    },
  },
  {
    id: 'wb-mime-by-ext', name: 'MIME Type by Extension', cat: 'web',
    desc: 'Find the MIME (media) type for a file extension or file name.',
    tags: ['mime', 'content-type', 'files'],
    inputs: [{ k: 'ext', type: 'text', label: 'Extension or filename', ph: 'image.png', def: '' }],
    run(v) {
      let e = S(v.ext).trim().toLowerCase();
      if (!e) return '';
      if (e.includes('.')) e = e.split('.').pop();
      e = e.replace(/^\./, '');
      const m = MIME_EXT[e];
      return m ? { out: m } : { error: `No known MIME type for ".${e}".` };
    },
  },
  {
    id: 'wb-ext-by-mime', name: 'Extension by MIME Type', cat: 'web',
    desc: 'Find file extensions associated with a MIME type.',
    tags: ['mime', 'content-type', 'files'],
    inputs: [{ k: 'mime', type: 'text', label: 'MIME type', ph: 'image/jpeg', def: '' }],
    run(v) {
      const m = S(v.mime).trim().toLowerCase();
      if (!m) return '';
      const hits = Object.keys(MIME_EXT).filter(k => MIME_EXT[k] === m);
      return hits.length ? { out: hits.map(x => '.' + x).join(', ') } : { error: `No known extension for "${m}".` };
    },
  },
  {
    id: 'wb-ua-parser', name: 'User-Agent Parser', cat: 'web',
    desc: 'Heuristically detect browser, OS, and device from a User-Agent string.',
    tags: ['user-agent', 'browser', 'parse'],
    inputs: [{ k: 'ua', type: 'textarea', label: 'User-Agent', rows: 3, ph: 'Mozilla/5.0 ...', def: '' }],
    run(v) {
      const ua = S(v.ua).trim();
      if (!ua) return '';
      let browser = 'Unknown';
      if (/Edg\//.test(ua)) browser = 'Edge';
      else if (/OPR\/|Opera/.test(ua)) browser = 'Opera';
      else if (/Firefox\//.test(ua)) browser = 'Firefox';
      else if (/Chrome\//.test(ua) && !/Chromium/.test(ua)) browser = 'Chrome';
      else if (/Chromium\//.test(ua)) browser = 'Chromium';
      else if (/Safari\//.test(ua) && /Version\//.test(ua)) browser = 'Safari';
      else if (/MSIE|Trident/.test(ua)) browser = 'Internet Explorer';
      let os = 'Unknown';
      if (/Windows NT 10/.test(ua)) os = 'Windows 10/11';
      else if (/Windows NT/.test(ua)) os = 'Windows';
      else if (/Android/.test(ua)) os = 'Android';
      else if (/iPhone|iPad|iPod/.test(ua)) os = 'iOS';
      else if (/Mac OS X/.test(ua)) os = 'macOS';
      else if (/Linux/.test(ua)) os = 'Linux';
      const device = /Mobile|iPhone|Android.*Mobile/.test(ua) ? 'Mobile' : /iPad|Tablet/.test(ua) ? 'Tablet' : 'Desktop';
      const bot = /bot|crawler|spider|slurp/i.test(ua);
      return { out: `Browser: ${browser}\nOS: ${os}\nDevice: ${device}\nBot: ${bot}` };
    },
  },
  {
    id: 'wb-qs-parse', name: 'Query String to Table', cat: 'web',
    desc: 'Parse a query string into decoded key/value pairs.',
    tags: ['url', 'query', 'parse'],
    inputs: [{ k: 'qs', type: 'textarea', label: 'Query string', rows: 3, ph: 'a=1&b=hello%20world', def: '' }],
    run(v) {
      let qs = S(v.qs).trim();
      if (!qs) return '';
      qs = qs.replace(/^\?/, '');
      const p = new URLSearchParams(qs);
      const lines = [];
      for (const [k, val] of p.entries()) lines.push(`${k} = ${val}`);
      return lines.length ? { out: lines.join('\n') } : { out: '(no parameters)' };
    },
  },
  {
    id: 'wb-qs-build', name: 'Build Query String', cat: 'web',
    desc: 'Build a URL-encoded query string from key=value lines.',
    tags: ['url', 'query', 'build'],
    inputs: [{ k: 'lines', type: 'textarea', label: 'key=value per line', rows: 6, ph: 'a=1\nb=hello world', def: '' }],
    run(v) {
      const txt = S(v.lines);
      if (!txt.trim()) return '';
      const p = new URLSearchParams();
      for (const line of txt.split('\n')) {
        if (!line.trim()) continue;
        const i = line.indexOf('=');
        if (i < 0) p.append(line.trim(), '');
        else p.append(line.slice(0, i).trim(), line.slice(i + 1).trim());
      }
      return { out: p.toString() };
    },
  },
  {
    id: 'wb-url-parse', name: 'URL Parser', cat: 'web',
    desc: 'Break a URL into protocol, host, port, path, query, and hash.',
    tags: ['url', 'parse'],
    inputs: [{ k: 'url', type: 'text', label: 'URL', ph: 'https://a.com:8080/p?x=1#h', def: '' }],
    run(v) {
      const s = S(v.url).trim();
      if (!s) return '';
      try {
        const u = new URL(s);
        return {
          out: `protocol: ${u.protocol}\nhost: ${u.hostname}\nport: ${u.port || '(default)'}\n` +
            `path: ${u.pathname}\nquery: ${u.search || '(none)'}\nhash: ${u.hash || '(none)'}\n` +
            `origin: ${u.origin}`,
        };
      } catch { return { error: 'Invalid URL.' }; }
    },
  },
  {
    id: 'wb-url-build', name: 'URL Builder', cat: 'web',
    desc: 'Assemble a URL from protocol, host, port, path, query, and hash parts.',
    tags: ['url', 'build'],
    inputs: [
      { k: 'proto', type: 'text', label: 'Protocol', ph: 'https', def: 'https' },
      { k: 'host', type: 'text', label: 'Host', ph: 'example.com', def: '' },
      { k: 'port', type: 'text', label: 'Port (optional)', ph: '8080', def: '' },
      { k: 'path', type: 'text', label: 'Path', ph: '/api/v1', def: '' },
      { k: 'query', type: 'text', label: 'Query (optional)', ph: 'a=1&b=2', def: '' },
      { k: 'hash', type: 'text', label: 'Hash (optional)', ph: 'section', def: '' },
    ],
    run(v) {
      const host = S(v.host).trim();
      if (!host) return '';
      let proto = S(v.proto || 'https').replace(/:.*$/, '').trim() || 'https';
      try {
        const u = new URL(proto + '://' + host);
        if (S(v.port).trim()) u.port = S(v.port).trim();
        let path = S(v.path).trim();
        if (path && !path.startsWith('/')) path = '/' + path;
        u.pathname = path || '/';
        if (S(v.query).trim()) u.search = S(v.query).trim().replace(/^\?/, '');
        if (S(v.hash).trim()) u.hash = S(v.hash).trim().replace(/^#/, '');
        return { out: u.toString() };
      } catch { return { error: 'Could not build a valid URL from those parts.' }; }
    },
  },
  {
    id: 'wb-url-set-param', name: 'Add / Replace Query Param', cat: 'web',
    desc: 'Set a query parameter in a URL, replacing any existing value.',
    tags: ['url', 'query'],
    inputs: [
      { k: 'url', type: 'text', label: 'URL', ph: 'https://a.com/?x=1', def: '' },
      { k: 'key', type: 'text', label: 'Param name', ph: 'x', def: '' },
      { k: 'val', type: 'text', label: 'Param value', ph: '2', def: '' },
    ],
    run(v) {
      const s = S(v.url).trim();
      if (!s || !S(v.key).trim()) return '';
      try {
        const u = new URL(s);
        u.searchParams.set(S(v.key).trim(), S(v.val));
        return { out: u.toString() };
      } catch { return { error: 'Invalid URL.' }; }
    },
  },
  {
    id: 'wb-url-remove-param', name: 'Remove Query Param', cat: 'web',
    desc: 'Delete a query parameter from a URL.',
    tags: ['url', 'query'],
    inputs: [
      { k: 'url', type: 'text', label: 'URL', ph: 'https://a.com/?x=1&y=2', def: '' },
      { k: 'key', type: 'text', label: 'Param to remove', ph: 'x', def: '' },
    ],
    run(v) {
      const s = S(v.url).trim();
      if (!s || !S(v.key).trim()) return '';
      try {
        const u = new URL(s);
        u.searchParams.delete(S(v.key).trim());
        return { out: u.toString() };
      } catch { return { error: 'Invalid URL.' }; }
    },
  },
  {
    id: 'wb-url-resolve', name: 'Resolve Relative URL', cat: 'web',
    desc: 'Resolve a relative URL against a base URL into an absolute URL.',
    tags: ['url', 'resolve'],
    inputs: [
      { k: 'base', type: 'text', label: 'Base URL', ph: 'https://a.com/dir/page', def: '' },
      { k: 'rel', type: 'text', label: 'Relative URL', ph: '../img/x.png', def: '' },
    ],
    run(v) {
      const base = S(v.base).trim(), rel = S(v.rel).trim();
      if (!base || !rel) return '';
      try { return { out: new URL(rel, base).toString() }; }
      catch { return { error: 'Invalid base or relative URL.' }; }
    },
  },
  {
    id: 'wb-url-domain', name: 'Extract Domain', cat: 'web',
    desc: 'Extract the host / domain name from a URL.',
    tags: ['url', 'domain'],
    inputs: [{ k: 'url', type: 'text', label: 'URL', ph: 'https://sub.example.com/p', def: '' }],
    run(v) {
      const s = S(v.url).trim();
      if (!s) return '';
      try { return { out: new URL(s).hostname }; }
      catch { return { error: 'Invalid URL.' }; }
    },
  },
  {
    id: 'wb-url-path', name: 'Extract Path', cat: 'web',
    desc: 'Extract the path portion from a URL.',
    tags: ['url', 'path'],
    inputs: [{ k: 'url', type: 'text', label: 'URL', ph: 'https://a.com/api/v1?x=1', def: '' }],
    run(v) {
      const s = S(v.url).trim();
      if (!s) return '';
      try { return { out: new URL(s).pathname }; }
      catch { return { error: 'Invalid URL.' }; }
    },
  },
  {
    id: 'wb-host-port', name: 'Split Host:Port', cat: 'web',
    desc: 'Split a host:port authority into separate host and port fields.',
    tags: ['host', 'port', 'parse'],
    inputs: [{ k: 'auth', type: 'text', label: 'host:port', ph: 'example.com:8080', def: '' }],
    run(v) {
      const s = S(v.auth).trim();
      if (!s) return '';
      const m = s.match(/^\[([^\]]+)\](?::(\d+))?$/);
      if (m) return { out: `host: ${m[1]}\nport: ${m[2] || '(none)'}` };
      const i = s.lastIndexOf(':');
      if (i < 0) return { out: `host: ${s}\nport: (none)` };
      const port = s.slice(i + 1);
      if (!/^\d+$/.test(port)) return { out: `host: ${s}\nport: (none)` };
      return { out: `host: ${s.slice(0, i)}\nport: ${port}` };
    },
  },
  {
    id: 'wb-cookie-parse', name: 'Cookie Header Parser', cat: 'web',
    desc: 'Parse a Cookie request header into name=value pairs.',
    tags: ['cookie', 'header', 'parse'],
    inputs: [{ k: 'h', type: 'textarea', label: 'Cookie header', rows: 3, ph: 'a=1; b=2; sid=abc', def: '' }],
    run(v) {
      let s = S(v.h).trim();
      if (!s) return '';
      s = s.replace(/^Cookie:\s*/i, '');
      const lines = s.split(';').map(x => x.trim()).filter(Boolean).map(pair => {
        const i = pair.indexOf('=');
        return i < 0 ? `${pair} = ` : `${pair.slice(0, i).trim()} = ${pair.slice(i + 1).trim()}`;
      });
      return { out: lines.join('\n') };
    },
  },
  {
    id: 'wb-setcookie-build', name: 'Set-Cookie Builder', cat: 'web',
    desc: 'Build a Set-Cookie response header from a name, value, and attributes.',
    tags: ['cookie', 'header', 'build'],
    inputs: [
      { k: 'name', type: 'text', label: 'Name', ph: 'session', def: '' },
      { k: 'value', type: 'text', label: 'Value', ph: 'abc123', def: '' },
      { k: 'path', type: 'text', label: 'Path', ph: '/', def: '/' },
      { k: 'domain', type: 'text', label: 'Domain (optional)', ph: 'example.com', def: '' },
      { k: 'maxage', type: 'text', label: 'Max-Age seconds (optional)', ph: '3600', def: '' },
      { k: 'samesite', type: 'select', label: 'SameSite', opts: ['(none)', 'Strict', 'Lax', 'None'], def: 'Lax' },
      { k: 'secure', type: 'checkbox', label: 'Secure', def: true },
      { k: 'httponly', type: 'checkbox', label: 'HttpOnly', def: true },
    ],
    run(v) {
      const name = S(v.name).trim();
      if (!name) return '';
      let out = `${name}=${S(v.value)}`;
      if (S(v.path).trim()) out += `; Path=${S(v.path).trim()}`;
      if (S(v.domain).trim()) out += `; Domain=${S(v.domain).trim()}`;
      if (S(v.maxage).trim()) {
        if (!/^\d+$/.test(S(v.maxage).trim())) return { error: 'Max-Age must be a number.' };
        out += `; Max-Age=${S(v.maxage).trim()}`;
      }
      if (v.samesite && v.samesite !== '(none)') out += `; SameSite=${v.samesite}`;
      if (v.secure) out += '; Secure';
      if (v.httponly) out += '; HttpOnly';
      return { out: 'Set-Cookie: ' + out };
    },
  },
  {
    id: 'wb-csp-build', name: 'Content-Security-Policy Builder', cat: 'web',
    desc: 'Build a CSP header from directive lines.',
    tags: ['csp', 'security', 'build'],
    inputs: [{ k: 'lines', type: 'textarea', label: 'directive sources per line', rows: 6, ph: "default-src 'self'\nimg-src 'self' data:", def: '' }],
    run(v) {
      const txt = S(v.lines);
      if (!txt.trim()) return '';
      const parts = txt.split('\n').map(l => l.trim().replace(/\s+/g, ' ')).filter(Boolean);
      return { out: 'Content-Security-Policy: ' + parts.join('; ') };
    },
  },
  {
    id: 'wb-csp-parse', name: 'CSP Parser', cat: 'web',
    desc: 'Parse a Content-Security-Policy header into directives and sources.',
    tags: ['csp', 'security', 'parse'],
    inputs: [{ k: 'csp', type: 'textarea', label: 'CSP header value', rows: 4, ph: "default-src 'self'; img-src *", def: '' }],
    run(v) {
      let s = S(v.csp).trim();
      if (!s) return '';
      s = s.replace(/^Content-Security-Policy:\s*/i, '');
      const lines = s.split(';').map(d => d.trim()).filter(Boolean).map(d => {
        const parts = d.split(/\s+/);
        return `${parts[0]}: ${parts.slice(1).join(' ') || '(none)'}`;
      });
      return { out: lines.join('\n') };
    },
  },
  {
    id: 'wb-cors-preflight', name: 'CORS Preflight Explainer', cat: 'web',
    desc: 'Explain the response headers a server must return for a CORS preflight.',
    tags: ['cors', 'security', 'http'],
    inputs: [
      { k: 'origin', type: 'text', label: 'Origin', ph: 'https://app.example.com', def: '' },
      { k: 'method', type: 'text', label: 'Requested method', ph: 'PUT', def: '' },
      { k: 'headers', type: 'text', label: 'Requested headers', ph: 'Content-Type, Authorization', def: '' },
      { k: 'creds', type: 'checkbox', label: 'Include credentials', def: false },
    ],
    run(v) {
      const origin = S(v.origin).trim(), method = S(v.method).trim().toUpperCase();
      if (!origin || !method) return '';
      const lines = [
        'The browser sends OPTIONS with:',
        `  Origin: ${origin}`,
        `  Access-Control-Request-Method: ${method}`,
      ];
      if (S(v.headers).trim()) lines.push(`  Access-Control-Request-Headers: ${S(v.headers).trim()}`);
      lines.push('', 'The server must respond (200/204) with:');
      lines.push(`  Access-Control-Allow-Origin: ${v.creds ? origin : origin + ' (or *)'}`);
      lines.push(`  Access-Control-Allow-Methods: ${method}`);
      if (S(v.headers).trim()) lines.push(`  Access-Control-Allow-Headers: ${S(v.headers).trim()}`);
      if (v.creds) lines.push('  Access-Control-Allow-Credentials: true  (wildcard origin not allowed)');
      lines.push('  Access-Control-Max-Age: 600  (optional, cache in seconds)');
      return { out: lines.join('\n') };
    },
  },
  {
    id: 'wb-cachecontrol-build', name: 'Cache-Control Builder', cat: 'web',
    desc: 'Build a Cache-Control header from common directives.',
    tags: ['cache', 'header', 'build'],
    inputs: [
      { k: 'visibility', type: 'select', label: 'Visibility', opts: ['(none)', 'public', 'private'], def: 'public' },
      { k: 'maxage', type: 'text', label: 'max-age seconds (optional)', ph: '3600', def: '' },
      { k: 'smaxage', type: 'text', label: 's-maxage seconds (optional)', ph: '', def: '' },
      { k: 'nocache', type: 'checkbox', label: 'no-cache', def: false },
      { k: 'nostore', type: 'checkbox', label: 'no-store', def: false },
      { k: 'immutable', type: 'checkbox', label: 'immutable', def: false },
      { k: 'mustreval', type: 'checkbox', label: 'must-revalidate', def: false },
    ],
    run(v) {
      const parts = [];
      if (v.visibility && v.visibility !== '(none)') parts.push(v.visibility);
      if (v.nostore) parts.push('no-store');
      if (v.nocache) parts.push('no-cache');
      if (S(v.maxage).trim()) {
        if (!/^\d+$/.test(S(v.maxage).trim())) return { error: 'max-age must be numeric.' };
        parts.push('max-age=' + S(v.maxage).trim());
      }
      if (S(v.smaxage).trim()) {
        if (!/^\d+$/.test(S(v.smaxage).trim())) return { error: 's-maxage must be numeric.' };
        parts.push('s-maxage=' + S(v.smaxage).trim());
      }
      if (v.mustreval) parts.push('must-revalidate');
      if (v.immutable) parts.push('immutable');
      if (!parts.length) return '';
      return { out: 'Cache-Control: ' + parts.join(', ') };
    },
  },
  {
    id: 'wb-cachecontrol-parse', name: 'Cache-Control Parser', cat: 'web',
    desc: 'Parse a Cache-Control header into directives with explanations.',
    tags: ['cache', 'header', 'parse'],
    inputs: [{ k: 'cc', type: 'textarea', label: 'Cache-Control value', rows: 3, ph: 'public, max-age=3600', def: '' }],
    run(v) {
      let s = S(v.cc).trim();
      if (!s) return '';
      s = s.replace(/^Cache-Control:\s*/i, '');
      const notes = {
        'public': 'may be cached by any cache',
        'private': 'only the browser may cache it',
        'no-cache': 'revalidate with the origin before reuse',
        'no-store': 'never cache anywhere',
        'must-revalidate': 'once stale, must revalidate before use',
        'immutable': 'body will not change while fresh',
        'proxy-revalidate': 'shared caches must revalidate when stale',
      };
      const lines = s.split(',').map(d => d.trim()).filter(Boolean).map(d => {
        const [k, val] = d.split('=');
        if (/max-age|s-maxage|stale-while-revalidate|stale-if-error/.test(k)) return `${d}  (${val || '?'} seconds)`;
        return notes[k] ? `${d}  (${notes[k]})` : d;
      });
      return { out: lines.join('\n') };
    },
  },
  {
    id: 'wb-content-disposition', name: 'Content-Disposition Builder', cat: 'web',
    desc: 'Build a Content-Disposition header for inline display or download.',
    tags: ['header', 'download', 'build'],
    inputs: [
      { k: 'type', type: 'select', label: 'Type', opts: ['attachment', 'inline'], def: 'attachment' },
      { k: 'filename', type: 'text', label: 'Filename (optional)', ph: 'report.pdf', def: '' },
    ],
    run(v) {
      let out = S(v.type || 'attachment');
      const fn = S(v.filename).trim();
      if (fn) {
        out += `; filename="${fn.replace(/"/g, '')}"`;
        if (/[^\x20-\x7E]/.test(fn)) out += `; filename*=UTF-8''${encodeURIComponent(fn)}`;
      }
      return { out: 'Content-Disposition: ' + out };
    },
  },
  {
    id: 'wb-basic-auth-build', name: 'Basic Auth Header Builder', cat: 'web',
    desc: 'Build an Authorization: Basic header from user and password.',
    tags: ['auth', 'header', 'base64'],
    inputs: [
      { k: 'user', type: 'text', label: 'Username', ph: 'admin', def: '' },
      { k: 'pass', type: 'text', label: 'Password', ph: 'secret', def: '' },
    ],
    run(v, H) {
      const user = S(v.user);
      if (!user && !S(v.pass)) return '';
      const token = H.b64encode(`${user}:${S(v.pass)}`);
      return { out: `Authorization: Basic ${token}` };
    },
  },
  {
    id: 'wb-basic-auth-decode', name: 'Basic Auth Decoder', cat: 'web',
    desc: 'Decode a Basic auth token or header back into user:password.',
    tags: ['auth', 'header', 'base64'],
    inputs: [{ k: 'token', type: 'text', label: 'Token or header', ph: 'Basic YWRtaW46c2VjcmV0', def: '' }],
    run(v, H) {
      let t = S(v.token).trim();
      if (!t) return '';
      t = t.replace(/^Authorization:\s*/i, '').replace(/^Basic\s+/i, '');
      let dec;
      try { dec = H.b64decode(t); } catch { return { error: 'Not valid base64.' }; }
      const i = dec.indexOf(':');
      if (i < 0) return { out: `username: ${dec}\npassword: (none)` };
      return { out: `username: ${dec.slice(0, i)}\npassword: ${dec.slice(i + 1)}` };
    },
  },
  {
    id: 'wb-bearer-build', name: 'Bearer Token Header Builder', cat: 'web',
    desc: 'Build an Authorization: Bearer header from a token.',
    tags: ['auth', 'header', 'bearer'],
    inputs: [{ k: 'token', type: 'text', label: 'Token', ph: 'eyJhbGciOi...', def: '' }],
    run(v) {
      const t = S(v.token).trim();
      if (!t) return '';
      return { out: `Authorization: Bearer ${t}` };
    },
  },
  {
    id: 'wb-datauri-build', name: 'data: URI Builder', cat: 'web',
    desc: 'Build a data: URI from a MIME type and text (plain or base64).',
    tags: ['data-uri', 'base64', 'build'],
    inputs: [
      { k: 'mime', type: 'text', label: 'MIME type', ph: 'text/plain', def: 'text/plain' },
      { k: 'content', type: 'textarea', label: 'Content', rows: 4, ph: 'Hello world', def: '' },
      { k: 'b64', type: 'checkbox', label: 'Base64 encode', def: true },
    ],
    run(v, H) {
      const content = S(v.content);
      if (!content) return '';
      const mime = S(v.mime).trim() || 'text/plain';
      if (v.b64) return { out: `data:${mime};base64,${H.b64encode(content)}` };
      return { out: `data:${mime},${encodeURIComponent(content)}` };
    },
  },
  {
    id: 'wb-datauri-parse', name: 'data: URI Parser', cat: 'web',
    desc: 'Parse a data: URI into MIME type, encoding, and decoded content.',
    tags: ['data-uri', 'base64', 'parse'],
    inputs: [{ k: 'uri', type: 'textarea', label: 'data: URI', rows: 4, ph: 'data:text/plain;base64,SGk=', def: '' }],
    run(v, H) {
      const s = S(v.uri).trim();
      if (!s) return '';
      const m = s.match(/^data:([^,]*),([\s\S]*)$/);
      if (!m) return { error: 'Not a valid data: URI.' };
      const meta = m[1], data = m[2];
      const isB64 = /;base64/i.test(meta);
      const mime = meta.replace(/;base64/i, '') || 'text/plain;charset=US-ASCII';
      let content;
      try { content = isB64 ? H.b64decode(data) : decodeURIComponent(data); }
      catch { return { error: 'Could not decode the data payload.' }; }
      return { out: `mime: ${mime}\nencoding: ${isB64 ? 'base64' : 'url'}\ncontent:\n${content}` };
    },
  },
  {
    id: 'wb-robots-build', name: 'robots.txt Builder', cat: 'web',
    desc: 'Build a robots.txt file from user-agent, allow, disallow, and sitemap.',
    tags: ['robots', 'seo', 'build'],
    inputs: [
      { k: 'ua', type: 'text', label: 'User-agent', ph: '*', def: '*' },
      { k: 'allow', type: 'textarea', label: 'Allow paths (per line)', rows: 3, ph: '/public', def: '' },
      { k: 'disallow', type: 'textarea', label: 'Disallow paths (per line)', rows: 3, ph: '/admin', def: '' },
      { k: 'sitemap', type: 'text', label: 'Sitemap URL (optional)', ph: 'https://a.com/sitemap.xml', def: '' },
    ],
    run(v) {
      const ua = S(v.ua).trim() || '*';
      const lines = [`User-agent: ${ua}`];
      S(v.allow).split('\n').map(x => x.trim()).filter(Boolean).forEach(p => lines.push(`Allow: ${p}`));
      S(v.disallow).split('\n').map(x => x.trim()).filter(Boolean).forEach(p => lines.push(`Disallow: ${p}`));
      if (S(v.sitemap).trim()) lines.push(`Sitemap: ${S(v.sitemap).trim()}`);
      if (lines.length === 1 && !S(v.allow).trim() && !S(v.disallow).trim() && !S(v.sitemap).trim()) return '';
      return { out: lines.join('\n') };
    },
  },
  {
    id: 'wb-robots-test', name: 'robots.txt Tester', cat: 'web',
    desc: 'Check whether a path is allowed by robots.txt rules (longest match wins).',
    tags: ['robots', 'seo', 'test'],
    inputs: [
      { k: 'rules', type: 'textarea', label: 'robots.txt content', rows: 6, ph: 'User-agent: *\nDisallow: /admin', def: '' },
      { k: 'path', type: 'text', label: 'Path to test', ph: '/admin/page', def: '' },
      { k: 'ua', type: 'text', label: 'User-agent', ph: '*', def: '*' },
    ],
    run(v) {
      const rules = S(v.rules), path = S(v.path).trim();
      if (!rules.trim() || !path) return '';
      const ua = S(v.ua).trim() || '*';
      const groups = [];
      let cur = null;
      for (const raw of rules.split('\n')) {
        const line = raw.replace(/#.*$/, '').trim();
        if (!line) continue;
        const i = line.indexOf(':');
        if (i < 0) continue;
        const field = line.slice(0, i).trim().toLowerCase(), val = line.slice(i + 1).trim();
        if (field === 'user-agent') {
          if (!cur || cur.rules.length) { cur = { agents: [], rules: [] }; groups.push(cur); }
          cur.agents.push(val);
        } else if ((field === 'allow' || field === 'disallow') && cur) {
          cur.rules.push({ type: field, path: val });
        }
      }
      let group = groups.find(g => g.agents.includes(ua)) || groups.find(g => g.agents.includes('*'));
      if (!group) return { out: `No matching group; ${path} is ALLOWED by default.` };
      let best = null;
      for (const r of group.rules) {
        const res = robotMatch(r.path, path);
        if (res.m && (!best || res.len > best.len || (res.len === best.len && r.type === 'allow')))
          best = { type: r.type, len: res.len, pattern: r.path };
      }
      if (!best) return { out: `${path} is ALLOWED (no rule matches).` };
      return { out: `${path} is ${best.type === 'allow' ? 'ALLOWED' : 'DISALLOWED'} by rule "${best.type}: ${best.pattern}".` };
    },
  },
  {
    id: 'wb-sitemap-entry', name: 'Sitemap URL Entry Builder', cat: 'web',
    desc: 'Build a sitemap.xml <url> entry with loc, lastmod, changefreq, and priority.',
    tags: ['sitemap', 'seo', 'xml'],
    inputs: [
      { k: 'loc', type: 'text', label: 'URL (loc)', ph: 'https://a.com/page', def: '' },
      { k: 'lastmod', type: 'text', label: 'Last modified (optional)', ph: '2026-01-01', def: '' },
      { k: 'freq', type: 'select', label: 'Change frequency', opts: ['(none)', 'always', 'hourly', 'daily', 'weekly', 'monthly', 'yearly', 'never'], def: '(none)' },
      { k: 'priority', type: 'text', label: 'Priority 0.0-1.0 (optional)', ph: '0.8', def: '' },
    ],
    run(v, H) {
      const loc = S(v.loc).trim();
      if (!loc) return '';
      const lines = ['  <url>', `    <loc>${H.escapeHtml(loc)}</loc>`];
      if (S(v.lastmod).trim()) lines.push(`    <lastmod>${H.escapeHtml(S(v.lastmod).trim())}</lastmod>`);
      if (v.freq && v.freq !== '(none)') lines.push(`    <changefreq>${v.freq}</changefreq>`);
      if (S(v.priority).trim()) lines.push(`    <priority>${H.escapeHtml(S(v.priority).trim())}</priority>`);
      lines.push('  </url>');
      return { out: lines.join('\n') };
    },
  },
  {
    id: 'wb-referrer-policy', name: 'Referrer-Policy Explainer', cat: 'web',
    desc: 'Explain a Referrer-Policy value, or list all values.',
    tags: ['referrer', 'security', 'reference'],
    inputs: [{ k: 'p', type: 'select', label: 'Policy', opts: ['(all)', 'no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url'], def: 'strict-origin-when-cross-origin' }],
    run(v) {
      const p = S(v.p || '(all)');
      if (p === '(all)') return { out: Object.keys(REFERRER_POLICY).map(k => `${k}: ${REFERRER_POLICY[k]}`).join('\n') };
      const d = REFERRER_POLICY[p];
      return d ? { out: `${p}\n${d}` } : { error: 'Unknown policy.' };
    },
  },
  {
    id: 'wb-permissions-policy', name: 'Permissions-Policy Builder', cat: 'web',
    desc: 'Build a Permissions-Policy header from feature=allowlist lines.',
    tags: ['permissions', 'security', 'build'],
    inputs: [{ k: 'lines', type: 'textarea', label: 'feature=origins per line', rows: 5, ph: 'geolocation=self\ncamera=none\nmicrophone=https://a.com', def: '' }],
    run(v) {
      const txt = S(v.lines);
      if (!txt.trim()) return '';
      const parts = [];
      for (const line of txt.split('\n')) {
        if (!line.trim()) continue;
        const i = line.indexOf('=');
        const feat = (i < 0 ? line : line.slice(0, i)).trim();
        let list = (i < 0 ? '' : line.slice(i + 1)).trim();
        if (list === 'none' || list === '') { parts.push(`${feat}=()`); continue; }
        const tokens = list.split(/\s+/).map(t => t === 'self' ? 'self' : t === '*' ? '*' : `"${t.replace(/"/g, '')}"`);
        parts.push(`${feat}=(${tokens.join(' ')})`);
      }
      return { out: 'Permissions-Policy: ' + parts.join(', ') };
    },
  },
  {
    id: 'wb-hsts-build', name: 'HSTS Header Builder', cat: 'web',
    desc: 'Build a Strict-Transport-Security header.',
    tags: ['hsts', 'security', 'build'],
    inputs: [
      { k: 'maxage', type: 'text', label: 'max-age seconds', ph: '31536000', def: '31536000' },
      { k: 'subdomains', type: 'checkbox', label: 'includeSubDomains', def: true },
      { k: 'preload', type: 'checkbox', label: 'preload', def: false },
    ],
    run(v) {
      const ma = S(v.maxage).trim() || '31536000';
      if (!/^\d+$/.test(ma)) return { error: 'max-age must be numeric.' };
      let out = `max-age=${ma}`;
      if (v.subdomains) out += '; includeSubDomains';
      if (v.preload) out += '; preload';
      return { out: 'Strict-Transport-Security: ' + out };
    },
  },
  {
    id: 'wb-hsts-parse', name: 'HSTS Parser', cat: 'web',
    desc: 'Parse a Strict-Transport-Security header into its directives.',
    tags: ['hsts', 'security', 'parse'],
    inputs: [{ k: 'h', type: 'text', label: 'HSTS value', ph: 'max-age=31536000; includeSubDomains', def: '' }],
    run(v) {
      let s = S(v.h).trim();
      if (!s) return '';
      s = s.replace(/^Strict-Transport-Security:\s*/i, '');
      const parts = s.split(';').map(x => x.trim()).filter(Boolean);
      const lines = [];
      for (const p of parts) {
        const m = p.match(/^max-age=(\d+)$/i);
        if (m) {
          const days = (parseInt(m[1], 10) / 86400).toFixed(1);
          lines.push(`max-age: ${m[1]} seconds (~${days} days)`);
        } else if (/^includeSubDomains$/i.test(p)) lines.push('includeSubDomains: applies to all subdomains');
        else if (/^preload$/i.test(p)) lines.push('preload: eligible for browser preload lists');
        else lines.push(p);
      }
      return { out: lines.join('\n') };
    },
  },
  {
    id: 'wb-etag-gen', name: 'ETag Generator', cat: 'web',
    desc: 'Generate a weak or strong ETag from content using a simple hash.',
    tags: ['etag', 'cache', 'hash'],
    inputs: [
      { k: 'content', type: 'textarea', label: 'Content', rows: 5, ph: 'response body', def: '' },
      { k: 'weak', type: 'checkbox', label: 'Weak validator (W/)', def: false },
    ],
    run(v) {
      const c = S(v.content);
      if (!c) return '';
      let h = 2166136261;
      for (let i = 0; i < c.length; i++) { h ^= c.charCodeAt(i); h = Math.imul(h, 16777619); }
      const hex = (h >>> 0).toString(16).padStart(8, '0');
      const tag = `"${c.length.toString(16)}-${hex}"`;
      return { out: 'ETag: ' + (v.weak ? 'W/' + tag : tag) };
    },
  },
  {
    id: 'wb-accept-lang', name: 'Accept-Language Parser', cat: 'web',
    desc: 'Parse Accept-Language, sorting languages by q-value.',
    tags: ['accept-language', 'header', 'parse'],
    inputs: [{ k: 'h', type: 'text', label: 'Accept-Language', ph: 'en-US,en;q=0.9,fr;q=0.8', def: '' }],
    run(v) {
      let s = S(v.h).trim();
      if (!s) return '';
      s = s.replace(/^Accept-Language:\s*/i, '');
      return { out: parseQList(s).map(x => `${x.val}  (q=${x.q})`).join('\n') };
    },
  },
  {
    id: 'wb-accept-parse', name: 'Accept Header Parser', cat: 'web',
    desc: 'Parse an Accept header into media types sorted by q-value.',
    tags: ['accept', 'header', 'parse'],
    inputs: [{ k: 'h', type: 'text', label: 'Accept', ph: 'text/html,application/xml;q=0.9,*/*;q=0.8', def: '' }],
    run(v) {
      let s = S(v.h).trim();
      if (!s) return '';
      s = s.replace(/^Accept:\s*/i, '');
      return { out: parseQList(s).map(x => `${x.val}  (q=${x.q})`).join('\n') };
    },
  },
  {
    id: 'wb-link-header', name: 'Link Header Builder', cat: 'web',
    desc: 'Build a Link header from URL + rel lines.',
    tags: ['link', 'header', 'build'],
    inputs: [{ k: 'lines', type: 'textarea', label: 'url rel per line', rows: 4, ph: '/page/2 next\n/page/1 prev', def: '' }],
    run(v) {
      const txt = S(v.lines);
      if (!txt.trim()) return '';
      const parts = [];
      for (const line of txt.split('\n')) {
        const t = line.trim();
        if (!t) continue;
        const sp = t.split(/\s+/);
        const url = sp[0];
        const rel = sp.slice(1).join(' ') || 'related';
        parts.push(`<${url}>; rel="${rel}"`);
      }
      return { out: 'Link: ' + parts.join(', ') };
    },
  },
  {
    id: 'wb-range-header', name: 'Range Header Builder', cat: 'web',
    desc: 'Build a Range request header for one or more byte ranges.',
    tags: ['range', 'header', 'build'],
    inputs: [
      { k: 'start', type: 'text', label: 'Start byte', ph: '0', def: '' },
      { k: 'end', type: 'text', label: 'End byte (optional)', ph: '1023', def: '' },
    ],
    run(v) {
      const start = S(v.start).trim(), end = S(v.end).trim();
      if (!start && !end) return '';
      if (start && !/^\d+$/.test(start)) return { error: 'Start must be numeric.' };
      if (end && !/^\d+$/.test(end)) return { error: 'End must be numeric.' };
      if (!start && end) return { out: `Range: bytes=-${end}` };
      return { out: `Range: bytes=${start}-${end}` };
    },
  },
  {
    id: 'wb-retry-after', name: 'Retry-After Builder', cat: 'web',
    desc: 'Build a Retry-After header as seconds or an HTTP date.',
    tags: ['retry-after', 'header', 'build'],
    inputs: [
      { k: 'mode', type: 'select', label: 'Mode', opts: [['secs', 'Seconds'], ['date', 'HTTP date (from now)']], def: 'secs' },
      { k: 'value', type: 'text', label: 'Seconds', ph: '120', def: '' },
    ],
    run(v) {
      const val = S(v.value).trim();
      if (!val) return '';
      if (!/^\d+$/.test(val)) return { error: 'Enter a number of seconds.' };
      if (v.mode === 'date') {
        const d = new Date(Date.now() + parseInt(val, 10) * 1000);
        return { out: 'Retry-After: ' + d.toUTCString() };
      }
      return { out: 'Retry-After: ' + val };
    },
  },
  {
    id: 'wb-xff-parse', name: 'X-Forwarded-For Parser', cat: 'web',
    desc: 'Parse X-Forwarded-For into the client IP and proxy chain.',
    tags: ['x-forwarded-for', 'proxy', 'parse'],
    inputs: [{ k: 'h', type: 'text', label: 'X-Forwarded-For', ph: '203.0.113.1, 70.41.3.18, 150.172.238.178', def: '' }],
    run(v) {
      let s = S(v.h).trim();
      if (!s) return '';
      s = s.replace(/^X-Forwarded-For:\s*/i, '');
      const ips = s.split(',').map(x => x.trim()).filter(Boolean);
      if (!ips.length) return { out: '(empty)' };
      const lines = [`Client (original): ${ips[0]}`];
      ips.slice(1).forEach((ip, i) => lines.push(`Proxy ${i + 1}: ${ip}`));
      return { out: lines.join('\n') };
    },
  },
  {
    id: 'wb-punycode-host', name: 'Punycode Host Encoder', cat: 'web',
    desc: 'Encode an internationalized (IDN) host to ASCII punycode.',
    tags: ['punycode', 'idn', 'url'],
    inputs: [{ k: 'host', type: 'text', label: 'Host', ph: 'münchen.de', def: '' }],
    run(v) {
      const host = S(v.host).trim();
      if (!host) return '';
      try {
        const u = new URL('http://' + host);
        return { out: u.host };
      } catch { return { error: 'Invalid host.' }; }
    },
  },
  {
    id: 'wb-favicon-link', name: 'Favicon Link Builder', cat: 'web',
    desc: 'Build a <link rel="icon"> tag for a favicon.',
    tags: ['favicon', 'html', 'build'],
    inputs: [
      { k: 'href', type: 'text', label: 'Href', ph: '/favicon.ico', def: '/favicon.ico' },
      { k: 'sizes', type: 'text', label: 'Sizes (optional)', ph: '32x32', def: '' },
    ],
    run(v, H) {
      const href = S(v.href).trim();
      if (!href) return '';
      const ext = href.split('.').pop().toLowerCase();
      const type = MIME_EXT[ext] || '';
      let out = `<link rel="icon"`;
      if (type) out += ` type="${type}"`;
      if (S(v.sizes).trim()) out += ` sizes="${H.escapeHtml(S(v.sizes).trim())}"`;
      out += ` href="${H.escapeHtml(href)}">`;
      return { out };
    },
  },
  {
    id: 'wb-og-tags', name: 'Open Graph Tags Builder', cat: 'web',
    desc: 'Build Open Graph <meta> tags for social sharing.',
    tags: ['open-graph', 'meta', 'seo'],
    inputs: [
      { k: 'title', type: 'text', label: 'og:title', ph: 'My Page', def: '' },
      { k: 'type', type: 'text', label: 'og:type', ph: 'website', def: 'website' },
      { k: 'url', type: 'text', label: 'og:url', ph: 'https://a.com', def: '' },
      { k: 'image', type: 'text', label: 'og:image', ph: 'https://a.com/img.png', def: '' },
      { k: 'desc', type: 'text', label: 'og:description', ph: 'A description', def: '' },
    ],
    run(v, H) {
      const map = { title: v.title, type: v.type, url: v.url, image: v.image, description: v.desc };
      const lines = [];
      for (const k in map) {
        const val = S(map[k]).trim();
        if (val) lines.push(`<meta property="og:${k}" content="${H.escapeHtml(val)}">`);
      }
      return lines.length ? { out: lines.join('\n') } : '';
    },
  },
  {
    id: 'wb-twitter-card', name: 'Twitter Card Tags Builder', cat: 'web',
    desc: 'Build Twitter card <meta> tags.',
    tags: ['twitter', 'meta', 'seo'],
    inputs: [
      { k: 'card', type: 'select', label: 'Card type', opts: ['summary', 'summary_large_image', 'app', 'player'], def: 'summary_large_image' },
      { k: 'site', type: 'text', label: '@site (optional)', ph: '@brand', def: '' },
      { k: 'title', type: 'text', label: 'Title', ph: 'My Page', def: '' },
      { k: 'desc', type: 'text', label: 'Description', ph: 'A description', def: '' },
      { k: 'image', type: 'text', label: 'Image URL', ph: 'https://a.com/img.png', def: '' },
    ],
    run(v, H) {
      const lines = [`<meta name="twitter:card" content="${S(v.card || 'summary')}">`];
      const map = { site: v.site, title: v.title, description: v.desc, image: v.image };
      for (const k in map) {
        const val = S(map[k]).trim();
        if (val) lines.push(`<meta name="twitter:${k}" content="${H.escapeHtml(val)}">`);
      }
      return { out: lines.join('\n') };
    },
  },
  {
    id: 'wb-meta-viewport', name: 'Meta Viewport Builder', cat: 'web',
    desc: 'Build a responsive <meta name="viewport"> tag.',
    tags: ['viewport', 'meta', 'responsive'],
    inputs: [
      { k: 'width', type: 'text', label: 'width', ph: 'device-width', def: 'device-width' },
      { k: 'scale', type: 'text', label: 'initial-scale', ph: '1', def: '1' },
      { k: 'userscale', type: 'checkbox', label: 'Allow user scaling', def: true },
    ],
    run(v) {
      const parts = [`width=${S(v.width).trim() || 'device-width'}`, `initial-scale=${S(v.scale).trim() || '1'}`];
      if (!v.userscale) parts.push('user-scalable=no', 'maximum-scale=1');
      return { out: `<meta name="viewport" content="${parts.join(', ')}">` };
    },
  },
  {
    id: 'wb-canonical-link', name: 'Canonical Link Builder', cat: 'web',
    desc: 'Build a <link rel="canonical"> tag.',
    tags: ['canonical', 'seo', 'html'],
    inputs: [{ k: 'url', type: 'text', label: 'Canonical URL', ph: 'https://a.com/page', def: '' }],
    run(v, H) {
      const url = S(v.url).trim();
      if (!url) return '';
      return { out: `<link rel="canonical" href="${H.escapeHtml(url)}">` };
    },
  },
  {
    id: 'wb-hreflang-tags', name: 'Hreflang Tags Builder', cat: 'web',
    desc: 'Build hreflang alternate <link> tags from lang url lines.',
    tags: ['hreflang', 'seo', 'i18n'],
    inputs: [{ k: 'lines', type: 'textarea', label: 'lang url per line', rows: 5, ph: 'en https://a.com/en\nfr https://a.com/fr\nx-default https://a.com', def: '' }],
    run(v, H) {
      const txt = S(v.lines);
      if (!txt.trim()) return '';
      const lines = [];
      for (const line of txt.split('\n')) {
        const t = line.trim();
        if (!t) continue;
        const sp = t.split(/\s+/);
        if (sp.length < 2) continue;
        lines.push(`<link rel="alternate" hreflang="${H.escapeHtml(sp[0])}" href="${H.escapeHtml(sp[1])}">`);
      }
      return lines.length ? { out: lines.join('\n') } : '';
    },
  },
  {
    id: 'wb-srcset-build', name: 'Srcset Builder', cat: 'web',
    desc: 'Build an img srcset attribute from url + width/density lines.',
    tags: ['srcset', 'responsive', 'images'],
    inputs: [{ k: 'lines', type: 'textarea', label: 'url descriptor per line', rows: 5, ph: 'small.jpg 480w\nlarge.jpg 1024w', def: '' }],
    run(v) {
      const txt = S(v.lines);
      if (!txt.trim()) return '';
      const parts = [];
      for (const line of txt.split('\n')) {
        const t = line.trim();
        if (!t) continue;
        const sp = t.split(/\s+/);
        parts.push(sp.length > 1 ? `${sp[0]} ${sp[1]}` : sp[0]);
      }
      return { out: `srcset="${parts.join(', ')}"` };
    },
  },
  {
    id: 'wb-www-auth-parse', name: 'WWW-Authenticate Parser', cat: 'web',
    desc: 'Parse a WWW-Authenticate header into scheme and parameters.',
    tags: ['auth', 'header', 'parse'],
    inputs: [{ k: 'h', type: 'textarea', label: 'WWW-Authenticate value', rows: 3, ph: 'Bearer realm="api", error="invalid_token"', def: '' }],
    run(v) {
      let s = S(v.h).trim();
      if (!s) return '';
      s = s.replace(/^WWW-Authenticate:\s*/i, '');
      const sp = s.indexOf(' ');
      const scheme = sp < 0 ? s : s.slice(0, sp);
      const rest = sp < 0 ? '' : s.slice(sp + 1);
      const lines = [`scheme: ${scheme}`];
      const re = /([a-zA-Z0-9_-]+)\s*=\s*(?:"([^"]*)"|([^,\s]+))/g;
      let m;
      while ((m = re.exec(rest)) !== null) lines.push(`${m[1]}: ${m[2] !== undefined ? m[2] : m[3]}`);
      return { out: lines.join('\n') };
    },
  },
  {
    id: 'wb-http-date', name: 'HTTP Date Formatter', cat: 'web',
    desc: 'Format a date as an IMF-fixdate HTTP date, defaulting to now.',
    tags: ['date', 'header', 'format'],
    inputs: [{ k: 'input', type: 'text', label: 'Date/time (blank = now)', ph: '2026-01-01T12:00:00Z', def: '' }],
    run(v) {
      const s = S(v.input).trim();
      const d = s ? new Date(s) : new Date();
      if (isNaN(d.getTime())) return { error: 'Could not parse that date.' };
      return { out: d.toUTCString() };
    },
  },
  {
    id: 'wb-url-encode', name: 'URL Encode / Decode', cat: 'web',
    desc: 'Percent-encode or decode a URL component.',
    tags: ['url', 'encode', 'decode'],
    inputs: [
      { k: 'text', type: 'textarea', label: 'Text', rows: 3, ph: 'hello world & more', def: '' },
      { k: 'mode', type: 'select', label: 'Mode', opts: [['enc', 'Encode'], ['dec', 'Decode']], def: 'enc' },
    ],
    run(v) {
      const t = S(v.text);
      if (!t) return '';
      try {
        return { out: v.mode === 'dec' ? decodeURIComponent(t) : encodeURIComponent(t) };
      } catch { return { error: 'Malformed percent-encoding.' }; }
    },
  },
  {
    id: 'wb-slug', name: 'URL Slug from Title', cat: 'web',
    desc: 'Convert a title into a clean, lowercase URL slug.',
    tags: ['slug', 'url', 'seo'],
    inputs: [{ k: 'title', type: 'text', label: 'Title', ph: 'Hello, World! 2026', def: '' }],
    run(v) {
      const t = S(v.title).trim();
      if (!t) return '';
      const slug = t.toLowerCase()
        .normalize('NFKD').replace(/[̀-ͯ]/g, '')
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '');
      return { out: slug || '(empty)' };
    },
  },
  {
    id: 'wb-extract-urls', name: 'Extract URLs from Text', cat: 'web',
    desc: 'Find all http/https URLs in a block of text.',
    tags: ['url', 'extract', 'text'],
    inputs: [{ k: 'text', type: 'textarea', label: 'Text', rows: 6, ph: 'Visit https://a.com and http://b.org', def: '' }],
    run(v) {
      const t = S(v.text);
      if (!t.trim()) return '';
      const m = t.match(/https?:\/\/[^\s<>"')\]]+/g) || [];
      const uniq = [...new Set(m)];
      return uniq.length ? { out: uniq.join('\n') } : { out: '(no URLs found)' };
    },
  },
  {
    id: 'wb-extract-params', name: 'Extract Query Params from URL', cat: 'web',
    desc: 'List all query parameters from a full URL.',
    tags: ['url', 'query', 'extract'],
    inputs: [{ k: 'url', type: 'text', label: 'URL', ph: 'https://a.com/?a=1&b=2', def: '' }],
    run(v) {
      const s = S(v.url).trim();
      if (!s) return '';
      try {
        const u = new URL(s);
        const lines = [];
        for (const [k, val] of u.searchParams.entries()) lines.push(`${k} = ${val}`);
        return lines.length ? { out: lines.join('\n') } : { out: '(no query parameters)' };
      } catch { return { error: 'Invalid URL.' }; }
    },
  },
  {
    id: 'wb-valid-url', name: 'Is Valid URL', cat: 'web',
    desc: 'Check whether a string is a valid absolute URL.',
    tags: ['url', 'validate'],
    inputs: [{ k: 'url', type: 'text', label: 'URL', ph: 'https://example.com', def: '' }],
    run(v) {
      const s = S(v.url).trim();
      if (!s) return '';
      try { const u = new URL(s); return { out: `Valid URL. Protocol: ${u.protocol}` }; }
      catch { return { out: 'Not a valid absolute URL.' }; }
    },
  },
  {
    id: 'wb-valid-email', name: 'Is Valid Email', cat: 'web',
    desc: 'Check whether a string looks like a valid email address.',
    tags: ['email', 'validate'],
    inputs: [{ k: 'email', type: 'text', label: 'Email', ph: 'user@example.com', def: '' }],
    run(v) {
      const s = S(v.email).trim();
      if (!s) return '';
      const ok = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(s);
      return { out: ok ? 'Looks like a valid email address.' : 'Does not look like a valid email address.' };
    },
  },
  {
    id: 'wb-valid-ipv4', name: 'Is Valid IPv4', cat: 'web',
    desc: 'Check whether a string is a valid IPv4 address.',
    tags: ['ip', 'ipv4', 'validate'],
    inputs: [{ k: 'ip', type: 'text', label: 'IPv4 address', ph: '192.168.0.1', def: '' }],
    run(v) {
      const s = S(v.ip).trim();
      if (!s) return '';
      const parts = s.split('.');
      const ok = parts.length === 4 && parts.every(p => /^\d{1,3}$/.test(p) && +p >= 0 && +p <= 255 && (p === '0' || !/^0/.test(p)));
      return { out: ok ? 'Valid IPv4 address.' : 'Not a valid IPv4 address.' };
    },
  },
  {
    id: 'wb-port-service', name: 'Port to Service Name', cat: 'web',
    desc: 'Look up the common service for a well-known port number.',
    tags: ['port', 'service', 'reference'],
    inputs: [{ k: 'port', type: 'text', label: 'Port number', ph: '443', def: '' }],
    run(v) {
      const s = S(v.port).trim();
      if (!s) return '';
      const n = parseInt(s, 10);
      if (isNaN(n)) return { error: 'Enter a numeric port.' };
      const svc = PORTS[n];
      return svc ? { out: `${n}: ${svc}` } : { error: `No well-known service registered for port ${n}.` };
    },
  },
  {
    id: 'wb-status-emoji', name: 'Status Code Emoji Summary', cat: 'web',
    desc: 'Summarize a status code with a class emoji, name, and meaning.',
    tags: ['http', 'status', 'emoji'],
    inputs: [{ k: 'code', type: 'text', label: 'Status code', ph: '500', def: '' }],
    run(v) {
      const s = S(v.code).trim();
      if (!s) return '';
      const code = parseInt(s, 10);
      if (isNaN(code)) return { error: 'Enter a numeric status code.' };
      const e = STATUS[code];
      if (!e) return { error: `${code} is not a standard status code.` };
      const label = { 1: '[INFO]', 2: '[OK]', 3: '[REDIRECT]', 4: '[CLIENT ERROR]', 5: '[SERVER ERROR]' }[Math.floor(code / 100)] || '[UNKNOWN]';
      return { out: `${label} ${code} ${e[0]} — ${e[1]}` };
    },
  },
  {
    id: 'wb-http-request-build', name: 'HTTP/1.1 Request Builder', cat: 'web',
    desc: 'Build a raw HTTP/1.1 request from method, path, host, headers, and body.',
    tags: ['http', 'request', 'build'],
    inputs: [
      { k: 'method', type: 'select', label: 'Method', opts: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'], def: 'GET' },
      { k: 'path', type: 'text', label: 'Path', ph: '/api/v1/items?x=1', def: '/' },
      { k: 'host', type: 'text', label: 'Host', ph: 'example.com', def: '' },
      { k: 'headers', type: 'textarea', label: 'Extra headers (Name: value per line)', rows: 4, ph: 'Accept: application/json', def: '' },
      { k: 'body', type: 'textarea', label: 'Body (optional)', rows: 3, ph: '', def: '' },
    ],
    run(v) {
      const host = S(v.host).trim();
      if (!host) return '';
      const method = S(v.method || 'GET');
      const path = S(v.path).trim() || '/';
      const lines = [`${method} ${path} HTTP/1.1`, `Host: ${host}`];
      for (const line of S(v.headers).split('\n')) {
        if (line.trim()) lines.push(line.trim());
      }
      const body = S(v.body);
      if (body) {
        lines.push(`Content-Length: ${body.length}`);
        lines.push('', body);
      } else {
        lines.push('');
      }
      return { out: lines.join('\n') };
    },
  },
  {
    id: 'wb-parse-headers', name: 'Parse Raw HTTP Headers', cat: 'web',
    desc: 'Parse a raw HTTP header block into a name/value table.',
    tags: ['http', 'headers', 'parse'],
    inputs: [{ k: 'block', type: 'textarea', label: 'Raw headers', rows: 8, ph: 'Content-Type: text/html\nCache-Control: no-cache', def: '' }],
    run(v) {
      const txt = S(v.block);
      if (!txt.trim()) return '';
      const lines = [];
      for (const raw of txt.split('\n')) {
        const line = raw.replace(/\r$/, '');
        if (!line.trim()) continue;
        if (/^HTTP\/\d/.test(line) || /^[A-Z]+ \S+ HTTP\//.test(line)) { lines.push(`[start-line] ${line.trim()}`); continue; }
        const i = line.indexOf(':');
        if (i < 0) { lines.push(`(malformed) ${line.trim()}`); continue; }
        lines.push(`${line.slice(0, i).trim()} = ${line.slice(i + 1).trim()}`);
      }
      return { out: lines.join('\n') };
    },
  },
  {
    id: 'wb-url-strip-tracking', name: 'Strip Tracking Params', cat: 'web',
    desc: 'Remove common tracking query parameters (utm_*, fbclid, gclid, and more) from a URL.',
    tags: ['url', 'privacy', 'query'],
    inputs: [{ k: 'url', type: 'text', label: 'URL', ph: 'https://a.com/p?id=1&utm_source=x&fbclid=y', def: '' }],
    run(v) {
      const s = S(v.url).trim();
      if (!s) return '';
      const junk = ['fbclid', 'gclid', 'dclid', 'gclsrc', 'msclkid', 'mc_cid', 'mc_eid', 'igshid', 'yclid', '_ga', 'ref', 'ref_src', 'vero_id'];
      try {
        const u = new URL(s);
        for (const key of [...u.searchParams.keys()]) {
          if (/^utm_/i.test(key) || junk.includes(key.toLowerCase())) u.searchParams.delete(key);
        }
        return { out: u.toString() };
      } catch { return { error: 'Invalid URL.' }; }
    },
  },
  {
    id: 'wb-url-normalize', name: 'URL Normalizer', cat: 'web',
    desc: 'Normalize a URL: lowercase host, drop default port, and sort query params.',
    tags: ['url', 'normalize'],
    inputs: [
      { k: 'url', type: 'text', label: 'URL', ph: 'HTTPS://Example.com:443/a/../b?c=2&a=1', def: '' },
      { k: 'sort', type: 'checkbox', label: 'Sort query params', def: true },
    ],
    run(v) {
      const s = S(v.url).trim();
      if (!s) return '';
      try {
        const u = new URL(s);
        u.hostname = u.hostname.toLowerCase();
        u.protocol = u.protocol.toLowerCase();
        if ((u.protocol === 'http:' && u.port === '80') || (u.protocol === 'https:' && u.port === '443')) u.port = '';
        if (v.sort) {
          const entries = [...u.searchParams.entries()].sort((a, b) => a[0].localeCompare(b[0]));
          const p = new URLSearchParams();
          for (const [k, val] of entries) p.append(k, val);
          u.search = p.toString();
        }
        return { out: u.toString() };
      } catch { return { error: 'Invalid URL.' }; }
    },
  },
];
