// API Security Review engine tests (public/js/appsec/apispec-engine.js).
// Fixtures follow the real layouts: OpenAPI 3.0 / 3.1 (spec.openapis.org), Swagger 2.0
// (swagger.io/specification/v2), Postman Collection v2.1 export (schema.getpostman.com
// collection/v2.1.0), GraphQL SDL (spec.graphql.org) and the standard introspection query result.

import { test, assert, group } from "../harness.mjs";
import {
  selfTest, analyze, parseInput, parseFile, exampleDataset, findingsToCsv, inventoryToCsv, toSarif, toTxt,
  jsonLineMap, yamlLineMap, parseYaml, expandYamlAnchors, parseGraphqlSdl, FINDING_COLS, INVENTORY_COLS, RULES,
} from "../../public/js/appsec/apispec-engine.js";

const run = (name, text, opts) => analyze([{ name, text }], opts);
const ids = (r) => r.findings.map((f) => f.ruleId);
const hits = (r, id) => r.findings.filter((f) => f.ruleId === id);
const oas = (paths, extra = {}) => JSON.stringify({ openapi: "3.0.3", info: { title: "Fixture", version: "1.0.0" }, servers: [{ url: "https://api.fixture.io" }], paths, ...extra }, null, 2);
const bearer = { components: { securitySchemes: { bearer: { type: "http", scheme: "bearer" } } }, security: [{ bearer: [] }] };
const ok200 = { 200: { description: "ok" } };

// OpenAPI 3.1 JSON, no security at all
const OAS31 = JSON.stringify({
  openapi: "3.1.0",
  info: { title: "Orchid Inventory", version: "0.9.1" },
  servers: [{ url: "https://inv.fixture.io/api" }],
  paths: {
    "/items/{itemId}": {
      parameters: [{ name: "itemId", in: "path", required: true, schema: { type: "string" } }],
      get: { responses: { 200: { description: "Item", content: { "application/json": { schema: { $ref: "#/components/schemas/Item" } } } } } },
      delete: { responses: { 204: { description: "Deleted" } } },
    },
  },
  components: { schemas: { Item: { type: "object", properties: { id: { type: ["string", "null"] }, name: { type: "string" } } } } },
}, null, 2);

// Swagger 2.0 JSON
const SWAGGER_JSON = `{
  "swagger": "2.0",
  "info": { "title": "Fernwood Files", "version": "1.2" },
  "host": "files.fixture.io",
  "basePath": "/v1",
  "schemes": ["http", "https"],
  "consumes": ["application/json"],
  "securityDefinitions": {
    "basicAuth": { "type": "basic" },
    "legacyOauth": { "type": "oauth2", "flow": "password", "tokenUrl": "https://files.fixture.io/oauth/token", "scopes": { "files:write": "Write files" } }
  },
  "security": [{ "basicAuth": [] }],
  "paths": {
    "/files": {
      "post": {
        "consumes": ["multipart/form-data"],
        "parameters": [
          { "name": "upload", "in": "formData", "type": "file", "required": true },
          { "name": "note", "in": "formData", "type": "string", "maxLength": 200 }
        ],
        "responses": { "201": { "description": "Stored" } }
      }
    },
    "/files/{fileId}": {
      "put": {
        "parameters": [
          { "name": "fileId", "in": "path", "required": true, "type": "string" },
          { "name": "body", "in": "body", "schema": { "$ref": "#/definitions/FileMeta" } }
        ],
        "responses": { "200": { "description": "ok", "schema": { "$ref": "#/definitions/FileMeta" } } }
      }
    }
  },
  "definitions": {
    "FileMeta": { "type": "object", "properties": { "name": { "type": "string", "maxLength": 100 }, "ownerId": { "type": "string", "maxLength": 36 } } }
  }
}`;

// Swagger 2.0 YAML
const SWAGGER_YAML = `swagger: "2.0"
info:
  title: Quillon Notes
  version: "3.0"
host: notes.fixture.io
schemes:
  - https
securityDefinitions:
  key:
    type: apiKey
    in: header
    name: X-API-Key
security:
  - key: []
paths:
  /notes:
    get:
      parameters:
        - name: limit
          in: query
          type: integer
          maximum: 100
      responses:
        "200":
          description: Notes
          schema:
            type: array
            items:
              $ref: "#/definitions/Note"
        "429":
          description: Too many requests
definitions:
  Note:
    type: object
    properties:
      id:
        type: string
      body:
        type: string
`;

// Postman Collection v2.1 export layout. The token is assembled at runtime so no
// credential-shaped literal is stored in the repository.
const FAKE_GH = "ghp_" + "Zq8".repeat(12);
const POSTMAN = `{
	"info": {
		"_postman_id": "6c0f2b7e-1d1a-4c1e-9a55-3f0f6c2b9d10",
		"name": "Brindle Orders",
		"schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
		"_exporter_id": "1234567"
	},
	"item": [
		{
			"name": "Orders",
			"item": [
				{
					"name": "Get order",
					"request": {
						"method": "GET",
						"header": [
							{ "key": "X-API-Key", "value": "{{apiKey}}", "type": "text" }
						],
						"url": {
							"raw": "{{baseUrl}}/orders/42",
							"host": ["{{baseUrl}}"],
							"path": ["orders", "42"]
						}
					},
					"response": []
				},
				{
					"name": "Create order",
					"request": {
						"auth": {
							"type": "basic",
							"basic": [
								{ "key": "password", "value": "Winter-Orchard-2026", "type": "string" },
								{ "key": "username", "value": "test@darknode.ai", "type": "string" }
							]
						},
						"method": "POST",
						"header": [],
						"body": { "mode": "raw", "raw": "{\\"sku\\": \\"A1\\"}" },
						"url": { "raw": "https://orders.fixture.io/orders", "protocol": "https", "host": ["orders", "fixture", "io"], "path": ["orders"] }
					},
					"response": []
				}
			]
		}
	],
	"auth": {
		"type": "bearer",
		"bearer": [
			{ "key": "token", "value": "${FAKE_GH}", "type": "string" }
		]
	},
	"variable": [
		{ "key": "baseUrl", "value": "http://orders.fixture.io", "type": "string" },
		{ "key": "apiKey", "value": "{{vaultKey}}", "type": "string" }
	]
}`;

// GraphQL introspection result (data.__schema), as returned by the standard query
const T = (kind, name, ofType = null) => ({ kind, name, ofType });
const INTROSPECTION = JSON.stringify({
  data: {
    __schema: {
      queryType: { name: "Query" }, mutationType: { name: "Mutation" }, subscriptionType: null,
      types: [
        { kind: "OBJECT", name: "Query", fields: [
          { name: "user", args: [{ name: "id", type: T("NON_NULL", null, T("SCALAR", "ID")), defaultValue: null }], type: T("OBJECT", "User"), isDeprecated: false, deprecationReason: null },
          { name: "users", args: [], type: T("NON_NULL", null, T("LIST", null, T("OBJECT", "User"))), isDeprecated: false, deprecationReason: null },
        ], inputFields: null, interfaces: [], enumValues: null, possibleTypes: null },
        { kind: "OBJECT", name: "Mutation", fields: [{ name: "deleteUser", args: [{ name: "id", type: T("NON_NULL", null, T("SCALAR", "ID")) }], type: T("SCALAR", "Boolean") }], inputFields: null, interfaces: [], enumValues: null, possibleTypes: null },
        { kind: "OBJECT", name: "User", fields: [{ name: "id", args: [], type: T("SCALAR", "ID") }, { name: "passwordHash", args: [], type: T("SCALAR", "String") }], inputFields: null, interfaces: [], enumValues: null, possibleTypes: null },
        { kind: "SCALAR", name: "ID", fields: null }, { kind: "SCALAR", name: "String", fields: null }, { kind: "SCALAR", name: "Boolean", fields: null },
        { kind: "OBJECT", name: "__Schema", fields: [] },
      ],
      directives: [{ name: "include", locations: ["FIELD"], args: [] }, { name: "skip", locations: ["FIELD"], args: [] }, { name: "deprecated", locations: ["FIELD_DEFINITION"], args: [] }],
    },
  },
}, null, 2);

const SDL = `"""Root query"""
type Query {
  "Fetch one account"
  account(id: ID!): Account @auth(requires: USER)
  accounts(first: Int = 20, after: String): [Account!]!
  node(nodeId: ID!): Account
}
type Mutation {
  closeAccount(id: ID!): Boolean @auth(requires: ADMIN)
  renameAccount(id: ID!, name: String!): Account
}
type Account implements Node & Owned @key(fields: "id") {
  id: ID!
  name: String
  apiKey: String
}
interface Node { id: ID! }
interface Owned { id: ID! }
enum Role { USER ADMIN }
directive @auth(requires: Role = USER) on OBJECT | FIELD_DEFINITION
directive @key(fields: String!) repeatable on OBJECT
`;

group("apispec: parsers", () => {
  test("OpenAPI 3.0 YAML (example) detected with high confidence", () => {
    const p = parseInput(exampleDataset().files);
    assert.equal(p.rows[0].format, "openapi-3.0");
    assert.equal(p.rows[0].confidence, "high");
    assert.equal(p.rows[1].format, "graphql-sdl");
  });
  test("OpenAPI 3.1 JSON detected and parsed", () => {
    const d = parseFile("inv.json", OAS31);
    assert.equal(d.format, "openapi-3.1"); assert.equal(d.confidence, "high");
    assert.equal(run("inv.json", OAS31).tables.endpoints.length, 2);
  });
  test("Swagger 2.0 JSON detected; servers built from schemes/host/basePath", () => {
    const r = run("files.json", SWAGGER_JSON);
    assert.equal(r.tables.files[0].format, "swagger-2.0");
    assert.ok(r.findings.some((f) => f.ruleId === "APISPEC-HTTP-SERVER" && f.description.includes("http://files.fixture.io/v1")));
  });
  test("Swagger 2.0 YAML detected", () => {
    const r = run("notes.yaml", SWAGGER_YAML);
    assert.equal(r.tables.files[0].format, "swagger-2.0");
    assert.equal(r.tables.endpoints[0].operation, "GET /notes");
    assert.equal(r.tables.endpoints[0].auth, "key (apiKey)");
  });
  test("Postman v2.1 export detected; folders walked into the inventory", () => {
    const r = run("orders.postman_collection.json", POSTMAN);
    assert.equal(r.tables.files[0].format, "postman-2.1");
    assert.equal(r.tables.endpoints.length, 2);
    assert.deepEqual(r.tables.endpoints.map((e) => e.method).sort(), ["GET", "POST"]);
  });
  test("Postman without info.schema is read with medium confidence", () => {
    assert.equal(parseFile("c.json", JSON.stringify({ info: { name: "x" }, item: [] })).confidence, "medium");
  });
  test("GraphQL SDL detected by extension and by content", () => {
    assert.equal(parseFile("schema.graphql", SDL).format, "graphql-sdl");
    assert.equal(parseFile("schema.txt", SDL).format, "graphql-sdl");
    const m = parseGraphqlSdl(SDL);
    assert.deepEqual(m.directiveDefs, ["auth", "key"]);
    assert.equal(m.types.Query.fields.length, 3);
    assert.equal(m.types.Account.fields[2].name, "apiKey");
  });
  test("GraphQL introspection JSON detected", () => {
    assert.equal(parseFile("intro.json", INTROSPECTION).format, "graphql-introspection");
  });
  test("unknown JSON, broken JSON and empty input are reported in skipped, not guessed", () => {
    const r = analyze([{ name: "a.json", text: '{"hello": 1}' }, { name: "b.json", text: "{ nope" }, { name: "c.yaml", text: "" }]);
    assert.equal(r.findings.length, 0);
    assert.equal(r.skipped.length, 3);
    assert.ok(r.skipped.some((s) => s.check === "parse:b.json" && /JSON parse error/.test(s.reason)));
  });
  test("YAML anchors, aliases and merge keys are expanded locally", () => {
    const y = "a: &base\n  type: string\n  maxLength: 5\nb: *base\nc:\n  <<: *base\n  format: email\nd: &v 7\ne: *v\n";
    assert.deepEqual(parseYaml(y), { a: { type: "string", maxLength: 5 }, b: { type: "string", maxLength: 5 }, c: { type: "string", maxLength: 5, format: "email" }, d: 7, e: 7 });
    assert.ok(!/[&*]base/.test(expandYamlAnchors(y)));
  });
  test("YAML flow maps, quoted keys and block scalars parse", () => {
    const y = "paths:\n  /x:\n    get:\n      description: |\n        Line one\n        line two: still text\n      responses: { '200': { description: ok } }\n";
    const o = parseYaml(y);
    assert.equal(o.paths["/x"].get.responses["200"].description, "ok");
    assert.ok(o.paths["/x"].get.description.includes("line two: still text"));
  });
  test("jsonLineMap maps pointers to lines", () => {
    const m = jsonLineMap(SWAGGER_JSON);
    assert.equal(m.get("/securityDefinitions/basicAuth"), 9);
    assert.equal(m.get("/paths/~1files~1{fileId}/put"), 25);
  });
  test("yamlLineMap maps keys and sequence items to lines", () => {
    const m = yamlLineMap(SWAGGER_YAML);
    assert.equal(m.get("/securityDefinitions/key/in"), 11);
    assert.equal(m.get("/paths/~1notes/get/parameters/0"), 19);
    assert.equal(m.get("/paths/~1notes/get/responses/429"), 30);
  });
});

group("apispec: authentication and authorization", () => {
  test("no security schemes fires on OpenAPI 3.1; silent when schemes exist", () => {
    assert.ok(ids(run("inv.json", OAS31)).includes("APISPEC-AUTH-NO-SCHEMES"));
    assert.ok(!ids(run("ex.yaml", exampleDataset().files[0].text)).includes("APISPEC-AUTH-NO-SCHEMES"));
  });
  test("BOLA candidate is high/likely with no auth and silent with operation-level scopes", () => {
    const b = hits(run("inv.json", OAS31), "APISPEC-BOLA-CANDIDATE");
    assert.equal(b.length, 2);
    assert.ok(b.every((f) => f.severity === "high" && f.confidence === "likely"));
    assert.equal(b[0].pointer, "/paths/~1items~1{itemId}/parameters/0");
    const scoped = oas({ "/o/{orderId}": { get: { security: [{ oa: ["orders:read"] }], responses: ok200 } } }, { components: { securitySchemes: { oa: { type: "oauth2", flows: { clientCredentials: { tokenUrl: "https://t.fixture.io", scopes: { "orders:read": "r" } } } } } } });
    assert.equal(hits(run("s.json", scoped), "APISPEC-BOLA-CANDIDATE").length, 0);
  });
  test("custom object-id pattern changes what counts as an id", () => {
    const t = oas({ "/o/{slug}": { get: { responses: ok200 } } }, bearer);
    assert.equal(hits(run("s.json", t), "APISPEC-BOLA-CANDIDATE").length, 0);
    assert.equal(hits(run("s.json", t, { objectIdPattern: "slug" }), "APISPEC-BOLA-CANDIDATE").length, 1);
  });
  test("security: [] opt-out fires only when a global requirement exists", () => {
    const t = oas({ "/reports": { get: { security: [], responses: ok200 } } }, bearer);
    assert.equal(hits(run("s.json", t), "APISPEC-AUTH-OPT-OUT").length, 1);
    const noGlobal = oas({ "/reports": { get: { security: [], responses: ok200 } } }, { components: bearer.components });
    assert.equal(hits(run("s.json", noGlobal), "APISPEC-AUTH-OPT-OUT").length, 0);
  });
  test("optional auth {} requirement fires", () => {
    const t = oas({ "/feed": { get: { security: [{ bearer: [] }, {}], responses: ok200 } } }, bearer);
    assert.equal(hits(run("s.json", t), "APISPEC-AUTH-OPTIONAL").length, 1);
  });
  test("write operation without auth is high; login-like path is low/review", () => {
    const t = oas({ "/orders": { post: { responses: ok200 } }, "/login": { post: { responses: ok200 } } }, { components: bearer.components });
    const f = hits(run("s.json", t), "APISPEC-AUTH-OP-NONE");
    assert.equal(f.find((x) => x.operation === "POST /orders").severity, "high");
    assert.equal(f.find((x) => x.operation === "POST /login").confidence, "review");
  });
  test("HTTP Basic over plain HTTP fires (Swagger); silent with https only", () => {
    assert.equal(hits(run("files.json", SWAGGER_JSON), "APISPEC-BASIC-NO-TLS").length, 1);
    const https = SWAGGER_JSON.replace('"schemes": ["http", "https"]', '"schemes": ["https"]');
    assert.equal(hits(run("files.json", https), "APISPEC-BASIC-NO-TLS").length, 0);
  });
  test("API key in query fires; header key does not", () => {
    assert.equal(hits(run("ex.yaml", exampleDataset().files[0].text), "APISPEC-APIKEY-IN-QUERY").length, 1);
    assert.equal(hits(run("notes.yaml", SWAGGER_YAML), "APISPEC-APIKEY-IN-QUERY").length, 0);
  });
  test("OAuth password (Swagger) and implicit (OpenAPI 3) flows fire", () => {
    const pw = hits(run("files.json", SWAGGER_JSON), "APISPEC-OAUTH-PASSWORD");
    assert.equal(pw.length, 1); assert.equal(pw[0].pointer, "/securityDefinitions/legacyOauth/flow");
    assert.equal(hits(run("ex.yaml", exampleDataset().files[0].text), "APISPEC-OAUTH-IMPLICIT").length, 1);
  });
  test("write op with scope-less OAuth requirement fires", () => {
    const f = hits(run("ex.yaml", exampleDataset().files[0].text), "APISPEC-WRITE-NO-SCOPES");
    assert.equal(f.length, 1); assert.equal(f[0].operation, "DELETE /accounts/{accountId}");
  });
  test("admin path: no auth is high, global-only is review, distinct scheme is silent", () => {
    const comps = { components: { securitySchemes: { bearer: { type: "http", scheme: "bearer" }, adminKey: { type: "apiKey", in: "header", name: "X-Admin" } } } };
    const t = oas({ "/admin/stats": { get: { security: [], responses: ok200 } }, "/internal-tools/x": { get: { responses: ok200 } }, "/admin/ok": { get: { security: [{ adminKey: [] }], responses: ok200 } } }, { ...comps, security: [{ bearer: [] }] });
    const r = run("s.json", t);
    assert.equal(hits(r, "APISPEC-ADMIN-NO-AUTH")[0].operation, "GET /admin/stats");
    assert.equal(hits(r, "APISPEC-ADMIN-GLOBAL-ONLY")[0].operation, "GET /internal-tools/x");
    assert.ok(!r.findings.some((f) => f.operation === "GET /admin/ok" && /ADMIN/.test(f.ruleId)));
  });
});

group("apispec: properties and resources", () => {
  test("mass assignment fires on writable privileged fields; readOnly and path-named are silent", () => {
    const body = (props) => ({ requestBody: { content: { "application/json": { schema: { type: "object", properties: props } } } }, responses: ok200 });
    const t = oas({ "/users": { post: body({ isAdmin: { type: "boolean" }, ownerId: { type: "string", readOnly: true } }) }, "/users/{id}/role": { put: body({ role: { type: "string", enum: ["a"] } }) } }, bearer);
    const f = hits(run("s.json", t), "APISPEC-MASS-ASSIGNMENT");
    assert.equal(f.length, 1); assert.equal(f[0].evidence[0].field, "isAdmin");
    assert.ok(f[0].controls.some((c) => c.id === "CWE-915") && f[0].controls.some((c) => c.id === "API3:2023"));
    assert.equal(hits(run("files.json", SWAGGER_JSON), "APISPEC-MASS-ASSIGNMENT")[0].evidence[0].field, "ownerId");
  });
  test("sensitive response fields fire; writeOnly and token endpoints are exempt", () => {
    const resp = (props) => ({ responses: { 200: { description: "ok", content: { "application/json": { schema: { type: "object", properties: props } } } } } });
    const t = oas({ "/me": { get: resp({ ssn: { type: "string" }, password: { type: "string", writeOnly: true } }) }, "/oauth/token": { post: resp({ access_token: { type: "string" } }) } }, bearer);
    const f = hits(run("s.json", t), "APISPEC-SENSITIVE-RESPONSE");
    assert.equal(f.length, 1); assert.equal(f[0].severity, "high"); assert.equal(f[0].evidence.length, 1);
  });
  test("unbounded strings: maxLength silences; the setting turns the check off", () => {
    const t = oas({ "/q": { get: { parameters: [{ name: "q", in: "query", schema: { type: "string" } }, { name: "r", in: "query", schema: { type: "string", maxLength: 9 } }], responses: ok200 } } }, bearer);
    const f = hits(run("s.json", t), "APISPEC-UNBOUNDED-STRING");
    assert.equal(f.length, 1); assert.equal(f[0].evidenceCount, 1);
    assert.equal(hits(run("s.json", t, { boundStrings: false }), "APISPEC-UNBOUNDED-STRING").length, 0);
  });
  test("file upload without size hint fires; a 413 response silences it", () => {
    assert.equal(hits(run("files.json", SWAGGER_JSON), "APISPEC-UPLOAD-NO-LIMIT").length, 1);
    const with413 = SWAGGER_JSON.replace('"201": { "description": "Stored" }', '"201": { "description": "Stored" }, "413": { "description": "Too large" }');
    assert.equal(hits(run("files.json", with413), "APISPEC-UPLOAD-NO-LIMIT").length, 0);
  });
  test("list endpoint without limit param fires; limit param silences", () => {
    assert.equal(hits(run("ex.yaml", exampleDataset().files[0].text), "APISPEC-NO-PAGINATION").length, 1);
    assert.equal(hits(run("notes.yaml", SWAGGER_YAML), "APISPEC-NO-PAGINATION").length, 0);
  });
  test("no 429 anywhere fires once; a documented 429 silences", () => {
    assert.equal(hits(run("inv.json", OAS31), "APISPEC-NO-429").length, 1);
    assert.equal(hits(run("notes.yaml", SWAGGER_YAML), "APISPEC-NO-429").length, 0);
  });
  test("SSRF candidate on URL-typed callback field", () => {
    const f = hits(run("ex.yaml", exampleDataset().files[0].text), "APISPEC-SSRF-PARAM");
    assert.equal(f.length, 1); assert.equal(f[0].severity, "medium");
    assert.ok(f[0].controls.some((c) => c.id === "CWE-918"));
  });
  test("wildcard CORS with credentials is high", () => {
    const t = oas({ "/x": { get: { responses: { 200: { description: "ok", headers: { "Access-Control-Allow-Origin": { schema: { type: "string", example: "*" } }, "Access-Control-Allow-Credentials": { schema: { type: "boolean", example: true } } } } } } } }, bearer);
    assert.equal(hits(run("s.json", t), "APISPEC-CORS-WILDCARD")[0].severity, "high");
  });
  test("verbose 500 schema fires; same field on 200 is silent", () => {
    const err = { type: "object", properties: { stack: { type: "string" } } };
    const t = oas({ "/x": { get: { responses: { 200: { description: "ok", content: { "application/json": { schema: err } } }, 500: { description: "e", content: { "application/json": { schema: err } } } } } } }, bearer);
    const f = hits(run("s.json", t), "APISPEC-VERBOSE-ERROR");
    assert.equal(f.length, 1); assert.equal(f[0].evidenceCount, 1);
  });
  test("additionalProperties: true on a request object fires", () => {
    assert.equal(hits(run("ex.yaml", exampleDataset().files[0].text), "APISPEC-ADDITIONAL-PROPS").length, 1);
  });
});

group("apispec: inventory and configuration", () => {
  test("multiple versions, deprecated op and non-production hosts fire on the example", () => {
    const r = run("ex.yaml", exampleDataset().files[0].text);
    assert.equal(hits(r, "APISPEC-MULTI-VERSION").length, 1);
    assert.equal(hits(r, "APISPEC-DEPRECATED-OP")[0].operation, "GET /v1/reports/export");
    assert.equal(hits(r, "APISPEC-NONPROD-SERVER").length, 2);
  });
  test("non-production host pattern is editable; invalid regex falls back and is reported", () => {
    const t = oas({ "/x": { get: { responses: ok200 } } }, { ...bearer, servers: [{ url: "https://qa1.fixture.io" }] });
    assert.equal(hits(run("s.json", t), "APISPEC-NONPROD-SERVER").length, 1);
    assert.equal(hits(run("s.json", t, { nonProdHostPattern: "staging" }), "APISPEC-NONPROD-SERVER").length, 0);
    const bad = run("s.json", t, { nonProdHostPattern: "(" });
    assert.ok(bad.skipped.some((s) => s.check === "nonprod-host-pattern"));
    assert.equal(hits(bad, "APISPEC-NONPROD-SERVER").length, 1);
  });
  test("external $ref is skipped with a reason; cyclic $ref terminates", () => {
    const t = oas({ "/x": { post: { requestBody: { content: { "application/json": { schema: { $ref: "common.yaml#/Thing" } } } }, responses: { 200: { description: "ok", content: { "application/json": { schema: { $ref: "#/components/schemas/Node" } } } } } } } },
      { ...bearer, components: { ...bearer.components, schemas: { Node: { type: "object", properties: { child: { $ref: "#/components/schemas/Node" }, loop: { $ref: "#/components/schemas/A" } } }, A: { $ref: "#/components/schemas/B" }, B: { $ref: "#/components/schemas/A" } } } });
    const r = run("s.json", t);
    assert.ok(r.skipped.some((s) => s.check === "external-ref:s.json" && s.reason.includes("common.yaml#/Thing")));
    assert.ok(r.skipped.some((s) => s.check === "ref-cycle:s.json"));
  });
  test("minSeverity threshold edge: high keeps critical+high only and counts the rest", () => {
    const all = run("ex.yaml", exampleDataset().files[0].text);
    const hi = run("ex.yaml", exampleDataset().files[0].text, { minSeverity: "high" });
    assert.ok(hi.findings.every((f) => f.severity === "high" || f.severity === "critical"));
    assert.equal(hi.findings.length + hi.summary.filteredOut, all.findings.length);
  });
  test("graph asset is the API title plus version", () => {
    const f = run("ex.yaml", exampleDataset().files[0].text).findings[0];
    assert.deepEqual(f.assets[0].name, "Larkspur Payments API 2.4.0");
    assert.equal(f.assets[0].type, "ASSET");
  });
});

group("apispec: GraphQL", () => {
  test("mutation without auth directive fires when the schema uses one elsewhere", () => {
    const f = hits(run("s.graphql", SDL), "APISPEC-GQL-MUTATION-NO-AUTH");
    assert.equal(f.length, 1); assert.equal(f[0].operation, "Mutation.renameAccount"); assert.equal(f[0].line, 10);
    const noAuth = SDL.replace(/@auth\([^)]*\)/g, "");
    assert.equal(hits(run("s.graphql", noAuth), "APISPEC-GQL-MUTATION-NO-AUTH").length, 0);
  });
  test("ID-argument queries without auth are BOLA candidates; list without limit fires", () => {
    const r = run("s.graphql", SDL);
    assert.deepEqual(hits(r, "APISPEC-GQL-ID-ARG").map((f) => f.operation), ["Query.node"]);
    assert.equal(hits(r, "APISPEC-GQL-LIST-NO-LIMIT").length, 0);
    assert.equal(hits(r, "APISPEC-GQL-SENSITIVE-FIELD")[0].severity, "medium");
  });
  test("introspection export: review finding, pointers, and mutation-auth skipped with reason", () => {
    const r = run("intro.json", INTROSPECTION);
    assert.equal(hits(r, "APISPEC-GQL-INTROSPECTION").length, 1);
    const id = hits(r, "APISPEC-GQL-ID-ARG")[0];
    assert.equal(id.pointer, "/data/__schema/types/0/fields/0");
    assert.ok(id.line > 1);
    assert.equal(hits(r, "APISPEC-GQL-LIST-NO-LIMIT")[0].operation, "Query.users");
    assert.equal(hits(r, "APISPEC-GQL-SENSITIVE-FIELD")[0].severity, "high");
    assert.ok(r.skipped.some((s) => s.check === "graphql-mutation-auth:intro.json"));
  });
  test("cost directive present silences the no-cost-limit check", () => {
    assert.equal(hits(run("s.graphql", SDL), "APISPEC-GQL-NO-COST-LIMIT").length, 1);
    assert.equal(hits(run("s.graphql", SDL + "directive @cost(weight: Int) on FIELD_DEFINITION\n"), "APISPEC-GQL-NO-COST-LIMIT").length, 0);
  });
  test("SDL syntax error is reported in skipped", () => {
    const r = run("bad.graphql", "type Query { a(: Int }");
    assert.equal(r.findings.length, 0);
    assert.ok(/GraphQL:/.test(r.skipped[0].reason));
  });
});

group("apispec: Postman", () => {
  test("credentials are found, masked and never echoed", () => {
    const r = run("orders.postman_collection.json", POSTMAN);
    const f = hits(r, "APISPEC-PM-SECRET");
    assert.equal(f.length, 2);
    const coll = f.find((x) => x.operation === "");
    assert.equal(coll.severity, "critical"); assert.equal(coll.confidence, "confirmed");
    assert.equal(coll.pointer, "/auth/bearer/0/value");
    const basic = f.find((x) => x.operation.startsWith("POST"));
    assert.equal(basic.evidence[0].field, "auth basic.password");
    const json = JSON.stringify(r);
    assert.ok(!json.includes(FAKE_GH) && !json.includes("Winter-Orchard-2026"));
  });
  test("template values ({{var}}) are not flagged", () => {
    const r = run("orders.postman_collection.json", POSTMAN);
    assert.ok(!r.findings.some((f) => f.evidence.some((e) => /X-API-Key|apiKey/.test(e.field))));
  });
  test("plain-HTTP requests found through the baseUrl variable", () => {
    const f = hits(run("orders.postman_collection.json", POSTMAN), "APISPEC-PM-HTTP");
    assert.equal(f.length, 1); assert.equal(f[0].evidenceCount, 1);
    assert.equal(f[0].url, "http://orders.fixture.io/orders/42");
  });
});

group("apispec: exports and contract", () => {
  test("findingsToCsv header row", () => {
    const csv = findingsToCsv(run("inv.json", OAS31).findings);
    assert.equal(csv.split("\n")[0], FINDING_COLS.join(","));
    assert.equal(findingsToCsv([]), FINDING_COLS.join(",") + "\n");
  });
  test("inventory CSV lists every endpoint", () => {
    const r = analyze(exampleDataset().files);
    const lines = inventoryToCsv(r.tables.endpoints).trim().split("\n");
    assert.equal(lines[0], INVENTORY_COLS.join(","));
    assert.equal(lines.length - 1, r.tables.endpoints.length);
  });
  test("SARIF 2.1.0: one rule per check, file + line + JSON pointer per result", () => {
    const r = analyze(exampleDataset().files);
    const s = toSarif(r);
    assert.equal(s.version, "2.1.0");
    assert.equal(s.runs[0].tool.driver.rules.length, RULES.length);
    assert.equal(s.runs[0].results.length, r.findings.length);
    const res = s.runs[0].results.find((x) => x.ruleId === "APISPEC-HTTP-SERVER");
    assert.equal(res.locations[0].physicalLocation.artifactLocation.uri, "larkspur-payments.openapi.yaml");
    assert.equal(res.locations[0].physicalLocation.region.startLine, 8);
    assert.equal(res.locations[0].logicalLocations[0].fullyQualifiedName, "/servers/1/url");
  });
  test("summary text lists OWASP counts and skipped checks", () => {
    const t = toTxt(analyze([...exampleDataset().files, { name: "x.json", text: "{}" }]));
    assert.ok(t.includes("API1:2023") && t.includes("Not evaluated:"));
  });
  test("every finding: valid severity/confidence, >=1 control, evidence <= 50 with count", () => {
    const r = analyze([...exampleDataset().files, { name: "f.json", text: SWAGGER_JSON }, { name: "p.json", text: POSTMAN }, { name: "i.json", text: INTROSPECTION }]);
    for (const f of r.findings) {
      assert.ok(["critical", "high", "medium", "low", "info"].includes(f.severity), f.id);
      assert.ok(["confirmed", "likely", "review"].includes(f.confidence), f.id);
      assert.ok(f.controls.length >= 1 && f.controls[0].framework === "OWASP API Security Top 10 2023", f.id);
      assert.ok(f.evidence.length <= 50 && f.evidenceCount >= f.evidence.length && f.evidenceCount >= 1, f.id);
    }
    assert.equal(new Set(r.findings.map((f) => f.id)).size, r.findings.length);
  });
  test("analyze is deterministic (byte-identical JSON)", () => {
    const files = [...exampleDataset().files, { name: "p.json", text: POSTMAN }];
    assert.equal(JSON.stringify(analyze(files)), JSON.stringify(analyze(files)));
  });
  test("progress callback is optional and reports completion", () => {
    const calls = [];
    analyze(exampleDataset().files, {}, { progress: (i, n, l) => calls.push([i, n, l]) });
    assert.deepEqual(calls[calls.length - 1], [2, 2, "done"]);
    analyze(exampleDataset().files, {}, {});
  });
  test("empty input yields zero findings and does not throw", () => {
    const r = analyze(parseInput("").rows);
    assert.equal(r.findings.length, 0); assert.equal(r.meta.rows, 0);
    assert.equal(analyze(null).findings.length, 0);
  });
  test("in-engine self-test passes", () => {
    const r = selfTest();
    assert.ok(r.pass, "failed: " + r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });
});
