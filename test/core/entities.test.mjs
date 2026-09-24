// Unit tests for public/js/core/entities.js
import { test, group, assert } from "../harness.mjs";
import {
  ENTITY_TYPES,
  RELATIONSHIP_TYPES,
  FIELD_TYPES,
  TYPE_SCHEMAS,
  isEntityType,
  describeType,
  catalog,
  validateField,
  validateData,
  validateEntity,
  isValidRelationship,
  relationshipsFrom,
  describeRelationship,
} from "../../public/js/core/entities.js";

group("entities: field validators", () => {
  test("ip accepts IPv4/IPv6, rejects junk", () => {
    assert.ok(validateField({ name: "a", type: "ip" }, "203.0.113.5").ok);
    assert.ok(validateField({ name: "a", type: "ip" }, "::1").ok);
    assert.notOk(validateField({ name: "a", type: "ip" }, "999.1.1.1").ok);
    assert.notOk(validateField({ name: "a", type: "ip" }, "not-an-ip").ok);
  });

  test("cidr enforces prefix bounds", () => {
    assert.ok(validateField({ name: "c", type: "cidr" }, "10.0.0.0/8").ok);
    assert.notOk(validateField({ name: "c", type: "cidr" }, "10.0.0.0/40").ok);
    assert.notOk(validateField({ name: "c", type: "cidr" }, "10.0.0.0").ok);
  });

  test("domain coerces to lowercase and strips trailing dot", () => {
    const r = validateField({ name: "d", type: "domain" }, "EVIL.Example.COM.");
    assert.ok(r.ok);
    assert.equal(r.value, "evil.example.com");
  });

  test("port coerces strings and bounds 0-65535", () => {
    assert.equal(validateField({ name: "p", type: "port" }, "443").value, 443);
    assert.notOk(validateField({ name: "p", type: "port" }, 70000).ok);
  });

  test("cve normalizes case and validates format", () => {
    const r = validateField({ name: "v", type: "cve" }, "cve-2024-3094");
    assert.ok(r.ok);
    assert.equal(r.value, "CVE-2024-3094");
    assert.notOk(validateField({ name: "v", type: "cve" }, "CVE-99").ok);
  });

  test("cvss bounds 0-10", () => {
    assert.ok(validateField({ name: "s", type: "cvss" }, "9.8").ok);
    assert.notOk(validateField({ name: "s", type: "cvss" }, 11).ok);
  });

  test("hash accepts md5/sha1/sha256 only", () => {
    assert.ok(validateField({ name: "h", type: "hash" }, "d".repeat(64)).ok);
    assert.ok(validateField({ name: "h", type: "hash" }, "a".repeat(32)).ok);
    assert.notOk(validateField({ name: "h", type: "hash" }, "abc").ok);
  });

  test("attack technique id", () => {
    assert.ok(validateField({ name: "t", type: "attack" }, "T1059.001").ok);
    assert.ok(validateField({ name: "t", type: "attack" }, "t1059").ok);
    assert.notOk(validateField({ name: "t", type: "attack" }, "1059").ok);
  });

  test("boolean coerces common truthy/falsey strings", () => {
    assert.equal(validateField({ name: "b", type: "boolean" }, "yes").value, true);
    assert.equal(validateField({ name: "b", type: "boolean" }, "0").value, false);
  });

  test("array splits comma strings", () => {
    assert.deepEqual(validateField({ name: "a", type: "array" }, "x, y ,z").value, ["x", "y", "z"]);
  });

  test("timestamp coerces to ISO-8601", () => {
    const r = validateField({ name: "t", type: "timestamp" }, "2024-01-02");
    assert.ok(r.ok);
    assert.ok(r.value.startsWith("2024-01-02T"));
  });

  test("enum membership enforced via field.values", () => {
    const field = { name: "e", type: "enum", values: ["a", "b"] };
    assert.ok(validateField(field, "a").ok);
    assert.notOk(validateField(field, "c").ok);
  });

  test("required missing value fails; optional missing is dropped", () => {
    assert.notOk(validateField({ name: "x", type: "string", required: true }, "").ok);
    const r = validateField({ name: "x", type: "string" }, "");
    assert.ok(r.ok);
    assert.equal(r.value, undefined);
  });
});

group("entities: type schemas", () => {
  test("every ENTITY_TYPE has a schema with fields", () => {
    for (const t of ENTITY_TYPES) {
      const d = describeType(t);
      assert.ok(d, `missing schema for ${t}`);
      assert.ok(Array.isArray(d.fields) && d.fields.length > 0, `${t} has no fields`);
    }
  });

  test("catalog() returns one entry per entity type", () => {
    assert.equal(catalog().length, ENTITY_TYPES.length);
  });

  test("every schema field uses a known FIELD_TYPE", () => {
    for (const t of ENTITY_TYPES) {
      for (const field of TYPE_SCHEMAS[t].fields) {
        assert.ok(FIELD_TYPES[field.type], `${t}.${field.name} uses unknown type ${field.type}`);
        if (field.type === "enum") assert.ok(Array.isArray(field.values) && field.values.length, `${t}.${field.name} enum needs values`);
      }
    }
  });

  test("isEntityType guards membership", () => {
    assert.ok(isEntityType("VULNERABILITY"));
    assert.notOk(isEntityType("NOPE"));
  });

  test("describeType returns null for unknown", () => {
    assert.equal(describeType("NOPE"), null);
  });
});

group("entities: validateData", () => {
  test("coerces and keeps valid fields", () => {
    const r = validateData("IP", { address: "203.0.113.9", asn: "64512", reputation: "malicious" });
    assert.ok(r.ok);
    assert.equal(r.normalized.address, "203.0.113.9");
    assert.equal(r.normalized.asn, 64512);
  });

  test("reports bad values as errors", () => {
    const r = validateData("VULNERABILITY", { cveId: "nope", cvss: 99 });
    assert.notOk(r.ok);
    assert.ok(r.errors.length >= 2);
  });

  test("required field enforced", () => {
    const r = validateData("ENDPOINT", {}); // hostname required
    assert.notOk(r.ok);
  });

  test("unknown fields are preserved but flagged", () => {
    const r = validateData("IP", { address: "10.0.0.1", weird: "x" });
    assert.ok(r.ok);
    assert.deepEqual(r.unknown, ["weird"]);
    assert.equal(r.normalized.weird, "x");
  });

  test("unknown type fails cleanly", () => {
    const r = validateData("NOPE", {});
    assert.notOk(r.ok);
  });
});

group("entities: validateEntity", () => {
  test("produces a createEntity-ready payload", () => {
    const r = validateEntity("IP", "  bad-ip-host ", { address: "203.0.113.1" }, { severity: "high", tags: ["C2", "c2", " Beacon "] });
    assert.ok(r.ok);
    assert.equal(r.entity.name, "bad-ip-host");
    assert.equal(r.entity.severity, "high");
    assert.equal(r.entity.status, "new");
    assert.equal(r.entity.source, "manual");
    assert.deepEqual(r.entity.tags, ["c2", "beacon"]); // deduped + lowercased
  });

  test("missing name fails", () => {
    const r = validateEntity("IP", "", { address: "10.0.0.1" });
    assert.notOk(r.ok);
  });

  test("bad severity/status rejected", () => {
    assert.notOk(validateEntity("IP", "x", { address: "10.0.0.1" }, { severity: "spicy" }).ok);
    assert.notOk(validateEntity("IP", "x", { address: "10.0.0.1" }, { status: "vibing" }).ok);
  });

  test("null severity allowed", () => {
    assert.ok(validateEntity("IP", "x", { address: "10.0.0.1" }, { severity: null }).ok);
  });
});

group("entities: relationships", () => {
  test("valid semantic relationships accepted", () => {
    assert.ok(isValidRelationship("exploits", "THREAT_ACTOR", "VULNERABILITY"));
    assert.ok(isValidRelationship("attributed_to", "CAMPAIGN", "THREAT_ACTOR"));
    assert.ok(isValidRelationship("related_to", "REPORT", "PORT")); // wildcard
  });

  test("invalid relationships rejected", () => {
    assert.notOk(isValidRelationship("exploits", "REPORT", "PORT"));
    assert.notOk(isValidRelationship("attributed_to", "IP", "PORT"));
    assert.notOk(isValidRelationship("nonexistent", "IP", "IP"));
    assert.notOk(isValidRelationship("exploits", "IP", "NOPE"));
  });

  test("relationshipsFrom lists originating types incl. wildcards", () => {
    const rels = relationshipsFrom("THREAT_ACTOR");
    assert.ok(rels.includes("exploits"));
    assert.ok(rels.includes("targets"));
    assert.ok(rels.includes("related_to")); // wildcard from
  });

  test("every RELATIONSHIP_TYPE has a rule and a description", () => {
    for (const rt of RELATIONSHIP_TYPES) {
      assert.ok(describeRelationship(rt), `no rule for ${rt}`);
    }
  });
});
