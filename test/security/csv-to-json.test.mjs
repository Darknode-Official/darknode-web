// CSV to JSON: number conversion must not change a value, and the header row must not
// lose columns (repeated names, __proto__, cells past the header).

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS } from "../../public/js/tools/coding.js";

const run = (csv, header = true) => JSON.parse(TOOLS.find((t) => t.id === "cd-csv-to-json").run({ csv, delim: ",", header, numbers: true }, H));

group("cd-csv-to-json: numbers and headers", () => {
  test("leading zeros, unsafe integers and out-of-range values stay text", () => {
    assert.deepEqual(run("zip,phone,id,e,x,z\n02134,0044123,12345678901234567890,1e999,1.50,0"),
      [{ zip: "02134", phone: "0044123", id: "12345678901234567890", e: "1e999", x: 1.5, z: 0 }]);
    assert.deepEqual(run("007,-0.5,9007199254740991", false), [["007", -0.5, 9007199254740991]]);
  });
  test("a repeated header is suffixed, __proto__ is a key, and extra cells are kept", () => {
    assert.deepEqual(run("a,a,a\n1,2,3"), [{ a: 1, "a.1": 2, "a.2": 3 }]);
    assert.equal(JSON.stringify(run("__proto__,b\n1,2")), '[{"__proto__":1,"b":2}]');
    assert.deepEqual(run("a,b\n1,2,3,4"), [{ a: 1, b: 2, _extra: [3, 4] }]);
  });
});

group("CSV to SQL: codes stay text, integer widths, quoted table names", () => {
  const sql = (id, csv, table) => TOOLS.find((t) => t.id === id).run({ csv, table, delim: "," }, H);
  const CSV = "zip,big,huge,n,i\n02134,3000000000,12345678901234567890,1.5,0\n00501,1,2,2,-7";
  test("INSERT quotes a leading-zero code and an integer past 64 bits", () => {
    assert.ok(sql("cd-csv-to-sql", CSV, "t").startsWith("INSERT INTO t (zip, big, huge, n, i) VALUES ('02134', 3000000000, '12345678901234567890', 1.5, 0);"));
  });
  test("CREATE TABLE picks text, INTEGER, BIGINT, NUMERIC and DOUBLE PRECISION", () => {
    assert.equal(sql("cd-csv-create-table", CSV, "t"), "CREATE TABLE t (\n  zip VARCHAR(5),\n  big BIGINT,\n  huge NUMERIC,\n  n DOUBLE PRECISION,\n  i INTEGER\n);\n");
  });
  test("the table name is quoted when needed; schema.table still works", () => {
    assert.ok(sql("cd-csv-to-sql", "a\n1", "sales data; x").startsWith('INSERT INTO "sales data; x" (a)'));
    assert.ok(sql("cd-csv-create-table", "a\n1", "public.orders").startsWith("CREATE TABLE public.orders ("));
  });
});
