// Cloud Spend Anomaly engine tests (public/js/finsec/cloudspend-engine.js): one parser test per
// vendor export with verbatim headers, robust statistics, every detection positive and negative,
// minimum-history skip, currency separation, correlation window edges, determinism, exports.

import { test, assert, group } from "../harness.mjs";
import {
  selfTest, analyze, parseInput, exampleDataset, detectFile, classifyHeaders, findingsToCsv, timelineToCsv, resourcesToCsv, accountsToCsv, summaryText,
  toMicros, microsToCents, dayOf, median, robust, robustZ, scanSeries, classifyFamily, isEgress, isServerless, normRegion, windowGap, ctGraphName, fmtMoney, DEFAULTS, FINDING_COLS,
} from "../../public/js/finsec/cloudspend-engine.js";
import { toEntities, findingKey } from "../../public/js/core/sink-map.js";

// ---------------------------------------------------------------------------
// Fixture builders (headers verbatim from the vendor exports)
// ---------------------------------------------------------------------------
const CUR = ["identity/LineItemId", "bill/PayerAccountId", "bill/BillingEntity", "lineItem/UsageAccountId", "lineItem/LineItemType", "lineItem/UsageStartDate", "lineItem/UsageEndDate", "lineItem/ProductCode", "lineItem/UsageType", "lineItem/Operation", "lineItem/AvailabilityZone", "lineItem/ResourceId", "lineItem/UsageAmount", "lineItem/UnblendedCost", "lineItem/BlendedCost", "lineItem/CurrencyCode", "lineItem/LegalEntity", "product/region", "product/instanceType", "product/productFamily"];
const q = (v) => (/[",\n]/.test(String(v)) ? '"' + String(v).replace(/"/g, '""') + '"' : String(v));
const D0 = Date.UTC(2026, 5, 1);
const day = (i) => new Date(D0 + i * 86400000).toISOString().slice(0, 10);
let lid = 0;
/** One CUR legacy row from a short spec. */
function curRow(i, s) {
  const r = {
    "identity/LineItemId": "t" + (++lid), "bill/PayerAccountId": "999999999999", "bill/BillingEntity": s.entity || "AWS", "lineItem/UsageAccountId": s.acct || "111111111111",
    "lineItem/LineItemType": s.type || "Usage", "lineItem/UsageStartDate": day(i) + "T00:00:00Z", "lineItem/UsageEndDate": day(i + 1) + "T00:00:00Z",
    "lineItem/ProductCode": s.prod || "AmazonEC2", "lineItem/UsageType": s.ut || "BoxUsage:m5.large", "lineItem/Operation": "RunInstances", "lineItem/AvailabilityZone": s.az || "",
    "lineItem/ResourceId": s.res == null ? "i-0base" : s.res, "lineItem/UsageAmount": String(s.usage == null ? 24 : s.usage), "lineItem/UnblendedCost": String(s.cost), "lineItem/BlendedCost": String(s.cost),
    "lineItem/CurrencyCode": s.cur || "USD", "lineItem/LegalEntity": s.seller || "Amazon Web Services, Inc.", "product/region": s.region == null ? "us-east-1" : s.region,
    "product/instanceType": s.it == null ? "m5.large" : s.it, "product/productFamily": s.fam || "Compute Instance",
  };
  return CUR.map((h) => q(r[h])).join(",");
}
/** CUR CSV for `days` days; spec(i) returns an array of row specs for day i. */
function cur(days, spec, headers = CUR) {
  const lines = [headers.join(",")];
  for (let i = 0; i < days; i++) for (const s of spec(i)) lines.push(curRow(i, s));
  return { name: "cur.csv", text: lines.join("\n") + "\n" };
}
const steady = (cost = 100) => ({ cost });
const cats = (r, c) => r.findings.filter((f) => f.category === c);

// ---------------------------------------------------------------------------
group("cloudspend: parsers (verbatim vendor headers)", () => {
  test("AWS CUR legacy is detected with high confidence and rows normalize", () => {
    const f = cur(2, () => [{ cost: "1.2345678", region: "", az: "us-west-2b" }]);
    const d = detectFile(f);
    assert.equal(d.format, "aws-cur"); assert.equal(d.provider, "aws"); assert.equal(d.confidence, 1);
    const p = parseInput(f);
    assert.equal(p.records.length, 2);
    const r = p.records[0];
    assert.equal(r.date, "2026-06-01"); assert.equal(r.account, "111111111111"); assert.equal(r.region, "us-west-2", "AZ stripped to region when product/region is blank");
    assert.equal(r.family, "m5"); assert.equal(r.micros, 1234568); assert.equal(r.currency, "USD");
  });

  test("AWS CUR 2.0 snake_case is detected and parsed", () => {
    const H = "line_item_usage_account_id,line_item_usage_start_date,line_item_product_code,line_item_usage_type,line_item_unblended_cost,product_region_code,product_instance_type,line_item_resource_id,line_item_currency_code,line_item_line_item_type";
    const text = H + "\n222233334444,2026-06-01 00:00:00,AmazonEC2,USE1-SpotUsage:g5.xlarge,4.5,us-east-1,g5.xlarge,i-0abc,USD,Usage\n222233334444,2026-06-01 00:00:00,AmazonEC2,USE1-SpotUsage:g5.xlarge,-4.5,us-east-1,g5.xlarge,i-0abc,USD,Credit\n";
    const d = detectFile("cur2.csv", text);
    assert.equal(d.format, "aws-cur2"); assert.equal(d.confidence, 1);
    const p = parseInput({ name: "cur2.csv", text });
    assert.equal(p.records.length, 1, "credit line excluded");
    assert.equal(p.files[0].excluded, 1);
    assert.equal(p.records[0].family, "g5"); assert.ok(p.records[0].gpu);
  });

  test("AWS Cost Explorer (service columns with ($), dates as rows) is unpivoted", () => {
    const text = '"Service","EC2-Instances($)","S3($)","Total costs($)"\n"Service total","30.00","3.00","33.00"\n"2026-06-01","10.00","1.00","11.00"\n"2026-06-02","20.00","2.00","22.00"\n';
    const d = detectFile("ce.csv", text);
    assert.equal(d.format, "aws-ce");
    const p = parseInput({ name: "ce.csv", text });
    assert.equal(p.records.length, 4, "total row and total column dropped");
    const ec2 = p.records.filter((r) => r.service === "EC2-Instances");
    assert.deepEqual(ec2.map((r) => [r.date, r.micros, r.currency]), [["2026-06-01", 10000000, "USD"], ["2026-06-02", 20000000, "USD"]]);
  });

  test("AWS Cost Explorer (dates as columns) is unpivoted; Linked account dimension becomes the account", () => {
    const text = "Linked account,2026-06-01,2026-06-02,Total\n111111111111 (prod),5.00,6.00,11.00\n222222222222 (dev),1.00,0,1.00\nTotal,6.00,6.00,12.00\n";
    const d = detectFile("ce2.csv", text);
    assert.equal(d.format, "aws-ce-bydate");
    const p = parseInput({ name: "ce2.csv", text });
    assert.deepEqual(p.records.map((r) => r.account + " " + r.date + " " + r.micros), ["111111111111 2026-06-01 5000000", "111111111111 2026-06-02 6000000", "222222222222 2026-06-01 1000000"]);
  });

  test("Azure cost details (PascalCase, MM/DD/YYYY) are parsed with meter families", () => {
    const H = "SubscriptionId,SubscriptionName,Date,MeterCategory,MeterSubCategory,MeterName,ResourceLocation,ResourceGroup,ResourceId,ConsumedService,Quantity,CostInBillingCurrency,BillingCurrency,ChargeType";
    const text = H + "\nAAAA1111-0000-4000-8000-000000000001,Fictional Labs,06/02/2026,Virtual Machines,NCv3 Series,NC6s v3,EastUS,rg-ml,/subscriptions/aaaa1111-0000-4000-8000-000000000001/resourceGroups/rg-ml/providers/Microsoft.Compute/virtualMachines/ml-01,Microsoft.Compute,24,73.44,EUR,Usage\n";
    const d = detectFile("az.csv", text);
    assert.equal(d.format, "azure-cost"); assert.equal(d.confidence, 1);
    const r = parseInput({ name: "az.csv", text }).records[0];
    assert.equal(r.date, "2026-06-02"); assert.equal(r.account, "aaaa1111-0000-4000-8000-000000000001");
    assert.equal(r.family, "NCv3"); assert.ok(r.gpu); assert.equal(r.region, "eastus"); assert.equal(r.currency, "EUR");
  });

  test("Azure actual-cost lower-camel variant (costInBillingCurrency) is parsed", () => {
    const H = "subscriptionId,subscriptionName,date,meterCategory,meterSubCategory,meterName,resourceLocation,resourceId,quantity,costInBillingCurrency,billingCurrency,chargeType";
    const text = H + "\nbbbb2222-0000-4000-8000-000000000002,Fictional Ops,2026-06-03,Bandwidth,Rtn Preference: MGN,Standard Data Transfer Out,westeurope,/subscriptions/bbbb2222-0000-4000-8000-000000000002/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/ip1,120,10.2,USD,Usage\n";
    const d = detectFile("az2.csv", text);
    assert.equal(d.format, "azure-cost");
    const r = parseInput({ name: "az2.csv", text }).records[0];
    assert.ok(r.egress, "Bandwidth data transfer out is egress"); assert.equal(r.micros, 10200000);
  });

  test("GCP billing export to BigQuery (CSV, dotted headers) is parsed", () => {
    const H = "billing_account_id,service.description,sku.description,usage_start_time,usage_end_time,project.id,location.region,cost,currency,usage.amount,usage.unit,labels";
    const text = H + '\n01ABCD-234567-89EFGH,Compute Engine,Nvidia Tesla V100 GPU running in Americas,2026-06-04 07:00:00 UTC,2026-06-04 08:00:00 UTC,fictional-ml-proj,us-central1,2.48,USD,3600,seconds,"[]"\n01ABCD-234567-89EFGH,Networking,Network Internet Egress from Americas to Americas,2026-06-04 07:00:00 UTC,2026-06-04 08:00:00 UTC,fictional-ml-proj,us-central1,0.12,USD,1073741824,bytes,"[]"\n';
    const d = detectFile("gcp.csv", text);
    assert.equal(d.format, "gcp-billing"); assert.equal(d.confidence, 1);
    const rs = parseInput({ name: "gcp.csv", text }).records;
    assert.equal(rs[0].account, "fictional-ml-proj"); assert.ok(rs[0].gpu); assert.equal(rs[0].family, "gpu tesla v100");
    assert.ok(rs[1].egress);
  });

  test("GCP billing export as nested JSON (NDJSON) is flattened and parsed", () => {
    const rec = (sku, cost) => JSON.stringify({ billing_account_id: "01ABCD-234567-89EFGH", service: { id: "6F81-5844-456A", description: "Compute Engine" }, sku: { id: "x", description: sku }, usage_start_time: "2026-06-05T00:00:00Z", usage_end_time: "2026-06-05T01:00:00Z", project: { id: "fictional-web", name: "Fictional Web" }, location: { region: "europe-west1", zone: "europe-west1-b" }, cost, currency: "EUR", usage: { amount: 3600, unit: "seconds" }, labels: [] });
    const text = rec("A2 Instance Core running in EMEA", 1.5) + "\n" + rec("N1 Predefined Instance Core running in EMEA", 0.4) + "\n";
    const d = detectFile("gcp.json", text);
    assert.equal(d.format, "gcp-billing-json");
    const rs = parseInput({ name: "gcp.json", text }).records;
    assert.equal(rs.length, 2); assert.equal(rs[0].family, "a2"); assert.ok(rs[0].gpu); assert.equal(rs[1].family, "n1"); assert.ok(!rs[1].gpu);
    assert.equal(rs[0].accountName, "Fictional Web"); assert.equal(rs[0].currency, "EUR");
  });

  test("GCP console cost table is medium confidence (mapping panel) and still parses", () => {
    const text = "Billing account name,Billing account ID,Project name,Project ID,Service description,Service ID,SKU description,SKU ID,Usage start date,Usage end date,Usage amount,Usage unit,Cost ($)\nFictional,01ABCD,Web,fictional-web,Cloud Run,152E,CPU Allocation Time,X,2026-06-01,2026-06-01,100,vCPU-seconds,1.25\n";
    const d = detectFile("table.csv", text);
    assert.equal(d.format, "gcp-cost-table"); assert.ok(d.confidence < 0.8);
    const r = parseInput({ name: "table.csv", text }).records[0];
    assert.equal(r.micros, 1250000); assert.equal(r.currency, "USD", "currency taken from the ($) header"); assert.ok(r.serverless);
  });

  test("unknown layout is low confidence; an explicit mapping makes it usable", () => {
    const text = "When,Who,What,Spend\n2026-06-01,acct-a,Compute,10\n";
    const d = detectFile("x.csv", text);
    assert.equal(d.format, "generic"); assert.ok(d.confidence < 0.5);
    const r0 = analyze([{ name: "x.csv", text }]);
    assert.ok(r0.skipped.some((s) => s.check === "file x.csv" && /required/.test(s.reason)));
    const r1 = parseInput([{ name: "x.csv", text }], { mappings: { "x.csv": { date: "When", account: "Who", service: "What", cost: "Spend" } } });
    assert.equal(r1.records.length, 1); assert.equal(r1.records[0].account, "acct-a");
  });

  test("a Cloud Audit Log Hunter export is recognised as the correlation input", () => {
    const ex = exampleDataset();
    assert.equal(detectFile(ex.files[1]).kind, "cloudtrail");
    assert.equal(parseInput(ex.files).cloudtrail.length, 1);
  });
});

// ---------------------------------------------------------------------------
group("cloudspend: numbers and statistics", () => {
  test("toMicros parses exact decimals, symbols, separators and parentheses", () => {
    assert.equal(toMicros("12.345678"), 12345678);
    assert.equal(toMicros("$1,234.50"), 1234500000);
    assert.equal(toMicros("(3.10)"), -3100000);
    assert.equal(toMicros("-$2"), -2000000);
    assert.equal(toMicros("1.5E-5"), 15);
    assert.equal(toMicros("EUR 7.25"), 7250000);
    assert.ok(Number.isNaN(toMicros("n/a")));
    assert.equal(microsToCents(1234567), 123); assert.equal(microsToCents(-5000), -1);
  });

  test("dayOf handles ISO, UTC suffix, offsets (converted to UTC) and US dates", () => {
    assert.equal(dayOf("2026-06-01T00:00:00Z"), "2026-06-01");
    assert.equal(dayOf("2026-06-01 07:00:00 UTC"), "2026-06-01");
    assert.equal(dayOf("2026-06-01T23:30:00-07:00"), "2026-06-02");
    assert.equal(dayOf("6/2/2026"), "2026-06-02");
    assert.equal(dayOf("garbage"), "");
  });

  test("median and MAD-based robust z", () => {
    assert.equal(median([3, 1, 2]), 2); assert.equal(median([4, 1, 3, 2]), 2.5);
    const b = robust([10, 12, 11, 13, 9, 11, 10]);
    assert.equal(b.median, 11); assert.equal(b.mad, 1);
    assert.ok(Math.abs(b.scale - 1.4826) < 1e-9);
    assert.ok(Math.abs(robustZ(20, b) - 9 / 1.4826) < 1e-9);
  });

  test("MAD of 0 falls back to mean absolute deviation, then to the floor", () => {
    const b = robust([5, 5, 5, 5, 9]);
    assert.equal(b.mad, 0); assert.ok(Math.abs(b.scale - 1.2533 * (3.2 / 5 + 0) - 1.2533 * 0) < 1); // mean |x - 5| = 0.8
    assert.ok(Math.abs(b.scale - 1.2533 * 0.8) < 1e-9);
    const flat = robust([7, 7, 7], 2);
    assert.equal(flat.scale, 2); assert.equal(robustZ(15, flat), 4);
  });

  test("scanSeries respects minimum history and merges consecutive spike days", () => {
    const s = Array(20).fill(100).concat([500, 600, 100]);
    const r = scanSeries(s, { ...DEFAULTS, minHistoryDays: 14, baselineDays: 28, spikeZ: 4 }, 1, 0);
    assert.equal(r.points.slice(0, 14).filter(Boolean).length, 0);
    assert.equal(r.runs.length, 1); assert.equal(r.runs[0].start, 20); assert.equal(r.runs[0].end, 21);
  });

  test("fmtMoney is deterministic and keeps the currency", () => {
    assert.equal(fmtMoney(123456, "USD"), "1234.56 USD"); assert.equal(fmtMoney(-5, "EUR"), "-0.05 EUR");
  });
});

// ---------------------------------------------------------------------------
group("cloudspend: classification", () => {
  test("GPU / accelerator families per provider", () => {
    for (const t of ["p3.2xlarge", "p4d.24xlarge", "p5.48xlarge", "g4dn.xlarge", "g6.xlarge", "inf2.xlarge", "trn1.32xlarge", "dl1.24xlarge"]) assert.ok(classifyFamily("aws", { instanceType: t }).gpu, t);
    for (const t of ["m5.large", "c6i.xlarge", "r7g.large", "t3.micro"]) assert.ok(!classifyFamily("aws", { instanceType: t }).gpu, t);
    assert.equal(classifyFamily("aws", { sku: "USE1-BoxUsage:p3.8xlarge" }).family, "p3");
    assert.ok(classifyFamily("azure", { service: "Virtual Machines", meterSub: "NDasrA100 v4 Series" }).gpu);
    assert.ok(!classifyFamily("azure", { service: "Virtual Machines", meterSub: "Dv3/DSv3 Series" }).gpu);
    assert.ok(classifyFamily("gcp", { sku: "G2 Instance Core running in Americas" }).gpu);
    assert.ok(classifyFamily("gcp", { sku: "Nvidia L4 GPU running in Americas" }).gpu);
    assert.ok(!classifyFamily("gcp", { sku: "E2 Instance Core running in Americas" }).gpu);
  });

  test("egress, serverless and region normalisation", () => {
    assert.ok(isEgress("aws", { sku: "USE1-DataTransfer-Out-Bytes" })); assert.ok(!isEgress("aws", { sku: "USE1-DataTransfer-In-Bytes" }));
    assert.ok(isEgress("gcp", { sku: "Network Internet Egress from Americas to EMEA" })); assert.ok(!isEgress("gcp", { sku: "Network Internet Ingress" }));
    assert.ok(isServerless("aws", { service: "AWSLambda" })); assert.ok(isServerless("gcp", { service: "Cloud Run" })); assert.ok(isServerless("azure", { service: "Functions" }));
    assert.equal(normRegion("aws", "", "eu-west-1c"), "eu-west-1"); assert.equal(normRegion("gcp", "us-central1-a"), "us-central1"); assert.equal(normRegion("aws", "global"), "");
  });
});

// ---------------------------------------------------------------------------
group("cloudspend: detections", () => {
  test("daily spend spike fires on a crafted spike and stays silent on a steady series", () => {
    const pos = analyze([cur(40, (i) => [{ cost: i === 35 ? 1000 : 100 }])]);
    const s = cats(pos, "spend-spike");
    assert.equal(s.length, 1); assert.equal(s[0].windowStart, day(35)); assert.equal(s[0].increaseCents, 90000);
    assert.equal(s[0].severity, "high"); assert.ok(s[0].mitre.includes("T1496"));
    const neg = analyze([cur(40, () => [steady()])]);
    assert.equal(cats(neg, "spend-spike").length, 0);
  });

  test("spike threshold edge: z equal to the threshold does not fire, just above does", () => {
    const at = analyze([cur(30, (i) => [{ cost: i === 25 ? 104 : 100 }])]);
    assert.equal(cats(at, "spend-spike").length, 0, "z = 4.00 is not > 4");
    const above = analyze([cur(30, (i) => [{ cost: i === 25 ? 104.01 : 100 }])]);
    assert.equal(cats(above, "spend-spike").length, 1);
  });

  test("minimum increase edge (cents): increase must exceed it", () => {
    const f = cur(30, (i) => [{ cost: i === 25 ? 1000 : 100 }]);
    assert.equal(cats(analyze([f], { minIncrease: 90000 }), "spend-spike").length, 0);
    assert.equal(cats(analyze([f], { minIncrease: 89999 }), "spend-spike").length, 1);
    assert.equal(cats(analyze([f], { minIncrease: "" }), "spend-spike").length, 1, "blank = 0");
  });

  test("minimum history: short data is skipped with a reason, never guessed", () => {
    const r = analyze([cur(10, (i) => [{ cost: i === 9 ? 5000 : 100 }])]);
    assert.equal(r.findings.length, 0);
    const sk = r.skipped.find((s) => s.check === "spend-spike");
    assert.ok(sk && /15 are needed/.test(sk.reason), JSON.stringify(r.skipped));
    assert.ok(/insufficient history/.test(r.tables.accounts[0].status));
  });

  test("per-service spike names the service", () => {
    const r = analyze([cur(30, (i) => [{ cost: 100 }, { prod: "AmazonS3", ut: "TimedStorage-ByteHrs", it: "", res: "bucket-a", cost: i === 27 ? 900 : 10 }])]);
    const s = cats(r, "service-spike");
    assert.equal(s.length, 1); assert.equal(s[0].scope, "AmazonS3");
  });

  test("new GPU family in an account with no GPU baseline is high (T1496); GPU from day one is silent", () => {
    const pos = analyze([cur(30, (i) => [{ cost: 100 }].concat(i >= 20 ? [{ it: "p3.16xlarge", ut: "BoxUsage:p3.16xlarge", res: "i-0gpu", cost: 500 }] : []))]);
    const g = cats(pos, "gpu-family");
    assert.equal(g.length, 1); assert.equal(g[0].severity, "high"); assert.equal(g[0].scope, "p3"); assert.equal(g[0].evidence[0].resourceId, "i-0gpu");
    const neg = analyze([cur(30, () => [{ cost: 100 }, { it: "p3.16xlarge", ut: "BoxUsage:p3.16xlarge", res: "i-0gpu", cost: 500 }])]);
    assert.equal(cats(neg, "gpu-family").length, 0);
  });

  test("sudden large compute in a new non-GPU family is medium; a small one is silent", () => {
    const big = analyze([cur(30, (i) => [{ cost: 100 }].concat(i >= 20 ? [{ it: "c6i.32xlarge", ut: "BoxUsage:c6i.32xlarge", res: "i-0c", cost: 60 }] : []))]);
    assert.equal(cats(big, "new-family").length, 1); assert.equal(cats(big, "new-family")[0].severity, "medium");
    const small = analyze([cur(30, (i) => [{ cost: 100 }].concat(i >= 20 ? [{ it: "t3.micro", ut: "BoxUsage:t3.micro", res: "i-0t", cost: 0.25 }] : []))]);
    assert.equal(cats(small, "new-family").length, 0);
  });

  test("new region: high with compute, low without; a region present from the start is silent", () => {
    const comp = analyze([cur(30, (i) => [{ cost: 100 }].concat(i >= 22 ? [{ region: "ap-southeast-3", res: "i-0new", cost: 50 }] : []))]);
    const nr = cats(comp, "new-region");
    assert.equal(nr.length, 1); assert.equal(nr[0].severity, "high"); assert.ok(nr[0].mitre.includes("T1535"));
    const stor = analyze([cur(30, (i) => [{ cost: 100 }].concat(i >= 22 ? [{ region: "eu-north-1", prod: "AmazonS3", ut: "TimedStorage-ByteHrs", it: "", res: "b", cost: 2 }] : []))]);
    assert.equal(cats(stor, "new-region")[0].severity, "low");
    const neg = analyze([cur(30, () => [{ cost: 100 }, { region: "eu-west-1", res: "i-0eu", cost: 20 }])]);
    assert.equal(cats(neg, "new-region").length, 0);
  });

  test("egress spike is reported (T1537 / T1530); steady egress is silent", () => {
    const eg = (c) => ({ ut: "USE1-DataTransfer-Out-Bytes", it: "", res: "i-0web", usage: c * 10, cost: c });
    const pos = analyze([cur(30, (i) => [{ cost: 100 }, eg(i === 26 ? 300 : 5)])]);
    const e = cats(pos, "egress-spike");
    assert.equal(e.length, 1); assert.equal(e[0].severity, "high"); assert.ok(e[0].mitre.includes("T1537") && e[0].mitre.includes("T1530"));
    const neg = analyze([cur(30, () => [{ cost: 100 }, eg(5)])]);
    assert.equal(cats(neg, "egress-spike").length, 0);
  });

  test("serverless burst is medium; steady Lambda is silent", () => {
    const fn = (c) => ({ prod: "AWSLambda", ut: "Lambda-GB-Second", it: "", res: "arn:aws:lambda:us-east-1:111111111111:function:f", cost: c });
    const pos = analyze([cur(30, (i) => [{ cost: 100 }, fn(i === 28 ? 80 : 4)])]);
    assert.equal(cats(pos, "serverless-burst").length, 1); assert.equal(cats(pos, "serverless-burst")[0].severity, "medium");
    assert.equal(cats(analyze([cur(30, () => [{ cost: 100 }, fn(4)])]), "serverless-burst").length, 0);
  });

  test("dormant account that starts spending is high; an active account is not dormant", () => {
    const pos = analyze([cur(30, (i) => [{ acct: "333333333333", prod: "AmazonS3", ut: "TimedStorage-ByteHrs", it: "", res: "b", cost: i >= 25 ? 400 : 0.05 }])]);
    const d = cats(pos, "dormant-account");
    assert.equal(d.length, 1); assert.equal(d[0].severity, "high"); assert.equal(d[0].windowStart, day(25)); assert.equal(d[0].windowEnd, day(29));
    const neg = analyze([cur(30, (i) => [{ cost: i >= 25 ? 400 : 100 }])]);
    assert.equal(cats(neg, "dormant-account").length, 0);
  });

  test("new marketplace charge is reported; one present from the start is silent", () => {
    const mk = { entity: "AWS Marketplace", prod: "prodcode1", ut: "SoftwareUsage", it: "", res: "", seller: "Fictional Vendor Ltd", cost: 30 };
    const pos = analyze([cur(30, (i) => [{ cost: 100 }].concat(i === 20 ? [mk] : []))]);
    const m = cats(pos, "marketplace");
    assert.equal(m.length, 1); assert.ok(/Fictional Vendor Ltd/.test(m[0].title));
    assert.equal(cats(analyze([cur(30, () => [{ cost: 100 }, mk])]), "marketplace").length, 0);
  });

  test("marketplace check is skipped when there is no billing-entity column", () => {
    const H = CUR.filter((h) => h !== "bill/BillingEntity");
    const lines = [H.join(",")];
    for (let i = 0; i < 20; i++) lines.push(curRow(i, { cost: 100 }).split(",").filter((_, k) => CUR[k] !== "bill/BillingEntity").join(","));
    const r = analyze([{ name: "nobe.csv", text: lines.join("\n") }]);
    assert.ok(r.skipped.some((s) => s.check === "marketplace" && /nobe\.csv/.test(s.reason)));
  });

  test("resource-id churn fires on many new ids in a day; a few new ids are silent", () => {
    const many = analyze([cur(30, (i) => [{ cost: 100 }].concat(i === 25 ? Array.from({ length: 20 }, (_, k) => ({ res: "i-0burst" + k, cost: 1 })) : []))]);
    const c = cats(many, "resource-churn");
    assert.equal(c.length, 1); assert.equal(c[0].evidenceCount, 20);
    const few = analyze([cur(30, (i) => [{ cost: 100 }].concat(i === 25 ? Array.from({ length: 5 }, (_, k) => ({ res: "i-0few" + k, cost: 1 })) : []))]);
    assert.equal(cats(few, "resource-churn").length, 0);
  });

  test("resource churn is skipped without a resource id column (Cost Explorer)", () => {
    const text = '"Service","EC2-Instances($)"\n' + Array.from({ length: 20 }, (_, i) => '"' + day(i) + '","10.00"').join("\n");
    const r = analyze([{ name: "ce.csv", text }]);
    assert.ok(r.skipped.some((s) => s.check === "resource-churn"));
  });
});

// ---------------------------------------------------------------------------
group("cloudspend: currencies", () => {
  test("two currencies on one account are never summed together", () => {
    const r = analyze([cur(20, () => [{ cost: 100, cur: "USD" }, { cost: 50, cur: "EUR", res: "i-0eu" }])]);
    assert.equal(r.tables.accounts.length, 2);
    assert.deepEqual(r.tables.accounts.map((a) => a.currency).sort(), ["EUR", "USD"]);
    assert.ok(r.tables.accounts.every((a) => a.multiCurrency));
    assert.deepEqual(r.summary.totals, [{ currency: "EUR", cents: 100000 }, { currency: "USD", cents: 200000 }]);
    const d1 = r.tables.daily.filter((d) => d.date === day(0));
    assert.deepEqual(d1.map((d) => [d.currency, d.totalCents]), [["EUR", 5000], ["USD", 10000]]);
  });

  test("a spike in one currency is measured only against that currency's baseline", () => {
    const r = analyze([cur(30, (i) => [{ cost: 100, cur: "USD" }, { cost: i === 25 ? 400 : 1, cur: "EUR", res: "i-0eu" }])]);
    const s = cats(r, "spend-spike");
    assert.equal(s.length, 1); assert.equal(s[0].currency, "EUR"); assert.equal(s[0].increaseCents, 39900);
  });
});

// ---------------------------------------------------------------------------
group("cloudspend: correlation with the Cloud Audit Log Hunter", () => {
  const billing = cur(30, (i) => [{ cost: 100 }].concat(i === 25 ? [{ region: "sa-east-1", it: "p3.2xlarge", ut: "SAE1-BoxUsage:p3.2xlarge", res: "i-0x", cost: 500 }] : []));
  const ct = (firstSeen, lastSeen, extra = {}) => ({ name: "ct.json", text: JSON.stringify({ meta: { tool: "cloudtrail", version: "1.0.0" }, findings: [{ id: "aws-run-instances-new-region:111111111111 sa-east-1", title: "Instances launched in a never-seen region: 111111111111 sa-east-1", severity: "medium", confidence: "likely", platform: "aws", firstSeen, lastSeen, controls: [{ framework: "MITRE", id: "T1535" }], evidence: [{ time: firstSeen, platform: "aws", account: extra.account || "111111111111", region: extra.region || "sa-east-1", principal: "arn:aws:iam::111111111111:user/ci@test.darknode.ai", action: "RunInstances" }], assets: [{ type: "IDENTITY", name: "arn:aws:iam::111111111111:user/ci@test.darknode.ai" }] }] }) });

  test("an audit finding inside the window raises both severities with a correlated-with row", () => {
    const base = analyze([billing]);
    const r = analyze([billing, ct(day(25) + "T03:00:00Z", day(25) + "T03:05:00Z")]);
    const g0 = cats(base, "gpu-family")[0], g1 = cats(r, "gpu-family")[0];
    assert.equal(g0.severity, "high"); assert.equal(g1.severity, "critical");
    assert.ok(g1.evidence[0].correlatedWith && /never-seen region/.test(g1.evidence[0].correlatedWith));
    assert.ok(g1.assets.some((a) => a.type === "IDENTITY" && a.name === "arn:aws:iam::111111111111:user/ci@test.darknode.ai"));
    const c = cats(r, "correlated-audit");
    assert.equal(c.length, 1); assert.equal(c[0].severity, "high", "medium audit finding raised one step");
    assert.ok(r.tables.correlations.length >= 1);
  });

  test("window edges: exactly 24 h after the anomaly day joins, 1 ms later does not", () => {
    const end = Date.UTC(2026, 5, 27); // end of day(25) = start of day(26); +24h
    const at = new Date(end + 86400000).toISOString();
    const after = new Date(end + 86400000 + 1000).toISOString();
    assert.ok(cats(analyze([billing, ct(at, at)]), "correlated-audit").length >= 1);
    assert.equal(cats(analyze([billing, ct(after, after)]), "correlated-audit").length, 0);
    assert.equal(windowGap(day(25), day(25), end + 86400000, end + 86400000), 86400000);
    assert.equal(windowGap(day(25), day(25), end - 1000, end), 0);
  });

  test("a different account or a different region does not join", () => {
    const t = day(25) + "T03:00:00Z";
    assert.equal(cats(analyze([billing, ct(t, t, { account: "444444444444" })]), "correlated-audit").length, 0);
    assert.equal(analyze([billing, ct(t, t, { region: "eu-west-1" })]).findings.filter((f) => f.category === "gpu-family" && f.correlated.length).length, 0);
  });

  test("graph name for the audit finding matches the sink naming used by cloudtrail", () => {
    const f = { id: "x:1", title: "Root account console sign-in: root" };
    const name = toEntities("cloudtrail", [f]).items.find((i) => i.type === "FINDING").name;
    assert.equal(ctGraphName(f), name);
    assert.equal(ctGraphName(f), "Root account console sign-in: root (cloudtrail:" + findingKey("cloudtrail", f) + ")");
  });
});

// ---------------------------------------------------------------------------
group("cloudspend: engine contract", () => {
  test("in-engine self-test passes", () => {
    const r = selfTest();
    assert.ok(r.pass, "failed: " + r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });

  test("analyze is deterministic (byte-identical JSON)", () => {
    const ex = exampleDataset();
    assert.equal(JSON.stringify(analyze(ex.files)), JSON.stringify(analyze(ex.files)));
  });

  test("streamed analyze equals analyze over parseInput records", () => {
    const f = cur(30, (i) => [{ cost: i === 25 ? 1000 : 100 }]);
    const a = analyze([f]), b = analyze(parseInput([f]));
    assert.equal(JSON.stringify(a.findings), JSON.stringify(b.findings));
  });

  test("example: GPU burst in a new region in a dormant account, egress spike, correlation", () => {
    const r = analyze(exampleDataset().files);
    assert.ok(cats(r, "gpu-family").some((f) => f.account === "333333333333"));
    assert.ok(cats(r, "new-region").some((f) => f.scope === "sa-east-1"));
    assert.ok(cats(r, "dormant-account").some((f) => f.account === "333333333333"));
    assert.ok(cats(r, "egress-spike").some((f) => f.account === "111111111111"));
    assert.ok(r.summary.correlated >= 1);
    assert.equal(r.summary.accounts, 3); assert.equal(r.summary.days, 60);
  });

  test("findings carry the common shape and cloud-account ASSET data", () => {
    const r = analyze(exampleDataset().files);
    for (const f of r.findings) {
      assert.ok(["critical", "high", "medium", "low", "info"].includes(f.severity));
      assert.ok(["confirmed", "likely", "review"].includes(f.confidence));
      assert.ok(f.controls.length >= 1 && f.title && f.recommendation && f.evidence.length <= 50);
    }
    const asset = r.findings[0].assets.find((a) => a.type === "ASSET");
    assert.equal(asset.data.kind, "cloud-account"); assert.equal(asset.data.provider, "aws");
    const ents = toEntities("cloudspend", r.findings, { sample: true });
    assert.ok(ents.items.some((i) => i.type === "ASSET" && /^AWS account 333333333333$/.test(i.name)));
  });

  test("evidence is capped at 50 rows with the full count kept", () => {
    const r = analyze([cur(30, (i) => [{ cost: 100 }].concat(i === 25 ? Array.from({ length: 70 }, (_, k) => ({ res: "i-0m" + k, cost: 10 })) : []))]);
    const s = cats(r, "spend-spike")[0];
    assert.equal(s.evidence.length, 50); assert.equal(s.evidenceCount, 71);
  });

  test("progress is reported every 1000 rows", () => {
    const calls = [];
    analyze([cur(30, () => Array.from({ length: 50 }, (_, k) => ({ res: "i-" + k, cost: 1 })))], {}, { progress: (i, n, l) => calls.push([i, n, l]) });
    assert.ok(calls.filter((c) => /reading/.test(c[2])).length >= 1);
  });

  test("empty input yields zero findings and does not throw", () => {
    const r = analyze([]);
    assert.equal(r.findings.length, 0); assert.equal(r.meta.rows, 0);
    assert.equal(analyze("").findings.length, 0);
  });

  test("findingsToCsv header row and one row per finding", () => {
    const r = analyze(exampleDataset().files);
    const lines = findingsToCsv(r.findings).trim().split("\n");
    assert.equal(lines[0], FINDING_COLS.join(","));
    assert.equal(lines[0].split(",")[0], "id");
    assert.ok(lines.length >= r.findings.length + 1);
    assert.equal(findingsToCsv([]), FINDING_COLS.join(",") + "\n");
  });

  test("timeline, top-resources and accounts CSV shapes and summary text", () => {
    const r = analyze(exampleDataset().files);
    assert.equal(timelineToCsv(r.tables.timeline).split("\n")[0], "date,provider,account,currency,kind,scope,severity,observed,baseline,z,finding_id");
    const res = resourcesToCsv(r.findings).split("\n");
    assert.equal(res[0], "finding_id,severity,provider,account,currency,window,resource_id,service,sku,region,family,cost,usage,unit");
    assert.ok(res.some((l) => /i-0gpu/.test(l)));
    assert.equal(accountsToCsv(r.tables.accounts).split("\n")[0].split(",")[0], "provider");
    assert.ok(/never converted/.test(summaryText(r)));
  });

  test("classifyHeaders is exact-set based and reports missing required columns", () => {
    const g = classifyHeaders(["foo", "bar"]);
    assert.equal(g.format, "generic"); assert.deepEqual(g.missing, ["date", "account", "service", "cost"]);
  });

  test("tables expose daily series with a baseline band once history exists", () => {
    const r = analyze([cur(20, () => [steady()])]);
    const pts = r.tables.series[0].points;
    assert.equal(pts.length, 20); assert.equal(pts[0][2], null); assert.equal(pts[14][2], 10000); assert.ok(pts[14][3] > pts[14][2]);
  });
});
