// License Compliance engine tests (public/js/appsec/licenseaudit-engine.js): SPDX expression
// parser, classification, policy and context rules, incompatibilities, one parser test per
// input format (fixtures in the exact layout each tool writes), exports and determinism.

import { test, assert, group } from "../harness.mjs";
import {
  selfTest, analyze, parseInput, exampleDataset, findingsToCsv, inventoryToCsv, toSpdx, toNotice, toTxt,
  parseExpression, exprToString, normalizeLicense, evaluate, classifyLeaf, incompatibility, parsePurl,
  resolutionPlan, extractResolvedLicense, TOOL_ID,
} from "../../public/js/appsec/licenseaudit-engine.js";

const one = (name, text) => parseInput([{ name, text }]).files[0];
const byName = (f, n) => f.components.find((c) => c.name === n);
const rules = (r) => r.findings.map((f) => f.ruleId);
const find = (r, rule) => r.findings.filter((f) => f.ruleId === rule);
const run = (files, opts) => analyze(parseInput(files), opts);
const npmLock = (pk) => JSON.stringify({ name: "app", version: "1.0.0", lockfileVersion: 3, requires: true, packages: pk }, null, 2);

// ---------------------------------------------------------------- fixtures
const CDX_JSON = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:1b671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2026-09-30T12:00:00Z",
    "component": { "type": "application", "bom-ref": "acme-app", "name": "acme-app", "version": "1.0.0", "licenses": [ { "license": { "id": "GPL-2.0-only" } } ] }
  },
  "components": [
    { "type": "library", "bom-ref": "pkg:npm/lodash@4.17.21", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21",
      "licenses": [ { "license": { "id": "MIT" } } ] },
    { "type": "library", "bom-ref": "pkg:npm/%40aws-sdk/client-s3@3.600.0", "group": "@aws-sdk", "name": "client-s3", "version": "3.600.0", "purl": "pkg:npm/%40aws-sdk/client-s3@3.600.0",
      "licenses": [ { "license": { "id": "Apache-2.0" } } ],
      "components": [ { "type": "library", "bom-ref": "pkg:npm/tslib@2.6.3", "name": "tslib", "version": "2.6.3", "purl": "pkg:npm/tslib@2.6.3", "licenses": [ { "license": { "id": "0BSD" } } ] } ] },
    { "type": "library", "bom-ref": "pkg:npm/dompurify@3.1.5", "name": "dompurify", "version": "3.1.5", "purl": "pkg:npm/dompurify@3.1.5",
      "licenses": [ { "expression": "(MPL-2.0 OR Apache-2.0)" } ] },
    { "type": "library", "bom-ref": "pkg:npm/vendored-thing@1.0.0", "name": "vendored-thing", "version": "1.0.0", "purl": "pkg:npm/vendored-thing@1.0.0",
      "licenses": [ { "license": { "name": "Apache License, Version 2.0" } } ] }
  ],
  "dependencies": [
    { "ref": "acme-app", "dependsOn": [ "pkg:npm/lodash@4.17.21", "pkg:npm/%40aws-sdk/client-s3@3.600.0", "pkg:npm/dompurify@3.1.5" ] },
    { "ref": "pkg:npm/%40aws-sdk/client-s3@3.600.0", "dependsOn": [ "pkg:npm/tslib@2.6.3" ] }
  ]
}`;

const CDX_XML = `<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4" serialNumber="urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79" version="1">
  <metadata>
    <timestamp>2026-09-30T12:00:00Z</timestamp>
    <component type="application" bom-ref="svc">
      <name>billing-svc</name>
      <version>2.0.0</version>
    </component>
  </metadata>
  <components>
    <component type="library" bom-ref="pkg:maven/org.hibernate.orm/hibernate-core@6.5.2.Final">
      <group>org.hibernate.orm</group>
      <name>hibernate-core</name>
      <version>6.5.2.Final</version>
      <licenses>
        <license>
          <id>LGPL-2.1-only</id>
        </license>
      </licenses>
      <purl>pkg:maven/org.hibernate.orm/hibernate-core@6.5.2.Final</purl>
    </component>
    <component type="library" bom-ref="pkg:maven/javax.mail/mail@1.4.7">
      <group>javax.mail</group>
      <name>mail</name>
      <version>1.4.7</version>
      <licenses>
        <expression>CDDL-1.0 OR GPL-2.0-only WITH Classpath-exception-2.0</expression>
      </licenses>
      <purl>pkg:maven/javax.mail/mail@1.4.7</purl>
    </component>
    <component type="library" bom-ref="pkg:maven/com.example.internal/legacy@0.1">
      <group>com.example.internal</group>
      <name>legacy</name>
      <version>0.1</version>
      <licenses>
        <license>
          <name>Acme Internal Terms</name>
        </license>
      </licenses>
      <purl>pkg:maven/com.example.internal/legacy@0.1</purl>
    </component>
  </components>
  <dependencies>
    <dependency ref="svc">
      <dependency ref="pkg:maven/org.hibernate.orm/hibernate-core@6.5.2.Final"/>
    </dependency>
    <dependency ref="pkg:maven/org.hibernate.orm/hibernate-core@6.5.2.Final">
      <dependency ref="pkg:maven/javax.mail/mail@1.4.7"/>
    </dependency>
  </dependencies>
</bom>`;

const SPDX_JSON = `{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "web-portal",
  "documentNamespace": "https://test.darknode.ai/spdx/web-portal-1",
  "creationInfo": { "created": "2026-09-30T12:00:00Z", "creators": [ "Tool: syft-1.11.0" ] },
  "documentDescribes": [ "SPDXRef-Package-root" ],
  "packages": [
    { "name": "web-portal", "SPDXID": "SPDXRef-Package-root", "versionInfo": "5.0.0", "downloadLocation": "NOASSERTION", "filesAnalyzed": false,
      "licenseConcluded": "Apache-2.0", "licenseDeclared": "Apache-2.0", "copyrightText": "NOASSERTION" },
    { "name": "readline-sync", "SPDXID": "SPDXRef-Package-npm-readline", "versionInfo": "1.4.10", "downloadLocation": "https://registry.npmjs.org/readline-sync/-/readline-sync-1.4.10.tgz",
      "filesAnalyzed": false, "licenseConcluded": "GPL-3.0-only", "licenseDeclared": "MIT", "copyrightText": "Copyright (c) test.darknode.ai",
      "externalRefs": [ { "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/readline-sync@1.4.10" } ] },
    { "name": "mystery", "SPDXID": "SPDXRef-Package-npm-mystery", "versionInfo": "0.0.1", "downloadLocation": "NOASSERTION", "filesAnalyzed": false,
      "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION",
      "externalRefs": [ { "referenceCategory": "PACKAGE_MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/mystery@0.0.1" } ] },
    { "name": "widget-kit", "SPDXID": "SPDXRef-Package-npm-widget", "versionInfo": "2.2.0", "downloadLocation": "NOASSERTION", "filesAnalyzed": false,
      "licenseConcluded": "LicenseRef-Widget-Commercial", "licenseDeclared": "LicenseRef-Widget-Commercial", "copyrightText": "NOASSERTION",
      "externalRefs": [ { "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/widget-kit@2.2.0" } ] }
  ],
  "hasExtractedLicensingInfos": [ { "licenseId": "LicenseRef-Widget-Commercial", "extractedText": "Licensed for use by paying customers only.", "name": "Widget Commercial License" } ],
  "relationships": [
    { "spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Package-root" },
    { "spdxElementId": "SPDXRef-Package-root", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Package-npm-widget" },
    { "spdxElementId": "SPDXRef-Package-npm-widget", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Package-npm-readline" },
    { "spdxElementId": "SPDXRef-Package-npm-mystery", "relationshipType": "DEPENDENCY_OF", "relatedSpdxElement": "SPDXRef-Package-root" }
  ]
}`;

const SPDX_TV = `SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: ops-tools
DocumentNamespace: https://test.darknode.ai/spdx/ops-tools-1
Creator: Tool: scancode-toolkit-32.2.1
Created: 2026-09-30T12:00:00Z

##### Package: ops-tools

PackageName: ops-tools
SPDXID: SPDXRef-Package-ops
PackageVersion: 1.0.0
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
PackageLicenseConcluded: MIT
PackageLicenseDeclared: MIT
PackageCopyrightText: NOASSERTION

##### Package: pyyaml

PackageName: PyYAML
SPDXID: SPDXRef-Package-pyyaml
PackageVersion: 6.0.1
PackageDownloadLocation: https://pypi.org/project/PyYAML/6.0.1
FilesAnalyzed: false
PackageLicenseConcluded: MIT
PackageLicenseDeclared: MIT
PackageCopyrightText: <text>Copyright (c) 2017-2021 Ingy döt Net
Copyright (c) 2006-2016 Kirill Simonov</text>
ExternalRef: PACKAGE-MANAGER purl pkg:pypi/pyyaml@6.0.1

##### Package: paramiko

PackageName: paramiko
SPDXID: SPDXRef-Package-paramiko
PackageVersion: 3.4.0
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
PackageLicenseConcluded: LGPL-2.1-or-later
PackageLicenseDeclared: LGPL-2.1
PackageCopyrightText: NOASSERTION
ExternalRef: PACKAGE-MANAGER purl pkg:pypi/paramiko@3.4.0

##### Other licensing

LicenseID: LicenseRef-Ops-Custom
ExtractedText: <text>Permission is granted to
use this file internally.</text>
LicenseName: Ops Custom

Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-ops
Relationship: SPDXRef-Package-ops DEPENDS_ON SPDXRef-Package-paramiko
Relationship: SPDXRef-Package-paramiko DEPENDS_ON SPDXRef-Package-pyyaml
`;

const LOCK_V3 = npmLock({
  "": { name: "app", version: "1.0.0", license: "MIT", dependencies: { "a-lib": "^1.0.0", "b-lib": "^2.0.0" }, devDependencies: { "test-kit": "^9.0.0" } },
  "node_modules/a-lib": { version: "1.0.0", resolved: "https://registry.npmjs.org/a-lib/-/a-lib-1.0.0.tgz", integrity: "sha512-x", license: "MIT", dependencies: { "gpl-core": "^3.0.0" } },
  "node_modules/gpl-core": { version: "3.1.0", resolved: "https://registry.npmjs.org/gpl-core/-/gpl-core-3.1.0.tgz", integrity: "sha512-x", license: "GPL-3.0-or-later" },
  "node_modules/b-lib": { version: "2.0.0", resolved: "https://registry.npmjs.org/b-lib/-/b-lib-2.0.0.tgz", integrity: "sha512-x", license: "ISC", dependencies: { "gpl-core": "^2.0.0" } },
  "node_modules/b-lib/node_modules/gpl-core": { version: "2.0.0", resolved: "https://registry.npmjs.org/gpl-core/-/gpl-core-2.0.0.tgz", integrity: "sha512-x", license: "GPL-2.0-only" },
  "node_modules/test-kit": { version: "9.0.0", resolved: "https://registry.npmjs.org/test-kit/-/test-kit-9.0.0.tgz", integrity: "sha512-x", dev: true, license: "AGPL-3.0-only" },
});

const LOCK_V1 = `{
  "name": "old-app",
  "version": "0.1.0",
  "lockfileVersion": 1,
  "requires": true,
  "dependencies": {
    "left-pad": { "version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", "integrity": "sha512-x" },
    "debug": { "version": "4.3.4", "resolved": "https://registry.npmjs.org/debug/-/debug-4.3.4.tgz", "integrity": "sha512-x", "requires": { "ms": "2.1.2" },
      "dependencies": { "ms": { "version": "2.1.2", "resolved": "https://registry.npmjs.org/ms/-/ms-2.1.2.tgz", "integrity": "sha512-x" } } }
  }
}`;

const YARN_V1 = `# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.24.7":
  version "7.24.7"
  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.24.7.tgz#882fd9e09e8ee324e496bd040401c6f046ef4465"
  integrity sha512-x
  dependencies:
    "@babel/highlight" "^7.24.7"

chalk@^2.4.2:
  version "2.4.2"
  resolved "https://registry.yarnpkg.com/chalk/-/chalk-2.4.2.tgz#cd42541677a54333cf541a49108c1432b44c9424"
  integrity sha512-x
`;

const PNPM_V6 = `lockfileVersion: '6.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

dependencies:
  express:
    specifier: ^4.19.2
    version: 4.19.2

devDependencies:
  vitest:
    specifier: ^1.6.0
    version: 1.6.0

packages:

  /accepts@1.3.8:
    resolution: {integrity: sha512-x}
    engines: {node: '>= 0.6'}
    dependencies:
      mime-types: 2.1.35
    dev: false

  /express@4.19.2:
    resolution: {integrity: sha512-x}
    engines: {node: '>= 0.10.0'}
    dependencies:
      accepts: 1.3.8
    dev: false

  /mime-types@2.1.35:
    resolution: {integrity: sha512-x}
    dev: false

  /vitest@1.6.0:
    resolution: {integrity: sha512-x}
    dev: true
`;

const PNPM_V9 = `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      '@scope/kit':
        specifier: ^2.0.0
        version: 2.0.1

packages:

  '@scope/kit@2.0.1':
    resolution: {integrity: sha512-x}

  inner-dep@1.0.0:
    resolution: {integrity: sha512-x}

snapshots:

  '@scope/kit@2.0.1':
    dependencies:
      inner-dep: 1.0.0

  inner-dep@1.0.0: {}
`;

const REQS = `# pinned by pip-compile
requests==2.32.3
urllib3==2.2.2 ; python_version >= "3.8"
flask>=3.0
`;

const PIPFILE_LOCK = `{
    "_meta": {
        "hash": { "sha256": "abc" },
        "pipfile-spec": 6,
        "requires": { "python_version": "3.12" },
        "sources": [ { "name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": true } ]
    },
    "default": {
        "certifi": { "hashes": [ "sha256:x" ], "index": "pypi", "markers": "python_version >= '3.6'", "version": "==2024.7.4" },
        "requests": { "hashes": [ "sha256:x" ], "index": "pypi", "version": "==2.32.3" }
    },
    "develop": {
        "pytest": { "hashes": [ "sha256:x" ], "index": "pypi", "version": "==8.2.2" }
    }
}`;

const POETRY = `# This file is automatically @generated by Poetry 1.8.3 and should not be changed by hand.

[[package]]
name = "Click"
version = "8.1.7"
description = "Composable command line interface toolkit"
optional = false
python-versions = ">=3.7"
files = [
    {file = "click-8.1.7-py3-none-any.whl", hash = "sha256:x"},
]

[[package]]
name = "pyqt5"
version = "5.15.10"
description = "Python bindings for the Qt cross platform application toolkit"
optional = false
python-versions = ">=3.7"

[metadata]
lock-version = "2.0"
python-versions = "^3.11"
content-hash = "abc"
`;

const GO_SUM = `github.com/google/uuid v1.6.0 h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=
github.com/google/uuid v1.6.0/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=
golang.org/x/text v0.16.0 h1:a94ExnEXNtEwYLGJSIUxnWoxoRz/ZcCsV63ROupILh4=
golang.org/x/text v0.16.0/go.mod h1:GhwF1Be+LQoKShO3cGOHzqOgRrGaYc9AvblQOmPVHnI=
`;

const CARGO = `# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 3

[[package]]
name = "ledger-cli"
version = "0.1.0"
dependencies = [
 "serde",
 "ring",
]

[[package]]
name = "ring"
version = "0.17.8"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "c17fa4cb658e3583423e915b9f3acc01cceaee1860e33d59ebae66adc3a2dc0d"
dependencies = [
 "untrusted",
]

[[package]]
name = "serde"
version = "1.0.204"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bc76f558e0cbb2a839d37354c575f1dc3fdc6546b5be373ba43d95f231bf7c12"

[[package]]
name = "untrusted"
version = "0.9.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "8ecb6da28b8a351d773b68d5825ac39017e680750f980f3a1a85cd8dd28a47c1"
`;

const GEMFILE_LOCK = `GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.16.6-x86_64-linux)
      racc (~> 1.4)
    racc (1.8.0)
    rails (7.1.3.4)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  nokogiri
  rails (~> 7.1)

BUNDLED WITH
   2.5.11
`;

const COMPOSER_LOCK = `{
    "_readme": [ "This file locks the dependencies of your project to a known state" ],
    "content-hash": "f1e2d3",
    "packages": [
        { "name": "monolog/monolog", "version": "3.7.0", "source": { "type": "git", "url": "https://github.com/Seldaek/monolog.git", "reference": "x" }, "type": "library", "license": [ "MIT" ] },
        { "name": "phpmailer/phpmailer", "version": "v6.9.1", "type": "library", "license": [ "LGPL-2.1-only" ] },
        { "name": "dual/pick", "version": "1.0.0", "type": "library", "license": [ "GPL-3.0-only", "MIT" ] }
    ],
    "packages-dev": [
        { "name": "phpunit/phpunit", "version": "11.2.6", "type": "library", "license": [ "BSD-3-Clause" ] }
    ],
    "minimum-stability": "stable"
}`;

const POM = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>ai.darknode.test</groupId>
  <artifactId>svc</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>33.2.1-jre</version>
    </dependency>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <version>\${junit.version}</version>
    </dependency>
  </dependencies>
</project>`;

const LICENSE_CHECKER_JSON = `{
  "chalk@4.1.2": { "licenses": "MIT", "repository": "https://github.com/chalk/chalk", "publisher": "Sindre Sorhus", "path": "/app/node_modules/chalk", "licenseFile": "/app/node_modules/chalk/license" },
  "hoek@4.2.1": { "licenses": "BSD-3-Clause", "repository": "https://github.com/hapijs/hoek", "path": "/app/node_modules/hoek", "licenseFile": "/app/node_modules/hoek/LICENSE" },
  "odd-pkg@0.0.3": { "licenses": "MIT*", "path": "/app/node_modules/odd-pkg", "licenseFile": "/app/node_modules/odd-pkg/README.md" },
  "multi@1.0.0": { "licenses": [ "MIT", "Apache-2.0" ], "path": "/app/node_modules/multi" }
}`;

const LICENSE_CHECKER_CSV = `"module name","license","repository"
"chalk@4.1.2","MIT","https://github.com/chalk/chalk"
"@scope/thing@1.0.0","Apache-2.0","https://github.com/scope/thing"
`;

const PIP_LICENSES_CSV = `"Name","Version","License"
"certifi","2024.7.4","Mozilla Public License 2.0 (MPL 2.0)"
"requests","2.32.3","Apache Software License"
"PyQt5","5.15.10","GPL v3"
`;

const ODD_CSV = `Component,Rev,Terms
widget,1.0,MIT
gadget,2.0,AGPL-3.0-only
`;

// ---------------------------------------------------------------- expression parser
group("licenseaudit: SPDX expression parser", () => {
  test("precedence: WITH > AND > OR", () => {
    const a = parseExpression("MIT OR Apache-2.0 AND GPL-2.0-only WITH Classpath-exception-2.0").ast;
    assert.equal(a.type, "or");
    assert.equal(a.args[1].type, "and");
    assert.equal(a.args[1].args[1].exception, "Classpath-exception-2.0");
  });
  test("parentheses override precedence and round-trip", () => {
    const p = parseExpression("(MIT OR Apache-2.0) AND BSD-3-Clause");
    assert.ok(p.ok);
    assert.equal(p.ast.type, "and");
    assert.equal(exprToString(p.ast), "(MIT OR Apache-2.0) AND BSD-3-Clause");
  });
  test("+ suffix, deprecated ids and case are canonicalised", () => {
    assert.equal(parseExpression("GPL-2.0+").ast.id, "GPL-2.0-or-later");
    assert.equal(parseExpression("LGPL-2.1").ast.id, "LGPL-2.1-only");
    assert.equal(parseExpression("apache-2.0").ast.id, "Apache-2.0");
    const mpl = parseExpression("MPL-1.1+").ast;
    assert.equal(mpl.id, "MPL-1.1"); assert.equal(mpl.plus, true);
    assert.equal(parseExpression("GPL-2.0-with-classpath-exception").ast.exception, "Classpath-exception-2.0");
  });
  test("LicenseRef, DocumentRef, NONE and NOASSERTION", () => {
    assert.ok(parseExpression("LicenseRef-Acme-1").ast.ref);
    assert.ok(parseExpression("DocumentRef-ext:LicenseRef-X").ast.ref);
    assert.equal(parseExpression("NONE").ast.type, "none");
    assert.equal(parseExpression("NOASSERTION").ast.type, "noassertion");
    assert.notOk(parseExpression("MIT AND NONE").ok);
  });
  test("invalid expressions are rejected with a reason", () => {
    for (const bad of ["MIT AND", "(MIT OR Apache-2.0", "AND MIT", "MIT WITH", "MIT ) ", "MIT $ BSD"]) {
      const p = parseExpression(bad);
      assert.notOk(p.ok, bad); assert.ok(p.error, bad);
    }
  });
  test("lower-case operators parse with a note", () => {
    const p = parseExpression("mit or apache-2.0");
    assert.ok(p.ok); assert.equal(p.ast.type, "or");
    assert.ok(p.notes.some((n) => /lower-case operator/.test(n)));
  });
  test("normalizeLicense: free text, classifiers, Cargo slash form, npm specials", () => {
    assert.equal(normalizeLicense("Apache License, Version 2.0").expr, "Apache-2.0");
    assert.equal(normalizeLicense("License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)").expr, "GPL-3.0-or-later");
    assert.equal(normalizeLicense("MIT/Apache-2.0").expr, "MIT OR Apache-2.0");
    assert.equal(normalizeLicense("UNLICENSED").expr, "LicenseRef-Proprietary");
    assert.equal(normalizeLicense("SEE LICENSE IN LICENSE.md").expr, "LicenseRef-See-File");
    assert.equal(normalizeLicense("").status, "missing");
    assert.equal(normalizeLicense("BSD").ast.unknown, true, "unversioned BSD stays an unknown id");
    assert.equal(normalizeLicense("Apache License 2 point oh").status, "invalid");
  });
});

// ---------------------------------------------------------------- classification / policy
group("licenseaudit: classification and policy", () => {
  test("categories, OSI flags and linking exceptions", () => {
    assert.equal(classifyLeaf({ id: "AGPL-3.0-only" }).category, "network-copyleft");
    const sspl = classifyLeaf({ id: "SSPL-1.0" });
    assert.equal(sspl.category, "network-copyleft"); assert.equal(sspl.osi, false);
    assert.equal(classifyLeaf({ id: "MPL-2.0" }).category, "weak-copyleft");
    assert.equal(classifyLeaf({ id: "CC0-1.0" }).category, "public-domain");
    assert.equal(classifyLeaf({ id: "BUSL-1.1" }).category, "proprietary");
    assert.equal(classifyLeaf({ id: "GPL-2.0-only", exception: "Classpath-exception-2.0" }).category, "weak-copyleft");
    assert.equal(classifyLeaf({ id: "Foo-1.0", unknown: true }).category, "unknown");
  });
  test("OR picks the most permissive allowed option; AND takes all", () => {
    const e = evaluate(parseExpression("GPL-3.0-only OR MIT").ast, {});
    assert.equal(e.chosen[0].id, "MIT"); assert.deepEqual(e.alternatives, ["GPL-3.0-only"]);
    const a = evaluate(parseExpression("MIT AND LGPL-2.1-only").ast, {});
    assert.equal(a.chosen.length, 2); assert.equal(a.category, "weak-copyleft");
  });
  test("OR avoids a denied option even when it is more permissive", () => {
    const e = evaluate(parseExpression("MIT OR MPL-2.0").ast, { deny: ["MIT"] });
    assert.equal(e.chosen[0].id, "MPL-2.0"); assert.equal(e.policy, "allow");
  });
  test("policy deny / review / allow-list, by id, glob and category", () => {
    const deps = [{ name: "package-lock.json", text: npmLock({
      "": { name: "app", version: "1.0.0", dependencies: { x: "1", y: "1", z: "1", w: "1" } },
      "node_modules/x": { version: "1.0.0", license: "GPL-3.0-only" },
      "node_modules/y": { version: "1.0.0", license: "MPL-2.0" },
      "node_modules/z": { version: "1.0.0", license: "Zlib" },
      "node_modules/w": { version: "1.0.0", license: "MIT" },
    }) }];
    const r = run(deps, { context: "saas", deny: ["GPL-*"], review: ["weak-copyleft"], allow: ["MIT"] });
    const deny = find(r, "LIC-POLICY-DENY"); assert.equal(deny.length, 1); assert.equal(deny[0].evidence[0].package, "x");
    assert.equal(find(r, "LIC-POLICY-REVIEW")[0].evidence[0].package, "y");
    assert.equal(find(r, "LIC-POLICY-UNLISTED")[0].evidence[0].package, "z");
    assert.equal(r.summary.policyHits, 2);
    const none = run(deps, { context: "saas" });
    assert.equal(find(none, "LIC-POLICY-DENY").length + find(none, "LIC-POLICY-UNLISTED").length, 0, "no policy = no policy findings");
  });
});

// ---------------------------------------------------------------- distribution context
group("licenseaudit: distribution context", () => {
  const files = (lic) => [{ name: "package-lock.json", text: npmLock({ "": { name: "app", version: "1.0.0", dependencies: { p: "1" } }, "node_modules/p": { version: "1.0.0", license: lic } }) }];
  const sevOf = (lic, ctx, rule) => { const f = find(run(files(lic), { context: ctx }), rule)[0]; return f ? f.severity : null; };
  test("AGPL and SSPL are flagged even for SaaS", () => {
    assert.equal(sevOf("AGPL-3.0-only", "saas", "LIC-CTX-NETWORK-COPYLEFT"), "high");
    assert.equal(sevOf("SSPL-1.0", "saas", "LIC-CTX-NETWORK-COPYLEFT"), "high");
    assert.ok(/not OSI-approved/.test(find(run(files("SSPL-1.0"), { context: "saas" }), "LIC-CTX-NETWORK-COPYLEFT")[0].description));
  });
  test("GPL: high for shipped and mobile, medium for SaaS, info internal", () => {
    assert.equal(sevOf("GPL-3.0-only", "binary", "LIC-CTX-STRONG-COPYLEFT"), "high");
    assert.equal(sevOf("GPL-3.0-only", "mobile", "LIC-CTX-STRONG-COPYLEFT"), "high");
    assert.equal(sevOf("GPL-3.0-only", "saas", "LIC-CTX-STRONG-COPYLEFT"), "medium");
    assert.equal(sevOf("GPL-3.0-only", "internal", "LIC-CTX-STRONG-COPYLEFT"), "info");
  });
  test("LGPL static-link caveat only for mobile", () => {
    assert.equal(sevOf("LGPL-2.1-only", "mobile", "LIC-LGPL-MOBILE"), "medium");
    assert.equal(sevOf("LGPL-2.1-only", "binary", "LIC-LGPL-MOBILE"), null);
    assert.equal(sevOf("LGPL-2.1-only", "binary", "LIC-CTX-WEAK-COPYLEFT"), "low");
    assert.equal(sevOf("LGPL-2.1-only", "internal", "LIC-CTX-WEAK-COPYLEFT"), null);
  });
  test("permissive licenses raise no obligation finding", () => {
    const r = run(files("MIT"), { context: "binary" });
    assert.equal(r.findings.filter((f) => f.category === "obligation").length, 0);
  });
  test("NONE is high when distributed, medium internal", () => {
    assert.equal(sevOf("NONE", "binary", "LIC-NONE"), "high");
    assert.equal(sevOf("NONE", "internal", "LIC-NONE"), "medium");
  });
  test("development-only packages are excluded unless includeDev", () => {
    const r = run([{ name: "package-lock.json", text: LOCK_V3 }], { context: "binary" });
    assert.equal(find(r, "LIC-CTX-NETWORK-COPYLEFT").length, 0);
    assert.equal(r.summary.devExcluded, 1);
    const r2 = run([{ name: "package-lock.json", text: LOCK_V3 }], { context: "binary", includeDev: true });
    assert.equal(find(r2, "LIC-CTX-NETWORK-COPYLEFT").length, 1);
  });
});

// ---------------------------------------------------------------- incompatibilities
group("licenseaudit: incompatibilities", () => {
  const L = (id, ex) => classifyLeaf({ id, exception: ex });
  test("FSF-listed pairs", () => {
    assert.ok(incompatibility(L("GPL-2.0-only"), L("Apache-2.0")));
    assert.notOk(incompatibility(L("GPL-2.0-or-later"), L("Apache-2.0")), "or-later can move to GPLv3");
    assert.ok(incompatibility(L("GPL-2.0-only"), L("GPL-3.0-only")));
    assert.ok(incompatibility(L("GPL-3.0-only"), L("GPL-2.0-only")));
    assert.ok(incompatibility(L("GPL-2.0-only"), L("LGPL-3.0-only")));
    assert.notOk(incompatibility(L("AGPL-3.0-only"), L("GPL-3.0-or-later")));
    assert.ok(incompatibility(L("GPL-3.0-only"), L("CDDL-1.0")));
    assert.ok(incompatibility(L("GPL-2.0-only"), L("EPL-1.0")));
    assert.notOk(incompatibility(L("GPL-2.0-only"), L("MIT")));
    assert.notOk(incompatibility(L("GPL-2.0-only", "Classpath-exception-2.0"), L("Apache-2.0")), "linking exception is not a host");
    assert.notOk(incompatibility(L("GPL-2.0-only", "Universal-FOSS-exception-1.0"), L("Apache-2.0")));
  });
  test("Apache-2.0 dependency in a GPL-2.0-only project is flagged; skipped without a project license", () => {
    const lock = npmLock({ "": { name: "gplapp", version: "1.0.0", license: "GPL-2.0-only", dependencies: { ap: "1" } }, "node_modules/ap": { version: "1.0.0", license: "Apache-2.0" } });
    const r = run([{ name: "package-lock.json", text: lock }], { context: "binary" });
    const f = find(r, "LIC-INCOMPAT-PROJECT");
    assert.equal(f.length, 1); assert.equal(f[0].severity, "high"); assert.ok(/FSF/.test(f[0].description));
    const r2 = run([{ name: "package-lock.json", text: lock }], { context: "binary", projectLicense: "GPL-3.0-or-later" });
    assert.equal(find(r2, "LIC-INCOMPAT-PROJECT").length, 0, "settings override the input project license");
    const r3 = run([{ name: "package-lock.json", text: lock.replace('"license": "GPL-2.0-only",', "") }], { context: "binary" });
    assert.ok(r3.skipped.some((s) => s.check === "project_incompatibility"));
  });
  test("dependency pairs are reported once per unordered pair, not for internal use", () => {
    const r = run([{ name: "package-lock.json", text: LOCK_V3 }], { context: "binary" });
    const pairs = find(r, "LIC-INCOMPAT-PAIR");
    assert.equal(pairs.length, 1);
    assert.equal(pairs[0].evidenceCount, 2);
    const ri = run([{ name: "package-lock.json", text: LOCK_V3 }], { context: "internal" });
    assert.equal(find(ri, "LIC-INCOMPAT-PAIR").length, 0);
    assert.ok(ri.skipped.some((s) => s.check === "dependency_incompatibility"));
  });
});

// ---------------------------------------------------------------- input formats
group("licenseaudit: input formats", () => {
  test("CycloneDX 1.5 JSON: ids, names, expressions, nested components, graph", () => {
    const f = one("bom.json", CDX_JSON);
    assert.equal(f.format, "cyclonedx-json"); assert.equal(f.confidence, "high");
    assert.equal(f.components.length, 5);
    assert.equal(byName(f, "@aws-sdk/client-s3").declared, "Apache-2.0");
    assert.equal(byName(f, "dompurify").declared, "(MPL-2.0 OR Apache-2.0)");
    assert.equal(byName(f, "tslib").path.join(">"), "acme-app>@aws-sdk/client-s3>tslib");
    assert.equal(f.project.license, "GPL-2.0-only");
    const r = analyze(parseInput([{ name: "bom.json", text: CDX_JSON }]), { context: "binary" });
    assert.equal(find(r, "LIC-INCOMPAT-PROJECT").length, 1, "Apache-2.0 deps vs GPL-2.0-only project");
    assert.ok(find(r, "LIC-NON-SPDX").length === 1, "license name normalised");
  });
  test("CycloneDX 1.4 XML: namespace, id/name/expression, dependency graph", () => {
    const f = one("bom.xml", CDX_XML);
    assert.equal(f.format, "cyclonedx-xml"); assert.equal(f.specVersion, "1.4");
    assert.equal(byName(f, "org.hibernate.orm:hibernate-core").declared, "LGPL-2.1-only");
    assert.equal(byName(f, "javax.mail:mail").declared, "CDDL-1.0 OR GPL-2.0-only WITH Classpath-exception-2.0");
    assert.equal(byName(f, "javax.mail:mail").path.length, 3);
    const r = analyze(parseInput([{ name: "bom.xml", text: CDX_XML }]), { context: "saas" });
    assert.equal(find(r, "LIC-INVALID-EXPR").length, 1, "free-text license name that is not SPDX");
    assert.equal(find(r, "LIC-TRANSITIVE-COPYLEFT").length, 1);
  });
  test("CycloneDX 1.6 acknowledgement: declared vs concluded mismatch", () => {
    const ex = exampleDataset();
    const r = analyze(parseInput([ex.files[0]]), { context: "binary" });
    const m = find(r, "LIC-DECLARED-CONCLUDED");
    assert.equal(m.length, 1); assert.equal(m[0].evidence[0].concluded, "MIT AND GPL-3.0-or-later");
  });
  test("SPDX 2.3 JSON: concluded wins, mismatch, NOASSERTION, LicenseRef text, graph", () => {
    const f = one("sbom.spdx.json", SPDX_JSON);
    assert.equal(f.format, "spdx-json"); assert.equal(f.components.length, 3);
    assert.equal(f.project.name, "web-portal"); assert.equal(f.project.license, "Apache-2.0");
    assert.equal(byName(f, "readline-sync").path.join(">"), "web-portal>widget-kit>readline-sync");
    assert.equal(byName(f, "mystery").path.join(">"), "web-portal>mystery", "DEPENDENCY_OF is reversed");
    const r = analyze(parseInput([{ name: "sbom.spdx.json", text: SPDX_JSON }]), { context: "binary" });
    assert.ok(rules(r).includes("LIC-DECLARED-CONCLUDED"));
    assert.ok(rules(r).includes("LIC-NOASSERTION"));
    const ref = find(r, "LIC-CUSTOM-REF")[0];
    assert.ok(ref && /Widget Commercial License/.test(ref.description));
    assert.equal(ref.evidence[0].licenseText, "Licensed for use by paying customers only.");
    assert.equal(find(r, "LIC-CTX-STRONG-COPYLEFT")[0].evidence[0].package, "readline-sync", "concluded GPL-3.0-only is used");
  });
  test("SPDX 2.3 tag-value: multi-line text, deprecated declared id, relationships", () => {
    const f = one("sbom.spdx", SPDX_TV);
    assert.equal(f.format, "spdx-tv"); assert.equal(f.components.length, 2);
    assert.equal(f.project.name, "ops-tools");
    assert.ok(/Kirill Simonov/.test(byName(f, "pyyaml").copyright));
    assert.equal(byName(f, "pyyaml").path.join(">"), "ops-tools>paramiko>pyyaml");
    assert.equal(f.extracted["LicenseRef-Ops-Custom"].text, "Permission is granted to\nuse this file internally.");
    const r = analyze(parseInput([{ name: "sbom.spdx", text: SPDX_TV }]), { context: "binary" });
    assert.ok(rules(r).includes("LIC-DECLARED-CONCLUDED"), "LGPL-2.1 (=LGPL-2.1-only) vs LGPL-2.1-or-later");
  });
  test("npm package-lock v3: license fields, node resolution paths, dev flag", () => {
    const f = one("package-lock.json", LOCK_V3);
    assert.equal(f.format, "package-lock"); assert.equal(f.components.length, 5);
    const g3 = f.components.find((c) => c.name === "gpl-core" && c.version === "3.1.0");
    const g2 = f.components.find((c) => c.name === "gpl-core" && c.version === "2.0.0");
    assert.equal(g3.path.join(">"), "app>a-lib>gpl-core");
    assert.equal(g2.path.join(">"), "app>b-lib>gpl-core", "nested node_modules resolved");
    assert.equal(byName(f, "test-kit").dev, true);
    assert.equal(f.project.license, "MIT");
    const r = analyze(parseInput([{ name: "package-lock.json", text: LOCK_V3 }]), { context: "binary" });
    assert.equal(find(r, "LIC-TRANSITIVE-COPYLEFT")[0].evidenceCount, 2);
  });
  test("npm package-lock v1: tree parsed, missing licenses reported, no paths", () => {
    const f = one("package-lock.json", LOCK_V1);
    assert.equal(f.components.length, 3);
    assert.ok(f.issues.some((i) => /lockfileVersion 1/.test(i)));
    const r = analyze(parseInput([{ name: "package-lock.json", text: LOCK_V1 }]));
    assert.equal(find(r, "LIC-NO-DATA")[0].evidenceCount, 3);
    assert.ok(r.skipped.some((s) => s.check === "transitive_copyleft"));
  });
  test("yarn.lock v1", () => {
    const f = one("yarn.lock", YARN_V1);
    assert.equal(f.format, "yarn-lock");
    assert.deepEqual(f.components.map((c) => c.name + "@" + c.version).sort(), ["@babel/code-frame@7.24.7", "chalk@2.4.2"]);
  });
  test("pnpm-lock.yaml v6 and v9 with root paths", () => {
    const f6 = one("pnpm-lock.yaml", PNPM_V6);
    assert.equal(f6.format, "pnpm-lock"); assert.equal(f6.components.length, 4);
    assert.equal(byName(f6, "mime-types").path.join(">"), "(project)>express@4.19.2>accepts@1.3.8>mime-types@2.1.35".replace(/@[\d.]+/g, ""));
    assert.equal(byName(f6, "vitest").dev, true);
    const f9 = one("pnpm-lock.yaml", PNPM_V9);
    assert.equal(byName(f9, "@scope/kit").version, "2.0.1");
    assert.equal(byName(f9, "inner-dep").path.join(">"), "(project)>@scope/kit>inner-dep");
  });
  test("requirements.txt keeps only == pins", () => {
    const f = one("requirements.txt", REQS);
    assert.equal(f.format, "requirements");
    assert.deepEqual(f.components.map((c) => c.name).sort(), ["requests", "urllib3"]);
  });
  test("Pipfile.lock default and develop", () => {
    const f = one("Pipfile.lock", PIPFILE_LOCK);
    assert.equal(f.format, "pipfile-lock"); assert.equal(f.components.length, 3);
    assert.equal(byName(f, "pytest").dev, true); assert.equal(byName(f, "certifi").version, "2024.7.4");
  });
  test("poetry.lock", () => {
    const f = one("poetry.lock", POETRY);
    assert.equal(f.format, "poetry-lock");
    assert.deepEqual(f.components.map((c) => c.name).sort(), ["click", "pyqt5"]);
    assert.equal(f.components[0].ecosystem, "pypi");
  });
  test("go.sum", () => {
    const f = one("go.sum", GO_SUM);
    assert.equal(f.format, "go-sum");
    assert.equal(byName(f, "github.com/google/uuid").purl, "pkg:golang/github.com/google/uuid@1.6.0");
  });
  test("Cargo.lock is not mistaken for poetry.lock and gets paths", () => {
    const f = one("Cargo.lock", CARGO);
    assert.equal(f.format, "cargo-lock"); assert.equal(f.components.length, 3);
    assert.equal(f.project.name, "ledger-cli");
    assert.equal(byName(f, "untrusted").path.join(">"), "ledger-cli>ring>untrusted");
    assert.equal(byName(f, "serde").ecosystem, "cargo");
  });
  test("Gemfile.lock", () => {
    const f = one("Gemfile.lock", GEMFILE_LOCK);
    assert.equal(f.format, "gemfile-lock"); assert.equal(f.components.length, 3);
    assert.equal(byName(f, "nokogiri").direct, true); assert.equal(byName(f, "racc").direct, false);
  });
  test("composer.lock: license arrays are a choice (OR), dev packages", () => {
    const f = one("composer.lock", COMPOSER_LOCK);
    assert.equal(f.format, "composer-lock");
    assert.equal(byName(f, "dual/pick").declared, "GPL-3.0-only OR MIT");
    assert.equal(byName(f, "phpmailer/phpmailer").version, "6.9.1");
    assert.equal(byName(f, "phpunit/phpunit").dev, true);
    const r = analyze(parseInput([{ name: "composer.lock", text: COMPOSER_LOCK }]), { context: "binary" });
    assert.equal(r.tables.inventory.find((x) => x.package === "dual/pick").chosen, "MIT");
  });
  test("Maven pom.xml skips property-managed versions", () => {
    const f = one("pom.xml", POM);
    assert.equal(f.format, "pom");
    assert.deepEqual(f.components.map((c) => c.name), ["com.google.guava:guava"]);
  });
  test("license-checker JSON: guessed (*) licenses and arrays", () => {
    const f = one("licenses.json", LICENSE_CHECKER_JSON);
    assert.equal(f.format, "license-checker-json"); assert.equal(f.components.length, 4);
    assert.equal(byName(f, "odd-pkg").declared, "MIT");
    assert.equal(byName(f, "multi").declared, "MIT OR Apache-2.0");
    assert.ok(f.issues.some((i) => /guessed/.test(i)));
  });
  test("license-checker CSV and pip-licenses CSV", () => {
    const a = one("licenses.csv", LICENSE_CHECKER_CSV);
    assert.equal(a.format, "license-csv"); assert.equal(a.confidence, "high");
    assert.equal(byName(a, "@scope/thing").version, "1.0.0");
    const b = one("pip-licenses.csv", PIP_LICENSES_CSV);
    const r = analyze(parseInput([{ name: "pip-licenses.csv", text: PIP_LICENSES_CSV }]), { context: "binary" });
    assert.equal(b.components.length, 3);
    const inv = Object.fromEntries(r.tables.inventory.map((x) => [x.package, x.license]));
    assert.equal(inv.certifi, "MPL-2.0"); assert.equal(inv.requests, "Apache-2.0"); assert.equal(inv.PyQt5, "GPL-3.0-only");
  });
  test("unrecognised CSV headers need mapping; mapping fixes it", () => {
    const f = one("odd.csv", ODD_CSV);
    assert.equal(f.confidence, "low"); assert.ok(f.components.every((c) => !c.declared), "no license column found");
    const ok = parseInput([{ name: "odd.csv", text: ODD_CSV }], { mapping: { "odd.csv": { name: "Component", version: "Rev", license: "Terms" } } }).files[0];
    assert.equal(ok.confidence, "high"); assert.equal(ok.components.length, 2);
    assert.equal(byName(ok, "gadget").declared, "AGPL-3.0-only");
  });
  test("unknown and empty files are reported in skipped, never guessed", () => {
    const p = parseInput([{ name: "notes.txt", text: "hello there\nthis is prose." }, { name: "blank", text: "   " }]);
    assert.equal(p.skipped.length, 2);
    assert.equal(analyze(p).findings.length, 0);
  });
  test("purl parsing", () => {
    assert.equal(parsePurl("pkg:npm/%40babel/core@7.24.7").fullName, "@babel/core");
    assert.equal(parsePurl("pkg:maven/org.apache/commons@1.0?type=jar").fullName, "org.apache:commons");
    assert.equal(parsePurl("pkg:golang/golang.org/x/text@v0.16.0").version, "v0.16.0");
    assert.equal(parsePurl("not a purl"), null);
  });
});

// ---------------------------------------------------------------- merge, resolve, exports
group("licenseaudit: merging, resolution and exports", () => {
  test("lockfile + SBOM merge; disagreement is reported", () => {
    const sbom = JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.5", version: 1, components: [{ type: "library", name: "a-lib", version: "1.0.0", purl: "pkg:npm/a-lib@1.0.0", licenses: [{ license: { id: "BSD-2-Clause" } }] }] });
    const r = run([{ name: "package-lock.json", text: LOCK_V3 }, { name: "bom.json", text: sbom }], { context: "binary" });
    const row = r.tables.inventory.find((x) => x.package === "a-lib");
    assert.equal(row.license, "BSD-2-Clause", "SBOM preferred"); assert.equal(row.files, "package-lock.json; bom.json");
    assert.equal(find(r, "LIC-SOURCE-CONFLICT").length, 1);
  });
  test("opts.resolved fills missing licenses and is labelled", () => {
    const p = parseInput([{ name: "Cargo.lock", text: CARGO }]);
    const r0 = analyze(p);
    assert.equal(r0.tables.unresolved.length, 3);
    const r = analyze(p, { context: "binary", resolved: { "cargo:ring@0.17.8": { license: "MIT AND ISC AND OpenSSL", host: "crates.io", at: "2026-10-17T00:00:00Z" }, "cargo:serde@1.0.204": { license: "MIT OR Apache-2.0", host: "crates.io" } } });
    assert.equal(r.summary.resolvedLive, 2);
    assert.equal(r.tables.unresolved.length, 1);
    assert.equal(find(r, "LIC-RESOLVED-LIVE")[0].evidenceCount, 2);
    assert.equal(r.tables.inventory.find((x) => x.package === "ring").resolvedFrom, "crates.io");
  });
  test("resolutionPlan builds registry and ClearlyDefined URLs", () => {
    const plan = resolutionPlan([
      { key: "npm:@scope/kit@2.0.1", ecosystem: "npm", name: "@scope/kit", version: "2.0.1" },
      { key: "pypi:requests@2.32.3", ecosystem: "pypi", name: "requests", version: "2.32.3" },
      { key: "cargo:ring@0.17.8", ecosystem: "cargo", name: "ring", version: "0.17.8" },
      { key: "maven:com.google.guava:guava@33.2.1-jre", ecosystem: "maven", name: "com.google.guava:guava", version: "33.2.1-jre" },
      { key: "go:golang.org/x/text@0.16.0", ecosystem: "go", name: "golang.org/x/text", version: "0.16.0" },
    ]);
    assert.equal(plan[0].urls[0].url, "https://registry.npmjs.org/@scope%2Fkit/2.0.1");
    assert.equal(plan[1].urls[0].url, "https://pypi.org/pypi/requests/2.32.3/json");
    assert.equal(plan[2].urls[0].url, "https://crates.io/api/v1/crates/ring/0.17.8");
    assert.equal(plan[3].urls[0].url, "https://api.clearlydefined.io/definitions/maven/mavencentral/com.google.guava/guava/33.2.1-jre");
    assert.equal(plan[4].urls[0].url, "https://api.clearlydefined.io/definitions/go/golang/golang.org%2Fx/text/v0.16.0");
  });
  test("extractResolvedLicense reads each registry's shape", () => {
    assert.equal(extractResolvedLicense("npm", { name: "x", version: "1.0.0", license: "ISC" }).license, "ISC");
    assert.equal(extractResolvedLicense("npm", { licenses: [{ type: "MIT" }, { type: "Apache-2.0" }] }).license, "MIT OR Apache-2.0");
    assert.equal(extractResolvedLicense("pypi", { info: { license_expression: "BSD-3-Clause", license: null } }).license, "BSD-3-Clause");
    assert.equal(extractResolvedLicense("pypi", { info: { license: "", classifiers: ["License :: OSI Approved :: MIT License", "Programming Language :: Python"] } }).license, "MIT");
    assert.equal(extractResolvedLicense("crates", { version: { num: "1.0.204", license: "MIT OR Apache-2.0" } }).license, "MIT OR Apache-2.0");
    assert.equal(extractResolvedLicense("clearlydefined", { licensed: { declared: "Apache-2.0" } }).license, "Apache-2.0");
    assert.equal(extractResolvedLicense("clearlydefined", { licensed: { declared: "NOASSERTION" } }), null);
  });
  test("findingsToCsv header row and formula guard", () => {
    const csv = findingsToCsv([{ severity: "high", confidence: "likely", ruleId: "R", category: "c", title: "=cmd()", description: "d", recommendation: "r", controls: [{ framework: "ISO27001", id: "A.5.32" }], evidence: [], evidenceCount: 3 }]);
    const [head, row] = csv.trim().split("\n");
    assert.equal(head, "severity,confidence,rule,category,title,description,recommendation,controls,evidenceCount,packages");
    assert.ok(row.includes("\"'=cmd()\""));
  });
  test("inventory CSV, NOTICE and SPDX 2.3 export", () => {
    const ex = exampleDataset();
    const r = analyze(parseInput(ex.files), { context: "binary" });
    const inv = inventoryToCsv(r).trim().split("\n");
    assert.equal(inv.length, r.tables.inventory.length + 1);
    assert.ok(inv[0].startsWith("package,version,ecosystem,purl,license,chosen,category"));
    const notice = toNotice(r);
    assert.ok(/AGPL-3.0-only {2}\(2 packages\)/.test(notice));
    assert.ok(/https:\/\/spdx\.org\/licenses\/MIT\.html/.test(notice));
    assert.notOk(/typescript/.test(notice), "dev-only package left out");
    const doc = toSpdx(r, { now: "2026-10-17T08:00:00.000Z" });
    assert.equal(doc.spdxVersion, "SPDX-2.3"); assert.equal(doc.creationInfo.created, "2026-10-17T08:00:00Z");
    assert.equal(doc.packages.length, r.tables.inventory.length);
    assert.equal(new Set(doc.packages.map((p) => p.SPDXID)).size, doc.packages.length);
    for (const p of doc.packages) { assert.ok(parseExpression(p.licenseDeclared).ok, p.licenseDeclared); assert.ok(parseExpression(p.licenseConcluded).ok); }
    assert.ok(doc.hasExtractedLicensingInfos.some((x) => x.licenseId === "LicenseRef-Chartsuite-EULA"));
    assert.equal(JSON.stringify(toSpdx(r, { now: "2026-10-17T08:00:00Z" })), JSON.stringify(doc));
    assert.ok(/License Compliance summary/.test(toTxt(r)));
  });
});

// ---------------------------------------------------------------- whole engine
group("licenseaudit: engine", () => {
  test("in-engine self-test passes", () => {
    const r = selfTest();
    assert.ok(r.pass, "failed: " + r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });
  test("analyze is deterministic (byte-identical JSON)", () => {
    const ex = exampleDataset();
    for (const ctx of ["saas", "binary", "mobile", "internal"]) {
      assert.equal(JSON.stringify(analyze(parseInput(ex.files), { context: ctx })), JSON.stringify(analyze(parseInput(ex.files), { context: ctx })));
    }
  });
  test("analyze accepts raw files as well as parsed input", () => {
    const ex = exampleDataset();
    assert.equal(JSON.stringify(analyze(ex.files, {})), JSON.stringify(analyze(parseInput(ex.files), {})));
  });
  test("example covers the headline detections", () => {
    const r = analyze(parseInput(exampleDataset().files), { context: "mobile" });
    for (const id of ["LIC-CTX-NETWORK-COPYLEFT", "LIC-CTX-PROPRIETARY", "LIC-LGPL-MOBILE", "LIC-NOASSERTION", "LIC-NO-DATA", "LIC-CUSTOM-REF", "LIC-DECLARED-CONCLUDED", "LIC-TRANSITIVE-COPYLEFT", "LIC-OR-ELECTION", "LIC-INCOMPAT-PAIR"]) assert.ok(rules(r).includes(id), id);
    for (const f of r.findings) {
      assert.ok(f.controls.length >= 1); assert.ok(f.recommendation);
      assert.ok(["confirmed", "likely", "review"].includes(f.confidence));
      assert.ok(f.evidence.length <= 50 && f.evidenceCount >= f.evidence.length);
      for (const a of f.assets) assert.equal(a.type, "ASSET");
    }
    assert.equal(r.meta.tool, TOOL_ID);
  });
  test("progress callback fires and ends at total", () => {
    const calls = [];
    analyze(parseInput(exampleDataset().files), {}, { progress: (i, n, l) => calls.push([i, n, l]) });
    assert.ok(calls.length >= 2);
    const last = calls[calls.length - 1]; assert.equal(last[0], last[1]);
  });
  test("empty input yields zero findings and does not throw", () => {
    const parsed = parseInput("");
    assert.equal(parsed.rows.length, 0);
    const r = analyze(parsed);
    assert.equal(r.findings.length, 0); assert.equal(r.meta.rows, 0);
  });
});
