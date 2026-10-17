#!/usr/bin/env node
// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Repo entry point for the Darknode Code Scanner CLI. The CLI itself lives in
// public/js/codescan/cli.mjs so the website serves the exact same file to the
// GitHub Actions workflow it generates for other repositories.
//   node scripts/darknode-scan.mjs [dir] --sarif out.sarif --diff-base <sha> --fail-on high
import { main } from "../public/js/codescan/cli.mjs";

main(process.argv.slice(2)).then((r) => process.exit(r.code), (e) => {
  process.stdout.write("darknode-scan: " + ((e && e.message) || e) + "\n");
  process.exit(2);
});
