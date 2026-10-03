// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
// Merges the plain-English help for every mini-tool: { id: { what, when, example } }.
import { HELP as encoding } from "/js/tools/help/encoding.js?v=20260926a";
import { HELP as hashing } from "/js/tools/help/hashing.js?v=20260926a";
import { HELP as network } from "/js/tools/help/network.js?v=20260926a";
import { HELP as websec } from "/js/tools/help/websec.js?v=20260926a";
import { HELP as dev } from "/js/tools/help/dev.js?v=20260926a";
import { HELP as webhttp } from "/js/tools/help/webhttp.js?v=20260926a";
import { HELP as appsec } from "/js/tools/help/appsec.js?v=20260926a";
import { HELP as devx } from "/js/tools/help/devx.js?v=20260926a";
export const HELP = Object.assign({}, encoding, hashing, network, websec, dev, webhttp, appsec, devx);
