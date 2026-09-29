// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Merges the plain-English help for every mini-tool: { id: { what, when, example } }.
import { HELP as encoding } from "/js/tools/help/encoding.js?v=20260926a";
import { HELP as hashing } from "/js/tools/help/hashing.js?v=20260926a";
import { HELP as generators } from "/js/tools/help/generators.js?v=20260926a";
import { HELP as converters } from "/js/tools/help/converters.js?v=20260926a";
import { HELP as network } from "/js/tools/help/network.js?v=20260926a";
import { HELP as websec } from "/js/tools/help/websec.js?v=20260926a";
import { HELP as text } from "/js/tools/help/text.js?v=20260926a";
import { HELP as dev } from "/js/tools/help/dev.js?v=20260926a";
import { HELP as color } from "/js/tools/help/color.js?v=20260926a";
import { HELP as datetime } from "/js/tools/help/datetime.js?v=20260926a";
import { HELP as mathx } from "/js/tools/help/mathx.js?v=20260926a";
import { HELP as datafmt } from "/js/tools/help/datafmt.js?v=20260926a";
import { HELP as webhttp } from "/js/tools/help/webhttp.js?v=20260926a";
import { HELP as appsec } from "/js/tools/help/appsec.js?v=20260926a";
import { HELP as textx } from "/js/tools/help/textx.js?v=20260926a";
import { HELP as devx } from "/js/tools/help/devx.js?v=20260926a";
export const HELP = Object.assign({}, encoding, hashing, generators, converters, network, websec, text, dev, color, datetime, mathx, datafmt, webhttp, appsec, textx, devx);
