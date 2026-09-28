#!/usr/bin/env bash
# Copies the committed Quelvra (public/quelvra, test/quelvra, SW tool) from this repo into the
# standalone repo (github.com/Darknode-Official/quelvra), rewriting paths for its layout:
# site at public/, tests at test/, relative URLs so it runs at a site root or under /quelvra/.
# Usage: tools/quelvra-sync.sh [path-to-standalone-repo]   (then review, test, commit there)
set -euo pipefail
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DST="${1:-$SRC/../quelvra}"
[ -d "$DST/.git" ] || { echo "not a git repo: $DST" >&2; exit 1; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
git -C "$SRC" archive HEAD public/quelvra test/quelvra tools/quelvra-sw-files.mjs $(git -C "$SRC" ls-files 'tools/quelvra-coverage*.mjs' 'tools/quelvra-fuzz*') | tar -x -C "$TMP"
rm -rf "$DST/public" "$DST/test"
mkdir -p "$DST/tools"
cp -r "$TMP/public/quelvra" "$DST/public"
cp -r "$TMP/test/quelvra" "$DST/test"
cp "$TMP/tools/quelvra-sw-files.mjs" "$DST/tools/sw-files.mjs"
cd "$DST"
sed -i 's#\.\./\.\./\.\./public/quelvra#../../public#g' test/bench/*.js
sed -i 's#\.\./\.\./public/quelvra#../public#g' test/*.js
sed -i 's#\.\./\.\./tools/quelvra-#../tools/#g' test/*.js
sed -i 's#\.\./public/quelvra/#../public/#; s#public/quelvra/sw.js#public/sw.js#; s#node tools/quelvra-sw-files.mjs#node tools/sw-files.mjs#' tools/sw-files.mjs
sed -i 's#href="/quelvra/icon.svg"#href="./icon.svg"#; s#href="/quelvra/manifest.webmanifest"#href="./manifest.webmanifest"#; s#href="/quelvra/app.css"#href="./app.css"#; s#src="/quelvra/app.js"#src="./app.js"#; s#class="wordmark" href="/quelvra/"#class="wordmark" href="./"#' public/index.html
sed -i 's#"/quelvra/icon.svg"#"./icon.svg"#g; s#"id": "/quelvra/"#"id": "./"#; s#"start_url": "/quelvra/"#"start_url": "./"#; s#"scope": "/quelvra/"#"scope": "./"#' public/manifest.webmanifest
sed -i 's#const BASE = "/quelvra/";#const BASE = new URL("./", self.location).pathname; // "/" on its own site, "/quelvra/" on darknode.ai#; s#Scope: /quelvra/ only.#Scope: the folder it is served from.#' public/sw.js
sed -i 's#navigator.serviceWorker.register("/quelvra/sw.js", { scope: "/quelvra/" })#navigator.serviceWorker.register("./sw.js", { scope: "./" })#' public/app.js
# the coverage and fuzz tools live in this repo's tools/ as well (quelvra- prefix dropped)
for f in "$TMP"/tools/quelvra-coverage*.mjs "$TMP"/tools/quelvra-fuzz*; do [ -e "$f" ] && sed 's#\.\./public/quelvra/#../public/#g; s#\./quelvra-#./#g; s#tools/quelvra-#tools/#g; s#test/quelvra/#test/#g; s#"quelvra-fuzz#"fuzz#g' "$f" > "tools/$(basename "$f" | sed 's/^quelvra-//')"; done
node tools/sw-files.mjs
if grep -rn '"/quelvra/' public --include=*.js --include=*.html --include=*.webmanifest | grep -v "engine/research" | grep -v "const BASE"; then echo "absolute /quelvra/ paths remain" >&2; exit 1; fi
echo "synced into $DST"
