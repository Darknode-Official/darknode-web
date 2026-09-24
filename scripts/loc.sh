#!/usr/bin/env bash
# Darknode meaningful-source LOC accounting.
# Counts project-owned source only. Excludes: node_modules, vendored/minified
# libs, build output, source maps, .git, lockfiles. Reports by category so
# growth is legible and can't be gamed by dumping vendor code or generated junk.
set -euo pipefail
ROOT="${1:-/home/manav/projects/darknode-web}"
cd "$ROOT"

EXCL=( -not -path "*/node_modules/*" -not -path "*/.git/*" -not -path "*/vendor/*" \
       -not -name "*.min.*" -not -name "*.map" -not -name "package-lock.json" )

count() { # $1 = human label; rest = find predicate args
  local label="$1"; shift
  local files lines
  files=$(find . "$@" "${EXCL[@]}" -type f 2>/dev/null | wc -l)
  lines=$(find . "$@" "${EXCL[@]}" -type f -print0 2>/dev/null | xargs -0 cat 2>/dev/null | wc -l)
  printf "%-28s %6s files  %10s lines\n" "$label" "$files" "$lines"
}

echo "===== Darknode meaningful source LOC ($(date -u +%Y-%m-%dT%H:%MZ)) ====="
count "App JS (public/js)"        -path "./public/js/*" -name "*.js"
count "Reference data (public/data)" -path "./public/data/*" -name "*.js"
count "CSS (public/css)"          -path "./public/css/*" -name "*.css"
count "HTML (public)"             -path "./public/*" -name "*.html"
count "JSON/schema (public)"      -path "./public/*" -name "*.json"
count "Backend (functions)"       -path "./functions/*" \( -name "*.js" -o -name "*.json" \)
count "Firebase rules/config"     \( -name "firestore.rules" -o -name "storage.rules" -o -name "firebase.json" -o -name "firestore.indexes.json" \)
count "Tests (test/)"             -path "./test/*" \( -name "*.mjs" -o -name "*.test.js" -o -name "*.spec.js" \)
count "Tooling/scripts+config"    \( -path "./scripts/*" -o -name "package.json" \) -not -path "./functions/*"
count "Docs (*.md)"               -name "*.md"
echo "-------------------------------------------------------------"
TOTAL=$(find . \( -path "./public/js/*" -o -path "./public/data/*" -o -path "./public/css/*" \
   -o -path "./public/*" -o -path "./functions/*" -o -path "./test/*" -o -path "./scripts/*" \
   -o -name "*.md" -o -name "package.json" \
   -o -name "firestore.rules" -o -name "storage.rules" -o -name "firestore.indexes.json" \) \
   "${EXCL[@]}" -type f \( -name "*.js" -o -name "*.mjs" -o -name "*.css" -o -name "*.html" -o -name "*.json" -o -name "*.md" -o -name "*.rules" -o -name "*.sh" \) \
   -print0 2>/dev/null | xargs -0 cat 2>/dev/null | wc -l)
printf "%-28s %26s lines\n" "TOTAL meaningful source" "$TOTAL"
