#!/usr/bin/env bash
# Compile every program in public/js/engine/programs.js and run the ones that
# need no input. Languages without a local compiler are reported as skipped.
#   bash tools/check-programs.sh
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
node --input-type=module -e '
import { PROGRAMS } from "'"$ROOT"'/public/js/engine/programs.js";
import fs from "fs";
const EXT = { python: "py", javascript: "js", typescript: "ts", rust: "rs", go: "go", java: "java", c: "c", cpp: "cpp", csharp: "cs", ruby: "rb", bash: "sh", html: "html" };
for (const p of PROGRAMS) for (const [l, code] of Object.entries(p.langs)) {
  const d = process.argv[1] + "/" + p.id + "_" + l;
  fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(d + "/main." + EXT[l], code + "\n");
}' "$WORK"
have() { command -v "$1" >/dev/null 2>&1; }
pass=0; fail=0; skip=0
cd "$WORK"
for d in */; do
  d=${d%/}; f=$(ls "$d"); ext=${f##*.}; out=""; run=""; ok=1
  cd "$d"; printf 'line one\nline two\n' > example.txt
  case $ext in
    py)   have python3 || { skip=$((skip+1)); cd ..; continue; }; out=$(python3 -m py_compile main.py 2>&1) || ok=0; run="python3 main.py" ;;
    js)   out=$(node --check main.js 2>&1) || ok=0; run="node main.js" ;;
    c)    have gcc || { skip=$((skip+1)); cd ..; continue; }; out=$(gcc -std=c11 -Wall -Wextra -o bin main.c 2>&1) || ok=0; [ -n "$out" ] && ok=0; run="./bin" ;;
    cpp)  have g++ || { skip=$((skip+1)); cd ..; continue; }; out=$(g++ -std=c++17 -Wall -Wextra -o bin main.cpp 2>&1) || ok=0; [ -n "$out" ] && ok=0; run="./bin" ;;
    go)   have go || { skip=$((skip+1)); cd ..; continue; }; out=$(go vet main.go 2>&1 && go build -o bin main.go 2>&1) || ok=0; run="./bin" ;;
    rs)   have rustc || { skip=$((skip+1)); cd ..; continue; }; out=$(rustc --edition 2021 -o bin main.rs 2>&1) || ok=0; [ -n "$out" ] && ok=0; run="./bin" ;;
    rb)   have ruby || { skip=$((skip+1)); cd ..; continue; }; out=$(ruby -c main.rb 2>&1 >/dev/null) || ok=0; run="ruby main.rb" ;;
    sh)   out=$(bash -n main.sh 2>&1) || ok=0; run="bash main.sh" ;;
    java) have javac || { echo "SKIP $d (no javac)"; skip=$((skip+1)); cd ..; continue; }; cls=$(grep -oP "public class \K\w+" main.java); cp main.java "$cls.java"; out=$(javac "$cls.java" 2>&1) || ok=0 ;;
    html) python3 -c 'import re;print("\n;\n".join(re.findall(r"<script>([\s\S]*?)</script>",open("main.html").read())))' > s.js; out=$(node --check s.js 2>&1) || ok=0 ;;
    *)    echo "SKIP $d (no checker for .$ext)"; skip=$((skip+1)); cd ..; continue ;;
  esac
  if [ $ok = 1 ]; then
    pass=$((pass+1))
    [ -n "$run" ] && echo "ok   $d: $(timeout 3 $run </dev/null 2>&1 | head -2 | tr '\n' '|' | cut -c1-100)"
  else
    fail=$((fail+1)); echo "FAIL $d:"; echo "$out" | head -8
  fi
  cd ..
done
echo "passed=$pass failed=$fail skipped=$skip"
[ $fail = 0 ]
