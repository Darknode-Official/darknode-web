#!/usr/bin/env bash
# Second-opinion review by the Codex CLI (runs on the ChatGPT plan it is logged in with).
# Claude Code builds; Codex reviews what changed and reports problems. Codex does not edit files here.
#
#   tools/codex-review.sh               review the last commit
#   tools/codex-review.sh <sha>         review one commit
#   tools/codex-review.sh --uncommitted review staged + unstaged + untracked changes
#   tools/codex-review.sh --base main   review this branch against a base branch
#   tools/codex-review.sh A..B          review a commit range (e.g. a merged branch: M^1..M^2)
#
# The report is printed and saved to .codex-reviews/<target>.md (git-ignored).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
command -v codex >/dev/null || { echo "codex CLI not found: npm i -g @openai/codex" >&2; exit 1; }

RULES='Project rules to check against, in addition to normal bugs, regressions and security issues:
- Static Firebase-hosted site: public/ is served as-is. ES modules are imported with ?v= cache tags; a changed module needs its tag bumped in every importer, up the chain to index.html.
- No emojis anywhere in UI text, code or comments.
- No invented data shown as real (fake counts, fake alerts, fake scan results). Sample data must be labelled as sample.
- Secrets (API keys, tokens) never in client code.
- Do not flag or suggest changes to the license/hostname guard in auth.js, the first script in public/quelvra/index.html, or line 3 of landing.js; those are intentional.
- CSS: styles are layered (styles.css, pro-theme.css, theme-command.css, buttons.css, console.css, aws.css last); check new rules against the Command skin (html[data-skin=command]) and dark style too.
- Check narrow screens (<= 900px) and keyboard access for UI changes.
Report findings ranked most severe first, each with file:line, what breaks, and a concrete fix. Say plainly if you find nothing serious.'

mkdir -p .codex-reviews
case "${1:-}" in
  --uncommitted) name="uncommitted"; what="the uncommitted changes"; diff=$(git diff HEAD; git ls-files --others --exclude-standard | sed 's/^/untracked: /') ;;
  --base)        name="base-${2:?branch}"; what="this branch against $2"; diff=$(git diff "$2"...HEAD) ;;
  *..*)          name="$1"; what="commits $1"; diff=$(git log -p --format='commit %H%n%s%n%n%b' "$1") ;;
  *)             sha=$(git rev-parse --short "${1:-HEAD}"); name="$sha"; what="commit $sha"; diff=$(git show --format='%H%n%s%n%n%b' "$sha") ;;
esac
# The diff goes in the prompt, so the review works even when Codex's shell sandbox cannot
# start (Ubuntu blocks the user namespaces bubblewrap needs unless an AppArmor profile allows it).
[ -n "$diff" ] || { echo "Nothing to review: the diff for $what is empty." >&2; exit 1; }
diff=$(printf '%s' "$diff" | head -c 400000)
name=$(printf '%s' "$name" | tr '/.' '--')
out=".codex-reviews/$name.md"
echo "Codex reviewing $what ..." >&2
# read-only sandbox: Codex can read files and run git/tests, but cannot modify the repo
# The prompt goes in on stdin: a large diff as one argument exceeds Linux's 128 KB per-argument limit.
printf 'You are reviewing code another agent wrote. Review %s in this repository. The full diff is below. If your shell works, read surrounding code as needed; do not modify any files.\n\n%s\n\n----- DIFF -----\n%s\n' "$what" "$RULES" "$diff" \
  | codex exec --sandbox read-only --ephemeral -c model_reasoning_effort=high -o "$out" - >&2
cat "$out"
echo "Saved: $out" >&2
