# Release process

Every change reaches production the same way. `docs/SHIP-CHECKLIST.md` covers a single
feature (registry, copy, legal, honesty, plans); this document covers how finished
work becomes a deploy.

## Branch model

| Branch | Purpose | Lifetime |
|---|---|---|
| `main` | What is live. Only release merges land here. | permanent |
| `release/YYYY-MM-DD` | One release candidate. Every branch going out in that deploy is merged into it. | until merged to main |
| `fix/*`, `feat/*` | One topic each, branched from `main` (or from the open release when it depends on it). | deleted once its release merges |
| `archive/*` (tags) | Old unmerged work kept for reference. Not branches, so they don't clutter `git branch`. | permanent |

Rules:
- One topic per branch. Never commit to `main` directly.
- At most one open `release/*` branch at a time. New work after a release is cut goes on the next one.
- Push only to `origin`, never `def`. No Co-Authored-By or AI trailers.
- After a release merges, delete its topic branches and their worktrees (`git worktree remove`).

## Steps

1. **Build each change** on its own topic branch and run `docs/SHIP-CHECKLIST.md` for it.
2. **Cut the release.** `git switch -c release/YYYY-MM-DD origin/main`, merge each topic branch, and resolve conflicts there (not on `main`).
3. **Gate.** `npm run release:check` must print `READY`. It checks:
   - the branch, and that the tree is clean;
   - `node --check` on every changed file;
   - secrets, native dialogs and emoji on added lines;
   - commit trailers;
   - the release build and the full test suite.

   Then do the browser pass from checklist step 7: a non-owner Free user, desktop and 390px wide.
4. **Ask the owner** to merge and deploy. Nothing below happens without a yes.
5. **Preview.** Open the PR from `release/*` to `main`; the Preview workflow posts a channel URL. Check sign-in (Google popup and email), the Deck, two or three changed tools, and the browser console on the preview.
6. **Deploy, in this order**, so each layer is ready for the next:
   1. Firestore and Storage rules: `npx firebase deploy --only firestore:rules,storage`. If the admin claim logic changed, run `scripts/set-admin.mjs` first.
   2. Worker staging, then production: `cd worker && npx wrangler deploy --env staging`, smoke-test it, then `npx wrangler deploy --env=""`.
   3. Hosting: `npx firebase deploy --only hosting`. It builds `dist/` first.
7. **Verify live.**
   - `curl https://darknode.ai/build.json` matches the build hash from step 3.
   - Security headers are present: `curl -sI https://darknode.ai/ | grep -i content-security`.
   - Sign in, open the Deck and one changed tool.
8. **Merge and record.**
   - Merge the PR, tag `vYYYY.MM.DD` on the merge commit, and push the tag.
   - Add `docs/releases/YYYY-MM-DD.md` (template below).
   - Delete the merged topic branches.

## Rollback

- Hosting: Firebase console → Hosting → Release history → Rollback, or `npx firebase hosting:clone <site>@<previous-version-id> <site>:live` for each site.
- Worker: `npx wrangler rollback` (Cloudflare keeps prior versions).
- Rules: redeploy the previous tag's `firebase/` files from a worktree (`git worktree add /tmp/rb vPREVIOUS`).
- Record the rollback and its cause in that release's record.

## Release record template

```
# Release YYYY-MM-DD
Build: <hash>   Worker: <version id>   Tag: vYYYY.MM.DD
## What changed (user-visible)
## Security / rules / data changes
## Verified (how)
## Skipped or known issues
## Owner decisions still open
```

## Other repos

`darknode-cli`, `darknode-app` and `darknode-os` follow the same branch model and
the same no-trailer rule. Each runs its own `npm test` (and CI) before merge. A web
release that depends on a CLI or app change names that branch in its record.
