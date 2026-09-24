# Darknode AI proxy (Cloud Function)

The web app is a static site, so any API key it ships is public. This function
is the **only** place the free-tier provider keys live. The browser calls
`/api/chat` (a same-origin Firebase Hosting rewrite → this function), and the
function injects the server key, calls the upstream provider, and streams the
answer back. Keys never reach the browser.

Providers served: **gemini** (default), **groq**, **openrouter**, **mistral**.
Every provider is normalized to OpenAI-style SSE so the client has one parser.
If a user enters their own key in *Settings → API Keys*, the app calls that
provider directly (BYOK) and skips the proxy.

## Setup

1. **Rotate the old keys.** The previous keys were shipped in client JS and are
   in Git history — treat them as compromised and regenerate them in each
   provider's dashboard.

2. **Provide the keys to the function.** For local/dev, put them in
   `functions/.env` (gitignored):

   ```
   GEMINI_KEY=...
   GROQ_KEY=...
   OPENROUTER_KEY=...
   MISTRAL_KEY=...
   ```

   For production, prefer Secret Manager over `.env`:

   ```
   firebase functions:secrets:set GEMINI_KEY
   ```

   (and bind the secret to the function via `runWith`/`secrets` if you switch
   from `process.env` to `defineSecret`).

3. **Deploy.** Cloud Functions require the **Blaze** plan.

   ```
   firebase deploy --only functions,hosting
   ```

   `--only hosting` alone will not update the function.

## Notes

- Until the function is deployed, the free tier returns a clear "add your own
  key" message; BYOK and local Ollama keep working.
- Region: `us-central1` (matches the hosting rewrite in `firebase.json`).
