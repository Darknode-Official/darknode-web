# Darknode

**darknode.ai** — AI-powered security platform.

Tools, threat intel, AI agents, and a code workbench — on the web and desktop.

## Stack

- **Website**: Static site on Cloudflare Pages
- **API**: Node.js on Fly.io (`api.darknode.ai`)
- **CLI**: `darknode` command (`npm i -g darknode-cli`)
- **Desktop**: Electron app
- **OS**: Custom Linux VM for security labs
- **Engine**: Nexus — 49-module AI agent engine

## Development

```bash
# Local dev
npx serve public/

# Deploy
git push  # auto-deploys via Cloudflare Pages
```

## License

See [LICENSE](LICENSE).
