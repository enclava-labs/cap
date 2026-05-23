# enclava-web

Web frontend for the Enclava CAP control plane. SvelteKit + TypeScript, static
SPA output, all data currently mocked.

Aesthetic: **Vault** (terminal-brutalist) — monospace only, ASCII boxes,
phosphor accents. Both dark and light modes are live; toggle via the button in
the top-right of the page header. The initial theme respects `prefers-color-scheme`
and is persisted to `localStorage` under `enclava-theme`.

## Routes

| Path                              | Purpose                                  |
| --------------------------------- | ---------------------------------------- |
| `/`                               | Redirects to `/login`                    |
| `/login`                          | OAuth/Nostr/email provider picker        |
| `/cli/approve`                    | CLI device-code approval screen          |
| `/dashboard`                      | Org overview · KPIs · recent deployments |
| `/orgs/[slug]/keyring`            | Org keyring viewer (read-only)           |
| `/orgs/[slug]/billing`            | Tier selector + pending Lightning invoice |
| `/apps/[name]`                    | App detail with deployment history       |

Use `/orgs/lio-a1b2c3d4/keyring`, `/orgs/lio-a1b2c3d4/billing`,
`/apps/chat-relay` while exploring.

## Develop

```sh
pnpm install        # or npm install
pnpm dev            # http://localhost:5173
pnpm check          # svelte-check + tsc
pnpm build          # static SPA bundle into ./build
pnpm preview        # serve ./build locally
```

## Layout

- `src/app.css` — design tokens for both themes under `[data-theme="dark|light"]`
- `src/lib/theme.svelte.ts` — reactive theme accessor + persistence
- `src/lib/tokens.css` *(none — collapsed into app.css)*
- `src/lib/types.ts` — domain types mirroring `crates/enclava-api/src/models.rs`
- `src/lib/mocks.ts` — fixture data
- `src/lib/format.ts` — helpers for sats, status labels, badge classes
- `src/lib/components/` — shared UI: `Badge`, `ScreenChrome`, `Sidebar`,
  `Terminal`, `ThemeToggle`
- `src/routes/` — page routes (SvelteKit file-based)

## Next steps (when wiring to the API)

1. Replace `src/lib/mocks.ts` with a typed API client hitting `enclava-api`.
2. Add a session store backed by the JWT returned by `/auth/device/poll` (see
   `MANUAL_CLI_DEPLOY_MVP_PLAN.md`).
3. Add `X-Enclava-Org` header on all org-scoped requests.
4. Switch `adapter-static` to `adapter-node` if you want SSR for SEO of marketing
   surface, or keep static and serve the bundle from `enclava-api`.
