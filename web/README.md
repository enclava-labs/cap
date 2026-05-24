# enclava-web

Web frontend for the Enclava CAP control plane. SvelteKit + TypeScript, static
SPA output, all data currently mocked.

Aesthetic: **Aurora** — extends the public `enclava.dev` landing page brand
into the application UI. Design tokens (navy slate background, electric cyan
primary, teal secondary, Plus Jakarta Sans + Inter + JetBrains Mono) are lifted
directly from `cap-website-redesign/client/src/index.css` so the marketing site
and the platform read as one product.

Dark-only by design — the landing page is dark and a single-mode brand is more
coherent. If a light Aurora is needed later, mirror the tokens under a
`[data-theme="light"]` selector in `src/app.css` and wire a toggle in the
layout.

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

- `src/app.css` — Aurora design tokens (single dark theme)
- `src/lib/types.ts` — domain types mirroring `crates/enclava-api/src/models.rs`
- `src/lib/mocks.ts` — fixture data
- `src/lib/format.ts` — helpers for sats, status labels, badge classes
- `src/lib/components/` — shared UI: `Badge`, `ScreenChrome`, `Sidebar`, `Terminal`
- `src/routes/` — page routes (SvelteKit file-based)

## Brand alignment

The CSS variables in `src/app.css` map 1:1 to the landing page tokens:

```
landing  hsl(222 30% 12%)  →  --bg-2
landing  hsl(222 30% 15%)  →  --card
landing  hsl(190 90% 45%)  →  --primary    (electric cyan)
landing  hsl(160 84% 39%)  →  --secondary  (teal)
landing  hsl(215 15% 75%)  →  --muted-fg
```

If the landing page rebrands, swap those HSL values and every screen here
moves with it.

## Next steps (when wiring to the API)

1. Replace `src/lib/mocks.ts` with a typed API client hitting `enclava-api`.
2. Add a session store backed by the JWT returned by `/auth/device/poll` (see
   `MANUAL_CLI_DEPLOY_MVP_PLAN.md`).
3. Add `X-Enclava-Org` header on all org-scoped requests.
4. Switch `adapter-static` to `adapter-node` if you want SSR for SEO, or keep
   static and serve the bundle from `enclava-api`.
