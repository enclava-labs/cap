<script lang="ts">
  import ScreenChrome from '$lib/components/ScreenChrome.svelte';
  import { activeOrg, orgSettings, currentUser } from '$lib/mocks';

  let displayName = $state(orgSettings.display_name);
  let customDomain = $state(orgSettings.custom_domain);
</script>

<ScreenChrome
  tabNum="12"
  tabLabel="SETTINGS"
  breadcrumb={`account / settings`}
  statusText={`active org · ${activeOrg.name}`}
>
  <div class="page">
    <div class="page-h">
      <div>
        <div class="eyebrow">CONFIGURATION</div>
        <h1>Org <span class="accent">settings</span></h1>
        <div class="crumbs">orgs / {activeOrg.name} / settings</div>
      </div>
    </div>

    <div class="section">
      <div class="section-h">
        <h2>Organisation</h2>
        <div class="sub">Display name and the cluster region your apps run in.</div>
      </div>
      <div class="form-card">
        <div class="field">
          <label for="dn">Display name</label>
          <input id="dn" type="text" bind:value={displayName} />
          <div class="hint">Used in invoices and the public app URL.</div>
        </div>
        <div class="field">
          <div class="lbl">Slug</div>
          <div class="readonly mono">{activeOrg.name}</div>
          <div class="hint">Permanent. Used as the subdomain — <span class="mono">{activeOrg.name}.app.enclava.dev</span>.</div>
        </div>
        <div class="field">
          <div class="lbl">Cluster region</div>
          <div class="readonly">{orgSettings.cluster_region}</div>
          <div class="hint">Region is locked for the lifetime of the org. Contact support to migrate.</div>
        </div>
        <div class="actions-row">
          <button class="btn primary">Save changes</button>
          <button class="btn">Discard</button>
        </div>
      </div>
    </div>

    <div class="section">
      <div class="section-h">
        <h2>Custom domain</h2>
        <div class="sub">Point a domain you own at your apps. Verified via a DNS TXT record.</div>
      </div>
      <div class="form-card">
        <div class="field">
          <label for="cd">Domain</label>
          <input id="cd" type="text" bind:value={customDomain} placeholder="app.example.com" />
        </div>
        <div class="field">
          <div class="lbl">Verification</div>
          <div class="verify-card">
            <div class="verify-status amber">⏳ pending TXT record</div>
            <div class="verify-instr">Add this TXT record at your DNS provider:</div>
            <pre>_enclava-verify  TXT  enclava-verify=8e5a1b4c9d273eaf-a1b2</pre>
            <button class="link">Re-check now →</button>
          </div>
        </div>
      </div>
    </div>

    <div class="section">
      <div class="section-h">
        <h2>Default cosign identity</h2>
        <div class="sub">New apps inherit these signer identity defaults.</div>
      </div>
      <div class="form-card">
        <div class="field">
          <div class="lbl">Subject</div>
          <div class="readonly mono">{orgSettings.default_signer_subject}</div>
        </div>
        <div class="field">
          <div class="lbl">Issuer</div>
          <div class="readonly mono">{orgSettings.default_signer_issuer}</div>
        </div>
        <div class="hint">
          Each individual app can override these in <span class="mono">enclava.toml</span>.
        </div>
      </div>
    </div>

    <div class="section">
      <div class="section-h">
        <h2>API keys</h2>
        <div class="sub">Scoped tokens for CI deploys.</div>
      </div>
      <div class="form-card empty-card">
        <div class="empty-h">No API keys yet</div>
        <p>API keys are a post-MVP feature. For now, use <span class="mono">enclava login</span> from your terminal.</p>
        <button class="btn" disabled>Generate API key (coming soon)</button>
      </div>
    </div>

    <div class="section danger">
      <div class="section-h">
        <h2 class="danger-h">Danger zone</h2>
        <div class="sub">These actions are permanent.</div>
      </div>
      <div class="danger-card">
        <div class="danger-row">
          <div>
            <div class="d-t">Delete organisation</div>
            <div class="d-s">
              Removes all apps, keyrings, billing history and the recovery seed reference.
              {#if activeOrg.is_personal}
                <b> Personal orgs cannot be deleted</b> — they are tied to your account.
              {/if}
            </div>
          </div>
          <button class="btn danger" disabled={activeOrg.is_personal}>Delete org</button>
        </div>
        <div class="danger-row">
          <div>
            <div class="d-t">Sign out</div>
            <div class="d-s">
              Ends this browser session. Your CLI session and recovery seed are unaffected.
            </div>
          </div>
          <button class="btn danger">Sign {currentUser.email} out</button>
        </div>
      </div>
    </div>
  </div>
</ScreenChrome>

<style>
  .page {
    padding: 30px 36px;
  }
  .page-h {
    margin-bottom: 32px;
  }
  .page-h h1 {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 30px;
    letter-spacing: -0.025em;
    margin: 8px 0 0;
  }
  .page-h h1 .accent {
    color: var(--primary);
  }
  .page-h .crumbs {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--dim);
    margin-top: 8px;
  }

  .section {
    margin-bottom: 36px;
  }
  .section-h h2 {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 17px;
    margin: 0;
  }
  .section-h .sub {
    font-size: 13px;
    color: var(--muted-fg);
    margin: 4px 0 14px;
  }

  .form-card {
    padding: 24px;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--card);
    display: grid;
    gap: 18px;
  }

  .field label,
  .field .lbl {
    display: block;
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--muted-fg);
    margin-bottom: 6px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .field input {
    width: 100%;
    padding: 11px 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--inset);
    color: var(--fg);
    font: inherit;
    font-size: 14px;
    outline: none;
  }
  .field input:focus {
    border-color: var(--primary);
    box-shadow: 0 0 0 3px var(--primary-soft);
  }
  .readonly {
    padding: 11px 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--inset);
    font-size: 14px;
    color: var(--fg-2);
  }
  .readonly.mono {
    font-family: var(--font-mono);
    font-size: 13px;
  }
  .hint {
    font-size: 12px;
    color: var(--muted-fg);
    margin-top: 6px;
  }
  .hint .mono {
    font-family: var(--font-mono);
    color: var(--primary);
  }
  .actions-row {
    display: flex;
    gap: 10px;
    padding-top: 6px;
  }

  .verify-card {
    padding: 16px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--inset);
  }
  .verify-status {
    font-family: var(--font-mono);
    font-size: 12px;
    margin-bottom: 10px;
  }
  .verify-status.amber {
    color: var(--amber);
  }
  .verify-instr {
    font-size: 13px;
    color: var(--muted-fg);
    margin-bottom: 8px;
  }
  pre {
    background: var(--bg);
    border: 1px solid var(--hair);
    padding: 10px 14px;
    border-radius: var(--radius);
    font-size: 12px;
    color: var(--primary);
    margin: 0 0 10px;
  }
  .link {
    background: transparent;
    border: 0;
    color: var(--primary);
    font-family: var(--font-mono);
    font-size: 12px;
    cursor: pointer;
    padding: 0;
  }
  .link:hover {
    text-decoration: underline;
  }

  .empty-card {
    align-items: center;
    text-align: center;
    padding: 32px;
  }
  .empty-card p {
    color: var(--muted-fg);
    font-size: 13.5px;
    margin: 8px 0 14px;
  }
  .empty-card .mono {
    font-family: var(--font-mono);
    color: var(--primary);
  }
  .empty-h {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 16px;
    color: var(--muted-fg);
  }

  .danger .danger-h {
    color: var(--red);
  }
  .danger-card {
    padding: 0;
    border: 1px solid var(--red);
    border-radius: var(--radius-lg);
    background: var(--red-soft);
  }
  .danger-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 16px;
    padding: 18px 22px;
    border-bottom: 1px solid hsla(0, 70%, 58%, 0.2);
  }
  .danger-row:last-child {
    border-bottom: 0;
  }
  .d-t {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 15px;
    color: var(--fg);
  }
  .d-s {
    font-size: 13px;
    color: var(--muted-fg);
    margin-top: 4px;
    max-width: 60ch;
  }
</style>
