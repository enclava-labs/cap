<script lang="ts">
  import ScreenChrome from '$lib/components/ScreenChrome.svelte';
  import { recoveryState, currentUser } from '$lib/mocks';
</script>

<ScreenChrome
  tabNum="10"
  tabLabel="RECOVERY SEED"
  breadcrumb={`account / recovery`}
  statusText={recoveryState.last_backup_at ? 'backup verified' : 'no backup yet'}
>
  <div class="page">
    <div class="page-h">
      <div>
        <div class="eyebrow">KEY MATERIAL</div>
        <h1>Recovery <span class="accent">seed</span></h1>
        <div class="crumbs">account / recovery</div>
      </div>
      <div class="actions">
        <button class="btn">Show fingerprint</button>
        <button class="btn primary">Create encrypted backup →</button>
      </div>
    </div>

    <div class="cards">
      <div class="status-card">
        <div class="badge-row">
          <span class="dot"></span>
          <span class="lab">SEED PRESENT ON THIS DEVICE</span>
        </div>
        <div class="big-mono">{recoveryState.fingerprint}</div>
        <div class="sub">
          Owner-key fingerprint · Ed25519 · derived locally on {recoveryState.derived_at.slice(0, 10)}.
        </div>
        <div class="row">
          <div class="k">DERIVED FOR</div>
          <div class="v">{currentUser.email}</div>
        </div>
        <div class="row">
          <div class="k">LAST BACKUP</div>
          <div class="v">
            {#if recoveryState.last_backup_at}
              {recoveryState.last_backup_at.slice(0, 10)}
              <span class="dim">· {recoveryState.backup_kdf}</span>
            {:else}
              <span class="warn">never · create a backup now</span>
            {/if}
          </div>
        </div>
      </div>

      <div class="callout">
        <div class="cl-h">⚠ &nbsp; The platform cannot recover your seed.</div>
        <p>
          Your recovery seed is generated and stored only on your machine. The platform never
          sees it. If you lose this device without a backup, you will not be able to publish
          new keyring revisions and your apps cannot be redeployed by this owner key.
        </p>
        <ul>
          <li>Create an <b>encrypted backup</b> file, encrypted with a passphrase.</li>
          <li>Store the backup somewhere physically separate (password manager, USB key).</li>
          <li>Restore on a new device with <code>enclava key restore enclava-recovery.json</code>.</li>
        </ul>
      </div>
    </div>

    <div class="section-h">
      <h2>Derived keys</h2>
      <div class="dim">HKDF-SHA256(seed, "enclava/v1", &lt;label&gt;)</div>
    </div>

    <div class="table-card">
      <table class="gx">
        <thead>
          <tr>
            <th>Label</th>
            <th>Kind</th>
            <th>Fingerprint</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each recoveryState.derived_keys as k}
            <tr>
              <td class="mono">{k.label}</td>
              <td>{k.kind}</td>
              <td class="mono">{k.fingerprint}</td>
              <td class="actions-cell"><button class="link">Copy →</button></td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </div>
</ScreenChrome>

<style>
  .page {
    padding: 30px 36px;
  }
  .page-h {
    display: flex;
    justify-content: space-between;
    align-items: end;
    margin-bottom: 28px;
    gap: 16px;
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
  .actions {
    display: flex;
    gap: 10px;
  }

  .cards {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
    margin-bottom: 32px;
  }
  .status-card {
    padding: 24px;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--card);
  }
  .badge-row {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 14px;
  }
  .badge-row .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--secondary);
    box-shadow: 0 0 0 4px hsla(160, 84%, 39%, 0.18);
  }
  .badge-row .lab {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--secondary);
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }
  .big-mono {
    font-family: var(--font-mono);
    font-size: 32px;
    color: var(--primary);
    letter-spacing: 0.02em;
    text-shadow: 0 0 30px var(--primary-glow);
    margin-bottom: 6px;
  }
  .sub {
    font-size: 13px;
    color: var(--muted-fg);
    margin-bottom: 18px;
  }
  .row {
    display: flex;
    justify-content: space-between;
    padding: 8px 0;
    border-top: 1px solid var(--hair);
    font-size: 13px;
  }
  .k {
    color: var(--muted-fg);
    font-family: var(--font-mono);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .v {
    color: var(--fg);
    font-family: var(--font-mono);
    font-size: 12.5px;
  }
  .v .dim {
    color: var(--muted-fg);
  }
  .v .warn {
    color: var(--amber);
  }

  .callout {
    padding: 24px;
    border: 1px solid var(--amber);
    border-radius: var(--radius-lg);
    background: var(--amber-soft);
  }
  .cl-h {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 16px;
    color: var(--amber);
    margin-bottom: 10px;
  }
  .callout p {
    font-size: 14px;
    color: var(--fg-2);
    margin: 0 0 12px;
    line-height: 1.55;
  }
  .callout ul {
    margin: 0;
    padding-left: 18px;
    font-size: 13.5px;
    color: var(--fg-2);
  }
  .callout ul li {
    padding: 4px 0;
  }
  .callout code {
    font-family: var(--font-mono);
    font-size: 12px;
    background: hsla(0, 0%, 0%, 0.2);
    color: var(--amber);
    padding: 2px 6px;
    border-radius: 4px;
  }

  .section-h {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    margin: 16px 0 14px;
  }
  .section-h h2 {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 17px;
    margin: 0;
  }
  .section-h .dim {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--muted-fg);
  }

  .table-card {
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
    background: var(--card);
  }
  table.gx {
    width: 100%;
    border-collapse: collapse;
  }
  table.gx th {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--muted-fg);
    text-align: left;
    padding: 12px 20px;
    border-bottom: 1px solid var(--hair);
    font-weight: 500;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    background: var(--inset);
  }
  table.gx td {
    padding: 13px 20px;
    border-bottom: 1px solid var(--hair);
    font-size: 13.5px;
  }
  table.gx tr:last-child td {
    border-bottom: 0;
  }
  table.gx .mono {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--fg-2);
  }
  .actions-cell {
    text-align: right;
  }
  .link {
    background: transparent;
    border: 0;
    color: var(--muted-fg);
    font-family: var(--font-mono);
    font-size: 12px;
    cursor: pointer;
    padding: 0;
  }
  .link:hover {
    color: var(--primary);
  }
</style>
