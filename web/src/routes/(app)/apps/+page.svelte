<script lang="ts">
  import ScreenChrome from '$lib/components/ScreenChrome.svelte';
  import Badge from '$lib/components/Badge.svelte';
  import { apps, activeOrg, deploymentsByApp } from '$lib/mocks';
  import { appStatusBadgeClass, appStatusLabel } from '$lib/format';
</script>

<ScreenChrome
  tabNum="07"
  tabLabel="APPS"
  breadcrumb={`orgs / ${activeOrg.name} / apps`}
  statusText={`${apps.length} apps · ${activeOrg.tier.toLowerCase()} tier`}
>
  <div class="page">
    <div class="page-h">
      <div>
        <div class="eyebrow">APPLICATIONS</div>
        <h1>Your <span class="accent">apps</span></h1>
        <div class="crumbs">orgs / {activeOrg.name} / apps</div>
      </div>
      <div class="actions">
        <button class="btn">⌘ Search</button>
        <button class="btn primary">+ New app</button>
      </div>
    </div>

    <div class="grid">
      {#each apps as app}
        <a class="app-card" href={`/apps/${app.name}`}>
          <div class="top">
            <div class="name">{app.name}</div>
            <Badge variant={appStatusBadgeClass(app.status).replace('b-', '') as any} small>
              {appStatusLabel(app.status).toLowerCase()}
            </Badge>
          </div>
          <div class="domain">{app.domain}</div>
          <div class="row">
            <span class="k">image</span>
            <span class="v mono">{app.current_image_digest}</span>
          </div>
          <div class="row">
            <span class="k">unlock</span>
            <span class="v">{app.unlock_mode}</span>
          </div>
          <div class="row">
            <span class="k">cosign</span>
            <span class="v" class:ok={app.cosign_verified} class:err={!app.cosign_verified}>
              {app.cosign_verified ? '✓ verified' : '✗ unverified'}
            </span>
          </div>
          <div class="row">
            <span class="k">resources</span>
            <span class="v">{app.cpu_limit} · {app.memory_limit}</span>
          </div>
          <div class="footer">
            <span class="dim">
              {deploymentsByApp[app.name]?.length ?? 1} deployments · created {app.created_at.slice(0, 10)}
            </span>
            <span class="arr">open →</span>
          </div>
        </a>
      {/each}
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

  .grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 16px;
  }
  .app-card {
    padding: 20px 22px;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--card);
    cursor: pointer;
    transition: 0.15s;
    color: var(--fg);
  }
  .app-card:hover {
    border-color: var(--primary);
    background: var(--card-2);
    transform: translateY(-1px);
    box-shadow: 0 8px 24px -10px var(--primary-glow);
  }
  .top {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 4px;
  }
  .name {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 20px;
    color: var(--fg);
  }
  .domain {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--primary);
    margin-bottom: 16px;
  }
  .row {
    display: flex;
    justify-content: space-between;
    padding: 6px 0;
    border-bottom: 1px solid var(--hair);
    font-size: 13px;
  }
  .row:last-of-type {
    border-bottom: 0;
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
  }
  .v.mono {
    font-family: var(--font-mono);
    font-size: 12px;
  }
  .v.ok {
    color: var(--secondary);
  }
  .v.err {
    color: var(--red);
  }
  .footer {
    margin-top: 14px;
    padding-top: 14px;
    border-top: 1px solid var(--hair);
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 12px;
  }
  .dim {
    color: var(--muted-fg);
    font-family: var(--font-mono);
  }
  .arr {
    color: var(--primary);
    font-family: var(--font-mono);
  }
</style>
