<script lang="ts">
  import ScreenChrome from '$lib/components/ScreenChrome.svelte';
  import Badge from '$lib/components/Badge.svelte';
  import { allDeployments, activeOrg } from '$lib/mocks';
  import { deployStatusBadgeClass, deployStatusLabel } from '$lib/format';

  let filter = $state<'all' | 'healthy' | 'failed' | 'rolled'>('all');

  const filtered = $derived(
    filter === 'all'
      ? allDeployments
      : allDeployments.filter((d) => {
          if (filter === 'healthy') return d.status === 'Healthy';
          if (filter === 'failed') return d.status === 'Failed';
          if (filter === 'rolled') return d.status === 'RolledBack';
          return true;
        })
  );
</script>

<ScreenChrome
  tabNum="08"
  tabLabel="DEPLOYMENTS"
  breadcrumb={`orgs / ${activeOrg.name} / deployments`}
  statusText={`${allDeployments.length} total · last 24h`}
>
  <div class="page">
    <div class="page-h">
      <div>
        <div class="eyebrow">CHANGE LOG</div>
        <h1>All <span class="accent">deployments</span></h1>
        <div class="crumbs">orgs / {activeOrg.name} / deployments</div>
      </div>
      <div class="filters">
        <button class="chip-btn" class:act={filter === 'all'} onclick={() => (filter = 'all')}>
          all
        </button>
        <button
          class="chip-btn"
          class:act={filter === 'healthy'}
          onclick={() => (filter = 'healthy')}
        >
          healthy
        </button>
        <button class="chip-btn" class:act={filter === 'failed'} onclick={() => (filter = 'failed')}>
          failed
        </button>
        <button class="chip-btn" class:act={filter === 'rolled'} onclick={() => (filter = 'rolled')}>
          rolled back
        </button>
      </div>
    </div>

    <div class="table-card">
      <table class="gx">
        <thead>
          <tr>
            <th>ID</th>
            <th>App</th>
            <th>Image</th>
            <th>Trigger</th>
            <th>Status</th>
            <th>When</th>
          </tr>
        </thead>
        <tbody>
          {#each filtered as d}
            <tr>
              <td class="dim">#{d.id}</td>
              <td>
                <a href={`/apps/${d.app_name}`} class="appn">{d.app_name}</a>
              </td>
              <td class="mono">{d.image_digest} {d.cosign_verified ? '✓' : '✗'}</td>
              <td class="dim">{d.trigger.toLowerCase()} · {d.triggered_by}</td>
              <td>
                <Badge variant={deployStatusBadgeClass(d.status).replace('b-', '') as any}>
                  {deployStatusLabel(d.status).toLowerCase()}
                </Badge>
              </td>
              <td class="dim">{d.age}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>

    {#if filtered.length === 0}
      <div class="empty">No deployments match this filter.</div>
    {/if}
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
  .filters {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
  }
  .chip-btn {
    padding: 7px 14px;
    border: 1px solid var(--border);
    border-radius: 999px;
    background: var(--card);
    color: var(--muted-fg);
    font-family: var(--font-mono);
    font-size: 12px;
    cursor: pointer;
  }
  .chip-btn:hover {
    border-color: var(--border-2);
    color: var(--fg);
  }
  .chip-btn.act {
    border-color: var(--primary);
    background: var(--primary-soft);
    color: var(--primary);
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
    padding: 14px 20px;
    border-bottom: 1px solid var(--hair);
    font-size: 13.5px;
  }
  table.gx tr:last-child td {
    border-bottom: 0;
  }
  table.gx tr:hover td {
    background: hsla(190, 90%, 45%, 0.04);
  }
  table.gx .mono {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--fg-2);
  }
  table.gx .appn {
    color: var(--fg);
    font-weight: 600;
  }
  table.gx .appn:hover {
    color: var(--primary);
  }
  table.gx .dim {
    color: var(--muted-fg);
    font-family: var(--font-mono);
    font-size: 12px;
  }

  .empty {
    padding: 60px;
    text-align: center;
    color: var(--muted-fg);
    font-family: var(--font-mono);
    font-size: 13px;
  }
</style>
