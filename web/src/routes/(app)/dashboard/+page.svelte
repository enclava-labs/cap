<script lang="ts">
  import ScreenChrome from '$lib/components/ScreenChrome.svelte';
  import Badge from '$lib/components/Badge.svelte';
  import { activeOrg, dashboardKpis, recentDeployments, currentUser } from '$lib/mocks';
  import { deployStatusBadgeClass, deployStatusLabel, sats } from '$lib/format';

  const kpi = dashboardKpis;
</script>

<ScreenChrome
  tabNum="02"
  tabLabel="OVERVIEW"
  breadcrumb={`${activeOrg.name} · ${activeOrg.tier.toLowerCase()}`}
  statusText="18:34Z"
>
  <div class="work">
    <div class="work-h">
      <div>
        <div class="eyebrow">DASHBOARD</div>
        <h1>Good evening, <span class="accent">{currentUser.display_name}.</span></h1>
        <div class="crumbs">orgs / {activeOrg.name} / overview</div>
      </div>
      <div class="work-h-right">
        <button class="btn"><span>⌘</span>Search</button>
        <button class="btn primary">+ New app</button>
      </div>
    </div>

    <div class="work-sub">
      Last attestation <span class="pill">{kpi.last_attestation}</span> · platform release
      <span class="pill">{kpi.platform_release}</span> · KBS reachable
    </div>

    <div class="kpi-grid">
      <div class="kpi">
        <div class="k">Apps deployed</div>
        <div class="v">{kpi.apps_deployed}<span class="u">/ {kpi.apps_max}</span></div>
        <div class="delta">+1 this week</div>
      </div>
      <div class="kpi teal">
        <div class="k">Running pods</div>
        <div class="v teal">{kpi.running_pods}</div>
        <div class="delta">all attested</div>
      </div>
      <div class="kpi amber">
        <div class="k">Balance</div>
        <div class="v amber">{sats(kpi.balance_sats)}<span class="u">sats</span></div>
        <div class="delta warn">renews in {kpi.renews_in_days}d</div>
      </div>
      <div class="kpi violet">
        <div class="k">Keyring</div>
        <div class="v">v{kpi.keyring_version}</div>
        <div class="delta dim">signed · ed25519 ok</div>
      </div>
    </div>

    <div class="section-h">
      <h2>Recent deployments</h2>
      <div class="a"><a href="/deployments">all →</a></div>
    </div>
    <div class="table-card">
      <table class="gx">
        <thead>
          <tr>
            <th>App</th>
            <th>Image</th>
            <th>Trigger</th>
            <th>Status</th>
            <th>When</th>
          </tr>
        </thead>
        <tbody>
          {#each recentDeployments as d}
            <tr>
              <td><a href={`/apps/${d.app_name}`} class="appn">{d.app_name}</a></td>
              <td class="mono">{d.image_digest}</td>
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
  </div>
</ScreenChrome>

<style>
  .work {
    padding: 30px 36px;
  }
  .work-h {
    display: flex;
    justify-content: space-between;
    align-items: end;
    margin-bottom: 6px;
    gap: 16px;
  }
  .work-h h1 {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 30px;
    letter-spacing: -0.025em;
    margin: 8px 0 0;
  }
  .work-h h1 .accent {
    color: var(--primary);
  }
  .work-h .crumbs {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--dim);
    margin-top: 8px;
  }
  .work-h-right {
    display: flex;
    gap: 10px;
  }
  .work-sub {
    color: var(--muted-fg);
    font-size: 13.5px;
    margin: 14px 0 28px;
  }
  .work-sub .pill {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--primary);
  }
  .kpi-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 14px;
    margin-bottom: 36px;
  }
  .kpi {
    padding: 18px 20px;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--card);
    position: relative;
    overflow: hidden;
  }
  .kpi::after {
    content: '';
    position: absolute;
    bottom: 0;
    left: 0;
    right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, var(--accent, var(--primary)), transparent);
    opacity: 0.5;
  }
  .kpi.teal {
    --accent: var(--secondary);
  }
  .kpi.amber {
    --accent: var(--amber);
  }
  .kpi.violet {
    --accent: var(--violet);
  }
  .kpi .k {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--muted-fg);
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }
  .kpi .v {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 34px;
    margin-top: 10px;
    letter-spacing: -0.025em;
    line-height: 1;
  }
  .kpi .v .u {
    font-family: var(--font-mono);
    font-size: 13px;
    color: var(--muted-fg);
    margin-left: 6px;
    font-weight: 400;
  }
  .kpi .v.teal {
    color: var(--secondary);
  }
  .kpi .v.amber {
    color: var(--amber);
  }
  .kpi .delta {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--secondary);
    margin-top: 8px;
  }
  .kpi .delta.warn {
    color: var(--amber);
  }
  .kpi .delta.dim {
    color: var(--muted-fg);
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
    letter-spacing: -0.01em;
  }
  .section-h .a a {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--muted-fg);
  }
  .section-h .a a:hover {
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
    font-size: 14px;
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
    font-weight: 600;
    color: var(--fg);
  }
  table.gx .appn:hover {
    color: var(--primary);
  }
  table.gx .dim {
    color: var(--muted-fg);
    font-family: var(--font-mono);
    font-size: 12px;
  }
</style>
