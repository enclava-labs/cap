<script lang="ts">
  import ScreenChrome from '$lib/components/ScreenChrome.svelte';
  import Sidebar from '$lib/components/Sidebar.svelte';
  import Badge from '$lib/components/Badge.svelte';
  import Terminal from '$lib/components/Terminal.svelte';
  import {
    activeOrg,
    dashboardKpis,
    recentDeployments,
    sampleLogs
  } from '$lib/mocks';
  import { deployStatusBadgeClass, deployStatusLabel, sats } from '$lib/format';

  const kpi = dashboardKpis;
</script>

<ScreenChrome
  tabNum="02"
  tabLabel="DASHBOARD / OVERVIEW"
  breadcrumb={`~ / orgs / ${activeOrg.name} / overview`}
  statusText="UID · 0xa39f…"
>
  <div class="dash">
    <Sidebar />

    <div class="work">
      <div class="work-h">
        <h2>Overview</h2>
        <div class="pwd-crumb">
          orgs <span class="dim">›</span> <b>{activeOrg.name}</b>
          <span class="dim">›</span> overview
        </div>
      </div>
      <div class="work-sub">
        Last attestation {kpi.last_attestation} · platform release
        <span class="phos">{kpi.platform_release}</span> · KBS reachable
      </div>

      <div class="kpis">
        <div class="kpi">
          <div class="k">APPS DEPLOYED</div>
          <div class="v">{String(kpi.apps_deployed).padStart(2, '0')} <span class="unit">/ {kpi.apps_max}</span></div>
          <div class="delta">+1 this week</div>
        </div>
        <div class="kpi">
          <div class="k">RUNNING PODS</div>
          <div class="v">{String(kpi.running_pods).padStart(2, '0')}</div>
          <div class="delta">all attested</div>
        </div>
        <div class="kpi">
          <div class="k">BALANCE</div>
          <div class="v">{sats(kpi.balance_sats)} <span class="unit">sats</span></div>
          <div class="delta warn">renews in {kpi.renews_in_days}d</div>
        </div>
        <div class="kpi">
          <div class="k">KEYRING VERSION</div>
          <div class="v">v{kpi.keyring_version}</div>
          <div class="delta">signed · verified</div>
        </div>
      </div>

      <div class="section-title">
        <h3>RECENT DEPLOYMENTS</h3>
        <span class="ln"></span>
        <span class="act"><a href="/deployments">view all ›</a></span>
      </div>
      <table class="t">
        <thead>
          <tr>
            <th>APP</th>
            <th>IMAGE</th>
            <th>TRIGGER</th>
            <th>STATUS</th>
            <th>STARTED</th>
            <th>BY</th>
          </tr>
        </thead>
        <tbody>
          {#each recentDeployments as d}
            <tr>
              <td><a href={`/apps/${d.app_name}`} class="appn">{d.app_name}</a></td>
              <td class="digest">{d.image_digest}</td>
              <td class="id">{d.trigger.toUpperCase()}</td>
              <td>
                <Badge variant={deployStatusBadgeClass(d.status).replace('b-', '') as any}>
                  {deployStatusLabel(d.status)}
                </Badge>
              </td>
              <td class="id">{d.started_at.split('T')[1]}</td>
              <td class="id">{d.triggered_by}</td>
            </tr>
          {/each}
        </tbody>
      </table>

      <div class="section-title">
        <h3>NEXT FROM YOUR CLI</h3>
        <span class="ln"></span>
      </div>
      <Terminal lines={sampleLogs} />
    </div>
  </div>
</ScreenChrome>

<style>
  .dash {
    display: grid;
    grid-template-columns: 220px 1fr;
  }
  .work {
    padding: 28px 32px;
  }
  .work-h {
    display: flex;
    align-items: baseline;
    gap: 18px;
    margin-bottom: 6px;
  }
  .work-h h2 {
    margin: 0;
    font-weight: 500;
    font-size: 24px;
    letter-spacing: 0.02em;
  }
  .work-h .pwd-crumb {
    color: var(--dim);
    font-size: 13px;
  }
  .work-h .pwd-crumb b {
    color: var(--phos);
    font-weight: 400;
  }
  .work-h .pwd-crumb .dim {
    color: var(--dimmer);
  }
  .work-sub {
    color: var(--dim);
    font-size: 13px;
    margin-bottom: 28px;
  }
  .work-sub .phos {
    color: var(--phos);
  }
  .kpis {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    border: 1px solid var(--line);
    margin-bottom: 32px;
  }
  :root[data-theme='light'] .kpis {
    background: var(--bg);
  }
  .kpi {
    padding: 18px;
    border-right: 1px dashed var(--line);
  }
  .kpi:last-child {
    border-right: 0;
  }
  .kpi .k {
    font-size: 11px;
    color: var(--dim);
    letter-spacing: 0.14em;
  }
  .kpi .v {
    font-size: 28px;
    color: var(--ink);
    margin-top: 8px;
    font-weight: 400;
    letter-spacing: 0.02em;
  }
  .kpi .v .unit {
    font-size: 13px;
    color: var(--dim);
    margin-left: 6px;
    letter-spacing: 0.1em;
  }
  .kpi .delta {
    font-size: 12px;
    color: var(--phos);
    margin-top: 4px;
  }
  .kpi .delta.warn {
    color: var(--amber);
  }
  .section-title {
    display: flex;
    align-items: baseline;
    gap: 12px;
    margin: 28px 0 12px;
  }
  .section-title h3 {
    margin: 0;
    font-weight: 500;
    font-size: 14px;
    color: var(--ink);
    letter-spacing: 0.1em;
  }
  .section-title .ln {
    flex: 1;
    border-top: 1px dashed var(--line);
    margin-bottom: 4px;
  }
  .section-title .act {
    font-size: 12px;
    color: var(--dim);
  }
  table.t {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  table.t th,
  table.t td {
    text-align: left;
    padding: 10px 14px;
    border-bottom: 1px dashed var(--line);
  }
  table.t th {
    font-weight: 400;
    color: var(--dim);
    font-size: 11px;
    letter-spacing: 0.14em;
    border-bottom: 1px solid var(--line);
  }
  table.t tr:hover td {
    background: var(--phos-soft);
  }
  table.t .id {
    color: var(--dim);
  }
  table.t .digest {
    color: var(--magenta);
  }
  table.t .appn {
    color: var(--ink);
    border-bottom: 0;
  }
  table.t .appn:hover {
    color: var(--phos);
  }
</style>
