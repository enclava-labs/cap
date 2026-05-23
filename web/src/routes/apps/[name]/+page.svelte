<script lang="ts">
  import { page } from '$app/stores';
  import ScreenChrome from '$lib/components/ScreenChrome.svelte';
  import Badge from '$lib/components/Badge.svelte';
  import Terminal from '$lib/components/Terminal.svelte';
  import {
    apps,
    deploymentsByApp,
    teeState,
    configKeys,
    sampleLogs
  } from '$lib/mocks';
  import { deployStatusBadgeClass, deployStatusLabel } from '$lib/format';

  const name = $derived($page.params.name ?? 'chat-relay');
  const app = $derived(apps.find((a) => a.name === name) ?? apps[0]);
  const deployments = $derived(deploymentsByApp[name] ?? deploymentsByApp['chat-relay']);
</script>

<ScreenChrome
  tabNum="06"
  tabLabel="APP · DEPLOYMENT HISTORY"
  breadcrumb={`~ / apps / ${name}`}
  statusText="RUNNING · TEE ATTESTED · 18:34Z"
>
  <div class="appd">
    <div class="appd-h">
      <h2>{app.name}</h2>
      <span class="dom">{app.domain}</span>
    </div>
    <div class="appd-sub">
      primary container · unlock = {app.unlock_mode} · namespace = {app.namespace} · instance_id = {app.instance_id}
    </div>

    <div class="ribbon">
      <div class="cell">
        <div class="k">STATUS</div>
        <div class="v">
          <Badge variant="healthy" small>RUNNING</Badge>
        </div>
      </div>
      <div class="cell">
        <div class="k">CURRENT IMAGE</div>
        <div class="v mono">{app.current_image_digest}</div>
      </div>
      <div class="cell">
        <div class="k">COSIGN</div>
        <div class="v ok">{app.cosign_verified ? '✓ verified' : '✗ unverified'}</div>
      </div>
      <div class="cell">
        <div class="k">SIGNER ID</div>
        <div class="v mono">{app.signer_subject} · {app.signer_issuer}</div>
      </div>
      <div class="cell">
        <div class="k">CPU / MEM</div>
        <div class="v">{app.cpu_limit} · {app.memory_limit}</div>
      </div>
    </div>

    <div class="appd-grid">
      <div class="appd-main">
        <div class="panel">
          <div class="panel-h">
            <span>DEPLOYMENT HISTORY</span>
            <span class="ln"></span>
            <a href="#">filter ›</a>
          </div>
          <div>
            {#each deployments as d}
              <div class="deploy-row">
                <div class="id">#{d.id}</div>
                <div>
                  <div class="digest">{d.image_digest}</div>
                  <div class="trig">{d.trigger.toUpperCase()} · {d.triggered_by}</div>
                </div>
                <div>
                  <Badge variant={deployStatusBadgeClass(d.status).replace('b-', '') as any}>
                    {deployStatusLabel(d.status)}
                  </Badge>
                </div>
                <div class="time">{d.age}</div>
                <div class="time">{d.started_at.split('T')[1]}</div>
                <div class="chev">›</div>
              </div>
            {/each}
          </div>
        </div>

        <div class="panel">
          <div class="panel-h">
            <span>POD LOGS · LIVE TAIL</span>
            <span class="ln"></span>
            <a href="#">expand ›</a>
          </div>
          <Terminal lines={sampleLogs} />
        </div>
      </div>

      <aside class="side-cards">
        <div class="right-card">
          <div class="h">TEE STATE</div>
          <div class="kv">
            <span class="k">platform</span><span class="v">{teeState.platform}</span>
          </div>
          <div class="kv">
            <span class="k">measurement</span><span class="v mono">{teeState.measurement}</span>
          </div>
          <div class="kv">
            <span class="k">policy</span><span class="v">{teeState.policy}</span>
          </div>
          <div class="kv">
            <span class="k">last attest</span><span class="v ok">{teeState.last_attest}</span>
          </div>
          <div class="kv">
            <span class="k">KBS</span>
            <span class="v" class:ok={teeState.kbs_reachable}>
              {teeState.kbs_reachable ? 'reachable' : 'unreachable'}
            </span>
          </div>
        </div>
        <div class="right-card">
          <div class="h">DESCRIPTOR</div>
          <div class="kv">
            <span class="k">signed by</span><span class="v mono">{deployments[0].signer_fp}</span>
          </div>
          <div class="kv">
            <span class="k">keyring</span><span class="v">v3 · owner</span>
          </div>
          <div class="kv">
            <span class="k">descriptor id</span><span class="v mono">{deployments[0].descriptor_id}</span>
          </div>
          <div class="kv">
            <span class="k">manifest hash</span><span class="v mono">{deployments[0].manifest_hash}</span>
          </div>
        </div>
        <div class="right-card">
          <div class="h">CONFIG KEYS</div>
          {#each configKeys as c}
            <div class="kv">
              <span class="k">{c.name}</span>
              <span class="v">{c.sealed ? 'sealed' : 'plaintext'}</span>
            </div>
          {/each}
        </div>
      </aside>
    </div>
  </div>
</ScreenChrome>

<style>
  .appd {
    padding: 32px;
  }
  .appd-h {
    display: flex;
    align-items: baseline;
    gap: 16px;
    margin-bottom: 4px;
  }
  .appd-h h2 {
    margin: 0;
    font-weight: 500;
    font-size: 24px;
  }
  .appd-h .dom {
    color: var(--magenta);
    font-size: 13px;
  }
  .appd-sub {
    color: var(--dim);
    margin-bottom: 24px;
    font-size: 13px;
  }
  .appd-grid {
    display: grid;
    grid-template-columns: 1fr 320px;
    gap: 28px;
  }
  .appd-main {
    display: grid;
    gap: 22px;
  }
  .ribbon {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    border: 1px solid var(--line);
    margin-bottom: 24px;
  }
  :root[data-theme='light'] .ribbon {
    background: var(--bg);
  }
  .ribbon .cell {
    padding: 14px 16px;
    border-right: 1px dashed var(--line);
  }
  .ribbon .cell:last-child {
    border-right: 0;
  }
  .ribbon .k {
    font-size: 11px;
    color: var(--dim);
    letter-spacing: 0.14em;
  }
  .ribbon .v {
    font-size: 14px;
    color: var(--ink);
    margin-top: 6px;
  }
  .ribbon .v.mono {
    color: var(--magenta);
    font-size: 12px;
  }
  .ribbon .v.ok {
    color: var(--phos);
  }
  .panel {
    border: 1px solid var(--line);
  }
  :root[data-theme='light'] .panel {
    background: var(--bg);
  }
  .panel-h {
    padding: 12px 16px;
    border-bottom: 1px dashed var(--line);
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 12px;
    color: var(--dim);
    letter-spacing: 0.12em;
    background: var(--elevation);
  }
  .panel-h .ln {
    flex: 1;
    border-top: 1px dashed var(--line);
    margin: 0 6px;
  }
  .panel-h a {
    font-size: 12px;
  }
  .deploy-row {
    display: grid;
    grid-template-columns: 100px 1fr 130px 110px 110px 24px;
    gap: 12px;
    align-items: center;
    padding: 12px 16px;
    border-bottom: 1px dashed var(--line);
    font-size: 13px;
  }
  .deploy-row:last-child {
    border-bottom: 0;
  }
  .deploy-row:hover {
    background: var(--phos-soft);
  }
  .deploy-row .id {
    color: var(--dim);
  }
  .deploy-row .digest {
    color: var(--magenta);
    font-size: 12px;
  }
  .deploy-row .trig {
    color: var(--dim);
    font-size: 12px;
    letter-spacing: 0.1em;
  }
  .deploy-row .time {
    color: var(--dim);
    font-size: 12px;
  }
  .deploy-row .chev {
    color: var(--dimmer);
    text-align: right;
  }
  .side-cards {
    display: grid;
    gap: 18px;
    align-content: start;
  }
  .right-card {
    padding: 18px;
    border: 1px solid var(--line);
  }
  :root[data-theme='light'] .right-card {
    background: var(--bg);
  }
  .right-card .h {
    font-size: 11px;
    color: var(--dim);
    letter-spacing: 0.14em;
    margin-bottom: 14px;
  }
  .kv {
    display: flex;
    justify-content: space-between;
    padding: 7px 0;
    border-bottom: 1px dashed var(--line);
    font-size: 13px;
  }
  .kv:last-child {
    border-bottom: 0;
  }
  .kv .k {
    color: var(--dim);
  }
  .kv .v {
    color: var(--ink);
  }
  .kv .v.ok {
    color: var(--phos);
  }
  .kv .v.mono {
    color: var(--magenta);
    font-size: 12px;
  }
</style>
