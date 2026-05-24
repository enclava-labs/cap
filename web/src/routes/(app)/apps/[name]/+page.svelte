<script lang="ts">
  import { page } from '$app/stores';
  import ScreenChrome from '$lib/components/ScreenChrome.svelte';
  import Badge from '$lib/components/Badge.svelte';
  import Terminal from '$lib/components/Terminal.svelte';
  import { apps, deploymentsByApp, teeState, configKeys, sampleLogs } from '$lib/mocks';
  import { deployStatusBadgeClass, deployStatusLabel } from '$lib/format';

  const name = $derived($page.params.name ?? 'chat-relay');
  const app = $derived(apps.find((a) => a.name === name) ?? apps[0]);
  const deployments = $derived(deploymentsByApp[name] ?? deploymentsByApp['chat-relay']);
</script>

<ScreenChrome
  tabNum="06"
  tabLabel="APP · DEPLOYMENTS"
  breadcrumb={`apps / ${name}`}
  statusText="running · attested 24s ago"
>
  <div class="app-pad">
    <div class="app-h">
      <div>
        <div class="eyebrow">APPLICATION</div>
        <h1>{app.name.split('-')[0]}-<span class="accent">{app.name.split('-').slice(1).join('-')}</span></h1>
      </div>
      <div class="live">
        STATUS<br />
        <span class="v">running &nbsp;·&nbsp; TEE attested</span>
      </div>
    </div>
    <div class="app-cb">
      apps / {app.name} · <span class="dom">{app.domain}</span>
    </div>

    <div class="facts">
      <div class="c">
        <div class="k">Image</div>
        <div class="v mono">{app.current_image_digest}</div>
      </div>
      <div class="c">
        <div class="k">Cosign</div>
        <div class="v ok">{app.cosign_verified ? '✓ verified' : '✗ unverified'}</div>
      </div>
      <div class="c">
        <div class="k">Signer ID</div>
        <div class="v mono">{app.signer_subject}</div>
      </div>
      <div class="c">
        <div class="k">Unlock</div>
        <div class="v">{app.unlock_mode}</div>
      </div>
      <div class="c">
        <div class="k">Resources</div>
        <div class="v">{app.cpu_limit} · {app.memory_limit}</div>
      </div>
      <div class="c">
        <div class="k">Namespace</div>
        <div class="v mono">{app.namespace}</div>
      </div>
    </div>

    <div class="app-grid">
      <div style="display:grid; gap:20px;">
        <div class="panel">
          <div class="panel-h">
            <h2>Deployment history</h2>
            <span class="h-sub"><a href="#">filter →</a></span>
          </div>
          <div>
            {#each deployments as d}
              <div class="dep-row">
                <div class="id">#{d.id}</div>
                <div class="img">
                  <div class="d">
                    {d.image_digest} &nbsp;·&nbsp; cosign {d.cosign_verified ? '✓' : '✗'}
                  </div>
                  <div class="by">{d.trigger.toLowerCase()} · {d.triggered_by}</div>
                </div>
                <div>
                  <Badge variant={deployStatusBadgeClass(d.status).replace('b-', '') as any}>
                    {deployStatusLabel(d.status).toLowerCase()}
                  </Badge>
                </div>
                <div class="age">{d.age}</div>
                <div class="when">{d.started_at.split('T')[1]}</div>
                <div class="chev">›</div>
              </div>
            {/each}
          </div>
        </div>

        <div class="panel">
          <div class="panel-h">
            <h2>Pod logs · live tail</h2>
            <span class="h-sub"><a href="#">expand →</a></span>
          </div>
          <Terminal lines={sampleLogs} />
        </div>
      </div>

      <aside class="side-cards">
        <div class="side-card">
          <h3>TEE STATE</h3>
          <div class="r">
            <span class="k">platform</span><span class="v">{teeState.platform}</span>
          </div>
          <div class="r">
            <span class="k">measurement</span><span class="v">{teeState.measurement}</span>
          </div>
          <div class="r">
            <span class="k">policy</span><span class="v">{teeState.policy}</span>
          </div>
          <div class="r">
            <span class="k">last attest</span><span class="v ok">{teeState.last_attest}</span>
          </div>
          <div class="r">
            <span class="k">KBS</span>
            <span class="v" class:ok={teeState.kbs_reachable}>
              {teeState.kbs_reachable ? 'reachable' : 'unreachable'}
            </span>
          </div>
        </div>
        <div class="side-card">
          <h3>DESCRIPTOR</h3>
          <div class="r">
            <span class="k">signed by</span><span class="v">{deployments[0].signer_fp}</span>
          </div>
          <div class="r"><span class="k">keyring</span><span class="v">v3 · owner</span></div>
          <div class="r">
            <span class="k">desc id</span><span class="v">{deployments[0].descriptor_id}</span>
          </div>
          <div class="r">
            <span class="k">manifest hash</span><span class="v">{deployments[0].manifest_hash}</span>
          </div>
        </div>
        <div class="side-card">
          <h3>SEALED CONFIG</h3>
          {#each configKeys as c}
            <div class="r">
              <span class="k">{c.name}</span>
              <span class="v" class:ok={c.sealed} class:warn={!c.sealed}>
                {c.sealed ? 'sealed' : 'plaintext'}
              </span>
            </div>
          {/each}
        </div>
      </aside>
    </div>
  </div>
</ScreenChrome>

<style>
  .app-pad {
    padding: 40px 44px 52px;
  }
  .app-h {
    display: flex;
    justify-content: space-between;
    align-items: end;
    gap: 32px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--hair);
    margin-bottom: 14px;
  }
  .app-h h1 {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 38px;
    margin: 8px 0 0;
    letter-spacing: -0.025em;
  }
  .app-h h1 .accent {
    color: var(--primary);
  }
  .app-h .live {
    text-align: right;
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--muted-fg);
  }
  .app-h .live .v {
    color: var(--secondary);
    font-size: 14px;
    display: block;
    margin-top: 4px;
  }
  .app-h .live .v::before {
    content: '● ';
  }
  .app-cb {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--muted-fg);
    margin-bottom: 26px;
  }
  .app-cb .dom {
    color: var(--primary);
  }
  .facts {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--card);
    margin-bottom: 32px;
    overflow: hidden;
  }
  .facts .c {
    padding: 16px 18px;
    border-right: 1px solid var(--hair);
  }
  .facts .c:last-child {
    border-right: 0;
  }
  .facts .k {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--muted-fg);
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }
  .facts .v {
    font-size: 14px;
    margin-top: 6px;
  }
  .facts .v.mono {
    font-family: var(--font-mono);
    font-size: 12.5px;
  }
  .facts .v.ok {
    color: var(--secondary);
  }
  .app-grid {
    display: grid;
    grid-template-columns: 1fr 320px;
    gap: 28px;
  }
  .panel {
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
    background: var(--card);
  }
  .panel-h {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    padding: 14px 22px;
    border-bottom: 1px solid var(--hair);
    background: var(--inset);
  }
  .panel-h h2 {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 15px;
    margin: 0;
  }
  .panel-h .h-sub {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--muted-fg);
  }
  .panel-h .h-sub a {
    color: var(--muted-fg);
  }
  .panel-h .h-sub a:hover {
    color: var(--primary);
  }

  .dep-row {
    display: grid;
    grid-template-columns: 110px 1fr 130px 110px 100px 22px;
    gap: 14px;
    align-items: center;
    padding: 14px 22px;
    border-bottom: 1px solid var(--hair);
    font-size: 13.5px;
  }
  .dep-row:last-child {
    border-bottom: 0;
  }
  .dep-row:hover {
    background: hsla(190, 90%, 45%, 0.04);
  }
  .dep-row .id {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--muted-fg);
  }
  .dep-row .img .d {
    font-family: var(--font-mono);
    font-size: 12.5px;
    color: var(--fg);
  }
  .dep-row .img .by {
    font-size: 11.5px;
    color: var(--muted-fg);
    margin-top: 2px;
  }
  .dep-row .when {
    font-family: var(--font-mono);
    font-size: 11.5px;
    color: var(--muted-fg);
  }
  .dep-row .age {
    font-size: 12.5px;
    color: var(--fg-2);
  }
  .dep-row .chev {
    color: var(--dim);
    text-align: right;
  }

  .side-cards {
    display: grid;
    gap: 16px;
    align-content: start;
  }
  .side-card {
    padding: 20px;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--card);
  }
  .side-card h3 {
    font-family: var(--font-mono);
    font-weight: 500;
    font-size: 11px;
    color: var(--muted-fg);
    margin: 0 0 14px;
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }
  .side-card .r {
    display: flex;
    justify-content: space-between;
    padding: 8px 0;
    border-bottom: 1px solid var(--hair);
    font-size: 13px;
  }
  .side-card .r:last-child {
    border-bottom: 0;
  }
  .side-card .k {
    color: var(--muted-fg);
    font-family: var(--font-mono);
    font-size: 11.5px;
  }
  .side-card .v {
    font-family: var(--font-mono);
    font-size: 12.5px;
    color: var(--fg);
  }
  .side-card .v.ok {
    color: var(--secondary);
  }
  .side-card .v.warn {
    color: var(--amber);
  }
</style>
