<script lang="ts">
  import ScreenChrome from '$lib/components/ScreenChrome.svelte';
  import { orgs, deviceLogin } from '$lib/mocks';
  import { goto } from '$app/navigation';

  let selected = $state(orgs[0].id);

  function approve() {
    console.log('Mock approve for org', selected);
    goto('/dashboard');
  }
  function deny() {
    console.log('Mock deny');
    goto('/login');
  }
</script>

<ScreenChrome
  tabNum="03"
  tabLabel="CLI · DEVICE APPROVAL"
  breadcrumb="app.enclava.dev/cli/approve?code=ABCD-EFGH"
  statusDot="amber"
  statusText="PENDING · 09:42 LEFT"
>
  <div class="approve">
    <div class="approve-l">
      <div class="code-tag">CLI VERIFICATION CODE</div>
      <h1 class="code-display">{deviceLogin.code.replace('-', ' – ')}</h1>
      <h2>Authorise enclava-cli @ studio-mbp</h2>
      <p>
        You started <code>enclava login</code> from a terminal. Confirm the code matches what your CLI is
        showing, then pick the org this session should act on.
      </p>
      <div class="meta-grid">
        <div>
          <div class="k">CLIENT</div>
          <div class="v">{deviceLogin.client}</div>
        </div>
        <div>
          <div class="k">REQUESTED FROM</div>
          <div class="v">{deviceLogin.source}</div>
        </div>
        <div>
          <div class="k">SCOPES</div>
          <div class="v">{deviceLogin.scopes}</div>
        </div>
        <div>
          <div class="k">EXPIRES</div>
          <div class="v">{deviceLogin.expires_in}</div>
        </div>
      </div>
      <div class="countdown">
        If you did not start this login, <b>deny</b> immediately and rotate your session token.
      </div>
    </div>

    <div class="approve-r">
      <div class="label">SELECT ORG FOR THIS SESSION</div>
      {#each orgs as o}
        <button
          type="button"
          class="org-row"
          class:sel={selected === o.id}
          onclick={() => (selected = o.id)}
        >
          <div>
            <div class="nm">{o.name}</div>
            <div class="sub">
              {o.is_personal ? 'personal' : 'team'} · {o.role.toLowerCase()} · {o.tier.toLowerCase()}
            </div>
          </div>
          <div class="check">{selected === o.id ? '✓' : ''}</div>
        </button>
      {/each}
      <div class="actions">
        <button class="btn" onclick={approve}>APPROVE ›</button>
        <button class="btn ghost" onclick={deny}>DENY</button>
      </div>
      <div class="countdown" style="margin-top:36px;">
        A session token will be sent to your CLI poll endpoint. Your recovery seed never leaves
        this device.
      </div>
    </div>
  </div>
</ScreenChrome>

<style>
  .approve {
    display: grid;
    grid-template-columns: 1fr 0.9fr;
    min-height: 540px;
  }
  .approve-l {
    padding: 56px 48px;
    border-right: 1px dashed var(--line);
  }
  .approve-r {
    padding: 56px 48px;
    background: var(--elevation);
  }
  .code-tag {
    font-size: 12px;
    color: var(--dim);
    letter-spacing: 0.14em;
    margin-bottom: 10px;
  }
  .code-display {
    font-size: 56px;
    font-weight: 300;
    letter-spacing: 0.1em;
    color: var(--phos);
    margin: 0 0 8px;
  }
  :root[data-theme='dark'] .code-display {
    text-shadow: 0 0 24px rgba(125, 255, 178, 0.35);
  }
  h2 {
    font-weight: 500;
    font-size: 22px;
    margin: 0 0 8px;
  }
  p {
    color: var(--dim);
    max-width: 50ch;
  }
  code {
    color: var(--phos);
    background: var(--phos-soft);
    padding: 1px 6px;
  }
  .meta-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 14px 30px;
    margin-top: 28px;
    font-size: 13px;
  }
  .meta-grid .k {
    color: var(--dim);
    font-size: 11px;
    letter-spacing: 0.14em;
    margin-bottom: 4px;
  }
  .meta-grid .v {
    color: var(--ink);
  }
  .label {
    font-size: 11px;
    color: var(--dim);
    letter-spacing: 0.14em;
    margin-bottom: 14px;
  }
  .org-row {
    display: grid;
    grid-template-columns: 1fr auto;
    align-items: center;
    width: 100%;
    padding: 14px 16px;
    border: 1px solid var(--line);
    margin-bottom: 8px;
    cursor: pointer;
    transition: 0.15s;
    text-align: left;
    background: transparent;
    color: var(--ink);
    font: inherit;
  }
  :root[data-theme='light'] .org-row {
    background: var(--panel);
    border-color: var(--line-2);
  }
  .org-row:hover {
    border-color: var(--phos);
  }
  .org-row.sel {
    border-color: var(--phos);
    background: var(--phos-soft);
  }
  .nm {
    color: var(--ink);
  }
  .sub {
    font-size: 12px;
    color: var(--dim);
  }
  .check {
    color: var(--phos);
  }
  .actions {
    display: flex;
    gap: 10px;
    margin-top: 28px;
  }
  .btn {
    padding: 12px 22px;
    border: 1px solid var(--phos);
    background: var(--phos);
    color: var(--on-phos);
    cursor: pointer;
    font: inherit;
    font-weight: 500;
    letter-spacing: 0.1em;
  }
  .btn:hover {
    background: var(--ink);
    border-color: var(--ink);
    color: var(--on-ink);
  }
  .btn.ghost {
    background: transparent;
    color: var(--ink);
    border-color: var(--line);
    font-weight: 400;
  }
  :root[data-theme='light'] .btn.ghost {
    border-color: var(--line-2);
  }
  .btn.ghost:hover {
    border-color: var(--red);
    color: var(--red);
    background: transparent;
  }
  .countdown {
    color: var(--dim);
    font-size: 12px;
    margin-top: 16px;
    letter-spacing: 0.1em;
  }
  .countdown b {
    color: var(--amber);
    font-weight: 400;
  }
</style>
