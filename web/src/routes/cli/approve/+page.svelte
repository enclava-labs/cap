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

  const avatarVariant = ['', 'alt2', 'alt3'];
</script>

<ScreenChrome
  tabNum="03"
  tabLabel="CLI DEVICE APPROVAL"
  breadcrumb="app.enclava.dev/cli/approve?code=ABCD-EFGH"
  statusDot="amber"
  statusText="pending · 09:42 left"
>
  <div class="approve-wrap">
    <div class="approve-l">
      <div class="inner">
        <div class="eyebrow">AUTHORISE TERMINAL</div>
        <h1>Confirm the code your <span class="accent">CLI</span> is showing.</h1>
        <div class="code-display">
          <div class="lab">CLI VERIFICATION CODE</div>
          <div class="code">{deviceLogin.code.replace('-', ' — ')}</div>
        </div>
        <p>
          You ran <code>enclava login</code> in a terminal. The four-letter pairs above must match
          your CLI exactly. Then choose which organisation this session may act on.
        </p>
        <div class="meta-list">
          <div class="row"><div class="k">CLIENT</div><div class="v">{deviceLogin.client}</div></div>
          <div class="row"><div class="k">SOURCE</div><div class="v">{deviceLogin.source}</div></div>
          <div class="row"><div class="k">SCOPES</div><div class="v">{deviceLogin.scopes}</div></div>
          <div class="row">
            <div class="k">EXPIRES</div>
            <div class="v amber">{deviceLogin.expires_in}</div>
          </div>
        </div>
      </div>
    </div>

    <div class="approve-r">
      <div class="eyebrow muted">SELECT ORG</div>
      <h3>Choose an organisation</h3>
      <div class="h-sub">This session will only access the org you choose.</div>
      {#each orgs as o, i}
        <button
          type="button"
          class="org-card"
          class:sel={selected === o.id}
          onclick={() => (selected = o.id)}
        >
          <div class="av {avatarVariant[i] ?? ''}">{o.name[0].toUpperCase()}</div>
          <div>
            <div class="nm">{o.name}</div>
            <div class="sub">
              {o.is_personal ? 'personal' : 'team'} · {o.role.toLowerCase()} · {o.tier.toLowerCase()}
            </div>
          </div>
          <div class="ch" class:un={selected !== o.id}>{selected === o.id ? '✓' : '○'}</div>
        </button>
      {/each}
      <div class="approve-actions">
        <button class="btn primary" onclick={approve}>Authorise CLI →</button>
        <button class="btn danger" onclick={deny}>Deny</button>
      </div>
      <div class="ttl">
        If you didn't start this login, <b>deny</b> and rotate your session token.
      </div>
    </div>
  </div>
</ScreenChrome>

<style>
  .approve-wrap {
    display: grid;
    grid-template-columns: 1.1fr 1fr;
    min-height: 600px;
  }
  .approve-l {
    padding: 64px 56px;
    border-right: 1px solid var(--hair);
    position: relative;
    overflow: hidden;
  }
  .approve-l::before {
    content: '';
    position: absolute;
    top: -40%;
    left: 50%;
    width: 700px;
    height: 700px;
    background: radial-gradient(circle, var(--primary-soft), transparent 60%);
    transform: translate(-50%, 0);
    pointer-events: none;
  }
  .approve-l .inner {
    position: relative;
  }
  .approve-l h1 {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 40px;
    line-height: 1.1;
    letter-spacing: -0.025em;
    margin: 12px 0 18px;
  }
  .approve-l h1 .accent {
    color: var(--primary);
  }
  .approve-l p {
    color: var(--muted-fg);
    max-width: 50ch;
    font-size: 15px;
  }
  .approve-l p code {
    font-family: var(--font-mono);
    font-size: 13px;
    background: var(--primary-soft);
    color: var(--primary);
    padding: 2px 8px;
    border-radius: 4px;
  }
  .code-display {
    margin: 28px 0 30px;
    padding: 28px 36px;
    border: 1px solid var(--primary);
    border-radius: var(--radius-lg);
    background: var(--primary-soft);
    display: inline-block;
    box-shadow:
      0 10px 40px -20px var(--primary-glow),
      inset 0 1px 0 hsla(0, 0%, 100%, 0.06);
  }
  .code-display .lab {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--primary);
    letter-spacing: 0.14em;
    margin-bottom: 8px;
    text-transform: uppercase;
  }
  .code-display .code {
    font-family: var(--font-mono);
    font-weight: 500;
    font-size: 52px;
    letter-spacing: 0.14em;
    color: var(--fg);
    line-height: 1;
  }
  .meta-list {
    margin-top: 32px;
  }
  .meta-list .row {
    display: grid;
    grid-template-columns: 150px 1fr;
    gap: 14px;
    padding: 12px 0;
    border-bottom: 1px solid var(--hair);
    font-size: 14px;
  }
  .meta-list .row:last-child {
    border-bottom: 0;
  }
  .meta-list .k {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--muted-fg);
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }
  .meta-list .v {
    font-family: var(--font-mono);
    font-size: 13px;
    color: var(--fg);
  }
  .meta-list .v.amber {
    color: var(--amber);
  }

  .approve-r {
    padding: 64px 56px;
    background: var(--bg-2);
  }
  .approve-r h3 {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 19px;
    margin: 12px 0 4px;
    letter-spacing: -0.01em;
  }
  .h-sub {
    font-size: 13.5px;
    color: var(--muted-fg);
    margin-bottom: 22px;
  }
  .org-card {
    display: grid;
    grid-template-columns: 36px 1fr auto;
    gap: 14px;
    align-items: center;
    width: 100%;
    padding: 16px 18px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--card);
    margin-bottom: 10px;
    cursor: pointer;
    transition: 0.15s;
    text-align: left;
    color: var(--fg);
    font: inherit;
  }
  .org-card:hover {
    border-color: var(--border-2);
  }
  .org-card.sel {
    border-color: var(--primary);
    background: var(--primary-soft);
    box-shadow: 0 6px 20px -10px var(--primary-glow);
  }
  .org-card .av {
    width: 32px;
    height: 32px;
    border-radius: var(--radius);
    background: linear-gradient(135deg, var(--primary), var(--secondary));
    color: var(--primary-fg);
    display: grid;
    place-items: center;
    font-weight: 700;
    font-size: 12px;
  }
  .org-card .av.alt2 {
    background: linear-gradient(135deg, var(--violet), var(--primary));
  }
  .org-card .av.alt3 {
    background: linear-gradient(135deg, var(--amber), var(--secondary));
  }
  .org-card .nm {
    font-size: 15px;
    font-weight: 600;
    line-height: 1.2;
  }
  .org-card .sub {
    font-size: 12px;
    color: var(--muted-fg);
    font-family: var(--font-mono);
    margin-top: 2px;
  }
  .org-card .ch {
    color: var(--primary);
    font-size: 18px;
  }
  .org-card .ch.un {
    color: var(--dim);
  }
  .approve-actions {
    display: flex;
    gap: 10px;
    margin-top: 24px;
  }
  .ttl {
    margin-top: 22px;
    font-size: 12.5px;
    color: var(--muted-fg);
    font-family: var(--font-mono);
  }
  .ttl b {
    color: var(--amber);
    font-weight: 500;
  }
</style>
