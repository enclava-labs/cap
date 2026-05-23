<script lang="ts">
  import { page } from '$app/stores';
  import ScreenChrome from '$lib/components/ScreenChrome.svelte';
  import { keyring, activeOrg } from '$lib/mocks';

  const slug = $derived($page.params.slug);
</script>

<ScreenChrome
  tabNum="04"
  tabLabel="ORG · KEYRING"
  breadcrumb={`~ / orgs / ${slug} / keyring`}
  statusText="SIGNATURE VERIFIED"
>
  <div class="org-page">
    <div class="org-head">
      <h2>{slug}</h2>
      {#if activeOrg.is_personal}
        <span class="pers">PERSONAL</span>
      {/if}
      <span class="id">id · 7af3-de91-2c11-04e2</span>
    </div>
    <div class="tabs">
      <a href="/dashboard">Overview</a>
      <a class="act" href={`/orgs/${slug}/keyring`}>Keyring</a>
      <a href={`/orgs/${slug}/members`}>Members</a>
      <a href={`/orgs/${slug}/billing`}>Billing</a>
      <a href="/audit">Audit log</a>
    </div>

    <div class="keyring-card">
      <div class="top">
        <div>
          <div class="ver">v{keyring.version}</div>
          <div class="vsub">CURRENT KEYRING · UPDATED {keyring.signed_at}</div>
        </div>
        <div>
          <div class="vsub">SIGNED BY OWNER</div>
          <div class="sig" style="margin-top:6px;">{keyring.signed_by_fp}</div>
        </div>
        <div>
          <div class="vsub">VERIFY</div>
          <div class="verify" style="margin-top:6px;">{keyring.verified ? '✓ ED25519 OK' : '✗ INVALID'}</div>
        </div>
      </div>
      <div class="members">
        {#each keyring.members as m}
          <div class="member">
            <div class="avatar">{m.display_name[0].toUpperCase()}</div>
            <div>
              <div class="name">{m.display_name}</div>
              <div class="fp">npub · {m.fingerprint}</div>
            </div>
            <div class="role" class:member={m.role === 'Member'}>{m.role.toUpperCase()}</div>
            <div class="added">{m.added_at}</div>
            <div class="actions-cell">
              {#if m.is_self}
                — self —
              {:else if m.role === 'Member'}
                <a href="#">remove ›</a>
              {:else}
                <a href="#">rotate ›</a>
              {/if}
            </div>
          </div>
        {/each}
      </div>
      <div class="raw">
        <div class="lbl">RAW KEYRING ARTIFACT · ENCLAVA-KEYRING/V1</div>
<pre>{`{
  "version": ${keyring.version},
  "org_id": "${keyring.org_id}",
  "members": [
${keyring.members.map((m) => `    { "role": "${m.role.toLowerCase()}", "pubkey": "${m.fingerprint}" }`).join(',\n')}
  ],
  "signature": "${keyring.signature}",
  "signed_at": "${keyring.signed_at}"
}`}</pre>
      </div>
    </div>
  </div>
</ScreenChrome>

<style>
  .org-page {
    padding: 32px;
  }
  .org-head {
    display: flex;
    align-items: baseline;
    gap: 16px;
    margin-bottom: 6px;
  }
  .org-head h2 {
    margin: 0;
    font-weight: 500;
    font-size: 24px;
  }
  .org-head .id {
    color: var(--dim);
    font-size: 12px;
  }
  .org-head .pers {
    color: var(--phos);
    font-size: 11px;
    letter-spacing: 0.14em;
    border: 1px solid var(--phos-dim);
    padding: 2px 8px;
  }
  :root[data-theme='light'] .org-head .pers {
    background: var(--phos-soft);
  }
  .tabs {
    display: flex;
    border-bottom: 1px solid var(--line);
    margin: 22px 0 28px;
  }
  .tabs a {
    color: var(--dim);
    padding: 10px 0;
    margin-right: 28px;
    border: 0;
    font-size: 13px;
    letter-spacing: 0.1em;
  }
  .tabs a.act {
    color: var(--phos);
    border-bottom: 1px solid var(--phos);
  }
  .keyring-card {
    border: 1px solid var(--line);
  }
  :root[data-theme='light'] .keyring-card {
    background: var(--bg);
  }
  .top {
    display: grid;
    grid-template-columns: 1fr auto auto;
    gap: 20px;
    align-items: center;
    padding: 16px 20px;
    border-bottom: 1px dashed var(--line);
    background: var(--elevation);
  }
  .ver {
    font-size: 28px;
    color: var(--ink);
    font-weight: 300;
  }
  .vsub {
    color: var(--dim);
    font-size: 12px;
    letter-spacing: 0.12em;
  }
  .sig {
    font-size: 12px;
    color: var(--phos);
  }
  .verify {
    font-size: 11px;
    letter-spacing: 0.14em;
    color: var(--phos);
  }
  .members {
    padding: 6px 0;
  }
  .member {
    display: grid;
    grid-template-columns: 38px 1fr 110px 90px 110px;
    gap: 14px;
    align-items: center;
    padding: 14px 20px;
    border-bottom: 1px dashed var(--line);
  }
  .member:last-child {
    border-bottom: 0;
  }
  .avatar {
    width: 36px;
    height: 36px;
    border: 1px solid var(--line);
    display: grid;
    place-items: center;
    color: var(--phos);
    font-size: 12px;
    background: var(--phos-soft);
  }
  .member .name {
    color: var(--ink);
  }
  .member .fp {
    color: var(--magenta);
    font-size: 12px;
  }
  .member .role {
    font-size: 11px;
    letter-spacing: 0.14em;
    color: var(--amber);
  }
  .member .role.member {
    color: var(--dim);
  }
  .member .added {
    font-size: 12px;
    color: var(--dim);
  }
  .member .actions-cell {
    text-align: right;
    font-size: 12px;
    color: var(--dim);
  }
  .raw {
    padding: 16px 20px;
    background: var(--bg);
    border-top: 1px dashed var(--line);
  }
  :root[data-theme='light'] .raw {
    background: var(--bg-2);
  }
  .raw .lbl {
    font-size: 11px;
    color: var(--dim);
    letter-spacing: 0.14em;
    margin-bottom: 10px;
  }
  .raw pre {
    margin: 0;
    color: var(--ink-2);
    font-size: 12px;
    line-height: 1.7;
    overflow: auto;
  }
</style>
