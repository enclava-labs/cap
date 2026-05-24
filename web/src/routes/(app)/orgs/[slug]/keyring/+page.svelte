<script lang="ts">
  import { page } from '$app/stores';
  import ScreenChrome from '$lib/components/ScreenChrome.svelte';
  import { keyring, activeOrg } from '$lib/mocks';

  const slug = $derived($page.params.slug ?? activeOrg.name);
  const avatarVariant = ['', 'alt2', 'alt3'];
</script>

<ScreenChrome
  tabNum="04"
  tabLabel="ORG · KEYRING"
  breadcrumb={`orgs / ${slug} / keyring`}
  statusText="signature verified · ed25519"
>
  <div class="orgpg">
    <div class="orgpg-h">
      <h1>{slug.split('-')[0]}-<span class="accent">{slug.split('-').slice(1).join('-')}</span></h1>
      {#if activeOrg.is_personal}
        <span class="bp">PERSONAL</span>
      {/if}
      <span class="id">org_7af3-de91-2c11-04e2</span>
    </div>
    <div class="orgpg-cb">organisations / {slug} / keyring</div>

    <div class="tabbar">
      <a href="/dashboard">Overview</a>
      <a class="act" href={`/orgs/${slug}/keyring`}>Keyring</a>
      <a href={`/orgs/${slug}/members`}>Members</a>
      <a href={`/orgs/${slug}/billing`}>Billing</a>
      <a href="/audit">Audit log</a>
    </div>

    <div class="kring-card">
      <div class="kring-h">
        <div class="ver-wrap">
          <div class="v"><span class="accent">v{keyring.version}</span></div>
          <div class="vs">CURRENT · {keyring.signed_at}</div>
        </div>
        <div></div>
        <div>
          <div class="k">SIGNED BY</div>
          <div class="vbig">{keyring.signed_by_fp}</div>
        </div>
        <div>
          <div class="k">VERIFY</div>
          <div class="vbig ok">{keyring.verified ? '✓ ed25519 OK' : '✗ INVALID'}</div>
        </div>
      </div>

      <div class="members">
        {#each keyring.members as m, i}
          <div class="member-row">
            <div class="av {avatarVariant[i] ?? ''}">{m.display_name[0].toUpperCase()}</div>
            <div>
              <div class="nm">{m.display_name}</div>
              <div class="sub">{m.email_or_npub}</div>
              <div class="fp">{m.fingerprint}</div>
            </div>
            <div class="role" class:owner={m.role === 'Owner'} class:member={m.role === 'Member'}>
              {m.role.toUpperCase()}
            </div>
            <div class="added">{m.added_at}</div>
            <div class="more">
              {#if m.is_self}
                — self —
              {:else if m.role === 'Member'}
                <a href="#">remove →</a>
              {:else}
                <a href="#">rotate →</a>
              {/if}
            </div>
          </div>
        {/each}
      </div>

      <div class="raw-block">
        <div class="h">› RAW KEYRING ARTIFACT · enclava-keyring/v1</div>
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
  .orgpg {
    padding: 40px 44px 48px;
  }
  .orgpg-h {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 6px;
  }
  .orgpg-h h1 {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 34px;
    letter-spacing: -0.025em;
    margin: 0;
  }
  .orgpg-h h1 .accent {
    color: var(--primary);
  }
  .orgpg-h .id {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--muted-fg);
  }
  .orgpg-h .bp {
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--primary);
    border: 1px solid var(--primary);
    padding: 3px 9px;
    border-radius: 999px;
    letter-spacing: 0.1em;
    background: var(--primary-soft);
    text-transform: uppercase;
  }
  .orgpg-cb {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--dim);
    margin-bottom: 22px;
  }

  .tabbar {
    display: flex;
    gap: 4px;
    padding: 4px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    margin-bottom: 28px;
    background: var(--inset);
    width: fit-content;
  }
  .tabbar a {
    padding: 8px 16px;
    font-size: 13.5px;
    color: var(--muted-fg);
    border-radius: var(--radius);
    font-weight: 500;
  }
  .tabbar a.act {
    background: var(--primary-soft);
    color: var(--primary);
  }
  .tabbar a:hover:not(.act) {
    color: var(--fg);
  }

  .kring-card {
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
    background: var(--card);
  }
  .kring-h {
    display: grid;
    grid-template-columns: auto 1fr auto auto;
    gap: 28px;
    align-items: center;
    padding: 22px 26px;
    border-bottom: 1px solid var(--hair);
    background: var(--inset);
  }
  .ver-wrap {
    display: flex;
    align-items: baseline;
    gap: 12px;
  }
  .ver-wrap .v {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 38px;
    letter-spacing: -0.03em;
  }
  .ver-wrap .v .accent {
    color: var(--primary);
  }
  .ver-wrap .vs {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--muted-fg);
  }
  .kring-h .k {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--muted-fg);
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }
  .kring-h .vbig {
    font-family: var(--font-mono);
    font-size: 13px;
    color: var(--fg);
    margin-top: 4px;
  }
  .kring-h .vbig.ok {
    color: var(--secondary);
  }

  .member-row {
    display: grid;
    grid-template-columns: 50px 1fr 140px 120px 120px;
    gap: 16px;
    align-items: center;
    padding: 18px 26px;
    border-bottom: 1px solid var(--hair);
  }
  .member-row:last-child {
    border-bottom: 0;
  }
  .member-row:hover {
    background: hsla(190, 90%, 45%, 0.04);
  }
  .member-row .av {
    width: 40px;
    height: 40px;
    border-radius: var(--radius);
    background: linear-gradient(135deg, var(--primary), var(--secondary));
    color: var(--primary-fg);
    font-weight: 700;
    font-size: 15px;
    display: grid;
    place-items: center;
  }
  .member-row .av.alt2 {
    background: linear-gradient(135deg, var(--violet), var(--primary));
  }
  .member-row .av.alt3 {
    background: linear-gradient(135deg, var(--amber), var(--secondary));
  }
  .member-row .nm {
    font-size: 15px;
    font-weight: 600;
  }
  .member-row .sub {
    font-size: 12px;
    color: var(--muted-fg);
    margin-top: 2px;
  }
  .member-row .fp {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--fg-2);
    margin-top: 3px;
  }
  .member-row .role {
    font-family: var(--font-mono);
    font-size: 11px;
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }
  .member-row .role.owner {
    color: var(--primary);
  }
  .member-row .role.member {
    color: var(--muted-fg);
  }
  .member-row .added {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--muted-fg);
  }
  .member-row .more {
    text-align: right;
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--muted-fg);
  }
  .member-row .more a {
    color: var(--muted-fg);
  }
  .member-row .more a:hover {
    color: var(--primary);
  }

  .raw-block {
    padding: 20px 26px;
    border-top: 1px solid var(--hair);
    background: var(--inset);
  }
  .raw-block .h {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--muted-fg);
    margin-bottom: 12px;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }
  .raw-block pre {
    font-family: var(--font-mono);
    font-size: 12.5px;
    line-height: 1.7;
    color: var(--fg-2);
    overflow: auto;
  }
</style>
