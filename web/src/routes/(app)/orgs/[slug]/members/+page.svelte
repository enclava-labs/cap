<script lang="ts">
  import { page } from '$app/stores';
  import ScreenChrome from '$lib/components/ScreenChrome.svelte';
  import { keyring, activeOrg } from '$lib/mocks';

  const slug = $derived($page.params.slug ?? activeOrg.name);
  const avatarVariant = ['', 'alt2', 'alt3'];
</script>

<ScreenChrome
  tabNum="09"
  tabLabel="ORG · MEMBERS"
  breadcrumb={`orgs / ${slug} / members`}
  statusText={`${keyring.members.length} members · ${activeOrg.tier.toLowerCase()} tier`}
>
  <div class="page">
    <div class="page-h">
      <div>
        <div class="eyebrow">ACCESS</div>
        <h1>{slug.split('-')[0]}-<span class="accent">{slug.split('-').slice(1).join('-')}</span></h1>
        <div class="crumbs">organisations / {slug} / members</div>
      </div>
      <button class="btn primary">+ Invite member</button>
    </div>

    <div class="tabbar">
      <a href="/dashboard">Overview</a>
      <a href={`/orgs/${slug}/keyring`}>Keyring</a>
      <a class="act" href={`/orgs/${slug}/members`}>Members</a>
      <a href={`/orgs/${slug}/billing`}>Billing</a>
      <a href="/audit">Audit log</a>
    </div>

    <div class="card">
      <div class="card-h">
        <div>
          <div class="t">Members</div>
          <div class="sub">
            Org-level membership. Owners can manage the keyring and billing.
            Members can read and deploy.
          </div>
        </div>
      </div>

      {#each keyring.members as m, i}
        <div class="member-row">
          <div class="av {avatarVariant[i] ?? ''}">{m.display_name[0].toUpperCase()}</div>
          <div class="info">
            <div class="nm">{m.display_name}</div>
            <div class="sub">{m.email_or_npub}</div>
          </div>
          <div class="col">
            <div class="k">ROLE</div>
            <div class="role" class:owner={m.role === 'Owner'} class:member={m.role === 'Member'}>
              {m.role}
            </div>
          </div>
          <div class="col">
            <div class="k">PUBKEY</div>
            <div class="fp">{m.fingerprint}</div>
          </div>
          <div class="col">
            <div class="k">JOINED</div>
            <div class="dim">{m.added_at}</div>
          </div>
          <div class="col actions">
            {#if m.is_self}
              <span class="self">— you —</span>
            {:else}
              <button class="link">Change role</button>
              <button class="link danger">Remove</button>
            {/if}
          </div>
        </div>
      {/each}
    </div>

    <div class="note">
      <div class="ico">ⓘ</div>
      <div>
        Adding members updates the org <a href={`/orgs/${slug}/keyring`}>keyring</a>. The new
        keyring revision is signed locally by an existing owner before being published — the
        platform never holds signing authority.
      </div>
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
    margin-bottom: 22px;
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

  .card {
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--card);
    overflow: hidden;
  }
  .card-h {
    padding: 20px 24px;
    border-bottom: 1px solid var(--hair);
    background: var(--inset);
  }
  .card-h .t {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 16px;
  }
  .card-h .sub {
    font-size: 13px;
    color: var(--muted-fg);
    margin-top: 4px;
  }

  .member-row {
    display: grid;
    grid-template-columns: 48px minmax(180px, 1fr) 110px 200px 110px 160px;
    gap: 18px;
    align-items: center;
    padding: 18px 24px;
    border-bottom: 1px solid var(--hair);
  }
  .member-row:last-child {
    border-bottom: 0;
  }
  .av {
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
  .av.alt2 {
    background: linear-gradient(135deg, var(--violet), var(--primary));
  }
  .av.alt3 {
    background: linear-gradient(135deg, var(--amber), var(--secondary));
  }
  .info .nm {
    font-size: 15px;
    font-weight: 600;
  }
  .info .sub {
    font-size: 12px;
    color: var(--muted-fg);
    margin-top: 2px;
  }
  .col .k {
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--dim);
    letter-spacing: 0.06em;
    text-transform: uppercase;
    margin-bottom: 4px;
  }
  .role {
    font-family: var(--font-mono);
    font-size: 12px;
  }
  .role.owner {
    color: var(--primary);
  }
  .role.member {
    color: var(--muted-fg);
  }
  .fp {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--fg-2);
  }
  .dim {
    color: var(--muted-fg);
    font-family: var(--font-mono);
    font-size: 12.5px;
  }
  .actions {
    display: flex;
    gap: 12px;
    align-items: center;
    justify-content: flex-end;
  }
  .self {
    color: var(--muted-fg);
    font-family: var(--font-mono);
    font-size: 12px;
  }
  .link {
    background: transparent;
    border: 0;
    color: var(--muted-fg);
    font: inherit;
    font-family: var(--font-mono);
    font-size: 12px;
    cursor: pointer;
    padding: 0;
  }
  .link:hover {
    color: var(--primary);
  }
  .link.danger:hover {
    color: var(--red);
  }

  .note {
    display: grid;
    grid-template-columns: 20px 1fr;
    gap: 10px;
    margin-top: 18px;
    padding: 14px 18px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--inset);
    font-size: 13px;
    color: var(--muted-fg);
  }
  .note .ico {
    color: var(--primary);
  }
  .note a {
    color: var(--primary);
  }
</style>
