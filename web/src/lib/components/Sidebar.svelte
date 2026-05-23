<script lang="ts">
  import { page } from '$app/stores';
  import { activeOrg } from '$lib/mocks';

  type Item = { href: string; label: string; kbd: string; icon?: string };

  const workspace: Item[] = [
    { href: '/dashboard', label: 'Overview', kbd: 'G O', icon: '▸' },
    { href: '/apps', label: 'Apps', kbd: 'G A', icon: '▸' },
    { href: '/deployments', label: 'Deployments', kbd: 'G D', icon: '▸' },
    { href: `/orgs/${activeOrg.name}/keyring`, label: 'Keyring', kbd: 'G K', icon: '▸' },
    { href: `/orgs/${activeOrg.name}/members`, label: 'Members', kbd: 'G M', icon: '▸' }
  ];
  const account: Item[] = [
    { href: `/orgs/${activeOrg.name}/billing`, label: 'Billing', kbd: 'G B', icon: '▸' },
    { href: '/recovery', label: 'Recovery', kbd: 'G R', icon: '▸' },
    { href: '/audit', label: 'Audit log', kbd: 'G L', icon: '▸' }
  ];

  function isActive(href: string): boolean {
    return $page.url.pathname === href || $page.url.pathname.startsWith(href + '/');
  }
</script>

<aside class="side">
  <div class="brand">
    <div class="bglyph">▣ ENCLAVA</div>
    <div class="bsub">CAP</div>
  </div>
  <div class="group">
    <div class="gh">WORKSPACE</div>
    <nav class="nav">
      {#each workspace as item}
        <a href={item.href} class:active={isActive(item.href)}>
          <span>{item.icon}</span>
          <span>{item.label}</span>
          <span class="kbd">{item.kbd}</span>
        </a>
      {/each}
    </nav>
  </div>
  <div class="group">
    <div class="gh">ACCOUNT</div>
    <nav class="nav">
      {#each account as item}
        <a href={item.href} class:active={isActive(item.href)}>
          <span>{item.icon}</span>
          <span>{item.label}</span>
          <span class="kbd">{item.kbd}</span>
        </a>
      {/each}
    </nav>
  </div>
  <div class="org-pill">
    <div class="top">
      <span>ACTIVE ORG</span><span class="tier">{activeOrg.tier.toUpperCase()}</span>
    </div>
    <div class="name">{activeOrg.name}</div>
    <div class="top">
      <span>{activeOrg.is_personal ? 'PERSONAL' : 'TEAM'} · {activeOrg.role.toUpperCase()}</span>
    </div>
  </div>
</aside>

<style>
  .side {
    border-right: 1px solid var(--line);
    padding: 18px 14px;
    min-height: 720px;
    background: var(--elevation);
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 28px;
    padding: 4px 6px;
  }
  .bglyph {
    color: var(--phos);
    font-weight: 700;
    letter-spacing: 0.05em;
  }
  .bsub {
    font-size: 11px;
    color: var(--dim);
    letter-spacing: 0.14em;
  }
  .group {
    margin-bottom: 18px;
  }
  .gh {
    font-size: 11px;
    color: var(--dimmer);
    letter-spacing: 0.14em;
    padding: 6px;
  }
  .nav {
    display: grid;
  }
  .nav a {
    display: grid;
    grid-template-columns: 16px 1fr auto;
    gap: 8px;
    align-items: center;
    padding: 7px 8px;
    border: 0;
    color: var(--ink-2);
    font-size: 13px;
  }
  .nav a:hover {
    background: var(--phos-soft);
    color: var(--phos);
  }
  .nav a.active {
    background: var(--phos-soft);
    color: var(--phos);
  }
  .nav a .kbd {
    font-size: 11px;
    color: var(--dimmer);
    border: 1px solid var(--line-2);
    padding: 0 4px;
    background: var(--panel);
  }
  .org-pill {
    margin: 16px 6px 0;
    padding: 10px 12px;
    border: 1px solid var(--line-2);
    background: var(--panel);
    display: grid;
    gap: 4px;
  }
  .org-pill .top {
    display: flex;
    justify-content: space-between;
    font-size: 11px;
    color: var(--dim);
    letter-spacing: 0.12em;
  }
  .org-pill .name {
    color: var(--ink);
  }
  .org-pill .tier {
    color: var(--amber);
  }
</style>
