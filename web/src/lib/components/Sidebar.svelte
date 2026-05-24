<script lang="ts">
  import { page } from '$app/stores';
  import { activeOrg } from '$lib/mocks';

  type Item = { href: string; label: string; kbd: string; icon: string };

  const workspace: Item[] = [
    { href: '/dashboard', label: 'Overview', kbd: 'G O', icon: '◐' },
    { href: '/apps', label: 'Apps', kbd: 'G A', icon: '▢' },
    { href: '/deployments', label: 'Deployments', kbd: 'G D', icon: '⤺' },
    { href: `/orgs/${activeOrg.name}/keyring`, label: 'Keyring', kbd: 'G K', icon: '⎈' },
    { href: `/orgs/${activeOrg.name}/members`, label: 'Members', kbd: 'G M', icon: '⌥' }
  ];
  const account: Item[] = [
    { href: `/orgs/${activeOrg.name}/billing`, label: 'Billing', kbd: 'G B', icon: '₿' },
    { href: '/recovery', label: 'Recovery seed', kbd: 'G R', icon: '⤓' },
    { href: '/audit', label: 'Audit log', kbd: 'G L', icon: '⊟' },
    { href: '/settings', label: 'Settings', kbd: '', icon: '⚙' }
  ];

  function isActive(href: string): boolean {
    return $page.url.pathname === href || $page.url.pathname.startsWith(href + '/');
  }
</script>

<aside class="nav-col">
  <div class="org-switcher">
    <div class="av">{activeOrg.name[0].toUpperCase()}</div>
    <div>
      <div class="nm">{activeOrg.name}</div>
      <div class="sb">
        {activeOrg.is_personal ? 'personal' : 'team'} · {activeOrg.tier.toLowerCase()}
      </div>
    </div>
    <div class="ch">⇅</div>
  </div>

  <div class="nav-grp">
    <div class="gh">Workspace</div>
    {#each workspace as item}
      <a class="nav-link" class:act={isActive(item.href)} href={item.href}>
        <span class="ico">{item.icon}</span>
        <span>{item.label}</span>
        {#if item.kbd}<span class="kbd">{item.kbd}</span>{/if}
      </a>
    {/each}
  </div>

  <div class="nav-grp">
    <div class="gh">Account</div>
    {#each account as item}
      <a class="nav-link" class:act={isActive(item.href)} href={item.href}>
        <span class="ico">{item.icon}</span>
        <span>{item.label}</span>
        {#if item.kbd}<span class="kbd">{item.kbd}</span>{/if}
      </a>
    {/each}
  </div>
</aside>

<style>
  .nav-col {
    padding: 18px 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--card);
    position: sticky;
    top: 24px;
    align-self: start;
    max-height: calc(100vh - 48px);
    overflow-y: auto;
  }

  .org-switcher {
    margin: 0 0 18px;
    padding: 12px 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--card);
    display: grid;
    grid-template-columns: 30px 1fr auto;
    gap: 10px;
    align-items: center;
    cursor: pointer;
  }
  .org-switcher:hover {
    border-color: var(--border-2);
  }
  .av {
    width: 28px;
    height: 28px;
    border-radius: var(--radius);
    background: linear-gradient(135deg, var(--primary), var(--secondary));
    color: var(--primary-fg);
    font-weight: 700;
    font-size: 12px;
    display: grid;
    place-items: center;
  }
  .nm {
    font-size: 13px;
    font-weight: 600;
    color: var(--fg);
  }
  .sb {
    font-size: 11px;
    color: var(--muted-fg);
    font-family: var(--font-mono);
  }
  .ch {
    color: var(--dim);
    font-size: 14px;
  }

  .nav-grp {
    padding: 4px 4px 14px;
  }
  .gh {
    font-family: var(--font-mono);
    font-size: 10px;
    letter-spacing: 0.14em;
    color: var(--dim);
    text-transform: uppercase;
    padding: 8px 10px;
  }
  .nav-link {
    display: grid;
    grid-template-columns: 18px 1fr auto;
    gap: 10px;
    align-items: center;
    padding: 8px 10px;
    border-radius: var(--radius);
    font-size: 13.5px;
    color: var(--fg-2);
    cursor: pointer;
  }
  .nav-link:hover {
    background: hsla(0, 0%, 100%, 0.04);
    color: var(--fg);
  }
  .nav-link.act {
    background: var(--primary-soft);
    color: var(--primary);
  }
  .nav-link .ico {
    color: var(--dim);
    font-family: var(--font-mono);
  }
  .nav-link.act .ico {
    color: var(--primary);
  }
  .nav-link .kbd {
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--dim);
    padding: 1px 5px;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: var(--card);
  }
</style>
