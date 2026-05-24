<script lang="ts">
  import ScreenChrome from '$lib/components/ScreenChrome.svelte';
  import { auditEvents, activeOrg } from '$lib/mocks';
  import type { AuditEvent } from '$lib/mocks';

  type Cat = AuditEvent['category'] | 'all';
  let filter = $state<Cat>('all');

  const filtered = $derived(
    filter === 'all' ? auditEvents : auditEvents.filter((e) => e.category === filter)
  );

  function catColor(c: AuditEvent['category']): string {
    switch (c) {
      case 'deploy':
        return 'cyan';
      case 'keyring':
        return 'violet';
      case 'member':
        return 'teal';
      case 'billing':
        return 'amber';
      case 'auth':
        return 'fg';
    }
  }
</script>

<ScreenChrome
  tabNum="11"
  tabLabel="AUDIT LOG"
  breadcrumb={`orgs / ${activeOrg.name} / audit`}
  statusText={`${auditEvents.length} events · append-only`}
>
  <div class="page">
    <div class="page-h">
      <div>
        <div class="eyebrow">EVENTS</div>
        <h1>Audit <span class="accent">log</span></h1>
        <div class="crumbs">orgs / {activeOrg.name} / audit</div>
      </div>
      <div class="filters">
        <button class="chip-btn" class:act={filter === 'all'} onclick={() => (filter = 'all')}>
          all
        </button>
        <button class="chip-btn" class:act={filter === 'deploy'} onclick={() => (filter = 'deploy')}>
          deploys
        </button>
        <button
          class="chip-btn"
          class:act={filter === 'keyring'}
          onclick={() => (filter = 'keyring')}
        >
          keyring
        </button>
        <button class="chip-btn" class:act={filter === 'member'} onclick={() => (filter = 'member')}>
          members
        </button>
        <button
          class="chip-btn"
          class:act={filter === 'billing'}
          onclick={() => (filter = 'billing')}
        >
          billing
        </button>
        <button class="chip-btn" class:act={filter === 'auth'} onclick={() => (filter = 'auth')}>
          auth
        </button>
      </div>
    </div>

    <div class="timeline">
      {#each filtered as e}
        <div class="ev">
          <div class="dot dot-{catColor(e.category)}"></div>
          <div class="body">
            <div class="head">
              <span class="cat cat-{catColor(e.category)}">{e.category}</span>
              <span class="actor">{e.actor}</span>
              <span class="dim">·</span>
              <span class="age">{e.age}</span>
            </div>
            <div class="msg">
              <span class="action">{e.action}</span>
              <span class="target">{e.target}</span>
            </div>
            <div class="meta">
              <span class="id">#{e.id}</span>
              <span class="dim">·</span>
              <span class="ts">{e.ts}</span>
            </div>
          </div>
        </div>
      {/each}
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
    margin-bottom: 28px;
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
  .filters {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
  }
  .chip-btn {
    padding: 7px 14px;
    border: 1px solid var(--border);
    border-radius: 999px;
    background: var(--card);
    color: var(--muted-fg);
    font-family: var(--font-mono);
    font-size: 12px;
    cursor: pointer;
  }
  .chip-btn:hover {
    border-color: var(--border-2);
    color: var(--fg);
  }
  .chip-btn.act {
    border-color: var(--primary);
    background: var(--primary-soft);
    color: var(--primary);
  }

  .timeline {
    position: relative;
    padding-left: 20px;
    border-left: 1px solid var(--hair);
  }
  .ev {
    position: relative;
    padding: 16px 0 16px 22px;
    border-bottom: 1px dashed var(--hair);
  }
  .ev:last-child {
    border-bottom: 0;
  }
  .dot {
    position: absolute;
    left: -27px;
    top: 22px;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    border: 2px solid var(--bg);
    background: var(--muted-fg);
  }
  .dot-cyan {
    background: var(--primary);
    box-shadow: 0 0 0 3px hsla(190, 90%, 45%, 0.2);
  }
  .dot-teal {
    background: var(--secondary);
    box-shadow: 0 0 0 3px hsla(160, 84%, 39%, 0.2);
  }
  .dot-violet {
    background: var(--violet);
    box-shadow: 0 0 0 3px hsla(265, 80%, 70%, 0.2);
  }
  .dot-amber {
    background: var(--amber);
    box-shadow: 0 0 0 3px var(--amber-soft);
  }
  .dot-fg {
    background: var(--fg);
    box-shadow: 0 0 0 3px hsla(210, 20%, 98%, 0.1);
  }

  .head {
    display: flex;
    align-items: baseline;
    gap: 8px;
    margin-bottom: 4px;
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--muted-fg);
  }
  .cat {
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }
  .cat-cyan {
    color: var(--primary);
  }
  .cat-teal {
    color: var(--secondary);
  }
  .cat-violet {
    color: var(--violet);
  }
  .cat-amber {
    color: var(--amber);
  }
  .cat-fg {
    color: var(--fg);
  }
  .actor {
    color: var(--fg-2);
  }
  .dim {
    color: var(--dimmer);
  }
  .age {
    color: var(--muted-fg);
  }

  .msg {
    font-size: 14px;
    color: var(--fg);
    margin-bottom: 4px;
  }
  .action {
    color: var(--fg);
    font-weight: 500;
  }
  .target {
    color: var(--muted-fg);
    margin-left: 6px;
  }
  .meta {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--dim);
  }
  .id {
    color: var(--muted-fg);
  }
</style>
