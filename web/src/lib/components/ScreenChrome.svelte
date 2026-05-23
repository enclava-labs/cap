<script lang="ts">
  interface Props {
    tabNum: string;
    tabLabel: string;
    breadcrumb: string;
    statusDot?: 'ok' | 'amber' | 'red';
    statusText?: string;
    children: import('svelte').Snippet;
  }
  let {
    tabNum,
    tabLabel,
    breadcrumb,
    statusDot = 'ok',
    statusText = '',
    children
  }: Props = $props();
</script>

<section class="screen">
  <div class="tab">
    <span>{tabNum} ·</span>
    {tabLabel}
  </div>
  <div class="screen-head">
    <span class="dot" class:amber={statusDot === 'amber'} class:red={statusDot === 'red'}></span>
    <span class="pwd">{breadcrumb}</span>
    <span class="spacer"></span>
    <span>{statusText}</span>
  </div>
  {@render children()}
</section>

<style>
  .screen {
    border: 1px solid var(--line);
    background: linear-gradient(180deg, var(--panel), var(--bg-2));
    margin-bottom: 56px;
    box-shadow:
      0 0 0 1px var(--bg) inset,
      0 30px 60px rgba(0, 0, 0, 0.45);
    position: relative;
  }
  :root[data-theme='light'] .screen {
    background: var(--panel);
    box-shadow:
      0 1px 0 rgba(255, 255, 255, 0.6) inset,
      0 30px 50px -25px rgba(20, 20, 15, 0.18);
  }
  .tab {
    position: absolute;
    top: -1px;
    left: 18px;
    transform: translateY(-100%);
    font-size: 11px;
    letter-spacing: 0.14em;
    color: var(--phos);
    background: var(--bg);
    padding: 5px 10px;
    border: 1px solid var(--line);
    border-bottom: 0;
  }
  .tab span {
    color: var(--dim);
  }
  .screen-head {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 12px 18px;
    border-bottom: 1px solid var(--line);
    background: var(--elevation);
    font-size: 12px;
    color: var(--dim);
    letter-spacing: 0.12em;
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--phos);
  }
  :root[data-theme='dark'] .dot {
    box-shadow: 0 0 8px var(--phos);
  }
  :root[data-theme='light'] .dot {
    box-shadow: 0 0 0 2px var(--phos-soft);
  }
  .dot.amber {
    background: var(--amber);
  }
  :root[data-theme='dark'] .dot.amber {
    box-shadow: 0 0 8px var(--amber);
  }
  :root[data-theme='light'] .dot.amber {
    box-shadow: 0 0 0 2px var(--amber-soft);
  }
  .dot.red {
    background: var(--red);
  }
  :root[data-theme='dark'] .dot.red {
    box-shadow: 0 0 8px var(--red);
  }
  .spacer {
    flex: 1;
  }
  .pwd {
    color: var(--ink);
    letter-spacing: 0;
  }
  :global(.pwd .slash) {
    color: var(--dimmer);
    margin: 0 6px;
  }
</style>
