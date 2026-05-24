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

<section class="frame">
  <div class="frame-head">
    <span class="dot" class:warn={statusDot === 'amber'} class:err={statusDot === 'red'}></span>
    <span class="num">{tabNum} · {tabLabel.toLowerCase()}</span>
    <span class="bc">· {breadcrumb}</span>
    <span class="spacer"></span>
    {#if statusText}
      <span class="status">{statusText}</span>
    {/if}
  </div>
  {@render children()}
</section>

<style>
  .frame {
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--bg-2);
    margin-bottom: 64px;
    overflow: hidden;
    box-shadow:
      0 1px 0 hsla(0, 0%, 100%, 0.04) inset,
      0 30px 60px -25px hsla(0, 0%, 0%, 0.5);
    position: relative;
  }
  .frame::before {
    content: '';
    position: absolute;
    top: 0;
    left: 20%;
    right: 20%;
    height: 1px;
    background: linear-gradient(90deg, transparent, hsla(190, 90%, 45%, 0.5), transparent);
    pointer-events: none;
  }
  .frame-head {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 14px 22px;
    border-bottom: 1px solid var(--hair);
    background: var(--inset);
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--dim);
  }
  .num {
    color: var(--primary);
    font-weight: 500;
  }
  .bc {
    color: var(--muted-fg);
  }
  .spacer {
    flex: 1;
  }
  .status {
    color: var(--muted-fg);
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--secondary);
    box-shadow: 0 0 0 4px hsla(160, 84%, 39%, 0.18);
  }
  .dot.warn {
    background: var(--amber);
    box-shadow: 0 0 0 4px var(--amber-soft);
  }
  .dot.err {
    background: var(--red);
    box-shadow: 0 0 0 4px var(--red-soft);
  }
</style>
