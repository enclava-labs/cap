<script lang="ts">
  interface Props {
    variant: 'healthy' | 'applying' | 'pending' | 'failed' | 'rolled' | 'stopped' | 'bitcoin';
    children: import('svelte').Snippet;
    small?: boolean;
  }
  let { variant, children, small = false }: Props = $props();
</script>

<span class="chip c-{variant}" class:small>
  {@render children()}
</span>

<style>
  .chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-family: var(--font-mono);
    font-size: 11px;
    font-weight: 500;
    padding: 3px 10px;
    border-radius: 999px;
    border: 1px solid currentColor;
    background: color-mix(in srgb, currentColor 10%, transparent);
    letter-spacing: 0.02em;
    text-transform: lowercase;
  }
  .chip.small {
    font-size: 10px;
    padding: 2px 8px;
  }
  .chip::before {
    content: '';
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: currentColor;
    box-shadow: 0 0 8px currentColor;
  }
  .c-healthy {
    color: var(--secondary);
  }
  .c-applying {
    color: var(--primary);
  }
  .c-pending {
    color: var(--amber);
  }
  .c-failed {
    color: var(--red);
  }
  .c-rolled {
    color: var(--violet);
  }
  .c-stopped {
    color: var(--muted-fg);
  }
  .c-bitcoin {
    color: var(--amber);
  }
</style>
