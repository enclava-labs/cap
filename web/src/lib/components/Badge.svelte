<script lang="ts">
  interface Props {
    variant: 'healthy' | 'applying' | 'pending' | 'failed' | 'rolled' | 'stopped';
    children: import('svelte').Snippet;
    small?: boolean;
  }
  let { variant, children, small = false }: Props = $props();
</script>

<span class="badge b-{variant}" class:small>
  {@render children()}
</span>

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 2px 8px;
    border: 1px solid currentColor;
    font-size: 11px;
    letter-spacing: 0.12em;
    background: var(--phos-soft);
  }
  .badge.small {
    font-size: 11px;
    padding: 1px 6px;
  }
  .badge::before {
    content: '';
    width: 5px;
    height: 5px;
    background: currentColor;
    border-radius: 50%;
  }
  :root[data-theme='dark'] .badge::before {
    box-shadow: 0 0 6px currentColor;
  }
  .b-healthy {
    color: var(--phos);
  }
  .b-applying {
    color: var(--blue);
  }
  .b-pending {
    color: var(--amber);
  }
  .b-failed {
    color: var(--red);
  }
  .b-rolled {
    color: var(--magenta);
  }
  .b-stopped {
    color: var(--dim);
  }
</style>
