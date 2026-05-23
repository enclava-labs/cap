<script lang="ts">
  import { theme } from '$lib/theme.svelte';
</script>

<button
  class="toggle"
  type="button"
  onclick={() => theme.toggle()}
  aria-label="Toggle theme"
  title={`Theme: ${theme.value} — click to switch`}
>
  <span class="ico">{theme.value === 'dark' ? '☾' : '☀'}</span>
  <span class="lbl">{theme.value === 'dark' ? 'DARK' : 'LIGHT'}</span>
</button>

<style>
  .toggle {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 5px 10px;
    background: transparent;
    border: 1px solid var(--line);
    color: var(--ink-2);
    font: inherit;
    font-size: 11px;
    letter-spacing: 0.14em;
    cursor: pointer;
    transition: 0.15s;
  }
  .toggle:hover {
    border-color: var(--phos);
    color: var(--phos);
  }
  .ico {
    color: var(--phos);
    font-size: 13px;
  }
</style>
