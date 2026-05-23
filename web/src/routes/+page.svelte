<script lang="ts">
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  onMount(() => {
    goto('/login', { replaceState: true });
  });
</script>

<div class="loading">▮ redirecting to /login…</div>

<style>
  .loading {
    color: var(--dim);
    padding: 80px 0;
    text-align: center;
    letter-spacing: 0.14em;
    font-size: 13px;
  }
</style>
