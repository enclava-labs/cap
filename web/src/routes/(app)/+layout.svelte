<script lang="ts">
  import Sidebar from '$lib/components/Sidebar.svelte';
  let { children } = $props();
</script>

<div class="shell">
  <Sidebar />
  <div class="main">
    {@render children()}
  </div>
</div>

<style>
  .shell {
    display: grid;
    grid-template-columns: 260px 1fr;
    gap: 24px;
    align-items: start;
  }
  .main {
    min-width: 0; /* prevent grid blowout from wide tables */
  }
</style>
