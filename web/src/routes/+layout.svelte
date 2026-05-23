<script lang="ts">
  import '../app.css';
  import ThemeToggle from '$lib/components/ThemeToggle.svelte';
  let { children } = $props();
</script>

<div class="stage">
  <div class="crown">
    <div class="mark">
      ▣ <b>ENCLAVA · CAP</b> · CONFIDENTIAL APPLICATION PLATFORM
    </div>
    <div class="crown-right">
      <span class="meta">cap-web v0.7.3-rc4</span>
      <ThemeToggle />
    </div>
  </div>

  {@render children()}
</div>

<style>
  .stage {
    max-width: 1280px;
    margin: 0 auto;
    padding: 32px 28px 100px;
  }
  .crown {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding-bottom: 14px;
    border-bottom: 1px solid var(--line);
    margin-bottom: 48px;
  }
  .mark {
    letter-spacing: 0.12em;
    font-size: 12px;
    color: var(--dim);
  }
  .mark b {
    color: var(--phos);
    font-weight: 500;
  }
  .crown-right {
    display: flex;
    align-items: center;
    gap: 16px;
  }
  .meta {
    font-size: 12px;
    color: var(--dim);
    letter-spacing: 0.05em;
  }
</style>
