<script lang="ts">
  import '../app.css';
  let { children } = $props();
</script>

<div class="stage">
  <header class="crown">
    <a class="wordmark" href="/dashboard">ENCLAVA<span class="dot">.</span></a>
    <div class="crown-meta">cap-web <b>v0.7.3-rc4</b></div>
  </header>

  {@render children()}
</div>

<style>
  .stage {
    max-width: 1320px;
    margin: 0 auto;
    padding: 40px 32px 120px;
  }
  .crown {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding-bottom: 18px;
    border-bottom: 1px solid var(--hair);
    margin-bottom: 56px;
  }
  .wordmark {
    font-family: var(--font-display);
    font-weight: 800;
    font-size: 19px;
    letter-spacing: 0.04em;
    color: var(--fg);
  }
  .wordmark:hover {
    color: var(--fg);
  }
  .wordmark .dot {
    color: var(--primary);
  }
  .crown-meta {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--dim);
  }
  .crown-meta b {
    color: var(--primary);
    font-weight: 500;
  }
</style>
