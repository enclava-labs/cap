<script lang="ts">
  import type { LogLine } from '$lib/types';
  interface Props {
    lines: LogLine[];
    maxHeight?: string;
  }
  let { lines, maxHeight = '280px' }: Props = $props();

  function levelClass(l: LogLine['level']): string {
    switch (l) {
      case 'I':
        return 'i';
      case 'W':
        return 'w';
      case 'E':
        return 'e';
      case 'O':
        return 'o';
    }
  }
  function levelLabel(l: LogLine['level']): string {
    return l === 'O' ? 'OK  ' : l === 'I' ? 'INFO' : l === 'W' ? 'WARN' : 'ERR ';
  }
</script>

<div class="term" style="max-height: {maxHeight}">
  {#each lines as line}
    <div>
      <span class="ts">{line.ts}</span><span class={levelClass(line.level)}>{levelLabel(line.level)}</span>
      {line.message}
    </div>
  {/each}
</div>

<style>
  .term {
    padding: 20px 22px;
    overflow: hidden;
    font-family: var(--font-mono);
    font-size: 12.5px;
    line-height: 1.75;
    color: var(--fg-2);
    background: var(--inset);
  }
  .ts {
    color: var(--dim);
    margin-right: 10px;
  }
  .i {
    color: var(--primary);
  }
  .w {
    color: var(--amber);
  }
  .e {
    color: var(--red);
  }
  .o {
    color: var(--secondary);
  }
</style>
