<script lang="ts">
  import type { LogLine } from '$lib/types';
  interface Props {
    lines: LogLine[];
    maxHeight?: string;
  }
  let { lines, maxHeight = '240px' }: Props = $props();

  function levelClass(l: LogLine['level']): string {
    switch (l) {
      case 'I':
        return 'lvl-i';
      case 'W':
        return 'lvl-w';
      case 'E':
        return 'lvl-e';
      case 'O':
        return 'lvl-o';
    }
  }
  function levelLabel(l: LogLine['level']): string {
    return l === 'O' ? 'OK  ' : l === 'I' ? 'INFO' : l === 'W' ? 'WARN' : 'ERR ';
  }
</script>

<div class="terminal" style="max-height: {maxHeight}">
  {#each lines as line}
    <div>
      <span class="ts">{line.ts}</span>
      <span class={levelClass(line.level)}>{levelLabel(line.level)}</span>
      {line.message}
    </div>
  {/each}
</div>

<style>
  .terminal {
    background: var(--terminal-bg);
    border: 1px solid var(--line);
    padding: 14px 16px;
    font-size: 12px;
    color: var(--terminal-fg);
    line-height: 1.7;
    overflow: hidden;
  }
  .ts {
    color: #7a7560;
    margin-right: 8px;
  }
  :root[data-theme='dark'] .ts {
    color: var(--dimmer);
  }
  .lvl-i {
    color: #79b8ff;
  }
  .lvl-w {
    color: #f0c674;
  }
  .lvl-e {
    color: #ff7a7a;
  }
  .lvl-o {
    color: #7dffb2;
  }
</style>
