<script lang="ts">
  import ScreenChrome from '$lib/components/ScreenChrome.svelte';
  import { goto } from '$app/navigation';

  let email = $state('');

  function continueWith(provider: string) {
    // mock: pretend we authenticated and jump to dashboard
    console.log('Mock auth via', provider);
    goto('/dashboard');
  }
</script>

<ScreenChrome
  tabNum="01"
  tabLabel="AUTH / LOGIN"
  breadcrumb="app.enclava.dev/cli/login"
  statusText="SESSION · GUEST"
>
  <div class="login-wrap">
    <div class="login-l">
      <pre class="glyph">  ╔══════════════════════════════════╗
  ║   E N C L A V A   ·   C A P      ║
  ║   confidential application       ║
  ║   platform                       ║
  ╚══════════════════════════════════╝</pre>
      <h1>Sign in to your enclave.</h1>
      <p>Your keys derive every deploy. Use any identity provider — none of them sign your code.</p>
      <div class="lede">
        <div>›  TEE attestation <b>AMD SEV-SNP</b></div>
        <div>›  Customer-signed descriptors</div>
        <div>›  Encrypted-by-default persistence</div>
      </div>
      <div class="footer-ascii">
        <span class="blink">▮</span> &nbsp; awaiting input · cap-web @ v0.7.3-rc4
      </div>
    </div>
    <div class="login-r">
      <div class="label">CONTINUE WITH</div>
      <button class="auth-btn" onclick={() => continueWith('nostr')}>
        <span class="ico">⌁</span>
        <span>
          <div class="lab">Nostr</div>
          <div class="sub">sign-in with npub via NIP-98</div>
        </span>
        <span class="key">⌘ N</span>
      </button>
      <button class="auth-btn" onclick={() => continueWith('github')}>
        <span class="ico">◆</span>
        <span>
          <div class="lab">GitHub</div>
          <div class="sub">OAuth 2.0 · org membership inherited</div>
        </span>
        <span class="key">⌘ G</span>
      </button>
      <button class="auth-btn" onclick={() => continueWith('google')}>
        <span class="ico">✉</span>
        <span>
          <div class="lab">Google</div>
          <div class="sub">OAuth 2.0 · email identity only</div>
        </span>
        <span class="key">⌘ M</span>
      </button>
      <div class="divider-x">OR LINK BY EMAIL</div>
      <form class="email-row" onsubmit={(e) => { e.preventDefault(); continueWith('email'); }}>
        <input placeholder="you@enclave.dev" bind:value={email} />
        <button type="submit">SEND ›</button>
      </form>
      <div class="fine">
        By continuing you accept the <a href="#">acceptable-use policy</a>
        and pledge not to deploy unsigned containers.
      </div>
    </div>
  </div>
</ScreenChrome>

<style>
  .login-wrap {
    display: grid;
    grid-template-columns: 1.05fr 1fr;
    min-height: 540px;
  }
  .login-l {
    padding: 56px 48px;
    border-right: 1px dashed var(--line);
    position: relative;
  }
  .login-r {
    padding: 56px 48px;
  }
  :root[data-theme='light'] .login-r {
    background: var(--bg);
  }
  .glyph {
    font-size: 12px;
    color: var(--phos);
    line-height: 1.15;
    margin: 0 0 28px;
  }
  h1 {
    font-weight: 500;
    font-size: 24px;
    color: var(--ink);
    margin: 0 0 10px;
    letter-spacing: 0.02em;
  }
  p {
    color: var(--dim);
    max-width: 32ch;
    margin: 0 0 30px;
  }
  .lede {
    display: grid;
    gap: 4px;
    font-size: 12px;
    color: var(--dim);
    letter-spacing: 0.08em;
  }
  .lede b {
    color: var(--phos);
    font-weight: 500;
  }
  .footer-ascii {
    position: absolute;
    bottom: 30px;
    left: 48px;
    right: 48px;
    color: var(--dimmer);
    font-size: 12px;
  }
  .blink {
    animation: blink 1.1s steps(2, end) infinite;
    color: var(--phos);
  }
  @keyframes blink {
    50% {
      opacity: 0;
    }
  }
  .label {
    color: var(--dim);
    font-size: 12px;
    letter-spacing: 0.12em;
    margin-bottom: 16px;
  }
  .auth-btn {
    display: grid;
    grid-template-columns: 28px 1fr auto;
    align-items: center;
    gap: 14px;
    width: 100%;
    padding: 14px 16px;
    margin-bottom: 10px;
    background: transparent;
    border: 1px solid var(--line);
    color: var(--ink);
    cursor: pointer;
    transition: 0.15s;
    text-align: left;
  }
  :root[data-theme='light'] .auth-btn {
    background: var(--panel);
    border-color: var(--line-2);
  }
  .auth-btn:hover {
    border-color: var(--phos);
    background: var(--phos-soft);
  }
  .lab {
    font-size: 14px;
  }
  .sub {
    color: var(--dim);
    font-size: 12px;
  }
  .key {
    color: var(--dimmer);
    font-size: 11px;
  }
  .ico {
    width: 22px;
    height: 22px;
    display: grid;
    place-items: center;
    color: var(--phos);
  }
  .divider-x {
    display: flex;
    align-items: center;
    gap: 12px;
    color: var(--dimmer);
    margin: 22px 0;
    font-size: 11px;
    letter-spacing: 0.12em;
  }
  .divider-x::before,
  .divider-x::after {
    content: '';
    flex: 1;
    border-top: 1px dashed var(--line);
  }
  .email-row {
    display: flex;
    border: 1px solid var(--line);
  }
  :root[data-theme='light'] .email-row {
    background: var(--panel);
    border-color: var(--line-2);
  }
  .email-row input {
    flex: 1;
    background: transparent;
    border: 0;
    padding: 13px 14px;
    color: var(--ink);
    outline: none;
  }
  .email-row input::placeholder {
    color: var(--dimmer);
  }
  .email-row button {
    background: var(--phos);
    color: var(--on-phos);
    border: 0;
    padding: 0 16px;
    font-weight: 500;
    cursor: pointer;
    letter-spacing: 0.08em;
  }
  .email-row button:hover {
    background: var(--ink);
    color: var(--on-ink);
  }
  .fine {
    color: var(--dimmer);
    font-size: 12px;
    margin-top: 14px;
  }
</style>
