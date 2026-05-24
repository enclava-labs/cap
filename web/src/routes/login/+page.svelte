<script lang="ts">
  import ScreenChrome from '$lib/components/ScreenChrome.svelte';
  import { goto } from '$app/navigation';

  let email = $state('');

  function continueWith(provider: string) {
    console.log('Mock auth via', provider);
    goto('/dashboard');
  }
</script>

<ScreenChrome
  tabNum="01"
  tabLabel="AUTH"
  breadcrumb="app.enclava.dev/cli/login"
  statusText="session · guest"
>
  <div class="auth">
    <div class="auth-l">
      <div class="inner">
        <div class="eyebrow">SIGN IN</div>
        <h1>The PaaS for <span class="accent">confidential apps.</span></h1>
        <p>
          Sign in to deploy containers into attested TEEs. Bring any identity — only your key signs
          your code.
        </p>
        <div class="pillars">
          <div class="pillar">
            <div class="ico">&lt;/&gt;</div>
            <div class="h">Declarative deploys</div>
            <div class="b">One file describes the app — image, resources, domain.</div>
          </div>
          <div class="pillar">
            <div class="ico">⌂</div>
            <div class="h">Sealed secrets</div>
            <div class="b">Encrypted on your machine, unsealed only inside the TEE.</div>
          </div>
          <div class="pillar">
            <div class="ico">≣</div>
            <div class="h">Encrypted volumes</div>
            <div class="b">Persistent data sealed with TEE-derived keys.</div>
          </div>
        </div>
      </div>
    </div>

    <div class="auth-r">
      <div class="eyebrow muted">CONTINUE WITH</div>
      <h3>Choose an identity for this session</h3>
      <button class="prov" type="button" onclick={() => continueWith('nostr')}>
        <span class="ico primary">⌁</span>
        <span class="text">
          <div class="lab">Nostr</div>
          <div class="sub">sign with npub · NIP-98 challenge</div>
        </span>
        <span class="arr">→</span>
      </button>
      <button class="prov" type="button" onclick={() => continueWith('github')}>
        <span class="ico">G</span>
        <span class="text">
          <div class="lab">GitHub</div>
          <div class="sub">OAuth 2.0 · inherits org membership</div>
        </span>
        <span class="arr">→</span>
      </button>
      <button class="prov" type="button" onclick={() => continueWith('google')}>
        <span class="ico secondary">M</span>
        <span class="text">
          <div class="lab">Google</div>
          <div class="sub">OAuth 2.0 · email identity only</div>
        </span>
        <span class="arr">→</span>
      </button>
      <div class="or">or magic link</div>
      <form
        class="email-row"
        onsubmit={(e) => {
          e.preventDefault();
          continueWith('email');
        }}
      >
        <input placeholder="you@enclave.dev" bind:value={email} />
        <button type="submit">Send →</button>
      </form>
      <div class="fine">
        By continuing you accept the <a href="#">acceptable-use policy</a>. Unsigned containers will
        not deploy.
      </div>
    </div>
  </div>
</ScreenChrome>

<style>
  .auth {
    display: grid;
    grid-template-columns: 1.1fr 1fr;
    min-height: 640px;
  }
  .auth-l {
    padding: 64px 56px;
    border-right: 1px solid var(--hair);
    position: relative;
    overflow: hidden;
  }
  .auth-l::after {
    content: '';
    position: absolute;
    inset: 0;
    pointer-events: none;
    background:
      radial-gradient(circle at 20% 90%, hsla(190, 90%, 45%, 0.12), transparent 50%),
      radial-gradient(circle at 90% 20%, hsla(160, 84%, 39%, 0.08), transparent 50%);
  }
  .auth-l .inner {
    position: relative;
  }
  .auth-l h1 {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 52px;
    line-height: 1.05;
    letter-spacing: -0.03em;
    margin: 16px 0 18px;
    max-width: 16ch;
  }
  .auth-l h1 .accent {
    color: var(--primary);
  }
  .auth-l p {
    color: var(--muted-fg);
    max-width: 42ch;
    font-size: 16px;
    line-height: 1.55;
    margin-bottom: 56px;
  }
  .pillars {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 14px;
  }
  .pillar {
    padding: 14px 14px 16px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--card);
  }
  .pillar .ico {
    color: var(--primary);
    margin-bottom: 8px;
    font-family: var(--font-mono);
    font-size: 16px;
    font-weight: 600;
  }
  .pillar .h {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 14px;
    margin-bottom: 4px;
  }
  .pillar .b {
    color: var(--muted-fg);
    font-size: 13px;
    line-height: 1.45;
  }

  .auth-r {
    padding: 64px 56px;
    background: var(--bg-2);
  }
  .auth-r h3 {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 22px;
    margin: 12px 0 24px;
    letter-spacing: -0.01em;
  }
  .prov {
    display: grid;
    grid-template-columns: 40px 1fr auto;
    gap: 14px;
    align-items: center;
    width: 100%;
    padding: 14px 16px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--card);
    margin-bottom: 10px;
    cursor: pointer;
    transition: 0.15s;
    text-align: left;
    color: var(--fg);
    font: inherit;
  }
  .prov:hover {
    border-color: var(--primary);
    background: var(--card-2);
    transform: translateY(-1px);
    box-shadow: 0 6px 20px -10px var(--primary-glow);
  }
  .prov .ico {
    width: 36px;
    height: 36px;
    border-radius: var(--radius);
    background: hsla(0, 0%, 100%, 0.04);
    display: grid;
    place-items: center;
    color: var(--fg);
    font-family: var(--font-mono);
    font-weight: 600;
    font-size: 14px;
  }
  .prov .ico.primary {
    background: var(--primary-soft);
    color: var(--primary);
  }
  .prov .ico.secondary {
    background: var(--secondary-soft);
    color: var(--secondary);
  }
  .prov .lab {
    font-size: 15px;
    font-weight: 600;
    line-height: 1.2;
  }
  .prov .sub {
    font-size: 12px;
    color: var(--muted-fg);
    margin-top: 2px;
  }
  .prov .arr {
    color: var(--dim);
    transition: 0.15s;
  }
  .prov:hover .arr {
    color: var(--primary);
    transform: translateX(4px);
  }
  .or {
    display: flex;
    align-items: center;
    gap: 12px;
    color: var(--dim);
    font-family: var(--font-mono);
    font-size: 11px;
    letter-spacing: 0.1em;
    margin: 22px 0;
    text-transform: uppercase;
  }
  .or::before,
  .or::after {
    content: '';
    flex: 1;
    border-top: 1px solid var(--hair);
  }
  .email-row {
    display: flex;
    gap: 8px;
  }
  .email-row input {
    flex: 1;
    padding: 12px 14px;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--fg);
    font-family: var(--font-sans);
    font-size: 14px;
    outline: none;
  }
  .email-row input::placeholder {
    color: var(--dim);
  }
  .email-row input:focus {
    border-color: var(--primary);
    box-shadow: 0 0 0 3px var(--primary-soft);
  }
  .email-row button {
    background: var(--primary);
    color: var(--primary-fg);
    border: 0;
    padding: 0 18px;
    border-radius: var(--radius);
    font-family: var(--font-sans);
    font-weight: 600;
    font-size: 14px;
    cursor: pointer;
  }
  .fine {
    font-size: 12px;
    color: var(--dim);
    margin-top: 22px;
    line-height: 1.6;
  }
  .fine a {
    color: var(--muted-fg);
    text-decoration: underline;
    text-decoration-color: var(--border-2);
    text-underline-offset: 3px;
  }
</style>
