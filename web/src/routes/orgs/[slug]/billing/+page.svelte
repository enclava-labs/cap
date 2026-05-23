<script lang="ts">
  import { page } from '$app/stores';
  import ScreenChrome from '$lib/components/ScreenChrome.svelte';
  import { tiers, pendingInvoice, activeOrg } from '$lib/mocks';
  import { sats } from '$lib/format';
  import type { Tier } from '$lib/types';

  const slug = $derived($page.params.slug);
  let selected = $state<Tier>('Pro');

  function priceUsd(tierName: Tier): string {
    if (tierName === 'Pro') return '≈ $63 · monthly · cancel anytime';
    if (tierName === 'Enterprise') return '≈ $315 · monthly · invoiceable';
    return 'forever · personal orgs only';
  }
</script>

<ScreenChrome
  tabNum="05"
  tabLabel="BILLING · TIER & INVOICE"
  breadcrumb={`~ / orgs / ${slug} / billing`}
  statusDot="amber"
  statusText="BTCPAY · LIGHTNING + ON-CHAIN"
>
  <div class="bill">
    <h2>Subscription</h2>
    <p class="sub">Pay in Lightning sats via Breez. We never store your card details — there are none.</p>

    <div class="tier-grid">
      {#each tiers as t}
        <div
          class="tier"
          class:current={t.name === activeOrg.tier}
          class:featured={selected === t.name && t.price_sats > 0}
        >
          {#if selected === t.name && t.price_sats > 0}
            <span class="badge-cur">★ SELECTED</span>
          {/if}
          <div class="nm">{t.name.toUpperCase()}</div>
          <div class="price">
            {sats(t.price_sats)}<span class="u">sats / mo</span>
          </div>
          <div class="pmo">{priceUsd(t.name)}</div>
          <ul>
            {#each t.features as f}
              <li>{f}</li>
            {/each}
          </ul>
          <button class="pick" onclick={() => (selected = t.name)}>
            {t.name === activeOrg.tier
              ? 'CURRENT —'
              : t.name === 'Enterprise'
              ? 'CONTACT ›'
              : `PAY ${sats(t.price_sats)} SATS ›`}
          </button>
        </div>
      {/each}
    </div>

    <div class="invoice">
      <div class="qr">
        <div class="qr-art" aria-hidden="true"></div>
      </div>
      <div class="det">
        <div class="row">
          <span class="k">INVOICE</span>
          <span class="v mono">{pendingInvoice.reference}</span>
        </div>
        <div class="row">
          <span class="k">AMOUNT</span>
          <span class="v amount">{sats(pendingInvoice.amount_sats)} sats</span>
        </div>
        <div class="row">
          <span class="k">SETTLES TO</span>
          <span class="v mono">{pendingInvoice.bolt11}</span>
        </div>
        <div class="row">
          <span class="k">EXPIRES</span>
          <span class="v">in {pendingInvoice.expires_in}</span>
        </div>
        <div class="row">
          <span class="k">FOR PERIOD</span>
          <span class="v">{pendingInvoice.period}</span>
        </div>
        <a class="open" href="#">OPEN IN BREEZ ›</a>
        <div class="note">
          Or scan with any Lightning wallet. Settlement triggers tier upgrade within ~3 seconds.
        </div>
      </div>
    </div>
  </div>
</ScreenChrome>

<style>
  .bill {
    padding: 32px;
  }
  .bill h2 {
    margin: 0 0 6px;
    font-weight: 500;
    font-size: 24px;
  }
  .bill .sub {
    color: var(--dim);
    margin-bottom: 28px;
  }
  .tier-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    border: 1px solid var(--line);
    margin-bottom: 32px;
  }
  :root[data-theme='light'] .tier-grid {
    background: var(--bg);
  }
  .tier {
    padding: 28px 24px;
    border-right: 1px dashed var(--line);
    position: relative;
  }
  .tier:last-child {
    border-right: 0;
  }
  .tier.current {
    background: var(--phos-soft);
  }
  .nm {
    font-size: 12px;
    color: var(--dim);
    letter-spacing: 0.14em;
  }
  .price {
    font-size: 32px;
    color: var(--ink);
    margin: 14px 0 4px;
    font-weight: 300;
  }
  .price .u {
    font-size: 13px;
    color: var(--dim);
    margin-left: 8px;
    letter-spacing: 0.1em;
  }
  .pmo {
    font-size: 12px;
    color: var(--dim);
    margin-bottom: 22px;
  }
  ul {
    list-style: none;
    padding: 0;
    margin: 0 0 24px;
    font-size: 13px;
    color: var(--ink-2);
  }
  ul li {
    padding: 6px 0;
    display: flex;
    gap: 10px;
  }
  ul li::before {
    content: '›';
    color: var(--phos);
  }
  .badge-cur {
    position: absolute;
    top: 14px;
    right: 14px;
    font-size: 11px;
    color: var(--phos);
    letter-spacing: 0.14em;
  }
  .pick {
    width: 100%;
    padding: 11px;
    background: transparent;
    border: 1px solid var(--line);
    color: var(--ink);
    font: inherit;
    cursor: pointer;
    letter-spacing: 0.1em;
  }
  :root[data-theme='light'] .pick {
    border-color: var(--line-2);
  }
  .pick:hover {
    border-color: var(--phos);
    color: var(--phos);
  }
  .tier.featured .pick {
    background: var(--phos);
    color: var(--on-phos);
    border-color: var(--phos);
    font-weight: 500;
  }
  .tier.featured .pick:hover {
    background: var(--ink);
    color: var(--on-ink);
    border-color: var(--ink);
  }

  .invoice {
    display: grid;
    grid-template-columns: 260px 1fr;
    border: 1px solid var(--line);
  }
  :root[data-theme='light'] .invoice {
    background: var(--bg);
  }
  .qr {
    padding: 28px;
    border-right: 1px dashed var(--line);
    display: grid;
    place-items: center;
  }
  :root[data-theme='light'] .qr {
    background: var(--bg-2);
  }
  .qr-art {
    width: 200px;
    height: 200px;
    background:
      linear-gradient(
        90deg,
        var(--ink) 0 8%,
        transparent 8% 12%,
        var(--ink) 12% 20%,
        transparent 20% 24%,
        var(--ink) 24% 36%,
        transparent 36% 40%,
        var(--ink) 40% 56%,
        transparent 56% 60%,
        var(--ink) 60% 72%,
        transparent 72% 76%,
        var(--ink) 76% 88%,
        transparent 88% 92%,
        var(--ink) 92% 100%
      ),
      linear-gradient(
        0deg,
        var(--ink) 0 6%,
        transparent 6% 10%,
        var(--ink) 10% 18%,
        transparent 18% 24%,
        var(--ink) 24% 38%,
        transparent 38% 42%,
        var(--ink) 42% 60%,
        transparent 60% 64%,
        var(--ink) 64% 76%,
        transparent 76% 80%,
        var(--ink) 80% 92%,
        transparent 92% 100%
      );
    background-blend-mode: multiply;
    image-rendering: pixelated;
  }
  .det {
    padding: 28px;
  }
  .row {
    display: flex;
    justify-content: space-between;
    padding: 10px 0;
    border-bottom: 1px dashed var(--line);
    font-size: 13px;
  }
  .row:last-of-type {
    border-bottom: 0;
  }
  .k {
    color: var(--dim);
    letter-spacing: 0.1em;
    font-size: 12px;
  }
  .v {
    color: var(--ink);
  }
  .v.mono {
    color: var(--magenta);
    font-size: 12px;
  }
  .v.amount {
    color: var(--amber);
    font-size: 19px;
  }
  .open {
    margin-top: 18px;
    display: inline-block;
    padding: 11px 20px;
    background: var(--amber);
    color: var(--on-amber);
    border: 0;
    font: inherit;
    cursor: pointer;
    font-weight: 500;
    letter-spacing: 0.1em;
  }
  .open:hover {
    background: var(--ink);
    color: var(--on-ink);
  }
  .note {
    font-size: 12px;
    color: var(--dim);
    margin-top: 14px;
  }
</style>
