<script lang="ts">
  import { page } from '$app/stores';
  import ScreenChrome from '$lib/components/ScreenChrome.svelte';
  import Badge from '$lib/components/Badge.svelte';
  import { tiers, pendingInvoice, activeOrg } from '$lib/mocks';
  import { sats } from '$lib/format';
  import type { Tier } from '$lib/types';

  const slug = $derived($page.params.slug ?? activeOrg.name);
  let selected = $state<Tier>('Pro');

  function priceUsd(tierName: Tier): string {
    if (tierName === 'Pro') return '≈ $63 · cancel anytime';
    if (tierName === 'Enterprise') return '≈ $315 · invoiceable';
    return 'forever · personal orgs only';
  }
</script>

<ScreenChrome
  tabNum="05"
  tabLabel="BILLING · LIGHTNING"
  breadcrumb={`orgs / ${slug} / billing`}
  statusDot="amber"
  statusText="BTCPay + Breez SDK"
>
  <div class="bill-pad">
    <div class="bill-h">
      <div>
        <div class="eyebrow amber">BILLING</div>
        <h1>Settle in <span class="accent">sats.</span></h1>
        <div class="lede">
          Pay in Bitcoin over Lightning via Breez. No cards, no recurring rails — settlement
          triggers a tier upgrade in seconds.
        </div>
      </div>
      <div class="price-meta">
        BTC / USD · 24h<br />
        <b>$ 63,481.20</b>
        <span class="up">+ 1.42 %</span>
      </div>
    </div>

    <div class="plans">
      {#each tiers as t}
        <div
          class="plan"
          class:feat={selected === t.name && t.price_sats > 0}
          class:current={t.name === activeOrg.tier}
        >
          {#if selected === t.name && t.price_sats > 0}
            <span class="badge-feat">★ SELECTED</span>
          {/if}
          <div class="nm">{t.name.toUpperCase()}</div>
          <div class="pr">
            {sats(t.price_sats)}<span class="u">sats / mo</span>
          </div>
          <div class="est">{priceUsd(t.name)}</div>
          <ul>
            {#each t.features as f}
              <li>{f}</li>
            {/each}
          </ul>
          <button class="pick" onclick={() => (selected = t.name)}>
            {t.name === activeOrg.tier
              ? 'Current —'
              : t.name === 'Enterprise'
                ? 'Contact us →'
                : `Pay ${sats(t.price_sats)} sats →`}
          </button>
        </div>
      {/each}
    </div>

    <div class="invoice-card">
      <div class="qr">
        <div class="qrart" aria-hidden="true"></div>
      </div>
      <div class="body">
        <div class="ic-h">
          <div class="t">Invoice — <span class="accent">{pendingInvoice.tier}</span> · May 2026</div>
          <Badge variant="bitcoin">awaiting payment</Badge>
        </div>
        <div class="ic-grid">
          <div class="r">
            <div class="k">REFERENCE</div>
            <div class="v">{pendingInvoice.reference}</div>
          </div>
          <div class="r">
            <div class="k">AMOUNT DUE</div>
            <div class="v amount">{sats(pendingInvoice.amount_sats)} sats</div>
          </div>
          <div class="r">
            <div class="k">SETTLES TO</div>
            <div class="v">{pendingInvoice.bolt11}</div>
          </div>
          <div class="r">
            <div class="k">EXPIRES IN</div>
            <div class="v amber">{pendingInvoice.expires_in}</div>
          </div>
          <div class="r">
            <div class="k">COVERS</div>
            <div class="v">{pendingInvoice.period}</div>
          </div>
        </div>
        <button class="open-breez">⚡ Open in Breez wallet →</button>
        <div class="ic-note">
          Or scan with any Lightning wallet. Tier upgrade applies within ~3 seconds of settlement.
        </div>
      </div>
    </div>
  </div>
</ScreenChrome>

<style>
  .bill-pad {
    padding: 40px 44px 48px;
  }
  .bill-h {
    display: grid;
    grid-template-columns: 1fr auto;
    align-items: end;
    gap: 24px;
    padding-bottom: 14px;
    margin-bottom: 36px;
    border-bottom: 1px solid var(--hair);
  }
  .bill-h h1 {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 38px;
    margin: 6px 0 6px;
    letter-spacing: -0.03em;
  }
  .bill-h h1 .accent {
    color: var(--amber);
  }
  .eyebrow.amber {
    color: var(--amber);
  }
  .lede {
    font-size: 14.5px;
    color: var(--muted-fg);
    max-width: 64ch;
  }
  .price-meta {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--muted-fg);
    text-align: right;
  }
  .price-meta b {
    color: var(--amber);
    font-size: 16px;
    font-weight: 600;
    display: inline-block;
    margin-bottom: 4px;
  }
  .price-meta .up {
    color: var(--secondary);
    margin-left: 6px;
  }

  .plans {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 16px;
    margin-bottom: 36px;
  }
  .plan {
    padding: 28px 26px;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--card);
    position: relative;
  }
  .plan.feat {
    border-color: var(--primary);
    background: linear-gradient(180deg, var(--primary-soft), var(--card) 60%);
    box-shadow: 0 10px 40px -10px var(--primary-glow);
  }
  .plan .nm {
    font-family: var(--font-mono);
    font-size: 11px;
    letter-spacing: 0.14em;
    color: var(--muted-fg);
    text-transform: uppercase;
  }
  .plan.feat .nm {
    color: var(--primary);
  }
  .plan .pr {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 42px;
    margin: 14px 0 0;
    letter-spacing: -0.03em;
  }
  .plan.feat .pr {
    color: var(--primary);
  }
  .plan .pr .u {
    font-family: var(--font-mono);
    font-size: 13px;
    color: var(--muted-fg);
    margin-left: 6px;
    font-weight: 400;
  }
  .plan .est {
    font-size: 12.5px;
    color: var(--muted-fg);
    margin: 4px 0 24px;
    font-family: var(--font-mono);
  }
  .plan ul {
    list-style: none;
    padding: 0;
    margin: 0 0 26px;
    font-size: 14px;
  }
  .plan ul li {
    padding: 9px 0;
    border-bottom: 1px solid var(--hair);
    display: grid;
    grid-template-columns: 20px 1fr;
    gap: 8px;
    align-items: baseline;
    color: var(--fg-2);
  }
  .plan ul li::before {
    content: '✓';
    color: var(--secondary);
    font-size: 13px;
  }
  .plan.feat ul li::before {
    color: var(--primary);
  }
  .plan .pick {
    width: 100%;
    padding: 12px;
    border-radius: var(--radius);
    background: hsla(0, 0%, 100%, 0.05);
    border: 1px solid var(--border);
    color: var(--fg);
    font: inherit;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
  }
  .plan .pick:hover {
    background: hsla(0, 0%, 100%, 0.08);
    border-color: var(--border-2);
  }
  .plan.feat .pick {
    background: var(--primary);
    color: var(--primary-fg);
    border-color: var(--primary);
  }
  .plan.feat .pick:hover {
    background: var(--fg);
    border-color: var(--fg);
    color: var(--primary-fg);
  }
  .plan .badge-feat {
    position: absolute;
    top: -10px;
    right: 20px;
    background: var(--primary);
    color: var(--primary-fg);
    font-family: var(--font-mono);
    font-size: 10px;
    font-weight: 600;
    padding: 4px 10px;
    border-radius: 999px;
    letter-spacing: 0.06em;
  }

  .invoice-card {
    display: grid;
    grid-template-columns: 280px 1fr;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
    background: var(--card);
  }
  .invoice-card .qr {
    padding: 32px;
    background: var(--amber-soft);
    border-right: 1px solid var(--hair);
    display: grid;
    place-items: center;
  }
  .qrart {
    width: 220px;
    height: 220px;
    padding: 12px;
    background: #fff;
    border-radius: var(--radius-md);
    box-shadow: 0 10px 30px -10px hsla(35, 90%, 55%, 0.5);
    background-image:
      linear-gradient(
        90deg,
        #0e0e0e 12%,
        transparent 12% 18%,
        #0e0e0e 18% 30%,
        transparent 30% 36%,
        #0e0e0e 36% 50%,
        transparent 50% 56%,
        #0e0e0e 56% 66%,
        transparent 66% 74%,
        #0e0e0e 74% 84%,
        transparent 84% 90%,
        #0e0e0e 90% 100%
      ),
      linear-gradient(
        0deg,
        #0e0e0e 12%,
        transparent 12% 20%,
        #0e0e0e 20% 32%,
        transparent 32% 38%,
        #0e0e0e 38% 50%,
        transparent 50% 56%,
        #0e0e0e 56% 70%,
        transparent 70% 76%,
        #0e0e0e 76% 88%,
        transparent 88% 100%
      );
    background-blend-mode: multiply;
    image-rendering: pixelated;
  }
  .invoice-card .body {
    padding: 28px 32px;
  }
  .ic-h {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 18px;
  }
  .ic-h .t {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 17px;
  }
  .ic-h .t .accent {
    color: var(--amber);
  }
  .ic-grid .r {
    display: grid;
    grid-template-columns: 160px 1fr;
    gap: 12px;
    padding: 11px 0;
    border-bottom: 1px solid var(--hair);
    font-size: 13.5px;
  }
  .ic-grid .r:last-of-type {
    border-bottom: 0;
  }
  .ic-grid .k {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--muted-fg);
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }
  .ic-grid .v {
    font-family: var(--font-mono);
    font-size: 13px;
    color: var(--fg);
  }
  .ic-grid .v.amount {
    font-family: var(--font-display);
    font-size: 22px;
    color: var(--amber);
    font-weight: 600;
    letter-spacing: -0.02em;
  }
  .ic-grid .v.amber {
    color: var(--amber);
  }
  .open-breez {
    margin-top: 20px;
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: var(--amber);
    color: hsl(35, 90%, 12%);
    border: 0;
    border-radius: var(--radius);
    padding: 13px 20px;
    font-family: var(--font-sans);
    font-weight: 600;
    font-size: 14px;
    cursor: pointer;
  }
  .open-breez:hover {
    background: var(--fg);
  }
  .ic-note {
    font-size: 12.5px;
    color: var(--muted-fg);
    margin-top: 16px;
  }
</style>
