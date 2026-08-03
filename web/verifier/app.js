import init, { verify_bundle } from './pkg/enclava_verifier_wasm.js';

const mediaType = 'application/vnd.enclava.proof-bundle.v1';
const form = document.querySelector('#verify-form');
const status = document.querySelector('#status');
const resultSection = document.querySelector('#result');
let lastBundle;

await init();

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  resultSection.hidden = true;
  status.textContent = 'Fetching fresh evidence…';
  try {
    const target = new URL(document.querySelector('#target').value);
    if (target.protocol !== 'https:' || target.origin + '/' !== target.href) throw new Error('Enter a bare HTTPS origin.');
    const nonce = crypto.getRandomValues(new Uint8Array(32));
    const encodedNonce = base64url(nonce);
    const response = await fetch(`${target.origin}/.well-known/confidential/proof-bundle?nonce=${encodedNonce}`, {
      headers: { Accept: mediaType }, credentials: 'omit', cache: 'no-store', redirect: 'error'
    });
    if (!response.ok || response.headers.get('content-type') !== mediaType) throw new Error(`Proof endpoint returned ${response.status}.`);
    lastBundle = new Uint8Array(await response.arrayBuffer());
    if (lastBundle.byteLength > 1048576) throw new Error('Proof bundle exceeds the v1 limit.');
    const policy = new Uint8Array(await document.querySelector('#policy').files[0].arrayBuffer());
    const appraisal = JSON.parse(verify_bundle(lastBundle, policy, JSON.stringify({
      challenge_nonce: hex(nonce), expected_target_origin: target.origin,
      now_unix_seconds: Math.floor(Date.now() / 1000), observed_channel_spki_sha256: null
    })));
    render(appraisal);
    status.textContent = 'Verification complete.';
  } catch (error) {
    status.textContent = `Verification could not complete: ${error.message}`;
  }
});

document.querySelector('#download').addEventListener('click', () => {
  if (!lastBundle) return;
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([lastBundle], { type: mediaType }));
  link.download = `enclava-proof-${Date.now()}.ce`;
  link.click();
  URL.revokeObjectURL(link.href);
});

function render(appraisal) {
  document.querySelector('#verdict').textContent = appraisal.verdict;
  document.querySelector('#verdict').dataset.verdict = appraisal.verdict;
  const checks = document.querySelector('#checks');
  checks.replaceChildren(...appraisal.checks.map((check) => {
    const row = document.createElement('tr');
    for (const value of [check.id, check.outcome, check.reason_code]) {
      const cell = document.createElement('td'); cell.textContent = value; row.append(cell);
    }
    return row;
  }));
  document.querySelector('#channel-warning').hidden = !appraisal.checks.some((check) =>
    check.id === 'transport.tls_channel_spki' && check.outcome === 'SKIPPED');
  resultSection.hidden = false;
}

function hex(bytes) { return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join(''); }
function base64url(bytes) {
  let binary = ''; for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}
