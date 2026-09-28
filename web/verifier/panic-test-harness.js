// Panic isolation on the real browser target (cap#141 review): a panic
// inside the wasm module (built for wasm32-unknown-unknown, whose panic
// strategy is abort) must surface as a *catchable* JS exception, and the
// instance must stay usable afterwards. This harness is only built and run
// in CI with the debug-panic-probe feature; the shipped release module
// exports no probe.
//
// External file, not an inline module: the page CSP allows scripts from
// 'self' only (matching the production verifier pages), which would block
// an inline module before it ever runs — exactly the failure mode the first
// version of this harness hit in CI (result stuck at RUNNING).
import init, { debug_panic_probe, debug_ping_probe } from './pkg/enclava_verifier_wasm.js';

const fail = (reason) => {
  document.querySelector('#result').textContent = `FAIL ${reason}`;
};

try {
  await init();
  let trapped = null;
  try {
    debug_panic_probe();
  } catch (error) {
    trapped = error;
  }
  if (!trapped) throw new Error('probe did not trap');
  if (!(trapped instanceof Error)) throw new Error('trap is not an Error');
  // The instance must still serve *normal* calls after the trap. Calling
  // the panicking probe again would prove nothing — it throws on a healthy
  // instance too — so a non-panicking export must return successfully;
  // a poisoned module would trap or return garbage (cap#168 review).
  const pong = debug_ping_probe(41);
  if (pong !== 42) throw new Error(`post-trap call returned ${pong}, expected 42`);
  // And the panic path itself must remain reproducible afterwards.
  let second = null;
  try {
    debug_panic_probe();
  } catch (error) {
    second = error;
  }
  if (!second) throw new Error('second probe did not trap');
  document.querySelector('#result').textContent = 'PASS panic-isolated';
} catch (error) {
  fail(error);
}
