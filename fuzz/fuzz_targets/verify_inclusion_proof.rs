#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split the input into a JSON inclusion-proof object and a body; both
    // are fully attacker-controlled in a Rekor entry. Any panic here is a
    // verifier robustness bug (cap#141).
    if data.len() < 4 {
        return;
    }
    let split = data.len() / 2;
    let _ = enclava_verifier::verify_inclusion_proof_for_fuzzing(&data[..split], &data[split..]);
});
