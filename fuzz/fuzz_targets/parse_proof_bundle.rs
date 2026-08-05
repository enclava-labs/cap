#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = enclava_verifier::parse_proof_bundle(data);
});
