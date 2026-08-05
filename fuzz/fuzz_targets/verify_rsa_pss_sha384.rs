#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 6 {
        return;
    }
    let payload = &data[4..];
    let modulus_end = data[0] as usize % (payload.len() + 1);
    let exponent_end = modulus_end + data[1] as usize % (payload.len() - modulus_end + 1);
    let message_end = exponent_end + data[2] as usize % (payload.len() - exponent_end + 1);
    let _ = enclava_verifier::verify_rsa_pss_sha384_for_fuzzing(
        &payload[..modulus_end],
        &payload[modulus_end..exponent_end],
        &payload[exponent_end..message_end],
        &payload[message_end..],
    );
});
