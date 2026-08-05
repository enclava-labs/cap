#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = enclava_common::canonical::ce_v1_decode(data);
});
