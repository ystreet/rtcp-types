#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let compound = rtcp_types::Compound::parse(data);
    if let Ok(compound) = compound {
        for _packet in compound {
        }
    }
});
