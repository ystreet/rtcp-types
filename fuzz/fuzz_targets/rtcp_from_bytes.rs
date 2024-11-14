#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let compound = rtcp_types::Compound::parse(data);
    if let Ok(compound) = compound {
        for packet in compound {
            match packet {
                Ok(rtcp_types::Packet::Xr(xr)) => {
                    for block in xr.block_iter() {
                        let _ = block.parse_into::<rtcp_types::DelaySinceLastReceiverReport>();
                        let _ = block.parse_into::<rtcp_types::DuplicateRle>();
                        let _ = block.parse_into::<rtcp_types::LossRle>();
                        let _ = block.parse_into::<rtcp_types::PacketReceiptTimes>();
                        let _ = block.parse_into::<rtcp_types::ReceiverReferenceTime>();
                    }
                }
                _ => (),
            }
        }
    }
});
