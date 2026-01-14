#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;

use abol_core::packet::Packet;

use abol_codegen::rfc2866::{AcctStatusType, Rfc2866Ext};

fuzz_target!(|data: &[u8]| {
    let bytes = Bytes::copy_from_slice(data);

    let secret: Arc<[u8]> = Arc::from(b"supersecretpassword".as_slice());

    if let Ok(packet) = Packet::parse_packet(bytes, secret) {
        let _ = packet.get_acct_status_type();
        let _ = packet.get_acct_terminate_cause();
        let _ = packet.get_acct_authentic();

        let _ = packet.get_acct_session_id();
        let _ = packet.get_acct_multi_session_id();

        let _ = packet.get_acct_input_octets();
        let _ = packet.get_acct_output_octets();
        let _ = packet.get_acct_session_time();
        let _ = packet.get_acct_delay_time();
        let _ = packet.get_acct_link_count();

        if let Some(status) = packet.get_acct_status_type() {
            let raw: u32 = status.into();
            let _ = AcctStatusType::from(raw);
        }
    }
});
