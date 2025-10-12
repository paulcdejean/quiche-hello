use crate::constants::MAX_DATAGRAM_SIZE;

// Maybe I'll want the http09 thing in the future?
#[allow(dead_code)]
pub mod alpns {
    pub const HTTP_09: [&[u8]; 2] = [b"hq-interop", b"http/0.9"];
    pub const HTTP_3: [&[u8]; 1] = [b"h3"];
}

pub fn example_config() -> quiche::Config {
    let mut config: quiche::Config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    config
        .load_cert_chain_from_pem_file("cert/cert.crt")
        .unwrap();
    config.load_priv_key_from_pem_file("cert/cert.key").unwrap();
    config
        .set_application_protos(&alpns::HTTP_3.to_vec())
        .unwrap();
    config.discover_pmtu(false);
    config.set_initial_rtt(std::time::Duration::from_millis(333));
    config.set_max_idle_timeout(30000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10000000);
    config.set_initial_max_stream_data_bidi_local(1000000);
    config.set_initial_max_stream_data_bidi_remote(1000000);
    config.set_initial_max_stream_data_uni(1000000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config.set_active_connection_id_limit(2);
    config.set_initial_congestion_window_packets(10);
    config.set_max_connection_window(25165824);
    config.set_max_stream_window(16777216);
    config.enable_pacing(false);

    config
}
