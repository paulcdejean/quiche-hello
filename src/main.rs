const MAX_BUF_SIZE: usize = 65507;
const MAX_DATAGRAM_SIZE: usize = 1350;

use log::{debug, error, info, trace, warn};
use ring::rand::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::io;
use std::io::prelude::*;
use std::net;
use std::rc::Rc;
use std::time::Duration;

use quiche::ConnectionId;
use quiche::h3::NameValue;
use quiche::h3::Priority;
use std::cmp;
use std::fmt::Write as _;
use std::path;

mod mint_token;
use mint_token::mint_token;

mod validate_token;
use validate_token::validate_token;

mod stdout_sink;
use stdout_sink::stdout_sink;

mod http_conn;
use http_conn::HttpConn;

mod partial_request;
use partial_request::PartialRequest;

mod partial_response;
use partial_response::PartialResponse;

mod make_resource_writer;
use make_resource_writer::make_resource_writer;

mod client;
use client::{Client, ClientIdMap, ClientMap};

fn main() {
    let mut buf: [u8; MAX_BUF_SIZE] = [0; MAX_BUF_SIZE];
    let mut out: [u8; MAX_BUF_SIZE] = [0; MAX_BUF_SIZE];
    let pacing: bool = false;

    env_logger::builder().format_timestamp_nanos().init();

    // Parse CLI parameters.
    let docopt: docopt::Docopt = docopt::Docopt::new(SERVER_USAGE).unwrap();
    let conn_args: CommonArgs = CommonArgs::with_docopt(&docopt);

    // Setup the event loop.
    let mut poll: mio::Poll = mio::Poll::new().unwrap();
    let mut events: mio::Events = mio::Events::with_capacity(1024);

    // Create the UDP listening socket, and register it with the event loop.
    let mut socket: mio::net::UdpSocket =
        mio::net::UdpSocket::bind("127.0.0.1:4433".parse().unwrap()).unwrap();

    info!("listening on {:}", socket.local_addr().unwrap());

    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    let max_datagram_size = MAX_DATAGRAM_SIZE;
    let enable_gso = false;

    // Create the configuration for the QUIC connections.
    let mut config: quiche::Config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    config
        .load_cert_chain_from_pem_file("cert/cert.crt")
        .unwrap();
    config.load_priv_key_from_pem_file("cert/cert.key").unwrap();

    config.set_application_protos(&conn_args.alpns).unwrap();

    config.discover_pmtu(false);
    config.set_initial_rtt(conn_args.initial_rtt);
    config.set_max_idle_timeout(conn_args.idle_timeout);
    config.set_max_recv_udp_payload_size(max_datagram_size);
    config.set_max_send_udp_payload_size(max_datagram_size);
    config.set_initial_max_data(conn_args.max_data);
    config.set_initial_max_stream_data_bidi_local(conn_args.max_stream_data);
    config.set_initial_max_stream_data_bidi_remote(conn_args.max_stream_data);
    config.set_initial_max_stream_data_uni(conn_args.max_stream_data);
    config.set_initial_max_streams_bidi(conn_args.max_streams_bidi);
    config.set_initial_max_streams_uni(conn_args.max_streams_uni);
    config.set_disable_active_migration(!conn_args.enable_active_migration);
    config.set_active_connection_id_limit(conn_args.max_active_cids);
    config.set_initial_congestion_window_packets(
        usize::try_from(conn_args.initial_cwnd_packets).unwrap(),
    );

    config.set_max_connection_window(conn_args.max_window);
    config.set_max_stream_window(conn_args.max_stream_window);

    config.enable_pacing(pacing);

    let mut keylog: Option<std::fs::File> = None;

    if conn_args.early_data {
        config.enable_early_data();
    }

    if conn_args.no_grease {
        config.grease(false);
    }

    config
        .set_cc_algorithm_name(&conn_args.cc_algorithm)
        .unwrap();

    if conn_args.disable_hystart {
        config.enable_hystart(false);
    }

    if conn_args.dgrams_enabled {
        config.enable_dgram(true, 1000, 1000);
    }

    let rng: SystemRandom = SystemRandom::new();
    let conn_id_seed: ring::hmac::Key =
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut next_client_id: u64 = 0;
    let mut clients_ids: HashMap<ConnectionId<'static>, u64> = ClientIdMap::new();
    let mut clients: HashMap<u64, Client> = ClientMap::new();

    let mut pkt_count: i32 = 0;

    let mut continue_write: bool = false;

    let local_addr: net::SocketAddr = socket.local_addr().unwrap();

    loop {
        // Find the shorter timeout from all the active connections.
        //
        // TODO: use event loop that properly supports timers
        let timeout = match continue_write {
            true => Some(std::time::Duration::from_secs(0)),

            false => clients.values().filter_map(|c| c.conn.timeout()).min(),
        };

        let mut poll_res: Result<(), io::Error> = poll.poll(&mut events, timeout);
        while let Err(e) = poll_res.as_ref() {
            if e.kind() == std::io::ErrorKind::Interrupted {
                trace!("mio poll() call failed, retrying: {e:?}");
                poll_res = poll.poll(&mut events, timeout);
            } else {
                panic!("mio poll() call failed fatally: {e:?}");
            }
        }

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() && !continue_write {
                trace!("timed out");

                clients.values_mut().for_each(|c| c.conn.on_timeout());

                break 'read;
            }

            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so end the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        trace!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {e:?}");
                }
            };

            trace!("got {len} bytes from {from} to {local_addr}");

            let pkt_buf = &mut buf[..len];

            if let Some(target_path) = conn_args.dump_packet_path.as_ref() {
                let path = format!("{target_path}/{pkt_count}.pkt");

                if let Ok(f) = std::fs::File::create(path) {
                    let mut f = std::io::BufWriter::new(f);
                    f.write_all(pkt_buf).ok();
                }
            }

            pkt_count += 1;

            // Parse the QUIC packet's header.
            let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                Ok(v) => v,

                Err(e) => {
                    error!("Parsing packet header failed: {e:?}");
                    continue 'read;
                }
            };

            trace!("got packet {hdr:?}");

            let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
            let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
            let conn_id: quiche::ConnectionId<'static> = conn_id.to_vec().into();

            // Lookup a connection based on the packet's connection ID. If there
            // is no connection matching, create a new one.
            let client = if !clients_ids.contains_key(&hdr.dcid)
                && !clients_ids.contains_key(&conn_id)
            {
                if hdr.ty != quiche::Type::Initial {
                    error!("Packet is not Initial");
                    continue 'read;
                }

                if !quiche::version_is_supported(hdr.version) {
                    warn!("Doing version negotiation");

                    let len = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out).unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, from) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            trace!("send() would block");
                            break;
                        }

                        panic!("send() failed: {e:?}");
                    }
                    continue 'read;
                }

                let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                scid.copy_from_slice(&conn_id);

                // Token is always present in Initial packets.
                let token = hdr.token.as_ref().unwrap();

                // Do stateless retry if the client didn't send a token.
                if token.is_empty() {
                    warn!("Doing stateless retry");

                    let scid = quiche::ConnectionId::from_ref(&scid);
                    let new_token = mint_token(&hdr, &from);

                    let len = quiche::retry(
                        &hdr.scid,
                        &hdr.dcid,
                        &scid,
                        &new_token,
                        hdr.version,
                        &mut out,
                    )
                    .unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, from) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            trace!("send() would block");
                            break;
                        }

                        panic!("send() failed: {e:?}");
                    }
                    continue 'read;
                }

                let odcid = validate_token(&from, token);

                // The token was not valid, meaning the retry failed, so
                // drop the packet.
                if odcid.is_none() {
                    error!("Invalid address validation token");
                    continue;
                }

                if scid.len() != hdr.dcid.len() {
                    error!("Invalid destination connection ID");
                    continue 'read;
                }

                // Reuse the source connection ID we sent in the Retry
                // packet, instead of changing it again.
                scid.copy_from_slice(&hdr.dcid);

                let scid = quiche::ConnectionId::from_vec(scid.to_vec());

                debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                #[allow(unused_mut)]
                let mut conn =
                    quiche::accept(&scid, odcid.as_ref(), local_addr, from, &mut config).unwrap();

                if let Some(keylog) = &mut keylog {
                    if let Ok(keylog) = keylog.try_clone() {
                        conn.set_keylog(Box::new(keylog));
                    }
                }

                let client_id = next_client_id;

                let client = Client {
                    conn,
                    http_conn: None,
                    client_id,
                    partial_requests: HashMap::new(),
                    partial_responses: HashMap::new(),
                    app_proto_selected: false,
                    max_datagram_size,
                    loss_rate: 0.0,
                    max_send_burst: MAX_BUF_SIZE,
                };

                clients.insert(client_id, client);
                clients_ids.insert(scid.clone(), client_id);

                next_client_id += 1;

                clients.get_mut(&client_id).unwrap()
            } else {
                let cid = match clients_ids.get(&hdr.dcid) {
                    Some(v) => v,

                    None => clients_ids.get(&conn_id).unwrap(),
                };

                clients.get_mut(cid).unwrap()
            };

            let recv_info = quiche::RecvInfo {
                to: local_addr,
                from,
            };

            // Process potentially coalesced packets.
            let read = match client.conn.recv(pkt_buf, recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                    continue 'read;
                }
            };

            trace!("{} processed {} bytes", client.conn.trace_id(), read);

            // Create a new application protocol session as soon as the QUIC
            // connection is established.
            if !client.app_proto_selected
                && (client.conn.is_in_early_data() || client.conn.is_established())
            {
                // At this stage the ALPN negotiation succeeded and selected a
                // single application protocol name. We'll use this to construct
                // the correct type of HttpConn but `application_proto()`
                // returns a slice, so we have to convert it to a str in order
                // to compare to our lists of protocols. We `unwrap()` because
                // we need the value and if something fails at this stage, there
                // is not much anyone can do to recover.
                let app_proto = client.conn.application_proto();

                #[allow(clippy::box_default)]
                if alpns::HTTP_09.contains(&app_proto) {
                    client.http_conn = Some(Box::<Http09Conn>::default());

                    client.app_proto_selected = true;
                } else if alpns::HTTP_3.contains(&app_proto) {
                    let dgram_sender = if conn_args.dgrams_enabled {
                        Some(Http3DgramSender::new(
                            conn_args.dgram_count,
                            conn_args.dgram_data.clone(),
                            1,
                        ))
                    } else {
                        None
                    };

                    client.http_conn = match Http3Conn::with_conn(
                        &mut client.conn,
                        conn_args.max_field_section_size,
                        conn_args.qpack_max_table_capacity,
                        conn_args.qpack_blocked_streams,
                        dgram_sender,
                        Rc::new(RefCell::new(stdout_sink)),
                    ) {
                        Ok(v) => Some(v),

                        Err(e) => {
                            trace!("{} {}", client.conn.trace_id(), e);
                            None
                        }
                    };

                    client.app_proto_selected = true;
                }

                // Update max_datagram_size after connection established.
                client.max_datagram_size = client.conn.max_send_udp_payload_size();
            }

            if client.http_conn.is_some() {
                let conn: &mut quiche::Connection = &mut client.conn;
                let http_conn: &mut Box<dyn HttpConn> = client.http_conn.as_mut().unwrap();
                let partial_responses: &mut HashMap<u64, PartialResponse> =
                    &mut client.partial_responses;

                // Visit all writable response streams to send any remaining HTTP
                // content.
                for stream_id in writable_response_streams(conn) {
                    http_conn.handle_writable(conn, partial_responses, stream_id);
                }

                if http_conn
                    .handle_requests(
                        conn,
                        &mut client.partial_requests,
                        partial_responses,
                        "webroot/",
                        "index.html",
                        &mut buf,
                    )
                    .is_err()
                {
                    continue 'read;
                }
            }

            handle_path_events(client);

            // See whether source Connection IDs have been retired.
            while let Some(retired_scid) = client.conn.retired_scid_next() {
                info!("Retiring source CID {retired_scid:?}");
                clients_ids.remove(&retired_scid);
            }

            // Provides as many CIDs as possible.
            while client.conn.scids_left() > 0 {
                let (scid, reset_token) = generate_cid_and_reset_token(&rng);
                if client.conn.new_scid(&scid, reset_token, false).is_err() {
                    break;
                }

                clients_ids.insert(scid, client.client_id);
            }
        }

        // Generate outgoing QUIC packets for all active connections and send
        // them on the UDP socket, until quiche reports that there are no more
        // packets to be sent.
        continue_write = false;
        for client in clients.values_mut() {
            // Reduce max_send_burst by 25% if loss is increasing more than 0.1%.
            let loss_rate = client.conn.stats().lost as f64 / client.conn.stats().sent as f64;
            if loss_rate > client.loss_rate + 0.001 {
                client.max_send_burst = client.max_send_burst / 4 * 3;
                // Minimum bound of 10xMSS.
                client.max_send_burst = client.max_send_burst.max(client.max_datagram_size * 10);
                client.loss_rate = loss_rate;
            }

            let max_send_burst = client.conn.send_quantum().min(client.max_send_burst)
                / client.max_datagram_size
                * client.max_datagram_size;
            let mut total_write = 0;
            let mut dst_info = None;

            while total_write < max_send_burst {
                let (write, send_info) =
                    match client.conn.send(&mut out[total_write..max_send_burst]) {
                        Ok(v) => v,

                        Err(quiche::Error::Done) => {
                            trace!("{} done writing", client.conn.trace_id());
                            break;
                        }

                        Err(e) => {
                            error!("{} send failed: {:?}", client.conn.trace_id(), e);

                            client.conn.close(false, 0x1, b"fail").ok();
                            break;
                        }
                    };

                total_write += write;

                // Use the first packet time to send, not the last.
                let _ = dst_info.get_or_insert(send_info);

                if write < client.max_datagram_size {
                    continue_write = true;
                    break;
                }
            }

            if total_write == 0 || dst_info.is_none() {
                continue;
            }

            if let Err(e) = send_to(
                &socket,
                &out[..total_write],
                &dst_info.unwrap(),
                client.max_datagram_size,
                pacing,
                enable_gso,
            ) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    trace!("send() would block");
                    break;
                }

                panic!("send_to() failed: {e:?}");
            }

            trace!(
                "{} written {total_write} bytes with {dst_info:?}",
                client.conn.trace_id()
            );

            if total_write >= max_send_burst {
                trace!("{} pause writing", client.conn.trace_id(),);
                continue_write = true;
                break;
            }
        }

        // Garbage collect closed connections.
        clients.retain(|_, ref mut c| {
            trace!("Collecting garbage");

            if c.conn.is_closed() {
                info!(
                    "{} connection collected {:?} {:?}",
                    c.conn.trace_id(),
                    c.conn.stats(),
                    c.conn.path_stats().collect::<Vec<quiche::PathStats>>()
                );

                for id in c.conn.source_ids() {
                    let id_owned = id.clone().into_owned();
                    clients_ids.remove(&id_owned);
                }
            }

            !c.conn.is_closed()
        });
    }
}

fn handle_path_events(client: &mut Client) {
    while let Some(qe) = client.conn.path_event_next() {
        match qe {
            quiche::PathEvent::New(local_addr, peer_addr) => {
                info!(
                    "{} Seen new path ({}, {})",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );

                // Directly probe the new path.
                client
                    .conn
                    .probe_path(local_addr, peer_addr)
                    .expect("cannot probe");
            }

            quiche::PathEvent::Validated(local_addr, peer_addr) => {
                info!(
                    "{} Path ({}, {}) is now validated",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            }

            quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                info!(
                    "{} Path ({}, {}) failed validation",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            }

            quiche::PathEvent::Closed(local_addr, peer_addr) => {
                info!(
                    "{} Path ({}, {}) is now closed and unusable",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            }

            quiche::PathEvent::ReusedSourceConnectionId(cid_seq, old, new) => {
                info!(
                    "{} Peer reused cid seq {} (initially {:?}) on {:?}",
                    client.conn.trace_id(),
                    cid_seq,
                    old,
                    new
                );
            }

            quiche::PathEvent::PeerMigrated(local_addr, peer_addr) => {
                info!(
                    "{} Connection migrated to ({}, {})",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            }
        }
    }
}

/// Contains commons arguments for creating a quiche QUIC connection.
pub struct CommonArgs {
    pub alpns: Vec<&'static [u8]>,
    pub max_data: u64,
    pub max_window: u64,
    pub max_stream_data: u64,
    pub max_stream_window: u64,
    pub max_streams_bidi: u64,
    pub max_streams_uni: u64,
    pub idle_timeout: u64,
    pub early_data: bool,
    pub dump_packet_path: Option<String>,
    pub no_grease: bool,
    pub cc_algorithm: String,
    pub disable_hystart: bool,
    pub dgrams_enabled: bool,
    pub dgram_count: u64,
    pub dgram_data: String,
    pub max_active_cids: u64,
    pub enable_active_migration: bool,
    pub max_field_section_size: Option<u64>,
    pub qpack_max_table_capacity: Option<u64>,
    pub qpack_blocked_streams: Option<u64>,
    pub initial_rtt: Duration,
    pub initial_cwnd_packets: u64,
}

/// Creates a new `CommonArgs` structure using the provided [`Docopt`].
///
/// The `Docopt` usage String needs to include the following:
///
/// --http-version VERSION      HTTP version to use.
/// --max-data BYTES            Connection-wide flow control limit.
/// --max-window BYTES          Connection-wide max receiver window.
/// --max-stream-data BYTES     Per-stream flow control limit.
/// --max-stream-window BYTES   Per-stream max receiver window.
/// --max-streams-bidi STREAMS  Number of allowed concurrent streams.
/// --max-streams-uni STREAMS   Number of allowed concurrent streams.
/// --dump-packets PATH         Dump the incoming packets in PATH.
/// --no-grease                 Don't send GREASE.
/// --cc-algorithm NAME         Set a congestion control algorithm.
/// --disable-hystart           Disable HyStart++.
/// --dgram-proto PROTO         DATAGRAM application protocol.
/// --dgram-count COUNT         Number of DATAGRAMs to send.
/// --dgram-data DATA           DATAGRAM data to send.
/// --max-active-cids NUM       Maximum number of active Connection IDs.
/// --enable-active-migration   Enable active connection migration.
/// --max-field-section-size BYTES  Max size of uncompressed field section.
/// --qpack-max-table-capacity BYTES  Max capacity of dynamic QPACK decoding.
/// --qpack-blocked-streams STREAMS  Limit of blocked streams while decoding.
/// --initial-cwnd-packets      Size of initial congestion window, in packets.
///
/// [`Docopt`]: https://docs.rs/docopt/1.1.0/docopt/
impl CommonArgs {
    fn with_docopt(docopt: &docopt::Docopt) -> Self {
        let args = docopt.parse().unwrap_or_else(|e| e.exit());

        let http_version = args.get_str("--http-version");
        let dgram_proto = args.get_str("--dgram-proto");
        let (alpns, dgrams_enabled) = match (http_version, dgram_proto) {
            ("HTTP/0.9", "none") => (alpns::HTTP_09.to_vec(), false),

            ("HTTP/0.9", _) => {
                panic!("Unsupported HTTP version and DATAGRAM protocol.")
            }

            ("HTTP/3", "none") => (alpns::HTTP_3.to_vec(), false),

            ("HTTP/3", "oneway") => (alpns::HTTP_3.to_vec(), true),

            ("all", "none") => (
                [alpns::HTTP_3.as_slice(), &alpns::HTTP_09]
                    .concat()
                    .to_vec(),
                false,
            ),

            (..) => panic!("Unsupported HTTP version and DATAGRAM protocol."),
        };

        let dgram_count = args.get_str("--dgram-count");
        let dgram_count = dgram_count.parse::<u64>().unwrap();

        let dgram_data = args.get_str("--dgram-data").to_string();

        let max_data = args.get_str("--max-data");
        let max_data = max_data.parse::<u64>().unwrap();

        let max_window = args.get_str("--max-window");
        let max_window = max_window.parse::<u64>().unwrap();

        let max_stream_data = args.get_str("--max-stream-data");
        let max_stream_data = max_stream_data.parse::<u64>().unwrap();

        let max_stream_window = args.get_str("--max-stream-window");
        let max_stream_window = max_stream_window.parse::<u64>().unwrap();

        let max_streams_bidi = args.get_str("--max-streams-bidi");
        let max_streams_bidi = max_streams_bidi.parse::<u64>().unwrap();

        let max_streams_uni = args.get_str("--max-streams-uni");
        let max_streams_uni = max_streams_uni.parse::<u64>().unwrap();

        let idle_timeout = args.get_str("--idle-timeout");
        let idle_timeout = idle_timeout.parse::<u64>().unwrap();

        let early_data = args.get_bool("--early-data");

        let dump_packet_path = if !args.get_str("--dump-packets").is_empty() {
            Some(args.get_str("--dump-packets").to_string())
        } else {
            None
        };

        let no_grease = args.get_bool("--no-grease");

        let cc_algorithm = args.get_str("--cc-algorithm");

        let disable_hystart = args.get_bool("--disable-hystart");

        let max_active_cids = args.get_str("--max-active-cids");
        let max_active_cids = max_active_cids.parse::<u64>().unwrap();

        let enable_active_migration = args.get_bool("--enable-active-migration");

        let max_field_section_size = if !args.get_str("--max-field-section-size").is_empty() {
            Some(
                args.get_str("--max-field-section-size")
                    .parse::<u64>()
                    .unwrap(),
            )
        } else {
            None
        };

        let qpack_max_table_capacity = if !args.get_str("--qpack-max-table-capacity").is_empty() {
            Some(
                args.get_str("--qpack-max-table-capacity")
                    .parse::<u64>()
                    .unwrap(),
            )
        } else {
            None
        };

        let qpack_blocked_streams = if !args.get_str("--qpack-blocked-streams").is_empty() {
            Some(
                args.get_str("--qpack-blocked-streams")
                    .parse::<u64>()
                    .unwrap(),
            )
        } else {
            None
        };

        let initial_rtt_millis = args.get_str("--initial-rtt").parse::<u64>().unwrap();
        let initial_rtt = Duration::from_millis(initial_rtt_millis);

        let initial_cwnd_packets = args
            .get_str("--initial-cwnd-packets")
            .parse::<u64>()
            .unwrap();

        CommonArgs {
            alpns,
            max_data,
            max_window,
            max_stream_data,
            max_stream_window,
            max_streams_bidi,
            max_streams_uni,
            idle_timeout,
            early_data,
            dump_packet_path,
            no_grease,
            cc_algorithm: cc_algorithm.to_string(),
            disable_hystart,
            dgrams_enabled,
            dgram_count,
            dgram_data,
            max_active_cids,
            enable_active_migration,
            max_field_section_size,
            qpack_max_table_capacity,
            qpack_blocked_streams,
            initial_rtt,
            initial_cwnd_packets,
        }
    }
}

impl Default for CommonArgs {
    fn default() -> Self {
        CommonArgs {
            alpns: alpns::HTTP_3.to_vec(),
            max_data: 10000000,
            max_window: 25165824,
            max_stream_data: 1000000,
            max_stream_window: 16777216,
            max_streams_bidi: 100,
            max_streams_uni: 100,
            idle_timeout: 30000,
            early_data: false,
            dump_packet_path: None,
            no_grease: false,
            cc_algorithm: "cubic".to_string(),
            disable_hystart: false,
            dgrams_enabled: false,
            dgram_count: 0,
            dgram_data: "quack".to_string(),
            max_active_cids: 2,
            enable_active_migration: false,
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            initial_rtt: Duration::from_millis(333),
            initial_cwnd_packets: 10,
        }
    }
}

/// Application-specific arguments that compliment the `CommonArgs`.

pub const SERVER_USAGE: &str = "Usage:
  quiche-server [options]
  quiche-server -h | --help

Options:
  --listen <addr>             Listen on the given IP:port [default: 127.0.0.1:4433]
  --cert <file>               TLS certificate path [default: cert/cert.crt]
  --key <file>                TLS certificate key path [default: cert/cert.key]
  --root <dir>                Root directory [default: webroot/]
  --index <name>              The file that will be used as index [default: index.html].
  --name <str>                Name of the server [default: quic.tech]
  --max-data BYTES            Connection-wide flow control limit [default: 10000000].
  --max-window BYTES          Connection-wide max receiver window [default: 25165824].
  --max-stream-data BYTES     Per-stream flow control limit [default: 1000000].
  --max-stream-window BYTES   Per-stream max receiver window [default: 16777216].
  --max-streams-bidi STREAMS  Number of allowed concurrent streams [default: 100].
  --max-streams-uni STREAMS   Number of allowed concurrent streams [default: 100].
  --idle-timeout TIMEOUT      Idle timeout in milliseconds [default: 30000].
  --dump-packets PATH         Dump the incoming packets as files in the given directory.
  --early-data                Enable receiving early data.
  --no-retry                  Disable stateless retry.
  --no-grease                 Don't send GREASE.
  --http-version VERSION      HTTP version to use [default: all].
  --dgram-proto PROTO         DATAGRAM application protocol to use [default: none].
  --dgram-count COUNT         Number of DATAGRAMs to send [default: 0].
  --dgram-data DATA           Data to send for certain types of DATAGRAM application protocol [default: brrr].
  --cc-algorithm NAME         Specify which congestion control algorithm to use [default: cubic].
  --disable-hystart           Disable HyStart++.
  --max-active-cids NUM       The maximum number of active Connection IDs we can support [default: 2].
  --enable-active-migration   Enable active connection migration.
  --max-field-section-size BYTES    Max size of uncompressed HTTP/3 field section. Default is unlimited.
  --qpack-max-table-capacity BYTES  Max capacity of QPACK dynamic table decoding. Any value other that 0 is currently unsupported.
  --qpack-blocked-streams STREAMS   Limit of streams that can be blocked while decoding. Any value other that 0 is currently unsupported.
  --initial-rtt MILLIS     The initial RTT in milliseconds [default: 333].
  --initial-cwnd-packets PACKETS      The initial congestion window size in terms of packet count [default: 10].
  -h --help                   Show this screen.
";

const H3_MESSAGE_ERROR: u64 = 0x10E;

/// ALPN helpers.
///
/// This module contains constants and functions for working with ALPN.
pub mod alpns {
    pub const HTTP_09: [&[u8]; 2] = [b"hq-interop", b"http/0.9"];
    pub const HTTP_3: [&[u8]; 1] = [b"h3"];
}

fn autoindex(path: path::PathBuf, index: &str) -> path::PathBuf {
    if let Some(path_str) = path.to_str() {
        if path_str.ends_with('/') {
            let path_str = format!("{path_str}{index}");
            return path::PathBuf::from(&path_str);
        }
    }

    path
}

fn dump_json(reqs: &[Http3Request], output_sink: &mut dyn FnMut(String)) {
    let mut out = String::new();

    writeln!(out, "{{").unwrap();
    writeln!(out, "  \"entries\": [").unwrap();
    let mut reqs = reqs.iter().peekable();

    while let Some(req) = reqs.next() {
        writeln!(out, "  {{").unwrap();
        writeln!(out, "    \"request\":{{").unwrap();
        writeln!(out, "      \"headers\":[").unwrap();

        let mut req_hdrs = req.hdrs.iter().peekable();
        while let Some(h) = req_hdrs.next() {
            writeln!(out, "        {{").unwrap();
            writeln!(
                out,
                "          \"name\": \"{}\",",
                std::str::from_utf8(h.name()).unwrap()
            )
            .unwrap();
            writeln!(
                out,
                "          \"value\": \"{}\"",
                std::str::from_utf8(h.value()).unwrap().replace('"', "\\\"")
            )
            .unwrap();

            if req_hdrs.peek().is_some() {
                writeln!(out, "        }},").unwrap();
            } else {
                writeln!(out, "        }}").unwrap();
            }
        }
        writeln!(out, "      ]}},").unwrap();

        writeln!(out, "    \"response\":{{").unwrap();
        writeln!(out, "      \"headers\":[").unwrap();

        let mut response_hdrs = req.response_hdrs.iter().peekable();
        while let Some(h) = response_hdrs.next() {
            writeln!(out, "        {{").unwrap();
            writeln!(
                out,
                "          \"name\": \"{}\",",
                std::str::from_utf8(h.name()).unwrap()
            )
            .unwrap();
            writeln!(
                out,
                "          \"value\": \"{}\"",
                std::str::from_utf8(h.value()).unwrap().replace('"', "\\\"")
            )
            .unwrap();

            if response_hdrs.peek().is_some() {
                writeln!(out, "        }},").unwrap();
            } else {
                writeln!(out, "        }}").unwrap();
            }
        }
        writeln!(out, "      ],").unwrap();
        writeln!(out, "      \"body\": {:?}", req.response_body).unwrap();
        writeln!(out, "    }}").unwrap();

        if reqs.peek().is_some() {
            writeln!(out, "}},").unwrap();
        } else {
            writeln!(out, "}}").unwrap();
        }
    }
    writeln!(out, "]").unwrap();
    writeln!(out, "}}").unwrap();

    output_sink(out);
}

pub fn hdrs_to_strings(hdrs: &[quiche::h3::Header]) -> Vec<(String, String)> {
    hdrs.iter()
        .map(|h| {
            let name = String::from_utf8_lossy(h.name()).to_string();
            let value = String::from_utf8_lossy(h.value()).to_string();

            (name, value)
        })
        .collect()
}

/// Generate a new pair of Source Connection ID and reset token.
pub fn generate_cid_and_reset_token<T: SecureRandom>(
    rng: &T,
) -> (quiche::ConnectionId<'static>, u128) {
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    rng.fill(&mut scid).unwrap();
    let scid = scid.to_vec().into();
    let mut reset_token = [0; 16];
    rng.fill(&mut reset_token).unwrap();
    let reset_token = u128::from_be_bytes(reset_token);
    (scid, reset_token)
}

/// Construct a priority field value from quiche apps custom query string.
pub fn priority_field_value_from_query_string(url: &url::Url) -> Option<String> {
    let mut priority = "".to_string();
    for param in url.query_pairs() {
        if param.0 == "u" {
            write!(priority, "{}={},", param.0, param.1).ok();
        }

        if param.0 == "i" && param.1 == "1" {
            priority.push_str("i,");
        }
    }

    if !priority.is_empty() {
        // remove trailing comma
        priority.pop();

        Some(priority)
    } else {
        None
    }
}

/// Construct a Priority from quiche apps custom query string.
pub fn priority_from_query_string(url: &url::Url) -> Option<Priority> {
    let mut urgency = None;
    let mut incremental = None;
    for param in url.query_pairs() {
        if param.0 == "u" {
            urgency = Some(param.1.parse::<u8>().unwrap());
        }

        if param.0 == "i" && param.1 == "1" {
            incremental = Some(true);
        }
    }

    match (urgency, incremental) {
        (Some(u), Some(i)) => Some(Priority::new(u, i)),

        (Some(u), None) => Some(Priority::new(u, false)),

        (None, Some(i)) => Some(Priority::new(3, i)),

        (None, None) => None,
    }
}

fn send_h3_dgram(
    conn: &mut quiche::Connection,
    flow_id: u64,
    dgram_content: &[u8],
) -> quiche::Result<()> {
    info!("sending HTTP/3 DATAGRAM on flow_id={flow_id} with data {dgram_content:?}");

    let len = octets::varint_len(flow_id) + dgram_content.len();
    let mut d = vec![0; len];
    let mut b = octets::OctetsMut::with_slice(&mut d);

    b.put_varint(flow_id)
        .map_err(|_| quiche::Error::BufferTooShort)?;
    b.put_bytes(dgram_content)
        .map_err(|_| quiche::Error::BufferTooShort)?;

    conn.dgram_send(&d)
}

pub fn writable_response_streams(conn: &quiche::Connection) -> impl Iterator<Item = u64> + use<> {
    conn.writable().filter(|id| id % 4 == 0)
}

/// Represents an HTTP/0.9 formatted request.
pub struct Http09Request {
    url: url::Url,
    cardinal: u64,
    request_line: String,
    stream_id: Option<u64>,
    response_writer: Option<std::io::BufWriter<std::fs::File>>,
}

/// Represents an HTTP/3 formatted request.
struct Http3Request {
    url: url::Url,
    cardinal: u64,
    stream_id: Option<u64>,
    hdrs: Vec<quiche::h3::Header>,
    priority: Option<Priority>,
    response_hdrs: Vec<quiche::h3::Header>,
    response_body: Vec<u8>,
    response_body_max: usize,
    response_writer: Option<std::io::BufWriter<std::fs::File>>,
}

type Http3ResponseBuilderResult =
    std::result::Result<(Vec<quiche::h3::Header>, Vec<u8>, Vec<u8>), (u64, String)>;

pub struct Http09Conn {
    stream_id: u64,
    reqs_sent: usize,
    reqs_complete: usize,
    reqs: Vec<Http09Request>,
    output_sink: Rc<RefCell<dyn FnMut(String)>>,
}

impl Default for Http09Conn {
    fn default() -> Self {
        Http09Conn {
            stream_id: Default::default(),
            reqs_sent: Default::default(),
            reqs_complete: Default::default(),
            reqs: Default::default(),
            output_sink: Rc::new(RefCell::new(stdout_sink)),
        }
    }
}

impl Http09Conn {
    pub fn with_urls(
        urls: &[url::Url],
        reqs_cardinal: u64,
        output_sink: Rc<RefCell<dyn FnMut(String)>>,
    ) -> Box<dyn HttpConn> {
        let mut reqs = Vec::new();
        for url in urls {
            for i in 1..=reqs_cardinal {
                let request_line = format!("GET {}\r\n", url.path());
                reqs.push(Http09Request {
                    url: url.clone(),
                    cardinal: i,
                    request_line,
                    stream_id: None,
                    response_writer: None,
                });
            }
        }

        let h_conn = Http09Conn {
            stream_id: 0,
            reqs_sent: 0,
            reqs_complete: 0,
            reqs,
            output_sink,
        };

        Box::new(h_conn)
    }
}

impl HttpConn for Http09Conn {
    fn send_requests(&mut self, conn: &mut quiche::Connection, target_path: &Option<String>) {
        let mut reqs_done = 0;

        for req in self.reqs.iter_mut().skip(self.reqs_sent) {
            match conn.stream_send(self.stream_id, req.request_line.as_bytes(), true) {
                Ok(v) => v,

                Err(quiche::Error::StreamLimit) => {
                    debug!("not enough stream credits, retry later...");
                    break;
                }

                Err(e) => {
                    error!("failed to send request {e:?}");
                    break;
                }
            };

            debug!("sending HTTP request {:?}", req.request_line);

            req.stream_id = Some(self.stream_id);
            req.response_writer = make_resource_writer(&req.url, target_path, req.cardinal);

            self.stream_id += 4;

            reqs_done += 1;
        }

        self.reqs_sent += reqs_done;
    }

    fn handle_responses(
        &mut self,
        conn: &mut quiche::Connection,
        buf: &mut [u8],
        req_start: &std::time::Instant,
    ) {
        // Process all readable streams.
        for s in conn.readable() {
            while let Ok((read, fin)) = conn.stream_recv(s, buf) {
                trace!("received {read} bytes");

                let stream_buf = &buf[..read];

                trace!("stream {} has {} bytes (fin? {})", s, stream_buf.len(), fin);

                let req = self
                    .reqs
                    .iter_mut()
                    .find(|r| r.stream_id == Some(s))
                    .unwrap();

                match &mut req.response_writer {
                    Some(rw) => {
                        rw.write_all(&buf[..read]).ok();
                    }

                    None => {
                        self.output_sink.borrow_mut()(unsafe {
                            String::from_utf8_unchecked(stream_buf.to_vec())
                        });
                    }
                }

                // The server reported that it has no more data to send on
                // a client-initiated
                // bidirectional stream, which means
                // we got the full response. If all responses are received
                // then close the connection.
                if &s % 4 == 0 && fin {
                    self.reqs_complete += 1;
                    let reqs_count = self.reqs.len();

                    debug!("{}/{} responses received", self.reqs_complete, reqs_count);

                    if self.reqs_complete == reqs_count {
                        info!(
                            "{}/{} response(s) received in {:?}, closing...",
                            self.reqs_complete,
                            reqs_count,
                            req_start.elapsed()
                        );

                        match conn.close(true, 0x00, b"kthxbye") {
                            // Already closed.
                            Ok(_) | Err(quiche::Error::Done) => (),

                            Err(e) => panic!("error closing conn: {e:?}"),
                        }

                        break;
                    }
                }
            }
        }
    }

    fn report_incomplete(&self, start: &std::time::Instant) -> bool {
        if self.reqs_complete != self.reqs.len() {
            error!(
                "connection timed out after {:?} and only completed {}/{} requests",
                start.elapsed(),
                self.reqs_complete,
                self.reqs.len()
            );

            return true;
        }

        false
    }

    fn handle_requests(
        &mut self,
        conn: &mut quiche::Connection,
        partial_requests: &mut HashMap<u64, PartialRequest>,
        partial_responses: &mut HashMap<u64, PartialResponse>,
        root: &str,
        index: &str,
        buf: &mut [u8],
    ) -> quiche::h3::Result<()> {
        // Process all readable streams.
        for s in conn.readable() {
            while let Ok((read, fin)) = conn.stream_recv(s, buf) {
                trace!("{} received {} bytes", conn.trace_id(), read);

                let stream_buf = &buf[..read];

                trace!(
                    "{} stream {} has {} bytes (fin? {})",
                    conn.trace_id(),
                    s,
                    stream_buf.len(),
                    fin
                );

                let stream_buf = if let Some(partial) = partial_requests.get_mut(&s) {
                    partial.req.extend_from_slice(stream_buf);

                    if !partial.req.ends_with(b"\r\n") {
                        return Ok(());
                    }

                    &partial.req
                } else {
                    if !stream_buf.ends_with(b"\r\n") {
                        let request = PartialRequest {
                            req: stream_buf.to_vec(),
                        };

                        partial_requests.insert(s, request);
                        return Ok(());
                    }

                    stream_buf
                };

                if stream_buf.starts_with(b"GET ") {
                    let uri = &stream_buf[4..stream_buf.len() - 2];
                    let uri = String::from_utf8(uri.to_vec()).unwrap();
                    let uri = String::from(uri.lines().next().unwrap());
                    let uri = path::Path::new(&uri);
                    let mut path = path::PathBuf::from(root);

                    partial_requests.remove(&s);

                    for c in uri.components() {
                        if let path::Component::Normal(v) = c {
                            path.push(v)
                        }
                    }

                    path = autoindex(path, index);

                    info!(
                        "{} got GET request for {:?} on stream {}",
                        conn.trace_id(),
                        path,
                        s
                    );

                    let body = std::fs::read(path.as_path())
                        .unwrap_or_else(|_| b"Not Found!\r\n".to_vec());

                    info!(
                        "{} sending response of size {} on stream {}",
                        conn.trace_id(),
                        body.len(),
                        s
                    );

                    let written = match conn.stream_send(s, &body, true) {
                        Ok(v) => v,

                        Err(quiche::Error::Done) => 0,

                        Err(e) => {
                            error!("{} stream send failed {:?}", conn.trace_id(), e);
                            return Err(From::from(e));
                        }
                    };

                    if written < body.len() {
                        let response = PartialResponse {
                            headers: None,
                            priority: None,
                            body,
                            written,
                        };

                        partial_responses.insert(s, response);
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_writable(
        &mut self,
        conn: &mut quiche::Connection,
        partial_responses: &mut HashMap<u64, PartialResponse>,
        stream_id: u64,
    ) {
        debug!(
            "{} response stream {} is writable with capacity {:?}",
            conn.trace_id(),
            stream_id,
            conn.stream_capacity(stream_id)
        );

        if !partial_responses.contains_key(&stream_id) {
            return;
        }

        let resp = partial_responses.get_mut(&stream_id).unwrap();
        let body = &resp.body[resp.written..];

        let written = match conn.stream_send(stream_id, body, true) {
            Ok(v) => v,

            Err(quiche::Error::Done) => 0,

            Err(e) => {
                partial_responses.remove(&stream_id);

                error!("{} stream send failed {:?}", conn.trace_id(), e);
                return;
            }
        };

        resp.written += written;

        if resp.written == resp.body.len() {
            partial_responses.remove(&stream_id);
        }
    }
}

pub struct Http3DgramSender {
    dgram_count: u64,
    pub dgram_content: String,
    pub flow_id: u64,
    pub dgrams_sent: u64,
}

impl Http3DgramSender {
    pub fn new(dgram_count: u64, dgram_content: String, flow_id: u64) -> Self {
        Self {
            dgram_count,
            dgram_content,
            flow_id,
            dgrams_sent: 0,
        }
    }
}

fn make_h3_config(
    max_field_section_size: Option<u64>,
    qpack_max_table_capacity: Option<u64>,
    qpack_blocked_streams: Option<u64>,
) -> quiche::h3::Config {
    let mut config = quiche::h3::Config::new().unwrap();

    if let Some(v) = max_field_section_size {
        config.set_max_field_section_size(v);
    }

    if let Some(v) = qpack_max_table_capacity {
        // quiche doesn't support dynamic QPACK, so clamp to 0 for now.
        config.set_qpack_max_table_capacity(v.clamp(0, 0));
    }

    if let Some(v) = qpack_blocked_streams {
        // quiche doesn't support dynamic QPACK, so clamp to 0 for now.
        config.set_qpack_blocked_streams(v.clamp(0, 0));
    }

    config
}

pub struct Http3Conn {
    h3_conn: quiche::h3::Connection,
    reqs_hdrs_sent: usize,
    reqs_complete: usize,
    largest_processed_request: u64,
    reqs: Vec<Http3Request>,
    body: Option<Vec<u8>>,
    sent_body_bytes: HashMap<u64, usize>,
    dump_json: bool,
    dgram_sender: Option<Http3DgramSender>,
    output_sink: Rc<RefCell<dyn FnMut(String)>>,
}

impl Http3Conn {
    #[allow(clippy::too_many_arguments)]
    pub fn with_urls(
        conn: &mut quiche::Connection,
        urls: &[url::Url],
        reqs_cardinal: u64,
        req_headers: &[String],
        body: &Option<Vec<u8>>,
        method: &str,
        send_priority_update: bool,
        max_field_section_size: Option<u64>,
        qpack_max_table_capacity: Option<u64>,
        qpack_blocked_streams: Option<u64>,
        dump_json: Option<usize>,
        dgram_sender: Option<Http3DgramSender>,
        output_sink: Rc<RefCell<dyn FnMut(String)>>,
    ) -> Box<dyn HttpConn> {
        let mut reqs = Vec::new();
        for url in urls {
            for i in 1..=reqs_cardinal {
                let authority = match url.port() {
                    Some(port) => format!("{}:{}", url.host_str().unwrap(), port),

                    None => url.host_str().unwrap().to_string(),
                };

                let mut hdrs = vec![
                    quiche::h3::Header::new(b":method", method.as_bytes()),
                    quiche::h3::Header::new(b":scheme", url.scheme().as_bytes()),
                    quiche::h3::Header::new(b":authority", authority.as_bytes()),
                    quiche::h3::Header::new(b":path", url[url::Position::BeforePath..].as_bytes()),
                    quiche::h3::Header::new(b"user-agent", b"quiche"),
                ];

                let priority = if send_priority_update {
                    priority_from_query_string(url)
                } else {
                    None
                };

                // Add custom headers to the request.
                for header in req_headers {
                    let header_split: Vec<&str> = header.splitn(2, ": ").collect();

                    if header_split.len() != 2 {
                        panic!("malformed header provided - \"{header}\"");
                    }

                    hdrs.push(quiche::h3::Header::new(
                        header_split[0].as_bytes(),
                        header_split[1].as_bytes(),
                    ));
                }

                if body.is_some() {
                    hdrs.push(quiche::h3::Header::new(
                        b"content-length",
                        body.as_ref().unwrap().len().to_string().as_bytes(),
                    ));
                }

                reqs.push(Http3Request {
                    url: url.clone(),
                    cardinal: i,
                    hdrs,
                    priority,
                    response_hdrs: Vec::new(),
                    response_body: Vec::new(),
                    response_body_max: dump_json.unwrap_or_default(),
                    stream_id: None,
                    response_writer: None,
                });
            }
        }

        let h_conn = Http3Conn {
            h3_conn: quiche::h3::Connection::with_transport(
                conn,
                &make_h3_config(
                    max_field_section_size,
                    qpack_max_table_capacity,
                    qpack_blocked_streams,
                ),
            ).expect("Unable to create HTTP/3 connection, check the server's uni stream limit and window size"),
            reqs_hdrs_sent: 0,
            reqs_complete: 0,
            largest_processed_request: 0,
            reqs,
            body: body.as_ref().map(|b| b.to_vec()),
            sent_body_bytes: HashMap::new(),
            dump_json: dump_json.is_some(),
            dgram_sender,
            output_sink,
        };

        Box::new(h_conn)
    }

    pub fn with_conn(
        conn: &mut quiche::Connection,
        max_field_section_size: Option<u64>,
        qpack_max_table_capacity: Option<u64>,
        qpack_blocked_streams: Option<u64>,
        dgram_sender: Option<Http3DgramSender>,
        output_sink: Rc<RefCell<dyn FnMut(String)>>,
    ) -> std::result::Result<Box<dyn HttpConn>, String> {
        let h3_conn = quiche::h3::Connection::with_transport(
            conn,
            &make_h3_config(
                max_field_section_size,
                qpack_max_table_capacity,
                qpack_blocked_streams,
            ),
        ).map_err(|_| "Unable to create HTTP/3 connection, check the client's uni stream limit and window size")?;

        let h_conn = Http3Conn {
            h3_conn,
            reqs_hdrs_sent: 0,
            reqs_complete: 0,
            largest_processed_request: 0,
            reqs: Vec::new(),
            body: None,
            sent_body_bytes: HashMap::new(),
            dump_json: false,
            dgram_sender,
            output_sink,
        };

        Ok(Box::new(h_conn))
    }

    /// Builds an HTTP/3 response given a request.
    fn build_h3_response(
        root: &str,
        index: &str,
        request: &[quiche::h3::Header],
    ) -> Http3ResponseBuilderResult {
        let mut file_path = path::PathBuf::from(root);
        let mut scheme = None;
        let mut authority = None;
        let mut host = None;
        let mut path = None;
        let mut method = None;
        let mut priority = vec![];

        // Parse some of the request headers.
        for hdr in request {
            match hdr.name() {
                b":scheme" => {
                    if scheme.is_some() {
                        return Err((H3_MESSAGE_ERROR, ":scheme cannot be duplicated".to_string()));
                    }

                    scheme = Some(std::str::from_utf8(hdr.value()).unwrap());
                }

                b":authority" => {
                    if authority.is_some() {
                        return Err((
                            H3_MESSAGE_ERROR,
                            ":authority cannot be duplicated".to_string(),
                        ));
                    }

                    authority = Some(std::str::from_utf8(hdr.value()).unwrap());
                }

                b":path" => {
                    if path.is_some() {
                        return Err((H3_MESSAGE_ERROR, ":path cannot be duplicated".to_string()));
                    }

                    path = Some(std::str::from_utf8(hdr.value()).unwrap())
                }

                b":method" => {
                    if method.is_some() {
                        return Err((H3_MESSAGE_ERROR, ":method cannot be duplicated".to_string()));
                    }

                    method = Some(std::str::from_utf8(hdr.value()).unwrap())
                }

                b":protocol" => {
                    return Err((H3_MESSAGE_ERROR, ":protocol not supported".to_string()));
                }

                b"priority" => priority = hdr.value().to_vec(),

                b"host" => host = Some(std::str::from_utf8(hdr.value()).unwrap()),

                _ => (),
            }
        }

        let decided_method = match method {
            Some(method) => {
                match method {
                    "" => {
                        return Err((
                            H3_MESSAGE_ERROR,
                            ":method value cannot be empty".to_string(),
                        ));
                    }

                    "CONNECT" => {
                        // not allowed
                        let headers = vec![
                            quiche::h3::Header::new(b":status", "405".to_string().as_bytes()),
                            quiche::h3::Header::new(b"server", b"quiche"),
                        ];

                        return Ok((headers, b"".to_vec(), Default::default()));
                    }

                    _ => method,
                }
            }

            None => return Err((H3_MESSAGE_ERROR, ":method cannot be missing".to_string())),
        };

        let decided_scheme = match scheme {
            Some(scheme) => {
                if scheme != "http" && scheme != "https" {
                    let headers = vec![
                        quiche::h3::Header::new(b":status", "400".to_string().as_bytes()),
                        quiche::h3::Header::new(b"server", b"quiche"),
                    ];

                    return Ok((headers, b"Invalid scheme".to_vec(), Default::default()));
                }

                scheme
            }

            None => return Err((H3_MESSAGE_ERROR, ":scheme cannot be missing".to_string())),
        };

        let decided_host = match (authority, host) {
            (None, Some("")) => {
                return Err((H3_MESSAGE_ERROR, "host value cannot be empty".to_string()));
            }

            (Some(""), None) => {
                return Err((
                    H3_MESSAGE_ERROR,
                    ":authority value cannot be empty".to_string(),
                ));
            }

            (Some(""), Some("")) => {
                return Err((
                    H3_MESSAGE_ERROR,
                    ":authority and host value cannot be empty".to_string(),
                ));
            }

            (None, None) => {
                return Err((H3_MESSAGE_ERROR, ":authority and host missing".to_string()));
            }

            // Any other combo, prefer :authority
            (..) => authority.unwrap(),
        };

        let decided_path = match path {
            Some("") => return Err((H3_MESSAGE_ERROR, ":path value cannot be empty".to_string())),

            None => return Err((H3_MESSAGE_ERROR, ":path cannot be missing".to_string())),

            Some(path) => path,
        };

        let url = format!("{decided_scheme}://{decided_host}{decided_path}");
        let url = url::Url::parse(&url).unwrap();

        let pathbuf = path::PathBuf::from(url.path());
        let pathbuf = autoindex(pathbuf, index);

        // Priority query string takes precedence over the header.
        // So replace the header with one built here.
        let query_priority = priority_field_value_from_query_string(&url);

        if let Some(p) = query_priority {
            priority = p.as_bytes().to_vec();
        }

        let (status, body) = match decided_method {
            "GET" => {
                for c in pathbuf.components() {
                    if let path::Component::Normal(v) = c {
                        file_path.push(v)
                    }
                }

                match std::fs::read(file_path.as_path()) {
                    Ok(data) => (200, data),

                    Err(_) => (404, b"Not Found!".to_vec()),
                }
            }

            _ => (405, Vec::new()),
        };

        let headers = vec![
            quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
            quiche::h3::Header::new(b"server", b"quiche"),
            quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
        ];

        Ok((headers, body, priority))
    }
}

impl HttpConn for Http3Conn {
    fn send_requests(&mut self, conn: &mut quiche::Connection, target_path: &Option<String>) {
        let mut reqs_done = 0;

        // First send headers.
        for req in self.reqs.iter_mut().skip(self.reqs_hdrs_sent) {
            let s = match self
                .h3_conn
                .send_request(conn, &req.hdrs, self.body.is_none())
            {
                Ok(v) => v,

                Err(quiche::h3::Error::TransportError(quiche::Error::StreamLimit)) => {
                    debug!("not enough stream credits, retry later...");
                    break;
                }

                Err(quiche::h3::Error::StreamBlocked) => {
                    debug!("stream is blocked, retry later...");
                    break;
                }

                Err(e) => {
                    error!("failed to send request {e:?}");
                    break;
                }
            };

            debug!("Sent HTTP request {:?}", &req.hdrs);

            if let Some(priority) = &req.priority {
                // If sending the priority fails, don't try again.
                self.h3_conn
                    .send_priority_update_for_request(conn, s, priority)
                    .ok();
            }

            req.stream_id = Some(s);
            req.response_writer = make_resource_writer(&req.url, target_path, req.cardinal);
            self.sent_body_bytes.insert(s, 0);

            reqs_done += 1;
        }
        self.reqs_hdrs_sent += reqs_done;

        // Then send any remaining body.
        if let Some(body) = &self.body {
            for (stream_id, sent_bytes) in self.sent_body_bytes.iter_mut() {
                if *sent_bytes == body.len() {
                    continue;
                }

                // Always try to send all remaining bytes, so always set fin to
                // true.
                let sent =
                    match self
                        .h3_conn
                        .send_body(conn, *stream_id, &body[*sent_bytes..], true)
                    {
                        Ok(v) => v,

                        Err(quiche::h3::Error::Done) => 0,

                        Err(e) => {
                            error!("failed to send request body {e:?}");
                            continue;
                        }
                    };

                *sent_bytes += sent;
            }
        }

        // And finally any DATAGRAMS.
        if let Some(ds) = self.dgram_sender.as_mut() {
            let mut dgrams_done = 0;

            for _ in ds.dgrams_sent..ds.dgram_count {
                match send_h3_dgram(conn, ds.flow_id, ds.dgram_content.as_bytes()) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("failed to send dgram {e:?}");
                        break;
                    }
                }

                dgrams_done += 1;
            }

            ds.dgrams_sent += dgrams_done;
        }
    }

    fn handle_responses(
        &mut self,
        conn: &mut quiche::Connection,
        buf: &mut [u8],
        req_start: &std::time::Instant,
    ) {
        loop {
            match self.h3_conn.poll(conn) {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    debug!(
                        "got response headers {:?} on stream id {}",
                        hdrs_to_strings(&list),
                        stream_id
                    );

                    let req = self
                        .reqs
                        .iter_mut()
                        .find(|r| r.stream_id == Some(stream_id))
                        .unwrap();

                    req.response_hdrs = list;
                }

                Ok((stream_id, quiche::h3::Event::Data)) => {
                    while let Ok(read) = self.h3_conn.recv_body(conn, stream_id, buf) {
                        debug!("got {read} bytes of response data on stream {stream_id}");

                        let req = self
                            .reqs
                            .iter_mut()
                            .find(|r| r.stream_id == Some(stream_id))
                            .unwrap();

                        let len =
                            std::cmp::min(read, req.response_body_max - req.response_body.len());
                        req.response_body.extend_from_slice(&buf[..len]);

                        match &mut req.response_writer {
                            Some(rw) => {
                                rw.write_all(&buf[..read]).ok();
                            }

                            None => {
                                if !self.dump_json {
                                    self.output_sink.borrow_mut()(unsafe {
                                        String::from_utf8_unchecked(buf[..read].to_vec())
                                    });
                                }
                            }
                        }
                    }
                }

                Ok((_stream_id, quiche::h3::Event::Finished)) => {
                    self.reqs_complete += 1;
                    let reqs_count = self.reqs.len();

                    debug!("{}/{} responses received", self.reqs_complete, reqs_count);

                    if self.reqs_complete == reqs_count {
                        info!(
                            "{}/{} response(s) received in {:?}, closing...",
                            self.reqs_complete,
                            reqs_count,
                            req_start.elapsed()
                        );

                        if self.dump_json {
                            dump_json(&self.reqs, &mut *self.output_sink.borrow_mut());
                        }

                        match conn.close(true, 0x100, b"kthxbye") {
                            // Already closed.
                            Ok(_) | Err(quiche::Error::Done) => (),

                            Err(e) => panic!("error closing conn: {e:?}"),
                        }

                        break;
                    }
                }

                Ok((_stream_id, quiche::h3::Event::Reset(e))) => {
                    error!("request was reset by peer with {e}, closing...");

                    match conn.close(true, 0x100, b"kthxbye") {
                        // Already closed.
                        Ok(_) | Err(quiche::Error::Done) => (),

                        Err(e) => panic!("error closing conn: {e:?}"),
                    }

                    break;
                }

                Ok((prioritized_element_id, quiche::h3::Event::PriorityUpdate)) => {
                    info!(
                        "{} PRIORITY_UPDATE triggered for element ID={}",
                        conn.trace_id(),
                        prioritized_element_id
                    );
                }

                Ok((goaway_id, quiche::h3::Event::GoAway)) => {
                    info!("{} got GOAWAY with ID {} ", conn.trace_id(), goaway_id);
                }

                Err(quiche::h3::Error::Done) => {
                    break;
                }

                Err(e) => {
                    error!("HTTP/3 processing failed: {e:?}");

                    break;
                }
            }
        }

        // Process datagram-related events.
        while let Ok(len) = conn.dgram_recv(buf) {
            let mut b = octets::Octets::with_slice(buf);
            if let Ok(flow_id) = b.get_varint() {
                info!(
                    "Received DATAGRAM flow_id={} len={} data={:?}",
                    flow_id,
                    len,
                    buf[b.off()..len].to_vec()
                );
            }
        }
    }

    fn report_incomplete(&self, start: &std::time::Instant) -> bool {
        if self.reqs_complete != self.reqs.len() {
            error!(
                "connection timed out after {:?} and only completed {}/{} requests",
                start.elapsed(),
                self.reqs_complete,
                self.reqs.len()
            );

            if self.dump_json {
                dump_json(&self.reqs, &mut *self.output_sink.borrow_mut());
            }

            return true;
        }

        false
    }

    fn handle_requests(
        &mut self,
        conn: &mut quiche::Connection,
        _partial_requests: &mut HashMap<u64, PartialRequest>,
        partial_responses: &mut HashMap<u64, PartialResponse>,
        root: &str,
        index: &str,
        buf: &mut [u8],
    ) -> quiche::h3::Result<()> {
        // Process HTTP stream-related events.
        //
        // This loops over any and all received HTTP requests and sends just the
        // HTTP response headers.
        loop {
            match self.h3_conn.poll(conn) {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    info!(
                        "{} got request {:?} on stream id {}",
                        conn.trace_id(),
                        hdrs_to_strings(&list),
                        stream_id
                    );

                    self.largest_processed_request =
                        std::cmp::max(self.largest_processed_request, stream_id);

                    // We decide the response based on headers alone, so
                    // stop reading the request stream so that any body
                    // is ignored and pointless Data events are not
                    // generated.
                    conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0)
                        .unwrap();

                    let (mut headers, body, mut priority) =
                        match Http3Conn::build_h3_response(root, index, &list) {
                            Ok(v) => v,

                            Err((error_code, _)) => {
                                conn.stream_shutdown(
                                    stream_id,
                                    quiche::Shutdown::Write,
                                    error_code,
                                )
                                .unwrap();
                                continue;
                            }
                        };

                    match self.h3_conn.take_last_priority_update(stream_id) {
                        Ok(v) => {
                            priority = v;
                        }

                        Err(quiche::h3::Error::Done) => (),

                        Err(e) => error!("{} error taking PRIORITY_UPDATE {}", conn.trace_id(), e),
                    }

                    if !priority.is_empty() {
                        headers.push(quiche::h3::Header::new(b"priority", priority.as_slice()));
                    }

                    let priority = quiche::h3::Priority::default();

                    info!(
                        "{} prioritizing response on stream {} as {:?}",
                        conn.trace_id(),
                        stream_id,
                        priority
                    );

                    match self
                        .h3_conn
                        .send_response_with_priority(conn, stream_id, &headers, &priority, false)
                    {
                        Ok(v) => v,

                        Err(quiche::h3::Error::StreamBlocked) => {
                            let response = PartialResponse {
                                headers: Some(headers),
                                priority: Some(priority),
                                body,
                                written: 0,
                            };

                            partial_responses.insert(stream_id, response);
                            continue;
                        }

                        Err(e) => {
                            error!("{} stream send failed {:?}", conn.trace_id(), e);

                            break;
                        }
                    }

                    let response = PartialResponse {
                        headers: None,
                        priority: None,
                        body,
                        written: 0,
                    };

                    partial_responses.insert(stream_id, response);
                }

                Ok((stream_id, quiche::h3::Event::Data)) => {
                    info!("{} got data on stream id {}", conn.trace_id(), stream_id);
                }

                Ok((_stream_id, quiche::h3::Event::Finished)) => (),

                Ok((_stream_id, quiche::h3::Event::Reset { .. })) => (),

                Ok((prioritized_element_id, quiche::h3::Event::PriorityUpdate)) => {
                    info!(
                        "{} PRIORITY_UPDATE triggered for element ID={}",
                        conn.trace_id(),
                        prioritized_element_id
                    );
                }

                Ok((goaway_id, quiche::h3::Event::GoAway)) => {
                    trace!("{} got GOAWAY with ID {} ", conn.trace_id(), goaway_id);
                    self.h3_conn
                        .send_goaway(conn, self.largest_processed_request)?;
                }

                Err(quiche::h3::Error::Done) => {
                    break;
                }

                Err(e) => {
                    error!("{} HTTP/3 error {:?}", conn.trace_id(), e);

                    return Err(e);
                }
            }
        }

        // Visit all writable response streams to send HTTP content.
        for stream_id in writable_response_streams(conn) {
            self.handle_writable(conn, partial_responses, stream_id);
        }

        // Process datagram-related events.
        while let Ok(len) = conn.dgram_recv(buf) {
            let mut b = octets::Octets::with_slice(buf);
            if let Ok(flow_id) = b.get_varint() {
                info!(
                    "Received DATAGRAM flow_id={} len={} data={:?}",
                    flow_id,
                    len,
                    buf[b.off()..len].to_vec()
                );
            }
        }

        if let Some(ds) = self.dgram_sender.as_mut() {
            let mut dgrams_done = 0;

            for _ in ds.dgrams_sent..ds.dgram_count {
                match send_h3_dgram(conn, ds.flow_id, ds.dgram_content.as_bytes()) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("failed to send dgram {e:?}");
                        break;
                    }
                }

                dgrams_done += 1;
            }

            ds.dgrams_sent += dgrams_done;
        }

        Ok(())
    }

    fn handle_writable(
        &mut self,
        conn: &mut quiche::Connection,
        partial_responses: &mut HashMap<u64, PartialResponse>,
        stream_id: u64,
    ) {
        debug!(
            "{} response stream {} is writable with capacity {:?}",
            conn.trace_id(),
            stream_id,
            conn.stream_capacity(stream_id)
        );

        if !partial_responses.contains_key(&stream_id) {
            return;
        }

        let resp = partial_responses.get_mut(&stream_id).unwrap();

        if let (Some(headers), Some(priority)) = (&resp.headers, &resp.priority) {
            match self
                .h3_conn
                .send_response_with_priority(conn, stream_id, headers, priority, false)
            {
                Ok(_) => (),

                Err(quiche::h3::Error::StreamBlocked) => {
                    return;
                }

                Err(e) => {
                    error!("{} stream send failed {:?}", conn.trace_id(), e);
                    return;
                }
            }
        }

        resp.headers = None;
        resp.priority = None;

        let body = &resp.body[resp.written..];

        let written = match self.h3_conn.send_body(conn, stream_id, body, true) {
            Ok(v) => v,

            Err(quiche::h3::Error::Done) => 0,

            Err(e) => {
                partial_responses.remove(&stream_id);

                error!("{} stream send failed {:?}", conn.trace_id(), e);
                return;
            }
        };

        resp.written += written;

        if resp.written == resp.body.len() {
            partial_responses.remove(&stream_id);
        }
    }
}

/// For non-Linux platforms.
#[cfg(not(target_os = "linux"))]
fn send_to_gso_pacing(
    _socket: &mio::net::UdpSocket,
    _buf: &[u8],
    _send_info: &quiche::SendInfo,
    _segment_size: usize,
) -> io::Result<usize> {
    panic!("send_to_gso() should not be called on non-linux platforms");
}

/// A wrapper function of send_to().
///
/// When GSO and SO_TXTIME are enabled, send packets using send_to_gso().
/// Otherwise, send packets using socket.send_to().
pub fn send_to(
    socket: &mio::net::UdpSocket,
    buf: &[u8],
    send_info: &quiche::SendInfo,
    segment_size: usize,
    pacing: bool,
    enable_gso: bool,
) -> io::Result<usize> {
    if pacing && enable_gso {
        match send_to_gso_pacing(socket, buf, send_info, segment_size) {
            Ok(v) => {
                return Ok(v);
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    let mut off = 0;
    let mut left = buf.len();
    let mut written = 0;

    while left > 0 {
        let pkt_len = cmp::min(left, segment_size);

        match socket.send_to(&buf[off..off + pkt_len], send_info.to) {
            Ok(v) => {
                written += v;
            }
            Err(e) => return Err(e),
        }

        off += pkt_len;
        left -= pkt_len;
    }

    Ok(written)
}
