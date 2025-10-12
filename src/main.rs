use std::cmp;
use std::collections::HashMap;
use std::net;

use log::{debug, error, info, trace, warn};
use quiche::ConnectionId;
use ring::rand::*;

mod autoindex;
mod client;
mod constants;
mod example_config;
mod generate_cid_and_reset_token;
mod handle_path_events;
mod hdrs_to_strings;
mod http09;
mod http3;
mod http3_dgram_sender;
mod http_conn;
mod make_h3_config;
mod make_resource_writer;
mod mint_token;
mod partial_request;
mod partial_response;
mod priority_field_value_from_query_string;
mod send_h3_dgram;
mod validate_token;
mod writable_response_streams;

use client::{Client, ClientIdMap, ClientMap};
use constants::{MAX_BUF_SIZE, MAX_DATAGRAM_SIZE};
use example_config::example_config;
use generate_cid_and_reset_token::generate_cid_and_reset_token;
use handle_path_events::handle_path_events;
use http_conn::HttpConn;
use http3::Http3Conn;
use http3_dgram_sender::Http3DgramSender;
use http09::Http09Conn;
use mint_token::mint_token;
use partial_response::PartialResponse;
use validate_token::validate_token;
use writable_response_streams::writable_response_streams;

fn main() {
    let mut buf: [u8; MAX_BUF_SIZE] = [0; MAX_BUF_SIZE];
    let mut out: [u8; MAX_BUF_SIZE] = [0; MAX_BUF_SIZE];

    env_logger::builder().format_timestamp_nanos().init();

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

    // Create the configuration for the QUIC connections.
    // let mut config: quiche::Config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    let mut config: quiche::Config = example_config();

    let rng: SystemRandom = SystemRandom::new();
    let conn_id_seed: ring::hmac::Key =
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();
    let mut next_client_id: u64 = 0;
    let mut clients_ids: HashMap<ConnectionId<'static>, u64> = ClientIdMap::new();
    let mut clients: HashMap<u64, Client> = ClientMap::new();
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

        let mut poll_res: Result<(), std::io::Error> = poll.poll(&mut events, timeout);
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
                    let dgram_sender: Option<Http3DgramSender> = None;

                    client.http_conn = match Http3Conn::with_conn(
                        &mut client.conn,
                        None,
                        None,
                        None,
                        dgram_sender,
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

/// ALPN helpers.
///
/// This module contains constants and functions for working with ALPN.
pub mod alpns {
    pub const HTTP_09: [&[u8]; 2] = [b"hq-interop", b"http/0.9"];
    pub const HTTP_3: [&[u8]; 1] = [b"h3"];
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
) -> std::io::Result<usize> {
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
