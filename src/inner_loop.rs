use ring::rand::*;
use std::collections::HashMap;

use log::{debug, error, info, trace, warn};

use crate::client::Client;
use crate::constants::{MAX_BUF_SIZE, MAX_DATAGRAM_SIZE};

use crate::mint_token::mint_token;
use crate::partial_response::PartialResponse;
use crate::validate_token::validate_token;
use crate::writable_response_streams::writable_response_streams;

use crate::http3::Http3Conn;
use crate::http3_dgram_sender::Http3DgramSender;
use crate::http09::Http09Conn;
use quiche::ConnectionId;

use crate::generate_cid_and_reset_token::generate_cid_and_reset_token;
use crate::handle_path_events::handle_path_events;

use crate::http_conn::HttpConn;

/// ALPN helpers.
///
/// This module contains constants and functions for working with ALPN.
pub mod alpns {
    pub const HTTP_09: [&[u8]; 2] = [b"hq-interop", b"http/0.9"];
    pub const HTTP_3: [&[u8]; 1] = [b"h3"];
}

// Too many args? Tell me about it...
// Still better than a huge inner loop

/// Read incoming UDP packets from the socket and feed them to quiche,
/// until there are no more packets to read.
pub fn inner_loop(
    events: &mut mio::Events,
    continue_write: bool,
    clients: &mut HashMap<u64, Client>,
    socket: &mut mio::net::UdpSocket,
    mut buf: [u8; MAX_BUF_SIZE],
    local_addr: std::net::SocketAddr,
    conn_id_seed: &ring::hmac::Key,
    clients_ids: &mut HashMap<ConnectionId<'static>, u64>,
    mut out: [u8; MAX_BUF_SIZE],
    config: &mut quiche::Config,
    next_client_id: &mut u64,
    rng: &SystemRandom,
) {
    loop {
        // If the event loop reported no events, it means that the timeout
        // has expired, so handle it without attempting to read packets. We
        // will then proceed with the send loop.
        if events.is_empty() && !continue_write {
            trace!("timed out");

            clients.values_mut().for_each(|c| c.conn.on_timeout());

            break;
        }

        let (len, from) = match socket.recv_from(&mut buf) {
            Ok(v) => v,

            Err(e) => {
                // There are no more UDP packets to read, so end the read
                // loop.
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    trace!("recv() would block");
                    break;
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
                continue;
            }
        };

        trace!("got packet {hdr:?}");

        let conn_id = ring::hmac::sign(conn_id_seed, &hdr.dcid);
        let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
        let conn_id: quiche::ConnectionId<'static> = conn_id.to_vec().into();

        // Lookup a connection based on the packet's connection ID. If there
        // is no connection matching, create a new one.
        let client = if !clients_ids.contains_key(&hdr.dcid) && !clients_ids.contains_key(&conn_id)
        {
            if hdr.ty != quiche::Type::Initial {
                error!("Packet is not Initial");
                continue;
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
                continue;
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
                continue;
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
                continue;
            }

            // Reuse the source connection ID we sent in the Retry
            // packet, instead of changing it again.
            scid.copy_from_slice(&hdr.dcid);

            let scid = quiche::ConnectionId::from_vec(scid.to_vec());

            debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

            #[allow(unused_mut)]
            let mut conn = quiche::accept(&scid, odcid.as_ref(), local_addr, from, config).unwrap();

            let client_id = *next_client_id;

            let client = Client {
                conn,
                http_conn: None,
                client_id,
                partial_requests: HashMap::new(),
                partial_responses: HashMap::new(),
                app_proto_selected: false,
                max_datagram_size: MAX_DATAGRAM_SIZE,
                max_send_burst: MAX_BUF_SIZE,
            };

            clients.insert(client_id, client);
            clients_ids.insert(scid.clone(), client_id);

            *next_client_id += 1;

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
                continue;
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

                client.http_conn =
                    match Http3Conn::with_conn(&mut client.conn, None, None, None, dgram_sender) {
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
                continue;
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
            let (scid, reset_token) = generate_cid_and_reset_token(rng);
            if client.conn.new_scid(&scid, reset_token, false).is_err() {
                break;
            }

            clients_ids.insert(scid, client.client_id);
        }
    }
}
