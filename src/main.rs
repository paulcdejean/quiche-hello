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
mod inner_loop;
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

use http_conn::HttpConn;

use inner_loop::inner_loop;


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

    // Create the configuration for the QUIC connections.
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
        inner_loop(
            &mut events,
            continue_write,
            clients,
            &mut socket,
            buf,
            local_addr,
            conn_id_seed,
            clients_ids,
            out,
            config,
            &mut next_client_id,
            &rng,
        );

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
