use log::{debug, error, info, trace};
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Write;

use std::rc::Rc;

use quiche::h3::NameValue;
use quiche::h3::Priority;
use std::path;

use crate::autoindex::autoindex;
use crate::constants::H3_MESSAGE_ERROR;
use crate::hdrs_to_strings::hdrs_to_strings;
use crate::http_conn::HttpConn;
use crate::http3_dgram_sender::Http3DgramSender;
use crate::make_h3_config::make_h3_config;
use crate::make_resource_writer::make_resource_writer;
use crate::partial_request::PartialRequest;
use crate::partial_response::PartialResponse;
use crate::priority_field_value_from_query_string::priority_field_value_from_query_string;
use crate::send_h3_dgram::send_h3_dgram;
use crate::writable_response_streams::writable_response_streams;

/// Represents an HTTP/3 formatted request.
#[allow(dead_code)]
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

#[allow(dead_code)]
pub struct Http3Conn {
    h3_conn: quiche::h3::Connection,
    reqs_hdrs_sent: usize,
    reqs_complete: usize,
    largest_processed_request: u64,
    reqs: Vec<Http3Request>,
    body: Option<Vec<u8>>,
    sent_body_bytes: HashMap<u64, usize>,
    dgram_sender: Option<Http3DgramSender>,
    output_sink: Rc<RefCell<dyn FnMut(String)>>,
}

impl Http3Conn {
    #[allow(clippy::too_many_arguments)]

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
                                self.output_sink.borrow_mut()(unsafe {
                                    String::from_utf8_unchecked(buf[..read].to_vec())
                                });
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
