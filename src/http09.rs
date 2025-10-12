use log::{debug, error, info, trace};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path;
use std::rc::Rc;

use crate::partial_request::PartialRequest;
use crate::partial_response::PartialResponse;

use crate::HttpConn;
use crate::autoindex::autoindex;
use crate::stdout_sink::stdout_sink;

/// Represents an HTTP/0.9 formatted request.
pub struct Http09Request {
    url: url::Url,
    cardinal: u64,
    request_line: String,
    stream_id: Option<u64>,
    response_writer: Option<std::io::BufWriter<std::fs::File>>,
}

pub struct Http09Conn {
    stream_id: u64,
    reqs_sent: usize,
    reqs_complete: usize,
    reqs: Vec<Http09Request>,
    output_sink: Rc<RefCell<dyn FnMut(String)>>,
}

impl HttpConn for Http09Conn {
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
