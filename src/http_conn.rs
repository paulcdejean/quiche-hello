use std::collections::HashMap;

use crate::partial_request::PartialRequest;
use crate::partial_response::PartialResponse;

#[allow(dead_code)]
pub trait HttpConn {
    fn send_requests(&mut self, conn: &mut quiche::Connection, target_path: &Option<String>);

    fn handle_responses(
        &mut self,
        conn: &mut quiche::Connection,
        buf: &mut [u8],
        req_start: &std::time::Instant,
    );

    fn report_incomplete(&self, start: &std::time::Instant) -> bool;

    fn handle_requests(
        &mut self,
        conn: &mut quiche::Connection,
        partial_requests: &mut HashMap<u64, PartialRequest>,
        partial_responses: &mut HashMap<u64, PartialResponse>,
        root: &str,
        index: &str,
        buf: &mut [u8],
    ) -> quiche::h3::Result<()>;

    fn handle_writable(
        &mut self,
        conn: &mut quiche::Connection,
        partial_responses: &mut HashMap<u64, PartialResponse>,
        stream_id: u64,
    );
}
