use std::collections::HashMap;

use crate::partial_request::PartialRequest;
use crate::partial_response::PartialResponse;

pub trait HttpConn {
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
