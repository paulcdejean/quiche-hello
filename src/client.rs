use crate::http_conn::HttpConn;
use crate::partial_request::PartialRequest;
use crate::partial_response::PartialResponse;
use quiche::ConnectionId;
use std::collections::HashMap;

pub type ClientId = u64;

pub struct Client {
    pub conn: quiche::Connection,

    pub http_conn: Option<Box<dyn HttpConn>>,

    pub client_id: u64,

    pub app_proto_selected: bool,

    pub partial_requests: std::collections::HashMap<u64, PartialRequest>,

    pub partial_responses: std::collections::HashMap<u64, PartialResponse>,

    pub max_datagram_size: usize,

    pub loss_rate: f64,

    pub max_send_burst: usize,
}

pub type ClientIdMap = HashMap<ConnectionId<'static>, ClientId>;
pub type ClientMap = HashMap<ClientId, Client>;
