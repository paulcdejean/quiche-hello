pub struct Http3DgramSender {
    pub(crate) dgram_count: u64,
    pub dgram_content: String,
    pub flow_id: u64,
    pub dgrams_sent: u64,
}
