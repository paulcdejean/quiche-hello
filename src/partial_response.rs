pub struct PartialResponse {
    pub headers: Option<Vec<quiche::h3::Header>>,
    pub priority: Option<quiche::h3::Priority>,

    pub body: Vec<u8>,

    pub written: usize,
}
