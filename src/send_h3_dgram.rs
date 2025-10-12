use log::info;

pub fn send_h3_dgram(
    conn: &mut quiche::Connection,
    flow_id: u64,
    dgram_content: &[u8],
) -> quiche::Result<()> {
    info!("sending HTTP/3 DATAGRAM on flow_id={flow_id} with data {dgram_content:?}");

    let len = octets::varint_len(flow_id) + dgram_content.len();
    let mut d = vec![0; len];
    let mut b = octets::OctetsMut::with_slice(&mut d);

    b.put_varint(flow_id)
        .map_err(|_| quiche::Error::BufferTooShort)?;
    b.put_bytes(dgram_content)
        .map_err(|_| quiche::Error::BufferTooShort)?;

    conn.dgram_send(&d)
}
