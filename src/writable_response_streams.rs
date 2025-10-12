pub fn writable_response_streams(conn: &quiche::Connection) -> impl Iterator<Item = u64> + use<> {
    conn.writable().filter(|id| id.is_multiple_of(4))
}
