pub fn writable_response_streams(conn: &quiche::Connection) -> impl Iterator<Item = u64> + use<> {
    conn.writable().filter(|id| id % 4 == 0)
}
