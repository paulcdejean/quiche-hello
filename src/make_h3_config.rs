pub fn make_h3_config(
    max_field_section_size: Option<u64>,
    qpack_max_table_capacity: Option<u64>,
    qpack_blocked_streams: Option<u64>,
) -> quiche::h3::Config {
    let mut config = quiche::h3::Config::new().unwrap();

    if let Some(v) = max_field_section_size {
        config.set_max_field_section_size(v);
    }

    if let Some(v) = qpack_max_table_capacity {
        // quiche doesn't support dynamic QPACK, so clamp to 0 for now.
        config.set_qpack_max_table_capacity(v.clamp(0, 0));
    }

    if let Some(v) = qpack_blocked_streams {
        // quiche doesn't support dynamic QPACK, so clamp to 0 for now.
        config.set_qpack_blocked_streams(v.clamp(0, 0));
    }

    config
}
