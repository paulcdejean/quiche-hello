use std::fmt::Write as _;

/// Construct a priority field value from quiche apps custom query string.
pub fn priority_field_value_from_query_string(url: &url::Url) -> Option<String> {
    let mut priority = "".to_string();
    for param in url.query_pairs() {
        if param.0 == "u" {
            write!(priority, "{}={},", param.0, param.1).ok();
        }

        if param.0 == "i" && param.1 == "1" {
            priority.push_str("i,");
        }
    }

    if !priority.is_empty() {
        // remove trailing comma
        priority.pop();

        Some(priority)
    } else {
        None
    }
}
