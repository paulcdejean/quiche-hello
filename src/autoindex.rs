pub fn autoindex(path: std::path::PathBuf, index: &str) -> std::path::PathBuf {
    if let Some(path_str) = path.to_str() {
        if path_str.ends_with('/') {
            let path_str = format!("{path_str}{index}");
            return std::path::PathBuf::from(&path_str);
        }
    }
    path
}
