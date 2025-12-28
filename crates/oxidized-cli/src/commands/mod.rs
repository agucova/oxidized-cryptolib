pub mod cat;
pub mod cp;
pub mod info;
pub mod init;
pub mod ls;
pub mod mkdir;
pub mod mv;
pub mod rm;
pub mod touch;
pub mod tree;
pub mod write;

/// Normalize a vault path to ensure it starts with `/`.
/// This makes paths like `test.txt` work the same as `/test.txt`.
pub fn normalize_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}
