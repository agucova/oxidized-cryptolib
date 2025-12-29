//! Test server harness for WebDAV integration tests.
//!
//! Provides a `TestServer` that manages the lifecycle of a WebDAV server
//! with a temporary or shared vault, along with HTTP convenience methods.

use bytes::Bytes;
use oxidized_cryptolib::vault::VaultCreator;
use oxidized_webdav::{CryptomatorWebDav, ServerConfig, WebDavServer};
use reqwest::{Client, Method, Response, StatusCode};
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;

/// URL-encode a path component for use in Destination headers.
/// This handles non-ASCII characters which must be percent-encoded in URIs.
fn url_encode_path(path: &str) -> String {
    let mut result = String::with_capacity(path.len() * 3);
    for c in path.chars() {
        // ASCII printable characters that are allowed in URI paths without encoding
        // (except for '?' and '#' which would start query/fragment)
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~' | '/' | ':' | '@' | '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '=') {
            result.push(c);
        } else {
            // Percent-encode the UTF-8 bytes
            for byte in c.to_string().as_bytes() {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

/// Test password for temporary vaults.
pub const TEST_PASSWORD: &str = "test-password-12345";

/// Test server with HTTP client and automatic cleanup.
pub struct TestServer {
    /// The running WebDAV server.
    server: WebDavServer,
    /// HTTP client for making requests.
    client: Client,
    /// Base URL for the server.
    pub base_url: String,
    /// Temporary directory (cleaned up on drop).
    _temp_dir: Option<TempDir>,
}

impl TestServer {
    /// Start a server with a fresh temporary vault.
    ///
    /// Creates a new empty vault that gets cleaned up when the server is dropped.
    pub async fn with_temp_vault() -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let vault_path = temp_dir.path().join("vault");

        // Create the vault
        let _vault_ops = VaultCreator::new(&vault_path, TEST_PASSWORD)
            .create()
            .expect("Failed to create test vault");

        // Open as WebDAV filesystem
        let fs = CryptomatorWebDav::open(&vault_path, TEST_PASSWORD)
            .expect("Failed to open vault for WebDAV");

        // Start server on random port
        let config = ServerConfig::default();
        let server = WebDavServer::start(fs, config)
            .await
            .expect("Failed to start WebDAV server");

        let base_url = server.url();

        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        let mut test_server = Self {
            server,
            client,
            base_url,
            _temp_dir: Some(temp_dir),
        };

        // Wait for server to be ready
        test_server.wait_ready().await;

        test_server
    }

    /// Start a server with the shared test_vault.
    ///
    /// Uses the repository's test_vault directory. Good for read-only tests.
    pub async fn with_test_vault() -> Self {
        let test_vault_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("test_vault");

        assert!(
            test_vault_path.exists(),
            "test_vault not found at {:?}",
            test_vault_path
        );

        // The test vault password
        let password = "test";

        let fs = CryptomatorWebDav::open(&test_vault_path, password)
            .expect("Failed to open test_vault for WebDAV");

        let config = ServerConfig::default();
        let server = WebDavServer::start(fs, config)
            .await
            .expect("Failed to start WebDAV server");

        let base_url = server.url();

        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        let mut test_server = Self {
            server,
            client,
            base_url,
            _temp_dir: None,
        };

        test_server.wait_ready().await;

        test_server
    }

    /// Wait for the server to be ready to accept connections.
    async fn wait_ready(&self) {
        for _ in 0..50 {
            if let Ok(resp) = self
                .client
                .request(Method::from_bytes(b"PROPFIND").unwrap(), &self.base_url)
                .header("Depth", "0")
                .send()
                .await
            {
                if resp.status().is_success() || resp.status() == StatusCode::MULTI_STATUS {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("Server did not become ready in time");
    }

    /// Build a full URL from a path.
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Build a URL-encoded URL for use in Destination headers.
    /// Non-ASCII characters must be percent-encoded in HTTP headers.
    fn url_encoded(&self, path: &str) -> String {
        format!("{}{}", self.base_url, url_encode_path(path))
    }

    // ========== HTTP Convenience Methods ==========

    /// GET a file's contents.
    pub async fn get(&self, path: &str) -> Response {
        self.client
            .get(self.url(path))
            .send()
            .await
            .expect("GET request failed")
    }

    /// GET a file's contents as bytes.
    pub async fn get_bytes(&self, path: &str) -> Result<Bytes, (StatusCode, String)> {
        let resp = self.get(path).await;
        let status = resp.status();
        if status.is_success() {
            Ok(resp.bytes().await.expect("Failed to read response bytes"))
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err((status, body))
        }
    }

    /// PUT file contents.
    pub async fn put(&self, path: &str, body: impl Into<reqwest::Body>) -> Response {
        self.client
            .put(self.url(path))
            .body(body)
            .send()
            .await
            .expect("PUT request failed")
    }

    /// PUT file contents and assert success.
    pub async fn put_ok(&self, path: &str, body: impl Into<reqwest::Body>) {
        let resp = self.put(path, body).await;
        let status = resp.status();
        assert!(
            status.is_success() || status == StatusCode::CREATED || status == StatusCode::NO_CONTENT,
            "PUT {} failed with status {}: {}",
            path,
            status,
            resp.text().await.unwrap_or_default()
        );
    }

    /// DELETE a file or directory.
    pub async fn delete(&self, path: &str) -> Response {
        self.client
            .delete(self.url(path))
            .send()
            .await
            .expect("DELETE request failed")
    }

    /// DELETE and assert success.
    pub async fn delete_ok(&self, path: &str) {
        let resp = self.delete(path).await;
        let status = resp.status();
        assert!(
            status.is_success() || status == StatusCode::NO_CONTENT,
            "DELETE {} failed with status {}: {}",
            path,
            status,
            resp.text().await.unwrap_or_default()
        );
    }

    /// MKCOL (create directory).
    pub async fn mkcol(&self, path: &str) -> Response {
        self.client
            .request(Method::from_bytes(b"MKCOL").unwrap(), self.url(path))
            .send()
            .await
            .expect("MKCOL request failed")
    }

    /// MKCOL and assert success.
    pub async fn mkcol_ok(&self, path: &str) {
        let resp = self.mkcol(path).await;
        let status = resp.status();
        assert!(
            status.is_success() || status == StatusCode::CREATED,
            "MKCOL {} failed with status {}: {}",
            path,
            status,
            resp.text().await.unwrap_or_default()
        );
    }

    /// PROPFIND (list directory or get properties).
    pub async fn propfind(&self, path: &str, depth: &str) -> Response {
        self.client
            .request(Method::from_bytes(b"PROPFIND").unwrap(), self.url(path))
            .header("Depth", depth)
            .send()
            .await
            .expect("PROPFIND request failed")
    }

    /// PROPFIND and return body as string.
    pub async fn propfind_body(&self, path: &str, depth: &str) -> (StatusCode, String) {
        let resp = self.propfind(path, depth).await;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        (status, body)
    }

    /// COPY a file or directory.
    pub async fn copy(&self, from: &str, to: &str, overwrite: bool) -> Response {
        self.client
            .request(Method::from_bytes(b"COPY").unwrap(), self.url(from))
            .header("Destination", self.url_encoded(to))
            .header("Overwrite", if overwrite { "T" } else { "F" })
            .send()
            .await
            .expect("COPY request failed")
    }

    /// COPY and assert success.
    pub async fn copy_ok(&self, from: &str, to: &str) {
        let resp = self.copy(from, to, true).await;
        let status = resp.status();
        assert!(
            status.is_success() || status == StatusCode::CREATED || status == StatusCode::NO_CONTENT,
            "COPY {} -> {} failed with status {}: {}",
            from,
            to,
            status,
            resp.text().await.unwrap_or_default()
        );
    }

    /// MOVE a file or directory.
    pub async fn move_(&self, from: &str, to: &str, overwrite: bool) -> Response {
        self.client
            .request(Method::from_bytes(b"MOVE").unwrap(), self.url(from))
            .header("Destination", self.url_encoded(to))
            .header("Overwrite", if overwrite { "T" } else { "F" })
            .send()
            .await
            .expect("MOVE request failed")
    }

    /// MOVE and assert success.
    pub async fn move_ok(&self, from: &str, to: &str) {
        let resp = self.move_(from, to, true).await;
        let status = resp.status();
        assert!(
            status.is_success() || status == StatusCode::CREATED || status == StatusCode::NO_CONTENT,
            "MOVE {} -> {} failed with status {}: {}",
            from,
            to,
            status,
            resp.text().await.unwrap_or_default()
        );
    }

    /// Stop the server explicitly (otherwise happens on drop).
    pub async fn stop(self) {
        self.server.stop().await;
    }
}

/// Shared test client for concurrent operations.
///
/// Use `TestServer::shared_client()` to get this for spawning concurrent tasks.
#[derive(Clone)]
pub struct SharedTestClient {
    client: Client,
    pub base_url: String,
}

impl SharedTestClient {
    /// Build a full URL from a path.
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// GET a file's contents.
    pub async fn get(&self, path: &str) -> Response {
        self.client
            .get(self.url(path))
            .send()
            .await
            .expect("GET request failed")
    }

    /// GET a file's contents as bytes.
    pub async fn get_bytes(&self, path: &str) -> Result<Bytes, (StatusCode, String)> {
        let resp = self.get(path).await;
        let status = resp.status();
        if status.is_success() {
            Ok(resp.bytes().await.expect("Failed to read response bytes"))
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err((status, body))
        }
    }

    /// PUT file contents.
    pub async fn put(&self, path: &str, body: impl Into<reqwest::Body>) -> Result<StatusCode, String> {
        self.client
            .put(self.url(path))
            .body(body)
            .send()
            .await
            .map(|r| r.status())
            .map_err(|e| e.to_string())
    }

    /// DELETE a file or directory.
    pub async fn delete(&self, path: &str) -> Result<StatusCode, String> {
        self.client
            .delete(self.url(path))
            .send()
            .await
            .map(|r| r.status())
            .map_err(|e| e.to_string())
    }

    /// MKCOL (create directory).
    pub async fn mkcol(&self, path: &str) -> Result<Response, String> {
        self.client
            .request(Method::from_bytes(b"MKCOL").unwrap(), self.url(path))
            .send()
            .await
            .map_err(|e| e.to_string())
    }

    /// PROPFIND (list directory or get properties).
    pub async fn propfind(&self, path: &str, depth: &str) -> Result<Response, String> {
        self.client
            .request(Method::from_bytes(b"PROPFIND").unwrap(), self.url(path))
            .header("Depth", depth)
            .send()
            .await
            .map_err(|e| e.to_string())
    }
}

impl TestServer {
    /// Get a shared client for concurrent operations.
    ///
    /// The returned client can be cloned and used across multiple tasks.
    pub fn shared_client(&self) -> SharedTestClient {
        SharedTestClient {
            client: self.client.clone(),
            base_url: self.base_url.clone(),
        }
    }
}
