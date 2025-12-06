
pub mod server;
pub mod handlers;
pub mod api;

pub use server::VirtualizerServer;
pub use api::{VirtualizeRequest, VirtualizeResponse};

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub cors: bool,
    pub max_body_size: usize,
    pub timeout_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 4000,
            cors: true,
            max_body_size: 10 * 1024 * 1024, // 10MB
            timeout_secs: 60,
        }
    }
}

impl ServerConfig {
    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
