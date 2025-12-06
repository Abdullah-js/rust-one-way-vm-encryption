
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct VirtualizeRequest {
    pub code: String,
    pub language: String,
    pub options: Option<VirtualizeOptions>,
}

#[derive(Debug, Deserialize)]
pub struct VirtualizeOptions {
    pub aggressive: Option<bool>,
    pub strip_symbols: Option<bool>,
    pub anti_debug: Option<bool>,
    pub compress: Option<bool>,
    pub encryption: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VirtualizeResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytecode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<BuildStats>,
}

#[derive(Debug, Serialize)]
pub struct BuildStats {
    pub bytecode_size: usize,
    pub runtime_size: usize,
    pub timestamp: u64,
}
