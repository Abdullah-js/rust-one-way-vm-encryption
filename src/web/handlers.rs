
use std::collections::HashMap;

#[derive(Debug)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

pub struct HttpResponse {
    status: u16,
    status_text: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl HttpResponse {
    pub fn new(status: u16, status_text: &str) -> Self {
        let mut headers = HashMap::new();
        headers.insert("Access-Control-Allow-Origin".to_string(), "*".to_string());
        headers.insert("Connection".to_string(), "close".to_string());
        
        Self {
            status,
            status_text: status_text.to_string(),
            headers,
            body: Vec::new(),
        }
    }
    
    pub fn ok() -> Self {
        Self::new(200, "OK")
    }
    
    pub fn bad_request() -> Self {
        Self::new(400, "Bad Request")
    }
    
    pub fn not_found() -> Self {
        Self::new(404, "Not Found")
    }
    
    pub fn internal_error() -> Self {
        Self::new(500, "Internal Server Error")
    }
    
    pub fn header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }
    
    pub fn json(self, body: &str) -> Self {
        self.header("Content-Type", "application/json")
            .body_bytes(body.as_bytes())
    }
    
    pub fn html(self, body: &str) -> Self {
        self.header("Content-Type", "text/html; charset=utf-8")
            .body_bytes(body.as_bytes())
    }
    
    pub fn text(self, body: &str) -> Self {
        self.header("Content-Type", "text/plain")
            .body_bytes(body.as_bytes())
    }
    
    pub fn body_bytes(mut self, body: &[u8]) -> Self {
        self.body = body.to_vec();
        self.headers.insert("Content-Length".to_string(), body.len().to_string());
        self
    }
    
    pub fn build(&self) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 {} {}\r\n",
            self.status, self.status_text
        );
        
        for (key, value) in &self.headers {
            response.push_str(&format!("{}: {}\r\n", key, value));
        }
        
        response.push_str("\r\n");
        
        let mut bytes = response.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

pub struct RateLimiter {
    requests: HashMap<String, Vec<u64>>,
    max_requests: usize,
    window_secs: u64,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window_secs: u64) -> Self {
        Self {
            requests: HashMap::new(),
            max_requests,
            window_secs,
        }
    }
    
    pub fn check(&mut self, client_id: &str) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let window_start = now.saturating_sub(self.window_secs);
        
        let requests = self.requests.entry(client_id.to_string()).or_default();
        
        // Remove old requests
        requests.retain(|&t| t >= window_start);
        
        // Check limit
        if requests.len() >= self.max_requests {
            return false;
        }
        
        // Record this request
        requests.push(now);
        true
    }
    
    pub fn cleanup(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let window_start = now.saturating_sub(self.window_secs);
        
        self.requests.retain(|_, reqs| {
            reqs.retain(|&t| t >= window_start);
            !reqs.is_empty()
        });
    }
}
