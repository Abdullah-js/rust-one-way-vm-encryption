
use std::io::{Read, Write, BufRead, BufReader};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use super::{ServerConfig, api::{VirtualizeRequest, VirtualizeResponse}};
use crate::build_pipeline::{BuildPipeline, BuildConfig};

pub struct VirtualizerServer {
    config: ServerConfig,
}

impl VirtualizerServer {
    pub fn new(config: ServerConfig) -> Self {
        Self { config }
    }
    
    pub fn run(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.config.address())?;
        println!("🚀 Virtualizer server running at http://{}", self.config.address());
        println!("📡 Endpoints:");
        println!("   POST /virtualize - Submit code for virtualization");
        println!("   GET  /health     - Health check");
        println!("   GET  /           - API documentation");
        
        let config = Arc::new(self.config.clone());
        
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let cfg = config.clone();
                    thread::spawn(move || {
                        if let Err(e) = handle_connection(stream, &cfg) {
                            eprintln!("Connection error: {}", e);
                        }
                    });
                }
                Err(e) => eprintln!("Accept error: {}", e),
            }
        }
        
        Ok(())
    }
}

fn handle_connection(mut stream: TcpStream, config: &ServerConfig) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    
    // Parse request line
    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
    if parts.len() < 2 {
        return send_response(&mut stream, 400, "Bad Request", "Invalid request line");
    }
    
    let method = parts[0];
    let path = parts[1];
    
    // Read headers
    let mut headers = std::collections::HashMap::new();
    let mut content_length = 0usize;
    
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().to_lowercase();
            let value = value.trim();
            if key == "content-length" {
                content_length = value.parse().unwrap_or(0);
            }
            headers.insert(key, value.to_string());
        }
    }
    
    // Read body if present
    let mut body = vec![0u8; content_length.min(config.max_body_size)];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }
    
    // Route request
    match (method, path) {
        ("GET", "/") => handle_index(&mut stream),
        ("GET", "/health") => handle_health(&mut stream),
        ("POST", "/virtualize") => handle_virtualize(&mut stream, &body),
        ("OPTIONS", _) => handle_cors_preflight(&mut stream),
        _ => send_response(&mut stream, 404, "Not Found", "Endpoint not found"),
    }
}

fn handle_index(stream: &mut TcpStream) -> std::io::Result<()> {
    let html = r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Code Virtualizer - One-Way Code Protection</title>
    <style>
        :root {
            --bg-primary: #0a0a0f;
            --bg-secondary: #12121a;
            --bg-tertiary: #1a1a25;
            --accent: #6366f1;
            --accent-hover: #818cf8;
            --accent-glow: rgba(99, 102, 241, 0.3);
            --success: #10b981;
            --error: #ef4444;
            --warning: #f59e0b;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --border: #2d2d3a;
            --code-bg: #0d0d12;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.6;
        }

        /* Animated Background */
        .bg-grid {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image: 
                linear-gradient(rgba(99, 102, 241, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(99, 102, 241, 0.03) 1px, transparent 1px);
            background-size: 50px 50px;
            pointer-events: none;
            z-index: 0;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
            position: relative;
            z-index: 1;
        }

        /* Header */
        header {
            text-align: center;
            padding: 40px 0;
            border-bottom: 1px solid var(--border);
            margin-bottom: 40px;
        }

        .logo {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 15px;
            margin-bottom: 15px;
        }

        .logo-icon {
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, var(--accent), #a855f7);
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 30px;
            box-shadow: 0 10px 40px var(--accent-glow);
        }

        h1 {
            font-size: 2.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--text-primary), var(--accent));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .tagline {
            color: var(--text-secondary);
            font-size: 1.1rem;
            margin-top: 10px;
        }

        /* Main Grid */
        .main-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin-bottom: 40px;
        }

        @media (max-width: 1000px) {
            .main-grid {
                grid-template-columns: 1fr;
            }
        }

        /* Panels */
        .panel {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 16px;
            overflow: hidden;
        }

        .panel-header {
            background: var(--bg-tertiary);
            padding: 15px 20px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .panel-title {
            font-size: 0.9rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .panel-title span {
            font-size: 1.1rem;
        }

        .panel-body {
            padding: 20px;
        }

        /* Code Editor */
        .code-editor {
            position: relative;
        }

        textarea {
            width: 100%;
            height: 350px;
            background: var(--code-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 14px;
            color: var(--text-primary);
            resize: vertical;
            outline: none;
            transition: border-color 0.3s, box-shadow 0.3s;
        }

        textarea:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-glow);
        }

        textarea::placeholder {
            color: var(--text-muted);
        }

        /* Controls */
        .controls {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin-top: 20px;
        }

        .control-group {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        label {
            font-size: 0.85rem;
            font-weight: 500;
            color: var(--text-secondary);
        }

        select {
            padding: 12px 15px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 10px;
            color: var(--text-primary);
            font-size: 14px;
            cursor: pointer;
            outline: none;
            transition: border-color 0.3s;
        }

        select:focus {
            border-color: var(--accent);
        }

        /* Toggle Switches */
        .toggles {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 12px;
            margin-top: 20px;
        }

        .toggle-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 15px;
            background: var(--bg-tertiary);
            border-radius: 10px;
            border: 1px solid var(--border);
        }

        .toggle-label {
            font-size: 0.9rem;
            color: var(--text-primary);
        }

        .toggle {
            position: relative;
            width: 44px;
            height: 24px;
        }

        .toggle input {
            opacity: 0;
            width: 0;
            height: 0;
        }

        .toggle-slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: var(--border);
            border-radius: 24px;
            transition: 0.3s;
        }

        .toggle-slider:before {
            position: absolute;
            content: "";
            height: 18px;
            width: 18px;
            left: 3px;
            bottom: 3px;
            background: var(--text-primary);
            border-radius: 50%;
            transition: 0.3s;
        }

        .toggle input:checked + .toggle-slider {
            background: var(--accent);
        }

        .toggle input:checked + .toggle-slider:before {
            transform: translateX(20px);
        }

        /* Virtualize Button */
        .btn-virtualize {
            width: 100%;
            padding: 18px;
            margin-top: 25px;
            background: linear-gradient(135deg, var(--accent), #a855f7);
            border: none;
            border-radius: 12px;
            color: white;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }

        .btn-virtualize:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 40px var(--accent-glow);
        }

        .btn-virtualize:active {
            transform: translateY(0);
        }

        .btn-virtualize:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }

        .btn-virtualize .spinner {
            width: 20px;
            height: 20px;
            border: 2px solid rgba(255,255,255,0.3);
            border-top-color: white;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            display: none;
        }

        .btn-virtualize.loading .spinner {
            display: block;
        }

        .btn-virtualize.loading .btn-text {
            display: none;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        /* Output Panel */
        .output-area {
            background: var(--code-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            height: 350px;
            overflow: auto;
            position: relative;
        }

        .output-placeholder {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
            color: var(--text-muted);
        }

        .output-placeholder .icon {
            font-size: 3rem;
            margin-bottom: 15px;
            opacity: 0.5;
        }

        .output-content {
            padding: 20px;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 13px;
            white-space: pre-wrap;
            word-break: break-all;
        }

        /* Stats Cards */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin-top: 20px;
        }

        .stat-card {
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }

        .stat-value {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--accent);
            margin-bottom: 5px;
        }

        .stat-label {
            font-size: 0.8rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        /* Status Messages */
        .status {
            padding: 12px 15px;
            border-radius: 10px;
            margin-top: 15px;
            display: none;
            align-items: center;
            gap: 10px;
        }

        .status.success {
            display: flex;
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.3);
            color: var(--success);
        }

        .status.error {
            display: flex;
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: var(--error);
        }

        /* Action Buttons */
        .action-buttons {
            display: flex;
            gap: 10px;
            margin-top: 15px;
        }

        .btn-action {
            flex: 1;
            padding: 12px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 10px;
            color: var(--text-secondary);
            font-size: 0.9rem;
            cursor: pointer;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }

        .btn-action:hover {
            background: var(--border);
            color: var(--text-primary);
        }

        /* Features Section */
        .features {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-top: 40px;
        }

        @media (max-width: 900px) {
            .features {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        @media (max-width: 500px) {
            .features {
                grid-template-columns: 1fr;
            }
        }

        .feature-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 25px;
            text-align: center;
            transition: transform 0.3s, border-color 0.3s;
        }

        .feature-card:hover {
            transform: translateY(-5px);
            border-color: var(--accent);
        }

        .feature-icon {
            width: 50px;
            height: 50px;
            background: linear-gradient(135deg, var(--accent), #a855f7);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            margin: 0 auto 15px;
        }

        .feature-title {
            font-size: 1rem;
            font-weight: 600;
            margin-bottom: 8px;
        }

        .feature-desc {
            font-size: 0.85rem;
            color: var(--text-muted);
        }

        /* Footer */
        footer {
            text-align: center;
            padding: 40px 0;
            margin-top: 40px;
            border-top: 1px solid var(--border);
            color: var(--text-muted);
            font-size: 0.9rem;
        }

        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }

        ::-webkit-scrollbar-track {
            background: var(--bg-tertiary);
        }

        ::-webkit-scrollbar-thumb {
            background: var(--border);
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: var(--text-muted);
        }

        /* Animations */
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .panel {
            animation: fadeIn 0.5s ease-out;
        }

        .feature-card:nth-child(1) { animation-delay: 0.1s; }
        .feature-card:nth-child(2) { animation-delay: 0.2s; }
        .feature-card:nth-child(3) { animation-delay: 0.3s; }
        .feature-card:nth-child(4) { animation-delay: 0.4s; }
    </style>
</head>
<body>
    <div class="bg-grid"></div>
    
    <div class="container">
        <header>
            <div class="logo">
                <div class="logo-icon">🔒</div>
                <h1>Code Virtualizer</h1>
            </div>
            <p class="tagline">Transform your source code into protected, irreversible bytecode</p>
        </header>

        <div class="main-grid">
            <!-- Input Panel -->
            <div class="panel">
                <div class="panel-header">
                    <div class="panel-title">
                        <span>📝</span> Source Code
                    </div>
                    <select id="language" style="padding: 8px 12px; font-size: 13px;">
                        <option value="javascript">JavaScript</option>
                        <option value="typescript">TypeScript</option>
                        <option value="python">Python</option>
                        <option value="ruby">Ruby</option>
                        <option value="lua">Lua</option>
                        <option value="php">PHP</option>
                    </select>
                </div>
                <div class="panel-body">
                    <div class="code-editor">
                        <textarea id="code" placeholder="// Paste your code here...
function secretAlgorithm(data) {
    const key = 'super-secret-key';
    let result = [];
    
    for (let i = 0; i < data.length; i++) {
        result.push(data[i] ^ key.charCodeAt(i % key.length));
    }
    
    return result;
}"></textarea>
                    </div>

                    <div class="controls">
                        <div class="control-group">
                            <label>Encryption Algorithm</label>
                            <select id="encryption">
                                <option value="both">AES + XChaCha20 (Max Security)</option>
                                <option value="aes">AES-256-GCM</option>
                                <option value="xchacha">XChaCha20-Poly1305</option>
                            </select>
                        </div>
                    </div>

                    <div class="toggles">
                        <div class="toggle-item">
                            <span class="toggle-label">Aggressive Mode</span>
                            <label class="toggle">
                                <input type="checkbox" id="aggressive" checked>
                                <span class="toggle-slider"></span>
                            </label>
                        </div>
                        <div class="toggle-item">
                            <span class="toggle-label">Strip Symbols</span>
                            <label class="toggle">
                                <input type="checkbox" id="stripSymbols" checked>
                                <span class="toggle-slider"></span>
                            </label>
                        </div>
                        <div class="toggle-item">
                            <span class="toggle-label">Anti-Debug</span>
                            <label class="toggle">
                                <input type="checkbox" id="antiDebug" checked>
                                <span class="toggle-slider"></span>
                            </label>
                        </div>
                        <div class="toggle-item">
                            <span class="toggle-label">Compression</span>
                            <label class="toggle">
                                <input type="checkbox" id="compress" checked>
                                <span class="toggle-slider"></span>
                            </label>
                        </div>
                    </div>

                    <button class="btn-virtualize" id="virtualizeBtn" onclick="virtualize()">
                        <span class="spinner"></span>
                        <span class="btn-text">🚀 Virtualize Code</span>
                    </button>
                </div>
            </div>

            <!-- Output Panel -->
            <div class="panel">
                <div class="panel-header">
                    <div class="panel-title">
                        <span>⚡</span> Protected Output
                    </div>
                    <span id="buildId" style="font-size: 12px; color: var(--text-muted);"></span>
                </div>
                <div class="panel-body">
                    <div class="output-area" id="outputArea">
                        <div class="output-placeholder" id="placeholder">
                            <div class="icon">🛡️</div>
                            <p>Your virtualized bytecode will appear here</p>
                        </div>
                        <div class="output-content" id="outputContent" style="display: none;"></div>
                    </div>

                    <div class="stats-grid" id="statsGrid" style="display: none;">
                        <div class="stat-card">
                            <div class="stat-value" id="bytecodeSize">-</div>
                            <div class="stat-label">Bytecode Size</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value" id="runtimeSize">-</div>
                            <div class="stat-label">Runtime Size</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value" id="buildTime">-</div>
                            <div class="stat-label">Build Time</div>
                        </div>
                    </div>

                    <div id="statusMessage" class="status"></div>

                    <div class="action-buttons" id="actionButtons" style="display: none;">
                        <button class="btn-action" onclick="copyBytecode()">
                            📋 Copy Bytecode
                        </button>
                        <button class="btn-action" onclick="downloadOutput()">
                            💾 Download
                        </button>
                        <button class="btn-action" onclick="copyRuntime()">
                            📄 Copy Runtime
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Features -->
        <div class="features">
            <div class="feature-card">
                <div class="feature-icon">🔐</div>
                <div class="feature-title">Military-Grade Encryption</div>
                <div class="feature-desc">AES-256-GCM and XChaCha20-Poly1305 dual encryption</div>
            </div>
            <div class="feature-card">
                <div class="feature-icon">🎭</div>
                <div class="feature-title">Code Obfuscation</div>
                <div class="feature-desc">Dead code injection, opaque predicates, and trampolines</div>
            </div>
            <div class="feature-card">
                <div class="feature-icon">🛡️</div>
                <div class="feature-title">Anti-Debug Protection</div>
                <div class="feature-desc">Timing checks, debugger detection, and integrity verification</div>
            </div>
            <div class="feature-card">
                <div class="feature-icon">⚡</div>
                <div class="feature-title">Custom VM Runtime</div>
                <div class="feature-desc">Proprietary instruction set with randomized opcodes</div>
            </div>
        </div>

        <footer>
            <p>Code Virtualizer v1.0.0 • One-Way Code Protection System</p>
        </footer>
    </div>

    <script>
        let lastResponse = null;

        async function virtualize() {
            const btn = document.getElementById('virtualizeBtn');
            const code = document.getElementById('code').value;
            const language = document.getElementById('language').value;
            
            if (!code.trim()) {
                showStatus('error', 'Please enter some code to virtualize');
                return;
            }

            btn.classList.add('loading');
            btn.disabled = true;
            hideStatus();

            const startTime = Date.now();

            try {
                const response = await fetch('/virtualize', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        code: code,
                        language: language,
                        options: {
                            aggressive: document.getElementById('aggressive').checked,
                            strip_symbols: document.getElementById('stripSymbols').checked,
                            anti_debug: document.getElementById('antiDebug').checked,
                            compress: document.getElementById('compress').checked,
                            encryption: document.getElementById('encryption').value
                        }
                    })
                });

                const data = await response.json();
                const elapsed = Date.now() - startTime;

                if (data.success) {
                    lastResponse = data;
                    showOutput(data, elapsed);
                    showStatus('success', 'Code virtualized successfully!');
                } else {
                    showStatus('error', data.error || 'Virtualization failed');
                }
            } catch (error) {
                showStatus('error', 'Network error: ' + error.message);
            } finally {
                btn.classList.remove('loading');
                btn.disabled = false;
            }
        }

        function showOutput(data, elapsed) {
            document.getElementById('placeholder').style.display = 'none';
            document.getElementById('outputContent').style.display = 'block';
            document.getElementById('statsGrid').style.display = 'grid';
            document.getElementById('actionButtons').style.display = 'flex';
            
            // Show bytecode preview
            const bytecode = data.bytecode || '';
            const preview = bytecode.substring(0, 2000) + (bytecode.length > 2000 ? '\n\n... [truncated]' : '');
            document.getElementById('outputContent').textContent = preview;
            
            // Update stats
            if (data.stats) {
                document.getElementById('bytecodeSize').textContent = formatBytes(data.stats.bytecode_size);
                document.getElementById('runtimeSize').textContent = formatBytes(data.stats.runtime_size);
            }
            document.getElementById('buildTime').textContent = elapsed + 'ms';
            
            // Show build ID
            if (data.build_id) {
                document.getElementById('buildId').textContent = 'Build: ' + data.build_id.substring(0, 8);
            }
        }

        function showStatus(type, message) {
            const status = document.getElementById('statusMessage');
            status.className = 'status ' + type;
            status.innerHTML = (type === 'success' ? '✅' : '❌') + ' ' + message;
        }

        function hideStatus() {
            document.getElementById('statusMessage').className = 'status';
        }

        function formatBytes(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
            return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
        }

        function copyBytecode() {
            if (lastResponse && lastResponse.bytecode) {
                navigator.clipboard.writeText(lastResponse.bytecode);
                showStatus('success', 'Bytecode copied to clipboard!');
            }
        }

        function copyRuntime() {
            if (lastResponse && lastResponse.runtime) {
                navigator.clipboard.writeText(lastResponse.runtime);
                showStatus('success', 'Runtime copied to clipboard!');
            }
        }

        function downloadOutput() {
            if (!lastResponse) return;
            
            const content = JSON.stringify(lastResponse, null, 2);
            const blob = new Blob([content], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'virtualized-' + (lastResponse.build_id || 'output') + '.json';
            a.click();
            URL.revokeObjectURL(url);
        }

        // Add sample code on load
        document.addEventListener('DOMContentLoaded', function() {
            const textarea = document.getElementById('code');
            if (!textarea.value.trim()) {
                textarea.value = `// Sample code - try virtualizing this!
function secretAlgorithm(data) {
    const key = 'super-secret-key';
    let result = [];
    
    for (let i = 0; i < data.length; i++) {
        result.push(data[i] ^ key.charCodeAt(i % key.length));
    }
    
    return result;
}

// License validation
function validateLicense(key) {
    const hash = key.split('').reduce((a, b) => {
        return ((a << 5) - a) + b.charCodeAt(0);
    }, 0);
    return hash === 0x7F3A2B1C;
}`;
            }
        });
    </script>
</body>
</html>"##;

    send_html_response(stream, 200, "OK", html)
}

fn handle_health(stream: &mut TcpStream) -> std::io::Result<()> {
    let response = r#"{"status":"ok","service":"virtualizer"}"#;
    send_json_response(stream, 200, "OK", response)
}

fn handle_virtualize(stream: &mut TcpStream, body: &[u8]) -> std::io::Result<()> {
    // Parse request
    let body_str = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return send_json_response(stream, 400, "Bad Request", 
            r#"{"error":"Invalid UTF-8 in request body"}"#),
    };
    
    let request: VirtualizeRequest = match serde_json::from_str(body_str) {
        Ok(r) => r,
        Err(e) => return send_json_response(stream, 400, "Bad Request",
            &format!(r#"{{"error":"Invalid JSON: {}"}}"#, e)),
    };
    
    // Build configuration
    let mut config = BuildConfig::default();
    
    if let Some(opts) = &request.options {
        config.aggressive_obfuscation = opts.aggressive.unwrap_or(true);
        config.strip_symbols = opts.strip_symbols.unwrap_or(true);
        config.anti_debug = opts.anti_debug.unwrap_or(true);
        config.compress = opts.compress.unwrap_or(true);
        
        if let Some(enc) = &opts.encryption {
            config.encryption = match enc.as_str() {
                "aes" => crate::build_pipeline::EncryptionType::AesGcm,
                "xchacha" => crate::build_pipeline::EncryptionType::XChaCha20,
                _ => crate::build_pipeline::EncryptionType::Both,
            };
        }
    }
    
    // Run build pipeline
    let mut pipeline = BuildPipeline::new(config);
    
    match pipeline.build(&request.code, &request.language) {
        Ok(output) => {
            let response = VirtualizeResponse {
                success: true,
                error: None,
                build_id: Some(output.manifest.build_id),
                bytecode: Some(base64_encode(&output.bytecode)),
                runtime: Some(output.vm_runtime),
                stats: Some(super::api::BuildStats {
                    bytecode_size: output.bytecode.len(),
                    runtime_size: output.manifest.runtime_size,
                    timestamp: output.manifest.timestamp,
                }),
            };
            
            let json = serde_json::to_string(&response).unwrap_or_default();
            send_json_response(stream, 200, "OK", &json)
        }
        Err(e) => {
            let response = VirtualizeResponse {
                success: false,
                error: Some(e.to_string()),
                build_id: None,
                bytecode: None,
                runtime: None,
                stats: None,
            };
            
            let json = serde_json::to_string(&response).unwrap_or_default();
            send_json_response(stream, 400, "Bad Request", &json)
        }
    }
}

fn handle_cors_preflight(stream: &mut TcpStream) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 204 No Content\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type\r\n\
         Access-Control-Max-Age: 86400\r\n\
         \r\n"
    );
    stream.write_all(response.as_bytes())
}

fn send_response(stream: &mut TcpStream, status: u16, status_text: &str, body: &str) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        status, status_text, body.len(), body
    );
    stream.write_all(response.as_bytes())
}

fn send_json_response(stream: &mut TcpStream, status: u16, status_text: &str, body: &str) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        status, status_text, body.len(), body
    );
    stream.write_all(response.as_bytes())
}

fn send_html_response(stream: &mut TcpStream, status: u16, status_text: &str, body: &str) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        status, status_text, body.len(), body
    );
    stream.write_all(response.as_bytes())
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    let mut result = String::new();
    let mut i = 0;
    
    while i < data.len() {
        let b0 = data[i] as usize;
        let b1 = data.get(i + 1).copied().unwrap_or(0) as usize;
        let b2 = data.get(i + 2).copied().unwrap_or(0) as usize;
        
        result.push(ALPHABET[(b0 >> 2) & 0x3F] as char);
        result.push(ALPHABET[((b0 << 4) | (b1 >> 4)) & 0x3F] as char);
        
        if i + 1 < data.len() {
            result.push(ALPHABET[((b1 << 2) | (b2 >> 6)) & 0x3F] as char);
        } else {
            result.push('=');
        }
        
        if i + 2 < data.len() {
            result.push(ALPHABET[b2 & 0x3F] as char);
        } else {
            result.push('=');
        }
        
        i += 3;
    }
    
    result
}
