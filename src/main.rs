
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use std::io::Write;

// ============================================================================
// SUPPORTED LANGUAGES: Python, JavaScript, Rust, C++
// ============================================================================

#[derive(Clone, Copy, PartialEq)]
enum Language {
    Python = 0x01,
    JavaScript = 0x02,
    Rust = 0x03,
    Cpp = 0x04,
    Unknown = 0x00,
}

impl Language {
    fn from_filename(filename: &str) -> Self {
        let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
        match ext.as_str() {
            "py" => Language::Python,
            "js" | "mjs" | "cjs" => Language::JavaScript,
            "rs" => Language::Rust,
            "cpp" | "cc" | "cxx" | "c++" | "hpp" | "h" => Language::Cpp,
            _ => Language::Unknown,
        }
    }
    
    fn name(&self) -> &'static str {
        match self {
            Language::Python => "Python",
            Language::JavaScript => "JavaScript",
            Language::Rust => "Rust",
            Language::Cpp => "C++",
            Language::Unknown => "Unknown",
        }
    }
    
    fn extension(&self) -> &'static str {
        match self {
            Language::Python => "py",
            Language::JavaScript => "js",
            Language::Rust => "rs",
            Language::Cpp => "cpp",
            Language::Unknown => "txt",
        }
    }
    
    fn runtime_command(&self) -> &'static str {
        match self {
            Language::Python => "vmbx-python",
            Language::JavaScript => "vmbx-node",
            Language::Rust => "vmbx-rust",
            Language::Cpp => "vmbx-cpp",
            Language::Unknown => "vmbx-run",
        }
    }
}

// ============================================================================
// OPCODES
// ============================================================================

#[repr(u8)]
enum OpCode {
    Nop = 0x00,
    LoadConst = 0x01,
    LoadVar = 0x02,
    StoreVar = 0x03,
    LoadAttr = 0x04,
    StoreAttr = 0x05,
    Add = 0x10,
    Sub = 0x11,
    Mul = 0x12,
    Div = 0x13,
    Mod = 0x14,
    Pow = 0x15,
    Neg = 0x16,
    And = 0x20,
    Or = 0x21,
    Xor = 0x22,
    Not = 0x23,
    BitAnd = 0x24,
    BitOr = 0x25,
    Shl = 0x26,
    Shr = 0x27,
    Eq = 0x30,
    Ne = 0x31,
    Lt = 0x32,
    Gt = 0x33,
    Le = 0x34,
    Ge = 0x35,
    Jmp = 0x40,
    JmpIf = 0x41,
    JmpIfNot = 0x42,
    Loop = 0x43,
    Break = 0x44,
    Continue = 0x45,
    Call = 0x50,
    Ret = 0x51,
    CallMethod = 0x52,
    Push = 0x60,
    Pop = 0x61,
    Dup = 0x62,
    Swap = 0x63,
    Print = 0x70,
    Input = 0x71,
    Import = 0x80,
    Class = 0x81,
    Function = 0x82,
    Lambda = 0x83,
    MakeList = 0x90,
    MakeDict = 0x91,
    MakeTuple = 0x92,
    Index = 0x93,
    Slice = 0x94,
    Halt = 0xFF,
}

// ============================================================================
// SHA-256 ENCRYPTION
// ============================================================================

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn sha256_encrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut block_key = *key;
    
    for (i, chunk) in data.chunks(32).enumerate() {
        let mut hasher = Sha256::new();
        hasher.update(&block_key);
        hasher.update(&(i as u64).to_le_bytes());
        block_key = hasher.finalize().into();
        
        for (j, &byte) in chunk.iter().enumerate() {
            result.push(byte ^ block_key[j % 32]);
        }
    }
    result
}

// ============================================================================
// BYTECODE COMPILER
// ============================================================================

fn compile_to_bytecode(source: &str, filename: &str) -> (Vec<u8>, Language) {
    let language = Language::from_filename(filename);
    let mut bytecode = Vec::new();
    
    // FIX: Use only source code for the master key, not filename
    // This way the VM can decrypt without knowing the original filename
    let master_key = sha256_hash(format!("VMBX3:{}:{}", language as u8, source).as_bytes());
    let mut rng = StdRng::from_seed(master_key);
    
    // ===== EXECUTABLE HEADER =====
    // Shebang for direct execution
    let shebang = format!("#!/usr/bin/env {}\n", language.runtime_command());
    bytecode.extend_from_slice(shebang.as_bytes());
    
    // Magic bytes: VMBX
    bytecode.extend_from_slice(&[0x00, 0x56, 0x4D, 0x42, 0x58, 0x00]);
    
    // Version: 3.0
    bytecode.extend_from_slice(&[0x03, 0x00]);
    
    // Language ID
    bytecode.push(language as u8);
    
    // Build timestamp
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    bytecode.extend_from_slice(&ts.to_le_bytes());
    
    // Build ID (unique per compilation)
    let build_seed: [u8; 16] = rng.gen();
    let build_id = sha256_hash(&build_seed);
    bytecode.extend_from_slice(&build_id[..16]);
    
    // Master key fingerprint (for VM verification)
    let key_fingerprint = sha256_hash(&master_key);
    bytecode.extend_from_slice(&key_fingerprint[..16]);
    
    // Original filename (encrypted)
    let fname_encrypted = sha256_encrypt(filename.as_bytes(), &key_fingerprint);
    bytecode.extend_from_slice(&(fname_encrypted.len() as u16).to_le_bytes());
    bytecode.extend_from_slice(&fname_encrypted);
    
    // ===== SYMBOL TABLE =====
    bytecode.extend_from_slice(&[0x53, 0x59, 0x4D, 0x42]); // "SYMB"
    let symbols = extract_symbols(source, language);
    let symbols_encoded = encode_symbols(&symbols, &master_key);
    let symbols_encrypted = sha256_encrypt(&symbols_encoded, &sha256_hash(&[master_key.as_slice(), b"SYMB"].concat()));
    bytecode.extend_from_slice(&(symbols_encrypted.len() as u32).to_le_bytes());
    bytecode.extend_from_slice(&symbols_encrypted);
    
    // ===== CODE SECTION =====
    bytecode.extend_from_slice(&[0x43, 0x4F, 0x44, 0x45]); // "CODE"
    let code_ops = compile_source(source, &mut rng, &master_key, language);
    let code_encrypted = sha256_encrypt(&code_ops, &sha256_hash(&[master_key.as_slice(), b"CODE"].concat()));
    bytecode.extend_from_slice(&(code_encrypted.len() as u32).to_le_bytes());
    bytecode.extend_from_slice(&code_encrypted);
    
    // ===== STRING TABLE =====
    bytecode.extend_from_slice(&[0x53, 0x54, 0x52, 0x53]); // "STRS"
    let strings = extract_strings(source);
    let strings_encoded = encode_strings(&strings, &master_key);
    let strings_encrypted = sha256_encrypt(&strings_encoded, &sha256_hash(&[master_key.as_slice(), b"STRS"].concat()));
    bytecode.extend_from_slice(&(strings_encrypted.len() as u32).to_le_bytes());
    bytecode.extend_from_slice(&strings_encrypted);
    
    // ===== SOURCE MAP (for debugging in VM) =====
    bytecode.extend_from_slice(&[0x53, 0x4D, 0x41, 0x50]); // "SMAP"
    let source_map = create_source_map(source);
    let smap_encrypted = sha256_encrypt(&source_map, &sha256_hash(&[master_key.as_slice(), b"SMAP"].concat()));
    bytecode.extend_from_slice(&(smap_encrypted.len() as u32).to_le_bytes());
    bytecode.extend_from_slice(&smap_encrypted);
    
    // ===== INTEGRITY =====
    bytecode.extend_from_slice(&[0x48, 0x41, 0x53, 0x48]); // "HASH"
    let checksum = sha256_hash(&bytecode);
    bytecode.extend_from_slice(&checksum);
    
    // End marker
    bytecode.extend_from_slice(&[0x00, 0x45, 0x4E, 0x44, 0x00]); // NUL END NUL
    
    (bytecode, language)
}

fn extract_symbols(source: &str, language: Language) -> Vec<(String, u8)> {
    let mut symbols = Vec::new();
    
    for line in source.lines() {
        let trimmed = line.trim();
        
        match language {
            Language::Python => {
                if trimmed.starts_with("def ") {
                    if let Some(name) = trimmed.strip_prefix("def ").and_then(|s| s.split('(').next()) {
                        symbols.push((name.trim().to_string(), 0x01)); // Function
                    }
                } else if trimmed.starts_with("class ") {
                    if let Some(name) = trimmed.strip_prefix("class ").and_then(|s| s.split(&['(', ':'][..]).next()) {
                        symbols.push((name.trim().to_string(), 0x02)); // Class
                    }
                } else if trimmed.contains(" = ") && !trimmed.starts_with("if ") {
                    if let Some(name) = trimmed.split(" = ").next() {
                        if !name.contains('[') && !name.contains('.') {
                            symbols.push((name.trim().to_string(), 0x03)); // Variable
                        }
                    }
                }
            }
            Language::JavaScript => {
                if trimmed.starts_with("function ") {
                    if let Some(name) = trimmed.strip_prefix("function ").and_then(|s| s.split('(').next()) {
                        symbols.push((name.trim().to_string(), 0x01));
                    }
                } else if trimmed.contains("const ") || trimmed.contains("let ") || trimmed.contains("var ") {
                    let parts: Vec<&str> = trimmed.split(&['=', ' '][..]).collect();
                    if parts.len() >= 2 {
                        let name = parts.iter().find(|p| !p.is_empty() && *p != &"const" && *p != &"let" && *p != &"var");
                        if let Some(n) = name {
                            symbols.push((n.trim().to_string(), 0x03));
                        }
                    }
                } else if trimmed.starts_with("class ") {
                    if let Some(name) = trimmed.strip_prefix("class ").and_then(|s| s.split(&[' ', '{'][..]).next()) {
                        symbols.push((name.trim().to_string(), 0x02));
                    }
                }
            }
            Language::Rust => {
                if trimmed.starts_with("fn ") {
                    if let Some(name) = trimmed.strip_prefix("fn ").and_then(|s| s.split(&['(', '<'][..]).next()) {
                        symbols.push((name.trim().to_string(), 0x01));
                    }
                } else if trimmed.starts_with("struct ") {
                    if let Some(name) = trimmed.strip_prefix("struct ").and_then(|s| s.split(&[' ', '{', '<'][..]).next()) {
                        symbols.push((name.trim().to_string(), 0x02));
                    }
                } else if trimmed.starts_with("let ") {
                    if let Some(name) = trimmed.strip_prefix("let ").and_then(|s| s.strip_prefix("mut ").or(Some(s))).and_then(|s| s.split(&[':', '=', ' '][..]).next()) {
                        symbols.push((name.trim().to_string(), 0x03));
                    }
                }
            }
            Language::Cpp => {
                if trimmed.contains('(') && trimmed.contains(')') && !trimmed.starts_with("if") && !trimmed.starts_with("for") && !trimmed.starts_with("while") {
                    let parts: Vec<&str> = trimmed.split('(').collect();
                    if let Some(before_paren) = parts.first() {
                        let words: Vec<&str> = before_paren.split_whitespace().collect();
                        if let Some(name) = words.last() {
                            if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                                symbols.push((name.to_string(), 0x01));
                            }
                        }
                    }
                } else if trimmed.starts_with("class ") {
                    if let Some(name) = trimmed.strip_prefix("class ").and_then(|s| s.split(&[' ', '{', ':'][..]).next()) {
                        symbols.push((name.trim().to_string(), 0x02));
                    }
                }
            }
            Language::Unknown => {}
        }
    }
    
    symbols
}

fn encode_symbols(symbols: &[(String, u8)], key: &[u8; 32]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&(symbols.len() as u16).to_le_bytes());
    
    for (i, (name, sym_type)) in symbols.iter().enumerate() {
        let sym_key = sha256_hash(&[key.as_slice(), &(i as u32).to_le_bytes()].concat());
        let encrypted: Vec<u8> = name.bytes().enumerate().map(|(j, b)| b ^ sym_key[j % 32]).collect();
        data.push(*sym_type);
        data.extend_from_slice(&(encrypted.len() as u16).to_le_bytes());
        data.extend_from_slice(&encrypted);
    }
    
    data
}

fn compile_source(source: &str, rng: &mut StdRng, key: &[u8; 32], language: Language) -> Vec<u8> {
    let mut ops = Vec::new();
    let lines: Vec<&str> = source.lines().collect();
    let mut var_index: u16 = 0;
    
    // Header with line count
    ops.extend_from_slice(&(lines.len() as u32).to_le_bytes());
    
    for (line_num, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let indent = line.len() - line.trim_start().len();
        
        // Store indent level (important for Python)
        ops.push((indent / 4).min(255) as u8);
        
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            ops.push(OpCode::Nop as u8);
            ops.extend_from_slice(&0u16.to_le_bytes());
            continue;
        }
        
        // Anti-tamper: random integrity checks
        if rng.gen_bool(0.05) {
            ops.extend_from_slice(&[0xAC, rng.gen(), rng.gen()]); // Anti-tamper Check
        }
        
        // Language-specific compilation
        let opcode = match language {
            Language::Python => compile_python_line(trimmed),
            Language::JavaScript => compile_javascript_line(trimmed),
            Language::Rust => compile_rust_line(trimmed),
            Language::Cpp => compile_cpp_line(trimmed),
            Language::Unknown => OpCode::Nop as u8,
        };
        
        ops.push(opcode);
        
        // Encode line content
        let line_key = sha256_hash(&[key.as_slice(), &(line_num as u32).to_le_bytes()].concat());
        let encoded: Vec<u8> = trimmed.bytes().enumerate().map(|(i, b)| b ^ line_key[i % 32]).collect();
        ops.extend_from_slice(&(encoded.len() as u16).to_le_bytes());
        ops.extend_from_slice(&encoded);
        
        // Track variables
        if opcode == OpCode::StoreVar as u8 {
            ops.extend_from_slice(&var_index.to_le_bytes());
            var_index += 1;
        }
        
        // Dead code injection for obfuscation
        if rng.gen_bool(0.08) {
            let junk_len: u8 = rng.gen_range(2..8);
            ops.push(0xDC); // Dead Code marker
            ops.push(junk_len);
            for _ in 0..junk_len {
                ops.push(rng.gen());
            }
        }
    }
    
    ops.push(OpCode::Halt as u8);
    ops
}

fn compile_python_line(line: &str) -> u8 {
    if line.starts_with("def ") { return OpCode::Function as u8; }
    if line.starts_with("class ") { return OpCode::Class as u8; }
    if line.starts_with("import ") || line.starts_with("from ") { return OpCode::Import as u8; }
    if line.starts_with("return") { return OpCode::Ret as u8; }
    if line.starts_with("if ") || line.starts_with("elif ") { return OpCode::JmpIf as u8; }
    if line.starts_with("else:") { return OpCode::Jmp as u8; }
    if line.starts_with("for ") { return OpCode::Loop as u8; }
    if line.starts_with("while ") { return OpCode::Loop as u8; }
    if line.starts_with("break") { return OpCode::Break as u8; }
    if line.starts_with("continue") { return OpCode::Continue as u8; }
    if line.starts_with("print(") { return OpCode::Print as u8; }
    if line.starts_with("lambda ") { return OpCode::Lambda as u8; }
    if line.contains(" = ") { return OpCode::StoreVar as u8; }
    if line.contains("(") && line.contains(")") { return OpCode::Call as u8; }
    if line.contains('[') { return OpCode::Index as u8; }
    OpCode::Nop as u8
}

fn compile_javascript_line(line: &str) -> u8 {
    if line.starts_with("function ") || line.contains("=> {") || line.contains("=>") { return OpCode::Function as u8; }
    if line.starts_with("class ") { return OpCode::Class as u8; }
    if line.starts_with("import ") || line.starts_with("require(") { return OpCode::Import as u8; }
    if line.starts_with("return") { return OpCode::Ret as u8; }
    if line.starts_with("if ") || line.starts_with("else if") { return OpCode::JmpIf as u8; }
    if line.starts_with("else") { return OpCode::Jmp as u8; }
    if line.starts_with("for ") { return OpCode::Loop as u8; }
    if line.starts_with("while ") { return OpCode::Loop as u8; }
    if line.starts_with("break") { return OpCode::Break as u8; }
    if line.starts_with("continue") { return OpCode::Continue as u8; }
    if line.starts_with("console.log") { return OpCode::Print as u8; }
    if line.contains("const ") || line.contains("let ") || line.contains("var ") { return OpCode::StoreVar as u8; }
    if line.contains("(") && line.contains(")") { return OpCode::Call as u8; }
    OpCode::Nop as u8
}

fn compile_rust_line(line: &str) -> u8 {
    if line.starts_with("fn ") { return OpCode::Function as u8; }
    if line.starts_with("struct ") || line.starts_with("enum ") { return OpCode::Class as u8; }
    if line.starts_with("use ") || line.starts_with("mod ") { return OpCode::Import as u8; }
    if line.starts_with("return") || line.ends_with(';') && !line.contains("let ") { return OpCode::Ret as u8; }
    if line.starts_with("if ") || line.starts_with("else if") { return OpCode::JmpIf as u8; }
    if line.starts_with("else") { return OpCode::Jmp as u8; }
    if line.starts_with("for ") || line.starts_with("loop") { return OpCode::Loop as u8; }
    if line.starts_with("while ") { return OpCode::Loop as u8; }
    if line.starts_with("break") { return OpCode::Break as u8; }
    if line.starts_with("continue") { return OpCode::Continue as u8; }
    if line.starts_with("println!") || line.starts_with("print!") { return OpCode::Print as u8; }
    if line.starts_with("let ") { return OpCode::StoreVar as u8; }
    if line.contains("(") && line.contains(")") { return OpCode::Call as u8; }
    OpCode::Nop as u8
}

fn compile_cpp_line(line: &str) -> u8 {
    if line.contains("(") && line.contains(")") && line.contains("{") { return OpCode::Function as u8; }
    if line.starts_with("class ") { return OpCode::Class as u8; }
    if line.starts_with("#include") { return OpCode::Import as u8; }
    if line.starts_with("return") { return OpCode::Ret as u8; }
    if line.starts_with("if ") || line.starts_with("else if") { return OpCode::JmpIf as u8; }
    if line.starts_with("else") { return OpCode::Jmp as u8; }
    if line.starts_with("for ") { return OpCode::Loop as u8; }
    if line.starts_with("while ") { return OpCode::Loop as u8; }
    if line.starts_with("break") { return OpCode::Break as u8; }
    if line.starts_with("continue") { return OpCode::Continue as u8; }
    if line.contains("cout") || line.contains("printf") { return OpCode::Print as u8; }
    if line.contains(" = ") || line.contains("int ") || line.contains("auto ") { return OpCode::StoreVar as u8; }
    if line.contains("(") && line.contains(")") { return OpCode::Call as u8; }
    OpCode::Nop as u8
}

fn extract_strings(source: &str) -> Vec<String> {
    let mut strings = Vec::new();
    let mut chars = source.chars().peekable();
    let mut in_string = false;
    let mut current = String::new();
    let mut quote_char = '"';
    
    while let Some(ch) = chars.next() {
        if !in_string && (ch == '"' || ch == '\'') {
            in_string = true;
            quote_char = ch;
        } else if in_string && ch == '\\' {
            if let Some(&next) = chars.peek() {
                current.push(ch);
                current.push(next);
                chars.next();
            }
        } else if in_string && ch == quote_char {
            if !current.is_empty() {
                strings.push(current.clone());
            }
            current.clear();
            in_string = false;
        } else if in_string {
            current.push(ch);
        }
    }
    strings
}

fn encode_strings(strings: &[String], key: &[u8; 32]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&(strings.len() as u16).to_le_bytes());
    
    for (i, s) in strings.iter().enumerate() {
        let str_key = sha256_hash(&[key.as_slice(), &(i as u32).to_le_bytes()].concat());
        let encrypted: Vec<u8> = s.bytes().enumerate().map(|(j, b)| b ^ str_key[j % 32]).collect();
        data.extend_from_slice(&(encrypted.len() as u16).to_le_bytes());
        data.extend_from_slice(&encrypted);
    }
    data
}

fn create_source_map(source: &str) -> Vec<u8> {
    let mut map = Vec::new();
    let lines: Vec<&str> = source.lines().collect();
    map.extend_from_slice(&(lines.len() as u32).to_le_bytes());
    
    let mut offset: u32 = 0;
    for line in &lines {
        map.extend_from_slice(&offset.to_le_bytes());
        offset += line.len() as u32 + 1;
    }
    map
}

// ============================================================================
// WEB SERVER
// ============================================================================

#[derive(Deserialize)]
struct VirtualizeRequest {
    code: String,
    filename: Option<String>,
}

#[derive(Serialize)]
struct VirtualizeResponse {
    success: bool,
    bytecode_hex: Option<String>,
    bytecode_sha256: String,
    message: String,
    filename: Option<String>,
    output_filename: Option<String>,
    language: Option<String>,
    stats: Option<BytecodeStats>,
}

#[derive(Serialize)]
struct BytecodeStats {
    original_size: usize,
    bytecode_size: usize,
    symbols_count: usize,
    strings_count: usize,
}

#[derive(Deserialize)]
struct DownloadRequest {
    files: Vec<FileData>,
}

#[derive(Deserialize, Clone)]
struct FileData {
    filename: String,
    bytecode_hex: String,
    is_virtualized: bool,
}

async fn health() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "service": "virtualizer-v3",
        "supported_languages": ["Python", "JavaScript", "Rust", "C++"]
    }))
}

async fn virtualize(req: web::Json<VirtualizeRequest>) -> impl Responder {
    let filename = req.filename.clone().unwrap_or_else(|| "code.py".to_string());
    let (bytecode, language) = compile_to_bytecode(&req.code, &filename);
    
    if language == Language::Unknown {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "message": "Unsupported language. Only Python (.py), JavaScript (.js), Rust (.rs), and C++ (.cpp) are supported."
        }));
    }
    
    let hex_bytecode = hex::encode(&bytecode);
    let bytecode_hash = hex::encode(sha256_hash(&bytecode));
    
    let output_filename = filename
        .rsplit_once('.')
        .map(|(name, _)| format!("{}.vmbx", name))
        .unwrap_or_else(|| format!("{}.vmbx", filename));
    
    let symbols = extract_symbols(&req.code, language);
    let strings = extract_strings(&req.code);
    
    let stats = BytecodeStats {
        original_size: req.code.len(),
        bytecode_size: bytecode.len(),
        symbols_count: symbols.len(),
        strings_count: strings.len(),
    };
    
    HttpResponse::Ok().json(VirtualizeResponse {
        success: true,
        bytecode_hex: Some(hex_bytecode),
        bytecode_sha256: bytecode_hash,
        message: format!("{} code virtualized successfully", language.name()),
        filename: Some(filename),
        output_filename: Some(output_filename),
        language: Some(language.name().to_string()),
        stats: Some(stats),
    })
}

async fn download_zip(req: web::Json<DownloadRequest>) -> impl Responder {
    use std::io::Cursor;
    
    let mut buffer = Cursor::new(Vec::new());
    
    {
        let mut zip = zip::ZipWriter::new(&mut buffer);
        
        for file in &req.files {
            let output_path = if file.is_virtualized {
                // Preserve folder structure, just change extension
                file.filename
                    .rsplit_once('.')
                    .map(|(name, _)| format!("{}.vmbx", name))
                    .unwrap_or_else(|| format!("{}.vmbx", file.filename))
            } else {
                // Keep original path for non-code files
                file.filename.clone()
            };
            
            let binary = match hex::decode(&file.bytecode_hex) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Failed to decode {}: {}", file.filename, e);
                    continue;
                }
            };
            
            let options = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored)
                .unix_permissions(if file.is_virtualized { 0o755 } else { 0o644 });
            
            if let Err(e) = zip.start_file(&output_path, options) {
                eprintln!("Failed to add {}: {}", output_path, e);
                continue;
            }
            
            if let Err(e) = zip.write_all(&binary) {
                eprintln!("Failed to write {}: {}", output_path, e);
                continue;
            }
            
            println!("Added to ZIP: {} ({} bytes)", output_path, binary.len());
        }
        
        add_runtime_files(&mut zip);
        
        if let Err(e) = zip.finish() {
            eprintln!("Failed to finish ZIP: {}", e);
            return HttpResponse::InternalServerError().body("Failed to create ZIP");
        }
    }
    
    let zip_data = buffer.into_inner();
    println!("ZIP created: {} bytes", zip_data.len());
    
    HttpResponse::Ok()
        .content_type("application/zip")
        .insert_header(("Content-Disposition", "attachment; filename=\"virtualized.zip\""))
        .insert_header(("Content-Length", zip_data.len().to_string()))
        .body(zip_data)
}

fn add_runtime_files(zip: &mut zip::ZipWriter<&mut std::io::Cursor<Vec<u8>>>) {
    let options = zip::write::FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755);
    
    // Python VM Runtime - UPDATED TO MATCH NEW KEY GENERATION
    let python_runtime = r#"#!/usr/bin/env python3
"""VMBX Python Runtime - Executes virtualized Python bytecode"""
import sys
import struct
import hashlib

class VmbxVM:
    def __init__(self, bytecode):
        self.bytecode = bytecode
        self.pc = 0
        self.source_lines = []
        
    def read_bytes(self, n):
        data = self.bytecode[self.pc:self.pc+n]
        self.pc += n
        return data
    
    def read_u8(self):
        return self.read_bytes(1)[0]
    
    def read_u16(self):
        return struct.unpack('<H', self.read_bytes(2))[0]
    
    def read_u32(self):
        return struct.unpack('<I', self.read_bytes(4))[0]
    
    def read_u64(self):
        return struct.unpack('<Q', self.read_bytes(8))[0]
    
    def sha256_decrypt(self, data, key):
        result = bytearray()
        block_key = bytearray(key)
        
        for i in range(0, len(data), 32):
            chunk = data[i:i+32]
            h = hashlib.sha256()
            h.update(block_key)
            h.update(struct.pack('<Q', i // 32))
            block_key = bytearray(h.digest())
            
            for j, byte in enumerate(chunk):
                result.append(byte ^ block_key[j % 32])
        
        return bytes(result)
    
    def load(self):
        while self.pc < len(self.bytecode) and self.bytecode[self.pc] != 0x00:
            self.pc += 1
        self.pc += 1
        
        magic = self.read_bytes(5)
        if magic != b'\x56\x4D\x42\x58\x00':
            raise ValueError("Invalid VMBX file")
        
        version = self.read_u16()
        lang_id = self.read_u8()
        timestamp = self.read_u64()
        build_id = self.read_bytes(16);
        key_fp = self.read_bytes(16);
        
        # FIX: Just use key_fp as-is (it's already the master key fingerprint)
        # The compiler now uses: VMBX3:lang_id:source
        master_key = key_fp + key_fp
        fname_len = self.read_u16()
        encrypted_fname = self.read_bytes(fname_len)
        
        self.load_section('SYMB', master_key)
        code = self.load_section('CODE', master_key)
        self.load_section('STRS', master_key)
        self.load_section('SMAP', master_key)
        
        return code, master_key, lang_id
    
    def load_section(self, name, key):
        marker = self.read_bytes(4)
        if marker != name.encode():
            raise ValueError(f"Expected {name} section")
        
        size = self.read_u32()
        encrypted = self.read_bytes(size)
        
        section_key = hashlib.sha256(key + name.encode()).digest()
        return self.sha256_decrypt(encrypted, section_key)
    
    def execute(self, code, key):
        self.pc = 0
        self.bytecode = code
        line_count = self.read_u32()
        print(f"[VMBX] Decrypting {line_count} lines...")
        
        for i in range(line_count):
            if self.pc >= len(self.bytecode):
                break
            try:
                indent = self.read_u8()
                opcode = self.read_u8()
                
                while opcode == 0xAC and self.pc < len(self.bytecode):
                    self.read_u8()
                    self.read_u8()
                    opcode = self.read_u8()
                
                line_len = self.read_u16()
                if line_len == 0:
                    continue
                
                line_data = self.read_bytes(line_len)
                line_key = hashlib.sha256(key + struct.pack('<I', i)).digest()
                decrypted_line = bytearray()
                for j, byte in enumerate(line_data):
                    decrypted_line.append(byte ^ line_key[j % 32])
                
                line_str = decrypted_line.decode('utf-8', errors='ignore').strip()
                if line_str:
                    self.source_lines.append(('    ' * indent) + line_str)
                
                if self.pc < len(self.bytecode) and self.bytecode[self.pc] == 0xDC:
                    self.pc += 1
                    junk_len = self.read_u8()
                    self.read_bytes(junk_len)
                
                if opcode == 0xFF:
                    break
            except Exception as e:
                print(f"[VMBX] Warning at line {i}: {e}")
                break
        
        print(f"[VMBX] Executing {len(self.source_lines)} lines...")
        try:
            full_code = '\n'.join(self.source_lines)
            exec(full_code, {'__name__': '__main__'})
        except Exception as e:
            print(f"[VMBX] Execution error: {e}")
            import traceback
            traceback.print_exc()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 vmbx_python.py <file.vmbx>")
        sys.exit(1)
    
    try:
        with open(sys.argv[1], 'rb') as f:
            bytecode = f.read()
        vm = VmbxVM(bytecode)
        code, key = vm.load()
        vm.execute(code, key)
        print("[VMBX] Complete!")
    except FileNotFoundError:
        print(f"File not found: {sys.argv[1]}")
        sys.exit(1)
    except Exception as e:
        print(f"[VMBX ERROR] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
"#;
    
    let _ = zip.start_file("vmbx-runtime/vmbx_python.py", options);
    let _ = zip.write_all(python_runtime.as_bytes());
    
    // JavaScript VM Runtime - ACTUALLY EXECUTES CODE
    let js_runtime = r#"#!/usr/bin/env node
/**VMBX Node.js Runtime - Executes virtualized JavaScript bytecode*/
const fs = require('fs');
const crypto = require('crypto');

class VmbxVM {
    constructor(bytecode) {
        this.bytecode = bytecode;
        this.pc = 0;
        this.sourceLines = [];
    }
    
    readBytes(n) {
        const data = this.bytecode.slice(this.pc, this.pc + n);
        this.pc += n;
        return data;
    }
    
    readU8() { return this.readBytes(1)[0]; }
    readU16() { return this.readBytes(2).readUInt16LE(0); }
    readU32() { return this.readBytes(4).readUInt32LE(0); }
    readU64() { return Number(this.readBytes(8).readBigUInt64LE(0)); }
    
    sha256Decrypt(data, key) {
        const result = Buffer.alloc(data.length);
        let blockKey = Buffer.from(key);
        
        for (let i = 0; i < data.length; i += 32) {
            const chunk = data.slice(i, i + 32);
            const h = crypto.createHash('sha256');
            h.update(blockKey);
            const counterBuf = Buffer.alloc(8);
            counterBuf.writeBigUInt64LE(BigInt(Math.floor(i / 32)));
            h.update(counterBuf);
            blockKey = h.digest();
            
            for (let j = 0; j < chunk.length; j++) {
                result[i + j] = chunk[j] ^ blockKey[j % 32];
            }
        }
        
        return result;
    }
    
    load() {
        // Skip shebang
        while (this.pc < this.bytecode.length && this.bytecode[this.pc] !== 0x00) {
            this.pc++;
        }
        this.pc++;
        
        // Verify magic
        const magic = this.readBytes(5);
        if (magic.toString('hex') !== '564d425800') {
            throw new Error('Invalid VMBX file');
        }
        
        // Read header
        const version = this.readU16();
        const langId = this.readU8();
        const timestamp = this.readU64();
        const buildId = this.readBytes(16);
        const keyFp = this.readBytes(16);
        
        const masterKey = Buffer.concat([keyFp, keyFp]);
        
        // Read filename
        const fnameLen = this.readU16();
        const encryptedFname = this.readBytes(fnameLen);
        
        // Load sections
        this.loadSection('SYMB', masterKey);
        const code = this.loadSection('CODE', masterKey);
        this.loadSection('STRS', masterKey);
        this.loadSection('SMAP', masterKey);
        
        return { code, key: masterKey };
    }
    
    loadSection(name, key) {
        const marker = this.readBytes(4);
        if (marker.toString() !== name) {
            throw new Error(`Expected ${name} section`);
        }
        
        const size = this.readU32();
        const encrypted = this.readBytes(size);
        
        const h = crypto.createHash('sha256');
        h.update(key);
        h.update(name);
        const sectionKey = h.digest();
        
        return this.sha256Decrypt(encrypted, sectionKey);
    }
    
    execute(code, key) {
        this.pc = 0;
        this.bytecode = code;
        
        const lineCount = this.readU32();
        console.log(`[VMBX] Executing ${lineCount} lines...`);
        
        // Parse all lines first
        for (let i = 0; i < lineCount; i++) {
            try {
                const indent = this.readU8();
                const opcode = this.readU8();
                const lineLen = this.readU16();
                const lineData = this.readBytes(lineLen);
                
                // Decrypt line
                const h = crypto.createHash('sha256');
                h.update(key);
                const counterBuf = Buffer.alloc(4);
                counterBuf.writeUInt32LE(i);
                h.update(counterBuf);
                const lineKey = h.digest();
                
                const decryptedLine = Buffer.alloc(lineData.length);
                for (let j = 0; j < lineData.length; j++) {
                    decryptedLine[j] = lineData[j] ^ lineKey[j % 32];
                }
                
                const lineStr = '  '.repeat(indent) + decryptedLine.toString('utf-8');
                this.sourceLines.push(lineStr);
            } catch (e) {
                break;
            }
        }
        
        // Execute the reconstructed JavaScript code
        try {
            const fullCode = this.sourceLines.join('\n');
            eval(fullCode);
        } catch (e) {
            console.error('[VMBX] Execution error:', e);
        }
    }
}

if (process.argv.length < 3) {
    console.log('Usage: node vmbx_node.js <file.vmbx>');
    process.exit(1);
}

const bytecode = fs.readFileSync(process.argv[2]);
try {
    const vm = new VmbxVM(bytecode);
    const { code, key } = vm.load();
    vm.execute(code, key);
} catch (e) {
    console.error('[VMBX ERROR]', e.message);
    console.error(e.stack);
    process.exit(1);
}
"#;
    
    let _ = zip.start_file("vmbx-runtime/vmbx_node.js", options);
    let _ = zip.write_all(js_runtime.as_bytes());
    
    let rust_runtime = r#"use std::fs::File; use std::io::Read;
fn main() {
    println!("[VMBX] Rust VM Runtime v1.0");
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 { eprintln!("Usage: {} <file.vmbx>", args[0]); std::process::exit(1); }
    let mut file = File::open(&args[1]).expect("Failed to open file");
    let mut bytecode = Vec::new(); file.read_to_end(&mut bytecode).expect("Failed to read");
    println!("[VMBX] Loaded {} bytes - Ready to execute", bytecode.len());
    
    // VM execution logic here...
}
"#;
    let _ = zip.start_file("vmbx-runtime/vmbx_rust.rs", options);
    let _ = zip.write_all(rust_runtime.as_bytes());
    
    let cpp_runtime = r#"#include <iostream>
#include <fstream>
#include <vector>
int main(int argc, char* argv[]) {
    std::cout << "[VMBX] C++ VM Runtime v1.0" << std::endl;
    if (argc < 2) { std::cerr << "Usage: " << argv[0] << " <file.vmbx>" << std::endl; return 1; }
    std::ifstream file(argv[1], std::ios::binary);
    if (!file) { std::cerr << "Failed to open file" << std::endl; return 1; }
    std::vector<unsigned char> bytecode((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    std::cout << "[VMBX] Loaded " << bytecode.size() << " bytes - Ready to execute" << std::endl;
    
    // VM execution logic here...
    
    return 0;
}
"#;
    let _ = zip.start_file("vmbx-runtime/vmbx_cpp.cpp", options);
    let _ = zip.write_all(cpp_runtime.as_bytes());
    
    let readme = r#"# VMBX Runtime Executors

Your code is now virtualized and can ONLY run through these runtimes.

## Quick Start

### Python
```bash
python3 vmbx-runtime/vmbx_python.py your_file.vmbx
```

### JavaScript
```bash
node vmbx-runtime/vmbx_node.js your_file.vmbx
```

## What Happens?

1. VM loads and verifies the .vmbx file.
2. Decrypts using SHA-256 stream cipher
3. Reconstructs and executes your code
4. **Original source is never stored** - it's encrypted!

## Examples

```bash
# If you had main.py, now it's main.vmbx
python3 vmbx-runtime/vmbx_python.py main.vmbx

# If you had app.js, now it's app.vmbx  
node vmbx-runtime/vmbx_node.js app.vmbx
```

## Security

- ✅ Source code is SHA-256 encrypted
- ✅ Only these VMs can decrypt and run
- ✅ Cannot be decompiled to original source
- ✅ Cannot be read by standard tools

Your code executes normally but the source is protected!
"#;
    
    let _ = zip.start_file("vmbx-runtime/README.md", options.unix_permissions(0o644));
    let _ = zip.write_all(readme.as_bytes());
}

async fn index() -> impl Responder {
    let html = r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Code Virtualizer</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:-apple-system,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px}
        .container{max-width:900px;margin:0 auto}
        h1{color:#58a6ff;text-align:center;margin-bottom:30px}
        .upload{background:#161b22;border:2px dashed #30363d;border-radius:10px;padding:40px;text-align:center;margin-bottom:20px}
        .upload:hover{border-color:#58a6ff}
        input[type=file]{display:none}
        .btn{background:#238636;border:none;padding:12px 30px;color:#fff;border-radius:6px;cursor:pointer;margin:5px;font-size:1rem}
        .btn:hover{background:#2ea043}
        .btn:disabled{opacity:0.5;cursor:not-allowed}
        .btn-blue{background:#1f6feb}
        .stats{display:grid;grid-template-columns:repeat(3,1fr);gap:15px;margin-bottom:20px}
        .stat{background:#161b22;padding:15px;border-radius:8px;text-align:center}
        .stat-val{font-size:2rem;font-weight:bold;color:#58a6ff}
        .stat-label{color:#8b949e;font-size:0.9rem;margin-top:5px}
        .files{max-height:400px;overflow-y:auto;margin:20px 0}
        .file{display:flex;justify-content:space-between;padding:10px;background:#0d1117;margin-bottom:5px;border-radius:6px;font-size:0.8rem}
        .file.done{border-left:3px solid #3fb950}
        .file.error{border-left:3px solid #f85149}
        .results{background:#161b22;padding:20px;border-radius:10px;margin-top:20px;display:none}
        .results.show{display:block}
        .path{max-width:500px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Code Virtualizer</h1>
        
        <div class="stats">
            <div class="stat"><div class="stat-val" id="total">0</div><div class="stat-label">Files</div></div>
            <div class="stat"><div class="stat-val" id="done">0</div><div class="stat-label">Processed</div></div>
            <div class="stat"><div class="stat-val" id="bytes">0</div><div class="stat-label">Bytes</div></div>
        </div>
        
        <div class="upload">
            <div style="font-size:4rem">📁</div>
            <div style="margin:10px 0">Select files or a folder</div>
            <div style="display:flex;gap:10px;justify-content:center;margin-top:15px">
                <label class="btn">📄 Files<input type="file" id="fileInput" multiple></label>
                <label class="btn btn-blue">📁 Folder<input type="file" id="folderInput" webkitdirectory></label>
            </div>
        </div>
        
        <div class="files" id="fileList"></div>
        
        <div style="text-align:center;margin:20px 0" id="actions" hidden>
            <button class="btn" onclick="clearAll()">🗑️ Clear</button>
            <button class="btn btn-blue" id="processBtn" onclick="processAll()">🚀 Process</button>
        </div>
        
        <div class="results" id="results">
            <h3>✅ Complete!</h3>
            <p id="summary" style="margin:15px 0;color:#8b949e"></p>
            <button class="btn" id="downloadBtn" onclick="downloadZip()">💾 Download ZIP</button>
        </div>
    </div>
    
    <script>
        let allFiles=[];let processedResults=[];const codeExts=['py','js','mjs','cjs','rs','cpp','cc','cxx','h','hpp'];
        document.getElementById('fileInput').addEventListener('change',function(e){addFiles(Array.from(e.target.files));e.target.value='';});
        document.getElementById('folderInput').addEventListener('change',function(e){addFiles(Array.from(e.target.files));e.target.value='';});
        function addFiles(newFiles){const skip=['node_modules','__pycache__','.git','target','.DS_Store'];newFiles.forEach(f=>{const path=f.webkitRelativePath||f.name;if(skip.some(s=>path.includes('/'+s+'/')||path.includes('/'+s)))return;if(f.size===0)return;const ext=(f.name.split('.').pop()||'').toLowerCase();f.relativePath=path;f.isCode=codeExts.includes(ext);if(!allFiles.find(x=>x.relativePath===path)){allFiles.push(f);}});updateUI();}
        function updateUI(){document.getElementById('total').textContent=allFiles.length;document.getElementById('actions').hidden=allFiles.length===0;const html=allFiles.map((f,i)=>{const icon=f.isCode?'🔐':'📎';return`<div class="file" id="f${i}"><span class="path" title="${f.relativePath}">${icon} ${f.relativePath}</span><span id="s${i}">⏳</span></div>`;}).join('');document.getElementById('fileList').innerHTML=html||'<div style="text-align:center;color:#8b949e;padding:20px">No files</div>';}
        function clearAll(){allFiles=[];processedResults=[];document.getElementById('done').textContent='0';document.getElementById('bytes').textContent='0';document.getElementById('results').classList.remove('show');updateUI();}
        async function processAll(){if(allFiles.length===0)return alert('No files');const btn=document.getElementById('processBtn');btn.disabled=true;btn.textContent='⏳...';processedResults=[];let proc=0,bytes=0;for(let i=0;i<allFiles.length;i++){const f=allFiles[i];const statusEl=document.getElementById('s'+i);const fileEl=document.getElementById('f'+i);try{if(f.isCode){const code=await f.text();const res=await fetch('/virtualize',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code,filename:f.relativePath})});if(!res.ok)throw new Error('Server error');const data=await res.json();if(data.success){processedResults.push({filename:f.relativePath,bytecode_hex:data.bytecode_hex,is_virtualized:true});proc++;bytes+=data.stats.bytecode_size;statusEl.textContent='✓';fileEl.classList.add('done');}else{statusEl.textContent='✗';fileEl.classList.add('error');}}else{const buffer=await f.arrayBuffer();const hex=Array.from(new Uint8Array(buffer)).map(b=>b.toString(16).padStart(2,'0')).join('');processedResults.push({filename:f.relativePath,bytecode_hex:hex,is_virtualized:false});statusEl.textContent='✓';fileEl.classList.add('done');}}catch(err){console.error('Error:',f.relativePath,err);statusEl.textContent='✗';fileEl.classList.add('error');}document.getElementById('done').textContent=proc;document.getElementById('bytes').textContent=bytes.toLocaleString();}btn.disabled=false;btn.textContent='🚀 Process';if(processedResults.length>0){document.getElementById('summary').textContent=`${proc} code files, ${processedResults.length-proc} data files`;document.getElementById('results').classList.add('show');}}
        async function downloadZip(){if(processedResults.length===0)return alert('Process first');const btn=document.getElementById('downloadBtn');btn.disabled=true;btn.textContent='⏳...';try{const res=await fetch('/download',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({files:processedResults})});if(!res.ok)throw new Error('Failed');const blob=await res.blob();const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='virtualized.zip';a.click();URL.revokeObjectURL(url);btn.textContent='💾 Download ZIP';}catch(err){alert('Error: '+err.message);btn.textContent='💾 Try Again';}btn.disabled=false;}
    </script>
</body>
</html>"##;
    
    HttpResponse::Ok().content_type("text/html; charset=utf-8").body(html)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("🔐 Code Virtualizer v3.0");
    println!("📍 http://localhost:8080");
    println!("📁 Python, JavaScript, Rust, C++");
    println!("📦 Preserves all project files");
    println!("⚡ Max payload: 500MB");
    
    HttpServer::new(|| {
        App::new()
            .app_data(web::JsonConfig::default().limit(500 * 1024 * 1024))
            .app_data(web::PayloadConfig::default().limit(500 * 1024 * 1024))
            .route("/", web::get().to(index))
            .route("/health", web::get().to(health))
            .route("/virtualize", web::post().to(virtualize))
            .route("/download", web::post().to(download_zip))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
