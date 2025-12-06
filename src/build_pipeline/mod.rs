
pub mod randomizer;
pub mod key_gen;
pub mod symbol_strip;
pub mod optimizer;

pub use randomizer::BuildRandomizer;
pub use key_gen::KeyGenerator;
pub use symbol_strip::SymbolStripper;
pub use optimizer::CodeOptimizer;

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct BuildConfig {
    pub build_id: String,
    pub timestamp: u64,
    pub seed: u64,
    pub aggressive_obfuscation: bool,
    pub strip_symbols: bool,
    pub anti_debug: bool,
    pub compress: bool,
    pub encryption: EncryptionType,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EncryptionType {
    AesGcm,
    XChaCha20,
    Both, // Layered encryption
}

impl Default for BuildConfig {
    fn default() -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        Self {
            build_id: format!("build_{:x}", timestamp),
            timestamp,
            seed: timestamp ^ 0x5DEECE66D,
            aggressive_obfuscation: true,
            strip_symbols: true,
            anti_debug: true,
            compress: true,
            encryption: EncryptionType::Both,
        }
    }
}

#[derive(Debug)]
pub struct BuildOutput {
    pub bytecode: Vec<u8>,
    pub vm_runtime: String,
    pub manifest: BuildManifest,
}

#[derive(Debug, Clone)]
pub struct BuildManifest {
    pub build_id: String,
    pub timestamp: u64,
    pub opcode_seed: u64,
    pub key_hash: [u8; 32],
    pub bytecode_hash: [u8; 32],
    pub runtime_size: usize,
}

pub struct BuildPipeline {
    config: BuildConfig,
    randomizer: BuildRandomizer,
    key_gen: KeyGenerator,
    stripper: SymbolStripper,
    optimizer: CodeOptimizer,
}

impl BuildPipeline {
    pub fn new(config: BuildConfig) -> Self {
        Self {
            randomizer: BuildRandomizer::new(config.seed),
            key_gen: KeyGenerator::new(config.seed),
            stripper: SymbolStripper::new(),
            optimizer: CodeOptimizer::new(),
            config,
        }
    }
    
    pub fn with_default_config() -> Self {
        Self::new(BuildConfig::default())
    }
    
    pub fn build(&mut self, source: &str, language: &str) -> Result<BuildOutput, BuildError> {
        // Step 1: Parse and compile source
        let mut bytecode = self.compile_source(source, language)?;
        
        // Step 2: Apply opcode randomization
        bytecode = self.randomizer.randomize_opcodes(&bytecode);
        
        // Step 3: Optimize bytecode
        bytecode = self.optimizer.optimize(&bytecode);
        
        // Step 4: Inject dead code
        if self.config.aggressive_obfuscation {
            bytecode = self.randomizer.inject_dead_code(&bytecode);
        }
        
        // Step 5: Compress if enabled
        if self.config.compress {
            bytecode = self.compress(&bytecode);
        }
        
        // Step 6: Encrypt
        let (encrypted, key_hash) = self.encrypt(&bytecode)?;
        
        // Step 7: Generate VM runtime
        let vm_runtime = self.generate_vm_runtime(language)?;
        
        // Step 8: Strip symbols if enabled
        let vm_runtime = if self.config.strip_symbols {
            self.stripper.strip(&vm_runtime)
        } else {
            vm_runtime
        };
        
        // Generate manifest
        let manifest = BuildManifest {
            build_id: self.config.build_id.clone(),
            timestamp: self.config.timestamp,
            opcode_seed: self.config.seed,
            key_hash,
            bytecode_hash: self.hash(&encrypted),
            runtime_size: vm_runtime.len(),
        };
        
        Ok(BuildOutput {
            bytecode: encrypted,
            vm_runtime,
            manifest,
        })
    }
    
    fn compile_source(&self, source: &str, language: &str) -> Result<Vec<u8>, BuildError> {
        use crate::compiler::{Compiler, LanguageCompiler};
        
        let compiled = match language {
            "javascript" | "js" => LanguageCompiler::compile_js(source)?,
            "typescript" | "ts" => LanguageCompiler::compile_js(source)?, // Treat as JS
            "python" | "py" => LanguageCompiler::compile_python(source)?,
            "ruby" | "rb" => LanguageCompiler::compile_ruby(source)?,
            "lua" => LanguageCompiler::compile_lua(source)?,
            "php" => LanguageCompiler::compile_php(source)?,
            _ => return Err(BuildError::UnsupportedLanguage(language.to_string())),
        };
        
        // Convert to bytecode bytes
        let mut bytecode = Vec::new();
        compiled.serialize(&mut bytecode);
        Ok(bytecode)
    }
    
    fn compress(&self, data: &[u8]) -> Vec<u8> {
        use crate::compression::lz_custom::LzCompressor;
        
        let compressor = LzCompressor::new();
        compressor.compress(data)
    }
    
    fn encrypt(&self, data: &[u8]) -> Result<(Vec<u8>, [u8; 32]), BuildError> {
        use crate::encryption::{aes_gcm::AesGcmEncryptor, xchacha::XChaCha20Encryptor, PayloadEncryptor};
        
        let key = self.key_gen.generate_key();
        let key_hash = self.hash(&key.key_data);
        
        let encrypted = match self.config.encryption {
            EncryptionType::AesGcm => {
                let encryptor = AesGcmEncryptor::new(key)?;
                encryptor.encrypt(data)?
            }
            EncryptionType::XChaCha20 => {
                let encryptor = XChaCha20Encryptor::new(key)?;
                encryptor.encrypt(data)?
            }
            EncryptionType::Both => {
                // Layer: XChaCha20 first, then AES-GCM
                let xchacha = XChaCha20Encryptor::new(key.clone())?;
                let first_pass = xchacha.encrypt(data)?;
                
                let aes_key = self.key_gen.generate_key();
                let aes = AesGcmEncryptor::new(aes_key)?;
                aes.encrypt(&first_pass)?
            }
        };
        
        Ok((encrypted, key_hash))
    }
    
    fn generate_vm_runtime(&self, language: &str) -> Result<String, BuildError> {
        use crate::vm_generator::VmRuntime;
        
        let opcode_map = self.randomizer.opcode_mapping();
        
        let runtime = match language {
            "javascript" | "js" | "typescript" | "ts" => {
                VmRuntime::generate_js(opcode_map, &self.config.build_id)?
            }
            "python" | "py" => {
                VmRuntime::generate_python(opcode_map, &self.config.build_id)?
            }
            "ruby" | "rb" => {
                VmRuntime::generate_ruby(opcode_map, &self.config.build_id)?
            }
            "lua" => {
                VmRuntime::generate_lua(opcode_map, &self.config.build_id)?
            }
            "php" => {
                VmRuntime::generate_php(opcode_map, &self.config.build_id)?
            }
            _ => return Err(BuildError::UnsupportedLanguage(language.to_string())),
        };
        
        Ok(runtime)
    }
    
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }
    
    pub fn config(&self) -> &BuildConfig {
        &self.config
    }
}

#[derive(Debug)]
pub enum BuildError {
    UnsupportedLanguage(String),
    CompilationError(String),
    EncryptionError(String),
    CompressionError(String),
    Runtime(String),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::UnsupportedLanguage(lang) => write!(f, "Unsupported language: {}", lang),
            BuildError::CompilationError(msg) => write!(f, "Compilation error: {}", msg),
            BuildError::EncryptionError(msg) => write!(f, "Encryption error: {}", msg),
            BuildError::CompressionError(msg) => write!(f, "Compression error: {}", msg),
            BuildError::Runtime(msg) => write!(f, "Runtime error: {}", msg),
        }
    }
}

impl std::error::Error for BuildError {}

impl From<crate::compiler::CompileError> for BuildError {
    fn from(err: crate::compiler::CompileError) -> Self {
        BuildError::CompilationError(err.to_string())
    }
}

impl From<crate::encryption::EncryptionError> for BuildError {
    fn from(err: crate::encryption::EncryptionError) -> Self {
        BuildError::EncryptionError(err.to_string())
    }
}

impl From<String> for BuildError {
    fn from(s: String) -> Self {
        BuildError::Runtime(s)
    }
}
