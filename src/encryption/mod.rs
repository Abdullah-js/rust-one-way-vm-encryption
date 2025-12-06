
pub mod aes_gcm;
pub mod xchacha;
pub mod key_obfuscation;

pub use aes_gcm::AesGcmEncryptor;
pub use xchacha::XChaCha20Encryptor;
pub use key_obfuscation::KeyObfuscator;

use rand::{Rng, RngCore};

#[derive(Debug, Clone)]
pub struct EncryptionKey {
    pub key_data: Vec<u8>,
    pub key_id: String,
}

#[derive(Debug, Clone)]
pub struct EncryptionError {
    pub message: String,
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for EncryptionError {}

impl From<String> for EncryptionError {
    fn from(message: String) -> Self {
        Self { message }
    }
}

impl From<&str> for EncryptionError {
    fn from(message: &str) -> Self {
        Self { message: message.to_string() }
    }
}

pub trait PayloadEncryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError>;
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EncryptionError>;
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EncryptionAlgorithm {
    AesGcm256,
    XChaCha20Poly1305,
}

#[derive(Debug, Clone)]
pub struct EncryptedPayload {
    pub algorithm: EncryptionAlgorithm,
    pub iv: Vec<u8>,
    pub auth_tag: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub key_fragments: Vec<KeyFragment>,
}

#[derive(Debug, Clone)]
pub struct KeyFragment {
    pub xor_mask: Vec<u8>,
    pub data: Vec<u8>,
    pub position: usize,
}

pub struct EncryptionEngine {
    algorithm: EncryptionAlgorithm,
    key: [u8; 32],
}

impl EncryptionEngine {
    pub fn new(algorithm: EncryptionAlgorithm) -> Self {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        
        Self { algorithm, key }
    }
    
    pub fn with_key(algorithm: EncryptionAlgorithm, key: [u8; 32]) -> Self {
        Self { algorithm, key }
    }
    
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedPayload, String> {
        let mut rng = rand::thread_rng();
        
        let (iv, auth_tag, ciphertext) = match self.algorithm {
            EncryptionAlgorithm::AesGcm256 => {
                let encryptor = AesGcmEncryptor::new(EncryptionKey(self.key.clone()))?;
                encryptor.encrypt(plaintext)?
            }
            EncryptionAlgorithm::XChaCha20Poly1305 => {
                let encryptor = XChaCha20Encryptor::new(EncryptionKey(self.key.clone()))?;
                encryptor.encrypt(plaintext)?
            }
        };
        
        // Generate obfuscated key fragments
        let key_fragments = KeyObfuscator::obfuscate_key(&self.key, &mut rng);
        
        Ok(EncryptedPayload {
            algorithm: self.algorithm,
            iv,
            auth_tag,
            ciphertext,
            key_fragments,
        })
    }
    
    pub fn decrypt(&self, payload: &EncryptedPayload) -> Result<Vec<u8>, String> {
        match self.algorithm {
            EncryptionAlgorithm::AesGcm256 => {
                let decryptor = AesGcmEncryptor::new(EncryptionKey(self.key.clone()))?;
                decryptor.decrypt(&payload.iv, &payload.auth_tag, &payload.ciphertext)
            }
            EncryptionAlgorithm::XChaCha20Poly1305 => {
                let decryptor = XChaCha20Encryptor::new(EncryptionKey(self.key.clone()))?;
                decryptor.decrypt(&payload.iv, &payload.auth_tag, &payload.ciphertext)
            }
        }
    }
    
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
}

impl EncryptedPayload {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        
        // Magic header: "VPAY" (Virtualized Payload)
        out.extend_from_slice(b"VPAY");
        
        // Version
        out.push(0x01);
        
        // Algorithm
        out.push(match self.algorithm {
            EncryptionAlgorithm::AesGcm256 => 0x01,
            EncryptionAlgorithm::XChaCha20Poly1305 => 0x02,
        });
        
        // IV length and data
        out.extend_from_slice(&(self.iv.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.iv);
        
        // Auth tag length and data
        out.extend_from_slice(&(self.auth_tag.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.auth_tag);
        
        // Ciphertext length and data
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.ciphertext);
        
        // Key fragments count
        out.extend_from_slice(&(self.key_fragments.len() as u16).to_le_bytes());
        
        for frag in &self.key_fragments {
            // Position
            out.push(frag.position as u8);
            // XOR mask length and data
            out.extend_from_slice(&(frag.xor_mask.len() as u16).to_le_bytes());
            out.extend_from_slice(&frag.xor_mask);
            // Fragment data length and data
            out.extend_from_slice(&(frag.data.len() as u16).to_le_bytes());
            out.extend_from_slice(&frag.data);
        }
        
        out
    }
    
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 6 || &data[0..4] != b"VPAY" {
            return Err("Invalid payload header".into());
        }
        
        let _version = data[4];
        let algorithm = match data[5] {
            0x01 => EncryptionAlgorithm::AesGcm256,
            0x02 => EncryptionAlgorithm::XChaCha20Poly1305,
            _ => return Err("Unknown encryption algorithm".into()),
        };
        
        let mut pos = 6;
        
        // IV
        let iv_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let iv = data[pos..pos + iv_len].to_vec();
        pos += iv_len;
        
        // Auth tag
        let tag_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let auth_tag = data[pos..pos + tag_len].to_vec();
        pos += tag_len;
        
        // Ciphertext
        let ct_len = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        let ciphertext = data[pos..pos + ct_len].to_vec();
        pos += ct_len;
        
        // Key fragments
        let frag_count = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        
        let mut key_fragments = Vec::with_capacity(frag_count);
        for _ in 0..frag_count {
            let position = data[pos] as usize;
            pos += 1;
            
            let mask_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            let xor_mask = data[pos..pos + mask_len].to_vec();
            pos += mask_len;
            
            let data_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            let frag_data = data[pos..pos + data_len].to_vec();
            pos += data_len;
            
            key_fragments.push(KeyFragment {
                xor_mask,
                data: frag_data,
                position,
            });
        }
        
        Ok(EncryptedPayload {
            algorithm,
            iv,
            auth_tag,
            ciphertext,
            key_fragments,
        })
    }
}
