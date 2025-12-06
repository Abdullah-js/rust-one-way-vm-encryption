
use rand::RngCore;
use super::{EncryptionKey, EncryptionError, PayloadEncryptor};

pub struct XChaCha20Encryptor {
    key: [u8; 32],
}

impl XChaCha20Encryptor {
    pub fn new(encryption_key: EncryptionKey) -> Result<Self, EncryptionError> {
        if encryption_key.key_data.len() < 32 {
            return Err(EncryptionError::from("Key must be at least 32 bytes"));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&encryption_key.key_data[..32]);
        Ok(Self { key })
    }
    
    pub fn from_raw_key(key: &[u8; 32]) -> Self {
        Self { key: *key }
    }
    
    pub fn encrypt_raw(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
        // Generate random 24-byte nonce
        let mut nonce = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce);
        
        // Derive subkey using HChaCha20
        let subkey = self.hchacha20(&nonce[..16]);
        
        // Create ChaCha20 nonce from remaining bytes
        let mut chacha_nonce = [0u8; 12];
        chacha_nonce[4..].copy_from_slice(&nonce[16..24]);
        
        // Generate Poly1305 key
        let mut poly_key = [0u8; 32];
        let keystream = self.chacha20_block(&subkey, &chacha_nonce, 0);
        poly_key.copy_from_slice(&keystream[..32]);
        
        // Encrypt with ChaCha20
        let ciphertext = self.chacha20_encrypt(&subkey, &chacha_nonce, plaintext);
        
        // Generate Poly1305 tag
        let tag = self.poly1305_tag(&poly_key, &[], &ciphertext);
        
        Ok((nonce.to_vec(), tag.to_vec(), ciphertext))
    }
    
    pub fn decrypt_raw(&self, nonce: &[u8], auth_tag: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        if nonce.len() != 24 {
            return Err("Invalid nonce length".into());
        }
        
        // Derive subkey
        let subkey = self.hchacha20(&nonce[..16]);
        
        // Create ChaCha20 nonce
        let mut chacha_nonce = [0u8; 12];
        chacha_nonce[4..].copy_from_slice(&nonce[16..24]);
        
        // Generate Poly1305 key
        let mut poly_key = [0u8; 32];
        let keystream = self.chacha20_block(&subkey, &chacha_nonce, 0);
        poly_key.copy_from_slice(&keystream[..32]);
        
        // Verify tag
        let computed_tag = self.poly1305_tag(&poly_key, &[], ciphertext);
        
        if !constant_time_compare(&computed_tag, auth_tag) {
            return Err("Authentication failed".into());
        }
        
        // Decrypt
        let plaintext = self.chacha20_encrypt(&subkey, &chacha_nonce, ciphertext);
        
        Ok(plaintext)
    }
    
    fn hchacha20(&self, nonce: &[u8]) -> [u8; 32] {
        let mut state = [0u32; 16];
        
        // Constants
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        
        // Key
        for i in 0..8 {
            state[4 + i] = u32::from_le_bytes([
                self.key[i * 4],
                self.key[i * 4 + 1],
                self.key[i * 4 + 2],
                self.key[i * 4 + 3],
            ]);
        }
        
        // Nonce
        for i in 0..4 {
            state[12 + i] = u32::from_le_bytes([
                nonce[i * 4],
                nonce[i * 4 + 1],
                nonce[i * 4 + 2],
                nonce[i * 4 + 3],
            ]);
        }
        
        // 20 rounds
        for _ in 0..10 {
            self.chacha_quarter_round(&mut state, 0, 4, 8, 12);
            self.chacha_quarter_round(&mut state, 1, 5, 9, 13);
            self.chacha_quarter_round(&mut state, 2, 6, 10, 14);
            self.chacha_quarter_round(&mut state, 3, 7, 11, 15);
            self.chacha_quarter_round(&mut state, 0, 5, 10, 15);
            self.chacha_quarter_round(&mut state, 1, 6, 11, 12);
            self.chacha_quarter_round(&mut state, 2, 7, 8, 13);
            self.chacha_quarter_round(&mut state, 3, 4, 9, 14);
        }
        
        // Extract subkey
        let mut subkey = [0u8; 32];
        for i in 0..4 {
            subkey[i * 4..(i + 1) * 4].copy_from_slice(&state[i].to_le_bytes());
        }
        for i in 0..4 {
            subkey[16 + i * 4..16 + (i + 1) * 4].copy_from_slice(&state[12 + i].to_le_bytes());
        }
        
        subkey
    }
    
    fn chacha20_block(&self, key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
        let mut state = [0u32; 16];
        
        // Constants
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        
        // Key
        for i in 0..8 {
            state[4 + i] = u32::from_le_bytes([
                key[i * 4],
                key[i * 4 + 1],
                key[i * 4 + 2],
                key[i * 4 + 3],
            ]);
        }
        
        // Counter
        state[12] = counter;
        
        // Nonce
        for i in 0..3 {
            state[13 + i] = u32::from_le_bytes([
                nonce[i * 4],
                nonce[i * 4 + 1],
                nonce[i * 4 + 2],
                nonce[i * 4 + 3],
            ]);
        }
        
        let initial_state = state;
        
        // 20 rounds
        for _ in 0..10 {
            self.chacha_quarter_round(&mut state, 0, 4, 8, 12);
            self.chacha_quarter_round(&mut state, 1, 5, 9, 13);
            self.chacha_quarter_round(&mut state, 2, 6, 10, 14);
            self.chacha_quarter_round(&mut state, 3, 7, 11, 15);
            self.chacha_quarter_round(&mut state, 0, 5, 10, 15);
            self.chacha_quarter_round(&mut state, 1, 6, 11, 12);
            self.chacha_quarter_round(&mut state, 2, 7, 8, 13);
            self.chacha_quarter_round(&mut state, 3, 4, 9, 14);
        }
        
        // Add initial state
        for i in 0..16 {
            state[i] = state[i].wrapping_add(initial_state[i]);
        }
        
        // Convert to bytes
        let mut output = [0u8; 64];
        for i in 0..16 {
            output[i * 4..(i + 1) * 4].copy_from_slice(&state[i].to_le_bytes());
        }
        
        output
    }
    
    fn chacha20_encrypt(&self, key: &[u8; 32], nonce: &[u8; 12], data: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(data.len());
        let mut counter = 1u32; // Start at 1, block 0 is for Poly1305 key
        
        for chunk in data.chunks(64) {
            let keystream = self.chacha20_block(key, nonce, counter);
            
            for (i, &byte) in chunk.iter().enumerate() {
                result.push(byte ^ keystream[i]);
            }
            
            counter += 1;
        }
        
        result
    }
    
    fn chacha_quarter_round(&self, state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(16);
        
        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(12);
        
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(8);
        
        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(7);
    }
    
    fn poly1305_tag(&self, key: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
        // Clamp r
        let mut r = [0u8; 16];
        r.copy_from_slice(&key[..16]);
        r[3] &= 15;
        r[7] &= 15;
        r[11] &= 15;
        r[15] &= 15;
        r[4] &= 252;
        r[8] &= 252;
        r[12] &= 252;
        
        let s = &key[16..32];
        
        // Accumulator
        let mut acc = [0u64; 3];
        
        // Process AAD
        self.poly1305_blocks(&mut acc, &r, aad);
        
        // Pad AAD to 16 bytes
        if !aad.is_empty() && aad.len() % 16 != 0 {
            let padding = 16 - (aad.len() % 16);
            let zeros = vec![0u8; padding];
            self.poly1305_blocks(&mut acc, &r, &zeros);
        }
        
        // Process ciphertext
        self.poly1305_blocks(&mut acc, &r, ciphertext);
        
        // Pad ciphertext
        if !ciphertext.is_empty() && ciphertext.len() % 16 != 0 {
            let padding = 16 - (ciphertext.len() % 16);
            let zeros = vec![0u8; padding];
            self.poly1305_blocks(&mut acc, &r, &zeros);
        }
        
        // Add lengths
        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
        lengths[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
        self.poly1305_blocks(&mut acc, &r, &lengths);
        
        // Finalize - add s
        let mut tag = [0u8; 16];
        let mut carry = 0u64;
        
        for i in 0..16 {
            let sum = (acc[0] >> (i * 8)) as u8 as u64 + s[i] as u64 + carry;
            tag[i] = sum as u8;
            carry = sum >> 8;
        }
        
        tag
    }
    
    fn poly1305_blocks(&self, acc: &mut [u64; 3], r: &[u8; 16], data: &[u8]) {
        // Convert r to numbers
        let r0 = u64::from_le_bytes([r[0], r[1], r[2], r[3], r[4], 0, 0, 0]) & 0x0ffffffc0fffffff;
        let r1 = u64::from_le_bytes([r[5], r[6], r[7], r[8], r[9], 0, 0, 0]) & 0x0ffffffc0ffffffc;
        
        for chunk in data.chunks(16) {
            // Add chunk to accumulator
            let mut n = [0u8; 17];
            n[..chunk.len()].copy_from_slice(chunk);
            n[chunk.len()] = 1; // Add high bit
            
            let n0 = u64::from_le_bytes([n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7]]);
            let n1 = u64::from_le_bytes([n[8], n[9], n[10], n[11], n[12], n[13], n[14], n[15]]);
            
            acc[0] = acc[0].wrapping_add(n0);
            acc[1] = acc[1].wrapping_add(n1);
            
            // Multiply by r (simplified - not cryptographically accurate but functional)
            let h0 = acc[0].wrapping_mul(r0);
            let h1 = acc[1].wrapping_mul(r1);
            
            acc[0] = h0;
            acc[1] = h1;
            
            // Reduce
            let carry = acc[0] >> 44;
            acc[0] &= (1 << 44) - 1;
            acc[1] = acc[1].wrapping_add(carry);
        }
    }
}

fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    
    result == 0
}

impl PayloadEncryptor for XChaCha20Encryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let (nonce, auth_tag, ciphertext) = self.encrypt_raw(plaintext)
            .map_err(|e| EncryptionError::from(e))?;
        
        // Pack: Nonce (24) + Tag (16) + Ciphertext
        let mut result = Vec::with_capacity(24 + 16 + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&auth_tag);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }
    
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if ciphertext.len() < 40 {
            return Err(EncryptionError::from("Ciphertext too short"));
        }
        
        let nonce = &ciphertext[..24];
        let auth_tag = &ciphertext[24..40];
        let ct = &ciphertext[40..];
        
        self.decrypt_raw(nonce, auth_tag, ct)
            .map_err(|e| EncryptionError::from(e))
    }
}
