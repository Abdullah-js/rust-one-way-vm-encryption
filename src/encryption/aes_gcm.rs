
use rand::RngCore;
use super::{EncryptionKey, EncryptionError, PayloadEncryptor};

pub struct AesGcmEncryptor {
    key: [u8; 32],
    round_keys: [[u8; 16]; 15],
}

impl AesGcmEncryptor {
    pub fn new(encryption_key: EncryptionKey) -> Result<Self, EncryptionError> {
        if encryption_key.key_data.len() < 32 {
            return Err(EncryptionError::from("Key must be at least 32 bytes"));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&encryption_key.key_data[..32]);
        let round_keys = Self::key_expansion(&key);
        Ok(Self { key, round_keys })
    }
    
    pub fn from_raw_key(key: &[u8; 32]) -> Self {
        let round_keys = Self::key_expansion(key);
        Self {
            key: *key,
            round_keys,
        }
    }
    
    pub fn encrypt_raw(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
        // Generate random 12-byte IV
        let mut iv = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut iv);
        
        // Encrypt using CTR mode
        let ciphertext = self.aes_ctr_encrypt(plaintext, &iv);
        
        // Generate authentication tag using GHASH
        let auth_tag = self.generate_tag(&iv, &[], &ciphertext);
        
        Ok((iv.to_vec(), auth_tag.to_vec(), ciphertext))
    }
    
    pub fn decrypt_raw(&self, iv: &[u8], auth_tag: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        if iv.len() != 12 {
            return Err("Invalid IV length".into());
        }
        
        // Verify authentication tag
        let computed_tag = self.generate_tag(iv.try_into().unwrap(), &[], ciphertext);
        
        if !constant_time_compare(&computed_tag, auth_tag) {
            return Err("Authentication failed".into());
        }
        
        // Decrypt using CTR mode
        let mut iv_arr = [0u8; 12];
        iv_arr.copy_from_slice(iv);
        let plaintext = self.aes_ctr_encrypt(ciphertext, &iv_arr);
        
        Ok(plaintext)
    }
    
    fn key_expansion(key: &[u8; 32]) -> [[u8; 16]; 15] {
        let mut round_keys = [[0u8; 16]; 15];
        
        // First two round keys are the original key
        round_keys[0].copy_from_slice(&key[0..16]);
        round_keys[1].copy_from_slice(&key[16..32]);
        
        let rcon: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
        
        for i in 2..15 {
            let mut temp = round_keys[i - 1];
            
            if i % 2 == 0 {
                // Rotate word
                temp = [temp[1], temp[2], temp[3], temp[0], temp[5], temp[6], temp[7], temp[4],
                        temp[9], temp[10], temp[11], temp[8], temp[13], temp[14], temp[15], temp[12]];
                
                // SubBytes on last 4 bytes
                for j in 12..16 {
                    temp[j] = SBOX[temp[j] as usize];
                }
                
                // XOR with Rcon
                temp[12] ^= rcon[(i / 2) - 1];
            } else {
                // SubBytes only
                for j in 0..16 {
                    temp[j] = SBOX[temp[j] as usize];
                }
            }
            
            for j in 0..16 {
                round_keys[i][j] = round_keys[i - 2][j] ^ temp[j];
            }
        }
        
        round_keys
    }
    
    fn aes_encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut state = *block;
        
        // Initial round key addition
        self.add_round_key(&mut state, 0);
        
        // Main rounds
        for round in 1..14 {
            self.sub_bytes(&mut state);
            self.shift_rows(&mut state);
            self.mix_columns(&mut state);
            self.add_round_key(&mut state, round);
        }
        
        // Final round (no MixColumns)
        self.sub_bytes(&mut state);
        self.shift_rows(&mut state);
        self.add_round_key(&mut state, 14);
        
        state
    }
    
    fn add_round_key(&self, state: &mut [u8; 16], round: usize) {
        for i in 0..16 {
            state[i] ^= self.round_keys[round][i];
        }
    }
    
    fn sub_bytes(&self, state: &mut [u8; 16]) {
        for byte in state.iter_mut() {
            *byte = SBOX[*byte as usize];
        }
    }
    
    fn shift_rows(&self, state: &mut [u8; 16]) {
        // Row 1: shift left by 1
        let temp = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = temp;
        
        // Row 2: shift left by 2
        let temp1 = state[2];
        let temp2 = state[6];
        state[2] = state[10];
        state[6] = state[14];
        state[10] = temp1;
        state[14] = temp2;
        
        // Row 3: shift left by 3 (right by 1)
        let temp = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = state[3];
        state[3] = temp;
    }
    
    fn mix_columns(&self, state: &mut [u8; 16]) {
        for i in 0..4 {
            let col = i * 4;
            let a = state[col];
            let b = state[col + 1];
            let c = state[col + 2];
            let d = state[col + 3];
            
            state[col] = gf_mul(a, 2) ^ gf_mul(b, 3) ^ c ^ d;
            state[col + 1] = a ^ gf_mul(b, 2) ^ gf_mul(c, 3) ^ d;
            state[col + 2] = a ^ b ^ gf_mul(c, 2) ^ gf_mul(d, 3);
            state[col + 3] = gf_mul(a, 3) ^ b ^ c ^ gf_mul(d, 2);
        }
    }
    
    fn aes_ctr_encrypt(&self, data: &[u8], iv: &[u8; 12]) -> Vec<u8> {
        let mut result = Vec::with_capacity(data.len());
        let mut counter = [0u8; 16];
        counter[..12].copy_from_slice(iv);
        counter[15] = 1; // Start counter at 1 for GCM
        
        for chunk in data.chunks(16) {
            let keystream = self.aes_encrypt_block(&counter);
            
            for (i, &byte) in chunk.iter().enumerate() {
                result.push(byte ^ keystream[i]);
            }
            
            // Increment counter
            for i in (12..16).rev() {
                counter[i] = counter[i].wrapping_add(1);
                if counter[i] != 0 {
                    break;
                }
            }
        }
        
        result
    }
    
    fn generate_tag(&self, iv: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
        // Generate H = AES_K(0^128)
        let h = self.aes_encrypt_block(&[0u8; 16]);
        
        // GHASH
        let mut tag = [0u8; 16];
        
        // Process AAD
        for chunk in aad.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            xor_blocks(&mut tag, &block);
            tag = ghash_multiply(&tag, &h);
        }
        
        // Process ciphertext
        for chunk in ciphertext.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            xor_blocks(&mut tag, &block);
            tag = ghash_multiply(&tag, &h);
        }
        
        // Add lengths
        let mut len_block = [0u8; 16];
        let aad_bits = (aad.len() as u64) * 8;
        let ct_bits = (ciphertext.len() as u64) * 8;
        len_block[..8].copy_from_slice(&aad_bits.to_be_bytes());
        len_block[8..].copy_from_slice(&ct_bits.to_be_bytes());
        xor_blocks(&mut tag, &len_block);
        tag = ghash_multiply(&tag, &h);
        
        // Final encryption: tag = GHASH ^ AES_K(IV || 0^31 || 1)
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(iv);
        j0[15] = 1;
        let encrypted_j0 = self.aes_encrypt_block(&j0);
        xor_blocks(&mut tag, &encrypted_j0);
        
        tag
    }
}

// AES S-Box
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

fn gf_mul(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut aa = a;
    let mut bb = b;
    
    for _ in 0..8 {
        if bb & 1 != 0 {
            result ^= aa;
        }
        let hi_bit = aa & 0x80;
        aa <<= 1;
        if hi_bit != 0 {
            aa ^= 0x1b; // AES irreducible polynomial
        }
        bb >>= 1;
    }
    
    result
}

fn xor_blocks(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

fn ghash_multiply(x: &[u8; 16], h: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *h;
    
    for i in 0..16 {
        for j in 0..8 {
            if (x[i] >> (7 - j)) & 1 != 0 {
                xor_blocks(&mut z, &v);
            }
            
            // Multiply v by x in GF(2^128)
            let lsb = v[15] & 1;
            for k in (1..16).rev() {
                v[k] = (v[k] >> 1) | (v[k - 1] << 7);
            }
            v[0] >>= 1;
            
            if lsb != 0 {
                v[0] ^= 0xe1; // GCM reduction polynomial
            }
        }
    }
    
    z
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

impl PayloadEncryptor for AesGcmEncryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let (iv, auth_tag, ciphertext) = self.encrypt_raw(plaintext)
            .map_err(|e| EncryptionError::from(e))?;
        
        // Pack: IV (12) + Tag (16) + Ciphertext
        let mut result = Vec::with_capacity(12 + 16 + ciphertext.len());
        result.extend_from_slice(&iv);
        result.extend_from_slice(&auth_tag);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }
    
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if ciphertext.len() < 28 {
            return Err(EncryptionError::from("Ciphertext too short"));
        }
        
        let iv = &ciphertext[..12];
        let auth_tag = &ciphertext[12..28];
        let ct = &ciphertext[28..];
        
        self.decrypt_raw(iv, auth_tag, ct)
            .map_err(|e| EncryptionError::from(e))
    }
}
