
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use sha2::{Sha256, Sha512, Digest};

use crate::encryption::EncryptionKey;

pub struct KeyGenerator {
    rng: StdRng,
    entropy_pool: Vec<u8>,
    generation_count: u64,
}

impl KeyGenerator {
    pub fn new(seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        
        // Initialize entropy pool
        let mut entropy_pool = vec![0u8; 256];
        rng.fill(&mut entropy_pool[..]);
        
        Self {
            rng,
            entropy_pool,
            generation_count: 0,
        }
    }
    
    pub fn generate_key(&self) -> EncryptionKey {
        let mut key_data = [0u8; 32];
        
        // Mix multiple entropy sources
        let mut hasher = Sha256::new();
        
        // Add entropy pool
        hasher.update(&self.entropy_pool);
        
        // Add generation count
        hasher.update(&self.generation_count.to_le_bytes());
        
        // Add timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        hasher.update(&timestamp.to_le_bytes());
        
        let hash = hasher.finalize();
        key_data.copy_from_slice(&hash);
        
        EncryptionKey {
            key_data: key_data.to_vec(),
            key_id: format!("key_{:016x}", self.generation_count),
        }
    }
    
    pub fn generate_key_sized(&mut self, size: usize) -> Vec<u8> {
        let mut key = vec![0u8; size];
        self.rng.fill(&mut key[..]);
        
        // Mix with entropy
        for (i, byte) in key.iter_mut().enumerate() {
            let pool_len = self.entropy_pool.len();
            self.entropy_pool[i % pool_len] ^= byte;
        }
        
        self.generation_count += 1;
        self.refresh_entropy();
        
        key
    }
    
    pub fn generate_nonce(&mut self, size: usize) -> Vec<u8> {
        let mut nonce = vec![0u8; size];
        self.rng.fill(&mut nonce[..]);
        nonce
    }
    
    fn refresh_entropy(&mut self) {
        // Hash existing pool
        let mut hasher = Sha512::new();
        hasher.update(&self.entropy_pool);
        hasher.update(&self.generation_count.to_le_bytes());
        let new_entropy = hasher.finalize();
        
        // Mix into existing pool
        for (i, &byte) in new_entropy.iter().enumerate() {
            let pool_len = self.entropy_pool.len();
            self.entropy_pool[i % pool_len] ^= byte;
        }
        
        // Rotate pool
        self.entropy_pool.rotate_left(17);
    }
    
    pub fn add_entropy(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(&self.entropy_pool);
        hasher.update(data);
        let mixed = hasher.finalize();
        
        for (i, &byte) in mixed.iter().enumerate() {
            let pool_len = self.entropy_pool.len();
            self.entropy_pool[i % pool_len] ^= byte;
        }
    }
    
    pub fn derive_key(&self, master_key: &[u8], context: &[u8], size: usize) -> Vec<u8> {
        // HKDF-like derivation
        let mut derived = Vec::with_capacity(size);
        let mut counter = 1u32;
        
        while derived.len() < size {
            let mut hasher = Sha256::new();
            hasher.update(master_key);
            hasher.update(context);
            hasher.update(&counter.to_le_bytes());
            
            let block = hasher.finalize();
            derived.extend_from_slice(&block);
            counter += 1;
        }
        
        derived.truncate(size);
        derived
    }
}

#[derive(Debug, Clone)]
pub struct KeySchedule {
    rounds: Vec<[u8; 32]>,
}

impl KeySchedule {
    pub fn new(master_key: &[u8], num_rounds: usize) -> Self {
        let mut rounds = Vec::with_capacity(num_rounds);
        let mut current = [0u8; 32];
        
        // Initialize from master
        let mut hasher = Sha256::new();
        hasher.update(master_key);
        hasher.update(b"key_schedule_init");
        current.copy_from_slice(&hasher.finalize());
        
        rounds.push(current);
        
        // Derive subsequent rounds
        for i in 1..num_rounds {
            let mut hasher = Sha256::new();
            hasher.update(&current);
            hasher.update(&(i as u64).to_le_bytes());
            hasher.update(b"round_key");
            current.copy_from_slice(&hasher.finalize());
            rounds.push(current);
        }
        
        Self { rounds }
    }
    
    pub fn round_key(&self, round: usize) -> Option<&[u8; 32]> {
        self.rounds.get(round)
    }
    
    pub fn all_keys(&self) -> &[[u8; 32]] {
        &self.rounds
    }
}
