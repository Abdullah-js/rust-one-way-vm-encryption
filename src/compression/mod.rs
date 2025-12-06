
pub mod lz_custom;
pub mod entropy_mixer;

pub use lz_custom::LzCompressor;
pub use entropy_mixer::EntropyMixer;

pub type PayloadCompressor = CompressionEngine;

pub struct CompressionEngine {
    level: CompressionLevel,
}

#[derive(Debug, Clone, Copy)]
pub enum CompressionLevel {
    Fast,
    Normal,
    Maximum,
}

#[derive(Debug, Clone)]
pub struct CompressedData {
    pub original_size: u32,
    pub version: u8,
    pub data: Vec<u8>,
    pub checksum: [u8; 4],
}

impl CompressionEngine {
    pub fn new(level: CompressionLevel) -> Self {
        Self { level }
    }
    
    pub fn compress(&self, input: &[u8]) -> CompressedData {
        // Calculate original checksum
        let checksum = self.calculate_checksum(input);
        
        // First pass: LZ compression
        let lz_compressed = CustomLzCompressor::compress(input, self.level);
        
        // Second pass: entropy mixing to eliminate patterns
        let mixed = EntropyMixer::mix(&lz_compressed);
        
        CompressedData {
            original_size: input.len() as u32,
            version: 1,
            data: mixed,
            checksum,
        }
    }
    
    pub fn decompress(&self, compressed: &CompressedData) -> Result<Vec<u8>, String> {
        // Reverse entropy mixing
        let unmixed = EntropyMixer::unmix(&compressed.data)?;
        
        // Decompress LZ
        let decompressed = CustomLzCompressor::decompress(&unmixed, compressed.original_size as usize)?;
        
        // Verify checksum
        let checksum = self.calculate_checksum(&decompressed);
        if checksum != compressed.checksum {
            return Err("Checksum mismatch".into());
        }
        
        Ok(decompressed)
    }
    
    fn calculate_checksum(&self, data: &[u8]) -> [u8; 4] {
        let mut hash: u32 = 0x811c9dc5; // FNV-1a offset basis
        for &byte in data {
            hash ^= byte as u32;
            hash = hash.wrapping_mul(0x01000193); // FNV prime
        }
        hash.to_le_bytes()
    }
}

impl CompressedData {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        
        // Magic: "VCMP"
        out.extend_from_slice(b"VCMP");
        
        // Version
        out.push(self.version);
        
        // Original size
        out.extend_from_slice(&self.original_size.to_le_bytes());
        
        // Checksum
        out.extend_from_slice(&self.checksum);
        
        // Compressed data length
        out.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        
        // Compressed data
        out.extend_from_slice(&self.data);
        
        out
    }
    
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 17 || &data[0..4] != b"VCMP" {
            return Err("Invalid compressed data header".into());
        }
        
        let version = data[4];
        let original_size = u32::from_le_bytes([data[5], data[6], data[7], data[8]]);
        let checksum = [data[9], data[10], data[11], data[12]];
        let data_len = u32::from_le_bytes([data[13], data[14], data[15], data[16]]) as usize;
        
        if data.len() < 17 + data_len {
            return Err("Truncated compressed data".into());
        }
        
        Ok(CompressedData {
            original_size,
            version,
            data: data[17..17 + data_len].to_vec(),
            checksum,
        })
    }
}

use crate::compression::lz_custom::CustomLzCompressor;
