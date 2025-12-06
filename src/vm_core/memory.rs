
use std::collections::HashMap;

pub struct VmMemory {
    chunks: HashMap<usize, MemoryChunk>,
    chunk_size: usize,
    capacity: usize,
    allocated: usize,
}

#[derive(Clone)]
struct MemoryChunk {
    data: Vec<u8>,
    protection: Protection,
    dirty: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Protection {
    None,
    Read,
    Write,
    ReadWrite,
    Execute,
    ReadExecute,
}

impl VmMemory {
    pub fn new(capacity: usize) -> Self {
        Self {
            chunks: HashMap::new(),
            chunk_size: 4096, // 4KB chunks
            capacity,
            allocated: 0,
        }
    }
    
    pub fn load8(&self, addr: usize) -> Result<u8, String> {
        let chunk_idx = addr / self.chunk_size;
        let offset = addr % self.chunk_size;
        
        if let Some(chunk) = self.chunks.get(&chunk_idx) {
            if chunk.protection == Protection::None {
                return Err("Memory protection violation".into());
            }
            Ok(chunk.data.get(offset).copied().unwrap_or(0))
        } else {
            Ok(0) // Unallocated memory reads as zero
        }
    }
    
    pub fn store8(&mut self, addr: usize, value: u8) -> Result<(), String> {
        if addr >= self.capacity {
            return Err("Out of memory bounds".into());
        }
        
        let chunk_idx = addr / self.chunk_size;
        let offset = addr % self.chunk_size;
        
        let chunk = self.chunks.entry(chunk_idx).or_insert_with(|| {
            self.allocated += self.chunk_size;
            MemoryChunk {
                data: vec![0; self.chunk_size],
                protection: Protection::ReadWrite,
                dirty: false,
            }
        });
        
        if chunk.protection == Protection::None || 
           chunk.protection == Protection::Read ||
           chunk.protection == Protection::Execute ||
           chunk.protection == Protection::ReadExecute {
            return Err("Memory protection violation".into());
        }
        
        chunk.data[offset] = value;
        chunk.dirty = true;
        Ok(())
    }
    
    pub fn load16(&self, addr: usize) -> Result<u16, String> {
        let b0 = self.load8(addr)?;
        let b1 = self.load8(addr + 1)?;
        Ok(u16::from_le_bytes([b0, b1]))
    }
    
    pub fn store16(&mut self, addr: usize, value: u16) -> Result<(), String> {
        let bytes = value.to_le_bytes();
        self.store8(addr, bytes[0])?;
        self.store8(addr + 1, bytes[1])
    }
    
    pub fn load32(&self, addr: usize) -> Result<u32, String> {
        let b0 = self.load8(addr)?;
        let b1 = self.load8(addr + 1)?;
        let b2 = self.load8(addr + 2)?;
        let b3 = self.load8(addr + 3)?;
        Ok(u32::from_le_bytes([b0, b1, b2, b3]))
    }
    
    pub fn store32(&mut self, addr: usize, value: u32) -> Result<(), String> {
        let bytes = value.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            self.store8(addr + i, b)?;
        }
        Ok(())
    }
    
    pub fn load64(&self, addr: usize) -> Result<u64, String> {
        let mut bytes = [0u8; 8];
        for i in 0..8 {
            bytes[i] = self.load8(addr + i)?;
        }
        Ok(u64::from_le_bytes(bytes))
    }
    
    pub fn store64(&mut self, addr: usize, value: u64) -> Result<(), String> {
        let bytes = value.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            self.store8(addr + i, b)?;
        }
        Ok(())
    }
    
    pub fn load_block(&self, addr: usize, size: usize) -> Result<Vec<u8>, String> {
        let mut result = Vec::with_capacity(size);
        for i in 0..size {
            result.push(self.load8(addr + i)?);
        }
        Ok(result)
    }
    
    pub fn store_block(&mut self, addr: usize, data: &[u8]) -> Result<(), String> {
        for (i, &byte) in data.iter().enumerate() {
            self.store8(addr + i, byte)?;
        }
        Ok(())
    }
    
    pub fn set_protection(&mut self, addr: usize, size: usize, prot: Protection) -> Result<(), String> {
        let start_chunk = addr / self.chunk_size;
        let end_chunk = (addr + size + self.chunk_size - 1) / self.chunk_size;
        
        for chunk_idx in start_chunk..end_chunk {
            if let Some(chunk) = self.chunks.get_mut(&chunk_idx) {
                chunk.protection = prot;
            }
        }
        
        Ok(())
    }
    
    pub fn zeroize(&mut self) {
        for (_, chunk) in &mut self.chunks {
            for byte in &mut chunk.data {
                *byte = 0;
            }
            chunk.dirty = false;
        }
        self.chunks.clear();
        self.allocated = 0;
    }
    
    pub fn zeroize_range(&mut self, addr: usize, size: usize) {
        for i in 0..size {
            let _ = self.store8(addr + i, 0);
        }
    }
    
    pub fn allocated_size(&self) -> usize {
        self.allocated
    }
    
    pub fn grow(&mut self, additional: usize) -> Result<usize, String> {
        let new_capacity = self.capacity + additional;
        if new_capacity > 1024 * 1024 * 1024 { // 1GB limit
            return Err("Memory limit exceeded".into());
        }
        self.capacity = new_capacity;
        Ok(self.capacity)
    }
}

impl Drop for VmMemory {
    fn drop(&mut self) {
        // Secure cleanup on drop
        self.zeroize();
    }
}
