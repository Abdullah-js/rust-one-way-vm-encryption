
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

pub struct EntropyMixer;

impl EntropyMixer {
    pub fn mix(input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return vec![];
        }
        
        let mut output = Vec::with_capacity(input.len() + 24);
        
        // Generate random seed and store it (encrypted form)
        let mut seed_bytes = [0u8; 8];
        rand::thread_rng().fill(&mut seed_bytes[..]);
        let seed = u64::from_le_bytes(seed_bytes);
        
        // XOR seed with magic constant for obfuscation
        let obfuscated_seed = seed ^ 0xDEADBEEFCAFEBABE;
        output.extend_from_slice(&obfuscated_seed.to_le_bytes());
        
        let mut rng = StdRng::seed_from_u64(seed);
        
        // Generate block schedule
        let block_size = 16;
        let num_blocks = (input.len() + block_size - 1) / block_size;
        
        // Store shuffled block order
        let mut block_order: Vec<usize> = (0..num_blocks).collect();
        for i in (1..block_order.len()).rev() {
            let j = rng.gen_range(0..=i);
            block_order.swap(i, j);
        }
        
        // Encode block order compactly
        output.extend_from_slice(&(num_blocks as u32).to_le_bytes());
        for &idx in &block_order {
            output.extend_from_slice(&(idx as u16).to_le_bytes());
        }
        
        // Process each block with XOR stream
        for chunk in input.chunks(block_size) {
            // Generate XOR mask for this block
            let mask: Vec<u8> = (0..chunk.len()).map(|_| rng.gen()).collect();
            
            // XOR data with mask
            for (i, &byte) in chunk.iter().enumerate() {
                output.push(byte ^ mask[i]);
            }
            
            // Add inter-block noise
            let noise_count = rng.gen_range(1..4);
            for _ in 0..noise_count {
                output.push(rng.gen());
            }
        }
        
        // Add final noise padding
        let final_noise = rng.gen_range(8..16);
        for _ in 0..final_noise {
            output.push(rng.gen());
        }
        
        output
    }
    
    pub fn unmix(input: &[u8]) -> Result<Vec<u8>, String> {
        if input.len() < 12 {
            return Err("Input too short".into());
        }
        
        // Read and de-obfuscate seed
        let obfuscated_seed = u64::from_le_bytes([
            input[0], input[1], input[2], input[3],
            input[4], input[5], input[6], input[7],
        ]);
        let seed = obfuscated_seed ^ 0xDEADBEEFCAFEBABE;
        
        let mut rng = StdRng::seed_from_u64(seed);
        
        // Read block count
        let num_blocks = u32::from_le_bytes([input[8], input[9], input[10], input[11]]) as usize;
        
        // Read block order
        let mut pos = 12;
        let mut block_order = Vec::with_capacity(num_blocks);
        for _ in 0..num_blocks {
            if pos + 2 > input.len() {
                return Err("Truncated block order".into());
            }
            block_order.push(u16::from_le_bytes([input[pos], input[pos + 1]]) as usize);
            pos += 2;
        }
        
        // Create inverse mapping
        let mut inverse_order = vec![0usize; num_blocks];
        for (i, &orig_idx) in block_order.iter().enumerate() {
            if orig_idx < num_blocks {
                inverse_order[orig_idx] = i;
            }
        }
        
        // Regenerate RNG state for shuffling (to skip those random calls)
        let mut shuffle_rng = StdRng::seed_from_u64(seed);
        for i in (1..num_blocks).rev() {
            let _ = shuffle_rng.gen_range(0..=i);
        }
        
        // Read blocks and de-XOR
        let block_size = 16;
        let mut blocks: Vec<Vec<u8>> = vec![Vec::new(); num_blocks];
        
        for block_idx in 0..num_blocks {
            // Generate XOR mask
            let remaining = input.len() - pos;
            let chunk_size = if block_idx == num_blocks - 1 {
                // Last block might be smaller
                remaining.min(block_size)
            } else {
                block_size.min(remaining)
            };
            
            let mask: Vec<u8> = (0..chunk_size).map(|_| rng.gen()).collect();
            
            // De-XOR data
            let mut block = Vec::with_capacity(chunk_size);
            for i in 0..chunk_size {
                if pos + i < input.len() {
                    block.push(input[pos + i] ^ mask[i]);
                }
            }
            pos += chunk_size;
            
            // Skip inter-block noise
            let noise_count = rng.gen_range(1..4);
            pos += noise_count;
            
            // Store in correct position
            let orig_idx = block_order[block_idx];
            if orig_idx < blocks.len() {
                blocks[orig_idx] = block;
            }
        }
        
        // Reassemble output
        let mut output = Vec::new();
        for block in blocks {
            output.extend_from_slice(&block);
        }
        
        Ok(output)
    }
    
    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        
        let mut freq = [0u64; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }
        
        let len = data.len() as f64;
        let mut entropy = 0.0;
        
        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_entropy_increase() {
        let original = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let original_entropy = EntropyMixer::calculate_entropy(original);
        
        let mixed = EntropyMixer::mix(original);
        let mixed_entropy = EntropyMixer::calculate_entropy(&mixed);
        
        // Mixed data should have higher entropy
        assert!(mixed_entropy > original_entropy);
    }
}
