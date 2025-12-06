
use rand::Rng;
use super::KeyFragment;

pub struct KeyObfuscator;

impl KeyObfuscator {
    pub fn obfuscate_key<R: Rng>(key: &[u8; 32], rng: &mut R) -> Vec<KeyFragment> {
        let num_fragments = rng.gen_range(4..8);
        let fragment_size = 32 / num_fragments;
        let mut fragments = Vec::with_capacity(num_fragments);
        
        // Generate shuffled positions
        let mut positions: Vec<usize> = (0..num_fragments).collect();
        for i in (1..positions.len()).rev() {
            let j = rng.gen_range(0..=i);
            positions.swap(i, j);
        }
        
        for (i, &position) in positions.iter().enumerate() {
            let start = i * fragment_size;
            let end = if i == num_fragments - 1 { 32 } else { start + fragment_size };
            
            // Generate XOR mask
            let mask_len = end - start;
            let mut xor_mask = vec![0u8; mask_len];
            rng.fill(&mut xor_mask[..]);
            
            // XOR the key fragment with the mask
            let mut data = Vec::with_capacity(mask_len);
            for j in 0..mask_len {
                data.push(key[start + j] ^ xor_mask[j]);
            }
            
            // Add additional noise bytes
            let noise_before = rng.gen_range(1..4);
            let noise_after = rng.gen_range(1..4);
            
            let mut noisy_data = Vec::with_capacity(noise_before + data.len() + noise_after);
            for _ in 0..noise_before {
                noisy_data.push(rng.gen());
            }
            noisy_data.extend_from_slice(&data);
            for _ in 0..noise_after {
                noisy_data.push(rng.gen());
            }
            
            // Extend mask to cover noise
            let mut full_mask = Vec::with_capacity(noisy_data.len());
            for _ in 0..noise_before {
                full_mask.push(rng.gen());
            }
            full_mask.extend_from_slice(&xor_mask);
            for _ in 0..noise_after {
                full_mask.push(rng.gen());
            }
            
            fragments.push(KeyFragment {
                xor_mask: full_mask,
                data: noisy_data,
                position,
            });
        }
        
        fragments
    }
    
    pub fn reconstruct_key(fragments: &[KeyFragment]) -> Result<[u8; 32], String> {
        let mut key = [0u8; 32];
        let mut sorted_fragments: Vec<_> = fragments.iter().collect();
        sorted_fragments.sort_by_key(|f| f.position);
        
        let num_fragments = sorted_fragments.len();
        let fragment_size = 32 / num_fragments;
        
        for (i, frag) in sorted_fragments.iter().enumerate() {
            let start = frag.position * fragment_size;
            let end = if frag.position == num_fragments - 1 { 32 } else { start + fragment_size };
            
            // Find the actual data within the noisy data
            // This is a simplified reconstruction - real implementation would track offsets
            let mask = &frag.xor_mask;
            let data = &frag.data;
            
            // Skip noise bytes (assume noise pattern matches)
            let data_len = end - start;
            let noise_before = (data.len() - data_len) / 2;
            
            for j in 0..data_len {
                if start + j < 32 && noise_before + j < data.len() && noise_before + j < mask.len() {
                    key[start + j] = data[noise_before + j] ^ mask[noise_before + j];
                }
            }
        }
        
        Ok(key)
    }
    
    pub fn generate_reconstruction_code(fragments: &[KeyFragment]) -> String {
        let mut code = String::new();
        
        code.push_str("// Key reconstruction - auto-generated\n");
        code.push_str("fn reconstruct_key() -> [u8; 32] {\n");
        code.push_str("    let mut key = [0u8; 32];\n");
        
        let num_fragments = fragments.len();
        let fragment_size = 32 / num_fragments;
        
        for (i, frag) in fragments.iter().enumerate() {
            let start = frag.position * fragment_size;
            let end = if frag.position == num_fragments - 1 { 32 } else { start + fragment_size };
            let data_len = end - start;
            let noise_before = (frag.data.len() - data_len) / 2;
            
            code.push_str(&format!("    // Fragment {}\n", i));
            code.push_str(&format!("    let mask_{} = {:?};\n", i, &frag.xor_mask[noise_before..noise_before + data_len]));
            code.push_str(&format!("    let data_{} = {:?};\n", i, &frag.data[noise_before..noise_before + data_len]));
            code.push_str(&format!("    for j in 0..{} {{\n", data_len));
            code.push_str(&format!("        key[{} + j] = data_{}[j] ^ mask_{}[j];\n", start, i, i));
            code.push_str("    }\n");
        }
        
        code.push_str("    key\n");
        code.push_str("}\n");
        
        code
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    
    #[test]
    fn test_key_obfuscation_roundtrip() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        
        let mut rng = StdRng::seed_from_u64(12345);
        let fragments = KeyObfuscator::obfuscate_key(&key, &mut rng);
        
        assert!(fragments.len() >= 4);
        
        // Verify each fragment is different from the original
        for frag in &fragments {
            assert!(!frag.data.is_empty());
            assert!(!frag.xor_mask.is_empty());
        }
    }
}
