
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use std::collections::HashMap;

pub struct TrampolineGenerator {
    base_address: usize,
    trampolines: HashMap<usize, Trampoline>,
    rng: StdRng,
}

#[derive(Debug, Clone)]
pub struct Trampoline {
    pub from: usize,
    pub to: usize,
    pub hops: Vec<usize>,
    pub prefix: Vec<u8>,
    pub suffix: Vec<u8>,
}

impl TrampolineGenerator {
    pub fn new(base_address: usize) -> Self {
        Self {
            base_address,
            trampolines: HashMap::new(),
            rng: StdRng::from_entropy(),
        }
    }
    
    pub fn with_seed(base_address: usize, seed: u64) -> Self {
        Self {
            base_address,
            trampolines: HashMap::new(),
            rng: StdRng::seed_from_u64(seed),
        }
    }
    
    pub fn generate(&mut self, handler_address: usize) -> Trampoline {
        let from = self.base_address + self.trampolines.len() * 64;
        
        // Decide number of hops
        let num_hops = self.rng.gen_range(0..3);
        let mut hops = Vec::with_capacity(num_hops);
        
        for i in 0..num_hops {
            hops.push(from + (i + 1) * 16);
        }
        
        // Generate padding
        let prefix_len = self.rng.gen_range(4..16);
        let suffix_len = self.rng.gen_range(4..16);
        
        let prefix: Vec<u8> = (0..prefix_len).map(|_| self.rng.gen()).collect();
        let suffix: Vec<u8> = (0..suffix_len).map(|_| self.rng.gen()).collect();
        
        let trampoline = Trampoline {
            from,
            to: handler_address,
            hops,
            prefix,
            suffix,
        };
        
        self.trampolines.insert(handler_address, trampoline.clone());
        trampoline
    }
    
    pub fn generate_bytecode(&self, trampoline: &Trampoline) -> Vec<u8> {
        let mut code = Vec::new();
        
        // Prefix padding (dead code)
        code.extend_from_slice(&trampoline.prefix);
        
        // Multi-hop trampolines
        if trampoline.hops.is_empty() {
            // Direct jump
            code.push(0x60); // JUMP opcode
            code.extend_from_slice(&(trampoline.to as u16).to_le_bytes());
        } else {
            // First hop
            let mut current_target = trampoline.hops[0];
            code.push(0x60);
            code.extend_from_slice(&(current_target as u16).to_le_bytes());
            
            // Intermediate hops
            for i in 0..trampoline.hops.len() {
                // Add some padding between hops
                for _ in 0..4 {
                    code.push(0xFE); // NOP
                }
                
                let next_target = if i + 1 < trampoline.hops.len() {
                    trampoline.hops[i + 1]
                } else {
                    trampoline.to
                };
                
                code.push(0x60);
                code.extend_from_slice(&(next_target as u16).to_le_bytes());
            }
        }
        
        // Suffix padding
        code.extend_from_slice(&trampoline.suffix);
        
        code
    }
    
    pub fn get_or_create(&mut self, handler_address: usize) -> &Trampoline {
        if !self.trampolines.contains_key(&handler_address) {
            self.generate(handler_address);
        }
        self.trampolines.get(&handler_address).unwrap()
    }
    
    pub fn generate_dispatch_table(&mut self, handler_addresses: &[usize]) -> Vec<usize> {
        handler_addresses
            .iter()
            .map(|&addr| {
                let trampoline = self.get_or_create(addr);
                trampoline.from
            })
            .collect()
    }
    
    pub fn randomize(&mut self) {
        let addresses: Vec<usize> = self.trampolines.keys().copied().collect();
        
        for addr in addresses {
            if let Some(trampoline) = self.trampolines.get_mut(&addr) {
                // Regenerate random parts
                let prefix_len = self.rng.gen_range(4..16);
                let suffix_len = self.rng.gen_range(4..16);
                
                trampoline.prefix = (0..prefix_len).map(|_| self.rng.gen()).collect();
                trampoline.suffix = (0..suffix_len).map(|_| self.rng.gen()).collect();
                
                // Regenerate hops
                let num_hops = self.rng.gen_range(0..3);
                trampoline.hops.clear();
                for i in 0..num_hops {
                    trampoline.hops.push(trampoline.from + (i + 1) * 16);
                }
            }
        }
    }
    
    pub fn trampolines(&self) -> &HashMap<usize, Trampoline> {
        &self.trampolines
    }
}

pub struct TrampolineChain {
    stages: Vec<TrampolineGenerator>,
}

impl TrampolineChain {
    pub fn new(depth: usize, base_address: usize) -> Self {
        let mut stages = Vec::with_capacity(depth);
        
        for i in 0..depth {
            stages.push(TrampolineGenerator::new(base_address + i * 0x10000));
        }
        
        Self { stages }
    }
    
    pub fn generate(&mut self, final_target: usize) -> Vec<Trampoline> {
        let mut trampolines = Vec::new();
        let mut current_target = final_target;
        
        for stage in self.stages.iter_mut().rev() {
            let trampoline = stage.generate(current_target);
            current_target = trampoline.from;
            trampolines.push(trampoline);
        }
        
        trampolines.reverse();
        trampolines
    }
    
    pub fn entry_point(&self, final_target: usize) -> Option<usize> {
        self.stages.first()?.trampolines().get(&final_target).map(|t| t.from)
    }
}
