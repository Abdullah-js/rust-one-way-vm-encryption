
use rand::{Rng, SeedableRng, seq::SliceRandom};
use rand::rngs::StdRng;
use std::collections::HashMap;

pub struct BuildRandomizer {
    rng: StdRng,
    opcode_map: HashMap<u8, u8>,
    reverse_map: HashMap<u8, u8>,
    bogus_opcodes: Vec<u8>,
}

impl BuildRandomizer {
    pub fn new(seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let (opcode_map, reverse_map) = Self::generate_opcode_mapping(&mut rng);
        let bogus_opcodes = Self::generate_bogus_opcodes(&mut rng);
        
        Self {
            rng,
            opcode_map,
            reverse_map,
            bogus_opcodes,
        }
    }
    
    fn generate_opcode_mapping(rng: &mut StdRng) -> (HashMap<u8, u8>, HashMap<u8, u8>) {
        // Core opcodes 0x00-0x40
        let mut core: Vec<u8> = (0x00..=0x40).collect();
        let mut shuffled = core.clone();
        shuffled.shuffle(rng);
        
        let mut map = HashMap::new();
        let mut reverse = HashMap::new();
        
        for (i, &shuffled_op) in shuffled.iter().enumerate() {
            map.insert(core[i], shuffled_op);
            reverse.insert(shuffled_op, core[i]);
        }
        
        (map, reverse)
    }
    
    fn generate_bogus_opcodes(rng: &mut StdRng) -> Vec<u8> {
        let mut bogus: Vec<u8> = (0xE0..=0xFD).collect();
        bogus.shuffle(rng);
        bogus
    }
    
    pub fn randomize_opcodes(&self, bytecode: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(bytecode.len());
        let mut i = 0;
        
        while i < bytecode.len() {
            let op = bytecode[i];
            
            if let Some(&mapped) = self.opcode_map.get(&op) {
                output.push(mapped);
            } else {
                output.push(op);
            }
            
            i += 1;
            
            // Copy operands (simplified - real impl would use opcode size info)
            // This is a basic implementation
        }
        
        output
    }
    
    pub fn inject_dead_code(&mut self, bytecode: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(bytecode.len() * 2);
        let mut i = 0;
        
        while i < bytecode.len() {
            // Randomly inject dead code
            if self.rng.gen_bool(0.15) {
                self.inject_random_dead_code(&mut output);
            }
            
            output.push(bytecode[i]);
            i += 1;
        }
        
        output
    }
    
    fn inject_random_dead_code(&mut self, output: &mut Vec<u8>) {
        let pattern = self.rng.gen_range(0..6);
        
        match pattern {
            0 => {
                // NOP sequence
                let count = self.rng.gen_range(1..4);
                for _ in 0..count {
                    output.push(0xFE); // NOP
                }
            }
            1 => {
                // Push and pop (no effect)
                output.push(0x02); // PUSH
                output.push(self.rng.gen()); // random value
                output.push(0x03); // POP
            }
            2 => {
                // Random bogus opcode
                if let Some(&bogus) = self.bogus_opcodes.choose(&mut self.rng) {
                    output.push(bogus);
                    // Add random operand
                    output.push(self.rng.gen());
                }
            }
            3 => {
                // XOR with zero (no change)
                output.push(0x12); // XOR
                output.push(0x00);
            }
            4 => {
                // Add zero
                output.push(0x0A); // ADD
                output.push(0x00);
            }
            5 => {
                // Conditional jump that never triggers
                output.push(0x65); // JZ
                output.push(0x01); // Jump +1
                output.push(0xFE); // NOP (jumped over)
            }
            _ => {}
        }
    }
    
    pub fn opcode_mapping(&self) -> &HashMap<u8, u8> {
        &self.opcode_map
    }
    
    pub fn reverse_mapping(&self) -> &HashMap<u8, u8> {
        &self.reverse_map
    }
    
    pub fn regenerate(&mut self) {
        let (map, reverse) = Self::generate_opcode_mapping(&mut self.rng);
        self.opcode_map = map;
        self.reverse_map = reverse;
        self.bogus_opcodes = Self::generate_bogus_opcodes(&mut self.rng);
    }
}

pub struct InstructionReorderer {
    rng: StdRng,
}

impl InstructionReorderer {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
        }
    }
    
    pub fn reorder(&mut self, bytecode: &[u8]) -> Vec<u8> {
        // Find basic blocks
        let blocks = self.find_basic_blocks(bytecode);
        
        let mut output = Vec::with_capacity(bytecode.len());
        
        for block in blocks {
            let reordered = self.reorder_block(&block);
            output.extend(reordered);
        }
        
        output
    }
    
    fn find_basic_blocks(&self, bytecode: &[u8]) -> Vec<Vec<u8>> {
        let mut blocks = Vec::new();
        let mut current = Vec::new();
        
        for &byte in bytecode {
            current.push(byte);
            
            // Check for block terminators
            if byte >= 0x60 && byte <= 0x6F {
                // Jump instruction - end of block
                blocks.push(current);
                current = Vec::new();
            }
        }
        
        if !current.is_empty() {
            blocks.push(current);
        }
        
        blocks
    }
    
    fn reorder_block(&mut self, block: &[u8]) -> Vec<u8> {
        // Simple reordering - shuffle independent instructions
        // Real implementation would do dependency analysis
        
        if block.len() < 4 {
            return block.to_vec();
        }
        
        // For safety, only shuffle a portion
        let safe_len = block.len().saturating_sub(2);
        let mut reorderable: Vec<u8> = block[..safe_len].to_vec();
        let tail = &block[safe_len..];
        
        // Shuffle pairs
        if reorderable.len() >= 4 && self.rng.gen_bool(0.3) {
            let idx = self.rng.gen_range(0..reorderable.len() - 2);
            reorderable.swap(idx, idx + 2);
        }
        
        reorderable.extend_from_slice(tail);
        reorderable
    }
}
