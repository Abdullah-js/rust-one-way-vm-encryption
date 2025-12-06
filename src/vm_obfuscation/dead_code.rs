
use rand::{Rng, RngCore};

pub struct DeadCodeGenerator {
    complexity: u8,
}

impl DeadCodeGenerator {
    pub fn new() -> Self {
        Self { complexity: 3 }
    }
    
    pub fn with_complexity(complexity: u8) -> Self {
        Self {
            complexity: complexity.clamp(1, 5),
        }
    }
    
    pub fn generate(&self, size: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut code = Vec::with_capacity(size);
        
        while code.len() < size {
            let pattern = rng.gen_range(0..10);
            
            match pattern {
                0..=2 => {
                    // Simple NOP-like sequences
                    code.extend_from_slice(&self.gen_nop_sequence(&mut rng));
                }
                3..=4 => {
                    // Fake arithmetic
                    code.extend_from_slice(&self.gen_fake_arithmetic(&mut rng));
                }
                5..=6 => {
                    // Fake load/store
                    code.extend_from_slice(&self.gen_fake_memory(&mut rng));
                }
                7..=8 => {
                    // Fake comparison/jump
                    code.extend_from_slice(&self.gen_fake_control(&mut rng));
                }
                _ => {
                    // Random bytes (as bogus opcodes)
                    code.push(rng.gen_range(0xD0..=0xED)); // Bogus opcode range
                }
            }
        }
        
        code.truncate(size);
        code
    }
    
    fn gen_nop_sequence(&self, rng: &mut impl Rng) -> Vec<u8> {
        let mut seq = Vec::new();
        let count = rng.gen_range(1..4);
        
        for _ in 0..count {
            // Various forms of NOPs
            match rng.gen_range(0..5) {
                0 => seq.push(0xFE), // Actual NOP
                1 => {
                    // PUSH + POP (net effect: nothing)
                    seq.push(0x02); // PUSH_INT8
                    seq.push(rng.gen());
                    seq.push(0x0A); // POP
                }
                2 => {
                    // DUP + POP
                    seq.push(0x0B); // DUP
                    seq.push(0x0A); // POP
                }
                3 => {
                    // ADD 0
                    seq.push(0x02); // PUSH_INT8
                    seq.push(0);
                    seq.push(0x20); // ADD
                }
                _ => {
                    // XOR 0
                    seq.push(0x02);
                    seq.push(0);
                    seq.push(0x32); // XOR
                }
            }
        }
        
        seq
    }
    
    fn gen_fake_arithmetic(&self, rng: &mut impl Rng) -> Vec<u8> {
        let mut seq = Vec::new();
        
        match rng.gen_range(0..4) {
            0 => {
                // x + y - y = x
                let val: u8 = rng.gen();
                seq.push(0x02);
                seq.push(val);
                seq.push(0x20); // ADD
                seq.push(0x02);
                seq.push(val);
                seq.push(0x21); // SUB
            }
            1 => {
                // x * 1 = x
                seq.push(0x02);
                seq.push(1);
                seq.push(0x22); // MUL
            }
            2 => {
                // x ^ x ^ x = x
                seq.push(0x0B); // DUP
                seq.push(0x32); // XOR
                seq.push(0x0B);
                seq.push(0x32);
            }
            _ => {
                // (x << n) >> n = x (for small n)
                let shift = rng.gen_range(1..8);
                seq.push(0x02);
                seq.push(shift);
                seq.push(0x34); // SHL
                seq.push(0x02);
                seq.push(shift);
                seq.push(0x35); // SHR
            }
        }
        
        seq
    }
    
    fn gen_fake_memory(&self, rng: &mut impl Rng) -> Vec<u8> {
        let mut seq = Vec::new();
        
        // These use local variables that are never read
        let fake_local = rng.gen_range(200..255); // High local slot unlikely to be used
        
        match rng.gen_range(0..3) {
            0 => {
                // Store to unused local
                seq.push(0x02); // PUSH value
                seq.push(rng.gen());
                seq.push(0x11); // STORE_LOCAL
                seq.push(fake_local);
            }
            1 => {
                // Load + pop (value discarded)
                seq.push(0x10); // LOAD_LOCAL
                seq.push(fake_local);
                seq.push(0x0A); // POP
            }
            _ => {
                // Store then immediately overwrite
                seq.push(0x02);
                seq.push(rng.gen());
                seq.push(0x11);
                seq.push(fake_local);
                seq.push(0x02);
                seq.push(rng.gen());
                seq.push(0x11);
                seq.push(fake_local);
            }
        }
        
        seq
    }
    
    fn gen_fake_control(&self, rng: &mut impl Rng) -> Vec<u8> {
        let mut seq = Vec::new();
        
        match rng.gen_range(0..3) {
            0 => {
                // Jump to next instruction (no-op jump)
                let next_offset = (seq.len() + 3) as u16;
                seq.push(0x60); // JUMP
                seq.extend_from_slice(&next_offset.to_le_bytes());
            }
            1 => {
                // Conditional jump that never triggers
                seq.push(0x01); // PUSH_BOOL
                seq.push(0);    // false
                seq.push(0x62); // JUMP_IF_TRUE (never triggers)
                seq.extend_from_slice(&0u16.to_le_bytes());
            }
            _ => {
                // Always-true condition, jump over nothing
                seq.push(0x01);
                seq.push(1);    // true
                seq.push(0x61); // JUMP_IF_FALSE (never triggers)
                seq.extend_from_slice(&0u16.to_le_bytes());
            }
        }
        
        seq
    }
    
    pub fn generate_block(&self, pattern: DeadCodePattern) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        
        match pattern {
            DeadCodePattern::NopSled(len) => {
                vec![0xFE; len]
            }
            DeadCodePattern::FakeLoop => {
                let mut code = Vec::new();
                // Push counter
                code.push(0x02);
                code.push(0);
                code.push(0x11); // Store to local 250
                code.push(250);
                // Label (implicit)
                let loop_start = code.len();
                // Increment counter
                code.push(0x10); // Load
                code.push(250);
                code.push(0x02);
                code.push(1);
                code.push(0x20); // Add
                code.push(0x11);
                code.push(250);
                // Check if < 0 (never true for unsigned)
                code.push(0x10);
                code.push(250);
                code.push(0x02);
                code.push(0);
                code.push(0x42); // LT
                code.push(0x62); // JUMP_IF_TRUE
                code.extend_from_slice(&(loop_start as u16).to_le_bytes());
                code
            }
            DeadCodePattern::FakeSwitch => {
                let mut code = Vec::new();
                // Push fake selector
                code.push(0x02);
                code.push(255); // Value that won't match any case
                // Series of comparisons that never match
                for i in 0..4 {
                    code.push(0x0B); // DUP
                    code.push(0x02);
                    code.push(i);
                    code.push(0x40); // EQ
                    code.push(0x62); // JUMP_IF_TRUE
                    code.extend_from_slice(&0u16.to_le_bytes()); // Jump to 0 (never happens)
                }
                code.push(0x0A); // POP selector
                code
            }
            DeadCodePattern::Random(len) => {
                self.generate(len)
            }
        }
    }
}

impl Default for DeadCodeGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub enum DeadCodePattern {
    NopSled(usize),
    FakeLoop,
    FakeSwitch,
    Random(usize),
}
