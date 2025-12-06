
use std::collections::{HashMap, HashSet};

pub struct CodeOptimizer {
    peephole: bool,
    dce: bool,
    constant_fold: bool,
}

impl CodeOptimizer {
    pub fn new() -> Self {
        Self {
            peephole: true,
            dce: true,
            constant_fold: true,
        }
    }
    
    pub fn optimize(&self, bytecode: &[u8]) -> Vec<u8> {
        let mut result = bytecode.to_vec();
        
        if self.constant_fold {
            result = self.fold_constants(&result);
        }
        
        if self.peephole {
            result = self.peephole_optimize(&result);
        }
        
        if self.dce {
            result = self.eliminate_dead_code(&result);
        }
        
        result
    }
    
    fn peephole_optimize(&self, bytecode: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(bytecode.len());
        let mut i = 0;
        
        while i < bytecode.len() {
            // Pattern: PUSH x; POP -> nothing
            if i + 2 < bytecode.len() 
                && bytecode[i] == 0x02 
                && bytecode[i + 2] == 0x03 
            {
                i += 3;
                continue;
            }
            
            // Pattern: NOP -> nothing
            if bytecode[i] == 0xFE {
                i += 1;
                continue;
            }
            
            // Pattern: ADD 0 or SUB 0 -> nothing
            if i + 1 < bytecode.len() 
                && (bytecode[i] == 0x0A || bytecode[i] == 0x0B)
                && bytecode[i + 1] == 0x00
            {
                i += 2;
                continue;
            }
            
            // Pattern: MUL 1 or DIV 1 -> nothing
            if i + 1 < bytecode.len()
                && (bytecode[i] == 0x0C || bytecode[i] == 0x0D)
                && bytecode[i + 1] == 0x01
            {
                i += 2;
                continue;
            }
            
            // Pattern: XOR 0 -> nothing
            if i + 1 < bytecode.len()
                && bytecode[i] == 0x12
                && bytecode[i + 1] == 0x00
            {
                i += 2;
                continue;
            }
            
            // Pattern: LOAD x; STORE x -> nothing (if no side effects)
            if i + 3 < bytecode.len()
                && bytecode[i] == 0x06
                && bytecode[i + 2] == 0x07
                && bytecode[i + 1] == bytecode[i + 3]
            {
                i += 4;
                continue;
            }
            
            // Pattern: JMP to next instruction -> nothing
            if i + 2 < bytecode.len()
                && bytecode[i] == 0x60
                && bytecode[i + 1] == 0x00
                && bytecode[i + 2] == 0x03
            {
                i += 3;
                continue;
            }
            
            result.push(bytecode[i]);
            i += 1;
        }
        
        result
    }
    
    fn fold_constants(&self, bytecode: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(bytecode.len());
        let mut i = 0;
        
        while i < bytecode.len() {
            // Pattern: CONST a; CONST b; ADD -> CONST (a+b)
            if i + 5 < bytecode.len()
                && bytecode[i] == 0x05
                && bytecode[i + 2] == 0x05
                && bytecode[i + 4] == 0x0A
            {
                let a = bytecode[i + 1] as i16;
                let b = bytecode[i + 3] as i16;
                let sum = (a.wrapping_add(b)) as u8;
                result.push(0x05); // CONST
                result.push(sum);
                i += 5;
                continue;
            }
            
            // Pattern: CONST a; CONST b; SUB -> CONST (a-b)
            if i + 5 < bytecode.len()
                && bytecode[i] == 0x05
                && bytecode[i + 2] == 0x05
                && bytecode[i + 4] == 0x0B
            {
                let a = bytecode[i + 1] as i16;
                let b = bytecode[i + 3] as i16;
                let diff = (a.wrapping_sub(b)) as u8;
                result.push(0x05);
                result.push(diff);
                i += 5;
                continue;
            }
            
            // Pattern: CONST a; CONST b; MUL -> CONST (a*b)
            if i + 5 < bytecode.len()
                && bytecode[i] == 0x05
                && bytecode[i + 2] == 0x05
                && bytecode[i + 4] == 0x0C
            {
                let a = bytecode[i + 1] as i32;
                let b = bytecode[i + 3] as i32;
                let prod = (a.wrapping_mul(b)) as u8;
                result.push(0x05);
                result.push(prod);
                i += 5;
                continue;
            }
            
            result.push(bytecode[i]);
            i += 1;
        }
        
        result
    }
    
    fn eliminate_dead_code(&self, bytecode: &[u8]) -> Vec<u8> {
        // Find all jump targets
        let mut targets: HashSet<usize> = HashSet::new();
        let mut i = 0;
        
        while i < bytecode.len() {
            match bytecode[i] {
                0x60..=0x6F => {
                    // Jump instructions
                    if i + 2 < bytecode.len() {
                        let offset = u16::from_le_bytes([
                            bytecode[i + 1],
                            bytecode.get(i + 2).copied().unwrap_or(0),
                        ]) as usize;
                        targets.insert(offset);
                    }
                }
                _ => {}
            }
            i += 1;
        }
        
        // Mark reachable code
        let mut reachable: HashSet<usize> = HashSet::new();
        let mut worklist = vec![0usize];
        
        while let Some(addr) = worklist.pop() {
            if reachable.contains(&addr) || addr >= bytecode.len() {
                continue;
            }
            reachable.insert(addr);
            
            // Add successor(s)
            if addr < bytecode.len() {
                let op = bytecode[addr];
                match op {
                    0x60 => {
                        // Unconditional jump
                        if addr + 2 < bytecode.len() {
                            let offset = u16::from_le_bytes([
                                bytecode[addr + 1],
                                bytecode[addr + 2],
                            ]) as usize;
                            worklist.push(offset);
                        }
                    }
                    0x61..=0x6F => {
                        // Conditional jump - add both targets
                        if addr + 2 < bytecode.len() {
                            let offset = u16::from_le_bytes([
                                bytecode[addr + 1],
                                bytecode[addr + 2],
                            ]) as usize;
                            worklist.push(offset);
                            worklist.push(addr + 3); // Fall through
                        }
                    }
                    0x00 | 0x01 => {
                        // HALT or RET - no successor
                    }
                    _ => {
                        // Normal instruction - fall through
                        worklist.push(addr + 1);
                    }
                }
            }
        }
        
        // Keep only reachable code (simplified - would need relocation)
        // For now, return original if too complex
        if reachable.len() < bytecode.len() / 2 {
            // Significant dead code - but relocation is complex
            // Return original for safety
            return bytecode.to_vec();
        }
        
        bytecode.to_vec()
    }
    
    pub fn set_peephole(&mut self, enable: bool) {
        self.peephole = enable;
    }
    
    pub fn set_dce(&mut self, enable: bool) {
        self.dce = enable;
    }
    
    pub fn set_constant_fold(&mut self, enable: bool) {
        self.constant_fold = enable;
    }
}

impl Default for CodeOptimizer {
    fn default() -> Self {
        Self::new()
    }
}
