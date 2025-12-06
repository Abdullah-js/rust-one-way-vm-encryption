
use super::NestedOpcode;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

pub struct NestedVm {
    bytecode: Vec<u8>,
    ip: usize,
    stack: Vec<u64>,
    memory: Vec<u8>,
    regs: [u64; 8],
    xor_key: [u8; 16],
    handlers: Vec<Vec<u8>>,
    running: bool,
}

impl NestedVm {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let mut xor_key = [0u8; 16];
        rng.fill(&mut xor_key);
        
        Self {
            bytecode: Vec::new(),
            ip: 0,
            stack: Vec::with_capacity(256),
            memory: vec![0; 4096],
            regs: [0; 8],
            xor_key,
            handlers: Vec::new(),
            running: false,
        }
    }
    
    pub fn load(&mut self, encrypted_bytecode: &[u8], key: &[u8; 16]) {
        self.bytecode = encrypted_bytecode
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % 16])
            .collect();
        self.xor_key = *key;
        self.ip = 0;
    }
    
    pub fn execute(&mut self) -> Result<u64, String> {
        self.running = true;
        
        while self.running && self.ip < self.bytecode.len() {
            let opcode = self.bytecode[self.ip];
            self.ip += 1;
            
            self.dispatch(opcode)?;
        }
        
        // Return top of stack or 0
        Ok(self.stack.pop().unwrap_or(0))
    }
    
    fn dispatch(&mut self, opcode: u8) -> Result<(), String> {
        match opcode {
            x if x == NestedOpcode::NvmPush as u8 => self.nvm_push(),
            x if x == NestedOpcode::NvmPop as u8 => self.nvm_pop(),
            x if x == NestedOpcode::NvmDup as u8 => self.nvm_dup(),
            x if x == NestedOpcode::NvmSwap as u8 => self.nvm_swap(),
            x if x == NestedOpcode::NvmAdd as u8 => self.nvm_add(),
            x if x == NestedOpcode::NvmSub as u8 => self.nvm_sub(),
            x if x == NestedOpcode::NvmMul as u8 => self.nvm_mul(),
            x if x == NestedOpcode::NvmXor as u8 => self.nvm_xor(),
            x if x == NestedOpcode::NvmRol as u8 => self.nvm_rol(),
            x if x == NestedOpcode::NvmRor as u8 => self.nvm_ror(),
            x if x == NestedOpcode::NvmLoad as u8 => self.nvm_load(),
            x if x == NestedOpcode::NvmStore as u8 => self.nvm_store(),
            x if x == NestedOpcode::NvmCopy as u8 => self.nvm_copy(),
            x if x == NestedOpcode::NvmJmp as u8 => self.nvm_jmp(),
            x if x == NestedOpcode::NvmJz as u8 => self.nvm_jz(),
            x if x == NestedOpcode::NvmJnz as u8 => self.nvm_jnz(),
            x if x == NestedOpcode::NvmCall as u8 => self.nvm_call(),
            x if x == NestedOpcode::NvmRet as u8 => self.nvm_ret(),
            x if x == NestedOpcode::NvmDecrypt as u8 => self.nvm_decrypt(),
            x if x == NestedOpcode::NvmVerify as u8 => self.nvm_verify(),
            x if x == NestedOpcode::NvmDispatch as u8 => self.nvm_dispatch(),
            x if x == NestedOpcode::NvmExit as u8 => self.nvm_exit(),
            _ => {
                // Unknown opcode - could be dead code, skip
                Ok(())
            }
        }
    }
    
    fn read_u8(&mut self) -> Result<u8, String> {
        if self.ip >= self.bytecode.len() {
            return Err("End of bytecode".into());
        }
        let val = self.bytecode[self.ip];
        self.ip += 1;
        Ok(val)
    }
    
    fn read_u16(&mut self) -> Result<u16, String> {
        let low = self.read_u8()? as u16;
        let high = self.read_u8()? as u16;
        Ok(low | (high << 8))
    }
    
    fn read_u64(&mut self) -> Result<u64, String> {
        let mut val = 0u64;
        for i in 0..8 {
            val |= (self.read_u8()? as u64) << (i * 8);
        }
        Ok(val)
    }
    
    // ==================== NESTED VM INSTRUCTIONS ====================
    
    fn nvm_push(&mut self) -> Result<(), String> {
        let val = self.read_u64()?;
        self.stack.push(val);
        Ok(())
    }
    
    fn nvm_pop(&mut self) -> Result<(), String> {
        self.stack.pop();
        Ok(())
    }
    
    fn nvm_dup(&mut self) -> Result<(), String> {
        if let Some(&val) = self.stack.last() {
            self.stack.push(val);
        }
        Ok(())
    }
    
    fn nvm_swap(&mut self) -> Result<(), String> {
        let len = self.stack.len();
        if len >= 2 {
            self.stack.swap(len - 1, len - 2);
        }
        Ok(())
    }
    
    fn nvm_add(&mut self) -> Result<(), String> {
        let b = self.stack.pop().unwrap_or(0);
        let a = self.stack.pop().unwrap_or(0);
        self.stack.push(a.wrapping_add(b));
        Ok(())
    }
    
    fn nvm_sub(&mut self) -> Result<(), String> {
        let b = self.stack.pop().unwrap_or(0);
        let a = self.stack.pop().unwrap_or(0);
        self.stack.push(a.wrapping_sub(b));
        Ok(())
    }
    
    fn nvm_mul(&mut self) -> Result<(), String> {
        let b = self.stack.pop().unwrap_or(0);
        let a = self.stack.pop().unwrap_or(0);
        self.stack.push(a.wrapping_mul(b));
        Ok(())
    }
    
    fn nvm_xor(&mut self) -> Result<(), String> {
        let b = self.stack.pop().unwrap_or(0);
        let a = self.stack.pop().unwrap_or(0);
        self.stack.push(a ^ b);
        Ok(())
    }
    
    fn nvm_rol(&mut self) -> Result<(), String> {
        let count = self.stack.pop().unwrap_or(0) as u32;
        let val = self.stack.pop().unwrap_or(0);
        self.stack.push(val.rotate_left(count));
        Ok(())
    }
    
    fn nvm_ror(&mut self) -> Result<(), String> {
        let count = self.stack.pop().unwrap_or(0) as u32;
        let val = self.stack.pop().unwrap_or(0);
        self.stack.push(val.rotate_right(count));
        Ok(())
    }
    
    fn nvm_load(&mut self) -> Result<(), String> {
        let addr = self.stack.pop().unwrap_or(0) as usize;
        if addr + 8 <= self.memory.len() {
            let mut val = 0u64;
            for i in 0..8 {
                val |= (self.memory[addr + i] as u64) << (i * 8);
            }
            self.stack.push(val);
        } else {
            self.stack.push(0);
        }
        Ok(())
    }
    
    fn nvm_store(&mut self) -> Result<(), String> {
        let val = self.stack.pop().unwrap_or(0);
        let addr = self.stack.pop().unwrap_or(0) as usize;
        if addr + 8 <= self.memory.len() {
            for i in 0..8 {
                self.memory[addr + i] = ((val >> (i * 8)) & 0xFF) as u8;
            }
        }
        Ok(())
    }
    
    fn nvm_copy(&mut self) -> Result<(), String> {
        let len = self.stack.pop().unwrap_or(0) as usize;
        let dst = self.stack.pop().unwrap_or(0) as usize;
        let src = self.stack.pop().unwrap_or(0) as usize;
        
        if src + len <= self.memory.len() && dst + len <= self.memory.len() {
            // Handle overlapping regions
            let data: Vec<u8> = self.memory[src..src + len].to_vec();
            self.memory[dst..dst + len].copy_from_slice(&data);
        }
        Ok(())
    }
    
    fn nvm_jmp(&mut self) -> Result<(), String> {
        let target = self.read_u16()? as usize;
        self.ip = target;
        Ok(())
    }
    
    fn nvm_jz(&mut self) -> Result<(), String> {
        let target = self.read_u16()? as usize;
        let val = self.stack.pop().unwrap_or(1);
        if val == 0 {
            self.ip = target;
        }
        Ok(())
    }
    
    fn nvm_jnz(&mut self) -> Result<(), String> {
        let target = self.read_u16()? as usize;
        let val = self.stack.pop().unwrap_or(0);
        if val != 0 {
            self.ip = target;
        }
        Ok(())
    }
    
    fn nvm_call(&mut self) -> Result<(), String> {
        let target = self.read_u16()? as usize;
        self.stack.push(self.ip as u64);
        self.ip = target;
        Ok(())
    }
    
    fn nvm_ret(&mut self) -> Result<(), String> {
        let return_addr = self.stack.pop().unwrap_or(0) as usize;
        self.ip = return_addr;
        Ok(())
    }
    
    fn nvm_decrypt(&mut self) -> Result<(), String> {
        // Decrypt a block of memory using XOR key
        let len = self.stack.pop().unwrap_or(0) as usize;
        let addr = self.stack.pop().unwrap_or(0) as usize;
        
        if addr + len <= self.memory.len() {
            for i in 0..len {
                self.memory[addr + i] ^= self.xor_key[i % 16];
            }
        }
        Ok(())
    }
    
    fn nvm_verify(&mut self) -> Result<(), String> {
        // Verify a checksum
        let expected = self.stack.pop().unwrap_or(0);
        let len = self.stack.pop().unwrap_or(0) as usize;
        let addr = self.stack.pop().unwrap_or(0) as usize;
        
        if addr + len <= self.memory.len() {
            let mut hash = 0u64;
            for i in 0..len {
                hash = hash.wrapping_add(self.memory[addr + i] as u64);
                hash = hash.rotate_left(7);
            }
            self.stack.push(if hash == expected { 1 } else { 0 });
        } else {
            self.stack.push(0);
        }
        Ok(())
    }
    
    fn nvm_dispatch(&mut self) -> Result<(), String> {
        // Dispatch to encrypted handler
        let handler_idx = self.stack.pop().unwrap_or(0) as usize;
        
        if handler_idx < self.handlers.len() {
            // Decrypt handler on the fly
            let encrypted = &self.handlers[handler_idx];
            let decrypted: Vec<u8> = encrypted
                .iter()
                .enumerate()
                .map(|(i, &b)| b ^ self.xor_key[i % 16])
                .collect();
            
            // Execute decrypted handler (simplified)
            // In real implementation, would interpret or JIT compile
            self.stack.push(1); // Success
        } else {
            self.stack.push(0); // Failure
        }
        Ok(())
    }
    
    fn nvm_exit(&mut self) -> Result<(), String> {
        self.running = false;
        Ok(())
    }
    
    pub fn register_handler(&mut self, handler_bytecode: &[u8]) -> usize {
        // Encrypt handler before storing
        let encrypted: Vec<u8> = handler_bytecode
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ self.xor_key[i % 16])
            .collect();
        
        let idx = self.handlers.len();
        self.handlers.push(encrypted);
        idx
    }
    
    pub fn zeroize(&mut self) {
        for byte in &mut self.bytecode {
            *byte = 0;
        }
        for byte in &mut self.memory {
            *byte = 0;
        }
        for reg in &mut self.regs {
            *reg = 0;
        }
        for byte in &mut self.xor_key {
            *byte = 0;
        }
        for handler in &mut self.handlers {
            for byte in handler {
                *byte = 0;
            }
        }
        self.stack.clear();
    }
}

impl Default for NestedVm {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for NestedVm {
    fn drop(&mut self) {
        self.zeroize();
    }
}
