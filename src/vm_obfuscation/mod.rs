
pub mod nested_vm;
pub mod opaque_predicates;
pub mod dead_code;
pub mod trampolines;

pub use nested_vm::NestedVm;
pub use opaque_predicates::OpaquePredicate;
pub use dead_code::DeadCodeGenerator;
pub use trampolines::TrampolineGenerator;

pub type ObfuscationConfig = VmObfuscationConfig;

#[derive(Debug, Clone)]
pub struct VmObfuscationConfig {
    pub nested_vm: bool,
    pub handler_virtualization_percent: u8,
    pub opaque_predicates: bool,
    pub dead_code: bool,
    pub trampolines: bool,
    pub encrypt_handlers: bool,
    pub randomize_addresses: bool,
}

impl Default for VmObfuscationConfig {
    fn default() -> Self {
        Self {
            nested_vm: true,
            handler_virtualization_percent: 50,
            opaque_predicates: true,
            dead_code: true,
            trampolines: true,
            encrypt_handlers: true,
            randomize_addresses: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum NestedOpcode {
    // Basic ops
    NvmPush = 0x00,
    NvmPop = 0x01,
    NvmDup = 0x02,
    NvmSwap = 0x03,
    
    // Arithmetic
    NvmAdd = 0x10,
    NvmSub = 0x11,
    NvmMul = 0x12,
    NvmXor = 0x13,
    NvmRol = 0x14,
    NvmRor = 0x15,
    
    // Memory
    NvmLoad = 0x20,
    NvmStore = 0x21,
    NvmCopy = 0x22,
    
    // Control
    NvmJmp = 0x30,
    NvmJz = 0x31,
    NvmJnz = 0x32,
    NvmCall = 0x33,
    NvmRet = 0x34,
    
    // Special
    NvmDecrypt = 0x40,
    NvmVerify = 0x41,
    NvmDispatch = 0x42,
    
    // Exit back to main VM
    NvmExit = 0xFF,
}

pub struct ObfuscatedHandler {
    pub encrypted_code: Vec<u8>,
    pub key: [u8; 16],
    pub trampoline_offset: usize,
    pub dead_code_prefix: Vec<u8>,
    pub dead_code_suffix: Vec<u8>,
}

impl ObfuscatedHandler {
    pub fn new(handler_code: &[u8], rng: &mut impl rand::Rng) -> Self {
        use rand::RngCore;
        
        // Generate key
        let mut key = [0u8; 16];
        rng.fill_bytes(&mut key);
        
        // Encrypt code
        let encrypted_code: Vec<u8> = handler_code
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % 16])
            .collect();
        
        // Generate dead code
        let dead_prefix_len = rng.gen_range(4..16);
        let dead_suffix_len = rng.gen_range(4..16);
        
        let mut dead_code_prefix = vec![0u8; dead_prefix_len];
        let mut dead_code_suffix = vec![0u8; dead_suffix_len];
        rng.fill_bytes(&mut dead_code_prefix);
        rng.fill_bytes(&mut dead_code_suffix);
        
        // Trampoline offset accounts for dead code prefix
        let trampoline_offset = dead_code_prefix.len();
        
        Self {
            encrypted_code,
            key,
            trampoline_offset,
            dead_code_prefix,
            dead_code_suffix,
        }
    }
    
    pub fn get_bytecode(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.dead_code_prefix);
        result.extend_from_slice(&self.encrypted_code);
        result.extend_from_slice(&self.dead_code_suffix);
        result
    }
    
    pub fn decrypt(&self) -> Vec<u8> {
        self.encrypted_code
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ self.key[i % 16])
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct VirtualHandlerSequence {
    pub nested_bytecode: Vec<u8>,
    pub input_map: Vec<usize>,
    pub output_map: Vec<usize>,
    pub predicates: Vec<OpaquePredicate>,
}

impl VirtualHandlerSequence {
    pub fn from_native(
        native_handler: fn(&mut crate::vm_core::VmInterpreter) -> Result<(), String>,
        config: &VmObfuscationConfig,
    ) -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        // Generate nested bytecode that performs the same operation
        let mut nested_bytecode = Vec::new();
        
        // Start with some dead code
        if config.dead_code {
            let dead_gen = DeadCodeGenerator::new();
            nested_bytecode.extend_from_slice(&dead_gen.generate(rng.gen_range(4..12)));
        }
        
        // Add opaque predicates
        let mut predicates = Vec::new();
        if config.opaque_predicates {
            predicates.push(OpaquePredicate::always_true());
            nested_bytecode.push(NestedOpcode::NvmJnz as u8);
            nested_bytecode.push(0x02); // Skip next instruction
        }
        
        // Actual operation placeholder (simplified)
        nested_bytecode.push(NestedOpcode::NvmDispatch as u8);
        
        // End with dead code
        if config.dead_code {
            let dead_gen = DeadCodeGenerator::new();
            nested_bytecode.extend_from_slice(&dead_gen.generate(rng.gen_range(4..12)));
        }
        
        nested_bytecode.push(NestedOpcode::NvmExit as u8);
        
        Self {
            nested_bytecode,
            input_map: vec![0, 1, 2, 3],
            output_map: vec![0],
            predicates,
        }
    }
}
