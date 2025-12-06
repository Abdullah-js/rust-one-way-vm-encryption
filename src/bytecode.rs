
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use sha2::{Sha256, Digest};

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum Opcode {
    // Stack operations
    PushNull = 0x00,
    PushBool = 0x01,
    PushInt = 0x02,
    PushFloat = 0x03,
    PushString = 0x04,
    Pop = 0x05,
    Dup = 0x06,
    
    // Local variables (numbered, not named)
    LoadLocal = 0x10,
    StoreLocal = 0x11,
    
    // Arithmetic
    Add = 0x20,
    Sub = 0x21,
    Mul = 0x22,
    Div = 0x23,
    Mod = 0x24,
    Neg = 0x25,
    
    // Comparison
    Eq = 0x30,
    Ne = 0x31,
    Lt = 0x32,
    Le = 0x33,
    Gt = 0x34,
    Ge = 0x35,
    
    // Logic
    And = 0x40,
    Or = 0x41,
    Not = 0x42,
    
    // Control flow
    Jump = 0x50,
    JumpIfFalse = 0x51,
    JumpIfTrue = 0x52,
    
    // Functions
    Call = 0x60,
    Return = 0x61,
    CallBuiltin = 0x62,
    
    // Objects/Arrays
    NewArray = 0x70,
    ArrayGet = 0x71,
    ArraySet = 0x72,
    ArrayLen = 0x73,
    NewObject = 0x74,
    ObjGet = 0x75,
    ObjSet = 0x76,
    
    // Special
    Halt = 0xFF,
    Nop = 0xFE,
}

impl Opcode {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Opcode::PushNull),
            0x01 => Some(Opcode::PushBool),
            0x02 => Some(Opcode::PushInt),
            0x03 => Some(Opcode::PushFloat),
            0x04 => Some(Opcode::PushString),
            0x05 => Some(Opcode::Pop),
            0x06 => Some(Opcode::Dup),
            0x10 => Some(Opcode::LoadLocal),
            0x11 => Some(Opcode::StoreLocal),
            0x20 => Some(Opcode::Add),
            0x21 => Some(Opcode::Sub),
            0x22 => Some(Opcode::Mul),
            0x23 => Some(Opcode::Div),
            0x24 => Some(Opcode::Mod),
            0x25 => Some(Opcode::Neg),
            0x30 => Some(Opcode::Eq),
            0x31 => Some(Opcode::Ne),
            0x32 => Some(Opcode::Lt),
            0x33 => Some(Opcode::Le),
            0x34 => Some(Opcode::Gt),
            0x35 => Some(Opcode::Ge),
            0x40 => Some(Opcode::And),
            0x41 => Some(Opcode::Or),
            0x42 => Some(Opcode::Not),
            0x50 => Some(Opcode::Jump),
            0x51 => Some(Opcode::JumpIfFalse),
            0x52 => Some(Opcode::JumpIfTrue),
            0x60 => Some(Opcode::Call),
            0x61 => Some(Opcode::Return),
            0x62 => Some(Opcode::CallBuiltin),
            0x70 => Some(Opcode::NewArray),
            0x71 => Some(Opcode::ArrayGet),
            0x72 => Some(Opcode::ArraySet),
            0x73 => Some(Opcode::ArrayLen),
            0x74 => Some(Opcode::NewObject),
            0x75 => Some(Opcode::ObjGet),
            0x76 => Some(Opcode::ObjSet),
            0xFF => Some(Opcode::Halt),
            0xFE => Some(Opcode::Nop),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Constant {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(Vec<u8>), // Scrambled string bytes
}

#[derive(Debug, Clone)]
pub struct BytecodeFunction {
    pub param_count: u8,
    pub local_count: u8,
    pub code: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BytecodeModule {
    pub magic: [u8; 4],
    pub scramble_key: [u8; 16],
    pub constants: Vec<Constant>,
    pub functions: Vec<BytecodeFunction>,
    pub builtins: Vec<Vec<u8>>,
}

impl BytecodeModule {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let mut magic = [0u8; 4];
        let mut scramble_key = [0u8; 16];
        rng.fill(&mut magic);
        rng.fill(&mut scramble_key);
        
        Self {
            magic,
            scramble_key,
            constants: Vec::new(),
            functions: Vec::new(),
            builtins: Vec::new(),
        }
    }
    
    pub fn add_constant(&mut self, c: Constant) -> u16 {
        let idx = self.constants.len() as u16;
        self.constants.push(c);
        idx
    }
    
    pub fn add_string(&mut self, s: &str) -> u16 {
        let scrambled = self.scramble_string(s);
        self.add_constant(Constant::String(scrambled))
    }
    
    pub fn add_builtin(&mut self, name: &str) -> u16 {
        let scrambled = self.scramble_string(name);
        let idx = self.builtins.len() as u16;
        self.builtins.push(scrambled);
        idx
    }
    
    fn scramble_string(&self, s: &str) -> Vec<u8> {
        let bytes = s.as_bytes();
        let mut hasher = Sha256::new();
        hasher.update(&self.scramble_key);
        hasher.update(bytes);
        let hash = hasher.finalize();
        
        let mut rng = StdRng::from_seed({
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&hash);
            seed
        });
        
        // XOR with pseudo-random stream
        bytes.iter().enumerate().map(|(i, &b)| {
            b ^ rng.gen::<u8>() ^ self.scramble_key[i % 16]
        }).collect()
    }
    
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        
        // Magic header
        out.extend_from_slice(&self.magic);
        
        // Scramble key
        out.extend_from_slice(&self.scramble_key);
        
        // Constants count
        out.extend_from_slice(&(self.constants.len() as u32).to_le_bytes());
        
        // Constants
        for c in &self.constants {
            match c {
                Constant::Null => out.push(0x00),
                Constant::Bool(b) => {
                    out.push(0x01);
                    out.push(if *b { 1 } else { 0 });
                }
                Constant::Int(n) => {
                    out.push(0x02);
                    out.extend_from_slice(&n.to_le_bytes());
                }
                Constant::Float(f) => {
                    out.push(0x03);
                    out.extend_from_slice(&f.to_le_bytes());
                }
                Constant::String(s) => {
                    out.push(0x04);
                    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
                    out.extend_from_slice(s);
                }
            }
        }
        
        // Builtins count
        out.extend_from_slice(&(self.builtins.len() as u32).to_le_bytes());
        for b in &self.builtins {
            out.extend_from_slice(&(b.len() as u32).to_le_bytes());
            out.extend_from_slice(b);
        }
        
        // Functions count
        out.extend_from_slice(&(self.functions.len() as u32).to_le_bytes());
        for f in &self.functions {
            out.push(f.param_count);
            out.push(f.local_count);
            out.extend_from_slice(&(f.code.len() as u32).to_le_bytes());
            out.extend_from_slice(&f.code);
        }
        
        // Add noise padding
        let mut rng = rand::thread_rng();
        let noise_len = rng.gen_range(16..64);
        for _ in 0..noise_len {
            out.push(rng.gen());
        }
        
        out
    }
    
    pub fn to_hex_string(&self) -> String {
        self.to_bytes()
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl Default for BytecodeModule {
    fn default() -> Self {
        Self::new()
    }
}
