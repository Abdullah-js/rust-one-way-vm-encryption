
use rand::{Rng, RngCore, SeedableRng};
use rand::rngs::StdRng;
use sha2::{Sha256, Digest};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ExtendedOpcode {
    // ==================== STACK OPERATIONS (0x00-0x0F) ====================
    PushNull = 0x00,
    PushBool = 0x01,
    PushInt8 = 0x02,
    PushInt16 = 0x03,
    PushInt32 = 0x04,
    PushInt64 = 0x05,
    PushFloat32 = 0x06,
    PushFloat64 = 0x07,
    PushString = 0x08,
    PushConst = 0x09,
    Pop = 0x0A,
    Dup = 0x0B,
    Dup2 = 0x0C,
    Swap = 0x0D,
    Rot3 = 0x0E,
    StackDepth = 0x0F,
    
    // ==================== LOCAL VARIABLES (0x10-0x1F) ====================
    LoadLocal = 0x10,
    StoreLocal = 0x11,
    LoadLocal0 = 0x12,
    LoadLocal1 = 0x13,
    LoadLocal2 = 0x14,
    LoadLocal3 = 0x15,
    StoreLocal0 = 0x16,
    StoreLocal1 = 0x17,
    StoreLocal2 = 0x18,
    StoreLocal3 = 0x19,
    IncLocal = 0x1A,
    DecLocal = 0x1B,
    
    // ==================== ARITHMETIC (0x20-0x2F) ====================
    Add = 0x20,
    Sub = 0x21,
    Mul = 0x22,
    Div = 0x23,
    Mod = 0x24,
    Neg = 0x25,
    Inc = 0x26,
    Dec = 0x27,
    Pow = 0x28,
    Abs = 0x29,
    Min = 0x2A,
    Max = 0x2B,
    Floor = 0x2C,
    Ceil = 0x2D,
    Round = 0x2E,
    Sqrt = 0x2F,
    
    // ==================== BITWISE (0x30-0x3F) ====================
    BitAnd = 0x30,
    BitOr = 0x31,
    BitXor = 0x32,
    BitNot = 0x33,
    Shl = 0x34,
    Shr = 0x35,
    Ushr = 0x36,
    Rol = 0x37,
    Ror = 0x38,
    Popcnt = 0x39,
    Clz = 0x3A,
    Ctz = 0x3B,
    
    // ==================== COMPARISON (0x40-0x4F) ====================
    Eq = 0x40,
    Ne = 0x41,
    Lt = 0x42,
    Le = 0x43,
    Gt = 0x44,
    Ge = 0x45,
    StrictEq = 0x46,
    StrictNe = 0x47,
    IsNull = 0x48,
    IsUndef = 0x49,
    TypeOf = 0x4A,
    InstanceOf = 0x4B,
    Compare3Way = 0x4C,
    
    // ==================== LOGIC (0x50-0x57) ====================
    And = 0x50,
    Or = 0x51,
    Not = 0x52,
    Xor = 0x53,
    Nand = 0x54,
    Nor = 0x55,
    
    // ==================== CONTROL FLOW (0x60-0x6F) ====================
    Jump = 0x60,
    JumpIfFalse = 0x61,
    JumpIfTrue = 0x62,
    JumpIfNull = 0x63,
    JumpIfNotNull = 0x64,
    JumpIfZero = 0x65,
    JumpIfNotZero = 0x66,
    JumpTable = 0x67,
    Loop = 0x68,
    LoopEnd = 0x69,
    Break = 0x6A,
    Continue = 0x6B,
    
    // ==================== FUNCTIONS (0x70-0x7F) ====================
    Call = 0x70,
    CallVirtual = 0x71,
    CallBuiltin = 0x72,
    CallIndirect = 0x73,
    Return = 0x74,
    ReturnNull = 0x75,
    Yield = 0x76,
    Await = 0x77,
    TailCall = 0x78,
    Closure = 0x79,
    BindThis = 0x7A,
    
    // ==================== OBJECTS/ARRAYS (0x80-0x8F) ====================
    NewArray = 0x80,
    NewArraySized = 0x81,
    ArrayGet = 0x82,
    ArraySet = 0x83,
    ArrayLen = 0x84,
    ArrayPush = 0x85,
    ArrayPop = 0x86,
    ArraySlice = 0x87,
    NewObject = 0x88,
    ObjGet = 0x89,
    ObjSet = 0x8A,
    ObjDelete = 0x8B,
    ObjHas = 0x8C,
    ObjKeys = 0x8D,
    ObjValues = 0x8E,
    ObjEntries = 0x8F,
    
    // ==================== STRINGS (0x90-0x9F) ====================
    StrConcat = 0x90,
    StrLen = 0x91,
    StrCharAt = 0x92,
    StrSubstr = 0x93,
    StrIndexOf = 0x94,
    StrReplace = 0x95,
    StrSplit = 0x96,
    StrUpper = 0x97,
    StrLower = 0x98,
    StrTrim = 0x99,
    StrStartsWith = 0x9A,
    StrEndsWith = 0x9B,
    StrMatch = 0x9C,
    
    // ==================== EXCEPTIONS (0xA0-0xA7) ====================
    Try = 0xA0,
    Catch = 0xA1,
    Finally = 0xA2,
    Throw = 0xA3,
    Rethrow = 0xA4,
    
    // ==================== MEMORY (0xB0-0xBF) ====================
    MemLoad8 = 0xB0,
    MemLoad16 = 0xB1,
    MemLoad32 = 0xB2,
    MemLoad64 = 0xB3,
    MemStore8 = 0xB4,
    MemStore16 = 0xB5,
    MemStore32 = 0xB6,
    MemStore64 = 0xB7,
    MemCopy = 0xB8,
    MemFill = 0xB9,
    MemSize = 0xBA,
    MemGrow = 0xBB,
    
    // ==================== I/O ABSTRACTION (0xC0-0xCF) ====================
    IoRead = 0xC0,
    IoWrite = 0xC1,
    IoFlush = 0xC2,
    IoClose = 0xC3,
    IoSeek = 0xC4,
    IoTell = 0xC5,
    NetConnect = 0xC6,
    NetSend = 0xC7,
    NetRecv = 0xC8,
    NetClose = 0xC9,
    
    // ==================== BOGUS OPCODES (0xD0-0xEF) - DO NOTHING ====================
    Bogus00 = 0xD0,
    Bogus01 = 0xD1,
    Bogus02 = 0xD2,
    Bogus03 = 0xD3,
    Bogus04 = 0xD4,
    Bogus05 = 0xD5,
    Bogus06 = 0xD6,
    Bogus07 = 0xD7,
    Bogus08 = 0xD8,
    Bogus09 = 0xD9,
    Bogus0A = 0xDA,
    Bogus0B = 0xDB,
    Bogus0C = 0xDC,
    Bogus0D = 0xDD,
    Bogus0E = 0xDE,
    Bogus0F = 0xDF,
    Bogus10 = 0xE0,
    Bogus11 = 0xE1,
    Bogus12 = 0xE2,
    Bogus13 = 0xE3,
    Bogus14 = 0xE4,
    Bogus15 = 0xE5,
    Bogus16 = 0xE6,
    Bogus17 = 0xE7,
    Bogus18 = 0xE8,
    Bogus19 = 0xE9,
    Bogus1A = 0xEA,
    Bogus1B = 0xEB,
    Bogus1C = 0xEC,
    Bogus1D = 0xED,
    
    // ==================== SPECIAL (0xF0-0xFF) ====================
    Nop = 0xFE,
    Halt = 0xFF,
}

impl ExtendedOpcode {
    pub fn bogus_opcodes() -> Vec<Self> {
        vec![
            Self::Bogus00, Self::Bogus01, Self::Bogus02, Self::Bogus03,
            Self::Bogus04, Self::Bogus05, Self::Bogus06, Self::Bogus07,
            Self::Bogus08, Self::Bogus09, Self::Bogus0A, Self::Bogus0B,
            Self::Bogus0C, Self::Bogus0D, Self::Bogus0E, Self::Bogus0F,
            Self::Bogus10, Self::Bogus11, Self::Bogus12, Self::Bogus13,
            Self::Bogus14, Self::Bogus15, Self::Bogus16, Self::Bogus17,
            Self::Bogus18, Self::Bogus19, Self::Bogus1A, Self::Bogus1B,
            Self::Bogus1C, Self::Bogus1D,
        ]
    }
    
    pub fn is_bogus(&self) -> bool {
        (*self as u8) >= 0xD0 && (*self as u8) <= 0xED
    }
    
    pub fn operand_size(&self) -> usize {
        match self {
            Self::PushNull | Self::Pop | Self::Dup | Self::Dup2 | Self::Swap |
            Self::Rot3 | Self::StackDepth | Self::LoadLocal0 | Self::LoadLocal1 |
            Self::LoadLocal2 | Self::LoadLocal3 | Self::StoreLocal0 | Self::StoreLocal1 |
            Self::StoreLocal2 | Self::StoreLocal3 | Self::Add | Self::Sub | Self::Mul |
            Self::Div | Self::Mod | Self::Neg | Self::Inc | Self::Dec | Self::Pow |
            Self::Abs | Self::Min | Self::Max | Self::Floor | Self::Ceil | Self::Round |
            Self::Sqrt | Self::BitAnd | Self::BitOr | Self::BitXor | Self::BitNot |
            Self::Shl | Self::Shr | Self::Ushr | Self::Rol | Self::Ror | Self::Popcnt |
            Self::Clz | Self::Ctz | Self::Eq | Self::Ne | Self::Lt | Self::Le |
            Self::Gt | Self::Ge | Self::StrictEq | Self::StrictNe | Self::IsNull |
            Self::IsUndef | Self::TypeOf | Self::InstanceOf | Self::Compare3Way |
            Self::And | Self::Or | Self::Not | Self::Xor | Self::Nand | Self::Nor |
            Self::Return | Self::ReturnNull | Self::Yield | Self::Await |
            Self::ArrayGet | Self::ArraySet | Self::ArrayLen | Self::ArrayPush |
            Self::ArrayPop | Self::ObjDelete | Self::ObjHas | Self::ObjKeys |
            Self::ObjValues | Self::ObjEntries | Self::StrConcat | Self::StrLen |
            Self::StrCharAt | Self::StrSubstr | Self::StrIndexOf | Self::StrReplace |
            Self::StrSplit | Self::StrUpper | Self::StrLower | Self::StrTrim |
            Self::StrStartsWith | Self::StrEndsWith | Self::StrMatch |
            Self::Rethrow | Self::Nop | Self::Halt => 0,
            
            Self::PushBool | Self::PushInt8 | Self::LoadLocal | Self::StoreLocal |
            Self::IncLocal | Self::DecLocal | Self::Call | Self::CallBuiltin |
            Self::MemLoad8 | Self::MemStore8 => 1,
            
            Self::PushInt16 | Self::PushString | Self::PushConst | Self::Jump |
            Self::JumpIfFalse | Self::JumpIfTrue | Self::JumpIfNull |
            Self::JumpIfNotNull | Self::JumpIfZero | Self::JumpIfNotZero |
            Self::Loop | Self::Break | Self::Continue | Self::NewArray |
            Self::NewArraySized | Self::NewObject | Self::ObjGet | Self::ObjSet |
            Self::Try | Self::Catch | Self::Finally | Self::Throw |
            Self::MemLoad16 | Self::MemStore16 => 2,
            
            Self::PushInt32 | Self::PushFloat32 | Self::MemLoad32 | Self::MemStore32 => 4,
            
            Self::PushInt64 | Self::PushFloat64 | Self::MemLoad64 | Self::MemStore64 => 8,
            
            // Variable-length operands
            Self::JumpTable | Self::ArraySlice | Self::Closure | Self::BindThis |
            Self::TailCall | Self::CallVirtual | Self::CallIndirect |
            Self::LoopEnd | Self::MemCopy | Self::MemFill | Self::MemSize |
            Self::MemGrow | Self::IoRead | Self::IoWrite | Self::IoFlush |
            Self::IoClose | Self::IoSeek | Self::IoTell | Self::NetConnect |
            Self::NetSend | Self::NetRecv | Self::NetClose => 0, // Variable
            
            // Bogus opcodes - random operand sizes for confusion
            Self::Bogus00 | Self::Bogus01 | Self::Bogus02 | Self::Bogus03 => 0,
            Self::Bogus04 | Self::Bogus05 | Self::Bogus06 | Self::Bogus07 => 1,
            Self::Bogus08 | Self::Bogus09 | Self::Bogus0A | Self::Bogus0B => 2,
            Self::Bogus0C | Self::Bogus0D | Self::Bogus0E | Self::Bogus0F => 3,
            Self::Bogus10 | Self::Bogus11 | Self::Bogus12 | Self::Bogus13 => 4,
            Self::Bogus14 | Self::Bogus15 | Self::Bogus16 | Self::Bogus17 => 0,
            Self::Bogus18 | Self::Bogus19 | Self::Bogus1A | Self::Bogus1B => 1,
            Self::Bogus1C | Self::Bogus1D => 2,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BytecodeHeader {
    pub magic: [u8; 8],
    pub version: u16,
    pub length: u32,
    pub checksum: [u8; 32],
    pub flags: u32,
    pub timestamp: u64,
    pub opcode_seed: [u8; 16],
}

pub struct OpcodeMapper {
    forward: HashMap<u8, u8>,
    reverse: HashMap<u8, u8>,
    seed: [u8; 16],
}

pub type OpcodeMapping = OpcodeMapper;

impl OpcodeMapper {
    pub fn new_random() -> Self {
        let mut seed = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut seed);
        Self::from_seed(seed)
    }
    
    pub fn from_seed(seed: [u8; 16]) -> Self {
        let mut rng = StdRng::from_seed({
            let mut full_seed = [0u8; 32];
            full_seed[..16].copy_from_slice(&seed);
            // Expand seed using SHA-256
            let hash = Sha256::digest(&seed);
            full_seed[16..].copy_from_slice(&hash[..16]);
            full_seed
        });
        
        // Generate permutation of 0-255
        let mut values: Vec<u8> = (0..=255).collect();
        for i in (1..256).rev() {
            let j = rng.gen_range(0..=i);
            values.swap(i, j);
        }
        
        let mut forward = HashMap::new();
        let mut reverse = HashMap::new();
        
        for (orig, &mapped) in values.iter().enumerate() {
            forward.insert(orig as u8, mapped);
            reverse.insert(mapped, orig as u8);
        }
        
        Self { forward, reverse, seed }
    }
    
    pub fn encode(&self, opcode: u8) -> u8 {
        *self.forward.get(&opcode).unwrap_or(&opcode)
    }
    
    pub fn decode(&self, encoded: u8) -> u8 {
        *self.reverse.get(&encoded).unwrap_or(&encoded)
    }
    
    pub fn seed(&self) -> &[u8; 16] {
        &self.seed
    }
}

pub mod variable_encoding {
    pub fn encode_varint(mut value: u64) -> Vec<u8> {
        let mut result = Vec::with_capacity(9);
        
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            
            if value != 0 {
                byte |= 0x80; // More bytes follow
            }
            
            result.push(byte);
            
            if value == 0 {
                break;
            }
        }
        
        result
    }
    
    pub fn decode_varint(data: &[u8]) -> Option<(u64, usize)> {
        let mut result = 0u64;
        let mut shift = 0;
        
        for (i, &byte) in data.iter().enumerate() {
            result |= ((byte & 0x7F) as u64) << shift;
            
            if byte & 0x80 == 0 {
                return Some((result, i + 1));
            }
            
            shift += 7;
            if shift > 63 {
                return None; // Overflow
            }
        }
        
        None // Incomplete
    }
    
    pub fn encode_signed(value: i64) -> Vec<u8> {
        let encoded = ((value << 1) ^ (value >> 63)) as u64;
        encode_varint(encoded)
    }
    
    pub fn decode_signed(data: &[u8]) -> Option<(i64, usize)> {
        let (encoded, len) = decode_varint(data)?;
        let value = ((encoded >> 1) as i64) ^ -((encoded & 1) as i64);
        Some((value, len))
    }
}

pub struct PaddingGenerator {
    rng: StdRng,
    min_padding: usize,
    max_padding: usize,
}

impl PaddingGenerator {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
            min_padding: 1,
            max_padding: 8,
        }
    }
    
    pub fn generate(&mut self) -> Vec<u8> {
        let len = self.rng.gen_range(self.min_padding..=self.max_padding);
        let mut padding = vec![0u8; len];
        self.rng.fill_bytes(&mut padding);
        padding
    }
    
    pub fn generate_with_entropy(&mut self, target_entropy: f64) -> Vec<u8> {
        let len = self.rng.gen_range(self.min_padding..=self.max_padding);
        let mut padding = vec![0u8; len];
        
        if target_entropy > 7.0 {
            // High entropy - all random
            self.rng.fill_bytes(&mut padding);
        } else if target_entropy > 4.0 {
            // Medium entropy - mix of patterns and random
            for byte in &mut padding {
                if self.rng.gen_bool(0.5) {
                    *byte = self.rng.gen();
                } else {
                    *byte = [0x00, 0xFF, 0xAA, 0x55][self.rng.gen_range(0..4)];
                }
            }
        } else {
            // Low entropy - repeated patterns
            let pattern = self.rng.gen::<u8>();
            for byte in &mut padding {
                *byte = pattern;
            }
        }
        
        padding
    }
}

impl BytecodeHeader {
    pub fn new(length: u32, flags: u32) -> Self {
        let mut magic = [0u8; 8];
        let mut opcode_seed = [0u8; 16];
        
        rand::thread_rng().fill_bytes(&mut magic);
        rand::thread_rng().fill_bytes(&mut opcode_seed);
        
        Self {
            magic,
            version: 0x0100, // v1.0
            length,
            checksum: [0u8; 32],
            flags,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() ^ 0xDEADBEEFCAFEBABE, // Obfuscated
            opcode_seed,
        }
    }
    
    pub fn compute_checksum(&mut self, bytecode: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(&self.magic);
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.length.to_le_bytes());
        hasher.update(&self.flags.to_le_bytes());
        hasher.update(bytecode);
        self.checksum = hasher.finalize().into();
    }
    
    pub fn verify_checksum(&self, bytecode: &[u8]) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(&self.magic);
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.length.to_le_bytes());
        hasher.update(&self.flags.to_le_bytes());
        hasher.update(bytecode);
        let computed: [u8; 32] = hasher.finalize().into();
        computed == self.checksum
    }
    
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(74);
        out.extend_from_slice(&self.magic);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.length.to_le_bytes());
        out.extend_from_slice(&self.checksum);
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.opcode_seed);
        out
    }
    
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 74 {
            return Err("Header too short".into());
        }
        
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&data[0..8]);
        
        let version = u16::from_le_bytes([data[8], data[9]]);
        let length = u32::from_le_bytes([data[10], data[11], data[12], data[13]]);
        
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&data[14..46]);
        
        let flags = u32::from_le_bytes([data[46], data[47], data[48], data[49]]);
        let timestamp = u64::from_le_bytes([
            data[50], data[51], data[52], data[53],
            data[54], data[55], data[56], data[57],
        ]);
        
        let mut opcode_seed = [0u8; 16];
        opcode_seed.copy_from_slice(&data[58..74]);
        
        Ok(Self {
            magic,
            version,
            length,
            checksum,
            flags,
            timestamp,
            opcode_seed,
        })
    }
}

pub mod flags {
    pub const DEBUG_ENABLED: u32 = 0x0001;
    pub const COMPRESSED: u32 = 0x0002;
    pub const ENCRYPTED: u32 = 0x0004;
    pub const LITTLE_ENDIAN: u32 = 0x0008;
    pub const HAS_SOURCE_MAP: u32 = 0x0010;
    pub const STRIPPED: u32 = 0x0020;
    pub const VIRTUALIZED: u32 = 0x0040;
    pub const OBFUSCATED: u32 = 0x0080;
}
