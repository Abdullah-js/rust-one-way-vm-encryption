
pub mod interpreter;
pub mod registers;
pub mod memory;
pub mod syscalls;

pub use interpreter::VmInterpreter;
pub use registers::RegisterFile;
pub use memory::VmMemory;
pub use syscalls::SyscallHandler;

#[derive(Debug, Clone)]
pub struct VmConfig {
    pub max_stack_depth: usize,
    pub max_memory: usize,
    pub max_steps: u64,
    pub debug_mode: bool,
    pub randomize_handlers: bool,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            max_stack_depth: 65536,
            max_memory: 16 * 1024 * 1024, // 16 MB
            max_steps: 0,
            debug_mode: false,
            randomize_handlers: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VmState {
    Ready,
    Running,
    Paused,
    Halted,
    Error,
}

#[derive(Debug)]
pub enum VmResult {
    Ok(VmValue),
    Halted,
    Error(String),
    Paused,
}

#[derive(Debug, Clone)]
pub enum VmValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Array(Vec<VmValue>),
    Object(std::collections::HashMap<String, VmValue>),
    Function(usize),
    Closure(Box<VmClosure>),
    External(Box<dyn std::any::Any + Send + Sync>),
}

impl VmValue {
    pub fn is_truthy(&self) -> bool {
        match self {
            VmValue::Null => false,
            VmValue::Bool(b) => *b,
            VmValue::Int(n) => *n != 0,
            VmValue::Float(f) => *f != 0.0 && !f.is_nan(),
            VmValue::String(s) => !s.is_empty(),
            VmValue::Array(arr) => !arr.is_empty(),
            VmValue::Object(_) => true,
            VmValue::Function(_) => true,
            VmValue::Closure(_) => true,
            VmValue::External(_) => true,
        }
    }
    
    pub fn type_name(&self) -> &'static str {
        match self {
            VmValue::Null => "null",
            VmValue::Bool(_) => "boolean",
            VmValue::Int(_) => "integer",
            VmValue::Float(_) => "float",
            VmValue::String(_) => "string",
            VmValue::Array(_) => "array",
            VmValue::Object(_) => "object",
            VmValue::Function(_) => "function",
            VmValue::Closure(_) => "closure",
            VmValue::External(_) => "external",
        }
    }
}

#[derive(Debug, Clone)]
pub struct VmClosure {
    pub function_index: usize,
    pub captured: Vec<VmValue>,
}

#[derive(Debug, Clone)]
pub struct CallFrame {
    pub function_index: usize,
    pub ip: usize,
    pub base_pointer: usize,
    pub return_address: usize,
    pub captured: Option<Vec<VmValue>>,
}

impl Clone for VmValue {
    fn clone(&self) -> Self {
        match self {
            VmValue::External(_) => panic!("Cannot clone External values"),
            VmValue::Null => VmValue::Null,
            VmValue::Bool(b) => VmValue::Bool(*b),
            VmValue::Int(n) => VmValue::Int(*n),
            VmValue::Float(f) => VmValue::Float(*f),
            VmValue::String(s) => VmValue::String(s.clone()),
            VmValue::Array(arr) => VmValue::Array(arr.clone()),
            VmValue::Object(obj) => VmValue::Object(obj.clone()),
            VmValue::Function(f) => VmValue::Function(*f),
            VmValue::Closure(c) => VmValue::Closure(c.clone()),
        }
    }
}
