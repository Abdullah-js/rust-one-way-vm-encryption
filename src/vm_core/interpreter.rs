
use super::{VmConfig, VmState, VmResult, VmValue, CallFrame, RegisterFile, VmMemory};
use crate::isa::{ExtendedOpcode, OpcodeMapper, BytecodeHeader};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use std::collections::HashMap;

type OpcodeHandler = fn(&mut VmInterpreter) -> Result<(), String>;

pub struct VmInterpreter {
    config: VmConfig,
    state: VmState,
    bytecode: Vec<u8>,
    ip: usize,
    stack: Vec<VmValue>,
    call_stack: Vec<CallFrame>,
    locals: Vec<Vec<VmValue>>,
    registers: RegisterFile,
    memory: VmMemory,
    opcode_mapper: OpcodeMapper,
    handlers: Vec<OpcodeHandler>,
    handler_offsets: Vec<usize>,
    constants: Vec<VmValue>,
    functions: Vec<BytecodeFunction>,
    steps: u64,
}

#[derive(Debug, Clone)]
pub struct BytecodeFunction {
    pub param_count: u8,
    pub local_count: u8,
    pub code_start: usize,
    pub code_end: usize,
}

impl VmInterpreter {
    pub fn new(config: VmConfig) -> Self {
        let randomize = config.randomize_handlers;
        
        let mut interpreter = Self {
            config,
            state: VmState::Ready,
            bytecode: Vec::new(),
            ip: 0,
            stack: Vec::new(),
            call_stack: Vec::new(),
            locals: vec![Vec::new()],
            registers: RegisterFile::new(),
            memory: VmMemory::new(16 * 1024 * 1024),
            opcode_mapper: OpcodeMapper::new_random(),
            handlers: Vec::new(),
            handler_offsets: Vec::new(),
            constants: Vec::new(),
            functions: Vec::new(),
            steps: 0,
        };
        
        interpreter.init_handlers(randomize);
        interpreter
    }
    
    fn init_handlers(&mut self, randomize: bool) {
        // Create handler table for all 256 possible opcodes
        self.handlers = vec![Self::handle_invalid as OpcodeHandler; 256];
        
        // Map actual handlers
        self.handlers[ExtendedOpcode::PushNull as usize] = Self::handle_push_null;
        self.handlers[ExtendedOpcode::PushBool as usize] = Self::handle_push_bool;
        self.handlers[ExtendedOpcode::PushInt8 as usize] = Self::handle_push_int8;
        self.handlers[ExtendedOpcode::PushInt16 as usize] = Self::handle_push_int16;
        self.handlers[ExtendedOpcode::PushInt32 as usize] = Self::handle_push_int32;
        self.handlers[ExtendedOpcode::PushInt64 as usize] = Self::handle_push_int64;
        self.handlers[ExtendedOpcode::PushFloat64 as usize] = Self::handle_push_float64;
        self.handlers[ExtendedOpcode::PushString as usize] = Self::handle_push_string;
        self.handlers[ExtendedOpcode::PushConst as usize] = Self::handle_push_const;
        self.handlers[ExtendedOpcode::Pop as usize] = Self::handle_pop;
        self.handlers[ExtendedOpcode::Dup as usize] = Self::handle_dup;
        self.handlers[ExtendedOpcode::Swap as usize] = Self::handle_swap;
        
        self.handlers[ExtendedOpcode::LoadLocal as usize] = Self::handle_load_local;
        self.handlers[ExtendedOpcode::StoreLocal as usize] = Self::handle_store_local;
        self.handlers[ExtendedOpcode::LoadLocal0 as usize] = Self::handle_load_local_0;
        self.handlers[ExtendedOpcode::LoadLocal1 as usize] = Self::handle_load_local_1;
        self.handlers[ExtendedOpcode::LoadLocal2 as usize] = Self::handle_load_local_2;
        self.handlers[ExtendedOpcode::LoadLocal3 as usize] = Self::handle_load_local_3;
        
        self.handlers[ExtendedOpcode::Add as usize] = Self::handle_add;
        self.handlers[ExtendedOpcode::Sub as usize] = Self::handle_sub;
        self.handlers[ExtendedOpcode::Mul as usize] = Self::handle_mul;
        self.handlers[ExtendedOpcode::Div as usize] = Self::handle_div;
        self.handlers[ExtendedOpcode::Mod as usize] = Self::handle_mod;
        self.handlers[ExtendedOpcode::Neg as usize] = Self::handle_neg;
        
        self.handlers[ExtendedOpcode::Eq as usize] = Self::handle_eq;
        self.handlers[ExtendedOpcode::Ne as usize] = Self::handle_ne;
        self.handlers[ExtendedOpcode::Lt as usize] = Self::handle_lt;
        self.handlers[ExtendedOpcode::Le as usize] = Self::handle_le;
        self.handlers[ExtendedOpcode::Gt as usize] = Self::handle_gt;
        self.handlers[ExtendedOpcode::Ge as usize] = Self::handle_ge;
        
        self.handlers[ExtendedOpcode::And as usize] = Self::handle_and;
        self.handlers[ExtendedOpcode::Or as usize] = Self::handle_or;
        self.handlers[ExtendedOpcode::Not as usize] = Self::handle_not;
        
        self.handlers[ExtendedOpcode::Jump as usize] = Self::handle_jump;
        self.handlers[ExtendedOpcode::JumpIfFalse as usize] = Self::handle_jump_if_false;
        self.handlers[ExtendedOpcode::JumpIfTrue as usize] = Self::handle_jump_if_true;
        
        self.handlers[ExtendedOpcode::Call as usize] = Self::handle_call;
        self.handlers[ExtendedOpcode::Return as usize] = Self::handle_return;
        self.handlers[ExtendedOpcode::CallBuiltin as usize] = Self::handle_call_builtin;
        
        self.handlers[ExtendedOpcode::NewArray as usize] = Self::handle_new_array;
        self.handlers[ExtendedOpcode::ArrayGet as usize] = Self::handle_array_get;
        self.handlers[ExtendedOpcode::ArraySet as usize] = Self::handle_array_set;
        self.handlers[ExtendedOpcode::ArrayLen as usize] = Self::handle_array_len;
        
        self.handlers[ExtendedOpcode::NewObject as usize] = Self::handle_new_object;
        self.handlers[ExtendedOpcode::ObjGet as usize] = Self::handle_obj_get;
        self.handlers[ExtendedOpcode::ObjSet as usize] = Self::handle_obj_set;
        
        self.handlers[ExtendedOpcode::Nop as usize] = Self::handle_nop;
        self.handlers[ExtendedOpcode::Halt as usize] = Self::handle_halt;
        
        // Bogus opcodes - do nothing
        for op in ExtendedOpcode::bogus_opcodes() {
            self.handlers[op as usize] = Self::handle_bogus;
        }
        
        // Generate handler offsets for address randomization
        if randomize {
            let mut rng = rand::thread_rng();
            self.handler_offsets = (0..256).map(|_| rng.gen::<usize>() % 1000).collect();
        } else {
            self.handler_offsets = vec![0; 256];
        }
    }
    
    pub fn load(&mut self, bytecode: &[u8]) -> Result<(), String> {
        if bytecode.len() < 74 {
            return Err("Bytecode too short".into());
        }
        
        // Parse header
        let header = BytecodeHeader::from_bytes(bytecode)?;
        
        // Verify checksum
        let body = &bytecode[74..];
        if !header.verify_checksum(body) {
            return Err("Checksum mismatch".into());
        }
        
        // Initialize opcode mapper from header seed
        self.opcode_mapper = OpcodeMapper::from_seed(header.opcode_seed);
        
        // Store bytecode body
        self.bytecode = body.to_vec();
        
        // Parse constants and functions (simplified)
        self.parse_module()?;
        
        self.state = VmState::Ready;
        Ok(())
    }
    
    fn parse_module(&mut self) -> Result<(), String> {
        // This would parse the full bytecode module
        // For now, simplified version
        self.functions.push(BytecodeFunction {
            param_count: 0,
            local_count: 0,
            code_start: 0,
            code_end: self.bytecode.len(),
        });
        
        self.locals = vec![vec![VmValue::Null; 256]];
        
        Ok(())
    }
    
    pub fn run(&mut self) -> VmResult {
        self.state = VmState::Running;
        self.ip = 0;
        
        loop {
            if self.state != VmState::Running {
                break;
            }
            
            // Check step limit
            if self.config.max_steps > 0 && self.steps >= self.config.max_steps {
                self.state = VmState::Error;
                return VmResult::Error("Execution limit exceeded".into());
            }
            
            // Fetch opcode
            if self.ip >= self.bytecode.len() {
                self.state = VmState::Halted;
                break;
            }
            
            let encoded_op = self.bytecode[self.ip];
            self.ip += 1;
            
            // Decode opcode using mapper
            let decoded_op = self.opcode_mapper.decode(encoded_op);
            
            // Indirect dispatch through handler table
            let handler = self.handlers[decoded_op as usize];
            
            if let Err(e) = handler(self) {
                self.state = VmState::Error;
                return VmResult::Error(e);
            }
            
            self.steps += 1;
        }
        
        match self.state {
            VmState::Halted => {
                if let Some(v) = self.stack.pop() {
                    VmResult::Ok(v)
                } else {
                    VmResult::Halted
                }
            }
            VmState::Error => VmResult::Error("Unknown error".into()),
            _ => VmResult::Halted,
        }
    }
    
    // ==================== OPCODE HANDLERS ====================
    
    fn handle_invalid(&mut self) -> Result<(), String> {
        Err("Invalid opcode".into())
    }
    
    fn handle_push_null(&mut self) -> Result<(), String> {
        self.stack.push(VmValue::Null);
        Ok(())
    }
    
    fn handle_push_bool(&mut self) -> Result<(), String> {
        let val = self.read_u8()?;
        self.stack.push(VmValue::Bool(val != 0));
        Ok(())
    }
    
    fn handle_push_int8(&mut self) -> Result<(), String> {
        let val = self.read_u8()? as i8 as i64;
        self.stack.push(VmValue::Int(val));
        Ok(())
    }
    
    fn handle_push_int16(&mut self) -> Result<(), String> {
        let val = self.read_u16()? as i16 as i64;
        self.stack.push(VmValue::Int(val));
        Ok(())
    }
    
    fn handle_push_int32(&mut self) -> Result<(), String> {
        let val = self.read_u32()? as i32 as i64;
        self.stack.push(VmValue::Int(val));
        Ok(())
    }
    
    fn handle_push_int64(&mut self) -> Result<(), String> {
        let val = self.read_u64()? as i64;
        self.stack.push(VmValue::Int(val));
        Ok(())
    }
    
    fn handle_push_float64(&mut self) -> Result<(), String> {
        let bits = self.read_u64()?;
        let val = f64::from_bits(bits);
        self.stack.push(VmValue::Float(val));
        Ok(())
    }
    
    fn handle_push_string(&mut self) -> Result<(), String> {
        let idx = self.read_u16()? as usize;
        if idx < self.constants.len() {
            self.stack.push(self.constants[idx].clone());
        } else {
            self.stack.push(VmValue::String(String::new()));
        }
        Ok(())
    }
    
    fn handle_push_const(&mut self) -> Result<(), String> {
        let idx = self.read_u16()? as usize;
        if idx < self.constants.len() {
            self.stack.push(self.constants[idx].clone());
        } else {
            self.stack.push(VmValue::Null);
        }
        Ok(())
    }
    
    fn handle_pop(&mut self) -> Result<(), String> {
        self.stack.pop();
        Ok(())
    }
    
    fn handle_dup(&mut self) -> Result<(), String> {
        if let Some(v) = self.stack.last() {
            self.stack.push(v.clone());
        }
        Ok(())
    }
    
    fn handle_swap(&mut self) -> Result<(), String> {
        let len = self.stack.len();
        if len >= 2 {
            self.stack.swap(len - 1, len - 2);
        }
        Ok(())
    }
    
    fn handle_load_local(&mut self) -> Result<(), String> {
        let idx = self.read_u8()? as usize;
        let frame = self.locals.last().ok_or("No frame")?;
        let val = frame.get(idx).cloned().unwrap_or(VmValue::Null);
        self.stack.push(val);
        Ok(())
    }
    
    fn handle_store_local(&mut self) -> Result<(), String> {
        let idx = self.read_u8()? as usize;
        let val = self.stack.pop().unwrap_or(VmValue::Null);
        if let Some(frame) = self.locals.last_mut() {
            while frame.len() <= idx {
                frame.push(VmValue::Null);
            }
            frame[idx] = val;
        }
        Ok(())
    }
    
    fn handle_load_local_0(&mut self) -> Result<(), String> {
        let frame = self.locals.last().ok_or("No frame")?;
        let val = frame.get(0).cloned().unwrap_or(VmValue::Null);
        self.stack.push(val);
        Ok(())
    }
    
    fn handle_load_local_1(&mut self) -> Result<(), String> {
        let frame = self.locals.last().ok_or("No frame")?;
        let val = frame.get(1).cloned().unwrap_or(VmValue::Null);
        self.stack.push(val);
        Ok(())
    }
    
    fn handle_load_local_2(&mut self) -> Result<(), String> {
        let frame = self.locals.last().ok_or("No frame")?;
        let val = frame.get(2).cloned().unwrap_or(VmValue::Null);
        self.stack.push(val);
        Ok(())
    }
    
    fn handle_load_local_3(&mut self) -> Result<(), String> {
        let frame = self.locals.last().ok_or("No frame")?;
        let val = frame.get(3).cloned().unwrap_or(VmValue::Null);
        self.stack.push(val);
        Ok(())
    }
    
    fn handle_add(&mut self) -> Result<(), String> {
        let b = self.stack.pop().unwrap_or(VmValue::Null);
        let a = self.stack.pop().unwrap_or(VmValue::Null);
        
        let result = match (a, b) {
            (VmValue::Int(x), VmValue::Int(y)) => VmValue::Int(x.wrapping_add(y)),
            (VmValue::Float(x), VmValue::Float(y)) => VmValue::Float(x + y),
            (VmValue::Int(x), VmValue::Float(y)) => VmValue::Float(x as f64 + y),
            (VmValue::Float(x), VmValue::Int(y)) => VmValue::Float(x + y as f64),
            (VmValue::String(x), VmValue::String(y)) => VmValue::String(x + &y),
            _ => VmValue::Null,
        };
        
        self.stack.push(result);
        Ok(())
    }
    
    fn handle_sub(&mut self) -> Result<(), String> {
        let b = self.stack.pop().unwrap_or(VmValue::Null);
        let a = self.stack.pop().unwrap_or(VmValue::Null);
        
        let result = match (a, b) {
            (VmValue::Int(x), VmValue::Int(y)) => VmValue::Int(x.wrapping_sub(y)),
            (VmValue::Float(x), VmValue::Float(y)) => VmValue::Float(x - y),
            (VmValue::Int(x), VmValue::Float(y)) => VmValue::Float(x as f64 - y),
            (VmValue::Float(x), VmValue::Int(y)) => VmValue::Float(x - y as f64),
            _ => VmValue::Null,
        };
        
        self.stack.push(result);
        Ok(())
    }
    
    fn handle_mul(&mut self) -> Result<(), String> {
        let b = self.stack.pop().unwrap_or(VmValue::Null);
        let a = self.stack.pop().unwrap_or(VmValue::Null);
        
        let result = match (a, b) {
            (VmValue::Int(x), VmValue::Int(y)) => VmValue::Int(x.wrapping_mul(y)),
            (VmValue::Float(x), VmValue::Float(y)) => VmValue::Float(x * y),
            (VmValue::Int(x), VmValue::Float(y)) => VmValue::Float(x as f64 * y),
            (VmValue::Float(x), VmValue::Int(y)) => VmValue::Float(x * y as f64),
            _ => VmValue::Null,
        };
        
        self.stack.push(result);
        Ok(())
    }
    
    fn handle_div(&mut self) -> Result<(), String> {
        let b = self.stack.pop().unwrap_or(VmValue::Null);
        let a = self.stack.pop().unwrap_or(VmValue::Null);
        
        let result = match (a, b) {
            (VmValue::Int(x), VmValue::Int(y)) if y != 0 => VmValue::Int(x / y),
            (VmValue::Float(x), VmValue::Float(y)) => VmValue::Float(x / y),
            (VmValue::Int(x), VmValue::Float(y)) => VmValue::Float(x as f64 / y),
            (VmValue::Float(x), VmValue::Int(y)) => VmValue::Float(x / y as f64),
            _ => VmValue::Null,
        };
        
        self.stack.push(result);
        Ok(())
    }
    
    fn handle_mod(&mut self) -> Result<(), String> {
        let b = self.stack.pop().unwrap_or(VmValue::Null);
        let a = self.stack.pop().unwrap_or(VmValue::Null);
        
        let result = match (a, b) {
            (VmValue::Int(x), VmValue::Int(y)) if y != 0 => VmValue::Int(x % y),
            (VmValue::Float(x), VmValue::Float(y)) => VmValue::Float(x % y),
            _ => VmValue::Null,
        };
        
        self.stack.push(result);
        Ok(())
    }
    
    fn handle_neg(&mut self) -> Result<(), String> {
        let a = self.stack.pop().unwrap_or(VmValue::Null);
        
        let result = match a {
            VmValue::Int(x) => VmValue::Int(-x),
            VmValue::Float(x) => VmValue::Float(-x),
            _ => VmValue::Null,
        };
        
        self.stack.push(result);
        Ok(())
    }
    
    fn handle_eq(&mut self) -> Result<(), String> {
        let b = self.stack.pop().unwrap_or(VmValue::Null);
        let a = self.stack.pop().unwrap_or(VmValue::Null);
        
        let result = match (&a, &b) {
            (VmValue::Null, VmValue::Null) => true,
            (VmValue::Bool(x), VmValue::Bool(y)) => x == y,
            (VmValue::Int(x), VmValue::Int(y)) => x == y,
            (VmValue::Float(x), VmValue::Float(y)) => x == y,
            (VmValue::String(x), VmValue::String(y)) => x == y,
            _ => false,
        };
        
        self.stack.push(VmValue::Bool(result));
        Ok(())
    }
    
    fn handle_ne(&mut self) -> Result<(), String> {
        self.handle_eq()?;
        self.handle_not()
    }
    
    fn handle_lt(&mut self) -> Result<(), String> {
        let b = self.stack.pop().unwrap_or(VmValue::Null);
        let a = self.stack.pop().unwrap_or(VmValue::Null);
        
        let result = match (a, b) {
            (VmValue::Int(x), VmValue::Int(y)) => x < y,
            (VmValue::Float(x), VmValue::Float(y)) => x < y,
            _ => false,
        };
        
        self.stack.push(VmValue::Bool(result));
        Ok(())
    }
    
    fn handle_le(&mut self) -> Result<(), String> {
        let b = self.stack.pop().unwrap_or(VmValue::Null);
        let a = self.stack.pop().unwrap_or(VmValue::Null);
        
        let result = match (a, b) {
            (VmValue::Int(x), VmValue::Int(y)) => x <= y,
            (VmValue::Float(x), VmValue::Float(y)) => x <= y,
            _ => false,
        };
        
        self.stack.push(VmValue::Bool(result));
        Ok(())
    }
    
    fn handle_gt(&mut self) -> Result<(), String> {
        let b = self.stack.pop().unwrap_or(VmValue::Null);
        let a = self.stack.pop().unwrap_or(VmValue::Null);
        
        let result = match (a, b) {
            (VmValue::Int(x), VmValue::Int(y)) => x > y,
            (VmValue::Float(x), VmValue::Float(y)) => x > y,
            _ => false,
        };
        
        self.stack.push(VmValue::Bool(result));
        Ok(())
    }
    
    fn handle_ge(&mut self) -> Result<(), String> {
        let b = self.stack.pop().unwrap_or(VmValue::Null);
        let a = self.stack.pop().unwrap_or(VmValue::Null);
        
        let result = match (a, b) {
            (VmValue::Int(x), VmValue::Int(y)) => x >= y,
            (VmValue::Float(x), VmValue::Float(y)) => x >= y,
            _ => false,
        };
        
        self.stack.push(VmValue::Bool(result));
        Ok(())
    }
    
    fn handle_and(&mut self) -> Result<(), String> {
        let b = self.stack.pop().unwrap_or(VmValue::Null);
        let a = self.stack.pop().unwrap_or(VmValue::Null);
        self.stack.push(VmValue::Bool(a.is_truthy() && b.is_truthy()));
        Ok(())
    }
    
    fn handle_or(&mut self) -> Result<(), String> {
        let b = self.stack.pop().unwrap_or(VmValue::Null);
        let a = self.stack.pop().unwrap_or(VmValue::Null);
        self.stack.push(VmValue::Bool(a.is_truthy() || b.is_truthy()));
        Ok(())
    }
    
    fn handle_not(&mut self) -> Result<(), String> {
        let a = self.stack.pop().unwrap_or(VmValue::Null);
        self.stack.push(VmValue::Bool(!a.is_truthy()));
        Ok(())
    }
    
    fn handle_jump(&mut self) -> Result<(), String> {
        let target = self.read_u16()? as usize;
        self.ip = target;
        Ok(())
    }
    
    fn handle_jump_if_false(&mut self) -> Result<(), String> {
        let target = self.read_u16()? as usize;
        let cond = self.stack.pop().unwrap_or(VmValue::Null);
        if !cond.is_truthy() {
            self.ip = target;
        }
        Ok(())
    }
    
    fn handle_jump_if_true(&mut self) -> Result<(), String> {
        let target = self.read_u16()? as usize;
        let cond = self.stack.pop().unwrap_or(VmValue::Null);
        if cond.is_truthy() {
            self.ip = target;
        }
        Ok(())
    }
    
    fn handle_call(&mut self) -> Result<(), String> {
        let arg_count = self.read_u8()? as usize;
        
        // Pop arguments
        let mut args = Vec::with_capacity(arg_count);
        for _ in 0..arg_count {
            args.push(self.stack.pop().unwrap_or(VmValue::Null));
        }
        args.reverse();
        
        // Pop function
        let func = self.stack.pop().unwrap_or(VmValue::Null);
        
        match func {
            VmValue::Function(idx) if idx < self.functions.len() => {
                // Save current frame
                self.call_stack.push(CallFrame {
                    function_index: 0,
                    ip: self.ip,
                    base_pointer: self.locals.len() - 1,
                    return_address: self.ip,
                    captured: None,
                });
                
                // Create new locals frame
                let mut new_locals = vec![VmValue::Null; 256];
                for (i, arg) in args.into_iter().enumerate() {
                    new_locals[i] = arg;
                }
                self.locals.push(new_locals);
                
                // Jump to function
                self.ip = self.functions[idx].code_start;
            }
            _ => {
                self.stack.push(VmValue::Null);
            }
        }
        
        Ok(())
    }
    
    fn handle_return(&mut self) -> Result<(), String> {
        let return_value = self.stack.pop().unwrap_or(VmValue::Null);
        
        if let Some(frame) = self.call_stack.pop() {
            self.ip = frame.return_address;
            self.locals.pop();
            self.stack.push(return_value);
        } else {
            self.state = VmState::Halted;
            self.stack.push(return_value);
        }
        
        Ok(())
    }
    
    fn handle_call_builtin(&mut self) -> Result<(), String> {
        let builtin_idx = self.read_u8()? as usize;
        // Builtin handling would be implemented here
        self.stack.push(VmValue::Null);
        Ok(())
    }
    
    fn handle_new_array(&mut self) -> Result<(), String> {
        let count = self.read_u16()? as usize;
        let mut arr = Vec::with_capacity(count);
        for _ in 0..count {
            arr.push(self.stack.pop().unwrap_or(VmValue::Null));
        }
        arr.reverse();
        self.stack.push(VmValue::Array(arr));
        Ok(())
    }
    
    fn handle_array_get(&mut self) -> Result<(), String> {
        let idx = self.stack.pop().unwrap_or(VmValue::Null);
        let arr = self.stack.pop().unwrap_or(VmValue::Null);
        
        let result = match (arr, idx) {
            (VmValue::Array(a), VmValue::Int(i)) if (i as usize) < a.len() => {
                a[i as usize].clone()
            }
            _ => VmValue::Null,
        };
        
        self.stack.push(result);
        Ok(())
    }
    
    fn handle_array_set(&mut self) -> Result<(), String> {
        let val = self.stack.pop().unwrap_or(VmValue::Null);
        let idx = self.stack.pop().unwrap_or(VmValue::Null);
        let arr = self.stack.pop().unwrap_or(VmValue::Null);
        
        let result = match (arr, idx) {
            (VmValue::Array(mut a), VmValue::Int(i)) if (i as usize) < a.len() => {
                a[i as usize] = val;
                VmValue::Array(a)
            }
            _ => VmValue::Null,
        };
        
        self.stack.push(result);
        Ok(())
    }
    
    fn handle_array_len(&mut self) -> Result<(), String> {
        let arr = self.stack.pop().unwrap_or(VmValue::Null);
        
        let len = match arr {
            VmValue::Array(a) => a.len() as i64,
            VmValue::String(s) => s.len() as i64,
            _ => 0,
        };
        
        self.stack.push(VmValue::Int(len));
        Ok(())
    }
    
    fn handle_new_object(&mut self) -> Result<(), String> {
        let count = self.read_u16()? as usize;
        let mut obj = HashMap::new();
        
        for _ in 0..count {
            let val = self.stack.pop().unwrap_or(VmValue::Null);
            let key = self.stack.pop().unwrap_or(VmValue::Null);
            
            if let VmValue::String(k) = key {
                obj.insert(k, val);
            }
        }
        
        self.stack.push(VmValue::Object(obj));
        Ok(())
    }
    
    fn handle_obj_get(&mut self) -> Result<(), String> {
        let key_idx = self.read_u16()? as usize;
        let obj = self.stack.pop().unwrap_or(VmValue::Null);
        
        let result = match obj {
            VmValue::Object(o) => {
                if key_idx < self.constants.len() {
                    if let VmValue::String(k) = &self.constants[key_idx] {
                        o.get(k).cloned().unwrap_or(VmValue::Null)
                    } else {
                        VmValue::Null
                    }
                } else {
                    VmValue::Null
                }
            }
            _ => VmValue::Null,
        };
        
        self.stack.push(result);
        Ok(())
    }
    
    fn handle_obj_set(&mut self) -> Result<(), String> {
        let val = self.stack.pop().unwrap_or(VmValue::Null);
        let key = self.stack.pop().unwrap_or(VmValue::Null);
        let obj = self.stack.pop().unwrap_or(VmValue::Null);
        
        let result = match (obj, key) {
            (VmValue::Object(mut o), VmValue::String(k)) => {
                o.insert(k, val);
                VmValue::Object(o)
            }
            _ => VmValue::Null,
        };
        
        self.stack.push(result);
        Ok(())
    }
    
    fn handle_nop(&mut self) -> Result<(), String> {
        Ok(())
    }
    
    fn handle_halt(&mut self) -> Result<(), String> {
        self.state = VmState::Halted;
        Ok(())
    }
    
    fn handle_bogus(&mut self) -> Result<(), String> {
        // Bogus opcodes do nothing but may consume operands
        // to confuse analysis
        Ok(())
    }
    
    // ==================== HELPER METHODS ====================
    
    fn read_u8(&mut self) -> Result<u8, String> {
        if self.ip >= self.bytecode.len() {
            return Err("Unexpected end of bytecode".into());
        }
        let val = self.bytecode[self.ip];
        self.ip += 1;
        Ok(val)
    }
    
    fn read_u16(&mut self) -> Result<u16, String> {
        if self.ip + 1 >= self.bytecode.len() {
            return Err("Unexpected end of bytecode".into());
        }
        let val = u16::from_le_bytes([self.bytecode[self.ip], self.bytecode[self.ip + 1]]);
        self.ip += 2;
        Ok(val)
    }
    
    fn read_u32(&mut self) -> Result<u32, String> {
        if self.ip + 3 >= self.bytecode.len() {
            return Err("Unexpected end of bytecode".into());
        }
        let val = u32::from_le_bytes([
            self.bytecode[self.ip],
            self.bytecode[self.ip + 1],
            self.bytecode[self.ip + 2],
            self.bytecode[self.ip + 3],
        ]);
        self.ip += 4;
        Ok(val)
    }
    
    fn read_u64(&mut self) -> Result<u64, String> {
        if self.ip + 7 >= self.bytecode.len() {
            return Err("Unexpected end of bytecode".into());
        }
        let val = u64::from_le_bytes([
            self.bytecode[self.ip],
            self.bytecode[self.ip + 1],
            self.bytecode[self.ip + 2],
            self.bytecode[self.ip + 3],
            self.bytecode[self.ip + 4],
            self.bytecode[self.ip + 5],
            self.bytecode[self.ip + 6],
            self.bytecode[self.ip + 7],
        ]);
        self.ip += 8;
        Ok(val)
    }
    
    pub fn zeroize(&mut self) {
        // Clear bytecode
        for byte in &mut self.bytecode {
            *byte = 0;
        }
        
        // Clear stack
        self.stack.clear();
        
        // Clear locals
        for frame in &mut self.locals {
            frame.clear();
        }
        
        // Clear constants
        self.constants.clear();
    }
}
