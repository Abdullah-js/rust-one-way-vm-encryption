
use super::VmValue;
use std::io::{Read, Write};

pub struct SyscallHandler {
    stdout_buffer: Vec<u8>,
    stderr_buffer: Vec<u8>,
    mock_mode: bool,
}

impl SyscallHandler {
    pub fn new() -> Self {
        Self {
            stdout_buffer: Vec::new(),
            stderr_buffer: Vec::new(),
            mock_mode: false,
        }
    }
    
    pub fn with_mock_mode() -> Self {
        Self {
            stdout_buffer: Vec::new(),
            stderr_buffer: Vec::new(),
            mock_mode: true,
        }
    }
    
    pub fn sys_print(&mut self, args: &[VmValue]) -> VmValue {
        let output: Vec<String> = args.iter().map(|v| self.value_to_string(v)).collect();
        let line = output.join(" ");
        
        if self.mock_mode {
            self.stdout_buffer.extend_from_slice(line.as_bytes());
            self.stdout_buffer.push(b'\n');
        } else {
            println!("{}", line);
        }
        
        VmValue::Null
    }
    
    pub fn sys_console_log(&mut self, args: &[VmValue]) -> VmValue {
        self.sys_print(args)
    }
    
    pub fn sys_console_error(&mut self, args: &[VmValue]) -> VmValue {
        let output: Vec<String> = args.iter().map(|v| self.value_to_string(v)).collect();
        let line = output.join(" ");
        
        if self.mock_mode {
            self.stderr_buffer.extend_from_slice(line.as_bytes());
            self.stderr_buffer.push(b'\n');
        } else {
            eprintln!("{}", line);
        }
        
        VmValue::Null
    }
    
    pub fn sys_read_line(&mut self) -> VmValue {
        if self.mock_mode {
            return VmValue::String(String::new());
        }
        
        let mut line = String::new();
        match std::io::stdin().read_line(&mut line) {
            Ok(_) => VmValue::String(line.trim_end().to_string()),
            Err(_) => VmValue::Null,
        }
    }
    
    pub fn sys_random(&self) -> VmValue {
        use rand::Rng;
        VmValue::Float(rand::thread_rng().gen::<f64>())
    }
    
    pub fn sys_time_now(&self) -> VmValue {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        VmValue::Int(now)
    }
    
    pub fn sys_typeof(&self, value: &VmValue) -> VmValue {
        VmValue::String(value.type_name().to_string())
    }
    
    pub fn sys_json_stringify(&self, value: &VmValue) -> VmValue {
        VmValue::String(self.value_to_json(value))
    }
    
    pub fn sys_json_parse(&self, json: &str) -> VmValue {
        // Simplified JSON parsing
        let trimmed = json.trim();
        
        if trimmed == "null" {
            return VmValue::Null;
        }
        if trimmed == "true" {
            return VmValue::Bool(true);
        }
        if trimmed == "false" {
            return VmValue::Bool(false);
        }
        if let Ok(n) = trimmed.parse::<i64>() {
            return VmValue::Int(n);
        }
        if let Ok(f) = trimmed.parse::<f64>() {
            return VmValue::Float(f);
        }
        if trimmed.starts_with('"') && trimmed.ends_with('"') {
            return VmValue::String(trimmed[1..trimmed.len()-1].to_string());
        }
        
        VmValue::Null
    }
    
    pub fn sys_parse_int(&self, s: &str, radix: Option<u32>) -> VmValue {
        let radix = radix.unwrap_or(10);
        match i64::from_str_radix(s.trim(), radix) {
            Ok(n) => VmValue::Int(n),
            Err(_) => VmValue::Null,
        }
    }
    
    pub fn sys_parse_float(&self, s: &str) -> VmValue {
        match s.trim().parse::<f64>() {
            Ok(f) => VmValue::Float(f),
            Err(_) => VmValue::Null,
        }
    }
    
    pub fn sys_is_nan(&self, value: &VmValue) -> VmValue {
        match value {
            VmValue::Float(f) => VmValue::Bool(f.is_nan()),
            _ => VmValue::Bool(false),
        }
    }
    
    pub fn get_stdout(&self) -> &[u8] {
        &self.stdout_buffer
    }
    
    pub fn get_stderr(&self) -> &[u8] {
        &self.stderr_buffer
    }
    
    pub fn clear_buffers(&mut self) {
        self.stdout_buffer.clear();
        self.stderr_buffer.clear();
    }
    
    // Helper functions
    
    fn value_to_string(&self, value: &VmValue) -> String {
        match value {
            VmValue::Null => "null".to_string(),
            VmValue::Bool(b) => b.to_string(),
            VmValue::Int(n) => n.to_string(),
            VmValue::Float(f) => {
                if f.fract() == 0.0 {
                    format!("{:.0}", f)
                } else {
                    f.to_string()
                }
            }
            VmValue::String(s) => s.clone(),
            VmValue::Array(arr) => {
                let items: Vec<String> = arr.iter().map(|v| self.value_to_string(v)).collect();
                format!("[{}]", items.join(", "))
            }
            VmValue::Object(obj) => {
                let items: Vec<String> = obj.iter()
                    .map(|(k, v)| format!("{}: {}", k, self.value_to_string(v)))
                    .collect();
                format!("{{{}}}", items.join(", "))
            }
            VmValue::Function(idx) => format!("[Function: {}]", idx),
            VmValue::Closure(_) => "[Closure]".to_string(),
            VmValue::External(_) => "[External]".to_string(),
        }
    }
    
    fn value_to_json(&self, value: &VmValue) -> String {
        match value {
            VmValue::Null => "null".to_string(),
            VmValue::Bool(b) => b.to_string(),
            VmValue::Int(n) => n.to_string(),
            VmValue::Float(f) => f.to_string(),
            VmValue::String(s) => format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")),
            VmValue::Array(arr) => {
                let items: Vec<String> = arr.iter().map(|v| self.value_to_json(v)).collect();
                format!("[{}]", items.join(","))
            }
            VmValue::Object(obj) => {
                let items: Vec<String> = obj.iter()
                    .map(|(k, v)| format!("\"{}\":{}", k, self.value_to_json(v)))
                    .collect();
                format!("{{{}}}", items.join(","))
            }
            _ => "null".to_string(),
        }
    }
}

impl Default for SyscallHandler {
    fn default() -> Self {
        Self::new()
    }
}
