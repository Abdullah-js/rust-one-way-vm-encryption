
use std::collections::HashMap;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

pub struct SymbolStripper {
    symbol_map: HashMap<String, String>,
    counter: usize,
    rng: StdRng,
}

impl SymbolStripper {
    pub fn new() -> Self {
        Self {
            symbol_map: HashMap::new(),
            counter: 0,
            rng: StdRng::from_entropy(),
        }
    }
    
    pub fn with_seed(seed: u64) -> Self {
        Self {
            symbol_map: HashMap::new(),
            counter: 0,
            rng: StdRng::seed_from_u64(seed),
        }
    }
    
    pub fn strip(&mut self, code: &str) -> String {
        let mut result = code.to_string();
        
        // Strip function names
        result = self.strip_function_names(&result);
        
        // Strip variable names
        result = self.strip_variable_names(&result);
        
        // Strip strings
        result = self.obfuscate_strings(&result);
        
        // Strip comments
        result = self.strip_comments(&result);
        
        // Strip whitespace
        result = self.minimize_whitespace(&result);
        
        result
    }
    
    fn strip_function_names(&mut self, code: &str) -> String {
        let mut result = code.to_string();
        
        // Pattern for function declarations
        let patterns = [
            ("function ", "("),
            ("def ", "("),
            ("fn ", "("),
        ];
        
        for (prefix, suffix) in patterns {
            let mut new_result = String::new();
            let mut remaining = result.as_str();
            
            while let Some(start) = remaining.find(prefix) {
                new_result.push_str(&remaining[..start + prefix.len()]);
                remaining = &remaining[start + prefix.len()..];
                
                if let Some(end) = remaining.find(suffix) {
                    let name = &remaining[..end];
                    if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                        let obfuscated = self.get_or_create_symbol(name);
                        new_result.push_str(&obfuscated);
                    } else {
                        new_result.push_str(name);
                    }
                    remaining = &remaining[end..];
                }
            }
            new_result.push_str(remaining);
            result = new_result;
        }
        
        result
    }
    
    fn strip_variable_names(&mut self, code: &str) -> String {
        let mut result = code.to_string();
        
        // Common variable declaration patterns
        let patterns = [
            "let ", "const ", "var ", "local ",
        ];
        
        for prefix in patterns {
            let mut new_result = String::new();
            let mut remaining = result.as_str();
            
            while let Some(start) = remaining.find(prefix) {
                new_result.push_str(&remaining[..start + prefix.len()]);
                remaining = &remaining[start + prefix.len()..];
                
                // Find end of identifier
                let end = remaining.find(|c: char| !c.is_alphanumeric() && c != '_')
                    .unwrap_or(remaining.len());
                
                let name = &remaining[..end];
                if !name.is_empty() {
                    let obfuscated = self.get_or_create_symbol(name);
                    new_result.push_str(&obfuscated);
                }
                remaining = &remaining[end..];
            }
            new_result.push_str(remaining);
            result = new_result;
        }
        
        result
    }
    
    fn obfuscate_strings(&mut self, code: &str) -> String {
        let mut result = String::new();
        let mut chars = code.chars().peekable();
        let mut in_string = false;
        let mut string_char = '"';
        let mut current_string = String::new();
        
        while let Some(c) = chars.next() {
            if !in_string {
                if c == '"' || c == '\'' {
                    in_string = true;
                    string_char = c;
                    current_string.clear();
                } else {
                    result.push(c);
                }
            } else {
                if c == '\\' {
                    // Handle escape
                    if let Some(&next) = chars.peek() {
                        current_string.push(c);
                        current_string.push(next);
                        chars.next();
                    }
                } else if c == string_char {
                    // End of string
                    let obfuscated = self.encode_string(&current_string);
                    result.push_str(&obfuscated);
                    in_string = false;
                } else {
                    current_string.push(c);
                }
            }
        }
        
        result
    }
    
    fn encode_string(&self, s: &str) -> String {
        // Convert string to hex encoding
        let bytes: Vec<String> = s.bytes().map(|b| format!("\\x{:02x}", b)).collect();
        format!("\"{}\"", bytes.join(""))
    }
    
    fn strip_comments(&self, code: &str) -> String {
        let mut result = String::new();
        let mut chars = code.chars().peekable();
        let mut in_line_comment = false;
        let mut in_block_comment = false;
        
        while let Some(c) = chars.next() {
            if in_line_comment {
                if c == '\n' {
                    in_line_comment = false;
                    result.push('\n');
                }
            } else if in_block_comment {
                if c == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    in_block_comment = false;
                }
            } else if c == '/' {
                match chars.peek() {
                    Some(&'/') => {
                        chars.next();
                        in_line_comment = true;
                    }
                    Some(&'*') => {
                        chars.next();
                        in_block_comment = true;
                    }
                    _ => result.push(c),
                }
            } else if c == '#' {
                // Python/Ruby comments
                in_line_comment = true;
            } else {
                result.push(c);
            }
        }
        
        result
    }
    
    fn minimize_whitespace(&self, code: &str) -> String {
        let mut result = String::new();
        let mut last_was_space = false;
        let mut last_was_newline = false;
        
        for c in code.chars() {
            if c == '\n' {
                if !last_was_newline {
                    result.push('\n');
                    last_was_newline = true;
                }
                last_was_space = false;
            } else if c.is_whitespace() {
                if !last_was_space && !last_was_newline {
                    result.push(' ');
                    last_was_space = true;
                }
            } else {
                result.push(c);
                last_was_space = false;
                last_was_newline = false;
            }
        }
        
        result
    }
    
    fn get_or_create_symbol(&mut self, name: &str) -> String {
        if let Some(existing) = self.symbol_map.get(name) {
            return existing.clone();
        }
        
        let obfuscated = self.generate_symbol();
        self.symbol_map.insert(name.to_string(), obfuscated.clone());
        obfuscated
    }
    
    fn generate_symbol(&mut self) -> String {
        let charset = b"_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        
        // Start with underscore or letter
        let first = charset[self.rng.gen_range(0..charset.len())] as char;
        
        // Generate random suffix
        let suffix_len = self.rng.gen_range(4..8);
        let suffix: String = (0..suffix_len)
            .map(|_| {
                let idx = self.rng.gen_range(0..charset.len());
                charset[idx] as char
            })
            .collect();
        
        self.counter += 1;
        format!("{}{}{:x}", first, suffix, self.counter)
    }
    
    pub fn symbol_map(&self) -> &HashMap<String, String> {
        &self.symbol_map
    }
}

impl Default for SymbolStripper {
    fn default() -> Self {
        Self::new()
    }
}
