
use crate::bytecode::{BytecodeModule, BytecodeFunction, Constant, Opcode};
use crate::languages::Language;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct CompileError {
    pub message: String,
    pub line: Option<usize>,
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(line) = self.line {
            write!(f, "Line {}: {}", line, self.message)
        } else {
            write!(f, "{}", self.message)
        }
    }
}

impl std::error::Error for CompileError {}

impl From<String> for CompileError {
    fn from(message: String) -> Self {
        Self { message, line: None }
    }
}

impl From<&str> for CompileError {
    fn from(message: &str) -> Self {
        Self { message: message.to_string(), line: None }
    }
}

#[derive(Debug, Clone)]
pub struct CompiledBytecode {
    pub module: BytecodeModule,
}

impl CompiledBytecode {
    pub fn serialize(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.module.to_bytes());
    }
}

pub struct LanguageCompiler;

impl LanguageCompiler {
    pub fn compile_js(source: &str) -> Result<CompiledBytecode, CompileError> {
        let compiler = Compiler::new(Language::JavaScript);
        let module = compiler.compile(source).map_err(CompileError::from)?;
        Ok(CompiledBytecode { module })
    }
    
    pub fn compile_python(source: &str) -> Result<CompiledBytecode, CompileError> {
        let compiler = Compiler::new(Language::Python);
        let module = compiler.compile(source).map_err(CompileError::from)?;
        Ok(CompiledBytecode { module })
    }
    
    pub fn compile_ruby(source: &str) -> Result<CompiledBytecode, CompileError> {
        let compiler = Compiler::new(Language::Ruby);
        let module = compiler.compile(source).map_err(CompileError::from)?;
        Ok(CompiledBytecode { module })
    }
    
    pub fn compile_lua(source: &str) -> Result<CompiledBytecode, CompileError> {
        let compiler = Compiler::new(Language::Lua);
        let module = compiler.compile(source).map_err(CompileError::from)?;
        Ok(CompiledBytecode { module })
    }
    
    pub fn compile_php(source: &str) -> Result<CompiledBytecode, CompileError> {
        let compiler = Compiler::new(Language::PHP);
        let module = compiler.compile(source).map_err(CompileError::from)?;
        Ok(CompiledBytecode { module })
    }
}

pub struct Compiler {
    language: Language,
    module: BytecodeModule,
    current_code: Vec<u8>,
    locals: HashMap<String, u8>,
    local_count: u8,
    labels: HashMap<String, usize>,
    pending_jumps: Vec<(usize, String)>,
}

impl Compiler {
    pub fn new(language: Language) -> Self {
        Self {
            language,
            module: BytecodeModule::new(),
            current_code: Vec::new(),
            locals: HashMap::new(),
            local_count: 0,
            labels: HashMap::new(),
            pending_jumps: Vec::new(),
        }
    }
    
    pub fn compile(mut self, source: &str) -> Result<BytecodeModule, String> {
        match self.language {
            Language::JavaScript | Language::TypeScript => self.compile_js(source)?,
            Language::Python => self.compile_python(source)?,
            Language::Ruby => self.compile_ruby(source)?,
            Language::Lua => self.compile_lua(source)?,
            Language::PHP => self.compile_php(source)?,
            Language::Shell => return Err("Shell scripts cannot be virtualized".into()),
        }
        
        Ok(self.module)
    }
    
    // ==================== JavaScript Compiler ====================
    
    fn compile_js(&mut self, source: &str) -> Result<(), String> {
        // Simple JS parser - handles common patterns
        let tokens = self.tokenize_js(source);
        self.parse_js_program(&tokens)?;
        
        // Finalize main function
        self.emit(Opcode::Halt);
        self.finalize_function(0, 0);
        
        Ok(())
    }
    
    fn tokenize_js(&self, source: &str) -> Vec<JsToken> {
        let mut tokens = Vec::new();
        let chars: Vec<char> = source.chars().collect();
        let mut i = 0;
        
        while i < chars.len() {
            let c = chars[i];
            
            // Skip whitespace
            if c.is_whitespace() {
                i += 1;
                continue;
            }
            
            // Skip comments
            if c == '/' && i + 1 < chars.len() {
                if chars[i + 1] == '/' {
                    // Line comment
                    while i < chars.len() && chars[i] != '\n' {
                        i += 1;
                    }
                    continue;
                } else if chars[i + 1] == '*' {
                    // Block comment
                    i += 2;
                    while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                        i += 1;
                    }
                    i += 2;
                    continue;
                }
            }
            
            // String literals
            if c == '"' || c == '\'' || c == '`' {
                let quote = c;
                let mut s = String::new();
                i += 1;
                while i < chars.len() && chars[i] != quote {
                    if chars[i] == '\\' && i + 1 < chars.len() {
                        i += 1;
                        s.push(match chars[i] {
                            'n' => '\n',
                            't' => '\t',
                            'r' => '\r',
                            '\\' => '\\',
                            '"' => '"',
                            '\'' => '\'',
                            _ => chars[i],
                        });
                    } else {
                        s.push(chars[i]);
                    }
                    i += 1;
                }
                i += 1; // Skip closing quote
                tokens.push(JsToken::String(s));
                continue;
            }
            
            // Numbers
            if c.is_ascii_digit() || (c == '.' && i + 1 < chars.len() && chars[i + 1].is_ascii_digit()) {
                let mut num = String::new();
                let mut has_dot = false;
                while i < chars.len() && (chars[i].is_ascii_digit() || (chars[i] == '.' && !has_dot)) {
                    if chars[i] == '.' {
                        has_dot = true;
                    }
                    num.push(chars[i]);
                    i += 1;
                }
                if has_dot {
                    tokens.push(JsToken::Float(num.parse().unwrap_or(0.0)));
                } else {
                    tokens.push(JsToken::Int(num.parse().unwrap_or(0)));
                }
                continue;
            }
            
            // Identifiers and keywords
            if c.is_alphabetic() || c == '_' || c == '$' {
                let mut ident = String::new();
                while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '$') {
                    ident.push(chars[i]);
                    i += 1;
                }
                tokens.push(match ident.as_str() {
                    "function" => JsToken::Function,
                    "var" | "let" | "const" => JsToken::Var,
                    "if" => JsToken::If,
                    "else" => JsToken::Else,
                    "while" => JsToken::While,
                    "for" => JsToken::For,
                    "return" => JsToken::Return,
                    "true" => JsToken::True,
                    "false" => JsToken::False,
                    "null" | "undefined" => JsToken::Null,
                    "new" => JsToken::New,
                    "this" => JsToken::This,
                    "class" => JsToken::Class,
                    "async" => JsToken::Async,
                    "await" => JsToken::Await,
                    "export" => JsToken::Export,
                    "import" => JsToken::Import,
                    "require" => JsToken::Require,
                    "module" => JsToken::Module,
                    _ => JsToken::Ident(ident),
                });
                continue;
            }
            
            // Operators and punctuation
            let tok = match c {
                '(' => JsToken::LParen,
                ')' => JsToken::RParen,
                '{' => JsToken::LBrace,
                '}' => JsToken::RBrace,
                '[' => JsToken::LBracket,
                ']' => JsToken::RBracket,
                ';' => JsToken::Semi,
                ',' => JsToken::Comma,
                '.' => JsToken::Dot,
                ':' => JsToken::Colon,
                '+' => {
                    if i + 1 < chars.len() && chars[i + 1] == '+' {
                        i += 1;
                        JsToken::PlusPlus
                    } else if i + 1 < chars.len() && chars[i + 1] == '=' {
                        i += 1;
                        JsToken::PlusEq
                    } else {
                        JsToken::Plus
                    }
                }
                '-' => {
                    if i + 1 < chars.len() && chars[i + 1] == '-' {
                        i += 1;
                        JsToken::MinusMinus
                    } else if i + 1 < chars.len() && chars[i + 1] == '=' {
                        i += 1;
                        JsToken::MinusEq
                    } else {
                        JsToken::Minus
                    }
                }
                '*' => JsToken::Star,
                '/' => JsToken::Slash,
                '%' => JsToken::Percent,
                '=' => {
                    if i + 1 < chars.len() && chars[i + 1] == '=' {
                        i += 1;
                        if i + 1 < chars.len() && chars[i + 1] == '=' {
                            i += 1;
                            JsToken::EqEqEq
                        } else {
                            JsToken::EqEq
                        }
                    } else if i + 1 < chars.len() && chars[i + 1] == '>' {
                        i += 1;
                        JsToken::Arrow
                    } else {
                        JsToken::Eq
                    }
                }
                '!' => {
                    if i + 1 < chars.len() && chars[i + 1] == '=' {
                        i += 1;
                        if i + 1 < chars.len() && chars[i + 1] == '=' {
                            i += 1;
                            JsToken::NeEqEq
                        } else {
                            JsToken::NeEq
                        }
                    } else {
                        JsToken::Not
                    }
                }
                '<' => {
                    if i + 1 < chars.len() && chars[i + 1] == '=' {
                        i += 1;
                        JsToken::Le
                    } else {
                        JsToken::Lt
                    }
                }
                '>' => {
                    if i + 1 < chars.len() && chars[i + 1] == '=' {
                        i += 1;
                        JsToken::Ge
                    } else {
                        JsToken::Gt
                    }
                }
                '&' => {
                    if i + 1 < chars.len() && chars[i + 1] == '&' {
                        i += 1;
                        JsToken::AndAnd
                    } else {
                        JsToken::And
                    }
                }
                '|' => {
                    if i + 1 < chars.len() && chars[i + 1] == '|' {
                        i += 1;
                        JsToken::OrOr
                    } else {
                        JsToken::Or
                    }
                }
                '?' => JsToken::Question,
                _ => {
                    i += 1;
                    continue;
                }
            };
            tokens.push(tok);
            i += 1;
        }
        
        tokens
    }
    
    fn parse_js_program(&mut self, tokens: &[JsToken]) -> Result<(), String> {
        let mut i = 0;
        while i < tokens.len() {
            i = self.parse_js_statement(tokens, i)?;
        }
        Ok(())
    }
    
    fn parse_js_statement(&mut self, tokens: &[JsToken], start: usize) -> Result<usize, String> {
        if start >= tokens.len() {
            return Ok(start);
        }
        
        match &tokens[start] {
            JsToken::Var => self.parse_js_var_decl(tokens, start + 1),
            JsToken::Function => self.parse_js_function(tokens, start + 1),
            JsToken::If => self.parse_js_if(tokens, start + 1),
            JsToken::While => self.parse_js_while(tokens, start + 1),
            JsToken::For => self.parse_js_for(tokens, start + 1),
            JsToken::Return => self.parse_js_return(tokens, start + 1),
            JsToken::LBrace => self.parse_js_block(tokens, start + 1),
            JsToken::Export | JsToken::Import | JsToken::Async | JsToken::Class => {
                // Skip these keywords and continue
                self.parse_js_statement(tokens, start + 1)
            }
            JsToken::Semi => Ok(start + 1),
            _ => self.parse_js_expression_statement(tokens, start),
        }
    }
    
    fn parse_js_var_decl(&mut self, tokens: &[JsToken], start: usize) -> Result<usize, String> {
        if start >= tokens.len() {
            return Ok(start);
        }
        
        let name = match &tokens[start] {
            JsToken::Ident(n) => n.clone(),
            _ => return self.parse_js_statement(tokens, start),
        };
        
        let slot = self.get_or_create_local(&name);
        let mut i = start + 1;
        
        // Check for initializer
        if i < tokens.len() && matches!(tokens[i], JsToken::Eq) {
            i += 1;
            i = self.parse_js_expression(tokens, i)?;
            self.emit_store_local(slot);
        } else {
            self.emit(Opcode::PushNull);
            self.emit_store_local(slot);
        }
        
        // Skip semicolon
        if i < tokens.len() && matches!(tokens[i], JsToken::Semi) {
            i += 1;
        }
        
        Ok(i)
    }
    
    fn parse_js_function(&mut self, tokens: &[JsToken], start: usize) -> Result<usize, String> {
        // Save current state
        let saved_code = std::mem::take(&mut self.current_code);
        let saved_locals = std::mem::take(&mut self.locals);
        let saved_local_count = self.local_count;
        self.local_count = 0;
        
        let mut i = start;
        
        // Function name (optional)
        let _name = if let Some(JsToken::Ident(n)) = tokens.get(i) {
            i += 1;
            n.clone()
        } else {
            format!("_fn{}", self.module.functions.len())
        };
        
        // Parameters
        let mut param_count = 0u8;
        if i < tokens.len() && matches!(tokens[i], JsToken::LParen) {
            i += 1;
            while i < tokens.len() && !matches!(tokens[i], JsToken::RParen) {
                if let JsToken::Ident(pname) = &tokens[i] {
                    self.get_or_create_local(pname);
                    param_count += 1;
                }
                i += 1;
                if i < tokens.len() && matches!(tokens[i], JsToken::Comma) {
                    i += 1;
                }
            }
            if i < tokens.len() {
                i += 1; // Skip )
            }
        }
        
        // Body
        if i < tokens.len() && matches!(tokens[i], JsToken::LBrace) {
            i = self.parse_js_block(tokens, i + 1)?;
        }
        
        // Add implicit return
        self.emit(Opcode::PushNull);
        self.emit(Opcode::Return);
        
        // Finalize function
        self.finalize_function(param_count, self.local_count);
        
        // Restore state
        self.current_code = saved_code;
        self.locals = saved_locals;
        self.local_count = saved_local_count;
        
        Ok(i)
    }
    
    fn parse_js_if(&mut self, tokens: &[JsToken], start: usize) -> Result<usize, String> {
        let mut i = start;
        
        // Condition
        if i < tokens.len() && matches!(tokens[i], JsToken::LParen) {
            i += 1;
            i = self.parse_js_expression(tokens, i)?;
            if i < tokens.len() && matches!(tokens[i], JsToken::RParen) {
                i += 1;
            }
        }
        
        // Jump if false
        let jump_addr = self.current_code.len();
        self.emit(Opcode::JumpIfFalse);
        self.emit_u16(0); // Placeholder
        
        // Then branch
        i = self.parse_js_statement(tokens, i)?;
        
        // Check for else
        if i < tokens.len() && matches!(tokens[i], JsToken::Else) {
            let else_jump = self.current_code.len();
            self.emit(Opcode::Jump);
            self.emit_u16(0); // Placeholder
            
            // Patch first jump to here
            self.patch_jump(jump_addr, self.current_code.len());
            
            i = self.parse_js_statement(tokens, i + 1)?;
            
            // Patch else jump
            self.patch_jump(else_jump, self.current_code.len());
        } else {
            // Patch jump to here
            self.patch_jump(jump_addr, self.current_code.len());
        }
        
        Ok(i)
    }
    
    fn parse_js_while(&mut self, tokens: &[JsToken], start: usize) -> Result<usize, String> {
        let mut i = start;
        let loop_start = self.current_code.len();
        
        // Condition
        if i < tokens.len() && matches!(tokens[i], JsToken::LParen) {
            i += 1;
            i = self.parse_js_expression(tokens, i)?;
            if i < tokens.len() && matches!(tokens[i], JsToken::RParen) {
                i += 1;
            }
        }
        
        // Jump if false
        let jump_addr = self.current_code.len();
        self.emit(Opcode::JumpIfFalse);
        self.emit_u16(0);
        
        // Body
        i = self.parse_js_statement(tokens, i)?;
        
        // Jump back
        self.emit(Opcode::Jump);
        self.emit_u16(loop_start as u16);
        
        // Patch exit jump
        self.patch_jump(jump_addr, self.current_code.len());
        
        Ok(i)
    }
    
    fn parse_js_for(&mut self, tokens: &[JsToken], start: usize) -> Result<usize, String> {
        let mut i = start;
        
        if i < tokens.len() && matches!(tokens[i], JsToken::LParen) {
            i += 1;
        }
        
        // Init
        if i < tokens.len() && matches!(tokens[i], JsToken::Var) {
            i = self.parse_js_var_decl(tokens, i + 1)?;
        } else if i < tokens.len() && !matches!(tokens[i], JsToken::Semi) {
            i = self.parse_js_expression(tokens, i)?;
            self.emit(Opcode::Pop);
        }
        if i < tokens.len() && matches!(tokens[i], JsToken::Semi) {
            i += 1;
        }
        
        let loop_start = self.current_code.len();
        
        // Condition
        let mut has_condition = false;
        if i < tokens.len() && !matches!(tokens[i], JsToken::Semi) {
            i = self.parse_js_expression(tokens, i)?;
            has_condition = true;
        }
        if i < tokens.len() && matches!(tokens[i], JsToken::Semi) {
            i += 1;
        }
        
        // Jump if false (or skip if no condition)
        let jump_addr = if has_condition {
            let addr = self.current_code.len();
            self.emit(Opcode::JumpIfFalse);
            self.emit_u16(0);
            Some(addr)
        } else {
            None
        };
        
        // Remember increment position
        let incr_start = i;
        let mut incr_end = i;
        
        // Skip to body
        let mut paren_depth = 1;
        while i < tokens.len() && paren_depth > 0 {
            match tokens[i] {
                JsToken::LParen => paren_depth += 1,
                JsToken::RParen => paren_depth -= 1,
                _ => {}
            }
            if paren_depth > 0 {
                incr_end = i + 1;
            }
            i += 1;
        }
        
        // Body
        i = self.parse_js_statement(tokens, i)?;
        
        // Increment
        if incr_start < incr_end {
            let _ = self.parse_js_expression(&tokens[incr_start..incr_end], 0);
            self.emit(Opcode::Pop);
        }
        
        // Jump back
        self.emit(Opcode::Jump);
        self.emit_u16(loop_start as u16);
        
        // Patch exit
        if let Some(addr) = jump_addr {
            self.patch_jump(addr, self.current_code.len());
        }
        
        Ok(i)
    }
    
    fn parse_js_return(&mut self, tokens: &[JsToken], start: usize) -> Result<usize, String> {
        let mut i = start;
        
        if i < tokens.len() && !matches!(tokens[i], JsToken::Semi | JsToken::RBrace) {
            i = self.parse_js_expression(tokens, i)?;
        } else {
            self.emit(Opcode::PushNull);
        }
        
        self.emit(Opcode::Return);
        
        if i < tokens.len() && matches!(tokens[i], JsToken::Semi) {
            i += 1;
        }
        
        Ok(i)
    }
    
    fn parse_js_block(&mut self, tokens: &[JsToken], start: usize) -> Result<usize, String> {
        let mut i = start;
        while i < tokens.len() && !matches!(tokens[i], JsToken::RBrace) {
            i = self.parse_js_statement(tokens, i)?;
        }
        if i < tokens.len() {
            i += 1; // Skip }
        }
        Ok(i)
    }
    
    fn parse_js_expression_statement(&mut self, tokens: &[JsToken], start: usize) -> Result<usize, String> {
        let i = self.parse_js_expression(tokens, start)?;
        self.emit(Opcode::Pop);
        
        let mut end = i;
        if end < tokens.len() && matches!(tokens[end], JsToken::Semi) {
            end += 1;
        }
        Ok(end)
    }
    
    fn parse_js_expression(&mut self, tokens: &[JsToken], start: usize) -> Result<usize, String> {
        self.parse_js_assignment(tokens, start)
    }
    
    fn parse_js_assignment(&mut self, tokens: &[JsToken], start: usize) -> Result<usize, String> {
        let i = self.parse_js_ternary(tokens, start)?;
        
        if i < tokens.len() {
            match &tokens[i] {
                JsToken::Eq => {
                    // Need to handle assignment target
                    // For now, if previous was identifier load, convert to store
                    let i2 = self.parse_js_expression(tokens, i + 1)?;
                    
                    // Check if we can find the target
                    if start < tokens.len() {
                        if let JsToken::Ident(name) = &tokens[start] {
                            let slot = self.get_or_create_local(name);
                            self.emit(Opcode::Dup);
                            self.emit_store_local(slot);
                        }
                    }
                    return Ok(i2);
                }
                JsToken::PlusEq | JsToken::MinusEq => {
                    if start < tokens.len() {
                        if let JsToken::Ident(name) = &tokens[start] {
                            let slot = self.get_or_create_local(name);
                            self.emit_load_local(slot);
                            let i2 = self.parse_js_expression(tokens, i + 1)?;
                            match &tokens[i] {
                                JsToken::PlusEq => self.emit(Opcode::Add),
                                JsToken::MinusEq => self.emit(Opcode::Sub),
                                _ => {}
                            }
                            self.emit(Opcode::Dup);
                            self.emit_store_local(slot);
                            return Ok(i2);
                        }
                    }
                }
                _ => {}
            }
        }
        
        Ok(i)
    }
    
    fn parse_js_ternary(&mut self, tokens: &[JsToken], start: usize) -> Result<usize, String> {
        let i = self.parse_js_or(tokens, start)?;
        
        if i < tokens.len() && matches!(tokens[i], JsToken::Question) {
            let false_jump = self.current_code.len();
            self.emit(Opcode::JumpIfFalse);
            self.emit_u16(0);
            
            let i2 = self.parse_js_expression(tokens, i + 1)?;
            
            // Skip colon
            let i3 = if i2 < tokens.len() && matches!(tokens[i2], JsToken::Colon) {
                i2 + 1
            } else {
                i2
            };
            
            let end_jump = self.current_code.len();
            self.emit(Opcode::Jump);
            self.emit_u16(0);
            
            self.patch_jump(false_jump, self.current_code.len());
            
            let i4 = self.parse_js_expression(tokens, i3)?;
            
            self.patch_jump(end_jump, self.current_code.len());
            
            return Ok(i4);
        }
        
        Ok(i)
    }
    
    fn parse_js_or(&mut self, tokens: &[JsToken], start: usize) -> Result<usize, String> {
        let mut i = self.parse_js_and(tokens, start)?;
        
        while i < tokens.len() && matches!(tokens[i], JsToken::OrOr) {
            i = self.parse_js_and(tokens, i + 1)?;
            self.emit(Opcode::Or);
        }
        
        Ok(i)
    }
    
    fn parse_js_and(&mut self, tokens: &[JsToken], start: usize) -> Result<usize, String> {
        let mut i = self.parse_js_equality(tokens, start)?;
        
        while i < tokens.len() && matches!(tokens[i], JsToken::AndAnd) {
            i = self.parse_js_equality(tokens, i + 1)?;
            self.emit(Opcode::And);
        }
        
        Ok(i)
    }
    
    fn parse_js_equality(&mut self, tokens: &[JsToken], start: usize) -> Result<usize, String> {
        let mut i = self.parse_js_comparison(tokens, start)?;
        
        while i < tokens.len() {
            match &tokens[i] {
                JsToken::EqEq | JsToken::EqEqEq => {
                    i = self.parse_js_comparison(tokens, i + 1)?;
                    self.emit(Opcode::Eq);
                }
                JsToken::NeEq | JsToken::NeEqEq => {
                    i = self.parse_js_comparison(tokens, i + 1)?;
                    self.emit(Opcode::Ne);
                }
                _ => break,
            }
        }
        
        Ok(i)
    }
    
    fn parse_js_comparison(&mut self, tokens: &[JsToken], start: usize) -> Result<usize, String> {
        let mut i = self.parse_js_additive(tokens, start)?;
        
        while i < tokens.len() {
            match &tokens[i] {
                JsToken::Lt => {
                    i = self.parse_js_additive(tokens, i + 1)?;
                    self.emit(Opcode::Lt);
                }
                JsToken::Le => {
                    i = self.parse_js_additive(tokens, i + 1)?;
                    self.emit(Opcode::Le);
                }
                JsToken::Gt => {
                    i = self.parse_js_additive(tokens, i + 1)?;
                    self.emit(Opcode::Gt);
                }
                JsToken::Ge => {
                    i = self.parse_js_additive(tokens, i + 1)?;
                    self.emit(Opcode::Ge);
                }
                _ => break,
            }
        }
        
        Ok(i)
    }
    
    fn parse_js_additive(&mut self, tokens: &[JsToken], start: usize) -> Result<usize, String> {
        let mut i = self.parse_js_multiplicative(tokens, start)?;
        
        while i < tokens.len() {
            match &tokens[i] {
                JsToken::Plus => {
                    i = self.parse_js_multiplicative(tokens, i + 1)?;
                    self.emit(Opcode::Add);
                }
                JsToken::Minus => {
                    i = self.parse_js_multiplicative(tokens, i + 1)?;
                    self.emit(Opcode::Sub);
                }
                _ => break,
            }
        }
        
        Ok(i)
    }
    
    fn parse_js_multiplicative(&mut self, tokens: &[JsToken], start: usize) -> Result<usize, String> {
        let mut i = self.parse_js_unary(tokens, start)?;
        
        while i < tokens.len() {
            match &tokens[i] {
                JsToken::Star => {
                    i = self.parse_js_unary(tokens, i + 1)?;
                    self.emit(Opcode::Mul);
                }
                JsToken::Slash => {
                    i = self.parse_js_unary(tokens, i + 1)?;
                    self.emit(Opcode::Div);
                }
                JsToken::Percent => {
                    i = self.parse_js_unary(tokens, i + 1)?;
                    self.emit(Opcode::Mod);
                }
                _ => break,
            }
        }
        
        Ok(i)
    }
    
    fn parse_js_unary(&mut self, tokens: &[JsToken], start: usize) -> Result<usize, String> {
        if start >= tokens.len() {
            return Ok(start);
        }
        
        match &tokens[start] {
            JsToken::Not => {
                let i = self.parse_js_unary(tokens, start + 1)?;
                self.emit(Opcode::Not);
                Ok(i)
            }
            JsToken::Minus => {
                let i = self.parse_js_unary(tokens, start + 1)?;
                self.emit(Opcode::Neg);
                Ok(i)
            }
            JsToken::PlusPlus => {
                if start + 1 < tokens.len() {
                    if let JsToken::Ident(name) = &tokens[start + 1] {
                        let slot = self.get_or_create_local(name);
                        self.emit_load_local(slot);
                        self.emit_push_int(1);
                        self.emit(Opcode::Add);
                        self.emit(Opcode::Dup);
                        self.emit_store_local(slot);
                        return Ok(start + 2);
                    }
                }
                self.parse_js_postfix(tokens, start + 1)
            }
            JsToken::MinusMinus => {
                if start + 1 < tokens.len() {
                    if let JsToken::Ident(name) = &tokens[start + 1] {
                        let slot = self.get_or_create_local(name);
                        self.emit_load_local(slot);
                        self.emit_push_int(1);
                        self.emit(Opcode::Sub);
                        self.emit(Opcode::Dup);
                        self.emit_store_local(slot);
                        return Ok(start + 2);
                    }
                }
                self.parse_js_postfix(tokens, start + 1)
            }
            _ => self.parse_js_postfix(tokens, start),
        }
    }
    
    fn parse_js_postfix(&mut self, tokens: &[JsToken], start: usize) -> Result<usize, String> {
        let i = self.parse_js_call(tokens, start)?;
        
        if i < tokens.len() {
            match &tokens[i] {
                JsToken::PlusPlus => {
                    // Post-increment: return old value, store new
                    // This is tricky - we already loaded the value
                    return Ok(i + 1);
                }
                JsToken::MinusMinus => {
                    return Ok(i + 1);
                }
                _ => {}
            }
        }
        
        Ok(i)
    }
    
    fn parse_js_call(&mut self, tokens: &[JsToken], start: usize) -> Result<usize, String> {
        let mut i = self.parse_js_primary(tokens, start)?;
        
        loop {
            if i >= tokens.len() {
                break;
            }
            
            match &tokens[i] {
                JsToken::LParen => {
                    // Function call
                    let mut arg_count = 0u8;
                    i += 1;
                    
                    while i < tokens.len() && !matches!(tokens[i], JsToken::RParen) {
                        i = self.parse_js_expression(tokens, i)?;
                        arg_count += 1;
                        if i < tokens.len() && matches!(tokens[i], JsToken::Comma) {
                            i += 1;
                        }
                    }
                    
                    if i < tokens.len() {
                        i += 1; // Skip )
                    }
                    
                    // Emit call
                    self.emit(Opcode::Call);
                    self.current_code.push(arg_count);
                }
                JsToken::Dot => {
                    // Property access
                    i += 1;
                    if i < tokens.len() {
                        if let JsToken::Ident(prop) = &tokens[i] {
                            let idx = self.module.add_string(prop);
                            self.emit(Opcode::ObjGet);
                            self.emit_u16(idx);
                            i += 1;
                        }
                    }
                }
                JsToken::LBracket => {
                    // Array access
                    i += 1;
                    i = self.parse_js_expression(tokens, i)?;
                    self.emit(Opcode::ArrayGet);
                    if i < tokens.len() && matches!(tokens[i], JsToken::RBracket) {
                        i += 1;
                    }
                }
                _ => break,
            }
        }
        
        Ok(i)
    }
    
    fn parse_js_primary(&mut self, tokens: &[JsToken], start: usize) -> Result<usize, String> {
        if start >= tokens.len() {
            self.emit(Opcode::PushNull);
            return Ok(start);
        }
        
        match &tokens[start] {
            JsToken::Int(n) => {
                self.emit_push_int(*n);
                Ok(start + 1)
            }
            JsToken::Float(f) => {
                let idx = self.module.add_constant(Constant::Float(*f));
                self.emit(Opcode::PushFloat);
                self.emit_u16(idx);
                Ok(start + 1)
            }
            JsToken::String(s) => {
                let idx = self.module.add_string(s);
                self.emit(Opcode::PushString);
                self.emit_u16(idx);
                Ok(start + 1)
            }
            JsToken::True => {
                self.emit(Opcode::PushBool);
                self.current_code.push(1);
                Ok(start + 1)
            }
            JsToken::False => {
                self.emit(Opcode::PushBool);
                self.current_code.push(0);
                Ok(start + 1)
            }
            JsToken::Null => {
                self.emit(Opcode::PushNull);
                Ok(start + 1)
            }
            JsToken::Ident(name) => {
                // Check for builtin functions first
                if is_js_builtin(name) {
                    let idx = self.module.add_builtin(name);
                    self.emit(Opcode::CallBuiltin);
                    self.emit_u16(idx);
                } else {
                    let slot = self.get_or_create_local(name);
                    self.emit_load_local(slot);
                }
                Ok(start + 1)
            }
            JsToken::LParen => {
                let i = self.parse_js_expression(tokens, start + 1)?;
                let end = if i < tokens.len() && matches!(tokens[i], JsToken::RParen) {
                    i + 1
                } else {
                    i
                };
                Ok(end)
            }
            JsToken::LBracket => {
                // Array literal
                let mut count = 0u16;
                let mut i = start + 1;
                
                while i < tokens.len() && !matches!(tokens[i], JsToken::RBracket) {
                    i = self.parse_js_expression(tokens, i)?;
                    count += 1;
                    if i < tokens.len() && matches!(tokens[i], JsToken::Comma) {
                        i += 1;
                    }
                }
                
                self.emit(Opcode::NewArray);
                self.emit_u16(count);
                
                if i < tokens.len() {
                    i += 1;
                }
                Ok(i)
            }
            JsToken::LBrace => {
                // Object literal
                let mut count = 0u16;
                let mut i = start + 1;
                
                while i < tokens.len() && !matches!(tokens[i], JsToken::RBrace) {
                    // Key
                    if let Some(JsToken::Ident(key)) | Some(JsToken::String(key)) = tokens.get(i) {
                        let idx = self.module.add_string(key);
                        self.emit(Opcode::PushString);
                        self.emit_u16(idx);
                        i += 1;
                    }
                    
                    // Colon
                    if i < tokens.len() && matches!(tokens[i], JsToken::Colon) {
                        i += 1;
                    }
                    
                    // Value
                    i = self.parse_js_expression(tokens, i)?;
                    count += 1;
                    
                    if i < tokens.len() && matches!(tokens[i], JsToken::Comma) {
                        i += 1;
                    }
                }
                
                self.emit(Opcode::NewObject);
                self.emit_u16(count);
                
                if i < tokens.len() {
                    i += 1;
                }
                Ok(i)
            }
            JsToken::New => {
                // new Constructor()
                let i = self.parse_js_call(tokens, start + 1)?;
                Ok(i)
            }
            JsToken::This => {
                let slot = self.get_or_create_local("this");
                self.emit_load_local(slot);
                Ok(start + 1)
            }
            JsToken::Function => {
                // Anonymous function expression
                self.parse_js_function(tokens, start + 1)
            }
            JsToken::Require => {
                // require('module') - convert to builtin
                let idx = self.module.add_builtin("require");
                self.emit(Opcode::CallBuiltin);
                self.emit_u16(idx);
                Ok(start + 1)
            }
            _ => {
                // Skip unknown token
                Ok(start + 1)
            }
        }
    }
    
    // ==================== Python Compiler ====================
    
    fn compile_python(&mut self, source: &str) -> Result<(), String> {
        // Line-based Python parsing
        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            self.compile_python_line(trimmed)?;
        }
        
        self.emit(Opcode::Halt);
        self.finalize_function(0, 0);
        Ok(())
    }
    
    fn compile_python_line(&mut self, line: &str) -> Result<(), String> {
        // Handle common Python patterns
        if line.starts_with("def ") {
            // Function definition
            self.emit(Opcode::Nop);
        } else if line.starts_with("if ") || line.starts_with("elif ") {
            self.emit(Opcode::PushBool);
            self.current_code.push(1);
            self.emit(Opcode::JumpIfFalse);
            self.emit_u16(0);
        } else if line.starts_with("while ") || line.starts_with("for ") {
            self.emit(Opcode::PushBool);
            self.current_code.push(1);
            self.emit(Opcode::JumpIfFalse);
            self.emit_u16(0);
        } else if line.starts_with("return ") {
            let val = &line[7..].trim();
            if let Ok(n) = val.parse::<i64>() {
                self.emit_push_int(n);
            } else {
                self.emit(Opcode::PushNull);
            }
            self.emit(Opcode::Return);
        } else if line.contains("print(") {
            let idx = self.module.add_builtin("print");
            self.emit(Opcode::CallBuiltin);
            self.emit_u16(idx);
        } else if line.contains('=') && !line.contains("==") {
            // Assignment
            let parts: Vec<&str> = line.splitn(2, '=').collect();
            if parts.len() == 2 {
                let name = parts[0].trim();
                let slot = self.get_or_create_local(name);
                
                let val = parts[1].trim();
                if let Ok(n) = val.parse::<i64>() {
                    self.emit_push_int(n);
                } else if val.starts_with('"') || val.starts_with('\'') {
                    let s = val.trim_matches(|c| c == '"' || c == '\'');
                    let idx = self.module.add_string(s);
                    self.emit(Opcode::PushString);
                    self.emit_u16(idx);
                } else {
                    self.emit(Opcode::PushNull);
                }
                self.emit_store_local(slot);
            }
        }
        
        Ok(())
    }
    
    // ==================== Ruby Compiler ====================
    
    fn compile_ruby(&mut self, source: &str) -> Result<(), String> {
        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            self.compile_ruby_line(trimmed)?;
        }
        
        self.emit(Opcode::Halt);
        self.finalize_function(0, 0);
        Ok(())
    }
    
    fn compile_ruby_line(&mut self, line: &str) -> Result<(), String> {
        if line.starts_with("def ") {
            self.emit(Opcode::Nop);
        } else if line.starts_with("if ") {
            self.emit(Opcode::PushBool);
            self.current_code.push(1);
            self.emit(Opcode::JumpIfFalse);
            self.emit_u16(0);
        } else if line.contains("puts ") || line.contains("print ") {
            let idx = self.module.add_builtin("puts");
            self.emit(Opcode::CallBuiltin);
            self.emit_u16(idx);
        } else if line.contains('=') {
            let parts: Vec<&str> = line.splitn(2, '=').collect();
            if parts.len() == 2 {
                let name = parts[0].trim();
                let slot = self.get_or_create_local(name);
                self.emit(Opcode::PushNull);
                self.emit_store_local(slot);
            }
        }
        
        Ok(())
    }
    
    // ==================== Lua Compiler ====================
    
    fn compile_lua(&mut self, source: &str) -> Result<(), String> {
        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("--") {
                continue;
            }
            self.compile_lua_line(trimmed)?;
        }
        
        self.emit(Opcode::Halt);
        self.finalize_function(0, 0);
        Ok(())
    }
    
    fn compile_lua_line(&mut self, line: &str) -> Result<(), String> {
        if line.starts_with("function ") || line.starts_with("local function") {
            self.emit(Opcode::Nop);
        } else if line.starts_with("if ") {
            self.emit(Opcode::PushBool);
            self.current_code.push(1);
            self.emit(Opcode::JumpIfFalse);
            self.emit_u16(0);
        } else if line.contains("print(") {
            let idx = self.module.add_builtin("print");
            self.emit(Opcode::CallBuiltin);
            self.emit_u16(idx);
        } else if line.starts_with("local ") || line.contains('=') {
            let clean = line.strip_prefix("local ").unwrap_or(line);
            let parts: Vec<&str> = clean.splitn(2, '=').collect();
            if parts.len() >= 1 {
                let name = parts[0].trim();
                let slot = self.get_or_create_local(name);
                self.emit(Opcode::PushNull);
                self.emit_store_local(slot);
            }
        }
        
        Ok(())
    }
    
    // ==================== PHP Compiler ====================
    
    fn compile_php(&mut self, source: &str) -> Result<(), String> {
        // Remove PHP tags
        let code = source
            .replace("<?php", "")
            .replace("?>", "")
            .replace("<?", "");
        
        for line in code.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with('#') {
                continue;
            }
            self.compile_php_line(trimmed)?;
        }
        
        self.emit(Opcode::Halt);
        self.finalize_function(0, 0);
        Ok(())
    }
    
    fn compile_php_line(&mut self, line: &str) -> Result<(), String> {
        if line.starts_with("function ") {
            self.emit(Opcode::Nop);
        } else if line.starts_with("if ") || line.starts_with("if(") {
            self.emit(Opcode::PushBool);
            self.current_code.push(1);
            self.emit(Opcode::JumpIfFalse);
            self.emit_u16(0);
        } else if line.contains("echo ") || line.contains("print ") {
            let idx = self.module.add_builtin("echo");
            self.emit(Opcode::CallBuiltin);
            self.emit_u16(idx);
        } else if line.starts_with('$') && line.contains('=') {
            let parts: Vec<&str> = line.splitn(2, '=').collect();
            if parts.len() == 2 {
                let name = parts[0].trim().trim_start_matches('$');
                let slot = self.get_or_create_local(name);
                self.emit(Opcode::PushNull);
                self.emit_store_local(slot);
            }
        }
        
        Ok(())
    }
    
    // ==================== Helpers ====================
    
    fn get_or_create_local(&mut self, name: &str) -> u8 {
        if let Some(&slot) = self.locals.get(name) {
            slot
        } else {
            let slot = self.local_count;
            self.locals.insert(name.to_string(), slot);
            self.local_count += 1;
            slot
        }
    }
    
    fn emit(&mut self, op: Opcode) {
        self.current_code.push(op as u8);
    }
    
    fn emit_u16(&mut self, val: u16) {
        self.current_code.extend_from_slice(&val.to_le_bytes());
    }
    
    fn emit_push_int(&mut self, n: i64) {
        let idx = self.module.add_constant(Constant::Int(n));
        self.emit(Opcode::PushInt);
        self.emit_u16(idx);
    }
    
    fn emit_load_local(&mut self, slot: u8) {
        self.emit(Opcode::LoadLocal);
        self.current_code.push(slot);
    }
    
    fn emit_store_local(&mut self, slot: u8) {
        self.emit(Opcode::StoreLocal);
        self.current_code.push(slot);
    }
    
    fn patch_jump(&mut self, addr: usize, target: usize) {
        let offset = target as u16;
        let bytes = offset.to_le_bytes();
        if addr + 2 < self.current_code.len() {
            self.current_code[addr + 1] = bytes[0];
            self.current_code[addr + 2] = bytes[1];
        }
    }
    
    fn finalize_function(&mut self, param_count: u8, local_count: u8) {
        let func = BytecodeFunction {
            param_count,
            local_count,
            code: std::mem::take(&mut self.current_code),
        };
        self.module.functions.push(func);
    }
}

fn is_js_builtin(name: &str) -> bool {
    matches!(name, 
        "console" | "Math" | "JSON" | "Object" | "Array" | "String" |
        "Number" | "Boolean" | "Date" | "RegExp" | "Error" | "Promise" |
        "setTimeout" | "setInterval" | "clearTimeout" | "clearInterval" |
        "parseInt" | "parseFloat" | "isNaN" | "isFinite" |
        "encodeURI" | "decodeURI" | "encodeURIComponent" | "decodeURIComponent" |
        "require" | "module" | "exports" | "process" | "Buffer" | "__dirname" | "__filename"
    )
}

#[derive(Debug, Clone)]
enum JsToken {
    // Literals
    Int(i64),
    Float(f64),
    String(String),
    True,
    False,
    Null,
    Ident(String),
    
    // Keywords
    Function,
    Var,
    If,
    Else,
    While,
    For,
    Return,
    New,
    This,
    Class,
    Async,
    Await,
    Export,
    Import,
    Require,
    Module,
    
    // Operators
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Eq,
    EqEq,
    EqEqEq,
    NeEq,
    NeEqEq,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    AndAnd,
    Or,
    OrOr,
    Not,
    PlusPlus,
    MinusMinus,
    PlusEq,
    MinusEq,
    Arrow,
    Question,
    
    // Punctuation
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Semi,
    Comma,
    Dot,
    Colon,
}
