
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Language {
    JavaScript,
    TypeScript,
    Python,
    Ruby,
    Lua,
    PHP,
    Shell,
}

impl Language {
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            "js" | "mjs" | "cjs" | "jsx" => Some(Language::JavaScript),
            "ts" | "tsx" | "mts" | "cts" => Some(Language::TypeScript),
            "py" | "pyw" | "pyi" => Some(Language::Python),
            "rb" | "rake" | "gemspec" => Some(Language::Ruby),
            "lua" => Some(Language::Lua),
            "php" | "phtml" => Some(Language::PHP),
            "sh" | "bash" | "zsh" => Some(Language::Shell),
            _ => None,
        }
    }
    
    pub fn runtime_language(&self) -> &'static str {
        match self {
            Language::JavaScript | Language::TypeScript => "javascript",
            Language::Python => "python",
            Language::Ruby => "ruby",
            Language::Lua => "lua",
            Language::PHP => "php",
            Language::Shell => "bash",
        }
    }
    
    pub fn is_virtualizable(&self) -> bool {
        matches!(self, 
            Language::JavaScript | 
            Language::TypeScript | 
            Language::Python |
            Language::Ruby |
            Language::Lua |
            Language::PHP
        )
    }
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Language::JavaScript => write!(f, "JavaScript"),
            Language::TypeScript => write!(f, "TypeScript"),
            Language::Python => write!(f, "Python"),
            Language::Ruby => write!(f, "Ruby"),
            Language::Lua => write!(f, "Lua"),
            Language::PHP => write!(f, "PHP"),
            Language::Shell => write!(f, "Shell"),
        }
    }
}
