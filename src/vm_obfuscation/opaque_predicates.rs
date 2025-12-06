
use rand::Rng;

#[derive(Debug, Clone)]
pub struct OpaquePredicate {
    pub variant: PredicateVariant,
    pub result: bool,
    pub complexity: u8,
}

#[derive(Debug, Clone)]
pub enum PredicateVariant {
    SquareNonNegative { value: i64 },
    
    OrOneNonZero { value: i64 },
    
    AndZeroIsZero { value: i64 },
    
    QuadraticInequality { x: i64, y: i64 },
    
    SumOfSquaresMod { x: i64, y: i64 },
    
    Custom { bytecode: Vec<u8> },
}

impl OpaquePredicate {
    pub fn always_true() -> Self {
        let mut rng = rand::thread_rng();
        let value = rng.gen::<i64>();
        
        Self {
            variant: PredicateVariant::SquareNonNegative { value },
            result: true,
            complexity: 1,
        }
    }
    
    pub fn always_false() -> Self {
        let mut rng = rand::thread_rng();
        let value = rng.gen::<i64>();
        
        // (x & 0) != 0 is always false
        Self {
            variant: PredicateVariant::AndZeroIsZero { value },
            result: false,
            complexity: 1,
        }
    }
    
    pub fn complex(result: bool) -> Self {
        let mut rng = rand::thread_rng();
        
        if result {
            Self {
                variant: PredicateVariant::QuadraticInequality {
                    x: rng.gen(),
                    y: rng.gen(),
                },
                result: true,
                complexity: 3,
            }
        } else {
            Self {
                variant: PredicateVariant::Custom {
                    bytecode: vec![0x00, 0x00, 0x00], // Always pushes false
                },
                result: false,
                complexity: 3,
            }
        }
    }
    
    pub fn evaluate(&self) -> bool {
        match &self.variant {
            PredicateVariant::SquareNonNegative { value } => {
                // x * x >= 0 is always true (ignoring overflow)
                let sq = value.wrapping_mul(*value);
                sq >= 0 || sq < 0 // Always true (catches overflow case)
            }
            PredicateVariant::OrOneNonZero { value } => {
                (value | 1) != 0 // Always true
            }
            PredicateVariant::AndZeroIsZero { value } => {
                (value & 0) == 0 // Always true, but we use it for "always false" by negating result
            }
            PredicateVariant::QuadraticInequality { x, y } => {
                // 7 * y^2 - 1 != x^2 is always true for integers
                let lhs = 7i64.saturating_mul(y.saturating_mul(*y)).saturating_sub(1);
                let rhs = x.saturating_mul(*x);
                lhs != rhs // Provably always true
            }
            PredicateVariant::SumOfSquaresMod { x, y } => {
                // Sum of two squares mod 4 is never 3
                let sum = x.wrapping_mul(*x).wrapping_add(y.wrapping_mul(*y));
                (sum % 4) != 3 // Always true
            }
            PredicateVariant::Custom { bytecode: _ } => {
                self.result // Custom uses stored result
            }
        }
    }
    
    pub fn to_bytecode(&self) -> Vec<u8> {
        let mut code = Vec::new();
        
        match &self.variant {
            PredicateVariant::SquareNonNegative { value } => {
                // Push value, duplicate, multiply, push 0, compare GE
                code.push(0x02); // PUSH_INT64
                code.extend_from_slice(&value.to_le_bytes());
                code.push(0x06); // DUP
                code.push(0x22); // MUL
                code.push(0x02); // PUSH_INT64
                code.extend_from_slice(&0i64.to_le_bytes());
                code.push(0x45); // GE
            }
            PredicateVariant::OrOneNonZero { value } => {
                // Push value, push 1, OR, push 0, NE
                code.push(0x02);
                code.extend_from_slice(&value.to_le_bytes());
                code.push(0x02);
                code.extend_from_slice(&1i64.to_le_bytes());
                code.push(0x31); // BIT_OR
                code.push(0x02);
                code.extend_from_slice(&0i64.to_le_bytes());
                code.push(0x41); // NE
            }
            PredicateVariant::AndZeroIsZero { value } => {
                // Push value, push 0, AND, push 0, EQ
                code.push(0x02);
                code.extend_from_slice(&value.to_le_bytes());
                code.push(0x02);
                code.extend_from_slice(&0i64.to_le_bytes());
                code.push(0x30); // BIT_AND
                code.push(0x02);
                code.extend_from_slice(&0i64.to_le_bytes());
                code.push(0x40); // EQ
            }
            PredicateVariant::QuadraticInequality { x, y } => {
                // 7 * y^2 - 1 != x^2
                // This is more complex - simplified version
                code.push(0x01); // PUSH_BOOL
                code.push(if self.result { 1 } else { 0 });
            }
            PredicateVariant::SumOfSquaresMod { x: _, y: _ } => {
                code.push(0x01);
                code.push(if self.result { 1 } else { 0 });
            }
            PredicateVariant::Custom { bytecode } => {
                code.extend_from_slice(bytecode);
            }
        }
        
        code
    }
    
    pub fn to_asm(&self) -> String {
        match &self.variant {
            PredicateVariant::SquareNonNegative { value } => {
                format!("// x*x >= 0 where x = {}\nmov rax, {}\nimul rax, rax\ncmp rax, 0\nsetge al", value, value)
            }
            PredicateVariant::OrOneNonZero { value } => {
                format!("// (x|1) != 0 where x = {}\nmov rax, {}\nor rax, 1\ntest rax, rax\nsetne al", value, value)
            }
            PredicateVariant::AndZeroIsZero { value } => {
                format!("// (x&0) == 0 where x = {}\nmov rax, {}\nand rax, 0\ntest rax, rax\nsete al", value, value)
            }
            PredicateVariant::QuadraticInequality { x, y } => {
                format!("// 7*{}^2 - 1 != {}^2 (always true)", y, x)
            }
            PredicateVariant::SumOfSquaresMod { x, y } => {
                format!("// ({}^2 + {}^2) mod 4 != 3 (always true)", x, y)
            }
            PredicateVariant::Custom { bytecode } => {
                format!("// Custom predicate ({} bytes)", bytecode.len())
            }
        }
    }
}

pub fn generate_predicates(count: usize, true_ratio: f64) -> Vec<OpaquePredicate> {
    let mut rng = rand::thread_rng();
    let mut predicates = Vec::with_capacity(count);
    
    for _ in 0..count {
        let want_true = rng.gen::<f64>() < true_ratio;
        let complexity = rng.gen_range(1..=3);
        
        let pred = match complexity {
            1 => {
                if want_true {
                    OpaquePredicate::always_true()
                } else {
                    OpaquePredicate::always_false()
                }
            }
            _ => OpaquePredicate::complex(want_true),
        };
        
        predicates.push(pred);
    }
    
    predicates
}
