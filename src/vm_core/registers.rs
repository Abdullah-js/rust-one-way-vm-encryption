
#[derive(Debug, Clone)]
pub struct RegisterFile {
    gpr: [u64; 32],
    fpr: [f64; 16],
    pc: usize,
    sp: usize,
    fp: usize,
    flags: u64,
}

impl RegisterFile {
    pub fn new() -> Self {
        Self {
            gpr: [0; 32],
            fpr: [0.0; 16],
            pc: 0,
            sp: 0,
            fp: 0,
            flags: 0,
        }
    }
    
    pub fn get_gpr(&self, idx: usize) -> u64 {
        if idx < 32 {
            self.gpr[idx]
        } else {
            0
        }
    }
    
    pub fn set_gpr(&mut self, idx: usize, value: u64) {
        if idx < 32 {
            self.gpr[idx] = value;
        }
    }
    
    pub fn get_fpr(&self, idx: usize) -> f64 {
        if idx < 16 {
            self.fpr[idx]
        } else {
            0.0
        }
    }
    
    pub fn set_fpr(&mut self, idx: usize, value: f64) {
        if idx < 16 {
            self.fpr[idx] = value;
        }
    }
    
    pub fn pc(&self) -> usize {
        self.pc
    }
    
    pub fn set_pc(&mut self, value: usize) {
        self.pc = value;
    }
    
    pub fn sp(&self) -> usize {
        self.sp
    }
    
    pub fn set_sp(&mut self, value: usize) {
        self.sp = value;
    }
    
    pub fn fp(&self) -> usize {
        self.fp
    }
    
    pub fn set_fp(&mut self, value: usize) {
        self.fp = value;
    }
    
    pub fn get_flag(&self, flag: Flag) -> bool {
        (self.flags & (1 << flag as u64)) != 0
    }
    
    pub fn set_flag(&mut self, flag: Flag, value: bool) {
        if value {
            self.flags |= 1 << flag as u64;
        } else {
            self.flags &= !(1 << flag as u64);
        }
    }
    
    pub fn clear_flags(&mut self) {
        self.flags = 0;
    }
    
    pub fn zeroize(&mut self) {
        for reg in &mut self.gpr {
            *reg = 0;
        }
        for reg in &mut self.fpr {
            *reg = 0.0;
        }
        self.pc = 0;
        self.sp = 0;
        self.fp = 0;
        self.flags = 0;
    }
}

impl Default for RegisterFile {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u64)]
pub enum Flag {
    Zero = 0,
    Carry = 1,
    Overflow = 2,
    Negative = 3,
    Equal = 4,
    Less = 5,
    Greater = 6,
    Interrupt = 7,
    Trap = 8,
}
