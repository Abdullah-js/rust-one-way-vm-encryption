
pub mod detection;
pub mod response;
pub mod timing;

pub use detection::DebuggerDetector;
pub use response::DebugResponse;
pub use timing::TimingChecker;

#[derive(Debug, Clone)]
pub struct AntiDebugConfig {
    pub ptrace_detection: bool,
    pub timing_detection: bool,
    pub breakpoint_scanning: bool,
    pub proc_status_check: bool,
    pub env_checks: bool,
    pub response: DebugResponse,
}

impl Default for AntiDebugConfig {
    fn default() -> Self {
        Self {
            ptrace_detection: true,
            timing_detection: true,
            breakpoint_scanning: true,
            proc_status_check: true,
            env_checks: true,
            response: DebugResponse::Abort,
        }
    }
}

pub struct AntiDebugEngine {
    config: AntiDebugConfig,
    detector: DebuggerDetector,
    timing: TimingChecker,
    check_count: u64,
    last_detection: Option<DetectionType>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DetectionType {
    Ptrace,
    Timing,
    Breakpoint,
    ProcessStatus,
    Environment,
    ParentProcess,
    MemoryModification,
}

impl AntiDebugEngine {
    pub fn new(config: AntiDebugConfig) -> Self {
        Self {
            detector: DebuggerDetector::new(),
            timing: TimingChecker::new(),
            config,
            check_count: 0,
            last_detection: None,
        }
    }
    
    pub fn check_all(&mut self) -> Option<DetectionType> {
        self.check_count += 1;
        
        // Ptrace detection
        if self.config.ptrace_detection && self.detector.check_ptrace() {
            self.last_detection = Some(DetectionType::Ptrace);
            return self.last_detection;
        }
        
        // Timing-based detection
        if self.config.timing_detection && self.timing.check() {
            self.last_detection = Some(DetectionType::Timing);
            return self.last_detection;
        }
        
        // Breakpoint scanning
        if self.config.breakpoint_scanning && self.detector.check_breakpoints() {
            self.last_detection = Some(DetectionType::Breakpoint);
            return self.last_detection;
        }
        
        // Process status check
        if self.config.proc_status_check && self.detector.check_proc_status() {
            self.last_detection = Some(DetectionType::ProcessStatus);
            return self.last_detection;
        }
        
        // Environment checks
        if self.config.env_checks && self.detector.check_environment() {
            self.last_detection = Some(DetectionType::Environment);
            return self.last_detection;
        }
        
        None
    }
    
    pub fn respond(&self) -> ! {
        match self.config.response {
            DebugResponse::Abort => {
                self.wipe_memory();
                std::process::abort();
            }
            DebugResponse::Exit => {
                self.wipe_memory();
                std::process::exit(1);
            }
            DebugResponse::FakeOutput => {
                self.produce_fake_output();
                self.wipe_memory();
                std::process::exit(0);
            }
            DebugResponse::InfiniteLoop => {
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            }
            DebugResponse::Crash => {
                // Intentional crash
                unsafe {
                    let ptr: *mut u8 = std::ptr::null_mut();
                    *ptr = 0;
                }
                std::process::abort();
            }
        }
    }
    
    fn wipe_memory(&self) {
        // This would call into the VM to zeroize bytecode
        // In a real implementation, this would be more sophisticated
    }
    
    fn produce_fake_output(&self) {
        // Output fake data that looks legitimate but is wrong
        println!("Operation completed successfully.");
    }
    
    pub fn stats(&self) -> (u64, Option<DetectionType>) {
        (self.check_count, self.last_detection)
    }
}
