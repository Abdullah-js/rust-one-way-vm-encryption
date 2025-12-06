
use std::fs;
use std::process::Command;

pub struct DebuggerDetector {
    critical_addresses: Vec<usize>,
}

impl DebuggerDetector {
    pub fn new() -> Self {
        Self {
            critical_addresses: Vec::new(),
        }
    }
    
    pub fn add_critical_address(&mut self, addr: usize) {
        self.critical_addresses.push(addr);
    }
    
    #[cfg(target_os = "linux")]
    pub fn check_ptrace(&self) -> bool {
        use std::os::unix::process::CommandExt;
        
        // Try to ptrace ourselves - if already traced, this fails
        unsafe {
            let result = libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);
            if result == -1 {
                return true; // Debugger detected
            }
            // Detach
            libc::ptrace(libc::PTRACE_DETACH, 0, 0, 0);
        }
        
        false
    }
    
    #[cfg(target_os = "macos")]
    pub fn check_ptrace(&self) -> bool {
        // macOS ptrace check
        unsafe {
            let mut info: libc::kinfo_proc = std::mem::zeroed();
            let mut size = std::mem::size_of::<libc::kinfo_proc>();
            let mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, libc::getpid()];
            
            if libc::sysctl(
                mib.as_ptr() as *mut _,
                4,
                &mut info as *mut _ as *mut _,
                &mut size,
                std::ptr::null_mut(),
                0,
            ) == 0 {
                // Check P_TRACED flag
                return (info.kp_proc.p_flag & 0x00000800) != 0;
            }
        }
        false
    }
    
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub fn check_ptrace(&self) -> bool {
        false // Not implemented for other platforms
    }
    
    #[cfg(target_os = "linux")]
    pub fn check_proc_status(&self) -> bool {
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("TracerPid:") {
                    let pid: i32 = line
                        .split(':')
                        .nth(1)
                        .and_then(|s| s.trim().parse().ok())
                        .unwrap_or(0);
                    return pid != 0;
                }
            }
        }
        false
    }
    
    #[cfg(not(target_os = "linux"))]
    pub fn check_proc_status(&self) -> bool {
        false
    }
    
    pub fn check_environment(&self) -> bool {
        let debug_vars = [
            "DYLD_INSERT_LIBRARIES", // macOS dylib injection
            "LD_PRELOAD",            // Linux preload
            "GHIDRA_HOME",           // Ghidra
            "IDA_HOME",              // IDA Pro
            "BINARYNINJA",           // Binary Ninja
            "_JAVA_OPTIONS",         // Java debugging
            "DEBUGGER",              // Generic
        ];
        
        for var in debug_vars {
            if std::env::var(var).is_ok() {
                return true;
            }
        }
        
        false
    }
    
    pub fn check_breakpoints(&self) -> bool {
        for &addr in &self.critical_addresses {
            unsafe {
                let ptr = addr as *const u8;
                // Check if readable and contains INT3
                if !ptr.is_null() {
                    // Note: In real implementation, need to handle page faults
                    // This is simplified
                    let byte = std::ptr::read_volatile(ptr);
                    if byte == 0xCC {
                        return true;
                    }
                }
            }
        }
        false
    }
    
    pub fn check_parent_process(&self) -> bool {
        let debugger_names = [
            "lldb", "gdb", "ida", "ida64", "x64dbg", "x32dbg",
            "ollydbg", "windbg", "radare2", "r2", "ghidra",
            "hopper", "binary ninja", "binaryninja",
        ];
        
        #[cfg(target_os = "linux")]
        {
            if let Ok(cmdline) = fs::read_to_string(format!("/proc/{}/cmdline", unsafe { libc::getppid() })) {
                let lower = cmdline.to_lowercase();
                for name in debugger_names {
                    if lower.contains(name) {
                        return true;
                    }
                }
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            let output = Command::new("ps")
                .args(["-o", "comm=", "-p", &format!("{}", unsafe { libc::getppid() })])
                .output();
            
            if let Ok(output) = output {
                let parent = String::from_utf8_lossy(&output.stdout).to_lowercase();
                for name in debugger_names {
                    if parent.contains(name) {
                        return true;
                    }
                }
            }
        }
        
        false
    }
    
    #[cfg(target_arch = "x86_64")]
    pub fn check_hardware_breakpoints(&self) -> bool {
        // Hardware breakpoint checking would require kernel cooperation
        // or specific system calls. This is a placeholder.
        false
    }
    
    #[cfg(not(target_arch = "x86_64"))]
    pub fn check_hardware_breakpoints(&self) -> bool {
        false
    }
    
    pub fn check_virtual_machine(&self) -> bool {
        // Check for common VM indicators
        let vm_indicators = [
            "VBOX", "VMWARE", "QEMU", "VIRTUAL", "XEN", "KVM",
        ];
        
        // Check CPU vendor
        #[cfg(target_arch = "x86_64")]
        {
            // Would use CPUID to check for hypervisor bit
            // Simplified check via /proc/cpuinfo on Linux
            #[cfg(target_os = "linux")]
            {
                if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
                    let upper = cpuinfo.to_uppercase();
                    for indicator in vm_indicators {
                        if upper.contains(indicator) {
                            return true;
                        }
                    }
                }
            }
        }
        
        false
    }
}

impl Default for DebuggerDetector {
    fn default() -> Self {
        Self::new()
    }
}
