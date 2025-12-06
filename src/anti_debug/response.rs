
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DebugResponse {
    Abort,
    Exit,
    FakeOutput,
    InfiniteLoop,
    Crash,
}

impl DebugResponse {
    pub fn execute(&self) -> ! {
        match self {
            DebugResponse::Abort => {
                std::process::abort();
            }
            DebugResponse::Exit => {
                std::process::exit(1);
            }
            DebugResponse::FakeOutput => {
                // Generate plausible-looking but wrong output
                println!("Success: Operation completed");
                std::process::exit(0);
            }
            DebugResponse::InfiniteLoop => {
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    // Consume CPU to frustrate analysis
                    let mut x = 0u64;
                    for i in 0..1000000 {
                        x = x.wrapping_add(i);
                    }
                    std::hint::black_box(x);
                }
            }
            DebugResponse::Crash => {
                // Intentional null pointer dereference
                unsafe {
                    let ptr: *mut u8 = std::ptr::null_mut();
                    std::ptr::write_volatile(ptr, 0);
                }
                std::process::abort();
            }
        }
    }
    
    pub fn description(&self) -> &'static str {
        match self {
            DebugResponse::Abort => "Abort process immediately",
            DebugResponse::Exit => "Exit with error code",
            DebugResponse::FakeOutput => "Produce fake output and exit normally",
            DebugResponse::InfiniteLoop => "Enter infinite loop",
            DebugResponse::Crash => "Crash intentionally",
        }
    }
}
