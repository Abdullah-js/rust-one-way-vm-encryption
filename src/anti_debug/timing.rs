
use std::time::{Duration, Instant};

pub struct TimingChecker {
    baseline_ns: u64,
    threshold_multiplier: f64,
    calibration_samples: usize,
    history: Vec<u64>,
    max_history: usize,
}

impl TimingChecker {
    pub fn new() -> Self {
        let mut checker = Self {
            baseline_ns: 0,
            threshold_multiplier: 5.0,
            calibration_samples: 100,
            history: Vec::new(),
            max_history: 1000,
        };
        checker.calibrate();
        checker
    }
    
    fn calibrate(&mut self) {
        let mut total = 0u64;
        
        for _ in 0..self.calibration_samples {
            let start = Instant::now();
            self.timing_payload();
            let elapsed = start.elapsed().as_nanos() as u64;
            total += elapsed;
        }
        
        self.baseline_ns = total / self.calibration_samples as u64;
        
        // Minimum baseline to avoid division issues
        if self.baseline_ns < 100 {
            self.baseline_ns = 100;
        }
    }
    
    #[inline(never)]
    fn timing_payload(&self) {
        // Simple operations that are fast but can't be optimized away
        let mut x = 0u64;
        for i in 0..100 {
            x = x.wrapping_add(i);
            x = x.wrapping_mul(7);
            x = x ^ (x >> 13);
        }
        std::hint::black_box(x);
    }
    
    pub fn check(&mut self) -> bool {
        let start = Instant::now();
        self.timing_payload();
        let elapsed = start.elapsed().as_nanos() as u64;
        
        // Store in history
        self.history.push(elapsed);
        if self.history.len() > self.max_history {
            self.history.remove(0);
        }
        
        // Check against threshold
        let threshold = (self.baseline_ns as f64 * self.threshold_multiplier) as u64;
        
        if elapsed > threshold {
            return true;
        }
        
        // Check for suspicious patterns in history
        if self.history.len() >= 10 {
            let recent: Vec<_> = self.history.iter().rev().take(10).collect();
            let avg: u64 = recent.iter().copied().map(|x| *x).sum::<u64>() / 10;
            
            // If recent average is much higher than baseline, suspicious
            if avg > threshold / 2 {
                return true;
            }
        }
        
        false
    }
    
    #[cfg(target_arch = "x86_64")]
    pub fn check_rdtsc(&self) -> bool {
        unsafe {
            let start = std::arch::x86_64::_rdtsc();
            
            // Simple operations
            let mut x = 0u64;
            for i in 0..50 {
                x = x.wrapping_add(i);
            }
            std::hint::black_box(x);
            
            let end = std::arch::x86_64::_rdtsc();
            let cycles = end.saturating_sub(start);
            
            // If it took more than 50000 cycles, suspicious
            // Normal execution should be < 1000 cycles
            cycles > 50000
        }
    }
    
    #[cfg(not(target_arch = "x86_64"))]
    pub fn check_rdtsc(&self) -> bool {
        false
    }
    
    pub fn check_consistency(&mut self) -> bool {
        let measurements: Vec<u64> = (0..5)
            .map(|_| {
                let start = Instant::now();
                self.timing_payload();
                start.elapsed().as_nanos() as u64
            })
            .collect();
        
        // Calculate variance
        let mean: f64 = measurements.iter().sum::<u64>() as f64 / 5.0;
        let variance: f64 = measurements
            .iter()
            .map(|&x| {
                let diff = x as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / 5.0;
        
        let stddev = variance.sqrt();
        
        // High variance indicates stepping/interference
        stddev > mean * 2.0
    }
    
    pub fn inline_check(&self) -> bool {
        let start = Instant::now();
        
        // Lightweight inline check
        let mut x = 0u32;
        for i in 0..20 {
            x = x.wrapping_add(i);
        }
        std::hint::black_box(x);
        
        let elapsed = start.elapsed();
        
        // Very tight threshold for inline checks
        elapsed > Duration::from_micros(100)
    }
}

impl Default for TimingChecker {
    fn default() -> Self {
        Self::new()
    }
}
