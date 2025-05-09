// Cross-platform process lock trait and Linux implementation (POSIX semaphore). To extend for Windows, add implementation in this file.
use std::time::Duration;
use crate::challenge_error::ChallengeError;

/// Process lock guard trait
pub trait LockGuard {}

/// Cross-platform process lock trait
pub trait TpmLock: Send + Sync {
    fn acquire(&self, timeout: Duration) -> Result<Box<dyn LockGuard>, ChallengeError>;
}

// ===== Linux implementation =====
#[cfg(target_os = "linux")]
pub mod platform {
    use super::*;
    use std::ffi::CString;
    use std::os::raw::c_uint;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use std::thread::sleep;
    use libc::{sem_t, sem_open, sem_trywait, sem_post, O_CREAT, O_RDWR, S_IRUSR, S_IWUSR, SEM_FAILED};
    use std::sync::Mutex;

    struct SemPtr(*mut sem_t);
    unsafe impl Send for SemPtr {}
    unsafe impl Sync for SemPtr {}
    pub struct GlibcSemaphoreLock {
        sem: Arc<Mutex<SemPtr>>,
        name: CString,
    }
    pub struct GlibcSemaphoreGuard {
        sem: Arc<Mutex<SemPtr>>,
        name: CString,
    }

    impl LockGuard for GlibcSemaphoreGuard {}

    impl Drop for GlibcSemaphoreGuard {
        fn drop(&mut self) {
            let sem = self.sem.lock().unwrap();
            unsafe {
                if sem_post(sem.0) != 0 {
                    log::warn!("Failed to post semaphore in Drop");
                }
            }
        }
    }

    impl GlibcSemaphoreLock {
        pub fn new() -> Result<Self, ChallengeError> {
            let c_name = CString::new("/tpm_lock").unwrap();
            let sem = unsafe {
                sem_open(
                    c_name.as_ptr(),
                    O_CREAT | O_RDWR,
                    S_IRUSR | S_IWUSR,
                    1 as c_uint,
                )
            };
            if sem == SEM_FAILED {
                log::error!("Failed to open POSIX semaphore");
                return Err(ChallengeError::InternalError("Failed to open POSIX semaphore".to_string()));
            }
            Ok(Self { sem: Arc::new(Mutex::new(SemPtr(sem))), name: c_name })
        }
    }

    impl TpmLock for GlibcSemaphoreLock {
        fn acquire(&self, timeout: Duration) -> Result<Box<dyn LockGuard>, ChallengeError> {
            let start = Instant::now();
            while start.elapsed() < timeout {
                let sem = self.sem.lock().unwrap();
                let ret = unsafe { sem_trywait(sem.0) };
                drop(sem);
                if ret == 0 {
                    return Ok(Box::new(GlibcSemaphoreGuard {
                        sem: Arc::clone(&self.sem),
                        name: self.name.clone(),
                    }));
                } else {
                    sleep(Duration::from_millis(50));
                }
            }

            log::error!("TPM semaphore lock acquire timeout");
            Err(ChallengeError::InternalError("TPM semaphore lock acquire timeout".to_string()))
        }
    }

    pub fn acquire_process_lock() -> Result<Box<dyn LockGuard>, ChallengeError> {
        GlibcSemaphoreLock::new()?.acquire(Duration::from_secs(120))
    }
}

// ===== Other platforms stub =====
#[cfg(not(target_os = "linux"))]
pub mod platform {
    use super::*;
    pub fn acquire_process_lock() -> Result<Box<dyn LockGuard>, ChallengeError> {
        log::error!("acquire_process_lock is only supported on Linux platform, not implemented on other platforms!");
        Err(ChallengeError::InternalError("acquire_process_lock is only supported on Linux platform, not implemented on other platforms!".to_string()))
    }
}