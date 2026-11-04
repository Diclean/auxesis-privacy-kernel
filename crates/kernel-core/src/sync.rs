//! Poison-tolerant lock helpers.
//!
//! A panic while a mutex is held poisons it; every later `.unwrap()` on that
//! lock panics again, turning one transient bug into a repeated-abort loop.
//! Recovery (`into_inner()`) with a logged error is the policy for daemon
//! state: a panic elsewhere is never a reason to abandon the daemon.

use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Lock `mutex`, recovering from a poisoned lock with a logged error.
pub fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            tracing::error!("a mutex was poisoned by a panic; recovering the guard");
            poisoned.into_inner()
        }
    }
}

/// Take a read guard from `lock`, recovering from poison with a logged error.
pub fn rwlock_read_recover<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    match lock.read() {
        Ok(guard) => guard,
        Err(poisoned) => {
            tracing::error!("an rwlock was poisoned by a panic; recovering the read guard");
            poisoned.into_inner()
        }
    }
}

/// Take a write guard from `lock`, recovering from poison with a logged error.
pub fn rwlock_write_recover<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    match lock.write() {
        Ok(guard) => guard,
        Err(poisoned) => {
            tracing::error!("an rwlock was poisoned by a panic; recovering the write guard");
            poisoned.into_inner()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn a_poisoned_lock_recovers_instead_of_panicking() {
        let mutex = Arc::new(Mutex::new(7i32));
        let poisoner = Arc::clone(&mutex);
        let _ = std::panic::catch_unwind(move || {
            let _guard = poisoner.lock().unwrap();
            panic!("poison the lock");
        });
        assert!(mutex.is_poisoned());
        assert_eq!(*lock_recover(&mutex), 7);
    }

    #[test]
    fn a_poisoned_rwlock_recovers_instead_of_panicking() {
        let lock = Arc::new(RwLock::new(7i32));
        let poisoner = Arc::clone(&lock);
        let _ = std::panic::catch_unwind(move || {
            let _guard = poisoner.write().unwrap();
            panic!("poison the lock");
        });
        assert!(lock.is_poisoned());
        assert_eq!(*rwlock_read_recover(&lock), 7);
        assert_eq!(*rwlock_write_recover(&lock), 7);
    }
}
