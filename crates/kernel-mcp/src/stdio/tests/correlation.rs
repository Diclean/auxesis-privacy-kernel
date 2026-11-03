use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use tokio::sync::{oneshot, watch, Notify, Semaphore};

use crate::stdio::framing::dispatch;
use crate::stdio::shared::{lock, Exit, Shared};

fn test_shared() -> Shared {
    let (exit, _rx) = watch::channel(Exit::Running);
    Shared {
        pending: Mutex::new(HashMap::new()),
        next_id: AtomicU64::new(1),
        unsolicited: AtomicUsize::new(0),
        pgid: AtomicUsize::new(0),
        inflight: Semaphore::new(1),
        dead: AtomicBool::new(false),
        output_bytes: AtomicUsize::new(0),
        kill: Notify::new(),
        exit,
    }
}

#[test]
fn a_delivered_response_reaches_only_its_registered_waiter() {
    let shared = test_shared();
    let (tx, mut rx) = oneshot::channel();
    lock(&shared.pending).insert(9, tx);
    let response = br#"{"jsonrpc":"2.0","id":9,"result":{"ok":true}}"#;
    assert!(dispatch(response, &shared).is_ok());
    let delivered = rx.try_recv().expect("waiter was not served");
    assert!(delivered.is_ok());
    assert_eq!(shared.unsolicited.load(Ordering::SeqCst), 0);
}

#[test]
fn unknown_response_id_is_counted_and_never_delivered() {
    let shared = test_shared();
    let (tx, mut rx) = oneshot::channel();
    lock(&shared.pending).insert(9, tx);
    // A response for an id no one is waiting on must not go to id 9.
    let response = br#"{"jsonrpc":"2.0","id":10,"result":{}}"#;
    assert!(dispatch(response, &shared).is_ok());
    assert_eq!(shared.unsolicited.load(Ordering::SeqCst), 1);
    assert!(lock(&shared.pending).contains_key(&9));
    assert!(
        rx.try_recv().is_err(),
        "a foreign response was misdelivered"
    );
}
