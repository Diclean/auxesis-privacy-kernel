//! Helpers shared by the kernel-privacy integration tests.

mod timing {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-support/timing.rs"
    ));
}

pub use timing::fastest;
