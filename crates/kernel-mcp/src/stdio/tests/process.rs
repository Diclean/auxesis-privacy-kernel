use std::os::unix::process::CommandExt;
use std::time::Duration;

use tokio::process::Command;

use crate::stdio::process::{child_is_unreaped, signal_group, wait_for_leader_exit};

#[tokio::test]
async fn waitid_keeps_the_group_leader_unreaped_until_signalling_finishes() {
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("sleep 30")
        .stdout(std::process::Stdio::null());
    command.as_std_mut().process_group(0);
    let mut child = command.spawn().expect("spawn probe child");
    let pgid = child.id().expect("pid") as usize;
    assert!(child_is_unreaped(pgid as libc::pid_t));
    signal_group(pgid as libc::pid_t, libc::SIGTERM);
    assert!(wait_for_leader_exit(pgid as libc::pid_t, Duration::from_secs(2)).await);
    assert!(
        child_is_unreaped(pgid as libc::pid_t),
        "leader was reaped early"
    );
    signal_group(pgid as libc::pid_t, libc::SIGKILL);
    let _ = child.wait().await;

    let mut exited = Command::new("/bin/sh")
        .arg("-c")
        .arg("exit 0")
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("spawn exiting child");
    let pgid = exited.id().expect("pid") as usize;
    assert!(child_is_unreaped(pgid as libc::pid_t));
    let status = exited.wait().await.expect("reap");
    assert!(status.success());
    // Once reaped, waitid reports ECHILD and no caller may signal the pgid.
    assert!(!child_is_unreaped(pgid as libc::pid_t));
}
