use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::jsonrpc::JsonRpcRequest;
use crate::stdio::command::StdioCommand;
use crate::stdio::limits::StdioLimits;
use crate::stdio::shared::lock;
use crate::stdio::transport::StdioTransport;
use crate::Transport;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ten_thousand_cancelled_calls_leave_no_pending_entries() {
    let command = StdioCommand::new("/bin/sh")
        .expect("explicit path")
        .args(["-c", "while IFS= read -r line; do :; done"]);
    let transport =
        Arc::new(StdioTransport::new_unsandboxed(command, StdioLimits::default()).unwrap());
    transport.start().await.expect("start silent server");

    for id in 0..10_000 {
        let task_transport = Arc::clone(&transport);
        let task = tokio::spawn(async move {
            task_transport
                .round_trip(
                    JsonRpcRequest::new(0, "tools/list", Value::Null),
                    Duration::from_secs(30),
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while lock(&transport.shared.pending).is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("request {id} was never registered"));
        task.abort();
        let _ = task.await;
        assert!(
            lock(&transport.shared.pending).is_empty(),
            "pending entry leaked after cancellation {id}"
        );
    }
    transport.shutdown().await.expect("shutdown silent server");
}
