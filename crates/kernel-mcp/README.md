# kernel-mcp

A bounded client for MCP (Model Context Protocol) tool servers over stdio and
HTTP. Frames are read with a size limit before they are parsed, untrusted
strings are sanitised before they reach a log, and a stdio server can be
confined to a sandbox profile.

The crate speaks JSON-RPC 2.0 and knows nothing about any one vendor.

```rust
use kernel_mcp::jsonrpc::JsonRpcRequest;
use serde_json::json;

let request = JsonRpcRequest::new(1, "tools/list", json!({}));
assert_eq!(request.jsonrpc, "2.0");
println!("{}", serde_json::to_string(&request).expect("serialise"));
```

## Licence

Apache-2.0. See the repository `LICENSE` and `NOTICE`.
