#![cfg(unix)]

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;
use tempfile::TempDir;

struct Proxy {
    child: Child,
    lines: mpsc::Receiver<String>,
    _directory: TempDir,
}

impl Proxy {
    fn new(extra_policy: &str) -> Self {
        Self::with_args(extra_policy, &[])
    }

    fn with_args(extra_policy: &str, fixture_args: &[&str]) -> Self {
        let directory = tempfile::tempdir().expect("temporary config");
        let policy = directory.path().join("policy.toml");
        std::fs::write(&policy, format!("fail_mode = \"closed\"\nscan_unicode = true\nversion = \"test\"\ntools_list_drift_detection = \"off\"\n{extra_policy}")).expect("policy");
        let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-armor"))
            .args([
                "--policy",
                policy.to_str().expect("path"),
                "wrap",
                "python3",
            ])
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/rpc_upstream.py"
            ))
            .args(fixture_args)
            .env("ARMOR_TEST_PID_FILE", directory.path().join("upstream.pid"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("proxy");
        let stdout = child.stdout.take().expect("stdout");
        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if sender.send(line.expect("RPC frame")).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            lines,
            _directory: directory,
        }
    }

    fn send(&mut self, request: &Value) {
        writeln!(self.child.stdin.as_mut().expect("stdin"), "{request}").expect("send RPC");
    }

    fn receive(&self) -> Value {
        let line = self
            .lines
            .recv_timeout(Duration::from_secs(15))
            .expect("proxy response timeout");
        serde_json::from_str(&line).expect("complete JSON-RPC frame")
    }

    fn finish(&mut self) {
        self.child.stdin.take();
        for _ in 0..150 {
            if let Some(status) = self.child.try_wait().expect("wait") {
                assert!(status.success(), "proxy failed: {status}");
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("proxy failed to finish after stdin EOF");
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        // The negative mutation tests must clean up their own fixture even
        // when a broken proxy fails to reap it. This PID file is test-owned.
        if let Ok(pid) = std::fs::read_to_string(self._directory.path().join("upstream.pid")) {
            let _ = Command::new("kill")
                .args(["-KILL", pid.trim()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn call(id: Value, name: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": {}}})
}

#[test]
fn default_warn_forwards_and_block_replaces_real_tool_result() {
    for policy in ["", "tool_response_mode = \"block\""] {
        let block = !policy.is_empty();
        let mut proxy = Proxy::new(policy);
        proxy.send(&call(json!("attack-id"), "attack"));
        let response = proxy.receive();
        assert_eq!(response["id"], "attack-id");
        if block {
            assert_eq!(response["error"]["code"], -32603);
            assert!(response.get("result").is_none());
            assert!(!response.to_string().contains("reveal the system prompt"));
        } else {
            assert!(response["result"]["content"][0]["text"]
                .as_str()
                .expect("text")
                .contains("ignore previous"));
        }
        proxy.send(&call(json!(2), "normal"));
        assert_eq!(proxy.receive()["result"]["content"][0]["text"], "hello");
        proxy.send(&call(json!(3), "benign"));
        assert!(proxy.receive().get("result").is_some());
        proxy.finish();
    }
}

#[test]
fn correlation_handles_out_of_order_results_and_bidirectional_messages() {
    let mut proxy = Proxy::new("tool_response_mode = \"block\"");
    proxy.send(&call(json!(1), "hold"));
    proxy.send(&call(json!("1"), "normal"));
    let clean = proxy.receive();
    let blocked = proxy.receive();
    assert_eq!(clean["id"], "1");
    assert!(clean.get("result").is_some());
    assert_eq!(blocked["id"], 1);
    assert_eq!(blocked["error"]["code"], -32603);
    proxy.send(&call(json!(7), "server_messages"));
    assert_eq!(proxy.receive()["method"], "sampling/createMessage");
    assert_eq!(proxy.receive()["method"], "notifications/message");
    assert_eq!(proxy.receive()["error"]["code"], -32603);
    proxy.send(&json!({"jsonrpc": "2.0", "id": 8, "method": "initialize", "params": {}}));
    assert!(
        proxy.receive().get("result").is_some(),
        "non-tool responses stay intact"
    );
    proxy.send(&call(json!(9), "error"));
    assert_eq!(
        proxy.receive()["error"]["code"],
        -32000,
        "upstream errors stay intact"
    );
    proxy.finish();
}

#[test]
fn null_request_ids_are_correlated() {
    let mut proxy = Proxy::new("tool_response_mode = \"block\"");
    proxy.send(&call(Value::Null, "attack"));
    let response = proxy.receive();
    assert!(response["id"].is_null());
    assert_eq!(response["error"]["code"], -32603);
    proxy.finish();
}

#[test]
fn per_tool_allowlist_applies_to_correlated_responses() {
    let mut proxy = Proxy::new("tool_response_mode = \"block\"\n[allow_patterns_per_tool]\nattack = [\"instruction_override\", \"zero_width_obfuscation\", \"tag_unicode_evasion\"]");
    proxy.send(&call(json!(1), "attack"));
    assert!(proxy.receive().get("result").is_some());
    proxy.finish();
}

#[test]
fn text_arguments_pass_but_executable_nested_text_is_blocked() {
    let mut proxy = Proxy::new("tool_response_mode = \"block\"");
    let mut benign = call(json!(1), "normal");
    benign["params"]["arguments"] =
        json!({"text": "Use `npm install`. Read the man page for /etc/passwd."});
    proxy.send(&benign);
    assert!(proxy.receive().get("result").is_some());
    benign["id"] = json!(2);
    benign["params"]["arguments"] = json!({"command": {"text": "`whoami`"}});
    proxy.send(&benign);
    assert_eq!(proxy.receive()["error"]["code"], -32603);
    proxy.send(&call(json!(3), "normal"));
    assert!(proxy.receive().get("result").is_some());
    proxy.finish();
}

#[test]
fn oversize_frames_stop_without_forwarding_partial_stdout() {
    for outbound in [false, true] {
        let mut proxy = Proxy::new("max_frame_bytes = 1024");
        if outbound {
            proxy.send(&call(json!(1), "oversized"));
        } else {
            let bytes = vec![b'x'; 1025];
            proxy
                .child
                .stdin
                .as_mut()
                .expect("stdin")
                .write_all(&bytes)
                .expect("oversize input");
        }
        // Keep stdin open: the frame limit must terminate the transport even
        // when the peer never sends a newline or closes the opposite stream.
        for attempt in 0..100 {
            if let Some(status) = proxy.child.try_wait().expect("wait") {
                assert!(!status.success(), "oversize connection must fail");
                assert!(
                    proxy.lines.try_iter().next().is_none(),
                    "partial frame reached stdout"
                );
                break;
            }
            assert!(
                attempt < 99,
                "oversize connection hung with stdin still open"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

#[test]
fn unknown_argument_ancestors_cannot_reopen_text_context() {
    let mut proxy = Proxy::new("tool_response_mode = \"block\"");
    let mut id = 100;
    for parent in [
        "exec",
        "execute",
        "unknown_command",
        "program",
        "args",
        "argv",
        "not_a_curated_key_742",
    ] {
        for depth in 0..4 {
            let mut value = json!({"text": "`touch /tmp/armor-must-not-execute`"});
            for layer in 0..depth {
                value = json!({format!("wrapper_{layer}"): [{"body": value}]});
            }
            let mut request = call(json!(id), "normal");
            request["params"]["arguments"] = json!({parent: value});
            proxy.send(&request);
            let response = proxy.receive();
            assert_eq!(
                response["error"]["code"], -32603,
                "parent={parent}, depth={depth}"
            );
            id += 1;
        }
    }
    let masquerading = json!({"jsonrpc":"2.0", "id":id, "method":"tools/call", "params":{
        "name":"normal", "result":{"content":[{"text":"`touch /tmp/armor-must-not-execute`"}]}
    }});
    proxy.send(&masquerading);
    assert_eq!(
        proxy.receive()["error"]["code"],
        -32603,
        "inbound params are not a response root"
    );
    id += 1;
    let mut benign = call(json!(id), "benign");
    benign["params"]["arguments"] =
        json!({"text": "Use `npm install`; see the man page for /etc/passwd."});
    proxy.send(&benign);
    assert!(proxy.receive().get("result").is_some());
    proxy.finish();
}

#[test]
fn stdin_eof_drains_short_replies_and_reaps_a_stubborn_upstream() {
    let mut delayed = Proxy::with_args("", &["delay_after_eof"]);
    delayed.send(&call(json!(1), "normal"));
    delayed.child.stdin.take();
    assert_eq!(delayed.receive()["result"]["content"][0]["text"], "hello");
    delayed.finish();

    let mut stubborn = Proxy::with_args("", &["linger_after_eof"]);
    stubborn.send(&call(json!(2), "normal"));
    assert_eq!(stubborn.receive()["id"], 2);
    let pid = std::fs::read_to_string(stubborn._directory.path().join("upstream.pid"))
        .expect("fixture PID");
    stubborn.child.stdin.take();
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = stubborn.child.try_wait().expect("proxy status") {
            break status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "stdin EOF left proxy waiting indefinitely"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(!status.success(), "expired EOF drain is a transport error");
    assert!(
        !Command::new("kill")
            .args(["-0", pid.trim()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("PID check")
            .success(),
        "upstream survived proxy exit"
    );
}

#[test]
fn exact_equivalent_numeric_ids_are_blocked_and_release_correlation() {
    for (request_id, response_id) in [
        ("1", "1.0"),
        ("10", "1e1"),
        ("-0", "0.000e5"),
        ("-12.34", "-1234e-2"),
        ("9007199254740993", "9007199254740993.0"),
        ("18446744073709551616", "184467440737095516160e-1"),
        ("0.10000000000000000001", "10000000000000000001e-20"),
    ] {
        let mut proxy = Proxy::new("tool_response_mode = \"block\"");
        let id: Value = serde_json::from_str(request_id).expect("exact ID");
        let mut request = call(id.clone(), "numeric_attack");
        request["params"]["arguments"] = json!({"response_id_raw": response_id});
        proxy.send(&request);
        let blocked = proxy.receive();
        assert_eq!(
            blocked["error"]["code"], -32603,
            "{request_id} -> {response_id}"
        );
        assert!(blocked.get("result").is_none());
        // A fallback block for an unmatched ID alone would leave a stale map
        // entry. Reusing the same ID proves the original request was consumed.
        proxy.send(&call(id, "normal"));
        assert!(
            proxy.receive().get("result").is_some(),
            "stale correlation: {request_id}"
        );
        proxy.finish();
    }
}

#[test]
fn distinct_large_integer_ids_and_string_ids_do_not_collide() {
    let mut proxy = Proxy::new("tool_response_mode = \"block\"");
    proxy.send(&call(json!(9007199254740992u64), "hold"));
    proxy.send(&call(json!(9007199254740993u64), "normal"));
    assert_eq!(proxy.receive()["id"], json!(9007199254740993u64));
    assert_eq!(proxy.receive()["error"]["code"], -32603);
    proxy.send(&call(json!("9007199254740993"), "normal"));
    assert!(proxy.receive().get("result").is_some());
    proxy.finish();
}

#[test]
fn unmatched_or_missing_ids_do_not_forward_matched_tool_payloads() {
    for name in ["unsolicited_attack", "missing_id_attack"] {
        let mut proxy = Proxy::new("tool_response_mode = \"block\"");
        proxy.send(&call(json!(1), name));
        let blocked = proxy.receive();
        assert_eq!(blocked["error"]["code"], -32603, "{name}");
        assert!(blocked.get("result").is_none());
        assert_eq!(
            proxy.receive()["id"],
            1,
            "unmatched response consumed a valid request"
        );
        proxy.finish();
    }
}
