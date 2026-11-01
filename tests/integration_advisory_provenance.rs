use mcp_armor::control::handle_request;
use mcp_armor::policy::Policy;
use mcp_armor::{ScanHistory, Scanner};
use serde_json::{json, Value};

fn check(product: &str, version: Option<&str>) -> Value {
    let scanner = Scanner::new().expect("scanner");
    let mut args = json!({"server_name": product});
    if let Some(version) = version {
        args["server_version"] = json!(version);
    }
    let request = json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{
        "name":"armor_check_cve", "arguments":args
    }});
    handle_request(
        &request,
        &scanner,
        &Policy::default(),
        &ScanHistory::new(10),
    )["result"]["structuredContent"]
        .clone()
}

#[test]
fn corrected_product_patch_boundaries_are_queryable() {
    for (product, vulnerable, patched, id) in [
        ("fastmcp", "3.1.9", "3.2.0", "CVE-2026-27124"),
        ("MCP Inspector", "0.14.0", "0.14.1", "CVE-2025-49596"),
        ("librechat", "0.8.2-rc1", "0.8.2-rc2", "CVE-2026-22252"),
        ("weknora", "0.2.4", "0.2.5", "CVE-2026-22688"),
        ("rmcp", "1.3.9", "1.4.0", "CVE-2026-42559"),
        ("n8n-mcp", "2.47.12", "2.47.13", "CVE-2026-42282"),
        ("excel-mcp-server", "0.1.7", "0.1.8", "CVE-2026-40576"),
    ] {
        let vulnerable = check(product, Some(vulnerable));
        assert_eq!(vulnerable["affected_cves"][0]["id"], id);
        assert_eq!(vulnerable["affected_cves"][0]["version_status"], "affected");
        assert_eq!(
            vulnerable["affected_cves"][0]["source_url"],
            format!("https://nvd.nist.gov/vuln/detail/{id}")
        );
        let fixed = check(product, Some(patched));
        assert_eq!(fixed["affected_cves"], json!([]));
        assert_eq!(fixed["not_affected_cves"][0]["id"], id);
        assert_eq!(fixed["not_affected_cves"][0]["fixed_in"], patched);
    }
}

#[test]
fn a_published_affected_example_does_not_invent_a_patch_or_all_versions_range() {
    for (product, known, other) in [
        ("windsurf", "1.9544.26", "1.9544.27"),
        ("gpt-researcher", "3.3.7", "3.3.8"),
        ("litellm", "1.18.10", "1.61.0"),
    ] {
        assert_eq!(
            check(product, Some(known))["affected_cves"][0]["fixed_in"],
            "unknown"
        );
        let result = check(product, Some(other));
        assert_eq!(result["affected_cves"], json!([]));
        assert_eq!(result["not_affected_cves"], json!([]));
        assert_eq!(result["unknown_cves"][0]["fixed_in"], "unknown");
        assert_eq!(result["unknown_cves"][0]["version_status"], "unknown");
        assert_eq!(result["version_match_used"], false);
    }
}

#[test]
fn product_matching_is_exact_and_unrelated_or_unverified_ids_do_not_leak() {
    for name in [
        "mcp",
        "n8n",
        "excel",
        "n8n-nodes-mcp",
        "mcp-spec",
        "fast",
        "n/a",
        "freerdp",
        "xibo",
        "discourse",
        "",
    ] {
        let result = check(name, None);
        assert_eq!(result["affected_cves"], json!([]), "{name}");
        assert_eq!(result["unknown_cves"], json!([]), "{name}");
        assert_eq!(result["advisories_consulted"], json!([]), "{name}");
    }
    assert_eq!(
        check("FASTmcp", None)["affected_cves"][0]["product"],
        "fastmcp"
    );
    assert_eq!(
        check("@modelcontextprotocol/inspector", None)["affected_cves"][0]["product"],
        "mcp-inspector"
    );
}

#[test]
fn invalid_versions_are_explicitly_unknown() {
    let result = check("fastmcp", Some("garbage"));
    assert_eq!(result["affected_cves"], json!([]));
    assert_eq!(result["not_affected_cves"], json!([]));
    assert_eq!(result["unknown_cves"][0]["version_status"], "unknown");
}

#[test]
fn generic_names_do_not_alias_different_products_and_metadata_preserves_precedence() {
    for product in ["n8n", "excel"] {
        let result = check(product, Some("1.0.0"));
        assert_eq!(result["affected_cves"], json!([]));
        assert_eq!(result["not_affected_cves"], json!([]));
        assert_eq!(result["unknown_cves"], json!([]));
    }
    for (product, version, id) in [
        ("czlonkowski/n8n-mcp", "2.47.12", "CVE-2026-42282"),
        (
            "haris-musa/excel-mcp-server",
            "0.1.7+build1",
            "CVE-2026-40576",
        ),
        ("excel-mcp-server", "0.1.8-rc1", "CVE-2026-40576"),
        ("windsurf", "1.9544.26+build1", "CVE-2026-30615"),
    ] {
        assert_eq!(check(product, Some(version))["affected_cves"][0]["id"], id);
    }
    assert_eq!(
        check("librechat", Some("0.8.2-rc2+build"))["not_affected_cves"][0]["fixed_in"],
        "0.8.2-rc2"
    );
}

#[test]
fn legacy_simulation_inputs_are_explicit_aliases_and_never_cve_evidence() {
    let scanner = Scanner::new().expect("scanner");
    for fixture in &mcp_armor::cve::simulations().expect("fixtures").simulations {
        for (field, input, legacy) in [
            ("simulation_id", &fixture.id, false),
            ("cve_id", &fixture.legacy_cve_id, true),
        ] {
            let mut arguments = json!({});
            arguments[field] = json!(input);
            let request = json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{
                "name":"armor_simulate_attack", "arguments": arguments
            }});
            let result = handle_request(
                &request,
                &scanner,
                &Policy::default(),
                &ScanHistory::new(10),
            );
            let result = &result["result"]["structuredContent"];
            assert_eq!(result["simulation_id"], fixture.id);
            assert_eq!(result["legacy_input"], legacy);
            assert_eq!(result["actual_verdict"], "block");
            assert_eq!(result["cve_refs"], json!([]));
            assert!(result["scope"]
                .as_str()
                .expect("scope")
                .contains("not a CVE exploit"));
        }
    }
}

#[test]
fn real_control_transport_exposes_correct_advisories_and_simulation_references() {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::Duration;
    let directory = tempfile::tempdir().expect("tmp");
    let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-armor"))
        .args([
            "--policy",
            directory
                .path()
                .join("missing.toml")
                .to_str()
                .expect("path"),
            "mcp-control",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("control server");
    let stdout = child.stdout.take().expect("stdout");
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if sender
                .send(serde_json::from_str::<Value>(&line.expect("frame")).expect("JSON"))
                .is_err()
            {
                break;
            }
        }
    });
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let input = child.stdin.as_mut().expect("stdin");
        writeln!(input, "{}", json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-11-25", "capabilities":{},"clientInfo":{"name":"advisory-test","version":"1"}
        }})).expect("initialize");
        let init = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("initialize response");
        assert_eq!(init["id"], 1);
        writeln!(
            input,
            "{}",
            json!({"jsonrpc":"2.0","method":"notifications/initialized"})
        )
        .expect("initialized");
        for (id, tool, arguments) in [
            (
                2,
                "armor_check_cve",
                json!({"server_name":"fastmcp","server_version":"3.2.0"}),
            ),
            (
                3,
                "armor_check_cve",
                json!({"server_name":"windsurf","server_version":"1.9544.27"}),
            ),
            (4, "armor_check_cve", json!({"server_name":"mcp-spec"})),
            (
                5,
                "armor_simulate_attack",
                json!({"simulation_id":"ARMOR-SIM-SHELL-SUBSTITUTION"}),
            ),
            (
                6,
                "armor_check_cve",
                json!({"server_name":"n8n", "server_version":"1.0.0"}),
            ),
            (
                7,
                "armor_check_cve",
                json!({"server_name":"excel", "server_version":"0.1.7"}),
            ),
        ] {
            writeln!(input, "{}", json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool,"arguments":arguments}})).expect("RPC");
            let response = receiver
                .recv_timeout(Duration::from_secs(10))
                .expect("tool response");
            assert_eq!(response["id"], id);
            let result = &response["result"]["structuredContent"];
            match id {
                2 => assert_eq!(result["not_affected_cves"][0]["fixed_in"], "3.2.0"),
                3 => assert_eq!(result["unknown_cves"][0]["fixed_in"], "unknown"),
                4 | 6 | 7 => assert_eq!(result["affected_cves"], json!([])),
                _ => {
                    assert_eq!(result["actual_verdict"], "block");
                    assert_eq!(result["cve_refs"], json!([]));
                }
            }
        }
    }));
    child.stdin.take();
    let _ = child.kill();
    let _ = child.wait();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}
