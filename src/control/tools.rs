//! Control-plane tool registry. Returns the JSON-Schema list MCP clients
//! consume via `tools/list`.
//!
//! v0.2 expansion: 9 tools (was 6). New entries:
//!   - `armor_get_keystore` — list pinned TOFU keys (read-only).
//!   - `armor_verify_bundle` — parse cosign sigstore.json + structural verify
//!     (read-only, offline).
//!   - `armor_rekor_lookup` — query the Sigstore Rekor transparency log
//!     for a manifest's inclusion (read-only, online — hits Rekor REST).
//!     Behind `--features sigstore-bridge` at build time; when the feature
//!     is off the schema is still listed (so clients see the surface) but
//!     calls return `error.code = -32004` "feature disabled".

use serde_json::{json, Value};

pub fn list() -> Value {
    json!({
        "tools": [
            {
                "name": "armor_scan_payload",
                "description": "Scan an arbitrary payload for prompt-injection patterns.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload": {"type": "string"},
                        "direction": {"type": "string", "enum": ["inbound", "outbound"]}
                    },
                    "required": ["payload", "direction"]
                },
                "annotations": {
                    "readOnlyHint": true,
                    "destructiveHint": false
                }
            },
            {
                "name": "armor_verify_manifest",
                "description": "Verify Ed25519 signature over canonical-JSON form of a tools/list response.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "tools_list_response": {"type": "object"},
                        "public_key_b64": {"type": "string"},
                        "signature_b64": {"type": "string"},
                        "signed_at_iso": {"type": "string"}
                    },
                    "required": ["tools_list_response", "public_key_b64", "signature_b64"]
                },
                "annotations": {
                    "readOnlyHint": true,
                    "destructiveHint": false
                }
            },
            {
                "name": "armor_list_blocked",
                "description": "Read recent blocked tool calls from the in-memory ring buffer.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "since_iso": {"type": "string"},
                        "limit": {"type": "integer", "minimum": 1}
                    }
                },
                "annotations": {
                    "readOnlyHint": true,
                    "destructiveHint": false
                }
            },
            {
                "name": "armor_get_policy",
                "description": "Return the active policy: file path, rules, fail mode, scan flags, version.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                },
                "annotations": {
                    "readOnlyHint": true,
                    "destructiveHint": false
                }
            },
            {
                "name": "armor_check_cve",
                "description": "Look up a server name in the curated CVE feed and return affected entries.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "server_name": {"type": "string"},
                        "server_version": {"type": "string"}
                    },
                    "required": ["server_name"]
                },
                "annotations": {
                    "readOnlyHint": true,
                    "destructiveHint": false
                }
            },
            {
                "name": "armor_simulate_attack",
                "description": "Run the static simulate_payload for a CVE through the scanner. Never spawns the upstream binary.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "cve_id": {"type": "string"}
                    },
                    "required": ["cve_id"]
                },
                "annotations": {
                    "readOnlyHint": true,
                    "destructiveHint": false
                }
            },
            {
                "name": "armor_get_keystore",
                "description": "v0.2 — List pinned TOFU maintainer public keys (server_name + fingerprint + pinned_at_iso). Read-only inspection of the keystore configured at sidecar startup (no caller-supplied path — operator-only via `--keystore` flag).",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": false
                },
                "annotations": {
                    "readOnlyHint": true,
                    "destructiveHint": false
                }
            },
            {
                "name": "armor_verify_bundle",
                "description": "v0.2 — Parse a cosign sigstore.json bundle and structurally verify the Rekor SignedEntryTimestamp shape. Offline.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "bundle_json": {"type": "string"}
                    },
                    "required": ["bundle_json"]
                },
                "annotations": {
                    "readOnlyHint": true,
                    "destructiveHint": false
                }
            },
            {
                "name": "armor_rekor_lookup",
                "description": "v0.2 — Query the Sigstore Rekor transparency log for inclusion of a manifest's artifact hash. Requires --features sigstore-bridge at build time. Network call.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "tools_list_response": {"type": "object"},
                        "rekor_url": {"type": "string", "description": "Override Rekor endpoint; defaults to https://rekor.sigstore.dev"}
                    },
                    "required": ["tools_list_response"]
                },
                "annotations": {
                    "readOnlyHint": true,
                    "destructiveHint": false
                }
            },
            {
                "name": "armor_get_drift_history",
                "description": "v0.5 Layer 7 — Inspect the tools-list schema-drift baselines persisted by `mcp-armor wrap`. Read-only. Optional `program` arg narrows the report to one upstream; omit it to list every pinned baseline. Closes the Rug-Pull / Silent-Redefinition threat class (Invariant Labs, CyberArk Full-Schema Poisoning).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "program": {
                            "type": "string",
                            "description": "When set, return the full per-tool fingerprint detail for one program. When omitted, return a summary list of every pinned baseline."
                        }
                    },
                    "additionalProperties": false
                },
                "annotations": {
                    "readOnlyHint": true,
                    "destructiveHint": false
                }
            }
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_has_ten_entries_v05() {
        let v = list();
        let arr = v["tools"].as_array().expect("array");
        assert_eq!(
            arr.len(),
            10,
            "v0.5 expects 10 control-plane tools (6 v0.1 + 3 v0.2 + 1 v0.5 drift)"
        );
        let names: Vec<&str> = arr
            .iter()
            .map(|t| t["name"].as_str().expect("string"))
            .collect();
        for required in [
            "armor_scan_payload",
            "armor_verify_manifest",
            "armor_list_blocked",
            "armor_get_policy",
            "armor_check_cve",
            "armor_simulate_attack",
            "armor_get_keystore",
            "armor_verify_bundle",
            "armor_rekor_lookup",
            "armor_get_drift_history",
        ] {
            assert!(names.contains(&required), "missing tool: {required}");
        }
    }

    #[test]
    fn all_tools_read_only() {
        let v = list();
        for t in v["tools"].as_array().expect("array") {
            assert_eq!(
                t["annotations"]["readOnlyHint"], true,
                "tool {} must be readOnly",
                t["name"]
            );
            assert_eq!(
                t["annotations"]["destructiveHint"], false,
                "tool {} must not be destructive",
                t["name"]
            );
        }
    }
}
