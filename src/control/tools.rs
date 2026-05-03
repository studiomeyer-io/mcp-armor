//! Control-plane tool registry. Returns the JSON-Schema list MCP clients
//! consume via `tools/list`.

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
            }
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_has_six_entries() {
        let v = list();
        let arr = v["tools"].as_array().expect("array");
        assert_eq!(arr.len(), 6);
        let names: Vec<&str> = arr
            .iter()
            .map(|t| t["name"].as_str().expect("string"))
            .collect();
        assert!(names.contains(&"armor_scan_payload"));
        assert!(names.contains(&"armor_verify_manifest"));
        assert!(names.contains(&"armor_list_blocked"));
        assert!(names.contains(&"armor_get_policy"));
        assert!(names.contains(&"armor_check_cve"));
        assert!(names.contains(&"armor_simulate_attack"));
    }

    #[test]
    fn all_tools_read_only() {
        let v = list();
        for t in v["tools"].as_array().expect("array") {
            assert_eq!(t["annotations"]["readOnlyHint"], true);
            assert_eq!(t["annotations"]["destructiveHint"], false);
        }
    }
}
