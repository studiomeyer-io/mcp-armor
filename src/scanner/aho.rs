use crate::error::ArmorError;
use aho_corasick::{AhoCorasick, MatchKind};

/// Aho-Corasick prefilter. Runs ASCII-case-insensitive on a small set of
/// trigger strings — it is the fast first pass.
pub struct AhoStage {
    ac: AhoCorasick,
    pattern_ids: Vec<String>,
}

impl AhoStage {
    pub fn new(pattern_ids: &[String]) -> Result<Self, ArmorError> {
        let mut needles: Vec<&str> = Vec::new();
        let mut ids: Vec<String> = Vec::new();
        for pid in pattern_ids {
            for needle in trigger_strings(pid) {
                needles.push(needle);
                ids.push(pid.clone());
            }
        }
        let ac = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(&needles)
            .map_err(|e| ArmorError::InvalidPattern(format!("aho-build: {e}")))?;
        Ok(Self {
            ac,
            pattern_ids: ids,
        })
    }

    pub fn matches(&self, haystack: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for m in self.ac.find_iter(haystack) {
            if let Some(pid) = self.pattern_ids.get(m.pattern().as_usize()) {
                if !out.contains(pid) {
                    out.push(pid.clone());
                }
            }
        }
        out
    }
}

/// Map a pattern id to the trigger strings the prefilter looks for. The regex
/// stage refines hits — Aho only needs to be a cheap first cut.
fn trigger_strings(pattern_id: &str) -> &'static [&'static str] {
    match pattern_id {
        "shell_substitution" => &["$(", "`", "; sh", "| sh", "&& sh"],
        "localhost_callback" => &["127.0.0.1", "localhost:", "0.0.0.0"],
        "auto_invoke_privileged" => &["auto_invoke", "/etc/passwd", "/etc/shadow", "id_rsa"],
        "javascript_uri" => &["javascript:", "data:text/html"],
        "instruction_override" => &[
            "ignore previous",
            "ignore prior",
            "disregard the above",
            "system prompt",
        ],
        "tag_injection" => &["</tool_result>", "</system>", "<system>", "</user>"],
        "zero_width_obfuscation" => &["ignore previous", "ignore prior"],
        "html_script_inject" => &["<script", "</script", "onerror=", "onload="],
        "tag_unicode_evasion" => &["ignore previous", "reveal", "secret"],
        "fullwidth_evasion" => &["sudo", "rm -rf", "curl", "wget"],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefilter_hits_shell_subst() {
        let stage = AhoStage::new(&["shell_substitution".to_string()]).expect("build");
        let hits = stage.matches("ls; $(whoami)");
        assert_eq!(hits, vec!["shell_substitution".to_string()]);
    }

    #[test]
    fn prefilter_no_hit_on_clean() {
        let stage = AhoStage::new(&["shell_substitution".to_string()]).expect("build");
        assert!(stage.matches("ls -la").is_empty());
    }

    #[test]
    fn prefilter_is_case_insensitive() {
        let stage = AhoStage::new(&["instruction_override".to_string()]).expect("build");
        let hits = stage.matches("IGNORE PREVIOUS messages");
        assert!(hits.contains(&"instruction_override".to_string()));
    }
}
