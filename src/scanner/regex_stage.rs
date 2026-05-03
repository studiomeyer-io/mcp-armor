use crate::error::ArmorError;
use regex::Regex;

/// Regex stage. Compiled once at construction time, run on every payload.
pub struct RegexStage {
    rules: Vec<(String, Regex)>,
}

impl RegexStage {
    pub fn new(pattern_ids: &[String]) -> Result<Self, ArmorError> {
        let mut rules: Vec<(String, Regex)> = Vec::new();
        for pid in pattern_ids {
            for source in regex_sources(pid) {
                let r = Regex::new(source)?;
                rules.push((pid.clone(), r));
            }
        }
        Ok(Self { rules })
    }

    pub fn matches(&self, haystack: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for (pid, r) in &self.rules {
            if r.is_match(haystack) && !out.contains(pid) {
                out.push(pid.clone());
            }
        }
        out
    }
}

/// Regex sources keyed by pattern id. Multiple per id allowed.
fn regex_sources(pattern_id: &str) -> &'static [&'static str] {
    match pattern_id {
        "shell_substitution" => &[r"\$\([^)]*\)", r"`[^`]+`", r"(?i);\s*(sh|bash|curl|wget)\b"],
        "localhost_callback" => &[r"https?://(127\.0\.0\.1|localhost|0\.0\.0\.0)(:\d+)?/"],
        "auto_invoke_privileged" => &[
            r#""auto_invoke"\s*:\s*true"#,
            r"/etc/(passwd|shadow|sudoers)",
            r"\.ssh/id_(rsa|ed25519|ecdsa)",
        ],
        "javascript_uri" => &[r"(?i)javascript:", r"(?i)data:text/html"],
        "instruction_override" => &[
            r"(?i)ignore\s+(previous|prior|all)\s+(instructions|messages|prompts)",
            r"(?i)disregard\s+(the\s+)?above",
            r"(?i)reveal\s+(the\s+)?system\s+prompt",
        ],
        "tag_injection" => &[r"</tool_result>", r"<system>", r"</system>", r"</user>"],
        "zero_width_obfuscation" => &[
            // Catches normalized form. Original raw form has zero-widths
            // stripped by the unicode stage before it lands here.
            r"(?i)ignore\s+(previous|prior)\s+instructions",
        ],
        "html_script_inject" => &[r"(?i)<script[\s>]", r"(?i)on(error|load|click)\s*="],
        "tag_unicode_evasion" => &[
            // post-normalization the tag chars are gone. Match the
            // resulting clear-text giveaway.
            r"(?i)reveal.+(secret|password|token|key)",
            r"(?i)ignore\s+previous",
        ],
        "fullwidth_evasion" => &[
            // post-NFKC fullwidth becomes ascii — match the ascii forms.
            r"(?i)\bsudo\s+rm\s+-rf\b",
            r"(?i)\bcurl\s+http",
            r"(?i)\bwget\s+http",
        ],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_subst_regex_matches() {
        let s = RegexStage::new(&["shell_substitution".to_string()]).expect("build");
        assert!(!s.matches("ls; $(whoami)").is_empty());
        assert!(s.matches("ls -la").is_empty());
    }

    #[test]
    fn javascript_uri_matches_case_insensitive() {
        let s = RegexStage::new(&["javascript_uri".to_string()]).expect("build");
        assert!(!s.matches("JAVASCRIPT:alert(1)").is_empty());
    }

    #[test]
    fn instruction_override_matches() {
        let s = RegexStage::new(&["instruction_override".to_string()]).expect("build");
        assert!(!s.matches("Please ignore previous instructions").is_empty());
        assert!(!s.matches("disregard above").is_empty());
    }
}
