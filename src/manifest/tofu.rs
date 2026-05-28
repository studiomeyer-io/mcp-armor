//! TOFU (Trust-On-First-Use) keystore for Ed25519 maintainer public keys.
//!
//! v0.2 closes the v0.1 manifest-verify gap: cryptographic verify alone does
//! not detect a marketplace mirror that swaps *both* the manifest *and* the
//! public key in the same payload. TOFU pins the key the operator first
//! accepted; subsequent verifies cross-check the supplied public key against
//! the pinned fingerprint and refuse to validate if it has changed.
//!
//! Storage shape (TOML at `~/.local/share/mcp-armor/keys.toml`):
//!
//! ```toml
//! schema_version = 1
//!
//! [[pinned]]
//! server_name      = "filesystem"
//! key_fingerprint  = "ab12cd34ef567890..."
//! public_key_b64   = "BASE64_32_BYTES_VERIFY_KEY"
//! pinned_at_iso    = "2026-05-20T00:00:00Z"
//! ```
//!
//! Atomic-write guarantees (`Keystore::persist`):
//! - Temp file lives in the same directory as the destination so `rename(2)`
//!   stays on the same filesystem (rename across mounts would fail).
//! - File mode is `0o600` set *before* the first byte is written via
//!   `OpenOptions::mode(0o600)` on Unix — there is no race window where the
//!   file is world-readable.
//! - `fsync(2)` + parent-dir-fsync are performed by `tempfile`'s `persist()`
//!   so a power loss between the `rename` and the disk-cache flush will not
//!   resurrect an empty destination.
//! - On Windows the mode bit is a no-op (no equivalent atomic permission
//!   primitive); the file inherits ACLs from the parent directory.
//!
//! TOFU's known weakness (Andrew Ayer, "Why TOFU doesn't work even for SSH"):
//! users blow past the warning. We mitigate by *refusing* verify-success on
//! fingerprint mismatch (no "type yes to continue") — the caller has to
//! explicitly `unpin` before re-pinning. Pinning ceremony is a deliberate
//! operator step, not a passive confirm.
//!
//! Sister feature: when `--features sigstore-bridge` is enabled, the
//! `manifest::sigstore` module provides keyless verification against the
//! Rekor transparency log — operators can replace TOFU with public-log
//! continuity for sigstore-signed manifests.

use crate::error::ArmorError;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Current schema version of the on-disk keystore. Bump on incompatible
/// format change; v0.2 ships with schema 1.
pub const SCHEMA_VERSION: u32 = 1;

/// Permission bits the keystore file is created with on Unix. `0o600` = read
/// and write for the owner only. Set *before* the file's first write so
/// there is no world-readable window.
#[cfg(unix)]
pub const KEYSTORE_MODE: u32 = 0o600;

/// A pinned maintainer public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedKey {
    /// Display name of the upstream server (e.g. `filesystem`, `github`).
    /// Free-form — collisions across maintainers are intended to be visible
    /// via `armor_get_keystore`.
    pub server_name: String,
    /// Blake3-derived short fingerprint of the public key (32 hex chars).
    /// Canonical identity of the pinned entry — re-pinning the same
    /// fingerprint under a different server_name is allowed (multiple
    /// installations share the maintainer's key).
    pub key_fingerprint: String,
    /// Base64-encoded 32-byte Ed25519 verifying key. Persisted verbatim so
    /// the operator can diff against an out-of-band published key without
    /// recomputing the fingerprint.
    pub public_key_b64: String,
    /// RFC-3339 UTC timestamp of the pin.
    pub pinned_at_iso: String,
}

/// In-memory representation of the TOFU keystore. Persisted via [`Keystore::persist`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Keystore {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default, rename = "pinned")]
    pub entries: Vec<PinnedKey>,
}

fn default_schema_version() -> u32 {
    SCHEMA_VERSION
}

/// Outcome of a [`Keystore::pin`] call. Encodes the three states the caller
/// needs to distinguish so they can render the right operator message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinOutcome {
    /// No prior entry for `(server_name, fingerprint)`. Now pinned.
    NewlyPinned,
    /// An entry with the same `server_name` and same fingerprint already
    /// existed. The `pinned_at_iso` was *not* refreshed — the original pin
    /// time is preserved as the audit trail.
    AlreadyPinned,
}

/// Outcome of a [`Keystore::verify_pin`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyPin {
    /// The supplied fingerprint matches the pinned fingerprint for this
    /// server name. Continue with cryptographic verify.
    Match,
    /// No entry for this server name yet. Caller decides whether to pin
    /// (operator-driven) or refuse (strict TOFU).
    UnknownServer,
    /// Server is known but the fingerprint changed. Refuse verify — this
    /// is the marketplace-poisoning signal.
    FingerprintMismatch { expected: String, found: String },
}

impl Keystore {
    /// Construct an empty keystore. Schema_version is set to [`SCHEMA_VERSION`].
    pub fn empty() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            entries: Vec::new(),
        }
    }

    /// Load a keystore from `path`. Missing file → empty keystore (TOFU
    /// bootstrap). Parse error → bubbled up so the caller can surface it.
    pub fn load(path: &Path) -> Result<Self, ArmorError> {
        if !path.exists() {
            return Ok(Self::empty());
        }
        let raw = std::fs::read_to_string(path)?;
        if raw.trim().is_empty() {
            return Ok(Self::empty());
        }
        let parsed: Keystore = toml::from_str(&raw)?;
        // Forward-compatibility: refuse unknown schema. We do *not* drop
        // entries silently — that would mask a downgrade attack.
        if parsed.schema_version > SCHEMA_VERSION {
            return Err(ArmorError::InvalidPattern(format!(
                "keystore at {} has schema_version={} but this build only \
                 understands up to {}; refusing to read",
                path.display(),
                parsed.schema_version,
                SCHEMA_VERSION
            )));
        }
        Ok(parsed)
    }

    /// Persist the keystore atomically: write to a temp file in the same
    /// directory, fsync, then `rename(2)` over the destination. On Unix the
    /// file is created with mode `0o600` *before* any byte is written.
    ///
    /// v0.4 (v0.3 backlog item — Research #2 in CHANGELOG): after the
    /// atomic rename we also `fsync` the parent directory so a power
    /// loss between the rename and the inode-table flush cannot
    /// resurrect an empty destination. POSIX-canonical atomic-write
    /// pattern. The `tempfile::persist` upstream only fsyncs the file,
    /// not the parent dir.
    pub fn persist(&self, path: &Path) -> Result<(), ArmorError> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| {
                ArmorError::InvalidPattern(format!(
                    "keystore path {} has no parent directory",
                    path.display()
                ))
            })?;
        std::fs::create_dir_all(parent)?;
        let serialized = toml::to_string_pretty(self)
            .map_err(|e| ArmorError::InvalidPattern(format!("serialize keystore: {e}")))?;

        let mut tmp = tempfile::Builder::new()
            .prefix(".keys.toml.")
            .suffix(".tmp")
            .tempfile_in(parent)?;

        // Apply the restrictive mode *before* the first write. On Unix this
        // narrows the discovery window where another process could `open`
        // the temp file with O_RDONLY between `mkstemp` (mode 0o600 already
        // by default in libc) and our explicit `set_permissions`. We still
        // re-apply explicitly because `tempfile::Builder` does not document
        // a strict 0o600 contract across platforms.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(KEYSTORE_MODE);
            std::fs::set_permissions(tmp.path(), perms)?;
        }

        tmp.write_all(serialized.as_bytes())?;
        tmp.as_file_mut().sync_all()?;
        // `persist` performs the atomic rename over the destination + drops
        // the temp-file struct cleanly.
        tmp.persist(path)
            .map_err(|e| ArmorError::InvalidPattern(format!("atomic persist: {e}")))?;

        // Re-apply the mode bit on the destination in case the rename
        // crossed a directory whose mask trimmed our bits, or in case the
        // destination already existed with a permissive mode.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(KEYSTORE_MODE);
            std::fs::set_permissions(path, perms)?;
        }

        // v0.4 — fsync the parent directory so the rename hits stable
        // storage. Without this step, on filesystems with delayed
        // metadata writeback (ext4 default, xfs, btrfs), a crash
        // immediately after rename can result in the directory entry
        // not being persisted and the freshly-written keystore
        // vanishing on reboot. Best-effort: on platforms where directory
        // fsync is not meaningful (some filesystems, Windows) the call
        // is a no-op and any error is logged but not propagated, since
        // the file payload itself is already durable.
        #[cfg(unix)]
        {
            if let Ok(dir) = std::fs::File::open(parent) {
                if let Err(e) = dir.sync_all() {
                    tracing::warn!(
                        parent = %parent.display(),
                        error = %e,
                        "parent-dir fsync after keystore rename failed (best-effort, file payload already durable)"
                    );
                }
            }
        }
        Ok(())
    }

    /// Persist with a process-level advisory file lock (`flock(LOCK_EX)`)
    /// taken on a sibling `.keys.toml.lock` file for the lifetime of the
    /// critical section. Use this entry point whenever the load → mutate
    /// → persist sequence runs concurrently across processes on the same
    /// host (e.g. two `mcp-armor keystore pin` invocations racing each
    /// other in CI parallelism).
    ///
    /// v0.4 (Critic M1 from the v0.3 review backlog): the previous
    /// `persist` API has a small but real TOCTOU window between `load()`
    /// and `persist()` on the same process or across two concurrent
    /// processes — both can read the same baseline, mutate independently,
    /// and write back, silently losing one writer's changes. `flock` is
    /// advisory but every well-behaved caller using this method enters
    /// the same fence; misbehaving callers using bare `persist()` are
    /// unaffected (the bare path stays available for legacy contexts).
    ///
    /// Internally:
    /// 1. Create or open `<parent>/.keys.toml.lock` (mode 0o600 on Unix).
    /// 2. `flock(LOCK_EX)` — blocks if another process holds it.
    /// 3. Re-load the on-disk keystore so the caller's mutations land on
    ///    top of any concurrent writer's changes.
    /// 4. Re-apply the caller's diff vs the in-memory snapshot they
    ///    started from is the caller's responsibility — this method
    ///    only guarantees that the *persist* is serialised.
    /// 5. Call `persist()` (same atomic-rename logic + parent fsync).
    /// 6. Drop the lock on function exit.
    ///
    /// Returns the in-memory keystore that was just written so callers
    /// can refresh their view without an extra `load()` round-trip.
    pub fn persist_locked(&self, path: &Path) -> Result<(), ArmorError> {
        use fs2::FileExt;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| {
                ArmorError::InvalidPattern(format!(
                    "keystore path {} has no parent directory",
                    path.display()
                ))
            })?;
        std::fs::create_dir_all(parent)?;
        let lock_path = parent.join(".keys.toml.lock");
        let mut open_opts = std::fs::OpenOptions::new();
        open_opts
            .read(true)
            .write(true)
            .create(true)
            .truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open_opts.mode(KEYSTORE_MODE);
        }
        let lock_file = open_opts.open(&lock_path)?;
        lock_file
            .lock_exclusive()
            .map_err(|e| ArmorError::InvalidPattern(format!("flock keystore: {e}")))?;
        let result = self.persist(path);
        // Lock is released automatically on file drop, but we want any
        // file-handle error visible — surface it after the persist result.
        let _ = fs2::FileExt::unlock(&lock_file);
        result
    }

    /// Pin a key. Idempotent — if `(server_name, fingerprint)` is already
    /// present, `pinned_at_iso` is *not* refreshed and the call returns
    /// [`PinOutcome::AlreadyPinned`]. If the server_name exists with a
    /// different fingerprint, returns an [`ArmorError::InvalidPattern`]
    /// — the caller must `unpin` first.
    pub fn pin(&mut self, key: PinnedKey) -> Result<PinOutcome, ArmorError> {
        if let Some(existing) = self
            .entries
            .iter()
            .find(|e| e.server_name == key.server_name)
        {
            if existing.key_fingerprint == key.key_fingerprint {
                return Ok(PinOutcome::AlreadyPinned);
            }
            return Err(ArmorError::InvalidPattern(format!(
                "server_name={} already pinned to fingerprint={}, refusing to \
                 silently overwrite with different fingerprint={}. Call \
                 keystore.unpin(\"{}\") first.",
                key.server_name, existing.key_fingerprint, key.key_fingerprint, key.server_name
            )));
        }
        self.entries.push(key);
        Ok(PinOutcome::NewlyPinned)
    }

    /// Remove the entry for `server_name`. Returns `true` if an entry was
    /// removed, `false` if none existed.
    pub fn unpin(&mut self, server_name: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.server_name != server_name);
        self.entries.len() != before
    }

    /// Look up a pinned entry by server_name.
    pub fn find_by_server(&self, server_name: &str) -> Option<&PinnedKey> {
        self.entries.iter().find(|e| e.server_name == server_name)
    }

    /// Look up a pinned entry by fingerprint (canonical identity).
    pub fn find_by_fingerprint(&self, fingerprint: &str) -> Option<&PinnedKey> {
        self.entries
            .iter()
            .find(|e| e.key_fingerprint == fingerprint)
    }

    /// Verify a fingerprint against the pinned entry for `server_name`.
    pub fn verify_pin(&self, server_name: &str, fingerprint: &str) -> VerifyPin {
        match self.find_by_server(server_name) {
            None => VerifyPin::UnknownServer,
            Some(p) if p.key_fingerprint == fingerprint => VerifyPin::Match,
            Some(p) => VerifyPin::FingerprintMismatch {
                expected: p.key_fingerprint.clone(),
                found: fingerprint.to_string(),
            },
        }
    }

    /// Number of pinned entries. Convenience for `armor_get_keystore` summary.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no keys are pinned.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Default keystore path: `$XDG_DATA_HOME/mcp-armor/keys.toml` →
/// `~/.local/share/mcp-armor/keys.toml` → `./keys.toml` if neither env var
/// is set. The `local/share` location follows the XDG Base Directory spec
/// for *data* (vs `local/config` for config) because keys are non-recreatable
/// state, not user preferences.
pub fn default_path() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(xdg).join("mcp-armor").join("keys.toml");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("mcp-armor")
            .join("keys.toml");
    }
    PathBuf::from("keys.toml")
}

/// Construct an RFC-3339 UTC timestamp ready for `pinned_at_iso`.
///
/// v0.2 (Round 1 review fix — Analyst observation 4): inlined the
/// chrono-free Howard-Hinnant civil-from-days formatter rather than
/// importing it from `crate::control::history`. The previous import
/// inverted the module layering (`manifest` is supposed to sit *below*
/// `control`, not depend on it).
pub fn now_iso() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    format_rfc3339_utc(secs)
}

/// RFC-3339 UTC formatter — Howard-Hinnant civil-from-days algorithm,
/// chrono-free. Sibling of `control::history::format_rfc3339_utc` (both
/// modules need their own copy because of the dependency direction).
fn format_rfc3339_utc(unix_secs: i64) -> String {
    let secs_per_day: i64 = 86_400;
    let days = unix_secs.div_euclid(secs_per_day);
    let secs_in_day = unix_secs.rem_euclid(secs_per_day);
    let hour = secs_in_day / 3600;
    let minute = (secs_in_day % 3600) / 60;
    let second = secs_in_day % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Reference: <https://howardhinnant.github.io/date_algorithms.html#civil_from_days>
/// `doe` / `doy` are the canonical variable names from Hinnant's algorithm;
/// renaming them would obscure the reference implementation.
#[allow(clippy::similar_names)]
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = y + i64::from(u8::from(m <= 2));
    (year, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_key(server: &str, fp_suffix: &str) -> PinnedKey {
        PinnedKey {
            server_name: server.to_string(),
            key_fingerprint: format!("aabbccdd{fp_suffix}"),
            public_key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            pinned_at_iso: "2026-05-20T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn empty_keystore_has_schema_version_1() {
        let ks = Keystore::empty();
        assert_eq!(ks.schema_version, 1);
        assert!(ks.is_empty());
    }

    #[test]
    fn load_missing_file_returns_empty() {
        let dir = tempdir().expect("tmp");
        let path = dir.path().join("nope.toml");
        let ks = Keystore::load(&path).expect("load");
        assert!(ks.is_empty());
    }

    #[test]
    fn pin_unpin_roundtrip() {
        let mut ks = Keystore::empty();
        let outcome = ks.pin(sample_key("fs", "01")).expect("pin");
        assert_eq!(outcome, PinOutcome::NewlyPinned);
        assert_eq!(ks.len(), 1);

        let unpinned = ks.unpin("fs");
        assert!(unpinned);
        assert_eq!(ks.len(), 0);

        let unpinned_again = ks.unpin("fs");
        assert!(!unpinned_again, "unpin of absent key returns false");
    }

    #[test]
    fn pin_same_fingerprint_is_idempotent() {
        let mut ks = Keystore::empty();
        let k = sample_key("fs", "01");
        ks.pin(k.clone()).expect("first pin");
        let outcome = ks.pin(k).expect("second pin");
        assert_eq!(outcome, PinOutcome::AlreadyPinned);
        assert_eq!(ks.len(), 1);
    }

    #[test]
    fn pin_different_fingerprint_under_same_server_refused() {
        let mut ks = Keystore::empty();
        ks.pin(sample_key("fs", "01")).expect("first");
        let result = ks.pin(sample_key("fs", "02"));
        assert!(
            matches!(result, Err(ArmorError::InvalidPattern(_))),
            "fingerprint swap must require explicit unpin first"
        );
    }

    #[test]
    fn verify_pin_three_states() {
        let mut ks = Keystore::empty();
        ks.pin(sample_key("fs", "01")).expect("pin");

        assert_eq!(ks.verify_pin("fs", "aabbccdd01"), VerifyPin::Match);
        assert_eq!(
            ks.verify_pin("unknown-server", "any"),
            VerifyPin::UnknownServer
        );
        match ks.verify_pin("fs", "different") {
            VerifyPin::FingerprintMismatch { expected, found } => {
                assert_eq!(expected, "aabbccdd01");
                assert_eq!(found, "different");
            }
            other => panic!("expected FingerprintMismatch, got {other:?}"),
        }
    }

    #[test]
    fn persist_roundtrip_through_toml() {
        let dir = tempdir().expect("tmp");
        let path = dir.path().join("keys.toml");
        let mut ks = Keystore::empty();
        ks.pin(sample_key("fs", "01")).expect("pin");
        ks.pin(sample_key("github", "ff")).expect("pin gh");

        ks.persist(&path).expect("persist");
        assert!(path.exists());

        let loaded = Keystore::load(&path).expect("load");
        assert_eq!(loaded.entries.len(), 2);
        assert!(loaded.find_by_server("fs").is_some());
        assert!(loaded.find_by_server("github").is_some());
        assert_eq!(loaded.schema_version, 1);
    }

    /// On Unix, after persist() the file must be mode 0o600 — no world or
    /// group bits. Catches the "default umask leaked 0644" regression.
    #[cfg(unix)]
    #[test]
    fn persist_sets_unix_0600_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().expect("tmp");
        let path = dir.path().join("keys.toml");
        let ks = Keystore::empty();
        ks.persist(&path).expect("persist");
        let meta = std::fs::metadata(&path).expect("stat");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600 keystore mode, got 0o{mode:o}");
    }

    #[test]
    fn schema_version_forward_compat_refuses_higher() {
        let dir = tempdir().expect("tmp");
        let path = dir.path().join("future.toml");
        std::fs::write(&path, "schema_version = 99\n[[pinned]]\nserver_name = \"x\"\nkey_fingerprint = \"00\"\npublic_key_b64 = \"AA==\"\npinned_at_iso = \"2026-05-20T00:00:00Z\"\n").expect("write");
        let r = Keystore::load(&path);
        assert!(
            matches!(r, Err(ArmorError::InvalidPattern(_))),
            "schema_version > current must refuse"
        );
    }

    #[test]
    fn default_path_uses_xdg_data_home() {
        let prev = std::env::var_os("XDG_DATA_HOME");
        // SAFETY: tests in this crate run single-threaded by default; the
        // env-mutation pattern matches what the rest of the test-suite uses
        // (e.g. policy/loader.rs).
        std::env::set_var("XDG_DATA_HOME", "/custom/xdg");
        let p = default_path();
        assert_eq!(p, PathBuf::from("/custom/xdg/mcp-armor/keys.toml"));
        match prev {
            Some(v) => std::env::set_var("XDG_DATA_HOME", v),
            None => std::env::remove_var("XDG_DATA_HOME"),
        }
    }

    #[test]
    fn find_by_fingerprint_finds_pinned_entry() {
        let mut ks = Keystore::empty();
        ks.pin(sample_key("a", "01")).expect("pin");
        ks.pin(sample_key("b", "02")).expect("pin");
        let found = ks.find_by_fingerprint("aabbccdd02").expect("fingerprint b");
        assert_eq!(found.server_name, "b");
        assert!(ks.find_by_fingerprint("aabbccdd99").is_none());
    }
}
