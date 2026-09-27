//! Atomic persistence of the JSON+YAML parser pair.
//!
//! Both callers that create an onboarded parser — the `ulpf onboard` CLI and
//! `POST /onboard` — write the same two files, so the guarantee lives here
//! rather than in one of them. A definition that is half-written, or half of a
//! pair, is worse than a failed write: it reads as present to the loader and is
//! not loadable, and nothing downstream can tell the difference.

use std::io::ErrorKind;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Temp-file disambiguator so concurrent publishers never share a name.
static PUBLISH_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A process-unique, monotonically increasing tag for scratch names.
///
/// Exposed so tests in other modules can build collision-free scratch paths
/// from the same counter, instead of inventing a second naming scheme that
/// could overlap a real temp file.
pub fn next_publish_tag() -> u64 {
    PUBLISH_TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Atomically publish the JSON+YAML parser pair.
///
/// Both payloads are written to temp files in the SAME directory, then
/// `rename`d over their targets. `rename(2)` is atomic on POSIX: readers
/// (e.g. `GET /parsers`) never observe a half-written definition, and a
/// crash between the two renames leaves at worst one stale-but-whole file —
/// never a truncated one. Temps live beside their targets so the rename
/// stays on one filesystem (no cross-device hop).
///
/// On any failure the temp files are removed and any already-renamed target is
/// rolled back to its prior contents. The three prior states get three
/// different answers — restore, remove, or leave-alone-and-report — because a
/// rollback that guesses wrong destroys a parser that was working.
///
/// A rollback that itself fails is NOT swallowed: the returned error names
/// both the original publish failure and whatever could not be undone, because
/// silently reporting only the first would leave a caller believing the
/// directory is clean when it is not.
pub fn publish_parser_pair(
    dir: &Path,
    json_file: &str,
    yaml_file: &str,
    json_str: &str,
    yaml_str: &str,
) -> std::io::Result<()> {
    let json_path = dir.join(json_file);
    let yaml_path = dir.join(yaml_file);

    // Snapshot BEFORE touching anything, so a rollback restores rather than
    // deletes a parser that was already published.
    //
    // Tri-state, deliberately. `read(..).ok()` collapses "no file there" and
    // "the file is there but unreadable" into the same `None`, and the rollback
    // below deletes on `None` — so an unreadable existing parser (bad
    // permissions, a transient I/O error, a path that is not a regular file)
    // would have been DELETED on failure rather than restored. Losing a
    // working parser because an unrelated write failed is the worst outcome a
    // rollback can produce.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Prior {
        /// Existed and was read; these are its bytes.
        Present,
        /// Did not exist, so a rollback should remove whatever landed.
        Absent,
        /// Existed but could not be read. Contents unknown — a rollback must
        /// not guess, and must not delete.
        Unreadable,
    }
    let snapshot = |path: &Path| -> (Option<Vec<u8>>, Prior) {
        // Existence is probed with `symlink_metadata` rather than inferred from
        // the read error. `read` on a DANGLING symlink reports `NotFound`, which
        // would classify an existing directory entry as absent and let a
        // rollback delete what landed — the same data-loss shape this tri-state
        // exists to prevent, just one edge case narrower.
        match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == ErrorKind::NotFound => (None, Prior::Absent),
            Err(_) => (None, Prior::Unreadable),
            Ok(_) => match std::fs::read(path) {
                Ok(bytes) => (Some(bytes), Prior::Present),
                Err(_) => (None, Prior::Unreadable),
            },
        }
    };
    let (prior_json, state_json) = snapshot(&json_path);
    let (prior_yaml, state_yaml) = snapshot(&yaml_path);

    let tag = format!("tmp-{}-{}", std::process::id(), next_publish_tag());
    let json_tmp = dir.join(format!("{json_file}.{tag}"));
    let yaml_tmp = dir.join(format!("{yaml_file}.{tag}"));

    // Clean up the temps, then undo any rename that already happened. Targets
    // that were never renamed are untouched — the originals are still whole on
    // disk. Restores go through their own temp + rename for the same reason the
    // publish does: a plain `write` to the target truncates it first, so a
    // failed restore would leave the previous definition destroyed rather than
    // merely unreverted.
    //
    // The two flags are exact, not conservative: each call site passes how far
    // it actually got, and there is no step after the second rename, so
    // `(true, true)` is unreachable. A wrong flag would restore or delete a
    // file that was never touched, which is why they are not simply derived.
    let rollback = |json_renamed: bool, yaml_renamed: bool| -> std::io::Result<()> {
        let mut problems: Vec<String> = Vec::new();
        // A temp that is already gone is the EXPECTED case, not a problem: the
        // half that renamed successfully no longer has one. Reporting it would
        // make every clean rollback claim to be incomplete.
        let mut drop_temp = |r: std::io::Result<()>, what: &str| match r {
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => problems.push(format!("{what}: {e}")),
            Ok(()) => {}
        };

        drop_temp(std::fs::remove_file(&json_tmp), "temp json");
        drop_temp(std::fs::remove_file(&yaml_tmp), "temp yaml");
        for (path, prior, prior_state, renamed, what) in [
            (&json_path, &prior_json, state_json, json_renamed, "json"),
            (&yaml_path, &prior_yaml, state_yaml, yaml_renamed, "yaml"),
        ] {
            if !renamed {
                continue;
            }
            match prior_state {
                Prior::Present => {
                    let bytes = prior.as_ref().expect("Present implies Some");
                    let restore_tmp = dir.join(format!(
                        "{}.rollback-{tag}",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    ));
                    if let Err(e) = std::fs::write(&restore_tmp, bytes)
                        .and_then(|()| std::fs::rename(&restore_tmp, path))
                    {
                        // Best effort: leaving a stale `*.rollback-tmp-*` behind
                        // would make the next publish's `assert_no_tmps`-style
                        // check fail for a rollback that already reported itself
                        // as incomplete. The restore error is the one that
                        // matters and is recorded below regardless.
                        let _ = std::fs::remove_file(&restore_tmp);
                        problems.push(format!("{what}: {e}"));
                    }
                }
                Prior::Absent => {
                    if let Err(e) = std::fs::remove_file(path) {
                        problems.push(format!("{what}: {e}"));
                    }
                }
                Prior::Unreadable => {
                    // The prior contents are unknown, so neither restoring nor
                    // deleting is defensible. Leave the new content in place —
                    // the file is at least valid — and say the rollback is
                    // incomplete so the operator knows to reconcile it.
                    problems.push(format!(
                        "{what}: could not read the prior file before publishing, so it was \
                         not restored; it now holds the new definition"
                    ));
                }
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(std::io::Error::other(problems.join("; ")))
        }
    };

    // Stage BOTH payloads before either becomes visible: a failure here
    // leaves the originals untouched.
    let fail = |e: std::io::Error, json_renamed: bool, yaml_renamed: bool| match rollback(
        json_renamed,
        yaml_renamed,
    ) {
        Ok(()) => e,
        Err(rollback_err) => std::io::Error::other(format!(
            "publish failed: {e}; and the rollback was incomplete: {rollback_err}"
        )),
    };

    if let Err(e) =
        std::fs::write(&json_tmp, json_str).and_then(|()| std::fs::write(&yaml_tmp, yaml_str))
    {
        return Err(fail(e, false, false));
    }
    if let Err(e) = std::fs::rename(&json_tmp, &json_path) {
        return Err(fail(e, false, false));
    }
    if let Err(e) = std::fs::rename(&yaml_tmp, &yaml_path) {
        return Err(fail(e, true, false));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fresh temp dir per test (pid-tagged): publish tests must not share
    /// state, and must not touch the repo's real `data/parsers`.
    fn scratch_dir(case: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ulpf-publish-test-{}-{}-{}",
            case,
            std::process::id(),
            PUBLISH_TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir must be creatable");
        dir
    }

    /// No temp file may survive a publish. A leftover `*.tmp-*` is a staged
    /// definition that was never published, and a `*.rollback-tmp-*` is a
    /// staged restore that never landed — both are debris, so the check covers
    /// both name shapes. `publish_parser_pair` never scans the directory, so
    /// this is purely an assertion that the cleanup paths ran.
    fn assert_no_tmps(dir: &std::path::Path) {
        let leftovers: Vec<_> = std::fs::read_dir(dir)
            .expect("scratch dir must be listable")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("tmp-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind after publish: {leftovers:?}"
        );
    }

    #[test]
    fn test_publish_pair_writes_both_then_renames() {
        let dir = scratch_dir("happy");
        publish_parser_pair(&dir, "fw.json", "fw.yaml", r#"{"a":1}"#, "a: 1\n")
            .expect("fresh publish must succeed");
        assert_eq!(
            std::fs::read_to_string(dir.join("fw.json")).unwrap(),
            r#"{"a":1}"#
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("fw.yaml")).unwrap(),
            "a: 1\n"
        );
        assert_no_tmps(&dir);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Crash-window proxy: block the YAML rename (a directory where the file
    /// must go — fails even as root, unlike permission bits) and assert the
    /// JSON half is NOT left behind with new content.
    #[test]
    fn test_publish_pair_failure_leaves_no_half_pair() {
        let dir = scratch_dir("half");
        std::fs::create_dir(dir.join("fw.yaml")).expect("blocker dir must be creatable");

        let err = publish_parser_pair(&dir, "fw.json", "fw.yaml", "NEW-JSON", "NEW-YAML")
            .expect_err("YAML rename onto a directory must fail");
        let _ = err;

        assert!(
            !dir.join("fw.json").exists(),
            "failed publish must not leave the JSON half behind"
        );
        // The blocker itself is untouched — rollback removes files, never dirs.
        assert!(dir.join("fw.yaml").is_dir());
        assert_no_tmps(&dir);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Same failure, but a parser was already published: the JSON target
    /// must be rolled back to its PRIOR contents, not deleted, and the YAML
    /// prior must be intact.
    #[test]
    fn test_publish_pair_failure_restores_prior() {
        let dir = scratch_dir("rollback");
        std::fs::write(dir.join("fw.json"), "OLD-JSON").unwrap();
        std::fs::write(dir.join("fw.yaml"), "OLD-YAML").unwrap();
        // Re-publish over the pair first: proves overwrite works mid-test.
        publish_parser_pair(&dir, "fw.json", "fw.yaml", "MID-JSON", "MID-YAML").unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("fw.json")).unwrap(),
            "MID-JSON"
        );

        // Now block the YAML target and re-publish: JSON rename succeeds,
        // YAML rename fails, JSON must roll back to MID-JSON.
        std::fs::remove_file(dir.join("fw.yaml")).unwrap();
        std::fs::create_dir(dir.join("fw.yaml")).unwrap();
        publish_parser_pair(&dir, "fw.json", "fw.yaml", "NEW-JSON", "NEW-YAML")
            .expect_err("blocked YAML rename must fail");
        assert_eq!(
            std::fs::read_to_string(dir.join("fw.json")).unwrap(),
            "MID-JSON",
            "JSON half must roll back to prior contents, not keep NEW-JSON"
        );
        assert!(dir.join("fw.yaml").is_dir());
        assert_no_tmps(&dir);

        // Unblock and prove the pair still publishes cleanly afterwards.
        std::fs::remove_dir(dir.join("fw.yaml")).unwrap();
        publish_parser_pair(&dir, "fw.json", "fw.yaml", "NEW-JSON", "NEW-YAML").unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("fw.json")).unwrap(),
            "NEW-JSON"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("fw.yaml")).unwrap(),
            "NEW-YAML"
        );
        assert_no_tmps(&dir);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A rollback that completes cleanly must report ONLY the publish failure.
    ///
    /// The half that renamed successfully no longer has a temp file, so
    /// `remove_file` on it returns `NotFound` — which is the expected case, not
    /// a rollback problem. Counting it made every clean rollback report itself
    /// as incomplete, which would train operators to ignore that signal.
    #[test]
    fn test_publish_pair_clean_rollback_reports_only_publish_failure() {
        let dir = scratch_dir("cleanrollback");
        std::fs::write(dir.join("fw.json"), "OLD-JSON").unwrap();
        std::fs::create_dir(dir.join("fw.yaml")).expect("blocker dir must be creatable");

        let err = publish_parser_pair(&dir, "fw.json", "fw.yaml", "NEW-JSON", "NEW-YAML")
            .expect_err("blocked YAML rename must fail");
        let msg = err.to_string();
        assert!(
            !msg.contains("rollback was incomplete"),
            "a rollback that restored cleanly must NOT claim incompleteness: {msg}"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("fw.json")).unwrap(),
            "OLD-JSON",
            "prior contents must be back"
        );
        assert_no_tmps(&dir);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An UNREADABLE prior file must never be deleted by a rollback.
    ///
    /// The snapshot used to be `fs::read(..).ok()`, which collapses "no file
    /// there" and "the file is there but I could not read it" into the same
    /// `None` — and the rollback deletes on `None`. So a parser that existed
    /// but was unreadable at snapshot time (bad ownership after a restore from
    /// another host, a transient I/O error, a file that is not a regular file)
    /// would have been DELETED when the publish failed, not restored. Losing a
    /// working parser because an unrelated write failed is the worst possible
    /// outcome of a rollback.
    ///
    /// A unix socket file is the deterministic stand-in for "exists, will not
    /// read": `read` fails `ENXIO`, which is not `NotFound`, while a rename over
    /// it succeeds, so the publish really does proceed and really does fail
    /// afterwards. A `chmod 000` file would be simpler but is unreliable — as
    /// root it is still readable, and this suite is documented to run as root.
    #[cfg(unix)]
    #[test]
    fn test_publish_pair_never_deletes_an_unreadable_prior_file() {
        use std::os::unix::net::UnixListener;

        let dir = scratch_dir("unreadable-prior");
        // Prior "parser" that cannot be read...
        let json_path = dir.join("fw.json");
        let listener = UnixListener::bind(&json_path).expect("socket path must be bindable");
        // ...and a YAML target that cannot be renamed over, to force the
        // failure that triggers the rollback.
        std::fs::create_dir(dir.join("fw.yaml")).expect("blocker dir must be creatable");

        let err = publish_parser_pair(&dir, "fw.json", "fw.yaml", "NEW-JSON", "NEW-YAML")
            .expect_err("blocked YAML rename must fail");
        let msg = err.to_string();

        assert!(
            msg.contains("rollback was incomplete"),
            "an unrestorable prior file must be reported, not swallowed: {msg}"
        );
        assert!(
            msg.contains("could not read the prior file"),
            "the error must name the reason: {msg}"
        );

        // The file must still be there, holding the new content. This is the
        // whole point: a rollback that deleted an unreadable prior file would
        // leave the path GONE, taking a parser definition with it. Leaving the
        // new content in place loses nothing that was readable, and the
        // incompleteness is reported above so an operator can reconcile it.
        assert!(
            json_path.exists(),
            "the prior file was DELETED instead of left in place"
        );
        assert_eq!(
            std::fs::read_to_string(&json_path).unwrap(),
            "NEW-JSON",
            "the new content must be intact, not truncated or removed"
        );

        drop(listener);
        std::fs::remove_file(&json_path).ok();
        assert_no_tmps(&dir);
        std::fs::remove_dir_all(&dir).ok();
    }
}
