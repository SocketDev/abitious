//! Auto-resolve the prebuilt stub `.node` from an installed `@abitious/<triple>` platform
//! package — the Rust mirror of the JS loader, std-only (no new deps, per the dep budget).
//!
//! When `abi build --compress` is run without `--stub`, the stub is found by walking up from
//! the cwd for `node_modules/@abitious/<host-triple>/stub.node` (the same file the JS loader
//! and codegen name via `STUB_NODE`). This is exactly how a Node package manager lays out an
//! installed optional dependency, so a normal `npm install @abitious/cli` makes `abi build
//! --compress` work with no flags. `--stub` always overrides. When nothing is found, the
//! caller emits [`stub_not_found_error`] — a LOUD What/Where/Saw/Fix naming the exact package
//! to install.

use std::path::{Path, PathBuf};

/// The prebuilt stub filename inside each platform package. Kept in lockstep with
/// `STUB_NODE` in scripts/targets.mts and npm/cli/loader.cjs.
pub const STUB_NODE: &str = "stub.node";

/// Walk up from `start_dir` (inclusive) looking for
/// `<ancestor>/node_modules/@abitious/<triple>/stub.node`; return the first hit. Pure
/// path-walking + an `exists` check, so it is unit-tested against a fabricated node_modules.
pub fn resolve_stub(start_dir: &Path, triple: &str) -> Option<PathBuf> {
    for ancestor in start_dir.ancestors() {
        let candidate = ancestor
            .join("node_modules")
            .join("@abitious")
            .join(triple)
            .join(STUB_NODE);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// A LOUD What/Where/Saw/Fix error for a missing stub: names the exact package to install and
/// the `--stub` override.
pub fn stub_not_found_error(triple: &str, start_dir: &Path) -> String {
    format!(
        "abi: could not auto-resolve a prebuilt stub for this host.\n  \
         Where: walked up from {start} for node_modules/@abitious/{triple}/{stub}\n  \
         Saw:   no installed @abitious/{triple} platform package\n  \
         Fix:   install it — `npm install @abitious/cli` (pulls @abitious/{triple} as the\n         \
         optional dependency for this platform), or pass --stub <path> to a prebuilt stub \
         .node (e.g. `cargo build -p abitious-stub --release`).",
        start = start_dir.display(),
        triple = triple,
        stub = STUB_NODE,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create `<root>/node_modules/@abitious/<triple>/stub.node` with some bytes.
    fn plant_stub(root: &Path, triple: &str) -> PathBuf {
        let dir = root.join("node_modules").join("@abitious").join(triple);
        std::fs::create_dir_all(&dir).expect("mkdir platform pkg");
        let stub = dir.join(STUB_NODE);
        std::fs::write(&stub, b"\x00stub").expect("write stub");
        stub
    }

    /// A unique scratch dir under the system tempdir for a single test.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "abitious-resolve-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    #[test]
    fn resolves_a_stub_planted_at_the_cwd() {
        let root = scratch("cwd");
        let planted = plant_stub(&root, "darwin-arm64");
        let found = resolve_stub(&root, "darwin-arm64").expect("resolves");
        assert_eq!(found, planted);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn walks_up_to_an_ancestor() {
        let root = scratch("ancestor");
        let planted = plant_stub(&root, "linux-x64-gnu");
        let nested = root.join("a").join("b").join("c");
        std::fs::create_dir_all(&nested).expect("nested");
        let found = resolve_stub(&nested, "linux-x64-gnu").expect("resolves from nested cwd");
        assert_eq!(found, planted);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn none_when_absent_and_error_is_actionable() {
        let root = scratch("absent");
        assert!(resolve_stub(&root, "win32-x64-msvc").is_none());
        let err = stub_not_found_error("win32-x64-msvc", &root);
        assert!(err.contains("@abitious/win32-x64-msvc"));
        assert!(err.contains("npm install @abitious/cli"));
        assert!(err.contains("--stub"));
        assert!(err.contains("Where:") && err.contains("Saw:") && err.contains("Fix:"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_directory_named_stub_node_does_not_count() {
        // Only a FILE at the stub path resolves — a stray directory must be ignored.
        let root = scratch("dir-not-file");
        let dir = root
            .join("node_modules")
            .join("@abitious")
            .join("darwin-x64")
            .join(STUB_NODE);
        std::fs::create_dir_all(&dir).expect("mkdir a dir named stub.node");
        assert!(resolve_stub(&root, "darwin-x64").is_none());
        std::fs::remove_dir_all(&root).ok();
    }
}
