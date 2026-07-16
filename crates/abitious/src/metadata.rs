//! Pure `cargo metadata` resolution — the host-testable core of `abi build`.
//!
//! Ports napi-rs `build.ts`'s cdylib-target resolution to Rust: from a `cargo metadata
//! --format-version 1 --no-deps` JSON document, pick the package (by `--package`, else the
//! single cdylib-bearing workspace member), find its `cdylib` target, and compute the
//! built artifact's on-disk path (`target/{debug,release}/{lib<name>.dylib | lib<name>.so |
//! <name>.dll}`) plus the `<name>.node` copy name. Every function here is a pure transform
//! over strings — no process spawning, no filesystem — so the CLI's resolution logic is
//! covered by unit tests against fixture metadata (the process invocation lives in
//! [`crate::build`]).

use std::path::PathBuf;

use abitious_decmpfs::Platform;

use crate::json::{self, Json};

/// The built cdylib artifact's absolute path for `package` (or the sole cdylib workspace
/// member when `package` is `None`), at the `release`-selected profile, on the HOST
/// platform. `None` if the metadata cannot be parsed, no matching package/cdylib target
/// exists, or the package choice is ambiguous. Mirrors `build.ts`:
/// `target_directory / {profile} / <platform artifact name>`.
pub fn cdylib_artifact_path(
    metadata_json: &str,
    package: Option<&str>,
    release: bool,
) -> Option<PathBuf> {
    let meta = json::parse(metadata_json).ok()?;
    let target_dir = target_directory(&meta)?;
    let cdylib = find_cdylib_name(&meta, package)?;
    let profile = if release { "release" } else { "debug" };
    let file = cdylib_file_name(&cdylib, Platform::detect());
    Some(target_dir.join(profile).join(file))
}

/// The cdylib target's crate name for `package` (or the sole cdylib workspace member when
/// `package` is `None`). This is what [`node_output_name`] turns into the `.node` copy name
/// and the basis of [`cdylib_file_name`]. Split out so the CLI can name the output without
/// re-deriving it from a platform-specific artifact filename.
pub fn cdylib_target_name(metadata_json: &str, package: Option<&str>) -> Option<String> {
    let meta = json::parse(metadata_json).ok()?;
    find_cdylib_name(&meta, package)
}

/// The built cdylib's filename on `platform`: `lib<name>.dylib` (darwin), `<name>.dll`
/// (win32), or `lib<name>.so` (linux). Dashes in the crate name become underscores, exactly
/// as cargo (and napi-rs `build.ts`) name the artifact. Platform-parameterized so all three
/// arms are unit-tested regardless of the host.
pub fn cdylib_file_name(cdylib_name: &str, platform: Platform) -> String {
    let lib = cdylib_name.replace('-', "_");
    match platform {
        Platform::Darwin => format!("lib{lib}.dylib"),
        Platform::Win32 => format!("{lib}.dll"),
        Platform::Linux => format!("lib{lib}.so"),
    }
}

/// The `.node` copy name for a cdylib crate: `<name>.node`, dashes normalized to underscores
/// (the `copyArtifact` rename in napi-rs `build.ts`). This is what the raw or compressed
/// addon is written as when `--out` is not given.
pub fn node_output_name(cdylib_name: &str) -> String {
    format!("{}.node", cdylib_name.replace('-', "_"))
}

/// The workspace `target_directory` from the metadata document.
fn target_directory(meta: &Json) -> Option<PathBuf> {
    meta.get("target_directory")
        .and_then(Json::as_str)
        .map(PathBuf::from)
}

/// The cdylib target's name for the selected package.
fn find_cdylib_name(meta: &Json, package: Option<&str>) -> Option<String> {
    let packages = meta.get("packages")?.as_array()?;
    let pkg = select_package(packages, package)?;
    cdylib_name_of(pkg)
}

/// Pick the package: by explicit name, else the single workspace member that has a cdylib
/// target (ambiguous — more than one — resolves to `None` so the CLI can ask for `-p`).
fn select_package<'a>(packages: &'a [Json], package: Option<&str>) -> Option<&'a Json> {
    match package {
        Some(name) => packages
            .iter()
            .find(|p| p.get("name").and_then(Json::as_str) == Some(name)),
        None => {
            let mut with_cdylib = packages.iter().filter(|p| cdylib_name_of(p).is_some());
            let first = with_cdylib.next()?;
            match with_cdylib.next() {
                Some(_) => None, // ambiguous: multiple cdylib packages, require --package
                None => Some(first),
            }
        }
    }
}

/// The name of a package's first `cdylib` target, if any (`crate_types` includes `cdylib`,
/// matching `build.ts`'s `t.crate_types.includes('cdylib')`).
fn cdylib_name_of(pkg: &Json) -> Option<String> {
    let targets = pkg.get("targets")?.as_array()?;
    for target in targets {
        let is_cdylib = target
            .get("crate_types")
            .and_then(Json::as_array)
            .is_some_and(|types| types.iter().any(|t| t.as_str() == Some("cdylib")));
        if is_cdylib {
            return target
                .get("name")
                .and_then(Json::as_str)
                .map(str::to_string);
        }
    }
    None
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// Fixture `cargo metadata --no-deps` for a workspace with a cdylib package (`my-addon`,
    /// cdylib target `my_addon`) and a plain bin package (`helper`). Trimmed to the fields
    /// the resolver reads.
    fn fixture() -> String {
        r#"{
            "target_directory": "/work/target",
            "workspace_root": "/work",
            "version": 1,
            "packages": [
                {
                    "name": "helper",
                    "manifest_path": "/work/helper/Cargo.toml",
                    "targets": [
                        { "name": "helper", "kind": ["bin"], "crate_types": ["bin"] }
                    ]
                },
                {
                    "name": "my-addon",
                    "manifest_path": "/work/my-addon/Cargo.toml",
                    "targets": [
                        { "name": "build-script-build", "kind": ["custom-build"], "crate_types": ["bin"] },
                        { "name": "my_addon", "kind": ["cdylib"], "crate_types": ["cdylib"] }
                    ]
                }
            ]
        }"#
        .to_string()
    }

    #[test]
    fn resolves_the_cdylib_artifact_on_the_host() {
        // No --package: the sole cdylib package (my-addon) is chosen unambiguously.
        let path = cdylib_artifact_path(&fixture(), None, true).expect("release path");
        let file = cdylib_file_name("my_addon", Platform::detect());
        assert_eq!(
            path,
            PathBuf::from("/work/target").join("release").join(&file)
        );

        let debug = cdylib_artifact_path(&fixture(), None, false).expect("debug path");
        assert_eq!(
            debug,
            PathBuf::from("/work/target").join("debug").join(&file)
        );
    }

    #[test]
    fn honors_explicit_package_selection() {
        let path = cdylib_artifact_path(&fixture(), Some("my-addon"), false).expect("by name");
        assert!(path.ends_with(cdylib_file_name("my_addon", Platform::detect())));
        assert_eq!(
            cdylib_target_name(&fixture(), Some("my-addon")).as_deref(),
            Some("my_addon")
        );
    }

    #[test]
    fn none_when_package_has_no_cdylib() {
        // `helper` is a bin-only package — no cdylib target.
        assert!(cdylib_artifact_path(&fixture(), Some("helper"), false).is_none());
        assert!(cdylib_target_name(&fixture(), Some("helper")).is_none());
    }

    #[test]
    fn none_for_unknown_package() {
        assert!(cdylib_artifact_path(&fixture(), Some("does-not-exist"), false).is_none());
    }

    #[test]
    fn none_when_no_package_has_a_cdylib() {
        let json = r#"{
            "target_directory": "/t",
            "packages": [
                { "name": "a", "targets": [ { "name": "a", "crate_types": ["bin"] } ] }
            ]
        }"#;
        assert!(cdylib_artifact_path(json, None, false).is_none());
    }

    #[test]
    fn none_when_multiple_cdylib_packages_and_no_selection() {
        let json = r#"{
            "target_directory": "/t",
            "packages": [
                { "name": "a", "targets": [ { "name": "a", "crate_types": ["cdylib"] } ] },
                { "name": "b", "targets": [ { "name": "b", "crate_types": ["cdylib"] } ] }
            ]
        }"#;
        // Ambiguous without --package.
        assert!(cdylib_artifact_path(json, None, false).is_none());
        // But each is resolvable by name.
        assert_eq!(cdylib_target_name(json, Some("a")).as_deref(), Some("a"));
        assert_eq!(cdylib_target_name(json, Some("b")).as_deref(), Some("b"));
    }

    #[test]
    fn none_on_unparseable_or_incomplete_metadata() {
        assert!(cdylib_artifact_path("not json", None, false).is_none());
        // No `packages` key at all.
        assert!(cdylib_artifact_path("{}", None, false).is_none());
        // Missing target_directory: cannot form a path even with a cdylib present.
        let no_dir = r#"{ "packages": [ { "name": "a", "targets": [ { "name": "a", "crate_types": ["cdylib"] } ] } ] }"#;
        assert!(cdylib_artifact_path(no_dir, None, false).is_none());
        assert!(cdylib_target_name(no_dir, None).as_deref() == Some("a"));
    }

    #[test]
    fn cdylib_file_name_per_platform() {
        assert_eq!(
            cdylib_file_name("my_addon", Platform::Darwin),
            "libmy_addon.dylib"
        );
        assert_eq!(
            cdylib_file_name("my_addon", Platform::Linux),
            "libmy_addon.so"
        );
        assert_eq!(
            cdylib_file_name("my_addon", Platform::Win32),
            "my_addon.dll"
        );
        // Dashes in the crate name become underscores in the artifact name.
        assert_eq!(
            cdylib_file_name("my-addon", Platform::Linux),
            "libmy_addon.so"
        );
    }

    #[test]
    fn node_output_name_appends_node_and_normalizes_dashes() {
        assert_eq!(node_output_name("my_addon"), "my_addon.node");
        assert_eq!(node_output_name("my-addon"), "my_addon.node");
    }

    #[test]
    fn cdylib_target_name_is_none_on_wrong_shaped_metadata() {
        // cdylib_target_name reaches find_cdylib_name directly (no target_directory gate in
        // front of it), so it drives the parse + `packages` + `targets` fall-through arms that
        // cdylib_artifact_path shields behind its earlier `target_directory?`.
        // Unparseable JSON → the `json::parse(..).ok()?` None arm.
        assert!(cdylib_target_name("not json at all", None).is_none());
        // No `packages` key → the `meta.get("packages")?` None arm.
        assert!(cdylib_target_name("{}", None).is_none());
        // `packages` present but not an array → the `.as_array()?` None arm.
        assert!(cdylib_target_name(r#"{ "packages": 7 }"#, None).is_none());
        // A selected package with no `targets` key → `pkg.get("targets")?` None.
        assert!(cdylib_target_name(r#"{ "packages": [ { "name": "a" } ] }"#, Some("a")).is_none());
        // A selected package whose `targets` is not an array → `.as_array()?` None.
        assert!(
            cdylib_target_name(r#"{ "packages": [ { "name": "a", "targets": 3 } ] }"#, Some("a"))
                .is_none()
        );
    }

    #[test]
    fn target_without_crate_types_is_skipped() {
        // A target lacking crate_types must not match; falls through to None.
        let json = r#"{
            "target_directory": "/t",
            "packages": [ { "name": "a", "targets": [ { "name": "a" } ] } ]
        }"#;
        assert!(cdylib_target_name(json, Some("a")).is_none());
    }
}
