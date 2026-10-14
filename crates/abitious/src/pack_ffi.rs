use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use abitious_producer::{compress_ffi, FfiReceipt, MAX_LEVEL, MIN_LEVEL};

use crate::args::PackFfiArgs;
use crate::json::{self, Json};

const TARGETS: [&str; 8] = [
    "darwin-arm64",
    "darwin-x64",
    "linux-x64-gnu",
    "linux-arm64-gnu",
    "linux-x64-musl",
    "linux-arm64-musl",
    "win32-x64-msvc",
    "win32-arm64-msvc",
];

pub fn run(args: &PackFfiArgs) -> Result<FfiReceipt, String> {
    let template = match &args.template {
        Some(path) => path.clone(),
        None => resolve_template(&args.target)?,
    };
    compress_ffi(
        &args.library,
        &args.target,
        &template,
        &args.out,
        args.compress_level.clamp(MIN_LEVEL, MAX_LEVEL),
    )
}

fn resolve_template(target: &str) -> Result<PathBuf, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot locate the abi executable: {error}"))?;
    let bundle = executable
        .parent()
        .ok_or_else(|| "abi executable has no parent directory".to_owned())?;
    let manifest_path = bundle.join("templates").join("manifest.json");
    let manifest = std::fs::read_to_string(&manifest_path).map_err(|error| {
        format!(
            "cannot read bundled FFI template manifest {}: {error}",
            manifest_path.display()
        )
    })?;
    resolve_manifest_template(bundle, target, &manifest)
}

fn resolve_manifest_template(bundle: &Path, target: &str, text: &str) -> Result<PathBuf, String> {
    let root =
        json::parse(text).map_err(|error| format!("invalid FFI template manifest: {error}"))?;
    if root.get("schemaVersion") != Some(&Json::Number(1.0)) {
        return Err("FFI template manifest schemaVersion must be 1".to_owned());
    }
    let producer_sha = root
        .get("producerSha")
        .and_then(Json::as_str)
        .ok_or_else(|| "FFI template manifest has no producerSha".to_owned())?;
    if producer_sha.len() != 40 || !producer_sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("FFI template manifest producerSha must be a 40-character Git SHA".to_owned());
    }
    let rows = root
        .get("templates")
        .and_then(Json::as_array)
        .ok_or_else(|| "FFI template manifest has no templates array".to_owned())?;
    if rows.len() != TARGETS.len() {
        return Err("FFI template manifest must contain exactly eight targets".to_owned());
    }
    let mut seen = BTreeSet::new();
    let mut chosen = None;
    for row in rows {
        let row_target = row
            .get("target")
            .and_then(Json::as_str)
            .ok_or_else(|| "FFI template row has no target".to_owned())?;
        if !TARGETS.contains(&row_target) || !seen.insert(row_target.to_owned()) {
            return Err(format!(
                "FFI template manifest has an unknown or duplicate target {row_target:?}"
            ));
        }
        let expected_path = format!("templates/{row_target}/ffi-stub.node");
        let row_path = row
            .get("path")
            .and_then(Json::as_str)
            .ok_or_else(|| format!("FFI template row for {row_target} has no path"))?;
        if row_path != expected_path {
            return Err(format!(
                "FFI template path for {row_target} must be {expected_path:?}"
            ));
        }
        let digest = row
            .get("sha512")
            .and_then(Json::as_str)
            .ok_or_else(|| format!("FFI template row for {row_target} has no sha512"))?;
        if digest.len() != 128 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!(
                "FFI template SHA-512 for {row_target} is malformed"
            ));
        }
        let template = bundle.join(row_path);
        if row_target == target {
            if !is_regular_file(&template) {
                return Err(format!(
                    "FFI template {} is missing or is not a regular file",
                    template.display()
                ));
            }
            let bytes = std::fs::read(&template).map_err(|error| {
                format!("cannot read FFI template {}: {error}", template.display())
            })?;
            if hex(&abitious_decmpfs::raw_sha512(&bytes)) != digest.to_ascii_lowercase() {
                return Err(format!(
                    "FFI template {} does not match its manifest SHA-512",
                    template.display()
                ));
            }
            chosen = Some(template);
        }
    }
    if seen.len() != TARGETS.len() {
        return Err("FFI template manifest does not cover every supported target".to_owned());
    }
    chosen.ok_or_else(|| format!("FFI template manifest has no row for target {target}"))
}

fn is_regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_template_requires_full_unique_target_set_and_matching_hash() {
        let root =
            std::env::temp_dir().join(format!("abitious-ffi-manifest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for target in TARGETS {
            let path = root.join(format!("templates/{target}/ffi-stub.node"));
            std::fs::create_dir_all(path.parent().expect("template parent")).expect("mkdir");
            std::fs::write(path, target.as_bytes()).expect("write template");
        }
        let rows = TARGETS.iter().map(|target| {
            let bytes = target.as_bytes();
            format!("{{\"target\":\"{target}\",\"path\":\"templates/{target}/ffi-stub.node\",\"sha512\":\"{}\"}}", hex(&abitious_decmpfs::raw_sha512(bytes)))
        }).collect::<Vec<_>>().join(",");
        let manifest = format!(
            "{{\"schemaVersion\":1,\"producerSha\":\"{}\",\"templates\":[{rows}]}}",
            "a".repeat(40)
        );
        assert_eq!(
            resolve_manifest_template(&root, "linux-x64-gnu", &manifest).unwrap(),
            root.join("templates/linux-x64-gnu/ffi-stub.node")
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
