use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use abitious_decmpfs::{
    build_ffi_section_payload, find_ffi_data_section, inject_ffi_data, raw_sha512,
    validate_ffi_target_object, FFI_ENVELOPE_MAGIC,
};

use crate::{MAX_LEVEL, MIN_LEVEL};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FfiReceipt {
    pub input: PathBuf,
    pub template: PathBuf,
    pub output: PathBuf,
    pub target: String,
    pub raw_size: usize,
    pub native_size: usize,
    pub raw_sha512: String,
}

impl FfiReceipt {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"input\":{},\"template\":{},\"output\":{},\"target\":{},\"rawSize\":{},\"nativeSize\":{},\"rawSha512\":{}}}",
            json_string(&self.input.display().to_string()),
            json_string(&self.template.display().to_string()),
            json_string(&self.output.display().to_string()),
            json_string(&self.target),
            self.raw_size,
            self.native_size,
            json_string(&self.raw_sha512),
        )
    }
}

impl std::fmt::Display for FfiReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_json())
    }
}

/// Package a verified native library inside a prebuilt N-API carrier.
pub fn compress_ffi(
    raw_library: &Path,
    target: &str,
    template: &Path,
    out: &Path,
    level: i32,
) -> Result<FfiReceipt, String> {
    #[cfg(not(target_os = "macos"))]
    if target.starts_with("darwin-") {
        return Err("Darwin FFI carriers require macOS for ad-hoc signing".to_owned());
    }

    let raw = std::fs::read(raw_library)
        .map_err(|error| format!("cannot read FFI library {}: {error}", raw_library.display()))?;
    let (platform, arch, libc) =
        validate_ffi_target_object(&raw, target).map_err(|error| error.to_string())?;
    let template_bytes = std::fs::read(template)
        .map_err(|error| format!("cannot read FFI template {}: {error}", template.display()))?;
    validate_ffi_target_object(&template_bytes, target)
        .map_err(|error| format!("FFI template {}: {error}", template.display()))?;
    if find_ffi_data_section(&template_bytes).is_some() {
        return Err(format!(
            "FFI template {} already contains an FFI section",
            template.display()
        ));
    }
    if abitious_decmpfs::inspect_hybrid(&template_bytes).is_some() {
        return Err(format!(
            "FFI template {} already contains a generic addon section",
            template.display()
        ));
    }
    let section = build_ffi_section_payload(
        &raw,
        target,
        platform,
        arch,
        libc,
        level.clamp(MIN_LEVEL, MAX_LEVEL),
    )
    .map_err(|error| error.to_string())?;
    if section.get(..FFI_ENVELOPE_MAGIC.len()) != Some(FFI_ENVELOPE_MAGIC.as_slice()) {
        return Err("FFI envelope encoder returned an invalid marker".to_owned());
    }
    let carrier = inject_ffi_data(&template_bytes, &section).map_err(|error| {
        format!(
            "cannot inject FFI section into {}: {error}",
            template.display()
        )
    })?;
    write_atomic(out, &carrier)
        .map_err(|error| format!("cannot write FFI carrier {}: {error}", out.display()))?;
    Ok(FfiReceipt {
        input: raw_library.to_path_buf(),
        template: template.to_path_buf(),
        output: out.to_path_buf(),
        target: target.to_owned(),
        raw_size: raw.len(),
        native_size: carrier.len(),
        raw_sha512: hex(&raw_sha512(&raw)),
    })
}

fn json_string(value: &str) -> String {
    let mut output = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            ch if (ch as u32) < 0x20 => {
                let _ = write!(output, "\\u{:04x}", ch as u32);
            }
            _ => output.push(ch),
        }
    }
    output.push('"');
    output
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn write_atomic(out: &Path, data: &[u8]) -> std::io::Result<()> {
    let parent = out
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let file_name = out.file_name().unwrap_or_default().to_string_lossy();
    for _ in 0..128 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp = parent.join(format!(
            ".{file_name}.abitious-ffi-{}-{sequence}.tmp",
            std::process::id()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&temp) {
            Ok(mut file) => {
                let result = std::io::Write::write_all(&mut file, data)
                    .and_then(|()| file.sync_all())
                    .and_then(|()| std::fs::rename(&temp, out));
                if result.is_err() {
                    let _ = std::fs::remove_file(&temp);
                }
                return result;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a unique temporary file",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn minimal_elf64_x64() -> Vec<u8> {
        fn put_u16(bytes: &mut [u8], at: usize, value: u16) {
            bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
            bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        fn put_u64(bytes: &mut [u8], at: usize, value: u64) {
            bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        let names = b"\0.shstrtab\0";
        let shoff = 80usize;
        let mut elf = vec![0u8; shoff + 128];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        put_u16(&mut elf, 16, 3);
        put_u16(&mut elf, 18, 0x003e);
        put_u16(&mut elf, 52, 64);
        put_u64(&mut elf, 40, shoff as u64);
        put_u16(&mut elf, 58, 64);
        put_u16(&mut elf, 60, 2);
        put_u16(&mut elf, 62, 1);
        elf[64..64 + names.len()].copy_from_slice(names);
        let header = shoff + 64;
        put_u32(&mut elf, header, 1);
        put_u32(&mut elf, header + 4, 3);
        put_u64(&mut elf, header + 24, 64);
        put_u64(&mut elf, header + 32, names.len() as u64);
        elf
    }

    #[test]
    fn compress_ffi_injects_a_distinct_section_and_receipt_digest() {
        let root =
            std::env::temp_dir().join(format!("abitious-ffi-producer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create scratch dir");
        let raw_path = root.join("library.so");
        let template_path = root.join("ffi-stub.node");
        let output_path = root.join("carrier.node");
        let raw = minimal_elf64_x64();
        let template = minimal_elf64_x64();
        std::fs::write(&raw_path, &raw).expect("write raw library");
        std::fs::write(&template_path, &template).expect("write FFI template");
        let receipt = compress_ffi(&raw_path, "linux-x64-gnu", &template_path, &output_path, 3)
            .expect("compress FFI library");
        assert_eq!(receipt.raw_sha512, hex(&raw_sha512(&raw)));
        assert_eq!(
            receipt.native_size,
            std::fs::metadata(&output_path)
                .expect("carrier metadata")
                .len() as usize
        );
        let carrier = std::fs::read(&output_path).expect("read carrier");
        let section = find_ffi_data_section(&carrier).expect("distinct FFI section");
        let decoded = abitious_decmpfs::decode_ffi_data(section).expect("decode FFI section");
        assert_eq!(decoded.raw, raw);
        assert!(abitious_decmpfs::inspect_hybrid(&carrier).is_none());
        let _ = std::fs::remove_dir_all(root);
    }
}
