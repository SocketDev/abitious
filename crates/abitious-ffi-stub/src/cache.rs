use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use abitious_decmpfs::{
    decode_ffi_data, find_ffi_data_section, host_ffi_target, inspect_ffi_data, raw_sha512,
    validate_ffi_target_object,
};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(super) fn resolve_library_path() -> Result<PathBuf, String> {
    let module = abitious_decmpfs::selfextract::self_path()
        .ok_or_else(|| "cannot locate the loaded FFI carrier file".to_owned())?;
    let bytes = std::fs::read(&module)
        .map_err(|error| format!("cannot read FFI carrier {}: {error}", module.display()))?;
    let section = find_ffi_data_section(&bytes)
        .ok_or_else(|| "loaded module has no FFI section".to_owned())?;
    let info = inspect_ffi_data(section).ok_or_else(|| {
        "FFI section has an invalid envelope, codec frame, or target metadata".to_owned()
    })?;
    let host = host_ffi_target();
    if info.target != host {
        return Err(format!(
            "FFI carrier target {} does not match host {host}",
            info.target
        ));
    }
    let cache_dir = cache_dir()?;
    prepare_cache_dir(&cache_dir)?;
    let suffix = match info.target.split('-').next() {
        Some("darwin") => "dylib",
        Some("win32") => "dll",
        Some("linux") => "so",
        _ => return Err("unsupported FFI carrier target".to_owned()),
    };
    let destination = cache_dir.join(format!("library-{}.{}", hex(&info.raw_sha512), suffix));
    if valid_cached_file(
        &destination,
        &info.raw_sha512,
        info.raw_size as usize,
        &info.target,
    )? {
        return Ok(destination);
    }
    let payload = decode_ffi_data(section).ok_or_else(|| {
        "FFI raw library failed full decode, target, or SHA-512 validation".to_owned()
    })?;
    if payload.target != info.target
        || payload.raw.len() as u64 != info.raw_size
        || payload.raw_sha512 != info.raw_sha512
    {
        return Err("FFI section metadata changed during extraction".to_owned());
    }
    write_atomic(&destination, &payload.raw, &info.raw_sha512, &info.target)?;
    if !valid_cached_file(
        &destination,
        &info.raw_sha512,
        info.raw_size as usize,
        &info.target,
    )? {
        return Err(format!(
            "cached FFI library {} failed its integrity check",
            destination.display()
        ));
    }
    Ok(destination)
}

fn cache_dir() -> Result<PathBuf, String> {
    let root = std::env::temp_dir();
    #[cfg(unix)]
    let identity = unsafe { libc::getuid() }.to_string();
    #[cfg(windows)]
    let identity = {
        let username = std::env::var("USERNAME").map_err(|_| {
            "cannot determine the current Windows user for the private FFI cache".to_owned()
        })?;
        username
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                    ch
                } else {
                    '_'
                }
            })
            .collect::<String>()
    };
    #[cfg(not(any(unix, windows)))]
    let identity = "user".to_owned();
    Ok(root.join(format!("abitious-ffi-{identity}")))
}

fn prepare_cache_dir(dir: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        match std::fs::DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!(
                    "cannot create private FFI cache {}: {error}",
                    dir.display()
                ))
            }
        }
        let metadata = std::fs::symlink_metadata(dir).map_err(|error| {
            format!(
                "cannot inspect private FFI cache {}: {error}",
                dir.display()
            )
        })?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != unsafe { libc::getuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(format!(
                "private FFI cache {} has unsafe type, owner, or permissions",
                dir.display()
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let temp = std::env::temp_dir();
        if temp.ancestors().any(has_reparse_point) {
            return Err(format!(
                "temporary directory {} contains a reparse point",
                temp.display()
            ));
        }
        match std::fs::create_dir(dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!(
                    "cannot create private FFI cache {}: {error}",
                    dir.display()
                ))
            }
        }
        let metadata = std::fs::symlink_metadata(dir).map_err(|error| {
            format!(
                "cannot inspect private FFI cache {}: {error}",
                dir.display()
            )
        })?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || has_reparse_point(dir)
        {
            return Err(format!(
                "private FFI cache {} is not a plain directory",
                dir.display()
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn has_reparse_point(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileAttributesW, FILE_ATTRIBUTE_REPARSE_POINT, INVALID_FILE_ATTRIBUTES,
    };
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
    attrs == INVALID_FILE_ATTRIBUTES || attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn has_reparse_point(_: &Path) -> bool {
    false
}

fn valid_cached_file(
    path: &Path,
    expected: &[u8; 64],
    expected_len: usize,
    target: &str,
) -> Result<bool, String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(format!(
                "cannot inspect cached FFI library {}: {error}",
                path.display()
            ))
        }
    };
    if !metadata.file_type().is_file() || has_reparse_point(path) {
        return Ok(false);
    }
    #[cfg(unix)]
    if metadata.uid() != unsafe { libc::getuid() } || metadata.mode() & 0o077 != 0 {
        return Ok(false);
    }
    if metadata.len() != expected_len as u64 {
        return Ok(false);
    }
    let bytes = std::fs::read(path)
        .map_err(|error| format!("cannot read cached FFI library {}: {error}", path.display()))?;
    if &raw_sha512(&bytes) != expected {
        return Ok(false);
    }
    Ok(validate_ffi_target_object(&bytes, target).is_ok())
}

fn write_atomic(
    destination: &Path,
    bytes: &[u8],
    expected: &[u8; 64],
    target: &str,
) -> Result<(), String> {
    let parent = destination
        .parent()
        .ok_or_else(|| "FFI cache file has no parent".to_owned())?;
    for _ in 0..128 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp = parent.join(format!(".ffi-{}-{sequence}.tmp", std::process::id()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&temp) {
            Ok(mut file) => {
                let write_result =
                    std::io::Write::write_all(&mut file, bytes).and_then(|()| file.sync_all());
                drop(file);
                if let Err(error) = write_result {
                    let _ = std::fs::remove_file(&temp);
                    return Err(format!(
                        "cannot write FFI cache temporary {}: {error}",
                        temp.display()
                    ));
                }
                match std::fs::rename(&temp, destination) {
                    Ok(()) => return Ok(()),
                    Err(error) => {
                        let _ = std::fs::remove_file(&temp);
                        if valid_cached_file(destination, expected, bytes.len(), target)
                            .unwrap_or(false)
                        {
                            return Ok(());
                        }
                        return Err(format!(
                            "cannot replace FFI cache file {}: {error}",
                            destination.display()
                        ));
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "cannot create FFI cache temporary {}: {error}",
                    temp.display()
                ))
            }
        }
    }
    Err("cannot allocate a unique FFI cache temporary file".to_owned())
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

    fn elf64_x64() -> Vec<u8> {
        let mut bytes = vec![0u8; 64];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&0x003eu16.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes
    }

    fn scratch_dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "abitious-ffi-stub-test-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).expect("create scratch directory");
        path
    }

    #[test]
    fn cache_hit_checks_full_hash_and_size() {
        let dir = scratch_dir();
        let path = dir.join("library.so");
        let bytes = elf64_x64();
        std::fs::write(&path, &bytes).expect("write cache entry");
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .expect("set private file mode");
        assert!(
            valid_cached_file(&path, &raw_sha512(&bytes), bytes.len(), "linux-x64-gnu")
                .expect("validate hit")
        );
        assert!(
            !valid_cached_file(&path, &[0; 64], bytes.len(), "linux-x64-gnu")
                .expect("reject hash mismatch")
        );
        assert!(
            !valid_cached_file(&path, &raw_sha512(&bytes), bytes.len() + 1, "linux-x64-gnu")
                .expect("reject size mismatch")
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn cache_rejects_a_symlink_directory() {
        use std::os::unix::fs::symlink;
        let root = scratch_dir();
        let target = root.join("target");
        std::fs::create_dir(&target).expect("create target directory");
        let link = root.join("cache-link");
        symlink(&target, &link).expect("create directory symlink");
        assert!(prepare_cache_dir(&link).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn concurrent_cache_writers_publish_one_verified_file() {
        let dir = scratch_dir();
        let destination = dir.join("library.so");
        let bytes = elf64_x64();
        let expected = raw_sha512(&bytes);
        let mut writers = Vec::new();
        for _ in 0..6 {
            let destination = destination.clone();
            let bytes = bytes.clone();
            writers.push(std::thread::spawn(move || {
                write_atomic(&destination, &bytes, &expected, "linux-x64-gnu")
            }));
        }
        for writer in writers {
            writer
                .join()
                .expect("writer thread")
                .expect("write cache entry");
        }
        assert!(
            valid_cached_file(&destination, &expected, bytes.len(), "linux-x64-gnu")
                .expect("validate result")
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
