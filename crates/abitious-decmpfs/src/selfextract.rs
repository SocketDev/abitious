//! Runtime **self-extraction** — the STUB half of a hybrid `.node`.
//!
//! When Node `dlopen`s a hybrid, the generic stub's `napi_register_module_v1` runs and
//! must recover the REAL addon that was compressed into its own
//! `SMOL/__PRESSED_DATA` **section** (M1's [`crate::unwrap_if_hybrid`] — a SECTION read,
//! never an EOF footer). The flow is:
//!
//! 1. [`self_path`] — find the on-disk path of the CURRENTLY-LOADED module via
//!    `dladdr` on a local function pointer (unix) / `GetModuleFileNameW` (Windows).
//! 2. [`resolve_self`] — read those bytes, [`crate::unwrap_if_hybrid`] them, and if the
//!    file IS a hybrid, atomically write the raw addon to a per-uid, content-addressed
//!    [`cache_path`] (reusing a warm cache file of the right size) and return that path.
//!    A non-hybrid, or ANY I/O error, returns `None`.
//! 3. the stub then `dlopen`s the returned path and forwards `napi_register_module_v1`.
//!
//! Every step is **fail-soft**: `Option`-returning, no panics, so the stub can fall back
//! to its own (empty) exports and never crash the host.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::unwrap_if_hybrid;

/// The 16-byte content-address the cache path is keyed on: the first 16 bytes of
/// SHA-256 over the raw addon — byte-for-byte the `cache_key` field
/// [`crate::build_section_payload`] stamps into the section, so the extracted file's
/// name matches what a producer reports.
const CACHE_KEY_LEN: usize = 16;

/// The on-disk path of the CURRENTLY-LOADED module (the hybrid `.node` this code is
/// linked into). `None` if the platform lookup fails.
///
/// On unix this is `dladdr` over a local function pointer: the returned `dli_fname` is
/// the path of the shared object that address lives in — i.e. THIS module. Because
/// `abitious-decmpfs` is statically linked into the stub cdylib, `anchor`'s code lives
/// in the loaded `.node`, so `dladdr` resolves to the hybrid on disk.
#[cfg(unix)]
pub fn self_path() -> Option<PathBuf> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;

    // A stable, non-inlined anchor whose address is guaranteed to sit inside this
    // module's image (a plain fn item would risk being merged/elided under LTO).
    extern "C" fn anchor() {}

    // SAFETY: `dladdr` reads the symbol table for the address we pass and only writes
    // the zeroed `Dl_info`; `dli_fname` (when non-null) is a NUL-terminated C string
    // owned by the loader, valid for the duration of this call.
    unsafe {
        let mut info: libc::Dl_info = std::mem::zeroed();
        if libc::dladdr(anchor as *const libc::c_void, &mut info) == 0 || info.dli_fname.is_null() {
            return None;
        }
        let bytes = CStr::from_ptr(info.dli_fname).to_bytes();
        if bytes.is_empty() {
            return None;
        }
        Some(PathBuf::from(OsStr::from_bytes(bytes)))
    }
}

/// Windows: the path of the module containing a local address, via
/// `GetModuleHandleExW(FROM_ADDRESS)` + `GetModuleFileNameW`. Best-effort for M3
/// (darwin-arm64 is the proof target).
#[cfg(windows)]
pub fn self_path() -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;

    use windows_sys::Win32::System::LibraryLoader::{
        GetModuleFileNameW, GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    };

    extern "C" fn anchor() {}

    // SAFETY: FFI into the loader. `module` is written by `GetModuleHandleExW`; the
    // buffer is stack-owned and sized before `GetModuleFileNameW` copies into it.
    unsafe {
        let mut module = std::ptr::null_mut();
        let ok = GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            anchor as *const u16,
            &mut module,
        );
        if ok == 0 {
            return None;
        }
        let mut buf = [0u16; 32768];
        let len = GetModuleFileNameW(module, buf.as_mut_ptr(), buf.len() as u32);
        if len == 0 {
            return None;
        }
        Some(PathBuf::from(std::ffi::OsString::from_wide(
            &buf[..len as usize],
        )))
    }
}

/// The current effective user id — namespaces the cache directory so it is not shared in
/// a world-writable `/tmp` (the cache-poisoning surface). Node itself appends `getuid()`
/// to its compile-cache key for the same reason; `%TEMP%` is already per-user on Windows.
#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: `getuid` is always safe and never fails.
    unsafe { libc::getuid() }
}

#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

/// A per-uid, content-addressed cache path for the extracted addon:
/// `<tmpdir>/abitious-cache/<uid>/<stem>-<hex cache_key>.node`.
///
/// Keying the file name on `cache_key` (the raw addon's content hash) means every distinct
/// addon gets a distinct, reusable file and the same addon always resolves to the same
/// path — so [`resolve_self`] can skip re-extracting on a warm hit. The `<uid>` subdir
/// keeps one user's cache out of another's writable reach.
pub fn cache_path(self_file: &Path, cache_key: &[u8]) -> PathBuf {
    let stem = self_file
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "addon".to_string());
    let mut name = String::with_capacity(stem.len() + 1 + cache_key.len() * 2 + 5);
    name.push_str(&stem);
    name.push('-');
    for byte in cache_key {
        use std::fmt::Write as _;
        // Infallible: writing to a String never errors.
        let _ = write!(name, "{byte:02x}");
    }
    name.push_str(".node");
    std::env::temp_dir()
        .join("abitious-cache")
        .join(current_uid().to_string())
        .join(name)
}

/// If `self_file` is a pressed-data hybrid, extract its embedded addon to the content-
/// addressed [`cache_path`] and return that path; otherwise (a plain, non-hybrid file)
/// return `None`. Fail-soft: ANY I/O, format, or integrity failure returns `None`.
///
/// A warm cache hit (the target already exists with the right size) is reused without
/// re-writing. On a miss the raw addon is written atomically (temp + rename) so a
/// concurrent loader never `dlopen`s a half-written file.
pub fn resolve_self(self_file: &Path) -> Option<PathBuf> {
    let bytes = std::fs::read(self_file).ok()?;
    // `None` here means "not a hybrid" (a plain addon or an unrecognized file) OR a failed
    // integrity check — either way the caller should not self-extract.
    let raw = unwrap_if_hybrid(&bytes)?;

    let cache_key = cache_key_of(&raw);
    let dest = cache_path(self_file, &cache_key);

    // Warm hit: an existing file of exactly the right size is trusted (its name is the
    // content hash) and reused with no decode and no write.
    if let Ok(meta) = std::fs::metadata(&dest) {
        if meta.len() == raw.len() as u64 {
            return Some(dest);
        }
    }

    let parent = dest.parent()?;
    std::fs::create_dir_all(parent).ok()?;
    write_atomic(&dest, &raw)?;
    Some(dest)
}

/// The 16-byte content-address of `raw` — the first 16 bytes of SHA-256, identical to the
/// `cache_key` [`crate::build_section_payload`] stamps into the section.
fn cache_key_of(raw: &[u8]) -> [u8; CACHE_KEY_LEN] {
    let digest = Sha256::digest(raw);
    let mut key = [0u8; CACHE_KEY_LEN];
    key.copy_from_slice(&digest[..CACHE_KEY_LEN]);
    key
}

/// Write `data` to a sibling temp file then rename it over `dest`, so a crash or a
/// concurrent reader never observes a partial extraction. The temp name is scoped to this
/// process (pid) and directory; a failed rename removes exactly that named temp.
fn write_atomic(dest: &Path, data: &[u8]) -> Option<()> {
    let dir = dest.parent()?;
    let file_name = dest.file_name()?.to_string_lossy().into_owned();
    let tmp = dir.join(format!(".{file_name}.{}.tmp", std::process::id()));
    std::fs::write(&tmp, data).ok()?;
    if std::fs::rename(&tmp, dest).is_err() {
        // Best-effort cleanup of the exact temp path we just created (never a glob).
        let _ = std::fs::remove_file(&tmp);
        return None;
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build_section_payload, inject_pressed_data, Arch, Libc, Platform};

    /// A scratch dir unique to one test; the test removes exactly this named dir.
    fn scratch_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "abitious-selfextract-{label}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    #[test]
    fn cache_path_is_per_uid_and_content_addressed() {
        let p = cache_path(Path::new("/some/dir/foo.node"), &[0xde, 0xad, 0xbe, 0xef]);
        let s = p.to_string_lossy();
        assert!(s.contains("abitious-cache"), "{s}");
        assert!(s.ends_with("foo-deadbeef.node"), "{s}");
        assert!(
            s.contains(&current_uid().to_string()),
            "cache path missing uid subdir: {s}"
        );
    }

    #[test]
    fn resolve_self_round_trips_an_injected_hybrid() {
        let dir = scratch_dir("roundtrip");
        // A raw "addon" (any bytes) → build the section → inject into a minimal ELF stub
        // (no code-signing needed for the round-trip) → write to a temp file.
        let raw = b"\x7fELF the real abitious addon payload, repeated!".repeat(37);
        let section = build_section_payload(&raw, Platform::Linux, Arch::X64, Libc::Glibc, 16);
        let hybrid = inject_pressed_data(&minimal_elf64(), &section).expect("inject");
        let hybrid_path = dir.join("hybrid.node");
        std::fs::write(&hybrid_path, &hybrid).expect("write hybrid");

        // resolve_self extracts to a cache path whose bytes == the original raw addon.
        let cached = resolve_self(&hybrid_path).expect("resolve_self returns Some for a hybrid");
        let got = std::fs::read(&cached).expect("read cache file");
        assert_eq!(got, raw, "extracted bytes differ from the original addon");

        // The cache path is content-addressed to the raw's SHA-256 prefix.
        assert_eq!(cached, cache_path(&hybrid_path, &cache_key_of(&raw)));

        // A second call is a warm hit and returns the same path.
        assert_eq!(
            resolve_self(&hybrid_path).as_deref(),
            Some(cached.as_path())
        );

        // Cleanup: exact named files only.
        let _ = std::fs::remove_file(&cached);
        let _ = std::fs::remove_file(&hybrid_path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_self_returns_none_for_a_plain_file() {
        let dir = scratch_dir("plain");
        let plain = dir.join("plain.node");
        std::fs::write(&plain, b"not a hybrid, just some bytes").expect("write plain");
        assert!(resolve_self(&plain).is_none());
        let _ = std::fs::remove_file(&plain);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_self_returns_none_for_a_missing_file() {
        let missing = std::env::temp_dir().join("abitious-selfextract-does-not-exist.node");
        assert!(resolve_self(&missing).is_none());
    }

    // A minimal valid ELF64 LE stub with a `.shstrtab` + 2-entry section table — the same
    // shape `inject::tests::minimal_elf64` grows; duplicated here so this module's test
    // does not reach into inject's private test helpers.
    fn minimal_elf64() -> Vec<u8> {
        fn put_u16(b: &mut [u8], off: usize, v: u16) {
            b[off..off + 2].copy_from_slice(&v.to_le_bytes());
        }
        fn put_u32(b: &mut [u8], off: usize, v: u32) {
            b[off..off + 4].copy_from_slice(&v.to_le_bytes());
        }
        fn put_u64(b: &mut [u8], off: usize, v: u64) {
            b[off..off + 8].copy_from_slice(&v.to_le_bytes());
        }
        let shstr: &[u8] = b"\0.shstrtab\0";
        let shoff = 80usize;
        let mut e = vec![0u8; shoff + 2 * 64];
        e[0..4].copy_from_slice(b"\x7fELF");
        e[4] = 2; // 64-bit
        e[5] = 1; // little-endian
        e[6] = 1; // version
        put_u64(&mut e, 40, shoff as u64); // e_shoff
        put_u16(&mut e, 58, 64); // e_shentsize
        put_u16(&mut e, 60, 2); // e_shnum
        put_u16(&mut e, 62, 1); // e_shstrndx
        e[64..64 + shstr.len()].copy_from_slice(shstr);
        let sh1 = shoff + 64;
        put_u32(&mut e, sh1, 1); // sh_name -> ".shstrtab"
        put_u32(&mut e, sh1 + 4, 3); // sh_type = SHT_STRTAB
        put_u64(&mut e, sh1 + 24, 64); // sh_offset
        put_u64(&mut e, sh1 + 32, shstr.len() as u64); // sh_size
        e
    }
}
