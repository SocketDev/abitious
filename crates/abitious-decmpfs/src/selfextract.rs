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
//!    [`cache_path`] and return that path. A warm cache file is reused only after its
//!    **SHA-512 is re-verified** against the addon the section decodes to (so a poisoned
//!    entry in a shared `/tmp` is never `dlopen`ed — see [`resolve_self`]). A non-hybrid,
//!    or ANY I/O error, returns `None`.
//! 3. the stub then `dlopen`s the returned path and forwards `napi_register_module_v1`.
//!
//! Every step is **fail-soft**: `Option`-returning, no panics, so the stub can fall back
//! to its own (empty) exports and never crash the host.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256, Sha512};

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
/// ## Warm-hit integrity re-verification (cache-poisoning defense)
/// The cache lives under a world-writable `/tmp` in the common case. A warm hit's file
/// NAME is the content address, but the file's CONTENTS could have been corrupted or
/// **poisoned** since we wrote it. Before handing a warm-hit path to the stub for
/// `dlopen`, its **SHA-512 is re-verified** against `expected` — the SHA-512 of the raw
/// addon this run just decoded AND integrity-checked ([`crate::unwrap_if_hybrid`] verifies
/// the section payload's SHA-512 before decompressing). A size mismatch, a hash mismatch,
/// or any read error is treated as a MISS: the addon is re-extracted (atomic overwrite)
/// and the fresh copy is used, so a poisoned/corrupt cache entry is never `dlopen`ed.
///
/// On a miss the raw addon is written atomically (temp + rename) so a concurrent loader
/// never `dlopen`s a half-written file.
pub fn resolve_self(self_file: &Path) -> Option<PathBuf> {
    let bytes = std::fs::read(self_file).ok()?;
    // `None` here means "not a hybrid" (a plain addon or an unrecognized file) OR a failed
    // integrity check — either way the caller should not self-extract.
    let raw = unwrap_if_hybrid(&bytes)?;

    let cache_key = cache_key_of(&raw);
    let dest = cache_path(self_file, &cache_key);

    // The trusted content hash: SHA-512 of the just-decoded, integrity-checked addon.
    let expected = sha512_of(&raw);

    // Warm hit: reuse an existing cache file ONLY if it is the exact right size AND its
    // SHA-512 matches `expected`. A mismatch (poisoned/corrupt) or any read error falls
    // through to a fresh, atomic re-extraction below.
    if let Ok(meta) = std::fs::metadata(&dest) {
        if meta.len() == raw.len() as u64 && sha512_file(&dest).as_ref() == Some(&expected) {
            return Some(dest);
        }
    }

    let parent = dest.parent()?;
    prepare_cache_dir(parent)?;
    write_atomic(&dest, &raw)?;
    Some(dest)
}

/// SHA-512 of an in-memory addon — the trusted content hash a warm hit is checked against.
fn sha512_of(data: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out.copy_from_slice(&Sha512::digest(data));
    out
}

/// Stream `path` through SHA-512 via a fixed 64 KiB buffer, never materializing a second
/// full copy of the addon (the decoded bytes are already in memory), so re-verifying a
/// warm hit stays memory-cheap even for a large `.node`. `None` on any read error.
fn sha512_file(path: &Path) -> Option<[u8; 64]> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha512::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&hasher.finalize());
    Some(out)
}

/// Prepare — and defensively validate — the per-uid cache directory before an addon is
/// extracted into it.
///
/// ## Threat model
/// `std::env::temp_dir()` is usually the world-writable `/tmp`. The cache is
/// `<tmpdir>/abitious-cache/<uid>/…`; the per-uid subdir is the trust boundary. A local
/// attacker could pre-create that subdir (or a symlink standing in for it) so an addon we
/// extract lands where they control, or so a poisoned file is waiting there. The PRIMARY
/// defense is the SHA-512-on-read re-verify in [`resolve_self`] (a poisoned entry is never
/// `dlopen`ed); this is cheap defense-in-depth:
///  * create the per-uid dir `0700` (owner-only), so no other user can drop files into a
///    dir we created;
///  * refuse to use it when it is a **symlink**, is **not owned by us**, or is
///    **group/other-writable** — each a signal it was pre-planted. Every refusal is
///    fail-soft (`None`; the stub falls back rather than trusting an attacker-shaped dir).
///
/// The atomic write ([`write_atomic`]) additionally opens the temp with
/// `O_NOFOLLOW`+`O_EXCL` so a pre-planted symlink/file at the temp path is refused rather
/// than written through.
#[cfg(unix)]
fn prepare_cache_dir(dir: &Path) -> Option<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    // The shared `abitious-cache` parent can be world-readable; the per-uid dir is the
    // boundary and is created 0700.
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).ok()?;
    }
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        // Already there from an earlier run (or a race) — fall through to validate it.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return None,
    }
    // Validate WITHOUT following a symlink.
    let meta = std::fs::symlink_metadata(dir).ok()?;
    if !meta.file_type().is_dir() {
        return None; // a symlink or plain file squatting the cache path — refuse.
    }
    if meta.uid() != current_uid() {
        return None; // owned by someone else — pre-planted; refuse.
    }
    if meta.mode() & 0o022 != 0 {
        return None; // group/other-writable — refuse.
    }
    Some(())
}

/// Non-unix: `%TEMP%` is already per-user, so just materialize the directory.
#[cfg(not(unix))]
fn prepare_cache_dir(dir: &Path) -> Option<()> {
    std::fs::create_dir_all(dir).ok()
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
///
/// The temp is opened `O_EXCL` (`create_new`) — plus `O_NOFOLLOW` on unix — so a
/// pre-planted file OR symlink at the exact temp path is refused rather than written
/// through (no write via a link an attacker dropped in a shared `/tmp`). A stale temp
/// from a crashed same-pid run is cleared first, by exact named path only — never a glob.
fn write_atomic(dest: &Path, data: &[u8]) -> Option<()> {
    use std::io::Write;

    let dir = dest.parent()?;
    let file_name = dest.file_name()?.to_string_lossy().into_owned();
    let tmp = dir.join(format!(".{file_name}.{}.tmp", std::process::id()));
    // `remove_file` unlinks the name itself (it does not follow a symlink), so clearing a
    // stale/pre-planted temp is safe; the O_EXCL open below then owns a fresh inode.
    let _ = std::fs::remove_file(&tmp);

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }

    let wrote = (|| -> std::io::Result<()> {
        let mut file = opts.open(&tmp)?;
        file.write_all(data)?;
        file.sync_all()
    })();
    if wrote.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return None;
    }
    if std::fs::rename(&tmp, dest).is_err() {
        // Best-effort cleanup of the exact temp path we just created (never a glob).
        let _ = std::fs::remove_file(&tmp);
        return None;
    }
    Some(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{build_section_payload, inject_pressed_data, Arch, Libc, Platform};

    #[cfg(unix)]
    #[test]
    fn self_path_resolves_the_loaded_module() {
        // dladdr on a local fn pointer resolves to THIS instrumented test binary — a real,
        // existing path — exercising the unix self_path happy path end to end.
        let p = self_path().expect("self_path resolves the loaded module");
        assert!(
            p.exists(),
            "self_path must point at a real file: {}",
            p.display()
        );
    }

    #[cfg(unix)]
    #[test]
    fn prepare_cache_dir_fails_soft_under_a_read_only_parent() {
        use std::os::unix::fs::PermissionsExt;
        // Root bypasses mode bits, so skip there.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let base = scratch_dir("prep-ro-parent");
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o500)).unwrap();
        // One level under a read-only dir → the DirBuilder create hits EACCES (not
        // AlreadyExists) → fail-soft None.
        assert!(prepare_cache_dir(&base.join("c")).is_none());
        // Two levels under → create_dir_all(parent) itself fails → fail-soft None.
        assert!(prepare_cache_dir(&base.join("a").join("b")).is_none());
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).ok();
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn write_atomic_fails_soft_when_the_rename_target_is_a_directory() {
        // The temp create + write succeed, but renaming a file over an existing directory
        // fails (EISDIR) → the rename-error cleanup arm returns None, dir left intact.
        let dir = scratch_dir("wa-rename");
        let target = dir.join("a-dir");
        std::fs::create_dir_all(&target).unwrap();
        assert!(write_atomic(&target, b"data").is_none());
        assert!(target.is_dir(), "the directory target is untouched");
        let _ = std::fs::remove_dir_all(&dir);
    }

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

    #[test]
    fn resolve_self_reextracts_a_same_length_tampered_cache_file() {
        // Deliverable 1: a warm cache hit must SHA-512-verify. Poison the cache file with
        // SAME-LENGTH but different bytes (so the size check passes and only the hash
        // re-verify can catch it) and prove the poison is detected + replaced, never loaded.
        let dir = scratch_dir("tamper");
        let raw = b"\x7fELF real abitious addon bytes, compressible payload here! ".repeat(29);
        let section = build_section_payload(&raw, Platform::Linux, Arch::X64, Libc::Glibc, 16);
        let hybrid = inject_pressed_data(&minimal_elf64(), &section).expect("inject");
        let hybrid_path = dir.join("hybrid.node");
        std::fs::write(&hybrid_path, &hybrid).expect("write hybrid");

        // Cold extract → the cache file holds the exact raw addon.
        let cached = resolve_self(&hybrid_path).expect("cold extract");
        assert_eq!(std::fs::read(&cached).unwrap(), raw);

        // POISON: same length, different bytes.
        let poison = vec![0xAAu8; raw.len()];
        assert_ne!(poison, raw, "poison must differ from the addon");
        std::fs::write(&cached, &poison).expect("poison the cache file");
        assert_eq!(std::fs::metadata(&cached).unwrap().len(), raw.len() as u64);

        // Re-resolve: the tamper is detected (hash mismatch) and the addon re-extracted;
        // the FINAL bytes equal the section's raw addon, never the poison.
        let reused = resolve_self(&hybrid_path).expect("re-extract after tamper");
        assert_eq!(reused, cached, "same content-addressed path");
        assert_eq!(
            std::fs::read(&reused).unwrap(),
            raw,
            "the tampered cache entry was replaced with the verified addon"
        );

        let _ = std::fs::remove_file(&cached);
        let _ = std::fs::remove_file(&hybrid_path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn prepare_cache_dir_creates_0700_and_validates_idempotently() {
        use std::os::unix::fs::PermissionsExt;
        let base = scratch_dir("prep-ok");
        let cache = base.join("uid-cache");
        assert!(prepare_cache_dir(&cache).is_some(), "fresh dir prepared");
        let mode = std::fs::metadata(&cache).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "per-uid dir is owner-only");
        // Second call: exists, owned by us, 0700 → still Some.
        assert!(prepare_cache_dir(&cache).is_some(), "idempotent");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn prepare_cache_dir_refuses_a_symlinked_cache_dir() {
        let base = scratch_dir("prep-symlink");
        let real = base.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(
            prepare_cache_dir(&link).is_none(),
            "a symlinked cache dir is refused (no writing through a pre-planted link)"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn prepare_cache_dir_refuses_a_world_writable_dir() {
        use std::os::unix::fs::PermissionsExt;
        let base = scratch_dir("prep-ww");
        let cache = base.join("uid-cache");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            prepare_cache_dir(&cache).is_none(),
            "a group/other-writable cache dir is refused"
        );
        std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o755)).ok();
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn write_atomic_fails_soft_on_a_bad_destination() {
        // No parent (root) → early None; and a parent dir that does not exist → the O_EXCL
        // temp open fails → None. Neither panics.
        assert!(write_atomic(Path::new("/"), b"x").is_none());
        let missing = std::env::temp_dir()
            .join(format!("abitious-selfextract-nodir-{}", std::process::id()))
            .join("sub")
            .join("x.node");
        assert!(write_atomic(&missing, b"data").is_none());
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
