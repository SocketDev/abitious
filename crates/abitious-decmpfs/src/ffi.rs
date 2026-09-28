use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::Path;

use crate::{probe, stat, Outcome, Support};

/// Return the FFI ABI version supported by this library.
#[no_mangle]
pub extern "C" fn abitious_ffi_version() -> u32 {
    1
}

/// Probe the filesystem containing `path`: 0 supported, 1 already compressed,
/// 2 unsupported, and -1 for invalid input or I/O failure.
#[no_mangle]
pub unsafe extern "C" fn abitious_probe(path: *const c_char) -> i32 {
    let Some(path) = c_path(path) else {
        return -1;
    };
    match probe(Path::new(path)) {
        Ok(Support::Supported) => 0,
        Ok(Support::AlreadyCompressed) => 1,
        Ok(Support::Unsupported(_)) => 2,
        Err(_) => -1,
    }
}

/// Inspect a file and write its state to non-null output pointers.
/// Returns 0 on success and -1 for invalid input or I/O failure.
#[no_mangle]
pub unsafe extern "C" fn abitious_stat(
    path: *const c_char,
    compressed: *mut bool,
    logical: *mut u64,
    physical: *mut u64,
) -> i32 {
    let Some(path) = c_path(path) else {
        return -1;
    };
    if compressed.is_null() || logical.is_null() || physical.is_null() {
        return -1;
    }
    let Ok(result) = stat(Path::new(path)) else {
        return -1;
    };
    // SAFETY: each output pointer was checked non-null and the caller owns it.
    unsafe {
        compressed.write(result.compressed);
        logical.write(result.logical);
        physical.write(result.physical);
    }
    0
}

/// Compress `path` with the OS filesystem backend. Returns the Outcome code or -1
/// for invalid input or an I/O error. Optional size pointers receive byte counts.
#[no_mangle]
pub unsafe extern "C" fn abitious_compress_file(
    path: *const c_char,
    before: *mut u64,
    after: *mut u64,
) -> i32 {
    let Some(path) = c_path(path) else {
        return -1;
    };
    let Ok(outcome) = crate::decmpfs::compress_file(Path::new(path)) else {
        return -1;
    };
    let (code, sizes) = match outcome {
        Outcome::Compressed { before, after } => (0, Some((before, after))),
        Outcome::NoGain { before, after } => (1, Some((before, after))),
        Outcome::AlreadyCompressed { before } => (2, Some((before, before))),
        Outcome::Unsupported { .. } => (3, None),
        Outcome::Skipped { .. } => (4, None),
    };
    if let Some((logical_before, logical_after)) = sizes {
        // SAFETY: optional output pointers are checked before each write.
        unsafe {
            if !before.is_null() {
                before.write(logical_before);
            }
            if !after.is_null() {
                after.write(logical_after);
            }
        }
    }
    code
}

unsafe fn c_path<'a>(path: *const c_char) -> Option<&'a str> {
    if path.is_null() {
        return None;
    }
    // SAFETY: the caller must pass a valid NUL-terminated UTF-8 path string.
    unsafe { CStr::from_ptr(path) }.to_str().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_version_is_stable_and_null_paths_fail_soft() {
        assert_eq!(abitious_ffi_version(), 1);
        // SAFETY: null is an explicitly supported invalid-input probe.
        assert_eq!(unsafe { abitious_probe(std::ptr::null()) }, -1);
        // SAFETY: null is an explicitly supported invalid-input probe.
        assert_eq!(
            unsafe {
                abitious_stat(
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            -1
        );
    }
}
