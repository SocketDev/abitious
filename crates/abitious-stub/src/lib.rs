//! The generic abitious **self-extracting trampoline stub**.
//!
//! ONE prebuilt stub cdylib ships per platform/arch. The producer
//! (`abitious-producer`) injects the compressed REAL addon into this stub's
//! `SMOL/__PRESSED_DATA` **section**, yielding a hybrid `.node`. When Node `dlopen`s the
//! hybrid it runs the STUB's `napi_register_module_v1`, which:
//!
//!   1. finds its own on-disk path (`abitious_decmpfs::selfextract::self_path`, `dladdr`),
//!   2. `resolve_self`s it — reads its own bytes, `unwrap_if_hybrid`s the
//!      `SMOL/__PRESSED_DATA` SECTION (NOT an EOF footer), and writes the raw addon to a
//!      per-uid, content-addressed cache file,
//!   3. `dlopen`s that cache file and `dlsym`s its `napi_register_module_v1`,
//!   4. forwards the SAME `(env, exports)` to the real addon and returns its result.
//!
//! The stub never calls a napi API itself — it only forwards opaque pointers, so it links
//! nothing from Node. **Fail-soft**: on ANY failure it returns the `exports` it was given
//! unchanged, so a mis-produced or unreadable hybrid degrades to an empty module rather
//! than crashing the host process.

// cargo-llvm-cov (nightly) sets `coverage_nightly`, enabling `#[coverage(off)]` on the
// dlopen-only trampoline (reached only under a real Node `dlopen`) and the in-module test
// block. A no-op on stable.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::ffi::c_void;
#[allow(unused_imports)] // `Path` is used by the unix + windows `load_register` arms.
use std::path::Path;

use abitious_decmpfs::selfextract::{resolve_self, self_path};

/// Opaque `napi_env` — the stub only forwards it, never dereferences it.
type NapiEnv = *mut c_void;
/// Opaque `napi_value` — likewise forwarded verbatim.
type NapiValue = *mut c_void;
/// The N-API module entry point signature, shared by the stub and the real addon.
type RegisterFn = unsafe extern "C" fn(NapiEnv, NapiValue) -> NapiValue;

/// Node's entry point for a native addon.
///
/// # Safety
/// Called by Node during module load with a valid `env` and `exports`.
// coverage(off): this cdylib entry — and the `trampoline` / `load_register` it drives — run
// only when Node `dlopen`s a real hybrid, so their SUCCESS (self-extract → dlopen → forward)
// path is unreachable in-process. It is proven end-to-end by the gated M3/M4/M6 Node-dlopen
// e2e (the marker-file oracle), which loads a SEPARATELY-BUILT, uninstrumented stub dylib
// that llvm-cov cannot observe — so it is excluded from the denominator rather than counted
// 0%. The in-module tests below still guard the fail-soft arms in-process.
#[cfg_attr(coverage_nightly, coverage(off))]
#[no_mangle]
pub unsafe extern "C" fn napi_register_module_v1(env: NapiEnv, exports: NapiValue) -> NapiValue {
  match trampoline(env, exports) {
    Some(real_exports) => real_exports,
    // Fail-soft: hand back the exports we were given rather than crash the host.
    None => exports,
  }
}

/// The self-extract → dlopen → forward path. Any `None` short-circuits to the fail-soft
/// fallback in [`napi_register_module_v1`].
///
/// # Safety
/// `env`/`exports` are the opaque pointers Node handed us; they are only forwarded to the
/// real addon's register function, never dereferenced here.
// coverage(off): see `napi_register_module_v1` — the success forward path is Node-dlopen-only
// (e2e-proven); the fail-soft `?` short-circuits are guarded by the in-module tests.
#[cfg_attr(coverage_nightly, coverage(off))]
unsafe fn trampoline(env: NapiEnv, exports: NapiValue) -> Option<NapiValue> {
  let me = self_path()?;
  // Section-based extraction (M1's unwrap_if_hybrid), NOT a footer: resolve_self returns
  // the path of the raw addon written to the content-addressed cache. `None` = this file
  // is not a hybrid (or an I/O error) → fail-soft.
  let loadable = resolve_self(&me)?;
  let register = load_register(&loadable)?;
  Some(register(env, exports))
}

/// `dlopen` the extracted addon and resolve its `napi_register_module_v1`.
///
/// `RTLD_LOCAL` keeps the real addon's symbols out of the global namespace, so the
/// `dlsym` below (scoped to this handle) resolves the addon's OWN register function and
/// never loops back into this stub's exported symbol of the same name.
///
/// # Safety
/// FFI into the dynamic loader; the returned pointer is transmuted to the shared
/// `RegisterFn` ABI, which the addon exports with exactly this signature.
// coverage(off): the dlsym-SUCCESS + transmute tail is reached only when Node dlopens a real
// addon exporting `napi_register_module_v1` (e2e-proven); the dlopen-null / dlsym-null
// fail-soft arms are guarded by the in-module tests.
#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(unix)]
unsafe fn load_register(path: &Path) -> Option<RegisterFn> {
  use std::os::unix::ffi::OsStrExt;

  let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
  let handle = libc::dlopen(cpath.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
  if handle.is_null() {
    return None;
  }
  let sym = libc::dlsym(handle, c"napi_register_module_v1".as_ptr());
  if sym.is_null() {
    return None;
  }
  Some(std::mem::transmute::<*mut c_void, RegisterFn>(sym))
}

/// Windows: `LoadLibraryW` + `GetProcAddress`. Best-effort for M3 (darwin-arm64 is the
/// proof target).
///
/// # Safety
/// FFI into the Windows loader; the resolved proc address is transmuted to the shared
/// `RegisterFn` ABI the addon exports.
// coverage(off): Windows loader forward — reached only under a real Node dlopen on win32
// (best-effort target); excluded like the unix twin above.
#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(windows)]
unsafe fn load_register(path: &Path) -> Option<RegisterFn> {
  use std::os::windows::ffi::OsStrExt;

  use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

  let wide: Vec<u16> = path
    .as_os_str()
    .encode_wide()
    .chain(std::iter::once(0))
    .collect();
  let module = LoadLibraryW(wide.as_ptr());
  if module.is_null() {
    return None;
  }
  let proc = GetProcAddress(module, c"napi_register_module_v1".as_ptr().cast())?;
  Some(std::mem::transmute::<
    unsafe extern "system" fn() -> isize,
    RegisterFn,
  >(proc))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
  use super::*;

  #[test]
  fn register_is_fail_soft_when_self_is_not_a_hybrid() {
    // In the test binary `self_path()` resolves to this (non-hybrid) executable, so
    // `resolve_self` returns None and the trampoline short-circuits: the entry hands back
    // the exact `exports` pointer it was given — fail-soft, never a crash on the host.
    let exports = 0xABCD_1234_usize as NapiValue;
    let got = unsafe { napi_register_module_v1(std::ptr::null_mut(), exports) };
    assert_eq!(
      got, exports,
      "fail-soft returns the given exports unchanged"
    );
  }

  #[cfg(unix)]
  #[test]
  fn load_register_is_none_for_a_nonexistent_path() {
    // dlopen of a path that does not exist → null handle → None (never a bogus transmute).
    let got = unsafe { load_register(Path::new("/no/such/abitious-stub/addon.node")) };
    assert!(got.is_none());
  }

  #[cfg(unix)]
  #[test]
  fn load_register_is_none_when_the_napi_symbol_is_absent() {
    // A real, loadable system dylib that does NOT export napi_register_module_v1: dlopen
    // succeeds but dlsym returns null → None. (macOS system libs load from the dyld cache
    // even without an on-disk file, so dlopen-by-name still yields a handle.)
    #[cfg(target_os = "macos")]
    let lib = Path::new("/usr/lib/libSystem.B.dylib");
    #[cfg(not(target_os = "macos"))]
    let lib = Path::new("libc.so.6");
    let got = unsafe { load_register(lib) };
    assert!(
      got.is_none(),
      "a lib without the napi symbol resolves to None"
    );
  }
}
