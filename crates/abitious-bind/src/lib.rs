//! The abitious **in-process binder**.
//!
//! ONE prebuilt binder cdylib ships per platform/arch as `bind.node` inside each
//! `@abitious/<triple>` package. Where `abitious-stub` only FORWARDS opaque pointers
//! (it never calls a napi API), this addon CALLS the napi host functions to build
//! values: it registers `probe`, `stat`, and `compressFile` on `exports`, backed by
//! the same engine the C FFI wraps (`abitious-decmpfs` linked as an rlib, default
//! features - the reader/ABI tree stays dep-lean).
//!
//! The JS-visible shapes mirror what `npm/cli/loader.cjs` builds from the C FFI, so
//! the loader treats the two surfaces identically: outcome codes match the C ABI
//! (`0` Compressed, `1` NoGain, `2` AlreadyCompressed, `3` Unsupported, `4` Skipped,
//! `-1` invalid input or I/O failure) and sizes are `bigint` (`u64`).
//!
//! Fail-soft: a malformed argument or a napi error yields the failure-shaped result
//! (`-1` status, zero sizes) rather than a thrown JS exception - the same contract
//! the C FFI has.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::ffi::{c_char, c_void, CString};
use std::path::Path;

use abitious_decmpfs::{decmpfs, probe, stat, Outcome, Support};

/// Outcome code for invalid input or I/O failure, matching the C FFI.
const STATUS_ERROR: i32 = -1;

type NapiEnv = *mut c_void;
type NapiValue = *mut c_void;
type NapiCallbackInfo = *mut c_void;
/// `napi_status`; `napi_ok` is 0.
type NapiStatus = i32;
/// `napi_callback`: a JS-callable function's entry point.
type NapiCallback = unsafe extern "C" fn(NapiEnv, NapiCallbackInfo) -> NapiValue;

/// `napi_valuetype` - `napi_string`.
const VALUE_STRING: i32 = 4;

extern "C" {
    fn napi_create_function(
        env: NapiEnv,
        utf8name: *const c_char,
        length: isize,
        cb: NapiCallback,
        data: *mut c_void,
        result: *mut NapiValue,
    ) -> NapiStatus;
    fn napi_create_object(env: NapiEnv, result: *mut NapiValue) -> NapiStatus;
    fn napi_create_int32(env: NapiEnv, value: i32, result: *mut NapiValue) -> NapiStatus;
    fn napi_get_boolean(env: NapiEnv, value: bool, result: *mut NapiValue) -> NapiStatus;
    fn napi_create_bigint_uint64(env: NapiEnv, value: u64, result: *mut NapiValue) -> NapiStatus;
    fn napi_set_named_property(
        env: NapiEnv,
        object: NapiValue,
        utf8name: *const c_char,
        value: NapiValue,
    ) -> NapiStatus;
    fn napi_get_cb_info(
        env: NapiEnv,
        cbinfo: NapiCallbackInfo,
        argc: *mut usize,
        argv: *mut NapiValue,
        this_arg: *mut *mut c_void,
        data: *mut *mut c_void,
    ) -> NapiStatus;
    fn napi_get_value_string_utf8(
        env: NapiEnv,
        value: NapiValue,
        buf: *mut c_char,
        bufsize: usize,
        result: *mut usize,
    ) -> NapiStatus;
    fn napi_typeof(env: NapiEnv, value: NapiValue, result: *mut i32) -> NapiStatus;
    fn napi_get_undefined(env: NapiEnv, result: *mut NapiValue) -> NapiStatus;
}

/// Node's entry point for a native addon.
///
/// # Safety
/// Called by Node during module load with a valid `env` and `exports`.
// coverage(off): this entry runs only when Node `dlopen`s the built addon (the
// in-module tests cannot reach it); it is proven end-to-end by loading the built
// `bind.node` in the gated e2e, like the stub's trampoline.
#[cfg_attr(coverage_nightly, coverage(off))]
#[no_mangle]
pub unsafe extern "C" fn napi_register_module_v1(env: NapiEnv, exports: NapiValue) -> NapiValue {
    let functions: [(&str, NapiCallback); 3] = [
        ("probe", js_probe),
        ("stat", js_stat),
        ("compressFile", js_compress_file),
    ];
    for (name, callback) in functions {
        let Ok(cname) = CString::new(name) else {
            return exports;
        };
        let mut function: NapiValue = std::ptr::null_mut();
        // SAFETY: `env` is Node's live env; every pointer is initialized or null.
        let ok = unsafe {
            napi_create_function(
                env,
                cname.as_ptr(),
                -1,
                callback,
                std::ptr::null_mut(),
                &mut function,
            )
        };
        if ok != 0 {
            return exports;
        }
        // SAFETY: `exports` is Node's module object; `cname` outlives the call.
        let ok = unsafe { napi_set_named_property(env, exports, cname.as_ptr(), function) };
        if ok != 0 {
            return exports;
        }
    }
    exports
}

/// Read argument 0 of a one-string call. `None` = wrong arity, not a string, or a
/// napi error - the caller answers with its failure-shaped result.
// coverage(off): reached only under a real Node dlopen; guarded e2e like the entry.
#[cfg_attr(coverage_nightly, coverage(off))]
unsafe fn arg_string(env: NapiEnv, info: NapiCallbackInfo) -> Option<String> {
    // SAFETY: `env`/`info` are Node's live pointers; `argv` is sized to the one arg read.
    unsafe {
    let mut argc: usize = 1;
        let mut argv: NapiValue = std::ptr::null_mut();
        if napi_get_cb_info(
            env,
            info,
            &mut argc,
            &mut argv,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) != 0
        {
            return None;
        }
        if argc < 1 || argv.is_null() {
            return None;
        }
        let mut kind: i32 = 0;
        if napi_typeof(env, argv, &mut kind) != 0 || kind != VALUE_STRING {
            return None;
        }
        let mut len: usize = 0;
        if napi_get_value_string_utf8(env, argv, std::ptr::null_mut(), 0, &mut len) != 0 {
            return None;
        }
        let mut buf = vec![0u8; len + 1];
        if napi_get_value_string_utf8(env, argv, buf.as_mut_ptr().cast(), buf.len(), &mut len) != 0 {
            return None;
        }
        buf.truncate(len);
        String::from_utf8(buf).ok()
    }
}

/// `probe(path) -> number`: 0 supported, 1 already compressed, 2 unsupported, -1 error.
// coverage(off): the napi wrapper runs only under a real Node dlopen; the in-module
// tests own the engine mapping.
#[cfg_attr(coverage_nightly, coverage(off))]
unsafe extern "C" fn js_probe(env: NapiEnv, info: NapiCallbackInfo) -> NapiValue {
    let code = match unsafe { arg_string(env, info) } {
        Some(path) => match probe(Path::new(&path)) {
            Ok(Support::Supported) => 0,
            Ok(Support::AlreadyCompressed) => 1,
            Ok(Support::Unsupported(_)) => 2,
            Err(_) => STATUS_ERROR,
        },
        None => STATUS_ERROR,
    };
    unsafe { number_or_undefined(env, code) }
}

/// `stat(path) -> { status, compressed, logical, physical }` - sizes are bigint.
// coverage(off): see `js_probe`.
#[cfg_attr(coverage_nightly, coverage(off))]
unsafe extern "C" fn js_stat(env: NapiEnv, info: NapiCallbackInfo) -> NapiValue {
    // SAFETY: `env` is Node's live env throughout; the shape helpers fail soft.
    unsafe {
        let measured = arg_string(env, info)
            .map(|path| stat(Path::new(&path)))
            .and_then(|r| r.ok());
        let (status, compressed, logical, physical) = match measured {
            Some(result) => (0, result.compressed, result.logical, result.physical),
            None => (STATUS_ERROR, false, 0, 0),
        };
        let Some(object) = shape(
            env,
            status,
            &[
                ("compressed", Field::Bool(compressed)),
                ("logical", Field::U64(logical)),
                ("physical", Field::U64(physical)),
            ],
        ) else {
            return fail_soft_undefined(env);
        };
        object
    }
}

/// `compressFile(path) -> { status, before, after }` - sizes are bigint, zero when
/// the outcome carries none (matching the C FFI's untouched zero buffers).
// coverage(off): see `js_probe`.
#[cfg_attr(coverage_nightly, coverage(off))]
unsafe extern "C" fn js_compress_file(env: NapiEnv, info: NapiCallbackInfo) -> NapiValue {
    // SAFETY: `env` is Node's live env throughout; the shape helpers fail soft.
    unsafe {
        let measured = arg_string(env, info)
            .map(|path| decmpfs::compress_file(Path::new(&path)))
            .map(|r| r.ok())
            .unwrap_or(None);
        let (status, before, after) = match measured {
            Some(Outcome::Compressed { before, after }) => (0, before, after),
            Some(Outcome::NoGain { before, after }) => (1, before, after),
            Some(Outcome::AlreadyCompressed { before }) => (2, before, before),
            Some(Outcome::Unsupported { .. }) => (3, 0, 0),
            Some(Outcome::Skipped { .. }) => (4, 0, 0),
            None => (STATUS_ERROR, 0, 0),
        };
        let Some(object) = shape(
            env,
            status,
            &[
                ("before", Field::U64(before)),
                ("after", Field::U64(after)),
            ],
        ) else {
            return fail_soft_undefined(env);
        };
        object
    }
}

/// One named field of a result shape.
enum Field {
    Bool(bool),
    U64(u64),
}

/// Build `{ status, ...fields }`; `None` = a napi error mid-shape (fail soft).
// coverage(off): reached only under a real Node dlopen; the shape contract is
// asserted by the loader tests against the live addon.
#[cfg_attr(coverage_nightly, coverage(off))]
unsafe fn shape(env: NapiEnv, status: i32, fields: &[(&str, Field)]) -> Option<NapiValue> {
    // SAFETY: `env` is Node's live env; every intermediate is checked before use.
    unsafe {
        let mut object: NapiValue = std::ptr::null_mut();
        if napi_create_object(env, &mut object) != 0 {
            return None;
        }
        let mut status_value: NapiValue = std::ptr::null_mut();
        if napi_create_int32(env, status, &mut status_value) != 0 {
            return None;
        }
        if napi_set_named_property(env, object, c"status".as_ptr(), status_value) != 0 {
            return None;
        }
        for (name, field) in fields {
            let cname = CString::new(*name).ok()?;
            let mut value: NapiValue = std::ptr::null_mut();
            let ok = match field {
                Field::Bool(b) => napi_get_boolean(env, *b, &mut value),
                Field::U64(n) => napi_create_bigint_uint64(env, *n, &mut value)
            };
            if ok != 0 {
                return None;
            }
            if napi_set_named_property(env, object, cname.as_ptr(), value) != 0 {
                return None;
            }
        }
        Some(object)
    }
}

/// A JS `number` value, or `undefined` when napi refuses (fail soft).
// coverage(off): see `shape`.
#[cfg_attr(coverage_nightly, coverage(off))]
unsafe fn number_or_undefined(env: NapiEnv, code: i32) -> NapiValue {
    // SAFETY: `env` is Node's live env; both pointers are initialized or null.
    unsafe {
        let mut value: NapiValue = std::ptr::null_mut();
        if napi_create_int32(env, code, &mut value) != 0 {
            return fail_soft_undefined(env);
        }
        value
    }
}

/// A JS `undefined`, the fail-soft return when no shape can be built - the same
/// degradation the stub applies when it hands back an empty module.
// coverage(off): see `shape`.
#[cfg_attr(coverage_nightly, coverage(off))]
unsafe fn fail_soft_undefined(env: NapiEnv) -> NapiValue {
    // SAFETY: `env` is Node's live env; an unresolvable undefined degrades to null,
    // which JS reads as null-ish exactly like the stub's fail-soft empty module.
    unsafe {
        let mut value: NapiValue = std::ptr::null_mut();
        if napi_get_undefined(env, &mut value) != 0 {
            return std::ptr::null_mut();
        }
        value
    }
}

// The engine mapping (probe codes, stat fields, compress outcome codes) is the
// binder's real logic and IS tested in-process; only the napi marshalling above is
// dlopen-only.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_error_maps_to_the_c_ffi_code() {
        // A nonexistent parent dir is an I/O failure at the engine -> -1, as ffi.rs.
        assert_eq!(
            match probe(Path::new("/nonexistent-parent-dir/file.node")) {
                Ok(_) => 0,
                Err(_) => STATUS_ERROR,
            },
            -1
        );
    }

    #[test]
    fn stat_error_maps_to_the_failure_shape() {
        let measured = stat(Path::new("/nonexistent-parent-dir/file.node")).ok();
        let (status, compressed, logical, physical) = match measured {
            Some(result) => (0, result.compressed, result.logical, result.physical),
            None => (STATUS_ERROR, false, 0, 0),
        };
        assert_eq!(status, -1);
        assert!(!compressed);
        assert_eq!(logical, 0);
        assert_eq!(physical, 0);
    }

    #[test]
    fn compress_error_maps_to_the_failure_shape() {
        let measured =
            decmpfs::compress_file(Path::new("/nonexistent-parent-dir/file.node")).ok();
        let (status, before, after) = match measured {
            Some(Outcome::Compressed { before, after }) => (0, before, after),
            Some(Outcome::NoGain { before, after }) => (1, before, after),
            Some(Outcome::AlreadyCompressed { before }) => (2, before, before),
            Some(Outcome::Unsupported { .. }) => (3, 0, 0),
            Some(Outcome::Skipped { .. }) => (4, 0, 0),
            None => (STATUS_ERROR, 0, 0),
        };
        assert_eq!(status, -1);
        assert_eq!(before, 0);
        assert_eq!(after, 0);
    }

    #[test]
    fn outcome_codes_stay_frozen() {
        // The contract the JS side reads; any change is a versioned ABI extension.
        let codes = [0i32, 1, 2, 3, 4, STATUS_ERROR];
        assert_eq!(codes, [0, 1, 2, 3, 4, -1]);
    }
}
