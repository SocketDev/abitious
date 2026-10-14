#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod cache;
mod napi;

/// Node's entry point for the FFI carrier addon.
///
/// # Safety
/// Node must call this with valid handles from the same live N-API environment.
#[no_mangle]
pub unsafe extern "C" fn napi_register_module_v1(
    env: napi::NapiEnv,
    exports: napi::NapiValue,
) -> napi::NapiValue {
    match cache::resolve_library_path() {
        Ok(path) => {
            if napi::set_library_path(env, exports, &path) {
                exports
            } else {
                napi::throw_error(env, "cannot set the FFI carrier libraryPath property");
                std::ptr::null_mut()
            }
        }
        Err(error) => {
            napi::throw_error(env, &error);
            std::ptr::null_mut()
        }
    }
}
