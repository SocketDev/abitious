use std::ffi::{c_char, c_void, CString};
use std::path::Path;

pub(super) type NapiEnv = *mut c_void;
pub(super) type NapiValue = *mut c_void;

pub(super) fn set_library_path(env: NapiEnv, exports: NapiValue, path: &Path) -> bool {
    let key = c"libraryPath";
    let mut value = std::ptr::null_mut();
    if !create_path_string(env, path, &mut value) || value.is_null() {
        return false;
    }
    // SAFETY: Node supplies `env`/`exports`; key remains valid for the call.
    unsafe { napi_set_named_property(env, exports, key.as_ptr(), value) == 0 }
}

#[cfg(unix)]
fn create_path_string(env: NapiEnv, path: &Path, value: *mut NapiValue) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(text) = std::str::from_utf8(path.as_os_str().as_bytes()) else {
        return false;
    };
    let Ok(text) = CString::new(text) else {
        return false;
    };
    // SAFETY: Node supplied env and `text` remains alive for this call.
    unsafe { napi_create_string_utf8(env, text.as_ptr(), text.as_bytes().len(), value) == 0 }
}

#[cfg(windows)]
fn create_path_string(env: NapiEnv, path: &Path, value: *mut NapiValue) -> bool {
    use std::os::windows::ffi::OsStrExt;
    let text: Vec<u16> = path.as_os_str().encode_wide().collect();
    // SAFETY: Node supplied env and the UTF-16 buffer remains alive for this call.
    unsafe { napi_create_string_utf16(env, text.as_ptr(), text.len(), value) == 0 }
}

pub(super) fn throw_error(env: NapiEnv, message: &str) {
    let message = message.replace('\0', "?");
    let Ok(message) = CString::new(message) else {
        return;
    };
    // SAFETY: `env` is the N-API environment supplied by Node.
    unsafe {
        let _ = napi_throw_error(env, std::ptr::null(), message.as_ptr());
    }
}

#[cfg(unix)]
unsafe fn napi_create_string_utf8(
    env: NapiEnv,
    value: *const c_char,
    length: usize,
    result: *mut NapiValue,
) -> i32 {
    unsafe extern "C" {
        fn napi_create_string_utf8(
            env: NapiEnv,
            value: *const c_char,
            length: usize,
            result: *mut NapiValue,
        ) -> i32;
    }
    unsafe { napi_create_string_utf8(env, value, length, result) }
}

#[cfg(unix)]
unsafe fn napi_set_named_property(
    env: NapiEnv,
    object: NapiValue,
    name: *const c_char,
    value: NapiValue,
) -> i32 {
    unsafe extern "C" {
        fn napi_set_named_property(
            env: NapiEnv,
            object: NapiValue,
            name: *const c_char,
            value: NapiValue,
        ) -> i32;
    }
    unsafe { napi_set_named_property(env, object, name, value) }
}

#[cfg(unix)]
unsafe fn napi_throw_error(env: NapiEnv, code: *const c_char, message: *const c_char) -> i32 {
    unsafe extern "C" {
        fn napi_throw_error(env: NapiEnv, code: *const c_char, message: *const c_char) -> i32;
    }
    unsafe { napi_throw_error(env, code, message) }
}

#[cfg(windows)]
unsafe fn napi_function(name: &str) -> Option<*mut c_void> {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    let module = unsafe { GetModuleHandleW(std::ptr::null()) };
    if module.is_null() {
        return None;
    }
    let name = CString::new(name).ok()?;
    let symbol = unsafe { GetProcAddress(module, name.as_ptr().cast()) }?;
    Some(symbol as *const () as *mut c_void)
}

#[cfg(windows)]
unsafe fn napi_create_string_utf16(
    env: NapiEnv,
    value: *const u16,
    length: usize,
    result: *mut NapiValue,
) -> i32 {
    let Some(function) = (unsafe { napi_function("napi_create_string_utf16") }) else {
        return -1;
    };
    let function = unsafe {
        std::mem::transmute::<
            *mut c_void,
            unsafe extern "C" fn(NapiEnv, *const u16, usize, *mut NapiValue) -> i32,
        >(function)
    };
    unsafe { function(env, value, length, result) }
}

#[cfg(windows)]
unsafe fn napi_set_named_property(
    env: NapiEnv,
    object: NapiValue,
    name: *const c_char,
    value: NapiValue,
) -> i32 {
    let Some(function) = (unsafe { napi_function("napi_set_named_property") }) else {
        return -1;
    };
    let function = unsafe {
        std::mem::transmute::<
            *mut c_void,
            unsafe extern "C" fn(NapiEnv, NapiValue, *const c_char, NapiValue) -> i32,
        >(function)
    };
    unsafe { function(env, object, name, value) }
}

#[cfg(windows)]
unsafe fn napi_throw_error(env: NapiEnv, code: *const c_char, message: *const c_char) -> i32 {
    let Some(function) = (unsafe { napi_function("napi_throw_error") }) else {
        return -1;
    };
    let function = unsafe {
        std::mem::transmute::<
            *mut c_void,
            unsafe extern "C" fn(NapiEnv, *const c_char, *const c_char) -> i32,
        >(function)
    };
    unsafe { function(env, code, message) }
}
