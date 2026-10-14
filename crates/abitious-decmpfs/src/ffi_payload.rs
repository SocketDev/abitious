use sha2::{Digest, Sha512};

use crate::{
    build_section_payload, decode_pressed_data, read_section_info, Arch, Libc, Platform,
    MAX_DECOMPRESSED,
};

pub const FFI_ENVELOPE_MAGIC: &[u8; 16] = b"ABI_FFI_PAYLOAD!";
pub const FFI_ENVELOPE_VERSION: u16 = 1;
const ENVELOPE_PREFIX_LEN: usize = 16 + 2 + 1;
const SHA512_LEN: usize = 64;
const MAX_TARGET_LEN: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FfiPayloadInfo {
    pub target: String,
    pub raw_size: u64,
    pub raw_sha512: [u8; SHA512_LEN],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FfiPayload {
    pub target: String,
    pub raw: Vec<u8>,
    pub raw_sha512: [u8; SHA512_LEN],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FfiPayloadError {
    UnsupportedTarget(String),
    TargetObjectMismatch { target: String, object: String },
    EmptyOrOversizedObject,
}

impl std::fmt::Display for FfiPayloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedTarget(target) => write!(f, "unsupported FFI target {target:?}"),
            Self::TargetObjectMismatch { target, object } => write!(
                f,
                "FFI object for {target} has incompatible native format or architecture ({object})"
            ),
            Self::EmptyOrOversizedObject => write!(
                f,
                "FFI object size must be between 1 and {MAX_DECOMPRESSED} bytes"
            ),
        }
    }
}

impl std::error::Error for FfiPayloadError {}

/// Build a versioned FFI envelope around the generic codec frame.
#[allow(clippy::expect_used)]
pub fn build_ffi_section_payload(
    raw: &[u8],
    target: &str,
    platform: Platform,
    arch: Arch,
    libc: Libc,
    level: i32,
) -> Result<Vec<u8>, FfiPayloadError> {
    if raw.is_empty() || raw.len() as u64 > MAX_DECOMPRESSED {
        return Err(FfiPayloadError::EmptyOrOversizedObject);
    }
    let (target_platform, target_arch, target_libc) = validate_ffi_target_object(raw, target)?;
    if (platform, arch, libc) != (target_platform, target_arch, target_libc) {
        return Err(FfiPayloadError::UnsupportedTarget(target.to_owned()));
    }
    if target.len() > MAX_TARGET_LEN {
        return Err(FfiPayloadError::UnsupportedTarget(target.to_owned()));
    }
    let codec = build_section_payload(raw, platform, arch, libc, level);
    let digest = Sha512::digest(raw);
    let mut envelope =
        Vec::with_capacity(ENVELOPE_PREFIX_LEN + target.len() + SHA512_LEN + codec.len());
    envelope.extend_from_slice(FFI_ENVELOPE_MAGIC);
    envelope.extend_from_slice(&FFI_ENVELOPE_VERSION.to_le_bytes());
    envelope.push(target.len() as u8);
    envelope.extend_from_slice(target.as_bytes());
    envelope.extend_from_slice(&digest);
    envelope.extend_from_slice(&codec);
    Ok(envelope)
}

/// Validate that a native shared library header matches one canonical target.
pub fn validate_ffi_target_object(
    raw: &[u8],
    target: &str,
) -> Result<(Platform, Arch, Libc), FfiPayloadError> {
    if raw.is_empty() || raw.len() as u64 > MAX_DECOMPRESSED {
        return Err(FfiPayloadError::EmptyOrOversizedObject);
    }
    let expected = target_parts(target)
        .ok_or_else(|| FfiPayloadError::UnsupportedTarget(target.to_owned()))?;
    let object = object_description(raw).ok_or_else(|| FfiPayloadError::TargetObjectMismatch {
        target: target.to_owned(),
        object: "unrecognized object format".to_owned(),
    })?;
    if object != (expected.0, expected.1) {
        return Err(FfiPayloadError::TargetObjectMismatch {
            target: target.to_owned(),
            object: format!("{}/{}", platform_label(object.0), arch_label(object.1)),
        });
    }
    Ok(expected)
}

/// Inspect and verify envelope metadata without decompressing the raw library.
pub fn inspect_ffi_data(section: &[u8]) -> Option<FfiPayloadInfo> {
    if section.get(..16)? != FFI_ENVELOPE_MAGIC.as_slice() {
        return None;
    }
    let version = u16::from_le_bytes(section.get(16..18)?.try_into().ok()?);
    if version != FFI_ENVELOPE_VERSION {
        return None;
    }
    let target_len = *section.get(18)? as usize;
    if target_len == 0 || target_len > MAX_TARGET_LEN {
        return None;
    }
    let target_at = ENVELOPE_PREFIX_LEN;
    let digest_at = target_at.checked_add(target_len)?;
    let codec_at = digest_at.checked_add(SHA512_LEN)?;
    let target = std::str::from_utf8(section.get(target_at..digest_at)?)
        .ok()?
        .to_owned();
    let raw_sha512 = section.get(digest_at..codec_at)?.try_into().ok()?;
    let (platform, arch, libc) = target_parts(&target)?;
    let codec = section.get(codec_at..)?;
    let info = read_section_info(codec)?;
    if !info.integrity_verified
        || info.has_config
        || info.uncompressed_size == 0
        || info.uncompressed_size > MAX_DECOMPRESSED
        || info.platform != Some(platform)
        || info.arch != Some(arch)
        || info.libc != Some(libc)
    {
        return None;
    }
    let codec_len = crate::HEADER_LEN.checked_add(usize::try_from(info.compressed_size).ok()?)?;
    if codec.get(..codec_len).is_none() || codec.get(codec_len..)?.iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(FfiPayloadInfo {
        target,
        raw_size: info.uncompressed_size,
        raw_sha512,
    })
}

/// Validate the envelope, codec frame, raw digest, target metadata and object headers.
pub fn decode_ffi_data(section: &[u8]) -> Option<FfiPayload> {
    let info = inspect_ffi_data(section)?;
    let target_len = *section.get(18)? as usize;
    let codec_at = ENVELOPE_PREFIX_LEN
        .checked_add(target_len)?
        .checked_add(SHA512_LEN)?;
    let codec = section.get(codec_at..)?;
    let section_info = read_section_info(codec)?;
    let codec_len =
        crate::HEADER_LEN.checked_add(usize::try_from(section_info.compressed_size).ok()?)?;
    let raw = decode_pressed_data(codec.get(..codec_len)?)?;
    let (platform, arch, _) = target_parts(&info.target)?;
    if raw.len() as u64 != info.raw_size
        || raw.is_empty()
        || raw.len() as u64 > MAX_DECOMPRESSED
        || Sha512::digest(&raw).as_slice() != info.raw_sha512
        || object_description(&raw)? != (platform, arch)
    {
        return None;
    }
    Some(FfiPayload {
        target: info.target,
        raw,
        raw_sha512: info.raw_sha512,
    })
}

pub fn host_ffi_target() -> String {
    let platform = Platform::detect();
    let arch = Arch::detect();
    let libc = Libc::detect();
    let os = match platform {
        Platform::Darwin => "darwin",
        Platform::Linux => "linux",
        Platform::Win32 => "win32",
    };
    let cpu = match arch {
        Arch::X64 => "x64",
        Arch::Arm64 => "arm64",
        Arch::Ia32 => "ia32",
        Arch::Arm => "arm",
    };
    let suffix = match platform {
        Platform::Darwin => "",
        Platform::Win32 => "-msvc",
        Platform::Linux if libc == Libc::Musl => "-musl",
        Platform::Linux => "-gnu",
    };
    format!("{os}-{cpu}{suffix}")
}

pub fn raw_sha512(raw: &[u8]) -> [u8; SHA512_LEN] {
    Sha512::digest(raw).into()
}

fn target_parts(target: &str) -> Option<(Platform, Arch, Libc)> {
    match target {
        "darwin-arm64" => Some((Platform::Darwin, Arch::Arm64, Libc::Na)),
        "darwin-x64" => Some((Platform::Darwin, Arch::X64, Libc::Na)),
        "linux-x64-gnu" => Some((Platform::Linux, Arch::X64, Libc::Glibc)),
        "linux-arm64-gnu" => Some((Platform::Linux, Arch::Arm64, Libc::Glibc)),
        "linux-x64-musl" => Some((Platform::Linux, Arch::X64, Libc::Musl)),
        "linux-arm64-musl" => Some((Platform::Linux, Arch::Arm64, Libc::Musl)),
        "win32-x64-msvc" => Some((Platform::Win32, Arch::X64, Libc::Na)),
        "win32-arm64-msvc" => Some((Platform::Win32, Arch::Arm64, Libc::Na)),
        _ => None,
    }
}

fn object_description(raw: &[u8]) -> Option<(Platform, Arch)> {
    match raw.get(..4)? {
        [0xcf, 0xfa, 0xed, 0xfe] if raw.len() >= 32 => {
            let cpu = u32::from_le_bytes(raw.get(4..8)?.try_into().ok()?);
            if !matches!(u32::from_le_bytes(raw.get(12..16)?.try_into().ok()?), 6 | 8) {
                return None;
            }
            let arch = match cpu {
                0x0100_000c => Arch::Arm64,
                0x0100_0007 => Arch::X64,
                _ => return None,
            };
            Some((Platform::Darwin, arch))
        }
        [0x7f, b'E', b'L', b'F']
            if raw.len() >= 64 && raw.get(4) == Some(&2) && raw.get(5) == Some(&1) =>
        {
            if u16::from_le_bytes(raw.get(16..18)?.try_into().ok()?) != 3
                || u16::from_le_bytes(raw.get(52..54)?.try_into().ok()?) != 64
            {
                return None;
            }
            let machine = u16::from_le_bytes(raw.get(18..20)?.try_into().ok()?);
            let arch = match machine {
                0x003e => Arch::X64,
                0x00b7 => Arch::Arm64,
                _ => return None,
            };
            Some((Platform::Linux, arch))
        }
        [b'M', b'Z', ..] if raw.len() >= 64 => {
            let pe_at = u32::from_le_bytes(raw.get(0x3c..0x40)?.try_into().ok()?) as usize;
            if raw.get(pe_at..pe_at.checked_add(24)?)?.get(..4)? != b"PE\0\0" {
                return None;
            }
            let machine = u16::from_le_bytes(raw.get(pe_at + 4..pe_at + 6)?.try_into().ok()?);
            let characteristics =
                u16::from_le_bytes(raw.get(pe_at + 22..pe_at + 24)?.try_into().ok()?);
            if characteristics & 0x2000 == 0 {
                return None;
            }
            let arch = match machine {
                0x8664 => Arch::X64,
                0xaa64 => Arch::Arm64,
                _ => return None,
            };
            Some((Platform::Win32, arch))
        }
        _ => None,
    }
}

fn platform_label(platform: Platform) -> &'static str {
    match platform {
        Platform::Darwin => "darwin",
        Platform::Linux => "linux",
        Platform::Win32 => "win32",
    }
}

fn arch_label(arch: Arch) -> &'static str {
    match arch {
        Arch::X64 => "x64",
        Arch::Arm64 => "arm64",
        Arch::Ia32 => "ia32",
        Arch::Arm => "arm",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf64_x64() -> Vec<u8> {
        let mut raw = vec![0u8; 64];
        raw[..4].copy_from_slice(b"\x7fELF");
        raw[4] = 2;
        raw[5] = 1;
        raw[6] = 1;
        raw[16..18].copy_from_slice(&3u16.to_le_bytes());
        raw[18..20].copy_from_slice(&0x003eu16.to_le_bytes());
        raw[52..54].copy_from_slice(&64u16.to_le_bytes());
        raw
    }

    #[test]
    fn envelope_round_trips_a_native_target_and_full_digest() {
        let raw = elf64_x64();
        let section = build_ffi_section_payload(
            &raw,
            "linux-x64-gnu",
            Platform::Linux,
            Arch::X64,
            Libc::Glibc,
            3,
        )
        .expect("build envelope");
        let decoded = decode_ffi_data(&section).expect("decode envelope");
        assert_eq!(decoded.target, "linux-x64-gnu");
        assert_eq!(decoded.raw, raw);
        assert_eq!(decoded.raw_sha512, raw_sha512(&decoded.raw));
    }

    #[test]
    fn envelope_rejects_a_changed_digest_or_target() {
        let raw = elf64_x64();
        let section = build_ffi_section_payload(
            &raw,
            "linux-x64-gnu",
            Platform::Linux,
            Arch::X64,
            Libc::Glibc,
            3,
        )
        .expect("build envelope");
        let mut corrupt = section.clone();
        let digest_at = ENVELOPE_PREFIX_LEN + "linux-x64-gnu".len();
        corrupt[digest_at] ^= 1;
        assert!(decode_ffi_data(&corrupt).is_none());
        let mut wrong_target = section;
        wrong_target[ENVELOPE_PREFIX_LEN] = b'x';
        assert!(decode_ffi_data(&wrong_target).is_none());
    }

    #[test]
    fn envelope_rejects_compressed_frame_corruption() {
        let section = build_ffi_section_payload(
            &elf64_x64(),
            "linux-x64-gnu",
            Platform::Linux,
            Arch::X64,
            Libc::Glibc,
            3,
        )
        .expect("build envelope");
        let codec_at = ENVELOPE_PREFIX_LEN + "linux-x64-gnu".len() + SHA512_LEN;
        let mut corrupt = section;
        let compressed_at = codec_at + crate::HEADER_LEN;
        *corrupt.get_mut(compressed_at).expect("compressed payload") ^= 1;
        assert!(decode_ffi_data(&corrupt).is_none());
    }

    #[test]
    fn build_rejects_object_architecture_mismatches() {
        let error = build_ffi_section_payload(
            &elf64_x64(),
            "linux-arm64-gnu",
            Platform::Linux,
            Arch::Arm64,
            Libc::Glibc,
            3,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            FfiPayloadError::TargetObjectMismatch { .. }
        ));
    }
}
