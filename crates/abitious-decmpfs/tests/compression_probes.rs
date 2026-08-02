//! Opt-in performance and memory probes for the install-time compression path.
//!
//! Both are `#[ignore]` — timing and RSS are machine-specific, so they are run by
//! hand rather than in CI. They drive the PUBLIC surface ([`compress_bytes`]), so
//! what they measure is what a package manager actually pays, engine plus the
//! safety layer around it.
//!
//! ```text
//! cargo test -p abitious-decmpfs --release --test compression_probes -- --ignored --nocapture
//! DECMPFS_SERIAL=1 cargo test -p abitious-decmpfs --release --test compression_probes \
//!   write_time -- --ignored --nocapture
//! ```
//!
//! `DECMPFS_SERIAL` forces the engine's single-threaded block encode, the A/B
//! baseline for the parallel win.

#![cfg(target_os = "macos")]
// Probes report their measurements to stderr; that IS the output.
#![allow(clippy::print_stderr)]

use std::path::Path;

use abitious_decmpfs::{compress_bytes, probe, Gate, Outcome, Support};

/// Compressible pseudo-random filler shaped like a native addon's text segment:
/// an xorshift stream interleaved with repeating ASCII so the codec finds real
/// matches instead of encoding noise.
fn synthetic_addon(len: usize) -> Vec<u8> {
    let mut raw: Vec<u8> = Vec::with_capacity(len);
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    while raw.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        raw.extend_from_slice(&x.to_le_bytes());
        raw.extend_from_slice(b"native addon .node text segment padding ");
    }
    raw.truncate(len);
    raw
}

/// Peak resident set size for this process, in bytes. macOS reports `ru_maxrss`
/// in bytes; the Linux/BSD kilobyte convention does not apply here.
fn peak_rss_bytes() -> u64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: FFI into getrusage with a zeroed, stack-owned `rusage` the kernel
    // fills in; the RUSAGE_SELF query cannot fail for a valid pointer.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return 0;
    }
    usage.ru_maxrss as u64
}

/// `Supported` on the scratch directory, or the host cannot exercise decmpfs.
fn decmpfs_available(dir: &Path) -> bool {
    matches!(probe(dir), Ok(Support::Supported))
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("abitious-probe-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
#[ignore]
fn write_time_probe() {
    let dir = scratch("time");
    if !decmpfs_available(&dir) {
        std::fs::remove_dir_all(&dir).ok();
        return;
    }
    let raw = synthetic_addon(40 << 20);
    let path = dir.join("addon.node");
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let serial = std::env::var_os("DECMPFS_SERIAL").is_some();

    let start = std::time::Instant::now();
    let outcome = compress_bytes(&path, &raw, &Gate::any()).unwrap();
    let ms = start.elapsed().as_secs_f64() * 1e3;

    eprintln!(
        "install write {}MiB — {} ({} cores): {:.1} ms [{outcome:?}]",
        raw.len() >> 20,
        if serial { "serial" } else { "parallel" },
        cores,
        ms,
    );
    assert_eq!(std::fs::read(&path).unwrap(), raw, "read-back is the input");
    std::fs::remove_dir_all(&dir).ok();
}

/// A payload past the engine's 64 MiB streaming threshold must not cost the
/// build-it-all-in-RAM multiple of the file. The in-memory path holds the raw
/// bytes, every per-block `Vec`, AND the concatenated resource fork at once
/// (~3x); the streaming path writes blocks out as it encodes, so the only
/// unavoidable resident copy is the caller's own input buffer (~1x).
///
/// The assertion is deliberately loose (2x the input) so it fails on a
/// regression to the concatenating path without being brittle about allocator
/// behavior.
#[test]
#[ignore]
fn large_payload_streams_instead_of_building_the_fork_in_memory() {
    let dir = scratch("rss");
    if !decmpfs_available(&dir) {
        std::fs::remove_dir_all(&dir).ok();
        return;
    }
    // 200 MiB is comfortably past the 64 MiB threshold, and large enough that a
    // 3x peak would be unmistakable next to a 1x one. `ABITIOUS_PROBE_MIB` sweeps
    // the size, so the same probe can be run BELOW the threshold to show the
    // in-memory path's growth for contrast.
    let len = std::env::var("ABITIOUS_PROBE_MIB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(200)
        << 20;
    let raw = synthetic_addon(len);
    let path = dir.join("big.node");

    let before = peak_rss_bytes();
    let outcome = compress_bytes(&path, &raw, &Gate::any()).unwrap();
    let after = peak_rss_bytes();

    let mib = |n: u64| n as f64 / (1024.0 * 1024.0);
    eprintln!(
        "streaming probe: input {} MiB, peak RSS {:.1} MiB before → {:.1} MiB after \
     (growth {:.1} MiB, {:.2}x input) [{outcome:?}]",
        len >> 20,
        mib(before),
        mib(after),
        mib(after.saturating_sub(before)),
        (after.saturating_sub(before)) as f64 / len as f64,
    );

    assert_eq!(
        std::fs::read(&path).unwrap(),
        raw,
        "the streamed resource fork still reads back byte-for-byte"
    );
    assert!(
        matches!(outcome, Outcome::Compressed { .. } | Outcome::NoGain { .. }),
        "a payload past the threshold is still written, got {outcome:?}"
    );
    // Only the streaming path carries the bounded-growth guarantee; a sweep below
    // the threshold is measuring the in-memory path on purpose.
    const STREAMING_THRESHOLD: usize = 64 << 20;
    if len > STREAMING_THRESHOLD {
        assert!(
            after.saturating_sub(before) < (2 * len) as u64,
            "peak RSS grew {:.1} MiB for a {} MiB input — the whole fork looks resident",
            mib(after.saturating_sub(before)),
            len >> 20,
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}
