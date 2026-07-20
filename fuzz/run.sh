#!/usr/bin/env bash
# abitious fuzz runner (fleet property-and-fuzz spec, mirror of envrypt/fuzz/run.sh).
# Single source of truth for the per-target libFuzzer flags so local acceptance
# runs and the nightly CI job match exactly.
#
#   fuzz/run.sh <target> [max_total_time_seconds]   # default 600 = 10 min/target
#   fuzz/run.sh all       [max_total_time_seconds]   # each target in turn
#
# Requires a nightly toolchain (cargo-fuzz sets the sanitizer flags + `--cfg
# fuzzing`). Invoked via `cargo +nightly fuzz run` when cargo is the rustup shim,
# or `rustup run nightly cargo fuzz run` otherwise (both handled below). The
# repo pins a stable channel in rust-toolchain.toml for the primary build, so the
# fuzz job pins its own nightly here — override with FUZZ_TOOLCHAIN (e.g. a dated
# nightly), and FUZZ_TARGET_TRIPLE if you need to cross-fuzz a non-host target.
set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DICT="$FUZZ_DIR/fuzz.dict"
DURATION="${2:-600}"
FUZZ_TOOLCHAIN="${FUZZ_TOOLCHAIN:-nightly}"
FUZZ_TARGET_TRIPLE="${FUZZ_TARGET_TRIPLE:-}"

# Per-target libFuzzer flags, calibrated for the ASan + coverage instrumentation
# cargo-fuzz builds with:
#   * `-timeout=10` — absorbs the ~10x ASan slowdown (a genuine hang is unbounded
#     and still caught). The zstd-bomb class (a tiny payload claiming a small
#     `uncompressed_size` yet expanding to many GiB) is neutralized in
#     abitious-decmpfs by the capped streaming `decode_capped` (bounded to
#     MAX_DECOMPRESSED + 1), NOT by a timeout hack.
#   * `-rss_limit_mb=2048` — ASan shadow memory + libFuzzer's accumulating
#     coverage counters push baseline RSS past the 512 MB default over a long run
#     with no per-exec blowup. A real unbounded allocation still trips 2048.
#   * `-max_len` bounds a single on-disk `.node`-sized input.
target_flags() {
  case "$1" in
    read_hybrid_node)    echo "-timeout=10 -rss_limit_mb=2048 -max_len=65536" ;;
    decode_pressed_data) echo "-timeout=10 -rss_limit_mb=2048 -max_len=4096" ;;
    *) echo "unknown target: $1" >&2; return 1 ;;
  esac
}

# Pick the invocation that handles `+<toolchain>` in this environment.
run_fuzz() {
  if cargo "+$FUZZ_TOOLCHAIN" --version >/dev/null 2>&1; then
    cargo "+$FUZZ_TOOLCHAIN" fuzz "$@"
  else
    rustup run "$FUZZ_TOOLCHAIN" cargo fuzz "$@"
  fi
}

run_one() {
  local t="$1"
  echo "===== fuzz: $t (max_total_time=${DURATION}s) ====="
  # `--target <triple>` only when FUZZ_TARGET_TRIPLE is set (default: host target).
  # Passed positionally rather than via an array so this stays bash-3.2 safe under
  # `set -u` (empty-array expansion is an unbound-variable error on macOS bash).
  # shellcheck disable=SC2046
  if [ -n "$FUZZ_TARGET_TRIPLE" ]; then
    run_fuzz run --target "$FUZZ_TARGET_TRIPLE" "$t" -- \
      -max_total_time="$DURATION" -dict="$DICT" -print_final_stats=1 \
      $(target_flags "$t")
  else
    run_fuzz run "$t" -- \
      -max_total_time="$DURATION" -dict="$DICT" -print_final_stats=1 \
      $(target_flags "$t")
  fi
}

case "${1:-all}" in
  all)
    for t in read_hybrid_node decode_pressed_data; do run_one "$t"; done ;;
  read_hybrid_node|decode_pressed_data)
    run_one "$1" ;;
  *)
    echo "usage: $0 <read_hybrid_node|decode_pressed_data|all> [seconds]" >&2
    exit 2 ;;
esac
