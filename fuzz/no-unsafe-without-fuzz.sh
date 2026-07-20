#!/usr/bin/env bash
# Grep-level lint (fleet property-and-fuzz spec, mirror of envrypt/fuzz/): every
# `unsafe` on the UNTRUSTED-INPUT PARSE SURFACE must carry a `// FUZZ: <target>`
# annotation naming the fuzz target that covers the path, so no `unsafe` reachable
# from attacker bytes ships without a fuzz target exercising it. The annotation
# appears on the same line as the `unsafe` token or within the 3 preceding lines.
#
# SCOPE — abitious-decmpfs/src/lib.rs, the hybrid `.node` reader + pressed-data
# section decoder (`unwrap_if_hybrid` / `inspect_hybrid` / `decode_pressed_data`
# / the Mach-O·ELF·PE object walkers), which is exactly the surface the
# `read_hybrid_node` + `decode_pressed_data` fuzz targets drive. This surface is
# pure safe Rust today (checked slice ops, `checked_add`) — the gate keeps it that
# way: an `unsafe` added here without a `// FUZZ:` annotation fails the gate.
#
# OUT OF SCOPE — the crate's other `unsafe` lives in selfextract.rs and
# fscompress/ (dlopen/dlsym/statfs/ioctl/getuid FFI syscalls). Those operate on
# file descriptors, filesystem paths, and dynamic loading — NOT on a `&[u8]`
# buffer — so a libFuzzer byte-input target cannot reach them; they are covered
# by their own unit/integration tests, not this byte-fuzz gate. See
# docs/PRESSED-DATA-FORMAT.md.
#
# Exit 0 = clean (the current state: zero `unsafe` on the parse surface). Exit 1
# lists every unannotated `unsafe` on that surface. Run from anywhere.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/crates/abitious-decmpfs/src/lib.rs"

offenders=0
# `-n` line numbers, word-boundary `unsafe`; skip if none.
while IFS= read -r hit; do
  [ -n "$hit" ] || continue
  file="${hit%%:*}"
  rest="${hit#*:}"
  line="${rest%%:*}"
  content="${rest#*:}"
  # Skip comment-only lines: a real `unsafe` block is never a `//`-led line, so the
  # only such matches are doc-comment word mentions.
  case "${content#"${content%%[![:space:]]*}"}" in
  //*) continue ;;
  esac
  start=$((line > 3 ? line - 3 : 1))
  # The annotation may be on the unsafe line or up to 3 lines above it.
  if sed -n "${start},${line}p" "$file" | grep -q '// FUZZ:'; then
    continue
  fi
  echo "::error file=${file#"$ROOT"/},line=${line}::unsafe on the parse surface without a '// FUZZ: <target>' annotation"
  offenders=$((offenders + 1))
done < <(grep -rn --include='*.rs' -E '(^|[^A-Za-z_])unsafe([^A-Za-z_]|$)' "$SRC" 2>/dev/null || true)

if [ "$offenders" -gt 0 ]; then
  echo "no-unsafe-without-fuzz: $offenders unannotated unsafe block(s) on the abitious-decmpfs parse surface" >&2
  exit 1
fi
echo "no-unsafe-without-fuzz: OK (the abitious-decmpfs parse surface carries no unfuzzed unsafe)"
