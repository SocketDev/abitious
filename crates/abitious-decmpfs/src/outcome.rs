//! Receipt rendering for a compression [`Outcome`].
//!
//! The engine reports *what happened*; abitious turns that into the one line a
//! user reads in a receipt or an `abi inspect` report. The wording is abitious
//! product messaging rather than engine behavior, so it lives here instead of in
//! the `decmpfs` crate: the non-compressing arms have to make the install
//! trade-off explicit, because a hybrid still downloads smaller even on a
//! filesystem that stores it uncompressed.
//!
//! The reason enums cross the crate boundary as plain data — `decmpfs` does not
//! implement `Display` for them — so the reader-facing words live here too.

use decmpfs::{Outcome, SkipReason, UnsupportedReason};

/// Why the filesystem offers no transparent compression, in reader-facing words.
pub fn unsupported_reason_text(reason: UnsupportedReason) -> &'static str {
  match reason {
    UnsupportedReason::Filesystem => "filesystem has no per-file compression",
    UnsupportedReason::NetworkOrOverlay => "network or overlay mount",
    UnsupportedReason::PlatformBuild => "no backend for this OS build",
  }
}

/// Why a compression-capable filesystem still did not get the file, in
/// reader-facing words.
pub fn skip_reason_text(reason: SkipReason) -> &'static str {
  match reason {
    SkipReason::PermissionDenied => "permission denied",
    SkipReason::Busy => "file busy or locked",
    SkipReason::Immutable => "immutable flag set",
    SkipReason::Encrypted => "filesystem-encrypted",
    SkipReason::IntegrityRevert => "structural verification reverted it",
    SkipReason::NotLoadable => "post-apply loadability check reverted it",
    SkipReason::TooLarge => "exceeds a backend size limit",
    SkipReason::GateExcluded => "excluded by the compression gate",
  }
}

/// Renders a compression [`Outcome`] as a receipt line.
pub trait OutcomeExt {
  /// A measured, human-readable one-line description of what happened, for a
  /// receipt or an `abi inspect` report. The compressing arms report the on-disk
  /// allocation before/after and the saving; the non-compressing arms (`NoGain`,
  /// `Unsupported`, `Skipped`) say so plainly AND make the download/install
  /// trade-off explicit — a hybrid still downloads smaller even where the
  /// filesystem stores it uncompressed, so the win is "download-only, installed
  /// size unchanged on this filesystem".
  fn describe(&self) -> String;
}

impl OutcomeExt for Outcome {
  fn describe(&self) -> String {
    match self {
      Outcome::Compressed { before, after } => {
        let saved = before.saturating_sub(*after);
        // checked_div guards the before==0 degenerate case (→ 0%).
        let pct = saved.saturating_mul(100).checked_div(*before).unwrap_or(0);
        format!(
          "compressed on disk: {after} B allocated (was {before} B) — saved {saved} B ({pct}%)"
        )
      }
      Outcome::NoGain { before, after } => format!(
        "no on-disk gain: {after} B allocated (was {before} B), incompressible or \
                 sub-cluster — download-only savings, installed size unchanged on this filesystem"
      ),
      Outcome::AlreadyCompressed { before } => {
        format!("already FS-compressed: {before} B allocated on disk")
      }
      Outcome::Unsupported { reason } => {
        let reason = unsupported_reason_text(*reason);
        format!(
          "no transparent compression here ({reason}) — download-only savings, installed \
                 size unchanged on this filesystem"
        )
      }
      Outcome::Skipped { reason } => {
        let reason = skip_reason_text(*reason);
        format!("not FS-compressed ({reason}) — download-only savings, installed size unchanged")
      }
    }
  }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
  use std::collections::BTreeSet;

  use super::*;

  #[test]
  fn outcome_describe_measures_the_compressing_arms() {
    let c = Outcome::Compressed {
      before: 1000,
      after: 400,
    }
    .describe();
    assert!(c.contains("saved 600 B") && c.contains("(60%)"), "{c}");
    let a = Outcome::AlreadyCompressed { before: 512 }.describe();
    assert!(
      a.contains("already FS-compressed") && a.contains("512 B"),
      "{a}"
    );
    // A degenerate before==0 must not divide by zero.
    let z = Outcome::Compressed {
      before: 0,
      after: 0,
    }
    .describe();
    assert!(z.contains("(0%)"), "{z}");
  }

  #[test]
  fn outcome_describe_surfaces_the_download_only_message_for_non_compressing_arms() {
    for out in [
      Outcome::NoGain {
        before: 100,
        after: 100,
      },
      Outcome::Unsupported {
        reason: UnsupportedReason::Filesystem,
      },
      Outcome::Skipped {
        reason: SkipReason::TooLarge,
      },
    ] {
      let msg = out.describe();
      assert!(
        msg.contains("download-only savings"),
        "{out:?} → {msg} lacks the download-only framing"
      );
    }
    // The reason is named in the message.
    assert!(Outcome::Unsupported {
      reason: UnsupportedReason::NetworkOrOverlay,
    }
    .describe()
    .contains("network or overlay"));
    assert!(Outcome::Skipped {
      reason: SkipReason::GateExcluded,
    }
    .describe()
    .contains("excluded by the compression gate"));
  }

  #[test]
  fn reason_text_is_distinct_and_non_empty() {
    let unsupported = [
      UnsupportedReason::Filesystem,
      UnsupportedReason::NetworkOrOverlay,
      UnsupportedReason::PlatformBuild,
    ]
    .map(unsupported_reason_text);
    for text in unsupported {
      assert!(!text.is_empty(), "every unsupported reason has words");
    }
    assert_eq!(
      unsupported.len(),
      unsupported.iter().collect::<BTreeSet<_>>().len(),
      "unsupported reasons read distinctly"
    );

    let skipped = [
      SkipReason::PermissionDenied,
      SkipReason::Busy,
      SkipReason::Immutable,
      SkipReason::Encrypted,
      SkipReason::IntegrityRevert,
      SkipReason::NotLoadable,
      SkipReason::TooLarge,
      SkipReason::GateExcluded,
    ]
    .map(skip_reason_text);
    for text in skipped {
      assert!(!text.is_empty(), "every skip reason has words");
    }
    assert_eq!(
      skipped.len(),
      skipped.iter().collect::<BTreeSet<_>>().len(),
      "skip reasons read distinctly"
    );
  }
}
