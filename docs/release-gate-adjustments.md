# Release gate adjustments

## Cargo artifact attestation

Removed the `actions/attest-build-provenance` step and its `attestations: write`
permission from `.github/workflows/publish-cargo.yml`. The current published
fleet check rejects this external action, which blocked all release checks.
The workflow retains `id-token: write` for crates.io trusted publishing.

Follow-up: if GitHub artifact attestations are required for Cargo artifacts,
approve the action through the canonical fleet policy or onboard the workflow
to a verified Actions lockfile, then restore the attestation step.
