# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-05-14

### Added
- **Dynamic ALPS Generation:** Replaced hardcoded ALPS extension bytes with a dynamic `build_alps_payload()` function that correctly packs HTTP/2 settings from `profile.h2.settings`. This prevents advanced WAFs from correlating stale TLS ALPS data with active HTTP/2 frames.
- **HPACK Validation Test:** Added `tests/hpack_never_indexed.rs` integration test verifying that `cookie` and `authorization` headers can be safely marked as sensitive (`never-indexed`) without panicking the underlying H2 encoder.

### Fixed
- **Missing Origin Header:** Chrome always sends the `Origin` header for state-mutating requests (`POST`, `PUT`, `PATCH`), even when the request is same-origin (to prevent CSRF). The `QuikSession` redirect engine now perfectly mirrors this behavior by automatically injecting the origin string derived from the target URI on mutation methods.

### Changed
- Documented future requirements for intelligent `:path` indexing. Chrome selectively skips indexing the `:path` pseudo-header for high-entropy REST API paths to avoid HPACK dynamic table bloat. A placeholder `TODO` was added to `request.rs` pending an upstream patch to the `http2` fork to support `no_index` on pseudo-headers.

## [0.1.0] - 2026-05-07

### Added
- Initial stable release.
- **Chrome 134 macOS ARM Identity:** Bit-perfect replication of TLS JA3/JA4 fingerprints and HTTP/2 Akamai fingerprints.
- Stateful connection pooling (9-minute lifetime) and stealth redirect mutation machine (`sec-fetch-site` downgrade algorithm).
