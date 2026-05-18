# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.8] - 2026-05-18

### Added
- **Chrome-Fingerprinted HTTP/3 + QUIC Dual-Stack Transport Engine**: Designed a complete, stealth-oriented HTTP/3 and QUIC transport layer using `quiche` linked against BoringSSL. Matches all parameters of Chrome v134-136, including static/dynamic QPACK tables, CONNECT bootstrap streams, PMTU discovery, dynamic pacer loop timing, and empty client Source Connection IDs (empty CID).
- **Resilient Fallback and Reuse Engine**: Implemented stateful `AltSvcCache` mapped to `Client`, along with a zero-delay transparent fallback block that degrades the cache and rolls back seamlessly to multiplexed HTTP/2 streams over existing TLS sessions on UDP blocks.
- **Hermetic HTTP/3 Fallback Integration Test Suite**: Developed the comprehensive `tests/h3_scenarios.rs` validating solicitation and transparent degraded H2 fallback behaviors offline.
- **Hermetic H2 + TLS Mock Server (`tests/common/mod.rs`)**: Implemented a dynamic, offline-safe mock HTTP/2 server that generates transient self-signed certificates and RSA key pairs at runtime via the BoringSSL cryptographic engine. Supports both single-connection and multi-connection multiplexed frame processing.
- **Elite Integration Test Suite**:
  - `tests/context_headers.rs`: End-to-end integration test validating Navigate request context headers on the wire.
  - `tests/fingerprint.rs`: TCP ClientHello interceptor asserting strict TLS Record Encapsulation and Handshake message layout.
  - `tests/redirect_chain.rs`: Dynamic cross-origin referral integrity validation (`strict-origin-when-cross-origin`).
  - `tests/waf_scenarios.rs`: Multi-stream keep-alive validation asserting stateful `Accept-CH` Client Hints platform version caching.
- **Fetch Metadata Unit Coverage (`src/client/request.rs`)**: Added full unit test coverage verifying Fetch Metadata injection for all 11 subresource variants of `RequestContext`, along with HPACK sensitive flag verification.

### Fixed
- **Strict Workspace Quality Clippy Hardening**: Resolved compiler warnings for module-level documentation empty lines (`empty_line_after_doc_comments`) and header vector initialization blocks (`vec_init_then_push`).
- **Windows OS Comment Alignment (`src/profile/chrome_134.rs`, `src/profile/mod.rs`)**: Fixed outdated developer comments referring to Windows version "13.0.0" to correctly match the active "15.0.0" implementation.

## [0.1.7] - 2026-05-18

### Added
- **Stateful Client Hints Caching (`src/client/pool.rs`)**: Introduced an automated, thread-safe `HintCache` (`Arc<RwLock<HashSet<String>>>`) to statefully track server-solicited `Accept-CH` headers, allowing the transport engine to emit the requested high-entropy platform version hints statefully.
- **Forensic Fetch Context Completion (`src/client/request.rs`)**: Expanded `RequestContext` to cover 11 specialized browser resource requests (Iframe, NoCorsScript, NoCorsStyle, NoCorsImage, NoCorsFont, NoCorsMedia, Worker, ServiceWorker, Prefetch) with exact `sec-fetch-*` modes, destinations, and context-dependent Accept headers.
- **Public API Exposure**: Publicly re-exported `RequestContext` at the crate root to enable external developers to programmatically control outbound subresource request metadata.

### Fixed
- **Post-Quantum ML-KEM Group Parity (`src/tls/connector.rs`, `Cargo.toml`)**: Enabled `pq-experimental` on `boring` and resolved the regression where post-quantum curve `4588` failed to resolve, perfectly matching standard Chrome 134 ClientHello fingerprints.
- **Connection Pool Head-of-Line Starvation (`src/client/pool.rs`)**: Refactored the HTTP/2 stream acquisition logic to clone active connections outside of the pool's async locking context, eliminating HoL blocking when concurrent requests await capacity.
- **Cross-Origin Referer Stripping (`src/client/pool.rs`)**: Implemented dynamic `strict-origin-when-cross-origin` policy enforcement, stripping path and query parameters for cross-site redirect hops.
- **GREASE Brand Shuffling & OS Accuracy (`src/profile/chrome_134.rs`, `Cargo.toml`)**: Upgraded to the modern `rand 0.10.1` API, resolving time-modulo correlations and brand alignment anomalies by uniformly shuffling GREASE names, versions (8/24/99), and position arrays across all three real Chrome configurations.
- **Platform Staleness Bumping**: Updated Windows 11 platform version to `"15.0.0"` (Windows 11 24H2) to prevent bot-detection heuristics from flagging EOL OS signals.

## [0.1.6] - 2026-05-17

There are no API changes in 0.1.6.

### Added
- **Stateful Request Contexts (`src/client/request.rs`)**: Added `RequestContext` enum (`Navigate`, `Xhr`, `Form`) governing `sec-fetch-dest` and `sec-fetch-mode` header generation. Outbound request headers are now mutated dynamically based on the active fetch origin context.
- **GREASE Delimiter and Brand Randomization (`src/profile/chrome_134.rs`)**: Implemented dynamic brand list randomization within `sec-ch-ua` to mirror Chrome's non-deterministic user-agent brand fingerprinting, including delimiter rotation, simulated versions, and array index slot positioning.
- **Concurrent HTTP/2 Connection Pool Multiplexing (`src/client/pool.rs`)**: Redesigned connection pool synchronization to prevent concurrent requests to the same origin from spawning redundant TCP/TLS dials. Wrapped connection entries inside `Arc<tokio::sync::Mutex<Option<QuikConnection>>>` and added origin-level locking for asynchronous stream multiplexing.
- **Referer Tracking across Redirections (`src/client/pool.rs`)**: Added automatic referer preservation and propagation across sequential redirect hops in the redirection loop.

### Fixed
- **TLS Signature Algorithm Preferences (`src/tls/connector.rs`)**: Resolved a configuration issue where the legacy `SSL_CTX_set1_sigalgs` API was used with raw algorithm identifiers, causing failures under BoringSSL and silent system defaults fallback. Switched to direct BoringSSL FFI functions (`SSL_CTX_set_signing_algorithm_prefs` and `SSL_CTX_set_verify_algorithm_prefs`) to enforce the Chrome 134 profile signature algorithm order.
- **Client Hints Information Disclosure (`src/client/request.rs`)**: Suppressed outbound `sec-ch-ua-platform-version` headers on initial requests, emitting them only when explicitly requested by the server via `accept-ch`.
- **Clippy Quality Gate Hardening**: Resolved strict workspace Clippy warnings and compiler quality blocks, introducing type aliases for complex connection pool types and standardizing modulo operations.

## [0.1.5] - 2026-05-15

### Added
- **Configurable TLS Verification**: Introduced `verify_peer` to `TlsProfile` and `.danger_accept_invalid_certs(bool)` to `ClientBuilder`. This enables developer-friendly bypasses for local debugging and proxying (mitmproxy) while maintaining secure-by-default behavior.
- **Strict Quality Gate**: Implemented a modular, multi-platform CI workflow (`test.yml`) that enforces strict quality checks across Ubuntu, Windows, and macOS.

### Fixed
- **Windows OS Stability**: Resolved persistent `CERTIFICATE_VERIFY_FAILED` errors on Windows environments by updating the integration and doc-test suites to utilize the new verification toggle where system CA stores are inaccessible.
- **Documentation Refinement**: Restored high-level `Client::new()` examples with hidden CI safety hacks and added developer notes for proxying.

## [0.1.4] - 2026-05-14

### Fixed
- **Hotfix:** Reverted the PQ curve string `X25519MLKEM768` back to `X25519Kyber768Draft00`. The v0.1.3 release introduced the new standardized string, but the `boring` crate v4 bindings in use do not yet parse the new string, causing a `TlsBuild` panic on initialization. The underlying network protocol identity (ID `4588`) remains identical to Chrome 134.

## [0.1.3] - 2026-05-14

### Fixed
- **Post-Quantum Group Identity:** Chrome 134 Stable relies on the finalized ML-KEM protocol for its post-quantum hybrid group (Group ID `0x11EC` / `4588`). Previously, this ID was mapped to an outdated draft name (`X25519Kyber768Draft00`). The mapping has been updated to the standardized BoringSSL name (`X25519MLKEM768`), ensuring the ClientHello advertises the exact PQ footprint expected by WAFs.
- **ALPS Injection Stability:** The raw BoringSSL FFI call used to inject Application-Layer Protocol Settings (ALPS) was previously ignoring its return value. `SSL_add_application_settings` is now explicitly checked. If ALPS injection fails (due to memory constraints or invalid state), the connection will safely abort with an `Error::Connect` rather than silently emitting a non-Chrome-compliant handshake.
- **HTTP Port Routing:** The automated redirect state machine and connection pooler previously defaulted to port `443` for all target authorities. The connection pool now inspects the URL scheme, correctly defaulting to port `80` for standard `http://` targets while maintaining `443` for `https://`.
- **User-Agent Patch Version Fidelity:** The OS-specific Chrome 134 profiles previously used a generic `.0.0.0` patch version in the `User-Agent` string. These have been updated to carry the exact Chrome 134 Stable patch version (`134.0.6998.35`), reducing detectability against heuristic analyzers that check for active release channel correlations.

## [0.1.2] - 2026-05-14

### Added
- **Cross-Platform Chrome 134 Profiles:** Added `chrome_134_windows_x64()` and `chrome_134_linux_x64()` profile constructors alongside the existing macOS profile. Each constructor emits the correct OS-specific User-Agent, `sec-ch-ua-platform`, `sec-ch-ua-platform-version`, and ALPS payload.
- **OS Auto-Detection (`profile_auto`):** New compile-time auto-detection via `cfg!(target_os)` selects the Chrome 134 profile matching the host kernel. `Client::new()` and `ClientBuilder::build()` now default to `profile_auto()` instead of hardcoding macOS.
- **`sec-ch-ua-platform-version` Header:** Added the `sec_ch_ua_platform_version` field to `HeaderProfile` and injected it into every outbound request. WAFs cross-check this value against the declared platform to detect spoofing (Windows 11 → `"13.0.0"`, macOS → `"15.0.0"`, Linux → `"0.0.0"`).
- **Platform-Specific ALPS Payload:** Added `alps_extra_settings` to `TlsProfile`. Windows and Linux Chrome append setting `0x7A9A` to the ALPS handshake data, producing a 30-byte payload versus macOS's 24 bytes. The ALPS builder in `connector.rs` now dynamically serializes these extra entries.

### Changed
- Refactored `chrome_134.rs` internals into shared `base_tls()` and `base_h2()` helpers to eliminate duplication across the three platform constructors.
- Updated crate-level and module-level documentation across `lib.rs`, `profile/mod.rs`, `profile/chrome_134.rs`, `client/connector.rs`, `client/request.rs`, and `client/pool.rs`.

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
