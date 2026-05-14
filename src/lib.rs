//! # http-quik
//!
//! High-fidelity stealth transport engine for Chrome network identity parity.
//!
//! `http-quik` provides low-level control over the entire protocol stack — from
//! TLS handshakes through HTTP/2 frame signaling — to make every outbound
//! connection indistinguishable from a genuine Chrome browser. It is the
//! transport layer of the [Phantom Engine](https://github.com/polymit/phantom-engine)
//! and is designed for production agentic navigation at scale.
//!
//! ## The Problem
//!
//! Modern anti-bot systems (Cloudflare, Akamai, DataDome) perform passive
//! fingerprinting at multiple protocol layers:
//!
//! 1. **TLS (JA3/JA4)** — cipher suite order, extension IDs, elliptic curves.
//! 2. **HTTP/2 (Akamai)** — SETTINGS values, pseudo-header ordering, stream priority.
//! 3. **Client Hints** — `sec-ch-ua-platform` cross-checked against the TLS handshake.
//!
//! Standard HTTP libraries (`reqwest`, `hyper`) fail these checks because they
//! use generic TLS stacks and default H2 settings. `http-quik` solves this with
//! a BoringSSL backend and forensic-level protocol replication.
//!
//! ## Core Features
//!
//! - **BoringSSL Integration** — Full ClientHello control including GREASE, ECH,
//!   and extension permutation via raw FFI calls.
//! - **Cross-Platform Profiles** — Pre-configured identities for Chrome 134 on
//!   macOS, Windows, and Linux with OS-specific ALPS payloads and Client Hints.
//! - **OS Auto-Detection** — [`Client::new()`] selects a profile matched to the
//!   host kernel, eliminating p0f mismatch flags without configuration.
//! - **Connection Pooling** — Managed H2 session reuse to maintain consistent
//!   behavioral fingerprints across request chains.
//! - **Stealth Redirects** — A redirect state machine that handles `sec-fetch-*`
//!   headers and method rotation identical to Chromium.
//!
//! ## Getting Started
//!
//! ```rust
//! use http_quik::Client;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), http_quik::Error> {
//!     // Auto-detects host OS and uses the matching Chrome 134 profile.
//!     let client = Client::new();
//!
//!     // Or target a specific platform explicitly:
//!     // use http_quik::{Platform, profile::chrome_134};
//!     // let client = Client::builder()
//!     //     .profile(chrome_134::profile(Platform::LinuxX64))
//!     //     .build()?;
//!
//!     let response = client.get("https://example.com").await?;
//!     println!("Status: {}", response.status());
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Safety & FFI
//!
//! This crate uses `boring` and `boring-sys` for low-level TLS control. All
//! `unsafe` blocks are localized to the `tls` and `client::connector` modules
//! and carry `// SAFETY:` annotations documenting the invariants they rely on.
//!
//! ## Changelog
//!
//! See [CHANGELOG.md](https://github.com/polymit/quik/blob/main/CHANGELOG.md)
//! for versioned release notes.

/// High-level client, connection pooling, and request execution.
pub mod client;

/// Crate-wide error types.
pub mod error;

/// Low-level HTTP/2 frame builder configuration.
///
/// Provides internal utilities for overriding the default H2 handshake
/// to replicate Chromium's SETTINGS order, WINDOW_UPDATE values, and
/// pseudo-header sequencing.
pub(crate) mod http2;

/// Chrome transport identity profiles.
///
/// Contains the data-only configuration schemas and pre-built profile
/// constructors for each supported Chrome version and platform.
pub mod profile;

/// TLS connector construction and BoringSSL FFI bindings.
///
/// Handles bit-perfect replication of Chrome's TLS handshake, including
/// post-quantum key shares (X25519MLKEM768), ALPS injection, and
/// extension permutation.
pub(crate) mod tls;

pub use crate::client::{connect, Client, ClientBuilder, Response};
pub use crate::error::{Error, Result};
pub use crate::profile::chrome_134::AKAMAI_FINGERPRINT;
pub use crate::profile::chrome_134::JA3_HASH;
pub use crate::profile::{ChromeProfile, Platform};
