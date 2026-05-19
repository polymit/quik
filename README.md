# http-quik: High-Fidelity Stealth Transport Engine

[![Crates.io](https://img.shields.io/crates/v/http-quik.svg)](https://crates.io/crates/http-quik)
[![Docs.rs](https://docs.rs/http-quik/badge.svg)](https://docs.rs/http-quik)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE.md)

[See the CHANGELOG for recent updates and release notes.](https://github.com/polymit/quik/blob/main/CHANGELOG.md)

`http-quik` is a specialized HTTP transport library built in Rust, designed for absolute network identity parity with Google Chrome. It provides low-level control over the entire protocol stack—from TLS handshakes to HTTP/2 frame signaling—to ensure that every network interaction is indistinguishable from a real browser.

This crate is a core component of the [Phantom Engine](https://github.com/polymit/phantom-engine) ecosystem.

## Why http-quik?

Modern anti-bot systems (like Cloudflare, Akamai, and DataDome) use passive fingerprinting to identify automated traffic. `http-quik` bypasses these systems by enforcing **Total Identity Consistency** across multiple layers:

- **TLS Fingerprints (JA3/JA4)**: Replicates Chrome's ClientHello using a custom BoringSSL stack, including GREASE, extension permutation, and post-quantum key shares (X25519MLKEM768).
- **HTTP/3 & QUIC Fingerprints**: Emulates Chrome v134-136 transport layouts using `quiche` over BoringSSL, supporting empty client CIDs, static/dynamic QPACK setups, PMTU discovery, and dynamic grease frames.
- **HTTP/2 Fingerprints (Akamai)**: Replicates Chromium's SETTINGS frame order, pseudo-header sequences, and connection window increments.
- **Cross-Platform Alignment**: Automatically aligns the TLS ALPS payload and Client Hints (`sec-ch-ua-platform`) with the host operating system to prevent p0f mismatches.
- **Behavioral Fingerprints**: Implements a Chrome-identical redirect state machine that handles `sec-fetch-*` headers and method rotation.
- **Dual-Stack Alt-Svc Fallback**: Stateful connection pooler automatically tracking server-solicited `Alt-Svc` headers, executing zero-delay transparent fallback to multiplexed H2 TCP streams on UDP network blockages.

## Core Capabilities

- **BoringSSL Integration**: Deep FFI bindings for low-level TLS control.
- **Chrome 147 Identity**: Bit-perfect replication of stable Chrome browser profiles.
- **Stealth HTTP/3 + QUIC**: Unified transport loop running dynamic pacers and Chrome settings.
- **OS Auto-Detection**: Defaults to a profile matching the host system (macOS, Windows, or Linux) for out-of-the-box stealth.
- **Connection Pooling**: Managed H2/H3 session reuse with concurrent lock-free stream readiness checks.
- **Rich Fetch Contexts**: Support for 11 distinct `RequestContext` variants (such as scripts, styles, images, and workers) with automated metadata matching.
- **Stateful Client Hints**: Automated cache (`Client::hint_cache`) tracking server-solicited `Accept-CH` headers to transmit platform details statefully.
- **Customizable Profiles**: Explicitly target specific platforms regardless of the host environment.

## Quick Start

Add `http-quik` to your `Cargo.toml`:

```toml
[dependencies]
http-quik = "0.1.9"
```

Execute a stealth request with automatic OS detection:

```rust
use http_quik::Client;

#[tokio::main]
async fn main() -> Result<(), http_quik::Error> {
    // Auto-detects host OS and uses the matching Chrome 147 profile
    let client = Client::new();

    // Execute a stealth GET request
    let response = client.get("https://example.com").await?;
    println!("Status: {}", response.status());

    Ok(())
}
```

Target a specific platform manually:

```rust
use http_quik::{Client, Platform, profile::chrome_147};

let client = Client::builder()
    .profile(chrome_147::profile(Platform::WindowsX64))
    .build()?;
```

> [!NOTE]
> `http-quik` is **secure by default** and performs full TLS certificate verification. For local development, testing, or proxy interception (e.g., mitmproxy), use `.danger_accept_invalid_certs(true)` on the `ClientBuilder`.


## Documentation

Full API documentation and usage guides are available on [Docs.rs](https://docs.rs/http-quik).

## License

This project is licensed under the [Apache License, Version 2.0](LICENSE.md).
