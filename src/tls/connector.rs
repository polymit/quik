use boring::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, SslConnector, SslMethod, SslVerifyMode,
};
use std::io::{Read, Write};

use crate::error::Result;
use crate::profile::TlsProfile;

/// Brotli decompressor for RFC 8879 certificate compression.
///
/// Chrome 134 supports algorithm ID 2 (Brotli). This implementation
/// allows the client to decompress certificates sent by the server,
/// mirroring standard browser capabilities.
pub struct BrotliCompressor;

impl CertificateCompressor for BrotliCompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: Write,
    {
        let mut reader = brotli::Decompressor::new(input, 4096);
        let mut buf = [0u8; 4096];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            output.write_all(&buf[..n])?;
        }
        Ok(())
    }
}

/// Builds a `boring` TLS connector configured for bit-perfect Chrome 134 parity.
///
/// This function translates the high-level [`TlsProfile`] into specific BoringSSL
/// configuration calls. It is the heart of the Layer 4 identity replication.
///
/// ## Identity Markers Applied:
/// - **Cipher Suites**: Exact ordering of 15 suites, starting with TLS 1.3 GREASE.
/// - **Handshake GREASE**: Randomized ciphers and extensions (RFC 8701) to
///   prevent "frozen" protocol Ossification.
/// - **Extension Permutation**: Per-connection randomized ordering of extensions
///   to match modern Chromium behavior.
/// - **Post-Quantum Cryptography**: Inclusion of the X25519MLKEM768 hybrid group
///   (Group ID 4588).
/// - **SCT Support**: Mandatory Signed Certificate Timestamps to match Chrome's
///   Certificate Transparency policy.
pub fn build_connector(profile: &TlsProfile) -> Result<SslConnector> {
    tracing::debug!("Building TLS connector...");
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;

    // TLS version bounds
    builder.set_min_proto_version(Some(profile.min_version))?;
    builder.set_max_proto_version(Some(profile.max_version))?;

    // Cipher list
    // Precision here is critical for JA3/JA4 consistency.
    builder.set_cipher_list(profile.cipher_list)?;

    // Curves
    // NOTE(agent): We resolve the PQ ML-KEM regression by enabling the `pq-experimental`
    // feature on the `boring` crate, allowing group `4588` to correctly resolve to
    // `"X25519MLKEM768"`, achieving perfect Chrome 134 TLS group parity.
    let mut curves_str = String::new();
    for (i, &group) in profile.curves.iter().enumerate() {
        if i > 0 {
            curves_str.push(':');
        }
        match group {
            4588 => curves_str.push_str("X25519MLKEM768"),
            29 => curves_str.push_str("X25519"),
            23 => curves_str.push_str("P-256"),
            24 => curves_str.push_str("P-384"),
            _ => curves_str.push_str(&group.to_string()),
        }
    }
    builder.set_curves_list(&curves_str)?;

    // GREASE and Extension Permutation
    // Both must be enabled to avoid "suspicious stability" flags in handshake analysis.
    if profile.grease_enabled {
        builder.set_grease_enabled(true);
    }
    if profile.permute_extensions {
        builder.set_permute_extensions(true);
    }

    // ALPN (h2, http/1.1)
    let mut alpn = Vec::new();
    for proto in profile.alpn_protocols {
        alpn.push(proto.len() as u8);
        alpn.extend_from_slice(proto);
    }
    builder.set_alpn_protos(&alpn)?;

    // SCT (Signed Certificate Timestamps)
    builder.enable_signed_cert_timestamps();

    // Advanced FFI configuration for features not yet exposed by the high-level API.
    let ctx_ptr = builder.as_ptr();

    // SAFETY: The `ctx_ptr` is valid for the duration of the builder lifecycle.
    // We pass a valid pointer to the sigalgs array and its length.
    unsafe {
        if boring_sys::SSL_CTX_set_signing_algorithm_prefs(
            ctx_ptr,
            profile.sigalgs.as_ptr(),
            profile.sigalgs.len(),
        ) != 1
        {
            return Err(crate::error::Error::TlsBuild(
                boring::error::ErrorStack::get(),
            ));
        }
        if boring_sys::SSL_CTX_set_verify_algorithm_prefs(
            ctx_ptr,
            profile.sigalgs.as_ptr(),
            profile.sigalgs.len(),
        ) != 1
        {
            return Err(crate::error::Error::TlsBuild(
                boring::error::ErrorStack::get(),
            ));
        }
    }

    // Certificate compression
    if profile.compress_certificate {
        builder.add_certificate_compression_algorithm(BrotliCompressor)?;
    }

    if !profile.verify_peer {
        builder.set_verify(SslVerifyMode::NONE);
    }

    Ok(builder.build())
}
