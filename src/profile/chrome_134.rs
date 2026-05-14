//! Chrome 134 identity constants and cross-platform profile constructors.
//!
//! Contains the exact byte sequences, fingerprint hashes, and protocol
//! parameters observed in Chrome 134 Stable across macOS, Windows, and Linux.
//! The TLS and H2 layers are platform-invariant; only the ALPS payload and
//! HTTP metadata (User-Agent, Client Hints) vary by operating system.
//!
//! Use [`profile_auto`] to select a profile that matches the host OS at
//! compile time, or [`profile`] to target a specific [`Platform`].

use boring::ssl::SslVersion;

use crate::profile::{
    ChromeProfile, HeaderProfile, HeadersPriority, Http2Profile, Platform, PseudoOrder,
    SettingsFrame, TlsProfile,
};

/// Reference JA3 fingerprint hash for Chrome 134.
///
/// Derived from the cipher suite and extension ordering in the ClientHello.
/// This hash is platform-independent — all three OS builds produce the same value.
pub const JA3_HASH: &str = "845db3b4e398789bdeb5b15594360a29";

/// Reference normalized JA3 (JA3N) hash.
pub const JA3N_HASH: &str = "8e19337e7524d2573be54efb2b0784c9";

/// Reference JA4 fingerprint identifier.
pub const JA4: &str = "t13d1516h2_8daaf6152771_d8a2da3f94cd";

/// Akamai HTTP/2 fingerprint string.
///
/// Encodes the SETTINGS values, WINDOW_UPDATE delta, priority dependency,
/// and pseudo-header ordering. Identical across all platforms.
pub const AKAMAI_FINGERPRINT: &str = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p";

/// Additional ALPS SETTINGS entries for Windows and Linux Chrome 134.
///
/// Chrome on Windows and Linux appends setting ID `0x7A9A` (31386) to the
/// ALPS handshake payload, producing a 30-byte SETTINGS block versus the
/// 24-byte block on macOS. WAFs that inspect ALPS length can use this
/// difference to correlate the TLS layer with the declared platform.
const ALPS_EXTRA_SETTINGS_WIN_LINUX: &[(u16, u32)] = &[(0x7A9A, 0xE3590A45)];

/// macOS Chrome 134 omits setting `0x7A9A` from the ALPS payload.
const ALPS_EXTRA_SETTINGS_MACOS: &[(u16, u32)] = &[];

/// Exact cipher suite list for Chrome 134.
///
/// Includes TLS 1.3 suites followed by ECDHE and RSA legacy suites in the
/// precise order emitted by the Chromium BoringSSL configuration.
const CIPHER_LIST: &str = concat!(
    "TLS_AES_128_GCM_SHA256:",
    "TLS_AES_256_GCM_SHA384:",
    "TLS_CHACHA20_POLY1305_SHA256:",
    "ECDHE-ECDSA-AES128-GCM-SHA256:",
    "ECDHE-RSA-AES128-GCM-SHA256:",
    "ECDHE-ECDSA-AES256-GCM-SHA384:",
    "ECDHE-RSA-AES256-GCM-SHA384:",
    "ECDHE-ECDSA-CHACHA20-POLY1305:",
    "ECDHE-RSA-CHACHA20-POLY1305:",
    "ECDHE-RSA-AES128-SHA:",
    "ECDHE-RSA-AES256-SHA:",
    "AES128-GCM-SHA256:",
    "AES256-GCM-SHA384:",
    "AES128-SHA:",
    "AES256-SHA"
);

/// Supported elliptic curve groups.
///
/// Group 4588 corresponds to X25519MLKEM768, Chrome's post-quantum hybrid group.
/// If this is missing from the ClientHello, the client is immediately flagged
/// as non-Chrome 131+.
const CURVES: &[u16] = &[4588, 29, 23, 24];

/// ALPN protocol identifier for HTTP/2.
const ALPN_H2: &[u8] = b"h2";
/// ALPN protocol identifier for HTTP/1.1 fallback.
const ALPN_HTTP_11: &[u8] = b"http/1.1";
/// Ordered ALPN list: H2 preferred, HTTP/1.1 as fallback.
const ALPN_PROTOCOLS: &[&[u8]] = &[ALPN_H2, ALPN_HTTP_11];

/// Signature algorithm preferences in JA4_r order (per Chromium BoringSSL).
const SIGALGS: &[u16] = &[
    0x0403, // ecdsa_secp256r1_sha256
    0x0804, // rsa_pss_rsae_sha256
    0x0401, // rsa_pkcs1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0805, // rsa_pss_rsae_sha384
    0x0501, // rsa_pkcs1_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0601, // rsa_pkcs1_sha512
];

/// HTTP/2 pseudo-header ordering (m,a,s,p).
///
/// Moving `:authority` to the second position is a key Chrome-specific
/// marker that differs from standard HTTP/2 library defaults.
const PSEUDO_ORDER: [PseudoOrder; 4] = [
    PseudoOrder::Method,
    PseudoOrder::Authority,
    PseudoOrder::Scheme,
    PseudoOrder::Path,
];

/// Builds the platform-invariant TLS configuration.
///
/// All Chrome 134 builds share the same cipher suites, curves, and extension
/// behavior. The only TLS-level difference is the `alps_extra` slice, which
/// controls the ALPS payload size.
fn base_tls(alps_extra: &'static [(u16, u32)]) -> TlsProfile {
    TlsProfile {
        min_version: SslVersion::TLS1_2,
        max_version: SslVersion::TLS1_3,
        cipher_list: CIPHER_LIST,
        curves: CURVES,
        grease_enabled: true,
        permute_extensions: true,
        enable_ech_grease: true,
        alps_enabled: true,
        alps_use_new_codepoint: true,
        alps_extra_settings: alps_extra,
        compress_certificate: true,
        session_ticket_enabled: true,
        alpn_protocols: ALPN_PROTOCOLS,
        sigalgs: SIGALGS,
    }
}

/// Builds the platform-invariant HTTP/2 configuration.
///
/// SETTINGS values, WINDOW_UPDATE increment, pseudo-header ordering, and
/// HEADERS priority are identical across all three platforms.
fn base_h2() -> Http2Profile {
    Http2Profile {
        settings: SettingsFrame {
            header_table_size: 65_536,
            enable_push: false,
            initial_window_size: 6_291_456,
            max_header_list_size: 262_144,
        },
        // Chrome sends a WINDOW_UPDATE of 15663105, producing a total
        // connection window of 15728640 (65535 default + 15663105 delta).
        initial_connection_window_size: 15_728_640,
        pseudo_order: PSEUDO_ORDER,
        headers_priority: HeadersPriority {
            dep: 0,
            weight: 255,
            exclusive: true,
        },
    }
}

/// `sec-ch-ua` brand string, shared across all platforms.
///
/// The GREASE brand (`Not:A-Brand`) and its version (`24`) are fixed for
/// Chrome 134 and do not vary by OS.
const SEC_CH_UA: &str =
    "\"Chromium\";v=\"134\", \"Not:A-Brand\";v=\"24\", \"Google Chrome\";v=\"134\"";

/// Chrome 134 profile for macOS on Apple Silicon (ARM64).
///
/// Uses the 24-byte ALPS payload (no extra settings) and reports
/// `sec-ch-ua-platform-version` as `"15.0.0"` for macOS Sequoia.
pub fn chrome_134_macos_arm() -> ChromeProfile {
    ChromeProfile {
        version: 134,
        platform: Platform::MacOsArm,
        tls: base_tls(ALPS_EXTRA_SETTINGS_MACOS),
        h2: base_h2(),
        headers: HeaderProfile {
            user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
                AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.35 Safari/537.36"
                .to_owned(),
            sec_ch_ua: SEC_CH_UA.to_owned(),
            sec_ch_ua_platform: "\"macOS\"".to_owned(),
            sec_ch_ua_platform_version: "\"15.0.0\"".to_owned(),
            include_priority_header: true,
            zstd_encoding: true,
        },
    }
}

/// Chrome 134 profile for Windows 11 on x86-64.
///
/// Uses the 30-byte ALPS payload (includes setting `0x7A9A`) and reports
/// `sec-ch-ua-platform-version` as `"13.0.0"` (Windows 11 kernel version).
pub fn chrome_134_windows_x64() -> ChromeProfile {
    ChromeProfile {
        version: 134,
        platform: Platform::WindowsX64,
        tls: base_tls(ALPS_EXTRA_SETTINGS_WIN_LINUX),
        h2: base_h2(),
        headers: HeaderProfile {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
                AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.35 Safari/537.36"
                .to_owned(),
            sec_ch_ua: SEC_CH_UA.to_owned(),
            sec_ch_ua_platform: "\"Windows\"".to_owned(),
            sec_ch_ua_platform_version: "\"13.0.0\"".to_owned(),
            include_priority_header: true,
            zstd_encoding: true,
        },
    }
}

/// Chrome 134 profile for Linux (Ubuntu/Debian x86-64).
///
/// Uses the 30-byte ALPS payload (includes setting `0x7A9A`) and reports
/// `sec-ch-ua-platform-version` as `"0.0.0"` (Linux does not expose a
/// meaningful kernel version through Client Hints).
pub fn chrome_134_linux_x64() -> ChromeProfile {
    ChromeProfile {
        version: 134,
        platform: Platform::LinuxX64,
        tls: base_tls(ALPS_EXTRA_SETTINGS_WIN_LINUX),
        h2: base_h2(),
        headers: HeaderProfile {
            user_agent: "Mozilla/5.0 (X11; Linux x86_64) \
                AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.35 Safari/537.36"
                .to_owned(),
            sec_ch_ua: SEC_CH_UA.to_owned(),
            sec_ch_ua_platform: "\"Linux\"".to_owned(),
            sec_ch_ua_platform_version: "\"0.0.0\"".to_owned(),
            include_priority_header: true,
            zstd_encoding: true,
        },
    }
}

/// Returns the Chrome 134 profile for the given [`Platform`].
///
/// Use this when you need explicit control over which OS persona to emit,
/// regardless of the host system.
pub fn profile(platform: Platform) -> ChromeProfile {
    match platform {
        Platform::MacOsArm | Platform::MacOsX86 => chrome_134_macos_arm(),
        Platform::WindowsX64 => chrome_134_windows_x64(),
        Platform::LinuxX64 => chrome_134_linux_x64(),
    }
}

/// Returns the Chrome 134 profile matched to the host OS at compile time.
///
/// This implements the **Total Consistency** strategy: the TLS and HTTP/2
/// persona aligns with the host kernel's TCP/IP stack, eliminating the
/// passive OS fingerprinting (p0f) mismatches that WAFs use to flag bots.
///
/// On Linux hosts this selects [`chrome_134_linux_x64`], on macOS it selects
/// [`chrome_134_macos_arm`], and on Windows it selects [`chrome_134_windows_x64`].
pub fn profile_auto() -> ChromeProfile {
    if cfg!(target_os = "macos") {
        chrome_134_macos_arm()
    } else if cfg!(target_os = "windows") {
        chrome_134_windows_x64()
    } else {
        chrome_134_linux_x64()
    }
}
