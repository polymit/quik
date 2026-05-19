//! Chrome 147 identity constants and cross-platform profile constructors.
//!
//! Contains the exact byte sequences, fingerprint hashes, and protocol
//! parameters observed in Chrome 147 Stable across macOS, Windows, and Linux.
//! The TLS and HTTP/2 layers are platform-invariant; only the HTTP metadata
//! (User-Agent, Client Hints) varies by operating system.
//!
//! Use [`profile_auto`] to select a profile that matches the host OS at
//! compile time, or [`profile`] to target a specific [`Platform`].

use boring::ssl::SslVersion;

use crate::profile::{
    ChromeProfile, HeaderProfile, HeadersPriority, Http2Profile, Platform, PseudoOrder,
    SettingsFrame, TlsProfile,
};

/// Reference JA3 fingerprint hash for Chrome 147.
///
/// Derived from the cipher suite and extension ordering in the ClientHello.
pub const JA3_HASH: &str = "82f426fce8cc17b3c83eefbc7dcf677b";

/// Reference JA4 fingerprint identifier.
pub const JA4: &str = "u13d0313h3_55b375c5d22e_226f3f127bbe";

/// Akamai HTTP/2 fingerprint string.
///
/// Encodes the SETTINGS values, WINDOW_UPDATE delta, priority dependency,
/// and pseudo-header ordering. Identical across all platforms.
pub const AKAMAI_FINGERPRINT: &str = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p";

/// Chrome 147 does not feature platform-specific differences in the ALPS
/// payload structure; all platforms share an empty extra settings array.
const ALPS_EXTRA_SETTINGS: &[(u16, u32)] = &[];

/// Exact cipher suite list for Chrome 147.
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
const CURVES: &[u16] = &[4588, 29, 23, 24];

/// ALPN protocol identifier for HTTP/2.
const ALPN_H2: &[u8] = b"h2";
/// ALPN protocol identifier for HTTP/1.1 fallback.
const ALPN_HTTP_11: &[u8] = b"http/1.1";
/// Ordered ALPN list: H2 preferred, HTTP/1.1 as fallback.
const ALPN_PROTOCOLS: &[&[u8]] = &[ALPN_H2, ALPN_HTTP_11];

/// Signature algorithm preferences in JA4_r order (per Chromium BoringSSL).
///
/// Chrome 147 appends the legacy RSA_PKCS1_SHA1 (0x0201) signature algorithm
/// at the end of the preferences list.
const SIGALGS: &[u16] = &[
    0x0403, // ecdsa_secp256r1_sha256
    0x0804, // rsa_pss_rsae_sha256
    0x0401, // rsa_pkcs1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0805, // rsa_pss_rsae_sha384
    0x0501, // rsa_pkcs1_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0601, // rsa_pkcs1_sha512
    0x0201, // rsa_pkcs1_sha1
];

/// HTTP/2 pseudo-header ordering (m,a,s,p).
const PSEUDO_ORDER: [PseudoOrder; 4] = [
    PseudoOrder::Method,
    PseudoOrder::Authority,
    PseudoOrder::Scheme,
    PseudoOrder::Path,
];

/// Builds the platform-invariant TLS configuration.
fn base_tls() -> TlsProfile {
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
        alps_extra_settings: ALPS_EXTRA_SETTINGS,
        compress_certificate: true,
        session_ticket_enabled: true,
        alpn_protocols: ALPN_PROTOCOLS,
        sigalgs: SIGALGS,
        verify_peer: true,
    }
}

/// Builds the platform-invariant HTTP/2 configuration.
fn base_h2() -> Http2Profile {
    Http2Profile {
        settings: SettingsFrame {
            header_table_size: 65_536,
            enable_push: false,
            initial_window_size: 6_291_456,
            max_header_list_size: 262_144,
        },
        initial_connection_window_size: 15_728_640,
        pseudo_order: PSEUDO_ORDER,
        headers_priority: HeadersPriority {
            dep: 0,
            weight: 255,
            exclusive: true,
        },
    }
}

/// Generates a randomized `sec-ch-ua` GREASE brand string matching Chrome 147.
///
/// Uses the period (.) delimiter and version "8" for the GREASE brand, combined
/// with Chromium and Google Chrome at version 147.
fn generate_sec_ch_ua() -> String {
    let brands = [
        "Not.A/Brand",
        "Not.A\\Brand",
        "Not.A)Brand",
        "Not.A;Brand",
        "Not.A=Brand",
    ];
    let brand = brands[rand::random_range(0..brands.len())];
    let v = "8";

    // Vary the position of the GREASE brand randomly to prevent static signature matching.
    let pos = rand::random_range(0..3);
    match pos {
        0 => format!(
            "\"{}\";v=\"{}\", \"Chromium\";v=\"147\", \"Google Chrome\";v=\"147\"",
            brand, v
        ),
        1 => format!(
            "\"Chromium\";v=\"147\", \"{}\";v=\"{}\", \"Google Chrome\";v=\"147\"",
            brand, v
        ),
        _ => format!(
            "\"Chromium\";v=\"147\", \"Google Chrome\";v=\"147\", \"{}\";v=\"{}\"",
            brand, v
        ),
    }
}

/// Chrome 147 profile for macOS on Apple Silicon (ARM64).
pub fn chrome_147_macos_arm() -> ChromeProfile {
    ChromeProfile {
        version: 147,
        platform: Platform::MacOsArm,
        tls: base_tls(),
        h2: base_h2(),
        headers: HeaderProfile {
            user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
                AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.7727.56 Safari/537.36"
                .to_owned(),
            sec_ch_ua: generate_sec_ch_ua(),
            sec_ch_ua_platform: "\"macOS\"".to_owned(),
            sec_ch_ua_platform_version: "\"14.4.0\"".to_owned(),
            include_priority_header: true,
            zstd_encoding: true,
            accept_language: "en-US,en;q=0.9".to_owned(),
        },
    }
}

/// Chrome 147 profile for Windows 11 on x86-64.
pub fn chrome_147_windows_x64() -> ChromeProfile {
    ChromeProfile {
        version: 147,
        platform: Platform::WindowsX64,
        tls: base_tls(),
        h2: base_h2(),
        headers: HeaderProfile {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
                AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.7727.56 Safari/537.36"
                .to_owned(),
            sec_ch_ua: generate_sec_ch_ua(),
            sec_ch_ua_platform: "\"Windows\"".to_owned(),
            sec_ch_ua_platform_version: "\"10.0.0\"".to_owned(),
            include_priority_header: true,
            zstd_encoding: true,
            accept_language: "en-US,en;q=0.9".to_owned(),
        },
    }
}

/// Chrome 147 profile for Linux (Ubuntu/Debian x86-64).
pub fn chrome_147_linux_x64() -> ChromeProfile {
    ChromeProfile {
        version: 147,
        platform: Platform::LinuxX64,
        tls: base_tls(),
        h2: base_h2(),
        headers: HeaderProfile {
            user_agent: "Mozilla/5.0 (X11; Linux x86_64) \
                AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.7727.56 Safari/537.36"
                .to_owned(),
            sec_ch_ua: generate_sec_ch_ua(),
            sec_ch_ua_platform: "\"Linux\"".to_owned(),
            sec_ch_ua_platform_version: "\"\"".to_owned(),
            include_priority_header: true,
            zstd_encoding: true,
            accept_language: "en-US,en;q=0.9".to_owned(),
        },
    }
}

/// Returns the Chrome 147 profile for the given [`Platform`].
pub fn profile(platform: Platform) -> ChromeProfile {
    match platform {
        Platform::MacOsArm | Platform::MacOsX86 => chrome_147_macos_arm(),
        Platform::WindowsX64 => chrome_147_windows_x64(),
        Platform::LinuxX64 => chrome_147_linux_x64(),
    }
}

/// Returns the Chrome 147 profile matched to the host OS at compile time.
pub fn profile_auto() -> ChromeProfile {
    if cfg!(target_os = "macos") {
        chrome_147_macos_arm()
    } else if cfg!(target_os = "windows") {
        chrome_147_windows_x64()
    } else {
        chrome_147_linux_x64()
    }
}
