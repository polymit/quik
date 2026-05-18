//! Data-only definitions for Chrome transport identity profiles.
//!
//! This module defines the configuration schemas used by the `tls` and `http2`
//! modules to construct browser-identical network handshakes. No protocol
//! logic resides here; these structures serve as the single source of truth
//! for all fingerprint-sensitive parameters.
//!
//! Each [`ChromeProfile`] encodes a complete, multi-layer network identity
//! spanning TLS (Layer 4), HTTP/2 (Layer 5), and HTTP metadata (Layer 7).

use boring::ssl::SslVersion;

pub mod chrome_134;

/// Alias for BoringSSL's internal version type.
pub type TlsVersion = SslVersion;

/// Target operating system and CPU architecture.
///
/// The platform determines OS-specific protocol parameters (ALPS payload
/// length, User-Agent string, Client Hint values) and is used by
/// [`chrome_134::profile_auto`] to align the network persona with the
/// host kernel's TCP/IP characteristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// macOS on Apple Silicon (M1/M2/M3/M4).
    MacOsArm,
    /// macOS on Intel x86-64.
    MacOsX86,
    /// Windows 10/11 on x86-64.
    WindowsX64,
    /// Linux (Ubuntu, Debian, etc.) on x86-64.
    LinuxX64,
}

/// Configuration for the TLS 1.2/1.3 handshake layer.
///
/// This structure defines the Layer 4 identity of the client. Small changes
/// here (such as the order of cipher suites) will change the JA3/JA4
/// fingerprint and can lead to immediate detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsProfile {
    /// Minimum allowed TLS version (typically TLS 1.2).
    pub min_version: TlsVersion,
    /// Maximum allowed TLS version (typically TLS 1.3).
    pub max_version: TlsVersion,
    /// Colon-separated list of cipher suites in OpenSSL format.
    ///
    /// Precision in the order of this list is critical as it directly
    /// impacts the JA3/JA4 fingerprint.
    pub cipher_list: &'static str,
    /// Numeric IDs for supported elliptic curve groups.
    pub curves: &'static [u16],
    /// Whether to enable TLS GREASE (RFC 8701) to simulate randomized extensions.
    pub grease_enabled: bool,
    /// Whether to permute (shuffle) TLS extensions per connection.
    pub permute_extensions: bool,
    /// Whether to send a dummy ECH (Encrypted Client Hello) extension for GREASE.
    pub enable_ech_grease: bool,
    /// Whether to enable ALPS (Application-Layer Protocol Settings).
    pub alps_enabled: bool,
    /// Whether to use the draft-01 or final ALPS codepoint.
    pub alps_use_new_codepoint: bool,
    /// Additional H2 SETTINGS IDs to append in the ALPS payload.
    ///
    /// Windows and Linux Chrome include an extra setting (ID 31386) in the
    /// ALPS handshake data that macOS omits. Each tuple is `(id, value)`.
    pub alps_extra_settings: &'static [(u16, u32)],
    /// Whether to support RFC 8879 certificate compression (Brotli).
    pub compress_certificate: bool,
    /// Whether to enable stateless session tickets for fast reconnection.
    pub session_ticket_enabled: bool,
    /// Ordered list of ALPN protocol identifiers.
    pub alpn_protocols: &'static [&'static [u8]],
    /// Ordered list of signature algorithm IDs (used for JA4_r).
    pub sigalgs: &'static [u16],
    /// Whether to verify the server's certificate chain.
    ///
    /// Real browsers always verify certificates. Disable only for testing or
    /// local proxy interception.
    pub verify_peer: bool,
}

/// Initial HTTP/2 SETTINGS frame parameters.
///
/// The values and the *order* in which they are sent are used by Akamai
/// and other WAFs to identify the client implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettingsFrame {
    /// SETTINGS_HEADER_TABLE_SIZE (ID 0x1).
    pub header_table_size: u32,
    /// SETTINGS_ENABLE_PUSH (ID 0x2).
    pub enable_push: bool,
    /// SETTINGS_INITIAL_WINDOW_SIZE (ID 0x4).
    pub initial_window_size: u32,
    /// SETTINGS_MAX_HEADER_LIST_SIZE (ID 0x6).
    pub max_header_list_size: u32,
}

/// Configuration for the HTTP/2 protocol layer.
///
/// Defines the Layer 5 identity, focusing on behavioral markers like
/// pseudo-header ordering and stream priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http2Profile {
    /// Initial SETTINGS frame values and order.
    pub settings: SettingsFrame,
    /// Total connection-level window size (default + delta).
    ///
    /// This value determines the initial `WINDOW_UPDATE` frame increment
    /// sent immediately after the handshake. Chrome uses a specific non-standard
    /// increment that acts as a strong identity signal.
    pub initial_connection_window_size: u32,
    /// Ordering of pseudo-headers (e.g., :method, :authority, :scheme, :path).
    pub pseudo_order: [PseudoOrder; 4],
    /// Priority parameters for the initial HEADERS frame.
    pub headers_priority: HeadersPriority,
}

/// Stream priority parameters embedded in the HEADERS frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadersPriority {
    /// Stream ID that this request depends on (typically 0).
    pub dep: u32,
    /// Priority weight (0-255).
    pub weight: u8,
    /// Whether this dependency is exclusive.
    pub exclusive: bool,
}

/// Canonical HTTP/2 pseudo-header identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PseudoOrder {
    /// `:method`
    Method,
    /// `:authority`
    Authority,
    /// `:scheme`
    Scheme,
    /// `:path`
    Path,
}

/// Chrome-specific HTTP header values and Client Hint metadata.
///
/// These values are injected into every outbound request and must match
/// the declared platform. WAFs cross-check `sec-ch-ua-platform` against
/// the TLS handshake and TCP stack to detect spoofed identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderProfile {
    /// Full `User-Agent` header value.
    pub user_agent: String,
    /// `sec-ch-ua` Client Hint brand list.
    pub sec_ch_ua: String,
    /// `sec-ch-ua-platform` Client Hint (e.g., `"macOS"`, `"Windows"`, `"Linux"`).
    pub sec_ch_ua_platform: String,
    /// `sec-ch-ua-platform-version` Client Hint.
    ///
    /// Must match the host OS: Windows 11 reports `"15.0.0"`,
    /// macOS Sequoia reports `"15.0.0"`, Linux reports `"0.0.0"`.
    pub sec_ch_ua_platform_version: String,
    /// Whether to include the RFC 9218 `priority` header (e.g., `u=0, i`).
    pub include_priority_header: bool,
    /// Whether to advertise `zstd` in the `accept-encoding` header.
    pub zstd_encoding: bool,
    /// The Accept-Language header value.
    pub accept_language: String,
}

/// A complete, multi-layer identity profile for a Chrome instance.
///
/// Combines TLS, HTTP/2, and HTTP metadata into a single configuration
/// that, when applied, makes the transport layer indistinguishable from
/// the specified Chrome version and platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChromeProfile {
    /// Major Chrome version (e.g., `134`).
    pub version: u32,
    /// Target operating system and architecture.
    pub platform: Platform,
    /// TLS handshake configuration (JA3/JA4 fingerprint source).
    pub tls: TlsProfile,
    /// HTTP/2 handshake configuration (Akamai fingerprint source).
    pub h2: Http2Profile,
    /// HTTP-level metadata and Client Hints.
    pub headers: HeaderProfile,
}
