//! Google Chrome fingerprinted HTTP/3 configuration profile.
//!
//! This module implements application-layer configuration parameters to match
//! the network footprints of modern Chromium-based engines (v134-136).
//! In stealth scanning and protocol emulation contexts, mismatches in these parameters
//! (such as QPACK limits or GREASE settings) are easily flagged by Web Application Firewalls (WAFs).

/// Chromium sets the QPACK dynamic table size limit to 64 KiB (65536 bytes).
/// This configuration dictates the maximum memory footprint allocated for compression
/// context storage in header field encoding/decoding.
const CHROME_SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 65536;

/// Chromium enforces a maximum field section size of 256 KiB (262144 bytes).
/// This parameter represents the aggregate byte ceiling for all fields in an HTTP
/// request or response block, protecting the decompression engine from resource exhaustion.
const CHROME_SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 262144;

/// Chromium allows up to 100 blocked streams during QPACK decompression updates.
/// A stream is blocked if it references a dynamic table entry that has not yet been
/// acknowledged by the encoder on the control channel. Permitting 100 parallel blocked
/// streams prevents local head-of-line blocking under heavy multiplexing.
const CHROME_SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 100;

/// Configures an HTTP/3 settings profile matching the exact identity of Google Chrome.
///
/// This function translates the target application-layer configurations into `quiche`'s H3 setup.
///
/// ### Why these specific constants?
/// - **QPACK Capacity (64 KiB) & Blocked Streams (100)**: These are hardcoded thresholds within
///   Chromium's HTTP/3 stack (`net/third_party/quiche/src/quiche/common/platform/api/quiche_flags.h`).
///   Providing standard defaults or library fallbacks will trigger signature anomalies in WAF parsers.
/// - **Extended CONNECT (true)**: Matches Chrome's advertising of RFC 8441 support, enabling
///   multiplexed WebSockets and raw stream proxying directly over established HTTP/3 channels.
/// - **GREASE Settings Injection**: Injects random/pseudo-random parameters to comply with the RFC 9000
///   anti-ossification design. Chrome injects parameters at ID `0x1f * N + 0x21` to verify that
///   network intermediaries correctly ignore unknown setting codes rather than breaking connections.
pub fn configure_chrome_h3() -> Result<quiche::h3::Config, quiche::h3::Error> {
    let mut config = quiche::h3::Config::new()?;

    // Align header compression context sizes with Chrome's network stack.
    config.set_qpack_max_table_capacity(CHROME_SETTINGS_QPACK_MAX_TABLE_CAPACITY);
    config.set_max_field_section_size(CHROME_SETTINGS_MAX_FIELD_SECTION_SIZE);
    config.set_qpack_blocked_streams(CHROME_SETTINGS_QPACK_BLOCKED_STREAMS);

    // Advertise support for WebSocket bootstrap streams over HTTP/3.
    config.enable_extended_connect(true);

    // Generate a RFC-compliant GREASE setting ID to bypass anti-ossification filters.
    // Chrome uses the formula: 0x1f * N + 0x21 (e.g. 0x157 when N = 10).
    let grease_setting_id = 0x1f * 10 + 0x21; // 0x157 (343)
    let grease_setting_value = 0xbeef;

    // Bind the GREASE configuration to the outbound control frame.
    config.set_additional_settings(vec![(grease_setting_id, grease_setting_value)])?;

    Ok(config)
}
