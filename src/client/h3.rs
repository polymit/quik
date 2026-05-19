//! Google Chrome fingerprinted HTTP/3 configuration profile.
//!
//! This module implements application-layer configuration parameters to match
//! the network footprints of modern Chromium-based engines (v148).
//! In stealth scanning and protocol emulation contexts, mismatches in these parameters
//! (such as QPACK limits or GREASE settings) are easily flagged by Web Application Firewalls (WAFs).

/// Chromium sets the QPACK dynamic table size limit to 0 (default, unlimited) in Chrome 148.
/// This configuration dictates that no active memory constraints are declared on the connection
/// control streams for compression dictionary storage, reflecting Chromium's high-memory allowance.
const CHROME_SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0;

/// Chromium sets the maximum field section size to 0 (effectively unlimited).
/// By omitting a strict threshold or specifying 0, Chromium leverages platform defaults
/// for deep header list processing, preventing local decompression bottleneck flags.
const CHROME_SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0;

/// Chromium allows up to 0 blocked streams by default under Chrome 148 settings.
/// This prevents decoder stream blocks, ensuring immediate parsing and low head-of-line latency.
const CHROME_SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0;

/// Configures an HTTP/3 settings profile matching the exact identity of Google Chrome 148.
///
/// This function translates the target application-layer configurations into `quiche`'s H3 setup.
///
/// ### Fingerprint Considerations:
/// Active WAF engines scan H3 handshake control frames. Standard libraries emit bounded QPACK
/// parameters which instantly fail identity tests because Chrome 148 operates with unbounded QPACK
/// limits by default. This constructor unifies our protocol footprint with Chrome's live behavior.
pub fn configure_chrome_h3() -> Result<quiche::h3::Config, quiche::h3::Error> {
    let mut config = quiche::h3::Config::new()?;

    // Align header compression context sizes with Chrome 148's exact network stack settings.
    config.set_qpack_max_table_capacity(CHROME_SETTINGS_QPACK_MAX_TABLE_CAPACITY);
    config.set_max_field_section_size(CHROME_SETTINGS_MAX_FIELD_SECTION_SIZE);
    config.set_qpack_blocked_streams(CHROME_SETTINGS_QPACK_BLOCKED_STREAMS);

    // Advertise support for WebSocket bootstrap streams over HTTP/3 (RFC 8441).
    config.enable_extended_connect(true);

    Ok(config)
}

