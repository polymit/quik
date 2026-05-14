use crate::profile::ChromeProfile;
use http::header::{HeaderMap, HeaderValue, ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, USER_AGENT};

/// Injects Chrome-identical headers into the provided request map.
///
/// Populates navigation metadata, Client Hints, compression preferences,
/// and HPACK sensitivity flags in the exact order and format emitted by
/// the target Chrome version.
///
/// ## Cross-Platform Consistency
/// The `sec-ch-ua-platform` and `sec-ch-ua-platform-version` values are
/// sourced from the active [`ChromeProfile`], ensuring they match the
/// OS persona declared during the TLS handshake.
///
/// ## HPACK Sensitivity
/// `cookie` and `authorization` headers are marked as sensitive to force
/// the HPACK encoder into "Literal Never Indexed" mode, preventing
/// side-channel leaks (CRIME mitigation).
pub fn inject_chrome_headers(
    headers: &mut HeaderMap,
    profile: &ChromeProfile,
    sec_fetch_site: &str,
    is_initial_navigation: bool,
) {
    // 1. Client Hints (Sec-CH-UA)
    // These headers provide granular version and platform information to the server.
    if let Ok(val) = HeaderValue::from_str(&profile.headers.sec_ch_ua) {
        headers.insert("sec-ch-ua", val);
    }
    headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
    if let Ok(val) = HeaderValue::from_str(&profile.headers.sec_ch_ua_platform) {
        headers.insert("sec-ch-ua-platform", val);
    }
    if let Ok(val) = HeaderValue::from_str(&profile.headers.sec_ch_ua_platform_version) {
        headers.insert("sec-ch-ua-platform-version", val);
    }

    // 2. Navigation / Fetch metadata
    headers.insert("upgrade-insecure-requests", HeaderValue::from_static("1"));
    if let Ok(val) = HeaderValue::from_str(&profile.headers.user_agent) {
        headers.insert(USER_AGENT, val);
    }

    // Exact Chrome 134 Accept string including avif, webp, and signed-exchange.
    headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"));

    // Inject dynamic sec-fetch-* state based on the current redirect context.
    if let Ok(val) = HeaderValue::from_str(sec_fetch_site) {
        headers.insert("sec-fetch-site", val);
    }
    headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));

    // The 'sec-fetch-user' header is present ONLY on the first hop of a user-initiated navigation.
    if is_initial_navigation {
        headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
    }

    headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));

    // 3. Compression & Language
    let encoding = if profile.headers.zstd_encoding {
        "gzip, deflate, br, zstd"
    } else {
        "gzip, deflate, br"
    };
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static(encoding));
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));

    // 4. Chrome Priority Header (u=0, i for navigations)
    if profile.headers.include_priority_header {
        headers.insert("priority", HeaderValue::from_static("u=0, i"));
    }

    // 5. HPACK "Never Index" (Sensitive) markers.
    // Chrome explicitly marks cookies and auth headers as sensitive. This forces
    // the HPACK encoder to use the "Literal Header Field Never Indexed" representation,
    // which prevents these values from entering the dynamic table (CRIME mitigation).
    for (name, value) in headers.iter_mut() {
        if name == "cookie" || name == "authorization" {
            value.set_sensitive(true);
        }
    }

    // TODO(agent): Intelligent `:path` indexing.
    // If the request path exceeds a certain entropy/length threshold (e.g., > 40 chars
    // for unique REST API IDs), we should flag the `:path` pseudo-header as sensitive
    // to prevent dynamic table bloat, matching Chrome's behavior. This requires a patch
    // in the upstream `0x676e67/http2` fork to support `no_index` on pseudo-headers.
}
