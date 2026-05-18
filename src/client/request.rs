use crate::profile::ChromeProfile;
use http::header::{HeaderMap, HeaderValue, ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, USER_AGENT};

/// Defines the context of the network request, mimicking browser fetch metadata.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestContext {
    /// A top-level page navigation (e.g., clicking a link or typing in the URL bar).
    Navigate,
    /// An asynchronous XMLHttpRequest or Fetch API call.
    Xhr,
    /// A form submission navigation.
    Form,
    /// An iframe navigation.
    Iframe,
    /// A parser-blocking or async script subresource.
    NoCorsScript,
    /// A stylesheet subresource.
    NoCorsStyle,
    /// An image subresource.
    NoCorsImage,
    /// A font subresource.
    NoCorsFont,
    /// A media subresource.
    NoCorsMedia,
    /// A Web Worker script.
    Worker,
    /// A Service Worker script.
    ServiceWorker,
    /// A prefetch request.
    Prefetch,
}

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
    context: RequestContext,
    accept_ch: bool,
    referer: Option<&str>,
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
    // Chrome only sends platform-version if explicitly solicited via Accept-CH in previous responses.
    if accept_ch {
        if let Ok(val) = HeaderValue::from_str(&profile.headers.sec_ch_ua_platform_version) {
            headers.insert("sec-ch-ua-platform-version", val);
        }
    }

    // 2. Navigation / Fetch metadata
    headers.insert("upgrade-insecure-requests", HeaderValue::from_static("1"));
    if let Ok(val) = HeaderValue::from_str(&profile.headers.user_agent) {
        headers.insert(USER_AGENT, val);
    }

    // Inject dynamic sec-fetch-* state based on the current redirect context.
    if let Ok(val) = HeaderValue::from_str(sec_fetch_site) {
        headers.insert("sec-fetch-site", val);
    }
    let (mode, dest, accept_val) = match context {
        RequestContext::Navigate | RequestContext::Form => ("navigate", "document", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
        RequestContext::Iframe => ("navigate", "iframe", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
        RequestContext::Xhr => ("cors", "empty", "*/*"),
        RequestContext::NoCorsScript => ("no-cors", "script", "*/*"),
        RequestContext::NoCorsStyle => ("no-cors", "style", "text/css,*/*;q=0.1"),
        RequestContext::NoCorsImage => ("no-cors", "image", "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"),
        RequestContext::NoCorsFont => ("no-cors", "font", "*/*"),
        RequestContext::NoCorsMedia => ("no-cors", "video", "*/*"),
        RequestContext::Worker => ("same-origin", "worker", "*/*"),
        RequestContext::ServiceWorker => ("same-origin", "serviceworker", "*/*"),
        RequestContext::Prefetch => ("no-cors", "empty", "*/*"),
    };
    headers.insert(ACCEPT, HeaderValue::from_static(accept_val));
    headers.insert("sec-fetch-mode", HeaderValue::from_static(mode));

    // The 'sec-fetch-user' header is present ONLY on the first hop of a user-initiated navigation.
    if is_initial_navigation && (context == RequestContext::Navigate || context == RequestContext::Form || context == RequestContext::Iframe) {
        headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
    }

    headers.insert("sec-fetch-dest", HeaderValue::from_static(dest));

    if let Some(r) = referer {
        if let Ok(val) = HeaderValue::from_str(r) {
            headers.insert(http::header::REFERER, val);
        }
    }

    // 3. Compression & Language
    let encoding = if profile.headers.zstd_encoding {
        "gzip, deflate, br, zstd"
    } else {
        "gzip, deflate, br"
    };
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static(encoding));
    if let Ok(val) = HeaderValue::from_str(&profile.headers.accept_language) {
        headers.insert(ACCEPT_LANGUAGE, val);
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::chrome_134::chrome_134_windows_x64;

    /// Verifies correct mapping of various request contexts to standard Fetch Metadata headers.
    ///
    /// The mapping matches Chrome's behavioral matrix, ensuring that header fields like
    /// `sec-fetch-dest`, `sec-fetch-mode`, and `sec-fetch-user` are accurately set based on
    /// the context (e.g., Navigate, Xhr, NoCorsImage, ServiceWorker).
    #[test]
    fn test_inject_chrome_headers_context_mapping() {
        let profile = chrome_134_windows_x64();

        // Scenario 1: Navigation context (Navigate)
        // High-entropy platform hints should NOT be leaked unsolicited on the initial request.
        let mut headers = HeaderMap::new();
        inject_chrome_headers(&mut headers, &profile, "same-origin", true, RequestContext::Navigate, false, None);
        assert_eq!(headers.get("sec-fetch-dest").unwrap().to_str().unwrap(), "document");
        assert_eq!(headers.get("sec-fetch-mode").unwrap().to_str().unwrap(), "navigate");
        assert_eq!(headers.get("sec-fetch-user").unwrap().to_str().unwrap(), "?1");
        assert!(headers.get("sec-ch-ua-platform-version").is_none());

        // Scenario 2: Standard API request (Xhr)
        // Platform hints are present if solicited or configured statefully.
        let mut headers = HeaderMap::new();
        inject_chrome_headers(&mut headers, &profile, "cross-site", false, RequestContext::Xhr, true, None);
        assert_eq!(headers.get("sec-fetch-dest").unwrap().to_str().unwrap(), "empty");
        assert_eq!(headers.get("sec-fetch-mode").unwrap().to_str().unwrap(), "cors");
        assert!(headers.get("sec-fetch-user").is_none());
        assert_eq!(headers.get("sec-ch-ua-platform-version").unwrap().to_str().unwrap(), "\"15.0.0\""); // Windows 11 platform version with double quotes

        // Scenario 3: Image fetch (NoCorsImage)
        // Checks that the specific Accept header is set to Chrome's default image formats.
        let mut headers = HeaderMap::new();
        inject_chrome_headers(&mut headers, &profile, "same-site", false, RequestContext::NoCorsImage, false, None);
        assert_eq!(headers.get("sec-fetch-dest").unwrap().to_str().unwrap(), "image");
        assert_eq!(headers.get("sec-fetch-mode").unwrap().to_str().unwrap(), "no-cors");
        assert!(headers.get("accept").unwrap().to_str().unwrap().contains("image/avif"));

        // Scenario 4: Background script execution (ServiceWorker)
        // Tests that specific background process contexts map appropriately.
        let mut headers = HeaderMap::new();
        inject_chrome_headers(&mut headers, &profile, "same-origin", false, RequestContext::ServiceWorker, false, None);
        assert_eq!(headers.get("sec-fetch-dest").unwrap().to_str().unwrap(), "serviceworker");
        assert_eq!(headers.get("sec-fetch-mode").unwrap().to_str().unwrap(), "same-origin");
    }

    /// Verifies that sensitive authorization and session headers are explicitly marked.
    ///
    /// Marking headers like `cookie` and `authorization` as sensitive ensures they are
    /// flagged as "never indexed" in HTTP/2 HPACK compression context, defending against
    /// local/remote side-channel extraction attacks.
    #[test]
    fn test_inject_sensitive_headers_marked_properly() {
        let profile = chrome_134_windows_x64();
        let mut headers = HeaderMap::new();
        headers.insert("cookie", HeaderValue::from_static("session=123"));
        headers.insert("authorization", HeaderValue::from_static("Bearer token"));
        headers.insert("host", HeaderValue::from_static("example.com"));

        inject_chrome_headers(&mut headers, &profile, "none", true, RequestContext::Navigate, false, None);

        // Assert sensitive flags are strictly flipped to active
        assert!(headers.get("cookie").unwrap().is_sensitive());
        assert!(headers.get("authorization").unwrap().is_sensitive());
        
        // Non-sensitive transport headers must not be marked as sensitive
        assert!(!headers.get("host").unwrap().is_sensitive());
    }
}
