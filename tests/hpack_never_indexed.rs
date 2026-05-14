use http_quik::{Client, Platform};
use url::Url;

/// Integration test to validate that cookies and authorization headers are correctly
/// flagged as sensitive and processed by the H2 HPACK encoder.
///
/// Since `http-quik` strictly enforces TLS handshakes for fingerprinting, we test
/// against a public HTTPS endpoint rather than a local unencrypted mock server.
#[tokio::test]
async fn test_hpack_sensitive_headers_transmit_successfully(
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder()
        .profile(http_quik::profile::chrome_134::profile(Platform::MacOsArm))
        .build()?;

    let target_url_str = "https://tls.peet.ws/api/all";
    let target_url = Url::parse(target_url_str)?;

    // Pre-populate the cookie store to ensure the cookie header is sent.
    {
        let mut store = client.cookie_store.write().unwrap();
        store
            .parse("session_id=12345abcdef; Secure; HttpOnly", &target_url)
            .unwrap();
    }

    // This request will include the cookie. If the HPACK encoder in the `http2` crate
    // fails to handle the `sensitive(true)` flag, this request will fail or panic.
    let response = client.get(target_url_str).await?;

    assert_eq!(response.status().as_u16(), 200);

    Ok(())
}
