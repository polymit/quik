mod common;

use common::TlsMockServer;
use http_quik::{Client, Platform};

/// Integration test validating strict-origin-when-cross-origin referer stripping.
///
/// This test verifies that during cross-site hops (simulated by redirecting from loopback IP
/// `127.0.0.1` to hostname `localhost`), `http-quik` correctly strips the referrer down to the
/// root origin (e.g. `https://127.0.0.1:<port>/`), stripping out path and query parameters
/// to avoid leaking sensitive information on the wire.
#[tokio::test]
async fn test_redirect_referer_policy_stripping_tls() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize local hermetic TLS Mock Server (bound to [::]:0 for dual-stack support)
    let server = TlsMockServer::start().await;
    let port = server.addr.port();

    // 2. Spawn the background TLS handler to process the redirect chain sequentially
    let server_handle = tokio::spawn(async move {
        // Hop 1: /source
        server
            .handle_next_h2(move |req, mut respond| async move {
                assert_eq!(req.uri().path(), "/source");

                // Redirect to target on 'localhost' (cross-origin boundary to trigger stripping)
                let redirect_location = format!("https://localhost:{}/target?secret=123", port);
                let response = http::Response::builder()
                    .status(302)
                    .header("Location", redirect_location)
                    .body(())
                    .unwrap();
                let _ = respond.send_response(response, true).unwrap();
            })
            .await;

        // Hop 2: /target (cross-origin referer header must be stripped to origin)
        server
            .handle_next_h2(move |req, mut respond| async move {
                assert_eq!(req.uri().path(), "/target");

                // Verify that the referer is stripped to root origin
                let referer = req.headers().get("referer").unwrap().to_str().unwrap();
                let expected_referer = format!("https://127.0.0.1:{}/", port);

                assert_eq!(referer, expected_referer);

                // Respond with 200 OK to complete the chain
                let response = http::Response::builder().status(200).body(()).unwrap();
                let _ = respond.send_response(response, true).unwrap();
            })
            .await;
    });

    // 3. Construct client bypass-verifying our self-signed TLS certs
    let client = Client::builder()
        .profile(http_quik::profile::chrome_134::profile(Platform::LinuxX64))
        .danger_accept_invalid_certs(true)
        .build()?;

    // 4. Dial the source endpoint using IPv4 address explicitly
    let target_url = format!("https://127.0.0.1:{}/source", port);
    let response = client.get(&target_url).await?;

    // 5. Assert successful redirect traversal
    assert_eq!(response.status().as_u16(), 200);

    // 6. Join background task handler for raw assertion execution
    server_handle.await?;
    Ok(())
}
