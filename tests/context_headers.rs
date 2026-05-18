mod common;

use common::TlsMockServer;
use http_quik::{Client, Platform};

/// End-to-end integration test validating standard `Navigate` subresource header injection.
///
/// This test spins up our custom local H2-over-TLS `TlsMockServer` and makes a simulated
/// browser navigation request. It asserts that standard Chrome metadata headers
/// (`sec-fetch-dest: document`, `sec-fetch-mode: navigate`, `sec-fetch-user: ?1`,
/// `upgrade-insecure-requests: 1`, and standard `User-Agent` substrings) are correctly
/// injected onto the wire.
#[tokio::test]
async fn test_navigate_context_headers_over_tls_mock() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize local hermetic TLS Mock Server
    let server = TlsMockServer::start().await;
    let port = server.addr.port();

    // 2. Spawn the background TLS + H2 handler task to validate incoming request stream
    let server_handle = tokio::spawn(async move {
        server.handle_next_h2(|req, mut respond| async move {
            // Verify all high-fidelity Chrome Navigate markers on the intercepted request
            assert_eq!(req.headers().get("sec-fetch-dest").unwrap().to_str().unwrap(), "document");
            assert_eq!(req.headers().get("sec-fetch-mode").unwrap().to_str().unwrap(), "navigate");
            assert_eq!(req.headers().get("sec-fetch-user").unwrap().to_str().unwrap(), "?1");
            assert_eq!(req.headers().get("upgrade-insecure-requests").unwrap().to_str().unwrap(), "1");
            assert!(req.headers().get("user-agent").unwrap().to_str().unwrap().contains("Chrome"));

            // Respond with a standard empty HTTP/2 OK status (200) frame
            let response = http::Response::builder().status(200).body(()).unwrap();
            let _ = respond.send_response(response, true).unwrap();
        }).await;
    });

    // 3. Construct the client bypass-verifying our self-signed TLS certs
    let client = Client::builder()
        .profile(http_quik::profile::chrome_134::profile(Platform::LinuxX64))
        .danger_accept_invalid_certs(true)
        .build()?;

    // 4. Dispatch the mock navigation request
    let target_url = format!("https://127.0.0.1:{}/test", port);
    let response = client.get(&target_url).await?;

    // 5. Verify successful HTTP/2 transaction
    assert_eq!(response.status().as_u16(), 200);

    // 6. Join background task handler for raw assertion execution
    server_handle.await?;
    Ok(())
}
