mod common;

use common::TlsMockServer;
use http_quik::{Client, Platform};

/// Integration test validating stateful `Accept-CH` (Client Hint) dynamic solicitation flow.
///
/// This test executes two sequential streams over a single multiplexed H2/TLS session:
/// 1. Stream 1 (/challenge): The client sends a request. The server verifies that no unsolicited
///    high-entropy hints (specifically `sec-ch-ua-platform-version`) are leaked, then responds
///    with `Accept-CH: sec-ch-ua-platform-version` to solicit the hint.
/// 2. Stream 2 (/resource): The client sends a second request. The server verifies that the client
///    statefully cached the solicitation challenge and correctly emitted the Windows 11 platform
///    version hint (`"15.0.0"`) inside double quotes.
#[tokio::test]
async fn test_accept_ch_dynamic_solicitation_flow_tls() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize local hermetic TLS Mock Server
    let server = TlsMockServer::start().await;
    let port = server.addr.port();

    // 2. Spawn the background TLS handler to process sequential streams on a single reused H2 connection
    let server_handle = tokio::spawn(async move {
        server
            .handle_next_h2_multi(2, move |req, mut respond| async move {
                match req.uri().path() {
                    "/challenge" => {
                        // Expect that client hints are NOT leaked unsolicited on first request
                        assert!(req.headers().get("sec-ch-ua-platform-version").is_none());

                        // Respond with solicitation header challenge
                        let response = http::Response::builder()
                            .status(200)
                            .header("Accept-CH", "sec-ch-ua-platform-version")
                            .body(())
                            .unwrap();
                        let _ = respond.send_response(response, true).unwrap();
                    }
                    "/resource" => {
                        // Assert that the client successfully parsed, cached, and sent the requested hint
                        let platform_version = req
                            .headers()
                            .get("sec-ch-ua-platform-version")
                            .unwrap()
                            .to_str()
                            .unwrap();
                        assert_eq!(platform_version, "\"15.0.0\"");

                        // Respond with 200 OK to finalize
                        let response = http::Response::builder().status(200).body(()).unwrap();
                        let _ = respond.send_response(response, true).unwrap();
                    }
                    _ => panic!("Unexpected request path: {}", req.uri().path()),
                }
            })
            .await;
    });

    // 3. Construct the client bypass-verifying our self-signed TLS certs under Windows profile
    let client = Client::builder()
        .profile(http_quik::profile::chrome_134::profile(
            Platform::WindowsX64,
        ))
        .danger_accept_invalid_certs(true)
        .build()?;

    // 4. Dispatch the first challenge request
    let challenge_url = format!("https://127.0.0.1:{}/challenge", port);
    let _ = client.get(&challenge_url).await?;

    // 5. Dispatch the second resource request (uses same pooled H2 connection and asserts cached hint injection)
    let resource_url = format!("https://127.0.0.1:{}/resource", port);
    let _ = client.get(&resource_url).await?;

    // 6. Join background task handler for raw assertion execution
    server_handle.await?;
    Ok(())
}
