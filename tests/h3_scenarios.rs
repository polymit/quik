mod common;

use common::TlsMockServer;
use http_quik::{Client, Platform};

/// Integration test validating stateful Alt-Svc caching, dual-stack routing, and TCP fallback.
///
/// ### Test Design and Systems Rationale:
/// Setting up automated end-to-end HTTP/3 integration testing inside virtualization/CI environments
/// is notoriously prone to race conditions, port conflicts, and firewall blocks.
/// Rather than running complex and flakey real UDP/QUIC mock servers, this test leverages a highly
/// robust, deterministic, offline/hermetic approach to validate the entire transport engine under fire:
///
/// 1. **Phase 1: Alt-Svc Solicitation**:
///    The client issues an initial request to a standard, compliant TLS/HTTP2 Mock Server `/solicit`.
///    The mock server emits a standard advertising header (`alt-svc: h3=":port"`).
///    The client interceptor successfully parses and registers this endpoint in its thread-safe `AltSvcCache`.
///
/// 2. **Phase 2: QUIC Dial Trigger**:
///    A second request is dispatched to `/fallback` on the same host. The client's pool detects
///    the active cache entry and initiates a real HTTP/3 dial. It binds a wildcard UDP socket
///    and connects it to the host address.
///
/// 3. **Phase 3: Real-World Transmission Failure**:
///    Since there is no UDP listener listening on that port, the initial QUIC packets are ignored or dropped.
///    The background driver detects that the handshake is not established, causing the request
///    transmission to fail.
///
/// 4. **Phase 4: Zero-Delay Multiplexed Fallback**:
///    The pool's state machine intercepts this H3 failure, evicts the origin entry from the `AltSvcCache`,
///    looks up the pooled connections for an active TCP/H2 session to preserve socket multiplexing,
///    re-uses that existing TCP pipe, and completes the request over H2 successfully.
///
/// 5. **Phase 5: Degradation Verification**:
///    Asserts that the response succeeded (status code 200) and that the cache was degraded and cleared,
///    guaranteeing that subsequent requests do not suffer connection delays.
#[tokio::test]
async fn test_alt_svc_caching_and_h2_fallback_flow() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize local hermetic TLS Mock Server.
    let server = TlsMockServer::start().await;
    let port = server.addr.port();

    // 2. Spawn the background TLS handler to process sequential streams on a single reused H2 connection.
    let server_handle = tokio::spawn(async move {
        server
            .handle_next_h2_multi(2, move |req, mut respond| async move {
                match req.uri().path() {
                    "/solicit" => {
                        // Respond with solicitation Alt-Svc header challenge.
                        let response = http::Response::builder()
                            .status(200)
                            .header("alt-svc", format!("h3=\":{}\"", port))
                            .body(())
                            .unwrap();
                        let _ = respond.send_response(response, true).unwrap();
                    }
                    "/fallback" => {
                        // Respond with 200 OK to finalize the fallback check.
                        let response = http::Response::builder().status(200).body(()).unwrap();
                        let _ = respond.send_response(response, true).unwrap();
                    }
                    _ => panic!("Unexpected request path: {}", req.uri().path()),
                }
            })
            .await;
    });

    // 3. Construct the client bypass-verifying our self-signed TLS certs under Windows profile.
    let client = Client::builder()
        .profile(http_quik::profile::chrome_134::profile(
            Platform::WindowsX64,
        ))
        .danger_accept_invalid_certs(true)
        .build()?;

    // 4. Dispatch the first request to solicit Alt-Svc.
    let solicit_url = format!("https://127.0.0.1:{}/solicit", port);
    let resp1 = client.get(&solicit_url).await?;
    assert_eq!(resp1.status(), 200);

    // 5. Verify the client statefully cached the Alt-Svc advertisement.
    let origin_key = format!("127.0.0.1:{}", port);
    assert!(client.alt_svc_cache.get(&origin_key).is_some());

    // 6. Dispatch the second request (triggers UDP H3 dial, fails, statefully falls back to H2/TCP).
    let fallback_url = format!("https://127.0.0.1:{}/fallback", port);
    let resp2 = client.get(&fallback_url).await?;
    assert_eq!(resp2.status(), 200);

    // 7. Verify the Alt-Svc cache degraded and removed the failed origin entry.
    assert!(client.alt_svc_cache.get(&origin_key).is_none());

    // 8. Join background task handler for raw assertion execution.
    server_handle.await?;
    Ok(())
}
