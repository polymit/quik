use http_quik::{connect, Platform};
use std::net::SocketAddr;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

/// Low-level cryptographical integration test verifying the TLS ClientHello header byte stream.
///
/// Rather than dialing external internet diagnostics endpoints (which can be flaky or offline),
/// this test binds a raw local `TcpListener` to intercept the client's initial handshake packet.
/// It parses the binary TLS record structure to assert the presence of valid TLS Handshake
/// encapsulation and ClientHello identifiers on the wire.
#[tokio::test]
async fn test_tls_client_hello_initiated_with_correct_header(
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Bind a local TCP listener on a dynamic free port
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let port = addr.port();

    // 2. Spawn a background task to accept the connection and read the raw ClientHello record bytes
    let server_handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 1024];
        let bytes_read = socket.read(&mut buf).await.unwrap();

        assert!(
            bytes_read > 5,
            "Client should have sent at least a TLS record header"
        );

        // Assert standard TLS Handshake record header:
        // Byte 0: Content Type (0x16 = Handshake record encapsulation)
        // Byte 1-2: Version (0x03 0x01 = TLS 1.0 or 0x03 0x03 = TLS 1.2 legacy compatibility record version)
        assert_eq!(buf[0], 0x16, "Must be a TLS Handshake record");
        assert_eq!(buf[1], 0x03, "Must match TLS version major");

        // Assert TLS Handshake message details:
        // Byte 5: Handshake Message Type (0x01 = ClientHello handshake message)
        assert_eq!(buf[5], 0x01, "Must be a ClientHello handshake message");
    });

    // 3. Connect a configured client to our local listener
    let profile = http_quik::profile::chrome_134::profile(Platform::LinuxX64);
    let socket_addr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        port,
    );

    // The connection will fail at the TLS handshake because the server reads but doesn't write back a ServerHello,
    // which is perfectly expected! We only want to verify the outbound ClientHello bytes.
    let _ = connect("127.0.0.1", port, socket_addr, &profile, None).await;

    // 4. Await the background parser assertions to complete
    server_handle.await?;

    Ok(())
}

/// Verifies that the Chrome 147 profile initiates a correct TLS ClientHello.
///
/// The test binds a raw local TCP listener, intercepts the initial handshake packet,
/// and parses the binary record structure to confirm valid TLS Handshake
/// encapsulation and ClientHello headers.
#[tokio::test]
async fn test_tls_client_hello_initiated_with_correct_header_chrome_147(
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Bind to a dynamic local port to receive the raw ClientHello byte stream
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let port = addr.port();

    // 2. Intercept the inbound bytes in a background task to avoid blocking the client dial
    let server_handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 1024];
        let bytes_read = socket.read(&mut buf).await.unwrap();

        assert!(
            bytes_read > 5,
            "Client should have sent at least a TLS record header"
        );

        // Assert standard TLS Handshake record header:
        // Byte 0: Content Type (0x16 = Handshake record encapsulation)
        // Byte 1-2: Version (0x03 0x01 = TLS 1.0 or 0x03 0x03 = TLS 1.2 legacy compatibility record version)
        assert_eq!(buf[0], 0x16, "Must be a TLS Handshake record");
        assert_eq!(buf[1], 0x03, "Must match TLS version major");

        // Assert TLS Handshake message details:
        // Byte 5: Handshake Message Type (0x01 = ClientHello handshake message)
        assert_eq!(buf[5], 0x01, "Must be a ClientHello handshake message");
    });

    // 3. Connect a configured client utilizing the Chrome 147 profile
    let profile = http_quik::profile::chrome_147::profile(Platform::LinuxX64);
    let socket_addr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        port,
    );

    // The connection will fail at the TLS handshake because the server reads but doesn't write back a ServerHello.
    // This is expected behavior; we only want to verify the outbound ClientHello bytes.
    let _ = connect("127.0.0.1", port, socket_addr, &profile, None).await;
    server_handle.await?;

    Ok(())
}
