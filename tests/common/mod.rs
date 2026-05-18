use boring::asn1::Asn1Time;
use boring::hash::MessageDigest;
use boring::pkey::PKey;
use boring::rsa::Rsa;
use boring::ssl::{SslAcceptor, SslMethod};
use boring::x509::X509;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

/// Generates a valid self-signed TLS certificate and private key at runtime.
///
/// This cryptographic utility leverages `BoringSSL`'s X509 API to generate a transient, 
/// short-lived self-signed certificate (`CN=127.0.0.1`) and a 2048-bit RSA key pair.
/// The output is used to bootstrap local HTTPS integration mock environments offline.
pub fn generate_self_signed_cert() -> (X509, PKey<boring::pkey::Private>) {
    // 1. Generate a premium 2048-bit RSA key pair.
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    // 2. Build the subject/issuer name mapping.
    let mut name = boring::x509::X509Name::builder().unwrap();
    name.append_entry_by_text("CN", "127.0.0.1").unwrap();
    let name = name.build();

    // 3. Construct the X509 certificate using standard metadata.
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();

    // 4. Set validity timestamps (0 to 365 days from now).
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();

    // 5. Sign the certificate using SHA-256 and the generated private key.
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let cert = builder.build();

    (cert, pkey)
}

/// A highly compliant TLS Mock Server running native HTTP/2 over TLS.
///
/// Under `http-quik` transport specifications, connections are strictly negotiated 
/// over TLS with advanced ALPN constraints. `TlsMockServer` implements a local
/// HTTP/2-over-TLS receiver to simulate high-fidelity network exchanges hermetically.
pub struct TlsMockServer {
    /// The local address the server TCP listener is bound to.
    pub addr: SocketAddr,
    /// The dynamic SSL/TLS context backing client connection handshakes.
    acceptor: Arc<SslAcceptor>,
    /// The underlying async TCP listener.
    listener: TcpListener,
}

#[allow(dead_code)]
impl TlsMockServer {
    /// Starts a new local `TlsMockServer` instance bound to a dynamic free port on 127.0.0.1.
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // 1. Generate local transient cryptographic identities.
        let (cert, pkey) = generate_self_signed_cert();
        
        // 2. Configure SslAcceptor with modern cryptographic guidelines (Mozilla Intermediate).
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor.set_private_key(&pkey).unwrap();
        acceptor.set_certificate(&cert).unwrap();

        // 3. Enforce HTTP/2 (`h2`) ALPN negotiation to establish stateful parity.
        acceptor.set_alpn_select_callback(|_, _| Ok(b"h2"));
        let acceptor = Arc::new(acceptor.build());

        Self {
            addr,
            acceptor,
            listener,
        }
    }

    /// Accepts a single inbound connection, performs the TLS + H2 server handshake, and yields the first request.
    ///
    /// The remaining lifespan of the HTTP/2 connection state machine is automatically
    /// driven to completion on a background task via the `PollClose` state driver.
    pub async fn handle_next_h2<F, Fut>(&self, handler: F) 
    where
        F: FnOnce(http::Request<http2::RecvStream>, http2::server::SendResponse<Bytes>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        // 1. Await next TCP connection and upgrade to TLS.
        let (socket, _) = self.listener.accept().await.unwrap();
        let ssl_stream = tokio_boring::accept(&self.acceptor, socket).await.unwrap();
        
        // 2. Perform HTTP/2 frame handshaking.
        let mut h2_conn = http2::server::handshake(ssl_stream).await.unwrap();
        if let Some(result) = h2_conn.accept().await {
            let (req, resp) = result.unwrap();

            // 3. Define a custom future wrapper to drive background polling of connection closure.
            struct PollClose(http2::server::Connection<tokio_boring::SslStream<tokio::net::TcpStream>, bytes::Bytes>);
            impl std::future::Future for PollClose {
                type Output = Result<(), http2::Error>;
                fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
                    self.0.poll_closed(cx)
                }
            }

            // 4. Drive the remaining lifetime of the connection on a dedicated background task.
            tokio::spawn(async move {
                let _ = PollClose(h2_conn).await;
            });
            
            // 5. Yield control back to the specific test scenario callback.
            handler(req, resp).await;
        }
    }

    /// Accepts an inbound connection, performs TLS + H2 server handshake, and handles multiple sequential multiplexed streams.
    ///
    /// This utility is highly useful for validating pooled/keep-alive behaviors (e.g. dynamic `Accept-CH` cache lookups)
    /// where multiple sequential requests reuse the exact same TCP/TLS session pipeline.
    pub async fn handle_next_h2_multi<F, Fut>(&self, num_streams: usize, mut handler: F) 
    where
        F: FnMut(http::Request<http2::RecvStream>, http2::server::SendResponse<Bytes>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        // 1. Await next TCP connection and upgrade to TLS.
        let (socket, _) = self.listener.accept().await.unwrap();
        let ssl_stream = tokio_boring::accept(&self.acceptor, socket).await.unwrap();
        
        // 2. Perform HTTP/2 frame handshaking.
        let mut h2_conn = http2::server::handshake(ssl_stream).await.unwrap();
        
        // 3. Process the exact number of streams sequentially over the multiplexed pipeline.
        for _ in 0..num_streams {
            if let Some(result) = h2_conn.accept().await {
                let (req, resp) = result.unwrap();
                handler(req, resp).await;
            }
        }

        // 4. Define connection-close future driver.
        struct PollClose(http2::server::Connection<tokio_boring::SslStream<tokio::net::TcpStream>, bytes::Bytes>);
        impl std::future::Future for PollClose {
            type Output = Result<(), http2::Error>;
            fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
                self.0.poll_closed(cx)
            }
        }

        // 5. Drive remaining H2 state frame pipelines in the background.
        tokio::spawn(async move {
            let _ = PollClose(h2_conn).await;
        });
    }
}
