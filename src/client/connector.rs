use bytes::Bytes;
use foreign_types::ForeignTypeRef;
use http2::client::SendRequest;
use std::net::SocketAddr;
use tokio::net::TcpStream;

use crate::client::proxy::{dial_proxy, Proxy};
use crate::client::response::Response;
use crate::error::Result;
use crate::http2::configure_builder;
use crate::profile::ChromeProfile;
use crate::tls::build_connector;

/// Establishes a new network connection following the Chrome transport pipeline.
///
/// This function orchestrates the full TLS + HTTP/2 handshake sequence,
/// injecting platform-specific ALPS data and ECH GREASE via raw BoringSSL
/// FFI calls. The resulting [`QuikConnection`] maintains the identity
/// established during the handshake for the lifetime of the session.
/// subsequent requests adhere to the same behavioral constraints (e.g.,
/// same SETTINGS, same window increments).
pub struct QuikConnection {
    /// The handle used to initiate new H2 streams.
    pub h2: SendRequest<Bytes>,
    /// The profile used for TLS and H2 handshake parity.
    pub profile: ChromeProfile,
}

/// Establishes a new network connection following the Chrome 134 transport pipeline.
///
/// This function orchestrates a multi-stage handshake to ensure the resulting
/// connection is indistinguishable from a real browser:
///
/// 1. **Proxy/TCP**: Dials the target host (optionally via a SOCKS5/HTTP tunnel).
/// 2. **TLS Handshake**: Performs a BoringSSL handshake with ClientHello permutation,
///    GREASE, and extension shuffling.
/// 3. **ALPS/ECH**: Injects per-connection application settings (ALPS) and ECH GREASE
///    via raw BoringSSL FFI calls.
/// 4. **H2 Handshake**: Negotiates the HTTP/2 session using a specialized builder that
///    replicates Chromium's SETTINGS frame order and connection window increments.
pub async fn connect(
    host: &str,
    port: u16,
    addr: SocketAddr,
    profile: &ChromeProfile,
    proxy: Option<&Proxy>,
) -> Result<QuikConnection> {
    // Stage 1: Establish raw TCP transport.
    let tcp = if let Some(p) = proxy {
        dial_proxy(p, host, port).await?
    } else {
        TcpStream::connect(addr).await?
    };

    // Stage 2: Configure the TLS connector.
    let connector = build_connector(&profile.tls)?;
    let mut config = connector.configure()?;

    // Request OCSP stapling to match Chrome's certificate verification behavior.
    config.set_status_type(boring::ssl::StatusType::OCSP)?;

    // Stage 3: Per-connection FFI for advanced Chrome features.
    let ssl_ptr = config.as_ptr();

    // Serializes the H2 SETTINGS into a raw ALPS payload.
    //
    // The base payload is 24 bytes (4 settings x 6 bytes each). On Windows
    // and Linux, `extra` adds one entry (setting 0x7A9A), extending the
    // payload to 30 bytes. macOS passes an empty slice, keeping it at 24.
    fn build_alps_payload(
        settings: &crate::profile::SettingsFrame,
        extra: &[(u16, u32)],
    ) -> Vec<u8> {
        let entry_count = 4 + extra.len();
        let mut payload = Vec::with_capacity(entry_count * 6);
        // Standard Chrome settings (IDs 1, 2, 4, 6).
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(&settings.header_table_size.to_be_bytes());
        payload.extend_from_slice(&2u16.to_be_bytes());
        payload.extend_from_slice(&(settings.enable_push as u32).to_be_bytes());
        payload.extend_from_slice(&4u16.to_be_bytes());
        payload.extend_from_slice(&settings.initial_window_size.to_be_bytes());
        payload.extend_from_slice(&6u16.to_be_bytes());
        payload.extend_from_slice(&settings.max_header_list_size.to_be_bytes());
        // OS-specific extra settings (e.g., 0x7A9A on Windows/Linux).
        for &(id, value) in extra {
            payload.extend_from_slice(&id.to_be_bytes());
            payload.extend_from_slice(&value.to_be_bytes());
        }
        payload
    }

    // SAFETY: The `ssl_ptr` is valid for the duration of the configuration phase.
    // We pass valid pointers for the ALPN protocol "h2" and the dynamically
    // built ALPS buffer. These calls are required because high-level Rust
    // wrappers do not yet expose the latest Chromium-specific BoringSSL features.
    unsafe {
        if profile.tls.enable_ech_grease {
            boring_sys::SSL_set_enable_ech_grease(ssl_ptr, 1);
        }
        if profile.tls.alps_enabled {
            let alps_data =
                build_alps_payload(&profile.h2.settings, profile.tls.alps_extra_settings);

            boring_sys::SSL_add_application_settings(
                ssl_ptr,
                b"h2".as_ptr(),
                2,
                alps_data.as_ptr(),
                alps_data.len(),
            );
        }
    }

    // Stage 4: TLS handshake.
    let tls_stream = tokio_boring::connect(config, host, tcp)
        .await
        .map_err(|e| {
            tracing::error!("TLS handshake failed: {:?}", e);
            e
        })?;

    // Stage 5: HTTP/2 handshake.
    let mut h2_builder = http2::client::Builder::new();
    configure_builder(&mut h2_builder, &profile.h2);

    let (h2, connection) = h2_builder.handshake(tls_stream).await?;

    // Drive the connection in the background. If this task terminates,
    // the H2 session is considered dead.
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::error!("HTTP/2 connection driver failed: {:?}", e);
        }
    });

    Ok(QuikConnection {
        h2,
        profile: profile.clone(),
    })
}

impl QuikConnection {
    /// Dispatches an HTTP request over the established H2 session.
    pub async fn send(
        &mut self,
        request: http::Request<()>,
        body: Option<Bytes>,
    ) -> Result<Response> {
        let url_str = request.uri().to_string();
        if let Some(data) = body {
            let (response_future, mut send_stream) = self.h2.send_request(request, false)?;
            send_stream.send_data(data, true)?;
            let response = response_future.await?;
            Ok(Response::new(response, url_str))
        } else {
            let (response_future, _) = self.h2.send_request(request, true)?;
            let response = response_future.await?;
            Ok(Response::new(response, url_str))
        }
    }
}
