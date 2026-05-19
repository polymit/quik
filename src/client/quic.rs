use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use quiche::h3::NameValue;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, instrument, warn};

use crate::client::h3::configure_chrome_h3;
use crate::client::response::{Response, ResponseBody};
use crate::error::{Error, Result};
use crate::profile::ChromeProfile;

/// Modern Google Chrome-fingerprinted QUIC transport parameters (v148).
///
/// Under Chromium's QUIC implementation:
/// - **Max Idle Timeout (30000ms)**: Standard session teardown duration in the absence of traffic,
///   striking a balance between resource reclamation and session persistence.
/// - **UDP Payload Size (1472 bytes)**: The standard target payload limit for standard Ethernet
///   MTU (1500 bytes - 20 bytes IPv4 header - 8 bytes UDP header). Aligns perfectly with network path MTU.
/// - **Initial Max Data (15 MiB)**: Global flow control limit at connection level, ensuring high throughput
///   without early window exhaustion.
/// - **Stream Max Data Limits (6 MiB)**: Window allocations per stream, preventing receiver buffer starvation
///   during parallel page asset downloads.
/// - **Max Streams (100 Bidi / 103 Uni)**: Dictates concurrent stream limits, with 103 unidirectional streams
///   providing space for auxiliary control, telemetry, and dynamic push mechanisms.
///
/// ### Forensic Parity Notes (Chrome 148):
/// These specific parameters were extracted from live Chromium net-logs during active HTTP/3
/// sessions. Deviances in any of these constants (such as decreasing `initial_max_data` or reducing
/// stream allowances) alter the initial transport handshake parameter collection, creating signatures
/// that can be flagged by bot detection middleboxes (e.g. Cloudflare).
const CHROME_MAX_IDLE_TIMEOUT: u64 = 30000;
const CHROME_MAX_UDP_PAYLOAD_SIZE: usize = 1472;
const CHROME_INITIAL_MAX_DATA: u64 = 15728640;
const CHROME_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 6291456;
const CHROME_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 6291456;
const CHROME_INITIAL_MAX_STREAM_DATA_UNI: u64 = 6291456;
const CHROME_INITIAL_MAX_STREAMS_BIDI: u64 = 100;
const CHROME_INITIAL_MAX_STREAMS_UNI: u64 = 103;

/// Configures a `quiche::Config` instance with the absolute, bit-perfect QUIC
/// parameters advertised by Google Chrome v148.
///
/// ### Design Rationale & WAF Considerations:
/// In fingerprint-sensitive environments, edge gateways analyze connection-level QUIC parameters.
/// Slight deviations in flow control windows or stream counts instantly expose automated runtimes.
/// This configuration enforces:
/// - **ALPN Matching**: Enforces standard `h3` and `h3-29` to match Chrome's protocol negotiation list.
/// - **Active Migration (Enabled)**: Prevents link failures during connection migration (active migration is set to `false` for disable, meaning it is active).
/// - **Datagram Support**: Chrome advertises support for DATAGRAM frames (RFC 9297) for WebTransport
///   and media streaming. We match this footprint with a standard 65536 byte queue constraint.
pub fn configure_chrome_quic_transport() -> Result<quiche::Config> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|e| Error::Connect(std::io::Error::other(e.to_string())))?;

    // Match Chrome's exact protocol lists during TLS ALPN handshakes.
    config
        .set_application_protos(&[b"h3", b"h3-29"])
        .map_err(|e| Error::Connect(std::io::Error::other(e.to_string())))?;

    config.set_max_idle_timeout(CHROME_MAX_IDLE_TIMEOUT);
    config.set_max_recv_udp_payload_size(CHROME_MAX_UDP_PAYLOAD_SIZE);
    config.set_max_send_udp_payload_size(CHROME_MAX_UDP_PAYLOAD_SIZE);

    config.set_initial_max_data(CHROME_INITIAL_MAX_DATA);
    config.set_initial_max_stream_data_bidi_local(CHROME_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL);
    config.set_initial_max_stream_data_bidi_remote(CHROME_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE);
    config.set_initial_max_stream_data_uni(CHROME_INITIAL_MAX_STREAM_DATA_UNI);

    config.set_initial_max_streams_bidi(CHROME_INITIAL_MAX_STREAMS_BIDI);
    config.set_initial_max_streams_uni(CHROME_INITIAL_MAX_STREAMS_UNI);

    config.set_disable_active_migration(false);

    // Enforce Datagram parameters to match Chrome's wire identity.
    config.enable_dgram(true, 10, 10);
    config.discover_pmtu(true);

    Ok(config)
}

/// Represents an active request transmission handle backed by the UDP background driver.
///
/// This session abstraction wraps a message-passing channel to a continuous event loop driver.
/// Because `quiche`'s QUIC connection state machine is non-thread-safe and bound to borrowing constraints,
/// we execute the core transport loop on a dedicated async task, accessing it thread-safely
/// via message-passing channels. This completely avoids mutability borrow hazards across thread bounds.
#[derive(Clone)]
pub struct QuicSession {
    /// Transmits HTTP/3 commands to the event loop driver.
    pub tx: mpsc::Sender<QuicCommand>,
    /// Target profile persona.
    #[allow(dead_code)]
    pub profile: ChromeProfile,
}

impl QuicSession {
    /// Dispatches an HTTP/3 request over the dynamic UDP event loop driver.
    ///
    /// This method converts the request into the binary representation required by `quiche::h3`,
    /// including formatting the pseudo-headers in Chrome-identical sorting order, and transmits
    /// it to the background event loop driver, awaiting the response.
    pub async fn send(
        &self,
        request: http::Request<()>,
        body: Option<bytes::Bytes>,
    ) -> Result<Response> {
        let url_str = request.uri().to_string();
        let (response_tx, response_rx) = oneshot::channel();

        // Populate pseudo-headers first to ensure perfect browser compliance.
        // Chrome strictly structures pseudo-headers (:method, :scheme, :authority, :path) first.
        let mut request_headers = vec![
            quiche::h3::Header::new(b":method", request.method().as_str().as_bytes()),
            quiche::h3::Header::new(b":scheme", request.uri().scheme_str().unwrap_or("https").as_bytes()),
            quiche::h3::Header::new(
                b":authority",
                request
                    .uri()
                    .authority()
                    .map(|a| a.as_str())
                    .unwrap_or("")
                    .as_bytes(),
            ),
            quiche::h3::Header::new(
                b":path",
                request
                    .uri()
                    .path_and_query()
                    .map(|pq| pq.as_str())
                    .unwrap_or("/")
                    .as_bytes(),
            ),
        ];

        // Append custom request headers.
        for (name, val) in request.headers() {
            request_headers.push(quiche::h3::Header::new(
                name.as_str().as_bytes(),
                val.as_bytes(),
            ));
        }

        // Dispatch command to the background driver loop.
        self.tx
            .send(QuicCommand::SendRequest {
                headers: request_headers,
                body,
                url: url_str,
                response_tx,
            })
            .await
            .map_err(|e| Error::Connect(std::io::Error::other(e.to_string())))?;

        // Await the response from the background reader.
        response_rx
            .await
            .map_err(|e| Error::Connect(std::io::Error::other(e.to_string())))?
    }
}

/// Commands driving the connection thread-safely.
pub enum QuicCommand {
    /// Dispatches a multiplexed HTTP/3 stream.
    SendRequest {
        /// Ordered request headers.
        headers: Vec<quiche::h3::Header>,
        /// Optional body payload.
        body: Option<bytes::Bytes>,
        /// Requested URL context.
        url: String,
        /// Response delivery channel.
        response_tx: oneshot::Sender<Result<Response>>,
    },
}

/// Tracks the active stream transaction context.
struct PendingRequest {
    /// Status code of the response.
    status: Option<StatusCode>,
    /// Accumulated response headers.
    headers: HeaderMap,
    /// Accumulated body data.
    body: Vec<u8>,
    /// URL string for context.
    url: String,
    /// Sender handle to complete the oneshot caller.
    response_tx: oneshot::Sender<Result<Response>>,
}

/// Executes the core asynchronous UDP event loop driving the QUIC + H3 connection.
///
/// ### Core Loop Design Rationale:
/// - **Borrow-Checker Invariant**: The HTTP/3 connection (`quiche::h3::Connection`) must borrow
///   the raw QUIC connection (`quiche::Connection`) during operations. To satisfy this within
///   Rust's safety invariants, co-locating both structures within a single async loop task
///   ensures exclusive ownership.
/// - **Zero-Length Source Connection ID (Empty Client CID)**: Chrome uses zero-length CIDs for
///   outbound packets to optimize packet MTU overhead and prevent persistent edge tracking.
///   This loop processes packet routing using loopback/wildcard sockets aligned to the client CID.
/// - **Dynamic Pacing & Timers**: Calculates `conn.timeout()` dynamically to wake up the loop
///   via `tokio::time::sleep`, ensuring accurate protocol timer execution (e.g. idle timeout, ping, and loss recovery).
#[instrument(skip(socket, conn), fields(peer = %peer_addr))]
pub async fn run_quic_driver(
    socket: Arc<UdpSocket>,
    mut conn: quiche::Connection,
    peer_addr: SocketAddr,
    mut rx: mpsc::Receiver<QuicCommand>,
) {
    let mut recv_buf = [0u8; 65536];
    let mut send_buf = [0u8; 65536];

    let mut h3_conn: Option<quiche::h3::Connection> = None;
    let h3_config = match configure_chrome_h3() {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to build Chrome H3 configuration profile: {:?}", e);
            return;
        }
    };

    let mut pending_requests: HashMap<u64, PendingRequest> = HashMap::new();

    loop {
        if conn.is_closed() {
            info!("QUIC connection closed successfully, terminating event loop driver.");
            break;
        }

        // Flush outgoing packets buffered by the QUIC state machine.
        while let Ok((write_len, send_info)) = conn.send(&mut send_buf) {
            if let Err(e) = socket.send_to(&send_buf[..write_len], send_info.to).await {
                error!(
                    "Failed to dispatch UDP packet to peer {}: {:?}",
                    peer_addr, e
                );
                break;
            }
        }

        // Calculate standard timing ticks to drive background pacing.
        let next_timeout = conn.timeout().unwrap_or(Duration::from_millis(50));

        tokio::select! {
            // Process commands from caller sessions.
            Some(cmd) = rx.recv() => {
                match cmd {
                    QuicCommand::SendRequest { headers, body, url, response_tx } => {
                        let h3_conn_ref = match h3_conn.as_mut() {
                            Some(h3) => h3,
                            None => {
                                let _ = response_tx.send(Err(Error::Connect(std::io::Error::other(
                                    "HTTP/3 connection not yet established".to_string()
                                ))));
                                continue;
                            }
                        };

                        // Issue the HTTP/3 request frame.
                        let has_body = body.is_some();
                        match h3_conn_ref.send_request(&mut conn, &headers, !has_body) {
                            Ok(stream_id) => {
                                if let Some(body_data) = body {
                                    if let Err(e) = h3_conn_ref.send_body(&mut conn, stream_id, &body_data, true) {
                                        warn!("Failed to dispatch HTTP/3 request body: {:?}", e);
                                    }
                                }

                                pending_requests.insert(stream_id, PendingRequest {
                                    status: None,
                                    headers: HeaderMap::new(),
                                    body: Vec::new(),
                                    url,
                                    response_tx,
                                });
                            }
                            Err(e) => {
                                let _ = response_tx.send(Err(Error::Connect(std::io::Error::other(
                                    format!("Failed to issue HTTP/3 request: {:?}", e)
                                ))));
                            }
                        }
                    }
                }
            }

            // Await raw incoming packets.
            recv_res = socket.recv_from(&mut recv_buf) => {
                match recv_res {
                    Ok((read_len, src_addr)) => {
                        let recv_info = quiche::RecvInfo {
                            from: src_addr,
                            to: socket.local_addr().unwrap_or(src_addr),
                        };

                        if let Err(e) = conn.recv(&mut recv_buf[..read_len], recv_info) {
                            warn!("Failed to process incoming QUIC packet: {:?}", e);
                        }

                        // Initialize H3 layer immediately upon handshake completion.
                        if conn.is_established() && h3_conn.is_none() {
                            match quiche::h3::Connection::with_transport(&mut conn, &h3_config) {
                                Ok(h3) => {
                                    info!("HTTP/3 handshake unified cleanly over QUIC transport!");
                                    h3_conn = Some(h3);
                                }
                                Err(e) => {
                                    error!("Failed to instantiate HTTP/3 sub-transport session: {:?}", e);
                                    break;
                                }
                            }
                        }

                        // Poll H3 event frames dynamically and aggregate fields.
                        if let Some(h3) = h3_conn.as_mut() {
                            let mut scratch_buf = [0u8; 8192];

                            while let Ok((stream_id, event)) = h3.poll(&mut conn) {
                                match event {
                                    quiche::h3::Event::Headers { list, .. } => {
                                        if let Some(req) = pending_requests.get_mut(&stream_id) {
                                            for header in list {
                                                let name = header.name();
                                                let val = header.value();

                                                if name == b":status" {
                                                    if let Ok(status_str) = std::str::from_utf8(val) {
                                                        if let Ok(code) = status_str.parse::<u16>() {
                                                            if let Ok(status_code) = StatusCode::from_u16(code) {
                                                                req.status = Some(status_code);
                                                            }
                                                        }
                                                    }
                                                } else if let Ok(header_name) = HeaderName::from_bytes(name) {
                                                    if let Ok(header_val) = HeaderValue::from_bytes(val) {
                                                        req.headers.append(header_name, header_val);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    quiche::h3::Event::Data => {
                                        if let Some(req) = pending_requests.get_mut(&stream_id) {
                                            while let Ok(read_len) = h3.recv_body(&mut conn, stream_id, &mut scratch_buf) {
                                                if read_len == 0 {
                                                    break;
                                                }
                                                req.body.extend_from_slice(&scratch_buf[..read_len]);
                                            }
                                        }
                                    }
                                    quiche::h3::Event::Finished => {
                                        if let Some(req) = pending_requests.remove(&stream_id) {
                                            let status = req.status.unwrap_or(StatusCode::OK);
                                            let response = Response::new(
                                                status,
                                                req.headers,
                                                ResponseBody::Http3(req.body),
                                                req.url,
                                            );
                                            let _ = req.response_tx.send(Ok(response));
                                        }
                                    }
                                    quiche::h3::Event::Reset(err) => {
                                        if let Some(req) = pending_requests.remove(&stream_id) {
                                            let _ = req.response_tx.send(Err(Error::Connect(std::io::Error::other(
                                                format!("HTTP/3 stream reset by peer: error {}", err)
                                            ))));
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("UDP socket read failure: {:?}", e);
                    }
                }
            }

            // Tick timeouts to drive pacers.
            _ = tokio::time::sleep(next_timeout) => {
                conn.on_timeout();
            }
        }
    }
}
