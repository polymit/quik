use bytes::Bytes;
use cookie_store::CookieStore;
use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex, RwLock};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use url::Url;

use crate::client::connector::{connect, QuikConnection};
use crate::client::proxy::Proxy;
use crate::client::quic::QuicSession;
use crate::client::request::{inject_chrome_headers, RequestContext};
use crate::client::response::Response;
use crate::error::{Error, Result};
use crate::profile::ChromeProfile;

/// Thread-safe registry for dynamically discovered HTTP/3 Alt-Svc advertisements.
///
/// Under RFC 9114, origins advertise QUIC support via the `Alt-Svc` HTTP header. 
/// This cache records valid `h3` mappings to preemptively bypass TCP and TLS handshakes 
/// on subsequent requests to the same origin, establishing QUIC connections directly.
///
/// The cache employs a reader-writer lock design to eliminate contention on the hot path.
/// Reads (origin lookups) are wait-free under shared locks, while exclusive locks are 
/// strictly reserved for initial discovery or deterministic eviction during network drops.
#[derive(Clone)]
pub struct AltSvcCache {
    entries: Arc<RwLock<HashMap<String, String>>>,
}

impl AltSvcCache {
    /// Instantiates a new thread-safe in-memory cache.
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Retrieves cached H3 signals for a target origin string.
    pub fn get(&self, origin: &str) -> Option<String> {
        let guard = self.entries.read().ok()?;
        guard.get(origin).cloned()
    }

    /// Stores/updates an Alt-Svc advertisement.
    pub fn insert(&self, origin: String, alt_svc: String) {
        if let Ok(mut guard) = self.entries.write() {
            guard.insert(origin, alt_svc);
        }
    }

    /// Evicts an origin from the cache to trigger protocol fallback.
    ///
    /// Used defensively when a QUIC handshake fails or a middlebox silently drops
    /// UDP packets. Eviction ensures that subsequent requests to the affected origin 
    /// are deterministically routed over HTTP/2 and TCP, maintaining connectivity 
    /// on restrictive networks.
    pub fn remove(&self, origin: &str) {
        if let Ok(mut guard) = self.entries.write() {
            guard.remove(origin);
        }
    }
}

/// An abstract representation of an active, multiplexed connection session.
///
/// This enum enforces strict transport decoupling. The request runner interacts 
/// exclusively with the polymorphic `send` interface, completely abstracting whether 
/// the underlying byte stream is multiplexed over HTTP/2 (TCP/TLS) or HTTP/3 (UDP/QUIC).
/// It ensures connection lifecycles and multiplexing limits are handled seamlessly 
/// behind a unified boundary.
#[derive(Clone)]
pub enum PooledConnection {
    /// Persistent HTTP/2 multiplexed TCP/TLS transport.
    Http2(QuikConnection),
    /// Stealth HTTP/3 multiplexed UDP/QUIC transport.
    Http3(QuicSession),
}

impl PooledConnection {
    /// Dispatches an HTTP request over the active session.
    pub async fn send(
        &mut self,
        request: http::Request<()>,
        body: Option<Bytes>,
    ) -> Result<Response> {
        match self {
            PooledConnection::Http2(conn) => conn.send(request, body).await,
            PooledConnection::Http3(conn) => conn.send(request, body).await,
        }
    }
}

type SharedConnection = Arc<tokio::sync::Mutex<Option<PooledConnection>>>;
type ConnectionPool = Arc<Mutex<HashMap<String, SharedConnection>>>;

/// A stateful HTTP client engine enforcing deterministic Chrome identity parity.
///
/// The `Client` is the primary interface for managing cross-origin requests. It maintains 
/// global state across its clones, enabling shared connection pooling and cookie persistence. 
/// Key operational guarantees include:
/// 
/// - **Transport Decoupling**: Transparently routes requests over H2 or H3 based on cache states.
/// - **Connection Pooling**: Reuses established multiplexed streams isolated by proxy and origin.
/// - **Automated State Tracking**: Synchronizes cookies, redirects, and client-hints seamlessly.
#[derive(Clone)]
pub struct Client {
    /// A synchronized hash map of active connections, strictly keyed by protocol, proxy, and origin.
    pool: ConnectionPool,
    /// The canonical identity profile governing TLS handshakes, H2 parameters, and HTTP metadata.
    profile: ChromeProfile,
    /// An optional proxy route applied uniformly to all outbound connections from this client.
    proxy: Option<Proxy>,
    /// A synchronized cookie jar enforcing RFC 6265 storage and cross-request persistence.
    pub cookie_store: Arc<RwLock<CookieStore>>,
    /// A cache tracking origins that explicitly solicited dynamic client hints (e.g. `Accept-CH`).
    pub hint_cache: Arc<RwLock<HashSet<String>>>,
    /// Thread-safe registry mapping origins to discovered `Alt-Svc` UDP/QUIC endpoints.
    pub alt_svc_cache: AltSvcCache,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// Creates a new `Client` with a Chrome profile auto-matched to the host OS.
    pub fn new() -> Self {
        Self::builder().build().unwrap_or_else(|_| Client {
            pool: Arc::new(Mutex::new(HashMap::new())),
            profile: crate::profile::chrome_134::profile_auto(),
            proxy: None,
            cookie_store: Arc::new(RwLock::new(CookieStore::default())),
            hint_cache: Arc::new(RwLock::new(HashSet::new())),
            alt_svc_cache: AltSvcCache::new(),
        })
    }

    /// Returns a [`ClientBuilder`] to configure a specialized `Client` instance.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// Executes a GET request and follows redirects stealthily.
    pub async fn get(&self, url: &str) -> Result<Response> {
        self.execute_with_redirects("GET", url, None, RequestContext::Navigate)
            .await
    }

    /// Executes a POST request and follows redirects stealthily.
    pub async fn post(&self, url: &str, body: Bytes) -> Result<Response> {
        self.execute_with_redirects("POST", url, Some(body), RequestContext::Navigate)
            .await
    }

    /// Executes the primary request lifecycle, including automated redirect evaluation 
    /// and dual-stack protocol fallback.
    ///
    /// ### Connection Acquisition and Fallback Topology
    /// 1. **Routing Phase**: Evaluates `AltSvcCache` to select the target transport (H2 vs H3).
    /// 2. **Lock Serialization**: Acquires an origin-specific async mutex to prevent connection 
    ///    storming when multiple tasks simultaneously fault on a new origin.
    /// 3. **Graceful Degradation**: If an active HTTP/3 dial fails or a request drops mid-flight 
    ///    due to UDP restrictions, the engine instantly evicts the Alt-Svc mapping and 
    ///    transparently fails over to HTTP/2 over TCP with zero user-visible latency.
    /// 
    /// Implements a strict limit of 10 redirects to prevent cyclical loops, applying 
    /// RFC 7231 method rotation and Chrome-parity cross-site referer truncation on each hop.
    async fn execute_with_redirects(
        &self,
        initial_method: &str,
        initial_url: &str,
        initial_body: Option<Bytes>,
        context: RequestContext,
    ) -> Result<Response> {
        let mut current_url_str = initial_url.to_string();
        let mut current_method = initial_method.to_string();
        let mut current_body = initial_body;
        let mut previous_url_str: Option<String> = None;

        let mut sec_fetch_site = "none".to_string();
        let mut is_cross_site = false;

        for hop in 0..10 {
            let parsed_url =
                Url::parse(&current_url_str).map_err(|e| Error::InvalidUrl(e.to_string()))?;
            let authority = parsed_url
                .host_str()
                .ok_or_else(|| Error::InvalidUrl("missing host".to_string()))?;
            let port = parsed_url.port().unwrap_or_else(|| {
                if parsed_url.scheme() == "http" {
                    80
                } else {
                    443
                }
            });

            // Isolate connection pools by proxy to prevent credential leakage or route mismatches.
            let proxy_prefix = self
                .proxy
                .as_ref()
                .map(|p| match p {
                    Proxy::Http(a) => format!("http://{}@", a),
                    Proxy::Socks5(a) => format!("socks5://{}@", a),
                })
                .unwrap_or_default();

            // Differentiate H2 and H3 keys to isolate TCP and UDP multiplexers.
            let origin_key = format!("{}:{}", authority, port);
            let mut has_alt_svc = self.alt_svc_cache.get(&origin_key).is_some();
            let transport_proto = if has_alt_svc { "h3" } else { "h2" };
            let pool_key = format!("{}{}:{}#{}", proxy_prefix, authority, port, transport_proto);

            // Extract cookies matched to the target domain.
            let cookie_header = {
                let store = self
                    .cookie_store
                    .read()
                    .map_err(|_| Error::Connect(std::io::Error::other("cookie store poisoned")))?;
                let cookies: Vec<_> = store
                    .matches(&parsed_url)
                    .iter()
                    .map(|c| format!("{}={}", c.name(), c.value()))
                    .collect();
                if cookies.is_empty() {
                    None
                } else {
                    Some(cookies.join("; "))
                }
            };

            // Injects Chrome-identical headers.
            let is_initial = hop == 0;
            let accept_ch = {
                let cache = self.hint_cache.read().unwrap();
                cache.contains(&parsed_url.origin().ascii_serialization())
            };

            // Strict-origin-when-cross-origin referer propagation.
            let referer_to_send = previous_url_str.as_ref().map(|prev| {
                if is_cross_site {
                    if let Ok(prev_url) = Url::parse(prev) {
                        return prev_url.origin().ascii_serialization() + "/";
                    }
                }
                prev.clone()
            });

            // Use an async Mutex per pool key to serialize connection establishment.
            // This prevents connection storms when making parallel requests to a new origin.
            let conn_mutex = {
                let mut pool = self.pool.lock().map_err(|_| {
                    Error::Connect(std::io::Error::other("connection pool poisoned"))
                })?;
                pool.entry(pool_key.clone())
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(None)))
                    .clone()
            };

            let mut pooled_client = loop {
                let conn_opt = {
                    let guard = conn_mutex.lock().await;
                    guard.as_ref().cloned()
                };

                if let Some(c) = conn_opt {
                    match c {
                        PooledConnection::Http2(mut conn) => {
                            // Rebuild the TCP stream if the socket was closed or encountered a TLS error.
                            match conn.h2.ready().await {
                                Ok(h2) => {
                                    conn.h2 = h2;
                                    break PooledConnection::Http2(conn);
                                }
                                Err(_) => {
                                    let mut guard = conn_mutex.lock().await;
                                    *guard = None;
                                }
                            }
                        }
                        PooledConnection::Http3(conn) => {
                            // HTTP/3 runs continuously via the background UDP worker task.
                            // Handshake and channel timeouts are handled internally by the driver.
                            break PooledConnection::Http3(conn);
                        }
                    }
                } else {
                    let mut guard = conn_mutex.lock().await;
                    if guard.is_none() {
                        // Dial either UDP/QUIC (H3) or TCP/TLS (H2) based on the target protocols.
                        match self.dial(authority, port, has_alt_svc, &self.profile).await {
                            Ok(new_conn) => {
                                *guard = Some(new_conn.clone());
                                break new_conn;
                            }
                            Err(e) => {
                                if has_alt_svc {
                                    // Fallback: UDP dial blocked. Evict from cache and retry over H2.
                                    tracing::warn!("HTTP/3 dial to {} failed ({:?}); falling back to HTTP/2/TCP.", origin_key, e);
                                    self.alt_svc_cache.remove(&origin_key);
                                    has_alt_svc = false;

                                    // Build H2 pool key and resolve.
                                    let h2_pool_key =
                                        format!("{}{}:{}#h2", proxy_prefix, authority, port);
                                    let h2_conn_mutex = {
                                        let mut pool = self.pool.lock().map_err(|_| {
                                            Error::Connect(std::io::Error::other(
                                                "connection pool poisoned",
                                            ))
                                        })?;
                                        pool.entry(h2_pool_key)
                                            .or_insert_with(|| {
                                                Arc::new(tokio::sync::Mutex::new(None))
                                            })
                                            .clone()
                                    };

                                    let mut h2_guard = h2_conn_mutex.lock().await;
                                    if h2_guard.is_none() {
                                        let h2_conn = self
                                            .dial(authority, port, false, &self.profile)
                                            .await?;
                                        *h2_guard = Some(h2_conn.clone());
                                        break h2_conn;
                                    } else {
                                        break h2_guard.as_ref().unwrap().clone();
                                    }
                                } else {
                                    return Err(e);
                                }
                            }
                        }
                    }
                }
            };

            // Build request dynamically for outbound session sending.
            let mut request = http::Request::builder()
                .method(current_method.as_str())
                .uri(parsed_url.as_str())
                .body(())
                .map_err(|e| Error::InvalidUrl(e.to_string()))?;

            if let Some(c) = cookie_header.as_deref() {
                if let Ok(val) = http::header::HeaderValue::from_str(c) {
                    request.headers_mut().insert("cookie", val);
                }
            }

            if current_method == "POST" || current_method == "PUT" || current_method == "PATCH" {
                if let Ok(val) =
                    http::header::HeaderValue::from_str(&parsed_url.origin().ascii_serialization())
                {
                    request.headers_mut().insert("origin", val);
                }
            }

            inject_chrome_headers(
                request.headers_mut(),
                &self.profile,
                &sec_fetch_site,
                is_initial,
                context,
                accept_ch,
                referer_to_send.as_deref(),
            );

            // Transmit request. If H3 fails mid-flight (e.g. silent UDP drop), evict and retry over H2.
            let mut response = match pooled_client.send(request, current_body.clone()).await {
                Ok(resp) => resp,
                Err(e) => {
                    if let PooledConnection::Http3(_) = pooled_client {
                        tracing::warn!("HTTP/3 request transmission failed ({:?}); falling back to HTTP/2/TCP.", e);
                        self.alt_svc_cache.remove(&origin_key);

                        // Check for an existing H2 connection to preserve multiplexing and avoid handshakes.
                        let h2_pool_key = format!("{}{}:{}#h2", proxy_prefix, authority, port);
                        let h2_conn_mutex = {
                            let mut pool = self.pool.lock().map_err(|_| {
                                Error::Connect(std::io::Error::other("connection pool poisoned"))
                            })?;
                            pool.entry(h2_pool_key)
                                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(None)))
                                .clone()
                        };

                        let mut h2_guard = h2_conn_mutex.lock().await;
                        let h2_conn = if let Some(PooledConnection::Http2(mut conn)) =
                            h2_guard.as_ref().cloned()
                        {
                            match conn.h2.ready().await {
                                Ok(h2) => {
                                    conn.h2 = h2;
                                    *h2_guard = Some(PooledConnection::Http2(conn.clone()));
                                    PooledConnection::Http2(conn)
                                }
                                Err(_) => {
                                    let new_conn =
                                        self.dial(authority, port, false, &self.profile).await?;
                                    *h2_guard = Some(new_conn.clone());
                                    new_conn
                                }
                            }
                        } else {
                            let new_conn = self.dial(authority, port, false, &self.profile).await?;
                            *h2_guard = Some(new_conn.clone());
                            new_conn
                        };

                        // Rebuild request for H2 transmission.
                        let mut fallback_request = http::Request::builder()
                            .method(current_method.as_str())
                            .uri(parsed_url.as_str())
                            .body(())
                            .map_err(|e| Error::InvalidUrl(e.to_string()))?;

                        if let Some(c) = cookie_header.as_deref() {
                            if let Ok(val) = http::header::HeaderValue::from_str(c) {
                                fallback_request.headers_mut().insert("cookie", val);
                            }
                        }
                        if current_method == "POST"
                            || current_method == "PUT"
                            || current_method == "PATCH"
                        {
                            if let Ok(val) = http::header::HeaderValue::from_str(
                                &parsed_url.origin().ascii_serialization(),
                            ) {
                                fallback_request.headers_mut().insert("origin", val);
                            }
                        }

                        inject_chrome_headers(
                            fallback_request.headers_mut(),
                            &self.profile,
                            &sec_fetch_site,
                            is_initial,
                            context,
                            accept_ch,
                            referer_to_send.as_deref(),
                        );

                        let mut h2_pooled = h2_conn;
                        h2_pooled
                            .send(fallback_request, current_body.clone())
                            .await?
                    } else {
                        return Err(e);
                    }
                }
            };

            // Store cookie, hints, and Alt-Svc headers from response.
            self.store_cookies(&response, &parsed_url);
            self.store_hints(&response, &parsed_url);
            self.store_alt_svc(&response, &parsed_url);

            let status = response.status();
            if status.is_redirection() {
                if let Some(location) = response.headers().get("location") {
                    let loc_str = location.to_str().unwrap_or("");
                    let next_url = parsed_url
                        .join(loc_str)
                        .map_err(|e| Error::InvalidUrl(e.to_string()))?;

                    // Rotate method to GET on 301/302/303 per RFC 7231 §6.4.
                    if status == http::StatusCode::MOVED_PERMANENTLY
                        || status == http::StatusCode::FOUND
                        || status == http::StatusCode::SEE_OTHER
                    {
                        current_method = "GET".to_string();
                        current_body = None;
                    }

                    if !is_cross_site {
                        if next_url.origin() == parsed_url.origin() {
                            sec_fetch_site = "same-origin".to_string();
                        } else if next_url.domain() == parsed_url.domain() {
                            sec_fetch_site = "same-site".to_string();
                        } else {
                            sec_fetch_site = "cross-site".to_string();
                            is_cross_site = true;
                        }
                    }

                    previous_url_str = Some(current_url_str);
                    current_url_str = next_url.to_string();
                    continue;
                }
            }

            response.set_url(current_url_str);
            return Ok(response);
        }

        Err(Error::Connect(std::io::Error::other(
            "Redirect limit exceeded (max 10)",
        )))
    }

    /// Initializes a network socket and negotiates the underlying protocol stream.
    ///
    /// ### Protocol Dispatch
    /// - **HTTP/3 (`dial_h3 = true`)**: Resolves the target via DNS, binds an ephemeral 
    ///   IPv4/IPv6 wildcard UDP socket, and delegates stream handling to a background 
    ///   `QuicSession` worker. Emits Chrome's zero-length connection ID signature.
    /// - **HTTP/2 (`dial_h3 = false`)**: Establishes a standard TCP connection, negotiating 
    ///   TLS 1.3 with ALPN strictly constrained to `h2` and HTTP/1.1 fallbacks.
    async fn dial(
        &self,
        authority: &str,
        port: u16,
        dial_h3: bool,
        profile: &ChromeProfile,
    ) -> Result<PooledConnection> {
        if dial_h3 {
            let addr_str = format!("{}:{}", authority, port);
            let addr = addr_str.to_socket_addrs()?.next().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "could not resolve host")
            })?;

            // Setup dual-stack loopback or wildcard listener.
            let local_addr: SocketAddr = if addr.is_ipv6() {
                "[::]:0".parse().unwrap()
            } else {
                "0.0.0.0:0".parse().unwrap()
            };

            let socket = UdpSocket::bind(local_addr).await?;
            socket.connect(addr).await?;

            let mut config = crate::client::quic::configure_chrome_quic_transport()?;
            if !profile.tls.verify_peer {
                config.verify_peer(false);
            }

            // Bind zero-length CID to match Chrome wire identity.
            let scid = quiche::ConnectionId::from_ref(&[]);
            let conn = quiche::connect(Some(authority), &scid, local_addr, addr, &mut config)
                .map_err(|e| Error::Connect(std::io::Error::other(e.to_string())))?;

            let (cmd_tx, cmd_rx) = mpsc::channel(100);
            let socket_arc = Arc::new(socket);

            tokio::spawn(crate::client::quic::run_quic_driver(
                socket_arc, conn, addr, cmd_rx,
            ));

            Ok(PooledConnection::Http3(QuicSession {
                tx: cmd_tx,
                profile: profile.clone(),
            }))
        } else {
            let addr_str = format!("{}:{}", authority, port);
            let addr = addr_str.to_socket_addrs()?.next().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "could not resolve host")
            })?;

            let conn = connect(authority, port, addr, profile, self.proxy.as_ref()).await?;
            Ok(PooledConnection::Http2(conn))
        }
    }

    /// Persists `Set-Cookie` headers from a response into the synchronized cookie store.
    fn store_cookies(&self, resp: &Response, url: &Url) {
        if let Ok(mut store) = self.cookie_store.write() {
            for v in resp.headers().get_all("set-cookie").iter() {
                if let Ok(cookie_str) = v.to_str() {
                    let _ = store.parse(cookie_str, url);
                }
            }
        }
    }

    /// Caches `Accept-CH` headers explicitly requested by the server.
    fn store_hints(&self, resp: &Response, url: &Url) {
        if let Some(accept_ch) = resp.headers().get("accept-ch") {
            if let Ok(ch_str) = accept_ch.to_str() {
                if ch_str.to_lowercase().contains("sec-ch-ua-platform-version") {
                    if let Ok(mut cache) = self.hint_cache.write() {
                        cache.insert(url.origin().ascii_serialization());
                    }
                }
            }
        }
    }

    /// Caches server Alt-Svc headers.
    fn store_alt_svc(&self, resp: &Response, url: &Url) {
        if let Some(alt_svc) = resp.headers().get("alt-svc") {
            if let Ok(alt_str) = alt_svc.to_str() {
                if alt_str.contains("h3") {
                    let origin_key = format!(
                        "{}:{}",
                        url.host_str().unwrap_or(""),
                        url.port().unwrap_or(443)
                    );
                    self.alt_svc_cache.insert(origin_key, alt_str.to_string());
                }
            }
        }
    }
}

/// A builder pattern for instantiating a custom [`Client`] with specific overrides.
///
/// Provides a declarative interface to override the default Chrome profile, configure 
/// outbound proxy routes, or inject a pre-populated synchronized cookie store.
#[derive(Default)]
pub struct ClientBuilder {
    profile: Option<ChromeProfile>,
    proxy: Option<Proxy>,
    cookie_store: Option<Arc<RwLock<CookieStore>>>,
    danger_accept_invalid_certs: bool,
}

impl ClientBuilder {
    /// Bypasses TLS certificate validation.
    ///
    /// Disables peer verification in BoringSSL. This is strictly intended for debugging 
    /// environments or corporate proxies and undermines transport layer security.
    pub fn danger_accept_invalid_certs(mut self, accept: bool) -> Self {
        self.danger_accept_invalid_certs = accept;
        self
    }

    /// Sets the Chrome identity profile.
    pub fn profile(mut self, profile: ChromeProfile) -> Self {
        self.profile = Some(profile);
        self
    }

    /// Configures an outbound proxy.
    pub fn proxy(mut self, proxy: Proxy) -> Self {
        self.proxy = Some(proxy);
        self
    }

    /// Provides a pre-existing synchronized cookie store.
    pub fn cookie_store(mut self, store: Arc<RwLock<CookieStore>>) -> Self {
        self.cookie_store = Some(store);
        self
    }

    /// Finalizes the configuration and constructs a `Client`.
    pub fn build(self) -> Result<Client> {
        let mut profile = self
            .profile
            .unwrap_or_else(crate::profile::chrome_147::profile_auto);

        if self.danger_accept_invalid_certs {
            profile.tls.verify_peer = false;
        }

        Ok(Client {
            pool: Arc::new(Mutex::new(HashMap::new())),
            profile,
            proxy: self.proxy,
            cookie_store: self
                .cookie_store
                .unwrap_or_else(|| Arc::new(RwLock::new(CookieStore::default()))),
            hint_cache: Arc::new(RwLock::new(HashSet::new())),
            alt_svc_cache: AltSvcCache::new(),
        })
    }
}
