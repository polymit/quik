use bytes::Bytes;
use http::header::{HeaderMap, CONTENT_ENCODING};
use http::StatusCode;
use http2::RecvStream;
use std::io::Read;

use crate::error::{Error, Result};

/// Polymorphic container representing the inbound data stream from either H2 or H3 transport.
///
/// ### Design Rationale:
/// - **HTTP/2 Transport**: Operates over a TCP/TLS connection using streaming data frames.
///   The payload is represented as `ResponseBody::Http2(RecvStream)`, which allows for asynchronous,
///   non-blocking polling of chunks to conserve memory.
/// - **HTTP/3 Transport**: Operates over a UDP/QUIC multiplexed connection. Because `quiche`
///   processes transport and application layers via a unified, single-threaded background event loop,
///   payload bytes are eagerly read from UDP sockets and compiled into an aggregated memory buffer
///   (`ResponseBody::Http3(Vec<u8>)`). This isolates the network layer from borrowing or concurrency hazards.
pub enum ResponseBody {
    /// Standard H2 receiver stream yielding sequential data frames.
    Http2(RecvStream),
    /// Eagerly downloaded and aggregated H3 buffer payload.
    Http3(Vec<u8>),
}

/// A high-level response wrapper providing transparent decompression and body management.
///
/// `Response` unifies both HTTP/2 and HTTP/3 connection payloads under a single,
/// public-API-compatible interface, implementing transparent decompression on hot paths.
///
/// ### Key Architecture:
/// - **Encapsulation**: Keeps the underlying transport polymorphic (H2 vs H3) transparent to the client caller.
/// - **Zero-Copy Decompression**: Employs stack-allocated decompressors (`brotli_decompressor`, `zstd`, `flate2`)
///   upon `bytes()` invocation, decoding raw buffers directly into final owned storage.
pub struct Response {
    /// Status code of the response.
    status: StatusCode,
    /// HTTP response headers.
    headers: HeaderMap,
    /// The polymorphic payload container.
    body: ResponseBody,
    /// The final, post-redirect URL that produced this response.
    url: String,
}

impl Response {
    /// Creates a new `Response` from polymorphic parts.
    pub fn new(status: StatusCode, headers: HeaderMap, body: ResponseBody, url: String) -> Self {
        Self {
            status,
            headers,
            body,
            url,
        }
    }

    /// Returns the HTTP status code.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns a reference to the header map.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Returns the final post-redirect URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Internal setter for the final URL (used by the redirect engine).
    pub(crate) fn set_url(&mut self, url: String) {
        self.url = url;
    }

    /// Collects the response body and returns the decompressed bytes.
    ///
    /// This method is async as it must support asynchronous polling of H2 chunks.
    /// Supports `gzip`, `br`, and `zstd` encodings.
    ///
    /// ### Implementation Strategy:
    /// 1. **Polymorphic Assembly**: Accumulates body frames from TCP/H2 streaming loops,
    ///    or yields the pre-buffered UDP/H3 vector.
    /// 2. **Transport Content-Encoding Negotiation**: Inspects the `Content-Encoding` header and routes
    ///    bytes dynamically through the appropriate decompression block (Brotli, Zstd, or Gzip).
    pub async fn bytes(self) -> Result<Bytes> {
        let mut data = Vec::new();

        match self.body {
            ResponseBody::Http2(mut body_stream) => {
                while let Some(chunk) = body_stream.data().await {
                    let chunk = chunk.map_err(Error::Http2)?;
                    data.extend_from_slice(chunk.as_ref());
                }
            }
            ResponseBody::Http3(body_data) => {
                data = body_data;
            }
        }

        let encoding = self
            .headers
            .get(CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if encoding.contains("br") {
            let mut decoder = brotli_decompressor::Decompressor::new(&data[..], 4096);
            let mut decoded = Vec::new();
            decoder
                .read_to_end(&mut decoded)
                .map_err(|e| Error::Connect(std::io::Error::other(e.to_string())))?;
            Ok(Bytes::from(decoded))
        } else if encoding.contains("zstd") {
            let decoded = zstd::decode_all(&data[..])
                .map_err(|e| Error::Connect(std::io::Error::other(e.to_string())))?;
            Ok(Bytes::from(decoded))
        } else if encoding.contains("gzip") {
            let mut decoder = flate2::read::GzDecoder::new(&data[..]);
            let mut decoded = Vec::new();
            decoder
                .read_to_end(&mut decoded)
                .map_err(|e| Error::Connect(std::io::Error::other(e.to_string())))?;
            Ok(Bytes::from(decoded))
        } else {
            Ok(Bytes::from(data))
        }
    }

    /// Collects the body and decodes it as a UTF-8 string.
    pub async fn text(self) -> Result<String> {
        let bytes = self.bytes().await?;
        String::from_utf8(bytes.to_vec())
            .map_err(|e| Error::Connect(std::io::Error::other(e.to_string())))
    }

    /// Collects the body and decodes it as JSON.
    pub async fn json<T: serde::de::DeserializeOwned>(self) -> Result<T> {
        let bytes = self.bytes().await?;
        serde_json::from_slice(&bytes)
            .map_err(|e| Error::Connect(std::io::Error::other(e.to_string())))
    }
}
