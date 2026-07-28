//! The HTTP-like handshake SSTP starts with, before the connection
//! switches to binary SSTP framing (RFC-less, Microsoft's own scheme —
//! ported from `vendor/sstp-client/src/sstp-http.c`'s doc comment and
//! request-builder, which we treated as the authoritative source for the
//! exact header set/order/values rather than general MS-SSTP documentation).

/// The fixed SSTP request path — a literal GUID Microsoft's spec hardcodes,
/// not something a client generates.
pub const SSTP_PATH: &str = "/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/";

/// `sstp-http.c` sends `Content-Length: 18446744073709551615` — literal
/// `(uint64_t)-1` — as a documented SSTP quirk meaning "an effectively
/// infinite streaming body follows"; the connection carries binary SSTP
/// framing for as long as the tunnel is up, not a bounded HTTP entity.
const INFINITE_CONTENT_LENGTH: u64 = u64::MAX;

/// Builds the initial `SSTP_DUPLEX_POST` request. `correlation_uuid` should
/// be a freshly generated UUID string (no braces — this function adds
/// them, matching `SSTPCORRELATIONID: {uuid}`).
pub fn build_request(host: &str, correlation_uuid: &str) -> Vec<u8> {
    format!(
        "SSTP_DUPLEX_POST {SSTP_PATH} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Length: {INFINITE_CONTENT_LENGTH}\r\n\
         SSTPCORRELATIONID: {{{correlation_uuid}}}\r\n\
         \r\n"
    )
    .into_bytes()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Headers haven't fully arrived yet; caller should read more bytes
    /// and try again (mirrors [`crate::packet::DecodeError::Incomplete`]).
    Incomplete,
    BadStatusLine(String),
    NonSuccessStatus(u16),
}

/// Looks for the end of the HTTP header block in `buf` and, once found,
/// parses the status line. On success returns the status code and the
/// byte offset where binary SSTP framing begins (i.e. right after the
/// blank line) — the caller is expected to feed any bytes at/after that
/// offset into `packet::PacketReader` rather than discard them, since a
/// real server can pipeline the start of its SSTP stream in the same TLS
/// read as the tail of the HTTP headers.
pub fn parse_response(buf: &[u8]) -> Result<(u16, usize), ParseError> {
    let header_end = find_double_crlf(buf).ok_or(ParseError::Incomplete)?;
    let header_text = String::from_utf8_lossy(&buf[..header_end]);
    let status_line = header_text.lines().next().unwrap_or("");
    let mut parts = status_line.splitn(3, ' ');
    let version_ok = parts.next().is_some_and(|v| v.starts_with("HTTP/"));
    let code: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .filter(|_| version_ok)
        .ok_or_else(|| ParseError::BadStatusLine(status_line.to_string()))?;

    if code != 200 {
        return Err(ParseError::NonSuccessStatus(code));
    }
    Ok((code, header_end + 4))
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_matches_reference_shape() {
        let req = build_request("vpn.example.com:8443", "11111111-2222-3333-4444-555555555555");
        let text = String::from_utf8(req).unwrap();
        assert!(text.starts_with("SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n"));
        assert!(text.contains("Host: vpn.example.com:8443\r\n"));
        assert!(text.contains("Content-Length: 18446744073709551615\r\n"));
        assert!(text.contains("SSTPCORRELATIONID: {11111111-2222-3333-4444-555555555555}\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn parses_successful_response_and_finds_body_offset() {
        let response = b"HTTP/1.1 200 OK\r\nServer: Microsoft-HTTPAPI/2.0\r\nDate: Sat, 19 Feb 2011 02:13:44 GMT\r\n\r\nBINARY-SSTP-BYTES";
        let (code, offset) = parse_response(response).unwrap();
        assert_eq!(code, 200);
        assert_eq!(&response[offset..], b"BINARY-SSTP-BYTES");
    }

    #[test]
    fn status_line_without_reason_phrase_still_parses() {
        // sstp-http.c's own doc comment shows the server replying with
        // just "HTTP/1.1 200" (no "OK"), so that must parse too.
        let response = b"HTTP/1.1 200\r\n\r\n";
        let (code, _) = parse_response(response).unwrap();
        assert_eq!(code, 200);
    }

    #[test]
    fn incomplete_headers_ask_for_more_bytes() {
        assert_eq!(parse_response(b"HTTP/1.1 200 OK\r\nServer: x"), Err(ParseError::Incomplete));
        assert_eq!(parse_response(b""), Err(ParseError::Incomplete));
    }

    #[test]
    fn non_200_status_is_a_distinct_error() {
        let response = b"HTTP/1.1 401 Unauthorized\r\n\r\n";
        assert_eq!(parse_response(response), Err(ParseError::NonSuccessStatus(401)));
    }

    #[test]
    fn garbage_status_line_is_a_distinct_error() {
        let response = b"NOT-HTTP AT ALL\r\n\r\n";
        assert!(matches!(parse_response(response), Err(ParseError::BadStatusLine(_))));
    }
}
