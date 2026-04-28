#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub host: Option<String>,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub version: String,
    pub status_code: u16,
    pub status_text: String,
    pub headers: Vec<(String, String)>,
    pub content_length: Option<usize>,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone)]
pub enum HttpMessage {
    Request(HttpRequest),
    Response(HttpResponse),
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HttpTransaction {
    pub number: usize,
    pub method: String,
    pub path: String,
    pub host: Option<String>,
    pub request_version: String,
    pub request_headers: Vec<(String, String)>,
    pub request_body: Vec<u8>,
    pub request_timestamp: String,
    pub flow_key: String,
    pub status_code: Option<u16>,
    pub status_text: Option<String>,
    pub response_version: Option<String>,
    pub response_headers: Vec<(String, String)>,
    pub content_length: Option<usize>,
    pub content_type: Option<String>,
    pub response_body: Vec<u8>,
    pub response_body_truncated: bool,
    pub response_timestamp: Option<String>,
    pub source: String,
    pub destination: String,
}

/// Maximum number of body bytes captured per response.
pub const MAX_BODY_PREVIEW: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct ParsedMessage {
    pub message: HttpMessage,
    pub body: Vec<u8>,
    pub body_truncated: bool,
}

const METHODS: &[&str] = &[
    "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
];

/// Decode the hex bytes from a tcpdump `-XX` style hex dump.
pub fn payload_bytes(hex_dump: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for line in hex_dump {
        let trimmed = line.trim_start();
        // Drop "0xOFFSET:" prefix if present.
        let after_prefix = match trimmed.split_once(':') {
            Some((_, rest)) => rest,
            None => trimmed,
        }
        .trim_start();
        // Hex section is separated from ASCII by two or more spaces.
        let hex_part = after_prefix.split("  ").next().unwrap_or("");
        let cleaned: String = hex_part
            .chars()
            .filter(|ch| ch.is_ascii_hexdigit())
            .collect();
        let bytes = cleaned.as_bytes();
        for chunk in bytes.chunks(2) {
            if chunk.len() == 2
                && let (Ok(hi), Ok(lo)) =
                    (char_to_hex(chunk[0] as char), char_to_hex(chunk[1] as char))
            {
                out.push((hi << 4) | lo);
            }
        }
    }
    out
}

fn char_to_hex(ch: char) -> Result<u8, ()> {
    match ch {
        '0'..='9' => Ok(ch as u8 - b'0'),
        'a'..='f' => Ok(ch as u8 - b'a' + 10),
        'A'..='F' => Ok(ch as u8 - b'A' + 10),
        _ => Err(()),
    }
}

/// Scan the packet bytes for an HTTP/1.x request or response and parse it.
#[allow(dead_code)]
pub fn detect_http(bytes: &[u8]) -> Option<HttpMessage> {
    for index in 0..bytes.len().saturating_sub(8) {
        let window = &bytes[index..];
        if window.starts_with(b"HTTP/1.")
            && let Some(response) = parse_response(window)
        {
            return Some(HttpMessage::Response(response));
        }
        for method in METHODS {
            if window.starts_with(method.as_bytes())
                && let Some(request) = parse_request(window)
            {
                return Some(HttpMessage::Request(request));
            }
        }
    }
    None
}

#[allow(dead_code)]
fn parse_request(bytes: &[u8]) -> Option<HttpRequest> {
    let text = String::from_utf8_lossy(bytes).to_string();
    let header_block = text.split("\r\n\r\n").next().unwrap_or(&text);
    let mut lines = header_block.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let version = parts.next()?.to_string();
    if !version.starts_with("HTTP/1.") {
        return None;
    }
    let headers = collect_headers(lines);
    let host = find_header(&headers, "host");
    Some(HttpRequest {
        method,
        path,
        version,
        host,
        headers,
    })
}

#[allow(dead_code)]
fn parse_response(bytes: &[u8]) -> Option<HttpResponse> {
    let text = String::from_utf8_lossy(bytes).to_string();
    let header_block = text.split("\r\n\r\n").next().unwrap_or(&text);
    let mut lines = header_block.split("\r\n");
    let status_line = lines.next()?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next()?.to_string();
    if !version.starts_with("HTTP/1.") {
        return None;
    }
    let status_code: u16 = parts.next()?.parse().ok()?;
    let status_text = parts.next().unwrap_or("").to_string();
    let headers = collect_headers(lines);
    let content_length = find_header(&headers, "content-length")
        .and_then(|value| value.trim().parse::<usize>().ok());
    let content_type = find_header(&headers, "content-type");
    Some(HttpResponse {
        version,
        status_code,
        status_text,
        headers,
        content_length,
        content_type,
    })
}

#[allow(dead_code)]
fn collect_headers<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<(String, String)> {
    lines
        .take_while(|line| !line.is_empty())
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

fn find_header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}

pub fn flow_key(source: &str, destination: &str) -> String {
    format!("{source}->{destination}")
}

pub fn reverse_flow_key(source: &str, destination: &str) -> String {
    format!("{destination}->{source}")
}

/// Extract just the TCP payload from raw frame bytes by parsing IPv4+TCP.
/// Tries the common link-layer header sizes (DLT_NULL on macOS lo0, Ethernet,
/// Linux SLL). If none of those work cleanly, falls back to scanning the first
/// 64 bytes for an IP-looking header.
pub fn tcp_payload(bytes: &[u8]) -> Option<Vec<u8>> {
    for offset in [0usize, 4, 14, 16] {
        if let Some(payload) = tcp_payload_at(bytes, offset) {
            return Some(payload.to_vec());
        }
    }
    // Fallback: scan for an IP header (version 4/6) anywhere in the
    // first part of the frame, in case the link-layer is unfamiliar.
    let scan_end = bytes.len().min(64);
    for offset in 0..scan_end {
        let byte = bytes[offset];
        let version = byte >> 4;
        let ihl = byte & 0x0f;
        if ((version == 4 && (5..=15).contains(&ihl)) || version == 6)
            && let Some(payload) = tcp_payload_at(bytes, offset)
        {
            return Some(payload.to_vec());
        }
    }
    None
}

fn tcp_payload_at(bytes: &[u8], link_offset: usize) -> Option<&[u8]> {
    if bytes.len() < link_offset + 20 {
        return None;
    }
    let ip = &bytes[link_offset..];
    match ip[0] >> 4 {
        4 => ipv4_tcp_payload(ip),
        6 => ipv6_tcp_payload(ip),
        _ => None,
    }
}

fn ipv4_tcp_payload(ip: &[u8]) -> Option<&[u8]> {
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ihl < 20 || ip.len() < ihl + 20 {
        return None;
    }
    if ip[9] != 6 {
        return None;
    }
    let total_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    // tcpdump may have truncated the captured packet, so clamp to what we have.
    let bounded_total = total_len.min(ip.len());
    if bounded_total < ihl + 20 {
        return None;
    }
    let tcp = &ip[ihl..];
    let data_offset = (tcp[12] >> 4) as usize * 4;
    if data_offset < 20 {
        return None;
    }
    let payload_start = ihl + data_offset;
    if payload_start > bounded_total {
        return None;
    }
    Some(&ip[payload_start..bounded_total])
}

fn ipv6_tcp_payload(ip: &[u8]) -> Option<&[u8]> {
    if ip.len() < 40 {
        return None;
    }

    let payload_len = u16::from_be_bytes([ip[4], ip[5]]) as usize;
    let bounded_total = if payload_len == 0 {
        ip.len()
    } else {
        (40 + payload_len).min(ip.len())
    };
    if bounded_total < 60 {
        return None;
    }

    let mut next_header = ip[6];
    let mut tcp_start = 40usize;

    while is_ipv6_extension_header(next_header) {
        if tcp_start + 2 > bounded_total {
            return None;
        }
        let current_header = next_header;
        next_header = ip[tcp_start];
        let header_len = match current_header {
            0 | 43 | 60 => (ip[tcp_start + 1] as usize + 1) * 8,
            44 => {
                if tcp_start + 8 > bounded_total {
                    return None;
                }
                let fragment = u16::from_be_bytes([ip[tcp_start + 2], ip[tcp_start + 3]]);
                if fragment & 0xfff8 != 0 {
                    return None;
                }
                8
            }
            51 => (ip[tcp_start + 1] as usize + 2) * 4,
            _ => return None,
        };
        tcp_start += header_len;
    }

    if next_header != 6 || tcp_start + 20 > bounded_total {
        return None;
    }
    let tcp = &ip[tcp_start..bounded_total];
    let data_offset = (tcp[12] >> 4) as usize * 4;
    if data_offset < 20 {
        return None;
    }
    let payload_start = tcp_start + data_offset;
    if payload_start > bounded_total {
        return None;
    }
    Some(&ip[payload_start..bounded_total])
}

fn is_ipv6_extension_header(next_header: u8) -> bool {
    matches!(next_header, 0 | 43 | 44 | 51 | 60)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Try to consume one HTTP message from the start of `buf`.
/// Returns `Some((message, consumed_bytes))` when a complete message has been
/// parsed, `None` if more bytes are needed. The caller should drop bytes when
/// the buffer cannot be aligned to a message start.
pub fn try_consume_message(buf: &[u8]) -> Option<(ParsedMessage, usize)> {
    let header_end = find_subslice(buf, b"\r\n\r\n")? + 4;
    let head_text = std::str::from_utf8(&buf[..header_end - 4]).ok()?;

    let mut lines = head_text.split("\r\n");
    let first = lines.next()?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_string(), value.trim().to_string()))
        })
        .collect();

    let (message, body_kind) = if first.starts_with("HTTP/1.") {
        let mut parts = first.splitn(3, ' ');
        let version = parts.next()?.to_string();
        let status_code: u16 = parts.next()?.parse().ok()?;
        let status_text = parts.next().unwrap_or("").to_string();
        let content_length =
            find_header(&headers, "content-length").and_then(|v| v.trim().parse::<usize>().ok());
        let content_type = find_header(&headers, "content-type");
        let transfer_encoding = find_header(&headers, "transfer-encoding")
            .map(|v| v.to_lowercase())
            .unwrap_or_default();
        let body_kind = if let Some(len) = content_length {
            BodyKind::Length(len)
        } else if transfer_encoding.contains("chunked") {
            BodyKind::Chunked
        } else if status_code < 200 || status_code == 204 || status_code == 304 {
            BodyKind::Length(0)
        } else {
            BodyKind::Streaming
        };
        (
            HttpMessage::Response(HttpResponse {
                version,
                status_code,
                status_text,
                headers: headers.clone(),
                content_length,
                content_type,
            }),
            body_kind,
        )
    } else if METHODS.iter().any(|m| first.starts_with(*m)) {
        let mut parts = first.splitn(3, ' ');
        let method = parts.next()?.to_string();
        let path = parts.next()?.to_string();
        let version = parts.next()?.to_string();
        if !version.starts_with("HTTP/1.") {
            return None;
        }
        let host = find_header(&headers, "host");
        let body_total =
            find_header(&headers, "content-length").and_then(|v| v.trim().parse::<usize>().ok());
        let transfer_encoding = find_header(&headers, "transfer-encoding")
            .map(|v| v.to_lowercase())
            .unwrap_or_default();
        let body_kind = if let Some(len) = body_total {
            BodyKind::Length(len)
        } else if transfer_encoding.contains("chunked") {
            BodyKind::Chunked
        } else {
            BodyKind::Length(0)
        };
        (
            HttpMessage::Request(HttpRequest {
                method,
                path,
                version,
                host,
                headers: headers.clone(),
            }),
            body_kind,
        )
    } else {
        return None;
    };

    match body_kind {
        BodyKind::Length(body_total) => {
            let needed = header_end + body_total;
            if buf.len() < needed {
                return None;
            }
            let captured_len = body_total.min(MAX_BODY_PREVIEW);
            let body = buf[header_end..header_end + captured_len].to_vec();
            let body_truncated = body_total > captured_len;
            Some((
                ParsedMessage {
                    message,
                    body,
                    body_truncated,
                },
                needed,
            ))
        }
        BodyKind::Chunked => {
            let (decoded, consumed_after_headers, truncated) = decode_chunked(&buf[header_end..])?;
            Some((
                ParsedMessage {
                    message,
                    body: decoded,
                    body_truncated: truncated,
                },
                header_end + consumed_after_headers,
            ))
        }
        BodyKind::Streaming => {
            // Without Content-Length or chunked encoding the body extends until
            // the connection closes. We can't know the boundary mid-stream, so
            // emit headers-only and leave the body bytes in the buffer; they
            // will be discarded the next time we realign.
            Some((
                ParsedMessage {
                    message,
                    body: Vec::new(),
                    body_truncated: false,
                },
                header_end,
            ))
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum BodyKind {
    Length(usize),
    Chunked,
    Streaming,
}

/// Decode an HTTP/1.1 chunked-transfer body. Returns the decoded bytes, the
/// number of input bytes consumed, and whether the body was truncated to the
/// preview cap.
fn decode_chunked(buf: &[u8]) -> Option<(Vec<u8>, usize, bool)> {
    let mut decoded = Vec::new();
    let mut truncated = false;
    let mut idx = 0usize;
    loop {
        let line_end = find_subslice_at(buf, idx, b"\r\n")?;
        let size_line = std::str::from_utf8(&buf[idx..line_end]).ok()?;
        let size_str = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16).ok()?;
        idx = line_end + 2;
        if size == 0 {
            // Optional trailers terminated by \r\n\r\n; require at least one
            // CRLF here.
            // Some servers send \r\n directly after the 0 size line.
            if buf[idx..].starts_with(b"\r\n") {
                idx += 2;
            }
            return Some((decoded, idx, truncated));
        }
        if buf.len() < idx + size + 2 {
            return None;
        }
        if decoded.len() < MAX_BODY_PREVIEW {
            let take = (MAX_BODY_PREVIEW - decoded.len()).min(size);
            decoded.extend_from_slice(&buf[idx..idx + take]);
            if take < size {
                truncated = true;
            }
        } else {
            truncated = true;
        }
        idx += size;
        if &buf[idx..idx + 2] != b"\r\n" {
            return None;
        }
        idx += 2;
    }
}

fn find_subslice_at(haystack: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if from > haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|pos| pos + from)
}

/// Drop bytes from the front of `buf` until it begins at a plausible HTTP
/// message start (request line or `HTTP/1.` response line). Returns whether a
/// realignment was found.
pub fn realign_buffer(buf: &mut Vec<u8>) -> bool {
    if buf.is_empty() {
        return false;
    }
    if let Some(idx) = (0..buf.len().saturating_sub(8)).find(|index| {
        let window = &buf[*index..];
        window.starts_with(b"HTTP/1.") || METHODS.iter().any(|m| window.starts_with(m.as_bytes()))
    }) {
        buf.drain(..idx);
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_get_request() {
        let raw = b"GET /api/users HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
        let message = detect_http(raw).expect("request");
        match message {
            HttpMessage::Request(req) => {
                assert_eq!(req.method, "GET");
                assert_eq!(req.path, "/api/users");
                assert_eq!(req.host.as_deref(), Some("example.com"));
            }
            _ => panic!("expected request"),
        }
    }

    #[test]
    fn parses_response_with_content_length() {
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"ok\":true}";
        let message = detect_http(raw).expect("response");
        match message {
            HttpMessage::Response(resp) => {
                assert_eq!(resp.status_code, 200);
                assert_eq!(resp.status_text, "OK");
                assert_eq!(resp.content_length, Some(17));
                assert_eq!(resp.content_type.as_deref(), Some("application/json"));
            }
            _ => panic!("expected response"),
        }
    }

    #[test]
    fn payload_bytes_decodes_real_tcpdump_xx_lines() {
        let lines = vec!["\t0x0000:  4845 4c4c 4f                              HELLO".to_string()];
        let bytes = payload_bytes(&lines);
        assert_eq!(bytes, b"HELLO");
    }

    #[test]
    fn detects_http_request_in_realistic_tcpdump_dump() {
        let lines = vec![
            "\t0x0000:  0200 0000 4500 0082 0000 4000 4006 0000  ....E.....@.@...".to_string(),
            "\t0x0010:  7f00 0001 7f00 0001 c000 46a0 0000 0001  ..........F.....".to_string(),
            "\t0x0020:  0000 0001 8018 18eb fe28 0000 0101 080a  .........(......".to_string(),
            "\t0x0030:  0000 0001 0000 0001 4745 5420 2f20 4854  ........GET / HT".to_string(),
            "\t0x0040:  5450 2f31 2e31 0d0a 486f 7374 3a20 6c6f  TP/1.1..Host: lo".to_string(),
            "\t0x0050:  6361 6c68 6f73 743a 3138 3038 300d 0a0d  calhost:18080...".to_string(),
            "\t0x0060:  0a                                       .".to_string(),
        ];
        let bytes = payload_bytes(&lines);
        let msg = detect_http(&bytes).expect("should detect");
        match msg {
            HttpMessage::Request(req) => {
                assert_eq!(req.method, "GET");
                assert_eq!(req.path, "/");
                assert_eq!(req.host.as_deref(), Some("localhost:18080"));
            }
            _ => panic!("expected request"),
        }
    }

    #[test]
    fn finds_request_inside_garbage_prefix() {
        let mut buffer = vec![0u8; 64];
        buffer.extend_from_slice(b"POST /login HTTP/1.1\r\nHost: a.b\r\n\r\n");
        let message = detect_http(&buffer).expect("request");
        assert!(matches!(message, HttpMessage::Request(_)));
    }

    #[test]
    fn tcp_payload_extracts_ipv6_loopback_http() {
        let payload = b"GET / HTTP/1.1\r\nHost: localhost:8080\r\n\r\n";
        let frame = ipv6_loopback_frame(payload, 49152, 8080);

        let extracted = tcp_payload(&frame).expect("tcp payload");

        assert_eq!(extracted, payload);
    }

    #[test]
    fn tcp_payload_extracts_ipv6_with_hop_by_hop_header() {
        let payload = b"POST /submit HTTP/1.1\r\nHost: localhost:8080\r\nContent-Length: 0\r\n\r\n";
        let frame = ipv6_loopback_frame_with_hop_by_hop(payload, 49152, 8080);

        let extracted = tcp_payload(&frame).expect("tcp payload");

        assert_eq!(extracted, payload);
    }

    fn ipv6_loopback_frame(payload: &[u8], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut frame = vec![0x1e, 0x00, 0x00, 0x00];
        append_ipv6_header(&mut frame, 20 + payload.len(), 6);
        append_tcp_segment(&mut frame, payload, src_port, dst_port);
        frame
    }

    fn ipv6_loopback_frame_with_hop_by_hop(
        payload: &[u8],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut frame = vec![0x1e, 0x00, 0x00, 0x00];
        append_ipv6_header(&mut frame, 8 + 20 + payload.len(), 0);
        frame.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
        append_tcp_segment(&mut frame, payload, src_port, dst_port);
        frame
    }

    fn append_ipv6_header(frame: &mut Vec<u8>, payload_len: usize, next_header: u8) {
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
        frame.push(next_header);
        frame.push(64);
        frame.extend_from_slice(&[0; 15]);
        frame.push(1);
        frame.extend_from_slice(&[0; 15]);
        frame.push(1);
    }

    fn append_tcp_segment(frame: &mut Vec<u8>, payload: &[u8], src_port: u16, dst_port: u16) {
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        frame.push(0x50);
        frame.push(0x18);
        frame.extend_from_slice(&[0x18, 0xeb]);
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(payload);
    }
}
