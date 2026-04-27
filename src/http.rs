use crate::model::Packet;

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
    pub request_timestamp: String,
    pub flow_key: String,
    pub status_code: Option<u16>,
    pub status_text: Option<String>,
    pub response_version: Option<String>,
    pub response_headers: Vec<(String, String)>,
    pub content_length: Option<usize>,
    pub content_type: Option<String>,
    pub response_timestamp: Option<String>,
    pub source: String,
    pub destination: String,
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

pub fn extract_from_packet(packet: &Packet) -> Option<HttpMessage> {
    if packet.hex_dump.is_empty() {
        return None;
    }
    let bytes = payload_bytes(&packet.hex_dump);
    detect_http(&bytes)
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
}
