use crate::model::Packet;

#[derive(Debug, Default)]
pub struct TcpdumpParser {
    next_number: usize,
    current: Option<PacketBuilder>,
}

#[derive(Debug)]
struct PacketBuilder {
    header: String,
    details: Vec<String>,
    hex_dump: Vec<String>,
}

impl TcpdumpParser {
    pub fn new() -> Self {
        Self {
            next_number: 1,
            current: None,
        }
    }

    pub fn ingest_line(&mut self, line: &str) -> Option<Packet> {
        if is_packet_header(line) {
            let completed = self.finish_current();
            self.current = Some(PacketBuilder {
                header: line.trim().to_string(),
                details: Vec::new(),
                hex_dump: Vec::new(),
            });
            return completed;
        }

        if let Some(current) = &mut self.current {
            let trimmed = line.trim_end().to_string();
            if is_hex_line(&trimmed) {
                current.hex_dump.push(trimmed);
            } else if !trimmed.trim().is_empty() {
                current.details.push(trimmed.trim().to_string());
            }
        }

        None
    }

    pub fn finish(mut self) -> Option<Packet> {
        self.finish_current()
    }

    fn finish_current(&mut self) -> Option<Packet> {
        let current = self.current.take()?;
        let mut packet = parse_header(self.next_number, &current.header);
        packet.details = current.details;
        packet.hex_dump = current.hex_dump;
        self.next_number += 1;
        Some(packet)
    }
}

fn parse_header(number: usize, header: &str) -> Packet {
    let (timestamp, summary) = split_timestamp(header);
    let protocol = parse_protocol(summary);
    let (source, destination) = parse_endpoints(summary);
    let length = parse_length(summary);

    Packet {
        number,
        timestamp: timestamp.to_string(),
        protocol,
        source,
        destination,
        length,
        summary: summary.to_string(),
        details: Vec::new(),
        hex_dump: Vec::new(),
    }
}

fn split_timestamp(line: &str) -> (&str, &str) {
    let line = line.trim();
    if line.len() >= 26 && looks_like_date_time(line) {
        let timestamp_end = line
            .char_indices()
            .find_map(|(idx, ch)| (idx > 19 && ch.is_whitespace()).then_some(idx))
            .unwrap_or(line.len());
        return (&line[..timestamp_end], line[timestamp_end..].trim());
    }

    if line.len() >= 8 && looks_like_time(line) {
        let timestamp_end = line.find(char::is_whitespace).unwrap_or(line.len());
        return (&line[..timestamp_end], line[timestamp_end..].trim());
    }

    ("", line)
}

fn parse_protocol(summary: &str) -> String {
    let first = summary
        .split_whitespace()
        .next()
        .unwrap_or("unknown")
        .trim_end_matches(',');

    match first {
        "IP" | "IP6" | "ARP" | "ICMP" | "ICMP6" | "UDP" | "TCP" => first.to_string(),
        "ethertype" => summary
            .split_whitespace()
            .nth(1)
            .unwrap_or("ether")
            .trim_end_matches(',')
            .to_string(),
        value => value.to_string(),
    }
}

fn parse_endpoints(summary: &str) -> (String, String) {
    let Some((left, right)) = summary.split_once(" > ") else {
        return ("-".to_string(), "-".to_string());
    };

    let source = left
        .split_whitespace()
        .last()
        .unwrap_or("-")
        .trim_matches(',')
        .to_string();
    let destination = right
        .split_once(": ")
        .map(|(destination, _)| destination)
        .unwrap_or(right)
        .trim()
        .trim_end_matches(':')
        .trim_matches(',')
        .to_string();

    (source, destination)
}

fn parse_length(summary: &str) -> Option<usize> {
    let marker = " length ";
    let (_, tail) = summary.rsplit_once(marker)?;
    tail.split(|ch: char| !ch.is_ascii_digit())
        .next()
        .and_then(|value| value.parse().ok())
}

fn is_packet_header(line: &str) -> bool {
    let line = line.trim_start();
    looks_like_date_time(line) || looks_like_time(line)
}

fn looks_like_date_time(line: &str) -> bool {
    let bytes = line.as_bytes();
    bytes.len() >= 19
        && bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && bytes[10].is_ascii_whitespace()
        && bytes[11..13].iter().all(u8::is_ascii_digit)
        && bytes[13] == b':'
        && bytes[14..16].iter().all(u8::is_ascii_digit)
        && bytes[16] == b':'
        && bytes[17..19].iter().all(u8::is_ascii_digit)
}

fn looks_like_time(line: &str) -> bool {
    let bytes = line.as_bytes();
    bytes.len() >= 8
        && bytes[0..2].iter().all(u8::is_ascii_digit)
        && bytes[2] == b':'
        && bytes[3..5].iter().all(u8::is_ascii_digit)
        && bytes[5] == b':'
        && bytes[6..8].iter().all(u8::is_ascii_digit)
}

fn is_hex_line(line: &str) -> bool {
    line.trim_start().starts_with("0x")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_header() {
        let packet = parse_header(
            7,
            "2026-04-27 15:35:01.123456 IP 10.0.0.2.54000 > 142.250.72.14.443: Flags [P.], length 98",
        );

        assert_eq!(packet.number, 7);
        assert_eq!(packet.timestamp, "2026-04-27 15:35:01.123456");
        assert_eq!(packet.protocol, "IP");
        assert_eq!(packet.source, "10.0.0.2.54000");
        assert_eq!(packet.destination, "142.250.72.14.443");
        assert_eq!(packet.length, Some(98));
    }

    #[test]
    fn parses_ipv6_header() {
        let packet = parse_header(
            7,
            "2026-04-27 15:35:01.123456 IP6 ::1.54000 > ::1.8080: Flags [P.], length 42",
        );

        assert_eq!(packet.protocol, "IP6");
        assert_eq!(packet.source, "::1.54000");
        assert_eq!(packet.destination, "::1.8080");
        assert_eq!(packet.length, Some(42));
    }

    #[test]
    fn groups_multiline_packets() {
        let mut parser = TcpdumpParser::new();

        assert!(
            parser
                .ingest_line("2026-04-27 15:35:01.123456 IP host.a.1 > host.b.2: length 4")
                .is_none()
        );
        assert!(parser.ingest_line("\t0x0000:  4500 002c").is_none());
        let packet = parser
            .ingest_line("2026-04-27 15:35:02.123456 ARP, Request who-has host.b")
            .unwrap();

        assert_eq!(packet.number, 1);
        assert_eq!(packet.hex_dump, vec!["\t0x0000:  4500 002c"]);

        let packet = parser.finish().unwrap();
        assert_eq!(packet.number, 2);
        assert_eq!(packet.protocol, "ARP");
    }
}
