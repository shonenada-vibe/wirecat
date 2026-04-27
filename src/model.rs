#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Packet {
    pub number: usize,
    pub timestamp: String,
    pub protocol: String,
    pub source: String,
    pub destination: String,
    pub length: Option<usize>,
    pub summary: String,
    pub details: Vec<String>,
    pub hex_dump: Vec<String>,
}

impl Packet {
    pub fn matches_filter(&self, filter: &str) -> bool {
        let filter = filter.trim();
        if filter.is_empty() {
            return true;
        }

        let haystack = format!(
            "{} {} {} {} {} {} {} {}",
            self.timestamp,
            self.protocol,
            self.source,
            self.destination,
            self.length
                .map(|value| value.to_string())
                .unwrap_or_default(),
            self.summary,
            self.details.join(" "),
            self.hex_dump.join(" ")
        )
        .to_lowercase();

        haystack.contains(&filter.to_lowercase())
    }
}

#[derive(Debug, Clone)]
pub enum CaptureEvent {
    Packet(Packet),
    Diagnostic(String),
}
