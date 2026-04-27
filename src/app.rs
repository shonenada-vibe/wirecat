use std::{
    collections::{HashMap, VecDeque},
    time::Instant,
};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::Rect;

use crate::{
    http::{self, HttpMessage, HttpTransaction},
    model::{CaptureEvent, Packet},
};

const MAX_DIAGNOSTICS: usize = 6;
const MIN_PANEL_PCT: u16 = 10;
const PANEL_RESIZE_STEP: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanelBorder {
    PacketsDetails,
    DetailsHex,
}

#[derive(Debug)]
pub struct App {
    pub packets: Vec<Packet>,
    pub pending_packets: Vec<Packet>,
    pub next_packet_number: usize,
    pub selected: usize,
    pub display_filter: String,
    pub editing_filter: bool,
    pub paused: bool,
    pub autoscroll: bool,
    pub should_quit: bool,
    pub fullscreen_detail: bool,
    pub diagnostics: VecDeque<String>,
    pub protocol_counts: HashMap<String, usize>,
    pub max_packets: usize,
    pub started_at: Instant,
    pub packets_pct: u16,
    pub details_pct: u16,
    pub last_body_area: Option<Rect>,
    pub dragging_border: Option<PanelBorder>,
    pub http_mode: bool,
    pub transactions: Vec<HttpTransaction>,
    pub pending_requests: HashMap<String, usize>,
    pub selected_transaction: usize,
    pub next_transaction_number: usize,
}

impl App {
    pub fn new(max_packets: usize, http_mode: bool) -> Self {
        Self {
            packets: Vec::new(),
            pending_packets: Vec::new(),
            next_packet_number: 1,
            selected: 0,
            display_filter: String::new(),
            editing_filter: false,
            paused: false,
            autoscroll: false,
            should_quit: false,
            fullscreen_detail: false,
            diagnostics: VecDeque::new(),
            protocol_counts: HashMap::new(),
            max_packets,
            started_at: Instant::now(),
            packets_pct: 48,
            details_pct: 28,
            last_body_area: None,
            dragging_border: None,
            http_mode,
            transactions: Vec::new(),
            pending_requests: HashMap::new(),
            selected_transaction: 0,
            next_transaction_number: 1,
        }
    }

    pub fn hex_pct(&self) -> u16 {
        100u16
            .saturating_sub(self.packets_pct)
            .saturating_sub(self.details_pct)
    }

    fn resize_packets(&mut self, delta: i16) {
        let new_packets = (self.packets_pct as i16 + delta).clamp(
            MIN_PANEL_PCT as i16,
            (100 - MIN_PANEL_PCT as i16 - self.details_pct as i16).max(MIN_PANEL_PCT as i16),
        ) as u16;
        let hex = 100 - self.details_pct - new_packets;
        if hex >= MIN_PANEL_PCT {
            self.packets_pct = new_packets;
        }
    }

    fn resize_details(&mut self, delta: i16) {
        let new_details = (self.details_pct as i16 + delta).clamp(
            MIN_PANEL_PCT as i16,
            (100 - MIN_PANEL_PCT as i16 - self.packets_pct as i16).max(MIN_PANEL_PCT as i16),
        ) as u16;
        let hex = 100 - self.packets_pct - new_details;
        if hex >= MIN_PANEL_PCT {
            self.details_pct = new_details;
        }
    }

    pub fn handle_mouse(&mut self, event: MouseEvent) {
        let Some(body) = self.last_body_area else {
            return;
        };
        match event.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some(border) = self.border_at(body, event.column, event.row) {
                    self.dragging_border = Some(border);
                }
            }
            MouseEventKind::Drag(MouseButton::Left) => {
                if let Some(border) = self.dragging_border {
                    self.apply_drag(body, border, event.row);
                }
            }
            MouseEventKind::Up(MouseButton::Left) => {
                self.dragging_border = None;
            }
            _ => {}
        }
    }

    fn border_at(&self, body: Rect, col: u16, row: u16) -> Option<PanelBorder> {
        if col < body.x || col >= body.x + body.width {
            return None;
        }
        let packets_h = body.height * self.packets_pct / 100;
        let details_h = body.height * self.details_pct / 100;
        let border1 = body.y + packets_h.saturating_sub(1);
        let border2 = body.y + (packets_h + details_h).saturating_sub(1);
        if row == border1 {
            Some(PanelBorder::PacketsDetails)
        } else if row == border2 {
            Some(PanelBorder::DetailsHex)
        } else {
            None
        }
    }

    fn apply_drag(&mut self, body: Rect, border: PanelBorder, row: u16) {
        if body.height == 0 {
            return;
        }
        let row = row.max(body.y).min(body.y + body.height - 1);
        let offset = row - body.y;
        let pct = ((offset as u32 + 1) * 100 / body.height as u32) as i32;
        match border {
            PanelBorder::PacketsDetails => {
                let target = pct.clamp(
                    MIN_PANEL_PCT as i32,
                    100 - MIN_PANEL_PCT as i32 - self.details_pct as i32,
                ) as u16;
                self.packets_pct = target;
            }
            PanelBorder::DetailsHex => {
                let target = pct.clamp(
                    self.packets_pct as i32 + MIN_PANEL_PCT as i32,
                    100 - MIN_PANEL_PCT as i32,
                ) as u16;
                self.details_pct = target.saturating_sub(self.packets_pct);
            }
        }
    }

    pub fn apply_capture_event(&mut self, event: CaptureEvent) {
        match event {
            CaptureEvent::Packet(packet) if self.paused => self.pending_packets.push(packet),
            CaptureEvent::Packet(packet) => self.push_packet(packet),
            CaptureEvent::Diagnostic(message) => self.push_diagnostic(message),
        }
    }

    pub fn selected_packet(&self) -> Option<&Packet> {
        let visible = self.visible_indices();
        visible
            .get(self.selected)
            .and_then(|packet_index| self.packets.get(*packet_index))
    }

    pub fn visible_indices(&self) -> Vec<usize> {
        self.packets
            .iter()
            .enumerate()
            .filter_map(|(index, packet)| {
                packet.matches_filter(&self.display_filter).then_some(index)
            })
            .collect()
    }

    pub fn status_line(&self) -> String {
        let elapsed = self.started_at.elapsed().as_secs();
        let mode = if self.paused { "paused" } else { "capturing" };
        let http_segment = if self.http_mode {
            format!(" | HTTP mode | {} requests", self.transactions.len())
        } else {
            String::new()
        };
        format!(
            "{mode} | {} packets | {} queued | {}s | autoscroll {}{}",
            self.packets.len(),
            self.pending_packets.len(),
            elapsed,
            if self.autoscroll { "on" } else { "off" },
            http_segment,
        )
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        if self.editing_filter {
            self.handle_filter_key(key);
            return;
        }

        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true;
            }
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Esc if !self.fullscreen_detail => self.should_quit = true,
            KeyCode::Esc | KeyCode::Char('e') if self.fullscreen_detail => {
                self.fullscreen_detail = false;
            }
            KeyCode::Enter
                if !self.fullscreen_detail
                    && (self.selected_packet().is_some()
                        || self.selected_http_transaction().is_some()) =>
            {
                self.fullscreen_detail = true;
            }
            KeyCode::Char('[') => self.resize_packets(-(PANEL_RESIZE_STEP as i16)),
            KeyCode::Char(']') => self.resize_packets(PANEL_RESIZE_STEP as i16),
            KeyCode::Char('{') => self.resize_details(-(PANEL_RESIZE_STEP as i16)),
            KeyCode::Char('}') => self.resize_details(PANEL_RESIZE_STEP as i16),
            KeyCode::Char('j') | KeyCode::Down if self.http_mode => self.select_next_transaction(),
            KeyCode::Char('k') | KeyCode::Up if self.http_mode => {
                self.select_previous_transaction()
            }
            KeyCode::Char('g') if self.http_mode => self.selected_transaction = 0,
            KeyCode::Char('G') if self.http_mode => self.select_last_transaction(),
            KeyCode::Char('j') | KeyCode::Down => self.select_next(),
            KeyCode::Char('k') | KeyCode::Up => self.select_previous(),
            KeyCode::Char('g') => self.selected = 0,
            KeyCode::Char('G') => self.select_last(),
            KeyCode::Char('/') if !self.fullscreen_detail => self.editing_filter = true,
            KeyCode::Char('p') => self.toggle_pause(),
            KeyCode::Char('a') => self.autoscroll = !self.autoscroll,
            KeyCode::Char('c') => self.clear(),
            _ => {}
        }
    }

    fn handle_filter_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                self.editing_filter = false;
                self.clamp_selection();
            }
            KeyCode::Backspace => {
                self.display_filter.pop();
                self.clamp_selection();
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.display_filter.clear();
                self.clamp_selection();
            }
            KeyCode::Char(ch) => {
                self.display_filter.push(ch);
                self.clamp_selection();
            }
            _ => {}
        }
    }

    fn push_packet(&mut self, mut packet: Packet) {
        packet.number = self.next_packet_number;
        self.next_packet_number += 1;

        *self
            .protocol_counts
            .entry(packet.protocol.clone())
            .or_insert(0) += 1;

        if self.http_mode {
            self.process_http(&packet);
        }

        self.packets.push(packet);

        if self.packets.len() > self.max_packets {
            let overflow = self.packets.len() - self.max_packets;
            self.packets.drain(0..overflow);
            self.rebuild_stats();
        }

        if self.autoscroll {
            self.select_last();
        } else {
            self.clamp_selection();
        }
    }

    fn process_http(&mut self, packet: &Packet) {
        let Some(message) = http::extract_from_packet(packet) else {
            return;
        };
        match message {
            HttpMessage::Request(request) => {
                let flow_key = http::flow_key(&packet.source, &packet.destination);
                let transaction = HttpTransaction {
                    number: self.next_transaction_number,
                    method: request.method,
                    path: request.path,
                    host: request.host,
                    request_version: request.version,
                    request_headers: request.headers,
                    request_timestamp: packet.timestamp.clone(),
                    flow_key: flow_key.clone(),
                    status_code: None,
                    status_text: None,
                    response_version: None,
                    response_headers: Vec::new(),
                    content_length: None,
                    content_type: None,
                    response_timestamp: None,
                    source: packet.source.clone(),
                    destination: packet.destination.clone(),
                };
                self.next_transaction_number += 1;
                let index = self.transactions.len();
                self.transactions.push(transaction);
                self.pending_requests.insert(flow_key, index);
            }
            HttpMessage::Response(response) => {
                let reverse = http::reverse_flow_key(&packet.source, &packet.destination);
                if let Some(index) = self.pending_requests.remove(&reverse)
                    && let Some(transaction) = self.transactions.get_mut(index)
                {
                    transaction.status_code = Some(response.status_code);
                    transaction.status_text = Some(response.status_text);
                    transaction.response_version = Some(response.version);
                    transaction.response_headers = response.headers;
                    transaction.content_length = response.content_length;
                    transaction.content_type = response.content_type;
                    transaction.response_timestamp = Some(packet.timestamp.clone());
                }
            }
        }
    }

    pub fn selected_http_transaction(&self) -> Option<&HttpTransaction> {
        self.transactions.get(self.selected_transaction)
    }

    fn select_next_transaction(&mut self) {
        if !self.transactions.is_empty() {
            self.selected_transaction =
                (self.selected_transaction + 1).min(self.transactions.len() - 1);
        }
    }

    fn select_previous_transaction(&mut self) {
        self.selected_transaction = self.selected_transaction.saturating_sub(1);
    }

    fn select_last_transaction(&mut self) {
        self.selected_transaction = self.transactions.len().saturating_sub(1);
    }

    fn push_diagnostic(&mut self, message: String) {
        if self.diagnostics.len() >= MAX_DIAGNOSTICS {
            self.diagnostics.pop_front();
        }
        self.diagnostics.push_back(message);
    }

    fn toggle_pause(&mut self) {
        self.paused = !self.paused;
        if !self.paused {
            let pending = std::mem::take(&mut self.pending_packets);
            for packet in pending {
                self.push_packet(packet);
            }
        }
    }

    fn select_next(&mut self) {
        let visible_len = self.visible_indices().len();
        if visible_len > 0 {
            self.selected = (self.selected + 1).min(visible_len - 1);
        }
    }

    fn select_previous(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    fn select_last(&mut self) {
        self.selected = self.visible_indices().len().saturating_sub(1);
    }

    fn clamp_selection(&mut self) {
        let visible_len = self.visible_indices().len();
        self.selected = self.selected.min(visible_len.saturating_sub(1));
    }

    fn clear(&mut self) {
        self.packets.clear();
        self.pending_packets.clear();
        self.protocol_counts.clear();
        self.next_packet_number = 1;
        self.selected = 0;
        self.transactions.clear();
        self.pending_requests.clear();
        self.next_transaction_number = 1;
        self.selected_transaction = 0;
    }

    #[cfg(test)]
    fn test_apply_packet(&mut self, packet: Packet) {
        self.apply_capture_event(CaptureEvent::Packet(packet));
    }

    fn rebuild_stats(&mut self) {
        self.protocol_counts.clear();
        for packet in &self.packets {
            *self
                .protocol_counts
                .entry(packet.protocol.clone())
                .or_insert(0) += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::TcpdumpParser;

    #[test]
    fn http_mode_captures_request_from_tcpdump_output() {
        let lines = [
            "2026-04-27 10:00:00.123456 IP 127.0.0.1.49152 > 127.0.0.1.18080: Flags [P.], length 78",
            "\t0x0000:  0200 0000 4500 0082 0000 4000 4006 0000  ....E.....@.@...",
            "\t0x0010:  7f00 0001 7f00 0001 c000 46a0 0000 0001  ..........F.....",
            "\t0x0020:  0000 0001 8018 18eb fe28 0000 0101 080a  .........(......",
            "\t0x0030:  0000 0001 0000 0001 4745 5420 2f20 4854  ........GET / HT",
            "\t0x0040:  5450 2f31 2e31 0d0a 486f 7374 3a20 6c6f  TP/1.1..Host: lo",
            "\t0x0050:  6361 6c68 6f73 743a 3138 3038 300d 0a0d  calhost:18080...",
            "\t0x0060:  0a                                       .",
            "2026-04-27 10:00:00.234567 IP 127.0.0.1.18080 > 127.0.0.1.49152: Flags [P.], length 37",
            "\t0x0000:  0200 0000 4500 005d 0000 4000 4006 0000  ....E..]..@.@...",
            "\t0x0010:  7f00 0001 7f00 0001 46a0 c000 0000 0001  ........F.......",
            "\t0x0020:  0000 0050 8018 18eb fe28 0000 0101 080a  ...P.....(......",
            "\t0x0030:  0000 0002 0000 0002 4854 5450 2f31 2e31  ........HTTP/1.1",
            "\t0x0040:  2032 3030 204f 4b0d 0a43 6f6e 7465 6e74  .200.OK..Content",
            "\t0x0050:  2d4c 656e 6774 683a 2032 0d0a 0d0a 4f4b  -Length:.2....OK",
        ];

        let mut parser = TcpdumpParser::new();
        let mut app = App::new(100, true);
        for line in lines {
            if let Some(packet) = parser.ingest_line(line) {
                app.test_apply_packet(packet);
            }
        }
        if let Some(packet) = parser.finish() {
            app.test_apply_packet(packet);
        }

        assert_eq!(app.transactions.len(), 1, "expected 1 transaction");
        let tx = &app.transactions[0];
        assert_eq!(tx.method, "GET");
        assert_eq!(tx.path, "/");
        assert_eq!(tx.host.as_deref(), Some("localhost:18080"));
        assert_eq!(tx.status_code, Some(200));
        assert_eq!(tx.content_length, Some(2));
    }
}
