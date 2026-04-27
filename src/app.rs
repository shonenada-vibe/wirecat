use std::{
    collections::{HashMap, VecDeque},
    time::Instant,
};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::Rect;

use crate::model::{CaptureEvent, Packet};

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
}

impl App {
    pub fn new(max_packets: usize) -> Self {
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
        format!(
            "{mode} | {} packets | {} queued | {}s | autoscroll {}",
            self.packets.len(),
            self.pending_packets.len(),
            elapsed,
            if self.autoscroll { "on" } else { "off" }
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
            KeyCode::Enter if !self.fullscreen_detail && self.selected_packet().is_some() => {
                self.fullscreen_detail = true;
            }
            KeyCode::Char('[') => self.resize_packets(-(PANEL_RESIZE_STEP as i16)),
            KeyCode::Char(']') => self.resize_packets(PANEL_RESIZE_STEP as i16),
            KeyCode::Char('{') => self.resize_details(-(PANEL_RESIZE_STEP as i16)),
            KeyCode::Char('}') => self.resize_details(PANEL_RESIZE_STEP as i16),
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
