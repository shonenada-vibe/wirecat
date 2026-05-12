use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap},
};

use crate::{app::App, http::HttpTransaction, model::Packet};

const SELECTED_STYLE: Style = Style::new()
    .fg(Color::Black)
    .bg(Color::Rgb(255, 196, 87))
    .add_modifier(Modifier::BOLD);

pub fn draw(frame: &mut Frame<'_>, app: &mut App) {
    if app.fullscreen_detail {
        let root = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(1)])
            .split(frame.area());
        draw_fullscreen_detail(frame, root[0], app);
        draw_fullscreen_footer(frame, root[1]);
        return;
    }

    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(1),
        ])
        .split(frame.area());

    draw_header(frame, root[0], app);
    draw_body(frame, root[1], app);
    draw_footer(frame, root[2], app);

    if app.editing_filter {
        draw_filter_cursor(frame, root[0], app);
    }
}

fn draw_fullscreen_detail(frame: &mut Frame<'_>, area: Rect, app: &App) {
    if app.http_mode {
        let lines = app
            .selected_http_transaction()
            .map(http_transaction_detail_lines)
            .unwrap_or_else(|| vec![Line::from("No HTTP request selected")]);
        let details = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("HTTP Request Details"),
            )
            .wrap(Wrap { trim: false });
        frame.render_widget(details, area);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    let detail_lines = app
        .selected_packet()
        .map(packet_detail_lines)
        .unwrap_or_else(|| vec![Line::from("No packet selected")]);
    let details = Paragraph::new(detail_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Packet Details (fullscreen)"),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(details, chunks[0]);

    let hex_lines = app
        .selected_packet()
        .map(|packet| {
            if packet.hex_dump.is_empty() {
                vec![Line::from("No hex dump available")]
            } else {
                packet
                    .hex_dump
                    .iter()
                    .map(|line| Line::from(line.clone()))
                    .collect()
            }
        })
        .unwrap_or_else(|| vec![Line::from("No packet selected")]);
    let hex = Paragraph::new(hex_lines)
        .block(Block::default().borders(Borders::ALL).title("Bytes"))
        .wrap(Wrap { trim: false });
    frame.render_widget(hex, chunks[1]);
}

fn draw_fullscreen_footer(frame: &mut Frame<'_>, area: Rect) {
    let footer = Paragraph::new("e/Esc back | q quit").style(Style::new().fg(Color::DarkGray));
    frame.render_widget(footer, area);
}

fn draw_header(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    let filter_style = if app.editing_filter {
        Style::new().fg(Color::Rgb(255, 196, 87))
    } else {
        Style::new().fg(Color::Gray)
    };

    let filter = if app.display_filter.is_empty() {
        "<empty>"
    } else {
        app.display_filter.as_str()
    };

    let status = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                "WireCat",
                Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::raw(app.status_line()),
        ]),
        Line::from(vec![
            Span::styled("display filter: ", Style::new().fg(Color::Gray)),
            Span::styled(filter, filter_style),
        ]),
    ])
    .block(Block::default().borders(Borders::ALL).title("Capture"));
    frame.render_widget(status, chunks[0]);

    let stats = protocol_stats(app);
    let stats = Paragraph::new(stats)
        .block(Block::default().borders(Borders::ALL).title("Protocols"))
        .wrap(Wrap { trim: true });
    frame.render_widget(stats, chunks[1]);
}

fn draw_body(frame: &mut Frame<'_>, area: Rect, app: &App) {
    if app.http_mode {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(app.packets_pct),
                Constraint::Percentage(app.details_pct + app.hex_pct()),
            ])
            .split(area);
        draw_http_table(frame, chunks[0], app);
        draw_http_details(frame, chunks[1], app);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(app.packets_pct),
            Constraint::Percentage(app.details_pct),
            Constraint::Percentage(app.hex_pct()),
        ])
        .split(area);

    draw_packet_table(frame, chunks[0], app);
    draw_details(frame, chunks[1], app);
    draw_hex(frame, chunks[2], app);
}

fn draw_http_table(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let rows = app.transactions.iter().map(|tx| {
        let status = tx
            .status_code
            .map(|code| code.to_string())
            .unwrap_or_else(|| "—".to_string());
        let status_style = match tx.status_code {
            Some(code) if (200..300).contains(&code) => Style::new().fg(Color::Green),
            Some(code) if (300..400).contains(&code) => Style::new().fg(Color::Cyan),
            Some(code) if (400..500).contains(&code) => Style::new().fg(Color::Yellow),
            Some(code) if (500..600).contains(&code) => Style::new().fg(Color::Red),
            _ => Style::new().fg(Color::Gray),
        };
        let host = tx.host.clone().unwrap_or_else(|| tx.destination.clone());
        let kind = tx.content_type.clone().unwrap_or_else(|| "—".to_string());
        let size = tx
            .content_length
            .map(human_size)
            .unwrap_or_else(|| "—".to_string());
        let time = tx
            .response_timestamp
            .as_deref()
            .or(Some(tx.request_timestamp.as_str()))
            .unwrap_or("")
            .to_string();
        Row::new(vec![
            Cell::from(tx.number.to_string()),
            Cell::from(tx.method.clone()).style(Style::new().fg(Color::Magenta)),
            Cell::from(status).style(status_style),
            Cell::from(host),
            Cell::from(tx.path.clone()),
            Cell::from(kind),
            Cell::from(size),
            Cell::from(time),
        ])
    });

    let header = Row::new([
        "No", "Method", "Status", "Host", "Path", "Type", "Size", "Time",
    ])
    .style(
        Style::new()
            .fg(Color::Rgb(131, 220, 255))
            .add_modifier(Modifier::BOLD),
    );

    let table = Table::new(
        rows,
        [
            Constraint::Length(5),
            Constraint::Length(7),
            Constraint::Length(6),
            Constraint::Length(24),
            Constraint::Min(20),
            Constraint::Length(20),
            Constraint::Length(8),
            Constraint::Length(26),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("HTTP Requests"),
    )
    .row_highlight_style(SELECTED_STYLE)
    .highlight_symbol(">> ");

    let mut state = TableState::default().with_selected(Some(app.selected_transaction));
    frame.render_stateful_widget(table, area, &mut state);
}

fn draw_http_details(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let lines = app
        .selected_http_transaction()
        .map(http_transaction_detail_lines)
        .unwrap_or_else(|| http_empty_state_lines(app));
    let details = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Request / Response"),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(details, area);
}

fn http_empty_state_lines(app: &App) -> Vec<Line<'static>> {
    let buffered_total: usize = app.flow_buffers.values().map(|b| b.len()).sum();
    let mut lines = vec![
        Line::from("No HTTP request captured yet."),
        Line::from(""),
        Line::from(format!(
            "Packets received from tcpdump: {}",
            app.packets.len()
        )),
        Line::from(format!(
            "Packets with TCP payload extracted: {} ({} bytes total)",
            app.http_payload_packets, app.http_payload_bytes
        )),
        Line::from(format!(
            "Active flows / buffered bytes: {} / {}",
            app.flow_buffers.len(),
            buffered_total
        )),
    ];
    if app.packets.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(
            "If packets stays at 0, tcpdump is not delivering packets.",
        ));
        lines.push(Line::from(
            "Common causes: missing sudo/BPF permissions, wrong -i interface,",
        ));
        lines.push(Line::from(
            "or BPF filter excluding your traffic. Check the diagnostics line below.",
        ));
    } else if app.http_payload_packets == 0 {
        lines.push(Line::from(""));
        lines.push(Line::from(
            "Packets are arriving but TCP payload extraction failed for all of them.",
        ));
        lines.push(Line::from(
            "Possible causes: unfamiliar link-layer header, IPv6, or non-TCP traffic.",
        ));
    } else {
        lines.push(Line::from(""));
        lines.push(Line::from(
            "TCP payloads are being captured, but no HTTP/1.x message has been",
        ));
        lines.push(Line::from(
            "fully decoded yet. The capture may have started mid-stream, or",
        ));
        lines.push(Line::from(
            "responses lack Content-Length (e.g. chunked encoding is not yet supported).",
        ));
    }
    if let Some(diag) = app.diagnostics.back() {
        lines.push(Line::from(""));
        lines.push(Line::from(format!("tcpdump: {diag}")));
    }
    lines
}

fn human_size(bytes: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = 1024 * 1024;
    if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} kB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn http_transaction_detail_lines(tx: &HttpTransaction) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let label = Style::new().fg(Color::Gray);

    lines.push(Line::from(vec![Span::styled(
        "General",
        Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    )]));
    lines.push(Line::from(vec![
        Span::styled("Request URL: ", label),
        Span::raw(format!(
            "{}{}",
            tx.host
                .clone()
                .map(|host| format!("http://{host}"))
                .unwrap_or_else(|| format!("http://{}", tx.destination)),
            tx.path
        )),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Method: ", label),
        Span::raw(tx.method.clone()),
    ]));
    let status_line = match (tx.status_code, tx.status_text.as_ref()) {
        (Some(code), Some(text)) => format!("{code} {text}"),
        (Some(code), None) => code.to_string(),
        _ => "(pending)".to_string(),
    };
    lines.push(Line::from(vec![
        Span::styled("Status: ", label),
        Span::raw(status_line),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Remote Address: ", label),
        Span::raw(tx.destination.clone()),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Started: ", label),
        Span::raw(tx.request_timestamp.clone()),
    ]));
    if let Some(ts) = &tx.response_timestamp {
        lines.push(Line::from(vec![
            Span::styled("Completed: ", label),
            Span::raw(ts.clone()),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![Span::styled(
        "Request Headers",
        Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    )]));
    lines.push(Line::from(format!(
        "{} {} {}",
        tx.method, tx.path, tx.request_version
    )));
    if tx.request_headers.is_empty() {
        lines.push(Line::from("(no headers captured)"));
    } else {
        for (name, value) in &tx.request_headers {
            lines.push(Line::from(vec![
                Span::styled(format!("{name}: "), label),
                Span::raw(value.clone()),
            ]));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![Span::styled(
        "Response Headers",
        Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    )]));
    if let Some(version) = &tx.response_version {
        let status_text = tx.status_text.clone().unwrap_or_default();
        let code = tx
            .status_code
            .map(|code| code.to_string())
            .unwrap_or_default();
        lines.push(Line::from(format!("{version} {code} {status_text}")));
    }
    if tx.response_headers.is_empty() {
        lines.push(Line::from("(no response captured yet)"));
    } else {
        for (name, value) in &tx.response_headers {
            lines.push(Line::from(vec![
                Span::styled(format!("{name}: "), label),
                Span::raw(value.clone()),
            ]));
        }
    }

    if !tx.request_body.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            "Request Body",
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )]));
        push_body_lines(&mut lines, &tx.request_body, false);
    }

    if tx.response_timestamp.is_some() {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            "Response Body",
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )]));
        if tx.response_body.is_empty() {
            lines.push(Line::from("(empty)"));
        } else {
            push_body_lines(&mut lines, &tx.response_body, tx.response_body_truncated);
        }
    }

    lines
}

fn push_body_lines(lines: &mut Vec<Line<'static>>, body: &[u8], truncated: bool) {
    lines.push(Line::from(format!(
        "({} bytes{})",
        body.len(),
        if truncated { ", truncated" } else { "" }
    )));
    let text = String::from_utf8_lossy(body);
    for line in text.lines().take(200) {
        lines.push(Line::from(line.to_string()));
    }
}

fn draw_packet_table(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let visible_indices = app.visible_indices();
    let rows = visible_indices.iter().filter_map(|index| {
        app.packets.get(*index).map(|packet| {
            Row::new(vec![
                Cell::from(packet.number.to_string()),
                Cell::from(packet.timestamp.clone()),
                Cell::from(packet.protocol.clone()),
                Cell::from(packet.source.clone()),
                Cell::from(packet.destination.clone()),
                Cell::from(
                    packet
                        .length
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                ),
                Cell::from(packet.summary.clone()),
            ])
        })
    });

    let header = Row::new([
        "No",
        "Time",
        "Proto",
        "Source",
        "Destination",
        "Len",
        "Info",
    ])
    .style(
        Style::new()
            .fg(Color::Rgb(131, 220, 255))
            .add_modifier(Modifier::BOLD),
    );

    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Length(26),
            Constraint::Length(8),
            Constraint::Length(24),
            Constraint::Length(24),
            Constraint::Length(7),
            Constraint::Min(30),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title("Packets"))
    .row_highlight_style(SELECTED_STYLE)
    .highlight_symbol(">> ");

    let mut state = TableState::default().with_selected(Some(app.selected));
    frame.render_stateful_widget(table, area, &mut state);
}

fn draw_details(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let lines = app
        .selected_packet()
        .map(packet_detail_lines)
        .unwrap_or_else(|| vec![Line::from("No packet selected")]);

    let details = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Packet Details"),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(details, area);
}

fn draw_hex(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let lines = app
        .selected_packet()
        .map(|packet| {
            if packet.hex_dump.is_empty() {
                vec![Line::from("No hex dump available")]
            } else {
                packet
                    .hex_dump
                    .iter()
                    .map(|line| Line::from(line.clone()))
                    .collect()
            }
        })
        .unwrap_or_else(|| vec![Line::from("No packet selected")]);

    let hex = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Bytes"))
        .wrap(Wrap { trim: false });
    frame.render_widget(hex, area);
}

fn draw_footer(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let latest_diag = app
        .diagnostics
        .back()
        .map(|value| format!(" | {value}"))
        .unwrap_or_default();
    let text = format!(
        "q quit | Enter detail | / filter | p pause | a autoscroll | j/k move | g/G top/bottom | c clear | [/] resize packets | {{/}} resize details{latest_diag}"
    );
    let footer = Paragraph::new(text).style(Style::new().fg(Color::DarkGray));
    frame.render_widget(footer, area);
}

fn draw_filter_cursor(frame: &mut Frame<'_>, header_area: Rect, app: &App) {
    let cursor_x = header_area.x + 18 + app.display_filter.chars().count() as u16;
    let cursor_y = header_area.y + 2;
    if cursor_x < header_area.right().saturating_sub(1) {
        frame.set_cursor_position((cursor_x, cursor_y));
    }
}

fn packet_detail_lines(packet: &Packet) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(vec![
            Span::styled("No: ", Style::new().fg(Color::Gray)),
            Span::raw(packet.number.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Time: ", Style::new().fg(Color::Gray)),
            Span::raw(packet.timestamp.clone()),
        ]),
        Line::from(vec![
            Span::styled("Protocol: ", Style::new().fg(Color::Gray)),
            Span::raw(packet.protocol.clone()),
        ]),
        Line::from(vec![
            Span::styled("Source: ", Style::new().fg(Color::Gray)),
            Span::raw(packet.source.clone()),
        ]),
        Line::from(vec![
            Span::styled("Destination: ", Style::new().fg(Color::Gray)),
            Span::raw(packet.destination.clone()),
        ]),
        Line::from(vec![
            Span::styled("Length: ", Style::new().fg(Color::Gray)),
            Span::raw(
                packet
                    .length
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
        ]),
        Line::from(vec![
            Span::styled("Summary: ", Style::new().fg(Color::Gray)),
            Span::raw(packet.summary.clone()),
        ]),
    ];

    if !packet.details.is_empty() {
        lines.push(Line::from(""));
        lines.extend(packet.details.iter().map(|line| Line::from(line.clone())));
    }

    lines
}

fn protocol_stats(app: &App) -> Vec<Line<'static>> {
    let mut stats = app.protocol_counts.iter().collect::<Vec<_>>();
    stats.sort_by(|left, right| right.1.cmp(left.1).then_with(|| left.0.cmp(right.0)));

    if stats.is_empty() {
        return vec![Line::from("Waiting for packets...")];
    }

    stats
        .into_iter()
        .take(8)
        .map(|(protocol, count)| {
            Line::from(vec![
                Span::styled(format!("{protocol:<8}"), Style::new().fg(Color::Gray)),
                Span::raw(count.to_string()),
            ])
        })
        .collect()
}
