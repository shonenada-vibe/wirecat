use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap},
};

use crate::{app::App, model::Packet};

const SELECTED_STYLE: Style = Style::new()
    .fg(Color::Black)
    .bg(Color::Rgb(255, 196, 87))
    .add_modifier(Modifier::BOLD);

pub fn draw(frame: &mut Frame<'_>, app: &App) {
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
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(48),
            Constraint::Percentage(28),
            Constraint::Percentage(24),
        ])
        .split(area);

    draw_packet_table(frame, chunks[0], app);
    draw_details(frame, chunks[1], app);
    draw_hex(frame, chunks[2], app);
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
        "q quit | / filter | p pause | a autoscroll | j/k move | g/G top/bottom | c clear{latest_diag}"
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
