mod app;
mod capture;
mod http;
mod model;
mod parser;
mod ssl_proxy;
mod ui;

use std::{
    io::{self, Stdout},
    net::SocketAddr,
    path::PathBuf,
    sync::mpsc,
    time::Duration,
};

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::{
    event::{self, Event},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};

use crate::{
    app::App,
    capture::{CaptureConfig, CaptureSession},
    ssl_proxy::{SslProxyConfig, SslProxySession},
};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "WireCat: Wireshark-like terminal UI for tcpdump"
)]
struct Cli {
    #[arg(short, long, value_name = "IFACE")]
    interface: Option<String>,

    #[arg(short = 'r', long, value_name = "PCAP")]
    read: Option<PathBuf>,

    #[arg(long, default_value = "tcpdump", value_name = "PATH")]
    tcpdump: String,

    #[arg(long, default_value_t = 5000, value_name = "N")]
    max_packets: usize,

    #[arg(long, value_name = "ADDR")]
    ssl_proxy: Option<SocketAddr>,

    #[arg(long, default_value = "wirecat-ca-cert.pem", value_name = "PATH")]
    ssl_ca_cert: PathBuf,

    #[arg(long, default_value = "wirecat-ca-key.pem", value_name = "PATH")]
    ssl_ca_key: PathBuf,

    #[arg(long, default_value_t = 8192, value_name = "N")]
    ssl_preview_bytes: usize,

    #[arg(long)]
    no_tcpdump: bool,

    /// HTTP mode: filter for HTTP traffic and present a Chrome-style request inspector.
    #[arg(long)]
    http: bool,

    #[arg(value_name = "BPF", trailing_var_arg = true)]
    bpf_filter: Vec<String>,
}

const HTTP_DEFAULT_FILTER: &[&str] = &[
    "tcp", "port", "80", "or", "tcp", "port", "8080", "or", "tcp", "port", "8000", "or", "tcp",
    "port", "3000",
];

fn main() -> Result<()> {
    let cli = Cli::parse();
    let (tx, rx) = mpsc::channel();

    let should_capture_tcpdump = !cli.no_tcpdump
        && (cli.ssl_proxy.is_none()
            || cli.interface.is_some()
            || cli.read.is_some()
            || !cli.bpf_filter.is_empty());
    let bpf_filter = if cli.http && cli.bpf_filter.is_empty() {
        HTTP_DEFAULT_FILTER
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    } else {
        cli.bpf_filter
    };

    let _capture = if should_capture_tcpdump {
        Some(CaptureSession::spawn(
            CaptureConfig {
                tcpdump: cli.tcpdump,
                interface: cli.interface,
                read_file: cli.read,
                bpf_filter,
            },
            tx.clone(),
        )?)
    } else {
        None
    };

    let _ssl_proxy = if let Some(listen) = cli.ssl_proxy {
        Some(SslProxySession::spawn(
            SslProxyConfig {
                listen,
                ca_cert_path: cli.ssl_ca_cert,
                ca_key_path: cli.ssl_ca_key,
                max_preview_bytes: cli.ssl_preview_bytes,
            },
            tx,
        )?)
    } else {
        None
    };

    let mut terminal = setup_terminal()?;
    let mut app = App::new(cli.max_packets, cli.http);
    let result = run_app(&mut terminal, &mut app, rx);
    restore_terminal(&mut terminal)?;
    result
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    rx: mpsc::Receiver<model::CaptureEvent>,
) -> Result<()> {
    loop {
        while let Ok(event) = rx.try_recv() {
            app.apply_capture_event(event);
        }

        terminal.draw(|frame| ui::draw(frame, app))?;

        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key) => app.handle_key(key),
                _ => {}
            }
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode().context("failed to enable terminal raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;
    Terminal::new(CrosstermBackend::new(stdout)).context("failed to initialize terminal")
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    disable_raw_mode().context("failed to disable terminal raw mode")?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)
        .context("failed to leave alternate screen")?;
    terminal.show_cursor().context("failed to restore cursor")
}
