use std::{
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc::Sender,
    thread,
};

use anyhow::{Context, Result, bail};

use crate::{model::CaptureEvent, parser::TcpdumpParser};

#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub tcpdump: String,
    pub interface: Option<String>,
    pub read_file: Option<PathBuf>,
    pub bpf_filter: Vec<String>,
}

pub struct CaptureSession {
    child: Child,
}

impl CaptureSession {
    pub fn spawn(config: CaptureConfig, tx: Sender<CaptureEvent>) -> Result<Self> {
        if config.interface.is_some() && config.read_file.is_some() {
            bail!("--interface and --read cannot be used together");
        }

        let mut command = Command::new(&config.tcpdump);
        command.args(["-l", "-nn", "-tttt", "-vv", "-XX"]);

        if let Some(interface) = &config.interface {
            command.args(["-i", interface]);
        }

        if let Some(read_file) = &config.read_file {
            command.arg("-r").arg(read_file);
        }

        command.args(&config.bpf_filter);
        command.stdout(Stdio::piped()).stderr(Stdio::piped());

        let mut child = command.spawn().with_context(|| {
            format!(
                "failed to start tcpdump executable '{}'",
                config.tcpdump.as_str()
            )
        })?;

        if let Some(stdout) = child.stdout.take() {
            let tx = tx.clone();
            thread::spawn(move || {
                let mut parser = TcpdumpParser::new();
                for line in BufReader::new(stdout).lines() {
                    match line {
                        Ok(line) => {
                            if let Some(packet) = parser.ingest_line(&line) {
                                let _ = tx.send(CaptureEvent::Packet(packet));
                            }
                        }
                        Err(error) => {
                            let _ = tx.send(CaptureEvent::Diagnostic(format!(
                                "tcpdump stdout read error: {error}"
                            )));
                            return;
                        }
                    }
                }

                if let Some(packet) = parser.finish() {
                    let _ = tx.send(CaptureEvent::Packet(packet));
                }
                let _ = tx.send(CaptureEvent::Diagnostic(
                    "tcpdump stdout closed".to_string(),
                ));
            });
        }

        if let Some(stderr) = child.stderr.take() {
            thread::spawn(move || {
                for line in BufReader::new(stderr).lines() {
                    match line {
                        Ok(line) if !line.trim().is_empty() => {
                            let _ = tx.send(CaptureEvent::Diagnostic(line));
                        }
                        Ok(_) => {}
                        Err(error) => {
                            let _ = tx.send(CaptureEvent::Diagnostic(format!(
                                "tcpdump stderr read error: {error}"
                            )));
                            return;
                        }
                    }
                }
            });
        }

        Ok(Self { child })
    }
}

impl Drop for CaptureSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
