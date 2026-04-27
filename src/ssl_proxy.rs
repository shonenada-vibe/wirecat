use std::{
    fs,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, mpsc::Sender},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    runtime::Runtime,
};
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    rustls::{
        ClientConfig, RootCertStore, ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    },
};

use crate::model::{CaptureEvent, Packet};

const CONNECT_HEADER_LIMIT: usize = 16 * 1024;

#[derive(Debug, Clone)]
pub struct SslProxyConfig {
    pub listen: SocketAddr,
    pub ca_cert_path: PathBuf,
    pub ca_key_path: PathBuf,
    pub max_preview_bytes: usize,
}

pub struct SslProxySession {
    _thread: thread::JoinHandle<()>,
}

#[derive(Clone)]
struct ProxyAuthority {
    cert: Arc<Certificate>,
    key: Arc<KeyPair>,
    cert_path: PathBuf,
}

impl SslProxySession {
    pub fn spawn(config: SslProxyConfig, tx: Sender<CaptureEvent>) -> Result<Self> {
        let authority = ProxyAuthority::load_or_create(&config.ca_cert_path, &config.ca_key_path)?;
        let listen = config.listen;
        let max_preview_bytes = config.max_preview_bytes;
        let cert_path = authority.cert_path.clone();
        let thread_tx = tx.clone();

        let thread = thread::Builder::new()
            .name("ssl-proxy".to_string())
            .spawn(move || {
                let runtime = match Runtime::new() {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = thread_tx.send(CaptureEvent::Diagnostic(format!(
                            "SSL proxy runtime failed: {error}"
                        )));
                        return;
                    }
                };

                runtime.block_on(async move {
                    if let Err(error) =
                        run_proxy(config, authority, thread_tx.clone(), max_preview_bytes).await
                    {
                        let _ = thread_tx.send(CaptureEvent::Diagnostic(format!(
                            "SSL proxy stopped: {error:#}"
                        )));
                    }
                });
            })
            .context("failed to spawn SSL proxy thread")?;

        tx.send(CaptureEvent::Diagnostic(format!(
            "SSL proxy listening on {listen}; trust CA certificate at {}",
            cert_path.display()
        )))
        .ok();

        Ok(Self { _thread: thread })
    }
}

impl ProxyAuthority {
    fn load_or_create(cert_path: &PathBuf, key_path: &PathBuf) -> Result<Self> {
        if cert_path.exists() && key_path.exists() {
            let cert_pem = fs::read_to_string(cert_path)
                .with_context(|| format!("failed to read CA cert {}", cert_path.display()))?;
            let key_pem = fs::read_to_string(key_path)
                .with_context(|| format!("failed to read CA key {}", key_path.display()))?;
            let params = CertificateParams::from_ca_cert_pem(&cert_pem)
                .context("failed to parse existing CA certificate")?;
            let key = KeyPair::from_pem(&key_pem).context("failed to parse existing CA key")?;
            let cert = params
                .self_signed(&key)
                .context("failed to reconstruct CA issuer")?;
            return Ok(Self {
                cert: Arc::new(cert),
                key: Arc::new(key),
                cert_path: cert_path.clone(),
            });
        }

        let key = KeyPair::generate().context("failed to generate CA key")?;
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "WireCat local SSL proxy CA");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let cert = params
            .self_signed(&key)
            .context("failed to generate CA certificate")?;

        fs::write(cert_path, cert.pem())
            .with_context(|| format!("failed to write CA cert {}", cert_path.display()))?;
        fs::write(key_path, key.serialize_pem())
            .with_context(|| format!("failed to write CA key {}", key_path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(key_path, fs::Permissions::from_mode(0o600)).ok();
        }

        Ok(Self {
            cert: Arc::new(cert),
            key: Arc::new(key),
            cert_path: cert_path.clone(),
        })
    }

    fn server_config_for_host(&self, host: &str) -> Result<ServerConfig> {
        let leaf_key = KeyPair::generate().context("failed to generate leaf key")?;
        let mut params = CertificateParams::new(vec![host.to_string()])
            .with_context(|| format!("failed to create certificate params for {host}"))?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let leaf_cert = params
            .signed_by(&leaf_key, &self.cert, &self.key)
            .with_context(|| format!("failed to sign leaf certificate for {host}"))?;

        let cert_chain = vec![
            leaf_cert.der().clone(),
            CertificateDer::from(self.cert.der().to_vec()),
        ];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .context("failed to build TLS server config")
    }
}

async fn run_proxy(
    config: SslProxyConfig,
    authority: ProxyAuthority,
    tx: Sender<CaptureEvent>,
    max_preview_bytes: usize,
) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("failed to bind SSL proxy on {}", config.listen))?;

    loop {
        let (client, peer) = listener.accept().await.context("failed to accept client")?;
        let authority = authority.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Err(error) =
                handle_client(client, peer, authority, tx.clone(), max_preview_bytes).await
            {
                let _ = tx.send(CaptureEvent::Diagnostic(format!(
                    "SSL proxy client error from {peer}: {error:#}"
                )));
            }
        });
    }
}

async fn handle_client(
    mut client: TcpStream,
    peer: SocketAddr,
    authority: ProxyAuthority,
    tx: Sender<CaptureEvent>,
    max_preview_bytes: usize,
) -> Result<()> {
    let header = read_connect_header(&mut client).await?;
    let header_text = String::from_utf8_lossy(&header);
    let first_line = header_text
        .lines()
        .next()
        .ok_or_else(|| anyhow!("empty proxy request"))?;

    let Some(authority_part) = first_line
        .strip_prefix("CONNECT ")
        .and_then(|tail| tail.split_whitespace().next())
    else {
        bail!("only explicit HTTPS CONNECT proxying is supported");
    };

    let (host, port) = parse_authority(authority_part)?;
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .context("failed to acknowledge CONNECT")?;

    let acceptor = TlsAcceptor::from(Arc::new(authority.server_config_for_host(&host)?));
    let client_tls = acceptor
        .accept(client)
        .await
        .with_context(|| format!("client TLS handshake failed for {host}"))?;

    let upstream_tcp = TcpStream::connect((host.as_str(), port))
        .await
        .with_context(|| format!("failed to connect upstream {host}:{port}"))?;
    let upstream_tls = upstream_connector()
        .connect(
            ServerName::try_from(host.clone()).context("invalid upstream server name")?,
            upstream_tcp,
        )
        .await
        .with_context(|| format!("upstream TLS handshake failed for {host}:{port}"))?;

    let _ = tx.send(CaptureEvent::Diagnostic(format!(
        "SSL proxy decrypted CONNECT {host}:{port} from {peer}"
    )));

    let (mut client_reader, mut client_writer) = tokio::io::split(client_tls);
    let (mut upstream_reader, mut upstream_writer) = tokio::io::split(upstream_tls);
    let client_to_server = copy_observed(
        &mut client_reader,
        &mut upstream_writer,
        tx.clone(),
        PlaintextMeta {
            protocol: "HTTPS-REQ",
            source: peer.to_string(),
            destination: format!("{host}:{port}"),
            max_preview_bytes,
        },
    );
    let server_to_client = copy_observed(
        &mut upstream_reader,
        &mut client_writer,
        tx,
        PlaintextMeta {
            protocol: "HTTPS-RESP",
            source: format!("{host}:{port}"),
            destination: peer.to_string(),
            max_preview_bytes,
        },
    );

    tokio::try_join!(client_to_server, server_to_client)?;
    Ok(())
}

struct PlaintextMeta {
    protocol: &'static str,
    source: String,
    destination: String,
    max_preview_bytes: usize,
}

async fn copy_observed<R, W>(
    reader: &mut R,
    writer: &mut W,
    tx: Sender<CaptureEvent>,
    meta: PlaintextMeta,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0; 16 * 1024];

    loop {
        let bytes_read = reader
            .read(&mut buffer)
            .await
            .context("failed to read TLS plaintext")?;
        if bytes_read == 0 {
            writer.shutdown().await.ok();
            break;
        }

        writer
            .write_all(&buffer[..bytes_read])
            .await
            .context("failed to forward TLS plaintext")?;
        emit_plaintext_packet(&tx, &meta, &buffer[..bytes_read]);
    }

    Ok(())
}

fn emit_plaintext_packet(tx: &Sender<CaptureEvent>, meta: &PlaintextMeta, bytes: &[u8]) {
    let preview_len = bytes.len().min(meta.max_preview_bytes);
    let preview = &bytes[..preview_len];
    let text = String::from_utf8_lossy(preview);
    let first_line = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("<binary or empty TLS plaintext chunk>");
    let truncated = bytes.len() > preview_len;

    let mut details = text
        .lines()
        .take(80)
        .map(|line| sanitize_line(line, 220))
        .collect::<Vec<_>>();

    if truncated {
        details.push(format!(
            "... truncated preview: showing {preview_len} of {} bytes",
            bytes.len()
        ));
    }

    let packet = Packet {
        number: 0,
        timestamp: unix_timestamp_millis(),
        protocol: meta.protocol.to_string(),
        source: meta.source.clone(),
        destination: meta.destination.clone(),
        length: Some(bytes.len()),
        summary: sanitize_line(first_line, 180),
        details,
        hex_dump: hex_preview(preview),
    };

    let _ = tx.send(CaptureEvent::Packet(packet));
}

fn upstream_connector() -> TlsConnector {
    let root_store = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

async fn read_connect_header(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut header = Vec::with_capacity(1024);
    let mut byte = [0; 1];

    while header.len() < CONNECT_HEADER_LIMIT {
        let n = stream
            .read(&mut byte)
            .await
            .context("failed to read proxy request")?;
        if n == 0 {
            bail!("client closed before sending CONNECT request");
        }
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            return Ok(header);
        }
    }

    bail!("CONNECT header exceeded {CONNECT_HEADER_LIMIT} bytes")
}

fn parse_authority(authority: &str) -> Result<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("invalid IPv6 CONNECT authority"))?;
        let port = tail
            .strip_prefix(':')
            .unwrap_or("443")
            .parse()
            .context("invalid CONNECT port")?;
        return Ok((host.to_string(), port));
    }

    let (host, port) = authority.rsplit_once(':').unwrap_or((authority, "443"));
    let port = port.parse().context("invalid CONNECT port")?;
    Ok((host.to_string(), port))
}

fn unix_timestamp_millis() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}", now.as_secs(), now.subsec_millis())
}

fn sanitize_line(line: &str, max_chars: usize) -> String {
    let mut output = line
        .chars()
        .map(|ch| {
            if ch.is_control() && ch != '\t' {
                '.'
            } else {
                ch
            }
        })
        .take(max_chars)
        .collect::<String>();

    if line.chars().count() > max_chars {
        output.push_str("...");
    }

    output
}

fn hex_preview(bytes: &[u8]) -> Vec<String> {
    bytes
        .chunks(16)
        .take(64)
        .enumerate()
        .map(|(row, chunk)| {
            let hex = chunk
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            let ascii = chunk
                .iter()
                .map(|byte| {
                    if byte.is_ascii_graphic() || *byte == b' ' {
                        *byte as char
                    } else {
                        '.'
                    }
                })
                .collect::<String>();
            format!("0x{:04x}:  {:<47}  {}", row * 16, hex, ascii)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_authority_with_port() {
        assert_eq!(
            parse_authority("example.com:8443").unwrap(),
            ("example.com".to_string(), 8443)
        );
    }

    #[test]
    fn parses_connect_authority_default_port() {
        assert_eq!(
            parse_authority("example.com").unwrap(),
            ("example.com".to_string(), 443)
        );
    }

    #[test]
    fn parses_ipv6_connect_authority() {
        assert_eq!(
            parse_authority("[::1]:9443").unwrap(),
            ("::1".to_string(), 9443)
        );
    }
}
