# WireCat

A terminal packet analyzer for `tcpdump`, written in Rust. It uses `tcpdump` for capture and renders a Wireshark-style TUI with:

- live packet list
- packet detail pane
- hex/ASCII bytes pane from `tcpdump -XX`
- display filter
- protocol statistics
- pause/resume and autoscroll controls
- explicit HTTPS proxy mode for inspecting decrypted HTTP over TLS

## Requirements

- `tcpdump`
- capture permissions for your platform

On macOS and Linux, live capture often requires elevated permissions:

```sh
sudo cargo run -- -i en0
```

Rust 1.90+ is required when building from source.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/shonenada-vibe/wirecat/main/install.sh | bash
```

The installer downloads the latest release for your platform and installs `wirecat` to `/usr/local/bin` when possible. Set `WIRECAT_INSTALL_DIR` to choose another location:

```sh
curl -fsSL https://raw.githubusercontent.com/shonenada-vibe/wirecat/main/install.sh | WIRECAT_INSTALL_DIR="$HOME/.local/bin" bash
```

## Usage

```sh
cargo run -- -i en0
cargo run -- -i en0 tcp port 443
cargo run -- -r capture.pcap
cargo run -- --ssl-proxy 127.0.0.1:8888
```

Options:

```text
-i, --interface <IFACE>    Capture interface
-r, --read <PCAP>          Read packets from a pcap file
--tcpdump <PATH>           tcpdump executable path
--max-packets <N>          Maximum packets kept in memory
--ssl-proxy <ADDR>         Start an explicit HTTPS MITM proxy
--ssl-ca-cert <PATH>       Local proxy CA certificate path
--ssl-ca-key <PATH>        Local proxy CA private key path
--ssl-preview-bytes <N>    Maximum decrypted bytes shown per TLS chunk
--no-tcpdump               Do not start tcpdump capture
<BPF>...                   Optional tcpdump BPF filter
```

## HTTPS Plaintext Inspection

The SSL proxy is an explicit debugging proxy. It does not decrypt arbitrary passive TLS captures. To inspect HTTPS plaintext:

1. Start the proxy:

```sh
cargo run -- --ssl-proxy 127.0.0.1:8888 --no-tcpdump
```

2. Trust the generated local CA certificate in the client/browser you control:

```text
wirecat-ca-cert.pem
```

3. Configure the client/browser HTTPS proxy to:

```text
127.0.0.1:8888
```

Decrypted request and response chunks appear in the packet list as `HTTPS-REQ` and `HTTPS-RESP`. The proxy intentionally requires explicit client configuration and a trusted local CA, so it is suitable for debugging your own traffic and test environments.

## Keys

| Key | Action |
| --- | --- |
| `q` | Quit |
| `j` / `Down` | Next packet |
| `k` / `Up` | Previous packet |
| `g` | First packet |
| `G` | Last packet |
| `/` | Edit display filter |
| `Esc` / `Enter` | Leave filter input |
| `Backspace` | Delete filter character |
| `p` | Pause/resume adding packets to the UI |
| `a` | Toggle autoscroll |
| `c` | Clear captured packets |
