#!/usr/bin/env bash
set -euo pipefail

REPO="${WIRECAT_REPO:-shonenada-vibe/wirecat}"
INSTALL_DIR="${WIRECAT_INSTALL_DIR:-/usr/local/bin}"
VERSION="${WIRECAT_VERSION:-${1:-latest}}"
TMP_DIR=""

cleanup() {
  if [ -n "${TMP_DIR:-}" ]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

err() {
  echo "wirecat install: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || err "missing required command: $1"
}

detect_target() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  case "${os}:${arch}" in
    Darwin:arm64) echo "aarch64-apple-darwin" ;;
    Darwin:x86_64) echo "x86_64-apple-darwin" ;;
    Linux:x86_64) echo "x86_64-unknown-linux-gnu" ;;
    *) err "unsupported platform: ${os} ${arch}" ;;
  esac
}

latest_version() {
  local url
  url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest")"
  basename "$url"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    err "missing required command: sha256sum or shasum"
  fi
}

verify_checksum() {
  local asset="$1"
  local checksum_path="$2"
  local expected actual

  expected="$(awk '{print $1}' "$checksum_path")"
  actual="$(sha256_file "$asset")"
  [ -n "$expected" ] || err "empty checksum file: $checksum_path"
  [ "$actual" = "$expected" ] || err "checksum mismatch for $asset"
}

install_binary() {
  local src="$1"
  local dst="${INSTALL_DIR}/wirecat"

  mkdir -p "$INSTALL_DIR" 2>/dev/null || true
  if [ -w "$INSTALL_DIR" ]; then
    install -m 0755 "$src" "$dst"
  elif command -v sudo >/dev/null 2>&1; then
    sudo mkdir -p "$INSTALL_DIR"
    sudo install -m 0755 "$src" "$dst"
  else
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_DIR"
    install -m 0755 "$src" "${INSTALL_DIR}/wirecat"
  fi
}

release_binary_runs() {
  "$1" --version >/dev/null 2>&1
}

install_from_source() {
  local tag="$1"
  local cargo_root="${TMP_DIR}/cargo"

  need cargo
  echo "Release binary is not compatible with this system; building from source instead." >&2
  cargo install --git "https://github.com/${REPO}.git" --tag "$tag" --locked --root "$cargo_root" wirecat
  [ -f "${cargo_root}/bin/wirecat" ] || err "cargo install did not produce wirecat binary"
  install_binary "${cargo_root}/bin/wirecat"
}

main() {
  need curl
  need tar

  local target tag asset base_url
  target="$(detect_target)"
  tag="$VERSION"
  if [ "$tag" = "latest" ]; then
    tag="$(latest_version)"
  fi

  asset="wirecat-${tag}-${target}.tar.gz"
  base_url="https://github.com/${REPO}/releases/download/${tag}"
  TMP_DIR="$(mktemp -d)"

  cd "$TMP_DIR"
  curl -fsSLO "${base_url}/${asset}"
  curl -fsSLO "${base_url}/${asset}.sha256"
  verify_checksum "$asset" "${asset}.sha256"
  tar -xzf "$asset"

  [ -f wirecat ] || err "archive did not contain wirecat binary"
  if release_binary_runs "$TMP_DIR/wirecat"; then
    install_binary "$TMP_DIR/wirecat"
  else
    install_from_source "$tag"
  fi

  echo "wirecat installed to ${INSTALL_DIR}/wirecat"
}

main "$@"
