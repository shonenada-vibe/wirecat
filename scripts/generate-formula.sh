#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <tag>  (e.g. v0.1.0)" >&2
  exit 1
fi

TAG="$1"
VERSION="${TAG#v}"
BASE_URL="https://github.com/shonenada-vibe/wirecat/releases/download/${TAG}"

fetch_sha256() {
  local target="$1"
  local url="${BASE_URL}/wirecat-${TAG}-${target}.tar.gz.sha256"
  local sha
  sha=$(curl -fsSL "$url" | awk '{print $1}')
  if [ -z "$sha" ]; then
    echo "Error: failed to fetch checksum for ${target}" >&2
    exit 1
  fi
  echo "$sha"
}

SHA_AARCH64_DARWIN=$(fetch_sha256 "aarch64-apple-darwin")
SHA_X86_64_DARWIN=$(fetch_sha256 "x86_64-apple-darwin")
SHA_X86_64_LINUX=$(fetch_sha256 "x86_64-unknown-linux-gnu")

cat <<EOF
class Wirecat < Formula
  desc "Terminal packet analyzer for tcpdump with a Wireshark-style TUI"
  homepage "https://github.com/shonenada-vibe/wirecat"
  version "${VERSION}"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "${BASE_URL}/wirecat-${TAG}-aarch64-apple-darwin.tar.gz"
      sha256 "${SHA_AARCH64_DARWIN}"
    elsif Hardware::CPU.intel?
      url "${BASE_URL}/wirecat-${TAG}-x86_64-apple-darwin.tar.gz"
      sha256 "${SHA_X86_64_DARWIN}"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "${BASE_URL}/wirecat-${TAG}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "${SHA_X86_64_LINUX}"
    end
  end

  def install
    bin.install "wirecat"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/wirecat --version")
  end
end
EOF
