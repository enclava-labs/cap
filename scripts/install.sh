#!/usr/bin/env bash
# curl | bash installer for the enclava CLI.
#
#   curl -fsSL https://raw.githubusercontent.com/enclava-labs/cap/main/scripts/install.sh | bash
#
# Env overrides:
#   ENCLAVA_VERSION     release tag (default: latest)
#   ENCLAVA_INSTALL_DIR default: ~/.enclava/bin
set -euo pipefail

REPO="enclava-labs/cap"
BIN="enclava"
INSTALL_DIR="${ENCLAVA_INSTALL_DIR:-$HOME/.enclava/bin}"

die() { echo "error: $*" >&2; exit 1; }

# --- resolve version -------------------------------------------------------
version="${ENCLAVA_VERSION:-${1:-}}"
if [[ -z "$version" ]]; then
  url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")"
  version="${url##*/}"
fi
[[ "$version" == v* ]] || version="v$version"

# --- detect platform -------------------------------------------------------
os="$(uname -s)"
case "$os" in
  Linux)  os="linux" ;;
  Darwin) os="macos" ;;
  *) die "unsupported OS '$os' (installer covers Linux and macOS; Windows: irm https://raw.githubusercontent.com/enclava-labs/cap/main/scripts/install.ps1 | iex; other Unix: cargo install --locked --git https://github.com/$REPO enclava-cli)" ;;
esac
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="x86_64" ;;
  aarch64|arm64) arch="aarch64" ;;
  *) die "unsupported architecture '$arch'" ;;
esac

echo "Installing $BIN $version ($os/$arch) to $INSTALL_DIR"

# --- download ---------------------------------------------------------------
base="https://github.com/$REPO/releases/download/$version"
asset="enclava-$os-$arch.tar.gz"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "$tmp/$asset" "$base/$asset" || die "download failed for $asset"
curl -fsSL -o "$tmp/SHA256SUMS.txt" "$base/SHA256SUMS.txt" || die "download failed for SHA256SUMS.txt"

# --- verify checksum --------------------------------------------------------
expected="$(grep " $asset\$" "$tmp/SHA256SUMS.txt" | awk '{print $1}')"
[[ -n "$expected" ]] || die "no checksum entry for $asset in SHA256SUMS.txt"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
else
  actual="$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')" || die "neither sha256sum nor shasum available"
fi
[[ "$actual" == "$expected" ]] || die "checksum mismatch for $asset (got $actual, want $expected)"

# --- verify signature when cosign is available -------------------------------
if command -v cosign >/dev/null 2>&1; then
  curl -fsSL -o "$tmp/SHA256SUMS.txt.sigstore.json" "$base/SHA256SUMS.txt.sigstore.json" || die "download failed for signature bundle"
  cosign verify-blob \
    --bundle "$tmp/SHA256SUMS.txt.sigstore.json" \
    --certificate-identity-regexp "^https://github.com/$REPO/" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "$tmp/SHA256SUMS.txt" >/dev/null || die "cosign signature verification failed"
  echo "Signature verified with cosign."
else
  echo "note: cosign not found; verified checksum only. Install cosign for signature verification."
fi

# --- install -----------------------------------------------------------------
mkdir -p "$INSTALL_DIR"
tar -xzf "$tmp/$asset" -C "$tmp"
install -m 0755 "$tmp/$BIN" "$INSTALL_DIR/$BIN"

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) cat <<EOF

$INSTALL_DIR is not in your PATH. Add this to your shell profile (~/.bashrc / ~/.zshrc):

  export PATH="$INSTALL_DIR:\$PATH"
EOF
  ;;
esac

"$INSTALL_DIR/$BIN" --version
echo "Installed $BIN $version -> $INSTALL_DIR/$BIN"
