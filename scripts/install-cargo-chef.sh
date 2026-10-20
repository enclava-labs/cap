#!/bin/sh
set -eu

version=0.1.78
case "$1" in
  amd64) target=x86_64-unknown-linux-musl; checksum=aca691abfbfbbe00d482e0ed2249eec3091b65e96a0ce92947fb5b254d48b16d ;;
  arm64) target=aarch64-unknown-linux-musl; checksum=cd59b90fce5fa84c4189648fec33404ec5491791eebdb812df5e7fca8336408d ;;
  *)
    # Upstream has no prebuilt binary for the other Rust image architectures.
    cargo install --locked --version "=$version" --root /usr/local cargo-chef
    exit 0
    ;;
esac

curl --proto '=https' --tlsv1.2 -fsSL \
  "https://github.com/LukeMathWalker/cargo-chef/releases/download/v${version}/cargo-chef-${target}.tar.xz" \
  -o /tmp/cargo-chef.tar.xz
echo "$checksum  /tmp/cargo-chef.tar.xz" | sha256sum -c -
tar -xJf /tmp/cargo-chef.tar.xz -C /usr/local/bin --strip-components=1 "cargo-chef-${target}/cargo-chef"
rm /tmp/cargo-chef.tar.xz
