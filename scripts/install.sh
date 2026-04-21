#!/usr/bin/env sh

set -eu

REPO="AHaldner/mailcheck"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
VERSION="${VERSION:-latest}"

sha256_file() {
    file="$1"

    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
        return
    fi

    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | awk '{print $1}'
        return
    fi

    if command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$file" | awk '{print $2}'
        return
    fi

    echo "missing checksum tool: need sha256sum, shasum, or openssl" >&2
    exit 1
}

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"

case "$os" in
darwin | linux) ;;
*)
    echo "unsupported OS: $os" >&2
    echo "For Windows, use the PowerShell installer:" >&2
    echo "  iwr https://raw.githubusercontent.com/$REPO/main/scripts/install.ps1 -useb | iex" >&2
    exit 1
    ;;
esac

case "$arch" in
x86_64 | amd64) arch="amd64" ;;
arm64 | aarch64) arch="arm64" ;;
*)
    echo "unsupported architecture: $arch" >&2
    exit 1
    ;;
esac

if [ "$VERSION" = "latest" ]; then
    VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": "\(v[^"]*\)".*/\1/p' | head -n1)"
fi

if [ -z "$VERSION" ]; then
    echo "failed to resolve release version" >&2
    exit 1
fi

release_url="https://github.com/$REPO/releases/download/$VERSION"
archive="mailcheck_${VERSION#v}_${os}_${arch}.tar.gz"
checksums="checksums.txt"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT INT TERM

curl -fsSL "$release_url/$archive" -o "$tmp_dir/$archive"
curl -fsSL "$release_url/$checksums" -o "$tmp_dir/$checksums"

expected_checksum="$(awk -v file="$archive" '$2 == file {print $1}' "$tmp_dir/$checksums")"
if [ -z "$expected_checksum" ]; then
    echo "missing checksum entry for $archive" >&2
    exit 1
fi

actual_checksum="$(sha256_file "$tmp_dir/$archive")"
if [ "$actual_checksum" != "$expected_checksum" ]; then
    echo "checksum mismatch for $archive" >&2
    echo "expected: $expected_checksum" >&2
    echo "actual:   $actual_checksum" >&2
    exit 1
fi

tar -xzf "$tmp_dir/$archive" -C "$tmp_dir"
if ! install -m 0755 "$tmp_dir/mailcheck" "$BIN_DIR/mailcheck"; then
    echo "failed to install to $BIN_DIR/mailcheck: permission denied" >&2
    echo >&2
    echo "Install without sudo to a user-owned directory:" >&2
    echo "  BIN_DIR=\"\$HOME/.local/bin\" curl -fsSL https://raw.githubusercontent.com/$REPO/main/scripts/install.sh | sh" >&2
    echo >&2
    echo "Or re-run with elevated privileges if you trust this release:" >&2
    echo "  curl -fsSL https://raw.githubusercontent.com/$REPO/main/scripts/install.sh | sudo sh" >&2
    echo >&2
    echo "Make sure your BIN_DIR is on PATH." >&2
    exit 1
fi

echo "installed mailcheck to $BIN_DIR/mailcheck"
