#!/usr/bin/env bash
# Download GeoLite2 Country database
# Requirements: maxmind account with free license key at https://www.maxmind.com/en/geolite2/signup

set -euo pipefail

GEO_DIR="$(dirname "$0")/../data"
mkdir -p "$GEO_DIR"

GEO_DB="$GEO_DIR/GeoLite2-Country.mmdb"

echo "Downloading GeoLite2 Country database..."

# Try with mmdbutil / maxmind cli first
if command -v maxmind &> /dev/null; then
    maxmind download-geolite2 "$GEO_DIR"
    echo "Downloaded via maxmind CLI"
    exit 0
fi

# Fallback: manual download using account credentials
if [ -z "${MAXMIND_ACCOUNT_ID:-}" ] || [ -z "${MAXMIND_LICENSE_KEY:-}" ]; then
    echo "ERROR: Set MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY environment variables."
    echo "Get your free license key at https://www.maxmind.com/en/geolite2/signup"
    echo ""
    echo "Then run: MAXMIND_ACCOUNT_ID=xxx MAXMIND_LICENSE_KEY=xxx bash scripts/download-geolite2.sh"
    exit 1
fi

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

curl -L -o "$TMPDIR/GeoLite2-Country.tar.gz" \
    "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"

tar -xzf "$TMPDIR/GeoLite2-Country.tar.gz" -C "$TMPDIR"

# Find the mmdb file
MMDB=$(find "$TMPDIR" -name 'GeoLite2-Country*.mmdb' | head -1)
if [ -z "$MMDB" ]; then
    echo "ERROR: No GeoLite2-Country.mmdb found in download archive"
    exit 1
fi

cp "$MMDB" "$GEO_DB"
echo "Downloaded to $GEO_DB"
echo "Size: $(du -h "$GEO_DB" | cut -f1)"
