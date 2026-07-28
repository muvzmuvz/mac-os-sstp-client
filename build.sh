#!/bin/sh
set -e
cd "$(dirname "$0")"

# sstp-proto (the SSTP/PPP/TLS engine, formerly the external sstpc/pppd/
# Homebrew stack) is a plain path dependency of the sstp-gui crate -- see
# Cargo.toml -- so it's statically compiled straight into this one binary.
# There is nothing else to build or bundle: no brew, no sstp-client, no
# libevent/openssl@3 dylibs, no vendor/sstp-client build step. A user only
# ever needs this single .app.
cargo build --release --bin sstp-gui

if [ ! -f assets/AppIcon.icns ]; then
    cargo run --release --bin gen_icon
fi

APP="SSTP GUI.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
mkdir -p "$APP/Contents/Resources"
cp target/release/sstp-gui "$APP/Contents/MacOS/sstp-gui"
cp Info.plist "$APP/Contents/Info.plist"
cp assets/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"

codesign --force --deep --sign - "$APP"

echo "Built: $(pwd)/$APP"
