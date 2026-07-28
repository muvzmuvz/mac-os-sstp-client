//! TLS setup for the SSTP control connection, via `native-tls` (macOS's own
//! Secure Transport under the hood, through the system's own TLS
//! implementation) rather than a pure-Rust stack.
//!
//! This project first tried `rustls`, which turned out to be a hard
//! architectural dead end against this session's actual production server:
//! `rustls` deliberately implements only TLS 1.2/1.3 with a curated modern
//! cipher suite list and has no configuration escape hatch for anything
//! older (by design -- it doesn't carry legacy/insecure code paths at
//! all). A live test against the real server came back with the server's
//! own `handshake_failure` alert -- sent *before* any certificate exchange
//! -- meaning the server rejected our ClientHello outright, consistent
//! with an older Windows RRAS/SSTP gateway that needs a protocol version
//! or cipher suite rustls simply refuses to offer. `native-tls` wraps
//! whatever the OS's own TLS stack supports, which is the same
//! compatibility surface the original `sstpc` (linked against OpenSSL's
//! broad "intermediate compatibility" cipher list) relied on successfully
//! against this exact server earlier in this project's history.
//!
//! Certificate handling is unchanged in spirit from the rustls version:
//! SSTP is designed to work with self-signed server certificates (this
//! corporate server uses one), because the protocol's own crypto-bind step
//! (`cmac::build_connected_message`) authenticates the *specific*
//! certificate seen during the handshake against the MS-CHAPv2-derived
//! keys, rather than relying on a CA chain the way ordinary HTTPS does --
//! so chain-of-trust and hostname validation are both intentionally
//! disabled here, matching `sstp-client`'s own `--cert-warn` flag.

/// Builds a `native-tls` connector that accepts any server certificate
/// (see module docs for why that's the correct tradeoff for SSTP
/// specifically) and allows protocol versions back to TLS 1.0, to match
/// whatever this session's actual production server turns out to require
/// -- unlike rustls, this is an actual tunable knob here rather than an
/// architectural wall.
pub fn client_config() -> Result<native_tls::TlsConnector, native_tls::Error> {
    native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .min_protocol_version(Some(native_tls::Protocol::Tlsv10))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_config_builds_without_panicking() {
        client_config().unwrap();
    }
}
