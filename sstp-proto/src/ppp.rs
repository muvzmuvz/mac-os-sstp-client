//! The outermost PPP frame: by default a 2-byte HDLC-style Address(0xFF) +
//! Control(0x03) prefix, then a 2-byte protocol number, then that
//! protocol's payload (RFC 1661 §6.6, §7.3). No async-HDLC *escaping* or
//! FCS is needed here (that only exists for real serial lines; see
//! [`crate::packet`]'s module docs) — but the Address/Control prefix
//! itself is a separate thing that every RFC-1661 peer MUST send unless
//! Address-and-Control-Field-Compression was explicitly negotiated in that
//! direction. Neither the production SSTP gateway nor a locally-run
//! accel-ppp test server ever offers ACFC from their side (confirmed by
//! comparing an accel-ppp debug log against this client: it logged `recv
//! [LCP ProtoRej id=2 <ff03>]` — this client misreading the server's
//! `FF 03` prefix as protocol number `0xFF03` and rejecting it, on every
//! single frame), so this client never omits the prefix on send and
//! tolerantly strips it if present on receive.

/// The default RFC 1661 §7.3 Address/Control prefix, sent on every frame
/// unless ACFC has been negotiated away — which in practice never happens
/// against either SSTP server this client has been tested against, so
/// sending it unconditionally (rather than tracking negotiated ACFC state)
/// is both simpler and matches every real-world peer's expectation.
const ADDRESS_CONTROL: [u8; 2] = [0xFF, 0x03];

/// Strips a leading Address/Control prefix if present, otherwise returns
/// `frame` unchanged. Exposed separately from [`decode`] for callers that
/// need the raw "Protocol field onward" bytes rather than an already-split
/// `(Protocol, payload)` pair — e.g. building a Protocol-Reject's
/// Rejected-Information field (RFC 1661 §5.7), which per spec starts at the
/// rejected packet's own Protocol field, never at its Address/Control.
pub fn strip_address_control(frame: &[u8]) -> &[u8] {
    frame.strip_prefix(&ADDRESS_CONTROL).unwrap_or(frame)
}

/// PPP protocol numbers we care about (RFC 1661 §2, RFC 1332 for IPCP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Ip,
    Lcp,
    Pap,
    Chap,
    Ipcp,
    Unknown(u16),
}

impl Protocol {
    pub fn to_u16(self) -> u16 {
        match self {
            Protocol::Ip => 0x0021,
            Protocol::Lcp => 0xC021,
            Protocol::Pap => 0xC023,
            Protocol::Chap => 0xC223,
            Protocol::Ipcp => 0x8021,
            Protocol::Unknown(v) => v,
        }
    }

    pub fn from_u16(v: u16) -> Protocol {
        match v {
            0x0021 => Protocol::Ip,
            0xC021 => Protocol::Lcp,
            0xC023 => Protocol::Pap,
            0xC223 => Protocol::Chap,
            0x8021 => Protocol::Ipcp,
            other => Protocol::Unknown(other),
        }
    }
}

/// Encodes a full PPP frame ready to hand to [`crate::packet::encode_data`],
/// including the mandatory-by-default Address/Control prefix (see the
/// module docs for why this is never conditionally omitted).
pub fn encode(protocol: Protocol, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 2 + payload.len());
    out.extend_from_slice(&ADDRESS_CONTROL);
    out.extend_from_slice(&protocol.to_u16().to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Splits a decoded `SSTP_MSG_DATA` payload into its protocol number and
/// the remaining bytes. Strips a leading Address/Control prefix if present
/// (every real peer sends one; see module docs), but doesn't require it —
/// tolerating a peer that did successfully negotiate ACFC and omits it.
/// Returns `None` if the frame is shorter than the 2-byte protocol field
/// itself, which shouldn't happen with a well-behaved peer but must never
/// panic given this reads directly off the network.
pub fn decode(frame: &[u8]) -> Option<(Protocol, &[u8])> {
    let frame = strip_address_control(frame);
    if frame.len() < 2 {
        return None;
    }
    let proto = Protocol::from_u16(u16::from_be_bytes([frame[0], frame[1]]));
    Some((proto, &frame[2..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_known_protocol() {
        let wire = encode(Protocol::Lcp, &[1, 2, 3]);
        assert_eq!(wire, vec![0xFF, 0x03, 0xC0, 0x21, 1, 2, 3], "must include the default Address/Control prefix");
        let (proto, payload) = decode(&wire).unwrap();
        assert_eq!(proto, Protocol::Lcp);
        assert_eq!(payload, &[1, 2, 3]);
    }

    #[test]
    fn decode_tolerates_a_missing_address_control_prefix() {
        // A peer that successfully negotiated ACFC (or just doesn't bother)
        // may omit the prefix entirely -- must still decode correctly.
        let (proto, payload) = decode(&[0xC0, 0x21, 1, 2, 3]).unwrap();
        assert_eq!(proto, Protocol::Lcp);
        assert_eq!(payload, &[1, 2, 3]);
    }

    #[test]
    fn unknown_protocol_preserved_numerically() {
        let wire = encode(Protocol::Unknown(0x8281), &[]);
        let (proto, _) = decode(&wire).unwrap();
        assert_eq!(proto, Protocol::Unknown(0x8281));
    }

    #[test]
    fn short_frame_is_none_not_a_panic() {
        assert_eq!(decode(&[]), None);
        assert_eq!(decode(&[0x00]), None);
    }
}
