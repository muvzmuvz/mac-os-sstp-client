//! SSTP wire framing: the 4-byte packet header, the control-message header,
//! and TLV attributes. Wire format ported byte-for-byte from the reference
//! implementation at `vendor/sstp-client/src/sstp-packet.c` (and its header),
//! which we treated as the authoritative spec rather than re-deriving it
//! from the general MS-SSTP documentation. Notably: for `SSTP_MSG_DATA`
//! packets, the payload right after the 4-byte header *is* the raw PPP
//! frame — the reference implementation's HDLC/FCS layer (`sstp-fcs.c`)
//! only exists to satisfy pppd's pty, not the wire protocol to the server,
//! so it has no equivalent here (see the plan doc for why).

use std::fmt;

/// SSTP protocol version this crate speaks (`SSTP_PROTO_VER`).
pub const PROTO_VERSION: u8 = 0x10;

/// Set on the packet header's `flags` byte for control messages
/// (`SSTP_MSG_FLAG_CTRL`); absent (0) for data messages.
const FLAG_CTRL: u8 = 0x01;

const PKT_HEADER_LEN: usize = 4;
const CTRL_HEADER_LEN: usize = 4;
const ATTR_HEADER_LEN: usize = 4;

/// `sstp_msg_t` — the control message type, carried in the control header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    ConnectRequest,
    ConnectAck,
    ConnectNak,
    Connected,
    Abort,
    Disconnect,
    DisconnectAck,
    EchoRequest,
    EchoReply,
    /// Any value the reference implementation doesn't define; kept instead
    /// of erroring so an unrecognized-but-well-formed control message can
    /// still be logged/inspected rather than dropped outright.
    Unknown(u16),
}

impl MsgType {
    fn to_u16(self) -> u16 {
        match self {
            MsgType::ConnectRequest => 0x0001,
            MsgType::ConnectAck => 0x0002,
            MsgType::ConnectNak => 0x0003,
            MsgType::Connected => 0x0004,
            MsgType::Abort => 0x0005,
            MsgType::Disconnect => 0x0006,
            MsgType::DisconnectAck => 0x0007,
            MsgType::EchoRequest => 0x0008,
            MsgType::EchoReply => 0x0009,
            MsgType::Unknown(v) => v,
        }
    }

    fn from_u16(v: u16) -> MsgType {
        match v {
            0x0001 => MsgType::ConnectRequest,
            0x0002 => MsgType::ConnectAck,
            0x0003 => MsgType::ConnectNak,
            0x0004 => MsgType::Connected,
            0x0005 => MsgType::Abort,
            0x0006 => MsgType::Disconnect,
            0x0007 => MsgType::DisconnectAck,
            0x0008 => MsgType::EchoRequest,
            0x0009 => MsgType::EchoReply,
            other => MsgType::Unknown(other),
        }
    }
}

/// `sstp_attr_t` — a control message attribute's type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrType {
    NoError,
    EncapProtocol,
    StatusInfo,
    CryptoBind,
    CryptoBindRequest,
    Unknown(u8),
}

impl AttrType {
    fn to_u8(self) -> u8 {
        match self {
            AttrType::NoError => 0x00,
            AttrType::EncapProtocol => 0x01,
            AttrType::StatusInfo => 0x02,
            AttrType::CryptoBind => 0x03,
            AttrType::CryptoBindRequest => 0x04,
            AttrType::Unknown(v) => v,
        }
    }

    fn from_u8(v: u8) -> AttrType {
        match v {
            0x00 => AttrType::NoError,
            0x01 => AttrType::EncapProtocol,
            0x02 => AttrType::StatusInfo,
            0x03 => AttrType::CryptoBind,
            0x04 => AttrType::CryptoBindRequest,
            other => AttrType::Unknown(other),
        }
    }
}

/// A decoded attribute: its type plus the raw bytes after the 4-byte
/// attribute header (i.e. `sstp_attr_len`/`sstp_attr_data`'s view, not the
/// on-wire length-inclusive-of-header form).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attr {
    pub attr_type: AttrType,
    pub data: Vec<u8>,
}

/// Human-readable form of an `SSTP_ATTR_STATUS_INFO` status code, ported
/// from `sstp_attr_status_str()` in the reference `sstp-packet.c`. Carried
/// on `CONNECT_NAK`/`ABORT` messages to say *why* the server is rejecting
/// us -- without this, both messages collapse to an opaque "the server
/// said no", which is exactly what made an earlier live failure
/// (`server aborted the connection`, no further detail) hard to act on.
pub fn status_reason(code: u32) -> &'static str {
    match code {
        0x01 => "Received Duplicate Attribute",
        0x02 => "Unrecognized Attribute",
        0x03 => "Invalid Attribute Length",
        0x04 => "Value of attribute is incorrect",
        0x09 => "Attribute is invalid or not supported",
        0x0a => "Attribute is missing",
        0x0b => "Invalid info attribute",
        _ => "Unknown Status Attribute",
    }
}

/// Finds and decodes the `STATUS_INFO` attribute in a `CONNECT_NAK`/`ABORT`
/// message's attribute list, if present. Layout per `sstp_state_connect_nak`:
/// 3 reserved bytes + a 1-byte "which attribute this refers to" id, then a
/// 4-byte big-endian status code.
pub fn describe_status(attrs: &[Attr]) -> Option<String> {
    let attr = attrs.iter().find(|a| a.attr_type == AttrType::StatusInfo)?;
    if attr.data.len() < 8 {
        return Some(format!("malformed status-info attribute: {:02x?}", attr.data));
    }
    let referenced_attr = attr.data[3];
    let code = u32::from_be_bytes(attr.data[4..8].try_into().expect("checked length above"));
    Some(format!("{} (code {code}, attribute {referenced_attr})", status_reason(code)))
}

/// A fully decoded SSTP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    /// A data message: the payload is a raw PPP frame, ready to hand to the
    /// PPP layer as-is (no HDLC de-framing needed — see module docs).
    Data(Vec<u8>),
    /// A control message with its parsed attributes.
    Ctrl { msg_type: MsgType, attrs: Vec<Attr> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Fewer bytes than the smallest possible packet; caller should keep
    /// buffering and try again once more bytes arrive.
    Incomplete,
    /// `version` byte wasn't `PROTO_VERSION`.
    BadVersion(u8),
    /// The header's `length` field disagreed with the bytes actually
    /// available/consumed, or an attribute's length ran past the packet.
    Malformed(&'static str),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Incomplete => write!(f, "incomplete packet"),
            DecodeError::BadVersion(v) => write!(f, "unsupported SSTP version 0x{v:02x}"),
            DecodeError::Malformed(why) => write!(f, "malformed SSTP packet: {why}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Encodes an `SSTP_MSG_DATA` packet carrying a raw PPP frame as its
/// payload (`sstp_pkt_init(SSTP_MSG_DATA)` — no control header, no
/// attributes, flags byte is 0).
pub fn encode_data(ppp_frame: &[u8]) -> Vec<u8> {
    let total_len = PKT_HEADER_LEN + ppp_frame.len();
    let mut out = Vec::with_capacity(total_len);
    out.push(PROTO_VERSION);
    out.push(0); // flags: no CTRL bit set
    out.extend_from_slice(&(total_len as u16).to_be_bytes());
    out.extend_from_slice(ppp_frame);
    out
}

/// Encodes a control message with the given attributes
/// (`sstp_pkt_init(type)` + repeated `sstp_pkt_attr`).
pub fn encode_ctrl(msg_type: MsgType, attrs: &[(AttrType, &[u8])]) -> Vec<u8> {
    let mut out = vec![0u8; PKT_HEADER_LEN + CTRL_HEADER_LEN];
    out[0] = PROTO_VERSION;
    out[1] = FLAG_CTRL;
    out[4..6].copy_from_slice(&msg_type.to_u16().to_be_bytes());
    out[6..8].copy_from_slice(&(attrs.len() as u16).to_be_bytes());

    for (attr_type, data) in attrs {
        let attr_len = ATTR_HEADER_LEN + data.len();
        out.push(0); // reserved
        out.push(attr_type.to_u8());
        out.extend_from_slice(&(attr_len as u16).to_be_bytes());
        out.extend_from_slice(data);
    }

    let total_len = out.len() as u16;
    out[2..4].copy_from_slice(&total_len.to_be_bytes());
    out
}

/// Decodes exactly one packet from `buf`, which must contain *at least*
/// one complete packet (use [`PacketReader`] when reading off a stream that
/// doesn't respect message boundaries, e.g. a TCP/TLS socket).
pub fn decode(buf: &[u8]) -> Result<Packet, DecodeError> {
    if buf.len() < PKT_HEADER_LEN {
        return Err(DecodeError::Incomplete);
    }
    let version = buf[0];
    if version != PROTO_VERSION {
        return Err(DecodeError::BadVersion(version));
    }
    let flags = buf[1];
    let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if length < PKT_HEADER_LEN {
        return Err(DecodeError::Malformed("header length smaller than header itself"));
    }
    if buf.len() < length {
        return Err(DecodeError::Incomplete);
    }

    if flags & FLAG_CTRL == 0 {
        return Ok(Packet::Data(buf[PKT_HEADER_LEN..length].to_vec()));
    }

    if length < PKT_HEADER_LEN + CTRL_HEADER_LEN {
        return Err(DecodeError::Malformed("control packet shorter than control header"));
    }
    let msg_type = MsgType::from_u16(u16::from_be_bytes([buf[4], buf[5]]));
    let nattr = u16::from_be_bytes([buf[6], buf[7]]);

    let mut attrs = Vec::with_capacity(nattr as usize);
    let mut pos = PKT_HEADER_LEN + CTRL_HEADER_LEN;
    for _ in 0..nattr {
        if pos + ATTR_HEADER_LEN > length {
            return Err(DecodeError::Malformed("attribute header runs past packet end"));
        }
        let attr_type = AttrType::from_u8(buf[pos + 1]);
        let attr_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        if attr_len < ATTR_HEADER_LEN || pos + attr_len > length {
            return Err(DecodeError::Malformed("attribute length invalid or runs past packet end"));
        }
        let data = buf[pos + ATTR_HEADER_LEN..pos + attr_len].to_vec();
        attrs.push(Attr { attr_type, data });
        pos += attr_len;
    }

    Ok(Packet::Ctrl { msg_type, attrs })
}

/// Accumulates bytes read off a stream (TCP/TLS doesn't preserve SSTP
/// message boundaries) and yields complete packets as they become
/// available, buffering the remainder for next time.
#[derive(Default)]
pub struct PacketReader {
    buf: Vec<u8>,
}

impl PacketReader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed newly-received bytes in.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Pop the next complete packet, if one has fully arrived.
    ///
    /// Returns `Ok(None)` (not an error) when more bytes are needed —
    /// `DecodeError::Incomplete` from the underlying `decode()` is exactly
    /// that "come back later" signal, not a real failure, so it's collapsed
    /// here rather than surfaced to callers who'd otherwise have to special
    /// case it on every call.
    pub fn next_packet(&mut self) -> Result<Option<Packet>, DecodeError> {
        match decode(&self.buf) {
            Ok(pkt) => {
                // Re-derive the consumed length the same way `decode` did,
                // rather than threading it back out of `decode`'s return
                // value, to keep `decode`'s signature simple for the (more
                // common) single-packet-in-hand callers.
                let consumed = u16::from_be_bytes([self.buf[2], self.buf[3]]) as usize;
                self.buf.drain(0..consumed);
                Ok(Some(pkt))
            }
            Err(DecodeError::Incomplete) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_status_decodes_reference_status_codes() {
        // ATTR_MISSING (0x0a), referencing attribute id 4 (CRYPTO_BIND_REQ).
        let mut data = vec![0u8, 0, 0, 4];
        data.extend_from_slice(&0x0au32.to_be_bytes());
        let attrs = vec![Attr { attr_type: AttrType::StatusInfo, data }];
        let described = describe_status(&attrs).unwrap();
        assert!(described.contains("Attribute is missing"), "{described}");
        assert!(described.contains("code 10"), "{described}");
        assert!(described.contains("attribute 4"), "{described}");
    }

    #[test]
    fn describe_status_is_none_without_a_status_info_attribute() {
        let attrs = vec![Attr { attr_type: AttrType::EncapProtocol, data: vec![0, 1] }];
        assert_eq!(describe_status(&attrs), None);
    }

    #[test]
    fn describe_status_handles_truncated_attribute_without_panicking() {
        let attrs = vec![Attr { attr_type: AttrType::StatusInfo, data: vec![0, 0, 0] }];
        let described = describe_status(&attrs).unwrap();
        assert!(described.contains("malformed"), "{described}");
    }

    #[test]
    fn unknown_status_code_has_a_fallback_message() {
        assert_eq!(status_reason(0xFF), "Unknown Status Attribute");
    }

    #[test]
    fn data_packet_round_trips() {
        let ppp_frame = b"\xff\x03\xc0\x21hello-ppp-frame";
        let wire = encode_data(ppp_frame);
        assert_eq!(wire[0], PROTO_VERSION);
        assert_eq!(wire[1], 0, "data packets must not set the CTRL flag");
        match decode(&wire).unwrap() {
            Packet::Data(payload) => assert_eq!(payload, ppp_frame),
            other => panic!("expected Data, got {other:?}"),
        }
    }

    /// Matches `sstp_state_send_request()` in sstp-state.c exactly: a
    /// CONNECT_REQ with one ENCAP_PROTO attribute carrying
    /// `htons(SSTP_ENCAP_PROTO_PPP)` i.e. the 2 bytes 0x00 0x01.
    #[test]
    fn connect_request_matches_reference_shape() {
        let proto_ppp: [u8; 2] = 1u16.to_be_bytes();
        let wire = encode_ctrl(MsgType::ConnectRequest, &[(AttrType::EncapProtocol, &proto_ppp)]);

        // 4 (pkt) + 4 (ctrl) + 4 (attr header) + 2 (attr data) = 14 bytes
        assert_eq!(wire.len(), 14);
        assert_eq!(wire[1] & FLAG_CTRL, FLAG_CTRL);

        match decode(&wire).unwrap() {
            Packet::Ctrl { msg_type, attrs } => {
                assert_eq!(msg_type, MsgType::ConnectRequest);
                assert_eq!(attrs.len(), 1);
                assert_eq!(attrs[0].attr_type, AttrType::EncapProtocol);
                assert_eq!(attrs[0].data, proto_ppp);
            }
            other => panic!("expected Ctrl, got {other:?}"),
        }
    }

    /// Matches `sstp_state_connect_ack()`'s expectations: a
    /// CRYPTO_BIND_REQ attribute whose 36-byte payload is a 4-byte header
    /// (hash-protocol in byte index 3) followed by a 32-byte nonce.
    #[test]
    fn connect_ack_crypto_bind_req_decodes_hash_protocol_and_nonce() {
        let mut payload = vec![0u8; 36];
        payload[3] = 0x02; // SSTP_PROTO_HASH_SHA256
        let nonce: Vec<u8> = (0u8..32).collect();
        payload[4..].copy_from_slice(&nonce);

        let wire = encode_ctrl(MsgType::ConnectAck, &[(AttrType::CryptoBindRequest, &payload)]);
        match decode(&wire).unwrap() {
            Packet::Ctrl { msg_type, attrs } => {
                assert_eq!(msg_type, MsgType::ConnectAck);
                let attr = &attrs[0];
                assert_eq!(attr.attr_type, AttrType::CryptoBindRequest);
                assert_eq!(attr.data.len(), 36);
                let hash_proto = attr.data[3];
                let received_nonce = &attr.data[4..];
                assert_eq!(hash_proto, 0x02);
                assert_eq!(received_nonce, &nonce[..]);
            }
            other => panic!("expected Ctrl, got {other:?}"),
        }
    }

    #[test]
    fn multiple_attributes_round_trip_in_order() {
        let a = [0xAAu8, 0xBB];
        let b = [0x01u8, 0x02, 0x03];
        let wire = encode_ctrl(MsgType::Connected, &[(AttrType::CryptoBind, &a), (AttrType::StatusInfo, &b)]);
        match decode(&wire).unwrap() {
            Packet::Ctrl { attrs, .. } => {
                assert_eq!(attrs.len(), 2);
                assert_eq!(attrs[0].data, a);
                assert_eq!(attrs[1].data, b);
            }
            other => panic!("expected Ctrl, got {other:?}"),
        }
    }

    #[test]
    fn rejects_wrong_version() {
        let mut wire = encode_data(b"x");
        wire[0] = 0x20;
        assert_eq!(decode(&wire), Err(DecodeError::BadVersion(0x20)));
    }

    #[test]
    fn empty_and_truncated_buffers_are_incomplete_not_a_hard_error() {
        assert_eq!(decode(&[]), Err(DecodeError::Incomplete));
        let wire = encode_ctrl(MsgType::EchoRequest, &[]);
        // Every truncation point short of the full packet must say
        // "incomplete", never panic and never misparse.
        for cut in 0..wire.len() {
            assert_eq!(decode(&wire[..cut]), Err(DecodeError::Incomplete), "cut at {cut}");
        }
    }

    #[test]
    fn attribute_length_overrunning_packet_is_malformed_not_a_panic() {
        let mut wire = encode_ctrl(MsgType::ConnectAck, &[(AttrType::StatusInfo, &[1, 2, 3, 4])]);
        // Corrupt the attribute's length field to claim more than exists.
        let attr_len_pos = PKT_HEADER_LEN + CTRL_HEADER_LEN + 2;
        wire[attr_len_pos..attr_len_pos + 2].copy_from_slice(&0xFFFFu16.to_be_bytes());
        assert!(matches!(decode(&wire), Err(DecodeError::Malformed(_))));
    }

    #[test]
    fn packet_reader_reassembles_fragmented_stream() {
        let pkt1 = encode_data(b"first-frame");
        let pkt2 = encode_ctrl(MsgType::EchoRequest, &[]);

        let mut all = Vec::new();
        all.extend_from_slice(&pkt1);
        all.extend_from_slice(&pkt2);

        let mut reader = PacketReader::new();
        // Feed one byte at a time to prove partial reads never misfire.
        for byte in &all {
            reader.push(&[*byte]);
        }

        let first = reader.next_packet().unwrap().expect("first packet ready");
        assert_eq!(first, Packet::Data(b"first-frame".to_vec()));

        let second = reader.next_packet().unwrap().expect("second packet ready");
        match second {
            Packet::Ctrl { msg_type, .. } => assert_eq!(msg_type, MsgType::EchoRequest),
            other => panic!("expected Ctrl, got {other:?}"),
        }

        assert!(reader.next_packet().unwrap().is_none(), "nothing left to read");
    }

    #[test]
    fn packet_reader_handles_two_packets_delivered_in_one_chunk() {
        let mut all = encode_data(b"a");
        all.extend_from_slice(&encode_data(b"bb"));

        let mut reader = PacketReader::new();
        reader.push(&all);

        assert_eq!(reader.next_packet().unwrap(), Some(Packet::Data(b"a".to_vec())));
        assert_eq!(reader.next_packet().unwrap(), Some(Packet::Data(b"bb".to_vec())));
        assert_eq!(reader.next_packet().unwrap(), None);
    }
}
