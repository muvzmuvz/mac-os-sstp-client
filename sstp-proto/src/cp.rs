//! Shared framing for PPP's "Configuration Protocols" (RFC 1661 §5): the
//! Code/Identifier/Length/Data header and TLV options both LCP and IPCP
//! build on. Kept separate from the LCP/IPCP-specific negotiation logic in
//! `lcp.rs`/`ipcp.rs` since the wire format itself is identical between
//! them (only the set of valid option types and how to react to Nak/Reject
//! for each differs).

/// RFC 1661 §5 control codes, shared by every "xCP" protocol (LCP, IPCP,
/// ...). Not every code applies to every protocol (Protocol-Reject and the
/// Echo/Discard codes are LCP-only), but the header format is identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    ConfigureRequest,
    ConfigureAck,
    ConfigureNak,
    ConfigureReject,
    TerminateRequest,
    TerminateAck,
    CodeReject,
    ProtocolReject,
    EchoRequest,
    EchoReply,
    DiscardRequest,
    Unknown(u8),
}

impl Code {
    fn to_u8(self) -> u8 {
        match self {
            Code::ConfigureRequest => 1,
            Code::ConfigureAck => 2,
            Code::ConfigureNak => 3,
            Code::ConfigureReject => 4,
            Code::TerminateRequest => 5,
            Code::TerminateAck => 6,
            Code::CodeReject => 7,
            Code::ProtocolReject => 8,
            Code::EchoRequest => 9,
            Code::EchoReply => 10,
            Code::DiscardRequest => 11,
            Code::Unknown(v) => v,
        }
    }

    fn from_u8(v: u8) -> Code {
        match v {
            1 => Code::ConfigureRequest,
            2 => Code::ConfigureAck,
            3 => Code::ConfigureNak,
            4 => Code::ConfigureReject,
            5 => Code::TerminateRequest,
            6 => Code::TerminateAck,
            7 => Code::CodeReject,
            8 => Code::ProtocolReject,
            9 => Code::EchoRequest,
            10 => Code::EchoReply,
            11 => Code::DiscardRequest,
            other => Code::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub code: Code,
    pub id: u8,
    /// For Configure-* codes: the encoded option TLVs (see [`encode_options`]
    /// / [`decode_options`]). For everything else: the raw payload (e.g. the
    /// 4-byte magic number of an Echo-Request, or the rejected protocol
    /// number + frame for Protocol-Reject).
    pub data: Vec<u8>,
}

pub fn encode(code: Code, id: u8, data: &[u8]) -> Vec<u8> {
    let len = 4 + data.len();
    let mut out = Vec::with_capacity(len);
    out.push(code.to_u8());
    out.push(id);
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Returns `None` if `buf` doesn't hold at least one complete, well-formed
/// frame (caller's transport already delivers whole PPP frames — one per
/// SSTP_MSG_DATA packet — so there's no partial-buffering concern here
/// unlike [`crate::packet::PacketReader`]).
pub fn decode(buf: &[u8]) -> Option<Frame> {
    if buf.len() < 4 {
        return None;
    }
    let code = Code::from_u8(buf[0]);
    let id = buf[1];
    let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if len < 4 || len > buf.len() {
        return None;
    }
    Some(Frame { code, id, data: buf[4..len].to_vec() })
}

/// A single Configure-* option: `Type(1) + Length(1, inclusive of these two
/// bytes) + Data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opt {
    pub kind: u8,
    pub data: Vec<u8>,
}

impl Opt {
    pub fn new(kind: u8, data: impl Into<Vec<u8>>) -> Self {
        Opt { kind, data: data.into() }
    }
}

pub fn encode_options(opts: &[Opt]) -> Vec<u8> {
    let mut out = Vec::new();
    for opt in opts {
        out.push(opt.kind);
        out.push((2 + opt.data.len()) as u8);
        out.extend_from_slice(&opt.data);
    }
    out
}

/// Malformed trailing bytes (an option claiming a length that runs past the
/// buffer) stop parsing and return what was successfully decoded so far,
/// rather than erroring out entirely — matches how real PPP peers are
/// forgiving of trailing garbage in practice, and there's no scenario where
/// silently ignoring undecodable trailing bytes is worse than crashing the
/// negotiation outright.
pub fn decode_options(buf: &[u8]) -> Vec<Opt> {
    let mut opts = Vec::new();
    let mut pos = 0;
    while pos + 2 <= buf.len() {
        let kind = buf[pos];
        let len = buf[pos + 1] as usize;
        if len < 2 || pos + len > buf.len() {
            break;
        }
        opts.push(Opt { kind, data: buf[pos + 2..pos + len].to_vec() });
        pos += len;
    }
    opts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trips() {
        let wire = encode(Code::ConfigureRequest, 7, &[0xAA, 0xBB]);
        let frame = decode(&wire).unwrap();
        assert_eq!(frame.code, Code::ConfigureRequest);
        assert_eq!(frame.id, 7);
        assert_eq!(frame.data, vec![0xAA, 0xBB]);
    }

    #[test]
    fn options_round_trip() {
        let opts = vec![Opt::new(5, [0x01, 0x02, 0x03, 0x04]), Opt::new(7, [])];
        let wire = encode_options(&opts);
        let decoded = decode_options(&wire);
        assert_eq!(decoded, opts);
    }

    #[test]
    fn decode_stops_cleanly_on_truncated_option() {
        // A 4-byte option (kind, len=4, 2 data bytes) followed by a
        // dangling byte that can't form another full option.
        let mut buf = encode_options(&[Opt::new(1, [0xAA, 0xBB])]);
        buf.push(0x99);
        let decoded = decode_options(&buf);
        assert_eq!(decoded, vec![Opt::new(1, [0xAA, 0xBB])]);
    }

    #[test]
    fn decode_frame_rejects_length_past_buffer() {
        let mut wire = encode(Code::ConfigureAck, 1, &[1, 2, 3]);
        wire[2..4].copy_from_slice(&0xFFFFu16.to_be_bytes());
        assert_eq!(decode(&wire), None);
    }

    /// Matches this exact real-world LCP ConfReq observed against the
    /// production server this session: magic number + PFC + ACFC options.
    #[test]
    fn decodes_captured_real_world_lcp_confreq() {
        // sent [LCP ConfReq id=0x1 <magic 0x6770957f> <pcomp> <accomp>]
        let opts = vec![Opt::new(5, 0x6770957fu32.to_be_bytes()), Opt::new(7, []), Opt::new(8, [])];
        let data = encode_options(&opts);
        let wire = encode(Code::ConfigureRequest, 1, &data);
        let frame = decode(&wire).unwrap();
        assert_eq!(decode_options(&frame.data), opts);
    }
}
