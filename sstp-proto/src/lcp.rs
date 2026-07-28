//! LCP (Link Control Protocol, RFC 1661) negotiation — the first phase of
//! PPP, run over `ppp::Protocol::Lcp` frames. Implements the practical
//! subset of RFC 1661 §4's automaton needed for a client talking to one
//! well-behaved peer over an already-reliable, already-ordered transport
//! (TLS/SSTP, not a lossy serial line): no retransmission timers, since a
//! dropped/reordered frame simply can't happen here the way it could over
//! a modem. `receive()` is driven purely by frames as they arrive.
//!
//! Option choices and the observed accept/reject pattern (offer PFC/ACFC,
//! expect them rejected, keep going) are cross-checked against this
//! session's real captured negotiation logs against the production server
//! (`~/Library/Logs/sstp-gui.log`), not just RFC 1661's text.

use crate::cp::{self, Opt};
use crate::ppp;

const OPT_MRU: u8 = 1;
const OPT_ACCM: u8 = 2;
const OPT_AUTH_PROTOCOL: u8 = 3;
const OPT_MAGIC_NUMBER: u8 = 5;
const OPT_PFC: u8 = 7;
const OPT_ACFC: u8 = 8;

/// MS-CHAPv2's algorithm byte within the Authentication-Protocol option
/// when the protocol is CHAP (RFC 2759 §4 references RFC 1994's CHAP
/// option format; 0x81 is the MS-CHAP-2 algorithm value observed in every
/// captured negotiation this session, e.g. `<auth chap MS-v2>`).
pub const CHAP_ALGORITHM_MSCHAPV2: u8 = 0x81;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerAuthRequirement {
    pub protocol: u16,
    pub algorithm: u8,
}

impl PeerAuthRequirement {
    pub fn is_mschapv2(&self) -> bool {
        self.protocol == ppp::Protocol::Chap.to_u16() && self.algorithm == CHAP_ALGORITHM_MSCHAPV2
    }
}

#[derive(Debug, Default)]
pub struct LcpResult {
    /// Frames to send, in order, in response to whatever was just received.
    pub to_send: Vec<Vec<u8>>,
    /// Whether LCP is in the Opened state (both directions configured)
    /// after processing this event.
    pub up: bool,
}

pub struct Lcp {
    identifier: u8,
    magic: u32,
    desired: Vec<Opt>,
    last_sent_id: Option<u8>,
    local_up: bool,
    remote_up: bool,
    peer_auth: Option<PeerAuthRequirement>,
}

impl Lcp {
    pub fn new() -> Self {
        let magic: u32 = rand::random();
        Lcp {
            identifier: 0,
            magic,
            // MRU/ACCM deliberately not offered: we're not a real serial
            // line, so async-escaping (ACCM) is meaningless, and the
            // default 1500-byte MRU is fine. PFC/ACFC are offered because
            // real pppd does and it's cheap, even though this session's
            // captured traces show the production server always rejects
            // them -- falling back to uncompressed framing either way.
            desired: vec![Opt::new(OPT_MAGIC_NUMBER, magic.to_be_bytes()), Opt::new(OPT_PFC, []), Opt::new(OPT_ACFC, [])],
            last_sent_id: None,
            local_up: false,
            remote_up: false,
            peer_auth: None,
        }
    }

    pub fn is_up(&self) -> bool {
        self.local_up && self.remote_up
    }

    pub fn peer_auth_requirement(&self) -> Option<PeerAuthRequirement> {
        self.peer_auth
    }

    /// The initial Configure-Request; call once to kick off negotiation.
    pub fn start(&mut self) -> Vec<u8> {
        self.send_config_request()
    }

    fn send_config_request(&mut self) -> Vec<u8> {
        self.identifier = self.identifier.wrapping_add(1);
        self.last_sent_id = Some(self.identifier);
        let data = cp::encode_options(&self.desired);
        cp::encode(cp::Code::ConfigureRequest, self.identifier, &data)
    }

    /// Feed one received LCP frame (the PPP payload after stripping the
    /// 2-byte protocol number) through the state machine.
    pub fn receive(&mut self, data: &[u8]) -> LcpResult {
        let mut to_send = Vec::new();

        let Some(frame) = cp::decode(data) else {
            return LcpResult { to_send, up: self.is_up() };
        };

        match frame.code {
            cp::Code::ConfigureRequest => {
                let peer_opts = cp::decode_options(&frame.data);
                let (nak, reject) = self.evaluate_peer_options(&peer_opts);
                if !reject.is_empty() {
                    to_send.push(cp::encode(cp::Code::ConfigureReject, frame.id, &cp::encode_options(&reject)));
                    self.remote_up = false;
                } else if !nak.is_empty() {
                    to_send.push(cp::encode(cp::Code::ConfigureNak, frame.id, &cp::encode_options(&nak)));
                    self.remote_up = false;
                } else {
                    to_send.push(cp::encode(cp::Code::ConfigureAck, frame.id, &frame.data));
                    self.remote_up = true;
                }
            }
            cp::Code::ConfigureAck => {
                if self.last_sent_id == Some(frame.id) {
                    self.local_up = true;
                }
            }
            cp::Code::ConfigureNak => {
                if self.last_sent_id == Some(frame.id) {
                    self.apply_nak(&cp::decode_options(&frame.data));
                    self.local_up = false;
                    to_send.push(self.send_config_request());
                }
            }
            cp::Code::ConfigureReject => {
                if self.last_sent_id == Some(frame.id) {
                    self.apply_reject(&cp::decode_options(&frame.data));
                    self.local_up = false;
                    to_send.push(self.send_config_request());
                }
            }
            cp::Code::EchoRequest => {
                // RFC 1661 §5.7: Echo-Reply data starts with our own magic
                // number, followed by whatever the peer sent after theirs.
                let mut reply = self.magic.to_be_bytes().to_vec();
                if frame.data.len() > 4 {
                    reply.extend_from_slice(&frame.data[4..]);
                }
                to_send.push(cp::encode(cp::Code::EchoReply, frame.id, &reply));
            }
            cp::Code::TerminateRequest => {
                to_send.push(cp::encode(cp::Code::TerminateAck, frame.id, &[]));
                self.local_up = false;
                self.remote_up = false;
            }
            _ => {}
        }

        LcpResult { to_send, up: self.is_up() }
    }

    /// Builds an LCP Protocol-Reject frame for a PPP frame received under a
    /// protocol number we don't implement (see `ppp::Protocol::Unknown`).
    /// `protocol_and_payload` is the *original* 2-byte protocol number
    /// followed by (as much of) the original payload as fits, matching
    /// `sent [LCP ProtRej id=0x3 82 81 01 01 00 04]` from this session's
    /// captured logs (`82 81` = the rejected protocol number 0x8281,
    /// followed by that frame's own payload).
    pub fn build_protocol_reject(&mut self, protocol_and_payload: &[u8]) -> Vec<u8> {
        self.identifier = self.identifier.wrapping_add(1);
        cp::encode(cp::Code::ProtocolReject, self.identifier, protocol_and_payload)
    }

    fn evaluate_peer_options(&mut self, opts: &[Opt]) -> (Vec<Opt>, Vec<Opt>) {
        let mut nak = Vec::new();
        let mut reject = Vec::new();

        for opt in opts {
            match opt.kind {
                OPT_MAGIC_NUMBER => {
                    if opt.data.len() != 4 {
                        reject.push(opt.clone());
                        continue;
                    }
                    let peer_magic = u32::from_be_bytes(opt.data.clone().try_into().unwrap());
                    if peer_magic == self.magic {
                        // Loopback per RFC 1661 §6.4: ask the peer to pick
                        // a different magic number.
                        let new_magic: u32 = rand::random();
                        nak.push(Opt::new(OPT_MAGIC_NUMBER, new_magic.to_be_bytes()));
                    }
                }
                OPT_AUTH_PROTOCOL => {
                    if opt.data.len() < 2 {
                        reject.push(opt.clone());
                        continue;
                    }
                    let proto = u16::from_be_bytes([opt.data[0], opt.data[1]]);
                    let algo = opt.data.get(2).copied();
                    if proto == ppp::Protocol::Chap.to_u16() && algo == Some(CHAP_ALGORITHM_MSCHAPV2) {
                        self.peer_auth = Some(PeerAuthRequirement { protocol: proto, algorithm: CHAP_ALGORITHM_MSCHAPV2 });
                    } else {
                        // We only speak MS-CHAPv2; ask for it explicitly
                        // rather than rejecting outright, so a peer that's
                        // flexible about auth method can still connect.
                        let chap = ppp::Protocol::Chap.to_u16();
                        nak.push(Opt::new(OPT_AUTH_PROTOCOL, [(chap >> 8) as u8, chap as u8, CHAP_ALGORITHM_MSCHAPV2]));
                    }
                }
                OPT_PFC | OPT_ACFC | OPT_MRU | OPT_ACCM => {
                    // We don't need any particular value here and don't do
                    // HDLC framing ourselves, so anything the peer proposes
                    // is fine -- accept as-is (falls through to the ack).
                }
                _ => reject.push(opt.clone()),
            }
        }

        (nak, reject)
    }

    fn apply_nak(&mut self, suggested: &[Opt]) {
        for s in suggested {
            if let Some(existing) = self.desired.iter_mut().find(|o| o.kind == s.kind) {
                existing.data = s.data.clone();
            }
            if s.kind == OPT_MAGIC_NUMBER && s.data.len() == 4 {
                self.magic = u32::from_be_bytes(s.data.clone().try_into().unwrap());
            }
        }
    }

    fn apply_reject(&mut self, rejected: &[Opt]) {
        self.desired.retain(|o| !rejected.iter().any(|r| r.kind == o.kind));
    }
}

impl Default for Lcp {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_sends_a_configure_request_with_magic_pfc_acfc() {
        let mut lcp = Lcp::new();
        let wire = lcp.start();
        let frame = cp::decode(&wire).unwrap();
        assert_eq!(frame.code, cp::Code::ConfigureRequest);
        let opts = cp::decode_options(&frame.data);
        let kinds: Vec<u8> = opts.iter().map(|o| o.kind).collect();
        assert!(kinds.contains(&OPT_MAGIC_NUMBER));
        assert!(kinds.contains(&OPT_PFC));
        assert!(kinds.contains(&OPT_ACFC));
    }

    #[test]
    fn peer_confreq_with_supported_options_gets_acked_and_opens_remote() {
        let mut lcp = Lcp::new();
        lcp.start();

        let peer_req = cp::encode(
            cp::Code::ConfigureRequest,
            1,
            &cp::encode_options(&[Opt::new(OPT_AUTH_PROTOCOL, [0xC2, 0x23, CHAP_ALGORITHM_MSCHAPV2]), Opt::new(OPT_MAGIC_NUMBER, 0xCCDA096Cu32.to_be_bytes())]),
        );
        let result = lcp.receive(&peer_req);

        assert_eq!(result.to_send.len(), 1);
        let reply = cp::decode(&result.to_send[0]).unwrap();
        assert_eq!(reply.code, cp::Code::ConfigureAck);
        assert_eq!(reply.id, 1);
        assert!(lcp.peer_auth_requirement().unwrap().is_mschapv2());
        assert!(!result.up, "remote is up but local isn't yet");
    }

    #[test]
    fn both_directions_acking_brings_lcp_up() {
        let mut lcp = Lcp::new();
        let our_req = lcp.start();
        let our_id = cp::decode(&our_req).unwrap().id;

        // Peer acks exactly what we asked for.
        let peer_ack = cp::encode(cp::Code::ConfigureAck, our_id, &cp::decode(&our_req).unwrap().data);
        let r1 = lcp.receive(&peer_ack);
        assert!(!r1.up, "only local side is up so far");

        // Peer sends its own (trivial) request, which we accept.
        let peer_req = cp::encode(cp::Code::ConfigureRequest, 5, &[]);
        let r2 = lcp.receive(&peer_req);
        assert!(r2.up, "both directions configured now");
    }

    /// Replays this session's real captured exchange: our first ConfReq
    /// (magic+PFC+ACFC) gets ConfRej'd for PFC/ACFC, we drop them and
    /// resend with just magic, which gets ConfAck'd.
    #[test]
    fn reproduces_captured_pfc_acfc_rejection_then_success() {
        let mut lcp = Lcp::new();
        let first_req = lcp.start();
        let first_id = cp::decode(&first_req).unwrap().id;

        let rejected = cp::encode(cp::Code::ConfigureReject, first_id, &cp::encode_options(&[Opt::new(OPT_PFC, []), Opt::new(OPT_ACFC, [])]));
        let result = lcp.receive(&rejected);
        assert_eq!(result.to_send.len(), 1);
        let second_req = cp::decode(&result.to_send[0]).unwrap();
        assert_eq!(second_req.code, cp::Code::ConfigureRequest);
        let remaining_kinds: Vec<u8> = cp::decode_options(&second_req.data).iter().map(|o| o.kind).collect();
        assert_eq!(remaining_kinds, vec![OPT_MAGIC_NUMBER], "PFC/ACFC must be dropped after rejection");

        let ack = cp::encode(cp::Code::ConfigureAck, second_req.id, &second_req.data);
        let final_result = lcp.receive(&ack);
        assert!(!final_result.up, "local is up, but remote side hasn't sent its own request yet");
    }

    #[test]
    fn magic_number_nak_adopts_suggested_value_and_resends() {
        let mut lcp = Lcp::new();
        let first_req = lcp.start();
        let first_id = cp::decode(&first_req).unwrap().id;

        let suggested: u32 = 0x1234_5678;
        let nak = cp::encode(cp::Code::ConfigureNak, first_id, &cp::encode_options(&[Opt::new(OPT_MAGIC_NUMBER, suggested.to_be_bytes())]));
        let result = lcp.receive(&nak);
        let resend = cp::decode(&result.to_send[0]).unwrap();
        let opts = cp::decode_options(&resend.data);
        let magic_opt = opts.iter().find(|o| o.kind == OPT_MAGIC_NUMBER).unwrap();
        assert_eq!(magic_opt.data, suggested.to_be_bytes());
    }

    #[test]
    fn unsupported_auth_protocol_is_naked_toward_mschapv2() {
        let mut lcp = Lcp::new();
        lcp.start();

        // Peer proposes plain MD5-CHAP (algorithm 0x05) instead of MS-CHAPv2.
        let peer_req = cp::encode(cp::Code::ConfigureRequest, 1, &cp::encode_options(&[Opt::new(OPT_AUTH_PROTOCOL, [0xC2, 0x23, 0x05])]));
        let result = lcp.receive(&peer_req);
        let reply = cp::decode(&result.to_send[0]).unwrap();
        assert_eq!(reply.code, cp::Code::ConfigureNak);
        let opts = cp::decode_options(&reply.data);
        assert_eq!(opts[0].data, vec![0xC2, 0x23, CHAP_ALGORITHM_MSCHAPV2]);
        assert!(lcp.peer_auth_requirement().is_none(), "must not record an unaccepted auth proposal");
    }

    #[test]
    fn unknown_option_is_rejected() {
        let mut lcp = Lcp::new();
        lcp.start();
        let peer_req = cp::encode(cp::Code::ConfigureRequest, 1, &cp::encode_options(&[Opt::new(200, [0x01])]));
        let result = lcp.receive(&peer_req);
        let reply = cp::decode(&result.to_send[0]).unwrap();
        assert_eq!(reply.code, cp::Code::ConfigureReject);
    }

    #[test]
    fn echo_request_gets_a_reply_with_our_magic() {
        let mut lcp = Lcp::new();
        lcp.start();
        let echo_req = cp::encode(cp::Code::EchoRequest, 9, &0xDEADBEEFu32.to_be_bytes());
        let result = lcp.receive(&echo_req);
        let reply = cp::decode(&result.to_send[0]).unwrap();
        assert_eq!(reply.code, cp::Code::EchoReply);
        assert_eq!(reply.id, 9);
        assert_eq!(reply.data.len(), 4);
    }

    #[test]
    fn terminate_request_is_acked_and_closes_the_link() {
        let mut lcp = Lcp::new();
        lcp.start();
        let peer_req = cp::encode(cp::Code::ConfigureRequest, 1, &[]);
        lcp.receive(&peer_req);

        let term = cp::encode(cp::Code::TerminateRequest, 2, &[]);
        let result = lcp.receive(&term);
        let reply = cp::decode(&result.to_send[0]).unwrap();
        assert_eq!(reply.code, cp::Code::TerminateAck);
        assert!(!result.up);
        assert!(!lcp.is_up());
    }

    #[test]
    fn protocol_reject_matches_captured_shape() {
        let mut lcp = Lcp::new();
        // Rejected protocol 0x8281 followed by its original payload, as
        // seen verbatim in this session's logs: "sent [LCP ProtRej id=0x3
        // 82 81 01 01 00 04]".
        let rejected_payload: [u8; 6] = [0x82, 0x81, 0x01, 0x01, 0x00, 0x04];
        let wire = lcp.build_protocol_reject(&rejected_payload);
        let frame = cp::decode(&wire).unwrap();
        assert_eq!(frame.code, cp::Code::ProtocolReject);
        assert_eq!(frame.data, rejected_payload);
    }
}
