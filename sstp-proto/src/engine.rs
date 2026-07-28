//! The SSTP+PPP client protocol engine: everything from `CONNECT_REQ`
//! through PPP negotiation to the final `CONNECTED` crypto-bind message,
//! and steady-state data forwarding/keepalive/disconnect afterward.
//!
//! Deliberately synchronous and I/O-free — `on_packet` takes an
//! already-decoded [`crate::packet::Packet`] and returns a list of
//! [`EngineEvent`]s (bytes to write verbatim to the transport, IP packets
//! to deliver to the local network stack, or lifecycle notifications). This
//! is what makes the entire handshake unit-testable without a live server
//! or TLS connection: the async I/O loop that owns the actual TLS stream
//! and a [`crate::packet::PacketReader`] is a thin, mostly untested-by-
//! necessity shim around this engine, not where the protocol logic lives.

use sha1::{Digest as _, Sha1};
use sha2::Sha256;

use crate::chap_fsm::{self, PendingResponse};
use crate::cmac::{self, HashAlgo};
use crate::cp;
use crate::ipcp::{Ipcp, NegotiatedConfig};
use crate::lcp::Lcp;
use crate::mppe::{self, MppeKeys};
use crate::packet::{self, AttrType, MsgType, Packet};
use crate::ppp;

#[derive(Debug)]
pub enum EngineEvent {
    /// Bytes ready to write verbatim to the TLS stream — already fully
    /// SSTP-packet-encoded (control or data), so the I/O layer never needs
    /// to know about `packet.rs` at all.
    Send(Vec<u8>),
    /// A human-readable breadcrumb of PPP/CHAP negotiation progress (which
    /// frame arrived, what we're doing about it) — not needed for the
    /// protocol to function, only for diagnosing a live failure after the
    /// fact without a packet capture. Added after a live session against
    /// the production server stalled somewhere in LCP/CHAP with no more
    /// specific error than an eventual server-initiated ABORT; this is what
    /// pinpoints exactly which negotiation step never completed.
    Trace(String),
    /// A raw IPv4 packet decapsulated from the tunnel; hand it to the local
    /// `utun` interface.
    DeliverIpPacket(Vec<u8>),
    /// PPP negotiation and the SSTP crypto-bind both completed; the tunnel
    /// is ready for traffic. `to_send` (from this same call) already
    /// contains the `CONNECTED` message to write before this event is
    /// acted on.
    Established { negotiated: NegotiatedConfig, mppe_keys: MppeKeys },
    /// The server ended the session (DISCONNECT/DISCONNECT_ACK exchange
    /// completed, or it sent DISCONNECT_ACK to *our* disconnect request).
    Disconnected,
    /// Unrecoverable protocol error; the caller should close the
    /// connection. Never a panic — every malformed-input path in this
    /// engine returns this instead.
    Fatal(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    WaitConnectAck,
    Lcp,
    Chap,
    Ipcp,
    Established,
}

pub struct Engine {
    username: String,
    password: String,
    cert_hash_sha1: [u8; 32],
    cert_hash_sha256: [u8; 32],
    lcp: Lcp,
    ipcp: Ipcp,
    phase: Phase,
    hash_algo: Option<HashAlgo>,
    server_nonce: Option<[u8; 32]>,
    pending_chap: Option<PendingResponse>,
    auth_challenge: Option<[u8; 16]>,
    mppe_keys: Option<MppeKeys>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the password, even in debug logs.
        f.debug_struct("Engine").field("username", &self.username).field("phase", &self.phase).finish_non_exhaustive()
    }
}

impl Engine {
    /// `server_cert_der` is the DER-encoded certificate the TLS layer saw
    /// from the peer — grabbed once up front so `Engine` never needs to
    /// touch TLS state itself; both SHA1 and SHA256 hashes are precomputed
    /// since the server's `CONNECT_ACK` (not anything we control) decides
    /// which one the crypto-bind step actually uses.
    pub fn new(username: impl Into<String>, password: impl Into<String>, server_cert_der: &[u8]) -> Self {
        let mut cert_hash_sha1 = [0u8; 32];
        cert_hash_sha1[..20].copy_from_slice(&Sha1::digest(server_cert_der));
        let cert_hash_sha256: [u8; 32] = Sha256::digest(server_cert_der).into();

        Engine {
            username: username.into(),
            password: password.into(),
            cert_hash_sha1,
            cert_hash_sha256,
            lcp: Lcp::new(),
            ipcp: Ipcp::new(),
            phase: Phase::WaitConnectAck,
            hash_algo: None,
            server_nonce: None,
            pending_chap: None,
            auth_challenge: None,
            mppe_keys: None,
        }
    }

    /// Builds the initial `CONNECT_REQ`; call once to start the handshake.
    pub fn start(&self) -> Vec<u8> {
        let proto: u16 = 0x0001; // SSTP_ENCAP_PROTO_PPP
        packet::encode_ctrl(MsgType::ConnectRequest, &[(AttrType::EncapProtocol, &proto.to_be_bytes())])
    }

    /// A `DISCONNECT` message for the caller to send when the user
    /// initiates a disconnect; wait for the resulting `Disconnected` event
    /// (from the server's `DISCONNECT_ACK`) with a bounded timeout before
    /// force-closing the transport, since a client-owned tokio task can't
    /// hang the way a killed pppd process used to.
    pub fn build_disconnect(&self) -> Vec<u8> {
        packet::encode_ctrl(MsgType::Disconnect, &[])
    }

    /// An `ECHO_REQUEST` for the caller's idle timer to send — the
    /// reference implementation fires one after 60s of receiving nothing at
    /// all, and gives up after 4 consecutive unanswered echoes (~4 minutes
    /// of total silence); replicate that policy in the I/O loop that owns
    /// the actual timer, since `Engine` itself has no concept of time.
    pub fn build_echo_request(&self) -> Vec<u8> {
        packet::encode_ctrl(MsgType::EchoRequest, &[])
    }

    /// Feed one fully-decoded packet through the engine.
    pub fn on_packet(&mut self, pkt: Packet) -> Vec<EngineEvent> {
        match pkt {
            Packet::Ctrl { msg_type, attrs } => self.on_ctrl(msg_type, &attrs),
            Packet::Data(ppp_frame) => self.on_ppp_frame(&ppp_frame),
        }
    }

    fn on_ctrl(&mut self, msg_type: MsgType, attrs: &[packet::Attr]) -> Vec<EngineEvent> {
        match msg_type {
            MsgType::ConnectAck => self.on_connect_ack(attrs),
            MsgType::ConnectNak => {
                let reason = packet::describe_status(attrs).unwrap_or_else(|| "no status info given".to_string());
                vec![EngineEvent::Fatal(format!("server sent CONNECT_NAK: {reason}"))]
            }
            MsgType::Abort => {
                let reason = packet::describe_status(attrs).unwrap_or_else(|| "no status info given".to_string());
                vec![EngineEvent::Fatal(format!("server aborted the connection: {reason}"))]
            }
            MsgType::Disconnect => {
                vec![EngineEvent::Send(packet::encode_ctrl(MsgType::DisconnectAck, &[])), EngineEvent::Disconnected]
            }
            MsgType::DisconnectAck => vec![EngineEvent::Disconnected],
            MsgType::EchoRequest => vec![EngineEvent::Send(packet::encode_ctrl(MsgType::EchoReply, &[]))],
            MsgType::EchoReply => vec![],
            // We're always the client: CONNECT_REQUEST and CONNECTED are
            // messages *we* send, never receive. A well-behaved server
            // won't send either back to us; ignore rather than fault if
            // one somehow does.
            MsgType::ConnectRequest | MsgType::Connected | MsgType::Unknown(_) => vec![],
        }
    }

    fn on_connect_ack(&mut self, attrs: &[packet::Attr]) -> Vec<EngineEvent> {
        if self.phase != Phase::WaitConnectAck {
            return vec![]; // stray/duplicate CONNECT_ACK; ignore
        }
        let Some(attr) = attrs.iter().find(|a| a.attr_type == AttrType::CryptoBindRequest) else {
            return vec![EngineEvent::Fatal("CONNECT_ACK is missing its crypto-bind-request attribute".to_string())];
        };
        if attr.data.len() != 36 {
            return vec![EngineEvent::Fatal(format!("crypto-bind-request attribute has the wrong length: {}", attr.data.len()))];
        }
        let hash_byte = attr.data[3];
        // Reference (`sstp_state_send_connect`): prefer SHA256 whenever the
        // server's bitmask offers it, otherwise fall back to SHA1.
        let algo = if hash_byte & 0x02 != 0 { HashAlgo::Sha256 } else { HashAlgo::Sha1 };
        let nonce: [u8; 32] = attr.data[4..36].try_into().expect("checked length above");

        self.hash_algo = Some(algo);
        self.server_nonce = Some(nonce);
        self.phase = Phase::Lcp;

        let lcp_req = self.lcp.start();
        vec![
            EngineEvent::Trace(format!("CONNECT_ACK ok (hash={algo:?}), starting LCP")),
            EngineEvent::Send(wrap_data(ppp::Protocol::Lcp, &lcp_req)),
        ]
    }

    fn on_ppp_frame(&mut self, frame: &[u8]) -> Vec<EngineEvent> {
        let Some((proto, payload)) = ppp::decode(frame) else {
            return vec![]; // frame too short to even hold a protocol number; nothing sane to do
        };
        match proto {
            ppp::Protocol::Lcp => self.handle_lcp(payload),
            ppp::Protocol::Chap => self.handle_chap(payload),
            ppp::Protocol::Ipcp => self.handle_ipcp(payload),
            ppp::Protocol::Ip => vec![EngineEvent::DeliverIpPacket(payload.to_vec())],
            ppp::Protocol::Pap | ppp::Protocol::Unknown(_) => {
                // RFC 1661 §5.7: tell the peer we don't implement this
                // protocol. Matches this session's captured
                // "sent [LCP ProtRej id=0x3 82 81 ...]" for an unrelated
                // Apple-proprietary NCP the server itself doesn't
                // implement -- we don't send anything unusual ourselves, so
                // this path exists purely as a defensive fallback.
                let reject = self.lcp.build_protocol_reject(ppp::strip_address_control(frame));
                vec![EngineEvent::Send(wrap_data(ppp::Protocol::Lcp, &reject))]
            }
        }
    }

    fn handle_lcp(&mut self, payload: &[u8]) -> Vec<EngineEvent> {
        let mut events = Vec::new();
        if let Some(frame) = cp::decode(payload) {
            events.push(EngineEvent::Trace(format!("LCP recv {:?} id={} ({} option bytes)", frame.code, frame.id, frame.data.len())));
        } else {
            events.push(EngineEvent::Trace(format!("LCP recv malformed frame ({} bytes)", payload.len())));
        }

        let result = self.lcp.receive(payload);
        for d in &result.to_send {
            if let Some(frame) = cp::decode(d) {
                events.push(EngineEvent::Trace(format!("LCP send {:?} id={}", frame.code, frame.id)));
            }
            events.push(EngineEvent::Send(wrap_data(ppp::Protocol::Lcp, d)));
        }

        if result.up && self.phase == Phase::Lcp {
            match self.lcp.peer_auth_requirement() {
                Some(req) if req.is_mschapv2() => self.phase = Phase::Chap,
                Some(_) => return vec![EngineEvent::Fatal("server requires an authentication method other than MS-CHAPv2, which is all we implement".to_string())],
                None => {
                    // SSTP's crypto-bind step needs MPPE keys, which only
                    // come out of an MS-CHAPv2 exchange -- a server that
                    // skips PPP auth entirely can't be crypto-bound at all
                    // with this design, so refuse rather than continue in a
                    // state we can't secure.
                    return vec![EngineEvent::Fatal("server did not request PPP authentication; refusing to continue without it".to_string())];
                }
            }
        }
        events
    }

    fn handle_chap(&mut self, payload: &[u8]) -> Vec<EngineEvent> {
        let Some(frame) = chap_fsm::decode(payload) else {
            return vec![EngineEvent::Fatal("malformed CHAP frame".to_string())];
        };
        let mut events = vec![EngineEvent::Trace(format!("CHAP recv {:?} id={} ({} data bytes)", frame.code, frame.id, frame.data.len()))];
        events.extend(match frame.code {
            chap_fsm::Code::Challenge => {
                let Some(info) = chap_fsm::parse_challenge(&frame) else {
                    return vec![EngineEvent::Fatal("malformed CHAP challenge".to_string())];
                };
                let auth_challenge: [u8; 16] = match info.value.clone().try_into() {
                    Ok(c) => c,
                    Err(v) => return vec![EngineEvent::Fatal(format!("CHAP challenge value must be 16 bytes, got {}", v.len()))],
                };
                self.auth_challenge = Some(auth_challenge);
                match chap_fsm::build_response(&info, &self.username, &self.password) {
                    Ok((wire, pending)) => {
                        self.pending_chap = Some(pending);
                        vec![
                            EngineEvent::Trace(format!("CHAP send Response id={} for user={:?}", frame.id, self.username)),
                            EngineEvent::Send(wrap_data(ppp::Protocol::Chap, &wire)),
                        ]
                    }
                    Err(e) => vec![EngineEvent::Fatal(format!("could not build CHAP response: {e:?}"))],
                }
            }
            chap_fsm::Code::Success => {
                let (Some(pending), Some(auth_challenge)) = (self.pending_chap.take(), self.auth_challenge) else {
                    return vec![EngineEvent::Fatal("received CHAP success with no pending response to verify it against".to_string())];
                };
                if !chap_fsm::verify_success(&frame.data, &self.password, &pending, &auth_challenge, &self.username) {
                    return vec![EngineEvent::Fatal(format!(
                        "server's CHAP authenticator response did not verify -- it may not actually know our password (possible MITM); server said: {:?}; aborting",
                        String::from_utf8_lossy(&frame.data)
                    ))];
                }
                let keys = mppe::mppe_get_keys(&self.password, &pending.nt_response, false);
                self.mppe_keys = Some(keys);
                self.phase = Phase::Ipcp;
                let ipcp_req = self.ipcp.start();
                vec![EngineEvent::Trace("CHAP success verified, starting IPCP".to_string()), EngineEvent::Send(wrap_data(ppp::Protocol::Ipcp, &ipcp_req))]
            }
            chap_fsm::Code::Failure => {
                vec![EngineEvent::Fatal(format!("CHAP authentication failed: {}", String::from_utf8_lossy(&frame.data)))]
            }
            // We're always the CHAP peer being challenged, never the
            // authenticator -- a Response is something *we* send, never
            // receive.
            chap_fsm::Code::Response | chap_fsm::Code::Unknown(_) => {
                vec![EngineEvent::Fatal(format!("unexpected CHAP code from server: {:?}", frame.code))]
            }
        });
        events
    }

    fn handle_ipcp(&mut self, payload: &[u8]) -> Vec<EngineEvent> {
        let mut events = Vec::new();
        if let Some(frame) = cp::decode(payload) {
            events.push(EngineEvent::Trace(format!("IPCP recv {:?} id={} ({} option bytes)", frame.code, frame.id, frame.data.len())));
        }

        let result = self.ipcp.receive(payload);
        for d in &result.to_send {
            if let Some(frame) = cp::decode(d) {
                events.push(EngineEvent::Trace(format!("IPCP send {:?} id={}", frame.code, frame.id)));
            }
            events.push(EngineEvent::Send(wrap_data(ppp::Protocol::Ipcp, d)));
        }

        if result.up && self.phase == Phase::Ipcp {
            self.phase = Phase::Established;

            let algo = self.hash_algo.expect("set from CONNECT_ACK before LCP could even start");
            let nonce = self.server_nonce.expect("set alongside hash_algo");
            let cert_hash = match algo {
                HashAlgo::Sha1 => self.cert_hash_sha1,
                HashAlgo::Sha256 => self.cert_hash_sha256,
            };
            let keys = self.mppe_keys.expect("set once CHAP succeeds, which must happen before IPCP could start");

            let connected_pkt = cmac::build_connected_message(algo, &nonce, &cert_hash, &keys.send_key, &keys.recv_key);
            events.push(EngineEvent::Send(connected_pkt));
            events.push(EngineEvent::Established { negotiated: self.ipcp.negotiated(), mppe_keys: keys });
        }
        events
    }
}

fn wrap_data(proto: ppp::Protocol, payload: &[u8]) -> Vec<u8> {
    packet::encode_data(&ppp::encode(proto, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chap::{generate_authenticator_response, generate_nt_response};
    use crate::cp::{self, Opt};
    use crate::lcp::CHAP_ALGORITHM_MSCHAPV2;
    use std::net::Ipv4Addr;

    const USERNAME: &str = "test.user";
    const PASSWORD: &str = "test-password-not-real";
    const FAKE_CERT_DER: &[u8] = b"totally-not-a-real-certificate-just-test-bytes";

    fn extract_send(events: &[EngineEvent]) -> Vec<&[u8]> {
        events.iter().filter_map(|e| if let EngineEvent::Send(b) = e { Some(b.as_slice()) } else { None }).collect()
    }

    fn unwrap_ppp(sstp_data_pkt: &[u8]) -> (ppp::Protocol, Vec<u8>) {
        let pkt = packet::decode(sstp_data_pkt).unwrap();
        let Packet::Data(ppp_frame) = pkt else { panic!("expected a Data packet") };
        let (proto, payload) = ppp::decode(&ppp_frame).unwrap();
        (proto, payload.to_vec())
    }

    /// Drives a full, realistic handshake end to end: CONNECT_REQ/ACK, LCP
    /// (including the PFC/ACFC rejection dance this session's real logs
    /// show), MS-CHAPv2 (with a *genuine* server-side authenticator
    /// response computed the same way a real server would, proving our own
    /// verification logic accepts correct input and not just that it's
    /// permissive), IPCP with the NAK-then-ack address/DNS flow, and
    /// finally checks the emitted `CONNECTED` message's crypto-bind MAC
    /// against an independently computed expectation.
    #[test]
    fn full_handshake_reaches_established_with_correct_crypto_bind() {
        let mut engine = Engine::new(USERNAME, PASSWORD, FAKE_CERT_DER);

        // 1. CONNECT_REQ -> CONNECT_ACK (server offers SHA256, a fixed nonce).
        let connect_req = engine.start();
        assert!(matches!(packet::decode(&connect_req).unwrap(), Packet::Ctrl { msg_type: MsgType::ConnectRequest, .. }));

        let mut crypto_bind_req_data = vec![0u8, 0, 0, 0x02]; // hash byte = SHA256
        let server_nonce = [0x7Au8; 32];
        crypto_bind_req_data.extend_from_slice(&server_nonce);
        let connect_ack = packet::encode_ctrl(MsgType::ConnectAck, &[(AttrType::CryptoBindRequest, &crypto_bind_req_data)]);
        let events = engine.on_packet(packet::decode(&connect_ack).unwrap());

        // Should have kicked off LCP.
        let sends = extract_send(&events);
        assert_eq!(sends.len(), 1);
        let (proto, lcp_payload) = unwrap_ppp(sends[0]);
        assert_eq!(proto, ppp::Protocol::Lcp);
        let our_lcp_req = cp::decode(&lcp_payload).unwrap();
        assert_eq!(our_lcp_req.code, cp::Code::ConfigureRequest);

        // 2. Server rejects PFC/ACFC (matches captured real traffic) --
        //    everything after the first (magic-number) option we offered.
        let our_opts = cp::decode_options(&our_lcp_req.data);
        let reject = cp::encode(cp::Code::ConfigureReject, our_lcp_req.id, &cp::encode_options(&our_opts[1..]));
        let events = engine.on_packet(packet::decode(&wrap_data(ppp::Protocol::Lcp, &reject)).unwrap());
        let sends = extract_send(&events);
        assert_eq!(sends.len(), 1);
        let (_, second_req_payload) = unwrap_ppp(sends[0]);
        let second_req = cp::decode(&second_req_payload).unwrap();

        // 3. Server acks our (now magic-only) request.
        let ack = cp::encode(cp::Code::ConfigureAck, second_req.id, &second_req.data);
        engine.on_packet(packet::decode(&wrap_data(ppp::Protocol::Lcp, &ack)).unwrap());

        // 4. Server sends its own LCP request, demanding MS-CHAPv2 auth.
        let server_lcp_req = cp::encode(
            cp::Code::ConfigureRequest,
            1,
            &cp::encode_options(&[Opt::new(3, [0xC2, 0x23, CHAP_ALGORITHM_MSCHAPV2]), Opt::new(5, 0xAABBCCDDu32.to_be_bytes())]),
        );
        let events = engine.on_packet(packet::decode(&wrap_data(ppp::Protocol::Lcp, &server_lcp_req)).unwrap());
        let sends = extract_send(&events);
        assert_eq!(sends.len(), 1, "must ack the server's LCP request, bringing LCP fully up");
        let (_, our_ack_payload) = unwrap_ppp(sends[0]);
        assert_eq!(cp::decode(&our_ack_payload).unwrap().code, cp::Code::ConfigureAck);

        // 5. Server issues a CHAP challenge.
        let auth_challenge = [0x11u8; 16];
        let challenge_data = {
            let mut d = vec![16u8];
            d.extend_from_slice(&auth_challenge);
            d.extend_from_slice(b"VPN-NEW");
            d
        };
        let challenge = chap_fsm::encode(chap_fsm::Code::Challenge, 1, &challenge_data);
        let events = engine.on_packet(packet::decode(&wrap_data(ppp::Protocol::Chap, &challenge)).unwrap());
        let sends = extract_send(&events);
        assert_eq!(sends.len(), 1);
        let (proto, response_payload) = unwrap_ppp(sends[0]);
        assert_eq!(proto, ppp::Protocol::Chap);
        let response_frame = chap_fsm::decode(&response_payload).unwrap();
        assert_eq!(response_frame.code, chap_fsm::Code::Response);

        // Extract the peer challenge we generated, so a "genuine server"
        // can compute the real authenticator response the same way RFC
        // 2759 requires -- this is what proves verify_success's
        // acceptance path (not just its rejection path) works correctly.
        let peer_challenge: [u8; 16] = response_frame.data[1..17].try_into().unwrap();
        let nt_response = generate_nt_response(&auth_challenge, &peer_challenge, USERNAME, PASSWORD);
        let genuine_auth_response = generate_authenticator_response(PASSWORD, &nt_response, &peer_challenge, &auth_challenge, USERNAME);

        // 6. Genuine CHAP success -> engine proceeds straight to IPCP.
        let success = chap_fsm::encode(chap_fsm::Code::Success, response_frame.id, genuine_auth_response.as_bytes());
        let events = engine.on_packet(packet::decode(&wrap_data(ppp::Protocol::Chap, &success)).unwrap());
        let sends = extract_send(&events);
        assert_eq!(sends.len(), 1);
        let (proto, ipcp_req_payload) = unwrap_ppp(sends[0]);
        assert_eq!(proto, ppp::Protocol::Ipcp);
        let our_ipcp_req = cp::decode(&ipcp_req_payload).unwrap();

        // 7. Server NAKs with the real assigned address + DNS servers.
        let assigned_ip = Ipv4Addr::new(10, 100, 1, 21);
        let dns1 = Ipv4Addr::new(172, 19, 50, 203);
        let dns2 = Ipv4Addr::new(172, 19, 50, 204);
        let nak = cp::encode(
            cp::Code::ConfigureNak,
            our_ipcp_req.id,
            &cp::encode_options(&[Opt::new(3, assigned_ip.octets()), Opt::new(129, dns1.octets()), Opt::new(131, dns2.octets())]),
        );
        let events = engine.on_packet(packet::decode(&wrap_data(ppp::Protocol::Ipcp, &nak)).unwrap());
        let sends = extract_send(&events);
        let (_, second_ipcp_payload) = unwrap_ppp(sends[0]);
        let second_ipcp_req = cp::decode(&second_ipcp_payload).unwrap();

        // 8. Server acks our updated request; we still need its own
        //    request (its tunnel-endpoint address) before IPCP is fully up.
        let ack = cp::encode(cp::Code::ConfigureAck, second_ipcp_req.id, &second_ipcp_req.data);
        let events = engine.on_packet(packet::decode(&wrap_data(ppp::Protocol::Ipcp, &ack)).unwrap());
        assert!(extract_send(&events).is_empty(), "nothing to send yet -- still waiting on the peer's own IPCP request");

        let peer_ip = Ipv4Addr::new(10, 100, 1, 250);
        let server_ipcp_req = cp::encode(cp::Code::ConfigureRequest, 1, &cp::encode_options(&[Opt::new(3, peer_ip.octets())]));
        let events = engine.on_packet(packet::decode(&wrap_data(ppp::Protocol::Ipcp, &server_ipcp_req)).unwrap());

        // Now: an IPCP ack for the peer's request, the CONNECTED message,
        // and the Established event, in that order.
        let sends = extract_send(&events);
        assert_eq!(sends.len(), 2, "IPCP ack for the peer's request, then the CONNECTED crypto-bind message");
        let (_, ipcp_ack_payload) = unwrap_ppp(sends[0]);
        assert_eq!(cp::decode(&ipcp_ack_payload).unwrap().code, cp::Code::ConfigureAck);

        let connected_pkt = packet::decode(sends[1]).unwrap();
        let Packet::Ctrl { msg_type, attrs } = connected_pkt else { panic!("expected Ctrl") };
        assert_eq!(msg_type, MsgType::Connected);
        let crypto_bind = &attrs.iter().find(|a| a.attr_type == AttrType::CryptoBind).unwrap().data;
        assert_eq!(crypto_bind[3], 0x02, "must use SHA256 as the server's CONNECT_ACK requested");
        assert_eq!(&crypto_bind[4..36], &server_nonce[..]);

        let established = events.iter().find_map(|e| match e {
            EngineEvent::Established { negotiated, mppe_keys } => Some((negotiated, mppe_keys)),
            _ => None,
        });
        let (negotiated, mppe_keys) = established.expect("must emit Established once both LCP/CHAP/IPCP finished");
        assert_eq!(negotiated.local_ip, Some(assigned_ip));
        assert_eq!(negotiated.peer_ip, Some(peer_ip));
        assert_eq!(negotiated.dns1, Some(dns1));
        assert_eq!(negotiated.dns2, Some(dns2));

        // Independently recompute the expected MAC and confirm the engine's
        // output matches -- this is the actual crypto-bind correctness
        // check, not just "some bytes got sent".
        let expected_cert_hash: [u8; 32] = Sha256::digest(FAKE_CERT_DER).into();
        let expected_mac = crate::cmac::compound_mac(HashAlgo::Sha256, &mppe_keys.send_key, &mppe_keys.recv_key, &{
            let mut zeroed = crypto_bind.clone();
            zeroed[68..100].fill(0);
            let mut full = packet::encode_ctrl(MsgType::Connected, &[(AttrType::CryptoBind, &zeroed)]);
            full[80..112].fill(0);
            full
        });
        assert_eq!(&crypto_bind[36..68], &expected_cert_hash[..]);
        assert_eq!(&crypto_bind[68..100], &expected_mac[..]);
    }

    #[test]
    fn connect_nak_is_fatal_with_reason() {
        let mut engine = Engine::new(USERNAME, PASSWORD, FAKE_CERT_DER);
        engine.start();
        let status_data = [0u8, 0, 0, 0, 0, 0, 0, 9]; // arbitrary status
        let nak = packet::encode_ctrl(MsgType::ConnectNak, &[(AttrType::StatusInfo, &status_data)]);
        let events = engine.on_packet(packet::decode(&nak).unwrap());
        assert!(matches!(events.as_slice(), [EngineEvent::Fatal(_)]));
    }

    #[test]
    fn wrong_chap_success_message_is_rejected_as_possible_mitm() {
        let mut engine = Engine::new(USERNAME, PASSWORD, FAKE_CERT_DER);
        engine.start();
        let connect_ack = packet::encode_ctrl(MsgType::ConnectAck, &[(AttrType::CryptoBindRequest, &{
            let mut d = vec![0u8, 0, 0, 1];
            d.extend_from_slice(&[0u8; 32]);
            d
        })]);
        engine.on_packet(packet::decode(&connect_ack).unwrap());

        let server_lcp_req = cp::encode(cp::Code::ConfigureRequest, 1, &cp::encode_options(&[Opt::new(3, [0xC2, 0x23, CHAP_ALGORITHM_MSCHAPV2])]));
        engine.on_packet(packet::decode(&wrap_data(ppp::Protocol::Lcp, &server_lcp_req)).unwrap());

        let auth_challenge = [0x33u8; 16];
        let challenge_data = {
            let mut d = vec![16u8];
            d.extend_from_slice(&auth_challenge);
            d.extend_from_slice(b"srv");
            d
        };
        let challenge = chap_fsm::encode(chap_fsm::Code::Challenge, 1, &challenge_data);
        engine.on_packet(packet::decode(&wrap_data(ppp::Protocol::Chap, &challenge)).unwrap());

        // A forged/incorrect Success message (as if from an attacker who
        // doesn't actually know the password).
        let bogus_success = chap_fsm::encode(chap_fsm::Code::Success, 1, b"S=0000000000000000000000000000000000000000");
        let events = engine.on_packet(packet::decode(&wrap_data(ppp::Protocol::Chap, &bogus_success)).unwrap());
        assert!(matches!(events.as_slice(), [EngineEvent::Fatal(msg)] if msg.contains("MITM")));
    }

    #[test]
    fn chap_failure_is_reported_fatal() {
        let mut engine = Engine::new(USERNAME, PASSWORD, FAKE_CERT_DER);
        engine.start();
        let connect_ack = packet::encode_ctrl(MsgType::ConnectAck, &[(AttrType::CryptoBindRequest, &{
            let mut d = vec![0u8, 0, 0, 1];
            d.extend_from_slice(&[0u8; 32]);
            d
        })]);
        engine.on_packet(packet::decode(&connect_ack).unwrap());
        let server_lcp_req = cp::encode(cp::Code::ConfigureRequest, 1, &cp::encode_options(&[Opt::new(3, [0xC2, 0x23, CHAP_ALGORITHM_MSCHAPV2])]));
        engine.on_packet(packet::decode(&wrap_data(ppp::Protocol::Lcp, &server_lcp_req)).unwrap());

        let challenge_data = {
            let mut d = vec![16u8];
            d.extend_from_slice(&[0u8; 16]);
            d.extend_from_slice(b"srv");
            d
        };
        let challenge = chap_fsm::encode(chap_fsm::Code::Challenge, 1, &challenge_data);
        engine.on_packet(packet::decode(&wrap_data(ppp::Protocol::Chap, &challenge)).unwrap());

        let failure = chap_fsm::encode(chap_fsm::Code::Failure, 1, b"E=691 R=0");
        let events = engine.on_packet(packet::decode(&wrap_data(ppp::Protocol::Chap, &failure)).unwrap());
        assert!(events.iter().any(|e| matches!(e, EngineEvent::Fatal(msg) if msg.contains("691"))));
    }

    #[test]
    fn ip_data_frame_is_delivered_as_is() {
        let mut engine = Engine::new(USERNAME, PASSWORD, FAKE_CERT_DER);
        let ip_packet = vec![0x45, 0x00, 0x00, 0x14, 0xAA, 0xBB];
        let sstp_data = wrap_data(ppp::Protocol::Ip, &ip_packet);
        let events = engine.on_packet(packet::decode(&sstp_data).unwrap());
        assert!(matches!(events.as_slice(), [EngineEvent::DeliverIpPacket(p)] if p == &ip_packet));
    }

    #[test]
    fn unknown_protocol_triggers_lcp_protocol_reject() {
        let mut engine = Engine::new(USERNAME, PASSWORD, FAKE_CERT_DER);
        let frame = ppp::encode(ppp::Protocol::Unknown(0x8281), &[0x01, 0x01, 0x00, 0x04]);
        let sstp_data = packet::encode_data(&frame);
        let events = engine.on_packet(packet::decode(&sstp_data).unwrap());
        let sends = extract_send(&events);
        assert_eq!(sends.len(), 1);
        let (proto, payload) = unwrap_ppp(sends[0]);
        assert_eq!(proto, ppp::Protocol::Lcp);
        let rej = cp::decode(&payload).unwrap();
        assert_eq!(rej.code, cp::Code::ProtocolReject);
        assert_eq!(rej.data, ppp::strip_address_control(&frame), "rejected-information starts at the Protocol field, not Address/Control");
    }

    #[test]
    fn server_initiated_disconnect_is_acked_and_reported() {
        let mut engine = Engine::new(USERNAME, PASSWORD, FAKE_CERT_DER);
        let disconnect = packet::encode_ctrl(MsgType::Disconnect, &[]);
        let events = engine.on_packet(packet::decode(&disconnect).unwrap());
        let sends = extract_send(&events);
        assert_eq!(sends.len(), 1);
        assert!(matches!(packet::decode(sends[0]).unwrap(), Packet::Ctrl { msg_type: MsgType::DisconnectAck, .. }));
        assert!(events.iter().any(|e| matches!(e, EngineEvent::Disconnected)));
    }

    #[test]
    fn echo_request_gets_a_reply() {
        let mut engine = Engine::new(USERNAME, PASSWORD, FAKE_CERT_DER);
        let echo = packet::encode_ctrl(MsgType::EchoRequest, &[]);
        let events = engine.on_packet(packet::decode(&echo).unwrap());
        let sends = extract_send(&events);
        assert_eq!(sends.len(), 1);
        assert!(matches!(packet::decode(sends[0]).unwrap(), Packet::Ctrl { msg_type: MsgType::EchoReply, .. }));
    }

    #[test]
    fn debug_impl_never_prints_password() {
        let engine = Engine::new(USERNAME, "super-secret-password", FAKE_CERT_DER);
        let debug_str = format!("{engine:?}");
        assert!(!debug_str.contains("super-secret-password"));
    }
}
