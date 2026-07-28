//! IPCP (IP Control Protocol, RFC 1332 + the Microsoft DNS extensions from
//! RFC 1877) — negotiated after LCP and CHAP succeed, over
//! `ppp::Protocol::Ipcp` frames. Same practical, timer-free automaton
//! approach as `lcp.rs`; see that module's docs for why.
//!
//! We deliberately never offer IP-Compression-Protocol (Van Jacobson
//! header compression, RFC 1332 option type 2): this session's captured
//! negotiation logs show the production server rejecting it every time
//! (`rcvd [IPCP ConfRej id=0x1 <compress VJ 0f 01>]`), and we have no
//! reason to implement VJ compression at all for a VPN tunnel, so skipping
//! the offer avoids a pointless extra round trip rather than replaying
//! pppd's legacy defaults.

use std::net::Ipv4Addr;

use crate::cp::{self, Opt};

const OPT_IP_ADDRESS: u8 = 3;
const OPT_PRIMARY_DNS: u8 = 129;
const OPT_SECONDARY_DNS: u8 = 131;

fn ip_opt(kind: u8, addr: Ipv4Addr) -> Opt {
    Opt::new(kind, addr.octets())
}

fn parse_ip_opt(opt: &Opt) -> Option<Ipv4Addr> {
    let bytes: [u8; 4] = opt.data.clone().try_into().ok()?;
    Some(Ipv4Addr::from(bytes))
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NegotiatedConfig {
    /// The address the server assigned us, once our Configure-Request for
    /// it has been acknowledged.
    pub local_ip: Option<Ipv4Addr>,
    /// The address the peer announced as its own in *its* Configure-Request
    /// (i.e. the tunnel's remote/gateway endpoint).
    pub peer_ip: Option<Ipv4Addr>,
    pub dns1: Option<Ipv4Addr>,
    pub dns2: Option<Ipv4Addr>,
}

#[derive(Debug, Default)]
pub struct IpcpResult {
    pub to_send: Vec<Vec<u8>>,
    pub up: bool,
}

pub struct Ipcp {
    identifier: u8,
    desired: Vec<Opt>,
    last_sent_id: Option<u8>,
    local_up: bool,
    remote_up: bool,
    negotiated: NegotiatedConfig,
}

impl Ipcp {
    pub fn new() -> Self {
        Ipcp {
            identifier: 0,
            // 0.0.0.0 across the board is the standard RFC 1332 §3.3 "I
            // don't have a value, please assign one" hint -- the server is
            // expected to ConfNak these with the real values, which is
            // exactly what this session's captured traces show it doing.
            desired: vec![
                ip_opt(OPT_IP_ADDRESS, Ipv4Addr::UNSPECIFIED),
                ip_opt(OPT_PRIMARY_DNS, Ipv4Addr::UNSPECIFIED),
                ip_opt(OPT_SECONDARY_DNS, Ipv4Addr::UNSPECIFIED),
            ],
            last_sent_id: None,
            local_up: false,
            remote_up: false,
            negotiated: NegotiatedConfig::default(),
        }
    }

    pub fn is_up(&self) -> bool {
        self.local_up && self.remote_up
    }

    pub fn negotiated(&self) -> NegotiatedConfig {
        self.negotiated
    }

    pub fn start(&mut self) -> Vec<u8> {
        self.send_config_request()
    }

    fn send_config_request(&mut self) -> Vec<u8> {
        self.identifier = self.identifier.wrapping_add(1);
        self.last_sent_id = Some(self.identifier);
        let data = cp::encode_options(&self.desired);
        cp::encode(cp::Code::ConfigureRequest, self.identifier, &data)
    }

    pub fn receive(&mut self, data: &[u8]) -> IpcpResult {
        let mut to_send = Vec::new();

        let Some(frame) = cp::decode(data) else {
            return IpcpResult { to_send, up: self.is_up() };
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
                    self.capture_accepted_values();
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
            cp::Code::TerminateRequest => {
                to_send.push(cp::encode(cp::Code::TerminateAck, frame.id, &[]));
                self.local_up = false;
                self.remote_up = false;
            }
            _ => {}
        }

        IpcpResult { to_send, up: self.is_up() }
    }

    fn evaluate_peer_options(&mut self, opts: &[Opt]) -> (Vec<Opt>, Vec<Opt>) {
        let nak = Vec::new();
        let mut reject = Vec::new();

        for opt in opts {
            match opt.kind {
                OPT_IP_ADDRESS => match parse_ip_opt(opt) {
                    Some(addr) => self.negotiated.peer_ip = Some(addr),
                    None => reject.push(opt.clone()),
                },
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
        }
    }

    fn apply_reject(&mut self, rejected: &[Opt]) {
        self.desired.retain(|o| !rejected.iter().any(|r| r.kind == o.kind));
    }

    fn capture_accepted_values(&mut self) {
        for opt in &self.desired {
            let Some(addr) = parse_ip_opt(opt) else { continue };
            match opt.kind {
                OPT_IP_ADDRESS => self.negotiated.local_ip = Some(addr),
                OPT_PRIMARY_DNS => self.negotiated.dns1 = Some(addr),
                OPT_SECONDARY_DNS => self.negotiated.dns2 = Some(addr),
                _ => {}
            }
        }
    }
}

impl Default for Ipcp {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_requests_unspecified_address_and_dns() {
        let mut ipcp = Ipcp::new();
        let wire = ipcp.start();
        let frame = cp::decode(&wire).unwrap();
        let opts = cp::decode_options(&frame.data);
        assert_eq!(opts.len(), 3);
        for opt in &opts {
            assert_eq!(opt.data, [0, 0, 0, 0]);
        }
    }

    /// Replays this session's real captured exchange almost exactly: we
    /// propose an address, get ConfNak'd with the server's real assignment
    /// plus DNS servers, resend with those values, and get ConfAck'd.
    #[test]
    fn reproduces_captured_address_and_dns_nak_then_ack_flow() {
        let mut ipcp = Ipcp::new();
        let first_req = ipcp.start();
        let first_id = cp::decode(&first_req).unwrap().id;

        let assigned_ip = Ipv4Addr::new(10, 100, 1, 21);
        let dns1 = Ipv4Addr::new(172, 19, 50, 203);
        let dns2 = Ipv4Addr::new(172, 19, 50, 204);
        let nak = cp::encode(
            cp::Code::ConfigureNak,
            first_id,
            &cp::encode_options(&[ip_opt(OPT_IP_ADDRESS, assigned_ip), ip_opt(OPT_PRIMARY_DNS, dns1), ip_opt(OPT_SECONDARY_DNS, dns2)]),
        );
        let result = ipcp.receive(&nak);
        assert_eq!(result.to_send.len(), 1);
        let second_req = cp::decode(&result.to_send[0]).unwrap();

        let ack = cp::encode(cp::Code::ConfigureAck, second_req.id, &second_req.data);
        let ack_result = ipcp.receive(&ack);
        assert!(!ack_result.up, "local side is up, but peer hasn't sent its own request yet");

        let negotiated = ipcp.negotiated();
        assert_eq!(negotiated.local_ip, Some(assigned_ip));
        assert_eq!(negotiated.dns1, Some(dns1));
        assert_eq!(negotiated.dns2, Some(dns2));
    }

    #[test]
    fn peer_confreq_with_its_address_is_acked_and_captured() {
        let mut ipcp = Ipcp::new();
        ipcp.start();

        let peer_ip = Ipv4Addr::new(10, 100, 1, 250);
        let peer_req = cp::encode(cp::Code::ConfigureRequest, 1, &cp::encode_options(&[ip_opt(OPT_IP_ADDRESS, peer_ip)]));
        let result = ipcp.receive(&peer_req);
        let reply = cp::decode(&result.to_send[0]).unwrap();
        assert_eq!(reply.code, cp::Code::ConfigureAck);
        assert_eq!(ipcp.negotiated().peer_ip, Some(peer_ip));
    }

    #[test]
    fn ipcp_up_only_once_both_directions_configured() {
        let mut ipcp = Ipcp::new();
        let first_req = ipcp.start();
        let first_id = cp::decode(&first_req).unwrap().id;

        let ack = cp::encode(cp::Code::ConfigureAck, first_id, &cp::decode(&first_req).unwrap().data);
        let r1 = ipcp.receive(&ack);
        assert!(!r1.up);

        let peer_req = cp::encode(cp::Code::ConfigureRequest, 1, &cp::encode_options(&[ip_opt(OPT_IP_ADDRESS, Ipv4Addr::new(10, 0, 0, 1))]));
        let r2 = ipcp.receive(&peer_req);
        assert!(r2.up);
        assert!(ipcp.is_up());
    }

    #[test]
    fn unknown_option_in_peer_request_is_rejected() {
        let mut ipcp = Ipcp::new();
        ipcp.start();
        let peer_req = cp::encode(cp::Code::ConfigureRequest, 1, &cp::encode_options(&[Opt::new(2, [0x0f, 0x01])]));
        let result = ipcp.receive(&peer_req);
        let reply = cp::decode(&result.to_send[0]).unwrap();
        assert_eq!(reply.code, cp::Code::ConfigureReject);
    }
}
