//! CHAP (RFC 1994) wire framing and the client-side MS-CHAPv2 protocol flow,
//! wrapping the pure crypto in `chap.rs`. Kept separate from `chap.rs`
//! itself for the same reason `lcp.rs` is separate from `cp.rs`: framing
//! versus protocol-specific logic.
//!
//! Not reusing `cp::Code`/`cp::decode` here even though the header shape is
//! identical (Code/Id/Length/Data): CHAP's codes 1-4 mean
//! Challenge/Response/Success/Failure, which would be actively misleading
//! spelled out as `cp::Code`'s LCP-flavored `ConfigureRequest`/`Ack`/etc
//! variant names.

use crate::chap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    Challenge,
    Response,
    Success,
    Failure,
    Unknown(u8),
}

impl Code {
    fn to_u8(self) -> u8 {
        match self {
            Code::Challenge => 1,
            Code::Response => 2,
            Code::Success => 3,
            Code::Failure => 4,
            Code::Unknown(v) => v,
        }
    }

    fn from_u8(v: u8) -> Code {
        match v {
            1 => Code::Challenge,
            2 => Code::Response,
            3 => Code::Success,
            4 => Code::Failure,
            other => Code::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub code: Code,
    pub id: u8,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeInfo {
    pub id: u8,
    pub value: Vec<u8>,
    pub name: String,
}

/// Parses a Challenge frame's `Value-Size(1) + Value + Name` data.
pub fn parse_challenge(frame: &Frame) -> Option<ChallengeInfo> {
    if frame.data.is_empty() {
        return None;
    }
    let value_size = frame.data[0] as usize;
    if frame.data.len() < 1 + value_size {
        return None;
    }
    let value = frame.data[1..1 + value_size].to_vec();
    let name = String::from_utf8_lossy(&frame.data[1 + value_size..]).into_owned();
    Some(ChallengeInfo { id: frame.id, value, name })
}

#[derive(Debug)]
pub enum ResponseError {
    /// The Challenge's Value field wasn't 16 bytes, as MS-CHAPv2 (RFC 2759
    /// §5) requires.
    BadChallengeLength(usize),
}

/// What we need to hang onto after sending a Response, to later derive
/// MPPE keys (needs `nt_response`) and independently verify the server's
/// Success message (needs `peer_challenge`, since the authenticator
/// response depends on it too).
pub struct PendingResponse {
    pub peer_challenge: [u8; 16],
    pub nt_response: [u8; 24],
}

/// Builds an MS-CHAPv2 Response (RFC 2759 §5) to `challenge`, generating a
/// fresh random PeerChallenge. The Response's own identifier must match
/// the Challenge's, per RFC 1994 §3.
pub fn build_response(challenge: &ChallengeInfo, username: &str, password: &str) -> Result<(Vec<u8>, PendingResponse), ResponseError> {
    let auth_challenge: [u8; 16] =
        challenge.value.clone().try_into().map_err(|v: Vec<u8>| ResponseError::BadChallengeLength(v.len()))?;
    let peer_challenge: [u8; 16] = rand::random();
    let nt_response = chap::generate_nt_response(&auth_challenge, &peer_challenge, username, password);

    // RFC 2759 §5: Value = PeerChallenge(16) || Reserved(8, zero) || NTResponse(24) || Flags(1, zero) = 49 bytes.
    let mut value = Vec::with_capacity(49);
    value.extend_from_slice(&peer_challenge);
    value.extend_from_slice(&[0u8; 8]);
    value.extend_from_slice(&nt_response);
    value.push(0);
    debug_assert_eq!(value.len(), 49);

    let mut data = Vec::with_capacity(1 + value.len() + username.len());
    data.push(value.len() as u8);
    data.extend_from_slice(&value);
    data.extend_from_slice(username.as_bytes());

    let wire = encode(Code::Response, challenge.id, &data);
    Ok((wire, PendingResponse { peer_challenge, nt_response }))
}

/// Verifies a Success frame's message against the authenticator response
/// we independently compute — this is what actually proves the server
/// knows our password (RFC 2759 §5), not just that it sent back a
/// Success-coded frame. A case-insensitive prefix match: some servers
/// append additional space-separated fields after the `S=<hex>` token.
pub fn verify_success(success_data: &[u8], password: &str, pending: &PendingResponse, auth_challenge: &[u8; 16], username: &str) -> bool {
    let expected = chap::generate_authenticator_response(password, &pending.nt_response, &pending.peer_challenge, auth_challenge, username);
    let text = String::from_utf8_lossy(success_data);
    match text.split_whitespace().next() {
        Some(token) => token.eq_ignore_ascii_case(&expected),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_challenge() -> ChallengeInfo {
        ChallengeInfo { id: 1, value: vec![0xAAu8; 16], name: "VPN-SERVER".to_string() }
    }

    #[test]
    fn challenge_frame_round_trips() {
        let wire = encode(Code::Challenge, 1, &{
            let mut d = vec![16u8];
            d.extend_from_slice(&[0xAA; 16]);
            d.extend_from_slice(b"VPN-SERVER");
            d
        });
        let frame = decode(&wire).unwrap();
        assert_eq!(frame.code, Code::Challenge);
        let info = parse_challenge(&frame).unwrap();
        assert_eq!(info.value, vec![0xAA; 16]);
        assert_eq!(info.name, "VPN-SERVER");
    }

    #[test]
    fn build_response_has_rfc2759_shape_and_matching_id() {
        let challenge = sample_challenge();
        let (wire, pending) = build_response(&challenge, "testuser", "hunter2").unwrap();
        let frame = decode(&wire).unwrap();
        assert_eq!(frame.code, Code::Response);
        assert_eq!(frame.id, challenge.id, "response id must match the challenge's");

        assert_eq!(frame.data[0], 49, "MS-CHAPv2 value-size is always 49");
        let value = &frame.data[1..50];
        assert_eq!(&value[0..16], &pending.peer_challenge, "value starts with the peer challenge");
        assert_eq!(&value[16..24], &[0u8; 8], "reserved field must be zero");
        assert_eq!(&value[24..48], &pending.nt_response, "value contains the nt-response");
        assert_eq!(value[48], 0, "flags byte must be zero");

        let name = &frame.data[50..];
        assert_eq!(name, b"testuser");
    }

    #[test]
    fn rejects_challenge_with_wrong_value_length() {
        let bad = ChallengeInfo { id: 1, value: vec![0u8; 8], name: "x".to_string() };
        let result = build_response(&bad, "u", "p");
        assert!(matches!(result, Err(ResponseError::BadChallengeLength(8))));
    }

    #[test]
    fn verify_success_accepts_correctly_derived_authenticator_response() {
        let auth_challenge = [0x11u8; 16];
        let challenge = ChallengeInfo { id: 1, value: auth_challenge.to_vec(), name: "srv".to_string() };
        let (_, pending) = build_response(&challenge, "user", "pw").unwrap();

        let expected = chap::generate_authenticator_response("pw", &pending.nt_response, &pending.peer_challenge, &auth_challenge, "user");
        assert!(verify_success(expected.as_bytes(), "pw", &pending, &auth_challenge, "user"));

        // A server message with a trailing field must still match on the
        // leading S=... token.
        let with_suffix = format!("{expected} M=Login OK");
        assert!(verify_success(with_suffix.as_bytes(), "pw", &pending, &auth_challenge, "user"));
    }

    #[test]
    fn verify_success_rejects_wrong_or_forged_response() {
        let auth_challenge = [0x22u8; 16];
        let challenge = ChallengeInfo { id: 1, value: auth_challenge.to_vec(), name: "srv".to_string() };
        let (_, pending) = build_response(&challenge, "user", "correct-password").unwrap();

        // A "server" that didn't actually know the password can't produce
        // a matching authenticator response.
        let forged = "S=0000000000000000000000000000000000000000";
        assert!(!verify_success(forged.as_bytes(), "correct-password", &pending, &auth_challenge, "user"));
    }
}
