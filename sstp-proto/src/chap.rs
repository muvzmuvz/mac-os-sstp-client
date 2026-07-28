//! MS-CHAPv2 (RFC 2759) challenge/response and authenticator-response
//! generation — the part of PPP authentication `sstp-client` never had to
//! implement itself, since it always delegated to pppd. Ported from
//! `pppd/crypto_ms.c` and `pppd/chap_ms.c` in the upstream `ppp` project
//! (github.com/paulusmack/ppp — the same lineage as Apple's own
//! `/usr/sbin/pppd`), which we treated as the authoritative reference over
//! re-deriving the DES key-parity expansion from RFC 2759's prose. Values
//! are checked against RFC 2759 §9.2's published test vector below.

use des::Des;
use des::cipher::{BlockEncrypt, KeyInit};
use md4::{Digest, Md4};
use sha1::Sha1;

/// RFC 2759 `NtPasswordHash`: MD4 of the password re-encoded as real
/// UTF-16LE (not the naive ASCII-doubling `sstp-chap.c`'s MPPE path uses —
/// for ASCII-only passwords the two are identical, but this handles
/// non-ASCII correctly too).
fn nt_password_hash(password: &str) -> [u8; 16] {
    let mut utf16le = Vec::with_capacity(password.len() * 2);
    for unit in password.encode_utf16() {
        utf16le.extend_from_slice(&unit.to_le_bytes());
    }
    Md4::digest(&utf16le).into()
}

/// RFC 2759 `ChallengeHash`: SHA1(PeerChallenge || AuthenticatorChallenge
/// || Username), truncated to 8 bytes. Only the part of `username` after
/// the last `\` is hashed, matching `chap_ms.c`'s `strrchr(username, '\\')`
/// handling of `DOMAIN\user`-style names.
fn challenge_hash(peer_challenge: &[u8; 16], auth_challenge: &[u8; 16], username: &str) -> [u8; 8] {
    let user = username.rsplit('\\').next().unwrap_or(username);
    let mut hasher = Sha1::new();
    hasher.update(peer_challenge);
    hasher.update(auth_challenge);
    hasher.update(user.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// `Get7Bits`: pull 7 bits starting at bit offset `start_bit` out of
/// `input` (which must have at least `start_bit/8 + 2` bytes — the extra
/// byte is read but not fully consumed, matching the reference's
/// intentional 1-byte lookahead), left-justified into a byte whose low bit
/// is always 0 (parity slot, filled in by `set_odd_parity`).
fn get7bits(input: &[u8], start_bit: usize) -> u8 {
    let byte_idx = start_bit / 8;
    let word = ((input[byte_idx] as u16) << 8) | (input[byte_idx + 1] as u16);
    let shifted = word >> (15 - (start_bit % 8 + 7));
    (shifted & 0xFE) as u8
}

/// `DES_set_odd_parity` for a single byte: `get7bits` always leaves bit 0
/// clear, so this just decides whether to set it to make the byte's total
/// population count odd. (DES's real key schedule ignores parity bits
/// entirely, so this has no effect on the ciphertext — it's here purely to
/// match the reference implementation exactly rather than assume that.)
fn set_odd_parity(b: u8) -> u8 {
    if b.count_ones().is_multiple_of(2) { b | 1 } else { b }
}

/// `MakeKey`: expand a 7-byte key (with 1 byte of safe lookahead, see
/// `get7bits`) into an 8-byte, odd-parity DES key.
fn make_key(key_with_lookahead: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = set_odd_parity(get7bits(key_with_lookahead, i * 7));
    }
    out
}

fn des_encrypt_block(key: &[u8; 8], clear: &[u8; 8]) -> [u8; 8] {
    let cipher = Des::new_from_slice(key).expect("DES key is always exactly 8 bytes");
    let mut block = (*clear).into();
    cipher.encrypt_block(&mut block);
    block.into()
}

/// RFC 2759 `ChallengeResponse`: the 16-byte NT password hash gets
/// zero-padded to 24 bytes (only 21 are ever meaningfully consumed, but the
/// reference implementation's buffer is 24 and its third DES-key read
/// touches an index shy of that, so we match its size exactly), then split
/// into three 7-byte keys, each DES-encrypting the same 8-byte challenge.
fn challenge_response(challenge: &[u8; 8], password_hash: &[u8; 16]) -> [u8; 24] {
    let mut zpadded = [0u8; 24];
    zpadded[..16].copy_from_slice(password_hash);

    let mut response = [0u8; 24];
    for (i, offset) in [0usize, 7, 14].into_iter().enumerate() {
        let key = make_key(&zpadded[offset..]);
        let block = des_encrypt_block(&key, challenge);
        response[i * 8..i * 8 + 8].copy_from_slice(&block);
    }
    response
}

/// RFC 2759 `GenerateNTResponse`: what the PPP CHAP layer sends back to the
/// server in its `Response` field, and also what `mppe::mppe_get_keys`
/// needs as `nt_response` to derive the MPPE session keys.
pub fn generate_nt_response(auth_challenge: &[u8; 16], peer_challenge: &[u8; 16], username: &str, password: &str) -> [u8; 24] {
    let challenge = challenge_hash(peer_challenge, auth_challenge, username);
    let pw_hash = nt_password_hash(password);
    challenge_response(&challenge, &pw_hash)
}

const AUTH_RESPONSE_MAGIC1: [u8; 39] = [
    0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69,
    0x65, 0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E,
    0x74,
];
const AUTH_RESPONSE_MAGIC2: [u8; 41] = [
    0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B, 0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D,
    0x6F, 0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E, 0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74,
    0x69, 0x6F, 0x6E,
];

/// RFC 2759 `GenerateAuthenticatorResponse`: proves to the *server's*
/// success message ("S=<hex>") that we independently derived the same
/// response without ever transmitting the password — verifying this (not
/// just checking the CHAP Success/Failure opcode) is what stops a
/// compromised/spoofed server from silently downgrading auth. Returns the
/// full `"S=" + 40 uppercase hex chars` form the server's Success message
/// carries, ready for direct comparison.
pub fn generate_authenticator_response(
    password: &str,
    nt_response: &[u8; 24],
    peer_challenge: &[u8; 16],
    auth_challenge: &[u8; 16],
    username: &str,
) -> String {
    let pw_hash = nt_password_hash(password);
    let pw_hash_hash: [u8; 16] = Md4::digest(pw_hash).into();

    let mut hasher = Sha1::new();
    hasher.update(pw_hash_hash);
    hasher.update(nt_response);
    hasher.update(AUTH_RESPONSE_MAGIC1);
    let digest1 = hasher.finalize();

    let challenge = challenge_hash(peer_challenge, auth_challenge, username);

    let mut hasher2 = Sha1::new();
    hasher2.update(digest1);
    hasher2.update(challenge);
    hasher2.update(AUTH_RESPONSE_MAGIC2);
    let digest2 = hasher2.finalize();

    let mut out = String::with_capacity(2 + digest2.len() * 2);
    out.push_str("S=");
    for byte in digest2 {
        out.push_str(&format!("{byte:02X}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 2759 §9.2 "Test Vectors" — the standard's own published values,
    // fetched from the RFC text itself rather than trusted from memory.
    const USERNAME: &str = "User";
    const PASSWORD: &str = "clientPass";
    const AUTH_CHALLENGE: [u8; 16] =
        [0x5B, 0x5D, 0x7C, 0x7D, 0x7B, 0x3F, 0x2F, 0x3E, 0x3C, 0x2C, 0x60, 0x21, 0x32, 0x26, 0x26, 0x28];
    const PEER_CHALLENGE: [u8; 16] =
        [0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A, 0x28, 0x29, 0x5F, 0x2B, 0x3A, 0x33, 0x7C, 0x7E];
    const EXPECTED_NT_RESPONSE: [u8; 24] = [
        0x82, 0x30, 0x9E, 0xCD, 0x8D, 0x70, 0x8B, 0x5E, 0xA0, 0x8F, 0xAA, 0x39, 0x81, 0xCD, 0x83, 0x54, 0x42, 0x33,
        0x11, 0x4A, 0x3D, 0x85, 0xD6, 0xDF,
    ];
    const EXPECTED_AUTH_RESPONSE: &str = "S=407A5589115FD0D6209F510FE9C04566932CDA56";

    #[test]
    fn nt_response_matches_rfc2759_test_vector() {
        let response = generate_nt_response(&AUTH_CHALLENGE, &PEER_CHALLENGE, USERNAME, PASSWORD);
        assert_eq!(response, EXPECTED_NT_RESPONSE);
    }

    #[test]
    fn authenticator_response_matches_rfc2759_test_vector() {
        let response =
            generate_authenticator_response(PASSWORD, &EXPECTED_NT_RESPONSE, &PEER_CHALLENGE, &AUTH_CHALLENGE, USERNAME);
        assert_eq!(response, EXPECTED_AUTH_RESPONSE);
    }

    #[test]
    fn domain_prefixed_username_only_hashes_the_user_part() {
        let plain = generate_nt_response(&AUTH_CHALLENGE, &PEER_CHALLENGE, USERNAME, PASSWORD);
        let domain_prefixed = generate_nt_response(&AUTH_CHALLENGE, &PEER_CHALLENGE, "CORP\\User", PASSWORD);
        assert_eq!(plain, domain_prefixed, "DOMAIN\\user must hash the same as just user");
    }

    #[test]
    fn different_password_produces_different_response() {
        let a = generate_nt_response(&AUTH_CHALLENGE, &PEER_CHALLENGE, USERNAME, "clientPass");
        let b = generate_nt_response(&AUTH_CHALLENGE, &PEER_CHALLENGE, USERNAME, "wrongPass");
        assert_ne!(a, b);
    }

    #[test]
    fn make_key_produces_odd_parity_bytes() {
        // Every byte MakeKey emits must have odd bit-parity, per
        // DES_set_odd_parity -- a cheap invariant check independent of the
        // full RFC vector above.
        let lookahead = [0xFFu8; 8];
        let key = make_key(&lookahead);
        for byte in key {
            assert_eq!(byte.count_ones() % 2, 1, "byte {byte:#04x} does not have odd parity");
        }
    }
}
