//! SSTP "Compound MAC" (crypto-bind) generation, ported from
//! `vendor/sstp-client/src/sstp-cmac.c`. Despite the name this is plain
//! HMAC-SHA1 or HMAC-SHA256, not the AES-CMAC construction — Microsoft's
//! own naming, kept here so the two "CMAC"s aren't confused when reading
//! the reference source alongside this file.
//!
//! This is what lets SSTP tolerate a self-signed/unvalidated TLS
//! certificate while still proving the PPP authentication and the TLS
//! session belong together: the MAC is computed over the server's
//! certificate hash *and* the MPPE keys derived from the MS-CHAPv2
//! exchange, so a man-in-the-middle presenting a different certificate (or
//! not knowing the real password) can't produce a matching value.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;

/// ASCII "SSTP inner method derived CMK" — the fixed seed `sstp_cmac_init`
/// hashes as part of deriving the Compound MAC Key from the raw MPPE keys.
const SEED: &[u8; 29] = b"SSTP inner method derived CMK";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgo {
    Sha1,
    Sha256,
}

impl HashAlgo {
    /// The single-byte length-of-output value baked into the CMK
    /// derivation input (`len0` in the reference; always fits in one byte
    /// for SHA1/SHA256, hence the reference's unused `len1` high byte).
    fn digest_len_byte(self) -> u8 {
        match self {
            HashAlgo::Sha1 => 20,
            HashAlgo::Sha256 => 32,
        }
    }
}

/// `sstp_cmac_makekey`: build the Higher-Level Authentication Key from the
/// two 16-byte MPPE keys. We only ever act as the SSTP/PPP *client*, so
/// (matching the reference's `SSTP_CMAC_SERVER`-unset branch) the key is
/// always `send_key || recv_key`.
fn make_hlak(send_key: &[u8; 16], recv_key: &[u8; 16]) -> [u8; 32] {
    let mut hlak = [0u8; 32];
    hlak[..16].copy_from_slice(send_key);
    hlak[16..].copy_from_slice(recv_key);
    hlak
}

fn hmac_sha1(key: &[u8], data: &[&[u8]]) -> Vec<u8> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
    for chunk in data {
        mac.update(chunk);
    }
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha256(key: &[u8], data: &[&[u8]]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    for chunk in data {
        mac.update(chunk);
    }
    mac.finalize().into_bytes().to_vec()
}

/// Computes the Compound MAC field for `message` (the `SSTP_MSG_CONNECTED`
/// packet bytes, with the 32-byte MAC field itself zeroed out while
/// hashing — matching the reference, which zeros that region in its
/// message buffer before calling this).
///
/// Returns the *natural* digest length (20 bytes for SHA1, 32 for SHA256) —
/// the wire format's crypto-bind field is a fixed 32 bytes, so a caller
/// embedding a SHA1 result must zero-pad the remaining 12 bytes itself
/// (this mirrors the reference implementation, whose `sstp_cmac_result`
/// only ever writes the natural digest length too, regardless of the
/// buffer size passed in — its own unit tests only ever compare that
/// natural length, never the padding).
pub fn compound_mac(algo: HashAlgo, send_key: &[u8; 16], recv_key: &[u8; 16], message: &[u8]) -> Vec<u8> {
    let hlak = make_hlak(send_key, recv_key);
    let len0 = algo.digest_len_byte();
    let len1 = 0u8;
    let iter = 0x01u8;
    let derive_input: [u8; 3] = [len0, len1, iter];

    match algo {
        HashAlgo::Sha1 => {
            let t1 = hmac_sha1(&hlak, &[SEED, &derive_input]);
            hmac_sha1(&t1, &[message])
        }
        HashAlgo::Sha256 => {
            let t1 = hmac_sha256(&hlak, &[SEED, &derive_input]);
            hmac_sha256(&t1, &[message])
        }
    }
}

impl HashAlgo {
    /// The single byte the wire format uses for "which hash algorithm":
    /// `SSTP_PROTO_HASH_SHA1`/`SHA256` in the reference (`sstp-packet.h`).
    fn wire_byte(self) -> u8 {
        match self {
            HashAlgo::Sha1 => 0x01,
            HashAlgo::Sha256 => 0x02,
        }
    }
}

/// Builds a complete, ready-to-send `SSTP_MSG_CONNECTED` packet — the final
/// step of the SSTP handshake, sent once PPP authentication (MS-CHAPv2) has
/// produced MPPE keys. Ported from `sstp_state_send_connect()` in
/// `sstp-state.c`: a single `CRYPTO_BIND` attribute holding a 4-byte header
/// (hash-algorithm byte at offset 3) + the 32-byte server nonce (echoed
/// back from its `CRYPTO_BIND_REQ`) + a 32-byte certificate hash
/// (zero-padded past byte 20 for SHA1) + a 32-byte MAC field — the whole
/// packet is hashed with that MAC field still zeroed, and the result is
/// then patched into those same 32 bytes (fully for SHA256, only the first
/// 20 bytes for SHA1, per `compound_mac`'s doc comment on natural digest
/// length).
///
/// `cert_hash32` must already be exactly 32 bytes: the raw digest
/// (SHA1 or SHA256 of the DER-encoded server certificate, matching `algo`)
/// left-aligned and zero-padded to 32 bytes — this mirrors
/// `sstp_get_cert_hash`'s own `memset(hash, 0, 32)` before writing the
/// (possibly shorter) digest.
pub fn build_connected_message(algo: HashAlgo, nonce: &[u8; 32], cert_hash32: &[u8; 32], send_key: &[u8; 16], recv_key: &[u8; 16]) -> Vec<u8> {
    let mut attr_data = [0u8; 100];
    attr_data[3] = algo.wire_byte();
    attr_data[4..36].copy_from_slice(nonce);
    attr_data[36..68].copy_from_slice(cert_hash32);
    // attr_data[68..100] (the MAC field) stays zero for the hash step below.

    let mut pkt = crate::packet::encode_ctrl(crate::packet::MsgType::Connected, &[(crate::packet::AttrType::CryptoBind, &attr_data)]);

    let mac = compound_mac(algo, send_key, recv_key, &pkt);
    const MAC_FIELD_OFFSET_IN_PACKET: usize = 4 /* pkt header */ + 4 /* ctrl header */ + 4 /* attr header */ + 68;
    pkt[MAC_FIELD_OFFSET_IN_PACKET..MAC_FIELD_OFFSET_IN_PACKET + mac.len()].copy_from_slice(&mac);
    pkt
}

#[cfg(test)]
mod tests {
    use super::*;

    // Both vectors below are `sstp_test_sha1`/`sstp_test_sha256` from
    // sstp-cmac.c's own `__SSTP_UNIT_TEST_CMAC` block: a full 112-byte
    // `SSTP_MSG_CONNECTED` packet (with its MAC field already zeroed), a
    // pair of MPPE keys, and the expected Compound MAC.

    #[test]
    fn sha1_matches_reference_test_vector() {
        #[rustfmt::skip]
        let sstp_msg: [u8; 112] = [
            0x10, 0x01, 0x00, 0x70, 0x00, 0x04, 0x00, 0x01,
            0x00, 0x03, 0x00, 0x68, 0x00, 0x00, 0x00, 0x01,
            0x0F, 0x1A, 0x2D, 0x58, 0xD4, 0xA3, 0xE3, 0x00,
            0x0F, 0xAD, 0x3C, 0xE4, 0x90, 0x6E, 0x07, 0xB7,
            0x07, 0xAA, 0x9E, 0x44, 0x1C, 0xCE, 0xAC, 0x5C,
            0xBD, 0x7B, 0x2C, 0xC1, 0xC9, 0xD8, 0x6C, 0xDF,
            0x58, 0x26, 0xB6, 0x29, 0xBD, 0xA5, 0x9B, 0x8E,
            0x6F, 0xD8, 0xDC, 0xD2, 0x62, 0x2F, 0xD3, 0x4C,
            0x53, 0x48, 0x05, 0xA5, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let send_key: [u8; 16] = [
            0x4B, 0x31, 0x28, 0xF4, 0x39, 0x25, 0xD9, 0x00, 0x6E, 0xEF, 0xB1, 0xC4, 0xE8, 0x65, 0x15, 0xA1,
        ];
        let recv_key: [u8; 16] = [
            0xD8, 0x8E, 0x56, 0xBA, 0xB3, 0xCA, 0x2B, 0xDF, 0x03, 0x73, 0xB7, 0xF5, 0xA8, 0xA1, 0x3B, 0x19,
        ];
        let expected: [u8; 20] = [
            0x69, 0x91, 0x5D, 0xD5, 0x83, 0xD8, 0x06, 0x2F, 0xEF, 0x16, 0xF6, 0x1D, 0xB2, 0xF0, 0x32, 0x90, 0xEC,
            0x27, 0xCB, 0x6C,
        ];

        let result = compound_mac(HashAlgo::Sha1, &send_key, &recv_key, &sstp_msg);
        assert_eq!(result, expected);
    }

    /// End-to-end check of `build_connected_message` using the exact same
    /// reference vector as `sha1_matches_reference_test_vector`, but this
    /// time reconstructing the whole packet from its nonce/cert-hash/keys
    /// instead of comparing only the raw HMAC output — this is what
    /// exercises the byte-offset bookkeeping (attribute layout, MAC field
    /// placement) that `compound_mac` alone doesn't touch.
    #[test]
    fn build_connected_message_matches_reference_sha1_vector() {
        #[rustfmt::skip]
        let sstp_msg_no_mac: [u8; 112] = [
            0x10, 0x01, 0x00, 0x70, 0x00, 0x04, 0x00, 0x01,
            0x00, 0x03, 0x00, 0x68, 0x00, 0x00, 0x00, 0x01,
            0x0F, 0x1A, 0x2D, 0x58, 0xD4, 0xA3, 0xE3, 0x00,
            0x0F, 0xAD, 0x3C, 0xE4, 0x90, 0x6E, 0x07, 0xB7,
            0x07, 0xAA, 0x9E, 0x44, 0x1C, 0xCE, 0xAC, 0x5C,
            0xBD, 0x7B, 0x2C, 0xC1, 0xC9, 0xD8, 0x6C, 0xDF,
            0x58, 0x26, 0xB6, 0x29, 0xBD, 0xA5, 0x9B, 0x8E,
            0x6F, 0xD8, 0xDC, 0xD2, 0x62, 0x2F, 0xD3, 0x4C,
            0x53, 0x48, 0x05, 0xA5, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let send_key: [u8; 16] = [
            0x4B, 0x31, 0x28, 0xF4, 0x39, 0x25, 0xD9, 0x00, 0x6E, 0xEF, 0xB1, 0xC4, 0xE8, 0x65, 0x15, 0xA1,
        ];
        let recv_key: [u8; 16] = [
            0xD8, 0x8E, 0x56, 0xBA, 0xB3, 0xCA, 0x2B, 0xDF, 0x03, 0x73, 0xB7, 0xF5, 0xA8, 0xA1, 0x3B, 0x19,
        ];
        let expected_mac: [u8; 20] = [
            0x69, 0x91, 0x5D, 0xD5, 0x83, 0xD8, 0x06, 0x2F, 0xEF, 0x16, 0xF6, 0x1D, 0xB2, 0xF0, 0x32, 0x90, 0xEC,
            0x27, 0xCB, 0x6C,
        ];

        let nonce: [u8; 32] = sstp_msg_no_mac[16..48].try_into().unwrap();
        let cert_hash: [u8; 32] = sstp_msg_no_mac[48..80].try_into().unwrap();

        let built = build_connected_message(HashAlgo::Sha1, &nonce, &cert_hash, &send_key, &recv_key);

        let mut expected_packet = sstp_msg_no_mac.to_vec();
        expected_packet[80..100].copy_from_slice(&expected_mac);
        // bytes [100..112) stay zero: SHA1's 20-byte MAC only fills the
        // first 20 of the 32-byte field.

        assert_eq!(built, expected_packet);
    }

    #[test]
    fn sha256_matches_reference_test_vector() {
        #[rustfmt::skip]
        let sstp_msg: [u8; 112] = [
            0x10, 0x01, 0x00, 0x70, 0x00, 0x04, 0x00, 0x01,
            0x00, 0x03, 0x00, 0x68, 0x00, 0x00, 0x00, 0x02,
            0x41, 0x2B, 0x48, 0x9A, 0xEB, 0xD7, 0xEC, 0xC7,
            0xD0, 0x89, 0x66, 0xF2, 0x6B, 0xE7, 0xCD, 0x72,
            0xB2, 0x31, 0xA0, 0xE9, 0x21, 0x0D, 0x7C, 0x91,
            0xB3, 0x08, 0x86, 0x2B, 0x03, 0x44, 0xC4, 0x35,
            0x79, 0x93, 0xEF, 0x31, 0x4C, 0x49, 0x3D, 0xAC,
            0xE9, 0xF0, 0x2D, 0x60, 0xE7, 0xE6, 0x1C, 0x84,
            0xB6, 0x69, 0x0A, 0xAF, 0xE9, 0xD7, 0xAE, 0xEA,
            0x92, 0xCB, 0xBE, 0x8A, 0xD5, 0x99, 0x42, 0x2D,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let send_key: [u8; 16] = [
            0x2A, 0x1B, 0xB4, 0x0D, 0x55, 0xAB, 0x0F, 0x5E, 0xF3, 0x2F, 0x06, 0xF2, 0xB3, 0xCC, 0x73, 0xC4,
        ];
        let recv_key: [u8; 16] = [
            0x8F, 0xD3, 0xFA, 0xC4, 0x1D, 0x7A, 0x13, 0x15, 0xA1, 0x92, 0x28, 0xD9, 0x02, 0x4C, 0xA1, 0x64,
        ];
        let expected: [u8; 32] = [
            0x52, 0xA6, 0x8E, 0xFD, 0x8C, 0xFF, 0xBF, 0x52, 0x77, 0x0B, 0x8F, 0x0F, 0xE8, 0xEC, 0x73, 0x71, 0x65,
            0x83, 0xAF, 0x6D, 0x61, 0x1E, 0xB6, 0xD1, 0x79, 0xB3, 0xB2, 0x08, 0x40, 0x98, 0x54, 0x49,
        ];

        let result = compound_mac(HashAlgo::Sha256, &send_key, &recv_key, &sstp_msg);
        assert_eq!(result, expected);
    }

    #[test]
    fn seed_matches_reference_byte_array() {
        assert_eq!(SEED.len(), 29);
        let expected: [u8; 29] = [
            0x53, 0x53, 0x54, 0x50, 0x20, 0x69, 0x6E, 0x6E, 0x65, 0x72, 0x20, 0x6d, 0x65, 0x74, 0x68, 0x6F, 0x64,
            0x20, 0x64, 0x65, 0x72, 0x69, 0x76, 0x65, 0x64, 0x20, 0x43, 0x4D, 0x4B,
        ];
        assert_eq!(*SEED, expected);
    }
}
