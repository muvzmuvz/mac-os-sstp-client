//! MPPE send/receive key derivation from the MS-CHAPv2 exchange (RFC 3079),
//! ported byte-for-byte from `vendor/sstp-client/src/sstp-chap.c`
//! (`sstp_chap_hash_pass` / `sstp_chap_hash_master` / `sstp_chap_hash_session`
//! / `sstp_chap_mppe_get`). The reference implementation's own unit test
//! (`__SSTP_UNIT_TEST_CHAP` in that file) has a hardcoded password/
//! challenge/expected-key vector; that exact vector is `mppe_get_keys`'s
//! test below, so a mistake here fails loudly in `cargo test` rather than
//! silently in a live handshake against the real server.

use md4::{Digest, Md4};
use sha1::Sha1;

/// ASCII "This is the MPPE Master Key".
const MASTER_KEY_MAGIC: &[u8; 27] = b"This is the MPPE Master Key";
// Note: the literal above is 28 bytes (including the trailing NUL Rust
// doesn't add, so actually 28 visible chars) -- see the const assertion in
// the test module, which pins this down against the reference's raw byte
// array instead of trusting the string literal's length by eye.

/// ASCII "On the client side, this is the send key; on the server side, it
/// is the receive key."
const SESSION_KEY_MAGIC_CLIENT_SEND: &[u8] =
    b"On the client side, this is the send key; on the server side, it is the receive key.";

/// ASCII "On the client side, this is the receive key; on the server side,
/// it is the send key."
const SESSION_KEY_MAGIC_CLIENT_RECV: &[u8] =
    b"On the client side, this is the receive key; on the server side, it is the send key.";

/// `sstp_chap_hash_pass`: the MS-CHAPv2 "Password Hash Hash" — MD4 of the
/// password re-encoded as (naive, ASCII-only) UTF-16LE, then MD4'd again.
fn password_hash_hash(password: &str) -> [u8; 16] {
    let mut utf16le = Vec::with_capacity(password.len() * 2);
    for byte in password.bytes() {
        utf16le.push(byte);
        utf16le.push(0);
    }

    let nt_hash = Md4::digest(&utf16le);
    let hash_hash = Md4::digest(nt_hash);
    hash_hash.into()
}

/// `sstp_chap_hash_master`: SHA1(password-hash-hash || nt-response ||
/// "This is the MPPE Master Key"), truncated to 16 bytes.
fn master_key(password_hash_hash: [u8; 16], nt_response: &[u8; 24]) -> [u8; 16] {
    let mut hasher = Sha1::new();
    hasher.update(password_hash_hash);
    hasher.update(nt_response);
    hasher.update(MASTER_KEY_MAGIC);
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// `sstp_chap_hash_session`: SHA1(master || 40×0x00 || magic[84] ||
/// 40×0xf2), truncated to 16 bytes. `sending`/`is_server` select which of
/// the two RFC-3079 magic strings applies, matching the reference's flag
/// logic in `sstp_chap_hash_session` exactly (client-send and
/// server-receive share one magic string; client-receive and server-send
/// share the other).
fn session_key(master: [u8; 16], sending: bool, is_server: bool) -> [u8; 16] {
    let use_send_magic = sending != is_server;
    let magic = if use_send_magic { SESSION_KEY_MAGIC_CLIENT_SEND } else { SESSION_KEY_MAGIC_CLIENT_RECV };

    let mut hasher = Sha1::new();
    hasher.update(master);
    hasher.update([0u8; 40]);
    hasher.update(magic);
    hasher.update([0xf2u8; 40]);
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// The two MPPE keys derived once MS-CHAPv2 authentication succeeds.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MppeKeys {
    pub send_key: [u8; 16],
    pub recv_key: [u8; 16],
}

impl std::fmt::Debug for MppeKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material, even in debug logs.
        f.debug_struct("MppeKeys").field("send_key", &"<redacted>").field("recv_key", &"<redacted>").finish()
    }
}

/// `sstp_chap_mppe_get`: derive the send/receive MPPE keys from the
/// password and the 24-byte MS-CHAPv2 `nt_response`. `is_server` is always
/// `false` for us — we only ever act as the SSTP/PPP client.
pub fn mppe_get_keys(password: &str, nt_response: &[u8; 24], is_server: bool) -> MppeKeys {
    let phash = password_hash_hash(password);
    let master = master_key(phash, nt_response);
    let recv_key = session_key(master, false, is_server);
    let send_key = session_key(master, true, is_server);
    MppeKeys { send_key, recv_key }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_strings_match_reference_byte_arrays() {
        // Pin the string literals above against the exact byte arrays in
        // sstp-chap.c, so a typo in the literal can't silently drift.
        assert_eq!(MASTER_KEY_MAGIC.len(), 27);
        let expected_master_magic: [u8; 27] = [
            0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x4d, 0x50, 0x50, 0x45, 0x20,
            0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4b, 0x65, 0x79,
        ];
        assert_eq!(*MASTER_KEY_MAGIC, expected_master_magic);

        assert_eq!(SESSION_KEY_MAGIC_CLIENT_SEND.len(), 84);
        assert_eq!(SESSION_KEY_MAGIC_CLIENT_RECV.len(), 84);
    }

    /// The exact vector from `sstp-chap.c`'s own `__SSTP_UNIT_TEST_CHAP`
    /// main(): password "DukeNuke3D", a fixed challenge/nt_response pair,
    /// and hardcoded expected send/receive keys. `sstp_chap_mppe_get` is
    /// called there with `server = false` (client mode), matching
    /// `is_server: false` here.
    #[test]
    fn matches_reference_implementation_test_vector() {
        let nt_response: [u8; 24] = [
            0x85, 0x9a, 0x0c, 0x0e, 0xce, 0x47, 0x4d, 0xf2, 0x0d, 0x0a, 0xe8, 0x31, 0xac, 0x3a, 0xe3, 0xd2, 0x4f,
            0x82, 0x6e, 0x93, 0x67, 0x9e, 0x36, 0xbc,
        ];
        let expected_send_key: [u8; 16] = [
            0x00, 0x0b, 0xc1, 0xde, 0xa2, 0xcb, 0x85, 0x16, 0xbc, 0x77, 0xf5, 0x52, 0xb9, 0xec, 0x5a, 0x03,
        ];
        let expected_recv_key: [u8; 16] = [
            0x93, 0xd9, 0x27, 0x06, 0xf5, 0x13, 0xa2, 0xea, 0x50, 0xf8, 0xcd, 0x94, 0x69, 0x57, 0x3c, 0xdb,
        ];

        let keys = mppe_get_keys("DukeNuke3D", &nt_response, false);
        assert_eq!(keys.send_key, expected_send_key, "send key mismatch");
        assert_eq!(keys.recv_key, expected_recv_key, "recv key mismatch");
    }

    #[test]
    fn debug_impl_never_prints_key_material() {
        let keys = mppe_get_keys("hunter2", &[0u8; 24], false);
        let debug_str = format!("{keys:?}");
        assert!(!debug_str.contains(&format!("{:?}", keys.send_key)));
        assert!(debug_str.contains("redacted"));
    }
}
