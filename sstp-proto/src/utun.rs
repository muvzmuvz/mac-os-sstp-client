//! macOS `utun` virtual network interface creation, entirely in userspace
//! via the kernel's `PF_SYSTEM`/`SYSPROTO_CONTROL` socket family — no
//! pppd, no kernel extension, no special entitlement beyond the root
//! privilege this app already needs to change routes. This is what lets
//! the engine own a real point-to-point network interface directly,
//! sidestepping every pppd-related failure mode this session ran into
//! (zombie interfaces, SIGKILL not being honored, syslog-only logging).
//!
//! The struct layouts and ioctl encoding below are XNU's
//! `<sys/kern_control.h>` / `<sys/sys_domain.h>`, reproduced directly
//! rather than assumed to be in the `libc` crate (which doesn't expose
//! these Apple-specific definitions) — the same approach WireGuard's and
//! other Rust VPN clients' macOS `utun` support takes.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const AF_SYSTEM: u8 = 32;
const AF_SYS_CONTROL: u16 = 2;
const SYSPROTO_CONTROL: libc::c_int = 2;
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";
const UTUN_OPT_IFNAME: libc::c_int = 2;

/// The 4-byte address-family header every packet read from/written to a
/// utun fd is prefixed with, network-byte-order `AF_INET` (utun's own
/// framing convention, unrelated to anything IP-header-level).
pub const IPV4_FAMILY_HEADER: [u8; 4] = [0, 0, 0, libc::AF_INET as u8];

#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [libc::c_char; 96],
}

#[repr(C)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

/// `_IOWR('N', 3, struct ctl_info)`, computed the same way `<sys/ioctl.h>`'s
/// macro does (BSD ioctl encoding packs direction/size/group/number into
/// one word) rather than hardcoded, so the derivation is checkable against
/// the struct's actual size instead of being a magic number.
fn ctliocginfo() -> libc::c_ulong {
    const IOC_INOUT: u32 = 0x8000_0000 | 0x4000_0000;
    const IOCPARM_MASK: u32 = 0x1fff;
    let len = std::mem::size_of::<CtlInfo>() as u32;
    (IOC_INOUT | ((len & IOCPARM_MASK) << 16) | ((b'N' as u32) << 8) | 3) as libc::c_ulong
}

#[derive(Debug, thiserror::Error)]
pub enum UtunError {
    #[error("failed to open the utun control socket: {0}")]
    Socket(io::Error),
    #[error("CTLIOCGINFO failed (only works on macOS): {0}")]
    ControlInfo(io::Error),
    #[error("connect() to the utun kernel control failed (this needs root): {0}")]
    Connect(io::Error),
    #[error("could not read back the assigned utun interface name: {0}")]
    GetIfName(io::Error),
}

/// A single open `utun` interface. Dropping this closes the fd, which
/// (unlike a killed pppd) the kernel guarantees tears the interface down
/// immediately and completely — no zombie-interface failure mode is even
/// possible here.
pub struct Utun {
    fd: OwnedFd,
    name: String,
}

impl Utun {
    /// Creates a new utun interface, letting the kernel assign the next
    /// free unit number (`utun0`, `utun1`, ...). Requires root — the
    /// `connect()` call to the kernel control fails with `EPERM`/`EACCES`
    /// otherwise.
    pub fn create() -> Result<Self, UtunError> {
        let raw_fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
        if raw_fd < 0 {
            return Err(UtunError::Socket(io::Error::last_os_error()));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        let mut info = CtlInfo { ctl_id: 0, ctl_name: [0; 96] };
        for (slot, byte) in info.ctl_name.iter_mut().zip(UTUN_CONTROL_NAME) {
            *slot = *byte as libc::c_char;
        }
        // SAFETY: `info` is a valid, correctly-sized `CtlInfo` for the
        // duration of this call; the kernel only reads `ctl_name` and
        // writes `ctl_id` back into it.
        let ret = unsafe { libc::ioctl(fd.as_raw_fd(), ctliocginfo(), &mut info) };
        if ret != 0 {
            return Err(UtunError::ControlInfo(io::Error::last_os_error()));
        }

        let addr = SockaddrCtl {
            sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
            sc_family: AF_SYSTEM,
            ss_sysaddr: AF_SYS_CONTROL,
            sc_id: info.ctl_id,
            sc_unit: 0, // 0 = let the kernel assign the next free utun unit
            sc_reserved: [0; 5],
        };
        // SAFETY: `addr` is a valid `sockaddr_ctl` for the duration of this
        // call, cast to the generic `sockaddr*` connect() expects; its
        // declared size matches what's passed as the length argument.
        let ret = unsafe {
            libc::connect(fd.as_raw_fd(), (&addr as *const SockaddrCtl).cast(), std::mem::size_of::<SockaddrCtl>() as libc::socklen_t)
        };
        if ret != 0 {
            return Err(UtunError::Connect(io::Error::last_os_error()));
        }

        let mut name_buf = [0u8; 64];
        let mut name_len = name_buf.len() as libc::socklen_t;
        // SAFETY: `name_buf`/`name_len` describe a valid writable buffer of
        // the given length for the duration of this call.
        let ret = unsafe {
            libc::getsockopt(fd.as_raw_fd(), SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name_buf.as_mut_ptr().cast(), &mut name_len)
        };
        if ret != 0 {
            return Err(UtunError::GetIfName(io::Error::last_os_error()));
        }
        let name = String::from_utf8_lossy(&name_buf[..name_len as usize]).trim_end_matches('\0').to_string();

        Ok(Utun { fd, name })
    }

    /// The kernel-assigned interface name, e.g. `"utun7"` — what the rest
    /// of this app (route management, `ifconfig`) refers to it by.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Assigns the point-to-point address pair IPCP negotiated and brings
    /// the interface up. Shells out to `ifconfig` rather than issuing the
    /// equivalent `SIOCAIFADDR` ioctl directly: this process is already
    /// running as root (required just to have created the utun fd at all),
    /// and reusing the same well-tested command-based approach the rest of
    /// this app's route management already relies on is simpler and no
    /// less correct than hand-rolling another ioctl struct for a one-shot
    /// setup step.
    pub fn configure_ipv4(&self, local: std::net::Ipv4Addr, peer: std::net::Ipv4Addr) -> io::Result<()> {
        let status = std::process::Command::new("/sbin/ifconfig")
            .args([&self.name, "inet", &local.to_string(), &peer.to_string(), "up"])
            .status()?;
        if !status.success() {
            return Err(io::Error::other(format!("ifconfig {} exited with {status}", self.name)));
        }
        Ok(())
    }

    /// Reads one packet, blocking the calling thread/task until one
    /// arrives. `connection.rs` drives this from a dedicated
    /// `spawn_blocking` thread rather than the main async loop, since a
    /// VPN's packet rate has no need for the extra complexity of
    /// non-blocking + `AsyncFd` readiness polling. Returns the raw IP
    /// packet with the 4-byte utun family header already stripped.
    pub fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut framed = vec![0u8; buf.len() + 4];
        let n = unsafe { libc::read(self.fd.as_raw_fd(), framed.as_mut_ptr().cast(), framed.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        if n < 4 {
            return Ok(0);
        }
        let payload_len = n - 4;
        buf[..payload_len].copy_from_slice(&framed[4..n]);
        Ok(payload_len)
    }

    /// Writes one IPv4 packet (without the family header — this adds it).
    pub fn write_packet(&self, ip_packet: &[u8]) -> io::Result<()> {
        let mut framed = Vec::with_capacity(4 + ip_packet.len());
        framed.extend_from_slice(&IPV4_FAMILY_HEADER);
        framed.extend_from_slice(ip_packet);
        let n = unsafe { libc::write(self.fd.as_raw_fd(), framed.as_ptr().cast(), framed.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl AsRawFd for Utun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctliocginfo_matches_known_macos_constant() {
        // This exact value (0xc0644e03) is the well-known, widely
        // cross-checked CTLIOCGINFO constant on macOS (every other utun
        // implementation -- WireGuard, various Rust `tun` crates -- uses
        // the same number); deriving it from the encoding macro and
        // pinning it here catches a struct-layout mistake immediately
        // instead of only at `Utun::create()` time (which needs root and
        // can only be exercised on real macOS).
        assert_eq!(ctliocginfo(), 0xc0644e03);
    }

    #[test]
    fn ctl_info_and_sockaddr_ctl_have_expected_sizes() {
        // 4-byte ctl_id + 96-byte name.
        assert_eq!(std::mem::size_of::<CtlInfo>(), 100);
        // sc_len(1) + sc_family(1) + ss_sysaddr(2) + sc_id(4) + sc_unit(4) + sc_reserved(5*4).
        assert_eq!(std::mem::size_of::<SockaddrCtl>(), 32);
    }

    #[test]
    fn ipv4_family_header_is_network_byte_order_af_inet() {
        assert_eq!(IPV4_FAMILY_HEADER, [0, 0, 0, libc::AF_INET as u8]);
    }
}
