// SPDX-License-Identifier: MIT

use std::{
    convert::TryFrom,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use base64::{prelude::BASE64_STANDARD, Engine};
use netlink_packet_wireguard::{
    WireguardAddressFamily, WireguardAllowedIp, WireguardAllowedIpAttr,
    WireguardAllowedIpFlags, WireguardPeer, WireguardPeerAttribute,
    WireguardPeerFlags, WireguardTimeSpec,
};

use super::parsed::decode_key;
use crate::{ErrorKind, WireguardError};

/// Nanoseconds of one second, `Duration::new()` panics when its
/// nanoseconds argument is not smaller than this.
const NANOS_PER_SECOND: i64 = 1_000_000_000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum WireguardParsedPeerFlags {
    RemoveMe,
    ReplaceAllowedIps,
    UpdateOnly,
    Other(u32),
}

impl From<WireguardParsedPeerFlags> for WireguardPeerFlags {
    fn from(flag: WireguardParsedPeerFlags) -> Self {
        match flag {
            WireguardParsedPeerFlags::RemoveMe => WireguardPeerFlags::RemoveMe,
            WireguardParsedPeerFlags::ReplaceAllowedIps => {
                WireguardPeerFlags::ReplaceAllowedIps
            }
            WireguardParsedPeerFlags::UpdateOnly => {
                WireguardPeerFlags::UpdateOnly
            }
            WireguardParsedPeerFlags::Other(bits) => {
                WireguardPeerFlags::from_bits_retain(bits)
            }
        }
    }
}

impl From<WireguardPeerFlags> for WireguardParsedPeerFlags {
    fn from(flag: WireguardPeerFlags) -> Self {
        match flag {
            WireguardPeerFlags::RemoveMe => WireguardParsedPeerFlags::RemoveMe,
            WireguardPeerFlags::ReplaceAllowedIps => {
                WireguardParsedPeerFlags::ReplaceAllowedIps
            }
            WireguardPeerFlags::UpdateOnly => {
                WireguardParsedPeerFlags::UpdateOnly
            }
            _ => WireguardParsedPeerFlags::Other(flag.bits()),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct WireguardPeerParsed {
    pub endpoint: Option<SocketAddr>,
    /// Base64 encoded public key
    pub public_key: Option<String>,
    /// Base64 encoded pre-shared key, this property will be display as
    /// `(hidden)` for `Debug` trait.
    pub preshared_key: Option<String>,
    pub persistent_keepalive: Option<u16>,
    /// Last handshake time since UNIX_EPOCH
    pub last_handshake: Option<Duration>,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
    pub allowed_ips: Option<Vec<WireguardIpAddress>>,
    pub protocol_version: Option<u32>,
    pub flags: Option<Vec<WireguardParsedPeerFlags>>,
}

// For simplifying the code on hide `preshared_key` in Debug display of
// [WireguardPeerParsed]
#[allow(dead_code)]
#[derive(Debug)]
struct _WireguardPeerParsed<'a> {
    endpoint: &'a Option<SocketAddr>,
    public_key: &'a Option<String>,
    preshared_key: Option<String>,
    persistent_keepalive: &'a Option<u16>,
    last_handshake: &'a Option<Duration>,
    rx_bytes: &'a Option<u64>,
    tx_bytes: &'a Option<u64>,
    allowed_ips: &'a Option<Vec<WireguardIpAddress>>,
    protocol_version: &'a Option<u32>,
    flags: &'a Option<Vec<WireguardParsedPeerFlags>>,
}

impl std::fmt::Debug for WireguardPeerParsed {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> Result<(), std::fmt::Error> {
        let Self {
            endpoint,
            public_key,
            preshared_key,
            persistent_keepalive,
            last_handshake,
            rx_bytes,
            tx_bytes,
            allowed_ips,
            protocol_version,
            flags,
        } = self;

        std::fmt::Debug::fmt(
            &_WireguardPeerParsed {
                endpoint,
                public_key,
                preshared_key: if preshared_key.is_some() {
                    Some("(hidden)".to_string())
                } else {
                    None
                },
                persistent_keepalive,
                last_handshake,
                rx_bytes,
                tx_bytes,
                allowed_ips,
                protocol_version,
                flags,
            },
            f,
        )
    }
}

impl From<WireguardPeer> for WireguardPeerParsed {
    fn from(attrs: WireguardPeer) -> Self {
        let mut ret = Self::default();
        for attr in attrs.0 {
            match attr {
                WireguardPeerAttribute::PublicKey(v) => {
                    ret.public_key = Some(BASE64_STANDARD.encode(v));
                }
                WireguardPeerAttribute::PresharedKey(v) => {
                    if v.as_slice().iter().all(|i| *i == 0) {
                        ret.preshared_key = None;
                    } else {
                        ret.preshared_key = Some(BASE64_STANDARD.encode(v));
                    }
                }
                WireguardPeerAttribute::Endpoint(v) => ret.endpoint = Some(v),
                WireguardPeerAttribute::PersistentKeepalive(v) => {
                    ret.persistent_keepalive = Some(v)
                }
                WireguardPeerAttribute::LastHandshake(v) => {
                    if v.seconds == 0 && v.nano_seconds == 0 {
                        ret.last_handshake = None;
                    } else if v.seconds >= 0
                        && v.nano_seconds >= 0
                        && v.nano_seconds < NANOS_PER_SECOND
                    {
                        ret.last_handshake = Some(Duration::new(
                            v.seconds as u64,
                            v.nano_seconds as u32,
                        ));
                    } else {
                        log::warn!(
                            "Ignoring invalid last handshake time: {v:?}"
                        );
                    }
                }
                WireguardPeerAttribute::RxBytes(v) => ret.rx_bytes = Some(v),
                WireguardPeerAttribute::TxBytes(v) => ret.tx_bytes = Some(v),
                WireguardPeerAttribute::ProtocolVersion(v) => {
                    ret.protocol_version = Some(v)
                }
                WireguardPeerAttribute::AllowedIps(wg_ips) => {
                    let mut ips = Vec::new();
                    for wg_ip in &wg_ips {
                        match WireguardIpAddress::try_from(wg_ip) {
                            Ok(i) => ips.push(i),
                            Err(e) => {
                                log::warn!(
                                    "Ignoring invalid WireguardAllowedIp: {e}"
                                );
                            }
                        }
                    }
                    ret.allowed_ips = Some(ips.into_iter().collect());
                }
                WireguardPeerAttribute::Flags(flag_bits) => {
                    let mut flags = Vec::new();
                    for flag_bit in flag_bits.iter() {
                        flags.push(WireguardParsedPeerFlags::from(flag_bit));
                    }
                    ret.flags = Some(flags);
                }
                _ => {
                    log::debug!("Unsupported WireguardPeerAttribute {attr:?}");
                }
            }
        }
        ret
    }
}

impl WireguardPeerParsed {
    /// Merge a continuation of this peer which the kernel sent in a
    /// following message.
    ///
    /// A peer which does not fit into a single message is repeated with
    /// only `WGPEER_A_PUBLIC_KEY` and the remaining `WGPEER_A_ALLOWEDIPS`,
    /// so adjacent peers with the same public key have to be coalesced.
    pub(crate) fn merge_continuation(&mut self, continuation: Self) {
        if let Some(more) = continuation.allowed_ips {
            match self.allowed_ips.as_mut() {
                Some(allowed_ips) => allowed_ips.extend(more),
                None => self.allowed_ips = Some(more),
            }
        }
        if self.public_key.is_none() {
            self.public_key = continuation.public_key;
        }
        if self.preshared_key.is_none() {
            self.preshared_key = continuation.preshared_key;
        }
        if self.endpoint.is_none() {
            self.endpoint = continuation.endpoint;
        }
        if self.persistent_keepalive.is_none() {
            self.persistent_keepalive = continuation.persistent_keepalive;
        }
        if self.last_handshake.is_none() {
            self.last_handshake = continuation.last_handshake;
        }
        if self.rx_bytes.is_none() {
            self.rx_bytes = continuation.rx_bytes;
        }
        if self.tx_bytes.is_none() {
            self.tx_bytes = continuation.tx_bytes;
        }
        if self.protocol_version.is_none() {
            self.protocol_version = continuation.protocol_version;
        }
        if let Some(flags) = continuation.flags {
            self.flags.get_or_insert_with(Vec::new).extend(flags);
        }
    }

    pub fn build(&self) -> Result<WireguardPeer, WireguardError> {
        let mut attrs: Vec<WireguardPeerAttribute> = Vec::new();

        if self.public_key.is_none() {
            return Err(WireguardError::new(
                ErrorKind::InvalidInput,
                "Peer is missing `public_key` which the kernel requires"
                    .to_string(),
                None,
            ));
        }

        if let Some(v) = self.endpoint {
            attrs.push(WireguardPeerAttribute::Endpoint(v));
        }

        if let Some(v) = self.public_key.as_deref() {
            attrs.push(WireguardPeerAttribute::PublicKey(decode_key(
                "peer.public_key",
                v,
            )?));
        }

        if let Some(v) = self.preshared_key.as_deref() {
            attrs.push(WireguardPeerAttribute::PresharedKey(decode_key(
                "peer.preshared_key",
                v,
            )?));
        }

        if let Some(v) = self.persistent_keepalive {
            attrs.push(WireguardPeerAttribute::PersistentKeepalive(v));
        }

        if let Some(v) = self.last_handshake {
            attrs.push(WireguardPeerAttribute::LastHandshake(
                WireguardTimeSpec {
                    seconds: v.as_secs() as i64,
                    nano_seconds: v.subsec_nanos() as i64,
                },
            ));
        }

        if let Some(v) = self.rx_bytes {
            attrs.push(WireguardPeerAttribute::RxBytes(v));
        }

        if let Some(v) = self.tx_bytes {
            attrs.push(WireguardPeerAttribute::TxBytes(v));
        }

        if let Some(ips) = self.allowed_ips.as_ref() {
            for ip in ips {
                ip.validate()?;
            }
            attrs.push(WireguardPeerAttribute::AllowedIps(
                ips.iter()
                    .map(|ip| {
                        WireguardAllowedIp(Vec::<WireguardAllowedIpAttr>::from(
                            ip,
                        ))
                    })
                    .collect(),
            ));
        }

        if let Some(v) = self.protocol_version {
            attrs.push(WireguardPeerAttribute::ProtocolVersion(v));
        }

        if let Some(flags) = self.flags.as_ref() {
            let flag_bits =
                flags.iter().map(|&f| WireguardPeerFlags::from(f)).collect();
            attrs.push(WireguardPeerAttribute::Flags(flag_bits));
        }

        Ok(WireguardPeer(attrs))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum WireguardParsedAllowedIpFlags {
    RemoveMe,
    Other(u32),
}

impl From<WireguardParsedAllowedIpFlags> for WireguardAllowedIpFlags {
    fn from(flag: WireguardParsedAllowedIpFlags) -> Self {
        match flag {
            WireguardParsedAllowedIpFlags::RemoveMe => {
                WireguardAllowedIpFlags::RemoveMe
            }
            WireguardParsedAllowedIpFlags::Other(bits) => {
                WireguardAllowedIpFlags::from_bits_retain(bits)
            }
        }
    }
}

impl From<WireguardAllowedIpFlags> for WireguardParsedAllowedIpFlags {
    fn from(flag: WireguardAllowedIpFlags) -> Self {
        match flag {
            WireguardAllowedIpFlags::RemoveMe => {
                WireguardParsedAllowedIpFlags::RemoveMe
            }
            _ => WireguardParsedAllowedIpFlags::Other(flag.bits()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireguardIpAddress {
    pub prefix_length: u8,
    pub ip_addr: IpAddr,
    pub flags: Option<Vec<WireguardParsedAllowedIpFlags>>,
}

impl WireguardIpAddress {
    /// Check that the prefix length matches the address family, the kernel
    /// rejects larger values with `-EINVAL`.
    fn validate(&self) -> Result<(), WireguardError> {
        let max_prefix_length = if self.ip_addr.is_ipv4() { 32 } else { 128 };
        if self.prefix_length > max_prefix_length {
            return Err(WireguardError::new(
                ErrorKind::InvalidInput,
                format!(
                    "`prefix_length` {} is too large for {}, expecting at \
                     most {}",
                    self.prefix_length, self.ip_addr, max_prefix_length
                ),
                None,
            ));
        }
        Ok(())
    }
}

impl TryFrom<&WireguardAllowedIp> for WireguardIpAddress {
    type Error = WireguardError;

    fn try_from(attrs: &WireguardAllowedIp) -> Result<Self, WireguardError> {
        let mut ip_addr: Option<IpAddr> = None;
        let mut prefix_length: Option<u8> = None;
        let mut flags: Option<Vec<WireguardParsedAllowedIpFlags>> = None;

        for attr in &attrs.0 {
            match attr {
                WireguardAllowedIpAttr::IpAddr(v) => ip_addr = Some(*v),
                WireguardAllowedIpAttr::Cidr(v) => prefix_length = Some(*v),
                WireguardAllowedIpAttr::Family(_) => (),
                WireguardAllowedIpAttr::Flags(flag_bits) => {
                    let mut flag_vec = Vec::new();
                    for flag_bit in flag_bits.iter() {
                        flag_vec.push(WireguardParsedAllowedIpFlags::from(
                            flag_bit,
                        ));
                    }
                    flags = Some(flag_vec);
                }
                _ => {
                    log::debug!("Unsupported WireguardAllowedIpAttr {attr:?}");
                }
            }
        }
        if let Some(ip_addr) = ip_addr {
            if let Some(prefix_length) = prefix_length {
                Ok(Self {
                    ip_addr,
                    prefix_length,
                    flags,
                })
            } else {
                Err(WireguardError::new(
                    ErrorKind::DecodeError,
                    "WireguardAllowedIp does not have \
                     WireguardAllowedIpAttr::Cidr defined"
                        .to_string(),
                    None,
                ))
            }
        } else {
            Err(WireguardError::new(
                ErrorKind::DecodeError,
                "WireguardAllowedIp does not have \
                 WireguardAllowedIpAttr::IpAddr defined"
                    .to_string(),
                None,
            ))
        }
    }
}

impl From<&WireguardIpAddress> for Vec<WireguardAllowedIpAttr> {
    fn from(ip: &WireguardIpAddress) -> Self {
        let mut result = Vec::with_capacity(4);
        result.push(WireguardAllowedIpAttr::Cidr(ip.prefix_length));
        if ip.ip_addr.is_ipv4() {
            result.push(WireguardAllowedIpAttr::Family(
                WireguardAddressFamily::Ipv4,
            ));
        } else {
            result.push(WireguardAllowedIpAttr::Family(
                WireguardAddressFamily::Ipv6,
            ));
        }
        result.push(WireguardAllowedIpAttr::IpAddr(ip.ip_addr));
        if let Some(flags) = ip.flags.as_ref() {
            let flag_bits = flags
                .iter()
                .map(|&f| WireguardAllowedIpFlags::from(f))
                .collect();
            result.push(WireguardAllowedIpAttr::Flags(flag_bits));
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    const PEER_PUBLIC_KEY: &str =
        "8bdQrVLqiw3ZoHCucNh1YfH0iCWuyStniRr8t7H24Fk=";

    fn peer_with_last_handshake(
        seconds: i64,
        nano_seconds: i64,
    ) -> WireguardPeer {
        WireguardPeer(vec![
            WireguardPeerAttribute::PublicKey([1u8; 32]),
            WireguardPeerAttribute::LastHandshake(WireguardTimeSpec {
                seconds,
                nano_seconds,
            }),
        ])
    }

    #[test]
    fn last_handshake_is_parsed() {
        let peer = WireguardPeerParsed::from(peer_with_last_handshake(
            1_700_000_000,
            123_456_789,
        ));

        assert_eq!(
            peer.last_handshake,
            Some(Duration::new(1_700_000_000, 123_456_789))
        );
    }

    #[test]
    fn invalid_last_handshake_is_ignored() {
        // `Duration::new()` panics when the nanoseconds are not smaller
        // than one second.
        for nano_seconds in [1_000_000_000i64, 1_500_000_000, 4_000_000_000] {
            let peer = WireguardPeerParsed::from(peer_with_last_handshake(
                1,
                nano_seconds,
            ));
            assert_eq!(peer.last_handshake, None);
        }

        for (seconds, nano_seconds) in [(-1i64, 0i64), (1, -1)] {
            let peer = WireguardPeerParsed::from(peer_with_last_handshake(
                seconds,
                nano_seconds,
            ));
            assert_eq!(peer.last_handshake, None);
        }
    }

    fn peer_with_allowed_ip(
        ip_addr: IpAddr,
        prefix_length: u8,
    ) -> WireguardPeerParsed {
        WireguardPeerParsed {
            public_key: Some(PEER_PUBLIC_KEY.to_string()),
            allowed_ips: Some(vec![WireguardIpAddress {
                ip_addr,
                prefix_length,
                flags: None,
            }]),
            ..Default::default()
        }
    }

    #[test]
    fn peer_without_public_key_is_rejected() {
        let err = WireguardPeerParsed::default().build().unwrap_err();

        assert_eq!(err.kind, ErrorKind::InvalidInput);
    }

    #[test]
    fn out_of_range_prefix_length_is_rejected() {
        for (ip_addr, prefix_length, expected) in [
            (IpAddr::V4(Ipv4Addr::new(10, 213, 0, 0)), 32u8, true),
            (IpAddr::V4(Ipv4Addr::new(10, 213, 0, 0)), 33, false),
            (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 128, true),
            (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 129, false),
        ] {
            let result = peer_with_allowed_ip(ip_addr, prefix_length).build();
            assert_eq!(
                result.is_ok(),
                expected,
                "{ip_addr}/{prefix_length}: {result:?}"
            );
            if let Err(err) = result {
                assert_eq!(err.kind, ErrorKind::InvalidInput);
            }
        }
    }
}
