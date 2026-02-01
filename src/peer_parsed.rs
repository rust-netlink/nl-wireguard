// SPDX-License-Identifier: MIT

use std::{
    convert::TryFrom,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use base64::{prelude::BASE64_STANDARD, Engine};

use super::parsed::decode_key;
use crate::{
    ErrorKind, WireguardAddressFamily, WireguardAllowedIp,
    WireguardAllowedIpAttr, WireguardError, WireguardPeer,
    WireguardPeerAttribute, WireguardTimeSpec,
};

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
    // TODO: Flags
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
                        && (v.nano_seconds as u64) < (u32::MAX as u64)
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
                _ => {
                    log::debug!("Unsupported WireguardPeerAttribute {attr:?}");
                }
            }
        }
        ret
    }
}

impl WireguardPeerParsed {
    pub fn build(&self) -> Result<WireguardPeer, WireguardError> {
        let mut attrs: Vec<WireguardPeerAttribute> = Vec::new();
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

        Ok(WireguardPeer(attrs))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireguardIpAddress {
    pub prefix_length: u8,
    pub ip_addr: IpAddr,
}

impl TryFrom<&WireguardAllowedIp> for WireguardIpAddress {
    type Error = WireguardError;

    fn try_from(attrs: &WireguardAllowedIp) -> Result<Self, WireguardError> {
        let mut ip_addr: Option<IpAddr> = None;
        let mut prefix_length: Option<u8> = None;

        for attr in &attrs.0 {
            match attr {
                WireguardAllowedIpAttr::IpAddr(v) => ip_addr = Some(*v),
                WireguardAllowedIpAttr::Cidr(v) => prefix_length = Some(*v),
                WireguardAllowedIpAttr::Family(_) => (),
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
        vec![
            WireguardAllowedIpAttr::Cidr(ip.prefix_length),
            if ip.ip_addr.is_ipv4() {
                WireguardAllowedIpAttr::Family(WireguardAddressFamily::Ipv4)
            } else {
                WireguardAllowedIpAttr::Family(WireguardAddressFamily::Ipv6)
            },
            WireguardAllowedIpAttr::IpAddr(ip.ip_addr),
        ]
    }
}
