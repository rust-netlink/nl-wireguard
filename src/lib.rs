// SPDX-License-Identifier: MIT

//! This crate provides methods to manipulate wireguard link via the generic
//! netlink protocol.
//!
//! To query wireguard interface:
//!
//! ```no_run
//! async fn print_wireguard_config(iface_name: &str) {
//!     let (conn, mut handle, _) = nl_wireguard::new_connection().unwrap();
//!     tokio::spawn(conn);
//!
//!     println!("{:?}", handle.get_by_name(iface_name).await.unwrap());
//! }
//! ```
//!
//! To set wireguard configuration.
//!
//! ```no_run
//! use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
//! use nl_wireguard::{
//!     WireguardPeerParsed, WireguardParsed, WireguardIpAddress};
//!
//! async fn set_wireguard_config(iface_name: &str) {
//!     let mut peer_config = WireguardPeerParsed::default();
//!     peer_config.endpoint = Some(SocketAddr::new(
//!         IpAddr::V4(Ipv4Addr::new(10, 10, 10, 1)),
//!         51820,
//!     ));
//!     peer_config.public_key =
//!         Some("8bdQrVLqiw3ZoHCucNh1YfH0iCWuyStniRr8t7H24Fk=".to_string());
//!     peer_config.allowed_ips = Some(vec![
//!         WireguardIpAddress {
//!             ip_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
//!             prefix_length: 0,
//!         },
//!         WireguardIpAddress {
//!             ip_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
//!             prefix_length: 0,
//!         },
//!     ]);
//!
//!     let mut config = WireguardParsed::default();
//!     config.iface_name = Some(iface_name.to_string());
//!     config.public_key =
//!         Some("JKossUAjywXuJ2YVcaeD6PaHs+afPmIthDuqEVlspwA=".to_string());
//!     config.private_key =
//!         Some("6LTHiAM4vgKEgi5vm30f/EBIEWFDmySkTc9EWCcIqEs=".to_string());
//!     config.listen_port = Some(51820);
//!     config.fwmark = Some(0);
//!     config.peers = Some(vec![peer_config]);
//!
//!     let (conn, mut handle, _) = nl_wireguard::new_connection().unwrap();
//!     tokio::spawn(conn);
//!     handle.set(config).await.unwrap();
//! }
//! ```

mod connection;
mod error;
mod handle;
mod parsed;
mod peer_parsed;

// Re-export netlink-packet-wireguard data types allowing crate use to
// depend on this crate only for full functionality.
pub use netlink_packet_wireguard::{
    WireguardAddressFamily, WireguardAllowedIp, WireguardAllowedIpAttr,
    WireguardAttribute, WireguardCmd, WireguardMessage, WireguardPeer,
    WireguardPeerAttribute, WireguardTimeSpec,
};

#[cfg(feature = "tokio_socket")]
pub use self::connection::new_connection;
pub use self::{
    connection::new_connection_with_socket,
    error::{ErrorKind, WireguardError},
    handle::WireguardHandle,
    parsed::WireguardParsed,
    peer_parsed::{WireguardIpAddress, WireguardPeerParsed},
};
