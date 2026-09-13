# Rust crate for linux wireguard netlink management


## To query wireguard interface

```rust
async fn print_wireguard_config(
    iface_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (conn, mut handle, _) = nl_wireguard::new_connection()?;
    tokio::spawn(conn);

    println!("{:?}", handle.get_by_name(iface_name).await?);
    Ok(())
}
```

## set wireguard configuration

You need to use `rtnetlink` crate to create a interface with `wireguard`
interface type before.

```rust
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use nl_wireguard::{
    WireguardIpAddress, WireguardParsed, WireguardParsedDeviceFlags,
    WireguardParsedPeerFlags, WireguardPeerParsed,
};

async fn set_wireguard_config(
    iface_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut peer_config = WireguardPeerParsed::default();
    peer_config.endpoint = Some(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(10, 10, 10, 1)),
        51820,
    ));
    peer_config.public_key =
        Some("8bdQrVLqiw3ZoHCucNh1YfH0iCWuyStniRr8t7H24Fk=".to_string());
    peer_config.allowed_ips = Some(vec![
        WireguardIpAddress {
            ip_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            prefix_length: 0,
            flags: None,
        },
        WireguardIpAddress {
            ip_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            prefix_length: 0,
            flags: None,
        },
    ]);
    peer_config.flags =
        Some(vec![WireguardParsedPeerFlags::ReplaceAllowedIps]);

    let mut config = WireguardParsed::default();
    config.iface_name = Some(iface_name.to_string());
    config.public_key =
        Some("JKossUAjywXuJ2YVcaeD6PaHs+afPmIthDuqEVlspwA=".to_string());
    config.private_key =
        Some("6LTHiAM4vgKEgi5vm30f/EBIEWFDmySkTc9EWCcIqEs=".to_string());
    config.listen_port = Some(51820);
    config.fwmark = Some(0);
    config.peers = Some(vec![peer_config]);
    config.flags = Some(vec![WireguardParsedDeviceFlags::ReplacePeers]);

    let (conn, mut handle, _) = nl_wireguard::new_connection()?;
    tokio::spawn(conn);
    handle.set(config).await?;
    Ok(())
}
```

## Notes

- `WireguardParsedDeviceFlags::ReplacePeers` and
  `WireguardParsedPeerFlags::ReplaceAllowedIps` replace the existing
  configuration instead of appending to it, without them repeated runs of
  the example add the peers and allowed IPs again.
- `WireguardParsed` and `WireguardPeerParsed` are `#[non_exhaustive]`, so
  they can not be built with a struct literal outside of this crate. Use
  `Default::default()` and assign the properties instead.
- `WireguardHandle::set()` splits a configuration which does not fit into
  a single netlink message over as many messages as the kernel requires.
