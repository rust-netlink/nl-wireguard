// SPDX-License-Identifier: MIT

use std::{
    env::args,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use nl_wireguard::{WireguardIpAddress, WireguardParsed, WireguardPeerParsed};

#[tokio::main]
async fn main() {
    env_logger::init();

    let argv: Vec<String> = args().collect();
    if argv.len() < 2 {
        eprintln!("Usage: set_wireguard <ifname>");
        return;
    }

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
        },
        WireguardIpAddress {
            ip_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            prefix_length: 0,
        },
    ]);

    let mut config = WireguardParsed::default();
    config.iface_name = Some(argv[1].to_string());
    config.public_key =
        Some("JKossUAjywXuJ2YVcaeD6PaHs+afPmIthDuqEVlspwA=".to_string());
    config.private_key =
        Some("6LTHiAM4vgKEgi5vm30f/EBIEWFDmySkTc9EWCcIqEs=".to_string());
    config.listen_port = Some(51820);
    config.fwmark = Some(0);
    config.peers = Some(vec![peer_config]);

    let (connection, mut handle, _) = nl_wireguard::new_connection().unwrap();
    tokio::spawn(connection);
    handle.set(config).await.unwrap();

    println!(
        "Applied config {:?}",
        handle.get_by_name(&argv[1]).await.unwrap()
    );
}
