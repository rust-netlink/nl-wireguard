// SPDX-License-Identifier: MIT

//! Integration tests exercising the kernel WireGuard API.
//!
//! These tests need `CAP_NET_ADMIN` and the `wireguard` kernel module, they
//! create and remove a temporary wireguard interface. Therefore they are
//! `#[ignore]`d by default. Build the test binary as an unprivileged user
//! and run it as root, for example:
//!
//! ```bash
//! cargo test --test wireguard_kernel --no-run
//! sudo ./target/debug/deps/wireguard_kernel-* --ignored --nocapture
//! ```

use std::{
    net::{IpAddr, Ipv4Addr},
    process::Command,
};

use nl_wireguard::{
    WireguardHandle, WireguardIpAddress, WireguardParsed, WireguardPeerParsed,
};

/// Interface used by `get_by_name_result_can_be_applied_again()`.
const IFACE_NAME: &str = "nlwgtest0";

/// Interface used by `set_configuration_larger_than_a_single_message()`.
/// Every test uses its own interface so that they can run in parallel.
const LARGE_IFACE_NAME: &str = "nlwgtest1";

/// Base64 encoded public key of a throwaway peer.
const PEER_PUBLIC_KEY: &str = "8bdQrVLqiw3ZoHCucNh1YfH0iCWuyStniRr8t7H24Fk=";

/// Base64 encoded private key of the throwaway device.
const DEVICE_PRIVATE_KEY: &str = "6LTHiAM4vgKEgi5vm30f/EBIEWFDmySkTc9EWCcIqEs=";

/// Test wireguard interface which is removed on drop.
struct TestIface(&'static str);

impl TestIface {
    fn create(name: &'static str) -> Self {
        let _ = Command::new("ip").args(["link", "del", name]).status();
        run("ip", &["link", "add", name, "type", "wireguard"]);
        run("ip", &["link", "set", name, "up"]);
        Self(name)
    }
}

impl Drop for TestIface {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["link", "del", self.0]).status();
    }
}

fn run(program: &str, args: &[&str]) {
    let status = Command::new(program)
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("failed to run `{program}`: {e}"));
    assert!(status.success(), "command `{program} {args:?}` failed");
}

async fn connect() -> WireguardHandle {
    let (connection, handle, _) =
        nl_wireguard::new_connection().expect("failed to open netlink socket");
    tokio::spawn(connection);
    handle
}

fn peer_with_allowed_ips(count: u32) -> WireguardPeerParsed {
    let mut peer = WireguardPeerParsed::default();
    peer.public_key = Some(PEER_PUBLIC_KEY.to_string());
    peer.allowed_ips = Some(
        (0..count)
            .map(|i| WireguardIpAddress {
                ip_addr: IpAddr::V4(Ipv4Addr::new(
                    10,
                    213,
                    (i / 256) as u8,
                    (i % 256) as u8,
                )),
                prefix_length: 32,
                flags: None,
            })
            .collect(),
    );
    peer
}

fn allowed_ip_count(config: &WireguardParsed) -> usize {
    config
        .peers
        .iter()
        .flatten()
        .map(|peer| peer.allowed_ips.iter().flatten().count())
        .sum()
}

fn large_config() -> WireguardParsed {
    let mut config = WireguardParsed::default();
    config.iface_name = Some(LARGE_IFACE_NAME.to_string());
    config.private_key = Some(DEVICE_PRIVATE_KEY.to_string());
    config.flags =
        Some(vec![nl_wireguard::WireguardParsedDeviceFlags::ReplacePeers]);
    config.peers = Some(vec![peer_with_allowed_ips(5_000)]);
    config
}

#[tokio::test]
#[ignore = "needs root and the wireguard kernel module"]
async fn set_configuration_larger_than_a_single_message() {
    let _iface = TestIface::create(LARGE_IFACE_NAME);
    let mut handle = connect().await;

    // Applying this configuration used to panic inside the netlink encoder
    // because one netlink attribute can not exceed 64 KiB.
    handle
        .set(large_config())
        .await
        .expect("failed to apply config");

    let parsed = handle
        .get_by_name(LARGE_IFACE_NAME)
        .await
        .expect("failed to get config");
    assert_eq!(allowed_ip_count(&parsed), 5_000);
}

#[tokio::test]
#[ignore = "needs root and the wireguard kernel module"]
async fn get_by_name_result_can_be_applied_again() {
    let _iface = TestIface::create(IFACE_NAME);
    let mut handle = connect().await;

    let mut peer = WireguardPeerParsed::default();
    peer.public_key = Some(PEER_PUBLIC_KEY.to_string());
    peer.allowed_ips = Some(vec![WireguardIpAddress {
        ip_addr: IpAddr::V4(Ipv4Addr::new(10, 213, 0, 1)),
        prefix_length: 32,
        flags: None,
    }]);

    let mut config = WireguardParsed::default();
    config.iface_name = Some(IFACE_NAME.to_string());
    config.private_key = Some(DEVICE_PRIVATE_KEY.to_string());
    config.peers = Some(vec![peer]);
    handle.set(config).await.expect("failed to apply config");

    let parsed = handle
        .get_by_name(IFACE_NAME)
        .await
        .expect("failed to get config");
    assert_eq!(parsed.peers.as_ref().map(Vec::len), Some(1));

    // `parsed` holds both the interface name and index, the kernel rejects
    // a request carrying both with `-EBADR`.
    handle
        .set(parsed)
        .await
        .expect("failed to apply the parsed config");
}
