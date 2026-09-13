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

/// Interface used by the integration tests.
const IFACE_NAME: &str = "nlwgtest0";

/// Base64 encoded public key of a throwaway peer.
const PEER_PUBLIC_KEY: &str = "8bdQrVLqiw3ZoHCucNh1YfH0iCWuyStniRr8t7H24Fk=";

/// Base64 encoded private key of the throwaway device.
const DEVICE_PRIVATE_KEY: &str = "6LTHiAM4vgKEgi5vm30f/EBIEWFDmySkTc9EWCcIqEs=";

/// Test wireguard interface which is removed on drop.
struct TestIface;

impl TestIface {
    fn create() -> Self {
        let _ = Command::new("ip")
            .args(["link", "del", IFACE_NAME])
            .status();
        run("ip", &["link", "add", IFACE_NAME, "type", "wireguard"]);
        run("ip", &["link", "set", IFACE_NAME, "up"]);
        Self
    }
}

impl Drop for TestIface {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["link", "del", IFACE_NAME])
            .status();
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

#[tokio::test]
#[ignore = "needs root and the wireguard kernel module"]
async fn get_by_name_result_can_be_applied_again() {
    let _iface = TestIface::create();
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
