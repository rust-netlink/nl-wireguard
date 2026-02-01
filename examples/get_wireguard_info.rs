// SPDX-License-Identifier: MIT

use std::env::args;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("debug"),
    )
    .init();

    let argv: Vec<String> = args().collect();
    if argv.len() < 2 {
        eprintln!("Usage: get_wireguard_info <ifname>");
        return;
    }

    let (connection, mut handle, _) = nl_wireguard::new_connection().unwrap();
    tokio::spawn(connection);

    println!("{:?}", handle.get_by_name(argv[1].as_str()).await.unwrap());
}
