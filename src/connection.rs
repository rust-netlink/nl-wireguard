// SPDX-License-Identifier: MIT

use futures_channel::mpsc::UnboundedReceiver;
use genetlink::{GenetlinkError, RawGenlMessage};
use netlink_packet_core::NetlinkMessage;
use netlink_proto::Connection;
use netlink_sys::{AsyncSocket, SocketAddr};

use crate::WireguardHandle;

#[cfg(feature = "tokio_socket")]
#[allow(clippy::type_complexity)]
pub fn new_connection() -> Result<
    (
        Connection<RawGenlMessage>,
        WireguardHandle,
        UnboundedReceiver<(NetlinkMessage<RawGenlMessage>, SocketAddr)>,
    ),
    GenetlinkError,
> {
    new_connection_with_socket()
}

#[allow(clippy::type_complexity)]
pub fn new_connection_with_socket<S>() -> Result<
    (
        Connection<RawGenlMessage, S>,
        WireguardHandle,
        UnboundedReceiver<(NetlinkMessage<RawGenlMessage>, SocketAddr)>,
    ),
    GenetlinkError,
>
where
    S: AsyncSocket,
{
    let (mut conn, handle, messages) = genetlink::new_connection_with_socket()?;
    // The kernel reports the result of a dump in the message which ends the
    // dump, forward it so that a failed dump is not silently truncated.
    conn.set_forward_done(true);
    Ok((conn, WireguardHandle::new(handle), messages))
}
