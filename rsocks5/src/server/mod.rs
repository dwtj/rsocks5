mod connection;

use mio::{Handler, EventLoop, Token, EventSet};
use mio::util::Slab;

use self::connection::Connection;


/**
 * Some simple definitions which are not strictly part of RFC 1928, but are needed for the SOCKS 5
 * server implementation. (Names are taken from NEC's reference implementation of SOCKS 5.)
 */
// TODO: Do we need these definitions?
pub const MAXNAMELEN: usize = 256;
pub const MAXHOSTNAMELEN: usize = 256;
pub const GENERICBUFSIZE: usize = 4096;
pub const IPPORT_RESERVED: u16 = 1024;
pub const SOCKS_DEF_PORT: u16 = 1080;


struct SocksServer {
    connections: Slab<Connection>,
}

impl Handler for SocksServer {
    type Timeout = ();
    type Message = ();

    fn ready(&mut self, event_loop: &mut EventLoop<SocksServer>, token: Token, events: EventSet) {
        let connection = match self.connections.get_mut(token) {
            None => {
                info!("`Server::ready()` called with token not associated with a connection");
                return;
            },
            Some(conn) => conn,
        };
        connection.ready(event_loop, events);
    }
}
