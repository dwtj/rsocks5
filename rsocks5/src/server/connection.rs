//! This module implements the server side of a SOCKS 5 connection.
//!
//! A basic overview of the SOCKS 5 protocol from RFC 1928:
//!
//! > When a TCP-based client wishes to establish a connection to an object
//! > that is reachable only via a firewall (such determination is left up
//! > to the implementation), it must open a TCP connection to the
//! > appropriate SOCKS port on the SOCKS server system.  The SOCKS service
//! > is conventionally located on TCP port 1080.  If the connection
//! > request succeeds, the client enters a negotiation for the
//! > authentication method to be used, authenticates with the chosen
//! > method, then sends a relay request.  The SOCKS server evaluates the
//! > request, and either establishes the appropriate connection or denies
//! > it.

#![allow(dead_code)]

/// This is currently set to the size needed to hold a full read request with `AddressType::IPv6`.
/// The buffer may need to grow in certain cases (e.g. with a long `AddressType::DOMAINNAME`).
const INITIAL_BUF_SIZE: usize = 22;


pub struct Connection {
    buf: Vec<u8>,
    state: State,
}

impl Connection {
    pub fn new() -> Connection {
        Connection {
            buf:   Vec::with_capacity(INITIAL_BUF_SIZE),
            state: State::ReadingMethods,
        }
    }
}


/// This implementation of a SOCKS 5 server models the protocol described in RFC 1928 by dividing
/// the connection's behavior into into 5 basic IO stages. Each of these stages is modeled as a
/// separate kind of `State` value. These stages are visited in order: when one stage is finished,
/// the connection transitions to the next.
#[derive(PartialEq, Eq)]
enum State {

    /// The client connects to the server, and sends a version identifier/method selection message.
    ReadingMethods,

    /// The server selects from one of the methods given in METHODS, and sends a METHOD selection
    /// message.
    WritingMethod,

    /// The client and server then enter a method-specific sub-negotiation. (These are described
    /// in RFCs other than RFC 1928.)
    NegotiatingMethod,

    /// Once the method-dependent subnegotiation has completed, the client sends the request
    /// details.
    ReadingRequest,

    /// The SOCKS server will typically evaluate the request based on source and destination
    /// addresses, and return one or more reply messages, as appropriate for the request type.
    WritingReplies,

    /// The SOCKS server's connection to the client has been closed (for one of various reasons).
    Closed,
}
