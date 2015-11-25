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

use std::io::{Error, Result};
use std::io::ErrorKind::{InvalidData};

use rfc1928::{AuthMethod, SocksVersion};


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
            state: State::ReadMethods,
        }
    }
}


/// This implementation of a SOCKS 5 server models the protocol described in RFC 1928 by dividing
/// the connection's behavior into into 5 basic IO stages. Each of these stages is modeled as a
/// separate kind of `State` value. These stages are visited in order: when one stage is finished,
/// the connection transitions to the next.
enum State {

    /// The client connects to the server, and sends a version identifier/method selection message.
    ReadMethods,

    /// The server selects from one of the methods given in METHODS, and sends a METHOD selection
    /// message.
    WriteMethod,

    /// The client and server then enter a method-specific sub-negotiation. (These are described
    /// in RFCs other than RFC 1928.)
    MethodNegotiation,

    /// Once the method-dependent subnegotiation has completed, the client sends the request
    /// details.
    ReadRequest,

    /// The SOCKS server will typically evaluate the request based on source and destination
    /// addresses, and return one or more reply messages, as appropriate for the request type.
    WriteReplies,

    /// The SOCKS server's connection to the client has been closed (for one of various reasons).
    Closed,
}


struct AuthMethodsSet {
    methods: Vec<AuthMethod>,
}


impl AuthMethodsSet {

    /// Helper method for extracting and validating the `version` octet from a message.
    fn version(buf: &Vec<u8>) -> Result<Option<SocksVersion>> {
        use rfc1928::SocksVersion::{SOCKS4, SOCKS5};
        let version = match buf.get(0) {
            None    => return Ok(None),
            Some(v) => *v,
        };
        let version = match SocksVersion::from_u8(version) {
            None    => return Err(Error::new(InvalidData, "unknown socks version")),
            Some(v) => v,
        };
        match version {
            SOCKS4 => Err(Error::new(InvalidData, "SOCKS v4 not supported")),
            SOCKS5 => Ok(Some(SOCKS5)),
        }
    }

    /// Helper method for extracting and validating the `nmethods` octet from a message.
    fn nmethods(buf: &Vec<u8>) -> Result<Option<u8>> {
        let nmethods = match buf.get(1) {
            None => return Ok(None),
            Some(n) => *n,
        };
        match nmethods {
            0 => Err(Error::new(InvalidData, "`nmethods` cannot be 0")),
            n => Ok(Some(n)),
        }
    }

    /// Tries to interpret `buf` as an authorization methods message and construct the set of
    /// specified in this message.
    ///
    /// When a `buf` can be interpreted as a valid message, a `Ok(Some(message))` value is
    /// returned.
    ///
    /// There are a number of reasons why a `buf` may not be able to be interpreted as an
    /// `AuthMethodsMessage`, but they all fall into one of two classes:
    ///
    /// - A return of `Ok(None)` indicates that not enough bytes have been read into `buf` for it
    ///   to be interpreted as either a valid or invalid message.
    /// - A return of `Err(error)` indicates that the message in `buf` has been determined to be
    ///   somehow malformed.
    pub fn methods(buf: &Vec<u8>) -> Result<Option<AuthMethodsSet>> {

        try!(Self::version(buf));

        let nmethods = match Self::nmethods(buf) {
            Err(e)      => return Err(e),
            Ok(None)    => return Ok(None),
            Ok(Some(n)) => n,
        };

        let expected_len = Self::expected_len(nmethods);
        if buf.len() < expected_len {
            return Ok(None);
        }

        let mut methods = AuthMethodsSet { methods: Vec::with_capacity(3) };
        for m_id in buf[2 .. expected_len].iter() {
            try!(methods.add_by_id(*m_id));
        }
        Ok(Some(methods))
    }

    #[inline]
    fn expected_len(nmethods: u8) -> usize {
        2 + (nmethods as usize)
    }

    #[inline]
    fn add_by_id(&mut self, method_id: u8) -> Result<()> {
        let method = match AuthMethod::from_u8(method_id) {
            None    => return Err(Error::new(InvalidData, "unknown auth method")),
            Some(m) => m,
        };
        self.add(method);
        Ok(())
    }

    #[inline]
    fn add(&mut self, method: AuthMethod) {
        if !self.methods.contains(&method) {
            self.methods.push(method);
        }
    }

    #[inline]
    pub fn contains(&self, method: &AuthMethod) -> bool {
        self.methods.contains(&method)
    }
}
