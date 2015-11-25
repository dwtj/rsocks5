//! Code for serializing and deserializing different various SOCKS5 protocol messages.
//!
//! Much code in this file which reads and interprets bytes in a buffer uses a style used by `mio`
//! where function names are prefixed with `try_` and the "real" return type `T` is boxed in a
//! `Result<Option<T>>`. These boxes allow for disambiguation of reasons why a buffer is not able
//! to be interpreted as a valid message. In general, the reasons fall into two categories:
//!
//! - Not enough bytes have been read into `buf` for it to be interpreted as either a valid or
//!   invalid message. These cases are indicated by returning `Ok(None)`.
//! - Enough bytes have been read into `buf` to determine that it is somehow malformed. These cases
//!   are indicated by returning an `Err(_)`
//!
//! Only in the "normal" case, were the buffer can be interpreted as a valid message, an
//! `Ok(Some(_))` is returned.

use std::io::{Error, Result};
use std::io::ErrorKind::{InvalidData};
use std::slice::Iter;

use rfc1928::{AuthMethod, SocksVersion};

struct AuthMethodsMessage {
    version: SocksVersion,
    methods: Vec<AuthMethod>,  // TODO: Consider removing this extra heap allocation.
}

impl AuthMethodsMessage {

    pub fn new(version: SocksVersion, methods: Iter<AuthMethod>) -> AuthMethodsMessage {
        let mut msg = AuthMethodsMessage {
            version: version,
            methods: Vec::with_capacity(3),
        };
        for m in methods {
            msg.add(*m);
        };
        return msg;
    }

    /// Tries to deserialize the first octets of `buf` as an authorization methods message.
    pub fn try_new(buf: &Vec<u8>) -> Result<Option<AuthMethodsMessage>> {

        let version = match try!(Self::try_version(buf)) {
            None => return Ok(None),
            Some(v) => v,
        };
        let methods = match try!(Self::try_methods(buf)) {
            None => return Ok(None),
            Some(m) => m,
        };

        let mut message = AuthMethodsMessage {
            version: version,
            methods: Vec::with_capacity(3),
        };
        for method_id in methods {
            try!(message.try_add_method(*method_id));
        }

        Ok(Some(message))
    }

    /// Helper method for extracting and validating the `version` octet from a message.
    fn try_version(buf: &Vec<u8>) -> Result<Option<SocksVersion>> {
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
    fn try_nmethods(buf: &Vec<u8>) -> Result<Option<u8>> {
        let nmethods = match buf.get(1) {
            None    => return Ok(None),
            Some(n) => *n,
        };
        match nmethods {
            0 => Err(Error::new(InvalidData, "`nmethods` cannot be 0")),
            n => Ok(Some(n)),
        }
    }

    /// Helper method for extracting the methods octets from a message.
    pub fn try_methods<'a>(buf: &'a Vec<u8>) -> Result<Option<Iter<'a, u8>>> {
        let nmethods = match Self::try_nmethods(buf) {
            Err(e)      => return Err(e),
            Ok(None)    => return Ok(None),
            Ok(Some(n)) => n,
        };

        let expected_len = Self::expected_len(nmethods);
        if buf.len() < expected_len {
            return Ok(None);
        }

        Ok(Some(buf[2 .. expected_len].iter()))
    }

    #[inline]
    fn expected_len(nmethods: u8) -> usize {
        2 + (nmethods as usize)
    }

    #[inline]
    fn try_add_method(&mut self, method_id: u8) -> Result<()> {
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
    /// Returns `true` iff the set contains the given authorization method.
    pub fn contains(&self, method: &AuthMethod) -> bool {
        self.methods.contains(&method)
    }
}
