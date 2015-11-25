#![allow(dead_code)]

//! Provides some simple definitions which are a core to the SOCKS 5 protocol.
//!
//! Constants' names are either derived from RFC 1928, or in cases where that's not an option,
//! from NEC's SOCKS5 reference implementation. Some rust-specific style choices were inspired by
//! `carllerche/nix-rust`.

pub enum SocksVersion {
    SOCKS4 = 0x04,
    SOCKS5 = 0x05,
}

impl SocksVersion {
    pub fn from_u8(octet: u8) -> Option<SocksVersion> {
        use self::SocksVersion::*;
        match octet {
            0x04 => Some(SOCKS4),
            0x05 => Some(SOCKS5),
            _ => None,
        }
    }
    pub fn desc(self) -> &'static str {
        use self::SocksVersion::*;
        match self {
            SOCKS4 => "SOCKS4",
            SOCKS5 => "SOCKS5",
        }
    }
}


#[derive(PartialEq, Eq)]
pub enum AuthMethod {
    NONE = 0x00,
    GSSAPI = 0x01,
    PASSWD = 0x02,
}

impl AuthMethod {
    pub fn from_u8(octet: u8) -> Option<AuthMethod> {
        use self::AuthMethod::*;
        match octet {
            0x00 => Some(NONE),
            0x01 => Some(GSSAPI),
            0x02 => Some(PASSWD),
            _ => None,
        }
    }
    pub fn desc(self) -> &'static str {
        use self::AuthMethod::*;
        match self {
            NONE   => "no authentication required",
            GSSAPI => "GSSAPI",
            PASSWD => "username/password",
        }
    }
}


pub enum Reply {
    NOERR       = 0x00,
    FAIL        = 0x01,
    AUTHORIZE   = 0x02,
    NETUNREACH  = 0x03,
    HOSTUNREACH = 0x04,
    CONNREF     = 0x05,
    TTLEXP      = 0x06,
    BADCMND     = 0x07,
    BADADDR     = 0x08,
}

impl Reply {
    pub fn from_u8(octet: u8) -> Option<Reply> {
        use self::Reply::*;
        match octet {
            0x00 => Some(NOERR),
            0x01 => Some(FAIL),
            0x02 => Some(AUTHORIZE),
            0x03 => Some(NETUNREACH),
            0x04 => Some(HOSTUNREACH),
            0x05 => Some(CONNREF),
            0x06 => Some(TTLEXP),
            0x07 => Some(BADCMND),
            0x08 => Some(BADADDR),
            _ => None,
        }
    }
    pub fn desc(self) -> &'static str {
        use self::Reply::*;
        match self {
            NOERR       => "succeeded",
            FAIL        => "general SOCKS server failure",
            AUTHORIZE   => "connection not allowed by ruleset",
            NETUNREACH  => "network unreachable",
            HOSTUNREACH => "host unreachable",
            CONNREF     => "connection refused",
            TTLEXP      => "TTL expired",
            BADCMND     => "command not supported",
            BADADDR     => "address type not supported",
        }
    }
}


pub enum Command {
    CONNECT = 0x01,
    BIND =    0x02,
    UDP =     0x03,
}

impl Command {
    pub fn from_u8(octet: u8) -> Option<Command> {
        use self::Command::*;
        match octet {
            0x01 => Some(CONNECT),
            0x02 => Some(BIND),
            0x03 => Some(UDP),
            _ => None,
        }
    }
    pub fn desc(self) -> &'static str {
        use self::Command::*;
        match self {
            CONNECT => "connect",
            BIND    => "bind",
            UDP     => "UDP associate"
        }
    }
}


pub enum AddressType {
    IPv4,
    DOMAINNAME(Option<u8>),  // May optionally hold information about the domain name's length.
    IPv6,
}

impl AddressType {
    pub fn from_u8(octet: u8) -> Option<AddressType> {
        use self::AddressType::*;
        match octet {
            0x01 => Some(IPv4),
            0x03 => Some(DOMAINNAME(None)),
            0x04 => Some(IPv6),
            _ => None,
        }
    }
    pub fn desc(self) -> &'static str {
        use self::AddressType::*;
        match self {
            IPv4                => "IPv4",
            DOMAINNAME(None)    => "domain name of unknown length",
            DOMAINNAME(Some(_)) => "domain name known length",
            IPv6                => "IPv6",
        }
    }
}
