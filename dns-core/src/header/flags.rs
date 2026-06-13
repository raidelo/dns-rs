/// The second 16 bits of the DNS message header, containing
/// various flags and codes that control the behavior of the
/// DNS message.
///
/// RFC 1035, Section 4.1.1
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Flags(u16);

impl Flags {
    /// A one bit field that specifies whether this message is a
    /// query (0), or a response (1).
    ///
    /// 1 bit field, represented as `bool`.
    ///
    /// RFC 1035, Section 4.1.1
    pub fn qr(&self) -> bool {
        (self.0 >> 15) & 1 == 1
    }

    /// A four bit field that specifies kind of query in this
    /// message. This value is set by the originator of a query
    /// and copied into the response. The values are:
    ///
    /// - `0` a standard query (QUERY)
    /// - `1` an inverse query (IQUERY)
    /// - `2` a server status request (STATUS)
    /// - `3-15` reserved for future use
    ///
    /// 4 bit field, represented as `u8` (values 0–15).
    ///
    /// RFC 1035, Section 4.1.1
    pub fn opcode(&self) -> u8 {
        ((self.0 >> 11) & 0xF) as u8
    }

    /// Authoritative Answer - this bit is valid in responses,
    /// and specifies that the responding name server is an
    /// authority for the domain name in question section.
    ///
    /// Note that the contents of the answer section may have
    /// multiple owner names because of aliases. The AA bit
    /// corresponds to the name which matches the query name, or
    /// the first owner name in the answer section.
    ///
    /// 1 bit field, represented as `bool`.
    ///
    /// RFC 1035, Section 4.1.1
    pub fn aa(&self) -> bool {
        (self.0 >> 10) & 1 == 1
    }

    /// TrunCation - specifies that this message was truncated
    /// due to length greater than that permitted on the
    /// transmission channel.
    ///
    /// 1 bit field, represented as `bool`.
    ///
    /// RFC 1035, Section 4.1.1
    pub fn tc(&self) -> bool {
        (self.0 >> 9) & 1 == 1
    }

    /// Recursion Desired - this bit may be set in a query and
    /// is copied into the response. If RD is set, it directs
    /// the name server to pursue the query recursively.
    /// Recursive query support is optional.
    ///
    /// 1 bit field, represented as `bool`.
    ///
    /// RFC 1035, Section 4.1.1
    pub fn rd(&self) -> bool {
        (self.0 >> 8) & 1 == 1
    }

    /// Recursion Available - this be is set or cleared in a
    /// response, and denotes whether recursive query support is
    /// available in the name server.
    ///
    /// 1 bit field, represented as `bool`.
    ///
    /// RFC 1035, Section 4.1.1
    pub fn ra(&self) -> bool {
        (self.0 >> 7) & 1 == 1
    }

    /// Reserved for future use. Must be zero in all queries
    /// and responses.
    ///
    /// 3 bit field, represented as `u8` (values 0–7).
    ///
    /// RFC 1035, Section 4.1.1
    pub fn z(&self) -> u8 {
        ((self.0 >> 4) & 0x7) as u8
    }

    /// Response code - this 4 bit field is set as part of
    /// responses. The values have the following
    /// interpretation:
    ///
    /// - `0` No error condition
    /// - `1` Format error - The name server was unable to interpret the query.
    /// - `2` Server failure - The name server was unable to process this query due to a problem with the name server.
    /// - `3` Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.
    /// - `4` Not Implemented - The name server does not support the requested kind of query.
    /// - `5` Refused - The name server refuses to perform the specified operation for policy reasons.  For example, a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data.
    /// - `6-15` Reserved for future use.
    ///
    /// 4 bit field, represented as `u8` (values 0–15).
    ///
    /// RFC 1035, Section 4.1.1
    pub fn rcode(&self) -> u8 {
        (self.0 & 0xF) as u8
    }
}

/// Converts a raw `u16` value into a [`Flags`] instance.
///
/// The bits are interpreted as laid out in RFC 1035, Section 4.1.1,
/// in big-endian (network byte order).
impl From<u16> for Flags {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_flags_from_u16_works() {
        let data: u16 = 0b11001100_01010101;

        let flags = Flags::from(data);

        assert!(flags.qr());
        assert_eq!(flags.opcode(), 0b1001);
        assert!(flags.aa());
        assert!(!flags.tc());
        assert!(!flags.rd());
        assert!(!flags.ra());
        assert_eq!(flags.z(), 0b101);
        assert_eq!(flags.rcode(), 0b0101);
    }
}
