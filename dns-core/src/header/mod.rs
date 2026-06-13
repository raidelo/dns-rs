//! DNS message header parsing and representation.

mod flags;

pub use flags::Flags;

use crate::errors::DNSError;

/// The header section of a DNS message. Every DNS message has a fixed-size
/// header of 12 bytes, present in all DNS messages (queries and responses).
///
/// ```text
///                                 1  1  1  1  1  1
///   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      ID                       |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    QDCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ANCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    NSCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ARCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
///
/// RFC 1035, Section 4.1.1
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DNSHeader {
    /// A 16 bit identifier assigned by the program that generates any kind of
    /// query. This identifier is copied the corresponding reply and can be used
    /// by the requester to match up replies to outstanding queries.
    ///
    /// RFC 1035, Section 4.1.1
    id: u16,

    /// The second 16 bits of the DNS header, containing various flags and
    /// codes. See [`Flags`] for details.
    ///
    /// RFC 1035, Section 4.1.1
    flags: Flags,

    /// An unsigned 16 bit integer specifying the number of entries in the
    /// question section.
    ///
    /// RFC 1035, Section 4.1.1
    qdcount: u16,

    /// An unsigned 16 bit integer specifying the number of resource records
    /// in the answer section.
    ///
    /// RFC 1035, Section 4.1.1
    ancount: u16,

    /// An unsigned 16 bit integer specifying the number of name server
    /// resource records in the authority records section.
    ///
    /// RFC 1035, Section 4.1.1
    nscount: u16,

    /// An unsigned 16 bit integer specifying the number of resource records
    /// in the additional records section.
    ///
    /// RFC 1035, Section 4.1.1
    arcount: u16,
}

/// Parses a [`DNSHeader`] from a byte slice in big-endian (network byte order),
/// as specified in RFC 1035, Section 4.1.1.
///
/// Returns [`DNSError::HeaderTooShort`] if the slice contains fewer than 12
/// bytes.
impl TryFrom<&[u8]> for DNSHeader {
    type Error = DNSError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 12 {
            return Err(DNSError::HeaderTooShort);
        }

        Ok(DNSHeader {
            id: u16::from_be_bytes([value[0], value[1]]),
            flags: Flags::from(u16::from_be_bytes([value[2], value[3]])),
            qdcount: u16::from_be_bytes([value[4], value[5]]),
            ancount: u16::from_be_bytes([value[6], value[7]]),
            nscount: u16::from_be_bytes([value[8], value[9]]),
            arcount: u16::from_be_bytes([value[10], value[11]]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_header_from_valid_byte_slice_is_ok() {
        let bytes: &[u8] = &[
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67,
        ];

        assert_eq!(
            DNSHeader::try_from(bytes).unwrap(),
            DNSHeader {
                id: 0x0123,
                flags: Flags::from(0x4567),
                qdcount: 0x89AB,
                ancount: 0xCDEF,
                nscount: 0x0123,
                arcount: 0x4567,
            }
        )
    }

    #[test]
    fn parse_header_from_invalid_byte_slice_is_err() {
        let bytes: &[u8] = &[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB];

        assert_eq!(
            DNSHeader::try_from(bytes).unwrap_err(),
            DNSError::HeaderTooShort
        )
    }
}
