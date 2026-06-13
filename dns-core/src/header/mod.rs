mod flags;

pub use flags::Flags;

use crate::errors::DNSError;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DNSHeader {
    id: u16,
    flags: Flags,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

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
