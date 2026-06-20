//! DNS resource record parsing and representation.
//!
//! Resource records appear in the answer, authority, and additional sections
//! of a DNS message. All three sections share the same record format.
//!
//! Multiple records can appear in a single message; the number of records in
//! each section is specified by the corresponding count field in the header
//! (`ANCOUNT`, `NSCOUNT`, and `ARCOUNT` respectively).
//!
//! This module provides [`ResourceRecord`], which represents a fully parsed
//! resource record.
//!
//! RFC 1035, Section 4.1.3

use crate::{
    class::Class,
    errors::DNSError,
    name::DomainName,
    type_::Type,
    utils::{read_u16, read_u32},
};

/// A fully parsed DNS resource record, containing the response data
/// for a queried domain name.
///
/// Resource records appear in the answer, authority, and additional
/// sections of a DNS message. The `rdata` field contains the raw record
/// data, whose interpretation depends on the `type_` field.
///
/// RFC 1035, Section 4.1.3
#[derive(Debug, PartialEq)]
pub struct ResourceRecord {
    name: DomainName,
    type_: Type,
    class: Class,
    ttl: u32,
    rdlength: u16,
    rdata: Vec<u8>,
}

impl ResourceRecord {
    /// Parses a [`ResourceRecord`] from a byte slice starting at `offset`, advancing
    /// `offset` by the number of bytes consumed.
    ///
    /// This method is intended for sequential parsing of Resource Records, where
    /// fields (like the header, questions, and answers) are parsed from the same buffer.
    /// For simple cases where the slice contains exactly one question, use
    /// [`TryFrom<&[u8]>`] instead.
    ///
    /// # Errors
    ///
    /// Returns [`DNSError::UnexpectedEnd`] if the slice is exhausted before
    /// the fixed-size fields (`type` and `class`) can be fully read.
    ///
    /// Propagates errors from [`DomainName::parse`] if the domain name is invalid
    /// or malformed.
    pub fn parse(value: &[u8], offset: &mut usize) -> Result<Self, DNSError> {
        let name = DomainName::parse(value, offset)?;
        let type_ = Type::try_from(read_u16(value, offset)?)?;
        let class = Class::try_from(read_u16(value, offset)?)?;
        let ttl = read_u32(value, offset)?;
        let rdlength = read_u16(value, offset)?;

        let bytes: &[u8] = value
            .get(*offset..*offset + rdlength as usize)
            .ok_or(DNSError::UnexpectedEnd)?;
        *offset += rdlength as usize;

        Ok(ResourceRecord {
            name,
            type_,
            class,
            ttl,
            rdlength,
            rdata: bytes.to_vec(),
        })
    }
}

impl TryFrom<&[u8]> for ResourceRecord {
    type Error = DNSError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut offset = 0usize;
        ResourceRecord::parse(value, &mut offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_record_from_valid_bytes_returns_ok() {
        let bytes = b"\x03www\x0Atestdomain\x03com\x00\x00\x01\x00\x01\x00\xAB\xCD\xEF\x00\x04\x89\xAB\xCD\xEF";

        let type_raw = u16::from_be_bytes((&bytes[20..22]).try_into().unwrap());
        let class_raw = u16::from_be_bytes((&bytes[22..24]).try_into().unwrap());
        let ttl_raw = u32::from_be_bytes((&bytes[24..28]).try_into().unwrap());
        let rdlength_raw = u16::from_be_bytes((&bytes[28..30]).try_into().unwrap());
        let rdata_raw = &bytes[30..(30 + rdlength_raw as usize)];

        assert_eq!(
            ResourceRecord::try_from(&bytes[..]).unwrap(),
            ResourceRecord {
                name: DomainName::try_from(&bytes[..20]).unwrap(),
                type_: Type::try_from(type_raw).unwrap(),
                class: Class::try_from(class_raw).unwrap(),
                ttl: ttl_raw,
                rdlength: rdlength_raw,
                rdata: rdata_raw.to_vec()
            }
        );
    }

    #[test]
    fn resource_record_missing_type_returns_unexpected_end() {
        let bytes = b"\x03www\x0Atestdomain\x03com\x00";

        assert_eq!(
            ResourceRecord::try_from(&bytes[..]),
            Err(DNSError::UnexpectedEnd)
        );
    }

    #[test]
    fn resource_record_missing_class_returns_unexpected_end() {
        let bytes = b"\x03www\x0Atestdomain\x03com\x00\x00\x01";

        assert_eq!(
            ResourceRecord::try_from(&bytes[..]),
            Err(DNSError::UnexpectedEnd)
        );
    }

    #[test]
    fn resource_record_missing_ttl_returns_unexpected_end() {
        let bytes = b"\x03www\x0Atestdomain\x03com\x00\x00\x01\x00\x01";

        assert_eq!(
            ResourceRecord::try_from(&bytes[..]),
            Err(DNSError::UnexpectedEnd)
        );
    }

    #[test]
    fn resource_record_missing_rdlength_returns_unexpected_end() {
        let bytes = b"\x03www\x0Atestdomain\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x3C";

        assert_eq!(
            ResourceRecord::try_from(&bytes[..]),
            Err(DNSError::UnexpectedEnd)
        );
    }

    #[test]
    fn resource_record_truncated_rdata_returns_unexpected_end() {
        // rdlength declares 4 bytes but there are only 2
        let bytes =
            b"\x03www\x0Atestdomain\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x04\x01\x02";

        assert_eq!(
            ResourceRecord::try_from(&bytes[..]),
            Err(DNSError::UnexpectedEnd)
        );
    }
}
