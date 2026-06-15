//! DNS domain name and label parsing and representation.
//!
//! A domain name is composed of a sequence of labels. Each label is preceded
//! by a length byte indicating the number of octets that follow. Labels must
//! start with a letter, end with a letter or digit, and contain only letters,
//! digits, and hyphens as interior characters, with a maximum length of 63
//! characters. The sequence is terminated by a zero-length label (`0x00`).
//!
//! This module provides [`Label`], which represents a single parsed label,
//! and [`DomainName`], which represents a fully parsed domain name.
//!
//! RFC 1035, Section 2.3.1 (composition rules)
//! RFC 1035, Section 2.3.4 (size limits)
//! RFC 1035, Section 3.1 (wire structure)

mod label;

use crate::errors::{DNSError, LabelError};

pub use label::Label;

/// A fully parsed DNS domain name, represented as a sequence of [`Label`]s.
///
/// The terminating zero-length label is not stored — its presence is required
/// during parsing but discarded after validation.
#[derive(Debug, PartialEq)]
pub struct DomainName(Vec<Label>);

impl DomainName {
    /// Parses a [`DomainName`] from a byte slice starting at `offset`, advancing
    /// `offset` by the number of bytes consumed (including the terminating
    /// zero-length label).
    ///
    /// This method is intended for sequential parsing of DNS messages, where
    /// multiple fields are parsed from the same buffer. For simple cases where
    /// the slice contains exactly one domain name, use [`TryFrom<&[u8]>`] instead.
    ///
    /// # Errors
    ///
    /// Returns [`DNSError::MissingNameTerminator`] if the slice is exhausted
    /// before the terminating zero-length label is found.
    ///
    /// Returns [`DNSError::InvalidLabel`] if any label in the sequence fails
    /// to parse.
    pub fn parse(value: &[u8], offset: &mut usize) -> Result<Self, DNSError> {
        let mut array: Vec<Label> = Vec::new();

        loop {
            match Label::try_from(&value[*offset..]) {
                Ok(label) => {
                    *offset += label.len() + 1;
                    array.push(label);
                }

                Err(LabelError::ZeroLength) => {
                    *offset += 1;
                    break Ok(Self(array));
                }

                Err(LabelError::EmptySlice) => return Err(DNSError::MissingNameTerminator),

                Err(err) => return Err(DNSError::InvalidLabel(err)),
            }
        }
    }
}

impl TryFrom<&[u8]> for DomainName {
    type Error = DNSError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut offset = 0usize;
        DomainName::parse(value, &mut offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_name_from_valid_bytes_returns_ok() {
        let bytes = b"\x03www\x0Atestdomain\x03com\x00";

        assert_eq!(
            DomainName::try_from(&bytes[..]).unwrap(),
            DomainName(vec![
                Label::try_from("\x03www".as_bytes()).unwrap(),
                Label::try_from("\x0Atestdomain".as_bytes()).unwrap(),
                Label::try_from("\x03com".as_bytes()).unwrap(),
            ])
        );
    }

    #[test]
    fn domain_name_from_bytes_without_terminator_returns_err() {
        let bytes = b"\x03www\x0Atestdomain\x03com";

        assert_eq!(
            DomainName::try_from(&bytes[..]).unwrap_err(),
            DNSError::MissingNameTerminator,
        );
    }

    #[test]
    fn domain_name_parse_advances_offset_correctly() {
        let bytes = b"\x03www\x03com\x00\xFF\xFF";
        //            |---4--|---4--|-1-| = 9 bytes consumed, \xFF\xFF untouched
        let mut offset = 0;

        DomainName::parse(bytes, &mut offset).unwrap();

        assert_eq!(offset, 9);
    }

    #[test]
    fn domain_name_parse_starts_at_given_offset() {
        let bytes = b"\xFF\xFF\x03www\x03com\x00";
        //            skip 2, then 9 bytes = offset ends at 11
        let mut offset = 2;

        DomainName::parse(bytes, &mut offset).unwrap();

        assert_eq!(offset, 11);
    }
}
