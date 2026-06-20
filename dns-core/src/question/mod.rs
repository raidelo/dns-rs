//! DNS question section parsing and representation.
//!
//! A DNS question represents a query made by a client. It consists of a
//! target domain name (`QNAME`), a query type (`QTYPE`), and a query class (`QCLASS`).
//!
//! In the wire format, the question section follows the DNS header. Multiple
//! questions can theoretically exist in a single message, although in practice
//! (and by RFC standards), messages almost always contain exactly one question.
//!
//! This module provides [`DNSQuestion`], which represents a fully parsed DNS query.
//!
//! RFC 1035, Section 4.1.2 (Question section format)

use crate::{class::QClass, errors::DNSError, name::DomainName, type_::QType, utils::read_u16};

/// A fully parsed DNS question, representing a query for a specific record.
#[derive(Debug, PartialEq)]
pub struct DNSQuestion {
    qname: DomainName,
    qtype: QType,
    qclass: QClass,
}

impl DNSQuestion {
    /// Parses a [`DNSQuestion`] from a byte slice starting at `offset`, advancing
    /// `offset` by the number of bytes consumed.
    ///
    /// This method is intended for sequential parsing of DNS messages, where
    /// fields (like the header, questions, and answers) are parsed from the same buffer.
    /// For simple cases where the slice contains exactly one question, use
    /// [`TryFrom<&[u8]>`] instead.
    ///
    /// # Errors
    ///
    /// Returns [`DNSError::UnexpectedEnd`] if the slice is exhausted before
    /// the fixed-size fields (`qtype` and `qclass`) can be fully read.
    ///
    /// Propagates errors from [`DomainName::parse`] if the domain name is invalid
    /// or malformed.
    pub fn parse(value: &[u8], offset: &mut usize) -> Result<Self, DNSError> {
        let qname = DomainName::parse(value, offset)?;
        let qtype = QType::try_from(read_u16(value, offset)?)?;
        let qclass = QClass::try_from(read_u16(value, offset)?)?;

        Ok(DNSQuestion {
            qname,
            qtype,
            qclass,
        })
    }
}

impl TryFrom<&[u8]> for DNSQuestion {
    type Error = DNSError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut offset = 0usize;
        DNSQuestion::parse(value, &mut offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_question_from_valid_bytes_returns_ok() {
        let bytes = b"\x03www\x0Atestdomain\x03com\x00\x00\x01\x00\x01";

        let qtype_raw = u16::from_be_bytes((&bytes[20..22]).try_into().unwrap());
        let qclass_raw = u16::from_be_bytes((&bytes[22..24]).try_into().unwrap());

        assert_eq!(
            DNSQuestion::try_from(&bytes[..]).unwrap(),
            DNSQuestion {
                qname: DomainName::try_from(&bytes[..20]).unwrap(),
                qtype: QType::try_from(qtype_raw).unwrap(),
                qclass: QClass::try_from(qclass_raw).unwrap(),
            }
        );
    }

    #[test]
    fn dns_question_with_truncated_bytes_returns_unexpected_end() {
        let bytes = b"\x03www\x0Atestdomain\x03com\x00";

        let result = DNSQuestion::try_from(&bytes[..]);

        assert_eq!(result, Err(DNSError::UnexpectedEnd));
    }

    #[test]
    fn dns_question_missing_qclass_returns_unexpected_end() {
        let bytes = b"\x03www\x0Atestdomain\x03com\x00\x00\x01";

        let result = DNSQuestion::try_from(&bytes[..]);

        assert_eq!(result, Err(DNSError::UnexpectedEnd));
    }
}
