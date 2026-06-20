//! DNS message parsing and representation.
//!
//! A DNS message consists of a fixed-size header followed by four variable-length
//! sections: questions, answers, authorities, and additionals. The number of
//! records in each section is specified by the corresponding count field in the
//! header (`QDCOUNT`, `ANCOUNT`, `NSCOUNT`, and `ARCOUNT` respectively).
//!
//! This module provides [`DNSMessage`], which represents a fully parsed DNS
//! message.
//!
//! RFC 1035, Section 4.1 (Format)

use crate::{
    errors::DNSError,
    header::DNSHeader,
    question::DNSQuestion,
    rr::{Additional, Answer, Authority, ResourceRecord},
};

/// A fully parsed DNS message.
///
/// A DNS message is composed of a header and up to four sections:
///
/// - **Question** — the queries being made.
/// - **Answer** — resource records that answer the question.
/// - **Authority** — resource records pointing to authoritative name servers.
/// - **Additional** — resource records with additional information.
///
/// The number of records in each section is determined by the header fields
/// `QDCOUNT`, `ANCOUNT`, `NSCOUNT`, and `ARCOUNT`.
///
/// RFC 1035, Section 4.1
#[derive(Debug, PartialEq)]
pub struct DNSMessage {
    header: DNSHeader,
    questions: Vec<DNSQuestion>,
    answers: Vec<Answer>,
    authorities: Vec<Authority>,
    additionals: Vec<Additional>,
}

impl DNSMessage {
    /// Parses a [`DNSMessage`] from a byte slice starting at `offset`, advancing
    /// `offset` by the number of bytes consumed.
    ///
    /// This method is intended for sequential parsing of DNS messages from a
    /// shared buffer. For simple cases where the slice contains exactly one
    /// message, use [`TryFrom<&[u8]>`] instead.
    ///
    /// # Errors
    ///
    /// Returns [`DNSError::HeaderTooShort`] if the slice contains fewer than
    /// 12 bytes.
    ///
    /// Returns [`DNSError::UnexpectedEnd`] if the slice is exhausted before
    /// all sections declared in the header have been fully parsed.
    ///
    /// Propagates any errors from [`DNSQuestion::parse`] or
    /// [`ResourceRecord::parse`] if any record is malformed.
    pub fn parse(value: &[u8], offset: &mut usize) -> Result<Self, DNSError> {
        let header = DNSHeader::try_from(value.get(0..12).ok_or(DNSError::HeaderTooShort)?)?;
        *offset += 12;

        let mut questions = Vec::new();
        for _ in 0..header.qdcount() {
            questions.push(DNSQuestion::parse(value, offset)?);
        }

        let mut answers = Vec::new();
        for _ in 0..header.ancount() {
            answers.push(Answer::from(ResourceRecord::parse(value, offset)?));
        }

        let mut authorities = Vec::new();
        for _ in 0..header.nscount() {
            authorities.push(Authority::from(ResourceRecord::parse(value, offset)?));
        }

        let mut additionals = Vec::new();
        for _ in 0..header.arcount() {
            additionals.push(Additional::from(ResourceRecord::parse(value, offset)?));
        }

        Ok(Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }
}

impl TryFrom<&[u8]> for DNSMessage {
    type Error = DNSError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut offset = 0usize;
        DNSMessage::parse(value, &mut offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUERY_RESPONSE: &[u8] = &[
        // Header
        0x12, 0x34, // ID: 0x1234
        0x85, 0x80, // flags: QR=1 RD=1 RA=1
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x01, // ANCOUNT: 1
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
        // Question: www.example.com A IN
        0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o',
        b'm', 0x00, // terminador
        0x00, 0x01, // QTYPE: A
        0x00, 0x01, // QCLASS: IN
        // Answer: www.example.com A IN TTL=60 93.184.216.34
        0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o',
        b'm', 0x00, // terminator byte
        0x00, 0x01, // TYPE: A
        0x00, 0x01, // CLASS: IN
        0x00, 0x00, 0x00, 0x3C, // TTL: 60
        0x00, 0x04, // RDLENGTH: 4
        93, 184, 216, 34, // RDATA: 93.184.216.34
    ];

    #[test]
    fn dns_message_from_valid_bytes_returns_ok() {
        assert!(DNSMessage::try_from(QUERY_RESPONSE).is_ok());
    }

    #[test]
    fn dns_message_header_is_parsed_correctly() {
        let msg = DNSMessage::try_from(QUERY_RESPONSE).unwrap();

        assert_eq!(
            msg.header,
            DNSHeader::try_from(&QUERY_RESPONSE[..12]).unwrap()
        );
    }

    #[test]
    fn dns_message_question_is_parsed_correctly() {
        let msg = DNSMessage::try_from(QUERY_RESPONSE).unwrap();

        assert_eq!(
            msg.questions,
            vec![DNSQuestion::try_from(&QUERY_RESPONSE[12..33]).unwrap()]
        );
    }

    #[test]
    fn dns_message_answer_is_parsed_correctly() {
        let msg = DNSMessage::try_from(QUERY_RESPONSE).unwrap();

        assert_eq!(
            msg.answers,
            vec![Answer::from(
                ResourceRecord::try_from(&QUERY_RESPONSE[33..]).unwrap()
            )]
        );
    }

    #[test]
    fn dns_message_with_no_sections_returns_ok() {
        let bytes: &[u8] = &[
            0x12, 0x34, // id
            0x00, 0x00, // flags: query
            0x00, 0x00, // QDCOUNT: 0
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
        ];

        let msg = DNSMessage::try_from(bytes).unwrap();

        assert!(msg.questions.is_empty());
        assert!(msg.answers.is_empty());
        assert!(msg.authorities.is_empty());
        assert!(msg.additionals.is_empty());
    }

    #[test]
    fn dns_message_with_truncated_header_returns_err() {
        let bytes: &[u8] = &[0x12, 0x34, 0x00, 0x00];

        assert_eq!(DNSMessage::try_from(bytes), Err(DNSError::HeaderTooShort));
    }

    #[test]
    fn dns_message_with_truncated_question_returns_err() {
        // Header says QDCOUNT=1 but there is not bytes for the question
        let bytes: &[u8] = &[
            0x12, 0x34, // id
            0x00, 0x00, // flags: query
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
        ];

        assert!(DNSMessage::try_from(bytes).is_err());
    }

    #[test]
    fn dns_message_with_truncated_answer_returns_err() {
        // Header says ANCOUNT=1 but there is not bytes for the answer
        let bytes: &[u8] = &[
            0x12, 0x34, // id
            0x00, 0x00, // flags: query
            0x00, 0x00, // QDCOUNT: 0
            0x00, 0x01, // ANCOUNT: 1
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
        ];

        assert!(DNSMessage::try_from(bytes).is_err());
    }
}
