//! DNS record type definitions.
//!
//! Provides [`Type`] for use in resource records, and [`QType`] for use
//! in the question section of a query. [`QType`] is a superset of [`Type`],
//! as defined in RFC 1035, Sections 3.2.2 and 3.2.3.

use crate::errors::DNSError;

/// TYPE fields are used in resource records. Note that these types are a
/// subset of QTYPEs.
///
/// RFC 1035, Section 3.2.2
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Type {
    /// A host address
    A,
    /// An authoritative name server
    NS,
    /// A mail destination (Obsolete - use MX)
    MD,
    /// A mail forwarder (Obsolete - use MX)
    MF,
    /// The canonical name for an alias
    CNAME,
    /// Marks the start of a zone of authority
    SOA,
    /// A mailbox domain name (EXPERIMENTAL)
    MB,
    /// A mail group member (EXPERIMENTAL)
    MG,
    /// A mail rename domain name (EXPERIMENTAL)
    MR,
    /// A null RR (EXPERIMENTAL)
    NULL,
    /// A well known service description
    WKS,
    /// A domain name pointer
    PTR,
    /// Host information
    HINFO,
    /// Mailbox or mail list information
    MINFO,
    /// Mail exchange
    MX,
    /// Text strings
    TXT,
}

impl TryFrom<u16> for Type {
    type Error = DNSError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            1 => Self::A,
            2 => Self::NS,
            3 => Self::MD,
            4 => Self::MF,
            5 => Self::CNAME,
            6 => Self::SOA,
            7 => Self::MB,
            8 => Self::MG,
            9 => Self::MR,
            10 => Self::NULL,
            11 => Self::WKS,
            12 => Self::PTR,
            13 => Self::HINFO,
            14 => Self::MINFO,
            15 => Self::MX,
            16 => Self::TXT,

            _ => return Err(DNSError::InvalidType(value)),
        })
    }
}

/// QTYPE fields appear in the question part of a query. QTYPES are a
/// superset of TYPEs, hence all TYPEs are valid QTYPEs. In addition, the
/// following QTYPEs are defined:
///
/// RFC 1035, Section 3.2.3
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum QType {
    /// A standard record type. All [`Type`] values are valid QTYPEs.
    Type(Type),
    /// A request for a transfer of an entire zone
    AXFR,
    /// A request for mailbox-related records (MB, MG or MR)
    MAILB,
    /// A request for mail agent RRs (Obsolete - see MX)
    MAILA,
    /// A request for all records
    ALL,
}

impl TryFrom<u16> for QType {
    type Error = DNSError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            1..=16 => Self::Type(Type::try_from(value)?),
            252 => Self::AXFR,
            253 => Self::MAILB,
            254 => Self::MAILA,
            255 => Self::ALL,

            _ => return Err(DNSError::InvalidQType(value)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_from_u16_for_type_is_ok_if_valid() {
        let pairs: [(u16, Type); 16] = [
            (1, Type::A),
            (2, Type::NS),
            (3, Type::MD),
            (4, Type::MF),
            (5, Type::CNAME),
            (6, Type::SOA),
            (7, Type::MB),
            (8, Type::MG),
            (9, Type::MR),
            (10, Type::NULL),
            (11, Type::WKS),
            (12, Type::PTR),
            (13, Type::HINFO),
            (14, Type::MINFO),
            (15, Type::MX),
            (16, Type::TXT),
        ];
        for (value, type_) in pairs {
            assert_eq!(Type::try_from(value), Ok(type_));
        }
    }

    #[test]
    fn try_from_u16_for_type_is_err_if_invalid() {
        for value in [0, 17, 0x0123, 0x4567, 0x89AB, 0xCDEF] {
            assert_eq!(Type::try_from(value), Err(DNSError::InvalidType(value)));
        }
    }

    #[test]
    fn try_from_u16_for_qtype_is_ok_if_valid() {
        let pairs: [(u16, QType); 6] = [
            (1, QType::Type(Type::A)),
            (16, QType::Type(Type::TXT)),
            (252, QType::AXFR),
            (253, QType::MAILB),
            (254, QType::MAILA),
            (255, QType::ALL),
        ];
        for (value, qtype_) in pairs {
            assert_eq!(QType::try_from(value), Ok(qtype_));
        }
    }

    #[test]
    fn try_from_u16_for_qtype_is_err_if_invalid() {
        for value in [0, 17, 251, 256, 0x0123, 0x4567, 0x89AB, 0xCDEF] {
            assert_eq!(QType::try_from(value), Err(DNSError::InvalidQType(value)));
        }
    }
}
