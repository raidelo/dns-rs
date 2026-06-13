//! DNS record class definitions.
//!
//! Provides [`Class`] for use in resource records, and [`QClass`] for use
//! in the question section of a query. [`QClass`] is a superset of [`Class`],
//! as defined in RFC 1035, Sections 3.2.4 and 3.2.5.

use crate::errors::DNSError;

/// CLASS fields appear in resource records. Note that these classes are a
/// subset of QCLASSes.
///
/// RFC 1035, Section 3.2.4
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Class {
    /// The Internet
    IN,
    /// The CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CS,
    /// The CHAOS class
    CH,
    /// Hesiod [Dyer 87]
    HS,
}

impl TryFrom<u16> for Class {
    type Error = DNSError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            1 => Self::IN,
            2 => Self::CS,
            3 => Self::CH,
            4 => Self::HS,

            _ => return Err(DNSError::InvalidClass(value)),
        })
    }
}

impl From<Class> for u16 {
    fn from(value: Class) -> Self {
        match value {
            Class::IN => 1,
            Class::CS => 2,
            Class::CH => 3,
            Class::HS => 4,
        }
    }
}

/// QCLASS fields appear in the question part of a query. QCLASSes are a
/// superset of CLASSes, hence all CLASSes are valid QCLASSes. In addition,
/// the following QCLASSes are defined:
///
/// RFC 1035, Section 3.2.5
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum QClass {
    /// A standard record class. All [`Class`] values are valid QCLASSes.
    Class(Class),
    /// Any class.
    ANY,
}

impl TryFrom<u16> for QClass {
    type Error = DNSError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            1..=4 => Self::Class(Class::try_from(value)?),
            255 => Self::ANY,

            _ => return Err(DNSError::InvalidQClass(value)),
        })
    }
}

impl From<QClass> for u16 {
    fn from(value: QClass) -> Self {
        match value {
            QClass::Class(c) => c.into(),
            QClass::ANY => 255,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_from_u16_for_class_is_ok_if_valid() {
        let pairs: [(u16, Class); 4] = [
            (1, Class::IN),
            (2, Class::CS),
            (3, Class::CH),
            (4, Class::HS),
        ];
        for (value, class) in pairs {
            assert_eq!(Class::try_from(value), Ok(class));
        }
    }

    #[test]
    fn try_from_u16_for_class_is_err_if_invalid() {
        for value in [0, 5, 0x0123, 0x4567, 0x89AB, 0xCDEF] {
            assert_eq!(Class::try_from(value), Err(DNSError::InvalidClass(value)));
        }
    }

    #[test]
    fn try_from_u16_for_qclass_is_ok_if_valid() {
        let pairs: [(u16, QClass); 5] = [
            (1, QClass::Class(Class::IN)),
            (2, QClass::Class(Class::CS)),
            (3, QClass::Class(Class::CH)),
            (4, QClass::Class(Class::HS)),
            (255, QClass::ANY),
        ];
        for (value, qclass) in pairs {
            assert_eq!(QClass::try_from(value), Ok(qclass));
        }
    }

    #[test]
    fn try_from_u16_for_qclass_is_err_if_invalid() {
        for value in [0, 5, 254, 256, 0x0123, 0x4567, 0x89AB, 0xCDEF] {
            assert_eq!(QClass::try_from(value), Err(DNSError::InvalidQClass(value)));
        }
    }

    #[test]
    fn from_class_into_u16_is_correct() {
        let pairs: [(Class, u16); 4] = [
            (Class::IN, 1),
            (Class::CS, 2),
            (Class::CH, 3),
            (Class::HS, 4),
        ];
        for (class, value) in pairs {
            assert_eq!(u16::from(class), value);
        }
    }

    #[test]
    fn from_qclass_into_u16_is_correct() {
        let pairs: [(QClass, u16); 3] = [
            (QClass::Class(Class::IN), 1),
            (QClass::Class(Class::HS), 4),
            (QClass::ANY, 255),
        ];
        for (qclass, value) in pairs {
            assert_eq!(u16::from(qclass), value);
        }
    }

    #[test]
    fn class_u16_roundtrip() {
        for value in 1u16..=4 {
            assert_eq!(u16::from(Class::try_from(value).unwrap()), value);
        }
    }
}
