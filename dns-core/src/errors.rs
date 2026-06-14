//! Error types for DNS message parsing and processing.

/// Errors that can occur during DNS message parsing and processing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DNSError {
    /// The byte slice is too short to contain a valid DNS header.
    /// A DNS header requires exactly 12 bytes.
    ///
    /// RFC 1035, Section 4.1.1
    HeaderTooShort,
    /// The value does not correspond to any known DNS TYPE.
    /// Contains the unrecognized value.
    ///
    /// RFC 1035, Section 3.2.2
    InvalidType(u16),

    /// The value does not correspond to any known DNS QTYPE.
    /// Contains the unrecognized value.
    ///
    /// RFC 1035, Section 3.2.3
    InvalidQType(u16),

    /// The value does not correspond to any known DNS CLASS.
    /// Contains the unrecognized value.
    ///
    /// RFC 1035, Section 3.2.4
    InvalidClass(u16),

    /// The value does not correspond to any known DNS QCLASS.
    /// Contains the unrecognized value.
    ///
    /// RFC 1035, Section 3.2.5
    InvalidQClass(u16),

    /// The label is invalid. Contains the specific reason for the failure.
    /// See [`InvalidLabelType`] for details.
    InvalidLabel(LabelError),
}

/// The specific reason a DNS label failed to parse.
///
/// RFC 1035, Section 2.3.1 (composition rules)
/// RFC 1035, Section 2.3.4 (size limits)
/// RFC 1035, Section 3.1 (wire structure)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LabelError {
    /// The slice is empty, no length byte is present.
    ///
    /// RFC 1035, Section 3.1
    EmptySlice,
    /// The length byte is zero. A zero-length label indicates the root
    /// of the domain name and should be handled by the caller, not parsed
    /// as a label.
    ///
    /// RFC 1035, Section 3.1
    ZeroLength,
    /// The slice is shorter than the length byte indicates.
    ///
    /// RFC 1035, Section 3.1
    SliceTooShort,
    /// The length byte exceeds the maximum label length of 63 bytes.
    ///
    /// RFC 1035, Section 2.3.4
    LengthTooLong(u8),
    /// The label contains a character that violates ARPANET host name rules.
    /// Labels must start with a letter, end with a letter or digit, and contain
    /// only letters, digits, and hyphens as interior characters.
    /// Contains the invalid byte.
    ///
    /// RFC 1035, Section 2.3.1
    InvalidCharacter(u8),
}
