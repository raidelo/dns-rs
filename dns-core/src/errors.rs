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
}
