//! DNS label parsing and representation.
//!
//! A domain name is composed of a sequence of labels. Each label is preceded
//! by a length byte indicating the number of octets that follow. Labels must
//! start with a letter, end with a letter or digit, and contain only letters,
//! digits, and hyphens as interior characters, with a maximum length of 63
//! characters.
//!
//! This module provides [`Label`], which represents a single
//! parsed label from a DNS name.
//!
//! RFC 1035, Section 2.3.1 (composition rules)
//! RFC 1035, Section 2.3.4 (size limits)
//! RFC 1035, Section 3.1 (wire structure)

use std::ops::Deref;

use crate::errors::LabelError;

/// A single label in a domain name.
///
/// Represents the content of a label after the length byte has been parsed
/// and validated. The length byte itself is not stored — it is reconstructed
/// from the content length during serialization.
#[derive(Debug, PartialEq)]
pub struct Label(Vec<u8>);

impl TryFrom<&[u8]> for Label {
    type Error = LabelError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let length = *value.first().ok_or(LabelError::EmptySlice)?;

        if length == 0 {
            return Err(LabelError::ZeroLength);
        }

        if length > 63 {
            return Err(LabelError::LengthTooLong(length));
        }

        let mut label: Vec<u8> = Vec::with_capacity(length as usize);

        for i in 1..=(length as usize) {
            let Some(b) = value.get(i) else {
                return Err(LabelError::SliceTooShort);
            };

            if !is_valid_character(*b) {
                return Err(LabelError::InvalidCharacter(*b));
            }

            label.push(*b);
        }

        if let Some(byte) = label.last()
            && *byte == b'-'
        {
            return Err(LabelError::InvalidCharacter(*byte));
        }

        if let Some(byte) = label.first()
            && !byte.is_ascii_alphabetic()
        {
            return Err(LabelError::InvalidCharacter(*byte));
        }

        Ok(Self(label))
    }
}

impl Deref for Label {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

fn is_valid_character(ch: u8) -> bool {
    ch.is_ascii_alphanumeric() || ch == b'-'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_from_valid_bytes_returns_ok() {
        let bytes = b"\x3FABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-0123456789";

        assert_eq!(
            Label::try_from(&bytes[..]).unwrap(),
            Label((bytes[1..]).to_vec())
        );
    }

    #[test]
    fn label_from_empty_slice_returns_err() {
        assert_eq!(
            Label::try_from(&b""[..]).unwrap_err(),
            LabelError::EmptySlice,
        );
    }

    #[test]
    fn label_from_zero_length_returns_err() {
        assert_eq!(
            Label::try_from(&b"\x00"[..]).unwrap_err(),
            LabelError::ZeroLength,
        );
    }

    #[test]
    fn label_from_short_slice_returns_err() {
        assert_eq!(
            Label::try_from(&b"\x05test"[..]).unwrap_err(),
            LabelError::SliceTooShort,
        );
    }

    #[test]
    fn label_from_length_too_long_returns_err() {
        assert_eq!(
            Label::try_from(&b"\x40test"[..]).unwrap_err(),
            LabelError::LengthTooLong(0x40),
        );
    }

    #[test]
    fn label_from_invalid_ending_byte_returns_err() {
        assert_eq!(
            Label::try_from(&b"\x05test-"[..]).unwrap_err(),
            LabelError::InvalidCharacter(b'-'),
        );
    }

    #[test]
    fn label_from_invalid_starting_byte_returns_err() {
        let mut invalid_starting_byte = *b"\x05\x00test";

        for byte in (b'0'..=b'9').chain(Some(b'-')) {
            invalid_starting_byte[1] = byte;

            assert_eq!(
                Label::try_from(&invalid_starting_byte[..]),
                Err(LabelError::InvalidCharacter(byte)),
                "Expected InvalidCharacter for byte 0x{byte:02X} ({byte})",
            );
        }
    }

    #[test]
    fn label_from_invalid_inner_byte_returns_err() {
        let mut invalid_inner_byte = *b"\x09some\x00test";

        for byte in (0x00u8..=0xFF).filter(|b| !is_valid_character(*b)) {
            invalid_inner_byte[5] = byte;

            assert_eq!(
                Label::try_from(&invalid_inner_byte[..]),
                Err(LabelError::InvalidCharacter(byte)),
                "Expected InvalidCharacter for byte 0x{byte:02X} ({byte})",
            );
        }
    }
}
