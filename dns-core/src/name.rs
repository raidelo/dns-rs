use crate::{
    errors::{DNSError, LabelError},
    label::Label,
};

#[derive(Debug, PartialEq)]
pub struct DomainName(Vec<Label>);

impl TryFrom<&[u8]> for DomainName {
    type Error = DNSError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut ptr = 0;

        let mut array: Vec<Label> = Vec::new();

        loop {
            match Label::try_from(&value[ptr..]) {
                Ok(label) => {
                    ptr += label.len() + 1;
                    array.push(label);
                }

                Err(LabelError::ZeroLength) => break Ok(Self(array)),

                Err(LabelError::EmptySlice) => return Err(DNSError::MissingNameTerminator),

                Err(err) => return Err(DNSError::InvalidLabel(err)),
            }
        }
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
}
