use crate::errors::DNSError;

/// Helper function to read a 2-byte big-endian integer from the slice
/// and advance the offset.
pub fn read_u16(value: &[u8], offset: &mut usize) -> Result<u16, DNSError> {
    let bytes = value
        .get(*offset..*offset + 2)
        .ok_or(DNSError::UnexpectedEnd)?
        .try_into()
        .expect("slice is guaranteed to be 2 bytes by .get()");
    *offset += 2;
    Ok(u16::from_be_bytes(bytes))
}
