#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Flags(u16);

impl Flags {
    pub fn qr(&self) -> bool {
        (self.0 >> 15) & 1 == 1
    }
    pub fn opcode(&self) -> u8 {
        ((self.0 >> 11) & 0xF) as u8
    }
    pub fn aa(&self) -> bool {
        (self.0 >> 10) & 1 == 1
    }
    pub fn tc(&self) -> bool {
        (self.0 >> 9) & 1 == 1
    }
    pub fn rd(&self) -> bool {
        (self.0 >> 8) & 1 == 1
    }
    pub fn ra(&self) -> bool {
        (self.0 >> 7) & 1 == 1
    }
    pub fn z(&self) -> u8 {
        ((self.0 >> 4) & 0x7) as u8
    }
    pub fn rcode(&self) -> u8 {
        (self.0 & 0xF) as u8
    }
}

impl From<u16> for Flags {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_flags_from_u16_works() {
        let data: u16 = 0b11001100_01010101;

        let flags = Flags::from(data);

        assert!(flags.qr());
        assert_eq!(flags.opcode(), 0b1001);
        assert!(flags.aa());
        assert!(!flags.tc());
        assert!(!flags.rd());
        assert!(!flags.ra());
        assert_eq!(flags.z(), 0b101);
        assert_eq!(flags.rcode(), 0b0101);
    }
}
