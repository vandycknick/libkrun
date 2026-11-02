use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    Limit,
    Overflow,
    Invalid(&'static str),
    Trailing,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated state"),
            Self::Limit => f.write_str("state exceeds bound"),
            Self::Overflow => f.write_str("state length overflow"),
            Self::Invalid(field) => write!(f, "invalid state: {field}"),
            Self::Trailing => f.write_str("trailing state bytes"),
        }
    }
}

impl std::error::Error for Error {}

pub struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len()
    }

    pub fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let result = self.bytes.get(..count).ok_or(Error::Truncated)?;
        self.bytes = self.bytes.get(count..).ok_or(Error::Truncated)?;
        Ok(result)
    }

    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Truncated)
    }

    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(u8::from_le_bytes(self.fixed()?))
    }

    pub fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.fixed()?))
    }

    pub fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.fixed()?))
    }

    pub fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.fixed()?))
    }

    pub fn u128(&mut self) -> Result<u128, Error> {
        Ok(u128::from_le_bytes(self.fixed()?))
    }

    pub fn bool(&mut self) -> Result<bool, Error> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Invalid("boolean")),
        }
    }

    pub fn count(&mut self, limit: usize, minimum_bytes: usize) -> Result<usize, Error> {
        let count = usize::try_from(self.u32()?).map_err(|_| Error::Overflow)?;
        if count > limit {
            return Err(Error::Limit);
        }
        let required = count.checked_mul(minimum_bytes).ok_or(Error::Overflow)?;
        if required > self.remaining() {
            return Err(Error::Truncated);
        }
        Ok(count)
    }

    pub fn bytes(&mut self, limit: usize) -> Result<&'a [u8], Error> {
        let count = self.count(limit, 1)?;
        self.take(count)
    }

    pub fn finish(self) -> Result<(), Error> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(Error::Trailing)
        }
    }
}

pub struct Writer {
    bytes: Vec<u8>,
    limit: usize,
}

impl Writer {
    pub fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    pub fn fixed(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let length = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(Error::Overflow)?;
        if length > self.limit {
            return Err(Error::Limit);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    pub fn u8(&mut self, value: u8) -> Result<(), Error> {
        self.fixed(&value.to_le_bytes())
    }
    pub fn u16(&mut self, value: u16) -> Result<(), Error> {
        self.fixed(&value.to_le_bytes())
    }
    pub fn u32(&mut self, value: u32) -> Result<(), Error> {
        self.fixed(&value.to_le_bytes())
    }
    pub fn u64(&mut self, value: u64) -> Result<(), Error> {
        self.fixed(&value.to_le_bytes())
    }
    pub fn u128(&mut self, value: u128) -> Result<(), Error> {
        self.fixed(&value.to_le_bytes())
    }
    pub fn bool(&mut self, value: bool) -> Result<(), Error> {
        self.u8(u8::from(value))
    }

    pub fn count(&mut self, count: usize, limit: usize) -> Result<(), Error> {
        if count > limit {
            return Err(Error::Limit);
        }
        self.u32(u32::try_from(count).map_err(|_| Error::Overflow)?)
    }

    pub fn bytes(&mut self, bytes: &[u8], limit: usize) -> Result<(), Error> {
        self.count(bytes.len(), limit)?;
        self.fixed(bytes)
    }

    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use crate::state::{Error, Reader, Writer};

    #[test]
    fn checked_state_primitives_roundtrip() {
        let mut writer = Writer::new(64);
        writer.u8(255).unwrap();
        writer.u16(0x1234).unwrap();
        writer.u32(0x12345678).unwrap();
        writer.u64(u64::MAX).unwrap();
        writer.u128(u128::MAX).unwrap();
        writer.bool(true).unwrap();
        writer.bytes(&[1, 2, 3], 3).unwrap();
        let bytes = writer.finish();
        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.u8().unwrap(), 255);
        assert_eq!(reader.u16().unwrap(), 0x1234);
        assert_eq!(reader.u32().unwrap(), 0x12345678);
        assert_eq!(reader.u64().unwrap(), u64::MAX);
        assert_eq!(reader.u128().unwrap(), u128::MAX);
        assert!(reader.bool().unwrap());
        assert_eq!(reader.bytes(3).unwrap(), &[1, 2, 3]);
        reader.finish().unwrap();
    }

    #[test]
    fn checked_state_bounds_before_allocation() {
        assert_eq!(Reader::new(&[2]).bool(), Err(Error::Invalid("boolean")));
        assert_eq!(Reader::new(&[0]).u64(), Err(Error::Truncated));
        assert_eq!(
            Reader::new(&u32::MAX.to_le_bytes()).bytes(1024),
            Err(Error::Limit)
        );
        assert_eq!(Reader::new(&[1]).finish(), Err(Error::Trailing));
        let mut writer = Writer::new(1);
        assert_eq!(writer.u16(0), Err(Error::Limit));
        assert_eq!(
            Reader::new(&[2, 0, 0, 0]).count(3, 8),
            Err(Error::Truncated)
        );
        assert_eq!(
            Reader::new(&[2, 0, 0, 0]).count(3, usize::MAX),
            Err(Error::Overflow)
        );
    }
}
