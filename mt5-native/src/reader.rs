use crate::error::{ProtocolError, Result};

pub(crate) struct Reader<'a> {
    pub remaining: &'a [u8],
}
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }
    pub fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        if size > self.remaining.len() {
            return Err(ProtocolError::new("truncated message"));
        }
        let (a, b) = self.remaining.split_at(size);
        self.remaining = b;
        Ok(a)
    }
    pub fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    pub fn i32(&mut self) -> Result<i32> {
        Ok(i32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn count(&mut self, minimum_stride: usize) -> Result<usize> {
        let count = self.i32()?;
        if count < 0 || count as usize > self.remaining.len() / minimum_stride.max(1) {
            return Err(ProtocolError::new("invalid record count"));
        }
        Ok(count as usize)
    }
}
