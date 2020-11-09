use super::com::Com;
use embedded_hal::blocking::i2c;

pub struct ComI2c<I2C> {
    com: I2C,
    addr: u8,
}
impl<I2C> ComI2c<I2C> {
    pub fn new(i2c: I2C, addr: u8) -> Self {
        Self {
            com: i2c,
            addr: addr,
        }
    }
}
impl<I2C> Com for ComI2c<I2C>
where
    I2C: i2c::Read + i2c::Write,
{
    fn read(&mut self, reg: u8, value: &mut [u8]) -> Result<(), ()> {
        if let Err(_) = self.com.write(self.addr, &[reg]) {
            return Err(());
        }
        if let Err(_) = self.com.read(self.addr, value) {
            return Err(());
        }
        return Ok(());
    }
    fn write(&mut self, reg: u8, value: &[u8]) -> Result<(), ()> {
        let tx_buf = &[&[reg], value].concat();
        if let Err(_) = self.com.write(self.addr, &tx_buf) {
            return Err(());
        }
        return Ok(());
    }
}
