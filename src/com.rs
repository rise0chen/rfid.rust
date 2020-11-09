pub trait Com {
    fn read(&mut self, reg: u8, value: &mut [u8]) -> Result<(), ()>;
    fn write(&mut self, reg: u8, value: &[u8]) -> Result<(), ()>;
}
