use spidev::{Spidev, SpidevOptions, SPI_MODE_0};
use std::io;

mod mfrc522;

fn create_spi() -> io::Result<Spidev> {
    let mut spi = Spidev::open("/dev/spidev1.0")?;
    let options = SpidevOptions::new()
        .bits_per_word(8)
        .max_speed_hz(20_000)
        .mode(SPI_MODE_0)
        .build();
    spi.configure(&options)?;
    Ok(spi)
}

fn main() {
    let spi = create_spi().unwrap();
    let mut mfrc = mfrc522::MFRC522 { spi };
    mfrc.init().expect("Init failed!");

    loop {
        let new_card = mfrc.new_card_present().is_ok();
        println!("{}", new_card);

        // mfrc.init().expect("Init failed!");

        mfrc.dump_registers().expect("Could not dump registers");

        if new_card {
            match mfrc.read_card_serial() {
                Ok(u) => println!("read card serial {:?}", u),
                Err(e) => println!("could not read card: {:?}", e),
            }

            mfrc.dump_registers().expect("Could not dump registers");

            match mfrc.read_card_serial() {
                Ok(u) => println!("read card serial {:?}", u),
                Err(e) => println!("could not read card: {:?}", e),
            }

            mfrc.dump_registers().expect("Could not dump registers");
        }
    }
}
