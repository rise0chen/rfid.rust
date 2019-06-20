use spidev::{Spidev, SpidevOptions, SpiModeFlags};
use std::io;

extern crate rfid_rs;
use rfid_rs::picc;

fn create_spi() -> io::Result<Spidev> {
    let mut spi = Spidev::open("/dev/spidev1.0")?;
    let options = SpidevOptions::new()
        .bits_per_word(8)
        .max_speed_hz(20_000)
        .mode(SpiModeFlags::SPI_MODE_0)
        .build();
    spi.configure(&options)?;
    Ok(spi)
}

fn main() {
    let spi = create_spi().unwrap();
    let mut mfrc522 = rfid_rs::MFRC522 { spi };
    mfrc522.init().expect("Init failed!");

    loop {
        let new_card = mfrc522.new_card_present().is_ok();

        if new_card {
            let key: rfid_rs::MifareKey = [0xffu8; 6];

            let uid = match mfrc522.read_card_serial() {
                Ok(u) => u,
                Err(e) => {
                    println!("Could not read card: {:?}", e);
                    continue
                },
            };

            let block = 1;
            let buffer = [0x42u8, 0x66u8, 0x13u8, 0x69u8, 0x42u8, 0x66u8, 0x13u8, 0x69u8,
                          0x42u8, 0x66u8, 0x13u8, 0x69u8, 0x42u8, 0x66u8, 0x13u8, 0x69u8];

            match mfrc522.authenticate(picc::Command::MfAuthKeyA, block, key, &uid) {
                Ok(_) => println!("Authenticated card"),
                Err(e) => {
                    println!("Could not authenticate card {:?}", e);
                    continue
                }
            }
            match mfrc522.mifare_write(block, &buffer) {
                Ok(_) => println!("Wrote block {} successfully", block),
                Err(e) => {
                    println!("Failed reading block {}: {:?}", block, e);
                    continue
                }
            }

            mfrc522.halt_a().expect("Could not halt");
            mfrc522.stop_crypto1().expect("Could not stop crypto1");
        }
    }
}
