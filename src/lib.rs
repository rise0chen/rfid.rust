#![no_std]
extern crate alloc;

pub mod com;
pub mod com_i2c;
pub mod mfrc522;
pub mod picc;

#[allow(dead_code)]
pub enum Error {
    /// 通信接口出错
    ComErr,
    Communication, // Error in communication
    Collision,     // Collission detected
    Timeout,       // Timeout in communication.
    NoRoom,        // A buffer is not big enough.
    InternalError, // Internal error in the code. Should not happen.
    Invalid,       // Invalid argument.
    CrcWrong,      // The CRC_A does not match
    MifareNack,    // A MIFARE PICC responded with NAK.
}

pub struct RFID {}
