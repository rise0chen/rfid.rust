#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Command {
    REQA = 0x26, // REQuest command, Type A. Invites PICCs in state IDLE to go to READY and prepare for anticollision or selection. 7 bit frame.
    WUPA = 0x52, // Wake-UP command, Type A. Invites PICCs in state IDLE and HALT to go to READY(*) and prepare for anticollision or selection. 7 bit frame.
    CT = 0x88,   // Cascade Tag. Not really a command, but used during anti collision.
    SelCl1 = 0x93, // Anti collision/Select, Cascade Level 1
    SelCl2 = 0x95, // Anti collision/Select, Cascade Level 2
    SelCl3 = 0x97, // Anti collision/Select, Cascade Level 3
    HLTA = 0x50, // HaLT command, Type A. Instructs an ACTIVE PICC to go to state HALT.
    RATS = 0xE0, // Request command for Answer To Reset.
    // The commands used for MIFARE Classic (from http://www.mouser.com/ds/2/302/MF1S503x-89574.pdf, Section 9)
    // Use PCD_MFAuthent to authenticate access to a sector, then use these commands to read/write/modify the blocks on the sector.
    // The read/write commands can also be used for MIFARE Ultralight.
    MfAuthKeyA = 0x60,  // Perform authentication with Key A
    MfAuthKeyB = 0x61,  // Perform authentication with Key B
    MfRead = 0x30, // Reads one 16 byte block from the authenticated sector of the PICC. Also used for MIFARE Ultralight.
    MfWrite = 0xA0, // Writes one 16 byte block to the authenticated sector of the PICC. Called "COMPATIBILITY WRITE" for MIFARE Ultralight.
    MfDecrement = 0xC0, // Decrements the contents of a block and stores the result in the internal data register.
    MfIncrement = 0xC1, // Increments the contents of a block and stores the result in the internal data register.
    MfRestore = 0xC2,   // Reads the contents of a block into the internal data register.
    MfTransfer = 0xB0,  // Writes the contents of the internal data register to a block.
    // The commands used for MIFARE Ultralight (from http://www.nxp.com/documents/data_sheet/MF0ICU1.pdf, Section 8.6)
    // The PICC_CMD_MF_READ and PICC_CMD_MF_WRITE can also be used for MIFARE Ultralight.
    UlWrite = 0xA2, // Writes one 4 byte page to the PICC.
}

#[derive(Debug)]
pub enum Type {
    Unknown,
    Iso14443_4,    // PICC compliant with ISO/IEC 14443-4 
    Iso18092,      // PICC compliant with ISO/IEC 18092 (NFC)
    MifareMini,    // MIFARE Classic protocol, 320 bytes
    Mifare1k,      // MIFARE Classic protocol, 1KB
    Mifare4k,      // MIFARE Classic protocol, 4KB
    MifareUL,      // MIFARE Ultralight or Ultralight C
    MifarePlus,    // MIFARE Plus
    MifareDesfire, // MIFARE DESFire
    TNP3XXX,       // Only mentioned in NXP AN 10833 MIFARE Type Identification Procedure
    NotComplete,   // SAK indicates UID is not complete.
}

#[derive(Debug)]
pub struct Response {
    pub data: Vec<u8>,
    pub valid_bits: u8,
    pub had_collision: bool,
}

pub fn get_type(sak: u8) -> Type {
    // http://www.nxp.com/documents/application_note/AN10833.pdf 
    // 3.2 Coding of Select Acknowledge (SAK)
    // ignore 8-bit (iso14443 starts with LSBit = bit 1)
    // fixes wrong type for manufacturer Infineon (http://nfc-tools.org/index.php?title=ISO14443A)
    match sak & 0x7F {
        0x04 => Type::NotComplete, // UID not complete
        0x09 => Type::MifareMini,
        0x08 => Type::Mifare1k,
        0x18 => Type::Mifare4k,
        0x00 => Type::MifareUL,
        0x10 | 0x11 => Type::MifarePlus,
        0x01 => Type::TNP3XXX,
        0x20 => Type::Iso14443_4,
        0x40 => Type::Iso18092,
        _ =>    Type::Unknown,
    }
}