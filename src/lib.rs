use std::io;
use std::io::prelude::*;
use std::result;
use std::thread;
use std::time;

use spidev;

pub mod picc;

/// Registers in the MFRC522, the Proximity Coupling Device (PCD) used here.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum Register {
    // Reserved         = 0x00,
    CommandReg = 0x01,
    ComlEnReg = 0x02,
    DivlEnReg = 0x03,
    ComIrqReg = 0x04,
    DivIrqReg = 0x05,
    ErrorReg = 0x06,
    Status1Reg = 0x07,
    Status2Reg = 0x08,
    FIFODataReg = 0x09,
    FIFOLevelReg = 0x0A,
    WaterLevelReg = 0x0B,
    ControlReg = 0x0C,
    BitFramingReg = 0x0D,
    CollReg = 0x0E,
    // Reserved         = 0x0F,
    // Reserved         = 0x10,
    ModeReg = 0x11,
    TxModeReg = 0x12,
    RxModeReg = 0x13,
    TxControlReg = 0x14,
    TxASKReg = 0x15,
    TxSelReg = 0x16,
    RxSelReg = 0x17,
    RxThresholdReg = 0x18,
    DemodReg = 0x19,
    // Reserved         = 0x1A,
    // Reserved         = 0x1B,
    MfTxReg = 0x1C,
    MfRxReg = 0x1D,
    // Reserved         = 0x1E,
    SerialSpeedReg = 0x1F,
    // Reserved         = 0x20,
    CRCResultRegHigh = 0x21,
    CRCResultRegLow = 0x22,
    // Reserved         = 0x23,
    ModWidthReg = 0x24,
    // Reserved         = 0x25,
    RFCfgReg = 0x26,
    GsNReg = 0x27,
    CWGsPReg = 0x28,
    ModGsPReg = 0x29,
    TModeReg = 0x2A,
    TPrescalerReg = 0x2B,
    TReloadRegHigh = 0x2C,
    TReloadRegLow = 0x2D,
    TCounterValRegHigh = 0x2E,
    TCounterValRegLow = 0x2F,
    // Reserved         = 0x30,
    TestSel1Reg = 0x31,
    TestSel2Reg = 0x32,
    TestPinEnReg = 0x33,
    TestPinValueReg = 0x34,
    TestBusReg = 0x35,
    AutoTestReg = 0x36,
    VersionReg = 0x37,
    AnalogTestReg = 0x38,
    TestDAC1Reg = 0x39,
    TestDAC2Reg = 0x3A,
    TestADCReg = 0x3B,
    // Reserved         = 0x3C-0x3F,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Command {
    Idle = 0b0000,
    Mem = 0b0001,
    GenerateRandomId = 0b0010,
    CalcCRC = 0b0011,
    Transmit = 0b0100,
    NoCmdChange = 0b0111,
    Receive = 0b1000,
    Transceive = 0b1100,
    MFAuthent = 0b1110,
    SoftReset = 0b1111,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum Error {
    Io(io::Error), // Error from std::io
    Communication, // Error in communication
    Collision,     // Collission detected
    Timeout,       // Timeout in communication.
    NoRoom,        // A buffer is not big enough.
    InternalError, // Internal error in the code. Should not happen.
    Invalid,       // Invalid argument.
    CrcWrong,      // The CRC_A does not match
    MifareNack,    // A MIFARE PICC responded with NAK.
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Io(error)
    }
}

type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub struct Uid {
    pub bytes: Vec<u8>,         // The UID can have 4, 7 or 10 bytes.
        select_acknowledge: u8, // The SAK (Select acknowledge) byte returned from the PICC after successful selection.
}

const MIFARE_ACK: u8 = 0xA;

const MIFARE_KEYSIZE: usize = 6;
pub type MifareKey = [u8; MIFARE_KEYSIZE];

pub struct MFRC522 {
    pub spi: spidev::Spidev,
}

impl MFRC522 {
    fn register_to_readvalue(reg: Register) -> u8 {
        (((reg as u8) << 1) | 0b1000_0000) & 0b1111_1110
    }

    fn register_to_writevalue(reg: Register) -> u8 {
        ((reg as u8) << 1) & 0b0111_1110
    }

    pub fn read_register(&mut self, reg: Register) -> Result<u8> {
        let rval = MFRC522::register_to_readvalue(reg);

        let tx_buf = [rval, 0];
        let mut rx_buf = [0; 2];
        {
            let mut transfer = spidev::SpidevTransfer::read_write(&tx_buf, &mut rx_buf);
            self.spi.transfer(&mut transfer)?;
        }
        // println!("Read {:#x?} from {:?}", rx_buf[1], reg);
        Ok(rx_buf[1])
    }

    pub fn read_multiple(&mut self, reg: Register, count: usize) -> Result<Vec<u8>> {
        if count == 0 {
            return Ok(Vec::new());
        }
        let address = MFRC522::register_to_readvalue(reg);
        let mut tx_buf = vec![address; count];
        tx_buf.push(0);
        let mut rx_buf = vec![0u8; count + 1];
        {
            let mut transfer = spidev::SpidevTransfer::read_write(&tx_buf, &mut rx_buf);
            self.spi.transfer(&mut transfer)?;
        }
        // println!("Read {:#x?} from {:?}", rx_buf, reg);
        rx_buf.remove(0);
        Ok(rx_buf)
    }

    pub fn write_register(&mut self, reg: Register, value: u8) -> Result<()> {
        let rval = MFRC522::register_to_writevalue(reg);
        self.spi.write_all(&[rval, value])?;
        // println!("Wrote {:#x?} to {:?}", value, reg);
        Ok(())
    }

    pub fn write_multiple(&mut self, reg: Register, value: &[u8]) -> Result<()> {
        let rval = MFRC522::register_to_writevalue(reg);
        self.spi.write_all(&[&[rval], value].concat())?;
        // println!("Wrote {:#x?} to {:?}", value, reg);
        Ok(())
    }

    pub fn init(&mut self) -> Result<()> {
        self.reset()?;

        self.write_register(Register::TxModeReg, 0x00)?;
        self.write_register(Register::RxModeReg, 0x00)?;
        // Reset ModWidthReg
        self.write_register(Register::ModWidthReg, 0x26)?;
        // When communicating with a PICC we need a timeout if something goes wrong.
        // f_timer = 13.56 MHz / (2*TPreScaler+1) where TPreScaler = [TPrescaler_Hi:TPrescaler_Lo].
        // TPrescaler_Hi are the four low bits in TModeReg. TPrescaler_Lo is TPrescalerReg.
        self.write_register(Register::TModeReg, 0x80)?; // TAuto=1; timer starts automatically at the end of the transmission in all communication modes at all speeds
        self.write_register(Register::TPrescalerReg, 0xA9)?; // TPreScaler = TModeReg[3..0]:TPrescalerReg, ie 0x0A9 = 169 => f_timer=40kHz, ie a timer period of 25μs.
        self.write_register(Register::TReloadRegHigh, 0x03)?; // Reload timer with 0x3E8 = 1000, ie 25ms before timeout.
        self.write_register(Register::TReloadRegLow, 0xE8)?;
        self.write_register(Register::TxASKReg, 0x40)?; // Default 0x00. Force a 100 % ASK modulation independent of the ModGsPReg register setting
        self.write_register(Register::ModeReg, 0x3D)?; // Default 0x3F. Set the preset value for the CRC coprocessor for the CalcCRC command to 0x6363 (ISO 14443-3 part 6.2.4)
        self.enable_antenna()?;
        Ok(())
    }

    pub fn reset(&mut self) -> Result<()> {
        self.write_register(Register::CommandReg, Command::SoftReset as u8)?;
        let mut count = 0;
        loop {
            thread::sleep(time::Duration::from_millis(50));
            let cmd_val = self.read_register(Register::CommandReg)?;
            if cmd_val & (1 << 4) == 0 || count >= 3 {
                break;
            }
            count += 1;
        }
        Ok(())
    }

    pub fn set_register_bitmask(&mut self, reg: Register, mask: u8) -> Result<()> {
        let tmp = self.read_register(reg)?;
        self.write_register(reg, tmp | mask)?;
        Ok(())
    }

    pub fn clear_register_bitmask(&mut self, reg: Register, mask: u8) -> Result<()> {
        let tmp = self.read_register(reg)?;
        self.write_register(reg, tmp & !mask)?;
        Ok(())
    }

    pub fn enable_antenna(&mut self) -> Result<()> {
        let control_reg = self.read_register(Register::TxControlReg)?;
        if (control_reg & 0x03) != 0x03 {
            self.write_register(Register::TxControlReg, control_reg | 0x03)?;
        }
        Ok(())
    }

    pub fn calculate_crc(&mut self, data: &[u8]) -> Result<[u8; 2]> {
        self.write_register(Register::CommandReg, Command::Idle as u8)?;
        self.write_register(Register::DivIrqReg, 0x04)?;
        self.write_register(Register::FIFOLevelReg, 0x80)?;
        self.write_multiple(Register::FIFODataReg, data)?;
        self.write_register(Register::CommandReg, Command::CalcCRC as u8)?;

        // Wait for the CRC calculation to complete. Each iteration of the while-loop takes 17.73us.
        for _ in 0..5000 {
            let n = self.read_register(Register::DivIrqReg)?;
            if n & 0x04 != 0 {
                self.write_register(Register::CommandReg, Command::Idle as u8)?;
                let res_low = self.read_register(Register::CRCResultRegLow)?;
                let res_high = self.read_register(Register::CRCResultRegHigh)?;
                return Ok([res_low, res_high]);
            }
        }
        Err(Error::Timeout)
    }

    /// Transfers data to the MFRC522 FIFO, executes a command,\
    /// waits for completion and transfers data back from the FIFO.\
    /// CRC validation will only be done if back_len is specified.
    ///
    /// @return STATUS_OK on success, STATUS_??? otherwise.
    ///
    #[allow(clippy::too_many_arguments)]
    pub fn communicate_with_picc(
        &mut self,
        command: Command, // The command to execute. One of the PCD_Command enums.
        wait_irq: u8, // The bits in the ComIrqReg register that signals successful completion of the command.
        send_data: &[u8], // Pointer to the data to transfer to the FIFO.
        back_len: u8, // Max number of bytes that should be returned.
        valid_bits: u8, // The number of valid bits in the last byte. 0 for 8 valid bits.
        rx_align: u8, // Defines the bit position for the first bit received. Default 0.
        check_crc: bool,
    ) -> Result<picc::Response> // Returns: data received from the MFRC522 + the number of valid bits in the last byte of the data
    {
        // Prepare values for BitFramingReg
        let bit_framing = (rx_align << 4) + valid_bits; // RxAlign = BitFramingReg[6..4]. TxLastBits = BitFramingReg[2..0]

        self.write_register(Register::CommandReg, Command::Idle as u8)?; // Stop any active command.
        self.write_register(Register::ComIrqReg, 0x7F)?; // Clear all seven interrupt request bits.
        self.write_register(Register::FIFOLevelReg, 0x80)?; // FlushBuffer = 1, FIFO initialization
        self.write_multiple(Register::FIFODataReg, send_data)?; // Write send_data to the FIFO
        self.write_register(Register::BitFramingReg, bit_framing)?; // Bit adjustments
        self.write_register(Register::CommandReg, command as u8)?; // Execute the command

        if command == Command::Transceive {
            self.set_register_bitmask(Register::BitFramingReg, 0x80)?;
        }

        // Wait for the command to complete.
        // In PCD_Init() we set the TAuto flag in TModeReg. This means the timer automatically starts when the PCD stops transmitting.
        // Each iteration of the do-while-loop takes 17.86μs.
        // TODO check/modify for other architectures than Arduino Uno 16bit
        let mut i: u16 = 40;
        while i > 0 {
            let n = self.read_register(Register::ComIrqReg)?;
            if n & wait_irq != 0 {
                // One of the interrupts that signal success has been set.
                break;
            }
            if n & 0x01 != 0 {
                // Timer interrupt - nothing received in 25ms
                return Err(Error::Timeout);
            }
            i -= 1;
        }

        // 35.7ms and nothing happend. Communication with the MFRC522 might be down.
        if i == 0 {
            return Err(Error::Timeout);
        }

        // Stop now if any errors except collisions were detected.
        let error_reg_value = self.read_register(Register::ErrorReg)?; // ErrorReg[7..0] bits are: WrErr TempErr reserved BufferOvfl CollErr CRCErr ParityErr ProtocolErr
        if error_reg_value & 0x13 != 0 {
            // BufferOvfl ParityErr ProtocolErr
            return Err(Error::Communication);
        }

        let mut recv_valid_bits = 0u8;
        let mut recv_data = Vec::new();
        // If the caller wants data back, get it from the MFRC522.
        if back_len != 0 {
            let n = self.read_register(Register::FIFOLevelReg)?; // Number of bytes in the FIFO
            if n > back_len {
                return Err(Error::NoRoom);
            }
            recv_data = self.read_multiple(Register::FIFODataReg, n as usize)?; // Get received data from FIFO
            if recv_data.len() != n as usize {
                return Err(Error::InternalError);
            }
            // RxLastBits[2:0] indicates the number of valid bits in the last received byte.
            // If this value is 0b000, the whole byte is valid.
            recv_valid_bits = self.read_register(Register::ControlReg)? & 0x07;
        }

        // Tell about collisions
        if error_reg_value & 0x08 != 0 {
            return Ok(picc::Response {
                data: recv_data,
                valid_bits: recv_valid_bits,
                had_collision: true,
            });
        }

        // Perform CRC_A validation if requested.
        if !recv_data.is_empty() && check_crc {
            // In this case a MIFARE Classic NAK is not OK.
            if recv_data.len() == 1 && recv_valid_bits == 4 {
                return Err(Error::MifareNack);
            }
            // We need at least the CRC_A value and all 8 bits of the last byte must be received.
            if recv_data.len() < 2 || recv_valid_bits != 0 {
                return Err(Error::CrcWrong);
            }
            // Verify CRC_A - do our own calculation and store the control in controlBuffer.
            let control_buffer = self.calculate_crc(&recv_data[0..recv_data.len() - 2])?;
            if recv_data[recv_data.len() - 2] != control_buffer[0]
                || recv_data[recv_data.len() - 1] != control_buffer[1]
            {
                return Err(Error::CrcWrong);
            }
        }

        Ok(picc::Response {
            data: recv_data,
            valid_bits: recv_valid_bits,
            had_collision: false,
        })
    }

    pub fn transceive_data(
        &mut self,
        send_data: &[u8], // Pointer to the data to transfer to the FIFO.
        back_len: u8,     // Max number of bytes that should be returned.
        valid_bits: u8,   // The number of valid bits in the last byte. 0 for 8 valid bits.
        rx_align: u8,     // Defines the bit position for the first bit received. Default 0.
        check_crc: bool,
    ) -> Result<picc::Response> {
        // Returns: data received from the MFRC522 + the number of valid bits in the last byte of the data
        let wait_irq = 0x30;
        self.communicate_with_picc(
            Command::Transceive,
            wait_irq,
            send_data,
            back_len,
            valid_bits,
            rx_align,
            check_crc,
        )
    }

    /// Transmits a REQuest command, Type A. Invites PICCs in state IDLE to go to READY\
    /// and prepare for anticollision or selection. 7 bit frame.\
    /// Beware: When two PICCs are in the field at the same time I often get STATUS_TIMEOUT - probably due do bad antenna design.
    ///
    /// @return STATUS_OK on success, STATUS_??? otherwise.
    ///
    pub fn request_a(&mut self, buffer_size: u8) -> Result<Vec<u8>> {
        self.request_a_or_wakeup_a(picc::Command::REQA, buffer_size)
    }

    /// Transmits a Wake-UP command, Type A. Invites PICCs in state IDLE and HALT to go to READY(*)\
    /// and prepare for anticollision or selection. 7 bit frame.\
    /// Beware: When two PICCs are in the field at the same time I often get STATUS_TIMEOUT - probably due do bad antenna design.
    ///
    /// @return STATUS_OK on success, STATUS_??? otherwise.
    ///
    pub fn wakeup_a(&mut self, buffer_size: u8) -> Result<Vec<u8>> {
        self.request_a_or_wakeup_a(picc::Command::WUPA, buffer_size)
    }

    /// Transmits REQA or WUPA commands.\
    /// Beware: When two PICCs are in the field at the same time I often get STATUS_TIMEOUT - probably due do bad antenna design.
    ///
    /// @return STATUS_OK on success, STATUS_??? otherwise.
    ///
    pub fn request_a_or_wakeup_a(
        &mut self,
        command: picc::Command, // The command to send - PICC_CMD_REQA or PICC_CMD_WUPA
        buffer_size: u8,
    ) -> Result<Vec<u8>> {
        if buffer_size < 2 {
            // The ATQA response is 2 bytes long.
            return Err(Error::NoRoom);
        }

        self.clear_register_bitmask(Register::CollReg, 0x80)?; // ValuesAfterColl=1 => Bits received after collision are cleared.
                                                               // For REQA and WUPA we need the short frame format - transmit only 7 bits of the last (and only) byte.
                                                               // TxLastBits = BitFramingReg[2..0]
        let valid_bits = 7;
        let picc_response =
            self.transceive_data(&[command as u8], buffer_size, valid_bits, 0, false)?;

        if picc_response.data.len() != 2 || picc_response.valid_bits != 0 {
            // ATQA must be exactly 16 bits.
            return Err(Error::Communication);
        }

        Ok(picc_response.data)
    }

    /// Transmits SELECT/ANTICOLLISION commands to select a single PICC.\
    /// Before calling this function the PICCs must be placed in the READY(*) state by calling PICC_RequestA() or PICC_WakeupA().\
    /// On success:
    /// 		- The chosen PICC is in state ACTIVE(*) and all other PICCs have returned to state IDLE/HALT. (Figure 7 of the ISO/IEC 14443-3 draft.)
    /// 		- The UID size and value of the chosen PICC is returned in *uid along with the SAK.
    ///
    /// A PICC UID consists of 4, 7 or 10 bytes.
    /// Only 4 bytes can be specified in a SELECT command, so for the longer UIDs two or three iterations are used:
    ///
    /// | UID size | Number of UID bytes | Cascade levels | Example of PICC       |
    /// | -------- |:-------------------:|:--------------:| --------------------- |
    /// | single   |        4            |        1       | MIFARE Classic        |
    /// | double   |        7            |        2       | MIFARE Ultralight     |
    /// | triple   |        0            |        3       | Not currently in use? |
    ///
    /// @return STATUS_OK on success, STATUS_??? otherwise.
    pub fn picc_select(
        &mut self,
        valid_bits: u8, // The number of bits supplied in uid_in. If not 0, uid_in should be Some.
        uid_in: Option<Uid>, // Optionally supply a known UID.
    ) -> Result<Uid> {
        let mut cascade_level = 1u8;
        let mut count: u8;
        let mut check_bit: u8;
        let mut index: usize;
        let mut uid_index: u8; // The first index in uid->uidByte[] that is used in the current Cascade Level.
        let mut current_level_known_bits: i8; // The number of known UID bits in the current Cascade Level.
        let mut buffer = vec![0u8; 9]; // The SELECT/ANTICOLLISION commands uses a 7 byte standard frame + 2 bytes CRC_A
        let mut buffer_used: u8; // The number of bytes used in the buffer, ie the number of bytes to transfer to the FIFO.
        let mut rx_align: u8; // Used in BitFramingReg. Defines the bit position for the first bit received.
        let mut tx_last_bits = 0u8; // Used in BitFramingReg. The number of valid bits in the last transmitted byte.
        let mut response_length;
        let mut response_uid = Uid {
            bytes: vec![0u8; 10],
            select_acknowledge: 0,
        };
        let mut picc_response = picc::Response {
            data: Vec::new(),
            valid_bits: 0,
            had_collision: false,
        };

        // Description of buffer structure:
        //		Byte 0: SEL 				Indicates the Cascade Level: PICC_CMD_SEL_CL1, PICC_CMD_SEL_CL2 or PICC_CMD_SEL_CL3
        //		Byte 1: NVB					Number of Valid Bits (in complete command, not just the UID): High nibble: complete bytes, Low nibble: Extra bits.
        //		Byte 2: UID-data or CT		See explanation below. CT means Cascade Tag.
        //		Byte 3: UID-data
        //		Byte 4: UID-data
        //		Byte 5: UID-data
        //		Byte 6: BCC					Block Check Character - XOR of bytes 2-5
        //		Byte 7: CRC_A
        //		Byte 8: CRC_A
        // The BCC and CRC_A are only transmitted if we know all the UID bits of the current Cascade Level.
        //
        // Description of bytes 2-5: (Section 6.5.4 of the ISO/IEC 14443-3 draft: UID contents and cascade levels)
        //		UID size	Cascade level	Byte2	Byte3	Byte4	Byte5
        //		========	=============	=====	=====	=====	=====
        //		 4 bytes		1			uid0	uid1	uid2	uid3
        //		 7 bytes		1			CT		uid0	uid1	uid2
        //						2			uid3	uid4	uid5	uid6
        //		10 bytes		1			CT		uid0	uid1	uid2
        //						2			CT		uid3	uid4	uid5
        //						3			uid6	uid7	uid8	uid9

        // Sanity checks: max 10 bytes
        if valid_bits > 80 {
            return Err(Error::Invalid);
        }
        let uid = if let Some(uid) = uid_in {
            uid
        } else {
            Uid {
                bytes: Vec::new(),
                select_acknowledge: 0,
            }
        };

        // Prepare MFRC522
        self.clear_register_bitmask(Register::CollReg, 0x80)?; // ValuesAfterColl=1 => Bits received after collision are cleared.

        // Repeat Cascade Level loop until we have a complete UID.
        let mut uid_complete = false;
        let mut select_done: bool;
        let mut use_cascade_tag: bool;
        while !uid_complete {
            // Set the Cascade Level in the SEL byte, find out if we need to use the Cascade Tag in byte 2.
            match cascade_level {
                1 => {
                    buffer[0] = picc::Command::SelCl1 as u8;
                    uid_index = 0;
                    use_cascade_tag = valid_bits != 0 && uid.bytes.len() > 4; // When we know that the UID has more than 4 bytes
                }

                2 => {
                    buffer[0] = picc::Command::SelCl2 as u8;
                    uid_index = 3;
                    use_cascade_tag = valid_bits != 0 && uid.bytes.len() > 7; // When we know that the UID has more than 7 bytes
                }
                3 => {
                    buffer[0] = picc::Command::SelCl3 as u8;
                    uid_index = 6;
                    use_cascade_tag = false; // Never used in CL3.
                }
                _ => {
                    return Err(Error::InternalError);
                }
            }

            // How many UID bits are known in this Cascade Level?
            current_level_known_bits = valid_bits as i8 - (8 * uid_index) as i8;
            if current_level_known_bits < 0 {
                current_level_known_bits = 0;
            }
            // Copy the known bits from uid->uidByte[] to buffer[]
            index = 2; // destination index in buffer[]
            if use_cascade_tag {
                buffer[index] = picc::Command::CT as u8;
                index += 1;
            }
            // The number of bytes needed to represent the known bits for this level.
            let mut bytes_to_copy = (current_level_known_bits / 8) as u8
                + if current_level_known_bits % 8 == 0 {
                    0
                } else {
                    1
                };
            if bytes_to_copy != 0 {
                let max_bytes = if use_cascade_tag { 3u8 } else { 4u8 }; // Max 4 bytes in each Cascade Level. Only 3 left if we use the Cascade Tag
                if bytes_to_copy > max_bytes {
                    bytes_to_copy = max_bytes;
                }
                for count in 0..bytes_to_copy {
                    buffer[index] = uid.bytes[(uid_index + count) as usize];
                    index += 1;
                }
            }
            // Now that the data has been copied we need to include the 8 bits in CT in current_level_known_bits
            if use_cascade_tag {
                current_level_known_bits += 8;
            }

            // Repeat anti collision loop until we can transmit all UID bits + BCC and receive a SAK - max 32 iterations.
            select_done = false;
            while !select_done {
                // Find out how many bits and bytes to send and receive.
                if current_level_known_bits >= 32 {
                    // All UID bits in this Cascade Level are known. This is a SELECT.
                    buffer[1] = 0x70; // NVB - Number of Valid Bits: Seven whole bytes
                                      // Calculate BCC - Block Check Character
                    buffer[6] = buffer[2] ^ buffer[3] ^ buffer[4] ^ buffer[5];
                    // Calculate CRC_A
                    let crc = self.calculate_crc(&buffer[0..7])?;
                    buffer[7] = crc[0];
                    buffer[8] = crc[1];

                    tx_last_bits = 0; // 0 => All 8 bits are valid.
                    buffer_used = 9;
                    // Store response in the last 3 bytes of buffer (BCC and CRC_A - not needed after tx)
                    index = 6;
                    response_length = 3;
                } else {
                    // This is an ANTICOLLISION.
                    tx_last_bits = current_level_known_bits as u8 % 8;
                    count = current_level_known_bits as u8 / 8; // Number of whole bytes in the UID part.
                    index = 2 + count as usize; // Number of whole bytes: SEL + NVB + UIDs
                    buffer[1] = ((index as u8) << 4) + tx_last_bits; // NVB - Number of Valid Bits
                    buffer_used = index as u8 + if tx_last_bits != 0 { 1 } else { 0 };
                    // Store response in the unused part of buffer
                    response_length = (buffer.len() - index) as u8;
                }

                // Set bit adjustments
                rx_align = tx_last_bits; // Having a separate variable is overkill. But it makes the next line easier to read.
                self.write_register(Register::BitFramingReg, (rx_align << 4) + tx_last_bits)?; // RxAlign = BitFramingReg[6..4]. TxLastBits = BitFramingReg[2..0]

                // Transmit the buffer and receive the response.
                match self.transceive_data(
                    &buffer[0..buffer_used as usize],
                    response_length,
                    tx_last_bits,
                    rx_align,
                    false,
                ) {
                    Ok(response) => {
                        // println!(
                        //     "Received select data: {:?} with clkb: {:?}",
                        //     response.data, current_level_known_bits
                        // );
                        picc_response = response;
                        // TODO: this is wrong, &buffer[6..] does not use index
                        for (i, &e) in picc_response.data.iter().enumerate() {
                            buffer[index + i] = e;
                        }

                        if picc_response.had_collision {
                            let value_of_coll_reg = self.read_register(Register::CollReg)?; // CollReg[7..0] bits are: ValuesAfterColl reserved CollPosNotValid CollPos[4:0]
                            if value_of_coll_reg & 0x20 != 0 {
                                // CollPosNotValid
                                return Err(Error::Collision); // Without a valid collision position we cannot continue
                            }
                            let mut collision_pos = value_of_coll_reg & 0x1F; // Values 0-31, 0 means bit 32.
                            if collision_pos == 0 {
                                collision_pos = 32;
                            }
                            if collision_pos <= current_level_known_bits as u8 {
                                // No progress - should not happen
                                return Err(Error::InternalError);
                            }
                            // Choose the PICC with the bit set.
                            current_level_known_bits = collision_pos as i8;
                            count = current_level_known_bits as u8 % 8; // The bit to modify
                            check_bit = (current_level_known_bits as u8 - 1) % 8;
                            index = (1
                                + (current_level_known_bits / 8)
                                + (if count != 0 { 1 } else { 0 }))
                                as usize; // First byte is index 0.
                            buffer[index] |= 1 << check_bit;
                        } else if current_level_known_bits >= 32 {
                            // This was a SELECT.
                            select_done = true; // No more anticollision
                                                // We continue below outside the while.
                        } else {
                            // This was an ANTICOLLISION.
                            // We now have all 32 bits of the UID in this Cascade Level
                            current_level_known_bits = 32;
                            // Run loop again to do the SELECT.
                        }
                    }
                    Err(e) => return Err(e),
                };
            } // End of while !select_done

            // We do not check the CBB - it was constructed by us above.

            // Copy the found UID bytes from buffer[] to uid->uidByte[]
            index = if buffer[2] == picc::Command::CT as u8 {
                3
            } else {
                2
            };
            bytes_to_copy = if buffer[2] == picc::Command::CT as u8 {
                3
            } else {
                4
            };
            for count in 0..bytes_to_copy {
                response_uid.bytes[(uid_index + count) as usize] = buffer[index];
                index += 1;
            }

            // Check response SAK (Select Acknowledge)
            if picc_response.data.len() != 3 || tx_last_bits != 0 {
                // SAK must be exactly 24 bits (1 byte + CRC_A).
                return Err(Error::Communication);
            }
            // Verify CRC_A - do our own calculation and store the control in buffer[2..3] - those bytes are not needed anymore.
            let crc_buf = self.calculate_crc(&picc_response.data[0..1])?;
            if crc_buf[0] != picc_response.data[1] || crc_buf[1] != picc_response.data[2] {
                return Err(Error::CrcWrong);
            }
            if picc_response.data[0] & 0x04 != 0 {
                // Cascade bit set - UID not complete yet
                cascade_level += 1;
            } else {
                uid_complete = true;
                response_uid.select_acknowledge = picc_response.data[0];
            }
        } // End of while !uid_complete

        // Set correct uid size
        response_uid.bytes.truncate(3 * cascade_level as usize + 1);

        Ok(response_uid)
    }

    pub fn halt_a(&mut self) -> Result<()> {
        let mut buffer = vec![picc::Command::HLTA as u8, 0];
        let crc = self.calculate_crc(&buffer)?;
        buffer.extend_from_slice(&crc);

        // Send the command.
        // The standard says:
        //		If the PICC responds with any modulation during a period of 1 ms after the end of the frame containing the
        //		HLTA command, this response shall be interpreted as 'not acknowledge'.
        // We interpret that this way: Only STATUS_TIMEOUT is a success.
        match self.transceive_data(&buffer, 0, 0, 0, false) {
            Err(Error::Timeout) => Ok(()),
            Ok(_) => Err(Error::Invalid),
            Err(e) => Err(e),
        }
    }

    /**
     * Executes the MFRC522 MFAuthent command.
     * This command manages MIFARE authentication to enable a secure communication to any MIFARE Mini, MIFARE 1K and MIFARE 4K card.
     * The authentication is described in the MFRC522 datasheet section 10.3.1.9 and http://www.nxp.com/documents/data_sheet/MF1S503x.pdf section 10.1.
     * For use with MIFARE Classic PICCs.
     * The PICC must be selected - ie in state ACTIVE(*) - before calling this function.
     * Remember to call PCD_StopCrypto1() after communicating with the authenticated PICC - otherwise no new communications can start.
     *
     * All keys are set to FFFFFFFFFFFFh at chip delivery.
     *
     * @return STATUS_OK on success, STATUS_??? otherwise. Probably STATUS_TIMEOUT if you supply the wrong key.
     */
    pub fn authenticate(
        &mut self,
        command: picc::Command, // PICC_CMD_MF_AUTH_KEY_A or PICC_CMD_MF_AUTH_KEY_B
        block_addr: u8,         // The block number. See numbering in the comments in the readme.
        key: MifareKey,         // Pointer to the Crypteo1 key to use (6 bytes)
        uid: &Uid,              // Pointer to Uid struct. The first 4 bytes of the UID is used.
    ) -> Result<picc::Response> {
        let wait_irq = 0x10u8; // IdleIRq

        // Build command buffer
        let mut send_data = vec![0u8; 12];
        send_data[0] = command as u8;
        send_data[1] = block_addr;
        send_data[2..2 + MIFARE_KEYSIZE].clone_from_slice(&key[..MIFARE_KEYSIZE]);

        // Use the last uid bytes as specified in http://cache.nxp.com/documents/application_note/AN10927.pdf
        // section 3.2.5 "MIFARE Classic Authentication".
        // The only missed case is the MF1Sxxxx shortcut activation,
        // but it requires cascade tag (CT) byte, that is not part of uid.
        for i in 0..4 {
            // The last 4 bytes of the UID
            send_data[8 + i] = uid.bytes[uid.bytes.len() - 4 + i];
        }

        // Start the authentication.
        self.communicate_with_picc(Command::MFAuthent, wait_irq, &send_data, 0, 0, 0, false)
    }

    pub fn stop_crypto1(&mut self) -> Result<()> {
        // Clear MFCrypto1On bit
        // Status2Reg[7..0] bits are: TempSensClear I2CForceHS reserved reserved MFCrypto1On ModemState[2:0]
        self.clear_register_bitmask(Register::Status2Reg, 0x08)
    }

    /**
     * Reads 16 bytes (+ 2 bytes CRC_A) from the active PICC.
     *
     * For MIFARE Classic the sector containing the block must be authenticated before calling this function.
     *
     * For MIFARE Ultralight only addresses 00h to 0Fh are decoded.
     * The MF0ICU1 returns a NAK for higher addresses.
     * The MF0ICU1 responds to the READ command by sending 16 bytes starting from the page address defined by the command argument.
     * For example; if blockAddr is 03h then pages 03h, 04h, 05h, 06h are returned.
     * A roll-back is implemented: If blockAddr is 0Eh, then the contents of pages 0Eh, 0Fh, 00h and 01h are returned.
     *
     * The buffer must be at least 18 bytes because a CRC_A is also returned.
     * Checks the CRC_A before returning STATUS_OK.
     *
     * @return STATUS_OK on success, STATUS_??? otherwise.
     */
    pub fn mifare_read(&mut self, block_addr: u8, back_len: u8) -> Result<picc::Response> {
        if back_len < 18 {
            return Err(Error::NoRoom);
        }

        let mut send_data = vec![picc::Command::MfRead as u8, block_addr];
        let crc = self.calculate_crc(&send_data)?;
        send_data.extend_from_slice(&crc);

        // Transmit the buffer and receive the response, validate CRC_A.
        self.transceive_data(&send_data, back_len, 0, 0, true)
    }

    /**
     * Writes 16 bytes to the active PICC.
     *
     * For MIFARE Classic the sector containing the block must be authenticated before calling this function.
     *
     * For MIFARE Ultralight the operation is called "COMPATIBILITY WRITE".
     * Even though 16 bytes are transferred to the Ultralight PICC, only the least significant 4 bytes (bytes 0 to 3)
     * are written to the specified address. It is recommended to set the remaining bytes 04h to 0Fh to all logic 0.
     * *
     * @return STATUS_OK on success, STATUS_??? otherwise.
     */
    pub fn mifare_write(&mut self, block_addr: u8, buffer: &[u8]) -> Result<()> {
        if buffer.len() < 16 {
            return Err(Error::Invalid);
        }

        // Mifare Classic protocol requires two communications to perform a write.
        // Step 1: Tell the PICC we want to write to block blockAddr.
        let cmd_buffer = vec![picc::Command::MfWrite as u8, block_addr];
        self.mifare_transceive(&cmd_buffer, false)?;

        self.mifare_transceive(buffer, false)
    }

    /**
     * Wrapper for MIFARE protocol communication.
     * Adds CRC_A, executes the Transceive command and checks that the response is MF_ACK or a timeout.
     *
     * @return STATUS_OK on success, STATUS_??? otherwise.
     */
    pub fn mifare_transceive(&mut self, send_data: &[u8], accept_timeout: bool) -> Result<()> {

        if send_data.len() > 16 {
            return Err(Error::Invalid);
        }

        let mut cmd_buffer = send_data.to_vec();
        // Copy sendData[] to cmdBuffer[] and add CRC_A
        let crc = self.calculate_crc(&send_data)?;
        cmd_buffer.extend_from_slice(&crc);

        // Transceive the data, store the reply in cmdBuffer[]
        let wait_irq = 0x30;
        let valid_bits = 0;
        let response = match self.communicate_with_picc(
            Command::Transceive,
            wait_irq,
            &cmd_buffer,
            cmd_buffer.len() as u8,
            valid_bits,
            0,
            false,
        ) {
            Ok(r) => r,
            Err(Error::Timeout) if accept_timeout => return Ok(()),
            Err(e) => return Err(e),
        };

        // The PICC must reply with a 4 bit ACK
        if response.data.len() != 1 || response.valid_bits != 4 {
            return Err(Error::Invalid);
        }

        if response.data[0] != MIFARE_ACK {
            return Err(Error::MifareNack);
        }

        Ok(())
    }

    pub fn new_card_present(&mut self) -> Result<()> {
        self.write_register(Register::TxModeReg, 0x00)?;
        self.write_register(Register::RxModeReg, 0x00)?;
        self.write_register(Register::ModWidthReg, 0x26)?; // Reset ModWidthReg

        match self.request_a(2) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn read_card_serial(&mut self) -> Result<Uid> {
        let result = self.picc_select(0, None)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_readvalue() {
        assert_eq!(
            MFRC522::register_to_readvalue(Register::CommandReg),
            0b1000_0010
        );
        assert_eq!(
            MFRC522::register_to_readvalue(Register::DivlEnReg),
            0b1000_0110
        );
        assert_eq!(
            MFRC522::register_to_readvalue(Register::TestADCReg),
            0b1111_0110
        );
    }
}
