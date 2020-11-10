//! mfrc522读写器

use crate::com::Com;
use crate::picc;
use crate::Error;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

type Result<T> = core::result::Result<T, Error>;

/// mfrc522寄存器
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub enum Register {
    /// PAGE 0
    RFU00 = 0x00,
    /// 启动和停止命令的执行
    Command = 0x01,
    /// 中断请求传递的使能和禁能控制位
    ComIEn = 0x02,
    /// 中断请求传递的使能和禁能控制位
    DivIEn = 0x03,
    /// 包含中断请求标志
    ComIrq = 0x04,
    /// 包含中断请求标志
    DivIrq = 0x05,
    /// 错误标志,指示执行的上个命令的错误状态
    Error = 0x06,
    /// 包含通信的状态标志
    Status1 = 0x07,
    /// 包含接收器和发射器的状态标志
    Status2 = 0x08,
    /// 64字节FIFO缓冲区的输入和输出
    FIFOData = 0x09,
    /// 指示FIFO中存储的字节数
    FIFOLevel = 0x0A,
    /// 定义FIFO下溢和上溢报警的FIFO深度
    WaterLevel = 0x0B,
    /// 不同的控制寄存器
    Control = 0x0C,
    /// 面向位的帧的调节
    BitFraming = 0x0D,
    /// RF接口上检测到的第一个位冲突的位的位置
    Coll = 0x0E,
    RFU0F = 0x0F,
    /// PAGE 1
    RFU10 = 0x10,
    /// 定义发送和接收的常用模式
    Mode = 0x11,
    /// 定义发送过程的数据传输速率
    TxMode = 0x12,
    /// 定义接收过程中的数据传输速率
    RxMode = 0x13,
    /// 控制天线驱动器管教TX1和TX2的逻辑特性
    TxControl = 0x14,
    /// 控制天线驱动器的设置
    TxAuto = 0x15,
    /// 选择天线驱动器的设置
    TxSel = 0x16,
    /// 选择内部的接收器设置
    RxSel = 0x17,
    /// 选择位译码器的阈值
    RxThreshold = 0x18,
    /// 定义解调器的设置
    Demod = 0x19,
    RFU1A = 0x1A,
    RFU1B = 0x1B,
    /// 控制ISO 14443/MIFARE模式中106kbit/s的通信
    Mifare = 0x1C,
    RFU1D = 0x1D,
    RFU1E = 0x1E,
    /// 选择串行UART接口的速率
    SerialSpeed = 0x1F,
    /// PAGE 2
    RFU20 = 0x20,
    //显示CRC计算的实际值
    CRCResultH = 0x21,
    //显示CRC计算的实际值
    CRCResultL = 0x22,
    RFU23 = 0x23,
    ModWidth = 0x24,
    RFU25 = 0x25,
    /// 配置接收器增益
    RFCfg = 0x26,
    /// 选择天线驱动器管脚TX1和TX2的调制电导
    GsN = 0x27,
    /// 选择天线驱动器管脚TX1和TX2的调制电导
    CWGsCfg = 0x28,
    /// 选择天线驱动器管脚TX1和TX2的调制电导
    ModGsCfg = 0x29,
    /// 定义内部定时器的设置
    TMode = 0x2A,
    /// 定义内部定时器的设置
    TPrescaler = 0x2B,
    /// 描述16位长的定时器重装值
    TReloadH = 0x2C,
    /// 描述16位长的定时器重装值
    TReloadL = 0x2D,
    /// 显示16位长的实际定时器值
    TCounterValH = 0x2E,
    /// 显示16位长的实际定时器值
    TCounterValL = 0x2F,
    /// PAGE 3
    RFU30 = 0x30,
    /// 常用测试信号的配置
    TestSel1 = 0x31,
    /// 常用测试信号的配置和PRBS控制
    TestSel2 = 0x32,
    /// D1-D7输出驱动器的使能管脚(注:仅用于串行接口)
    TestPinEn = 0x33,
    /// 定义D1-D7用作I/O总线时的值
    TestPinValue = 0x34,
    /// 显示内部测试总线的状态
    TestBus = 0x35,
    /// 控制数字自测试
    AutoTest = 0x36,
    /// 显示版本
    Version = 0x37,
    //控制管脚AUX1和AUX2
    AnalogTest = 0x38,
    //定义TestDAC1的测试值
    TestDAC1 = 0x39,
    //定义TestDAC2的测试值
    TestDAC2 = 0x3A,
    /// 显示ADCI 和Q通道的实际值
    TestADC = 0x3B,
    RFU3C = 0x3C,
    RFU3D = 0x3D,
    RFU3E = 0x3E,
    RFU3F = 0x3F,
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
pub enum Command {
    ///取消当前命令
    Idle = 0x00,
    Mem = 0x01,
    GenerateRandomId = 0x02,
    /// CRC计算
    CalcCRC = 0x03,
    ///发送数据
    Transmit = 0x04,
    NoCmdChange = 0x07,
    ///接收数据
    Receive = 0x08,
    ///发送并接收数据
    Transceive = 0x0C,
    ///验证密钥
    Authent = 0x0E,
    ///复位
    Reset = 0x0F,
}

pub struct Uid {
    /// The UID can have 4, 7 or 10 bytes.
    pub bytes: Vec<u8>,
    /// The SAK (Select acknowledge) byte returned from the PICC after successful selection.
    select_acknowledge: u8,
}

const MIFARE_ACK: u8 = 0xA;
const MIFARE_KEYSIZE: usize = 6;
pub type MifareKey = [u8; MIFARE_KEYSIZE];

pub struct MFRC522 {
    com: Box<dyn Com>,
}
impl MFRC522 {
    pub fn new(com: Box<dyn Com>) -> Self {
        Self { com: com }
    }
    fn read_register(&mut self, reg: Register) -> Result<u8> {
        let mut rx_buf = [0; 1];
        if let Err(_) = self.com.write(reg as u8, &[]) {
            return Err(Error::ComErr);
        }
        if let Err(_) = self.com.read(reg as u8, &mut rx_buf) {
            return Err(Error::ComErr);
        }
        return Ok(rx_buf[0]);
    }
    fn read_multiple(&mut self, reg: Register, count: usize) -> Result<Vec<u8>> {
        if count == 0 {
            return Ok(Vec::new());
        }
        let mut rx_buf = vec![0; count];
        if let Err(_) = self.com.write(reg as u8, &[]) {
            return Err(Error::ComErr);
        }
        if let Err(_) = self.com.read(reg as u8, &mut rx_buf) {
            return Err(Error::ComErr);
        }
        return Ok(rx_buf);
    }

    fn write_register(&mut self, reg: Register, value: u8) -> Result<()> {
        if let Err(_) = self.com.write(reg as u8, &[value]) {
            return Err(Error::ComErr);
        }
        return Ok(());
    }
    fn write_multiple(&mut self, reg: Register, value: &[u8]) -> Result<()> {
        if let Err(_) = self.com.write(reg as u8, value) {
            return Err(Error::ComErr);
        }
        return Ok(());
    }
    fn set_bitmask(&mut self, reg: Register, mask: u8) -> Result<()> {
        let tmp = self.read_register(reg)?;
        self.write_register(reg, tmp | mask)?;
        Ok(())
    }
    fn clear_bitmask(&mut self, reg: Register, mask: u8) -> Result<()> {
        let tmp = self.read_register(reg)?;
        self.write_register(reg, tmp & !mask)?;
        Ok(())
    }

    pub fn close_antenna(&mut self) -> Result<()> {
        self.clear_bitmask(Register::TxControl, 0x03)?;
        Ok(())
    }
    pub fn open_antenna(&mut self) -> Result<()> {
        let control_reg = self.read_register(Register::TxControl)?;
        if (control_reg & 0x03) != 0x03 {
            self.write_register(Register::TxControl, control_reg | 0x03)?;
        }
        Ok(())
    }

    pub fn init(&mut self) -> Result<()> {
        self.reset()?;

        self.write_register(Register::ModWidth, 0x26)?;
        // f_timer = 13.56 MHz / (2*TPreScaler+1) = 2kHz
        // TPreScaler = TModeReg[3..0]:TPrescalerReg
        // Timer: TreloadVal/f_timer = 25ms
        self.write_register(Register::TMode, 0x8D)?;
        self.write_register(Register::TPrescaler, 0x3E)?;
        self.write_register(Register::TReloadH, 0x00)?;
        self.write_register(Register::TReloadL, 0x32)?;
        self.write_register(Register::TxAuto, 0x40)?; //强制100%ASK调制
        self.write_register(Register::Mode, 0x3D)?; // CRC初始值0x6363
        self.write_register(Register::Command, Command::Idle as u8)?;
        self.write_register(Register::RFCfg, 0x7F)?; //接收器增益.0x0F:18dB; 0x4F:33dB; 0x7F:48dB

        self.close_antenna()?;
        self.open_antenna()?;
        Ok(())
    }

    pub fn reset(&mut self) -> Result<()> {
        self.write_register(Register::Command, Command::Reset as u8)?;
        let mut count = 0;
        loop {
            let cmd_val = self.read_register(Register::Command)?;
            if cmd_val & (1 << 4) == 0 || count >= 3 {
                break;
            }
            count += 1;
        }
        Ok(())
    }

    pub fn calculate_crc(&mut self, data: &[u8]) -> Result<[u8; 2]> {
        self.write_register(Register::Command, Command::Idle as u8)?;
        self.write_register(Register::DivIrq, 0x04)?;
        self.write_register(Register::FIFOLevel, 0x80)?;
        self.write_multiple(Register::FIFOData, data)?;
        self.write_register(Register::Command, Command::CalcCRC as u8)?;

        // Wait for the CRC calculation to complete. Each iteration of the while-loop takes 17.73us.
        for _ in 0..5000 {
            let n = self.read_register(Register::DivIrq)?;
            if n & 0x04 != 0 {
                self.write_register(Register::Command, Command::Idle as u8)?;
                let res_low = self.read_register(Register::CRCResultL)?;
                let res_high = self.read_register(Register::CRCResultH)?;
                return Ok([res_low, res_high]);
            }
        }
        Err(Error::Timeout)
    }

    /// 与卡片通信
    pub fn communicate_with_picc(
        &mut self,
        command: Command,
        data: &[u8],
    ) -> Result<picc::Response> {
        let irq_en: u8 = match command {
            Command::Authent => 0x12,
            Command::Transceive => 0x77,
            _ => 0x00,
        };
        let wait_cnt: u8 = match command {
            Command::Authent => 0x10,
            Command::Transceive => 0x30,
            _ => 0x00,
        };
        self.write_register(Register::Command, Command::Idle as u8)?;
        self.write_register(Register::ComIEn, irq_en | 0x80)?;
        self.clear_bitmask(Register::ComIrq, 0x80)?;
        self.set_bitmask(Register::FIFOLevel, 0x80)?;
        self.write_multiple(Register::FIFOData, data)?;
        self.write_register(Register::Command, command as u8)?;

        if let Command::Transceive = command {
            self.set_bitmask(Register::BitFraming, 0x80)?;
        }

        let mut i: u16 = 40;
        while i > 0 {
            let n = self.read_register(Register::ComIrq)?;
            if n & wait_cnt != 0 {
                // One of the interrupts that signal success has been set.
                break;
            }
            if n & 0x01 != 0 {
                // Timer interrupt - nothing received in 25ms
                return Err(Error::Timeout);
            }
            i -= 1;
        }
        if i == 0 {
            return Err(Error::Timeout);
        }

        // Stop now if any errors except collisions were detected.
        let error_reg_value = self.read_register(Register::Error)?;
        if error_reg_value & 0x1B != 0 {
            // BufferOvfl ParityErr ProtocolErr
            return Err(Error::Communication);
        }

        let mut recv_valid_bits = 0u8;
        let mut recv_data = Vec::new();
        // If the caller wants data back, get it from the MFRC522.
        if let Command::Transceive = command {
            let n = self.read_register(Register::FIFOLevel)?;
            recv_data = self.read_multiple(Register::FIFOData, n as usize)?;
            if recv_data.len() != n as usize {
                return Err(Error::InternalError);
            }
            recv_valid_bits = self.read_register(Register::Control)? & 0x07;
        }

        Ok(picc::Response {
            data: recv_data,
            valid_bits: recv_valid_bits,
            had_collision: false,
        })
    }

    /// 寻卡
    pub fn request_picc(&mut self, command: picc::Command) -> Result<Vec<u8>> {
        self.clear_bitmask(Register::Status2, 0x08)?;
        self.write_register(Register::BitFraming, 0x07)?;
        self.set_bitmask(Register::TxControl, 0x03)?;
        let picc_response = self.communicate_with_picc(Command::Transceive, &[command as u8])?;

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
        self.clear_bitmask(Register::Coll, 0x80)?; // ValuesAfterColl=1 => Bits received after collision are cleared.

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
                self.write_register(Register::BitFraming, (rx_align << 4) + tx_last_bits)?; // RxAlign = BitFramingReg[6..4]. TxLastBits = BitFramingReg[2..0]

                // Transmit the buffer and receive the response.
                match self
                    .communicate_with_picc(Command::Transceive, &buffer[0..buffer_used as usize])
                {
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
                            let value_of_coll_reg = self.read_register(Register::Coll)?; // CollReg[7..0] bits are: ValuesAfterColl reserved CollPosNotValid CollPos[4:0]
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
        match self.communicate_with_picc(Command::Transceive, &buffer) {
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
        self.communicate_with_picc(Command::Authent, &send_data)
    }

    pub fn stop_crypto1(&mut self) -> Result<()> {
        // Clear MFCrypto1On bit
        // Status2Reg[7..0] bits are: TempSensClear I2CForceHS reserved reserved MFCrypto1On ModemState[2:0]
        self.clear_bitmask(Register::Status2, 0x08)
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

        self.communicate_with_picc(Command::Transceive, &send_data)
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
        let response = match self.communicate_with_picc(Command::Transceive, &cmd_buffer) {
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

    pub fn read_card_serial(&mut self) -> Result<Uid> {
        let result = self.picc_select(0, None)?;
        Ok(result)
    }
}
