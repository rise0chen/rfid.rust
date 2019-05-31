use super::MFRC522;

pub fn dump_registers(mfrc: &mut MFRC522) -> Result<()> {
    for &reg in [
        Register::CommandReg,
        Register::ComlEnReg,
        Register::DivlEnReg,
        Register::ComIrqReg,
        Register::DivIrqReg,
        Register::ErrorReg,
        Register::Status1Reg,
        Register::Status2Reg,
        Register::FIFODataReg,
        Register::FIFOLevelReg,
        Register::WaterLevelReg,
        Register::ControlReg,
        Register::BitFramingReg,
        Register::CollReg,
        Register::ModeReg,
        Register::TxModeReg,
        Register::RxModeReg,
        Register::TxControlReg,
        Register::TxASKReg,
        Register::TxSelReg,
        Register::RxSelReg,
        Register::RxThresholdReg,
        Register::DemodReg,
        Register::MfTxReg,
        Register::MfRxReg,
        Register::SerialSpeedReg,
        Register::CRCResultRegLow,
        Register::CRCResultRegHigh,
        Register::ModWidthReg,
        Register::RFCfgReg,
        Register::GsNReg,
        Register::CWGsPReg,
        Register::ModGsPReg,
        Register::TModeReg,
        Register::TPrescalerReg,
        Register::TReloadRegLow,
        Register::TReloadRegHigh,
        Register::TCounterValRegLow,
        Register::TCounterValRegHigh,
    ]
    .iter()
    {
        println!("{:?}: {:02x?}", reg, mfrc.read_register(reg)?);
    }
    Ok(())
}