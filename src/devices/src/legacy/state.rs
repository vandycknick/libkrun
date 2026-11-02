use utils::state::{Error, Reader, Writer};

pub const MAX_SERIAL_INPUT: usize = 64 * 1024;
pub const MAX_LEGACY_DEVICES: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UartState {
    pub interrupt_enable: u8,
    pub interrupt_identification: u8,
    pub line_control: u8,
    pub line_status: u8,
    pub modem_control: u8,
    pub modem_status: u8,
    pub scratch: u8,
    pub baud_divisor: u16,
    pub input: Vec<u8>,
    pub has_input: bool,
    pub has_output: bool,
    pub input_closed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CmosState {
    pub index: u8,
    pub data: [u8; 128],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct I8042State {
    pub status: u8,
    pub control: u8,
    pub output: u8,
    pub command: u8,
    pub buffer: [u8; 16],
    pub head: u8,
    pub length: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pl011State {
    pub flags: u32,
    pub lcr: u32,
    pub rsr: u32,
    pub cr: u32,
    pub dmacr: u32,
    pub debug: u32,
    pub interrupt_enabled: u32,
    pub interrupt_level: u32,
    pub ilpr: u32,
    pub ibrd: u32,
    pub fbrd: u32,
    pub ifl: u32,
    pub read_count: u32,
    pub read_trigger: u32,
    pub input: Vec<u8>,
    pub has_input: bool,
    pub has_output: bool,
    pub input_closed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtcState {
    pub guest_nanoseconds: u64,
    pub match_value: u32,
    pub load: u32,
    pub interrupt_mask: u32,
    pub interrupt_status: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GpioState {
    pub data: u32,
    pub direction: u32,
    pub interrupt_sense: u32,
    pub interrupt_both_edges: u32,
    pub interrupt_event: u32,
    pub interrupt_mask: u32,
    pub interrupt_status: u32,
    pub alternate_function: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LegacyPayload {
    Uart(UartState),
    Cmos(CmosState),
    I8042(I8042State),
    Pl011(Pl011State),
    Rtc(RtcState),
    Gpio(GpioState),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyState {
    pub address: u64,
    pub irq: Option<u32>,
    pub payload: LegacyPayload,
}

impl LegacyPayload {
    pub fn tag(&self) -> u8 {
        match self {
            Self::Uart(_) => 1,
            Self::Cmos(_) => 2,
            Self::I8042(_) => 3,
            Self::Pl011(_) => 4,
            Self::Rtc(_) => 5,
            Self::Gpio(_) => 6,
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Uart(state)
                if state.input.len() > MAX_SERIAL_INPUT || state.interrupt_enable & !15 != 0 =>
            {
                Err(Error::Invalid("UART state"))
            }
            Self::Cmos(state) if state.index > 127 => Err(Error::Invalid("CMOS index")),
            Self::I8042(state) if state.head >= 16 || state.length > 16 => {
                Err(Error::Invalid("i8042 buffer"))
            }
            Self::Pl011(state)
                if state.input.len() > MAX_SERIAL_INPUT || state.read_trigger != 1 =>
            {
                Err(Error::Invalid("PL011 FIFO"))
            }
            Self::Rtc(state)
                if state.guest_nanoseconds > i64::MAX as u64
                    || state.interrupt_mask > 1
                    || state.interrupt_status > 1 =>
            {
                Err(Error::Invalid("RTC state"))
            }
            Self::Gpio(state)
                if [
                    state.data,
                    state.direction,
                    state.interrupt_sense,
                    state.interrupt_both_edges,
                    state.interrupt_event,
                    state.interrupt_mask,
                    state.interrupt_status,
                    state.alternate_function,
                ]
                .iter()
                .any(|value| *value > 255) =>
            {
                Err(Error::Invalid("GPIO register"))
            }
            _ => Ok(()),
        }
    }
}

impl LegacyState {
    pub fn encode(&self, writer: &mut Writer) -> Result<(), Error> {
        self.payload.validate()?;
        writer.u8(self.payload.tag())?;
        writer.u16(1)?;
        writer.u64(self.address)?;
        writer.bool(self.irq.is_some())?;
        if let Some(irq) = self.irq {
            writer.u32(irq)?;
        }
        match &self.payload {
            LegacyPayload::Uart(s) => {
                for value in [
                    s.interrupt_enable,
                    s.interrupt_identification,
                    s.line_control,
                    s.line_status,
                    s.modem_control,
                    s.modem_status,
                    s.scratch,
                ] {
                    writer.u8(value)?;
                }
                writer.u16(s.baud_divisor)?;
                writer.bytes(&s.input, MAX_SERIAL_INPUT)?;
                writer.bool(s.has_input)?;
                writer.bool(s.has_output)?;
                writer.bool(s.input_closed)?;
            }
            LegacyPayload::Cmos(s) => {
                writer.u8(s.index)?;
                writer.fixed(&s.data)?;
            }
            LegacyPayload::I8042(s) => {
                for value in [s.status, s.control, s.output, s.command, s.head, s.length] {
                    writer.u8(value)?;
                }
                writer.fixed(&s.buffer)?;
            }
            LegacyPayload::Pl011(s) => {
                for value in [
                    s.flags,
                    s.lcr,
                    s.rsr,
                    s.cr,
                    s.dmacr,
                    s.debug,
                    s.interrupt_enabled,
                    s.interrupt_level,
                    s.ilpr,
                    s.ibrd,
                    s.fbrd,
                    s.ifl,
                    s.read_count,
                    s.read_trigger,
                ] {
                    writer.u32(value)?;
                }
                writer.bytes(&s.input, MAX_SERIAL_INPUT)?;
                writer.bool(s.has_input)?;
                writer.bool(s.has_output)?;
                writer.bool(s.input_closed)?;
            }
            LegacyPayload::Rtc(s) => {
                writer.u64(s.guest_nanoseconds)?;
                for value in [s.match_value, s.load, s.interrupt_mask, s.interrupt_status] {
                    writer.u32(value)?;
                }
            }
            LegacyPayload::Gpio(s) => {
                for value in [
                    s.data,
                    s.direction,
                    s.interrupt_sense,
                    s.interrupt_both_edges,
                    s.interrupt_event,
                    s.interrupt_mask,
                    s.interrupt_status,
                    s.alternate_function,
                ] {
                    writer.u32(value)?;
                }
            }
        }
        Ok(())
    }

    pub fn decode(reader: &mut Reader<'_>) -> Result<Self, Error> {
        let tag = reader.u8()?;
        if reader.u16()? != 1 {
            return Err(Error::Invalid("legacy codec version"));
        }
        let address = reader.u64()?;
        let irq = if reader.bool()? {
            Some(reader.u32()?)
        } else {
            None
        };
        let payload = match tag {
            1 => LegacyPayload::Uart(UartState {
                interrupt_enable: reader.u8()?,
                interrupt_identification: reader.u8()?,
                line_control: reader.u8()?,
                line_status: reader.u8()?,
                modem_control: reader.u8()?,
                modem_status: reader.u8()?,
                scratch: reader.u8()?,
                baud_divisor: reader.u16()?,
                input: reader.bytes(MAX_SERIAL_INPUT)?.to_vec(),
                has_input: reader.bool()?,
                has_output: reader.bool()?,
                input_closed: reader.bool()?,
            }),
            2 => LegacyPayload::Cmos(CmosState {
                index: reader.u8()?,
                data: reader.fixed()?,
            }),
            3 => LegacyPayload::I8042(I8042State {
                status: reader.u8()?,
                control: reader.u8()?,
                output: reader.u8()?,
                command: reader.u8()?,
                head: reader.u8()?,
                length: reader.u8()?,
                buffer: reader.fixed()?,
            }),
            4 => LegacyPayload::Pl011(Pl011State {
                flags: reader.u32()?,
                lcr: reader.u32()?,
                rsr: reader.u32()?,
                cr: reader.u32()?,
                dmacr: reader.u32()?,
                debug: reader.u32()?,
                interrupt_enabled: reader.u32()?,
                interrupt_level: reader.u32()?,
                ilpr: reader.u32()?,
                ibrd: reader.u32()?,
                fbrd: reader.u32()?,
                ifl: reader.u32()?,
                read_count: reader.u32()?,
                read_trigger: reader.u32()?,
                input: reader.bytes(MAX_SERIAL_INPUT)?.to_vec(),
                has_input: reader.bool()?,
                has_output: reader.bool()?,
                input_closed: reader.bool()?,
            }),
            5 => LegacyPayload::Rtc(RtcState {
                guest_nanoseconds: reader.u64()?,
                match_value: reader.u32()?,
                load: reader.u32()?,
                interrupt_mask: reader.u32()?,
                interrupt_status: reader.u32()?,
            }),
            6 => LegacyPayload::Gpio(GpioState {
                data: reader.u32()?,
                direction: reader.u32()?,
                interrupt_sense: reader.u32()?,
                interrupt_both_edges: reader.u32()?,
                interrupt_event: reader.u32()?,
                interrupt_mask: reader.u32()?,
                interrupt_status: reader.u32()?,
                alternate_function: reader.u32()?,
            }),
            _ => return Err(Error::Invalid("unknown legacy kind")),
        };
        payload.validate()?;
        Ok(Self {
            address,
            irq,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::legacy::state::*;

    #[test]
    fn legacy_state_codec_roundtrip_and_bounds() {
        let states = [
            LegacyPayload::Uart(UartState {
                interrupt_enable: 1,
                interrupt_identification: 4,
                line_control: 3,
                line_status: 0x61,
                modem_control: 8,
                modem_status: 0xb0,
                scratch: 19,
                baud_divisor: 12,
                input: vec![1, 2, 3],
                has_input: true,
                has_output: false,
                input_closed: true,
            }),
            LegacyPayload::Pl011(Pl011State {
                flags: 0x90,
                lcr: 3,
                rsr: 0,
                cr: 0x300,
                dmacr: 0,
                debug: 0,
                interrupt_enabled: 1,
                interrupt_level: 1,
                ilpr: 1,
                ibrd: 12,
                fbrd: 3,
                ifl: 0x12,
                read_count: 2,
                read_trigger: 1,
                input: vec![5, 7],
                has_input: false,
                has_output: true,
                input_closed: false,
            }),
            LegacyPayload::Cmos(CmosState {
                index: 67,
                data: [91; 128],
            }),
            LegacyPayload::I8042(I8042State {
                status: 17,
                control: 5,
                output: 0,
                command: 0x60,
                buffer: [5; 16],
                head: 15,
                length: 16,
            }),
            LegacyPayload::Rtc(RtcState {
                guest_nanoseconds: 999,
                match_value: 12,
                load: 4,
                interrupt_mask: 1,
                interrupt_status: 1,
            }),
            LegacyPayload::Gpio(GpioState {
                data: 8,
                direction: 1,
                interrupt_sense: 2,
                interrupt_both_edges: 3,
                interrupt_event: 4,
                interrupt_mask: 5,
                interrupt_status: 6,
                alternate_function: 7,
            }),
        ];
        for payload in states {
            let state = LegacyState {
                address: 0x60,
                irq: Some(1),
                payload,
            };
            let mut writer = Writer::new(4096);
            state.encode(&mut writer).unwrap();
            let bytes = writer.finish();
            for length in 0..bytes.len() {
                assert!(LegacyState::decode(&mut Reader::new(&bytes[..length])).is_err());
            }
            let mut reader = Reader::new(&bytes);
            assert_eq!(LegacyState::decode(&mut reader).unwrap(), state);
            reader.finish().unwrap();
        }
        assert!(
            LegacyPayload::I8042(I8042State {
                status: 0,
                control: 0,
                output: 0,
                command: 0,
                buffer: [0; 16],
                head: 16,
                length: 0
            })
            .validate()
            .is_err()
        );
    }
}
