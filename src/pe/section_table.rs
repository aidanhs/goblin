use scroll::{self, Pread};
use error;

use pe::characteristic::SectionCharacteristics;

#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub struct SectionTable {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: SectionCharacteristics,
}

pub const SIZEOF_SECTION_TABLE: usize = 8 * 5;

impl SectionTable {
    pub fn parse(bytes: &[u8], offset: &mut usize) -> error::Result<Self> {
        let mut table = SectionTable::default();
        let mut name = [0u8; 8];
        for i in 0..8 {
            name[i] = bytes.gread_with(offset, scroll::LE)?;
        }
        table.name = name;
        table.virtual_size = bytes.gread_with(offset, scroll::LE)?;
        table.virtual_address = bytes.gread_with(offset, scroll::LE)?;
        table.size_of_raw_data = bytes.gread_with(offset, scroll::LE)?;
        table.pointer_to_raw_data = bytes.gread_with(offset, scroll::LE)?;
        table.pointer_to_relocations = bytes.gread_with(offset, scroll::LE)?;
        table.pointer_to_linenumbers = bytes.gread_with(offset, scroll::LE)?;
        table.number_of_relocations = bytes.gread_with(offset, scroll::LE)?;
        table.number_of_linenumbers = bytes.gread_with(offset, scroll::LE)?;
        table.characteristics = SectionCharacteristics::from_bits(bytes.gread_with(offset, scroll::LE)?)
            .expect("failed to interpret section characteristics, but bitflags are exhaustive!");
        Ok(table)
    }
    pub fn name(&self) -> error::Result<&str> {
        Ok(self.name.pread(0)?)
    }
}
