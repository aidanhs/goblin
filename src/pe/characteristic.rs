/*
type characteristic =
    | IMAGE_FILE_RELOCS_STRIPPED
    | IMAGE_FILE_EXECUTABLE_IMAGE
    | IMAGE_FILE_LINE_NUMS_STRIPPED
    | IMAGE_FILE_LOCAL_SYMS_STRIPPED
    | IMAGE_FILE_AGGRESSIVE_WS_TRIM
    | IMAGE_FILE_LARGE_ADDRESS_AWARE
    | RESERVED
    | IMAGE_FILE_BYTES_REVERSED_LO
    | IMAGE_FILE_32BIT_MACHINE
    | IMAGE_FILE_DEBUG_STRIPPED
    | IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP
    | IMAGE_FILE_NET_RUN_FROM_SWAP
    | IMAGE_FILE_SYSTEM
    | IMAGE_FILE_DLL
    | IMAGE_FILE_UP_SYSTEM_ONLY
    | IMAGE_FILE_BYTES_REVERSED_HI
    | UNKNOWN of int

let get_characteristic =
  function
  | 0x0001 -> IMAGE_FILE_RELOCS_STRIPPED
  | 0x0002 -> IMAGE_FILE_EXECUTABLE_IMAGE
  | 0x0004 -> IMAGE_FILE_LINE_NUMS_STRIPPED
  | 0x0008 -> IMAGE_FILE_LOCAL_SYMS_STRIPPED
  | 0x0010 -> IMAGE_FILE_AGGRESSIVE_WS_TRIM
  | 0x0020 -> IMAGE_FILE_LARGE_ADDRESS_AWARE
  | 0x0040 -> RESERVED
  | 0x0080 -> IMAGE_FILE_BYTES_REVERSED_LO
  | 0x0100 -> IMAGE_FILE_32BIT_MACHINE
  | 0x0200 -> IMAGE_FILE_DEBUG_STRIPPED
  | 0x0400 -> IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP
  | 0x0800 -> IMAGE_FILE_NET_RUN_FROM_SWAP
  | 0x1000 -> IMAGE_FILE_SYSTEM
  | 0x2000 -> IMAGE_FILE_DLL
  | 0x4000 -> IMAGE_FILE_UP_SYSTEM_ONLY
  | 0x8000 -> IMAGE_FILE_BYTES_REVERSED_HI
  | x -> UNKNOWN x

let characteristic_to_string =
  function
  | IMAGE_FILE_RELOCS_STRIPPED -> "IMAGE_FILE_RELOCS_STRIPPED"
  | IMAGE_FILE_EXECUTABLE_IMAGE -> "IMAGE_FILE_EXECUTABLE_IMAGE"
  | IMAGE_FILE_LINE_NUMS_STRIPPED -> "IMAGE_FILE_LINE_NUMS_STRIPPED"
  | IMAGE_FILE_LOCAL_SYMS_STRIPPED -> "IMAGE_FILE_LOCAL_SYMS_STRIPPED"
  | IMAGE_FILE_AGGRESSIVE_WS_TRIM -> "IMAGE_FILE_AGGRESSIVE_WS_TRIM"
  | IMAGE_FILE_LARGE_ADDRESS_AWARE -> "IMAGE_FILE_LARGE_ADDRESS_AWARE"
  | RESERVED -> "RESERVED"
  | IMAGE_FILE_BYTES_REVERSED_LO -> "IMAGE_FILE_BYTES_REVERSED_LO"
  | IMAGE_FILE_32BIT_MACHINE -> "IMAGE_FILE_32BIT_MACHINE"
  | IMAGE_FILE_DEBUG_STRIPPED -> "IMAGE_FILE_DEBUG_STRIPPED"
  | IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP -> "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP"
  | IMAGE_FILE_NET_RUN_FROM_SWAP -> "IMAGE_FILE_NET_RUN_FROM_SWAP"
  | IMAGE_FILE_SYSTEM -> "IMAGE_FILE_SYSTEM"
  | IMAGE_FILE_DLL -> "IMAGE_FILE_DLL"
  | IMAGE_FILE_UP_SYSTEM_ONLY -> "IMAGE_FILE_UP_SYSTEM_ONLY"
  | IMAGE_FILE_BYTES_REVERSED_HI -> "IMAGE_FILE_BYTES_REVERSED_HI"
  | UNKNOWN x -> Printf.sprintf "UNKNOWN_CHARACTERISTIC 0x%x" x

let is_dll characteristics =
  let characteristic = characteristic_to_int IMAGE_FILE_DLL in
  characteristics land characteristic = characteristic

let has characteristic characteristics =
  let characteristic = characteristic_to_int characteristic in
  characteristics land characteristic = characteristic

(* TODO: this is a mad hack *)
let show_type characteristics =
  if (has IMAGE_FILE_DLL characteristics) then "DLL"
  else if (has IMAGE_FILE_EXECUTABLE_IMAGE characteristics) then "EXE"
  else "MANY"                   (* print all *)
 */

macro_rules! rex {
    ($a:ident, $b:ident) => {
        pub const $b: $a = $a::$b;
    };
}

rex!(Characteristics, IMAGE_FILE_RELOCS_STRIPPED);
rex!(Characteristics, IMAGE_FILE_EXECUTABLE_IMAGE);
rex!(Characteristics, IMAGE_FILE_LINE_NUMS_STRIPPED);
rex!(Characteristics, IMAGE_FILE_LOCAL_SYMS_STRIPPED);
rex!(Characteristics, IMAGE_FILE_AGGRESSIVE_WS_TRIM);
rex!(Characteristics, IMAGE_FILE_LARGE_ADDRESS_AWARE);
rex!(Characteristics, _IMAGE_FILE_RESERVED);
rex!(Characteristics, IMAGE_FILE_BYTES_REVERSED_LO);
rex!(Characteristics, IMAGE_FILE_32BIT_MACHINE);
rex!(Characteristics, IMAGE_FILE_DEBUG_STRIPPED);
rex!(Characteristics, IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP);
rex!(Characteristics, IMAGE_FILE_NET_RUN_FROM_SWAP);
rex!(Characteristics, IMAGE_FILE_SYSTEM);
rex!(Characteristics, IMAGE_FILE_DLL);
rex!(Characteristics, IMAGE_FILE_UP_SYSTEM_ONLY);
rex!(Characteristics, IMAGE_FILE_BYTES_REVERSED_HI);

// exhaustive
bitflags! {
    #[derive(Default)]
    pub struct Characteristics: u16 {
        // 0x0000 is not reserved
        const IMAGE_FILE_RELOCS_STRIPPED = 0x0001;
        const IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
        const IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004;
        const IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008;
        const IMAGE_FILE_AGGRESSIVE_WS_TRIM = 0x0010;
        const IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020;
        const _IMAGE_FILE_RESERVED = 0x0040;
        const IMAGE_FILE_BYTES_REVERSED_LO = 0x0080;
        const IMAGE_FILE_32BIT_MACHINE = 0x0100;
        const IMAGE_FILE_DEBUG_STRIPPED = 0x0200;
        const IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400;
        const IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800;
        const IMAGE_FILE_SYSTEM = 0x1000;
        const IMAGE_FILE_DLL = 0x2000;
        const IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000;
        const IMAGE_FILE_BYTES_REVERSED_HI = 0x8000;
    }
}

// exhaustive
bitflags! {
    #[derive(Default)]
    pub struct SectionCharacteristics: u32 {
        // 0x00000000 is reserved, which is unusual in a bitflag field
        const _IMAGE_SCN_RESERVED2 = 0x00000001;
        const _IMAGE_SCN_RESERVED3 = 0x00000002;
        const _IMAGE_SCN_RESERVED4 = 0x00000004;
        const IMAGE_SCN_TYPE_NO_PAD = 0x00000008;
        const _IMAGE_SCN_RESERVED5 = 0x00000010;
        const IMAGE_SCN_CNT_CODE = 0x00000020;
        const IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
        const IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;
        const IMAGE_SCN_LNK_OTHER = 0x00000100;
        const IMAGE_SCN_LNK_INFO = 0x00000200;
        const _IMAGE_SCN_RESERVED6 = 0x00000400;
        const IMAGE_SCN_LNK_REMOVE = 0x00000800;
        const IMAGE_SCN_LNK_COMDAT = 0x00001000;
        const _IMAGE_SCN_UNKNOWN1 = 0x00002000; // undocumented
        const _IMAGE_SCN_UNKNOWN2 = 0x00004000; // undocumented
        const IMAGE_SCN_GPREL = 0x00008000;
        const _IMAGE_SCN_UNKNOWN3 = 0x00010000; // undocumented
        const IMAGE_SCN_MEM_PURGEABLE = 0x00020000; // yes, this is the same as the next
        const IMAGE_SCN_MEM_16BIT = 0x00020000;
        const IMAGE_SCN_MEM_LOCKED = 0x00040000;
        const IMAGE_SCN_MEM_PRELOAD = 0x00080000;
        // The align fields aren't really bitflags, since they're mutually exclusive
        const IMAGE_SCN_ALIGN_BIT0 = 0x00100000;
        const IMAGE_SCN_ALIGN_BIT1 = 0x00200000;
        const IMAGE_SCN_ALIGN_BIT2 = 0x00400000;
        const IMAGE_SCN_ALIGN_BIT3 = 0x00800000;
        //const IMAGE_SCN_ALIGN_1BYTES = 0x00100000;
        //const IMAGE_SCN_ALIGN_2BYTES = 0x00200000;
        //const IMAGE_SCN_ALIGN_4BYTES = 0x00300000;
        //const IMAGE_SCN_ALIGN_8BYTES = 0x00400000;
        //const IMAGE_SCN_ALIGN_16BYTES = 0x00500000;
        //const IMAGE_SCN_ALIGN_32BYTES = 0x00600000;
        //const IMAGE_SCN_ALIGN_64BYTES = 0x00700000;
        //const IMAGE_SCN_ALIGN_128BYTES = 0x00800000;
        //const IMAGE_SCN_ALIGN_256BYTES = 0x00900000;
        //const IMAGE_SCN_ALIGN_512BYTES = 0x00A00000;
        //const IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000;
        //const IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000;
        //const IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000;
        //const IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000;
        const IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000;
        const IMAGE_SCN_MEM_DISCARDABLE = 0x02000000;
        const IMAGE_SCN_MEM_NOT_CACHED = 0x04000000;
        const IMAGE_SCN_MEM_NOT_PAGED = 0x08000000;
        const IMAGE_SCN_MEM_SHARED = 0x10000000;
        const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
        const IMAGE_SCN_MEM_READ = 0x40000000;
        const IMAGE_SCN_MEM_WRITE = 0x80000000;
    }
}

pub fn is_dll(characteristics: Characteristics) -> bool {
  characteristics.contains(Characteristics::IMAGE_FILE_DLL)
}

pub fn is_exe(characteristics: Characteristics) -> bool {
  characteristics.contains(Characteristics::IMAGE_FILE_EXECUTABLE_IMAGE)
}
