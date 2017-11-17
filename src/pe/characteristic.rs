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

bitflags! {
    #[derive(Default)]
    pub struct Characteristics: u16 {
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

pub fn is_dll(characteristics: Characteristics) -> bool {
  characteristics.contains(Characteristics::IMAGE_FILE_DLL)
}

pub fn is_exe(characteristics: Characteristics) -> bool {
  characteristics.contains(Characteristics::IMAGE_FILE_EXECUTABLE_IMAGE)
}
