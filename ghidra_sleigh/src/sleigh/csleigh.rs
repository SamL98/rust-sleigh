use libc::{c_char, c_void, c_uchar, c_uint};
use std::ffi::{CString, CStr};
use std::fmt;
use super::types::AddressSpace;

#[repr(C)]
pub struct csleigh_Address {
    pub space: *const c_void,
    pub off: u64
}

#[repr(C)]
pub struct csleigh_Varnode {
    pub space: *const c_void,
    pub off: u64,
    pub size: u32
}

#[repr(C)]
pub struct csleigh_SeqNum {
    pub pc: csleigh_Address,
    pub uniq: u32,
    pub order: u32
}

#[repr(C)]
pub struct csleigh_PcodeOp {
    pub seq: csleigh_SeqNum,
    pub opcode: u32,
    pub output: *const csleigh_Varnode,
    pub inputs: *const csleigh_Varnode,
    pub num_inputs: u32
}

#[repr(C)]
pub struct csleigh_Translation {
    pub addr: csleigh_Address,
    pub len: i32,
    padding: u32,
    pub mnem: *const c_char,
    pub body: *const c_char,
    pub ops: *const csleigh_PcodeOp,
    pub num_ops: u32
}

/*#[repr(C)]
pub struct csleigh_UnimplError {
    addr: csleigh_Address,
    insn_len: i32
}

#[repr(C)]
pub struct csleigh_BaddataError {
    addr: csleigh_Address
}

#[repr(C)]
pub union csleigh_ErrorUnion {
    unimpl: csleigh_UnimplError,
    baddata: csleigh_BaddataError
}*/

#[repr(C)]
pub struct csleigh_Error {
    pub error_type: u32,
    //explain: *const c_char,
    //error: csleigh_ErrorUnion
    padding2: u64,
    padding3: u64,
    padding4: u64,
    padding5: u32,
}

#[repr(C)]
pub struct csleigh_TranslationResult {
    pub error: csleigh_Error,
    pub insns: *const csleigh_Translation,
    pub num_insns: u32
}

#[repr(C)]
pub struct csleigh_RegisterDefinition {
    pub name: *const c_char,
    pub vnode: csleigh_Varnode
}

#[link(name = "csleigh")]
extern {
    pub fn csleigh_createContext(slafile: *const c_char) -> *const c_void;
    pub fn csleigh_setVariableDefault(ctx: *const c_void, var: *const c_char, val: u32) -> c_void;
    pub fn csleigh_Sleigh_getAllRegisters(ctx: *const c_void, count: *const c_uint) -> *const csleigh_RegisterDefinition;
    pub fn csleigh_setData(ctx: *const c_void, bytes: *const u8, max_len: u32) -> c_void;
    pub fn csleigh_resetVariables(ctx: *const c_void);
    pub fn csleigh_addSegment(ctx: *const c_void, addr: u64, off: u64, size: u32) -> c_void;
    pub fn csleigh_translate(ctx: *const c_void, addr: u64, max_inst: u32, bb_terminating: u8) -> *const csleigh_TranslationResult;
    pub fn csleigh_AddrSpace_getName(addr_space: *const c_void) -> *const c_char;
    pub fn csleigh_isConst(vnode: *const csleigh_Varnode) -> bool;
    pub fn csleigh_isRegister(vnode: *const csleigh_Varnode) -> bool;
    pub fn csleigh_isRam(vnode: *const csleigh_Varnode) -> bool;
    pub fn csleigh_isUnique(vnode: *const csleigh_Varnode) -> bool;
    pub fn csleigh_isConstSpace(addr_space: *const c_void) -> bool;
    pub fn csleigh_isRegisterSpace(addr_space: *const c_void) -> bool;
    pub fn csleigh_isRamSpace(addr_space: *const c_void) -> bool;
    pub fn csleigh_isUniqueSpace(addr_space: *const c_void) -> bool;
}

pub fn get_addr_space_name(addr_space_c: *const c_void) -> String {
    let addr_space_ptr = unsafe { csleigh_AddrSpace_getName(addr_space_c) };
    return get_str(addr_space_ptr);
}

pub fn get_str(ptr: *const c_char) -> String {
    let cstr = unsafe { CStr::from_ptr(ptr) };
    return cstr.to_str().unwrap().to_string();
}

pub fn get_addr_space(addr_space_c: *const c_void) -> AddressSpace {
    if unsafe { csleigh_isRegisterSpace(addr_space_c )} {
        AddressSpace::Register
    } else if unsafe { csleigh_isConstSpace(addr_space_c )} {
        AddressSpace::Const
    } else if unsafe { csleigh_isRamSpace(addr_space_c )} {
        AddressSpace::Ram
    } else if unsafe { csleigh_isUniqueSpace(addr_space_c )} {
        AddressSpace::Unique
    } else {
        AddressSpace::Other(get_addr_space_name(unsafe { addr_space_c }))
    }
}

pub fn get_space(vnode_c: *const csleigh_Varnode) -> AddressSpace {
    if unsafe { csleigh_isRegister(vnode_c )} {
        AddressSpace::Register
    } else if unsafe { csleigh_isConst(vnode_c )} {
        AddressSpace::Const
    } else if unsafe { csleigh_isRam(vnode_c )} {
        AddressSpace::Ram
    } else if unsafe { csleigh_isUnique(vnode_c )} {
        AddressSpace::Unique
    } else {
        AddressSpace::Other(get_addr_space_name(unsafe { (*vnode_c).space }))
    }
}

impl fmt::Display for AddressSpace {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AddressSpace::Const => write!(f, "const"),
            AddressSpace::Register => write!(f, "register"),
            AddressSpace::Ram => write!(f, "ram"),
            AddressSpace::Unique => write!(f, "unique"),
            AddressSpace::Other(s) => write!(f, "{}", s),
        }
    }
}
