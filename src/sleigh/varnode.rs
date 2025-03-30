use super::types::{
    AddressSpace,
    Varnode,
    // Context
};

use flexstr::LocalStr;

// use std::cmp::{PartialEq, Eq};
// use std::hash::{Hash, Hasher};
use std::fmt::{self, Debug, Display};
use std::collections::HashMap;
use std::clone::Clone;
use std::hash::Hash;

impl AddressSpace {
    pub fn from_str(s: &str) -> Self {
        use AddressSpace::*;
        match s {
            "ram" => Ram,
            "register" => Register,
            "const" => Const,
            "unique" => Unique,
            "dummy" => Dummy,
            _ => panic!("unknown space {}", s),
        }
    }

    // pub fn try_from_str(s: &str) -> Option<Self> {
    //     use AddressSpace::*;
    //     match s {
    //         "ram" => Some(Ram),
    //         "register" => Some(Register),
    //         "const" => Some(Const),
    //         "unique" => Some(Unique),
    //         "dummy" => Some(Dummy),
    //         _ => None,
    //     }
    // }
}

impl fmt::Display for AddressSpace {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use AddressSpace::*;
        let s = match self {
            Ram => "ram",
            Unique => "unique",
            Const => "const",
            Register => "register",
            Dummy => "DUMMY",
        };
        write!(f, "{}", s)
    }
}

pub trait VarnodeIface: Debug + Display + Clone + Eq + PartialEq + Hash {
    fn is_negative(&self) -> bool;
    fn is_ram(&self) -> bool;
    fn is_const(&self) -> bool;
    fn is_reg(&self) -> bool;
    fn space(&self) -> AddressSpace;
    fn offset(&self) -> u64;
    fn size(&self) -> u64;
    fn succeeds(&self, other: &Self) -> bool;
    fn with_size(&self, size: u64, name: Option<LocalStr>) -> Self;
    fn fmt_call_target(&self) -> String;
}

impl Varnode{
    pub fn dummy() -> Self {
        Self {
            name: None,
            space: AddressSpace::Dummy,
            offset: 0,
            size: 0,
        }
    }

    fn to_string(&self) -> String {
        match &self.name {
            Some(name) if name != "fixup_start" && name != "fixup_end" => name.to_string(),
            _ => match self.space {
                AddressSpace::Unique => format!("U{:x}:{}", self.offset, self.size),
                AddressSpace::Const => format!("0x{:x}:{}", self.offset, self.size),
                AddressSpace::Register => format!("R{:x}:{}", self.offset, self.size), // FIXME
                AddressSpace::Ram => format!("[ram]0x{:x}:{}", self.offset, self.size),
                AddressSpace::Dummy => "DUMMY".to_string(),
            }
        }
    }

    pub fn negate(&self) -> Varnode {
        let shift = 64 - self.size * 8;
        let off = (((self.offset << shift) as i64) >> shift) as u64; // sign-extend.
        let signed_off = (off ^ 0xffffffffffffffff) + 1;

        Varnode {
            name: self.name.clone(),
            space: self.space.clone(),
            offset: signed_off,
            size: self.size,
        }
    }

    pub fn subpiece(&self, addend: u64, new_size: u64, varnode_map: &HashMap<(u64, u64), LocalStr>) -> Self {
        let new_offset = self.offset + addend;

        let new_name = if self.space == AddressSpace::Register {
            varnode_map.get(&(new_offset, new_size)).cloned()
        } else {
            None
        };

        Varnode {
            name: new_name,
            space: self.space.clone(),
            offset: new_offset,
            size: new_size,
        }
    }

    pub fn adding(&self, addend: u64) -> Self {
        Self {
            name: None,
            space: self.space.clone(),
            offset: self.offset + addend,
            size: self.size,
        }
    }
}

impl VarnodeIface for Varnode {
    fn is_negative(&self) -> bool {
        self.is_const() && self.offset >> ((self.size * 8) - 1) != 0
    }

    fn is_ram(&self) -> bool {
        self.space == AddressSpace::Ram
    }

    fn is_reg(&self) -> bool {
        self.space == AddressSpace::Register
    }

    fn is_const(&self) -> bool {
        self.space == AddressSpace::Const
    }

    fn space(&self) -> AddressSpace {
        self.space
    }

    fn offset(&self) -> u64 {
        self.offset
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn succeeds(&self, other: &Self) -> bool {
        self.space == other.space &&
            self.offset == other.offset + 1
    }

    fn with_size(&self, size: u64, name: Option<LocalStr>) -> Self {
        Self {
            name: name,
            space: self.space,
            offset: self.offset,
            size: size,
        }
    }

    fn fmt_call_target(&self) -> String {
        format!("FUN_{:x}", self.offset())
    }
}

impl fmt::Debug for Varnode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl fmt::Display for Varnode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}
