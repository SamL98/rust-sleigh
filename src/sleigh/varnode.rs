use super::types::{
    AddressSpace,
    Varnode,
    // Context
};

// use std::cmp::{PartialEq, Eq};
// use std::hash::{Hash, Hasher};
use std::collections::HashMap;
use std::clone::Clone;
use std::fmt;

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
            Some(name) => name.to_owned(),
            None => match self.space {
                AddressSpace::Unique => format!("U{:x}:{}", self.offset, self.size),
                AddressSpace::Const => format!("0x{:x}:{}", self.offset, self.size),
                AddressSpace::Register => format!("R{:x}:{}", self.offset, self.size), // FIXME
                AddressSpace::Ram => format!("[ram]0x{:x}:{}", self.offset, self.size),
                AddressSpace::Dummy => "DUMMY".to_string(),
            }
        }
    }

    pub fn is_negative(&self) -> bool {
        // println!("{:x} {} {}", self.offset, self.size, self.offset >> ((self.size * 8) - 1));
        self.space == AddressSpace::Const && self.offset >> ((self.size * 8) - 1) != 0

        // match self.size {
        //     1 if (*val >> 7) != 0 => ((*val ^ 0xff) as u64 + 1, "-"),
        //     2 if (*val >> 15) != 0 => ((*val ^ 0xffff) as u64 + 1, "-"),
        //     4 if (*val >> 31) != 0 => ((*val ^ 0xffffffff) as u64 + 1, "-"),
        //     8 if (*val >> 63) != 0 => ((*val ^ 0xffffffffffffffffu64 as i64) as u64 + 1, "-"),
        //     _ => (*val as u64, ""),
        // }
    }

    // pub fn is_ram(&self) -> bool {
    //     self.space == AddressSpace::Ram
    // }

    // pub fn is_const(&self) -> bool {
    //     self.space == AddressSpace::Const
    // }

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

    pub fn subpiece(&self, addend: u64, new_size: u64, varnode_map: &HashMap<(u64, u64), String>) -> Self {
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
