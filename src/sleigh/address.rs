use super::seqnum::SeqNum;

use std::fmt::{self, Debug, Display};
use std::cmp::Ordering;
use std::str::FromStr;

#[repr(u8)]
#[derive(Eq, PartialEq, Hash, Copy, Clone, Debug, Default)]
pub enum AddressSpace {
    Const,
    Unique,
    Register,
    Ram,
    Stack,
    Deref,
    #[default]
    Dummy,
}

impl From<&str> for AddressSpace {
    fn from(s: &str) -> Self {
        use AddressSpace::*;
        match s {
            "ram" => Ram,
            "register" => Register,
            "const" => Const,
            "unique" => Unique,
            "stack" => Stack,
            "deref" => Deref,
            "dummy" => Dummy,
            _ => panic!("unknown space {}", s),
        }
    }
}

impl FromStr for AddressSpace {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(s.into())
    }
}

impl AddressSpace {
    pub fn is_unique(&self) -> bool {
        self == &AddressSpace::Unique
    }

    pub fn is_const(&self) -> bool {
        self == &AddressSpace::Const
    }

    pub fn is_ram(&self) -> bool {
        self == &AddressSpace::Ram
    }

    pub fn is_dummy(&self) -> bool {
        self == &AddressSpace::Dummy
    }
}

impl Display for AddressSpace {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use AddressSpace::*;
        let s = match self {
            Ram => "ram",
            Unique => "unique",
            Const => "const",
            Register => "register",
            Stack => "stack",
            Deref => "deref",
            Dummy => "DUMMY",
        };
        write!(f, "{}", s)
    }
}

#[derive(Eq, PartialEq, Hash, Copy, Clone, Default)]
pub struct Address {
    pub space: AddressSpace,
    pub offset: u64
}

impl From<&str> for Address {
    fn from(s: &str) -> Self {
        Self::ram(u64::from_str_radix(s.strip_prefix("0x").unwrap(), 16).unwrap())
    }
}

impl Address {
    pub fn adding(&self, addend: u64) -> Self {
        Self {
            space: self.space,
            offset: self.offset + addend,
        }
    }

    pub fn ram(off: u64) -> Self {
        Self {
            space: AddressSpace::Ram,
            offset: off,
        }
    }

    pub fn seq(&self) -> SeqNum {
        SeqNum {
            pc: *self,
            uniq: 0,
        }
    }
}

impl PartialOrd for Address {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Address {
    fn cmp(&self, other: &Self) -> Ordering {
        self.offset.cmp(&other.offset)
    }
}

impl Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{:x}", self.offset)
    }
}
