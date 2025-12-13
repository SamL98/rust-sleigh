use super::address::*;
use super::op::*;

use std::fmt::{self, Debug, Display};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::cmp::Ordering;
use std::clone::Clone;

#[derive(Clone)]
pub struct Varnode {
    pub name: Option<String>,
    pub space: AddressSpace,
    pub offset: u64,
    pub size: u64
}

impl Hash for Varnode {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.space.hash(state);
        self.offset.hash(state);
        self.size.hash(state);
    }
}

impl PartialEq for Varnode {
    fn eq(&self, other: &Self) -> bool {
        self.space == other.space &&
            self.offset == other.offset &&
            self.size == other.size
    }
}

impl Eq for Varnode {}

impl PartialOrd for Varnode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Varnode {
    fn cmp(&self, other: &Self) -> Ordering {
        self.offset.cmp(&other.offset)
    }
}

impl Debug for Varnode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl Display for Varnode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.name {
            Some(name) => {
                if name.starts_with('"') && name.ends_with('"') {
                    write!(f, "\x1b[1;35m{}\x1b[0m", name)
                } else {
                    write!(f, "\x1b[1;33m{}\x1b[0m", name)
                }
            },
            _ => match self.space {
                AddressSpace::Unique => write!(f, "U{:x}:{}", self.offset, self.size),
                AddressSpace::Const => write!(f, "\x1b[1;32m0x{:x}\x1b[0m", self.offset),
                // AddressSpace::Const => write!(f, "0x{:x}", self.offset),
                AddressSpace::Register => write!(f, "R{:x}:{}", self.offset, self.size), // FIXME
                AddressSpace::Ram => write!(f, "[ram]0x{:x}:{}", self.offset, self.size),
                AddressSpace::Stack => write!(f, "[stack]0x{:x}:{}", self.offset, self.size),
                AddressSpace::Deref => write!(f, "[deref]0x{:x}:{}", self.offset, self.size),
                AddressSpace::Dummy => write!(f, "DUMMY"),
            }
        }
    }
}

impl FmtIface for Varnode {
    fn fmt_call_target(&self) -> String {
        match &self.name {
            Some(name) => name.clone(),
            _ => {
                if self.space.is_ram() || self.space.is_const() {
                    format!("\x1b[1m\x1b[38;5;208mFUN_{:x}\x1b[0m", self.offset)
                } else {
                    self.to_string()
                }
            },
        }
    }

    fn fmt_output(&self) -> String {
        self.to_string()
    }
}

impl Varnode {
    pub fn atom(&self, off: u64) -> Varnode {
        Varnode { name: None, space: self.space, offset: off, size: 1 }
    }

    pub fn dummy() -> Self {
        Self {
            name: None,
            space: AddressSpace::Dummy,
            offset: 0,
            size: 0,
        }
    }

    pub fn constant(off: u64, size: u64) -> Self {
        Self {
            name: None,
            space: AddressSpace::Const,
            offset: off,
            size,
        }
    }

    pub fn is_negative(&self) -> bool {
        self.space.is_const() && self.offset >> ((self.size * 8) - 1) != 0
    }

    pub fn negate(&self) -> Varnode {
        let shift = 64 - self.size * 8;
        let off = (((self.offset << shift) as i64) >> shift) as u64; // sign-extend.
        let signed_off = (off ^ 0xffffffffffffffff) + 1;

        Varnode {
            name: self.name.clone(),
            space: self.space,
            offset: signed_off,
            size: self.size,
        }
    }

    pub fn truncate(&self, addend: u64, new_size: u64, varnode_map: &HashMap<(u64, u64), String>) -> Self {
        let new_offset = self.offset + addend;

        let new_name = if self.space == AddressSpace::Register {
            varnode_map.get(&(new_offset, new_size)).cloned()
        } else {
            None
        };

        Varnode {
            name: new_name,
            space: self.space,
            offset: new_offset,
            size: new_size,
        }
    }
}
