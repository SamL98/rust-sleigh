use super::types::{SeqNum, Address, AddressSpace};

use std::clone::Clone;
use std::fmt;

pub trait AddressIface {
    fn as_int(&self) -> u64;
    fn adding(&self, addend: u64) -> Address;
}

impl AddressIface for Address {
    fn as_int(&self) -> u64 {
        return self.offset;
    }

    fn adding(&self, addend: u64) -> Address {
        return Address {
            space: self.space.clone(),
            offset: self.offset + addend,
        };
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> fmt::Result {
        write!(f, "0x{:x}", self.offset)
    }
}

impl fmt::Display for SeqNum {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.pc, self.uniq)
    }
}
