use super::types::{AddressSpace, Address};
use std::fmt;

impl AddressSpace {
    pub fn is_dummy(&self) -> bool {
        self == &AddressSpace::Dummy
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> fmt::Result {
        write!(f, "0x{:x}", self.offset)
    }
}
