use super::types::{AddressSpace, Address};
use std::fmt;

impl AddressSpace {
    pub fn is_dummy(&self) -> bool {
        return self == &AddressSpace::Dummy
    }
}

impl Address {
    pub fn to_string(&self) -> String {
        format!("0x{:x}", self.offset)
    }
}


impl fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}
