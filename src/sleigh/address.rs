use super::types::Address;

use std::cmp::{PartialEq, Eq};
use std::hash::{Hash, Hasher};
use std::clone::Clone;

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
            offset: self.offset + addend
        };
    }
}

impl PartialEq for Address {
    fn eq(&self, other: &Self) -> bool {
        return self.space == other.space && self.offset == other.offset;
    }
}

impl Eq for Address {}

impl Hash for Address {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.space.hash(state);
        self.offset.hash(state);
    }
}

impl Clone for Address {
    fn clone(&self) -> Self {
        return Address {
            space: self.space.clone(),
            offset: self.offset
        };
    }
}
