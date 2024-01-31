use super::types::{
    Varnode,
    Context
};

use std::cmp::{PartialEq, Eq};
use std::hash::{Hash, Hasher};
use std::clone::Clone;
use std::fmt;

impl fmt::Debug for Varnode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:0x{:x}:{}", self.space, self.offset, self.size)
    }
}

impl fmt::Display for Varnode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:0x{:x}:{}", self.space, self.offset, self.size)
    }
}
