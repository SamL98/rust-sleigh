use super::types::{
    Varnode,
    Context
};

use std::cmp::{PartialEq, Eq};
use std::hash::{Hash, Hasher};
use std::clone::Clone;
use std::fmt;

impl Varnode{
    fn to_string(&self) -> String {
        match &self.name {
            Some(name) => name.to_owned(),
            None => match self.space.as_str() {
                "unique" => format!("U{:x}:{}", self.offset, self.size),
                "const" => format!("{:x}:{}", self.offset, self.size),
                "ram" => format!("[ram]{:x}:{}", self.offset, self.size),
                _ => panic!()
            }
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
