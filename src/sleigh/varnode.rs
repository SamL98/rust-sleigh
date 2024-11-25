use super::types::{
    Varnode,
    // Context
};

// use std::cmp::{PartialEq, Eq};
// use std::hash::{Hash, Hasher};
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
                "DUMMY" => "DUMMY".to_string(),
                _ => panic!()
            }
        }
    }

    pub fn is_negative(&self) -> bool {
        self.space.as_str() == "const" && self.offset >> (self.size * 8 - 1) == 1
    }

    pub fn negate(&self) -> Varnode {
        let signed_off = match self.size {
            1 => -(self.offset as i8) as u64,
            2 => -(self.offset as i16) as u64,
            4 => -(self.offset as i32) as u64,
            8 => -(self.offset as i64) as u64,
            _ => self.offset,
        };

        Varnode {
            name: self.name.clone(),
            space: self.space.clone(),
            offset: signed_off,
            size: self.size,
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
