use super::types::SeqNum;

use std::fmt;

impl SeqNum {
    pub fn next(&self) -> Self {
        Self {
            pc: self.pc.clone(),
            uniq: self.uniq + 1,
            order: self.order,
        }
    }

    pub fn prev(&self) -> Self {
        Self {
            pc: self.pc.clone(),
            uniq: self.uniq - 1,
            order: self.order,
        }
    }

    fn to_string(&self) -> String {
        format!("{}:{}", self.pc, self.uniq)
    }
}

impl fmt::Debug for SeqNum {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl fmt::Display for SeqNum {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}
