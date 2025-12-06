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
}

impl fmt::Display for SeqNum {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.pc, self.uniq)
    }
}
