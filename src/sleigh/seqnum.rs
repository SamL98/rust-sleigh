use super::address::Address;

use std::fmt::{self, Debug, Display};
use std::cmp::Ordering;

#[derive(Eq, PartialEq, Hash, Copy, Clone, Default)]
pub struct SeqNum {
    pub pc: Address,
    pub uniq: i32,
}

impl From<&str> for SeqNum {
    fn from(s: &str) -> Self {
        let (first, second) = s.split_once(':').unwrap();
        Self {
            pc: first.into(),
            uniq: second.parse::<i32>().unwrap(),
        }
    }
}

impl SeqNum {
    pub fn at(off: u64) -> Self {
        Self {
            pc: Address::ram(off),
            uniq: 0,
        }
    }

    pub fn prev(&self) -> Self {
        Self {
            pc: self.pc,
            uniq: self.uniq - 1,
        }
    }

    pub fn next(&self) -> Self {
        Self {
            pc: self.pc,
            uniq: self.uniq + 1,
        }
    }

    pub fn offset_by(&self, off: i32) -> Self {
        Self {
            pc: self.pc,
            uniq: self.uniq + off,
        }
    }
}

impl PartialOrd for SeqNum {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SeqNum {
    fn cmp(&self, other: &Self) -> Ordering {
        self.pc.cmp(&other.pc).then(self.uniq.cmp(&other.uniq))
    }
}

impl Debug for SeqNum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl Display for SeqNum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.pc, self.uniq)
    }
}
