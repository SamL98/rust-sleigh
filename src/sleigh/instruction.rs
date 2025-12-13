use super::address::*;
use super::pcode::*;

use std::fmt::{self, Display};

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct Instruction {
    pub address: Address,
    pub length: u64,
    pub asm: String,
    pub ops: Vec<PcodeOp>,
}

impl Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.asm)
    }
}
