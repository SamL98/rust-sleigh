use super::types::{
    // Context,
    Instruction,
    // PcodeOp,
    // Address
};
// use super::pcode::PcodeIface;

use std::fmt;

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.asm)
    }
}
