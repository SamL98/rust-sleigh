use super::types::*;

use std::fmt;

impl BlockElement for Instruction {
    fn returns(&self) -> bool {
        self.ops.last().map(|o| o.returns()).unwrap_or(false)
    }

    fn branches(&self) -> bool {
        self.ops.last().map(|o| o.branches()).unwrap_or(false)
    }

    fn terminates(&self) -> bool {
        self.ops.last().map(|o| o.terminates()).unwrap_or(false)
    }

    fn is_conditional(&self) -> bool {
        self.ops.last().map(|o| o.is_conditional()).unwrap_or(false)
    }

    fn target(&self) -> Option<Address> {
        for op in &self.ops {
            if op.branches() {
                return op.target();
            }
        }
        None
    }

    fn has_fallthrough(&self) -> bool {
        !(self.returns()
            || (self.branches() && !self.is_conditional())
            || self.ops.iter().any(|o| !o.has_fallthrough()))
    }
}

impl Instruction {
    pub fn fallthrough(&self) -> Option<Address> {
        if self.has_fallthrough() {
            return Some(self.address.add(self.bit_len as u64 / 8));
        } else {
            return None;
        }
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.asm)
    }
}
