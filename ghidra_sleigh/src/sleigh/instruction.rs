use super::csleigh::{csleigh_Translation, get_addr_space, get_str};
use super::pcode::PcodeIface;
use super::types::{Address, Context, Instruction, PcodeOp};

use std::fmt;

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.mnemonic, self.body)
    }
}

// impl fmt::Debug for Instruction {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         write!(f, "{} {}", self.mnemonic, self.body)
//     }
// }

pub trait InstructionIface {
    fn new(ctx: &Context, insn_c: *const csleigh_Translation) -> Instruction;
}

impl InstructionIface for Instruction {
    fn new(ctx: &Context, insn_c: *const csleigh_Translation) -> Instruction {
        let addr_space_ptr = unsafe { (*insn_c).addr.space };
        let addr_space = get_addr_space(addr_space_ptr);

        let num_ops = unsafe { (*insn_c).num_ops };
        let mut ops: Vec<PcodeOp> = Vec::with_capacity(num_ops as usize);

        for i in 0..(num_ops as usize) {
            let op_c = unsafe { (*insn_c).ops.offset(i as isize) };
            let op = PcodeOp::new(ctx, op_c);
            ops.push(op);
        }

        let off = unsafe { (*insn_c).addr.off };

        return Instruction {
            address: Address {
                space: addr_space,
                offset: off,
            },
            length: u64::try_from(unsafe { (*insn_c).len }).ok().unwrap(),
            mnemonic: get_str(unsafe { (*insn_c).mnem }),
            body: get_str(unsafe { (*insn_c).body }),
            ops: ops,
        };
    }
}

impl Instruction {
    pub fn asm(&self) -> String {
        if self.body.len() > 0 {
            format!("{} {}", self.mnemonic, self.body)
        } else {
            self.mnemonic.clone()
        }
    }
}
