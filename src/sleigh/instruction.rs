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

//pub trait InstructionIface {
//    //fn new(ctx: &Context, insn_c: *const csleigh_Translation) -> Instruction;
//}

/*impl InstructionIface for Instruction {
    fn new(ctx: &Context, insn_c: *const csleigh_Translation) -> Instruction {
        let addr_space_ptr = unsafe { (*insn_c).addr.space };
        let addr_space_str = get_addr_space_name(addr_space_ptr);

        let mut ops: Vec<PcodeOp> = Vec::new();
        let num_ops = unsafe { (*insn_c).num_ops };

        for i in 0..(num_ops as usize) {
            let op_c = unsafe { 
                (*insn_c).ops.offset(i as isize)
            };
            let op = PcodeOp::new(ctx, op_c);
            ops.push(op);
        }

        let off = unsafe { (*insn_c).addr.off };

        return Instruction {
            address: Address { space: addr_space_str, offset: off },
            length: u64::try_from(unsafe { (*insn_c).len }).ok().unwrap(),
            mnemonic: get_str(unsafe { (*insn_c).mnem }),
            body: get_str(unsafe { (*insn_c).body }),
            ops: ops
        };
    }
}*/

// impl Hash for Instruction {
//     fn hash<H: Hasher>(&self, state: &mut H) {
//         self.address.hash(state);
//         for op in &self.ops {
//             op.hash(state);
//         }
//     }
// }

// impl PartialEq for Instruction {
//     fn eq(&self, other: &Self) -> bool {
//         let mut equal = self.address == other.address;
//         equal &= self.ops.len() == other.ops.len();

//         if equal {
//             for i in 0..self.ops.len() {
//                 equal &= self.ops[i] == other.ops[i]
//             }
//         }

//         return equal;
//     }
// }

// impl Eq for Instruction {}

// impl Clone for Instruction {
//     fn clone(&self) -> Self {
//         return Instruction {
//             address: self.address.clone(),
//             length: self.length,
//             asm: self.asm.clone(),
//             ops: self.ops.clone()
//         };
//     }
// }
