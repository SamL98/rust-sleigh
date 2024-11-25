use wasm_bindgen::prelude::*;
use super::types::{
    // SeqNum, 
    // Varnode, 
    PcodeOp, 
    // Context,
    // Address
};
use super::opcode::OpCode;
// use super::varnode::*;

use std::fmt;
// use std::mem;

impl PcodeOp {
    fn fmt_unary(&self, opstr: &str) -> String {
        format!("{}({})", opstr, self.inputs[0])
    }

    fn fmt_binary(&self, opstr: &str) -> String {
        format!("{} {} {}", self.inputs[0], opstr, self.inputs[1])
    }

    fn fmt_func(&self, opstr: &str) -> String {
        format!("{}({})", opstr, self.inputs.iter()
                                            .map(|x| format!("{}", x))
                                            .collect::<Vec<String>>()
                                            .join(", "))
    }

    fn fmt_inputs(&self) -> String {
        match &self.opcode {
            &OpCode::Copy => format!("{}", self.inputs[0]),
            &OpCode::Store => format!("*{} = {}", self.inputs[1], self.inputs[2]),
            &OpCode::Load => format!("*{}", self.inputs[1]),
            &OpCode::Branch => format!("goto {}", self.inputs[0]),
            &OpCode::BranchInd => format!("goto [{}]", self.inputs[0]),
            &OpCode::Call => format!("call({})", self.inputs.iter()
                                                     .map(|x| format!("{}", x))
                                                     .collect::<Vec<String>>()
                                                     .join(", ")),
            &OpCode::CallInd => format!("call(*({}), {})", self.inputs[0], 
                                                           self.inputs[1..].iter()
                                                                  .map(|x| format!("{}", x))
                                                                  .collect::<Vec<String>>()
                                                                  .join(", ")),
            &OpCode::CBranch => format!("if ({}) goto {}", self.inputs[1], self.inputs[0]),
            &OpCode::Return => format!("return {}", self.inputs[1..].iter()
                                                           .map(|x| format!("{}", x))
                                                           .collect::<Vec<String>>()
                                                           .join(", ")),
            &OpCode::CPoolRef => self.fmt_func("cpool"),
            &OpCode::FloatAbs => self.fmt_func("abs"),
            &OpCode::FloatCeil => self.fmt_func("ceil"),
            &OpCode::FloatFloat2Float => self.fmt_func("float2float"),
            &OpCode::FloatFloor => self.fmt_func("floor"),
            &OpCode::FloatInt2Float => self.fmt_func("int2float"),
            &OpCode::FloatNan => self.fmt_func("nan"),
            &OpCode::FloatRound => self.fmt_func("round"),
            &OpCode::FloatSqrt => self.fmt_func("sqrt"),
            &OpCode::FloatTrunc => self.fmt_func("trunc"),
            &OpCode::IntCarry => self.fmt_func("carry"),
            &OpCode::IntSBorrow => self.fmt_func("sborrow"),
            &OpCode::IntSCarry => self.fmt_func("scarry"),
            &OpCode::IntSext => self.fmt_func("sext"),
            &OpCode::IntZext => self.fmt_func("zext"),
            &OpCode::New => self.fmt_func("newobject"),
            &OpCode::PopCount => self.fmt_func("popcount"),
            &OpCode::BoolAnd => self.fmt_binary("&&"),
            &OpCode::BoolOr => self.fmt_binary("||"),
            &OpCode::BoolXor => self.fmt_binary("^^"),
            &OpCode::FloatAdd => self.fmt_binary("f+"),
            &OpCode::FloatDiv => self.fmt_binary("f/"),
            &OpCode::FloatEqual => self.fmt_binary("f=="),
            &OpCode::FloatLess => self.fmt_binary("f<"),
            &OpCode::FloatLessEqual => self.fmt_binary("f<="),
            &OpCode::FloatMult => self.fmt_binary("f*"),
            &OpCode::FloatNotEqual => self.fmt_binary("f!="),
            &OpCode::FloatSub => self.fmt_binary("f-"),
            &OpCode::IntAdd => self.fmt_binary("+"),
            &OpCode::IntAnd => self.fmt_binary("&"),
            &OpCode::IntDiv => self.fmt_binary("/"),
            &OpCode::IntEqual => self.fmt_binary("=="),
            &OpCode::IntLess => self.fmt_binary("<"),
            &OpCode::IntLeft => self.fmt_binary("<<"),
            &OpCode::IntLessEqual => self.fmt_binary("<="),
            &OpCode::IntMult => self.fmt_binary("*"),
            &OpCode::IntNegate => self.fmt_binary("~"),
            &OpCode::IntNotEqual => self.fmt_binary("!="),
            &OpCode::IntOr => self.fmt_binary("|"),
            &OpCode::IntRem => self.fmt_binary("%"),
            &OpCode::IntRight => self.fmt_binary(">>"),
            &OpCode::IntSDiv => self.fmt_binary("s/"),
            &OpCode::IntSLess => self.fmt_binary("s<"),
            &OpCode::IntSRem => self.fmt_binary("s%"),
            &OpCode::IntSRight => self.fmt_binary("s>>"),
            &OpCode::IntSub => self.fmt_binary("-"),
            &OpCode::IntXor => self.fmt_binary("^"),
            &OpCode::BoolNegate => self.fmt_unary("!"),
            &OpCode::FloatNeg => self.fmt_unary("f-"),
            &OpCode::Int2Comp => self.fmt_unary("-"),
            _ => panic!("Don't know how to format {}!", self.opcode)
        }
    }

    fn fmt_output(&self) -> String {
        match &self.output {
            Some(vnode) => format!("{} = ", vnode),
            None        => "".to_string()
        }
    }
}

#[wasm_bindgen]
impl PcodeOp {
    pub fn to_string(&self) -> String {
        format!("{}{}", self.fmt_output(), self.fmt_inputs())
    }
}

impl fmt::Debug for PcodeOp {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

pub trait PcodeIface {
    //fn new(ctx: &Context, op_c: *const csleigh_PcodeOp) -> PcodeOp;
}

impl PcodeIface for PcodeOp {
    /*fn new(ctx: &Context, op_c: *const csleigh_PcodeOp) -> PcodeOp {
        let addr_space_ptr = unsafe { (*op_c).seq.pc.space };
        let addr_space_str = get_addr_space_name(addr_space_ptr);

        let off = unsafe { (*op_c).seq.pc.off };
        let pc = Address { space: addr_space_str, offset: off };
        let opcode: OpCode = unsafe { mem::transmute((*op_c).opcode) };

        let mut inputs: Vec<Varnode> = Vec::new();
        let num_inputs = unsafe { (*op_c).num_inputs };

        for i in 0..(num_inputs as usize) {
            let input_c = unsafe { 
                (*op_c).inputs.offset(i as isize)
            };
            inputs.push(Varnode::new(ctx, input_c));
        }

        let output = unsafe {
            if (*op_c).output.is_null() { 
                None 
            } 
            else { 
                Some(Varnode::new(ctx, (*op_c).output))
            }
        };

        let uniq = unsafe { (*op_c).seq.uniq };
        let order = unsafe { (*op_c).seq.order };

        return PcodeOp {
            seq: SeqNum { pc: pc, uniq: uniq, order: order },
            opcode: opcode,
            inputs: inputs,
            output: output
        };
    }*/
}
