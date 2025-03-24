use super::types::*;
use super::opcode::OpCode;
use super::varnode::VarnodeIface;

use std::fmt;
// use std::mem;

impl<T: VarnodeIface> Op<OpCode, T> {
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
            &OpCode::Call => format!("FUN_{:x}({})", self.inputs[0].offset(), self.inputs[1..].iter()
                                                     .map(|x| format!("{}", x))
                                                     .collect::<Vec<String>>()
                                                     .join(", ")),
            &OpCode::CallInd => {
                let mut input_iter = self.inputs.iter();
                let _ = input_iter.next();

                format!("*({})({})", self.inputs[0], 
                    input_iter
                        .map(|x| format!("{}", x))
                        .collect::<Vec<String>>()
                        .join(", "))
            },
            &OpCode::CBranch => format!("if ({}) goto {}", self.inputs[1], self.inputs[0]),
            &OpCode::Return => format!("return {}", self.inputs.iter()
                                                           .map(|x| format!("{}", x))
                                                           .collect::<Vec<String>>()
                                                           .join(", ")),
            &OpCode::MultiEqual => self.fmt_func("phi"),
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
            &OpCode::IntGreater => self.fmt_binary(">"),
            &OpCode::IntLeft => self.fmt_binary("<<"),
            &OpCode::IntLessEqual => self.fmt_binary("<="),
            &OpCode::IntGreaterEqual => self.fmt_binary(">="),
            &OpCode::IntMult => self.fmt_binary("*"),
            &OpCode::IntNegate => self.fmt_unary("~"),
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
            &OpCode::SubPiece => format!("({})({})", self.inputs[0], self.inputs[1]),
            &OpCode::CallOther => self.fmt_func("callother"),
            _ => panic!("Don't know how to format {}!", self.opcode)
        }
    }

    fn fmt_output(&self) -> String {
        match &self.output {
            Some(vnode) => format!("{} = ", vnode),
            None        => "".to_string()
        }
    }

    pub fn is_call(&self) -> bool {
        return self.opcode == OpCode::Call || self.opcode == OpCode::CallInd;
    }
}

impl<T: VarnodeIface> Op<OpCode, T> {
    pub fn to_string(&self) -> String {
        format!("{}{}", self.fmt_output(), self.fmt_inputs())
    }

    pub fn new(seq: SeqNum, opcode: OpCode, inputs: Vec<T>, output: Option<T>) -> Self {
        Self {
            seq: seq,
            opcode: opcode,
            inputs: inputs,
            output: output,
        }
    }
}

impl<T: VarnodeIface> BlockElement for Op<OpCode, T> {
    fn returns(&self) -> bool {
        return self.opcode == OpCode::Return;
    }

    fn branches(&self) -> bool {
        return match self.opcode {
            OpCode::Branch | OpCode::CBranch | OpCode::BranchInd => true,
            _ => false,
        };
    }

    fn terminates(&self) -> bool {
        return self.branches() || self.returns();
    }

    fn is_conditional(&self) -> bool {
        return self.opcode == OpCode::CBranch;
    }

    fn target(&self) -> Option<Address> {
        // TODO: Actually make BRANCHIND read from memory.
        if self.branches()
            && self.inputs.len() > 0
            && self.inputs[0].is_ram()
            && self.opcode != OpCode::BranchInd
        {
            let address = Address {
                space: self.inputs[0].space().to_owned(),
                offset: self.inputs[0].offset(),
            };
            return Some(address);
        } else {
            return None;
        }
    }

    fn has_fallthrough(&self) -> bool {
        !(self.returns() || (self.branches() && !self.is_conditional()))
    }
}

impl<T: VarnodeIface> fmt::Debug for Op<OpCode, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl<T: VarnodeIface> fmt::Display for Op<OpCode, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}
