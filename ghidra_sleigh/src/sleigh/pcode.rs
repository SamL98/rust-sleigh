use fxhash::FxHashMap;

use super::compound_varnode::{CompoundVarnodeIface, CompoundVarnodeIface2};

use super::compound_varnode::{VarnodeMap, VarnodeStack};
use super::csleigh::{csleigh_PcodeOp, get_addr_space};
use super::opcode::OpCode;
use super::types::{
    Address, AddressSpace, CompVnode, CompoundVarnode, Context, GenericPcodeOp, PcodeOp, PcodeType, SeqNum,
    SsaCompoundVarnode, SsaPcodeOp, SsaVarnode, Varnode, VarnodeDefns, VarnodeUses
};
use super::varnode::VarnodeIface;

use core::num;
use std::cell::RefCell;
use std::fmt;
use std::hash::Hash;
use std::mem;
use std::sync::{Arc, Mutex};

impl<V: CompVnode> GenericPcodeOp<V> {
    fn fmt_unary(&self, opstr: &str) -> String {
        format!("{}({})", opstr, self.inputs[0])
    }

    fn fmt_binary(&self, opstr: &str) -> String {
        format!("{} {} {}", self.inputs[0], opstr, self.inputs[1])
    }

    fn fmt_func(&self, opstr: &str) -> String {
        format!(
            "{}({})",
            opstr,
            self.inputs
                .iter()
                .map(|x| format!("{}", x))
                .collect::<Vec<String>>()
                .join(", ")
        )
    }

    fn fmt_inputs(&self) -> String {
        match self.opcode {
            OpCode::COPY => format!("{}", self.inputs[0]),
            OpCode::STORE => format!("*{} = {}", self.inputs[1], self.inputs[2]),
            OpCode::LOAD => format!("*{}", self.inputs[1]),
            OpCode::BRANCH => format!("goto {}", self.inputs[0]),
            OpCode::BRANCHIND => format!("goto [{}]", self.inputs[0]),
            OpCode::CALL => format!(
                "call({})",
                self.inputs
                    .iter()
                    .map(|x| format!("{}", x))
                    .collect::<Vec<String>>()
                    .join(", ")
            ),
            OpCode::CALLIND => format!(
                "call(*({}), {})",
                self.inputs[0],
                self.inputs[1..]
                    .iter()
                    .map(|x| format!("{}", x))
                    .collect::<Vec<String>>()
                    .join(", ")
            ),
            OpCode::CBRANCH => format!("if ({}) goto {}", self.inputs[1], self.inputs[0]),
            OpCode::RETURN => format!(
                "return {}",
                self.inputs
                    .iter()
                    .map(|x| format!("{}", x))
                    .collect::<Vec<String>>()
                    .join(", ")
            ),
            OpCode::CPOOLREF => self.fmt_func("cpool"),
            OpCode::FLOAT_ABS => self.fmt_func("abs"),
            OpCode::FLOAT_CEIL => self.fmt_func("ceil"),
            OpCode::FLOAT_FLOAT2FLOAT => self.fmt_func("float2float"),
            OpCode::FLOAT_FLOOR => self.fmt_func("floor"),
            OpCode::FLOAT_INT2FLOAT => self.fmt_func("int2float"),
            OpCode::FLOAT_NAN => self.fmt_func("nan"),
            OpCode::FLOAT_ROUND => self.fmt_func("round"),
            OpCode::FLOAT_SQRT => self.fmt_func("sqrt"),
            OpCode::FLOAT_TRUNC => self.fmt_func("trunc"),
            OpCode::INT_CARRY => self.fmt_func("carry"),
            OpCode::INT_SBORROW => self.fmt_func("sborrow"),
            OpCode::INT_SCARRY => self.fmt_func("scarry"),
            OpCode::INT_SEXT => self.fmt_func("sext"),
            OpCode::INT_ZEXT => self.fmt_func("zext"),
            OpCode::NEW => self.fmt_func("newobject"),
            OpCode::POPCOUNT => self.fmt_func("popcount"),
            OpCode::BOOL_AND => self.fmt_binary("&&"),
            OpCode::BOOL_OR => self.fmt_binary("||"),
            OpCode::BOOL_XOR => self.fmt_binary("^^"),
            OpCode::FLOAT_ADD => self.fmt_binary("f+"),
            OpCode::FLOAT_DIV => self.fmt_binary("f/"),
            OpCode::FLOAT_EQUAL => self.fmt_binary("f=="),
            OpCode::FLOAT_LESS => self.fmt_binary("f<"),
            OpCode::FLOAT_LESSEQUAL => self.fmt_binary("f<="),
            OpCode::FLOAT_MULT => self.fmt_binary("f*"),
            OpCode::FLOAT_NOTEQUAL => self.fmt_binary("f!="),
            OpCode::FLOAT_SUB => self.fmt_binary("f-"),
            OpCode::INT_ADD => self.fmt_binary("+"),
            OpCode::INT_AND => self.fmt_binary("&"),
            OpCode::INT_DIV => self.fmt_binary("/"),
            OpCode::INT_EQUAL => self.fmt_binary("=="),
            OpCode::INT_LESS => self.fmt_binary("<"),
            OpCode::INT_LEFT => self.fmt_binary("<<"),
            OpCode::INT_LESSEQUAL => self.fmt_binary("<="),
            OpCode::INT_MULT => self.fmt_binary("*"),
            OpCode::INT_NEGATE => self.fmt_unary("~"),
            OpCode::INT_NOTEQUAL => self.fmt_binary("!="),
            OpCode::INT_OR => self.fmt_binary("|"),
            OpCode::INT_REM => self.fmt_binary("%"),
            OpCode::INT_RIGHT => self.fmt_binary(">>"),
            OpCode::INT_SDIV => self.fmt_binary("s/"),
            OpCode::INT_SLESS => self.fmt_binary("s<"),
            OpCode::INT_SREM => self.fmt_binary("s%"),
            OpCode::INT_SRIGHT => self.fmt_binary("s>>"),
            OpCode::INT_SUB => self.fmt_binary("-"),
            OpCode::INT_XOR => self.fmt_binary("^"),
            OpCode::BOOL_NEGATE => self.fmt_unary("!"),
            OpCode::FLOAT_NEG => self.fmt_unary("f-"),
            OpCode::INT_2COMP => self.fmt_unary("-"),
            OpCode::CALLOTHER => self.fmt_func("callother"),
            OpCode::INT_SLESSEQUAL => todo!(),
            OpCode::MULTIEQUAL => self.fmt_func("phi"),
            OpCode::INDIRECT => todo!(),
            OpCode::PIECE => todo!(),
            OpCode::SUBPIECE => {
                format!("({})({})", self.inputs[0], self.inputs[1])
            }
            OpCode::CAST => todo!(),
            OpCode::PTRADD => todo!(),
            OpCode::PTRSUB => todo!(),
            OpCode::SEGMENTOP => todo!(),
            OpCode::INSERT => todo!(),
            OpCode::EXTRACT => todo!(),
            _ => unimplemented!("unimplemented opcode {:?}", self.opcode),
        }
    }

    fn fmt_output(&self) -> String {
        match &self.output {
            Some(vnode) => format!("{} = ", vnode),
            None => "".to_string(),
        }
    }

    fn to_string(&self) -> String {
        format!("{}{}", self.fmt_output(), self.fmt_inputs())
    }
}

impl<V: CompVnode> fmt::Display for GenericPcodeOp<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

pub trait PcodeIface<V: CompVnode> {
    fn is_load(&self) -> bool;
    fn is_store(&self) -> bool;
    fn is_copy(&self) -> bool;
    fn is_phi(&self) -> bool;
    fn is_call(&self) -> bool;
    fn is_return(&self) -> bool;
    fn setting_output(&self, new_output: V) -> GenericPcodeOp<V>;
    fn unioning_output(&self, new_output_part: V) -> GenericPcodeOp<V>;
}

impl PcodeOp {
    pub fn new(ctx: &Context, op_c: *const csleigh_PcodeOp) -> PcodeOp {
        let addr_space_ptr = unsafe { (*op_c).seq.pc.space };
        let addr_space = get_addr_space(addr_space_ptr);

        let off = unsafe { (*op_c).seq.pc.off };
        let pc = Address {
            space: addr_space,
            offset: off,
        };
        let mut opcode: OpCode = unsafe { mem::transmute((*op_c).opcode) };

        let num_inputs = unsafe { (*op_c).num_inputs };
        let mut inputs: Vec<CompoundVarnode> = Vec::with_capacity(num_inputs as usize);

        for i in 0..(num_inputs as usize) {
            let input_c = unsafe { (*op_c).inputs.offset(i as isize) };
            inputs.push(CompoundVarnode::new(
                Varnode::new(ctx, input_c),
                ctx.reg_sizes.clone(),
            ));
        }

        let output = unsafe {
            if (*op_c).output.is_null() {
                None
            } else {
                Some(CompoundVarnode::new(
                    Varnode::new(ctx, (*op_c).output),
                    ctx.reg_sizes.clone(),
                ))
            }
        };

        let uniq = unsafe { (*op_c).seq.uniq };
        let order = unsafe { (*op_c).seq.order };

        // let is_reorderable =
        //     opcode != OpCode::LOAD && opcode != OpCode::STORE && opcode != OpCode::MULTIEQUAL &&
        //     opcode != OpCode::BRANCH && opcode != OpCode::CBRANCH;

        // if is_reorderable && inputs.len() == 2 && inputs[1].dominates(&inputs[0]) {
        //     inputs.swap(0, 1);
        // }

        if opcode == OpCode::RETURN {
            inputs.remove(0);
        } else if opcode == OpCode::INT_ADD
            && inputs[1].is_const()
            && (inputs[1].offset() >> 63) == 1
        {
            opcode = OpCode::INT_SUB;
            inputs[1] = CompoundVarnode::new(
                Varnode {
                    name: None,
                    space: AddressSpace::Const,
                    offset: (inputs[1].offset() ^ 0xffffffffffffffff) + 1,
                    size: inputs[1].size(),
                },
                ctx.reg_sizes.clone(),
            )
        }

        let kind = match opcode {
            OpCode::CALL | OpCode::CALLIND => PcodeType::Call,
            OpCode::RETURN => PcodeType::Ret,
            OpCode::MULTIEQUAL => PcodeType::Phi,
            _ => PcodeType::Default,
        };

        let op = PcodeOp {
            kind: kind,
            seq: SeqNum {
                pc: pc,
                uniq: uniq as i32,
                order: order,
            },
            opcode: opcode,
            inputs: inputs,
            output: output,
            killed: vec![],
            used: vec![],
        };

        return op;
    }
}

impl<V: CompVnode> PcodeIface<V> for GenericPcodeOp<V> {
    fn is_load(&self) -> bool {
        self.opcode == OpCode::LOAD
    }

    fn is_store(&self) -> bool {
        self.opcode == OpCode::STORE
    }

    fn is_copy(&self) -> bool {
        self.opcode == OpCode::COPY
    }

    fn is_phi(&self) -> bool {
        self.kind == PcodeType::Phi
    }

    fn is_call(&self) -> bool {
        self.kind == PcodeType::Call
    }

    fn is_return(&self) -> bool {
        self.kind == PcodeType::Ret
    }

    fn setting_output(&self, new_output: V) -> GenericPcodeOp<V> {
        GenericPcodeOp {
            kind: self.kind.clone(),
            seq: self.seq.clone(),
            opcode: self.opcode.clone(),
            inputs: self.inputs.clone(),
            output: Some(new_output),
            killed: self.killed.clone(),
            used: self.used.clone(),
        }
    }

    fn unioning_output(&self, new_output_part: V) -> GenericPcodeOp<V> {
        GenericPcodeOp {
            kind: self.kind.clone(),
            seq: self.seq.clone(),
            opcode: self.opcode.clone(),
            inputs: self.inputs.clone(),
            output: self.output.clone().map(|o| o.union_with(&new_output_part)),
            killed: self.killed.clone(),
            used: self.used.clone(),
        }
    }
}

impl<V: CompVnode> PartialEq for GenericPcodeOp<V> {
    fn eq(&self, other: &Self) -> bool {
        self.seq == other.seq
            && self.opcode == other.opcode
            && self.inputs == other.inputs
            && self.output == other.output
            && self.killed == other.killed
            && self.used == other.used
    }
}

