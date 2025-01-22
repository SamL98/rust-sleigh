use std::fmt::{Debug, Display};
use std::hash::Hash;

use super::opcode::OpCode;
use flexstr::LocalStr;

// use std::collections::HashMap;

#[derive(Eq, PartialEq, Hash, Clone)]
pub struct Address {
    pub space: AddressSpace,
    pub offset: u64
}

#[derive(Eq, PartialEq, Hash, Clone)]
pub struct SeqNum {
    pub pc: Address,
    pub uniq: i32,
    pub order: u32
}

#[repr(u8)]
#[derive(Eq, PartialEq, Hash, Copy, Clone, Debug)]
pub enum AddressSpace {
    Const,
    Unique,
    Register,
    Ram,
    Dummy,
}

#[derive(Eq, PartialEq, Hash, Clone)]
pub struct Varnode {
    pub name: Option<LocalStr>,
    pub space: AddressSpace,
    pub offset: u64,
    pub size: u64
}

#[derive(Eq, PartialEq, Hash, Clone)]
pub struct Op<
    O: Debug + Display + Clone + Eq + PartialEq + Hash,
    T: Debug + Display + Clone + Eq + PartialEq + Hash,
> {
    pub seq: SeqNum,
    pub opcode: O,
    pub inputs: Vec<T>,
    pub output: Option<T>,
}

pub type PcodeOp = Op<OpCode, Varnode>;

#[derive(Eq, PartialEq, Hash, Clone)]
pub struct Instruction {
    pub address: Address,
    pub bit_len: usize,
    pub asm: String,
    pub ops: Vec<PcodeOp>,
}

pub trait BlockElement {
    fn returns(&self) -> bool;
    fn branches(&self) -> bool;
    fn target(&self) -> Option<Address>;
    fn terminates(&self) -> bool;
    fn is_conditional(&self) -> bool;
    fn has_fallthrough(&self) -> bool;
}
