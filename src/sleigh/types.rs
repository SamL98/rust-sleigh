use super::opcode::OpCode;
use flexstr::LocalStr;

// use std::collections::HashMap;

#[derive(Eq, PartialEq, Hash, Clone)]
pub struct Address {
    pub space: String,
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
pub struct PcodeOp {
    pub seq: SeqNum,
    pub opcode: OpCode,
    pub inputs: Vec<Varnode>,
    pub output: Option<Varnode>,
}

#[derive(Eq, PartialEq, Hash, Clone)]
pub struct Instruction {
    pub address: Address,
    pub bit_len: usize,
    pub asm: String,
    pub ops: Vec<PcodeOp>,
}

// pub struct Context {}
