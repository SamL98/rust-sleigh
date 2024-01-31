use super::opcode::OpCode;

use std::collections::HashMap;

pub struct Address {
    pub space: String,
    pub offset: u64
}

pub struct SeqNum {
    pub pc: Address,
    pub uniq: u32,
    pub order: u32
}

#[derive(Eq, PartialEq, Hash, Clone)]
pub struct Varnode {
    pub space: String,
    pub offset: u64,
    pub size: u64
}

pub struct PcodeOp {
    pub seq: SeqNum,
    pub opcode: OpCode,
    pub inputs: Vec<Varnode>,
    pub output: Option<Varnode>,
}

pub struct Instruction {
    pub address: Address,
    pub length: u64,
    pub mnemonic: String,
    pub body: String,
    pub ops: Vec<PcodeOp>
}

pub struct Context {}
