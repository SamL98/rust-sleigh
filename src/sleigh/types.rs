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
pub struct GenericVarnode {
    pub space: String,
    pub offset: u64,
    pub size: u32
}

#[derive(Eq, PartialEq, Hash, Clone)]
pub struct RegisterVarnode {
    pub name: String,
    pub space: String,
    pub offset: u64,
    pub size: u32
}

#[derive(Eq, PartialEq, Hash, Clone)]
pub enum Varnode {
    Generic(GenericVarnode),
    Register(RegisterVarnode)
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

pub struct Context {
    pub registers: HashMap<GenericVarnode, RegisterVarnode>
}

