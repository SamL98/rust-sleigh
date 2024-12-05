use super::opcode::OpCode;
use wasm_bindgen::prelude::*;

// use std::collections::HashMap;

#[wasm_bindgen(getter_with_clone)]
#[derive(Eq, PartialEq, Hash, Clone)]
pub struct Address {
    pub space: String,
    pub offset: u64
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Eq, PartialEq, Hash, Clone)]
pub struct SeqNum {
    pub pc: Address,
    pub uniq: u32,
    pub order: u32
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Eq, PartialEq, Hash, Clone)]
pub struct Varnode {
    pub name: Option<String>,
    pub space: String,
    pub offset: u64,
    pub size: u64
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Eq, PartialEq, Hash, Clone)]
pub struct PcodeOp {
    pub seq: SeqNum,
    pub opcode: OpCode,
    pub inputs: Vec<Varnode>,
    pub output: Option<Varnode>,
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Eq, PartialEq, Hash, Clone)]
pub struct Instruction {
    pub address: Address,
    pub bit_len: usize,
    pub asm: String,
    pub ops: Vec<PcodeOp>
}

// pub struct Context {}
