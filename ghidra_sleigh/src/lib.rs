use fxhash::{FxHashMap, FxHashSet};

pub mod sleigh;

use crate::sleigh::arch::get_context as _get_context;
use crate::sleigh::ContextIface;
use crate::sleigh::types::{Context, SsaCompoundVarnode, Address, Instruction};

use std::fmt::Display;
use std::fs::{self, File};
use std::io;
use std::io::{Read, Write, Seek};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::thread;

use std::ffi::{CString, CStr};
use libc::c_char;

pub fn parse_int(input: &str) -> u64 {
	if input.starts_with("0x") {
        u64::from_str_radix(&input[2..], 16).unwrap()
    } else if input.starts_with("0b") {
        u64::from_str_radix(&input[2..], 2).unwrap()
    } else {
        input.parse().unwrap()
    }
}

pub fn get_context(buf: &[u8], data_addr: usize, data_size: usize) -> Context {
    let mut ctx = _get_context("x86", "x86:LE:64:default", "gcc").unwrap();
    ctx.set_data(buf);
    ctx.add_segment(data_addr as u64, 0, data_size as u32);
    ctx
}

pub struct Disassembler<'a> {
    ctx: &'a Context,
}

pub struct DisassemblyIter<'a> {
    disasm: &'a Disassembler<'a>,
    data: &'a [u8],
    orig_pc: u64,
    pc: u64,
}

impl<'a> Iterator for DisassemblyIter<'a> {
    type Item = Option<Instruction>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pc >= self.orig_pc + (self.data.len() as u64) {
            return None;
        }

        // if self.pc % 0x1000 == 0 {
        //     println!("0x{:x} / 0x{:x}", pc - data_addr, data_size);
        // }

        if let Some(insn) = self.disasm.ctx.disassemble_one(self.pc as u64) {
            self.pc += insn.length as u64;
            Some(Some(insn))
        } else {
            self.pc += 1;
            Some(None)
        }
    }
}

impl<'a> Disassembler<'a> {
    pub fn new(ctx: &'a Context) -> Self {
        Self {
            ctx: ctx,
        }
    }

    pub fn disassemble(&self, buf: &'a [u8], orig_pc: u64) -> DisassemblyIter {
        DisassemblyIter {
            disasm: self,
            data: buf,
            orig_pc: orig_pc,
            pc: orig_pc,
        }
    }
}
