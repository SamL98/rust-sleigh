use crate::sleigh::types::*;

use crate::sla_parser::*;
use crate::symbol_resolver::*;
use crate::pcode_builder::*;
use crate::logger::Logger;
use crate::log;

use std::collections::{HashSet, HashMap};
use bitvec::prelude::*;

#[allow(dead_code)]
pub struct Disassembler<'a> {
    language_id: String,
    compiler_id: String,
    pub ctx: Vec<u32>,
    num: Option<u64>,
    log_modules: HashSet<String>,
    pub lang: &'a SleighLanguage,
    reg_space: BitVec<u8, Msb0>,
    build_cache: HashMap<MatchedSymbol<'a>, Vec<PcodeOp>>,
    depth: usize,
}

impl Logger for Disassembler<'_> {
    fn should_log(&self) -> bool {
        self.log_modules.contains("disassembler")
    }

    fn depth(&self) -> usize {
        self.depth
    }

    fn inc_depth(&mut self) {
        self.depth += 1
    }

    fn dec_depth(&mut self) {
        self.depth -= 1
    }
}

pub struct DisassemblyIter<'a, 'b> {
    disasm: &'b mut Disassembler<'a>,
    orig_pc: u64,
    data: &'a [u8],
    bits_consumed: usize,
    num_insns: usize,
}

impl<'a, 'b> Iterator for DisassemblyIter<'a, 'b> {
    type Item = Instruction;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bits_consumed >= self.data.len() * 8 {
            return None;
        }

        if let Some(n) = self.disasm.num {
            if self.num_insns >= n as usize {
                return None;
            }
        }

        let mut ctx = self.disasm.ctx.clone();

        while self.bits_consumed / 8 < self.data.len() {
            let pc = Address {
                space: AddressSpace::Ram,
                offset: (self.orig_pc as usize + self.bits_consumed / 8) as u64,
            };

            match self.disasm.disassemble_one(&self.data[self.bits_consumed / 8..], pc, &mut ctx) {
                Some(insn) => {
                    log!(&self.disasm, "0x{:x} {}: {}", insn.address.offset, insn.asm, insn.bit_len);
                    for op in &insn.ops {
                        log!(&self.disasm, "    {}: {}", op.seq, op);
                    }

                    self.bits_consumed += insn.bit_len;
                    self.num_insns += 1;

                    return Some(insn);
                },
                None => {
                    self.bits_consumed += self.disasm.lang.bit_align;
                }
            };
        }

        None
    }
}

impl<'a> Disassembler<'a> {
    pub fn new(
        language_id: String,
        compiler_id: String,
        num: Option<u64>,
        log_modules: &Vec<String>,
        lang: &'a SleighLanguage,
    ) -> Self {
        let mut reg_space: BitVec<u8, Msb0> = BitVec::with_capacity(lang.reg_space_size * 8);
        for _ in 0..(lang.reg_space_size * 8) {
            reg_space.push(false);
        }

        for (var, val) in &lang.language.pspec.defaults {
            if let Some(sym) = lang.context_syms.get(var.as_str()) {
                let start = (lang.context_reg.offset * 8 + (sym.low as u64)) as usize;
                let end = (lang.context_reg.offset * 8 + (sym.high as u64) + 1) as usize;
                let existing = reg_space[start..end].load_be::<u32>();
                reg_space[start..end].store_be(val | existing);
            }
        }

        let log_modules = HashSet::from_iter(log_modules.clone());
        let ctx = read_reg(&lang.context_reg, &reg_space);

        Self {
            language_id,
            compiler_id,
            ctx,
            num,
            lang,
            reg_space,
            build_cache: HashMap::default(),
            log_modules,
            depth: 0,
        }
    }

    pub fn disassemble_one(&mut self, data: &[u8], pc: Address, ctx: &mut Vec<u32>) -> Option<Instruction> {
        resolve_symbol(
            data,
            pc.offset,
            &self.lang.symbols[&self.lang.insn_table_id],
            &self.lang,
            ctx,
            &self.reg_space,
            &self.log_modules,
        ).map(|(matched_symbol, mut num_bits)|{
            if num_bits % self.lang.bit_align != 0 {
                // TODO: bit-hacking.
                num_bits += num_bits - (num_bits % self.lang.bit_align);
            }

            let mut should_insert = false;

            let pcodeops = if let Some(ops) = self.build_cache.get(&matched_symbol) {
                let mut new_ops = ops.clone();

                for op in new_ops.iter_mut() {
                    for i in 0..op.inputs.len() {
                        let input = &mut op.inputs[i];

                        if input.name.as_ref().map(|n| n == "fixup_start" || n == "fixup_end").unwrap_or(false) {
                            input.offset += pc.offset - op.seq.pc.offset; // TODO: Make this work for signed integers.
                        }
                    }

                    op.seq.pc.offset = pc.offset;
                }

                new_ops
            } else {
                let mut ops = build_sym(
                    &matched_symbol,
                    &pc,
                    num_bits,
                    &self.lang,
                );

                for (i, op) in ops.iter_mut().enumerate() {
                    op.seq.uniq = i as i32;
                }

                should_insert = true;
                ops
            };

            let asm = build_text(&matched_symbol, &pcodeops);

            if should_insert {
                self.build_cache.insert(matched_symbol, pcodeops.clone());
            }

            Instruction {
                address: pc,
                bit_len: num_bits,
                asm: asm,
                ops: pcodeops,
            }
        })
    }

    pub fn disassemble<'b>(&'b mut self, buf: &'a [u8], orig_pc: u64) -> DisassemblyIter<'a, 'b> {
        DisassemblyIter {
            disasm: self,
            orig_pc: orig_pc,
            data: buf,
            bits_consumed: 0,
            num_insns: 0,
        }
    }
}
