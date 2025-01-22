use crate::sleigh::types::*;
use crate::parser::*;
use crate::log;

use std::collections::{HashSet, HashMap};
use bitvec::prelude::*;
use std::sync::Arc;
use std::thread;

pub struct Disassembler<'a> {
    language_id: String,
    compiler_id: String,
    ctx: Vec<u32>,
    num: Option<u64>,
    log_modules: HashSet<String>,
    lang: &'a SleighLanguage,
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
    type Item = Option<Instruction>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bits_consumed >= self.data.len() * 8 {
            return None;
        }

        if let Some(n) = self.disasm.num {
            if self.num_insns >= n as usize {
                return None;
            }
        }

        let pc = Address {
            space: AddressSpace::Ram,
            offset: (self.orig_pc as usize + self.bits_consumed / 8) as u64,
        };

        if pc.offset % 0x1000 == 0 {
            println!("0x{:x} / 0x{:x}", pc.offset - self.orig_pc, self.data.len());
        }

        let off = pc.offset;

        let (rv, num_bits) = match self.disasm.disassemble_one(&self.data[self.bits_consumed / 8..], pc) {
            Some(insn) => {
                log!(&self.disasm, "0x{:x} {}: {}", insn.address.offset, insn.asm, insn.bit_len);
                for op in &insn.ops {
                    log!(&self.disasm, "    {}", op);
                }

                let bit_len = insn.bit_len;
                (Some(insn), bit_len)
            },
            None => {
                (None, self.disasm.lang.bit_align)
            }
        };

        self.bits_consumed += num_bits;
        self.num_insns += 1;

        Some(rv)
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

    pub fn disassemble_one(&mut self, data: &[u8], pc: Address) -> Option<Instruction> {
        let mut ctx = self.ctx.clone();

        resolve_symbol(
            data,
            pc.offset,
            &self.lang.symbols[&self.lang.insn_table_id],
            &self.lang,
            &mut ctx,
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
                let ops = build_sym(
                    &matched_symbol,
                    &pc,
                    num_bits,
                    &self.lang,
                );

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

    fn get_instruction_starts(&mut self, buf: &[u8], orig_pc: u64) -> Vec<u64> {
        let mut ctx = read_reg(&self.lang.context_reg, &self.reg_space);
        let mut starts = vec![];
        let mut bits_consumed = 0;

        while bits_consumed < buf.len() * 8 {
            let pc = orig_pc + bits_consumed as u64 / 8;

            let num_bits = resolve_symbol(
                buf,
                pc,
                &self.lang.symbols[&self.lang.insn_table_id],
                &self.lang,
                &mut ctx,
                &self.reg_space,
                &self.log_modules,
            ).map(|(_, mut num_bits)|{
                if num_bits % self.lang.bit_align != 0 {
                    num_bits += num_bits - (num_bits % self.lang.bit_align);
                }
                num_bits
            }).unwrap_or(self.lang.bit_align);

            starts.push(pc);
            bits_consumed += num_bits;
        }

        starts
    }

    pub fn parallel_disassemble(&mut self, buf: &[u8], orig_pc: u64) {
        let starts = self.get_instruction_starts(buf, orig_pc);
        println!("Calculated {} instruction starts", starts.len());

        let num_threads = 8;

        let buf = Arc::new(buf.to_vec());
        let starts = Arc::new(starts);

        let mut handles = vec![];
        // let max_insns = self.args.num.unwrap_or(0xffffffffffffffff) as usize;
        let chunk_size = starts.len() / num_threads;

        for i in 0..num_threads {
            let buf = buf.clone();
            let starts = starts.clone();
            let language_id = self.language_id.clone();
            let compiler_id = self.compiler_id.clone();
            let num = self.num.clone();

            let handle = thread::spawn(move || {
                let lang = SleighLanguage::create(&language_id, &compiler_id);
                let mut disasm = Disassembler::new(language_id, compiler_id, num, &vec![], &lang);

                for (j, start) in starts[i * chunk_size .. (i + 1) * chunk_size].iter().enumerate() {
                    if j % 0x10000 == 0 {
                        println!("{} / {}", j, chunk_size);
                    }

                    let pc = Address {
                        space: AddressSpace::Ram,
                        offset: *start,
                    };

                    if let Some(insn) = disasm.disassemble_one(&buf[(*start - orig_pc) as usize..], pc) {
                    }
                }
            });

            handles.push(handle);
        }

        for handle in handles.into_iter() {
            handle.join().unwrap();
        }
    }
}
