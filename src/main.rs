mod arch;
mod parser;
mod sleigh;
mod utils;

extern crate bitvec;
extern crate nom;

use clap::Parser;

use crate::parser::*;
use crate::sleigh::types::{Address, PcodeOp, Instruction};

use bitvec::prelude::*;

use std::time::Instant;
use std::collections::{HashSet, HashMap};
use std::thread;
use std::sync::Arc;
use std::fs::File;
use std::io::Read;

fn parse_hex(s: &str) -> Result<u64, String> {
    Ok(u64hex(s))
}

#[derive(Parser, Debug, Default)]
struct Args {
    #[arg(short, long, value_parser = parse_hex)]
    start_addr: Option<u64>,

    #[arg(short, long, value_parser = parse_hex)]
    end_addr: Option<u64>,

    #[arg(short, long)]
    num: Option<u64>,

    #[arg(short, long)]
    time: bool,

    #[arg(short, long)]
    parallel: bool,

    #[arg(short, long)]
    language_id: String,

    #[arg(short, long)]
    file_name: String,

    #[arg(short = 'm', long = "log")]
    log_modules: Vec<String>,
}

struct Disassembler<'a> {
    args: Args,
    lang: &'a SleighLanguage,
    reg_space: BitVec<u8, Msb0>,
    build_cache: HashMap<MatchedSymbol<'a>, Vec<PcodeOp>>,
    log_modules: HashSet<String>,
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

struct DisassemblyIter<'a> {
    disasm: &'a mut Disassembler<'a>,
    orig_pc: u64,
    data: &'a [u8],
    ctx: Vec<u32>,
    bits_consumed: usize,
    num_insns: usize,
}

impl<'a> Iterator for DisassemblyIter<'a> {
    type Item = Option<Instruction>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bits_consumed >= self.data.len() * 8 {
            return None;
        }

        if let Some(n) = self.disasm.args.num {
            if self.num_insns >= n as usize {
                return None;
            }
        }

        let pc = Address {
            space: "ram".to_owned(),
            offset: (self.orig_pc as usize + self.bits_consumed / 8) as u64,
        };

        if pc.offset % 0x1000 == 0 {
            println!("0x{:x} / 0x{:x}", pc.offset - self.orig_pc, self.data.len());
        }

        let (rv, num_bits) = match self.disasm.disassemble_one(&self.data[self.bits_consumed / 8..], pc, &mut self.ctx.clone()) {
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
    pub fn new(args: Args, lang: &'a SleighLanguage) -> Self {
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

        let log_modules = HashSet::from_iter(args.log_modules.clone());

        Self {
            args: args,
            lang: lang,
            reg_space: reg_space,
            build_cache: HashMap::default(),
            log_modules: log_modules,
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

    pub fn disassemble(&'a mut self, buf: &'a [u8], orig_pc: u64) -> DisassemblyIter {
        let ctx = read_reg(&self.lang.context_reg, &self.reg_space);

        DisassemblyIter {
            disasm: self,
            orig_pc: orig_pc,
            data: buf,
            ctx: ctx,
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
            let language_id = self.args.language_id.clone();

            let handle = thread::spawn(move || {
                let lang = SleighLanguage::create(&language_id);
                let mut disasm = Disassembler::new(Args::default(), &lang);
                let mut ctx = read_reg(&disasm.lang.context_reg, &disasm.reg_space);

                for (j, start) in starts[i * chunk_size .. (i + 1) * chunk_size].iter().enumerate() {
                    if j % 0x10000 == 0 {
                        println!("{} / {}", j, chunk_size);
                    }

                    let pc = Address {
                        space: "ram".to_owned(),
                        offset: *start,
                    };

                    if let Some(insn) = disasm.disassemble_one(&buf[(*start - orig_pc) as usize..], pc, &mut ctx) {
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

fn main() {
    let args = Args::parse();

    let mut file = File::open(&args.file_name).unwrap();
    let mut bytes = vec![];
    file.read_to_end(&mut bytes).unwrap();

    // let mut buf = &bytes[0xe070..0x1cd72e5];
    // let mut orig_pc = 0x10000e070;

    let data_addr = 0x52b8;
    let data_size = 0xb2b80;
    let mut buf = &bytes[data_addr..data_addr + data_size];
    let mut orig_pc = 0x1000052b8;

    // let data_addr = 0x5bb0;
    // let data_size = 0x49d65a;
    // let mut buf = &bytes[data_addr..data_addr + data_size];
    // let mut orig_pc = 0x100005bb0;

    if let Some(addr) = args.start_addr {
        buf = &buf[(addr - orig_pc) as usize..];
        orig_pc = addr;
    }

    if let Some(addr) = args.end_addr {
        buf = &buf[..(addr - orig_pc) as usize];
    }

    let lang = SleighLanguage::create(&args.language_id);

    let start = Instant::now();
    let print_time = args.time;

    if args.parallel {
        let mut disasm = Disassembler::new(args, &lang);
        disasm.parallel_disassemble(&buf, orig_pc);
    } else {
        let mut disasm = Disassembler::new(args, &lang);
        for _ in disasm.disassemble(&buf, orig_pc) {}
    }

    if print_time {
        println!("Disassembly took {}s", ((Instant::now() - start).as_millis() as f64) / 1000.0);
    }
}

#[cfg(test)]
mod tests {
    use crate::sleigh::opcode::OpCode;
    use super::*;

    use ghidra_sleigh::get_context;
    use ghidra_sleigh::Disassembler as GhidraDisassembler;
    use ghidra_sleigh::sleigh::compound_varnode::CompoundVarnodeIface;
    use ghidra_sleigh::sleigh::opcode::OpCode as GhidraOpcode;

    fn normalize_varnode(vn1_offset: u64, vn2_offset: u64, vn2_size: u32, data_addr: usize, data_size: usize) -> (u64, u32) {
        match (vn1_offset, vn2_offset, vn2_size) {
            // (_, 0xffffffff, 8) => (0xffffffffffffffff, 8),
            (_, o2, 4) if o2 > 0xffffffffffff => (o2, 8),
            (o1, o2, 8) if (o1 >> 63) == 1 && (o1 & 0xffffffff) == o2 => (0xffffffff00000000 | o2, 8),
            (o1, o2, sz) if o1 >= data_addr as u64 && o1 < (data_addr + data_size) as u64 && o2 < data_addr as u64 => (o2 | 0x100000000, sz),
            _ => (vn2_offset, vn2_size),
        }
    }

    #[test]
    fn test_scitools() {
        let data_off: usize = 0xe070;
        let data_size: usize = 0x1cc9275;
        let data_addr: usize = 0x10000e070;

        const SCITOOLS: &[u8] = include_bytes!("../test_assets/understand_x64");
        let buf = &SCITOOLS[data_off..(data_off + data_size)];

        // Create Ghidra context.
        let ghidra_ctx = get_context(buf, data_addr, data_size);
        let ghidra_disasm = GhidraDisassembler::new(&ghidra_ctx);
        let mut ghidra_disasm_iter = ghidra_disasm.disassemble(buf, data_addr as u64);

        // Create my context.
        let lang = SleighLanguage::create("x86", "x86:LE:64:default");
        let mut disasm = Disassembler::new(Args::default(), &lang);
        let mut disasm_iter = disasm.disassemble(buf, data_addr as u64);

        while let (Some(insn), Some(ghidra_insn)) = (disasm_iter.next(), ghidra_disasm_iter.next()) {
            if let (Some(insn), Some(ghidra_insn)) = (insn, ghidra_insn) {
                println!("0x{:x}: {} vs. {}", insn.address.offset, insn, ghidra_insn);

                // TODO: Gradually increase this limit.
                if insn.address.offset >= 0x100082706 {
                    break;
                }

                if ghidra_insn.mnemonic == "JMPF" || 
                   ghidra_insn.mnemonic == "RETF" || 
                   ghidra_insn.mnemonic == "IN" || 
                   ghidra_insn.mnemonic == "OUT" || 
                   ghidra_insn.mnemonic == "INT" || 
                   ghidra_insn.mnemonic == "UNPCKLPD" {
                    continue;
                }

                assert_eq!(insn.address.offset, ghidra_insn.address.offset);
                assert_eq!(insn.bit_len / 8, ghidra_insn.length as usize);
                // assert_eq!(insn.asm, ghidra_insn.asm()); // TODO: Implement negative number nomalization.

                // This kinda sucks.
                if insn.ops.len() == 2 && ghidra_insn.ops.len() == 1 && insn.ops[0].opcode == OpCode::Load && insn.ops[1].opcode == OpCode::Copy {
                    continue;
                }

                assert_eq!(insn.ops.len(), ghidra_insn.ops.len());

                for (op1, op2) in insn.ops.iter().zip(ghidra_insn.ops.iter()) {
                    println!("    {} vs. {}", op1, op2);

                    // TODO: Actually check for correctness.
                    match (op1.opcode, op2.opcode) {
                        (OpCode::IntSub, GhidraOpcode::INT_ADD) => continue,
                        (OpCode::IntAdd, GhidraOpcode::INT_SUB) => continue,
                        _ => (),
                    }

                    assert_eq!(format!("{}", op1.opcode).to_uppercase(), op2.opcode.to_str().replace("_", ""));
                    assert_eq!(op1.inputs.len(), op2.inputs.len());

                    for (i, (in1, in2)) in op1.inputs.iter().zip(op2.inputs.iter()).enumerate() {
                        if (op1.opcode == OpCode::Store || op1.opcode == OpCode::Load) && i == 0 {
                            continue;
                        }

                        // Do some fixups for fudging correctness.
                        let (off2, sz2) = normalize_varnode(in1.offset, in2.offset(), in2.size(), data_addr, data_size);
                        assert_eq!(format!("{}", in1.space), format!("{}", in2.space()));
                        assert_eq!(in1.offset, off2);
                        assert_eq!(in1.size, sz2 as u64);
                    }

                    if let (Some(out1), Some(out2)) = (op1.output.as_ref(), op2.output.as_ref()) {
                        let (off2, sz2) = normalize_varnode(out1.offset, out2.offset(), out2.size(), data_addr, data_size);
                        assert_eq!(format!("{}", out1.space), format!("{}", out2.space()));
                        assert_eq!(out1.offset, off2);
                        assert_eq!(out1.size, sz2 as u64);
                    }
                }
            }
        }
    }

    // #[test]
    // fn test_ireal() {
    //     let data_off: usize = 0x5bb0;
    //     let data_size: usize = 0x49d65a;
    //     let data_addr: usize = 0x100005bb0;

    //     const IREAL: &[u8] = include_bytes!("../test_assets/ireal_x64");
    //     let buf = &IREAL[data_off..(data_off + data_size)];

    //     // Create Ghidra context.
    //     let ghidra_ctx = get_context(buf, data_addr, data_size);
    //     let ghidra_disasm = GhidraDisassembler::new(&ghidra_ctx);
    //     let mut ghidra_disasm_iter = ghidra_disasm.disassemble(buf, data_addr as u64);

    //     // Create my context.
    //     let contents = read_file("x86-64.sla");
    //     let lang = SleighLanguage::create("x86", "x86:LE:64:default", &contents);
    //     let mut disasm = Disassembler::new(Args::default(), &lang);
    //     let mut disasm_iter = disasm.disassemble(buf, data_addr as u64);

    //     while let (Some(insn), Some(ghidra_insn)) = (disasm_iter.next(), ghidra_disasm_iter.next()) {
    //         if let (Some(insn), Some(ghidra_insn)) = (insn, ghidra_insn) {
    //             println!("0x{:x}: {} vs. {}", insn.address.offset, insn, ghidra_insn);

    //             // TODO: Gradually increase this limit.
    //             if insn.address.offset >= 0x100082706 {
    //                 break;
    //             }

    //             if ghidra_insn.mnemonic == "JMPF" || 
    //                ghidra_insn.mnemonic == "RETF" || 
    //                ghidra_insn.mnemonic == "IN" || 
    //                ghidra_insn.mnemonic == "OUT" || 
    //                ghidra_insn.mnemonic == "INT" || 
    //                ghidra_insn.mnemonic == "UNPCKLPD" {
    //                 continue;
    //             }

    //             assert_eq!(insn.address.offset, ghidra_insn.address.offset);
    //             assert_eq!(insn.bit_len / 8, ghidra_insn.length as usize);
    //             // assert_eq!(insn.asm, ghidra_insn.asm()); // TODO: Implement negative number nomalization.
    //             assert_eq!(insn.ops.len(), ghidra_insn.ops.len());

    //             for (op1, op2) in insn.ops.iter().zip(ghidra_insn.ops.iter()) {
    //                 println!("    {} vs. {}", op1, op2);

    //                 // TODO: Actually check for correctness.
    //                 match (op1.opcode, op2.opcode) {
    //                     (OpCode::IntSub, GhidraOpcode::INT_ADD) => continue,
    //                     (OpCode::IntAdd, GhidraOpcode::INT_SUB) => continue,
    //                     _ => (),
    //                 }

    //                 assert_eq!(format!("{}", op1.opcode).to_uppercase(), op2.opcode.to_str().replace("_", ""));
    //                 assert_eq!(op1.inputs.len(), op2.inputs.len());

    //                 for (i, (in1, in2)) in op1.inputs.iter().zip(op2.inputs.iter()).enumerate() {
    //                     if (op1.opcode == OpCode::Store || op1.opcode == OpCode::Load) && i == 0 {
    //                         continue;
    //                     }

    //                     // Do some fixups for fudging correctness.
    //                     let (off2, sz2) = match (op1.opcode, in1.offset, in2.offset(), in2.size()) {
    //                         // (_, 0xffffffff, 8) => (0xffffffffffffffff, 8),
    //                         (_, o1, o2, 8) if (o1 >> 63) == 1 && (o1 & 0xffffffff) == o2 => (0xffffffff00000000 | o2, 8),
    //                         (_, o1, o2, sz) if o1 >= data_addr as u64 && o1 < (data_addr + data_size) as u64 && o2 < data_addr as u64 => (o2 | 0x100000000, sz),
    //                         (_, _, o2, 4) if o2 > 0xffffffffffff => (o2, 8),
    //                         (OpCode::FloatTrunc, _, o2, 8) => (o2, 4),
    //                         _ => (in2.offset(), in2.size()),
    //                     };

    //                     assert_eq!(format!("{}", in1.space), format!("{}", in2.space()));
    //                     assert_eq!(in1.offset, off2);
    //                     assert_eq!(in1.size, sz2 as u64);
    //                 }

    //                 if let (Some(out1), Some(out2)) = (op1.output.as_ref(), op2.output.as_ref()) {
    //                     let (off2, sz2) = match (format!("{}", out1.space).as_str(), out1.offset, out1.size, out2.offset(), out2.size()) {
    //                         ("ram", _, sz, o2, _) => (o2, sz as u32),
    //                         (_, _, _, 0xffffffff, 8) => (0xffffffffffffffff, 8),
    //                         (_, o1, _, o2, sz) if o1 >= data_addr as u64 && o1 < (data_addr + data_size) as u64 && o2 < data_addr as u64 => (o2 | 0x100000000, sz),
    //                         (_, _, _, o2, 4) if o2 > 0xffffffff => (o2, 8),
    //                         _ => (out2.offset(), out2.size()),
    //                     };

    //                     assert_eq!(format!("{}", out1.space), format!("{}", out2.space()));
    //                     assert_eq!(out1.offset, off2);
    //                     assert_eq!(out1.size, sz2 as u64);
    //                 }
    //             }
    //         }
    //     }
    // }
}
