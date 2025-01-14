mod arch;
mod parser;
mod sleigh;
mod utils;

extern crate bitvec;
extern crate nom;

use clap::Parser;

use crate::parser::*;
use crate::sleigh::types::{Address, Instruction};

use bitvec::prelude::*;

fn parse_hex(s: &str) -> Result<u64, String> {
    Ok(u64hex(s))
}

#[derive(Parser, Debug, Default)]
struct Args {
    #[arg(short, long, value_parser = parse_hex)]
    addr: Option<u64>,

    #[arg(short, long)]
    num: Option<u64>,

    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

// const FILE_BYTES: &[u8] = include_bytes!("/Users/samlerner/Projects/cracks/roots/Payload/Random Roots.app/Random Roots");
const FILE_BYTES: &[u8] = include_bytes!("../test_assets/understand_x64");

struct Disassembler<'a> {
    args: Args,
    lang: &'a SleighLanguage,
    reg_space: BitVec<u8, Msb0>,
}

struct DisassemblyIter<'a> {
    disasm: &'a Disassembler<'a>,
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
                if self.disasm.args.verbose {
                    println!("0x{:x} {}: {}", insn.address.offset, insn.asm, insn.bit_len);
                    for op in &insn.ops {
                        println!("    {}", op);
                    }
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

        Self {
            args: args,
            lang: lang,
            reg_space: reg_space,
        }
    }

    pub fn disassemble_one(&self, data: &[u8], pc: Address, ctx: &mut Vec<u32>) -> Option<Instruction> {
        resolve_symbol(
            data,
            pc.offset,
            &self.lang.symbols[&self.lang.insn_table_id],
            &self.lang.symbols,
            ctx,
            &self.reg_space,
            &mut ResolverDebug::default(),
        ).map(|(matched_symbol, mut num_bits)|{
            if num_bits % self.lang.bit_align != 0 {
                // TODO: bit-hacking.
                num_bits += num_bits - (num_bits % self.lang.bit_align);
            }

            let pcodeops = build_sym(
                &matched_symbol,
                &pc,
                num_bits,
                &self.lang.spaces,
                &self.lang.varnode_map,
            );

            let asm = build_text(&matched_symbol, &pcodeops);

            Instruction {
                address: pc,
                bit_len: num_bits,
                asm: asm,
                ops: pcodeops,
            }
        })
    }

    pub fn disassemble(&'a self, buf: &'a [u8], orig_pc: u64) -> DisassemblyIter {
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
}

fn main() {
    let args = Args::parse();

    let mut buf = &FILE_BYTES[0xe070..0x1cd72e5];
    let mut orig_pc = 0x10000e070;

    if let Some(addr) = args.addr {
        buf = &buf[(addr - orig_pc) as usize..];
        orig_pc = addr;
    }

    let contents = read_file("x86-64.sla");
    let lang = SleighLanguage::create("x86", "x86:LE:64:default", &contents);
    let disasm = Disassembler::new(args, &lang);

    for _ in disasm.disassemble(&buf, orig_pc) {}
}

#[cfg(test)]
mod tests {
    use crate::sleigh::opcode::OpCode;
    use super::*;

    use ghidra_sleigh::get_context;
    use ghidra_sleigh::Disassembler as GhidraDisassembler;
    use ghidra_sleigh::sleigh::compound_varnode::CompoundVarnodeIface;
    use ghidra_sleigh::sleigh::opcode::OpCode as GhidraOpcode;

    #[test]
    fn test_scitools() {
        let data_off: usize = 0xe070;
        let data_size: usize = 0x1cc9275;
        let data_addr: usize = 0x10000e070;

        let buf = &FILE_BYTES[data_off..(data_off + data_size)];
        let orig_pc: u64 = 0x10000e070;

        // Create Ghidra context.
        let ghidra_ctx = get_context(buf, data_addr, data_size);
        let ghidra_disasm = GhidraDisassembler::new(&ghidra_ctx);
        let mut ghidra_disasm_iter = ghidra_disasm.disassemble(buf, data_addr as u64);

        // Create my context.
        let contents = read_file("x86-64.sla");
        let lang = SleighLanguage::create("x86", "x86:LE:64:default", &contents);
        let disasm = Disassembler::new(Args::default(), &lang);
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
                        let (off2, sz2) = match (in1.offset, in2.offset(), in2.size()) {
                            // (_, 0xffffffff, 8) => (0xffffffffffffffff, 8),
                            (o1, o2, 8) if (o1 >> 63) == 1 && (o1 & 0xffffffff) == o2 => (0xffffffff00000000 | o2, 8),
                            (o1, o2, sz) if o1 >= data_addr as u64 && o1 < (data_addr + data_size) as u64 && o2 < data_addr as u64 => (o2 | 0x100000000, sz),
                            (_, o2, 4) if o2 > 0xffffffffffff => (o2, 8),
                            _ => (in2.offset(), in2.size()),
                        };

                        assert_eq!(format!("{}", in1.space), format!("{}", in2.space()));
                        assert_eq!(in1.offset, off2);
                        assert_eq!(in1.size, sz2 as u64);
                    }

                    if let (Some(out1), Some(out2)) = (op1.output.as_ref(), op2.output.as_ref()) {
                        let (off2, sz2) = match (out1.offset, out2.offset(), out2.size()) {
                            (_, 0xffffffff, 8) => (0xffffffffffffffff, 8),
                            (o1, o2, sz) if o1 >= data_addr as u64 && o1 < (data_addr + data_size) as u64 && o2 < data_addr as u64 => (o2 | 0x100000000, sz),
                            (_, o2, 4) if o2 > 0xffffffff => (o2, 8),
                            _ => (out2.offset(), out2.size()),
                        };

                        assert_eq!(format!("{}", out1.space), format!("{}", out2.space()));
                        assert_eq!(out1.offset, off2);
                        assert_eq!(out1.size, sz2 as u64);
                    }
                }
            }
        }
    }
}
