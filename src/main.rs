mod arch;
pub mod parser;
mod sleigh;
mod utils;
pub mod disasm;

extern crate bitvec;
extern crate nom;

use clap::Parser;

use crate::parser::*;
use crate::disasm::Disassembler;

use std::time::Instant;
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

fn main() {
    let args = Args::parse();

    let mut file = File::open(&args.file_name).unwrap();
    let mut bytes = vec![];
    file.read_to_end(&mut bytes).unwrap();

    // let mut buf = &bytes[0xe070..0x1cd72e5];
    // let mut orig_pc = 0x10000e070;

    // let data_addr = 0x52b8;
    // let data_size = 0xb2b80;
    // let mut orig_pc = 0x1000052b8;
    let data_addr = 11200;
    let data_size = 0x3439f4;
    let mut orig_pc = 0x100002bc0;
    let mut buf = &bytes[data_addr..data_addr + data_size];

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

    let start = Instant::now();
    let print_time = args.time;
    let lang_id = args.language_id.clone();
    let comp_id = "gcc".to_string();
    let num = args.num.clone();

    let lang = SleighLanguage::create(&lang_id, &comp_id);

    if args.parallel {
        let mut disasm = Disassembler::new(lang_id, comp_id, num, &args.log_modules, &lang);
        disasm.parallel_disassemble(&buf, orig_pc);
    } else {
        let mut disasm = Disassembler::new(lang_id, comp_id, num, &args.log_modules, &lang);
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
        let lang_id = "x86:LE:64:default".to_string();
        let comp_id = "gcc".to_string();
        let lang = SleighLanguage::create(&lang_id, &comp_id);
        let mut disasm = Disassembler::new(lang_id, comp_id, None, &vec![], &lang);
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
