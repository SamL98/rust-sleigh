mod arch;
mod parser;
mod sleigh;
mod utils;

extern crate bitvec;
extern crate nom;

use clap::Parser;

use crate::parser::*;
use crate::sleigh::types::Address;
// use crate::sleigh::opcode::OpCode;

use bitvec::prelude::*;

use std::fs::File;
use std::io::Write;
use std::time::Instant;

fn parse_hex(s: &str) -> Result<u64, String> {
    Ok(u64hex(s))
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, value_parser = parse_hex)]
    addr: Option<u64>,

    #[arg(short, long)]
    num: Option<u64>,

    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

// const FILE_BYTES: &[u8] = include_bytes!("/Users/samlerner/Projects/cracks/roots/Payload/Random Roots.app/Random Roots");
const FILE_BYTES: &[u8] = include_bytes!("/Users/samlerner/Projects/cracks/scitools/understand_x64");

fn main() {
    let args = Args::parse();

    // let contents = read_file("AARCH64.sla");
    // let lang = SleighLanguage::create("AARCH64", "AARCH64:LE:64:v8A", &contents);

    let contents = read_file("x86-64.sla");
    let lang = SleighLanguage::create("x86", "x86:LE:64:default", &contents);

    // Create a bit vector for the entire register space.
    // TODO: Figure out how to properly initialize the BitVec.
    let mut reg_space: BitVec<u8, Msb0> = BitVec::with_capacity(lang.reg_space_size * 8);
    for _ in 0..(lang.reg_space_size * 8) {
        reg_space.push(false);
    }

    for (var, val) in lang.language.pspec.defaults {
        if let Some(sym) = lang.context_syms.get(var.as_str()) {
            let start = (lang.context_reg.offset * 8 + (sym.low as u64)) as usize;
            let end = (lang.context_reg.offset * 8 + (sym.high as u64) + 1) as usize;
            let existing = reg_space[start..end].load_be::<u32>();
            reg_space[start..end].store_be(val | existing);
        }
    }

    let mut buf = &FILE_BYTES[0xe070..0x1cd72e5];
    let mut orig_pc = 0x10000e070;

    if let Some(addr) = args.addr {
        buf = &buf[(addr - orig_pc) as usize..];
        orig_pc = addr;
    }

    let ctx = read_reg(&lang.context_reg, &reg_space);
    let mut bits_consumed = 0;
    let mut num_insns = 0;

    let mut file = File::create("insns.txt").unwrap();
    let start = Instant::now();

    while bits_consumed < buf.len() * 8 {
        if let Some(n) = args.num {
            if num_insns >= n {
                break;
            }
        }

        let pc = Address {
            space: "ram".to_owned(),
            offset: (orig_pc as usize + bits_consumed / 8) as u64,
        };

        if pc.offset % 0x1000 == 0 {
            println!("0x{:x} / 0x{:x}", pc.offset - orig_pc, buf.len());
        }

        let num_bits = match resolve_symbol(
            &buf[bits_consumed / 8..],
            pc.offset,
            &lang.symbols[&lang.insn_table_id],
            &lang.symbols,
            &mut ctx.clone(),
            &reg_space,
            &mut ResolverDebug::default(),
        ) {
            Some((matched_symbol, mut num_bits)) => {
                if num_bits % lang.bit_align != 0 {
                    // TODO: bit-hacking.
                    num_bits += num_bits - (num_bits % lang.bit_align);
                }

                let pcodeops = build_sym(
                    &matched_symbol,
                    &pc,
                    num_bits,
                    &lang.spaces,
                    &lang.varnode_map,
                );

                let asm = build_text(&matched_symbol, &pcodeops);

                if args.verbose {
                    println!("0x{:x} {}: {}", pc.offset, asm, num_bits);
                    for op in &pcodeops {
                        println!("    {}", op);
                    }
                }

                let _ = writeln!(file, "0x{:x} ~~ {} ~~ {} ~~ {}", pc.offset, asm, num_bits / 8, pcodeops.len());
                for op in &pcodeops {
                    let _ = writeln!(file, "    {}", op);
                }

                num_bits
            },
            None => {
                lang.bit_align
            }
        };

        // println!("\nInstruction took {} bits", num_bits);
        bits_consumed += num_bits;
        num_insns += 1;
    }

    println!("Took {}s to complete", start.elapsed().as_secs());
}
