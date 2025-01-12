mod arch;
mod parser;
mod sleigh;
mod utils;

extern crate bitvec;
extern crate nom;

use crate::parser::*;
use crate::sleigh::types::Address;
use crate::sleigh::opcode::OpCode;

use bitvec::prelude::*;

use std::collections::HashMap;
use std::string::FromUtf8Error;
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::time::Instant;

// const FILE_BYTES: &[u8] = include_bytes!("/Users/samlerner/Projects/cracks/roots/Payload/Random Roots.app/Random Roots");
const FILE_BYTES: &[u8] = include_bytes!("/Users/samlerner/Projects/cracks/scitools/understand_x64");

fn main() {
    // let args = env::args().collect::<Vec<String>>();
    // let pattern = PcodePattern::new(&args[1]);
    // println!("{:#?}", pattern);

    // let mut syms: HashMap<u64, &str> = HashMap::new();
    // syms.insert(0x1000b8bac, "_objc_msgSend");

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

    // let buf = &FILE_BYTES[0x52b8..0xb7e38];
    // let orig_pc = 0x1000052b8;

    let buf = &FILE_BYTES[0xe070..0x1cd72e5];
    let orig_pc = 0x10000e070;

    // let a = 0x10000e08d;
    // let buf = &buf[(a - orig_pc)..(a - orig_pc + 5)];
    // let orig_pc = a;

    // let buf = &FILE_BYTES[0xa33f0..0xb7e38];
    // let orig_pc = 0x1000a33f0;

    let ctx = read_reg(&lang.context_reg, &reg_space);
    let mut bits_consumed = 0;

    let mut file = File::create("insns.txt").unwrap();
    let start = Instant::now();

    while bits_consumed < buf.len() * 8 {
        let pc = Address {
            space: "ram".to_owned(),
            offset: (orig_pc + bits_consumed / 8) as u64,
        };

        if pc.offset % 0x1000 == 0 {
            println!("0x{:x} / 0x{:x}", (pc.offset as usize) - orig_pc, buf.len());
        }

        // let b = bits_consumed / 8;
        // println!("{} {:?}", bits_consumed, &buf[b..(b+4)]);

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

                let asm = build_text(&matched_symbol);

                let pcodeops = build_sym(
                    &matched_symbol,
                    &pc,
                    num_bits,
                    &lang.spaces,
                    &lang.varnode_map,
                );

                // println!("0x{:x} {}: {}", pc.offset, asm, num_bits);

                // for op in &pcodeops {
                //     println!("    {}", op);
                // }

                writeln!(file, "0x{:x} ~~ {} ~~ {} ~~ {}", pc.offset, asm, num_bits / 8, pcodeops.len());

                for op in &pcodeops {
                    writeln!(file, "    {}", op);
                }

                num_bits
            },
            None => {
                lang.bit_align
            }
        };

        // println!("\nInstruction took {} bits", num_bits);
        bits_consumed += num_bits;
    }

    // println!("Took {}s to complete", start.elapsed().as_secs());
}
