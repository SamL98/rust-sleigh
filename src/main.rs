mod arch;
mod parser;
mod sleigh;
mod utils;

extern crate bitvec;
extern crate nom;

use crate::parser::*;
use crate::patterns::*;
use crate::sleigh::types::Address;
use crate::sleigh::opcode::OpCode;

use bitvec::prelude::*;
use rayon::prelude::*;

use std::collections::HashMap;
use std::string::FromUtf8Error;
use std::env;
use std::fs;

const FILE_BYTES: &[u8] = include_bytes!("/Users/samlerner/Projects/cracks/roots/Payload/Random Roots.app/Random Roots");

fn is_char(c: u8) -> bool {
    (c >= 0x30 && c <= 0x3a) || (c >= 41 && c <= 0x90) || (c >= 0x61 && c <= 0x7a)
}

fn read_str(mut off: usize) -> Result<String, FromUtf8Error> {
    let mut tmp_buf = vec![];
    let mut c = FILE_BYTES[off];

    while is_char(c) {
        tmp_buf.push(c);
        off += 1;
        c = FILE_BYTES[off];
    }


    String::from_utf8(tmp_buf)
}

fn ascii_const(off: u64) -> Result<String, FromUtf8Error> {
    let mut tmp_buf = vec![];
    for i in 0..8 {
        let d = ((off >> (i * 8)) & 0xff) as u8;
        tmp_buf.insert(0, d);
    }

    for (i, c) in tmp_buf.iter().enumerate() {
        if !is_char(*c) && i > 3 {
            return String::from_utf8(tmp_buf[..i].to_vec())
        }
    }

    return String::from_utf8(tmp_buf);
}

fn main() {
    // let args = env::args().collect::<Vec<String>>();
    // let pattern = PcodePattern::new(&args[1]);
    // println!("{:#?}", pattern);

    // let mut syms: HashMap<u64, &str> = HashMap::new();
    // syms.insert(0x1000b8bac, "_objc_msgSend");

    let contents = read_file("AARCH64.sla");
    let lang = SleighLanguage::create("AARCH64", "AARCH64:LE:64:v8A", &contents);

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

    let buf = &FILE_BYTES[0x52b8..0xb7e38];
    let orig_pc = 0x1000052b8;

    // let buf = &FILE_BYTES[0xa33f0..0xb7e38];
    // let orig_pc = 0x1000a33f0;

    const NUM_CHUNKS: usize = 8;

    (0..NUM_CHUNKS)
        .into_par_iter()
        .for_each(|i| {
            let ctx = read_reg(&lang.context_reg, &reg_space);
            let mut bits_consumed = (buf.len() * 8) / NUM_CHUNKS * i;
            // let mut reg_space = reg_space.clone();

            // let mut uniq_space: BitVec<u8, Msb0> = BitVec::with_capacity(0x1000 * 8);
            // for _ in 0..(0x1000 * 8) {
            //     uniq_space.push(false);
            // }

            while bits_consumed < (buf.len() * 8) / NUM_CHUNKS * (i + 1) {
                let pc = Address {
                    space: "ram".to_owned(),
                    offset: (orig_pc + bits_consumed / 8) as u64,
                };

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
                        if lang.bit_align % num_bits != 0 { // TODO: bit-hacking.
                            num_bits += lang.bit_align % num_bits;
                        }

                        let asm = build_text(&matched_symbol);

                        let (pcodeops, _) = build_sym(
                            &matched_symbol,
                            &pc,
                            num_bits,
                            &lang.spaces,
                            &lang.varnode_map,
                        );

                        let mut comment = String::new();

                        for op in &pcodeops {
                            if op.opcode == OpCode::Load && op.inputs[1].is_const() {
                                let off = (op.inputs[1].offset - 0x100000000) as usize;
                                let addr = (FILE_BYTES[off] as usize) |
                                    ((FILE_BYTES[off+1] as usize) << 0x8) |
                                    ((FILE_BYTES[off+2] as usize) << 0x10) |
                                    ((FILE_BYTES[off+3] as usize) << 0x18) |
                                    ((FILE_BYTES[off+4] as usize) << 0x20) |
                                    ((FILE_BYTES[off+5] as usize) << 0x28) |
                                    ((FILE_BYTES[off+6] as usize) << 0x30) |
                                    ((FILE_BYTES[off+7] as usize) << 0x38);
                                // println!("{:x}", addr);

                                if addr > 0x100000000 && addr < (0x100000000 + FILE_BYTES.len()) {
                                    if let Ok(s) = read_str(addr - 0x100000000) {
                                        if s.len() > 0 {
                                            comment = format!(" ; \"{}\"", s);
                                            // println!("{}", s);
                                        }
                                    }
                                }
                            }
                            else if op.opcode == OpCode::IntAdd && op.inputs[0].is_const() && op.inputs[1].is_const() {
                                let addr = (op.inputs[0].offset + op.inputs[1].offset) as usize;

                                if addr > 0x100000000 && addr < (0x100000000 + FILE_BYTES.len()) {
                                    if let Ok(s) = read_str(addr - 0x100000000) {
                                        if s.len() > 0 {
                                            comment = format!(" ; \"{}\"", s);
                                            // println!("{}", s);
                                        }
                                    }
                                }
                            }

                            // for input in &op.inputs {
                            //     if input.is_const() {
                            //         if let Ok(s) = ascii_const(input.offset) {
                            //             println!("{}", s);
                            //         }
                            //     }
                            // }
                        }

                        println!("0x{:x}: {}{}", pc.offset, asm, comment);

                        // for op in &pcodeops {
                        //     eval_op(op, &mut reg_space, &mut uniq_space, &FILE_BYTES);
                        // }

                        // if asm == "bl 0x1000b8bac" {
                        //     // let x1 = read_reg(&lang._varnodes["x1"], &reg_space);
                        //     // println!("0x{:x}", x1);
                        // }

                        // println!("{:#?}\n", pcodeops);
                        num_bits
                    },
                    None => {
                        lang.bit_align
                    }
                };

                // println!("\nInstruction took {} bits", num_bits);
                bits_consumed += num_bits;
            }
        });
}
