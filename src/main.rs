mod arch;
mod parser;
mod sleigh;
mod utils;

extern crate bitvec;
extern crate nom;

use crate::arch::get_language;
use crate::parser::*;
use crate::sleigh::types::Address;

use bitvec::prelude::*;

use std::io::{self, Read, Seek};
use std::fs;

use std::collections::{HashMap, HashSet};

fn main() {
    let contents = read_file("x86-64.sla");
    let lang = SleighLanguage::create("x86", "x86:LE:64:default", &contents);
    // let insn_table = get_table(insn_table_id, &symbols);

    // Create a bit vector for the entire register space.
    // TODO: Figure out how to properly initialize the BitVec.
    let mut reg_space: BitVec<u8, Msb0> = BitVec::with_capacity(lang.reg_space_size * 8);
    for _ in 0..(lang.reg_space_size * 8) {
        reg_space.push(false);
    }

    for (var, val) in lang.language.pspec.defaults {
        // println!("{} {:?}", var, lang.context_syms.get(var.as_str()));
        if let Some(sym) = lang.context_syms.get(var.as_str()) {
            let start = (lang.context_reg.offset * 8 + (sym.low as u64)) as usize;
            let end = (lang.context_reg.offset * 8 + (sym.high as u64) + 1) as usize;
            // println!("{}, {}, {}, {}", var, start, end, val);
            let existing = reg_space[start..end].load_be::<u32>();
            reg_space[start..end].store_be(val | existing);
        }
    }

    //println!("{:#?}", tables["Reg8"][0].decision_tree);
    //let data: [u8; 1] = [0x55];
    // let word = 0x55000000;
    // let word = 0x53000000;
    // let word = 0x554889e5;
    // let word = 0x4889e500;
    // let buf = vec![0x55];
    // let buf = vec![0x41, 0x54];
    // let buf = vec![0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56];
    // let buf = vec![0x48, 0x89, 0xe5];

    // let binary_path = "/Users/sam/scratch/rust-sleigh/test";
    let binary_path = "/Users/samlerner/Projects/ideco_PUBLIC/test_cases/simple_linked_list";
    let mut target_file = fs::File::open(binary_path).expect(format!("Could not open
             {}", binary_path).as_str());

    let mut raw_bytes: Vec<u8> = Vec::new();
    let _ = target_file.read_to_end(&mut raw_bytes);
    // let buf = &raw_bytes[0x3f20..0x3f95];
    // let orig_pc = 0x100003f20;

    let buf = &raw_bytes[0x3dc0..0x3eb3];
    let orig_pc = 0x100003dc0;
        
    let mut bits_consumed = 0;

    let mut ctx = read_ctx(&lang.context_reg, &reg_space);

    while bits_consumed < buf.len() * 8 {
        let mut tmp_buf: Vec<u8> = buf[bits_consumed / 8..].to_vec();
        // tmp_buf[0] = tmp_buf[0].overflowing_shl((bits_consumed % 8) as u32).0;

        let pc = Address {
            space: "ram".to_owned(),
            offset: (orig_pc + bits_consumed / 8) as u64,
        };

        let (matched_symbol, num_bits) = resolve_symbol(
            &tmp_buf,
            pc.offset,
            &lang.symbols[&lang.insn_table_id],
            &lang.symbols,
            &mut ctx.clone(),
            &mut ResolverDebug::default(),
        ).unwrap();

        bits_consumed += num_bits;
        // println!("\nInstruction took {} bits", num_bits);

        // println!("{} {}", num_bits, bits_consumed);
        // println!("{:#?}", matched_symbol);

        let asm = build_text(&matched_symbol);
        println!("0x{:x}: {}", pc.offset, asm);

        let (pcodeops, _) = build_sym(
            &matched_symbol,
            &pc,
            num_bits,
            &lang.spaces,
            &lang.varnode_map,
            (false, 0),
        );

        // if pc.offset == 0x100003e29 {
        //     break
        // }
        
        // println!("{:#?}\n", pcodeops);
    }
}
