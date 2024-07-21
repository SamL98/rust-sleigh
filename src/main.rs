mod arch;
mod parser;
mod sleigh;
mod utils;

extern crate bitvec;
extern crate nom;

use crate::arch::get_language;
use crate::parser::*;
use crate::sleigh::types::Address;

use nom::branch::*;
use nom::bytes::complete::*;
use nom::character::complete::*;
use nom::character::*;
use nom::combinator::*;
use nom::error::*;
use nom::multi::*;
use nom::sequence::*;
use nom::*;

use bitvec::prelude::*;

use termios::{Termios, TCSANOW, ECHO, ICANON, tcsetattr};
use std::io::{self, Read, Seek};
use std::fs;

use std::collections::{HashMap, HashSet};
use gpgpu::{Framework, GpuBuffer, GpuBufferUsage, DescriptorSet, Kernel, BufOps, Shader};
use gpgpu;

fn _explore_dtree(
    dtree: &DecisionTree,
    depth: usize,
    line: usize,
    selected_line: usize,
    open_idxs: &HashSet<usize>,
    table: &Subtable,
) -> usize {
    let mut num_lines = 0;

    match dtree {
        DecisionTree::NonLeaf((is_context, start, size, children)) => {
            let c = if line == selected_line { '>' } else { ' ' };
            println!("{} {}+ ({}, {}, {})", c, " ".repeat(depth * 2), start, size, is_context);
            num_lines += 1;

            if open_idxs.contains(&line) {
                for child in children {
                    num_lines += _explore_dtree(
                        child,
                        depth + 1,
                        line + num_lines,
                        selected_line,
                        open_idxs,
                        table
                    );
                }
            }
        },
        DecisionTree::Leaf(pairs) => {
            for (ct_id, pattern) in pairs {
                let c = if line + num_lines == selected_line { '>' } else { ' ' };
                let ct = &table.constructors[*ct_id as usize];
                println!("{} {}{:?}", c, " ".repeat(depth * 2), ct.print_commands);
                num_lines += 1
            }
        },
    };

    num_lines
}

fn explore_dtree(
    dtree: &DecisionTree,
    selected_line: usize,
    open_idxs: &HashSet<usize>,
    table: &Subtable,
) {
    _explore_dtree(dtree, 0, 0, selected_line, open_idxs, table);
}

fn main() {
    //let fw = Framework::default();

    //// Original CPU data
    //let cpu_data = (0..10000).into_iter().collect::<Vec<u32>>();

    //// GPU buffer creation
    //let buf_a = GpuBuffer::from_slice(&fw, &cpu_data);       // Input
    //let buf_b = GpuBuffer::from_slice(&fw, &cpu_data);       // Input
    //let buf_c = GpuBuffer::<u32>::with_capacity(&fw, cpu_data.len() as u64);  // Output

    //// Shader load from SPIR-V binary file
    //let shader = Shader::from_wgsl_file(&fw, "src/foo.wgsl").unwrap();    

    //// Descriptor set and program creation
    //let desc = DescriptorSet::default()
    //    .bind_buffer(&buf_a, GpuBufferUsage::ReadOnly)
    //    .bind_buffer(&buf_b, GpuBufferUsage::ReadOnly)
    //    .bind_buffer(&buf_c, GpuBufferUsage::ReadWrite);
    //let program = gpgpu::Program::new(&shader, "main").add_descriptor_set(desc); // Entry point

    //// Kernel creation and enqueuing
    //Kernel::new(&fw, program).enqueue(cpu_data.len() as u32, 1, 1); // Enqueuing, not very optimus

    //let output = buf_c.read_vec_blocking().unwrap();                        // Read back C from GPU
    //for (a, b) in cpu_data.into_iter().zip(output) {
    //    assert_eq!(a.pow(2), b);
    //}
    //println!("all good");
	//return;

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

    // let termios = Termios::from_fd(0).unwrap();
    // let mut new_termios = termios.clone();
    // new_termios.c_lflag &= !(ICANON | ECHO);
    // tcsetattr(0, TCSANOW, &mut new_termios).unwrap();

    // if let SymbolBody::Subtable(table) = &lang.symbols[&lang.insn_table_id].body {
    //     let mut open_idxs = HashSet::new();
    //     let mut selected_line = 0;

    //     'outer: loop {
    //         println!("\x1b[2J\x1b[H");
    //         explore_dtree(&table.decision_tree, selected_line, &open_idxs, table);

    //         let mut buf = [0; 1];
    //         io::stdin().read_exact(&mut buf).unwrap();
            
    //         match (buf[0] as char) {
    //             'q' => break 'outer,
    //             'j' => selected_line += 1,
    //             'k' => selected_line -= 1,
    //             '\n' => {
    //                 if open_idxs.contains(&selected_line) {
    //                     open_idxs.remove(&selected_line);
    //                 } else {
    //                     open_idxs.insert(selected_line);
    //                 }
    //             }
    //             _ => {}
    //         }
    //     }
    // }

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

    let binary_path = "/Users/samlerner/Projects/cracks/scitools/understand_x64";
    let mut target_file = fs::File::open(binary_path).expect(format!("Could not open
             {}", binary_path).as_str());

    let mut raw_bytes: Vec<u8> = Vec::new();
    let _ = target_file.read_to_end(&mut raw_bytes);
    let buf = &raw_bytes[0xe070..0x1cd72e5];
        
    let mut bits_consumed = 0;

    let mut ctx = read_ctx(&lang.context_reg, &reg_space);

    while bits_consumed < buf.len() * 8 {
        let mut tmp_buf: Vec<u8> = buf[bits_consumed / 8..].to_vec();
        tmp_buf[0] = tmp_buf[0].overflowing_shl((bits_consumed % 8) as u32).0;

        let (matched_symbol, num_bits) = resolve_symbol(
            &tmp_buf,
            &lang.symbols[&lang.insn_table_id],
            &lang.symbols,
            &mut ctx.clone(),
        ).unwrap();

        bits_consumed += num_bits;

        println!("{} {}", num_bits, bits_consumed);
        // println!("{:#?}", matched_symbol);

        let pc = Address {
            space: "ram".to_owned(),
            offset: 0x1337,
        };

        let (pcodeops, _) = build_sym(
            &matched_symbol,
            &pc,
            &lang.spaces,
            &lang.varnode_map,
        );
        println!("{:#?}", pcodeops);

        let asm = build_text(&matched_symbol);
        println!("{}", asm);
    }
}
