use fxhash::{FxHashMap, FxHashSet};

use deco::sleigh::arch::get_context;
use deco::sleigh::ContextIface;
use deco::sleigh::types::{Context, SsaCompoundVarnode, Address, Instruction};
use deco::utils::*;

use std::fmt::Display;
use std::fs::{self, File};
use std::io;
use std::io::{Read, Write, Seek};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::thread;

fn main() {
    let mut ctx = Arc::new(get_context("x86", "x86:LE:64:default", "gcc").unwrap());

    // let binary_path = "/Users/samlerner/Projects/MyDeco/test_cases/rust";
    // let binary_path = "/Users/samlerner/Projects/MyDeco/test_cases/playback.dylib";
    let binary_path = "/Users/samlerner/Projects/cracks/scitools/understand_x64";
    let mut target_file = fs::File::open(binary_path).expect(format!("Could not open {}", binary_path).as_str());

    let mut raw_bytes: Vec<u8> = Vec::new();
    let _ = target_file.read_to_end(&mut raw_bytes);
    // let binary_path = "/Users/samlerner/Projects/MyDeco/test_cases/playback.dylib";
    // let mut bin_file = fs::File::open(binary_path).unwrap();

    let data_off: usize = 57456;
    let data_size: usize = 0x1cc9275;
    let data_addr: usize = 0x10000e070;
    let data = &raw_bytes[data_off..(data_off + data_size)];

    ctx.set_data(data);
    ctx.add_segment(data_addr as u64, 0, data_size as u32);

    let mut file = File::create("insns.txt").unwrap();
    let mut pc = data_addr;

    let start = Instant::now();

    while pc < data_addr + data_size {
        if pc % 0x1000 == 0 {
            println!("0x{:x} / 0x{:x}", pc - data_addr, data_size);
        }

        if let Some(insn) = ctx.disassemble_one(pc as u64) {
            pc += insn.length as usize;

            let asm = if insn.body.len() > 0 {
                format!("{} {}", insn.mnemonic, insn.body)
            } else {
                insn.mnemonic.clone()
            };

            writeln!(file, "{} ~~ {} ~~ {} ~~ {}", insn.address, asm, insn.length, insn.ops.len());

            for op in &insn.ops {
                writeln!(file, "    {}", op);
            }
        } else {
            pc += 1;
        }
    }

    println!("{}s to complete", start.elapsed().as_secs());
}
