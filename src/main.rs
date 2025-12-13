mod utils;
mod logger;
mod sleigh;
mod arch;
mod sla_parser;
mod symbol_resolver;
mod pcode_builder;
mod disassembler;

extern crate bitvec;
extern crate nom;

use crate::sla_parser::*;
use crate::disassembler::Disassembler;

use std::io::{Read, Write};
use std::time::Instant;
use std::fs::File;

#[cfg(feature = "bin")]
use object::{Object, ObjectSection, SectionKind};

#[cfg(feature = "bin")]
use clap::Parser;

fn parse_hex(s: &str) -> Result<u64, String> {
    Ok(u64hex(s))
}

#[cfg(feature = "bin")]
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
    language_id: String,

    #[arg(short, long)]
    compiler_id: String,

    #[arg(short, long)]
    file_name: String,

    #[arg(short = 'm', long = "log")]
    log_modules: Vec<String>,

    #[arg(long = "print_asm")]
    print_asm: bool,

    #[arg(long = "print_pcode")]
    print_pcode: bool,
}

#[cfg(feature = "bin")]
fn main() {
    let args = Args::parse();

    let lang_id = args.language_id.clone();
    let comp_id = args.compiler_id.clone();

    let mut file = File::open(&args.file_name).unwrap();
    let mut bytes = vec![];
    file.read_to_end(&mut bytes).unwrap();

    let start = Instant::now();
    let print_time = args.time;
    let num = args.num;

    let mut disasm = Disassembler::new(lang_id, comp_id, num, &args.log_modules);

    let obj = object::File::parse(&*bytes).unwrap();
    let mut num_bytes = 0;
    let mut num_insns = 0;

    let mut start_addr = args.start_addr.unwrap_or(u64::MAX);
    let end_addr = args.end_addr.unwrap_or(u64::MAX);
    let max_insns = args.num.unwrap_or(u64::MAX);

    let print_progress = !(args.print_asm || args.print_pcode) && args.log_modules.is_empty();

    'outer: for section in obj.sections() {
        if section.kind() == SectionKind::Text {
            let mut addr = section.address();
            let size = section.size();

            if let Some((off, _)) = section.file_range() {
                let mut start = off as usize;
                let end = (off + size) as usize;

                if start_addr != u64::MAX {
                    if start_addr < addr || start_addr >= (addr + size) {
                        continue;
                    }

                    let delta = start_addr - addr;
                    start += delta as usize;
                    addr += delta;
                    start_addr = addr + size;
                }

                const NUM_TICKS: usize = 30;
                let mut prev_num_ticks = 0;

                if print_progress {
                    print!("[{}]", ".".repeat(NUM_TICKS));
                    std::io::stdout().flush().unwrap();
                }

                for insn in disasm.disassemble(&bytes[start..end], addr) {
                    num_insns += 1;
                    num_bytes += insn.bit_len / 8;

                    if print_progress {
                        let num_ticks = (((insn.address.offset - addr) as f64 / (end - start) as f64) * (NUM_TICKS as f64)) as usize;
                        if num_ticks != prev_num_ticks {
                            print!("\x1b[2K\r[{}{}]", "+".repeat(num_ticks), ".".repeat(NUM_TICKS - num_ticks));
                            std::io::stdout().flush().unwrap();
                            prev_num_ticks = num_ticks;
                        }
                    }

                    if args.print_asm {
                        println!("0x{:x}: {}", insn.address.offset, insn.asm);
                    }

                    if args.print_pcode {
                        for op in &insn.ops {
                            println!("    {}: {}", op.seq, op);
                        }
                    }

                    if num_insns > max_insns || (end_addr != u64::MAX && insn.address.offset >= end_addr) {
                        break 'outer;
                    }
                }

                if print_progress {
                    println!();
                }
            }
        }
    }

    if print_time {
        println!(
            "Disassembled {} bytes ({} instructions) in {}s",
            num_bytes, 
            num_insns,
            ((Instant::now() - start).as_millis() as f64) / 1000.0
        );
    }
}
