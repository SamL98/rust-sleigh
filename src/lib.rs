use wasm_bindgen::prelude::*;
use console_error_panic_hook;

mod arch;
mod parser;
mod sleigh;
mod utils;

use crate::arch::get_language;
use crate::parser::*;
use crate::sleigh::types::Address;

use bitvec::prelude::*;

#[wasm_bindgen]
extern {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen(module = "/utils.js")]
extern "C" {
    pub fn sync_fetch(url: &str) -> String;
}

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn do_get_request(url: &str) -> String {
    sync_fetch(url)
}

const FILE_BYTES: &[u8] = include_bytes!("/Users/samlerner/Projects/ideco_PUBLIC/test_cases/simple_linked_list");

#[wasm_bindgen]
pub fn disassemble() {
    init_panic_hook();

    let contents = read_file("x86-64.sla");
    let lang = SleighLanguage::create("x86", "x86:LE:64:default", &contents);

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

    let buf = &FILE_BYTES[0x3dc0..0x3eb3];
    let orig_pc: u64 = 0x100003dc0;
        
    let mut bits_consumed = 0;

    let mut ctx = read_ctx(&lang.context_reg, &reg_space);

    while bits_consumed < buf.len() * 8 {
        let mut tmp_buf: Vec<u8> = buf[bits_consumed / 8..].to_vec();
        tmp_buf[0] = tmp_buf[0].overflowing_shl((bits_consumed % 8) as u32).0;

        let pc = Address {
            space: "ram".to_owned(),
            offset: (orig_pc + bits_consumed as u64 / 8) as u64,
        };

        let (matched_symbol, num_bits) = resolve_symbol(
            &tmp_buf,
            pc.offset,
            &lang.symbols[&lang.insn_table_id],
            &lang.symbols,
            &mut ctx.clone(),
            (false, 0),
        ).unwrap();

        bits_consumed += num_bits;

        let asm = build_text(&matched_symbol);
        log(format!("0x{:x}: {}", pc.offset, asm).as_str());

        // let (pcodeops, _) = build_sym(
        //     &matched_symbol,
        //     &pc,
        //     num_bits,
        //     &lang.spaces,
        //     &lang.varnode_map,
        //     (false, 0),
        // );

        // println!("{:#?}\n", pcodeops);
    }
}
