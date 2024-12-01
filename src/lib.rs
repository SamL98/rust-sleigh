use wasm_bindgen::prelude::*;
use console_error_panic_hook;

mod arch;
mod parser;
mod sleigh;
mod utils;

use crate::parser::*;
use crate::sleigh::types::{Address, Instruction};

use bitvec::prelude::*;

#[wasm_bindgen]
extern {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen(module = "/utils.js")]
extern "C" {
    pub fn sync_fetch(url: &str) -> String;
    pub fn create_div(children: Vec<JsValue>) -> JsValue;
    pub fn create_p(text: &str) -> JsValue;
    pub fn create_li(content: &str) -> JsValue;
    pub fn create_ul(elems: Vec<JsValue>) -> JsValue;
}

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn do_get_request(url: &str) -> String {
    sync_fetch(url)
}

const FILE_BYTES: &[u8] = include_bytes!("/Users/sam/scratch/rust-sleigh/test");

#[wasm_bindgen]
pub fn bytes() -> Vec<u8> {
    FILE_BYTES[0x3f20..0x3f95].to_vec()
}

pub struct WasmContext {
    lang: SleighLanguage,
    ctx: Vec<u32>,
    addr: u64,
    offset: usize,
}

#[wasm_bindgen]
pub fn context() -> *mut WasmContext {
    init_panic_hook();

    let contents = read_file("x86-64.sla");
    let lang = SleighLanguage::create("x86", "x86:LE:64:default", &contents);

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

    let ctx = read_ctx(&lang.context_reg, &reg_space);

    Box::into_raw(Box::new(WasmContext {
        lang: lang,
        ctx: ctx,
        addr: 0x100003f20,
        offset: 0,
    }))
}

#[wasm_bindgen]
pub fn get_context(ctx: *mut WasmContext) -> Vec<u32> {
    unsafe { (*ctx).ctx.clone() }
}

#[wasm_bindgen]
pub fn get_addr(ctx: *mut WasmContext) -> u64 {
    unsafe { (*ctx).addr }
}

#[wasm_bindgen]
pub fn get_offset(ctx: *mut WasmContext) -> usize {
    unsafe { (*ctx).offset }
}

pub fn disassemble_one(
    ctx: *mut WasmContext,
    bytes: Vec<u8>,
    pc: u64,
    resolver_debug: &mut ResolverDebug,
) -> Instruction {
    let lang = unsafe { &(*ctx).lang };
    let ctx = unsafe { &(*ctx).ctx };

    let pc = Address {
        space: "ram".to_owned(),
        offset: pc,
    };

    let (matched_symbol, num_bits) = resolve_symbol(
        &bytes,
        pc.offset,
        &lang.symbols[&lang.insn_table_id],
        &lang.symbols,
        &mut ctx.clone(),
        resolver_debug,
    ).unwrap();

    let asm = build_text(&matched_symbol);

    let (pcodeops, _) = build_sym(
        &matched_symbol,
        &pc,
        num_bits,
        &lang.spaces,
        &lang.varnode_map,
        (false, 0),
    );

    Instruction {
        address: pc,
        bit_len: num_bits,
        asm: asm,
        ops: pcodeops,
    }
}

#[wasm_bindgen(getter_with_clone)]
pub struct WasmInstruction {
    pub insn: Instruction,
    pub debug: *mut ResolverDebug,
    pub num_events: usize,
}

#[wasm_bindgen]
impl WasmInstruction {
    pub fn render_event(&self, idx: usize, wasm_ctx: *mut WasmContext) -> JsValue {
        let lang = unsafe { &(*wasm_ctx).lang };
        let events = unsafe { &(*self.debug).events };

        match events[idx] {
            ResolverEvent::InstructionBits {
                sym: sym_idx,
                start: start,
                end: end,
                word: word,
                val: val,
            } => {
                let sym = &lang.symbols[&sym_idx];

                match &sym.body {
                    SymbolBody::Subtable(table) => {
                        let title = create_p(format!("Table: {}", table.name).as_str());
                        let elem1 = create_li("foo");
                        let elem2 = create_li("bar");
                        let ul = create_ul(vec![elem1, elem2]);
                        let html = create_div(vec![title, ul]);
                        html
                    },
                    _ => todo!(),
                }
            },
            _ => todo!(),
        }
    }
}

#[wasm_bindgen]
pub fn disassemble(wasm_ctx: *mut WasmContext) -> Vec<WasmInstruction> {
    init_panic_hook();

    let ctx = unsafe { &(*wasm_ctx).ctx };
    let lang = unsafe { &(*wasm_ctx).lang };

    // let buf = &FILE_BYTES[0x3dc0..0x3eb3];
    // let orig_pc: u64 = 0x100003dc0;

    let buf = &FILE_BYTES[0x3f20..0x3f95];
    let orig_pc: u64 = 0x100003f20;
        
    let mut bits_consumed = 0;
    let mut insns = vec![];

    while bits_consumed < buf.len() * 8 {
        let tmp_buf: Vec<u8> = buf[bits_consumed / 8..].to_vec();
        let mut debug = ResolverDebug::default();

        let insn = disassemble_one(
            wasm_ctx,
            tmp_buf,
            (orig_pc + bits_consumed as u64 / 8) as u64,
            &mut debug,
        );

        let num_events = debug.events.len();
        bits_consumed += insn.bit_len;

        insns.push(WasmInstruction{
            insn: insn,
            debug: Box::into_raw(Box::new(debug)),
            num_events: num_events,
        });
    }

    insns
}
