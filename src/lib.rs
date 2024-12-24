use wasm_bindgen::prelude::*;
use web_sys::{Element, HtmlElement};
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
    pub fn generate_guid() -> String;
    pub fn append_child(parent: &Element, child: JsValue);
    pub fn remove_child(parent: JsValue, child: JsValue);
    pub fn create_div(children: Vec<JsValue>) -> JsValue;
    pub fn create_span(text: &str) -> JsValue;
    pub fn create_p(text: &str) -> JsValue;
    pub fn create_button(text: &str) -> JsValue;
    pub fn create_li(child: JsValue) -> JsValue;
    pub fn create_ul(elems: Vec<JsValue>) -> JsValue;
    pub fn toggle_visible(elem: &JsValue);
}

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn do_get_request(url: &str) -> String {
    sync_fetch(url)
}

// const FILE_BYTES: &[u8] = include_bytes!("/Users/samlerner/Projects/ideco_PUBLIC/test_cases/simple_linked_list");
// const FILE_BYTES: &[u8] = &[0x1, 0xa9, 0x46, 0xf9];
const FILE_BYTES: &[u8] = &[0xe1, 0x03, 0x18, 0xaa];

#[wasm_bindgen]
pub fn bytes() -> Vec<u8> {
    // FILE_BYTES[0x3f20..0x3f95].to_vec()
    // FILE_BYTES[0x3dc0..0x3eb3].to_vec()
    FILE_BYTES.to_vec()
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

    // let contents = read_file("x86-64.sla");
    let contents = read_file("AARCH64.sla");
    let lang = SleighLanguage::create("AARCH64", "AARCH64:LE:64:v8A", &contents);

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
        // addr: 0x100003dc0,
        addr: 0x1000064d4,
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

fn render_constructor(ct: &Constructor) -> JsValue {
    let c = ct.print_commands.as_ref().map(|pcs| {
        let strings = pcs.iter().map(|pc| {
            if let PrintCommand::Op(idx) = pc {
                format!("op#{}", idx)
            } else if let PrintCommand::Piece(piece) = pc {
                piece.clone()
            } else {
                String::new()
            }
        })
        .collect::<Vec<String>>();

        strings.join("")
    })
    .unwrap_or(String::new());

    create_span(c.as_str())
}

fn render_dtree(table: &Subtable, dtree: &DecisionTree) -> JsValue {
    match dtree {
        DecisionTree::NonLeaf((is_context, start, size, children)) => {
            let title_str = format!("Context: {}, Start: {}, Size: {}", is_context, start, size);
            let mut lis = vec![];

            for (_i, child) in children.iter().enumerate() {
                let subtree = render_dtree(table, child);
                let li = create_li(subtree);
                lis.push(li);
            }

            let ul = create_ul(lis);
            let ul_id = generate_guid();
            let ul_html = ul.dyn_ref::<HtmlElement>().unwrap();
            ul_html.set_id(ul_id.as_str());

            let title = create_button(title_str.as_str());

            let onclick = Closure::<dyn Fn()>::new(move || {
                let window = web_sys::window().unwrap();
                let document = window.document().unwrap();
                let ul = document.get_element_by_id(ul_id.as_str()).unwrap();
                toggle_visible(&ul)
            });
            title.dyn_ref::<HtmlElement>().unwrap().set_onclick(Some(onclick.as_ref().unchecked_ref()));
            onclick.forget();

            let div = create_div(vec![title, ul]);
            div
        }
        DecisionTree::Leaf(pairs) => {
            let mut lis = vec![];

            for (ct_id, _pattern) in pairs {
                let ct = &table.constructors[*ct_id as usize];
                // TODO: render the decision blocks.
                let li = create_li(render_constructor(ct));
                lis.push(li);
            }

            create_ul(lis)
        }
    }
}

fn render_p(s: String, id: &str) -> JsValue {
    let window = web_sys::window().unwrap();
    let document = window.document().unwrap();

    match document.get_element_by_id(id) {
        Some(p) => {
            p.set_inner_html(s.as_str());
            p.into()
        },
        None => {
            let p = create_p(s.as_str());
            let _ = p.dyn_ref::<HtmlElement>().unwrap().set_id(id);
            p
        }
    }
}

fn render_div(children: Vec<JsValue>, id: &str) -> JsValue {
    let window = web_sys::window().unwrap();
    let document = window.document().unwrap();

    match document.get_element_by_id(id) {
        Some(div) => {
            div.set_inner_html("");

            for child in children {
                append_child(&div, child);
            }

            div.into()
        },
        None => {
            let div = create_div(children);
            let _ = div.dyn_ref::<HtmlElement>().unwrap().set_id(id);
            div
        }
    }
}

fn render_word_view(word: u32, start: usize, end: usize, is_context: bool) -> JsValue {
    let hex_view = create_span(format!("{:0>8x}", word).as_str());

    let mut bit_views = vec![];

    for i in 0..32 {
        let color = if i >= start && i < (end - 1) {
            "red"
        } else {
            "black"
        };

        let bit = (word >> (31 - i)) & 1;
        let bit_view = create_span(format!("{}", bit).as_str());
        let css = format!("color: {};", color);
        bit_view.dyn_ref::<HtmlElement>().unwrap().style().set_css_text(css.as_str());
        bit_views.push(bit_view);
    }

    let bin_view = create_div(bit_views);
    bin_view.dyn_ref::<HtmlElement>().unwrap().style().set_css_text("display: inline-block;");

    let context_str = if is_context {
        "Context"
    } else {
        "Instruction"
    };

    let content = vec![
        create_span(format!("Word ({}): ", context_str).as_str()),
        hex_view,
        create_span("    "),
        bin_view,
    ];

    render_div(content, "word-view")
}

fn render_idx_view(idx: usize) -> JsValue {
    let index_str = format!("Index: {}", idx);
    render_p(index_str, "index-view")
}

fn render_dtree_title(name: &str) -> JsValue {
    let title_str = format!("Table: {}", name);
    render_p(title_str, "decision-tree-title")
}

#[wasm_bindgen]
impl WasmInstruction {
    pub fn render_event(&self, idx: usize, wasm_ctx: *mut WasmContext) {
        let lang = unsafe { &(*wasm_ctx).lang };
        let events = unsafe { &(*self.debug).events };

        let window = web_sys::window().unwrap();
        let document = window.document().unwrap();
        let event_view = document.get_element_by_id("event-view").unwrap();

        let (html, event_type) = match &events[idx] {
            ResolverEvent::Bits {
                sym: sym_idx,
                is_context,
                start,
                end,
                word,
                path,
            } => {
                let sym = &lang.symbols[sym_idx];

                let word_view = render_word_view(*word, *start, *end, *is_context);
                let idx_view = render_idx_view(path[path.len() - 1]);

                let body_view = match &sym.body {
                    SymbolBody::Subtable(table) => {
                        let title = render_dtree_title(table.name.as_str());

                        let dt = match document.get_element_by_id("decision-tree") {
                            Some(div) => {
                                let prev_table = div.get_attribute("table").unwrap_or("".to_string());

                                if prev_table != table.name {
                                    div.parent_node().map(|n| remove_child(n.into(), div.into()));
                                    let dt = render_dtree(table, &table.decision_tree);
                                    dt.dyn_ref::<HtmlElement>().unwrap().set_id("decision-tree");
                                    dt
                                } else {
                                    div.into()
                                }
                            },
                            None => {
                                let dt = render_dtree(table, &table.decision_tree);
                                dt.dyn_ref::<HtmlElement>().unwrap().set_id("decision-tree");
                                dt
                            },
                        };

                        let dt_html = dt.dyn_ref::<HtmlElement>().unwrap();
                        let _ = dt_html.set_attribute(
                            "path",
                            path
                                .iter()
                                .map(|ix| format!("{}", ix))
                                .collect::<Vec<String>>()
                                .join(",")
                                .as_str()
                        );
                        let _ = dt_html.set_attribute("table", table.name.as_str());

                        render_div(vec![title, dt], "decision-tree-container")
                    },
                    _ => todo!(),
                };

                (render_div(vec![word_view, idx_view, body_view], "decision-tree-event"), "bits")
            },
            ResolverEvent::Var {
                sym: sym_idx,
                var: var_idx,
                start,
                end,
                word,
                idx,
            } => {
                let sym = &lang.symbols[sym_idx];
                let var = &lang.symbols[var_idx];

                let word_view = render_word_view(*word, *start, *end, false);
                let idx_view = render_idx_view(*idx);

                let mut choices = vec![];

                if let SymbolBody::Varlist(varlist) = &sym.body {
                    for (i, var) in varlist.vars.iter().enumerate() {
                        let text = match var {
                            Some(ix) => {
                                match &lang.symbols[ix].body {
                                    SymbolBody::Varnode(vn) => {
                                        format!("{}", vn.name)
                                    },
                                    _ => todo!(),
                                }
                            },
                            None => "_".to_string()
                        };

                        let choice = create_li(create_span(text.as_str()));

                        if i == *idx {
                            choice
                                .dyn_ref::<HtmlElement>()
                                .unwrap()
                                .class_list()
                                .add_1("selected")
                                .unwrap();
                        }

                        choices.push(choice);
                    }
                }


                let body_view = create_ul(choices);

                (render_div(vec![word_view, idx_view, body_view], "var-event"), "var")
            },
            ResolverEvent::Val {
                val,
                start,
                end,
                word,
            } => {
                let word_view = render_word_view(*word, *start, *end, false);
                let body_view = create_p(format!("0x{:x}", val).as_str());
                (render_div(vec![word_view, body_view], "val-event"), "val")
            },
        };

        if let Some(t) = event_view.get_attribute("event-type") {
            if t != event_type {
                event_view.set_inner_html("");
                let _ = append_child(&event_view, html.into());
            }
        } else {
            event_view.set_inner_html("");
            let _ = append_child(&event_view, html.into());
        }

        let _ = event_view.set_attribute("event-type", event_type);
    }
}

#[wasm_bindgen]
pub fn disassemble(wasm_ctx: *mut WasmContext, buf: Vec<u8>) -> Vec<WasmInstruction> {
    init_panic_hook();

    let orig_pc: u64 = unsafe { (*wasm_ctx).addr };

    // let buf = &FILE_BYTES[0x3f20..0x3f95];
    // let orig_pc: u64 = 0x100003f20;
        
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
