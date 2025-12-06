use crate::sla_parser::*;
use crate::logger::Logger;
use crate::log;

use std::collections::{HashSet, HashMap};
use std::hash::{Hash, Hasher};

use bitvec::prelude::*;

pub struct ResolveContext<'a, 'b> {
    lang: &'a SleighLanguage,
    ctx: &'b mut Vec<u32>,
    reg_space: &'b BitVec<u8, Msb0>,
    log_modules: &'b HashSet<String>,
    depth: usize,
}

impl Logger for ResolveContext<'_, '_> {
    fn should_log(&self) -> bool {
        self.log_modules.contains("resolver")
    }

    fn depth(&self) -> usize {
        self.depth
    }

    fn inc_depth(&mut self) {
        self.depth += 1
    }

    fn dec_depth(&mut self) {
        self.depth -= 1
    }
}

fn get_operand<'a>(id: &u32, symbols: &'a HashMap<u32, Symbol>) -> &'a Operand {
    let sym = &symbols[id];
    match &sym.body {
        SymbolBody::Operand(operand) => operand,
        _ => panic!(),
    }
}

fn match_ctx_pattern_block(block: &PatternBlock, words: &Vec<u32>) -> bool {
    let mut word_idx = (block.offset / 4) as usize;
    let byte_idx = block.offset % 4;

    for (_, mask_word) in block.masks.iter().enumerate() {
        let cw = words[word_idx];
        let nw = if word_idx < words.len() - 1 { words[word_idx+1] } else { 0 };
        let word = (cw & (((1_u64 << (32 - (byte_idx * 8))) - 1) as u32)).overflowing_shl(byte_idx * 8).0 | 
                   nw.overflowing_shr(32 - (byte_idx * 8)).0;

        word_idx += 1;

        if (word & mask_word.mask) != mask_word.val {
            return false;
        }
    }
    true
}

fn match_insn_pattern_block(block: &PatternBlock, words: &[u8]) -> bool {
    for (i, mask_word) in block.masks.iter().enumerate() {
        let word = get_word(words, (block.offset as usize) + i * 4, 4) as u32;
        // println!("Matching instruction pattern: {:?}", block);
        if (word & mask_word.mask) != mask_word.val {
            return false;
        }
    }
    true
}

fn match_pattern(pattern: &DecisionPattern, insn_words: &[u8], ctx_words: &Vec<u32>) -> bool {
    // TODO: Maybe use offset for ctx?
    match pattern {
        DecisionPattern::Context(pat_blk) => match_ctx_pattern_block(pat_blk, ctx_words),
        DecisionPattern::Instruction(pat_blk) => match_insn_pattern_block(pat_blk, insn_words),
        DecisionPattern::Combine((pat1, pat2)) => {
            match_pattern(&*pat1, insn_words, ctx_words) && match_pattern(&*pat2, insn_words, ctx_words)
        }
    }
}

#[derive(Debug, Clone)]
pub enum MatchedSymbol<'a> {
    Constructor((&'a Constructor, Vec<(MatchedSymbol<'a>, Option<FixupType>)>)),
    Symbol(&'a Symbol, usize),
    Literal((i64, usize)),
    String(&'a str),
}

impl Hash for MatchedSymbol<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        use MatchedSymbol::*;

        match self {
            Constructor((ct, operands)) => {
                ct.line.hash(state);

                for (op, _) in operands {
                    op.hash(state);
                }
            },
            Symbol(sym, _) => sym.id.hash(state),
            Literal((val, sz)) => (val, sz).hash(state),
            String(s) => s.hash(state),
        }
    }
}

impl PartialEq for MatchedSymbol<'_> {
    fn eq(&self, other: &Self) -> bool {
        use MatchedSymbol::*;

        match (self, other) {
            (Constructor((ct1, ops1)), Constructor((ct2, ops2))) => {
                if ct1.line != ct2.line {
                    return false;
                }

                for (op1, op2) in ops1.iter().zip(ops2.iter()) {
                    if op1 != op2 {
                        return false;
                    }
                }

                return true;
            },
            (Symbol(sym1, _), Symbol(sym2, _)) => sym1.id == sym2.id,
            (Literal((v1, sz1)), Literal((v2, sz2))) => v1 == v2 && sz1 == sz2,
            (String(s1), String(s2)) => s1 == s2,
            _ => false,
        }
    }
}

impl Eq for MatchedSymbol<'_> {}

fn resolve_constructor<'a, 'b>(
    words: &[u8],
    table: &'a Subtable,
    ctx: &ResolveContext<'a, 'b>,
) -> Option<(&'a Constructor, usize)> {
    let mut dtree = &table.decision_tree;
    let mut bits_consumed = 0;
    let mut path = vec![];
    let mut result = None;

    loop {
        match dtree {
            DecisionTree::NonLeaf((is_context, start, size, children)) => {
                if children.len() == 0 {
                    return None;
                }

                if *size == 0 && children.len() == 1 {
                    dtree = &children[0];
                    continue;
                }

                let bit_start = 32 - (start + size);

                if !is_context {
                    let word = get_word(words, 0, 4) as u32;
                    let idx = ((word >> bit_start) & ((1 << size) - 1)) as usize;
                    path.push(idx);

                    dtree = &children[idx.min(children.len() - 1)];
                    bits_consumed = bits_consumed.max(start + size);
                } else {
                    let ctx_word = ctx.ctx[(*start as usize) / 32];
                    let idx = (ctx_word.overflowing_shr(bit_start).0 & ((1 << size) - 1)) as usize;
                    path.push(idx);

                    dtree = &children[idx.min(children.len() - 1)];
                }
            }
            DecisionTree::Leaf(pairs) => {
                for (ct_id, pattern) in pairs {
                    let ct = &table.constructors[*ct_id as usize];

                    if match_pattern(pattern, &words, &ctx.ctx) {
                        log!(ctx, "Matched constructor on line {}:{}", ct.line.0, ct.line.1);
                        result = Some((ct, (ct.length * 8) as usize));
                        break;
                    }
                }

                if result.is_none() {
                    log!(ctx, "Didn't match constructor");
                }

                break;
            }
        };
    }

    result
}

fn resolve_varlist<'a, 'b>(
    words: &[u8],
    varlist: &'a Varlist,
    ctx: &ResolveContext<'a, 'b>,
) -> Option<(MatchedSymbol<'a>, usize)> {
    match &varlist.field {
        Field::Token(token) => {
            let num_bytes = (token.end_byte - token.start_byte + 1) as usize;
            let sb = token.start_byte as usize;

            let token_word = if token.big_endian {
                get_word(words, sb, num_bytes)
            } else {
                get_word_le(words, sb, num_bytes)
            };

            let start = token.start_bit - token.start_byte * 8;
            let size = token.end_bit - token.start_bit + 1;
            let idx = ((token_word >> start) & ((1 << size) - 1)) as usize;

            varlist.vars[idx].map(|var_idx| {
                let var = &ctx.lang.symbols[&var_idx];

                // Not super sure if this size calculation is right but it seems to work.
                let bit_end = (token.end_byte * 8 + (8 - (token.end_bit % 8) - 1) + size) as usize;
                ((MatchedSymbol::Symbol(var, idx)), bit_end)
            })
        },
        Field::Context(token) => {
            let num_bytes = (token.end_byte - token.start_byte + 1) as usize;
            let sb = token.start_byte as usize;
            let mut token_word: u32 = 0;

            for i in 0..num_bytes {
                token_word <<= 8;

                if sb + i < words.len() {
                    token_word |= words[sb + i] as u32;
                } else {
                    token_word |= 0;
                }
            }

            let start = token.start_bit - token.start_byte * 8;
            let size = token.end_bit - token.start_bit + 1;
            let idx = ((token_word >> start) & ((1 << size) - 1)) as usize;

            varlist.vars[idx].map(|var_idx| {
                let var = &ctx.lang.symbols[&var_idx];

                // Not super sure if this size calculation is right but it seems to work.
                let bit_end = (token.end_byte * 8 + (8 - (token.end_bit % 8) - 1) + size) as usize;
                ((MatchedSymbol::Symbol(var, idx)), bit_end)
            })
        }
    }
}

fn resolve_nametab<'a, 'b>(
    words: &[u8],
    nametab: &'a NameTable,
    _ctx: &ResolveContext<'a, 'b>,
) -> Option<(MatchedSymbol<'a>, usize)> {
    match &nametab.field {
        Field::Token(token) => {
            let num_bytes = (token.end_byte - token.start_byte + 1) as usize;
            let sb = token.start_byte as usize;
            let mut token_word: u32 = 0;

            for i in 0..num_bytes {
                token_word <<= 8;
                token_word |= words[sb + i] as u32;
            }

            let start = token.start_bit - token.start_byte * 8;
            let size = token.end_bit - token.start_bit + 1;
            let idx = ((token_word >> start) & ((1 << size) - 1)) as usize;
            let name = nametab.names[idx].as_ref().unwrap();
            let bit_end = (token.end_byte * 8 + (8 - (token.end_bit % 8) - 1) + size) as usize;
            Some((MatchedSymbol::String(name), bit_end))
        }
        _ => todo!(),
    }
}

fn resolve_valuemap<'a, 'b>(
    words: &[u8],
    valuemap: &'a Valuemap,
    _ctx: &ResolveContext<'a, 'b>,
) -> Option<(MatchedSymbol<'a>, usize)> {
    match &valuemap.field {
        Field::Token(token) => {
            let num_bytes = (token.end_byte - token.start_byte + 1) as usize;
            let sb = token.start_byte as usize;
            let mut token_word: u32 = 0;

            for i in 0..num_bytes {
                token_word <<= 8;
                token_word |= words[sb + i] as u32;
            }

            let start = token.start_bit;
            let size = token.end_bit - start + 1;
            let idx = ((token_word >> start) & ((1 << size) - 1)) as usize;
            let val = valuemap.vars[idx] as i64;

            // Not super sure if this size calculation is right but it seems to work.
            let literal = MatchedSymbol::Literal((val, size as usize));
            let token_size = (token.end_byte * 8 + (8 - token.end_bit - 1) + size) as usize;
            Some((literal, token_size))
        }
        _ => todo!(),
    }
}

fn evaluate_expr(
    expr: &Expr,
    ctx: &Vec<u32>,
    operands: &Vec<(MatchedSymbol, Option<FixupType>)>,
    reg_space: &BitVec<u8, Msb0>,
) -> (i64, usize, Option<FixupType>) {
    match expr {
        Expr::Const(val) => (*val, 8, None), // FIXME
        Expr::Operand(op_expr) if (op_expr.idx as usize) < operands.len() => {
            let op = &operands[op_expr.idx as usize].0;

            if let MatchedSymbol::Literal((val, sz)) = op {
                let signed_val = match *sz {
                    1 => (*val as i8) as i64,
                    2 => (*val as i16) as i64,
                    4 => (*val as i32) as i64,
                    8 => (*val as i64) as i64,
                    _ => *val,
                };

                (signed_val, *sz, None)
            } else if let MatchedSymbol::Symbol(sym, idx) = op {
                if let SymbolBody::Varnode(_vnode_sym) = &sym.body {
                    (*idx as i64, 8, None)
                } else {
                    panic!("{:?}", op);
                }
            } else {
                panic!("{:?}", op);
            }
        },
        Expr::Binary((op, lhs, rhs)) => {
            let (lhs_val, lhs_sz, lhs_fixme) = evaluate_expr(&**lhs, ctx, operands, reg_space);
            let (rhs_val, rhs_sz, rhs_fixme) = evaluate_expr(&**rhs, ctx, operands, reg_space);

            use ExprOp::*;
            let result = match op {
                Xor => lhs_val ^ rhs_val,
                Add => lhs_val + rhs_val,
                Sub => lhs_val - rhs_val,
                Mult => lhs_val.overflowing_mul(rhs_val).0,
                And => lhs_val & rhs_val,
                Or => lhs_val | rhs_val,
                Lshift => {
                    let (r, o) = lhs_val.overflowing_shl(rhs_val as u32);
                    if o { 0 } else { r }
                },
                Rshift => lhs_val >> rhs_val,
                _ => panic!("unknown binary opcode {:?}", op),
            };

            (result, lhs_sz.max(rhs_sz), lhs_fixme.or(rhs_fixme)) // FIXME
        },
        Expr::Unary((op, hs)) => {
            let (val, sz, fixme) = evaluate_expr(&**hs, ctx, operands, reg_space);

            use ExprOp::*;
            let result = match op {
                Not => !val,
                Minus => -val,
                _ => panic!("unknown unary opcode {:?}", op),
            };

            (result, sz, fixme)
        },
        Expr::Field(Field::Context(ctx_field)) => {
            // FIXME: Use BitVec for context. Use end_byte.
            let idx = (ctx_field.start_bit / 32) as usize;
            let ctx_word = ctx[idx];
            let size = ctx_field.end_bit - ctx_field.start_bit + 1;
            let bit_start = 32 - (ctx_field.start_bit + size);
            let rv = ((ctx_word >> bit_start) & ((1 << size) - 1)) as i64;
            (rv, (size / 8) as usize, None)
        },
        Expr::Start => {
            (0, 8, Some(FixupType::Start))
        },
        Expr::End => {
            (0, 8, Some(FixupType::End))
        },
        _ => todo!("{:?}", expr),
    }
}

fn resolve_operands<'a, 'b>(
    words: &[u8],
    pc: u64,
    ct: &'a Constructor,
    ctx: &mut ResolveContext<'a, 'b>,
) -> (Vec<(MatchedSymbol<'a>, Option<FixupType>)>, usize, bool) {
    let mut matched_ops = vec![];
    let mut bit_ends = vec![];
    let mut bit_end: usize = 0;
    let mut total_bit_end: usize = 0;
    let mut ok = true;

    for op_idx in &ct.operands {
        // TODO: Handle min_len.
        let operand = get_operand(&op_idx, &ctx.lang.symbols);
        log!(ctx, "Base: {}, MinLen: {}, RelOff: {}", operand.base, operand.min_len, operand.off);

        match &operand.expr {
            Some(Expr::Field(Field::Token(expr))) => {
                log!(ctx, "{:?}", expr);

                let size = expr.end_bit - expr.start_bit + 1;
                let num_bytes = (expr.end_byte - expr.start_byte + 1) as usize;
                let mut sb = expr.start_byte as usize;

                if operand.base >= 0 {
                    sb += (bit_ends[operand.base as usize] / 8) as usize;
                }

                let word = if !expr.big_endian {
                    get_word_le(words, sb, num_bytes)
                } else {
                    get_word(words, sb, num_bytes)
                };

                let mask = if size >= 64 { u64::MAX } else { (1_u64 << size) - 1 };
                let start_bit = expr.start_bit % 8;
                // let val = (((word >> start_bit) & mask) >> expr.shift) as i64;
                let val = ((word >> start_bit) & mask) as i64;

                bit_end = sb * 8 + (size as usize);
                total_bit_end = total_bit_end.max(bit_end);

                matched_ops.push((MatchedSymbol::Literal((val, num_bytes)), None));
                bit_ends.push(bit_end);

                log!(ctx, "Bit end is ({}, {}) after token operand", bit_end, total_bit_end);
                log!(ctx, "  Start: ({}, {}), Shift: {}", expr.start_bit, expr.end_bit, expr.shift);
                log!(ctx, "  Words: {:x?}, Val: 0x{:x}", &words[sb..(sb + 4)], val);
            },
            Some(Expr::Field(Field::Context(expr))) => {
                let size = expr.end_bit - expr.start_bit + 1;
                let bit_start = 32 - (expr.start_bit + size);
                let val = (ctx.ctx[(expr.start_bit / 32) as usize] >> bit_start) & ((1 << size) - 1);
                let num_bytes = (expr.end_byte - expr.start_byte + 1) as usize;
                matched_ops.push((MatchedSymbol::Literal((val as i64, num_bytes)), None));
                bit_ends.push(0);
            },
            Some(Expr::Unary(_) | Expr::Binary(_)) => {
                log!(ctx, "Evaluating expr {:?}", operand.expr);
                let (val, sz, fixup_type) = evaluate_expr(operand.expr.as_ref().unwrap(), &ctx.ctx, &matched_ops, &ctx.reg_space);
                log!(ctx, "  => {}", val);
                matched_ops.push((MatchedSymbol::Literal((val, sz)), fixup_type));
                bit_ends.push(0);
            },
            Some(Expr::Const(val)) => {
                // TODO: Fix size.
                matched_ops.push((MatchedSymbol::Literal((*val, 8)), None));
                bit_ends.push(0);
            }
            None => {
                let op_sym = &ctx.lang.symbols[&operand.subsym];

                // TODO: Figure out if thise guess is right.
                let base = if operand.base < 0 {
                    operand.off as usize
                } else {
                    bit_ends[operand.base as usize] / 8
                };

                // Before recursively resolving a symbol, we first need to modify the context.
                for op in &ct.context_ops {
                    let existing = ctx.ctx[op.i as usize];
                    let mask = op.mask;

                    // TODO: Handle no-flow context symbols.
                    let (val, _, _) = evaluate_expr(&op.expr, &ctx.ctx, &matched_ops, &ctx.reg_space);
                    let v = (val as u32) << op.shift;
                    ctx.ctx[op.i as usize] = (existing & !mask) | (v & mask);
                }

                match _resolve_symbol(&words[base..], pc + base as u64, op_sym, ctx) {
                    Some((matched_sym, sub_bit_end)) => {
                        let new_bit_end = bit_end.max((base * 8) as usize + sub_bit_end);
                        matched_ops.push((matched_sym, None));
                        bit_ends.push(new_bit_end);
                        // total_bit_end = new_bit_end;
                        total_bit_end = total_bit_end.max(new_bit_end);

                        // if operand.base == -1 {
                        //     bit_end = total_bit_end;
                        // }

                        log!(ctx, "After resolving operand, new bit end is {}, total bit end: {}", new_bit_end, total_bit_end);
                    },
                    None => ok = false,
                };
            },
            _ => todo!("{:?}", operand.expr)
        }
    }

    // (matched_ops, bit_end.max(total_bit_end), ok)
    (matched_ops, total_bit_end, ok)
}

pub fn _resolve_symbol<'a, 'b>(
    words: &[u8],
    pc: u64,
    sym: &'a Symbol,
    ctx: &mut ResolveContext<'a, 'b>,
) -> Option<(MatchedSymbol<'a>, usize)> {
    ctx.inc_depth();
    
    let result = match &sym.body {
        SymbolBody::Subtable(table) => {
            log!(ctx, "Resolving sub-table {}", table.name);

            match resolve_constructor(words, table, ctx) {
                Some((ct, bit_end)) => {
                    let (operands, ops_bit_end, ok) = resolve_operands(words, pc, ct, ctx);
                    let bit_len = bit_end.max(ops_bit_end);
                    log!(ctx, "After all operands, bit end is {}, constructor took {} bits", bit_len, bit_end);

                    if ok {
                        Some((MatchedSymbol::Constructor((ct, operands)), bit_len))
                    } else {
                        None
                    }
                }
                None => None,
            }
        },
        SymbolBody::Varlist(varlist) => {
            resolve_varlist(words, varlist, ctx)
        },
        SymbolBody::Valuemap(valuemap) => {
            resolve_valuemap(words, valuemap, ctx)
        },
        SymbolBody::Varnode(_) => {
            Some((MatchedSymbol::Symbol(sym, 0), 0)) // NOTE: dummy index value here.
        },
        SymbolBody::Nametab(nametab) => {
            resolve_nametab(words, nametab, ctx)
        },
        _ => todo!("{:?}", sym.body),
    };

    ctx.dec_depth();
    result
}

fn apply_fixups(matched_sym: &mut MatchedSymbol, fixup_type: &Option<FixupType>, pc: u64, bit_len: usize) {
    match matched_sym {
        MatchedSymbol::Constructor((_, operands)) => {
            for (oper, t) in operands.iter_mut() {
                apply_fixups(oper, t, pc, bit_len);
            }
        },
        MatchedSymbol::Literal((val, _)) => {
            *val = match fixup_type {
                Some(FixupType::Start) => *val + pc as i64,
                Some(FixupType::End) => *val + (pc as usize + bit_len / 8) as i64,
                _ => *val,
            };
        },
        _ => (),
    }
}

pub fn resolve_symbol<'a, 'b>(
    words: &[u8],
    pc: u64,
    sym: &'a Symbol,
    lang: &'a SleighLanguage,
    ctx: &'b mut Vec<u32>,
    reg_space: &'b BitVec<u8, Msb0>,
    log_modules: &'b HashSet<String>,
) -> Option<(MatchedSymbol<'a>, usize)> {
    let mut ctx = ResolveContext { lang, ctx, reg_space, log_modules, depth: 0 };

    if let Some((mut matched_sym, bit_len)) = _resolve_symbol(words, pc, sym, &mut ctx) {
        apply_fixups(&mut matched_sym, &None, pc, bit_len);
        // println!("{:#?}", matched_sym);
        Some((matched_sym, bit_len))
    } else {
        None
    }
}
