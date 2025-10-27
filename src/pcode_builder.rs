use crate::sleigh::varnode::VarnodeIface;
use crate::sleigh::opcode::OpCode;
use crate::sleigh::types::*;

use crate::sla_parser::*;
use crate::symbol_resolver::*;
use crate::logger::*;

use std::collections::HashMap;
use std::borrow::Cow;
use std::fmt;

use flexstr::{local_str, LocalStr, ToLocalStr};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum VarnodeValue<'a> {
    Space(AddressSpace),
    String(&'a String),
    Int(u64),
    Rel(u64),
    Op(Cow<'a, Varnode>),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Handle {
    space: AddressSpace,
    pointer: Varnode,
    temp: Varnode,
}

impl Handle {
    fn needs_resolving(&self) -> bool {
        self.temp.space != AddressSpace::Dummy
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.needs_resolving() {
            write!(f, "{}", self.pointer)
        } else {
            write!(f, "*({}){}", self.temp, self.pointer)
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PcodeObject {
    Dummy,
    Varnode(Varnode),
    Handle(Handle),
}

impl fmt::Display for PcodeObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PcodeObject::Dummy => write!(f, "DUMMY"),
            PcodeObject::Varnode(vn) => write!(f, "{}", vn),
            PcodeObject::Handle(h) => write!(f, "{}", h),
        }
    }
}

pub struct BuildContext<'a> {
    pc: &'a Address,
    bit_len: usize,
    lang: &'a SleighLanguage,
}

fn build_value<'a>(
    const_tpl: &'a ConstTemplate,
    objs: &'a [PcodeObject],
    ctx: &BuildContext,
) -> (VarnodeValue<'a>, Option<FixupType>) {
    match const_tpl {
        ConstTemplate::SpaceId(space) => (VarnodeValue::String(space), None),
        ConstTemplate::Val(val) => (VarnodeValue::Int(*val), None),
        ConstTemplate::Handle((idx, expr)) => {
            let ix = *idx as usize;

            let mut vn: Cow<'a, Varnode> = Cow::Borrowed(match &objs[ix] {
                PcodeObject::Varnode(vn) => vn,
                PcodeObject::Handle(h) if h.needs_resolving() => &h.temp,
                PcodeObject::Handle(h) => &h.pointer,
                _ => panic!("{}", objs[ix])
            });

            match expr {
                Some(HandleExpr::OffsetPlus(addend)) => vn = Cow::Owned(vn.subpiece(*addend as u64, vn.size, &ctx.lang.varnode_map)),
                _ => ()
            };

            (VarnodeValue::Op(vn), None)
        },
        // For now just use the const index for intra-pcode branching.
        // I think this is right but we'll see.
        ConstTemplate::Relative(idx) => (VarnodeValue::Rel(*idx as u64), None),
        ConstTemplate::Start => (VarnodeValue::Int(ctx.pc.offset), Some(FixupType::Start)),
        ConstTemplate::Next => (VarnodeValue::Int(ctx.pc.offset + (ctx.bit_len / 8) as u64), Some(FixupType::End)),
        ConstTemplate::CurSpace => (VarnodeValue::Space(AddressSpace::Ram), None), // FIXME
        ConstTemplate::CurSpaceSize => (VarnodeValue::Int(8), None), // FIXME
    }
}

fn build_offset<'a>(
    const_tpl: &'a ConstTemplate,
    objs: &'a [PcodeObject],
    ctx: &BuildContext,
) -> (u64, Option<FixupType>) {
    let (val, ft) = build_value(const_tpl, objs, ctx);
    match &val {
        VarnodeValue::Int(sz) => (*sz, ft),
        VarnodeValue::Op(op) => (op.offset, ft),
        VarnodeValue::Space(_) => (8, ft), // FIXME
        VarnodeValue::String(s) => (ctx.lang.spaces[s.as_str()], ft),
        VarnodeValue::Rel(ix) => (*ix, ft),
    }
}

fn build_size<'a>(
    const_tpl: &'a ConstTemplate,
    objs: &'a [PcodeObject],
    ctx: &BuildContext,
) -> (u64, Option<FixupType>) {
    let (val, ft) = build_value(const_tpl, objs, ctx);
    match &val {
        VarnodeValue::Int(sz) => (*sz, ft),
        VarnodeValue::Op(op) => (op.size, ft),
        VarnodeValue::Space(_) => (8, ft), // FIXME
        VarnodeValue::String(s) => (ctx.lang.spaces[s.as_str()], ft),
        _ => panic!("Unknown varnode value type for int {:?}", val),
    }
}

fn build_space<'a>(
    const_tpl: &'a ConstTemplate,
    objs: &'a [PcodeObject],
    ctx: &BuildContext,
) -> (AddressSpace, Option<FixupType>) {
    match build_value(const_tpl, objs, ctx) {
        (VarnodeValue::String(s), ft) => (AddressSpace::from_str(s.as_str()), ft),
        (VarnodeValue::Space(spc), ft) => (spc, ft),
        (VarnodeValue::Op(op), ft) => (op.space, ft),
        (VarnodeValue::Int(0), ft) => (AddressSpace::Dummy, ft),
        _ => panic!(),
    }
}

fn sign_extend(val: u64, from: u64, to: u64) -> u64 {
    let mut result = val;

    let shift = 64 - from * 8;
    result = (((result << shift) as i64) >> shift) as u64;

    let shift = 64 - to * 8;
    result = (result << shift) >> shift;

    result
}

fn build_handle<'a>(
    handle_tpl: &'a HandleTemplate,
    objs: &'a [PcodeObject],
    ctx: &BuildContext,
) -> PcodeObject {
    let deref_space = build_space(&handle_tpl.space_template, objs, ctx).0;
    let deref_size = build_size(&handle_tpl.size_template, objs, ctx).0;
    let pointer = build_varnode(&handle_tpl.pointer_template, objs, ctx);
    let temp_space = build_space(&handle_tpl.temp_space_template, objs, ctx).0;
    let temp_offset = build_offset(&handle_tpl.temp_offset_template, objs, ctx).0;

    let temp = Varnode {
        name: None,
        space: temp_space,
        offset: temp_offset,
        size: deref_size,
    };

    // println!("Handle: {}\n  ({:?}, {:?}, {}, {:?}, {:?})\n", handle_tpl, deref_space, deref_size, pointer, temp_space, temp_offset);

    if deref_space == AddressSpace::Ram && pointer.space == AddressSpace::Const {// && pointer.size == 0 {
        PcodeObject::Varnode(Varnode {
            name: pointer.name.clone(),
            space: deref_space,
            offset: pointer.offset,
            size: pointer.size,
        })
    } else if !temp.space.is_dummy() && deref_space != AddressSpace::Const {
        PcodeObject::Handle(Handle {
            space: deref_space,
            pointer: pointer,
            temp: temp,
        })
    } else if deref_space == AddressSpace::Const {
        let mut offset = pointer.offset;

        if deref_size > 0 && pointer.size > 0 {
            offset = sign_extend(offset, pointer.size, deref_size);
        }

        PcodeObject::Varnode(Varnode {
            name: None,
            space: deref_space,
            offset: offset,
            size: deref_size.max(pointer.size),
        })
    } else if deref_space != AddressSpace::Dummy {
        let name = ctx.lang.varnode_map.get(&(pointer.offset, deref_size)).cloned();

        PcodeObject::Varnode(Varnode {
            name: name,
            space: deref_space,
            offset: pointer.offset,
            size: deref_size,
        })
    } else {
        PcodeObject::Varnode(pointer.clone())
    }
}

fn build_varnode<'a>(
    vnode_tpl: &'a VarnodeTemplate,
    objs: &'a [PcodeObject],
    ctx: &BuildContext,
) -> Varnode {
    use ConstTemplate::*;

    let mut fixup_type = None;

    match (&vnode_tpl.space_template, &vnode_tpl.offset_template, &vnode_tpl.size_template) {
        (Val(0), Handle((ix, _)), Val(0)) => {
            match &objs[*ix as usize] {
                PcodeObject::Varnode(vn) => vn.clone(),
                PcodeObject::Handle(h) => h.pointer.clone(), // FIXME
                _ => panic!(),
            }
        },
        (Handle((ix, _)), Handle((ix2, _)), Val(0)) if ix == ix2 => {
            match &objs[*ix as usize] {
                PcodeObject::Varnode(vn) => vn.clone(),
                PcodeObject::Handle(h) => h.pointer.clone(), // FIXME
                _ => panic!(),
            }
        },
        _ => {
            let (space, ft) = build_space(&vnode_tpl.space_template, objs, ctx);
            fixup_type = fixup_type.or(ft);

            let (mut offset, ft) = build_offset(&vnode_tpl.offset_template, objs, ctx);
            fixup_type = fixup_type.or(ft);

            let (size, ft) = build_size(&vnode_tpl.size_template, objs, ctx);
            fixup_type = fixup_type.or(ft);

            let name = match space {
                AddressSpace::Register => ctx.lang.varnode_map.get(&(offset, size)).map(|x| x.clone()),
                _ => match fixup_type {
                    Some(FixupType::Start) => Some(local_str!("fixup_start")),
                    Some(FixupType::End) => Some(local_str!("fixup_end")),
                    _ => None,
                },
            };

            // Need to sign-extend.
            if space == AddressSpace::Const {
                if let (Handle((ix, _)), Handle((ix2, _))) = (&vnode_tpl.space_template, &vnode_tpl.offset_template) {
                    if ix == ix2 {
                        if let PcodeObject::Varnode(vn) = &objs[*ix as usize] {
                            offset = sign_extend(offset, vn.size, size);
                        }
                    }
                }
            }

            // println!("{}\n  {:?}\n  ({}, {:x}, {})\n", vnode_tpl, objs, space, offset, size);

            Varnode {
                name: name,
                space: space.to_owned(),
                offset: offset,
                size: size,
            }
        }
    }
}

fn fix_sizes(opcode: &mut OpCode, inputs: &mut Vec<Varnode>, output: &mut Option<Varnode>, ctx: &BuildContext) {
    // TODO: Add more cases.
    // println!("{} {:?}", opcode, inputs);
    if *opcode == OpCode::IntAdd {
        if inputs[1].is_negative() {
            *opcode = OpCode::IntSub;
            inputs[1] = inputs[1].negate();
        } else if inputs[0].is_negative() {
            *opcode = OpCode::IntSub;
            let c = inputs[0].clone();
            inputs[0] = inputs[1].clone();
            inputs[1] = c.negate();
        }
    } else if *opcode == OpCode::IntSub {
        if inputs[1].is_negative() {
            *opcode = OpCode::IntAdd;
            inputs[1] = inputs[1].negate();
        } 
    }

    // println!("{} {:?}", opcode, inputs);

    if !matches!(*opcode, OpCode::Store | OpCode::Call | OpCode::CallInd | OpCode::CallOther | OpCode::SubPiece) {
        let output_size = output.as_ref().map(|o| o.size).unwrap_or(0);

        // let mut max_sz = inputs.iter().map(|i| i.size).max().unwrap();
        let mut sz = 0;

        for input in inputs.iter() {
            if input.space == AddressSpace::Register {
                sz = input.size;
                break;
            }
        }

        if sz == 0 {
            // TODO: Cleanup.
            // sz = inputs.iter().map(|i| i.size).max().unwrap();

            for (i, input) in inputs.iter().enumerate() {
                if !(matches!(*opcode, OpCode::IntLeft | OpCode::IntRight | OpCode::IntSRight) && i == 1) {
                    sz = sz.max(input.size);
                }
            }
        }

        if !matches!(*opcode, OpCode::Load | OpCode::IntSext | OpCode::IntZext | OpCode::FloatInt2Float) && !opcode.is_conditional() {
            // max_sz = max_sz.max(output_size);
            if output.as_ref().map(|o| o.space == AddressSpace::Register).unwrap_or(false) {
                sz = output_size;
            }

            if sz == 0 || *opcode == OpCode::Copy {
                sz = sz.max(output_size);
            }
        }

        for i in 0..inputs.len() {
            let input = &mut inputs[i];

            if input.space != AddressSpace::Register && !(i == 1 && *opcode == OpCode::SubPiece) && 
               !(i == 0 && *opcode == OpCode::CBranch) && 
                !(i == 1 && matches!(*opcode, OpCode::IntLeft | OpCode::IntRight | OpCode::IntSRight)) {
                if input.space == AddressSpace::Const && input.size > 0 && input.size <= 8 && *opcode != OpCode::IntSub && *opcode != OpCode::IntAdd {
                    let shift = 64 - input.size * 8;
                    input.offset = (((input.offset << shift) as i64) >> shift) as u64;

                    let shift = 64 - sz * 8;
                    input.offset = input.offset.overflowing_shl(shift as u32).0.overflowing_shr(shift as u32).0;
                }

                input.size = sz;
            }
        }

        if matches!(*opcode, OpCode::IntAdd | OpCode::IntSub | OpCode::IntMult | OpCode::IntDiv | OpCode::Copy) {
            output.as_mut().unwrap().size = sz;
        }

        if *opcode == OpCode::CBranch && inputs[1].size > 1 {
            inputs[1].size = 1;
        }

        if *opcode == OpCode::SubPiece && output_size > inputs[1].size {
            *output = Some(output.as_ref().unwrap().subpiece(0, inputs[1].size, &ctx.lang.varnode_map));
        }
    } else if *opcode == OpCode::Store {
        inputs[1].size = 8; // FIXME
    }

    // HACK, FIXME
    if *opcode == OpCode::Load {
        inputs[1].size = 8;
    }
}

fn build_pcodeop<'a>(
    mut seq: SeqNum,
    op_tpl: &'a OpTemplate,
    objs: &'a [PcodeObject],
    ops: &mut Vec<PcodeOp>,
    ctx: &BuildContext,
) {
    let mut opcode = OpCode::from_str(op_tpl.code.as_str());

    let mut input_iter = op_tpl.inputs.iter();

    if opcode == OpCode::Return {
        let _ = input_iter.next();
    }

    let mut inputs = vec![];

    for tpl in input_iter {
        if let Some(idx) = tpl.handle_index() {
            let obj = &objs[idx];

            match obj {
                PcodeObject::Varnode(vn) => inputs.push(vn.clone()),
                PcodeObject::Handle(h) => {
                    if !h.temp.space.is_dummy() {
                        let load_inputs = vec![Varnode::dummy(), h.pointer.clone()];
                        ops.push(PcodeOp::new(seq.clone(), OpCode::Load, load_inputs, Some(h.temp.clone())));

                        seq = seq.next();
                        inputs.push(h.temp.clone());
                    } else {
                        inputs.push(h.pointer.clone());
                    }
                },
                _ => panic!("unexpected dummy varnode at 0x{:x}", ctx.pc.offset),
            };
        } else {
            let vn = build_varnode(tpl, objs, ctx);
            inputs.push(vn);
        }
    }

    let mut output = None;

    if let Some(tpl) = &op_tpl.output {
        if let Some(idx) = tpl.handle_index() {
            let obj = &objs[idx];

            match obj {
                PcodeObject::Varnode(vn) => output = Some(vn.clone()),
                PcodeObject::Handle(h) => {
                    if !h.temp.space.is_dummy() {
                        let mut output = Some(h.temp.clone());
                        fix_sizes(&mut opcode, &mut inputs, &mut output, ctx);
                        ops.push(PcodeOp::new(seq.clone(), opcode, inputs.clone(), output));

                        seq = seq.next();
                        opcode = OpCode::Store;
                        inputs = vec![Varnode::dummy(), h.pointer.clone(), h.temp.clone()];
                    } else {
                        output = Some(h.pointer.clone());
                    }
                },
                _ => panic!(),
            };
        } else {
            let vn = build_varnode(tpl, objs, ctx);
            output = Some(vn);
        }
    }

    // println!("{} {:?} {:?}", opcode, inputs, output);
    fix_sizes(&mut opcode, &mut inputs, &mut output, ctx);

    let op = PcodeOp {
        seq: seq,
        opcode: opcode,
        inputs: inputs,
        output: output,
    };

    ops.push(op);
}

pub fn _build_sym<'a>(
    matched_sym: &'a MatchedSymbol,
    built_pcodeops: &mut Vec<PcodeOp>,
    built_objects: &mut Vec<PcodeObject>,
    order: &mut Vec<usize>,
    ctx: &BuildContext,
) -> (Option<PcodeObject>, usize, usize) {
    let mut sub_op_ranges = vec![];

    let start_op_idx = built_pcodeops.len();
    let start_obj_idx = built_objects.len();
    let mut handle = None;

    let mut built_op = false;
    let mut ops_start = 0;
    let mut num_ops = 0;

    if let MatchedSymbol::Constructor((ct, operands)) = &matched_sym {
        for (_i, (op, fixup_type)) in operands.iter().enumerate() {
            let mut op_handle = None;
            let mut sub_op_start = 0;
            let mut sub_op_size = 0;

            if let MatchedSymbol::Symbol(sym) = op {
                if let SymbolBody::Varnode(vnode) = &sym.body {
                    let name = match vnode.space {
                        AddressSpace::Register => ctx.lang.varnode_map.get(&(vnode.offset, vnode.size)),
                        _ => None,
                    };

                    let varnode = PcodeObject::Varnode(Varnode {
                        name: name.map(|x| x.clone()),
                        space: vnode.space.to_owned(),
                        offset: vnode.offset,
                        size: vnode.size,
                    });

                    op_handle = Some(varnode);
                }
            }
            else if let MatchedSymbol::Literal((val, size)) = op {
                // NOTE: We're using the name as out-of-band data so that the build cache can re-fixup varnodes. Very hacky.
                let name = match fixup_type {
                    Some(FixupType::Start) => Some(local_str!("fixup_start")),
                    Some(FixupType::End) => Some(local_str!("fixup_end")),
                    _ => None,
                };

                let varnode = PcodeObject::Varnode(Varnode {
                    name: name,
                    space: AddressSpace::Const.to_owned(),
                    offset: *val as u64,
                    size: *size as u64,
                });

                op_handle = Some(varnode);
            } else if let MatchedSymbol::Constructor(_) = op {
                let sub_obj_start = built_objects.len();
                (op_handle, sub_op_start, sub_op_size) = _build_sym(op, built_pcodeops, built_objects, order, ctx);
                built_objects.drain(sub_obj_start..built_objects.len());
            }

            sub_op_ranges.push((sub_op_start, sub_op_size));

            if let Some(handle) = op_handle {
                built_objects.push(handle);
            } else {
                // NOTE: We need a dummy handle for the operand indices to line up??
                built_objects.push(PcodeObject::Dummy);
            }
        }

        let template = ct.template.as_ref().unwrap();

        for stmt in &template.statements {
            if let ConsTemplate::Op(op_template) = stmt {
                if !built_op {
                    ops_start = order.len();
                    built_op = true;
                }

                if op_template.code == "BUILD" {
                    if let ConstTemplate::Val(op_idx) = op_template.inputs[0].offset_template {
                        let idx = op_idx as usize;
                        let (start, sz) = sub_op_ranges[idx];

                        for i in start..(start + sz) {
                            order.push(order[i]);
                        }

                        num_ops += sz;
                    };
                } else {
                    let start = built_pcodeops.len();

                    let seq = SeqNum {
                        pc: ctx.pc.clone(),
                        uniq: (start_op_idx + num_ops) as i32,
                        order: 0,
                    };

                    build_pcodeop(
                        seq,
                        &op_template,
                        &built_objects[start_obj_idx..],
                        built_pcodeops,
                        ctx,
                    );

                    let end = built_pcodeops.len();

                    for i in start..end {
                        order.push(i);
                    }

                    num_ops += end - start;
                } 
            }
        }

        // Handle the varnodes after all the operands have been built.
        for stmt in &template.statements {
            if let ConsTemplate::Handle(handle_template) = stmt {
                let objs = &built_objects[start_obj_idx..];
                let my_handle = build_handle(&handle_template, objs, ctx);
                handle = Some(my_handle);
            }
        }
    }

    (handle, ops_start, num_ops)
}

fn sort_by_indices<T>(data: &mut [T], mut indices: Vec<usize>) {
    for idx in 0..data.len() {
        if indices[idx] != idx {
            let mut current_idx = idx;
            loop {
                let target_idx = indices[current_idx];
                indices[current_idx] = current_idx;
                if indices[target_idx] == target_idx {
                    break;
                }
                data.swap(current_idx, target_idx);
                current_idx = target_idx;
            }
        }
    }
}

pub fn build_sym<'a>(
    matched_sym: &'a MatchedSymbol,
    pc: &Address,
    bit_len: usize,
    lang: &'a SleighLanguage,
) -> Vec<PcodeOp> {
    let ctx = BuildContext {
        lang: lang,
        pc: pc,
        bit_len: bit_len,
    };

    let mut ops = vec![];
    let mut objs = vec![];
    let mut order = vec![];

    let (_, ops_start, num_ops) = _build_sym(matched_sym, &mut ops, &mut objs, &mut order, &ctx);

    let _ = order.drain(0..ops_start);
    order.truncate(num_ops);

    sort_by_indices(&mut ops, order);

    while let Some(op) = ops.last().as_ref() {
        if op.opcode == OpCode::Load && op.output.as_ref().unwrap().space == AddressSpace::Unique {
            let _ = ops.pop();
        } else {
            break;
        }
    }

    let mut labels: HashMap<SeqNum, u64> = HashMap::default();
    let mut label_idxs: HashMap<u64, usize> = HashMap::default();

    for (i, op) in ops.iter().enumerate() {
        if op.opcode == OpCode::Label {
            let seq = if i + 1 < ops.len() {
                ops[i + 1].seq.clone()
            } else {
                ops[ops.len() - 1].seq.next() // FIXME
            };

            labels.insert(seq, op.inputs[0].offset);
        }
    }

    ops.retain(|op| op.opcode != OpCode::Label);

    for (i, op) in ops.iter().enumerate() {
        if let Some(lbl_idx) = labels.get(&op.seq) {
            label_idxs.insert(*lbl_idx, i);
        }
    }

    let n = ops.len();

    for (i, op) in ops.iter_mut().enumerate() {
        if (op.opcode == OpCode::Branch || op.opcode == OpCode::CBranch) && op.inputs[0].space == AddressSpace::Const {
            let idx = op.inputs[0].offset;
            let lbl_idx = label_idxs.get(&idx).copied().unwrap_or(n);
            op.inputs[0].offset = ((lbl_idx as i64 - i as i64) as u32) as u64;
        }
    }

    // Fixup the seqnums.
    for (i, op) in ops.iter_mut().enumerate() {
        op.seq.uniq = i as i32;
    }

    ops
}

fn _build_cmd_text(cmd: &PrintCommand, operands: &Vec<(MatchedSymbol, Option<FixupType>)>, text: &mut String, ops: &[PcodeOp]) {
    match cmd {
        PrintCommand::Op(op_idx) => _build_text(&operands[*op_idx as usize].0, text, ops),
        PrintCommand::Piece(piece) => text.push_str(piece),
    }
}

pub fn _build_text(matched_sym: &MatchedSymbol, text: &mut String, ops: &[PcodeOp]) {
    match &matched_sym {
        MatchedSymbol::Constructor((ct, operands)) => {
            if let Some(cmds) = &ct.print_commands {
                for cmd in cmds {
                    _build_cmd_text(cmd, &operands, text, ops);
                }
            }
        },
        MatchedSymbol::Symbol(sym) => {
            if let SymbolBody::Varnode(vnode) = &sym.body {
                text.push_str(&vnode.name);
            }
        },
        MatchedSymbol::Literal((val, sz)) => {
            let mut v = *val as u64;
            let mut sign_str = "";

            let (neg_v, is_neg) = match sz {
                1 if (*val >> 7) != 0 => ((*val ^ 0xff) as u64 + 1, true),
                2 if (*val >> 15) != 0 => ((*val ^ 0xffff) as u64 + 1, true),
                4 if (*val >> 31) != 0 => ((*val ^ 0xffffffff) as u64 + 1, true),
                8 if (*val >> 63) != 0 => ((*val ^ 0xffffffffffffffffu64 as i64) as u64 + 1, true),
                _ => (*val as u64, false),
            };

            let shift = 64 - (*sz as usize) * 8;
            let sext_v = (((v << shift) as i64) >> shift) as u64;

            for op in ops {
                if matches!(op.opcode, OpCode::IntSub) && op.inputs[1].space == AddressSpace::Const && op.inputs[1].offset > 0 && op.inputs[1].offset == neg_v && is_neg {
                    v = neg_v;
                    sign_str = "-";
                    break;
                } else if matches!(op.opcode, OpCode::IntSBorrow) && op.inputs[1].space == AddressSpace::Const && op.inputs[1].offset > 0 && is_neg {
                    if op.inputs[1].offset == (sext_v >> (64 - op.inputs[1].size * 8)) {
                        v = neg_v;
                        sign_str = "-";
                        break;
                    }
                }
            }

            if *sz == 8 && is_neg {
                v = neg_v;
                sign_str = "-";
            }

            text.push_str(format!("{}0x{:x}", sign_str, v).as_str());
        },
        MatchedSymbol::String(s) => {
            text.push_str(&s);
        }
    }
}

pub fn build_text(matched_sym: &MatchedSymbol, ops: &[PcodeOp]) -> String {
    let mut text = String::new();
    _build_text(matched_sym, &mut text, ops);
    text
}
