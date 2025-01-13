use fxhash::{FxHashMap, FxHashSet};

use super::csleigh::{
    csleigh_Sleigh_getAllRegisters, csleigh_createContext, csleigh_setVariableDefault, csleigh_resetVariables,
    csleigh_translate, csleigh_setData, csleigh_addSegment, get_addr_space_name, get_str, get_space
};
// csleigh_Sleigh_getNumRegisters,
use super::instruction::InstructionIface;
use super::types::{
    Address, CContext, Context, Instruction, Language, Prototype, Varnode,
};

use libc::c_void;
use std::ffi::CString;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use std::fs;
use std::io;
use std::io::{Read, Seek};

pub trait ContextIface {
    fn new(
        c_ctx: CContext,
        lang: Language,
        registers: Arc<RegMap>,
        reg_sizes: Arc<Vec<Vec<Varnode>>>,
        compiler_id: &str,
    ) -> Context;
    fn set_data(&self, raw_bytes: &[u8]);
    fn add_segment(&self, address: u64, offset: u64, size: u32);
    fn reset(&self);
    fn disassemble_one(&self, address: u64) -> Option<Instruction>;
}

pub type RegMap = FxHashMap<(u64, u32), Varnode>;
pub type RegNameMap = FxHashMap<String, Varnode>;

pub fn load_c_ctx(sla_path: &str) -> (*const c_void, RegMap, Vec<Vec<Varnode>>, RegNameMap) {
    let sla_path_cstr = CString::new(sla_path).unwrap();
    let c_ctx = unsafe { csleigh_createContext(sla_path_cstr.as_ptr()) };

    let mut num_registers: u32 = 0;
    let register_defs_ptr = unsafe { csleigh_Sleigh_getAllRegisters(c_ctx, &mut num_registers) };
    let register_defs =
        unsafe { std::slice::from_raw_parts(register_defs_ptr, num_registers as usize) };

    let mut registers: RegMap = FxHashMap::default();
    let mut register_names: RegNameMap = FxHashMap::default();
    let mut max_off = 0;

    for def in register_defs {
        let name = get_str(def.name);

        let register = Varnode {
            name: Some(name.clone()),
            space: get_space(&def.vnode),
            offset: def.vnode.off,
            size: def.vnode.size,
        };

        registers.insert((def.vnode.off, def.vnode.size), register.clone());
        register_names.insert(name.clone(), register.clone());

        max_off = max_off.max(def.vnode.off + def.vnode.size as u64);
    }

    let mut register_sizes: Vec<Vec<Varnode>> = Vec::with_capacity(max_off as usize);

    for _ in 0..max_off {
        register_sizes.push(vec![]);
    }

    for reg in registers.values() {
        register_sizes[reg.offset as usize].push(reg.clone());
    }

    for i in 0..register_sizes.len() {
        register_sizes[i].sort_by(|a, b| a.size.cmp(&b.size));
    }

    (c_ctx, registers, register_sizes, register_names)
}

impl ContextIface for Context {
    fn new(
        c_ctx: CContext,
        lang: Language,
        registers: Arc<RegMap>,
        reg_sizes: Arc<Vec<Vec<Varnode>>>,
        compiler_id: &str,
    ) -> Context {
        // Set the context variables.
        for (var, val) in &lang.pspec.defaults {
            let var_cstr = CString::new(var.as_str()).unwrap();
            unsafe { csleigh_setVariableDefault(c_ctx.ptr, var_cstr.as_ptr(), *val) };
        }

        return Context {
            ctx_c: c_ctx,
            lang: lang.clone(),
            registers: registers,
            reg_sizes: reg_sizes,
            cspec: lang.cspecs[compiler_id].clone(),
        };
    }

    fn set_data(&self, raw_bytes: &[u8]) {
        unsafe { csleigh_setData(self.ctx_c.ptr, raw_bytes.as_ptr(), raw_bytes.len() as u32) };
    }

    fn reset(&self) {
        unsafe { csleigh_resetVariables(self.ctx_c.ptr) };
    }

    fn add_segment(&self, address: u64, offset: u64, size: u32) {
        unsafe { csleigh_addSegment(self.ctx_c.ptr, address, offset, size) };
    }

    fn disassemble_one(&self, address: u64) -> Option<Instruction> {
        let res = unsafe { csleigh_translate(self.ctx_c.ptr, address, 1, 1) };

        if res.is_null() {
            println!("Null translation result at {:x}", address);
            return None;
        }

        if unsafe { (*res).error.error_type } > 0 {
            // println!("Could not disassemble instruction at {:x}", address);
            return None;
        }

        let num_insns = unsafe { (*res).num_insns };
        let insns = unsafe { (*res).insns };

        if num_insns == 0 || insns.is_null() {
            println!("No instructions disassembled at {:x}", address);
            return None;
        }

        let insn = Instruction::new(self, insns);
        return Some(insn);
    }
}

