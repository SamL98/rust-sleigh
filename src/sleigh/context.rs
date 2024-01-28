use super::types::{
    Context,
    Instruction,
    GenericVarnode,
    RegisterVarnode
};
use super::instruction::InstructionIface;
use crate::arch::Language;

use std::collections::HashMap;

pub trait ContextIface {
    fn new(lang: Language, compiler_id: &str) -> Context;
    fn disassemble_one(&self, bytes: &Vec<u8>, address: u64) -> Option<Instruction>;
}

/*impl ContextIface for Context {
    fn new(lang: Language, compiler_id: &str) -> Context {
        let sla_path_cstr = CString::new(lang.sla_path.to_str().unwrap()).unwrap();
        let ctx_c = unsafe { csleigh_createContext(sla_path_cstr.as_ptr()) };

        // Set the context variables.
        for (var, val) in lang.pspec.defaults {
            let var_cstr = CString::new(var.as_str()).unwrap();
            unsafe { csleigh_setVariableDefault(ctx_c, var_cstr.as_ptr(), val) };
        }

        let num_registers = unsafe { csleigh_Sleigh_getNumRegisters(ctx_c) };
        let mut register_defs: Vec<csleigh_RegisterDefinition> = Vec::with_capacity(num_registers as usize);
        unsafe { csleigh_Sleigh_getAllRegisters(ctx_c, num_registers, register_defs.as_mut_ptr()) };
        unsafe { register_defs.set_len(num_registers as usize) };

        let mut registers: HashMap<GenericVarnode, RegisterVarnode> = HashMap::new();

        for def in register_defs {
            let varnode = GenericVarnode {
                space: get_addr_space_name(def.vnode.space),
                offset: def.vnode.off,
                size: def.vnode.size
            };

            let register = RegisterVarnode {
                name: get_str(def.name),
                space: get_addr_space_name(def.vnode.space),
                offset: def.vnode.off,
                size: def.vnode.size
            };

            registers.insert(varnode, register);
        }

        return Context {
            ctx_c: ctx_c,
            registers: registers
        };
    }

    fn disassemble_one(&self, bytes: &Vec<u8>, address: u64) -> Option<Instruction> {
        let res = unsafe { 
            csleigh_translate(self.ctx_c, bytes.as_ptr(), 0x10, address, 1, 1) 
        };

        if res.is_null() {
            println!("Null translation result at {:x}", address);
            return None;
        }

        if unsafe { (*res).error.error_type } > 0 {
            println!("Could not disassemble instruction at {:x}", address);
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
}*/
