use super::types::{
    GenericVarnode,
    RegisterVarnode,
    Varnode,
    Context
};

use std::cmp::{PartialEq, Eq};
use std::hash::{Hash, Hasher};
use std::clone::Clone;
use std::fmt;

impl fmt::Display for GenericVarnode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{:X}:{}", self.space, self.offset, self.size)
    }
}

impl fmt::Display for RegisterVarnode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl fmt::Display for Varnode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Varnode::Generic(generic) => write!(f, "{}", generic),
            Varnode::Register(register) => write!(f, "{}", register)
        }
    }
}

pub trait VarnodeIface {
    //fn new(ctx: &Context, vnode_c: *const csleigh_Varnode) -> Varnode;
    fn space(&self) -> &String;
    fn offset(&self) -> u64;
    fn size(&self) -> u32;
}

impl VarnodeIface for Varnode {
     /*fn new(ctx: &Context, vnode_c: *const csleigh_Varnode) -> Varnode {
        let addr_space_str = get_addr_space_name(unsafe { (*vnode_c).space });
        let generic_vnode = GenericVarnode {
            space: addr_space_str,
            offset: unsafe { (*vnode_c).off },
            size: unsafe { (*vnode_c).size }
        };

        if ctx.registers.contains_key(&generic_vnode) {
            Varnode::Register(ctx.registers.get(&generic_vnode).unwrap().clone())
        }
        else {
            Varnode::Generic(generic_vnode)
        }
    }*/

    fn space(&self) -> &String {
        match self {
            Varnode::Generic(generic) => &generic.space,
            Varnode::Register(register) => &register.space,
        }
    }

    fn offset(&self) -> u64 {
        match self {
            Varnode::Generic(generic) => generic.offset,
            Varnode::Register(register) => register.offset,
        }
    }

    fn size(&self) -> u32 {
        match self {
            Varnode::Generic(generic) => generic.size,
            Varnode::Register(register) => register.size,
        }
    }
}
