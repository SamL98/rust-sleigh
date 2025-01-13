use super::compound_varnode::{VarnodeMap, VarnodeStack};
use super::csleigh::{csleigh_Varnode, get_addr_space_name, csleigh_isConst, csleigh_isRegister, csleigh_isRam, csleigh_isUnique, get_space};
use super::types::{Context, SsaVarnode, Varnode, VarnodeUses, AddressSpace};

use std::cell::RefCell;
use std::clone::Clone;
use std::cmp::{Eq, PartialEq};
use std::fmt;
use std::hash::{Hash, Hasher};

impl Varnode {
    fn to_string(&self) -> String {
        match &self.name {
            Some(name) => format!("{}", name),
            None => match &self.space {
                AddressSpace::Register => format!("{}_{}", self.offset, self.size),
                AddressSpace::Unique => format!("U{:x}:{}", self.offset, self.size),
                AddressSpace::Const => format!("0x{:x}:{}", self.offset, self.size),
                AddressSpace::Ram => format!("[ram]0x{:x}:{}", self.offset, self.size),
                AddressSpace::Other(s) => format!("[{}]0x{:x}:{}", s, self.offset, self.size),
            },
        }
    }

    pub fn is_live(&self, atom_stack: &RefCell<VarnodeStack>) -> bool {
        if self.is_const() {
            return true;
        }

        match atom_stack.borrow().get(self) {
            Some(vnodes) => vnodes.len() > 0 && vnodes[vnodes.len() - 1].version > 0,
            _ => false,
        }
    }

    pub fn unwind_version(&self, atom_stack: &RefCell<VarnodeStack>) {
        if let Some(atoms) = atom_stack.borrow_mut().get_mut(self) {
            if atoms.len() > 0 {
                atoms.pop();
            }
        }
    }

    pub fn get_top(
        &self,
        existing_atoms: &RefCell<VarnodeMap>,
        atom_stack: &RefCell<VarnodeStack>,
    ) -> SsaVarnode {
        if self.space == AddressSpace::Const {
            return SsaVarnode {
                inner: self.clone(),
                version: 0,
            };
        }

        let mut result: Option<SsaVarnode> = None;

        if let Some(curr_stack) = atom_stack.borrow().get(self) {
            if let Some(last) = curr_stack.last() {
                result = Some(last.clone());
            }
        }

        if result == None {
            result = Some(SsaVarnode::new(self, existing_atoms, atom_stack));
        }

        result.unwrap()
    }
}

impl fmt::Debug for Varnode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({}, {:x}, {})", self.space, self.offset, self.size)
    }
}

// impl Hash for Varnode {
//     fn hash<H: Hasher>(&self, state: &mut H) {
//         self.space.hash(state);
//         self.offset.hash(state);
//         self.size.hash(state);
//     }
// }

impl fmt::Debug for SsaVarnode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "({}, {:x}, {}) - {}",
            self.inner.space, self.inner.offset, self.inner.size, self.version
        )
    }
}

impl fmt::Display for Varnode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

const SUBSCRIPTS: [&'static str; 10] = [
    "\u{2080}", "\u{2081}", "\u{2082}", "\u{2083}", "\u{2084}", "\u{2085}", "\u{2086}", "\u{2087}",
    "\u{2088}", "\u{2089}",
];

impl SsaVarnode {
    pub fn new(
        vnode: &Varnode,
        existing_atoms: &RefCell<VarnodeMap>,
        atom_stack: &RefCell<VarnodeStack>,
    ) -> SsaVarnode {
        let mut version = 0;

        if let Some(existing_versions) = existing_atoms.borrow().get(&vnode) {
            if !existing_versions.is_empty() {
                version = existing_versions.iter().map(|it| it.version).max().unwrap() + 1;
            }
        }

        let vn = SsaVarnode {
            inner: vnode.clone(),
            version: version,
        };

        existing_atoms
            .borrow_mut()
            .entry(vnode.clone())
            .or_insert_with(Vec::new)
            .push(vn.clone());

        atom_stack
            .borrow_mut()
            .entry(vnode.clone())
            .or_insert_with(Vec::new)
            .push(vn.clone());

        vn
    }

    fn to_string(&self) -> String {
        let mut subscripts = vec![SUBSCRIPTS[(self.version % 10) as usize]];
        let mut remainder = self.version / 10;

        while remainder > 0 {
            subscripts.insert(0, SUBSCRIPTS[(remainder % 10) as usize]);
            remainder = remainder / 10;
        }

        format!("{}{}", self.inner.to_string(), subscripts.join(""))
    }

    pub fn is_dead(&self, uses: &VarnodeUses) -> bool {
        !uses.contains_key(self) || uses[self].len() == 0
    }
}

impl fmt::Display for SsaVarnode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

pub trait VarnodeIface {
    fn space(&self) -> &AddressSpace;
    fn offset(&self) -> u64;
    fn size(&self) -> u32;
    fn is_const(&self) -> bool;
    fn is_unique(&self) -> bool;
    fn is_ram(&self) -> bool;
    fn is_reg(&self) -> bool;
    fn dominates(&self, other: Self) -> bool;
    fn atoms(&self) -> Vec<Self> where Self: Sized;
    fn as_vnode(&self) -> Varnode;
}

impl Varnode {
    pub fn new(ctx: &Context, vnode_c: *const csleigh_Varnode) -> Varnode {
        // let addr_space_str = get_addr_space_name(unsafe { (*vnode_c).space });
        let space = get_space(vnode_c);
        let offset = unsafe { (*vnode_c).off };
        let size = unsafe { (*vnode_c).size };

        // if addr_space_str == "register" {
        if space == AddressSpace::Register {
            match ctx.registers.get(&(offset, size)) {
                Some(vnode) => vnode.clone(),
                None => Varnode {
                    name: None,
                    space: space,
                    offset: offset,
                    size: size,
                },
            }
        } else {
            Varnode {
                name: None,
                space: space,
                offset: offset,
                size: size,
            }
        }
    }
}

pub trait VarnodeIface2 {
    fn copy_with(&self, offset: u64, size: u32, name: Option<String>) -> Self;
    fn is_next(&self, other: &Self) -> bool;
}

impl VarnodeIface2 for Varnode {
    fn copy_with(&self, offset: u64, size: u32, name: Option<String>) -> Self {
        Varnode {
            name: name,
            space: self.space().clone(),
            offset: offset,
            size: size,
        }
    }

    fn is_next(&self, other: &Self) -> bool {
        other.offset() + 1 == self.offset() && self.space() == other.space()
    }
}

impl VarnodeIface2 for SsaVarnode {
    fn copy_with(&self, offset: u64, size: u32, name: Option<String>) -> Self {
        SsaVarnode {
            inner: self.inner.copy_with(offset, size, name),
            version: self.version,
        }
    }

    fn is_next(&self, other: &Self) -> bool {
        self.inner.is_next(&other.inner) && self.version == other.version
    }
}

impl VarnodeIface for Varnode {
    fn as_vnode(&self) -> Varnode {
        self.clone()
    }

    #[inline(always)]
    fn space(&self) -> &AddressSpace {
        &self.space
    }

    #[inline(always)]
    fn offset(&self) -> u64 {
        self.offset
    }

    #[inline(always)]
    fn size(&self) -> u32 {
        self.size
    }

    #[inline(always)]
    fn is_const(&self) -> bool {
        self.space == AddressSpace::Const
    }

    #[inline(always)]
    fn is_unique(&self) -> bool {
        self.space == AddressSpace::Unique
    }

    #[inline(always)]
    fn is_ram(&self) -> bool {
        self.space == AddressSpace::Ram
    }

    #[inline(always)]
    fn is_reg(&self) -> bool {
        self.space == AddressSpace::Register
    }

    #[inline(always)]
    fn dominates(&self, other: Self) -> bool {
        other.is_const()
    }

    fn atoms(&self) -> Vec<Self> {
        if self.is_const() {
            vec![self.clone()]
        } else {
            (0..self.size()).map(|i| self.copy_with(i as u64, 1, None)).collect()
        }
    }
}

impl VarnodeIface for SsaVarnode {
    fn as_vnode(&self) -> Varnode {
        self.inner.clone()
    }

    #[inline(always)]
    fn space(&self) -> &AddressSpace {
        &self.inner.space
    }

    #[inline(always)]
    fn offset(&self) -> u64 {
        self.inner.offset
    }

    #[inline(always)]
    fn size(&self) -> u32 {
        self.inner.size
    }

    #[inline(always)]
    fn is_const(&self) -> bool {
        self.inner.is_const()
    }

    #[inline(always)]
    fn is_unique(&self) -> bool {
        self.inner.is_unique()
    }

    #[inline(always)]
    fn is_ram(&self) -> bool {
        self.inner.is_ram()
    }

    #[inline(always)]
    fn is_reg(&self) -> bool {
        self.inner.is_reg()
    }

    #[inline(always)]
    fn dominates(&self, other: Self) -> bool {
        other.is_const()
    }

    fn atoms(&self) -> Vec<Self> {
        if self.is_const() {
            vec![self.clone()]
        } else {
            (0..self.size()).map(|i| self.copy_with(i as u64, 1, None)).collect()
        }
    }
}
