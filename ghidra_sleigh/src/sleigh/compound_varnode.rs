use fxhash::{FxHashMap, FxHashSet};

use super::context::RegMap;
use super::pcode::PcodeIface;
use super::types::{
    Address, CompoundVarnode, Context, GenericCompoundVarnode, GenericPcodeOp, PcodeOp, PcodeType,
    SsaCompoundVarnode, SsaPcodeOp, SsaVarnode, Varnode, VarnodeDefns, VarnodeUses, Vnode, VarnodeComps, AddressSpace
};
use super::varnode::{VarnodeIface, VarnodeIface2};

use std::cell::{Ref, RefCell};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

pub trait CompoundVarnodeIface {
    type VnodeType;

    fn space(&self) -> &AddressSpace;
    fn offset(&self) -> u64;
    fn size(&self) -> u32;
    fn is_const(&self) -> bool;
    fn is_unique(&self) -> bool;
    fn is_ram(&self) -> bool;
    fn is_reg(&self) -> bool;
    fn dominates(&self, other: Self) -> bool;
    fn addr(&self) -> Option<Address>;
    fn atoms(&self) -> Vec<Self::VnodeType>;
    fn intersects(&self, other: &Self) -> bool;
}

pub trait CompoundVarnodeIface2 {
    type VnodeType;

    fn convert_to_const(&self, val: u64, size: u32) -> Self;
    fn copy_with(&self, comps: Vec<Self::VnodeType>) -> Self;
    fn union_with(&self, other: &Self) -> Self;
    fn intersection_with(&self, other: &Self) -> Self;
}

impl<V: Vnode> CompoundVarnodeIface for GenericCompoundVarnode<V> {
    type VnodeType = V;

    #[inline(always)]
    fn space(&self) -> &AddressSpace {
        match &self.comps {
            VarnodeComps::Simple(vn) => vn.space(),
            VarnodeComps::Complex(vns) => vns[0].space(),
        }
    }

    #[inline(always)]
    fn offset(&self) -> u64 {
        match &self.comps {
            VarnodeComps::Simple(vn) => vn.offset(),
            VarnodeComps::Complex(vns) => vns[0].offset(),
        }
    }

    fn size(&self) -> u32 {
        match &self.comps {
            VarnodeComps::Simple(vn) => vn.size(),
            VarnodeComps::Complex(vns) => vns.iter().map(|v| v.size()).sum(),
        }
    }

    #[inline(always)]
    fn is_const(&self) -> bool {
        match &self.comps {
            VarnodeComps::Simple(vn) => vn.is_const(),
            VarnodeComps::Complex(vns) => vns[0].is_const(),
        }
    }

    #[inline(always)]
    fn is_unique(&self) -> bool {
        match &self.comps {
            VarnodeComps::Simple(vn) => vn.is_unique(),
            VarnodeComps::Complex(vns) => vns[0].is_unique(),
        }
    }

    #[inline(always)]
    fn is_ram(&self) -> bool {
        match &self.comps {
            VarnodeComps::Simple(vn) => vn.is_ram(),
            VarnodeComps::Complex(vns) => vns[0].is_ram(),
        }
    }

    #[inline(always)]
    fn is_reg(&self) -> bool {
        match &self.comps {
            VarnodeComps::Simple(vn) => vn.is_reg(),
            VarnodeComps::Complex(vns) => vns[0].is_reg(),
        }
    }

    #[inline(always)]
    fn dominates(&self, other: Self) -> bool {
        other.is_const()
    }

    #[inline(always)]
    fn addr(&self) -> Option<Address> {
        if self.is_ram() {
            Some(Address {
                space: self.space().clone(),
                offset: self.offset(),
            })
        } else {
            None
        }
    }

    fn atoms(&self) -> Vec<Self::VnodeType> {
        match &self.comps {
            VarnodeComps::Simple(vn) => vn.atoms(),
            VarnodeComps::Complex(vns) => {
                let mut atoms = vec![];
                for vn in vns {
                    atoms.append(&mut vn.atoms());
                }
                atoms
            }
        }
    }

    fn intersects(&self, other: &Self) -> bool {
        let set1: FxHashSet<V> = self.atoms().into_iter().collect();
        let set2: FxHashSet<V> = other.atoms().into_iter().collect();
        return set1
            .intersection(&set2)
            .into_iter()
            .collect::<Vec<&V>>()
            .len()
            > 0;
    }
}

impl CompoundVarnodeIface2 for CompoundVarnode {
    type VnodeType = Varnode;

    fn convert_to_const(&self, val: u64, size: u32) -> Self {
        let vnode = Varnode {
            name: None,
            space: AddressSpace::Const,
            offset: val,
            size: size,
        };
        CompoundVarnode::new(vnode, self.reg_sizes.clone())
    }

    fn copy_with(&self, comps: Vec<Self::VnodeType>) -> Self {
        let actual_comps = if comps.len() == 1 {
            VarnodeComps::Simple(comps[0].clone())
        } else {
            VarnodeComps::Complex(comps)
        };

        CompoundVarnode {
            comps: actual_comps,
            reg_sizes: self.reg_sizes.clone(),
        }
    }

    fn union_with(&self, other: &Self) -> Self {
        let set1: FxHashSet<Self::VnodeType> = self.atoms().into_iter().collect();
        let set2: FxHashSet<Self::VnodeType> = other.atoms().into_iter().collect();

        let mut new_atoms = set1
            .union(&set2)
            .into_iter()
            .cloned()
            .collect::<Vec<Self::VnodeType>>();

        new_atoms.sort_by(|a, b| a.offset().cmp(&b.offset()));
        let new_comps = coalesce_atoms(&new_atoms, &self.reg_sizes);
        return self.copy_with(new_comps);
    }

    fn intersection_with(&self, other: &Self) -> Self {
        let set1: FxHashSet<Self::VnodeType> = self.atoms().into_iter().collect();
        let set2: FxHashSet<Self::VnodeType> = other.atoms().into_iter().collect();

        let mut new_atoms = set1
            .intersection(&set2)
            .into_iter()
            .cloned()
            .collect::<Vec<Self::VnodeType>>();

        new_atoms.sort_by(|a, b| a.offset().cmp(&b.offset()));
        let new_comps = coalesce_atoms(&new_atoms, &self.reg_sizes);
        return self.copy_with(new_comps);
    }
}

impl CompoundVarnodeIface2 for SsaCompoundVarnode {
    type VnodeType = SsaVarnode;

    fn convert_to_const(&self, val: u64, size: u32) -> Self {
        let vnode = Varnode {
            name: None,
            space: AddressSpace::Const,
            offset: val,
            size: size,
        };
        let ssa_vnode = SsaVarnode {
            inner: vnode,
            version: 0,
        };
        SsaCompoundVarnode::new(ssa_vnode, self.reg_sizes.clone())
    }

    fn copy_with(&self, comps: Vec<Self::VnodeType>) -> Self {
        let actual_comps = if comps.len() == 1 {
            VarnodeComps::Simple(comps[0].clone())
        } else {
            VarnodeComps::Complex(comps)
        };

        SsaCompoundVarnode {
            comps: actual_comps,
            reg_sizes: self.reg_sizes.clone(),
        }
    }

    fn union_with(&self, other: &Self) -> Self {
        let set1: FxHashSet<Self::VnodeType> = self.atoms().into_iter().collect();
        let set2: FxHashSet<Self::VnodeType> = other.atoms().into_iter().collect();

        let mut new_atoms = set1
            .union(&set2)
            .into_iter()
            .cloned()
            .collect::<Vec<Self::VnodeType>>();

        new_atoms.sort_by(|a, b| a.offset().cmp(&b.offset()));
        let new_comps = coalesce_atoms(&new_atoms, &self.reg_sizes);
        return self.copy_with(new_comps);
    }

    fn intersection_with(&self, other: &Self) -> Self {
        let set1: FxHashSet<Self::VnodeType> = self.atoms().into_iter().collect();
        let set2: FxHashSet<Self::VnodeType> = other.atoms().into_iter().collect();

        let mut new_atoms = set1
            .intersection(&set2)
            .into_iter()
            .cloned()
            .collect::<Vec<Self::VnodeType>>();

        new_atoms.sort_by(|a, b| a.offset().cmp(&b.offset()));
        let new_comps = coalesce_atoms(&new_atoms, &self.reg_sizes);
        return self.copy_with(new_comps);
    }
}

pub type VarnodeMap = FxHashMap<Varnode, Vec<SsaVarnode>>;
pub type VarnodeStack = FxHashMap<Varnode, Vec<SsaVarnode>>;

impl<V: Vnode> GenericCompoundVarnode<V> {
    pub fn new(vnode: V, reg_sizes: Arc<Vec<Vec<Varnode>>>) -> GenericCompoundVarnode<V> {
        GenericCompoundVarnode {
            comps: VarnodeComps::Simple(vnode),
            reg_sizes: reg_sizes,
        }
    }

    pub fn neighbors(&self, other: &Self) -> bool {
        // TODO: Make work with complex varnodes.
        match (&self.comps, &other.comps) {
            (VarnodeComps::Simple(vn1), VarnodeComps::Simple(vn2)) if vn1.space() == vn2.space() => {
                let min: i64 = vn1.offset().max(vn2.offset()) as i64;
                let max: i64 = (vn1.offset() + vn1.size() as u64).min(vn2.offset() + vn2.size() as u64) as i64;
                (max - min) >= 0
            },
            _ => false,
        }
    }

    pub fn is_sp(&self, ctx: Arc<Context>) -> bool {
        match &self.comps {
            VarnodeComps::Simple(vn) => vn.as_vnode() == ctx.cspec.stack_pointer,
            VarnodeComps::Complex(vns) => vns.len() == 1 && vns[0].as_vnode() == ctx.cspec.stack_pointer,
        }
    }
}

impl<V: Vnode> Hash for VarnodeComps<V> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            VarnodeComps::Simple(vn) => vn.hash(state),
            VarnodeComps::Complex(vns) => {
                for vn in vns {
                    vn.hash(state);
                }
            }
        }
    }
}

impl<V: Vnode> Hash for GenericCompoundVarnode<V> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.comps.hash(state);
    }
}

impl<V: Vnode> PartialEq for VarnodeComps<V> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (VarnodeComps::Simple(vn1), VarnodeComps::Simple(vn2)) => vn1 == vn1,
            (VarnodeComps::Complex(vns1), VarnodeComps::Complex(vns2)) => vns1 == vns2,
            _ => false,
        }
    }
}

impl<V: Vnode> PartialEq for GenericCompoundVarnode<V> {
    fn eq(&self, other: &Self) -> bool {
        self.comps == other.comps
    }
}

impl<V: Vnode> Eq for VarnodeComps<V> {}
impl<V: Vnode> Eq for GenericCompoundVarnode<V> {}

impl<V: Vnode> fmt::Debug for GenericCompoundVarnode<V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.comps {
            VarnodeComps::Simple(vn) => write!(f, "{:?}", vn),
            VarnodeComps::Complex(vns) => {
                write!(
                    f,
                    "{}",
                    vns
                        .iter()
                        .map(|v| format!("{:?}", v))
                        .collect::<Vec<String>>()
                        .join(":")
                )
            }
        }
    }
}

impl<V: Vnode> fmt::Display for GenericCompoundVarnode<V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.comps {
            VarnodeComps::Simple(vn) => write!(f, "{}", vn),
            VarnodeComps::Complex(vns) => {
                write!(
                    f,
                    "{}",
                    coalesce_atoms(vns, &self.reg_sizes)
                        .iter()
                        .map(|v| format!("{}", v))
                        .collect::<Vec<String>>()
                        .join(":")
                )
            }
        }
    }
}

// TODO: Make varnode tree where you gradually look for larger matching registers.
fn _coalesce_reg_atoms<V: Vnode>(atoms: Vec<&V>, reg_sizes: &Arc<Vec<Vec<Varnode>>>) -> Vec<V> {
    let mut comps: Vec<V> = vec![];
    let mut i = 0;

    while i < atoms.len() {
        let off = atoms[i].offset();

        // If the current atom is not mapped to a register start, take atoms until it is.
        if reg_sizes[atoms[i].offset() as usize].len() == 0 {
            let mut prev_atom = atoms[i];
            let start_idx = i;
            i += 1;

            while i < atoms.len()
                && reg_sizes[atoms[i].offset() as usize].len() == 0
                && atoms[i].is_next(prev_atom)
            {
                prev_atom = atoms[i];
                i += 1;
            }

            if i > start_idx {
                let comp_size = atoms[i - 1].offset() - off + 1;
                comps.push(atoms[start_idx].copy_with(off, comp_size as u32, None));
                continue;
            }
        } else {
            let mut matched_size = 1;
            let mut matched_reg: Option<&Varnode> = None;

            for reg in &reg_sizes[off as usize] {
                let reg_size = reg.size;

                // Bail if there simply aren't enough atoms for a register of this size.
                if i + reg_size as usize > atoms.len() {
                    break;
                }

                // Otherwise check if the next N atoms are consecutive atoms of the register.
                // Start the iteration one back so that can check if continguous with previous varnodes.
                let mut matched = true;
                let mut prev_atom = atoms[i];

                for j in 1..(reg_size as usize) {
                    if !atoms[i + j].is_next(prev_atom) {
                        matched = false;
                        break;
                    }

                    prev_atom = atoms[i + j];
                }

                if matched {
                    matched_size = reg_size;
                    matched_reg = Some(reg);
                }
            }

            match matched_reg {
                Some(reg) => {
                    comps.push(atoms[i].copy_with(reg.offset(), reg.size(), reg.name.clone()))
                }
                None => comps.push(atoms[i].copy_with(off, matched_size, None)),
            }
            i += matched_size as usize;
        }
    }

    comps
}

fn _coalesce_atoms<V: Vnode>(atoms: Vec<&V>) -> Vec<V> {
    let mut comps = vec![];

    if atoms.len() == 0 {
        return comps;
    }

    let mut start_atom = atoms[0];
    let mut prev_atom = atoms[0];

    for atom in &atoms[1..] {
        if !atom.is_next(prev_atom) {
            comps.push(atom.copy_with(
                start_atom.offset(),
                (prev_atom.offset() - start_atom.offset()) as u32,
                None,
            ));
            start_atom = atom;
        }
        prev_atom = atom;
    }

    if start_atom.offset() <= atoms[atoms.len() - 1].offset() {
        comps.push(atoms[atoms.len() - 1].copy_with(
            start_atom.offset(),
            (atoms[atoms.len() - 1].offset() + 1 - start_atom.offset()) as u32,
            None,
        ));
    }

    comps
}

pub fn space_atoms<'a, V: VarnodeIface>(atoms: &'a Vec<V>, space: AddressSpace) -> Vec<&'a V> {
    atoms
        .iter()
        .filter(|v| v.space() == &space)
        .collect()
}

fn coalesce_atoms<V: Vnode>(atoms: &Vec<V>, reg_sizes: &Arc<Vec<Vec<Varnode>>>) -> Vec<V> {
    let mut comps: Vec<V> = vec![];
    comps.extend(
        space_atoms(atoms, AddressSpace::Const)
            .iter()
            .cloned()
            .cloned()
            .collect::<Vec<V>>(),
    );
    comps.extend(_coalesce_reg_atoms(
        space_atoms(atoms, AddressSpace::Register),
        reg_sizes,
    ));
    comps.extend(_coalesce_atoms(space_atoms(atoms, AddressSpace::Unique)));
    comps.extend(_coalesce_atoms(space_atoms(atoms, AddressSpace::Ram)));
    comps
}

impl<V: Vnode> GenericCompoundVarnode<V> {
    pub fn comps(&self) -> Vec<V> {
        match &self.comps {
            VarnodeComps::Simple(vn) => vec![vn.clone()],
            VarnodeComps::Complex(vns) => vns.clone(),
        }
    }

    pub fn join_with(&self, other: GenericCompoundVarnode<V>) -> GenericCompoundVarnode<V> {
        let mut new_atoms = self.atoms().clone();
        new_atoms.extend(other.atoms().clone());
        new_atoms.sort_by(|a, b| a.offset().cmp(&b.offset()));
        new_atoms.dedup();

        let vnodes = coalesce_atoms(&new_atoms, &self.reg_sizes);
        let comps = if vnodes.len() == 1 {
            VarnodeComps::Simple(vnodes[0].clone())
        } else {
            VarnodeComps::Complex(vnodes)
        };

        GenericCompoundVarnode {
            comps: comps,
            reg_sizes: self.reg_sizes.clone(),
        }
    }
}
