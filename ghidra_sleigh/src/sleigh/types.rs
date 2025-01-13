use fxhash::{FxHashMap, FxHashSet};

pub use super::compound_varnode::{CompoundVarnodeIface, CompoundVarnodeIface2};
pub use super::context::RegMap;
pub use super::opcode::OpCode;
pub use super::varnode::{VarnodeIface, VarnodeIface2};

use libc::c_void;
use std::cell::{Ref, RefCell};
use std::collections::HashSet;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::ops::{Add, Deref};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub enum AddressSpace {
    Const,
    Register,
    Ram,
    Unique,
    Other(String),
}

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct Address {
    pub space: AddressSpace,
    pub offset: u64,
}

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct SeqNum {
    pub pc: Address,
    pub uniq: i32,
    pub order: u32,
}

#[derive(Eq, PartialEq, Hash, Clone)]
pub struct Varnode {
    pub name: Option<String>,
    pub space: AddressSpace,
    pub offset: u64,
    pub size: u32,
}

#[derive(Eq, PartialEq, Hash, Clone)]
pub struct SsaVarnode {
    pub inner: Varnode,
    pub version: u32,
}

pub type VarnodeDefns = FxHashMap<SsaVarnode, usize>;
pub type VarnodeUses = FxHashMap<SsaVarnode, FxHashMap<usize, Vec<usize>>>;

pub trait Vnode:
    VarnodeIface + VarnodeIface2 + Hash + Clone + PartialEq + Eq + Debug + Display
{}

impl Vnode for Varnode {}
impl Vnode for SsaVarnode {}

pub trait CompVnode:
    CompoundVarnodeIface + CompoundVarnodeIface2 + Hash + Clone + PartialEq + Eq + Debug + Display
{}

#[derive(Clone)]
pub enum VarnodeComps<V: Vnode> {
    Simple(V),
    Complex(Vec<V>),
}

#[derive(Clone)]
pub struct GenericCompoundVarnode<V: Vnode> {
    pub comps: VarnodeComps<V>,
    pub reg_sizes: Arc<Vec<Vec<Varnode>>>,
}

pub type CompoundVarnode = GenericCompoundVarnode<Varnode>;
pub type SsaCompoundVarnode = GenericCompoundVarnode<SsaVarnode>;

impl CompVnode for CompoundVarnode {}
impl CompVnode for SsaCompoundVarnode {}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum PcodeType {
    Default,
    Call,
    Ret,
    Phi,
}

#[derive(Eq, Hash, Clone, Debug)]
pub struct GenericPcodeOp<V: CompVnode> {
    pub kind: PcodeType,
    pub seq: SeqNum,
    pub opcode: OpCode,
    pub inputs: Vec<V>,
    pub output: Option<V>,
    pub killed: Vec<V>,
    pub used: Vec<V>,
}

pub type PcodeOp = GenericPcodeOp<CompoundVarnode>;
pub type SsaPcodeOp = GenericPcodeOp<SsaCompoundVarnode>;

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct Instruction {
    pub address: Address,
    pub length: u64,
    pub mnemonic: String,
    pub body: String,
    pub ops: Vec<PcodeOp>,
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct Prototype {
    pub name: String,
    pub extrapop: u64,
    pub stackshift: u64,
    pub inputs: FxHashMap<String, Vec<CompoundVarnode>>,
    pub outputs: FxHashMap<String, Vec<CompoundVarnode>>,
    pub killed: HashSet<CompoundVarnode>,
    pub unaff: HashSet<CompoundVarnode>,
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct CompilerSpec {
    pub stack_pointer: Varnode,
    pub default_proto: String,
    pub prototypes: FxHashMap<String, Prototype>,
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct ProcessorSpec {
    pub pc_reg: Varnode,
    pub defaults: FxHashMap<String, u32>,
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct Language {
    pub name: String,
    pub pspec: ProcessorSpec,
    pub cspecs: FxHashMap<String, CompilerSpec>,
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct CContext {
    pub ptr: *const c_void,
}

unsafe impl Send for CContext {}

#[derive(Debug, Clone)]
pub struct Context {
    pub ctx_c: CContext,
    pub registers: Arc<FxHashMap<(u64, u32), Varnode>>,
    pub reg_sizes: Arc<Vec<Vec<Varnode>>>,
    pub lang: Language,
    pub cspec: CompilerSpec,
}

impl PartialEq for Context {
    fn eq(&self, other: &Self) -> bool {
        self.ctx_c == other.ctx_c
    }
}

impl Eq for Context {}
