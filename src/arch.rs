use crate::sleigh::address::*;
use crate::sleigh::varnode::*;
use crate::sleigh::pcode::PcodeOp;
use crate::sleigh::opcode::OpCode;
use crate::sleigh::op::op_matches;

use std::collections::{HashSet, HashMap};
use roxmltree::{Document, Node};

use std::path::{Path, PathBuf};
use std::env;
use std::fs;

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct Prototype {
    pub name: String,
    pub extrapop: u64,
    pub stackshift: u64,
    pub inputs: HashMap<String, Vec<Varnode>>,
    pub outputs: HashMap<String, Vec<Varnode>>,
    pub killed: HashSet<Varnode>,
    pub unaff: HashSet<Varnode>,
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct CompilerSpec {
    pub stack_pointer: Varnode,
    pub return_address: Varnode,
    pub default_proto: String,
    pub prototypes: HashMap<String, Prototype>,
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct ProcessorSpec {
    pub pc_reg: Varnode,
    pub defaults: HashMap<String, u32>,
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct Language {
    pub name: String,
    pub pspec: ProcessorSpec,
    pub cspecs: HashMap<String, CompilerSpec>,
    pub cspec: CompilerSpec,
}

fn parse_int(input: &str) -> u64 {
    if let Some(stripped) = input.strip_prefix("0x") {
        u64::from_str_radix(stripped, 16).unwrap()
    } else if let Some(stripped) = input.strip_prefix("0b") {
        u64::from_str_radix(stripped, 2).unwrap()
    } else {
        input.parse().unwrap()
    }
}

fn find<'a, 'b>(node: &Node<'a, 'b>, tag: &str) -> Option<Node<'a, 'b>> {
    node.children().find(|&child| child.tag_name().name() == tag)
}

fn find_rec<'a, 'b>(node: &Node<'a, 'b>, tag: &str) -> Option<Node<'a, 'b>> {
    node.descendants().find(|&child| child.tag_name().name() == tag)
}

fn parse_varnode_tag(varnode_tag: &Node, registers: &HashMap<String, Varnode>) -> Varnode {
    match varnode_tag.tag_name().name() {
        "register" => {
            let name = varnode_tag.attribute("name").unwrap().to_string();
            registers[&name].clone()
        },
        "varnode" => Varnode {
            name: None,
            space: varnode_tag.attribute("space").unwrap().into(),
            offset: parse_int(varnode_tag.attribute("offset").unwrap()),
            size: parse_int(varnode_tag.attribute("size").unwrap()),
        },
        _ => unimplemented!("{}", varnode_tag.tag_name().name()),
    }
}

fn parse_pentries(pentries: Option<&Node>, registers: &HashMap<String, Varnode>) -> HashMap<String, Vec<Varnode>> {
    let mut entries: HashMap<String, Vec<Varnode>> = HashMap::default();

    if let Some(pentries) = pentries {
        for pentry in pentries.children() {
            if pentry.tag_name().name() != "pentry" {
                continue;
            }
            let metatype = pentry.attribute("metatype").unwrap_or("int").to_string();

            // TODO: Handle stack/joined parameters.
            if let Some(varnode_tag) = find(&pentry, "register") {
                let varnode = parse_varnode_tag(&varnode_tag, registers);
                entries.entry(metatype).or_default().push(varnode);
            }
        }
    }

    entries
}

fn parse_varnodes(varnode_tags: Option<&Node>, registers: &HashMap<String, Varnode>) -> HashSet<Varnode> {
    let mut varnodes = HashSet::default();

    if let Some(varnode_tags) = varnode_tags {
        for varnode_tag in varnode_tags.children() {
            if varnode_tag.tag_name().name().is_empty() {
                continue;
            }
            let varnode = parse_varnode_tag(&varnode_tag, registers);

            for off in varnode.offset..varnode.offset + varnode.size {
                varnodes.insert(varnode.atom(off));
            }
        }
    }

    varnodes
}

impl Prototype {
    pub fn new(elem: &Node, registers: &HashMap<String, Varnode>) -> Self {
        let name = elem.attribute("name").unwrap_or_default().to_string();
        let extrapop = elem.attribute("extrapop").unwrap_or_default().parse().unwrap_or_default();
        let stackshift = elem.attribute("stackshift").unwrap_or_default().parse().unwrap_or_default();

        let inputs = parse_pentries(find(elem, "input").as_ref(), registers);
        let outputs = parse_pentries(find(elem, "output").as_ref(), registers);
        let killed = parse_varnodes(find(elem, "killedbycall").as_ref(), registers);
        let unaff = parse_varnodes(find(elem, "unaffected").as_ref(), registers);

        Prototype { name, extrapop, stackshift, inputs, outputs, killed, unaff }
    }
}

impl CompilerSpec {
    fn new(cspec_elem: &Node, registers: &HashMap<String, Varnode>) -> Self {
        let sp_name = find_rec(cspec_elem, "stackpointer").unwrap().attribute("register").unwrap().to_string();
        let stack_pointer = registers[&sp_name].clone();

        let ra_elem = find_rec(cspec_elem, "returnaddress").unwrap();
        let return_address = {
            let mut res = None;
            for child in ra_elem.children() {
                if !child.tag_name().name().is_empty() {
                    res = Some(parse_varnode_tag(&child, registers));
                    break;
                }
            }
            res.unwrap()
        };

        let proto_elem = find_rec(cspec_elem, "default_proto").unwrap();
        let proto_elem = find(&proto_elem, "prototype").unwrap();
        let default_proto = Prototype::new(&proto_elem, registers);

        let mut prototypes = HashMap::default();
        prototypes.insert(default_proto.name.clone(), default_proto.clone());

        for proto_elem in cspec_elem.descendants() {
            if proto_elem.tag_name().name() != "prototype" {
                continue;
            }
            let proto = Prototype::new(&proto_elem, registers);
            prototypes.insert(proto.name.clone(), proto.clone());
        }

        Self {
            stack_pointer,
            return_address,
            default_proto: default_proto.name.clone(),
            prototypes,
        }
    }

    pub fn default_proto(&self) -> &Prototype {
        &self.prototypes[&self.default_proto]
    }

    pub fn is_call_setup(&self, mut ops: &[PcodeOp], ft: u64) -> bool {
        let sp = &self.stack_pointer;
        let ra = &self.return_address;

        let shift = Varnode::constant(self.default_proto().stackshift, sp.size);
        let ft = Varnode::constant(ft, ra.size);

        if shift.offset > 0 {
            if op_matches!(ops[0], (sp => IntSub sp, &shift)) {
                ops = &ops[1..];
            } else {
                return false;
            }
        }

        if ra.space == AddressSpace::Stack {
            op_matches!(ops[0], (Store sp, &ft))
        } else {
            op_matches!(ops[0], (ra => Copy &ft))
        }
    }
}

impl ProcessorSpec {
    fn new(elem: &Node, reg_names: &HashMap<String, Varnode>) -> Self {
        let pc_reg = reg_names[find_rec(elem, "programcounter").unwrap().attribute("register").unwrap()].clone();
        let mut defaults: HashMap<String, u32> = HashMap::default();

        if let Some(ctx_data_elem) = find_rec(elem, "context_data") &&
            let Some(ctx_set_elem) = find(&ctx_data_elem, "context_set")
        {
            for var_elem in ctx_set_elem.children() {
                if var_elem.tag_name().name() != "set" {
                    continue;
                }
                if let (Some(name), Some(val)) = (var_elem.attribute("name"), var_elem.attribute("val")) {
                    defaults.insert(name.to_string(), parse_int(val) as u32);
                }
            }
        }

        Self { pc_reg, defaults }
    }
}

pub fn read_file(path: PathBuf, _root: &Path) -> String {
    fs::read_to_string(path.to_str().unwrap()).expect("Could not read file")
}

pub fn get_sla(arch_name: &str, language_id: &str) -> Option<String> {
    let ghidra_root_path = Path::new(file!()).parent().unwrap().parent().unwrap();

    let arch_path = ghidra_root_path.join("Ghidra")
                                    .join("Processors")
                                    .join(arch_name)
                                    .join("data")
                                    .join("languages");

    // TODO: Make wasm search ldef paths.
    let ldef_path = arch_path.join(format!("{}.ldefs", arch_name));
    let ldef_contents = read_file(ldef_path, &arch_path);

    let ldef = Document::parse(&ldef_contents).unwrap();
    let ldef_elem = find(&ldef.root(), "language_definitions").unwrap();

    for language_elem in ldef_elem.children() {
        if language_elem.tag_name().name() != "language" {
            continue;
        }
        if let (Some(lang_id), Some(sla_file)) = (language_elem.attribute("id"), language_elem.attribute("slafile")) {
            if lang_id.eq(language_id) {
                let sla = read_file(arch_path.join(sla_file), &arch_path);
                return Some(sla);
            }
        }
    }

    None
}

pub fn get_language(
    arch_name: &str,
    language_id: &str,
    compiler_id: &str,
    registers: &HashMap<String, Varnode>,
) -> Option<Language> {
    let ghidra_path_env = env::var("GHIDRA_PATH");

    let ghidra_root_path = match &ghidra_path_env {
        Ok(p) => Path::new(p),
        Err(_) => Path::new(file!()).parent().unwrap().parent().unwrap(),
    };

    let arch_path = ghidra_root_path.join("Ghidra")
                                    .join("Processors")
                                    .join(arch_name)
                                    .join("data")
                                    .join("languages");

    // TODO: Make wasm search ldef paths.
    let ldef_path = arch_path.join(format!("{}.ldefs", arch_name));
    let ldef_contents = read_file(ldef_path, &arch_path);

    let ldef = Document::parse(&ldef_contents).unwrap();
    let ldef_elem = find(&ldef.root(), "language_definitions").unwrap();

    for language_elem in ldef_elem.children() {
        if language_elem.tag_name().name() != "language" {
            continue;
        }
        if let Some(lang_id) = language_elem.attribute("id") {
            if lang_id.eq(language_id) {
                let language = Language::new(&arch_path, &language_elem, compiler_id, registers);
                return Some(language);
            }
        }
    }

    None
}

impl Language {
    pub fn new(
        arch_path: &Path,
        lang: &Node,
        compiler_id: &str,
        registers: &HashMap<String, Varnode>,
    ) -> Self {
        let name = lang.attribute("id").unwrap().to_string();

        let pspec_filename = lang.attribute("processorspec").unwrap();
        let pspec_path = arch_path.join(pspec_filename);
        let pspec_contents =
            fs::read_to_string(pspec_path.to_str().unwrap()).expect("Could not read pspec");

        let pspec_elem = Document::parse(&pspec_contents).unwrap();
        let pspec = ProcessorSpec::new(&pspec_elem.root(), registers);

        let mut cspecs: HashMap<String, CompilerSpec> = HashMap::default();

        for compiler_elem in lang.children() {
            if compiler_elem.tag_name().name() != "compiler" {
                continue;
            }
            let cspec_name = compiler_elem.attribute("name").unwrap();
            let cspec_filename = compiler_elem.attribute("spec").unwrap();
            let cspec_path = arch_path.join(cspec_filename);
            let cspec_contents =
                fs::read_to_string(cspec_path.to_str().unwrap()).expect("Could not read cspec");

            let cspec_elem = Document::parse(&cspec_contents).unwrap();
            let cspec = CompilerSpec::new(&cspec_elem.root(), registers);
            cspecs.insert(cspec_name.to_string(), cspec);
        }

        let cspec = cspecs[compiler_id].clone();
        Self { name, pspec, cspecs, cspec, }
    }
}
