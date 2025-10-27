use crate::sleigh::types::{AddressSpace, Varnode};

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::env;

use flexstr::IntoLocalStr;
use elementtree::Element;

use {
    // std::env,
    std::fs,
    // std::fs::File,
    // glob::glob,
};

fn parse_int(input: &str) -> u64 {
    if input.starts_with("0x") {
        u64::from_str_radix(&input[2..], 16).unwrap()
    } else if input.starts_with("0b") {
        u64::from_str_radix(&input[2..], 2).unwrap()
    } else {
        input.parse().unwrap()
    }
}

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

impl Prototype {
    pub fn new(elem: &Element, registers: &HashMap<String, (u64, u64)>) -> Prototype {
        let name = elem.get_attr("name").unwrap_or_default().to_string();
        let extrapop = elem.get_attr("extrapop").unwrap_or_default().parse().unwrap_or_default();
        let stackshift = elem.get_attr("stackshift").unwrap_or_default().parse().unwrap_or_default();

        let inputs = Self::parse_pentries(elem.find("input"), registers);
        let outputs = Self::parse_pentries(elem.find("output"), registers);
        let killed = Self::parse_varnodes(elem.find("killedbycall"), registers);
        let unaff = Self::parse_varnodes(elem.find("unaffected"), registers);

        Prototype { name, extrapop, stackshift, inputs, outputs, killed, unaff }
    }

    fn parse_varnode_tag(varnode_tag: &Element, registers: &HashMap<String, (u64, u64)>) -> Varnode {
        match varnode_tag.tag().name() {
            "register" => {
                let name = varnode_tag.get_attr("name").unwrap().to_string();
                let (offset, size) = registers[&name];
                Varnode { name: Some(name.into_local_str()), space: AddressSpace::Register, offset: offset, size: size }
            },
            "varnode" => Varnode {
                name: None,
                space: AddressSpace::from_str(varnode_tag.get_attr("space").unwrap()),
                offset: parse_int(varnode_tag.get_attr("offset").unwrap()),
                size: parse_int(varnode_tag.get_attr("size").unwrap()),
            },
            _ => unimplemented!(),
        }
    }

    fn parse_pentries(pentries: Option<&Element>, registers: &HashMap<String, (u64, u64)>) -> HashMap<String, Vec<Varnode>> {
        let mut entries: HashMap<String, Vec<Varnode>> = HashMap::default();

        if let Some(pentries) = pentries {
            for pentry in pentries.find_all("pentry") {
                let metatype = pentry.get_attr("metatype").unwrap_or("int").to_string();

                // TODO: Handle stack/joined parameters.
                if let Some(varnode_tag) = pentry.find("register") {
                    let varnode = Self::parse_varnode_tag(varnode_tag, registers);
                    entries.entry(metatype).or_default().push(varnode);
                }
            }
        }

        entries
    }

    fn parse_varnodes(varnode_tags: Option<&Element>, registers: &HashMap<String, (u64, u64)>) -> HashSet<Varnode> {
        let mut varnodes = HashSet::default();

        if let Some(varnode_tags) = varnode_tags {
            for varnode_tag in varnode_tags.children() {
                let varnode = Self::parse_varnode_tag(varnode_tag, registers);
                varnodes.insert(varnode);
            }
        }

        varnodes
    }
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct CompilerSpec {
    pub stack_pointer: Varnode,
    pub default_proto_name: String,
    pub prototypes: HashMap<String, Prototype>,
}

#[allow(dead_code)]
impl CompilerSpec {
    fn new(cspec_path: &PathBuf, registers: &HashMap<String, (u64, u64)>) -> Self {
        let cspec_contents = fs::read_to_string(cspec_path.to_str().unwrap()).expect("Could not read cspec");
        let cspec_elem = Element::from_reader(cspec_contents.as_bytes()).unwrap();

        let sp_name = cspec_elem.find("stackpointer").unwrap().get_attr("register").unwrap().to_string();
        let (sp_off, sp_size) = registers[&sp_name].clone();

        let stack_pointer = Varnode {
            name: Some(sp_name.into_local_str()),
            space: AddressSpace::Register,
            offset: sp_off,
            size: sp_size,
        };

        let proto_elem = cspec_elem.find("default_proto").unwrap().find("prototype").unwrap();
        let default_proto = Prototype::new(proto_elem, registers);

        let mut prototypes = HashMap::default();
        prototypes.insert(default_proto.name.clone(), default_proto.clone());

        for proto_elem in cspec_elem.find_all("prototype") {
            let proto = Prototype::new(proto_elem, registers);
            prototypes.insert(proto.name.clone(), proto.clone());
        }

        return CompilerSpec {
            stack_pointer,
            default_proto_name: default_proto.name.clone(),
            prototypes,
        };
    }

    pub fn default_proto(&self) -> &Prototype {
        &self.prototypes[&self.default_proto_name]
    }
}

pub fn read_file(path: PathBuf, _root: &Path) -> String {
    fs::read_to_string(path.to_str().unwrap()).expect("Could not read file")
}

pub struct ProcessorSpec {
    pub defaults: HashMap<String, u32>
}

impl ProcessorSpec {
    fn new(elem: &Element) -> ProcessorSpec {
        let mut defaults: HashMap<String, u32> = HashMap::new();

        if let Some(ctx_data_elem) = elem.find("context_data") {
            if let Some(ctx_set_elem) = ctx_data_elem.find("context_set") {
                for var_elem in ctx_set_elem.find_all("set") {
                    if let (Some(name), Some(val)) = (var_elem.get_attr("name"), var_elem.get_attr("val")) {
                        defaults.insert(name.to_string(), parse_int(val) as u32);
                    }
                }
            }
        }

        return ProcessorSpec {
            defaults: defaults
        };
    }
}

#[allow(dead_code)]
pub struct Language {
    pub _name: String,
    pub _sla_path: PathBuf,
    pub pspec: ProcessorSpec,
    pub cspec: CompilerSpec,
}

impl Language {
    fn new(arch_path: &PathBuf, lang: &Element, compiler_id: &str, registers: &HashMap<String, (u64, u64)>) -> Language {
        let name = lang.get_attr("id").unwrap().to_string();

        let sla_filename = lang.get_attr("slafile").unwrap();
        let sla_path = arch_path.join(sla_filename);

        let pspec_filename = lang.get_attr("processorspec").unwrap();
        let pspec_path = arch_path.join(pspec_filename);
        let pspec_contents = read_file(pspec_path, arch_path);

        let pspec_elem = Element::from_reader(pspec_contents.as_bytes()).unwrap();
        let pspec = ProcessorSpec::new(&pspec_elem);

        let mut cspec = None;

        for compiler_elem in lang.find_all("compiler") {
            if compiler_elem.get_attr("name").unwrap() == compiler_id {
                let cspec_filename = compiler_elem.get_attr("spec").unwrap();
                let cspec_path = arch_path.join(cspec_filename);
                cspec = Some(CompilerSpec::new(&cspec_path, &registers));
                break;
            }
        }

        return Language {
            _name: name,
            _sla_path: sla_path,
            pspec: pspec,
            cspec: cspec.unwrap(),
        }
    }
}

/*pub struct Architecture {
    ldef: Element,
    languages: Vec<Language>
}

impl Architecture {
    fn new(arch_path: &PathBuf, ldef_path: &PathBuf) -> Architecture {
        let ldef_contents = fs::read_to_string(ldef_path.to_str().unwrap())
                                    .expect("Could not read ldef");

        let ldef = Element::from_reader(ldef_contents.as_bytes()).unwrap();

        let mut languages: Vec<Language> = Vec::new();

        for language_elem in ldef.find_all("language") {
            let language = Language::new(arch_path, language_elem);
            languages.push(language);
        }

        return Architecture {
            ldef: ldef,
            languages: languages
        }
    }
}*/

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

    let ldef = Element::from_reader(ldef_contents.as_bytes()).unwrap();

    for language_elem in ldef.find_all("language") {
        if let (Some(lang_id), Some(sla_file)) = (language_elem.get_attr("id"), language_elem.get_attr("slafile")) {
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
    registers: &HashMap<String, (u64, u64)>,
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

    let ldef = Element::from_reader(ldef_contents.as_bytes()).unwrap();

    for language_elem in ldef.find_all("language") {
        if let Some(lang_id) = language_elem.get_attr("id") {
            if lang_id.eq(language_id) {
                let language = Language::new(&arch_path, language_elem, compiler_id, registers);
                return Some(language);
            }
        }
    }

    None
}
