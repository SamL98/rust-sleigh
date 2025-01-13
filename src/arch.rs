use crate::sleigh::types::Varnode;
use crate::utils::*;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use elementtree::Element;

use {
    std::env,
    std::fs,
    // std::fs::File,
    // glob::glob,
};

pub struct Prototype {
    pub _name: String,
    pub _extrapop: u64,
    pub _stackshift: u64,
    pub _inputs: HashMap<String, Vec<Varnode>>,
    pub _outputs: HashMap<String, Vec<Varnode>>,
    pub _killed: HashSet<Varnode>,
    pub _unaff: HashSet<Varnode>
}

pub struct CompilerSpec {
    pub _stack_pointer: Varnode,
    pub _default_proto: Prototype,
    pub _prototypes: Vec<Prototype>
}

pub fn read_file(path: PathBuf, _root: &Path) -> String {
    fs::read_to_string(path.to_str().unwrap()).expect("Could not read file")
}

/*impl CompilerSpec {
    fn new(arch_path: Path, compiler: &Element) -> CompilerSpec {
        let cspec_filename = compiler.get_attr("spec").unwrap();
        let cspec_path = arch_path.join(cspec_filename);
        let cspec_contents = fs::.read_to_string(cspec_path.to_str().unwrap())
                                    .expect("Could not read cspec");

        let mut prototypes: Vec<Prototype> = Vec::new();

        return CompilerSpec {
            stack_pointer: ,
            default_proto: ,
            prototypes: prototypes
        }
    }
}*/

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

pub struct Language {
    pub _name: String,
    pub _sla_path: PathBuf,
    pub pspec: ProcessorSpec,
    pub _cspecs: Vec<CompilerSpec>
}

impl Language {
    fn new(arch_path: &PathBuf, lang: &Element) -> Language {
        let name = lang.get_attr("id").unwrap().to_string();

        let sla_filename = lang.get_attr("slafile").unwrap();
        let sla_path = arch_path.join(sla_filename);

        let pspec_filename = lang.get_attr("processorspec").unwrap();
        let pspec_path = arch_path.join(pspec_filename);
        let pspec_contents = read_file(pspec_path, arch_path);

        let pspec_elem = Element::from_reader(pspec_contents.as_bytes()).unwrap();
        let pspec = ProcessorSpec::new(&pspec_elem);

        // let mut cspecs: Vec<CompilerSpec> = Vec::new();

        /*for compiler_elem in lang.find_all("compiler") {
            let cspec = CompilerSpec::new(arch_path, compiler_elem);
            cspecs.push(cspec);
        }*/

        return Language {
            _name: name,
            _sla_path: sla_path,
            pspec: pspec,
            _cspecs: vec![],
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

pub fn get_language(arch_name: &str, language_id: &str) -> Option<Language> {
    // let mut ghidra_root_envvar = ".".to_string();
    let ghidra_root_envvar = ".";

    let ghidra_root_path = Path::new(&ghidra_root_envvar);

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
                let language = Language::new(&arch_path, language_elem);
                return Some(language);
            }
        }
    }

    return None;
}
