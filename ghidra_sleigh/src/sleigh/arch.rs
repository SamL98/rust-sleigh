use fxhash::FxHashMap;

use super::context::{load_c_ctx, ContextIface, RegMap, RegNameMap};
use super::types::{
    AddressSpace, CContext, CompilerSpec, CompoundVarnode, Context, Language, ProcessorSpec, Prototype, Varnode,
};

use elementtree::Element;
use glob::glob;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

fn parse_int(input: &str) -> u64 {
    if input.starts_with("0x") {
        u64::from_str_radix(&input[2..], 16).unwrap()
    } else if input.starts_with("0b") {
        u64::from_str_radix(&input[2..], 2).unwrap()
    } else {
        input.parse().unwrap()
    }
}

impl Prototype {
    pub fn new(
        elem: &Element,
        regnames: &RegNameMap,
        registers: &Arc<RegMap>,
        register_sizes: &Arc<Vec<Vec<Varnode>>>,
    ) -> Prototype {
        let name = elem.get_attr("name").unwrap_or_default().to_string();
        let extrapop = elem
            .get_attr("extrapop")
            .unwrap_or_default()
            .parse()
            .unwrap_or_default();
        let stackshift = elem
            .get_attr("stackshift")
            .unwrap_or_default()
            .parse()
            .unwrap_or_default();

        let mut inputs = FxHashMap::default();
        let mut outputs = FxHashMap::default();
        let mut killed = HashSet::new();
        let mut unaff = HashSet::new();

        Self::parse_pentries(
            &mut inputs,
            elem.find("input"),
            regnames,
            registers,
            register_sizes,
        );
        Self::parse_pentries(
            &mut outputs,
            elem.find("output"),
            regnames,
            registers,
            register_sizes,
        );
        Self::parse_varnodes(
            &mut killed,
            elem.find("killedbycall"),
            regnames,
            registers,
            register_sizes,
        );
        Self::parse_varnodes(
            &mut unaff,
            elem.find("unaffected"),
            regnames,
            registers,
            register_sizes,
        );

        Prototype {
            name,
            extrapop,
            stackshift,
            inputs,
            outputs,
            killed,
            unaff,
        }
    }

    fn parse_varnode_tag(
        varnode_tag: &Element,
        regnames: &RegNameMap,
        registers: &Arc<RegMap>,
        register_sizes: &Arc<Vec<Vec<Varnode>>>,
    ) -> CompoundVarnode {
        match varnode_tag.tag().name() {
            "register" => {
                let name = varnode_tag.get_attr("name").unwrap();
                CompoundVarnode::new(regnames[name].clone(), register_sizes.clone())
            }
            "addr" => {
                if varnode_tag.get_attr("space") == Some("join") {
                    let piece1 = CompoundVarnode::new(
                        regnames[varnode_tag.get_attr("piece1").unwrap()].clone(),
                        register_sizes.clone(),
                    );
                    let piece2 = CompoundVarnode::new(
                        regnames[varnode_tag.get_attr("piece2").unwrap()].clone(),
                        register_sizes.clone(),
                    );
                    piece1.join_with(piece2)
                } else {
                    panic!();
                }
            }
            "varnode" => CompoundVarnode::new(
                Varnode {
                    name: None,
                    space: match varnode_tag.get_attr("space").unwrap() {
                        "const" => AddressSpace::Const,
                        "register" => AddressSpace::Register,
                        "ram" => AddressSpace::Ram,
                        "unique" => AddressSpace::Unique,
                        _ => AddressSpace::Other(varnode_tag.get_attr("space").unwrap().to_string())
                    },
                    offset: parse_int(varnode_tag.get_attr("offset").unwrap()),
                    size: parse_int(varnode_tag.get_attr("size").unwrap()) as u32,
                },
                register_sizes.clone(),
            ),
            _ => unimplemented!(),
        }
    }

    fn parse_pentries(
        entries: &mut FxHashMap<String, Vec<CompoundVarnode>>,
        pentries: Option<&Element>,
        regnames: &RegNameMap,
        registers: &Arc<RegMap>,
        register_sizes: &Arc<Vec<Vec<Varnode>>>,
    ) {
        if let Some(pentries) = pentries {
            for pentry in pentries.find_all("pentry") {
                let metatype = pentry.get_attr("metatype").unwrap_or("int").to_string();
                if let Some(varnode_tag) = pentry.find("register") {
                    let varnode =
                        Self::parse_varnode_tag(varnode_tag, regnames, registers, register_sizes);
                    entries.entry(metatype).or_default().push(varnode);
                }
            }
        }
    }

    fn parse_varnodes(
        varnodes: &mut HashSet<CompoundVarnode>,
        varnode_tags: Option<&Element>,
        regnames: &RegNameMap,
        registers: &Arc<RegMap>,
        register_sizes: &Arc<Vec<Vec<Varnode>>>,
    ) {
        if let Some(varnode_tags) = varnode_tags {
            for varnode_tag in varnode_tags.children() {
                let varnode =
                    Self::parse_varnode_tag(varnode_tag, regnames, registers, register_sizes);
                varnodes.insert(varnode);
            }
        }
    }
}

impl CompilerSpec {
    fn new(
        elem: &Element,
        regnames: &RegNameMap,
        registers: &Arc<RegMap>,
        register_sizes: &Arc<Vec<Vec<Varnode>>>,
    ) -> CompilerSpec {
        let sp_reg = regnames[elem
            .find("stackpointer")
            .unwrap()
            .get_attr("register")
            .unwrap()]
        .clone();

        let default_proto = Prototype::new(
            elem.find("default_proto")
                .unwrap()
                .find("prototype")
                .unwrap(),
            regnames,
            registers,
            register_sizes,
        );

        let mut prototypes = FxHashMap::default();
        prototypes.insert(default_proto.name.clone(), default_proto.clone());

        for proto_elem in elem.find_all("prototype") {
            let proto = Prototype::new(proto_elem, regnames, registers, register_sizes);
            prototypes.insert(proto.name.clone(), proto.clone());
        }

        return CompilerSpec {
            stack_pointer: sp_reg.clone(),
            default_proto: default_proto.name.clone(),
            prototypes: prototypes,
        };
    }
}

impl ProcessorSpec {
    fn new(elem: &Element, regnames: &RegNameMap) -> ProcessorSpec {
        let pc_reg = regnames[elem
            .find("programcounter")
            .unwrap()
            .get_attr("register")
            .unwrap()]
        .clone();
        let mut defaults: FxHashMap<String, u32> = FxHashMap::default();

        if let Some(ctx_data_elem) = elem.find("context_data") {
            if let Some(ctx_set_elem) = ctx_data_elem.find("context_set") {
                for var_elem in ctx_set_elem.find_all("set") {
                    if let (Some(name), Some(val)) =
                        (var_elem.get_attr("name"), var_elem.get_attr("val"))
                    {
                        defaults.insert(name.to_string(), parse_int(val) as u32);
                    }
                }
            }
        }

        return ProcessorSpec {
            pc_reg: pc_reg.clone(),
            defaults: defaults,
        };
    }
}

impl Language {
    fn new(
        arch_path: &PathBuf,
        lang: &Element,
        regnames: &RegNameMap,
        registers: &Arc<RegMap>,
        register_sizes: &Arc<Vec<Vec<Varnode>>>,
    ) -> Language {
        let name = lang.get_attr("id").unwrap().to_string();

        let pspec_filename = lang.get_attr("processorspec").unwrap();
        let pspec_path = arch_path.join(pspec_filename);
        let pspec_contents =
            fs::read_to_string(pspec_path.to_str().unwrap()).expect("Could not read pspec");

        let pspec_elem = Element::from_reader(pspec_contents.as_bytes()).unwrap();
        let pspec = ProcessorSpec::new(&pspec_elem, regnames);

        let mut cspecs: FxHashMap<String, CompilerSpec> = FxHashMap::default();

        for compiler_elem in lang.find_all("compiler") {
            let cspec_name = compiler_elem.get_attr("name").unwrap();
            let cspec_filename = compiler_elem.get_attr("spec").unwrap();
            let cspec_path = arch_path.join(cspec_filename);
            let cspec_contents =
                fs::read_to_string(cspec_path.to_str().unwrap()).expect("Could not read cspec");

            let cspec_elem = Element::from_reader(cspec_contents.as_bytes()).unwrap();
            let cspec = CompilerSpec::new(&cspec_elem, regnames, registers, register_sizes);
            cspecs.insert(cspec_name.to_string(), cspec);
        }

        return Language {
            name: name,
            pspec: pspec,
            cspecs: cspecs,
        };
    }
}

pub fn get_context<'a>(arch_name: &'a str, language_id: &'a str, compiler_id: &'a str) -> Option<Context> {
    let ghidra_root_envvar = ".".to_string();
    let ghidra_root_path = Path::new(&ghidra_root_envvar);

    let arch_path = ghidra_root_path
        .join("Ghidra")
        .join("Processors")
        .join(arch_name)
        .join("data")
        .join("languages");

    for ldef_entry in glob(&format!("{}/*.ldefs", arch_path.display())).expect("Couldn't read glob")
    {
        if let Ok(ldef_path) = ldef_entry {
            let ldef_contents =
                fs::read_to_string(ldef_path.to_str().unwrap()).expect("Could not read ldef");

            let ldef = Element::from_reader(ldef_contents.as_bytes()).unwrap();

            for language_elem in ldef.find_all("language") {
                if let Some(lang_id) = language_elem.get_attr("id") {
                    if lang_id.eq(language_id) {
                        let sla_filename = language_elem.get_attr("slafile").unwrap();
                        let sla_path_buf = arch_path.join(sla_filename);
                        let sla_path = sla_path_buf.to_str().unwrap();

                        let (c_ctx, regs, reg_sizes, register_names) = load_c_ctx(sla_path);
                        let registers = Arc::new(regs);
                        let register_sizes = Arc::new(reg_sizes);
                        let language = Language::new(
                            &arch_path,
                            language_elem,
                            &register_names,
                            &registers,
                            &register_sizes,
                        );

                        return Some(Context::new(
                            CContext { ptr: c_ctx },
                            language,
                            registers,
                            register_sizes,
                            compiler_id,
                        ));
                    }
                }
            }
        }
    }

    return None;
}
