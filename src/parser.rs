use crate::arch::get_language;
use crate::sleigh::opcode::OpCode;
use crate::sleigh::types::{Address, PcodeOp, SeqNum, Varnode};

extern crate bitvec;
extern crate nom;

use super::arch::Language;

use nom::branch::*;
use nom::bytes::complete::*;
use nom::character::complete::*;
use nom::character::*;
use nom::combinator::*;
use nom::error::*;
use nom::multi::*;
use nom::sequence::*;
use nom::*;

use bitvec::prelude::*;

use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::fmt;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::Write;

static SLEIGH_PATH: &'static str =
    "/Users/samlerner/ghidra_10.3_PUBLIC/Ghidra/Processors/x86/data/languages";

pub type Res<T, U> = IResult<T, U, Error<T>>;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MaskWord {
    mask: u32,
    val: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PatternBlock {
    offset: u32,
    nonzero: u32,
    masks: Vec<MaskWord>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DecisionPattern {
    Context(PatternBlock),
    Instruction(PatternBlock),
    Combine((Box<DecisionPattern>, Box<DecisionPattern>)),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DecisionTree {
    Leaf(Vec<(u32, DecisionPattern)>),
    NonLeaf((bool, u32, u32, Vec<DecisionTree>)),
}

impl Hash for DecisionTree {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            DecisionTree::Leaf(patterns) => {
                "Leaf".hash(state);
                patterns.hash(state);
            }
            DecisionTree::NonLeaf((b, u1, u2, subtrees)) => {
                "NonLeaf".hash(state);
                b.hash(state);
                u1.hash(state);
                u2.hash(state);
                subtrees.hash(state);
            }
        }
    }
}

impl Hash for MaskWord {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.mask.hash(state);
        self.val.hash(state);
    }
}

impl Hash for PatternBlock {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.offset.hash(state);
        self.nonzero.hash(state);
        self.masks.hash(state);
    }
}

impl Hash for DecisionPattern {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            DecisionPattern::Context(block) => {
                "Context".hash(state);
                block.hash(state);
            }
            DecisionPattern::Instruction(block) => {
                "Instruction".hash(state);
                block.hash(state);
            }
            DecisionPattern::Combine((p1, p2)) => {
                "Combine".hash(state);
                p1.hash(state);
                p2.hash(state);
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Space<'a> {
    pub name: &'a str,
    pub index: u32,
    pub big_endian: bool,
    pub delay: u32,
    pub size: u32,
    pub physical: bool,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Scope {
    parent: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SymbolHead<'a> {
    pub name: &'a str,
    pub scope: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VarnodeSym<'a> {
    pub name: &'a str,
    pub scope: u32,
    pub space: &'a str,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Value<'a> {
    name: &'a str,
    scope: u32,
    field: Field,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Varlist<'a> {
    name: &'a str,
    scope: u32,
    field: Field,
    vars: Vec<Option<u32>>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Valuemap<'a> {
    name: &'a str,
    scope: u32,
    field: Field,
    vars: Vec<u64>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Operand<'a> {
    pub name: &'a str,
    scope: u32,
    subsym: u32,
    off: u64,
    base: i64,
    min_len: u64,
    idx: u64,
    is_code: bool,
    operand_expr: OperandExpr,
    expr: Option<Expr>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Context<'a> {
    pub name: &'a str,
    pub scope: u32,
    pub varnode: u32,
    pub low: u32,
    pub high: u32,
    pub flow: bool,
    pub context_field: ContextField,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UserOp<'a> {
    name: &'a str,
    scope: u32,
    idx: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SymbolBody<'a> {
    Scope(Scope),
    SymHead(SymbolHead<'a>),
    Subtable(Subtable<'a>),
    Varnode(VarnodeSym<'a>),
    Value(Value<'a>),
    Varlist(Varlist<'a>),
    Valuemap(Valuemap<'a>),
    Operand(Operand<'a>),
    Context(Context<'a>),
    UserOp(UserOp<'a>),
    Start(SymbolHead<'a>),
    End(SymbolHead<'a>),
    Next2(SymbolHead<'a>),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Symbol<'a> {
    pub id: u32,
    pub body: SymbolBody<'a>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Subtable<'a> {
    pub name: &'a str,
    pub scope: u32,
    pub constructors: Vec<Constructor<'a>>,
    pub decision_tree: DecisionTree,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ContextField {
    sign_bit: bool,
    start_bit: u32,
    end_bit: u32,
    start_byte: u32,
    end_byte: u32,
    shift: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TokenField {
    big_endian: bool,
    sign_bit: bool,
    start_bit: u32,
    end_bit: u32,
    start_byte: u32,
    end_byte: u32,
    shift: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Field {
    Context(ContextField),
    Token(TokenField),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OperandExpr {
    idx: u32,
    table: u32,
    ct: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Expr {
    Const(i64),
    Operand(OperandExpr),
    Field(Field),
    Not(Box<Expr>),
    Xor((Box<Expr>, Box<Expr>)),
    Add((Box<Expr>, Box<Expr>)),
    Lshift((Box<Expr>, Box<Expr>)),
    Rshift((Box<Expr>, Box<Expr>)),
    Mult((Box<Expr>, Box<Expr>)),
    And((Box<Expr>, Box<Expr>)),
    Or((Box<Expr>, Box<Expr>)),
    End,
    Start,
    Next2,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Constructor<'a> {
    pub parent: u32,
    pub first: i32,
    pub length: u32,
    pub operands: Vec<u32>,
    pub print_commands: Option<Vec<PrintCommand<'a>>>,
    pub context_ops: Vec<ContextOp>,
    pub template: Option<ConstructorTemplate<'a>>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PrintCommand<'a> {
    Op(u32),
    Piece(&'a str),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ContextOp {
    i: u32,
    shift: u32,
    mask: u32,
    expr: Expr,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConstructorTemplate<'a> {
    num_labels: u32,
    statements: Vec<ConsTemplate<'a>>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OpTemplate<'a> {
    code: &'a str,
    output: Option<VarnodeTemplate<'a>>,
    inputs: Vec<VarnodeTemplate<'a>>,
}

impl fmt::Display for OpTemplate<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let input_str = self.inputs.iter().map(|i| format!("{}", i)).collect::<Vec<String>>().join(", ");

        if let Some(output) = &self.output {
            write!(f, "{} = {}({})", output, self.code, input_str)
        } else {
            write!(f, "{}({})", self.code, input_str)
        }
    }
}


#[derive(Debug, PartialEq, Eq, Clone)]
pub struct HandleTemplate<'a> {
    varnode_template: VarnodeTemplate<'a>,
    exported_template: VarnodeTemplate<'a>,
    indirect_template: VarnodeTemplate<'a>,
}

impl fmt::Display for HandleTemplate<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if matches!(self.indirect_template.space_template, ConstTemplate::SpaceId(_)) {
            write!(f, "[{}]({})", self.indirect_template, self.varnode_template)
        } else {
            write!(f, "{}", self.varnode_template)
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ConsTemplate<'a> {
    Op(OpTemplate<'a>),
    Handle(HandleTemplate<'a>),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConcreteVarnodeTemplate<'a> {
    space: &'a str,
    offset: u64,
    size: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VarnodeTemplate<'a> {
    space_template: ConstTemplate<'a>,
    offset_template: ConstTemplate<'a>,
    size_template: ConstTemplate<'a>,
}

impl fmt::Display for VarnodeTemplate<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ConstTemplate::*;

        match (&self.space_template, &self.offset_template, &self.size_template) {
            (Handle(h1), Handle(h2), Handle(h3)) if h1 == h2 && h2 == h3 => {
                write!(f, "Handle#{}", h1)
            },
            _ => {
                write!(f, "{}:{}:{}", self.space_template, self.offset_template, self.size_template)
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ConstTemplate<'a> {
    SpaceId(&'a str),
    Val(u64),
    Handle(u32),
    Relative(u32),
    Start,
    Next,
    CurSpace,
    CurSpaceSize,
}

impl fmt::Display for ConstTemplate<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ConstTemplate::*;

        match self {
            SpaceId(space) => write!(f, "{}", space),
            Val(val) => write!(f, "{:x}", val),
            Handle(idx) => write!(f, "Handle#{}", idx),
            _ => write!(f, "{:?}", self)
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Program<'a> {
    pub version: u32,
    pub bigendian: bool,
    pub align: u32,
    pub uniqbase: u64,
    pub default_space: &'a str,
    pub spaces: Vec<Space<'a>>,
    pub symbols: Vec<Symbol<'a>>,
}

fn source_files(input: &str) -> Res<&str, &str> {
    delimited(
        tag("<sourcefiles>"),
        take_until("</sourcefiles>"),
        tag("</sourcefiles>"),
    )(input)
}

fn space(input: &str) -> Res<&str, Space> {
    delimited(
        alt((tag("<space_other"), tag("<space_unique"), tag("<space"))),
        take_until("/>"),
        tag("/>"),
    )(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        //println!("{} {:?}", res, attrs);
        let space = Space {
            name: attrs[0].1,
            index: u32dec(attrs[1].1),
            big_endian: to_bool(attrs[2].1),
            delay: u32dec(attrs[3].1),
            size: u32dec(attrs[4].1),
            physical: to_bool(attrs[5].1),
        };
        (next, space)
    })
}

fn spaces(input: &str) -> Res<&str, (&str, Vec<Space>)> {
    tuple((
        terminated(
            delimited(tag("<spaces "), take_until(">"), tag(">")),
            line_ending,
        ),
        terminated(
            separated_list1(line_ending, space),
            preceded(line_ending, tag("</spaces>")),
        ),
    ))(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res.0).finish().unwrap();
        (next, (attrs[0].1, res.1))
    })
}

fn to_bool(s: &str) -> bool {
    s.parse::<bool>().unwrap()
}

fn u32hex(s: &str) -> u32 {
    u32::from_str_radix(&s[2..], 16).unwrap()
}

fn u64hex(s: &str) -> u64 {
    u64::from_str_radix(&s[2..], 16).unwrap()
}

fn u64dec(s: &str) -> u64 {
    u64::from_str_radix(&s, 10).unwrap()
}

fn u32dec(s: &str) -> u32 {
    u32::from_str_radix(&s, 10).unwrap()
}

fn i32dec(s: &str) -> i32 {
    i32::from_str_radix(&s, 10).unwrap()
}

fn i64dec(s: &str) -> i64 {
    i64::from_str_radix(&s, 10).unwrap()
}

fn scope(input: &str) -> Res<&str, Symbol> {
    delimited(tag("<scope "), take_until("/>"), tag("/>"))(input).map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        //println!("{} {:?}", res, attrs);
        let id = u32hex(attrs[1].1);
        let scope = Scope {
            parent: u32hex(&attrs[1].1),
        };
        (
            next,
            Symbol {
                id: id,
                body: SymbolBody::Scope(scope),
            },
        )
    })
}

fn sym_head(input: &str) -> Res<&str, Symbol> {
    delimited(
        preceded(
            tag("<"),
            alt((
                terminated(
                    alt((
                        tag("subtable"),
                        tag("start"),
                        tag("end"),
                        tag("next2"),
                        tag("varnode"),
                        tag("valuemap"),
                        tag("varlist"),
                        tag("value"),
                        tag("context"),
                        tag("operand"),
                    )),
                    tag("_sym_head "),
                ),
                tag("userop_head "),
            )),
        ),
        take_until("/>"),
        tag("/>"),
    )(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        //println!("{} {:?}", res, attrs);
        let id = u32hex(attrs[1].1);
        let sym_head = SymbolHead {
            name: attrs[0].1,
            scope: u32hex(attrs[2].1),
        };
        (
            next,
            Symbol {
                id: id,
                body: SymbolBody::SymHead(sym_head),
            },
        )
    })
}

fn operand(input: &str) -> Res<&str, u32> {
    delimited(tag("<oper"), take_until("/>"), tag("/>"))(input).map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        //println!("{} {:?}", res, attrs);
        (next, u32hex(attrs[0].1))
    })
}

fn operands(input: &str) -> Res<&str, Vec<u32>> {
    separated_list1(line_ending, operand)(input)
}

fn opprint(input: &str) -> Res<&str, PrintCommand> {
    delimited(tag("<opprint"), take_until("/>"), tag("/>"))(input).map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        (next, PrintCommand::Op(u32dec(attrs[0].1)))
    })
}

fn print_piece(input: &str) -> Res<&str, PrintCommand> {
    delimited(tag("<print"), take_until("/>"), tag("/>"))(input).map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        (next, PrintCommand::Piece(attrs[0].1))
    })
}

fn print_command(input: &str) -> Res<&str, PrintCommand> {
    alt((opprint, print_piece))(input)
}

fn print_commands(input: &str) -> Res<&str, Vec<PrintCommand>> {
    separated_list1(line_ending, print_command)(input)
}

fn const_expr(input: &str) -> Res<&str, Expr> {
    //println!("const {}", &input[0..20]);
    delimited(tag("<intb"), take_until("/>"), tag("/>"))(input).map(|(next, res)| {
        //println!("foobar {:?}", res);
        let (_, attrs) = attrs(res).finish().unwrap();
        //println!("{} {:?}", res, attrs);
        (next, Expr::Const(i64dec(attrs[0].1)))
    })
}

fn operand_expr(input: &str) -> Res<&str, Expr> {
    delimited(tag("<operand_exp"), take_until("/>"), tag("/>"))(input).map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        //println!("{} {:?}", res, attrs);
        let operand_expr = OperandExpr {
            idx: u32dec(attrs[0].1),
            table: u32hex(attrs[1].1),
            ct: u32hex(attrs[2].1),
        };
        (next, Expr::Operand(operand_expr))
    })
}

fn contextfield(input: &str) -> Res<&str, Field> {
    delimited(tag("<contextfield"), take_until("/>"), tag("/>"))(input).map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        let context_field = ContextField {
            sign_bit: to_bool(attrs[0].1),
            start_bit: u32dec(attrs[1].1),
            end_bit: u32dec(attrs[2].1),
            start_byte: u32dec(attrs[3].1),
            end_byte: u32dec(attrs[4].1),
            shift: u32dec(attrs[5].1),
        };
        (next, Field::Context(context_field))
    })
}

fn field_expr(input: &str) -> Res<&str, Expr> {
    //println!("* field {}", &input[0..20]);
    field(input).map(|(next, res)| (next, Expr::Field(res)))
}

fn start_expr(input: &str) -> Res<&str, Expr> {
    tag("<start_exp/>")(input).map(|(next, res)| (next, (Expr::Start)))
}

fn end_expr(input: &str) -> Res<&str, Expr> {
    tag("<end_exp/>")(input).map(|(next, res)| (next, (Expr::End)))
}

fn next2_expr(input: &str) -> Res<&str, Expr> {
    tag("<next2_exp/>")(input).map(|(next, res)| (next, (Expr::Next2)))
}

fn unary_expr(input: &str) -> Res<&str, Expr> {
    //println!("* unary {}", &input[0..20]);
    let expr_types = alt((tag("not_exp"), tag("dummy_exp")));

    let (input, (expr_type, hs_expr, _)) = tuple((
        terminated(delimited(char('<'), expr_types, char('>')), line_ending),
        expr,
        preceded(line_ending, delimited(tag("</"), identifier, char('>'))),
    ))(input)?;

    let hs = Box::new(hs_expr);

    let expr = match expr_type {
        "not_exp" => Expr::Not(hs),
        _ => todo!(),
    };

    Ok((input, expr))
}

fn binary_expr(input: &str) -> Res<&str, Expr> {
    //println!("* binary {}", &input[0..20]);
    let expr_types = alt((
        tag("plus_exp"),
        tag("and_exp"),
        tag("xor_exp"),
        tag("or_exp"),
        tag("lshift_exp"),
        tag("rshift_exp"),
        tag("mult_exp"),
    ));

    let (input, (expr_type, (lhs_expr, rhs_expr), _)) = tuple((
        terminated(delimited(char('<'), expr_types, char('>')), line_ending),
        separated_pair(expr, opt(line_ending), expr),
        preceded(line_ending, delimited(tag("</"), identifier, char('>'))),
    ))(input)?;

    let lhs = Box::new(lhs_expr);
    let rhs = Box::new(rhs_expr);

    let expr = match expr_type {
        "plus_exp" => Expr::Add((lhs, rhs)),
        "and_exp" => Expr::And((lhs, rhs)),
        "or_exp" => Expr::Or((lhs, rhs)),
        "xor_exp" => Expr::Xor((lhs, rhs)),
        "lshift_exp" => Expr::Lshift((lhs, rhs)),
        "rshift_exp" => Expr::Rshift((lhs, rhs)),
        "mult_exp" => Expr::Mult((lhs, rhs)),
        _ => todo!(),
    };

    Ok((input, expr))
}

fn expr(input: &str) -> Res<&str, Expr> {
    //println!("* context expr {}", &input[0..20]);
    alt((
        start_expr,
        end_expr,
        next2_expr,
        const_expr,
        operand_expr,
        field_expr,
        unary_expr,
        binary_expr,
    ))(input)
}

fn context_op(input: &str) -> Res<&str, ContextOp> {
    tuple((
        terminated(
            delimited(tag("<context_op"), take_until(">"), tag(">")),
            line_ending,
        ),
        terminated(expr, terminated(line_ending, tag("</context_op>"))),
    ))(input)
    .map(|(next, res)| {
        //println!("context {:?}", res.0);
        let (_, attrs) = attrs(res.0).finish().unwrap();
        //println!("{} {:?}", res.0, attrs);
        let context_op = ContextOp {
            i: u32dec(attrs[0].1),
            shift: u32dec(attrs[1].1),
            mask: u32hex(attrs[2].1),
            expr: res.1,
        };
        (next, context_op)
    })
}

fn context_ops(input: &str) -> Res<&str, Vec<ContextOp>> {
    separated_list1(line_ending, context_op)(input)
}

fn const_template(input: &str) -> Res<&str, ConstTemplate> {
    //println!("const {}", &input[0..20]);
    delimited(tag("<const_tpl"), take_until("/>"), tag("/>"))(input).map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        //println!("{} {:?}", res, attrs);

        let const_template = match attrs[0].1 {
            "spaceid" => ConstTemplate::SpaceId(attrs[1].1),
            "real" => ConstTemplate::Val(u64hex(attrs[1].1)),
            "handle" => ConstTemplate::Handle(u32dec(attrs[1].1)),
            "relative" => ConstTemplate::Relative(u32hex(attrs[1].1)),
            "start" => ConstTemplate::Start,
            "next" => ConstTemplate::Next,
            "curspace" => ConstTemplate::CurSpace,
            "curspace_size" => ConstTemplate::CurSpaceSize,
            _ => todo!(),
        };

        (next, const_template)
    })
}

fn nonnull_varnode_template(input: &str) -> Res<&str, Option<VarnodeTemplate>> {
    //println!("vnode {}", &input[0..20]);
    delimited(
        tag("<varnode_tpl>"),
        tuple((const_template, const_template, const_template)),
        tag("</varnode_tpl>"),
    )(input)
    .map(|(next, res)| {
        //println!("varnode {:?}", res.1);
        let varnode_template = VarnodeTemplate {
            space_template: res.0,
            offset_template: res.1,
            size_template: res.2,
        };
        (next, Some(varnode_template))
    })
}

fn null_varnode_template(input: &str) -> Res<&str, Option<VarnodeTemplate>> {
    tag("<null/>")(input).map(|(next, res)| (next, None))
}

fn varnode_template(input: &str) -> Res<&str, Option<VarnodeTemplate>> {
    alt((null_varnode_template, nonnull_varnode_template))(input)
}

fn op_template(input: &str) -> Res<&str, ConsTemplate> {
    //println!("op {}", &input[0..20]);
    preceded(
        opt(tag("<null/>")),
        tuple((
            delimited(tag("<op_tpl"), take_until(">"), tag(">")),
            terminated(varnode_template, line_ending),
            terminated(
                separated_list0(line_ending, varnode_template),
                terminated(line_ending, tag("</op_tpl>")),
            ),
        )),
    )(input)
    .map(|(next, res)| {
        //println!("op {:?}", res.1);
        let (_, attrs) = attrs(res.0).finish().unwrap();
        let op_template = OpTemplate {
            code: attrs[0].1,
            output: res.1,
            inputs: res.2.into_iter().filter_map(|x| x).collect(),
        };
        // println!("{} {}", op_template.code, op_template.inputs.len());
        (next, ConsTemplate::Op(op_template))
    })
}

fn handle_template(input: &str) -> Res<&str, ConsTemplate> {
    preceded(
        opt(tag("<null/>")),
        delimited(
            tag("<handle_tpl>"),
            tuple((
                const_template,
                const_template,
                const_template,
                const_template,
                const_template,
                const_template,
                const_template,
            )),
            tag("</handle_tpl>"),
        ),
    )(input)
    .map(|(next, res)| {
        //println!("op {:?}", res.1);
        let vn_tmpl = VarnodeTemplate {
            space_template: res.0.clone(),
            offset_template: res.3,
            size_template: res.1.clone(),
        };

        let ind_tmpl = VarnodeTemplate {
            space_template: res.5,
            size_template: res.1,
            offset_template: res.6,
        };

        let exp_tmpl = VarnodeTemplate {
            space_template: res.0,
            size_template: res.2,
            offset_template: res.4,
        };

        let handle_template = HandleTemplate {
            varnode_template: vn_tmpl,
            exported_template: exp_tmpl,
            indirect_template: ind_tmpl,
        };

        (next, ConsTemplate::Handle(handle_template))
    })
}

fn null_ops(input: &str) -> Res<&str, Vec<ConsTemplate>> {
    tag("<null/>")(input).map(|(next, res)| (next, vec![]))
}

fn constructor_template(input: &str) -> Res<&str, ConstructorTemplate> {
    tuple((
        terminated(
            delimited(tag("<construct_tpl"), take_until(">"), tag(">")),
            line_ending,
        ),
        terminated(
            alt((
                terminated(
                    separated_list0(line_ending, alt((op_template, handle_template))),
                    line_ending,
                ),
                null_ops,
            )),
            tag("</construct_tpl>"),
        ),
    ))(input)
    .map(|(next, res)| {
        //println!("construtor_tpl {:?}", res);
        let (_, attrs) = attrs(res.0).finish().unwrap();

        let num_labels = match attrs.len() {
            0 => 0,
            1 => u32dec(attrs[0].1),
            _ => todo!(),
        };

        let constructor_template = ConstructorTemplate {
            num_labels: num_labels,
            statements: res.1,
        };

        (next, constructor_template)
    })
}

fn constructor(input: &str) -> Res<&str, Constructor> {
    tuple((
        delimited(
            tag("<constructor "),
            take_until(">"),
            terminated(tag(">"), line_ending),
        ),
        terminated(
            tuple((
                opt(terminated(operands, line_ending)),
                opt(terminated(print_commands, line_ending)),
                opt(terminated(context_ops, line_ending)),
                opt(terminated(constructor_template, line_ending)),
            )),
            tag("</constructor>"),
        ),
    ))(input)
    .map(|(next, res)| {
        //println!("constructor {:?}", res.1);
        let (_, attrs) = attrs(res.0).finish().unwrap();
        //println!("{:?}", attrs);
        let constructor = Constructor {
            parent: u32hex(attrs[0].1),
            first: i32dec(attrs[1].1),
            length: u32dec(attrs[2].1),
            operands: res.1 .0.unwrap_or_default(),
            print_commands: res.1 .1,
            context_ops: res.1 .2.unwrap_or_default(),
            template: res.1 .3,
        };
        (next, constructor)
    })
}

fn mask_word(input: &str) -> Res<&str, MaskWord> {
    delimited(tag("<mask_word "), take_until("/>"), tag("/>"))(input).map(|(next, res)| {
        //println!("mask word {:?}", res);
        let (_, attrs) = attrs(res).finish().unwrap();
        let mask_word = MaskWord {
            mask: u32hex(attrs[0].1),
            val: u32hex(attrs[1].1),
        };
        (next, mask_word)
    })
}

fn pattern_block(input: &str) -> Res<&str, PatternBlock> {
    tuple((
        terminated(
            delimited(tag("<pat_block "), take_until(">"), tag(">")),
            line_ending,
        ),
        alt((
            terminated(
                separated_list1(line_ending, preceded(space0, mask_word)),
                line_ending,
            ),
            separated_list0(line_ending, mask_word),
        )),
        tag("</pat_block>"),
    ))(input)
    .map(|(next, res)| {
        //println!("pattern block {:?}", res);
        let (_, attrs) = attrs(res.0).finish().unwrap();
        let pattern_block = PatternBlock {
            offset: u32dec(attrs[0].1),
            nonzero: u32dec(attrs[1].1),
            masks: res.1,
        };
        (next, pattern_block)
    })
}

fn combine_pattern(input: &str) -> Res<&str, DecisionPattern> {
    delimited(
        terminated(tag("<combine_pat>"), line_ending),
        separated_pair(decision_pattern, line_ending, decision_pattern),
        preceded(line_ending, tag("</combine_pat>")),
    )(input)
    .map(|(next, res)| {
        //println!("combine pattern {:?}", res);
        (
            next,
            DecisionPattern::Combine((Box::new(res.0), Box::new(res.1))),
        )
    })
}

fn context_pattern(input: &str) -> Res<&str, DecisionPattern> {
    delimited(
        terminated(tag("<context_pat>"), line_ending),
        pattern_block,
        preceded(line_ending, tag("</context_pat>")),
    )(input)
    .map(|(next, res)| {
        //println!("context pattern {:?}", res);
        (next, DecisionPattern::Context(res))
    })
}

fn instruction_pattern(input: &str) -> Res<&str, DecisionPattern> {
    delimited(
        terminated(tag("<instruct_pat>"), line_ending),
        pattern_block,
        preceded(line_ending, tag("</instruct_pat>")),
    )(input)
    .map(|(next, res)| {
        //println!("instruct pattern {:?}", res);
        (next, DecisionPattern::Instruction(res))
    })
}

fn decision_pattern(input: &str) -> Res<&str, DecisionPattern> {
    alt((context_pattern, instruction_pattern, combine_pattern))(input)
}

fn decision_pair(input: &str) -> Res<&str, (u32, DecisionPattern)> {
    tuple((
        terminated(
            delimited(tag("<pair "), take_until(">"), tag(">")),
            line_ending,
        ),
        terminated(terminated(decision_pattern, line_ending), tag("</pair>")),
    ))(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res.0).finish().unwrap();
        let id = u32dec(attrs[0].1);
        (next, (id, res.1))
    })
}

fn decision_pairs(input: &str) -> Res<&str, DecisionTree> {
    separated_list1(line_ending, decision_pair)(input).map(|(next, res)| {
        //println!("decision pairs {:?}", res);
        (next, DecisionTree::Leaf(res))
    })
}

fn decision_body(input: &str) -> Res<&str, DecisionTree> {
    alt((decision_pairs, decision_tree))(input)
}

fn decision_tree(input: &str) -> Res<&str, DecisionTree> {
    //println!("decision tree {}", &input[0..20]);
    tuple((
        delimited(
            tag("<decision"),
            take_until(">"),
            terminated(tag(">"), line_ending),
        ),
        terminated(
            alt((
                terminated(separated_list1(line_ending, decision_body), line_ending),
                separated_list0(line_ending, decision_body),
            )),
            tag("</decision>"),
        ),
    ))(input)
    .map(|(next, res)| {
        //println!("decision body {:?}", res);
        let (_, attrs) = attrs(res.0).finish().unwrap();
        //println!("{} {:?}", res.0, attrs);
        let is_context = to_bool(attrs[1].1);
        let start = u32dec(attrs[2].1);
        let size = u32dec(attrs[3].1);
        (
            next,
            DecisionTree::NonLeaf((is_context, start, size, res.1)),
        )
    })
}

fn subtable_sym(input: &str) -> Res<&str, Symbol> {
    //println!("subtable_sym {}", &input[0..50]);
    tuple((
        delimited(
            tag("<subtable_sym "),
            take_until(">"),
            terminated(tag(">"), line_ending),
        ),
        terminated(
            tuple((
                terminated(separated_list1(line_ending, constructor), line_ending),
                decision_tree,
            )),
            preceded(line_ending, tag("</subtable_sym>")),
        ),
    ))(input)
    .map(|(next, res)| {
        //println!("{:?}", res.1.0.len());
        let (_, attrs) = attrs(res.0).finish().unwrap();
        //println!("{} {:?}", res.0, attrs);
        let id = u32hex(attrs[1].1);
        let subtable = Subtable {
            name: attrs[0].1,
            scope: u32hex(attrs[2].1),
            constructors: res.1 .0,
            decision_tree: res.1 .1,
        };
        (
            next,
            Symbol {
                id: id,
                body: SymbolBody::Subtable(subtable),
            },
        )
    })
}

fn start_sym(input: &str) -> Res<&str, Symbol> {
    delimited(tag("<start_sym "), take_until("/>"), tag("/>"))(input).map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        let id = u32hex(attrs[1].1);
        let sym_head = SymbolHead {
            name: attrs[0].1,
            scope: u32hex(attrs[2].1),
        };
        (
            next,
            Symbol {
                id: id,
                body: SymbolBody::Start(sym_head),
            },
        )
    })
}

fn end_sym(input: &str) -> Res<&str, Symbol> {
    delimited(tag("<end_sym "), take_until("/>"), tag("/>"))(input).map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        let id = u32hex(attrs[1].1);
        let sym_head = SymbolHead {
            name: attrs[0].1,
            scope: u32hex(attrs[2].1),
        };
        (
            next,
            Symbol {
                id: id,
                body: SymbolBody::End(sym_head),
            },
        )
    })
}

fn next2_sym(input: &str) -> Res<&str, Symbol> {
    delimited(tag("<next2_sym "), take_until("/>"), tag("/>"))(input).map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        let id = u32hex(attrs[1].1);
        let sym_head = SymbolHead {
            name: attrs[0].1,
            scope: u32hex(attrs[2].1),
        };
        (
            next,
            Symbol {
                id: id,
                body: SymbolBody::Next2(sym_head),
            },
        )
    })
}

fn varnode_sym(input: &str) -> Res<&str, Symbol> {
    terminated(
        delimited(
            tag("<varnode_sym "),
            take_until(">"),
            terminated(tag(">"), line_ending),
        ),
        tag("</varnode_sym>"),
    )(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        //println!("{} {:?}", res, attrs);
        let id = u32hex(attrs[1].1);
        let varnode = VarnodeSym {
            name: attrs[0].1,
            scope: u32hex(attrs[2].1),
            space: attrs[3].1,
            offset: u64hex(attrs[4].1),
            size: u64dec(attrs[5].1),
        };
        (
            next,
            Symbol {
                id: id,
                body: SymbolBody::Varnode(varnode),
            },
        )
    })
}

fn tokenfield(input: &str) -> Res<&str, Field> {
    delimited(tag("<tokenfield"), take_until("/>"), tag("/>"))(input).map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        let token_field = TokenField {
            big_endian: to_bool(attrs[0].1),
            sign_bit: to_bool(attrs[1].1),
            start_bit: u32dec(attrs[2].1),
            end_bit: u32dec(attrs[3].1),
            start_byte: u32dec(attrs[4].1),
            end_byte: u32dec(attrs[5].1),
            shift: u32dec(attrs[6].1),
        };
        (next, Field::Token(token_field))
    })
}

fn field(input: &str) -> Res<&str, Field> {
    alt((contextfield, tokenfield))(input)
}

fn valuetab(input: &str) -> Res<&str, u64> {
    //println!("valuetab {}", &input[0..20]);
    delimited(tag("<valuetab"), take_until("/>"), tag("/>"))(input).map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        let val = u64dec(attrs[0].1);
        (next, val)
    })
}

fn valuemap_sym(input: &str) -> Res<&str, Symbol> {
    tuple((
        delimited(
            tag("<valuemap_sym "),
            take_until(">"),
            terminated(tag(">"), line_ending),
        ),
        terminated(
            separated_pair(
                field,
                line_ending,
                terminated(separated_list0(line_ending, valuetab), line_ending),
            ),
            tag("</valuemap_sym>"),
        ),
    ))(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res.0).finish().unwrap();
        let id = u32hex(attrs[1].1);
        let valuemap = Valuemap {
            name: attrs[0].1,
            scope: u32hex(attrs[2].1),
            field: res.1 .0,
            vars: res.1 .1,
        };
        (
            next,
            Symbol {
                id: id,
                body: SymbolBody::Valuemap(valuemap),
            },
        )
    })
}

fn nonnull_var(input: &str) -> Res<&str, Option<u32>> {
    delimited(tag("<var"), take_until("/>"), tag("/>"))(input).map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        let id = u32hex(attrs[0].1);
        (next, Some(id))
    })
}

fn null_var(input: &str) -> Res<&str, Option<u32>> {
    tag("<null/>")(input).map(|(next, res)| (next, None))
}

fn var(input: &str) -> Res<&str, Option<u32>> {
    //println!("var {}", &input[0..20]);
    alt((nonnull_var, null_var))(input)
}

fn varlist_sym(input: &str) -> Res<&str, Symbol> {
    //println!("varlist {}", &input[0..50]);
    tuple((
        delimited(
            tag("<varlist_sym "),
            take_until(">"),
            terminated(tag(">"), line_ending),
        ),
        terminated(
            separated_pair(
                field,
                line_ending,
                terminated(separated_list0(line_ending, var), line_ending),
            ),
            tag("</varlist_sym>"),
        ),
    ))(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res.0).finish().unwrap();
        let id = u32hex(attrs[1].1);
        let varlist = Varlist {
            name: attrs[0].1,
            scope: u32hex(attrs[2].1),
            field: res.1 .0,
            vars: res.1 .1,
        };
        (
            next,
            Symbol {
                id: id,
                body: SymbolBody::Varlist(varlist),
            },
        )
    })
}

fn value_sym(input: &str) -> Res<&str, Symbol> {
    tuple((
        delimited(
            tag("<value_sym "),
            take_until(">"),
            terminated(tag(">"), line_ending),
        ),
        terminated(tokenfield, preceded(line_ending, tag("</value_sym>"))),
    ))(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res.0).finish().unwrap();
        let id = u32hex(attrs[1].1);
        let value = Value {
            name: attrs[0].1,
            scope: u32hex(attrs[2].1),
            field: res.1,
        };
        (
            next,
            Symbol {
                id: id,
                body: SymbolBody::Value(value),
            },
        )
    })
}

fn context_sym(input: &str) -> Res<&str, Symbol> {
    tuple((
        delimited(
            tag("<context_sym "),
            take_until(">"),
            terminated(tag(">"), line_ending),
        ),
        terminated(contextfield, preceded(line_ending, tag("</context_sym>"))),
    ))(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res.0).finish().unwrap();

        let context_field = match res.1 {
            Field::Context(ctx_field) => ctx_field,
            _ => panic!(),
        };

        let id = u32hex(attrs[1].1);

        let context = Context {
            name: attrs[0].1,
            scope: u32hex(attrs[2].1),
            varnode: u32hex(attrs[3].1),
            low: u32dec(attrs[4].1),
            high: u32dec(attrs[5].1),
            flow: to_bool(attrs[6].1),
            context_field: context_field,
        };
        (
            next,
            Symbol {
                id: id,
                body: SymbolBody::Context(context),
            },
        )
    })
}

fn operand_sym(input: &str) -> Res<&str, Symbol> {
    tuple((
        delimited(
            tag("<operand_sym "),
            take_until(">"),
            terminated(tag(">"), line_ending),
        ),
        terminated(
            tuple((operand_expr, opt(preceded(line_ending, expr)))),
            preceded(line_ending, tag("</operand_sym>")),
        ),
    ))(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res.0).finish().unwrap();
        //println!("{} {:?}", res.0, attrs);

        let operand_expr = match res.1 .0 {
            Expr::Operand(op_expr) => op_expr,
            _ => panic!(),
        };

        let kvs: HashMap<&str, &str> = attrs.into_iter().collect();
        let id = u32hex(kvs["id"]);

        let operand = Operand {
            name: kvs["name"],
            scope: u32hex(kvs["scope"]),
            subsym: kvs.get("subsym").map(|s| u32hex(s)).unwrap_or(0),
            off: kvs.get("off").map(|s| u64dec(s)).unwrap_or(0),
            base: kvs.get("base").map(|s| i64dec(s)).unwrap_or(0),
            min_len: kvs.get("minlen").map(|s| u64dec(s)).unwrap_or(0),
            idx: kvs.get("idx").map(|s| u64dec(s)).unwrap_or(0),
            is_code: kvs.get("code").map(|s| to_bool(s)).unwrap_or(false),
            operand_expr: operand_expr,
            expr: res.1 .1,
        };
        (
            next,
            Symbol {
                id: id,
                body: SymbolBody::Operand(operand),
            },
        )
    })
}

fn userop(input: &str) -> Res<&str, Symbol> {
    delimited(tag("<userop "), take_until("/>"), tag("/>"))(input).map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        let id = u32hex(attrs[1].1);

        let userop = UserOp {
            name: attrs[0].1,
            scope: u32hex(attrs[2].1),
            idx: u32dec(attrs[3].1),
        };

        (
            next,
            Symbol {
                id: id,
                body: SymbolBody::UserOp(userop),
            },
        )
    })
}

fn sym(input: &str) -> Res<&str, Symbol> {
    //println!("** {}", &input[0..20]);
    alt((
        subtable_sym,
        varnode_sym,
        start_sym,
        end_sym,
        next2_sym,
        valuemap_sym,
        varlist_sym,
        value_sym,
        context_sym,
        operand_sym,
        userop,
    ))(input)
}

fn symbol(input: &str) -> Res<&str, Symbol> {
    alt((scope, sym_head, sym))(input)
}

fn symbol_table(input: &str) -> Res<&str, Vec<Symbol>> {
    tuple((
        terminated(
            delimited(tag("<symbol_table "), take_until(">"), tag(">")),
            line_ending,
        ),
        terminated(
            separated_list1(line_ending, symbol),
            preceded(line_ending, tag("</symbol_table>")),
        ),
    ))(input)
    .map(|(next, res)| {
        //println!("{:?}", res.1.len());
        (next, res.1)
    })
}

fn attrs(input: &str) -> Res<&str, Vec<(&str, &str)>> {
    //println!("{:?}", &input);
    preceded(
        space0,
        separated_list0(char(' '), separated_pair(identifier, char('='), string)),
    )(input)
    .map(|(next, res)| {
        //println!("{:?}", res);
        (next, res)
    })
}

pub fn program(input: &str) -> Res<&str, Program> {
    tuple((
        terminated(
            delimited(tag("<sleigh "), take_until(">"), tag(">")),
            line_ending,
        ),
        terminated(source_files, line_ending),
        terminated(spaces, line_ending),
        terminated(symbol_table, line_ending),
    ))(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res.0).finish().unwrap();
        let prog = Program {
            version: u32::from_str_radix(attrs[0].1, 10).unwrap(),
            bigendian: attrs[1].1.parse::<bool>().unwrap(),
            align: u32::from_str_radix(attrs[2].1, 10).unwrap(),
            uniqbase: u64::from_str_radix(&attrs[3].1[2..], 16).unwrap(),
            default_space: res.2 .0,
            spaces: res.2 .1,
            symbols: res.3,
        };
        (next, prog)
    })
}

fn identifier(input: &str) -> Res<&str, &str> {
    recognize(pair(
        alt((alpha1, tag("_"), tag("."))),
        many0_count(alt((alphanumeric1, tag("_"), tag(".")))),
    ))(input)
}

fn identifier_ws(input: &str) -> Res<&str, &str> {
    terminated(identifier, space0)(input)
}

fn string(input: &str) -> Res<&str, &str> {
    delimited(char('"'), take_until("\""), char('"'))(input)
}

pub fn read_file(filename: &str) -> String {
    fs::read_to_string(format!("{}/{}", SLEIGH_PATH, filename)).expect("can't read file")
}

fn match_ctx_pattern_block(block: &PatternBlock, words: &Vec<u32>) -> bool {
    let mut word_idx = (block.offset / 4) as usize;
    let mut byte_idx = block.offset % 4;

    for (i, mask_word) in block.masks.iter().enumerate() {
        let cw = words[word_idx];
        let nw = if word_idx < words.len() - 1 { words[word_idx+1] } else { 0 };
        let word = (cw & (((1_u64 << (32 - (byte_idx * 8))) - 1) as u32)).overflowing_shl(byte_idx * 8).0 | 
                   nw.overflowing_shr(32 - (byte_idx * 8)).0;

        word_idx += 1;

        // let word = words[i];
        // println!("ctx {:x} vs {:x}, {:x} ({:x})", word & mask_word.mask, mask_word.val, mask_word.mask, word);
        if (word & mask_word.mask) != mask_word.val {
            return false;
        }
    }
    true
}

fn match_insn_pattern_block(block: &PatternBlock, words: &Vec<u8>) -> bool {
    for (i, mask_word) in block.masks.iter().enumerate() {
        let word = get_word(words, (block.offset as usize) + i * 4);
        // println!("insn {:x} vs {:x}, {:x}", word & mask_word.mask, mask_word.val, mask_word.mask);
        if (word & mask_word.mask) != mask_word.val {
            return false;
        }
    }
    true
}

fn match_pattern(pattern: &DecisionPattern, insn_words: &Vec<u8>, ctx_words: &Vec<u32>) -> bool {
    // TODO: Maybe use offset for ctx?
    match pattern {
        DecisionPattern::Context(pat_blk) => match_ctx_pattern_block(pat_blk, ctx_words),
        DecisionPattern::Instruction(pat_blk) => match_insn_pattern_block(pat_blk, insn_words),
        DecisionPattern::Combine((pat1, pat2)) => {
            match_pattern(&*pat1, insn_words, ctx_words) && match_pattern(&*pat2, insn_words, ctx_words)
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MatchedSymbol<'a> {
    Constructor((&'a Constructor<'a>, Vec<MatchedSymbol<'a>>)),
    Symbol(&'a Symbol<'a>),
    Literal((i64, usize)),
}

pub fn read_ctx(
    ctx_reg: &VarnodeSym,
    reg_space: &BitVec<u8, Msb0>,
) -> Vec<u32> {
    let mut words = vec![];
    let mut size_left = ctx_reg.size * 8;

    while size_left > 0 {
        let start = (ctx_reg.offset * 8 + (words.len() as u64) * 32) as usize;
        let end = (start + 32) as usize;
        words.push(reg_space[start..end].load_be::<u32>());
        size_left -= size_left.min(32);
    }

    words
}

fn write_ctx(
    ctx: &Vec<u32>,
    ctx_reg: &VarnodeSym,
    reg_space: &mut BitVec<u8, Msb0>,
) {
    for (i, word) in ctx.iter().enumerate() {
        let start = (ctx_reg.offset * 8 + (i as u64) * 32) as usize;
        let end = (start + 32) as usize;
        reg_space[start..end].store_be(*word);
    }
}

fn get_word(words: &Vec<u8>, start: usize) -> u32 {
    let mut word: u32 = 0;

    if words.len() > start {
        word |= ((words[start] as u32) << 24);
    }

    if words.len() > start +1 {
        word |= ((words[start+1] as u32) << 16);
    }

    if words.len() > start + 2 {
        word |= ((words[start+2] as u32) << 8);
    }

    if words.len() > start + 3 {
        word |= words[start+3] as u32;
    }

    word
}

fn resolve_constructor<'a>(
    words: &Vec<u8>,
    table: &'a Subtable,
    symbols: &'a HashMap<u32, Symbol>,
    ctx: &mut Vec<u32>,
) -> Option<(&'a Constructor<'a>, usize)> {
    let mut dtree = &table.decision_tree;
    let mut bits_consumed = 0;

    loop {
        match dtree {
            DecisionTree::NonLeaf((is_context, start, size, children)) => {
                if *size == 0 && children.len() == 1 {
                    dtree = &children[0];
                    continue;
                }

                let bit_start = 32 - (start + size);

                if !is_context {
                    // println!("-- {} {} {}", bit_start, start, size);
                    let word = get_word(words, 0);
                    let idx = ((word >> bit_start) & ((1 << size) - 1)) as usize;
                    // println!("{} {} {}", start, size, idx);
                    dtree = &children[idx.min(children.len() - 1)];
                    bits_consumed = bits_consumed.max(start + size);
                } else {
                    // let ctx_start = (ctx_reg.offset * 8 + (*start as u64)) as usize;
                    // let ctx_end = ctx_start + (*size as usize);
                    // let idx = reg_space[ctx_start..ctx_end].load_be::<usize>();
                    let ctx_word = ctx[(*start as usize) / 32];
                    let idx = (ctx_word.overflowing_shr(bit_start).0 & ((1 << size) - 1)) as usize;
                    // println!("~~~ ctx {} {} {}", start, size, idx);
                    dtree = &children[idx.min(children.len() - 1)];
                }
            }
            DecisionTree::Leaf(pairs) => {
                // let ctx_base = (ctx_reg.offset * 8) as usize;
                // let ctx_end = ctx_base + (32 as usize);
                // // let ctx_words = reg_space[ctx_base..ctx_end].load_be::<u32>();
                // let ctx_words = read_ctx(ctx_reg, reg_space);
                // println!("--> ctx: {:?} {:?}", ctx_words, pairs);

                for (ct_id, pattern) in pairs {
                    let ct = &table.constructors[*ct_id as usize];
                    // println!("{:?}", ct.print_commands);

                    if match_pattern(pattern, &words, &ctx) {
                        // println!("matched {:?}", ct.print_commands);
                        return Some((ct, bits_consumed as usize));
                        // return Some(ct);
                    }
                }

                println!("did not match");
                return None;
            }
        };
    }
}

fn resolve_varlist<'a>(
    words: &Vec<u8>,
    varlist: &'a Varlist,
    symbols: &'a HashMap<u32, Symbol>,
    ctx: &mut Vec<u32>,
) -> Option<(MatchedSymbol<'a>, usize)> {
    match &varlist.field {
        Field::Token(token) => {
            // println!("{:?}", token);
            let num_bytes = (token.end_byte - token.start_byte + 1) as usize;
            let sb = token.start_byte as usize;
            let mut token_word: u32 = 0;

            for i in 0..num_bytes {
                token_word <<= 8;
                token_word |= words[sb + i] as u32;
            }

            let start = token.start_bit;
            let size = token.end_bit - start + 1;
            let idx = ((token_word >> start) & ((1 << size) - 1)) as usize;
            let var = &symbols[&varlist.vars[idx].unwrap()];

            // Not super sure if this size calculation is right but it seems to work.
            Some(((MatchedSymbol::Symbol(var)), (token.end_byte * 8 + (8 - token.end_bit - 1) + size) as usize))
        }
        _ => todo!(),
    }
}

fn resolve_valuemap<'a>(
    words: &Vec<u8>,
    valuemap: &'a Valuemap,
    symbols: &'a HashMap<u32, Symbol>,
    ctx: &mut Vec<u32>,
) -> Option<(MatchedSymbol<'a>, usize)> {
    match &valuemap.field {
        Field::Token(token) => {
            // println!("{:?}", token);
            let num_bytes = (token.end_byte - token.start_byte + 1) as usize;
            let sb = token.start_byte as usize;
            let mut token_word: u32 = 0;

            for i in 0..num_bytes {
                token_word <<= 8;
                token_word |= words[sb + i] as u32;
            }

            let start = token.start_bit;
            let size = token.end_bit - start + 1;
            let idx = ((token_word >> start) & ((1 << size) - 1)) as usize;
            let val = valuemap.vars[idx] as i64;

            // Not super sure if this size calculation is right but it seems to work.
            Some(((MatchedSymbol::Literal((val, size as usize))), (token.end_byte * 8 + (8 - token.end_bit - 1) + size) as usize))
        }
        _ => todo!(),
    }
}

fn evaluate_expr(
    expr: &Expr,
    ctx: &Vec<u32>,
    operands: &Vec<MatchedSymbol<'_>>,
) -> i64 {
    match expr {
        Expr::Const(val) => *val,
        Expr::Operand(op_expr) if (op_expr.idx as usize) < operands.len() => {
            if let MatchedSymbol::Literal((val, _)) = &operands[op_expr.idx as usize] {
                *val
            } else {
                panic!();
            }
        },
        Expr::Xor((lhs, rhs)) => {
            let lhs_val = evaluate_expr(&**lhs, ctx, operands);
            let rhs_val = evaluate_expr(&**rhs, ctx, operands);
            lhs_val ^ rhs_val
        },
        Expr::Field(Field::Context(ctx_field)) => {
            // FIXME: Use BitVec for context. Use end_byte.
            // println!("{:?}", ctx_field);
            let idx = (ctx_field.start_bit / 32) as usize;
            // let ctx_word = (ctx[idx] >> (32 - (ctx_field.start_byte * 8 + 8))) & 0xff;
            let ctx_word = ctx[idx];
            let size = ctx_field.end_bit - ctx_field.start_bit + 1;
            // println!("{} {}", ctx_field.start_bit, size);
            let bit_start = 32 - (ctx_field.start_bit + size);
            ((ctx_word >> bit_start) & ((1 << size) - 1)) as i64
        },
        _ => todo!("{:?}", expr),
    }
}

fn resolve_operands<'a>(
    words: &Vec<u8>,
    ct: &'a Constructor,
    symbols: &'a HashMap<u32, Symbol>,
    ctx: &mut Vec<u32>,
) -> (Vec<MatchedSymbol<'a>>, usize) {
    let mut matched_ops = vec![];
    let mut bit_end: usize = 0;
    // println!("{:?}\n", ct);

    for op_idx in &ct.operands {
        let operand = get_operand(&op_idx, &symbols);
        // println!("{} {:?}\n", op_idx, operand);

        match &operand.expr {
            Some(Expr::Field(Field::Token(expr))) => {
                // TODO: Handle end_byte.
                let size = expr.end_bit - expr.start_bit + 1;
                let bit_start = 32 - (expr.start_bit + size);
                let mut word: u32 = 0;

                for i in 0..4 {
                    word |= (words[bit_end / 8 + expr.start_byte as usize + i] as u32) << (i * 8);
                }

                let val = (word >> expr.start_bit) & (((1_u64 << size) - 1) as u32);
                // println!("{:x} {:x} {:x} {:?}", words[expr.start_byte as usize], word, val, expr);
                let num_bytes = (expr.end_byte - expr.start_byte + 1) as usize;
                matched_ops.push(MatchedSymbol::Literal((val as i64, num_bytes)));
                bit_end = bit_end.max((expr.end_byte * 8 + size) as usize);
            },
            Some(Expr::Field(Field::Context(expr))) => {
                // TODO: Handle end_byte.
                let size = expr.end_bit - expr.start_bit + 1;
                let bit_start = 32 - (expr.start_bit + size);
                let val = (ctx[(expr.start_bit / 32) as usize] >> bit_start) & ((1 << size) - 1);
                let num_bytes = (expr.end_byte - expr.start_byte + 1) as usize;
                matched_ops.push(MatchedSymbol::Literal((val as i64, num_bytes)));
                bit_end = bit_end.max((expr.end_byte * 8 + size) as usize);
            },
            None => {
                let op_sym = &symbols[&operand.subsym];
                let new_words = words[(operand.off as usize)..].to_vec(); // TODO: Remove this clone.

                // Before recursively resolving a symbol, we first need to modify the context.
                for op in &ct.context_ops {
                    let existing = ctx[op.i as usize];
                    let mask = op.mask;
                    // println!("{:?}", op);

                    let val = evaluate_expr(&op.expr, ctx, &matched_ops);
                    let v = ((val as u32) << op.shift);
                    ctx[op.i as usize] = (existing & !mask) | (v & mask);

                    // println!("ctx: {:x}", ctx[op.i as usize]);
                }

                // write_ctx(&ctx, ctx_reg, reg_space);

                match resolve_symbol(&new_words, op_sym, symbols, ctx) {
                    Some((matched_sym, sub_bit_end)) => {
                        matched_ops.push(matched_sym);
                        // println!("sub-constructor took {} bits, started at bit {}", sub_bit_end, operand.off * 8);
                        bit_end = bit_end.max((operand.off * 8) as usize + sub_bit_end);
                    },
                    None => (),
                };
            },
            _ => todo!("{:?}", operand.expr)
        }
    }

    (matched_ops, bit_end)
}

pub fn resolve_symbol<'a>(
    words: &Vec<u8>,
    sym: &'a Symbol,
    symbols: &'a HashMap<u32, Symbol>,
    ctx: &mut Vec<u32>,
) -> Option<(MatchedSymbol<'a>, usize)> {
    // println!("{}", sym.id);
    match &sym.body {
        SymbolBody::Subtable(table) => {
            // println!("{:#?}", table);
            match resolve_constructor(words, table, symbols, ctx) {
                Some((ct, bit_end)) => {
                    // println!("constructor took {} bits", bit_end);
                    let (operands, ops_bit_end) = resolve_operands(words, ct, symbols, ctx);
                    // println!("operands took {} bits", ops_bit_end);
                    Some((MatchedSymbol::Constructor((ct, operands)), bit_end.max(ops_bit_end)))
                }
                None => None,
            }
        },
        SymbolBody::Varlist(varlist) => {
            resolve_varlist(words, varlist, symbols, ctx)
        },
        SymbolBody::Valuemap(valuemap) => {
            resolve_valuemap(words, valuemap, symbols, ctx)
        },
        SymbolBody::Varnode(vnode) => {
            Some((MatchedSymbol::Symbol(sym), 0))
        },
        _ => todo!("{:?}", sym.body),
    }
}

fn get_table<'a>(id: u32, symbols: &'a HashMap<u32, Symbol>) -> &'a Subtable<'a> {
    let sym = &symbols[&id];
    match &sym.body {
        SymbolBody::Subtable(subtable) => subtable,
        _ => panic!(),
    }
}

fn get_operand<'a>(id: &u32, symbols: &'a HashMap<u32, Symbol>) -> &'a Operand<'a> {
    let sym = &symbols[id];
    match &sym.body {
        SymbolBody::Operand(operand) => operand,
        _ => panic!(),
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum VarnodeValue<'a> {
    String(&'a str),
    Int(u64),
    Op(&'a Varnode),
}

// #[derive(Debug, PartialEq, Eq, Clone)]
// pub enum Handle {
//     Dummy,
//     Varnode(Varnode),
//     Indirect((Varnode, Varnode)),
// }

// impl fmt::Display for Handle {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         match self {
//             Handle::Varnode(vn) => write!(f, "{}", vn),
//             Handle::Indirect((vn1, vn2)) => write!(f, "[{}]({})", vn1, vn2),
//             _ => write!(f, "DUMMY"),
//         }
//     }
// }

fn build_value<'a>(
    const_tpl: &'a ConstTemplate,
    varnodes: &'a Vec<Varnode>,
    debug: (bool, usize),
) -> VarnodeValue<'a> {
    match const_tpl {
        ConstTemplate::SpaceId(space) => VarnodeValue::String(space),
        ConstTemplate::Val(val) => VarnodeValue::Int(*val),
        ConstTemplate::Handle(idx) => {
            let ix = *idx as usize;
            VarnodeValue::Op(&varnodes[ix])

            // match &varnodes[ix] {
            //     Handle::Varnode(vn) => VarnodeValue::Op(vn),
            //     Handle::Indirect((space_vn, ptr_vn)) if space_vn.space == "const" => {
            //         VarnodeValue::Op(space_vn)
            //     }
            //     Handle::Indirect((space_vn, ptr_vn)) => panic!("{} {}", space_vn, ptr_vn),
            //     _ => panic!(),
            // }
        },
        ConstTemplate::Relative(idx) => todo!(),
        ConstTemplate::Start => todo!(),
        ConstTemplate::Next => todo!(),
        ConstTemplate::CurSpace => todo!(),
        ConstTemplate::CurSpaceSize => todo!(),
    }
}

fn build_handle<'a>(
    handle_tpl: &'a HandleTemplate,
    varnodes: &'a Vec<Varnode>,
    spaces: &'a HashMap<&'a str, u64>,
    varnode_map: &'a HashMap<(u64, u64), &'a str>,
    debug: (bool, usize),
) -> Varnode {
    let varnode = build_varnode(
        &handle_tpl.varnode_template,
        varnodes,
        spaces,
        varnode_map,
        debug
    );

    varnode

    // if matches!(handle_tpl.indirect_template.space_template, ConstTemplate::SpaceId(_)) {
    //     let pointer = build_varnode(
    //         &handle_tpl.indirect_template,
    //         varnodes,
    //         spaces,
    //         varnode_map,
    //         debug
    //     );

    //     Handle::Indirect((varnode, pointer))
    // } else {
    //     Handle::Varnode(varnode)
    // }
}

fn build_varnode<'a>(
    vnode_tpl: &'a VarnodeTemplate,
    varnodes: &'a Vec<Varnode>,
    spaces: &'a HashMap<&'a str, u64>,
    varnode_map: &'a HashMap<(u64, u64), &'a str>,
    debug: (bool, usize),
) -> Varnode {
    if debug.0 {
        let indent = " ".repeat(debug.1 * 4);
        println!("{}Building vnode: {}", indent, vnode_tpl);
        println!("{}    varnodes: {:?}\n", indent, varnodes);
    }

    let space = match build_value(&vnode_tpl.space_template, varnodes, debug) {
        VarnodeValue::String(name) => name,
        VarnodeValue::Op(op) => op.space.as_str(),
        _ => panic!(),
    };

    let size = match build_value(&vnode_tpl.size_template, varnodes, debug) {
        VarnodeValue::Int(sz) => sz,
        VarnodeValue::Op(op) => op.size,
        _ => panic!(),
    };

    let offset = match build_value(&vnode_tpl.offset_template, varnodes, debug) {
        VarnodeValue::Int(off) => off,
        VarnodeValue::Op(op) => {
            if space == "const" {
                match op.size {
                    1 => (((op.offset as i8) as i64) as u64),
                    2 => (((op.offset as i16) as i64) as u64),
                    4 => (((op.offset as i32) as i64) as u64),
                    8 => (((op.offset as i64) as i64) as u64),
                    _ => op.offset,
                }
            } else {
                op.offset
            }
        },
        VarnodeValue::String(name) => spaces[name],
        _ => panic!(),
    };

    let name = match space {
        "register" => varnode_map.get(&(offset, size)).map(|x| x.to_string()),
        _ => None,
    };

    Varnode {
        name: name,
        space: space.to_owned(),
        offset: offset,
        size: size,
    }
}

fn build_pcodeop<'a>(
    seq: SeqNum,
    op_tpl: &'a OpTemplate,
    varnodes: &'a Vec<Varnode>,
    spaces: &'a HashMap<&'a str, u64>,
    varnode_map: &'a HashMap<(u64, u64), &'a str>,
    debug: (bool, usize),
) -> PcodeOp {
    if debug.0 {
        let indent = " ".repeat(debug.1 * 4);
        println!("{}Building op: {}", indent, op_tpl);
        println!("{}    varnodes: {:?}\n", indent, varnodes);
    }

    PcodeOp {
        seq: seq,
        opcode: OpCode::from_str(op_tpl.code),
        inputs: op_tpl
            .inputs
            .iter()
            .map(|tpl| build_varnode(&tpl, varnodes, spaces, varnode_map, debug))
            .collect(),
        output: op_tpl
            .output
            .as_ref()
            .map(|tpl| build_varnode(&tpl, varnodes, spaces, varnode_map, debug)),
    }
}

pub fn build_sym<'a>(
    matched_sym: &'a MatchedSymbol,
    pc: &Address,
    spaces: &'a HashMap<&'a str, u64>,
    varnode_map: &'a HashMap<(u64, u64), &'a str>,
    debug: (bool, usize),
) -> (Vec<PcodeOp>, Option<Varnode>) {
    let mut built_pcodeops = vec![];
    let mut built_varnodes = vec![];
    let mut handle = None;

    let mut op_pcodeops = vec![];

    if let MatchedSymbol::Constructor((ct, operands)) = &matched_sym {
        for (i, op) in operands.iter().enumerate() {
            let mut op_ops = vec![];
            let mut op_handle = None;

            if debug.0 {
                println!("{}Building operand {}", " ".repeat(debug.1 * 4), i);
            }

            if let MatchedSymbol::Symbol(sym) = op {
                if let SymbolBody::Varnode(vnode) = &sym.body {
                    let name = match vnode.space {
                        "register" => varnode_map.get(&(vnode.offset, vnode.size)),
                        _ => None,
                    };

                    let varnode = Varnode {
                        name: name.map(|x| x.to_string()),
                        space: vnode.space.to_owned(),
                        offset: vnode.offset,
                        size: vnode.size,
                    };

                    if debug.0 {
                        println!("{}Built operand {}: {}", " ".repeat(debug.1 * 4), built_varnodes.len(), varnode);
                    }

                    op_handle = Some(varnode);
                }
            }
            else if let MatchedSymbol::Literal((val, size)) = op {
                let varnode = Varnode {
                    name: None,
                    space: "const".to_owned(),
                    offset: *val as u64,
                    size: *size as u64,
                };

                if debug.0 {
                    println!("{}Built operand {}: {}", " ".repeat(debug.1 * 4), built_varnodes.len(), varnode);
                }

                op_handle = Some(varnode);
            } else if let MatchedSymbol::Constructor(_) = op {
                (op_ops, op_handle) = build_sym(op, pc, spaces, varnode_map, (debug.0, debug.1 + 1));
            }

            op_pcodeops.push(op_ops);

            if let Some(handle) = op_handle {
                built_varnodes.push(handle);
            } else {
                // NOTE: We need a dummy handle for the operand indices to line up??
                // built_varnodes.push(Handle::Dummy);
                built_varnodes.push(Varnode {
                    name: None,
                    space: "DUMMY".to_string(),
                    offset: 0,
                    size: 0,
                });
            }
        }

        let template = ct.template.as_ref().unwrap();

        for stmt in &template.statements {
            if let ConsTemplate::Op(op_template) = stmt {
                if op_template.code == "BUILD" {
                    if let ConstTemplate::Val(op_idx) = op_template.inputs[0].offset_template {
                        let idx = op_idx as usize;

                        if debug.0 {
                            // println!("{}BUILD {:?}", " ".repeat(debug.1 * 4), operands[idx]);
                            println!("{}{}", " ".repeat(debug.1 * 4), op_template);
                        }

                        built_pcodeops.extend(op_pcodeops[idx].clone());
                    };
                } else {
                    let seq = SeqNum {
                        pc: pc.to_owned(),
                        uniq: built_pcodeops.len() as u32,
                        order: 0,
                    };
                    let pcodeop = build_pcodeop(
                        seq,
                        &op_template,
                        &built_varnodes,
                        spaces,
                        varnode_map,
                        debug,
                    );
                    built_pcodeops.push(pcodeop)
                }
            }
        }

        // Handle the varnodes after all the operands have been built.
        for stmt in &template.statements {
            if let ConsTemplate::Handle(handle_template) = stmt {
                let my_handle = build_handle(
                        &handle_template,
                        &built_varnodes,
                        spaces,
                        varnode_map,
                        debug
                );

                if debug.0 {
                    println!("{}Created handle: {}\n", " ".repeat(debug.1 * 4), my_handle);
                }

                handle = Some(my_handle);
            }
        }
    }

    (built_pcodeops, handle)
}

fn build_cmd_text(cmd: &PrintCommand, operands: &Vec<MatchedSymbol>) -> String {
    match cmd {
        PrintCommand::Op(op_idx) => build_text(&operands[*op_idx as usize]),
        PrintCommand::Piece(piece) => piece.to_string(),
    }
}

pub fn build_text(matched_sym: &MatchedSymbol) -> String {
    match &matched_sym {
        MatchedSymbol::Constructor((ct, operands)) => match &ct.print_commands {
            Some(cmds) => cmds
                .iter()
                .map(|c| build_cmd_text(&c, &operands))
                .collect::<Vec<String>>()
                .join(""),
            None => "".to_owned(),
        },
        MatchedSymbol::Symbol(sym) => match &sym.body {
            SymbolBody::Varnode(vnode) => vnode.name.to_owned(),
            _ => panic!(),
        },
        MatchedSymbol::Literal((val, _)) => format!("0x{:x}", val),
        _ => todo!()
    }
}

pub struct SleighLanguage<'a> {
    pub language: Language,
    pub program: Program<'a>,
    pub symbols: HashMap<u32, Symbol<'a>>,
    pub spaces: HashMap<&'a str, u64>,
    pub varnodes: HashMap<&'a str, VarnodeSym<'a>>,
    pub varnode_map: HashMap<(u64, u64), &'a str>,
    pub context_syms: HashMap<&'a str, Context<'a>>,
    pub reg_space_size: usize,
    pub insn_table_id: u32,
    pub context_reg: VarnodeSym<'a>,
}

impl<'a> SleighLanguage<'a> {
    pub fn create(arch_family: &str, lang_id: &str, sla_contents: &'a str) -> SleighLanguage<'a> {
        let lang = get_language(arch_family, lang_id).unwrap();
        let (_, sla) = program(sla_contents).finish().unwrap();

        let mut symbols: HashMap<u32, Symbol> = HashMap::new();
        let mut spaces: HashMap<&str, u64> = HashMap::new();
        let mut varnodes: HashMap<&str, VarnodeSym> = HashMap::new();
        let mut varnode_map: HashMap<(u64, u64), &str> = HashMap::new();
        let mut context_syms: HashMap<&str, Context> = HashMap::new();
        let mut reg_space_size: usize = 0;
        let mut insn_table_id = 0;

        for space in &sla.spaces {
            spaces.insert(space.name, spaces.len() as u64);
        }

        for sym in &sla.symbols {
            match &sym.body {
                SymbolBody::Subtable(subtable) => {
                    if subtable.name == "instruction" {
                        insn_table_id = sym.id;
                    }
                }
                SymbolBody::Varnode(varnode) => {
                    varnodes.insert(varnode.name, varnode.clone());

                    if varnode.space == "register" {
                        reg_space_size =
                            reg_space_size.max((varnode.offset + varnode.size) as usize);
                        varnode_map.insert((varnode.offset, varnode.size), varnode.name);
                    }
                }
                SymbolBody::Context(ctx) => {
                    context_syms.insert(ctx.name, ctx.clone());
                }
                _ => (),
            }

            symbols.insert(sym.id, sym.clone());
        }

        let ctx_reg = varnodes["contextreg"].clone();

        SleighLanguage {
            language: lang,
            program: sla,
            symbols: symbols,
            spaces: spaces,
            varnodes: varnodes,
            varnode_map: varnode_map,
            context_syms: context_syms,
            reg_space_size: reg_space_size,
            insn_table_id: insn_table_id,
            context_reg: ctx_reg,
        }
    }
}
