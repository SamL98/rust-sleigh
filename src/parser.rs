use crate::arch::get_language;
use crate::sleigh::opcode::OpCode;
use crate::sleigh::types::{Address, AddressSpace, PcodeOp, SeqNum, Varnode};

extern crate bitvec;
extern crate nom;

use super::arch::Language;
// use super::patterns::PcodePattern;

use nom::branch::*;
use nom::bytes::complete::*;
use nom::character::complete::*;
use nom::combinator::*;
use nom::error::*;
use nom::multi::*;
use nom::sequence::*;
use nom::*;

use flexstr::{local_str, LocalStr, ToLocalStr};

use bitvec::prelude::*;

use debug_macro::DebugPrint;

use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::borrow::Cow;

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
pub struct Space {
    pub name: String,
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
pub struct SymbolHead {
    pub name: String,
    pub scope: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VarnodeSym {
    pub name: String,
    pub scope: u32,
    pub space: AddressSpace,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Value {
    name: String,
    scope: u32,
    field: Field,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Varlist {
    pub name: String,
    pub scope: u32,
    pub field: Field,
    pub vars: Vec<Option<u32>>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NameTable {
    name: String,
    scope: u32,
    field: Field,
    names: Vec<Option<String>>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Valuemap {
    name: String,
    scope: u32,
    field: Field,
    vars: Vec<u64>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Operand {
    pub name: String,
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
pub struct Context {
    pub name: String,
    pub scope: u32,
    pub varnode: u32,
    pub low: u32,
    pub high: u32,
    pub flow: bool,
    pub context_field: ContextField,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UserOp {
    name: String,
    scope: u32,
    idx: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SymbolBody {
    Scope(Scope),
    SymHead(SymbolHead),
    Subtable(Subtable),
    Varnode(VarnodeSym),
    Value(Value),
    Varlist(Varlist),
    Nametab(NameTable),
    Valuemap(Valuemap),
    Operand(Operand),
    Context(Context),
    UserOp(UserOp),
    Start(SymbolHead),
    End(SymbolHead),
    Next2(SymbolHead),
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub id: u32,
    pub body: SymbolBody,
}

impl PartialEq for Symbol {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Symbol {}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Subtable {
    pub name: String,
    pub scope: u32,
    pub constructors: Vec<Constructor>,
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
pub enum ExprOp {
    Not, Minus,
    Xor, Add, Sub, Lshift, Rshift, Mult, And, Or
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Expr {
    Const(i64),
    Operand(OperandExpr),
    Field(Field),
    Unary((ExprOp, Box<Expr>)),
    Binary((ExprOp, Box<Expr>, Box<Expr>)),
    End,
    Start,
    Next2,
}

#[derive(Debug, Clone, DebugPrint)]
pub struct Constructor {
    pub _parent: u32,
    pub _first: i32,
    pub length: u32,
    pub operands: Vec<u32>,
    pub print_commands: Option<Vec<PrintCommand>>,
    pub context_ops: Vec<ContextOp>,
    pub template: Option<ConstructorTemplate>,
    pub line: (usize, usize),
}

impl PartialEq for Constructor {
    fn eq(&self, other: &Self) -> bool {
        self.line == other.line
    }
}

impl Eq for Constructor {}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PrintCommand {
    Op(u32),
    Piece(String),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ContextOp {
    i: u32,
    shift: u32,
    mask: u32,
    expr: Expr,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConstructorTemplate {
    num_labels: u32,
    statements: Vec<ConsTemplate>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OpTemplate {
    code: String,
    output: Option<VarnodeTemplate>,
    inputs: Vec<VarnodeTemplate>,
}

impl fmt::Display for OpTemplate {
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
pub struct HandleTemplate {
    space_template: ConstTemplate,
    size_template: ConstTemplate,
    pointer_template: VarnodeTemplate,
    temp_space_template: ConstTemplate,
    temp_offset_template: ConstTemplate,
}

impl fmt::Display for HandleTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "*[{}:{}]({})", self.space_template, self.size_template, self.pointer_template)
        // if matches!(self.temp_space_template, ConstTemplate::SpaceId(_)) {
        //     write!(f, "[{}]({})", self.indirect_template, self.varnode_template)
        // } else {
        //     write!(f, "{}", self.varnode_template)
        // }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ConsTemplate {
    Op(OpTemplate),
    Handle(HandleTemplate),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConcreteVarnodeTemplate {
    space: String,
    offset: u64,
    size: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VarnodeTemplate {
    space_template: ConstTemplate,
    offset_template: ConstTemplate,
    size_template: ConstTemplate,
}

impl VarnodeTemplate {
    fn handle_index(&self) -> Option<usize> {
        use ConstTemplate::*;

        match (&self.space_template, &self.offset_template, &self.size_template) {
            (Handle((h1, _)), Handle((h2, _)), Handle((h3, _))) if h1 == h2 && h2 == h3 => Some(*h1 as usize),
            _ => None
        }
    }
}

impl fmt::Display for VarnodeTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ConstTemplate::*;

        match (&self.space_template, &self.offset_template, &self.size_template) {
            (Handle((h1, _)), Handle((h2, _)), Handle((h3, _))) if h1 == h2 && h2 == h3 => {
                write!(f, "Handle#{}", h1)
            },
            _ => {
                write!(f, "{}:{}:{}", self.space_template, self.offset_template, self.size_template)
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum HandleExpr {
    OffsetPlus(u32),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ConstTemplate {
    SpaceId(String),
    Val(u64),
    Handle((u32, Option<HandleExpr>)),
    Relative(u32),
    Start,
    Next,
    CurSpace,
    CurSpaceSize,
}

impl fmt::Display for ConstTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ConstTemplate::*;

        match self {
            SpaceId(space) => write!(f, "{}", space),
            Val(val) => write!(f, "{:x}", val),
            Handle((idx, _)) => write!(f, "Handle#{}", idx),
            _ => write!(f, "{:?}", self)
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Program {
    pub version: u32,
    pub bigendian: bool,
    pub align: u32,
    pub uniqbase: u64,
    pub default_space: String,
    pub spaces: Vec<Space>,
    pub symbols: Vec<Symbol>,
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
            name: attrs[0].1.to_string(),
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

pub fn u32hex(s: &str) -> u32 {
    u32::from_str_radix(&s[2..], 16).unwrap()
}

pub fn u64hex(s: &str) -> u64 {
    u64::from_str_radix(&s[2..], 16).unwrap()
}

pub fn u64dec(s: &str) -> u64 {
    u64::from_str_radix(&s, 10).unwrap()
}

pub fn u32dec(s: &str) -> u32 {
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
                        tag("name"),
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
            name: attrs[0].1.to_string(),
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
    let res = delimited(tag("<oper"), take_until("/>"), tag("/>"))(input).map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        //println!("{} {:?}", res, attrs);
        (next, u32hex(attrs[0].1))
    });

    // if res.is_err() {
    //     panic!("Could not parse operand at {}", input);
    // }
    
    res
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
        (next, PrintCommand::Piece(attrs[0].1.to_string()))
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
    tag("<start_exp/>")(input).map(|(next, _)| (next, (Expr::Start)))
}

fn end_expr(input: &str) -> Res<&str, Expr> {
    tag("<end_exp/>")(input).map(|(next, _)| (next, (Expr::End)))
}

fn next2_expr(input: &str) -> Res<&str, Expr> {
    tag("<next2_exp/>")(input).map(|(next, _)| (next, (Expr::Next2)))
}

fn unary_expr(input: &str) -> Res<&str, Expr> {
    //println!("* unary {}", &input[0..20]);
    let expr_types = alt((
        tag("not_exp"),
        tag("minus_exp"),
        tag("dummy_exp")
    ));

    let (input, (expr_type, hs_expr, _)) = tuple((
        terminated(delimited(char('<'), expr_types, char('>')), line_ending),
        expr,
        preceded(line_ending, delimited(tag("</"), identifier, char('>'))),
    ))(input)?;

    let hs = Box::new(hs_expr);

    let op = match expr_type {
        "not_exp" => ExprOp::Not,
        "minus_exp" => ExprOp::Minus,
        _ => todo!(),
    };

    Ok((input, Expr::Unary((op, hs))))
}

fn binary_expr(input: &str) -> Res<&str, Expr> {
    //println!("* binary {}", &input[0..20]);
    let expr_types = alt((
        tag("plus_exp"),
        tag("sub_exp"),
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

    let op = match expr_type {
        "plus_exp" => ExprOp::Add,
        "sub_exp" => ExprOp::Sub,
        "and_exp" => ExprOp::And,
        "or_exp" => ExprOp::Or,
        "xor_exp" => ExprOp::Xor,
        "lshift_exp" => ExprOp::Lshift,
        "rshift_exp" => ExprOp::Rshift,
        "mult_exp" => ExprOp::Mult,
        _ => todo!(),
    };

    Ok((input, Expr::Binary((op, lhs, rhs))))
}

fn expr(input: &str) -> Res<&str, Expr> {
    //println!("* context expr {}", &input[0..20]);
    let res = alt((
        start_expr,
        end_expr,
        next2_expr,
        const_expr,
        operand_expr,
        field_expr,
        unary_expr,
        binary_expr,
    ))(input);

    // if res.is_err() {
    //     panic!("Could not parse expr at {}", input);
    // }

    res
}

fn context_op(input: &str) -> Res<&str, ContextOp> {
    let res = tuple((
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
    });

    // if res.is_err() {
    //     panic!("Could not parse context op at {}", input);
    // }

    res
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
            "spaceid" => ConstTemplate::SpaceId(attrs[1].1.to_string()),
            "real" => ConstTemplate::Val(u64hex(attrs[1].1)),
            "handle" => {
                let expr = if attrs.len() > 2 && attrs[2].0 == "s" {
                    match attrs[2].1 {
                        "offset_plus" => Some(HandleExpr::OffsetPlus(u32hex(attrs[3].1) & 0xffff)),
                        _ => None,
                    }
                } else {
                    None
                };

                ConstTemplate::Handle((u32dec(attrs[1].1), expr))
            },
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
    tag("<null/>")(input).map(|(next, _)| (next, None))
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
            code: attrs[0].1.to_string(),
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
        let pointer_template = VarnodeTemplate {
            space_template: res.2,
            offset_template: res.3,
            size_template: res.4,
        };

        let handle_template = HandleTemplate {
            space_template: res.0,
            size_template: res.1,
            pointer_template: pointer_template,
            temp_space_template: res.5,
            temp_offset_template: res.6,
        };

        (next, ConsTemplate::Handle(handle_template))
    })
}

fn null_ops(input: &str) -> Res<&str, Vec<ConsTemplate>> {
    tag("<null/>")(input).map(|(next, _)| (next, vec![]))
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
    let res = tuple((
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

        // println!("{}", attrs[3].1);
        let mut iter = attrs[3].1.split(":");

        let constructor = Constructor {
            _parent: u32hex(attrs[0].1),
            _first: i32dec(attrs[1].1),
            length: u32dec(attrs[2].1),
            operands: res.1.0.unwrap_or_default(),
            print_commands: res.1.1,
            context_ops: res.1.2.unwrap_or_default(),
            template: res.1.3,
            line: (u64dec(iter.nth(0).unwrap()) as usize, u64dec(iter.nth(0).unwrap()) as usize),
        };

        // if constructor.line.0 == 0 && constructor.line.1 == 8255 {
        //     println!("{}", &input[..2000]);
        // }

        (next, constructor)
    });

    // if res.is_err() {
    //     panic!("Could not parse constructor at {}", input);
    // }

    res
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
            name: attrs[0].1.to_string(),
            scope: u32hex(attrs[2].1),
            constructors: res.1.0,
            decision_tree: res.1.1,
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
            name: attrs[0].1.to_string(),
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
            name: attrs[0].1.to_string(),
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
            name: attrs[0].1.to_string(),
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
            name: attrs[0].1.to_string(),
            scope: u32hex(attrs[2].1),
            space: AddressSpace::from_str(attrs[3].1),
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
            name: attrs[0].1.to_string(),
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
    tag("<null/>")(input).map(|(next, _)| (next, None))
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
            name: attrs[0].1.to_string(),
            scope: u32hex(attrs[2].1),
            field: res.1.0,
            vars: res.1.1,
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

fn name(input: &str) -> Res<&str, Option<String>> {
    //println!("name {}", &input[0..20]);
    delimited(tag("<nametab"), take_until("/>"), tag("/>"))(input).map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();

        if attrs.len() == 0 {
            (next, None)
        } else {
            let name = attrs[0].1.to_string();
            (next, Some(name))
        }
    })
}

fn name_sym(input: &str) -> Res<&str, Symbol> {
    //println!("varlist {}", &input[0..50]);
    tuple((
        delimited(
            tag("<name_sym "),
            take_until(">"),
            terminated(tag(">"), line_ending),
        ),
        terminated(
            separated_pair(
                field,
                line_ending,
                terminated(separated_list0(line_ending, name), line_ending),
            ),
            tag("</name_sym>"),
        ),
    ))(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res.0).finish().unwrap();
        let id = u32hex(attrs[1].1);
        let nametab = NameTable {
            name: attrs[0].1.to_string(),
            scope: u32hex(attrs[2].1),
            field: res.1.0,
            names: res.1.1,
        };
        (
            next,
            Symbol {
                id: id,
                body: SymbolBody::Nametab(nametab),
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
            name: attrs[0].1.to_string(),
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
            name: attrs[0].1.to_string(),
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
            name: kvs["name"].to_string(),
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
            name: attrs[0].1.to_string(),
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
        name_sym,
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
            default_space: res.2.0.to_string(),
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

fn string(input: &str) -> Res<&str, &str> {
    delimited(char('"'), take_until("\""), char('"'))(input)
}

#[derive(Default, Clone)]
pub struct ResolverDebug {}

fn match_ctx_pattern_block(block: &PatternBlock, words: &Vec<u32>) -> bool {
    let mut word_idx = (block.offset / 4) as usize;
    let byte_idx = block.offset % 4;

    for (_, mask_word) in block.masks.iter().enumerate() {
        let cw = words[word_idx];
        let nw = if word_idx < words.len() - 1 { words[word_idx+1] } else { 0 };
        let word = (cw & (((1_u64 << (32 - (byte_idx * 8))) - 1) as u32)).overflowing_shl(byte_idx * 8).0 | 
                   nw.overflowing_shr(32 - (byte_idx * 8)).0;

        word_idx += 1;

        if (word & mask_word.mask) != mask_word.val {
            return false;
        }
    }
    true
}

fn match_insn_pattern_block(block: &PatternBlock, words: &[u8]) -> bool {
    for (i, mask_word) in block.masks.iter().enumerate() {
        let word = get_word(words, (block.offset as usize) + i * 4, 4) as u32;
        // println!("Matching instruction pattern: {:?}", block);
        if (word & mask_word.mask) != mask_word.val {
            return false;
        }
    }
    true
}

fn match_pattern(pattern: &DecisionPattern, insn_words: &[u8], ctx_words: &Vec<u32>) -> bool {
    // TODO: Maybe use offset for ctx?
    match pattern {
        DecisionPattern::Context(pat_blk) => match_ctx_pattern_block(pat_blk, ctx_words),
        DecisionPattern::Instruction(pat_blk) => match_insn_pattern_block(pat_blk, insn_words),
        DecisionPattern::Combine((pat1, pat2)) => {
            match_pattern(&*pat1, insn_words, ctx_words) && match_pattern(&*pat2, insn_words, ctx_words)
        }
    }
}

#[derive(Debug, Clone)]
pub enum MatchedSymbol<'a> {
    Constructor((&'a Constructor, Vec<(MatchedSymbol<'a>, Option<FixupType>)>)),
    Symbol(&'a Symbol),
    Literal((i64, usize)),
    String(&'a str),
}

impl Hash for MatchedSymbol<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        use MatchedSymbol::*;

        match self {
            Constructor((ct, operands)) => {
                ct.line.hash(state);

                for (op, _) in operands {
                    op.hash(state);
                }
            },
            Symbol(sym) => sym.id.hash(state),
            Literal((val, sz)) => (val, sz).hash(state),
            String(s) => s.hash(state),
        }
    }
}

impl PartialEq for MatchedSymbol<'_> {
    fn eq(&self, other: &Self) -> bool {
        use MatchedSymbol::*;

        match (self, other) {
            (Constructor((ct1, ops1)), Constructor((ct2, ops2))) => {
                if ct1.line != ct2.line {
                    return false;
                }

                for (op1, op2) in ops1.iter().zip(ops2.iter()) {
                    if op1 != op2 {
                        return false;
                    }
                }

                return true;
            },
            (Symbol(sym1), Symbol(sym2)) => sym1.id == sym2.id,
            (Literal((v1, sz1)), Literal((v2, sz2))) => v1 == v2 && sz1 == sz2,
            (String(s1), String(s2)) => s1 == s2,
            _ => false,
        }
    }
}

impl Eq for MatchedSymbol<'_> {}

pub fn read_reg(
    reg: &VarnodeSym,
    reg_space: &BitVec<u8, Msb0>,
) -> Vec<u32> {
    let mut words = vec![];
    let mut size_left = reg.size * 8;

    while size_left > 0 {
        let start = (reg.offset * 8 + (words.len() as u64) * 32) as usize;
        let end = (start + 32) as usize;
        words.push(reg_space[start..end].load_be::<u32>());
        size_left -= size_left.min(32);
    }

    words
}

fn get_word(words: &[u8], start: usize, size: usize) -> u64 {
    let mut word: u64 = 0;

    for i in 0..size {
        if start + i >= words.len() {
            break;
        }

        word = (word << 8) | (words[start + i] as u64);
    }

    word
}

fn get_word_le(words: &[u8], start: usize, size: usize) -> u64 {
    let mut word: u64 = 0;

    for i in 0..size {
        if start + i >= words.len() {
            break;
        }

        word |= (words[start + i] as u64) << (i * 8);
    }

    word
}

fn resolve_constructor<'a>(
    words: &[u8],
    table: &'a Subtable,
    _symbols: &'a HashMap<u32, Symbol>,
    ctx: &mut Vec<u32>,
) -> Option<(&'a Constructor, usize)> {
    let mut dtree = &table.decision_tree;
    let mut bits_consumed = 0;
    let mut path = vec![];

    loop {
        match dtree {
            DecisionTree::NonLeaf((is_context, start, size, children)) => {
                if children.len() == 0 {
                    return None;
                }

                if *size == 0 && children.len() == 1 {
                    dtree = &children[0];
                    continue;
                }

                let bit_start = 32 - (start + size);

                if !is_context {
                    let word = get_word(words, 0, 4) as u32;
                    let idx = ((word >> bit_start) & ((1 << size) - 1)) as usize;
                    path.push(idx);

                    dtree = &children[idx.min(children.len() - 1)];
                    bits_consumed = bits_consumed.max(start + size);
                } else {
                    let ctx_word = ctx[(*start as usize) / 32];
                    let idx = (ctx_word.overflowing_shr(bit_start).0 & ((1 << size) - 1)) as usize;
                    path.push(idx);

                    dtree = &children[idx.min(children.len() - 1)];
                }
            }
            DecisionTree::Leaf(pairs) => {
                for (ct_id, pattern) in pairs {
                    let ct = &table.constructors[*ct_id as usize];
                    // println!("{}:{}", ct.line.0, ct.line.1);

                    if match_pattern(pattern, &words, &ctx) {
                        return Some((ct, (ct.length * 8) as usize));
                    }
                }

                return None;
            }
        };
    }
}

fn resolve_varlist<'a>(
    words: &[u8],
    varlist: &'a Varlist,
    symbols: &'a HashMap<u32, Symbol>,
    _ctx: &mut Vec<u32>,
) -> Option<(MatchedSymbol<'a>, usize)> {
    // println!("{:?}", varlist);
    match &varlist.field {
        Field::Token(token) => {
            let num_bytes = (token.end_byte - token.start_byte + 1) as usize;
            let sb = token.start_byte as usize;
            let mut token_word: u32 = 0;

            for i in 0..num_bytes {
                token_word <<= 8;

                if sb + i < words.len() {
                    token_word |= words[sb + i] as u32;
                } else {
                    token_word |= 0;
                }
            }

            let start = token.start_bit - token.start_byte * 8;
            let size = token.end_bit - token.start_bit + 1;
            let idx = ((token_word >> start) & ((1 << size) - 1)) as usize;

            varlist.vars[idx].map(|var_idx| {
                let var = &symbols[&var_idx];

                // Not super sure if this size calculation is right but it seems to work.
                let bit_end = (token.end_byte * 8 + (8 - (token.end_bit % 8) - 1) + size) as usize;
                ((MatchedSymbol::Symbol(var)), bit_end)
            })
        }
        _ => todo!(),
    }
}

fn resolve_nametab<'a>(
    words: &[u8],
    nametab: &'a NameTable,
    _symbols: &'a HashMap<u32, Symbol>,
    _ctx: &mut Vec<u32>,
) -> Option<(MatchedSymbol<'a>, usize)> {
    match &nametab.field {
        Field::Token(token) => {
            let num_bytes = (token.end_byte - token.start_byte + 1) as usize;
            let sb = token.start_byte as usize;
            let mut token_word: u32 = 0;

            for i in 0..num_bytes {
                token_word <<= 8;
                token_word |= words[sb + i] as u32;
            }

            let start = token.start_bit - token.start_byte * 8;
            let size = token.end_bit - token.start_bit + 1;
            let idx = ((token_word >> start) & ((1 << size) - 1)) as usize;
            let name = nametab.names[idx].as_ref().unwrap();
            let bit_end = (token.end_byte * 8 + (8 - (token.end_bit % 8) - 1) + size) as usize;
            Some((MatchedSymbol::String(name), bit_end))
        }
        _ => todo!(),
    }
}

fn resolve_valuemap<'a>(
    words: &[u8],
    valuemap: &'a Valuemap,
    _symbols: &'a HashMap<u32, Symbol>,
    _ctx: &mut Vec<u32>,
) -> Option<(MatchedSymbol<'a>, usize)> {
    match &valuemap.field {
        Field::Token(token) => {
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
            let literal = MatchedSymbol::Literal((val, size as usize));
            let token_size = (token.end_byte * 8 + (8 - token.end_bit - 1) + size) as usize;
            Some((literal, token_size))
        }
        _ => todo!(),
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum FixupType {
    Start, End,
}

fn evaluate_expr(
    expr: &Expr,
    ctx: &Vec<u32>,
    operands: &Vec<(MatchedSymbol, Option<FixupType>)>,
    reg_space: &BitVec<u8, Msb0>,
) -> (i64, usize, Option<FixupType>) {
    match expr {
        Expr::Const(val) => (*val, 8, None), // FIXME
        Expr::Operand(op_expr) if (op_expr.idx as usize) < operands.len() => {
            let op = &operands[op_expr.idx as usize].0;

            if let MatchedSymbol::Literal((val, sz)) = op {
                let signed_val = match *sz {
                    1 => (*val as i8) as i64,
                    2 => (*val as i16) as i64,
                    4 => (*val as i32) as i64,
                    8 => (*val as i64) as i64,
                    _ => *val,
                };

                (signed_val, *sz, None)
            } else if let MatchedSymbol::Symbol(sym) = op {
                if let SymbolBody::Varnode(_vnode_sym) = &sym.body {
                    // let words = read_reg(vnode_sym, reg_space);
                    // TODO: How to handle SIMD values???
                    println!("doing vnode expr value hack. probably bad");
                    (0, 8, None)
                } else {
                    panic!("{:?}", op);
                }
            } else {
                panic!("{:?}", op);
            }
        },
        Expr::Binary((op, lhs, rhs)) => {
            let (lhs_val, lhs_sz, lhs_fixme) = evaluate_expr(&**lhs, ctx, operands, reg_space);
            let (rhs_val, rhs_sz, rhs_fixme) = evaluate_expr(&**rhs, ctx, operands, reg_space);

            use ExprOp::*;
            let result = match op {
                Xor => lhs_val ^ rhs_val,
                Add => lhs_val + rhs_val,
                Sub => lhs_val - rhs_val,
                Mult => lhs_val * rhs_val,
                And => lhs_val & rhs_val,
                Or => lhs_val | rhs_val,
                Lshift => lhs_val.overflowing_shl(rhs_val as u32).0,
                Rshift => lhs_val >> rhs_val,
                _ => panic!("unknown binary opcode {:?}", op),
            };

            (result, lhs_sz.max(rhs_sz), lhs_fixme.or(rhs_fixme)) // FIXME
        },
        Expr::Unary((op, hs)) => {
            let (val, sz, fixme) = evaluate_expr(&**hs, ctx, operands, reg_space);

            use ExprOp::*;
            let result = match op {
                Not => !val,
                Minus => -val,
                _ => panic!("unknown unary opcode {:?}", op),
            };

            (result, sz, fixme)
        },
        Expr::Field(Field::Context(ctx_field)) => {
            // FIXME: Use BitVec for context. Use end_byte.
            let idx = (ctx_field.start_bit / 32) as usize;
            let ctx_word = ctx[idx];
            let size = ctx_field.end_bit - ctx_field.start_bit + 1;
            let bit_start = 32 - (ctx_field.start_bit + size);
            let rv = ((ctx_word >> bit_start) & ((1 << size) - 1)) as i64;
            (rv, (size / 8) as usize, None)
        },
        Expr::Start => {
            (0, 8, Some(FixupType::Start))
        },
        Expr::End => {
            (0, 8, Some(FixupType::End))
        },
        _ => todo!("{:?}", expr),
    }
}

fn resolve_operands<'a>(
    words: &[u8],
    pc: u64,
    ct: &'a Constructor,
    symbols: &'a HashMap<u32, Symbol>,
    ctx: &mut Vec<u32>,
    reg_space: &BitVec<u8, Msb0>,
) -> (Vec<(MatchedSymbol<'a>, Option<FixupType>)>, usize, bool) {
    let mut matched_ops = vec![];
    let mut bit_end: usize = 0;
    let mut total_bit_end: usize = 0;
    let mut ok = true;

    for op_idx in &ct.operands {
        let operand = get_operand(&op_idx, &symbols);

        match &operand.expr {
            Some(Expr::Field(Field::Token(expr))) => {
                // TODO: Handle shift field.
                let size = expr.end_bit - expr.start_bit + 1;
                let num_bytes = (expr.end_byte - expr.start_byte + 1) as usize;

                // TODO: Figure out if this is right. I'm just guessing.
                let word = if !expr.big_endian {
                    get_word_le(words, bit_end / 8 + expr.start_byte as usize, num_bytes)
                } else {
                    get_word(words, bit_end / 8 + expr.start_byte as usize, num_bytes)
                };

                let mask = 0xffffffffffffffff_u64 >> ((8 - num_bytes) * 8);
                let val = ((word >> expr.start_bit) & mask) as i64;

                matched_ops.push((MatchedSymbol::Literal((val, num_bytes)), None));
                let byte_start = (bit_end + (expr.start_byte as usize)) / 8; // FIXME
                bit_end = bit_end.max(byte_start * 8);
                total_bit_end = total_bit_end.max(byte_start * 8 + size as usize);
            },
            Some(Expr::Field(Field::Context(expr))) => {
                let size = expr.end_bit - expr.start_bit + 1;
                let bit_start = 32 - (expr.start_bit + size);
                let val = (ctx[(expr.start_bit / 32) as usize] >> bit_start) & ((1 << size) - 1);
                let num_bytes = (expr.end_byte - expr.start_byte + 1) as usize;
                matched_ops.push((MatchedSymbol::Literal((val as i64, num_bytes)), None));
            },
            Some(Expr::Unary(_) | Expr::Binary(_)) => {
                let (val, sz, fixup_type) = evaluate_expr(operand.expr.as_ref().unwrap(), ctx, &matched_ops, reg_space);
                matched_ops.push((MatchedSymbol::Literal((val, sz)), fixup_type));
            },
            Some(Expr::Const(val)) => {
                // TODO: Fix size.
                matched_ops.push((MatchedSymbol::Literal((*val, 8)), None));
            }
            None => {
                let op_sym = &symbols[&operand.subsym];

                // TODO: Figure out if thise guess is right.
                let base = if operand.base == -1 {
                    operand.off as usize
                } else {
                    bit_end / 8
                };

                // Before recursively resolving a symbol, we first need to modify the context.
                for op in &ct.context_ops {
                    let existing = ctx[op.i as usize];
                    let mask = op.mask;

                    let (val, _, _) = evaluate_expr(&op.expr, ctx, &matched_ops, reg_space);
                    let v = (val as u32) << op.shift;
                    ctx[op.i as usize] = (existing & !mask) | (v & mask);
                }

                match _resolve_symbol(&words[base..], pc + base as u64, op_sym, symbols, ctx, reg_space) {
                    Some((matched_sym, sub_bit_end)) => {
                        let new_bit_end = bit_end.max((base * 8) as usize + sub_bit_end);
                        matched_ops.push((matched_sym, None));
                        total_bit_end = new_bit_end;

                        if operand.base == -1 {
                            bit_end = total_bit_end;
                        }
                    },
                    None => ok = false,
                };
            },
            _ => todo!("{:?}", operand.expr)
        }
    }

    (matched_ops, bit_end.max(total_bit_end), ok)
}

pub fn _resolve_symbol<'a>(
    words: &[u8],
    pc: u64,
    sym: &'a Symbol,
    symbols: &'a HashMap<u32, Symbol>,
    ctx: &mut Vec<u32>,
    reg_space: &BitVec<u8, Msb0>,
) -> Option<(MatchedSymbol<'a>, usize)> {
    // println!("{:?}", words);
    match &sym.body {
        SymbolBody::Subtable(table) => {
            match resolve_constructor(words, table, symbols, ctx) {
                Some((ct, bit_end)) => {
                    let (operands, ops_bit_end, ok) = resolve_operands(words, pc, ct, symbols, ctx, reg_space);
                    let bit_len = bit_end.max(ops_bit_end);

                    if ok {
                        Some((MatchedSymbol::Constructor((ct, operands)), bit_len))
                    } else {
                        None
                    }
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
        SymbolBody::Varnode(_) => {
            Some((MatchedSymbol::Symbol(sym), 0))
        },
        SymbolBody::Nametab(nametab) => {
            resolve_nametab(words, nametab, symbols, ctx)
        },
        _ => todo!("{:?}", sym.body),
    }
}

fn apply_fixups(matched_sym: &mut MatchedSymbol, fixup_type: &Option<FixupType>, pc: u64, bit_len: usize) {
    match matched_sym {
        MatchedSymbol::Constructor((_, operands)) => {
            for (oper, t) in operands.iter_mut() {
                apply_fixups(oper, t, pc, bit_len);
            }
        },
        MatchedSymbol::Literal((val, _)) => {
            *val = match fixup_type {
                Some(FixupType::Start) => *val + pc as i64,
                Some(FixupType::End) => *val + (pc as usize + bit_len / 8) as i64,
                _ => *val,
            };
        },
        _ => (),
    }
}

pub fn resolve_symbol<'a>(
    words: &[u8],
    pc: u64,
    sym: &'a Symbol,
    symbols: &'a HashMap<u32, Symbol>,
    ctx: &mut Vec<u32>,
    reg_space: &BitVec<u8, Msb0>,
) -> Option<(MatchedSymbol<'a>, usize)> {
    if let Some((mut matched_sym, bit_len)) = _resolve_symbol(words, pc, sym, symbols, ctx, reg_space) {
        apply_fixups(&mut matched_sym, &None, pc, bit_len);
        Some((matched_sym, bit_len))
    } else {
        None
    }
}

fn get_operand<'a>(id: &u32, symbols: &'a HashMap<u32, Symbol>) -> &'a Operand {
    let sym = &symbols[id];
    match &sym.body {
        SymbolBody::Operand(operand) => operand,
        _ => panic!(),
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum VarnodeValue<'a> {
    Space(AddressSpace),
    String(&'a String),
    Int(u64),
    Rel(u64),
    Op(Cow<'a, Varnode>),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Handle {
    space: AddressSpace,
    pointer: Varnode,
    temp: Varnode,
}

impl Handle {
    fn needs_resolving(&self) -> bool {
        self.temp.space != AddressSpace::Dummy
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.needs_resolving() {
            write!(f, "{}", self.pointer)
        } else {
            write!(f, "*({}){}", self.temp, self.pointer)
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PcodeObject {
    Dummy,
    Varnode(Varnode),
    Handle(Handle),
}

impl fmt::Display for PcodeObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PcodeObject::Dummy => write!(f, "DUMMY"),
            PcodeObject::Varnode(vn) => write!(f, "{}", vn),
            PcodeObject::Handle(h) => write!(f, "{}", h),
        }
    }
}

pub struct BuildContext<'a> {
    pc: &'a Address,
    bit_len: usize,
    lang: &'a SleighLanguage,
}

fn build_value<'a>(
    const_tpl: &'a ConstTemplate,
    objs: &'a [PcodeObject],
    ctx: &BuildContext,
) -> (VarnodeValue<'a>, Option<FixupType>) {
    match const_tpl {
        ConstTemplate::SpaceId(space) => (VarnodeValue::String(space), None),
        ConstTemplate::Val(val) => (VarnodeValue::Int(*val), None),
        ConstTemplate::Handle((idx, expr)) => {
            let ix = *idx as usize;

            let mut vn: Cow<'a, Varnode> = Cow::Borrowed(match &objs[ix] {
                PcodeObject::Varnode(vn) => vn,
                PcodeObject::Handle(h) if h.needs_resolving() => &h.temp,
                PcodeObject::Handle(h) => &h.pointer,
                _ => panic!("{}", objs[ix])
            });

            match expr {
                Some(HandleExpr::OffsetPlus(addend)) => vn = Cow::Owned(vn.subpiece(*addend as u64, vn.size, &ctx.lang.varnode_map)),
                _ => ()
            };

            (VarnodeValue::Op(vn), None)
        },
        // For now just use the const index for intra-pcode branching.
        // I think this is right but we'll see.
        ConstTemplate::Relative(idx) => (VarnodeValue::Rel(*idx as u64), None),
        ConstTemplate::Start => (VarnodeValue::Int(ctx.pc.offset), Some(FixupType::Start)),
        ConstTemplate::Next => (VarnodeValue::Int(ctx.pc.offset + (ctx.bit_len / 8) as u64), Some(FixupType::End)),
        ConstTemplate::CurSpace => (VarnodeValue::Space(AddressSpace::Ram), None), // FIXME
        ConstTemplate::CurSpaceSize => (VarnodeValue::Int(8), None), // FIXME
    }
}

fn build_offset<'a>(
    const_tpl: &'a ConstTemplate,
    objs: &'a [PcodeObject],
    ctx: &BuildContext,
) -> (u64, Option<FixupType>) {
    let (val, ft) = build_value(const_tpl, objs, ctx);
    match &val {
        VarnodeValue::Int(sz) => (*sz, ft),
        VarnodeValue::Op(op) => (op.offset, ft),
        VarnodeValue::Space(_) => (8, ft), // FIXME
        VarnodeValue::String(s) => (ctx.lang.spaces[s.as_str()], ft),
        VarnodeValue::Rel(ix) => (*ix, ft),
    }
}

fn build_size<'a>(
    const_tpl: &'a ConstTemplate,
    objs: &'a [PcodeObject],
    ctx: &BuildContext,
) -> (u64, Option<FixupType>) {
    let (val, ft) = build_value(const_tpl, objs, ctx);
    match &val {
        VarnodeValue::Int(sz) => (*sz, ft),
        VarnodeValue::Op(op) => (op.size, ft),
        VarnodeValue::Space(_) => (8, ft), // FIXME
        VarnodeValue::String(s) => (ctx.lang.spaces[s.as_str()], ft),
        _ => panic!("Unknown varnode value type for int {:?}", val),
    }
}

fn build_space<'a>(
    const_tpl: &'a ConstTemplate,
    objs: &'a [PcodeObject],
    ctx: &BuildContext,
) -> (AddressSpace, Option<FixupType>) {
    match build_value(const_tpl, objs, ctx) {
        (VarnodeValue::String(s), ft) => (AddressSpace::from_str(s.as_str()), ft),
        (VarnodeValue::Space(spc), ft) => (spc, ft),
        (VarnodeValue::Op(op), ft) => (op.space, ft),
        (VarnodeValue::Int(0), ft) => (AddressSpace::Dummy, ft),
        _ => panic!(),
    }
}

fn sign_extend(val: u64, from: u64, to: u64) -> u64 {
    let mut result = val;

    let shift = 64 - from * 8;
    result = (((result << shift) as i64) >> shift) as u64;

    let shift = 64 - to * 8;
    result = (result << shift) >> shift;

    result
}

fn build_handle<'a>(
    handle_tpl: &'a HandleTemplate,
    objs: &'a [PcodeObject],
    ctx: &BuildContext,
) -> PcodeObject {
    let deref_space = build_space(&handle_tpl.space_template, objs, ctx).0;
    let deref_size = build_size(&handle_tpl.size_template, objs, ctx).0;
    let pointer = build_varnode(&handle_tpl.pointer_template, objs, ctx);
    let temp_space = build_space(&handle_tpl.temp_space_template, objs, ctx).0;
    let temp_offset = build_offset(&handle_tpl.temp_offset_template, objs, ctx).0;

    let temp = Varnode {
        name: None,
        space: temp_space,
        offset: temp_offset,
        size: deref_size,
    };

    // println!("Handle: {}\n  ({:?}, {:?}, {}, {:?}, {:?})\n", handle_tpl, deref_space, deref_size, pointer, temp_space, temp_offset);

    if deref_space == AddressSpace::Ram && pointer.space == AddressSpace::Const {// && pointer.size == 0 {
        PcodeObject::Varnode(Varnode {
            name: pointer.name.clone(),
            space: deref_space,
            offset: pointer.offset,
            size: pointer.size,
        })
    } else if !temp.space.is_dummy() && deref_space != AddressSpace::Const {
        PcodeObject::Handle(Handle {
            space: deref_space,
            pointer: pointer,
            temp: temp,
        })
    } else if deref_space == AddressSpace::Const {
        let mut offset = pointer.offset;

        if deref_size > 0 && pointer.size > 0 {
            offset = sign_extend(offset, pointer.size, deref_size);
        }

        PcodeObject::Varnode(Varnode {
            name: None,
            space: deref_space,
            offset: offset,
            size: deref_size.max(pointer.size),
        })
    } else if deref_space != AddressSpace::Dummy {
        let name = ctx.lang.varnode_map.get(&(pointer.offset, deref_size)).cloned();

        PcodeObject::Varnode(Varnode {
            name: name,
            space: deref_space,
            offset: pointer.offset,
            size: deref_size,
        })
    } else {
        PcodeObject::Varnode(pointer.clone())
    }
}

fn build_varnode<'a>(
    vnode_tpl: &'a VarnodeTemplate,
    objs: &'a [PcodeObject],
    ctx: &BuildContext,
) -> Varnode {
    use ConstTemplate::*;

    let mut fixup_type = None;

    match (&vnode_tpl.space_template, &vnode_tpl.offset_template, &vnode_tpl.size_template) {
        (Val(0), Handle((ix, _)), Val(0)) => {
            match &objs[*ix as usize] {
                PcodeObject::Varnode(vn) => vn.clone(),
                PcodeObject::Handle(h) => h.pointer.clone(), // FIXME
                _ => panic!(),
            }
        },
        (Handle((ix, _)), Handle((ix2, _)), Val(0)) if ix == ix2 => {
            match &objs[*ix as usize] {
                PcodeObject::Varnode(vn) => vn.clone(),
                PcodeObject::Handle(h) => h.pointer.clone(), // FIXME
                _ => panic!(),
            }
        },
        _ => {
            let (space, ft) = build_space(&vnode_tpl.space_template, objs, ctx);
            fixup_type = fixup_type.or(ft);

            let (mut offset, ft) = build_offset(&vnode_tpl.offset_template, objs, ctx);
            fixup_type = fixup_type.or(ft);

            let (size, ft) = build_size(&vnode_tpl.size_template, objs, ctx);
            fixup_type = fixup_type.or(ft);

            let name = match space {
                AddressSpace::Register => ctx.lang.varnode_map.get(&(offset, size)).map(|x| x.clone()),
                _ => match fixup_type {
                    Some(FixupType::Start) => Some(local_str!("fixup_start")),
                    Some(FixupType::End) => Some(local_str!("fixup_end")),
                    _ => None,
                },
            };

            // Need to sign-extend.
            if space == AddressSpace::Const {
                if let (Handle((ix, _)), Handle((ix2, _))) = (&vnode_tpl.space_template, &vnode_tpl.offset_template) {
                    if ix == ix2 {
                        if let PcodeObject::Varnode(vn) = &objs[*ix as usize] {
                            offset = sign_extend(offset, vn.size, size);
                        }
                    }
                }
            }

            // println!("{}\n  {:?}\n  ({}, {:x}, {})\n", vnode_tpl, objs, space, offset, size);

            Varnode {
                name: name,
                space: space.to_owned(),
                offset: offset,
                size: size,
            }
        }
    }
}

fn fix_sizes(opcode: &mut OpCode, inputs: &mut Vec<Varnode>, output: &mut Option<Varnode>, ctx: &BuildContext) {
    // TODO: Add more cases.
    // println!("{} {:?}", opcode, inputs);
    if *opcode == OpCode::IntAdd {
        if inputs[1].is_negative() {
            *opcode = OpCode::IntSub;
            inputs[1] = inputs[1].negate();
        } else if inputs[0].is_negative() {
            *opcode = OpCode::IntSub;
            let c = inputs[0].clone();
            inputs[0] = inputs[1].clone();
            inputs[1] = c.negate();
        }
    } else if *opcode == OpCode::IntSub {
        if inputs[1].is_negative() {
            *opcode = OpCode::IntAdd;
            inputs[1] = inputs[1].negate();
        } 
    }

    // println!("{} {:?}", opcode, inputs);

    if !matches!(*opcode, OpCode::Store | OpCode::Call | OpCode::CallInd | OpCode::CallOther | OpCode::SubPiece) {
        let output_size = output.as_ref().map(|o| o.size).unwrap_or(0);

        // let mut max_sz = inputs.iter().map(|i| i.size).max().unwrap();
        let mut sz = 0;

        for input in inputs.iter() {
            if input.space == AddressSpace::Register {
                sz = input.size;
                break;
            }
        }

        if sz == 0 {
            // TODO: Cleanup.
            // sz = inputs.iter().map(|i| i.size).max().unwrap();

            for (i, input) in inputs.iter().enumerate() {
                if !(matches!(*opcode, OpCode::IntLeft | OpCode::IntRight | OpCode::IntSRight) && i == 1) {
                    sz = sz.max(input.size);
                }
            }
        }

        if !matches!(*opcode, OpCode::Load | OpCode::IntSext | OpCode::IntZext | OpCode::FloatInt2Float) && !opcode.is_conditional() {
            // max_sz = max_sz.max(output_size);
            if output.as_ref().map(|o| o.space == AddressSpace::Register).unwrap_or(false) {
                sz = output_size;
            }

            if sz == 0 || *opcode == OpCode::Copy {
                sz = sz.max(output_size);
            }
        }

        for i in 0..inputs.len() {
            let input = &mut inputs[i];

            if input.space != AddressSpace::Register && !(i == 1 && *opcode == OpCode::SubPiece) && 
               !(i == 0 && *opcode == OpCode::CBranch) && 
                !(i == 1 && matches!(*opcode, OpCode::IntLeft | OpCode::IntRight | OpCode::IntSRight)) {
                if input.space == AddressSpace::Const && input.size > 0 && input.size <= 8 && *opcode != OpCode::IntSub && *opcode != OpCode::IntAdd {
                    let shift = 64 - input.size * 8;
                    input.offset = (((input.offset << shift) as i64) >> shift) as u64;

                    let shift = 64 - sz * 8;
                    input.offset = input.offset.overflowing_shl(shift as u32).0.overflowing_shr(shift as u32).0;
                }

                input.size = sz;
            }
        }

        if matches!(*opcode, OpCode::IntAdd | OpCode::IntSub | OpCode::IntMult | OpCode::IntDiv | OpCode::Copy) {
            output.as_mut().unwrap().size = sz;
        }

        if *opcode == OpCode::CBranch && inputs[1].size > 1 {
            inputs[1].size = 1;
        }

        if *opcode == OpCode::SubPiece && output_size > inputs[1].size {
            *output = Some(output.as_ref().unwrap().subpiece(0, inputs[1].size, &ctx.lang.varnode_map));
        }
    } else if *opcode == OpCode::Store {
        inputs[1].size = 8; // FIXME
    }

    // HACK, FIXME
    if *opcode == OpCode::Load {
        inputs[1].size = 8;
    }
}

fn build_pcodeop<'a>(
    mut seq: SeqNum,
    op_tpl: &'a OpTemplate,
    objs: &'a [PcodeObject],
    ops: &mut Vec<PcodeOp>,
    ctx: &BuildContext,
) {
    let mut opcode = OpCode::from_str(op_tpl.code.as_str());

    let mut input_iter = op_tpl.inputs.iter();

    if opcode == OpCode::Return {
        let _ = input_iter.next();
    }

    let mut inputs = vec![];

    for tpl in input_iter {
        if let Some(idx) = tpl.handle_index() {
            let obj = &objs[idx];

            match obj {
                PcodeObject::Varnode(vn) => inputs.push(vn.clone()),
                PcodeObject::Handle(h) => {
                    if !h.temp.space.is_dummy() {
                        let load_inputs = vec![Varnode::dummy(), h.pointer.clone()];
                        ops.push(PcodeOp::new(seq.clone(), OpCode::Load, load_inputs, Some(h.temp.clone())));

                        seq = seq.next();
                        inputs.push(h.temp.clone());
                    } else {
                        inputs.push(h.pointer.clone());
                    }
                },
                _ => panic!("unexpected dummy varnode at 0x{:x}", ctx.pc.offset),
            };
        } else {
            let vn = build_varnode(tpl, objs, ctx);
            inputs.push(vn);
        }
    }

    let mut output = None;

    if let Some(tpl) = &op_tpl.output {
        if let Some(idx) = tpl.handle_index() {
            let obj = &objs[idx];

            match obj {
                PcodeObject::Varnode(vn) => output = Some(vn.clone()),
                PcodeObject::Handle(h) => {
                    if !h.temp.space.is_dummy() {
                        let mut output = Some(h.temp.clone());
                        fix_sizes(&mut opcode, &mut inputs, &mut output, ctx);
                        ops.push(PcodeOp::new(seq.clone(), opcode, inputs.clone(), output));

                        seq = seq.next();
                        opcode = OpCode::Store;
                        inputs = vec![Varnode::dummy(), h.pointer.clone(), h.temp.clone()];
                    } else {
                        output = Some(h.pointer.clone());
                    }
                },
                _ => panic!(),
            };
        } else {
            let vn = build_varnode(tpl, objs, ctx);
            output = Some(vn);
        }
    }

    // println!("{} {:?} {:?}", opcode, inputs, output);
    fix_sizes(&mut opcode, &mut inputs, &mut output, ctx);

    let op = PcodeOp {
        seq: seq,
        opcode: opcode,
        inputs: inputs,
        output: output,
    };

    ops.push(op);
}

pub fn _build_sym<'a>(
    matched_sym: &'a MatchedSymbol,
    built_pcodeops: &mut Vec<PcodeOp>,
    built_objects: &mut Vec<PcodeObject>,
    order: &mut Vec<usize>,
    ctx: &BuildContext,
) -> (Option<PcodeObject>, usize, usize) {
    let mut sub_op_ranges = vec![];

    let start_op_idx = built_pcodeops.len();
    let start_obj_idx = built_objects.len();
    let mut handle = None;

    let mut built_op = false;
    let mut ops_start = 0;
    let mut num_ops = 0;

    if let MatchedSymbol::Constructor((ct, operands)) = &matched_sym {
        for (_i, (op, fixup_type)) in operands.iter().enumerate() {
            let mut op_handle = None;
            let mut sub_op_start = 0;
            let mut sub_op_size = 0;

            if let MatchedSymbol::Symbol(sym) = op {
                if let SymbolBody::Varnode(vnode) = &sym.body {
                    let name = match vnode.space {
                        AddressSpace::Register => ctx.lang.varnode_map.get(&(vnode.offset, vnode.size)),
                        _ => None,
                    };

                    let varnode = PcodeObject::Varnode(Varnode {
                        name: name.map(|x| x.clone()),
                        space: vnode.space.to_owned(),
                        offset: vnode.offset,
                        size: vnode.size,
                    });

                    op_handle = Some(varnode);
                }
            }
            else if let MatchedSymbol::Literal((val, size)) = op {
                // NOTE: We're using the name as out-of-band data so that the build cache can re-fixup varnodes. Very hacky.
                let name = match fixup_type {
                    Some(FixupType::Start) => Some(local_str!("fixup_start")),
                    Some(FixupType::End) => Some(local_str!("fixup_end")),
                    _ => None,
                };

                let varnode = PcodeObject::Varnode(Varnode {
                    name: name,
                    space: AddressSpace::Const.to_owned(),
                    offset: *val as u64,
                    size: *size as u64,
                });

                op_handle = Some(varnode);
            } else if let MatchedSymbol::Constructor(_) = op {
                let sub_obj_start = built_objects.len();
                (op_handle, sub_op_start, sub_op_size) = _build_sym(op, built_pcodeops, built_objects, order, ctx);
                built_objects.drain(sub_obj_start..built_objects.len());
            }

            sub_op_ranges.push((sub_op_start, sub_op_size));

            if let Some(handle) = op_handle {
                built_objects.push(handle);
            } else {
                // NOTE: We need a dummy handle for the operand indices to line up??
                built_objects.push(PcodeObject::Dummy);
            }
        }

        let template = ct.template.as_ref().unwrap();

        for stmt in &template.statements {
            if let ConsTemplate::Op(op_template) = stmt {
                if !built_op {
                    ops_start = order.len();
                    built_op = true;
                }

                if op_template.code == "BUILD" {
                    if let ConstTemplate::Val(op_idx) = op_template.inputs[0].offset_template {
                        let idx = op_idx as usize;
                        let (start, sz) = sub_op_ranges[idx];

                        for i in start..(start + sz) {
                            order.push(order[i]);
                        }

                        num_ops += sz;
                    };
                } else {
                    let start = built_pcodeops.len();

                    let seq = SeqNum {
                        pc: ctx.pc.clone(),
                        uniq: (start_op_idx + num_ops) as i32,
                        order: 0,
                    };

                    build_pcodeop(
                        seq,
                        &op_template,
                        &built_objects[start_obj_idx..],
                        built_pcodeops,
                        ctx,
                    );

                    let end = built_pcodeops.len();

                    for i in start..end {
                        order.push(i);
                    }

                    num_ops += end - start;
                } 
            }
        }

        // Handle the varnodes after all the operands have been built.
        for stmt in &template.statements {
            if let ConsTemplate::Handle(handle_template) = stmt {
                let objs = &built_objects[start_obj_idx..];
                let my_handle = build_handle(&handle_template, objs, ctx);
                handle = Some(my_handle);
            }
        }
    }

    (handle, ops_start, num_ops)
}

fn sort_by_indices<T>(data: &mut [T], mut indices: Vec<usize>) {
    for idx in 0..data.len() {
        if indices[idx] != idx {
            let mut current_idx = idx;
            loop {
                let target_idx = indices[current_idx];
                indices[current_idx] = current_idx;
                if indices[target_idx] == target_idx {
                    break;
                }
                data.swap(current_idx, target_idx);
                current_idx = target_idx;
            }
        }
    }
}

pub fn build_sym<'a>(
    matched_sym: &'a MatchedSymbol,
    pc: &Address,
    bit_len: usize,
    lang: &'a SleighLanguage,
) -> Vec<PcodeOp> {
    let ctx = BuildContext {
        lang: lang,
        pc: pc,
        bit_len: bit_len,
    };

    let mut ops = vec![];
    let mut objs = vec![];
    let mut order = vec![];

    let (_, ops_start, num_ops) = _build_sym(matched_sym, &mut ops, &mut objs, &mut order, &ctx);

    let _ = order.drain(0..ops_start);
    order.truncate(num_ops);

    sort_by_indices(&mut ops, order);

    while let Some(op) = ops.last().as_ref() {
        if op.opcode == OpCode::Load && op.output.as_ref().unwrap().space == AddressSpace::Unique {
            let _ = ops.pop();
        } else {
            break;
        }
    }

    let mut labels: HashMap<SeqNum, u64> = HashMap::default();
    let mut label_idxs: HashMap<u64, usize> = HashMap::default();

    for (i, op) in ops.iter().enumerate() {
        if op.opcode == OpCode::Label {
            let seq = if i + 1 < ops.len() {
                ops[i + 1].seq.clone()
            } else {
                ops[ops.len() - 1].seq.next() // FIXME
            };

            labels.insert(seq, op.inputs[0].offset);
        }
    }

    ops.retain(|op| op.opcode != OpCode::Label);

    for (i, op) in ops.iter().enumerate() {
        if let Some(lbl_idx) = labels.get(&op.seq) {
            label_idxs.insert(*lbl_idx, i);
        }
    }

    let n = ops.len();

    for (i, op) in ops.iter_mut().enumerate() {
        if (op.opcode == OpCode::Branch || op.opcode == OpCode::CBranch) && op.inputs[0].space == AddressSpace::Const {
            let idx = op.inputs[0].offset;
            let lbl_idx = label_idxs.get(&idx).copied().unwrap_or(n);
            op.inputs[0].offset = ((lbl_idx as i64 - i as i64) as u32) as u64;
        }
    }

    ops
}

fn _build_cmd_text(cmd: &PrintCommand, operands: &Vec<(MatchedSymbol, Option<FixupType>)>, text: &mut String, ops: &[PcodeOp]) {
    match cmd {
        PrintCommand::Op(op_idx) => _build_text(&operands[*op_idx as usize].0, text, ops),
        PrintCommand::Piece(piece) => text.push_str(piece),
    }
}

pub fn _build_text(matched_sym: &MatchedSymbol, text: &mut String, ops: &[PcodeOp]) {
    match &matched_sym {
        MatchedSymbol::Constructor((ct, operands)) => {
            if let Some(cmds) = &ct.print_commands {
                for cmd in cmds {
                    _build_cmd_text(cmd, &operands, text, ops);
                }
            }
        },
        MatchedSymbol::Symbol(sym) => {
            if let SymbolBody::Varnode(vnode) = &sym.body {
                text.push_str(&vnode.name);
            }
        },
        MatchedSymbol::Literal((val, sz)) => {
            let mut v = *val as u64;
            let mut sign_str = "";

            let (neg_v, is_neg) = match sz {
                1 if (*val >> 7) != 0 => ((*val ^ 0xff) as u64 + 1, true),
                2 if (*val >> 15) != 0 => ((*val ^ 0xffff) as u64 + 1, true),
                4 if (*val >> 31) != 0 => ((*val ^ 0xffffffff) as u64 + 1, true),
                8 if (*val >> 63) != 0 => ((*val ^ 0xffffffffffffffffu64 as i64) as u64 + 1, true),
                _ => (*val as u64, false),
            };

            let shift = 64 - (*sz as usize) * 8;
            let sext_v = (((v << shift) as i64) >> shift) as u64;

            for op in ops {
                if matches!(op.opcode, OpCode::IntSub) && op.inputs[1].space == AddressSpace::Const && op.inputs[1].offset > 0 && op.inputs[1].offset == neg_v && is_neg {
                    v = neg_v;
                    sign_str = "-";
                    break;
                } else if matches!(op.opcode, OpCode::IntSBorrow) && op.inputs[1].space == AddressSpace::Const && op.inputs[1].offset > 0 && is_neg {
                    if op.inputs[1].offset == (sext_v >> (64 - op.inputs[1].size * 8)) {
                        v = neg_v;
                        sign_str = "-";
                        break;
                    }
                }
            }

            if *sz == 8 && is_neg {
                v = neg_v;
                sign_str = "-";
            }

            text.push_str(format!("{}0x{:x}", sign_str, v).as_str());
        },
        MatchedSymbol::String(s) => {
            text.push_str(&s);
        }
    }
}

pub fn build_text(matched_sym: &MatchedSymbol, ops: &[PcodeOp]) -> String {
    let mut text = String::new();
    _build_text(matched_sym, &mut text, ops);
    text
}

pub struct SleighLanguage {
    pub language: Language,
    pub bit_align: usize,
    pub symbols: HashMap<u32, Symbol>,
    pub spaces: HashMap<String, u64>,
    pub _varnodes: HashMap<String, VarnodeSym>,
    pub varnode_map: HashMap<(u64, u64), LocalStr>,
    pub context_syms: HashMap<String, Context>,
    pub reg_space_size: usize,
    pub insn_table_id: u32,
    pub context_reg: VarnodeSym,
}

impl SleighLanguage {
    pub fn create<'a>(lang_id: &str) -> SleighLanguage {
        let arch_family = lang_id.split(":").next().unwrap();
        let (lang, sla_contents) = get_language(arch_family, lang_id).unwrap();
        let (_, sla) = program(&sla_contents).finish().unwrap();

        let mut symbols: HashMap<u32, Symbol> = HashMap::new();
        let mut spaces: HashMap<String, u64> = HashMap::new();
        let mut varnodes: HashMap<String, VarnodeSym> = HashMap::new();
        let mut varnode_map: HashMap<(u64, u64), LocalStr> = HashMap::new();
        let mut context_syms: HashMap<String, Context> = HashMap::new();
        let mut reg_space_size: usize = 0;
        let mut insn_table_id = 0;

        for space in &sla.spaces {
            spaces.insert(space.name.clone(), spaces.len() as u64);
        }

        for sym in &sla.symbols {
            match &sym.body {
                SymbolBody::Subtable(subtable) => {
                    if subtable.name == "instruction" {
                        insn_table_id = sym.id;
                    }
                }
                SymbolBody::Varnode(varnode) => {
                    varnodes.insert(varnode.name.clone(), varnode.clone());

                    if varnode.space == AddressSpace::Register {
                        reg_space_size =
                            reg_space_size.max((varnode.offset + varnode.size) as usize);
                        varnode_map.insert((varnode.offset, varnode.size), varnode.name.to_local_str());
                    }
                }
                SymbolBody::Context(ctx) => {
                    context_syms.insert(ctx.name.clone(), ctx.clone());
                }
                _ => (),
            }

            symbols.insert(sym.id, sym.clone());
        }

        let ctx_reg = varnodes["contextreg"].clone();

        SleighLanguage {
            language: lang,
            bit_align: (sla.align * 8) as usize,
            symbols: symbols,
            spaces: spaces,
            _varnodes: varnodes,
            varnode_map: varnode_map,
            context_syms: context_syms,
            reg_space_size: reg_space_size,
            insn_table_id: insn_table_id,
            context_reg: ctx_reg,
        }
    }
}
