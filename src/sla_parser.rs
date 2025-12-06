use crate::arch::{get_sla, get_language};
use crate::sleigh::types::*;

extern crate bitvec;
extern crate nom;

use super::arch::Language;

use nom::branch::*;
use nom::bytes::complete::*;
use nom::character::complete::*;
use nom::combinator::*;
use nom::error::*;
use nom::multi::*;
use nom::sequence::*;
use nom::*;

use flexstr::{LocalStr, ToLocalStr};

use bitvec::prelude::*;

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::fmt;

pub type Res<T, U> = IResult<T, U, Error<T>>;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MaskWord {
    pub mask: u32,
    pub val: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PatternBlock {
    pub offset: u32,
    pub nonzero: u32,
    pub masks: Vec<MaskWord>,
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
    pub name: String,
    pub scope: u32,
    pub field: Field,
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
    pub name: String,
    pub scope: u32,
    pub field: Field,
    pub names: Vec<Option<String>>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Valuemap {
    pub name: String,
    pub scope: u32,
    pub field: Field,
    pub vars: Vec<u64>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Operand {
    pub name: String,
    pub scope: u32,
    pub subsym: u32,
    pub off: u64,
    pub base: i64,
    pub min_len: u64,
    pub idx: u64,
    pub is_code: bool,
    pub operand_expr: OperandExpr,
    pub expr: Option<Expr>,
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
    pub sign_bit: bool,
    pub start_bit: u32,
    pub end_bit: u32,
    pub start_byte: u32,
    pub end_byte: u32,
    pub shift: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TokenField {
    pub big_endian: bool,
    pub sign_bit: bool,
    pub start_bit: u32,
    pub end_bit: u32,
    pub start_byte: u32,
    pub end_byte: u32,
    pub shift: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Field {
    Context(ContextField),
    Token(TokenField),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OperandExpr {
    pub idx: u32,
    pub table: u32,
    pub ct: u32,
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

#[derive(Debug, Clone)]
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
    pub i: u32,
    pub shift: u32,
    pub mask: u32,
    pub expr: Expr,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConstructorTemplate {
    pub num_labels: u32,
    pub statements: Vec<ConsTemplate>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OpTemplate {
    pub code: String,
    pub output: Option<VarnodeTemplate>,
    pub inputs: Vec<VarnodeTemplate>,
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
    pub space_template: ConstTemplate,
    pub size_template: ConstTemplate,
    pub pointer_template: VarnodeTemplate,
    pub temp_space_template: ConstTemplate,
    pub temp_offset_template: ConstTemplate,
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
    pub space_template: ConstTemplate,
    pub offset_template: ConstTemplate,
    pub size_template: ConstTemplate,
}

impl VarnodeTemplate {
    pub fn handle_index(&self) -> Option<usize> {
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

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum FixupType {
    Start, End,
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
    u64::from_str_radix(s, 10).unwrap()
}

pub fn u32dec(s: &str) -> u32 {
    u32::from_str_radix(s, 10).unwrap()
}

fn i32dec(s: &str) -> i32 {
    i32::from_str_radix(s, 10).unwrap()
}

fn i64dec(s: &str) -> i64 {
    i64::from_str_radix(s, 10).unwrap()
}

fn scope(input: &str) -> Res<&str, Symbol> {
    delimited(tag("<scope "), take_until("/>"), tag("/>"))(input).map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        //println!("{} {:?}", res, attrs);
        let id = u32hex(attrs[1].1);
        let scope = Scope {
            parent: u32hex(attrs[1].1),
        };
        (
            next,
            Symbol {
                id,
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
                id,
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
    

    // if res.is_err() {
    //     panic!("Could not parse expr at {}", input);
    // }

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
            inputs: res.2.into_iter().flatten().collect(),
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
            pointer_template,
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
            num_labels,
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
            line: (u64dec(iter.next().unwrap()) as usize, u64dec(iter.next().unwrap()) as usize),
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
                id,
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
                id,
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
                id,
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
                id,
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
                id,
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
                id,
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
                id,
                body: SymbolBody::Varlist(varlist),
            },
        )
    })
}

fn name(input: &str) -> Res<&str, Option<String>> {
    //println!("name {}", &input[0..20]);
    delimited(tag("<nametab"), take_until("/>"), tag("/>"))(input).map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();

        if attrs.is_empty() {
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
                id,
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
                id,
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
            context_field,
        };
        (
            next,
            Symbol {
                id,
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
            operand_expr,
            expr: res.1 .1,
        };
        (
            next,
            Symbol {
                id,
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
                id,
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

pub fn read_reg(
    reg: &VarnodeSym,
    reg_space: &BitVec<u8, Msb0>,
) -> Vec<u32> {
    let mut words = vec![];
    let mut size_left = reg.size * 8;

    while size_left > 0 {
        let start = (reg.offset * 8 + (words.len() as u64) * 32) as usize;
        let end = start + 32;
        words.push(reg_space[start..end].load_be::<u32>());
        size_left -= size_left.min(32);
    }

    words
}

pub fn get_word(words: &[u8], start: usize, size: usize) -> u64 {
    let mut word: u64 = 0;

    for i in 0..size {
        if start + i >= words.len() {
            break;
        }

        word = (word << 8) | (words[start + i] as u64);
    }

    word
}

pub fn get_word_le(words: &[u8], start: usize, size: usize) -> u64 {
    let mut word: u64 = 0;

    for i in 0..size {
        if start + i >= words.len() {
            break;
        }

        word |= (words[start + i] as u64) << (i * 8);
    }

    word
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct FuncInfo {
    pub name: Option<String>,
    pub num_params: Option<usize>,
}

#[allow(dead_code)]
pub struct SleighLanguage {
    pub language: Language,
    pub bit_align: usize,
    pub symbols: HashMap<u32, Symbol>,
    pub spaces: HashMap<String, u64>,
    pub _varnodes: HashMap<String, VarnodeSym>,
    pub varnode_map: HashMap<(u64, u64), LocalStr>,
    pub context_syms: HashMap<String, Context>,
    pub reg_sizes: Vec<Vec<Varnode>>,
    pub reg_space_size: usize,
    pub insn_table_id: u32,
    pub context_reg: VarnodeSym,
    pub func_info: HashMap<u64, FuncInfo>,
}

impl SleighLanguage {
    pub fn create<'a>(lang_id: &str, compiler_id: &str) -> SleighLanguage {
        let arch_family = lang_id.split(":").next().unwrap();
        let sla_contents = get_sla(arch_family, lang_id).unwrap();
        let (_, sla) = program(&sla_contents).finish().unwrap();

        let mut symbols: HashMap<u32, Symbol> = HashMap::new();
        let mut spaces: HashMap<String, u64> = HashMap::new();
        let mut varnodes: HashMap<String, VarnodeSym> = HashMap::new();
        let mut varnode_map: HashMap<(u64, u64), LocalStr> = HashMap::new();
        let mut rev_varnode_map: HashMap<String, (u64, u64)> = HashMap::new();
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
                        reg_space_size = reg_space_size.max((varnode.offset + varnode.size) as usize);
                        varnode_map.insert((varnode.offset, varnode.size), varnode.name.to_local_str());
                        rev_varnode_map.insert(varnode.name.clone(), (varnode.offset, varnode.size));
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
        let lang = get_language(arch_family, lang_id, compiler_id, &rev_varnode_map).unwrap();

        let mut registers = HashMap::new();
        let mut max_off = 0;

        for ((start, sz), name) in &varnode_map {
            let register = Varnode {
                name: Some(name.clone()),
                space: AddressSpace::Register,
                offset: *start,
                size: *sz,
            };

            registers.insert((*start, *sz), register.clone());
            max_off = max_off.max(*start + *sz);
        }

        let mut reg_sizes: Vec<Vec<Varnode>> = Vec::with_capacity(max_off as usize);

        for _ in 0..max_off {
            reg_sizes.push(vec![]);
        }

        for reg in registers.values() {
            reg_sizes[reg.offset as usize].push(reg.clone());
        }

        for i in 0..reg_sizes.len() {
            reg_sizes[i].sort_by(|a, b| a.size.cmp(&b.size));
        }

        SleighLanguage {
            language: lang,
            bit_align: (sla.align * 8) as usize,
            symbols,
            spaces,
            _varnodes: varnodes,
            varnode_map,
            context_syms,
            reg_sizes,
            reg_space_size,
            insn_table_id,
            context_reg: ctx_reg,
            func_info: HashMap::new(),
        }
    }
}
