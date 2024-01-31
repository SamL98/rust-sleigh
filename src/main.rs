mod sleigh;
mod utils;
mod arch;

use crate::arch::get_language;

extern crate nom;
extern crate bitvec;

use nom::character::complete::*;
use nom::bytes::complete::*;
use nom::combinator::*;
use nom::character::*;
use nom::sequence::*;
use nom::branch::*;
use nom::error::*;
use nom::multi::*;
use nom::*;

use bitvec::prelude::*;

use std::hash::{Hash, Hasher};
use std::collections::HashMap;
use std::collections::HashSet;
use std::io::Write;
use std::fs::File;
use std::fs;

static SLEIGH_PATH: &'static str = "/Users/samlerner/ghidra_10.3_PUBLIC/Ghidra/Processors/x86/data/languages";

type Res<T, U> = IResult<T, U, Error<T>>;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MaskWord {
    mask: u64,
    val: u64
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PatternBlock {
    offset: u32,
    nonzero: u32,
    masks: Vec<MaskWord>
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
    NonLeaf((bool, u32, u32, Vec<DecisionTree>))
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
    name: &'a str,
    index: u32,
    big_endian: bool,
    delay: u32,
    size: u32,
    physical: bool
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Scope {
    id: u32,
    parent: u32
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SymbolHead<'a> {
    name: &'a str,
    id: u32,
    scope: u32
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Varnode<'a> {
    name: &'a str,
    id: u32,
    scope: u32,
    space: &'a str,
    offset: u64,
    size: u64
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Value<'a> {
    name: &'a str,
    id: u32,
    scope: u32,
    field: Field,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Varlist<'a> {
    name: &'a str,
    id: u32,
    scope: u32,
    field: Field,
    vars: Vec<Option<u32>>
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Valuemap<'a> {
    name: &'a str,
    id: u32,
    scope: u32,
    field: Field,
    vars: Vec<u64>
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Operand<'a> {
    name: &'a str,
    id: u32,
    scope: u32,
    subsym: u32,
    off: u64,
    base: i64,
    min_len: u64,
    idx: u64,
    is_code: bool,
    operand_expr: OperandExpr,
    expr: Option<Expr>
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Context<'a> {
    name: &'a str,
    id: u32,
    scope: u32,
    varnode: u32,
    low: u32,
    high: u32,
    flow: bool,
    context_field: ContextField
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UserOp<'a> {
    name: &'a str,
    id: u32,
    scope: u32,
    idx: u32
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Symbol<'a> {
    Scope(Scope),
    SymHead(SymbolHead<'a>),
    Subtable(Subtable<'a>),
    Varnode(Varnode<'a>),
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
pub struct Subtable<'a> {
    name: &'a str,
    id: u32,
    scope: u32,
    constructors: Vec<Constructor<'a>>,
    decision_tree: DecisionTree
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
    Token(TokenField)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OperandExpr {
    idx: u32,
    table: u32,
    ct: u32
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
    Next2
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Constructor<'a> {
    parent: u32,
    first: i32,
    length: u32,
    operands: Option<Vec<u32>>,
    print_commands: Option<Vec<PrintCommand<'a>>>,
    context_ops: Option<Vec<ContextOp>>,
    template: Option<ConstructorTemplate<'a>>
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PrintCommand<'a> {
    Op(u32),
    Piece(&'a str)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ContextOp {
    i: u32,
    shift: u32,
    mask: u32,
    expr: Expr
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConstructorTemplate<'a> {
    num_labels: u32,
    statements: Vec<ConsTemplate<'a>>
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OpTemplate<'a> {
    code: &'a str,
    output: Option<VarnodeTemplate<'a>>,
    inputs: Vec<VarnodeTemplate<'a>>
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct HandleTemplate<'a> {
    space_template: ConstTemplate<'a>,
    size_template: ConstTemplate<'a>,
    exported_size_template: ConstTemplate<'a>,
    offset_template: ConstTemplate<'a>,
    exported_offset_template: ConstTemplate<'a>,
    unk_template3: ConstTemplate<'a>,
    unk_template4: ConstTemplate<'a>,
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
    size: u32
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VarnodeTemplate<'a> {
    space_template: ConstTemplate<'a>,
    offset_template: ConstTemplate<'a>,
    size_template: ConstTemplate<'a>,
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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Program<'a> {
    version: u32,
    bigendian: bool,
    align: u32,
    uniqbase: u64,
    default_space: &'a str,
    spaces: Vec<Space<'a>>,
    symbols: Vec<Symbol<'a>>
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
        alt((
            tag("<space_other"),
            tag("<space_unique"),
            tag("<space"),
        )),
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
            delimited(
                tag("<spaces "),
                take_until(">"),
                tag(">")
            ),
            line_ending
        ),
        terminated(
            separated_list1(line_ending, space),
            preceded(line_ending, tag("</spaces>"))
        )
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
    delimited(
        tag("<scope "),
        take_until("/>"),
        tag("/>"),
    )(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        //println!("{} {:?}", res, attrs);
        let scope = Scope {
            id: u32hex(&attrs[0].1),
            parent: u32hex(&attrs[1].1)
        };
        (next, Symbol::Scope(scope))
    })
}

fn sym_head(input: &str) -> Res<&str, Symbol> {
    delimited(
        preceded(
            tag("<"),
            alt((
                terminated(
                    alt((
                        tag("subtable"), tag("start"), tag("end"),
                        tag("next2"), tag("varnode"), tag("valuemap"),
                        tag("varlist"), tag("value"), tag("context"),
                        tag("operand")
                    )),
                    tag("_sym_head ")
                ),
                tag("userop_head ")
            ))
        ),
        take_until("/>"),
        tag("/>")
    )(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        //println!("{} {:?}", res, attrs);
        let sym_head = SymbolHead {
            name: attrs[0].1,
            id: u32hex(attrs[1].1),
            scope: u32hex(attrs[2].1)
        };
        (next, Symbol::SymHead(sym_head))
    })
}

fn operand(input: &str) -> Res<&str, u32> {
    delimited(
        tag("<oper"),
        take_until("/>"),
        tag("/>")
    )(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        //println!("{} {:?}", res, attrs);
        (next, u32hex(attrs[0].1))
    })
}

fn operands(input: &str) -> Res<&str, Vec<u32>> {
    separated_list1(
        line_ending,
        operand
    )(input)
}

fn opprint(input: &str) -> Res<&str, PrintCommand> {
    delimited(
        tag("<opprint"),
        take_until("/>"),
        tag("/>")
    )(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        (next, PrintCommand::Op(u32dec(attrs[0].1)))
    })
}

fn print_piece(input: &str) -> Res<&str, PrintCommand> {
    delimited(
        tag("<print"),
        take_until("/>"),
        tag("/>")
    )(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        (next, PrintCommand::Piece(attrs[0].1))
    })
}

fn print_command(input: &str) -> Res<&str, PrintCommand> {
    alt((opprint, print_piece))(input)
}

fn print_commands(input: &str) -> Res<&str, Vec<PrintCommand>> {
    separated_list1(
        line_ending,
        print_command
    )(input)
}

fn const_expr(input: &str) -> Res<&str, Expr> {
    //println!("const {}", &input[0..20]);
    delimited(
        tag("<intb"),
        take_until("/>"),
        tag("/>")
    )(input)
    .map(|(next, res)| {
        //println!("foobar {:?}", res);
        let (_, attrs) = attrs(res).finish().unwrap();
        //println!("{} {:?}", res, attrs);
        (next, Expr::Const(i64dec(attrs[0].1)))
    })
}

fn operand_expr(input: &str) -> Res<&str, Expr> {
    delimited(
        tag("<operand_exp"),
        take_until("/>"),
        tag("/>")
    )(input)
    .map(|(next, res)| {
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
    delimited(
        tag("<contextfield"),
        take_until("/>"),
        tag("/>")
    )(input)
    .map(|(next, res)| {
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
    field(input)
    .map(|(next, res)| {
        (next, Expr::Field(res))
    })
}

fn start_expr(input: &str) -> Res<&str, Expr> {
    tag("<start_exp/>")(input).map(|(next, res)| { (next, (Expr::Start)) })
}

fn end_expr(input: &str) -> Res<&str, Expr> {
    tag("<end_exp/>")(input).map(|(next, res)| { (next, (Expr::End)) })
}

fn next2_expr(input: &str) -> Res<&str, Expr> {
    tag("<next2_exp/>")(input).map(|(next, res)| { (next, (Expr::Next2)) })
}

fn unary_expr(input: &str) -> Res<&str, Expr> {
    //println!("* unary {}", &input[0..20]);
    let expr_types = alt((
        tag("not_exp"),
        tag("dummy_exp"),
    ));

    let (input, (expr_type, hs_expr, _)) = tuple((
        terminated(
            delimited(char('<'), expr_types, char('>')),
            line_ending
        ),
        expr,
        preceded(
            line_ending,
            delimited(tag("</"), identifier, char('>'))
        )
    ))(input)?;

    let hs = Box::new(hs_expr);

    let expr = match expr_type {
        "not_exp" => Expr::Not(hs),
        _ => todo!()
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
        terminated(
            delimited(char('<'), expr_types, char('>')),
            line_ending
        ),
        separated_pair(
            expr,
            opt(line_ending),
            expr
        ),
        preceded(
            line_ending,
            delimited(tag("</"), identifier, char('>'))
        )
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
        _ => todo!()
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
        binary_expr
    ))(input)
}

fn context_op(input: &str) -> Res<&str, ContextOp> {
    tuple((
        terminated(
            delimited(
                tag("<context_op"),
                take_until(">"),
                tag(">")
            ),
            line_ending
        ),
        terminated(
            expr,
            terminated(line_ending, tag("</context_op>"))
        ),
    ))(input)
    .map(|(next, res)| {
        //println!("context {:?}", res.0);
        let (_, attrs) = attrs(res.0).finish().unwrap();
        //println!("{} {:?}", res.0, attrs);
        let context_op = ContextOp {
            i: u32dec(attrs[0].1),
            shift: u32dec(attrs[1].1),
            mask: u32hex(attrs[2].1),
            expr: res.1
        };
        (next, context_op)
    })
}

fn context_ops(input: &str) -> Res<&str, Vec<ContextOp>> {
    separated_list1(
        line_ending,
        context_op
    )(input)
}

fn const_template(input: &str) -> Res<&str, ConstTemplate> {
    //println!("const {}", &input[0..20]);
    delimited(
        tag("<const_tpl"),
        take_until("/>"),
        tag("/>")
    )(input)
    .map(|(next, res)| {
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
            _ => todo!()
        };

        (next, const_template)
    })
}

fn nonnull_varnode_template(input: &str) -> Res<&str, Option<VarnodeTemplate>> {
    //println!("vnode {}", &input[0..20]);
    delimited(
        tag("<varnode_tpl>"),
        tuple((
            const_template,
            const_template,
            const_template
        )),
        tag("</varnode_tpl>")
    )(input)
    .map(|(next, res)| {
        //println!("varnode {:?}", res.1);
        let varnode_template = VarnodeTemplate {
            space_template: res.0,
            offset_template: res.1,
            size_template: res.2
        };
        (next, Some(varnode_template))
    })
}

fn null_varnode_template(input: &str) -> Res<&str, Option<VarnodeTemplate>> {
    tag("<null/>")(input)
    .map(|(next, res)| {
        (next, None)
    })
}

fn varnode_template(input: &str) -> Res<&str, Option<VarnodeTemplate>> {
    alt((null_varnode_template, nonnull_varnode_template))(input)
}

fn op_template(input: &str) -> Res<&str, ConsTemplate> {
    //println!("op {}", &input[0..20]);
    preceded(
        opt(tag("<null/>")),
        tuple((
            delimited(
                tag("<op_tpl"),
                take_until(">"),
                tag(">")
            ),
            terminated(
                varnode_template,
                line_ending
            ),
            terminated(
                separated_list0(
                    line_ending,
                    varnode_template
                ),
                terminated(line_ending, tag("</op_tpl>"))
            )
        ))
    )(input)
    .map(|(next, res)| {
        //println!("op {:?}", res.1);
        let (_, attrs) = attrs(res.0).finish().unwrap();
        let op_template = OpTemplate {
            code: attrs[0].1,
            output: res.1,
            inputs: res.2.into_iter().filter_map(|x| x).collect()
        };
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
            tag("</handle_tpl>")
        )
    )(input)
    .map(|(next, res)| {
        //println!("op {:?}", res.1);
        let handle_template = HandleTemplate {
            space_template: res.0,
            size_template: res.1,
            exported_size_template: res.2,
            offset_template: res.3,
            exported_offset_template: res.4,
            unk_template3: res.5,
            unk_template4: res.6,
        };
        (next, ConsTemplate::Handle(handle_template))
    })
}

fn null_ops(input: &str) -> Res<&str, Vec<ConsTemplate>> {
    tag("<null/>")(input)
    .map(|(next, res)| {
        (next, vec![])
    })
}

fn constructor_template(input: &str) -> Res<&str, ConstructorTemplate> {
    tuple((
        terminated(
            delimited(
                tag("<construct_tpl"),
                take_until(">"),
                tag(">")
            ),
            line_ending
        ),
        terminated(
            alt((
                terminated(
                    separated_list0(
                        line_ending,
                        alt((
                            op_template,
                            handle_template
                        ))
                    ),
                    line_ending
                ),
                null_ops,
            )),
            tag("</construct_tpl>")
        )
    ))(input)
    .map(|(next, res)| {
        //println!("construtor_tpl {:?}", res);
        let (_, attrs) = attrs(res.0).finish().unwrap();
        
        let num_labels = match attrs.len() {
            0 => 0,
            1 => u32dec(attrs[0].1),
            _ => todo!()
        };

        let constructor_template = ConstructorTemplate {
            num_labels: num_labels,
            statements: res.1
        };

        (next, constructor_template)
    })
}

fn constructor(input: &str) -> Res<&str, Constructor> {
    tuple((
        delimited(
            tag("<constructor "),
            take_until(">"),
            terminated(tag(">"), line_ending)
        ),
        terminated(
            tuple((
                opt(terminated(operands, line_ending)),
                opt(terminated(print_commands, line_ending)),
                opt(terminated(context_ops, line_ending)),
                opt(terminated(constructor_template, line_ending)),
            )),
            tag("</constructor>")
        )
    ))(input)
    .map(|(next, res)| {
        //println!("constructor {:?}", res.1);
        let (_, attrs) = attrs(res.0).finish().unwrap();
        //println!("{:?}", attrs);
        let constructor = Constructor {
            parent: u32hex(attrs[0].1),
            first: i32dec(attrs[1].1),
            length: u32dec(attrs[2].1),
            operands: res.1.0,
            print_commands: res.1.1,
            context_ops: res.1.2,
            template: res.1.3
        };
        (next, constructor)
    })
}

fn mask_word(input: &str) -> Res<&str, MaskWord> {
    delimited(
        tag("<mask_word "),
        take_until("/>"),
        tag("/>")
    )(input)
    .map(|(next, res)| {
        //println!("mask word {:?}", res);
        let (_, attrs) = attrs(res).finish().unwrap();
        let mask_word = MaskWord {
            mask: u64hex(attrs[0].1),
            val: u64hex(attrs[1].1)
        };
        (next, mask_word)
    })
}

fn pattern_block(input: &str) -> Res<&str, PatternBlock> {
    tuple((
        terminated(
            delimited(
                tag("<pat_block "),
                take_until(">"),
                tag(">")
            ),
            line_ending
        ),
        alt((
            terminated(
                separated_list1(
                    line_ending,
                    preceded(
                        space0,
                        mask_word
                    ),
                ),
                line_ending
            ),
            separated_list0(line_ending, mask_word)
        )),
        tag("</pat_block>")
    ))(input)
    .map(|(next, res)| {
        //println!("pattern block {:?}", res);
        let (_, attrs) = attrs(res.0).finish().unwrap();
        let pattern_block = PatternBlock {
            offset: u32dec(attrs[0].1),
            nonzero: u32dec(attrs[1].1),
            masks: res.1
        };
        (next, pattern_block)
    })
}

fn combine_pattern(input: &str) -> Res<&str, DecisionPattern> {
    delimited(
        terminated(tag("<combine_pat>"), line_ending),
        separated_pair(
            decision_pattern,
            line_ending,
            decision_pattern
        ),
        preceded(line_ending, tag("</combine_pat>"))
    )(input)
    .map(|(next, res)| {
        //println!("combine pattern {:?}", res);
        (next, DecisionPattern::Combine((Box::new(res.0), Box::new(res.1))))
    })
}

fn context_pattern(input: &str) -> Res<&str, DecisionPattern> {
    delimited(
        terminated(tag("<context_pat>"), line_ending),
        pattern_block,
        preceded(line_ending, tag("</context_pat>"))
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
        preceded(line_ending, tag("</instruct_pat>"))
    )(input)
    .map(|(next, res)| {
        //println!("instruct pattern {:?}", res);
        (next, DecisionPattern::Instruction(res))
    })
}

fn decision_pattern(input: &str) -> Res<&str, DecisionPattern> {
    alt((
        context_pattern,
        instruction_pattern,
        combine_pattern
    ))(input)
}

fn decision_pair(input: &str) -> Res<&str, (u32, DecisionPattern)> {
    tuple((
        terminated(
            delimited(
                tag("<pair "),
                take_until(">"),
                tag(">")
            ),
            line_ending
        ),
        terminated(
            terminated(decision_pattern, line_ending),
            tag("</pair>")
        )
    ))(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res.0).finish().unwrap();
        let id = u32dec(attrs[0].1);
        (next, (id, res.1))
    })
}

fn decision_pairs(input: &str) -> Res<&str, DecisionTree> {
    separated_list1(
        line_ending,
        decision_pair
    )(input)
    .map(|(next, res)| {
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
            terminated(tag(">"), line_ending)
        ),
        terminated(
            alt((
                terminated(separated_list1(line_ending, decision_body), line_ending),
                separated_list0(line_ending, decision_body),
            )),
            tag("</decision>")
        )
    ))(input)
    .map(|(next, res)| {
        //println!("decision body {:?}", res);
        let (_, attrs) = attrs(res.0).finish().unwrap();
        //println!("{} {:?}", res.0, attrs);
        let is_context = to_bool(attrs[1].1);
        let start = u32dec(attrs[2].1);
        let size = u32dec(attrs[3].1);
        (next, DecisionTree::NonLeaf((is_context, start, size, res.1)))
    })
}

fn subtable_sym(input: &str) -> Res<&str, Symbol> {
    //println!("subtable_sym {}", &input[0..50]);
    tuple((
        delimited(
            tag("<subtable_sym "),
            take_until(">"),
            terminated(tag(">"), line_ending)
        ),
        terminated(
            tuple((
                terminated(
                    separated_list1(line_ending, constructor),
                    line_ending
                ),
                decision_tree,
            )),
            preceded(line_ending, tag("</subtable_sym>"))
        )
    ))(input)
    .map(|(next, res)| {
        //println!("{:?}", res.1.0.len());
        let (_, attrs) = attrs(res.0).finish().unwrap();
        //println!("{} {:?}", res.0, attrs);
        let subtable = Subtable {
            name: attrs[0].1,
            id: u32hex(attrs[1].1),
            scope: u32hex(attrs[2].1),
            constructors: res.1.0,
            decision_tree: res.1.1
        };
        (next, Symbol::Subtable(subtable))
    })
}

fn start_sym(input: &str) -> Res<&str, Symbol> {
    delimited(tag("<start_sym "), take_until("/>"), tag("/>"))(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        let sym_head = SymbolHead {
            name: attrs[0].1,
            id: u32hex(attrs[1].1),
            scope: u32hex(attrs[2].1),
        };
        (next, Symbol::Start(sym_head))
    })
}
fn end_sym(input: &str) -> Res<&str, Symbol> {
    delimited(tag("<end_sym "), take_until("/>"), tag("/>"))(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        let sym_head = SymbolHead {
            name: attrs[0].1,
            id: u32hex(attrs[1].1),
            scope: u32hex(attrs[2].1),
        };
        (next, Symbol::End(sym_head))
    })
}
fn next2_sym(input: &str) -> Res<&str, Symbol> {
    delimited(tag("<next2_sym "), take_until("/>"), tag("/>"))(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        let sym_head = SymbolHead {
            name: attrs[0].1,
            id: u32hex(attrs[1].1),
            scope: u32hex(attrs[2].1),
        };
        (next, Symbol::Next2(sym_head))
    })
}

fn varnode_sym(input: &str) -> Res<&str, Symbol> {
    terminated(
        delimited(
            tag("<varnode_sym "),
            take_until(">"),
            terminated(tag(">"), line_ending)
        ),
        tag("</varnode_sym>")
    )(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        //println!("{} {:?}", res, attrs);
        let varnode = Varnode {
            name: attrs[0].1,
            id: u32hex(attrs[1].1),
            scope: u32hex(attrs[2].1),
            space: attrs[3].1,
            offset: u64hex(attrs[4].1),
            size: u64dec(attrs[5].1),
        };
        (next, Symbol::Varnode(varnode))
    })
}

fn tokenfield(input: &str) -> Res<&str, Field> {
    delimited(
        tag("<tokenfield"),
        take_until("/>"),
        tag("/>")
    )(input)
    .map(|(next, res)| {
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
    delimited(
        tag("<valuetab"),
        take_until("/>"),
        tag("/>")
    )(input)
    .map(|(next, res)| {
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
            terminated(tag(">"), line_ending)
        ),
        terminated(
            separated_pair(
                field,
                line_ending,
                terminated(
                    separated_list0(
                        line_ending,
                        valuetab
                    ),
                    line_ending
                ),
            ),
            tag("</valuemap_sym>")
        )
    ))(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res.0).finish().unwrap();
        let valuemap = Valuemap {
            name: attrs[0].1,
            id: u32hex(attrs[1].1),
            scope: u32hex(attrs[2].1),
            field: res.1.0,
            vars: res.1.1
        };
        (next, Symbol::Valuemap(valuemap))
    })
}

fn nonnull_var(input: &str) -> Res<&str, Option<u32>> {
    delimited(
        tag("<var"),
        take_until("/>"),
        tag("/>")
    )(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();
        let id = u32hex(attrs[0].1);
        (next, Some(id))
    })
}

fn null_var(input: &str) -> Res<&str, Option<u32>> {
    tag("<null/>")(input)
    .map(|(next, res)| { (next, None) })
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
            terminated(tag(">"), line_ending)
        ),
        terminated(
            separated_pair(
                field,
                line_ending,
                terminated(
                    separated_list0(
                        line_ending,
                        var
                    ),
                    line_ending
                ),
            ),
            tag("</varlist_sym>")
        )
    ))(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res.0).finish().unwrap();
        let varlist = Varlist {
            name: attrs[0].1,
            id: u32hex(attrs[1].1),
            scope: u32hex(attrs[2].1),
            field: res.1.0,
            vars: res.1.1
        };
        (next, Symbol::Varlist(varlist))
    })
}

fn value_sym(input: &str) -> Res<&str, Symbol> {
    tuple((
        delimited(
            tag("<value_sym "),
            take_until(">"),
            terminated(tag(">"), line_ending)
        ),
        terminated(
            tokenfield,
            preceded(line_ending, tag("</value_sym>"))
        )
    ))(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res.0).finish().unwrap();
        let value = Value {
            name: attrs[0].1,
            id: u32hex(attrs[1].1),
            scope: u32hex(attrs[2].1),
            field: res.1
        };
        (next, Symbol::Value(value))
    })
}

fn context_sym(input: &str) -> Res<&str, Symbol> {
    tuple((
        delimited(
            tag("<context_sym "),
            take_until(">"),
            terminated(tag(">"), line_ending)
        ),
        terminated(
            contextfield,
            preceded(line_ending, tag("</context_sym>"))
        )
    ))(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res.0).finish().unwrap();

        let context_field = match res.1 {
            Field::Context(ctx_field) => ctx_field,
            _ => panic!()
        };

        let context = Context {
            name: attrs[0].1,
            id: u32hex(attrs[1].1),
            scope: u32hex(attrs[2].1),
            varnode: u32hex(attrs[3].1),
            low: u32dec(attrs[4].1),
            high: u32dec(attrs[5].1),
            flow: to_bool(attrs[6].1),
            context_field: context_field
        };
        (next, Symbol::Context(context))
    })
}

fn operand_sym(input: &str) -> Res<&str, Symbol> {
    tuple((
        delimited(
            tag("<operand_sym "),
            take_until(">"),
            terminated(tag(">"), line_ending)
        ),
        terminated(
            tuple((
                operand_expr,
                opt(preceded(line_ending, expr)),
            )),
            preceded(line_ending, tag("</operand_sym>"))
        )
    ))(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res.0).finish().unwrap();
        //println!("{} {:?}", res.0, attrs);

        let operand_expr = match res.1.0 {
            Expr::Operand(op_expr) => op_expr,
            _ => panic!()
        };

        let kvs: HashMap<&str, &str> = attrs.into_iter().collect();

        let operand = Operand {
            name: kvs["name"],
            id: u32hex(kvs["id"]),
            scope: u32hex(kvs["scope"]),
            subsym: kvs.get("subsym").map(|s| u32hex(s)).unwrap_or(0),
            off: kvs.get("off").map(|s| u64dec(s)).unwrap_or(0),
            base: kvs.get("base").map(|s| i64dec(s)).unwrap_or(0),
            min_len: kvs.get("minlen").map(|s| u64dec(s)).unwrap_or(0),
            idx: kvs.get("idx").map(|s| u64dec(s)).unwrap_or(0),
            is_code: kvs.get("code").map(|s| to_bool(s)).unwrap_or(false),
            operand_expr: operand_expr,
            expr: res.1.1
        };
        (next, Symbol::Operand(operand))
    })
}

fn userop(input: &str) -> Res<&str, Symbol> {
    delimited(
        tag("<userop "),
        take_until("/>"),
        tag("/>")
    )(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res).finish().unwrap();

        let userop = UserOp {
            name: attrs[0].1,
            id: u32hex(attrs[1].1),
            scope: u32hex(attrs[2].1),
            idx: u32dec(attrs[3].1)
        };

        (next, Symbol::UserOp(userop))
    })
}

fn sym(input: &str) -> Res<&str, Symbol> {
    //println!("** {}", &input[0..20]);
    alt((
        subtable_sym, varnode_sym, start_sym, end_sym,
        next2_sym, valuemap_sym, varlist_sym, value_sym,
        context_sym, operand_sym, userop
    ))(input)
}

fn symbol(input: &str) -> Res<&str, Symbol> {
    alt((
        scope, sym_head, sym
    ))(input)
}

fn symbol_table(input: &str) -> Res<&str, Vec<Symbol>> {
    tuple((
        terminated(
            delimited(
                tag("<symbol_table "),
                take_until(">"),
                tag(">")
            ),
            line_ending
        ),
        terminated(
            separated_list1(line_ending, symbol),
            preceded(line_ending, tag("</symbol_table>"))
        )
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
        separated_list0(
            char(' '),
            separated_pair(
                identifier,
                char('='),
                string
            )
        )
    )(input)
    .map(|(next, res)| {
        //println!("{:?}", res);
        (next, res)
    })
}

fn program(input: &str) -> Res<&str, Program> {
    tuple((
        terminated(
            delimited(
                tag("<sleigh "),
                take_until(">"),
                tag(">")
            ),
            line_ending
        ),
        terminated(
            source_files,
            line_ending
        ),
        terminated(
            spaces,
            line_ending
        ),
        terminated(
            symbol_table,
            line_ending
        )
    ))(input)
    .map(|(next, res)| {
        let (_, attrs) = attrs(res.0).finish().unwrap();
        let prog = Program {
            version: u32::from_str_radix(attrs[0].1, 10).unwrap(),
            bigendian: attrs[1].1.parse::<bool>().unwrap(),
            align: u32::from_str_radix(attrs[2].1, 10).unwrap(),
            uniqbase: u64::from_str_radix(&attrs[3].1[2..], 16).unwrap(),
            default_space: res.2.0,
            spaces: res.2.1,
            symbols: res.3
        };
        (next, prog)
    })
}

fn identifier(input: &str) -> Res<&str, &str> {
    recognize(
        pair(
            alt((alpha1, tag("_"), tag("."))),
            many0_count(alt((alphanumeric1, tag("_"), tag("."))))))(input)
}

fn identifier_ws(input: &str) -> Res<&str, &str> {
    terminated(identifier, space0)(input)
}

fn string(input: &str) -> Res<&str, &str> {
    delimited(char('"'),
              take_until("\""),
              char('"'))(input)
}

fn read_file(filename: &str) -> String {
    fs::read_to_string(format!("{}/{}", SLEIGH_PATH, filename)).expect("can't read file")
}

fn main() {
    let lang = get_language("x86", "x86:LE:64:default").unwrap();

    let contents = read_file("x86-64.sla");
    let (_, sla) = program(&contents).finish().unwrap();
    //println!("{:?}", sla);
    
    let mut tables: HashMap<&str, Vec<Subtable>> = HashMap::new();
    let mut varnodes: HashMap<&str, Varnode> = HashMap::new();
    let mut context_syms: HashMap<&str, Context> = HashMap::new();
    let mut reg_space_size: usize = 0;

    for sym in sla.symbols {
        match sym {
            Symbol::Subtable(subtable) => {
                tables.entry(subtable.name).or_insert(vec![]).push(subtable);
            },
            Symbol::Varnode(varnode) =>  {
                varnodes.insert(varnode.name, varnode.clone());

                if varnode.space == "register" {
                    reg_space_size = reg_space_size.max((varnode.offset + varnode.size) as usize);
                }
            },
            Symbol::Context(ctx) =>  {
                context_syms.insert(ctx.name, ctx.clone());
            }
            _ => ()
        }
    }

    let insn_table = &tables["instruction"][0];
    let ctx_reg = &varnodes["contextreg"];
    //println!("{:#?}", insn_table.decision_tree);

    // Create a bit vector for the entire register space.
    // TODO: Figure out how to properly initialize the BitVec.
    let mut reg_space: BitVec<u8, Msb0> = BitVec::with_capacity(reg_space_size * 8);
    for _ in 0..(reg_space_size * 8) {
        reg_space.push(false);
    }

    for (var, val) in lang.pspec.defaults {
        //println!("{} {:?}", var, context_syms.get(var.as_str()));
        if let Some(sym) = context_syms.get(var.as_str()) {
            let start = (ctx_reg.offset * 8 + (sym.low as u64)) as usize;
            let end = (ctx_reg.offset * 8  + (sym.high as u64) + 1) as usize;
            println!("{}, {}, {}, {}", var, start, end, val);
            let existing = reg_space[start..end].load_be::<u32>();
            reg_space[start..end].store_be(val | existing);
        }
    }

    //println!("{:#?}", tables["Reg8"][0].decision_tree);
    let data: [u8; 1] = [0x55];
    let byte = data[0];
    
    let mut dtree = &insn_table.decision_tree;
    /*let mut buf = vec![(&insn_table.decision_tree, vec![])];
    let mut visited = HashSet::new();

    while let Some((dtree, path)) = buf.pop() {
        if visited.contains(dtree) {
            continue;
        }
        visited.insert(dtree);

        match dtree {
            DecisionTree::NonLeaf((is_ctx, start, size, children)) => {
                for (i, child) in children.into_iter().enumerate() {
                    let mut child_path = path.clone();
                    child_path.push((is_ctx, start, size, i));
                    buf.push((&child, child_path));
                }
            },
            DecisionTree::Leaf(pairs) => {
                for (ct_id, pattern) in pairs {
                    let ct = &insn_table.constructors[*ct_id as usize];

                    if let Some(pcs) = &ct.print_commands {
                        if pcs.len() > 0 {
                            if let PrintCommand::Piece("PUSH") = pcs[0] {
                                println!("{:?}", path);
                                println!("{:?} {:?}", pcs, pattern);
                                break;
                            }
                        }
                    }
                }
            }
        };
    }*/

    loop {
        match dtree {
            DecisionTree::NonLeaf((is_context, start, size, children)) => {
                if !is_context {
                    let bit_start = 8 - (start + size);
                    let idx = ((byte >> bit_start) & ((1 << size) - 1)) as usize;
                    println!("non-context {}, {}, {}, {}", start, size, children.len(), idx);
                    dtree = &children[idx.min(children.len() - 1)];
                }
                else {
                    //println!("context {}, {}, {}", start, size, children.len());
                    let ctx_start = (ctx_reg.offset * 8 + (*start as u64)) as usize;
                    let ctx_end = ctx_start + (*size as usize);
                    let idx = reg_space[ctx_start..ctx_end].load_be::<usize>();
                    println!("* {}, {}, {}, {}, {}", ctx_start, ctx_end, idx, start, size);
                    dtree = &children[idx.min(children.len() - 1)];
                }
            },
            DecisionTree::Leaf(pairs) => {
                for (ct_id, pattern) in pairs {
                    let ct = &insn_table.constructors[*ct_id as usize];
                    println!("{:#?}", ct.print_commands);
                }
                panic!();
            }
        };
    }
}
