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

use std::collections::HashMap;
use std::fs;

type Res<T, U> = IResult<T, U, Error<T>>;

fn read_file(filename: &str) -> String {
    fs::read_to_string(filename).expect("can't read file")
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Program<'a> {
    stmts: Vec<Stmt<'a>>
}

fn comment_without_newline(input: &str) -> Res<&str, Stmt> {
    preceded(
        space0,
        preceded(
            char('#'),
            take_until("\n")))(input)
    .map(|(next, _)| {
        (next, Stmt::COMMENT)
    })
}

fn comment(input: &str) -> Res<&str, Stmt> {
    terminated(
        comment_without_newline,
        line_ending)(input)
    .map(|(next, _)| {
        (next, Stmt::COMMENT)
    })
}

fn line_end_comment_without_newline(input: &str) -> Res<&str, Stmt> {
    preceded(space0, comment_without_newline)(input)
}

fn line_end_comment(input: &str) -> Res<&str, Option<Stmt>> {
    preceded(space0, opt(comment))(input)
}

fn is_newline_char(chr: char) -> bool {
    let mut c = [0; 1];
    let _ = chr.encode_utf8(&mut c);
    is_newline(c[0])
}


fn program(input: &str) -> Res<&str, Program> {
    preceded(
        multispace0,
        many0(
            terminated(
                terminated(
                    alt((comment, stmt)),
                    line_end_comment),
                take_while(is_newline_char))))(input)
    .map(|(next, res)| {
        (next, Program { stmts: res })
    })
}

fn stmt(input: &str) -> Res<&str, Stmt> {
    alt((define, attach, sleigh_macro, constructor))(input)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Stmt<'a> {
    Define(DefineStmt<'a>),
    Attach(AttachStmt<'a>),
    Constructor(ConstructorStmt<'a>),
    Macro(MacroStmt<'a>),
    COMMENT
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Endianness {
    BIG,
    LITTLE
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SpaceType {
    RAM,
    ROM,
    REGISTER
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SpaceAttribute {
    TYPE(SpaceType),
    SIZE(u64),
    DEFAULT,
    WOrDSIZE(u64)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SpaceDefinition<'a> {
    name: &'a str,
    attrs: Vec<SpaceAttribute>
}

fn rom_type(input: &str) -> Res<&str, SpaceType> {
    tag("rom_space")(input)
    .map(|(next, _)| {
        (next, SpaceType::ROM)
    })
}

fn ram_type(input: &str) -> Res<&str, SpaceType> {
    tag("ram_space")(input)
    .map(|(next, _)| {
        (next, SpaceType::RAM)
    })
}

fn register_type(input: &str) -> Res<&str, SpaceType> {
    tag("register_space")(input)
    .map(|(next, _)| {
        (next, SpaceType::REGISTER)
    })
}

fn space_type(input: &str) -> Res<&str, SpaceType> {
    alt((rom_type, ram_type, register_type))(input)
}

fn space_default_attr(input: &str) -> Res<&str, SpaceAttribute> {
    tag("default")(input)
    .map(|(next, _)| {
        (next, SpaceAttribute::DEFAULT)
    })
}

fn space_type_attr(input: &str) -> Res<&str, SpaceAttribute> {
    preceded(
        tag("type="),
        space_type)(input)
    .map(|(next, res)| {
        (next, SpaceAttribute::TYPE(res))
    })
}

fn space_size_attr(input: &str) -> Res<&str, SpaceAttribute> {
    preceded(
        tag("size="),
        digit1)(input)
    .map(|(next, res)| {
        (next, SpaceAttribute::SIZE(res.parse::<u64>().unwrap()))
    })
}

fn space_wordsize_attr(input: &str) -> Res<&str, SpaceAttribute> {
    preceded(
        tag("wordsize="),
        digit1)(input)
    .map(|(next, res)| {
        (next, SpaceAttribute::WOrDSIZE(res.parse::<u64>().unwrap()))
    })
}

fn space_attrs(input: &str) -> Res<&str, Vec<SpaceAttribute>> {
    separated_list0(
        space1,
        alt((space_default_attr, space_size_attr, space_type_attr, space_wordsize_attr)))(input)
}

fn space_define(input: &str) -> Res<&str, DefineStmt> {
    terminated(
        preceded(terminated(tag("space"), space1),
            tuple((
                terminated(identifier, space1),
                space_attrs))),
        terminated(tag(";"), line_ending))(input)
    .map(|(next, res)| {
        (next, DefineStmt::Space(SpaceDefinition { name: res.0, attrs: res.1 }))
    })
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SpaceName<'a> {
    Name(&'a str),
    NONE
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SpaceNamesDefinition<'a> {
    name: &'a str,
    offset: u64,
    size: u64,
    names: Vec<SpaceName<'a>>
}

fn name_space_name(input: &str) -> Res<&str, SpaceName> {
    identifier(input)
    .map(|(next, res)| {
        (next, SpaceName::Name(res))
    })
}

fn none_space_name(input: &str) -> Res<&str, SpaceName> {
    tag("_")(input)
    .map(|(next, _)| {
        (next, SpaceName::NONE)
    })
}

fn space_name(input: &str) -> Res<&str, SpaceName> {
    alt((none_space_name, name_space_name))(input)
}

fn many_space_name(input: &str) -> Res<&str, Vec<SpaceName>> {
    terminated(
        terminated(
            preceded(
                terminated(char('['), multispace0),
                separated_list1(multispace1, space_name)
            ),
            multispace0
        ),
        char(']')
    )(input)
}

fn single_space_name(input: &str) -> Res<&str, Vec<SpaceName>> {
    space_name(input)
    .map(|(next, res)| {
        (next, vec![res])
    })
}

fn space_name_list(input: &str) -> Res<&str, Vec<SpaceName>> {
    alt((single_space_name, many_space_name))(input)
}

fn dec_num(input: &str) -> Res<&str, u64> {
    digit1(input)
    .map(|(next, res)| {
        (next, res.parse::<u64>().unwrap())
    })
}

fn hex_num(input: &str) -> Res<&str, u64> {
    preceded(tag("0x"), hex_digit1)(input)
    .map(|(next, res)| {
        (next, u64::from_str_radix(res, 16).unwrap())
    })
}

fn is_bin_digit(chr: char) -> bool {
    /*let mut c = [0; 1];
    let _ = chr.encode_utf8(&mut c);
    is_newline(c[0])*/
    chr == '0' || chr == '1'
}

fn bin_num(input: &str) -> Res<&str, u64> {
    preceded(tag("0b"), take_while(is_bin_digit))(input)
    .map(|(next, res)| {
        (next, u64::from_str_radix(res, 2).unwrap())
    })
}

fn num(input: &str) -> Res<&str, u64> {
    alt((hex_num, bin_num, dec_num))(input)
    .map(|(next, res)| {
        (next, res)
    })
}

fn space_names_define(input: &str) -> Res<&str, DefineStmt> {
    terminated(
        tuple((
            terminated(identifier, space1),
            terminated(
                preceded(
                    tag("offset="),
                    num
                ),
                space1),
            terminated(
                preceded(
                    tag("size="),
                    digit1
                ),
                space1),
            space_name_list)),
        tag(";")
    )(input)
    .map(|(next, res)| {
        let size = res.2.parse::<u64>().unwrap();
        (next, DefineStmt::Names(SpaceNamesDefinition { name: res.0, offset: res.1, size: size, names: res.3 }))
    })
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BitRange {
    start: u64,
    len: u64
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BitRangeDefinition<'a> {
    name: &'a str,
    reg: &'a str,
    range: BitRange
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum FieldAttribute {
    SIGNED, HEX, DEC, NOFLOW
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TokenField<'a> {
    name: &'a str,
    range: BitRange,
    attrs: Vec<FieldAttribute>
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ContextDefinition<'a> {
    register: &'a str,
    fields: Vec<TokenField<'a>>
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Token<'a> {
    name: &'a str,
    bit_size: u64,
    fields: Vec<TokenField<'a>>
}

fn signed_attr(input: &str) -> Res<&str, FieldAttribute> {
    tag("signed")(input)
    .map(|(next, _)| {
        (next, FieldAttribute::SIGNED)
    })
}

fn hex_attr(input: &str) -> Res<&str, FieldAttribute> {
    tag("hex")(input)
    .map(|(next, _)| {
        (next, FieldAttribute::HEX)
    })
}

fn dec_attr(input: &str) -> Res<&str, FieldAttribute> {
    tag("dec")(input)
    .map(|(next, _)| {
        (next, FieldAttribute::DEC)
    })
}

fn noflow_attr(input: &str) -> Res<&str, FieldAttribute> {
    tag("noflow")(input)
    .map(|(next, _)| {
        (next, FieldAttribute::NOFLOW)
    })
}

fn token_attr(input: &str) -> Res<&str, FieldAttribute> {
    alt((signed_attr, hex_attr, dec_attr, noflow_attr))(input)
}

fn token_field(input: &str) -> Res<&str, TokenField> {
    terminated(
        tuple((
            terminated(identifier, terminated(delimited(space0, char('='), space0), char('('))),
            terminated(digit1, char(',')),
            terminated(digit1, char(')')),
            opt(preceded(
                space1,
                separated_list1(space1, token_attr)
            ))
        )),
        opt(comment_without_newline)
    )(input)
    .map(|(next, res)| {
        let bit_start = res.1.parse::<u64>().unwrap();
        let bit_end = res.2.parse::<u64>().unwrap();
        let field = TokenField {
                        name: res.0, 
                        range: BitRange {
                            start: bit_start,
                            len: (bit_end - bit_start) + 1,
                        },
                        attrs: res.3.unwrap_or_else(|| Vec::new())
                    };
        (next, field)
    })
}

fn context_define(input: &str) -> Res<&str, DefineStmt> {
    terminated(
        preceded(
            terminated(tag("context"), space1),
            separated_pair(
                identifier,
                multispace1,
                separated_list1(multispace1, preceded(space0, token_field))
            )
        ),
        preceded(multispace0, tag(";"))
    )(input)
    .map(|(next, res)| {
        (next, DefineStmt::Context(ContextDefinition { register: res.0, fields: res.1 }))
    })
}

fn token_define(input: &str) -> Res<&str, DefineStmt> {
    terminated(
        preceded(
            terminated(tag("token"), space1),
            separated_pair(
                tuple((
                    terminated(identifier, space1),
                    delimited(char('('), digit1, char(')'))
                )),
                multispace1,
                separated_list1(multispace1, preceded(space0, token_field))
            )
        ),
        preceded(multispace0, tag(";"))
    )(input)
    .map(|(next, res)| {
        let bit_size = res.0.1.parse::<u64>().unwrap();
        (next, DefineStmt::Token(Token { name: res.0.0, bit_size: bit_size, fields: res.1 }))
    })
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DefineStmt<'a> {
    Endianness(Endianness),
    Alignment(u64),
    Space(SpaceDefinition<'a>),
    Names(SpaceNamesDefinition<'a>),
    BitRange(Vec<BitRangeDefinition<'a>>),
    PcodeOp(&'a str),
    Context(ContextDefinition<'a>),
    Token(Token<'a>),
}

fn pcodeop_define(input: &str) -> Res<&str, DefineStmt> {
    terminated(
        preceded(
            tag("pcodeop "),
            identifier
        ),
        terminated(preceded(space0, tag(";")), opt(comment_without_newline))
    )(input)
    .map(|(next, res)| {
        (next, DefineStmt::PcodeOp(res))
    })
}

fn bitrange_definition(input: &str) -> Res<&str, BitRangeDefinition> {
    tuple((
        terminated(identifier, tag("=")),
        terminated(identifier, tag("[")),
        terminated(digit1, tag(",")),
        terminated(digit1, tag("]"))
    ))(input)
    .map(|(next, res)| {
        let bit_start = res.2.parse::<u64>().unwrap();
        let num_bits = res.3.parse::<u64>().unwrap();
        (next, BitRangeDefinition {
                name: res.0,
                reg: res.1,
                range: BitRange {
                    start: bit_start, 
                    len: num_bits
                }
            })
    })
}

fn bitrange_define(input: &str) -> Res<&str, DefineStmt> {
    terminated(
        preceded(
            tag("define bitrange "),
            separated_list1(
                multispace1,
                bitrange_definition
            )
        ),
        terminated(tag(";"), line_ending)
    )(input)
    .map(|(next, res)| {
        (next, DefineStmt::BitRange(res))
    })
}

fn big_endian(input: &str) -> Res<&str, Endianness> {
    tag("big")(input)
    .map(|(next, _)| {
        (next, Endianness::BIG)
    })
}

fn little_endian(input: &str) -> Res<&str, Endianness> {
    tag("little")(input)
    .map(|(next, _)| {
        (next, Endianness::LITTLE)
    })
}

fn endianness(input: &str) -> Res<&str, Endianness> {
    alt((big_endian, little_endian))(input)
}

fn endianness_define(input: &str) -> Res<&str, DefineStmt> {
    terminated(
        preceded(tag("endian="), endianness),
        terminated(tag(";"), line_ending))(input)
    .map(|(next, res)| {
        (next, DefineStmt::Endianness(res))
    })
}

fn alignment_define(input: &str) -> Res<&str, DefineStmt> {
    terminated(
        terminated(
            tag("alignment="),
            digit1),
        terminated(tag(";"), line_ending))(input)
    .map(|(next, res)| {
        (next, DefineStmt::Alignment(res.parse::<u64>().unwrap()))
    })
}

fn identifier(input: &str) -> Res<&str, &str> {
    recognize(
        pair(
            alt((alpha1, tag("_"), tag("."))),
            many0_count(alt((alphanumeric1, tag("_"), tag("."))))))(input)
}

fn define(input: &str) -> Res<&str, Stmt> {
    preceded(
        terminated(tag("define"), space1),
        alt((
            endianness_define,
            alignment_define,
            space_define,
            space_names_define,
            bitrange_define,
            pcodeop_define,
            context_define,
            token_define)))(input)
    .map(|(next, res)| {
        //println!("{:?}", Stmt::Define(res.clone()));
        (next, Stmt::Define(res))
    })
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VariableAttachStmt<'a> {
    fields: Vec<SpaceName<'a>>,
    registers: Vec<SpaceName<'a>>
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ValueAttachStmt<'a> {
    fields: Vec<SpaceName<'a>>,
    values: Vec<u64>
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AttachStmt<'a> {
    Variable(VariableAttachStmt<'a>),
    Value(ValueAttachStmt<'a>),
}

fn attach_variables(input: &str) -> Res<&str, AttachStmt> {
    delimited(
        terminated(tag("variables"), space1),
        separated_pair(space_name_list, multispace1, space_name_list),
        char(';')
    )(input)
    .map(|(next, res)| {
        (next, AttachStmt::Variable(VariableAttachStmt { fields: res.0, registers: res.1 }))
    })
}

fn num_list(input: &str) -> Res<&str, Vec<u64>> {
    delimited(
        terminated(char('['), space0),
        separated_list1(space1, num),
        preceded(space0, char(']'))
    )(input)
}

fn attach_values(input: &str) -> Res<&str, AttachStmt> {
    delimited(
        terminated(tag("values"), space1),
        separated_pair(space_name_list, multispace1, num_list),
        char(';')
    )(input)
    .map(|(next, res)| {
        (next, AttachStmt::Value(ValueAttachStmt { fields: res.0, values: res.1 }))
    })
}

fn attach(input: &str) -> Res<&str, Stmt> {
    preceded(
        terminated(tag("attach"), space1),
        alt((attach_variables, attach_values))
    )(input)
    .map(|(next, res)| {
        //println!("{:?}", Stmt::Attach(res.clone()));
        (next, Stmt::Attach(res))
    })
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DisplayPart<'a> {
    Literal(char),
    QuotedLiteral(&'a str),
    Caret(Box<DisplayPart<'a>>),
    Ident(&'a str),
    Empty,
    Space,
}

fn ident_display_part(input: &str) -> Res<&str, DisplayPart> {
    identifier(input)
    .map(|(next, res)| {
        (next, DisplayPart::Ident(res))
    })
}

fn is_not_ident_char(chr: char) -> bool {
    let mut c = [0; 1];
    let _ = chr.encode_utf8(&mut c);
    is_alphanumeric(c[0])
}

fn is_space_char(chr: char) -> bool {
    let mut c = [0; 1];
    let _ = chr.encode_utf8(&mut c);
    is_space(c[0])
}

fn space_display_part(input: &str) -> Res<&str, DisplayPart> {
    space1(input)
    .map(|(next, _)| {
        (next, DisplayPart::Space)
    })
}

fn literal_display_part(input: &str) -> Res<&str, DisplayPart> {
    anychar(input)
    .map(|(next, res)| {
        (next, DisplayPart::Literal(res))
    })
}

fn quoted_literal_display_part(input: &str) -> Res<&str, DisplayPart> {
    delimited(
        char('"'),
        take_until("\""),
        char('"')
    )(input)
    .map(|(next, res)| {
        (next, DisplayPart::QuotedLiteral(res))
    })
}

fn caret_literal_display_part(input: &str) -> Res<&str, DisplayPart> {
    preceded(
        char('^'),
        display_part
    )(input)
    .map(|(next, res)| {
        //println!("caret {:?}", res);
        (next, DisplayPart::Caret(Box::new(res)))
    })
}

fn display_part(input: &str) -> Res<&str, DisplayPart> {
    alt((
        caret_literal_display_part,
        ident_display_part,
        space_display_part,
        quoted_literal_display_part,
        literal_display_part
    ))(input)
}

fn display_section(input: &str) -> Res<&str, Vec<DisplayPart>> {
    //println!("{}", &input[0..20]);
    take_until("is")(input)
    .and_then(|(next, res)| {
        if res.len() == 0 {
            Ok((next, vec![DisplayPart::Empty]))
        }
        else {
            //println!("{}", res.trim_end());
            many1(display_part)(res.trim_end())
            .map(|(_, res)| {
                //println!("{:?}", res);
                (next, res)
            })
        }
    })
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PatternConstraint<'a> {
    Eq((&'a str, u64)),
    Neq((&'a str, u64)),
    Less((&'a str, u64)),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PatternExpr<'a> {
    Constraint(PatternConstraint<'a>),
    And((Box<PatternExpr<'a>>, Box<PatternExpr<'a>>)),
    Or((Box<PatternExpr<'a>>, Box<PatternExpr<'a>>)),
    Concat((Box<PatternExpr<'a>>, Box<PatternExpr<'a>>)),
    Extend(Box<PatternExpr<'a>>),
    Constructor(&'a str),
    Empty
}

fn eq_constraint(input: &str) -> Res<&str, PatternConstraint> {
    separated_pair(
        identifier,
        delimited(space0, char('='), space0),
        num
    )(input)
    .map(|(next, res)| {
        (next, PatternConstraint::Eq(res))
    })
}

fn neq_constraint(input: &str) -> Res<&str, PatternConstraint> {
    separated_pair(
        identifier,
        delimited(space0, tag("!="), space0),
        num
    )(input)
    .map(|(next, res)| {
        (next, PatternConstraint::Neq(res))
    })
}

fn less_constraint(input: &str) -> Res<&str, PatternConstraint> {
    separated_pair(
        identifier,
        delimited(space0, tag("<"), space0),
        num
    )(input)
    .map(|(next, res)| {
        (next, PatternConstraint::Less(res))
    })
}

fn constraint_pattern(input: &str) -> Res<&str, Box<PatternExpr>> {
    alt((eq_constraint, neq_constraint, less_constraint))(input)
    .map(|(next, res)| {
        (next, Box::new(PatternExpr::Constraint(res)))
    })
}

fn constructor_pattern(input: &str) -> Res<&str, Box<PatternExpr>> {
    identifier(input)
    .map(|(next, res)| {
        (next, Box::new(PatternExpr::Constructor(res)))
    })
}

fn _pattern_expr(input: &str) -> Res<&str, Box<PatternExpr>> {
    let (rest, expr) = alt((
        constraint_pattern,
        constructor_pattern,
        delimited(
            terminated(char('('), space0),
            pattern_expr,
            preceded(space0, char(')'))
        )
    ))(input)?;

    let rest_rest = rest.trim_start();
    if rest_rest.len() >= 3 && &rest_rest[0..3] == "..." {
        //let extend_expr = Box::new(PatternExpr::Extend(expr));
        //return Ok((&rest_rest[3..rest_rest.len()], extend_expr));
        return Ok((&rest_rest[3..rest_rest.len()], expr));
    }

    Ok((rest, expr))
}

fn pattern_expr(input: &str) -> Res<&str, Box<PatternExpr>> {
    //println!("{}", &input[0..20]);
    let (input, first_expr) = _pattern_expr(input)?;
    let (input, ops) = many0(
        pair(
            delimited(
                multispace0,
                alt((
                    tag("&"), tag("|"), tag(";"),
                )),
                multispace0
            ),
            _pattern_expr
        )
    )(input)?;
    let (input, _) = take_while(is_space_char)(input)?;

    let mut expr = first_expr;

    for (op, operand) in ops {
        expr = match op {
            "&" => Box::new(PatternExpr::And((expr, operand))),
            "|" => Box::new(PatternExpr::Or((expr, operand))),
            ";" => Box::new(PatternExpr::Concat((expr, operand))),
            _ => unreachable!("Unimplemented pattern opcode")
        }
    }

    /*if input.len() >= 3 && &input[0..3] == "..." {
        expr = Box::new(PatternExpr::Extend(expr));
        return Ok((&input[3..input.len()], expr));
    }*/

    //println!("{:?}", expr);
    Ok((input, expr))
}

fn pattern_section(input: &str) -> Res<&str, Box<PatternExpr>> {
    preceded(
        terminated(tag("is"), space1),
        pattern_expr
    )(input)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DisassemblyExpr<'a> {
    Add((Box<DisassemblyExpr<'a>>, Box<DisassemblyExpr<'a>>)),
    Sub((Box<DisassemblyExpr<'a>>, Box<DisassemblyExpr<'a>>)),
    Mult((Box<DisassemblyExpr<'a>>, Box<DisassemblyExpr<'a>>)),
    Div((Box<DisassemblyExpr<'a>>, Box<DisassemblyExpr<'a>>)),
    ShiftLeft((Box<DisassemblyExpr<'a>>, Box<DisassemblyExpr<'a>>)),
    ShiftRight((Box<DisassemblyExpr<'a>>, Box<DisassemblyExpr<'a>>)),
    BitAnd((Box<DisassemblyExpr<'a>>, Box<DisassemblyExpr<'a>>)),
    BitOr((Box<DisassemblyExpr<'a>>, Box<DisassemblyExpr<'a>>)),
    BitXor((Box<DisassemblyExpr<'a>>, Box<DisassemblyExpr<'a>>)),
    BitNot(Box<DisassemblyExpr<'a>>),
    Ident(&'a str),
    NUM(u64)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DisassemblyAction<'a> {
    lvalue: &'a str,
    rvalue: Box<DisassemblyExpr<'a>>
}

fn bit_not_disas_expr(input: &str) -> Res<&str, Box<DisassemblyExpr>> {
    preceded(char('~'), disassembly_expr)(input)
    .map(|(next, res)| {
        (next, Box::new(DisassemblyExpr::BitNot(res)))
    })
}

fn constructor_disas_expr(input: &str) -> Res<&str, Box<DisassemblyExpr>> {
    identifier(input)
    .map(|(next, res)| {
        (next, Box::new(DisassemblyExpr::Ident(res)))
    })
}

fn num_disas_expr(input: &str) -> Res<&str, Box<DisassemblyExpr>> {
    num(input)
    .map(|(next, res)| {
        (next, Box::new(DisassemblyExpr::NUM(res)))
    })
}

fn _disassembly_expr(input: &str) -> Res<&str, Box<DisassemblyExpr>> {
    alt((
        constructor_disas_expr,
        num_disas_expr,
        bit_not_disas_expr,
        delimited(
            char('('),
            disassembly_expr,
            char(')')
        )
    ))(input)
}

fn disassembly_expr(input: &str) -> Res<&str, Box<DisassemblyExpr>> {
    let (input, first_expr) = _disassembly_expr(input)?;
    let (input, ops) = many0(
        pair(
            delimited(
                space0,
                alt((tag("&"), tag("|"), tag("^"),
                     tag("+"), tag("-"), tag("*"), tag("/"),
                     tag(">>"), tag("<<"),
                     tag("$and"), tag("$or")
                )),
                space0
            ),
            _disassembly_expr
        )
    )(input)?;

    let mut expr = first_expr;

    for (op, operand) in ops {
        expr = match op {
            "&" => Box::new(DisassemblyExpr::BitAnd((expr, operand))),
            "|" => Box::new(DisassemblyExpr::BitOr((expr, operand))),
            "^" => Box::new(DisassemblyExpr::BitXor((expr, operand))),
            "+" => Box::new(DisassemblyExpr::Add((expr, operand))),
            "-" => Box::new(DisassemblyExpr::Sub((expr, operand))),
            "*" => Box::new(DisassemblyExpr::Mult((expr, operand))),
            "/" => Box::new(DisassemblyExpr::Div((expr, operand))),
            "<<" => Box::new(DisassemblyExpr::ShiftLeft((expr, operand))),
            ">>" => Box::new(DisassemblyExpr::ShiftRight((expr, operand))),
            "$and" => Box::new(DisassemblyExpr::BitAnd((expr, operand))),
            "$or" => Box::new(DisassemblyExpr::BitOr((expr, operand))),
            _ => unreachable!("Unimplemented disassembly action opcode")
        }
    }

    println!("{:?}", expr);
    Ok((input, expr))
}

fn disassembly_action(input: &str) -> Res<&str, DisassemblyAction> {
    separated_pair(
        identifier,
        delimited(space0, char('='), space0),
        terminated(disassembly_expr, char(';'))
    )(input)
    .map(|(next, res)| {
        //println!("{:?}", res);
        (next, DisassemblyAction { lvalue: res.0, rvalue: res.1 })
    })
}

fn disassembly_actions(input: &str) -> Res<&str, &str> {
    terminated(
        preceded(
            char('['),
            take_until("]")
        ),
        char(']')
    )(input)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SemanticExprGotoDest<'a> {
    Ident(&'a str),
    Label(&'a str)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SemanticExprCallDest<'a> {
    Ident(&'a str),
    Indirect(&'a str)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SemanticExprVariable<'a> {
    name: &'a str,
    size: Option<u64>
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SemanticExprRef<'a> {
    space: Option<&'a str>,
    size: u64,
    ptr: Box<SemanticExprValue<'a>>
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SemanticExprLvalue<'a> {
    Var(SemanticExprVariable<'a>),
    Ref(Box<SemanticExprRef<'a>>)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SemanticExprNum {
    value: u64,
    size: Option<u64>
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SemanticExprValue<'a> {
    Add((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    Sub((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    Mult((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    Div((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    SDiv((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    Rem((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    SRem((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    ShiftLeft((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    ShiftRight((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    SignedShiftRight((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    And((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    Or((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    Xor((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    Less((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    SLess((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    LessEqual((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    SLessEqual((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    Greater((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    SGreater((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    GreaterEqual((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    SGreaterEqual((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    FLess((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    FLessEqual((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    FGreater((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    FGreaterEqual((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    Eq((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    Neq((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    FEq((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    FNeq((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    BoolAnd((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    BoolOr((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    BoolXor((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    BoolNot(Box<SemanticExprValue<'a>>),
    PopCount(Box<SemanticExprValue<'a>>),
    ZEXT(Box<SemanticExprValue<'a>>),
    SEXT(Box<SemanticExprValue<'a>>),
    TwosComp(Box<SemanticExprValue<'a>>),
    NEGATE(Box<SemanticExprValue<'a>>),
    FNEGATE(Box<SemanticExprValue<'a>>),
    ISNAN(Box<SemanticExprValue<'a>>),
    INT2FLOAT(Box<SemanticExprValue<'a>>),
    FLOAT2FLOAT(Box<SemanticExprValue<'a>>),
    TRUNC(Box<SemanticExprValue<'a>>),
    CEIL(Box<SemanticExprValue<'a>>),
    ROUND(Box<SemanticExprValue<'a>>),
    FLOOr(Box<SemanticExprValue<'a>>),
    Carry((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    SCarry((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    Borrow((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    SBorrow((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    UserDefined((&'a str, Vec<Box<SemanticExprValue<'a>>>)),
    Variable(SemanticExprVariable<'a>),
    Ref(Box<SemanticExprRef<'a>>),
    AddrOf((Option<u64>, Box<SemanticExprValue<'a>>)),
    Ident(&'a str),
    NUM(SemanticExprNum),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SemanticExpr<'a> {
    Export(Box<SemanticExprValue<'a>>),
    Build(&'a str),
    LocalAssign((SemanticExprLvalue<'a>, Option<Box<SemanticExprValue<'a>>>),),
    Assign((SemanticExprLvalue<'a>, Box<SemanticExprValue<'a>>),),
    IfGoto((Box<SemanticExprValue<'a>>, SemanticExprGotoDest<'a>)),
    Goto(SemanticExprGotoDest<'a>),
    Label(&'a str),
    PcodeOpCall((&'a str, Vec<Box<SemanticExprValue<'a>>>)),
    Call(SemanticExprCallDest<'a>)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SemanticAction<'a> {
    expr: Box<SemanticExpr<'a>>,
}

fn ident_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    semantic_expr_variable(input)
}

fn num_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    tuple((
        num,
        opt(preceded(
            char(':'),
            num
        ))
    ))(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::NUM(SemanticExprNum { value: res.0, size: res.1 })))
    })
}

fn zext_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    preceded(
        tag("zext"),
        delimited(
            terminated(char('('), space0),
            semantic_expr_value,
            preceded(space0, char(')'))
        )
    )(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::ZEXT(res)))
    })
}

fn sext_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    preceded(
        tag("sext"),
        delimited(
            terminated(char('('), space0),
            semantic_expr_value,
            preceded(space0, char(')'))
        )
    )(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::SEXT(res)))
    })
}

fn popcount_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    preceded(
        tag("popcount"),
        delimited(terminated(char('('), space0), semantic_expr_value, preceded(space0, char(')')))
    )(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::PopCount(res)))
    })
}

fn twos_comp_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    preceded(
        tag("-"),
        delimited(terminated(char('('), space0), semantic_expr_value, preceded(space0, char(')')))
    )(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::TwosComp(res)))
    })
}

fn negate_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    preceded(
        tag("~"),
        delimited(terminated(char('('), space0), semantic_expr_value, preceded(space0, char(')')))
    )(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::NEGATE(res)))
    })
}

fn fnegate_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    preceded(
        tag("f-"),
        delimited(terminated(char('('), space0), semantic_expr_value, preceded(space0, char(')')))
    )(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::FNEGATE(res)))
    })
}

fn nan_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    preceded(
        tag("nan"),
        delimited(terminated(char('('), space0), semantic_expr_value, preceded(space0, char(')')))
    )(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::ISNAN(res)))
    })
}

fn int2float_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    preceded(
        tag("int2float"),
        delimited(terminated(char('('), space0), semantic_expr_value, preceded(space0, char(')')))
    )(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::INT2FLOAT(res)))
    })
}

fn float2float_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    preceded(
        tag("float2float"),
        delimited(terminated(char('('), space0), semantic_expr_value, preceded(space0, char(')')))
    )(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::FLOAT2FLOAT(res)))
    })
}

fn trunc_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    preceded(
        tag("trunc"),
        delimited(terminated(char('('), space0), semantic_expr_value, preceded(space0, char(')')))
    )(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::TRUNC(res)))
    })
}

fn ceil_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    preceded(
        tag("ceil"),
        delimited(terminated(char('('), space0), semantic_expr_value, preceded(space0, char(')')))
    )(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::CEIL(res)))
    })
}

fn floor_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    preceded(
        tag("floor"),
        delimited(terminated(char('('), space0), semantic_expr_value, preceded(space0, char(')')))
    )(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::FLOOr(res)))
    })
}

fn round_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    preceded(
        tag("round"),
        delimited(terminated(char('('), space0), semantic_expr_value, preceded(space0, char(')')))
    )(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::ROUND(res)))
    })
}

fn carry_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    preceded(
        tag("carry"),
        delimited(
            terminated(char('('), space0),
            separated_pair(
                semantic_expr_value,
                terminated(char(','), space0),
                semantic_expr_value,
            ),
            preceded(space0, char(')'))
        )
    )(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::Carry(res)))
    })
}

fn scarry_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    preceded(
        tag("scarry"),
        delimited(
            terminated(char('('), space0),
            separated_pair(
                semantic_expr_value,
                terminated(char(','), space0),
                semantic_expr_value,
            ),
            preceded(space0, char(')'))
        )
    )(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::SCarry(res)))
    })
}

fn borrow_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    preceded(
        tag("borrow"),
        delimited(
            terminated(char('('), space0),
            separated_pair(
                semantic_expr_value,
                terminated(char(','), space0),
                semantic_expr_value,
            ),
            preceded(space0, char(')'))
        )
    )(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::Borrow(res)))
    })
}

fn sborrow_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    preceded(
        tag("sborrow"),
        delimited(
            terminated(char('('), space0),
            separated_pair(
                semantic_expr_value,
                terminated(char(','), space0),
                semantic_expr_value,
            ),
            preceded(space0, char(')'))
        )
    )(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::SBorrow(res)))
    })
}
fn bool_not_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    preceded(
        char('!'),
        alt((
            delimited(
                char('('),
                semantic_expr_value,
                char(')')
            ),
            semantic_expr_value
        ))
    )(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::BoolNot(res)))
    })
}

fn no_param_semantic_expr_value(input: &str) -> Res<&str, Vec<Box<SemanticExprValue>>> {
    Ok((input, vec![]))
}

fn _user_defined_semantic_expr_value(input: &str) -> Res<&str, (&str, Vec<Box<SemanticExprValue>>)> {
    tuple((
        identifier,
        delimited(
            terminated(char('('), space0),
            separated_list0(terminated(char(','), space0), semantic_expr_value),
            preceded(space0, char(')'))
        )
    ))(input)
}

fn user_defined_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    //println!("hello? {}", &input[0..20]);
    _user_defined_semantic_expr_value(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::UserDefined(res)))
    })
}

fn _ref_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprRef>> {
    tuple((
        preceded(
            char('*'),
            opt(delimited(
                char('['),
                identifier,
                char(']')
            ))
        ),
        preceded(
            char(':'),
            num
        ),
        preceded(
            space1,
            semantic_expr_value
        )
    ))(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprRef { space: res.0, size: res.1, ptr: res.2 }))
    })
}

fn addrof_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    preceded(
        char('&'),
        tuple((
            opt(preceded(char(':'), num)),
            preceded(space0, semantic_expr_value)
        ))
    )(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::AddrOf(res)))
    })
}

fn ref_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    _ref_semantic_expr_value(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::Ref(res)))
    })
}

fn ref_semantic_expr_value_lvalue(input: &str) -> Res<&str, SemanticExprLvalue> {
    _ref_semantic_expr_value(input)
    .map(|(next, res)| {
        (next, SemanticExprLvalue::Ref(res))
    })
}

fn _semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    alt((
        alt((bool_not_semantic_expr_value,
        twos_comp_semantic_expr_value,
        negate_semantic_expr_value,
        fnegate_semantic_expr_value)),
        sext_semantic_expr_value,
        zext_semantic_expr_value,
        popcount_semantic_expr_value,
        alt((nan_semantic_expr_value,
        int2float_semantic_expr_value,
        float2float_semantic_expr_value)),
        alt((trunc_semantic_expr_value,
        ceil_semantic_expr_value,
        floor_semantic_expr_value,
        round_semantic_expr_value,
        carry_semantic_expr_value,
        scarry_semantic_expr_value,
        borrow_semantic_expr_value,
        sborrow_semantic_expr_value)),
        user_defined_semantic_expr_value,
        ident_semantic_expr_value,
        num_semantic_expr_value,
        ref_semantic_expr_value,
        addrof_semantic_expr_value,
        delimited(
            terminated(char('('), multispace0),
            semantic_expr_value,
            preceded(multispace0, char(')'))
        )
    ))(input)
    .map(|(next, res)| {
        //println!("{:?} {}", res, &next[0..20]);
        (next, res)
    })
}

fn semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    let (input, first_expr) = _semantic_expr_value(input)?;
    let (input, ops) = many0(
        pair(
            delimited(
                multispace0,
                alt((
                    tag("+"), tag("-"), tag("*"),
                    alt((tag("/"), tag("s/"), tag("%"), tag("s%"))),
                    alt((tag("<<"), tag(">>"), tag("s>>"))),
                    tag("=="), tag("!="),
                    alt((tag("&&"), tag("||"), tag("^^"))),
                    alt((tag("&"), tag("|"), tag("^"))),
                    alt((tag("<"), tag("s<"), tag(">"), tag("s>"))),
                    alt((tag("<="), tag("s<="), tag("s>"), tag("s>="))),
                    alt((tag("f<"), tag("f>"), tag("f<="), tag("f>="))),
                    tag("f=="), tag("f!="),
                    tag("f*"), tag("f/"), tag("f%")
                )),
                multispace0
            ),
            _semantic_expr_value
        )
    )(input)?;

    let mut expr = first_expr;

    for (op, operand) in ops {
        expr = match op {
            "+" => Box::new(SemanticExprValue::Add((expr, operand))),
            "-" => Box::new(SemanticExprValue::Sub((expr, operand))),
            "*" => Box::new(SemanticExprValue::Mult((expr, operand))),
            "/" => Box::new(SemanticExprValue::Div((expr, operand))),
            "s/" => Box::new(SemanticExprValue::SDiv((expr, operand))),
            "%" => Box::new(SemanticExprValue::Rem((expr, operand))),
            "s%" => Box::new(SemanticExprValue::SRem((expr, operand))),
            "<<" => Box::new(SemanticExprValue::ShiftLeft((expr, operand))),
            ">>" => Box::new(SemanticExprValue::ShiftRight((expr, operand))),
            "s>>" => Box::new(SemanticExprValue::SignedShiftRight((expr, operand))),
            "&" => Box::new(SemanticExprValue::And((expr, operand))),
            "|" => Box::new(SemanticExprValue::Or((expr, operand))),
            "^" => Box::new(SemanticExprValue::Xor((expr, operand))),
            "<" => Box::new(SemanticExprValue::Less((expr, operand))),
            "s<" => Box::new(SemanticExprValue::SLess((expr, operand))),
            "<=" => Box::new(SemanticExprValue::LessEqual((expr, operand))),
            "s<=" => Box::new(SemanticExprValue::SLessEqual((expr, operand))),
            ">" => Box::new(SemanticExprValue::Greater((expr, operand))),
            "s>" => Box::new(SemanticExprValue::SGreater((expr, operand))),
            ">=" => Box::new(SemanticExprValue::GreaterEqual((expr, operand))),
            "s>=" => Box::new(SemanticExprValue::SGreaterEqual((expr, operand))),
            "f<" => Box::new(SemanticExprValue::FLess((expr, operand))),
            "f<=" => Box::new(SemanticExprValue::FLessEqual((expr, operand))),
            "f>" => Box::new(SemanticExprValue::FGreater((expr, operand))),
            "f>=" => Box::new(SemanticExprValue::FGreaterEqual((expr, operand))),
            "f==" => Box::new(SemanticExprValue::FEq((expr, operand))),
            "f!=" => Box::new(SemanticExprValue::FNeq((expr, operand))),
            "==" => Box::new(SemanticExprValue::Eq((expr, operand))),
            "!=" => Box::new(SemanticExprValue::Neq((expr, operand))),
            "&&" => Box::new(SemanticExprValue::BoolAnd((expr, operand))),
            "||" => Box::new(SemanticExprValue::BoolOr((expr, operand))),
            "^^" => Box::new(SemanticExprValue::BoolXor((expr, operand))),
            _ => unreachable!()
        }
    }

    println!("{:?}", expr);
    Ok((input, expr))
}

fn export_semantic_expr(input: &str) -> Res<&str, Box<SemanticExpr>> {
    preceded(terminated(tag("export"), space1), semantic_expr_value)(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExpr::Export(res)))
    })
}

fn ident_semantic_expr_dest(input: &str) -> Res<&str, SemanticExprGotoDest> {
    identifier(input)
    .map(|(next, res)| {
        (next, SemanticExprGotoDest::Ident(res))
    })
}

fn goto_label_semantic_expr(input: &str) -> Res<&str, SemanticExprGotoDest> {
    delimited(
        char('<'),
        identifier,
        char('>'),
    )(input)
    .map(|(next, res)| {
        (next, SemanticExprGotoDest::Label(res))
    })
}

fn goto_dest_semantic_expr(input: &str) -> Res<&str, SemanticExprGotoDest> {
    alt((goto_label_semantic_expr, ident_semantic_expr_dest))(input)
}

fn label_semantic_expr(input: &str) -> Res<&str, Box<SemanticExpr>> {
    delimited(
        char('<'),
        identifier,
        char('>'),
    )(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExpr::Label(res)))
    })
}

fn ifgoto_semantic_expr(input: &str) -> Res<&str, Box<SemanticExpr>> {
    //println!("{}", &input[0..50]);
    tuple((
        delimited(
            terminated(tag("if"), space1),
            delimited(
                terminated(char('('), space0),
                semantic_expr_value,
                preceded(space0, char(')'))
            ),
            space1
        ),
        preceded(
            terminated(tag("goto"), space1),
            goto_dest_semantic_expr
        )
    ))(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExpr::IfGoto(res)))
    })
}

fn goto_semantic_expr(input: &str) -> Res<&str, Box<SemanticExpr>> {
    //println!("goto hello? {}", &input[0..20]);
    preceded(
        terminated(tag("goto"), space1),
        goto_dest_semantic_expr
    )(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExpr::Goto(res)))
    })
}

fn build_semantic_expr(input: &str) -> Res<&str, Box<SemanticExpr>> {
    //println!("build hello? {}", &input[0..20]);
    preceded(terminated(tag("build"), space1), identifier)(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExpr::Build(res)))
    })
}

fn _semantic_expr_variable(input: &str) -> Res<&str, SemanticExprVariable> {
    tuple((
        identifier,
        opt(preceded(char(':'), num))
    ))(input)
    .map(|(next, res)| {
        (next, SemanticExprVariable { name: res.0, size: res.1 })
    })
}

fn semantic_expr_variable(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    _semantic_expr_variable(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::Variable(res)))
    })
}

fn semantic_expr_variable_lvalue(input: &str) -> Res<&str, SemanticExprLvalue> {
    _semantic_expr_variable(input)
    .map(|(next, res)| {
        (next, SemanticExprLvalue::Var(res))
    })
}

fn semantic_expr_lvalue(input: &str) -> Res<&str, SemanticExprLvalue> {
    alt((semantic_expr_variable_lvalue, ref_semantic_expr_value_lvalue))(input)
}

fn local_assign_semantic_expr(input: &str) -> Res<&str, Box<SemanticExpr>> {
    //println!("local hello? {}", &input[0..20]);
    preceded(
        terminated(tag("local"), space1),
        tuple((
            semantic_expr_lvalue,
            opt(preceded(
                delimited(space0, char('='), space0),
                semantic_expr_value
            ))
        ))
    )(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExpr::LocalAssign(res)))
    })
}

fn assign_semantic_expr(input: &str) -> Res<&str, Box<SemanticExpr>> {
    //println!("assign hello? {}", &input[0..20]);
    separated_pair(
        semantic_expr_lvalue,
        delimited(space0, char('='), space0),
        semantic_expr_value
    )(input)
    .map(|(next, res)| {
        //println!("{:?}", res);
        (next, Box::new(SemanticExpr::Assign(res)))
    })
}

fn pcodeop_call_semantic_expr(input: &str) -> Res<&str, Box<SemanticExpr>> {
    //println!("call hello? {}", &input[0..20]);
    _user_defined_semantic_expr_value(input)
    .map(|(next, res)| {
        //println!("{:?}", res);
        (next, Box::new(SemanticExpr::PcodeOpCall(res)))
    })
}

fn call_dest_identifier(input: &str) -> Res<&str, SemanticExprCallDest> {
    identifier(input)
    .map(|(next, res)| {
        (next, SemanticExprCallDest::Ident(res))
    })
}

fn call_dest_indirect(input: &str) -> Res<&str, SemanticExprCallDest> {
    delimited(
        char('['),
        identifier,
        char(']'),
    )(input)
    .map(|(next, res)| {
        (next, SemanticExprCallDest::Indirect(res))
    })
}

fn call_dest_semantic_expr_value(input: &str) -> Res<&str, SemanticExprCallDest> {
    alt((call_dest_identifier, call_dest_indirect))(input)
}

fn call_semantic_expr(input: &str) -> Res<&str, Box<SemanticExpr>> {
    //println!("call hello? {}", &input[0..20]);
    //_user_defined_semantic_expr_value(input)
    preceded(
        terminated(tag("call"), space1),
        call_dest_semantic_expr_value
    )(input)
    .map(|(next, res)| {
        //println!("{:?}", res);
        (next, Box::new(SemanticExpr::Call(res)))
    })
}

fn semantic_expr(input: &str) -> Res<&str, Box<SemanticExpr>> {
    alt((
        ifgoto_semantic_expr,
        goto_semantic_expr,
        export_semantic_expr,
        build_semantic_expr,
        local_assign_semantic_expr,
        assign_semantic_expr,
        call_semantic_expr,
        pcodeop_call_semantic_expr
    ))(input)
    .map(|(next, res)| {
        println!("{:?}", res);
        (next, res)
    })
}

fn semantic_action(input: &str) -> Res<&str, SemanticAction> {
    alt((
        label_semantic_expr,
        terminated(semantic_expr, preceded(space0, char(';')))
    ))(input)
    .and_then(|(next, res)| {
        let action = SemanticAction { expr: res };
        for c in next.chars().skip_while(|&c| c.is_whitespace()) {
            if c == '#' {
                return line_end_comment_without_newline(next)
                        .map(|(next, _)| {
                            (next, action)
                        })
            }
            break;
        }
        Ok((next, action))
    })
    /*.map(|(next, res)| {
        //println!("{:?}", res);
        (next, SemanticAction { expr: res })
    })*/
}

fn single_semantic_action(input: &str) -> Res<&str, Vec<SemanticAction>> {
    semantic_action(input)
    .map(|(next, res)| {
        (next, vec![res])
    })
}

fn semantic_actions(input: &str) -> Res<&str, &str> {
    //println!("HERE {}", &input[0..50]);
    terminated(
        preceded(
            char('{'),
            take_until("}")
        ),
        char('}')
    )(input)
    .and_then(|(next, res)| {
        for c in next.chars().skip_while(|&c| c.is_whitespace()) {
            if c == '#' {
                return line_end_comment_without_newline(next)
                        .map(|(next, _)| {
                            (next, res)
                        })
            }
            break;
        }
        Ok((next, res))
    })
    /*.map(|(next, res)| {
        println!("{:?}", res);
        (next, res)
    })*/
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConstructorStmt<'a> {
    table: &'a str,
    display: Vec<DisplayPart<'a>>,
    pattern: Box<PatternExpr<'a>>,
    actions: Option<&'a str>,
    semantics: &'a str
}

fn is_not_colon(chr: char) -> bool {
    chr != ':'
}

fn table_header(input: &str) -> Res<&str, &str> {
    terminated(
        take_while(is_not_colon),
        char(':')
    )(input)
    .map(|(next, res)| {
        //println!("table \"{}\"", res);
        if res.len() == 0 {
            (next, "instruction")
        }
        else {
            (next, res)
        }
    })
}

fn constructor(input: &str) -> Res<&str, Stmt> {
    tuple((
        terminated(table_header, space0),
        display_section,
        terminated(pattern_section, multispace0),
        opt(terminated(disassembly_actions, multispace0)),
        terminated(semantic_actions, space0),
    ))(input)
    .map(|(next, res)| {
        let constructor = ConstructorStmt {
            table: res.0,
            display: res.1,
            pattern: res.2,
            actions: res.3,
            semantics: res.4
        };
        //println!("{:#?}", Stmt::Constructor(constructor.clone()));
        (next, Stmt::Constructor(constructor))
    })
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MacroStmt<'a> {
    name: &'a str,
    params: Vec<&'a str>,
    body: &'a str
}

fn sleigh_macro(input: &str) -> Res<&str, Stmt> {
    tuple((
        preceded(terminated(preceded(space0, tag("macro")), space1), identifier),
        terminated(
            delimited(
                terminated(preceded(multispace0, char('(')), multispace0),
                separated_list0(terminated(char(','), space0), identifier),
                preceded(multispace0, char(')'))
            ),
            space0
        ),
        semantic_actions
    ))(input)
    .map(|(next, res)| {
        let mac = MacroStmt {
            name: res.0,
            params: res.1,
            body: res.2,
        };
        //println!("{:#?}", Stmt::Macro(mac.clone()));
        (next, Stmt::Macro(mac))
    })
}

type DecisionTreeInner<'a> = (
    &'a mut Vec<Vec<u8>>,
    &'a mut Vec<&'a str>,
    &'a mut Vec<Vec<Vec<u8>>>
);

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DecisionTree<'a> {
    context_masks: Vec<Vec<u8>>,
    token_names: Vec<&'a str>,
    token_masks: Vec<Vec<Vec<u8>>>
}

#[repr(u8)]
#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug)]
pub enum TernaryBit {
    DontCare = 1,
    Zero,
    One,
    Always
}

impl<'a> TernaryBit {
    pub fn from(value: u8) -> Self {
        match value {
            0 => TernaryBit::Zero,
            1 => TernaryBit::One,
            _ => panic!()
        }
    }

    pub fn or(&self, other: u8) -> Self {
        match TernaryBit::from(other) {
            TernaryBit::Zero => {
                match self {
                    TernaryBit::Zero => TernaryBit::Zero,
                    TernaryBit::One => TernaryBit::One,
                    TernaryBit::Always => TernaryBit::Always,
                    _ => TernaryBit::Zero
                }
            },
            TernaryBit::One => {
                match self {
                    TernaryBit::Zero => TernaryBit::One,
                    TernaryBit::One => TernaryBit::One,
                    TernaryBit::Always => TernaryBit::Always,
                    _ => TernaryBit::Zero
                }
            },
            TernaryBit::Always => {
                TernaryBit::Always
            },
            _ => *self
        }
    }

    pub fn and(&self, other: &TernaryBit) -> Self {
        match other {
            TernaryBit::DontCare => *other,
            TernaryBit::Zero => TernaryBit::Zero,
            TernaryBit::One => {
                match self {
                    TernaryBit::Zero => TernaryBit::Zero,
                    TernaryBit::One => TernaryBit::One,
                    TernaryBit::Always => TernaryBit::Always,
                    _ => TernaryBit::DontCare
                }
            },
            TernaryBit::Always => {
                match self {
                    TernaryBit::Zero => TernaryBit::Zero,
                    TernaryBit::One => TernaryBit::Always,
                    TernaryBit::Always => TernaryBit::Always,
                    _ => TernaryBit::DontCare
                }
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BitPattern<'a> {
    Context(Vec<TernaryBit>),
    Token((&'a str, Vec<TernaryBit>)),
    Concat((Box<BitPattern<'a>>, Box<BitPattern<'a>>)),
}

fn _eval_eq_constraint<'a>(val: u64, size: usize, start: usize, totalSize: usize) -> Vec<TernaryBit> {
    let mut mask: Vec<TernaryBit> = Vec::with_capacity(totalSize);
    for _ in 0..totalSize {
        mask.push(TernaryBit::DontCare);
    }
    for i in 0..size {
        let bit = ((val >> i) & 1) as u8;
        mask[start + i] = mask[start + i].or(bit);
    }
    return mask;
}

fn _eval_token<'a>(val: u64, size: usize, start: usize, totalSize: usize) -> Vec<TernaryBit> {
    let mut mask: Vec<TernaryBit> = Vec::with_capacity(totalSize);
    for _ in 0..totalSize {
        mask.push(TernaryBit::DontCare);
    }
    for i in 0..size {
        let bit = ((val >> i) & 1) as u8;
        mask[start + i] = mask[start + i].or(bit);
    }
    return mask;
}

fn _eval_field<'a>(size: usize, start: usize, totalSize: usize) -> Vec<TernaryBit> {
    let mut mask: Vec<TernaryBit> = Vec::with_capacity(totalSize);
    for _ in 0..totalSize {
        mask.push(TernaryBit::DontCare);
    }
    for i in 0..size {
        mask[start + i] = TernaryBit::Always;
    }
    return mask;
}

fn eval_eq_constraint<'a>
(
    field_name: &'a str,
    val: u64,
    tokens: &'a HashMap<&'a str, (&'a Token<'a>, &'a TokenField)>,
    ctx_reg: &BitRange,
    ctx_fields: &HashMap<&'a str, &BitRange>
) -> Vec<(Option<BitPattern<'a>>, BitPattern<'a>)>
{
    if let Some(ctx_field) = ctx_fields.get(field_name) {
        println!("{}, {:?}", field_name, ctx_field);
        let mask = _eval_eq_constraint(val, ctx_field.len as usize, ctx_field.start as usize, ctx_reg.len as usize);
        return vec![(BitPattern::Context(mask)), vec![]);
    }
    else if let Some((token, token_field)) = tokens.get(field_name) {
        let mask = _eval_eq_constraint(val, token_field.range.len as usize, token_field.range.start as usize, token.bit_size as usize);
        return (None, vec![BitPattern::Token((token.name, mask))]);
    }
    else {
        panic!("Pattern op is neither a context field nor a token field");
    }
}

fn eval_constraint<'a>
(
    constraint: &PatternConstraint<'a>,
    tokens: &'a HashMap<&'a str, (&'a Token<'a>, &TokenField)>,
    ctx_reg: &BitRange,
    ctx_fields: &HashMap<&'a str, &BitRange>
) -> Vec<BitPattern<'a>>
{
    match constraint {
        PatternConstraint::Eq((field_name, val)) => eval_eq_constraint(field_name, *val, &tokens, &ctx_reg, &ctx_fields),
        _ => todo!()
    }
}

fn _eval_and(lhs: &Vec<TernaryBit>, rhs: &Vec<TernaryBit>) -> Vec<TernaryBit> {
    let mut res: Vec<TernaryBit> = Vec::with_capacity(lhs.len());
    for _ in 0..lhs.len() {
        res.push(TernaryBit::DontCare);
    }
    for (i, (bit1, bit2)) in lhs.iter().zip(rhs.iter()).enumerate() {
        res[i] = bit1.and(bit2);
    }
    return res;
}

fn eval_and<'a>(lhs: &BitPattern<'a>, rhs: &BitPattern<'a>) -> BitPattern<'a> {
    if let (BitPattern::Context(mask1), BitPattern::Context(mask2)) = (lhs, rhs) {
        BitPattern::Context(_eval_and(mask1, mask2))
    }
    else if let (BitPattern::Token((tok1, mask1)), BitPattern::Token((tok2, mask2))) = (lhs, rhs) {
        if tok1 != tok2 {
            panic!("Tokens should match");
        }
        BitPattern::Token((tok2, _eval_and(mask1, mask2)))
    }
    else {
        panic!("Don't know how to combine bit patterns {:?} and {:?}", lhs, rhs);
    }
    /*else if let (BitPattern::Context(mask1), BitPattern::Token((tok2, mask2))) = (lhs, rhs) {
        BitPattern::Concat((
            Box::new(BitPattern::Context(mask1.clone())),
            Box::new(BitPattern::Token((tok2, mask2.clone())))
        ))
    }
    else if let (BitPattern::Token((tok1, mask1)), BitPattern::Context(mask2)) = (lhs, rhs) {
        BitPattern::Concat((
            Box::new(BitPattern::Token((tok1, mask1.clone()))),
            Box::new(BitPattern::Context(mask2.clone()))
        ))
    }*/
}

fn eval_pattern<'a>
(
    pattern: &PatternExpr<'a>,
    constructors: &'a HashMap<&'a str, Vec<PatternExpr<'a>>>,
    tokens: &'a HashMap<&'a str, (&'a Token<'a>, &TokenField)>,
    ctx_reg: &BitRange,
    ctx_fields: &HashMap<&'a str, &BitRange>
) -> Vec<(Option<BitPattern<'a>>, BitPattern<'a>)>
{
    println!("{:#?}", pattern);
    let pats = match pattern {
        PatternExpr::Constraint(constraint) => {
            eval_constraint(&constraint, &tokens, &ctx_reg, &ctx_fields)
        },
        PatternExpr::And((lhs_pat, rhs_pat)) => {
            let l_pats = eval_pattern(lhs_pat, constructors, &tokens, &ctx_reg, &ctx_fields);
            let r_pats = eval_pattern(rhs_pat, constructors, &tokens, &ctx_reg, &ctx_fields);
            let mut pats: Vec<BitPattern> = Vec::with_capacity(lhs_pats.len() * rhs_pats.len());

            for (l_ctx, l_pat) in &l_pats {
                for (r_ctx, r_pat) in &r_pats {
                    let ctx = eval_and(&l_ctx, &r_ctx);
                    let pat = eval_and(&lhs, &rhs)
                    let _ = &pats.push((ctx, pat));
                }
            }

            pats
        },
        PatternExpr::Concat((lhs_pat, rhs_pat)) => {
            let l_pats = eval_pattern(lhs_pat, constructors, &tokens, &ctx_reg, &ctx_fields);
            let r_pats = eval_pattern(rhs_pat, constructors, &tokens, &ctx_reg, &ctx_fields);
            let mut pats: Vec<BitPattern> = Vec::with_capacity(lhs_pats.len() + rhs_pats.len());

            for (l_ctx, l_pat) in &l_pats {
                for (r_ctx, r_pat) in &r_pats {
                    let ctx = eval_and(&l_ctx, &r_ctx);
                    let pat = BitPattern::Concat((Box::new(lhs.clone()), Box::new(rhs.clone())))
                    let _ = &pats.push((ctx, pat));
                }
            }

            pats
        },
        PatternExpr::Constructor(child_table_name) => {
            if let Some((token, token_field)) = tokens.get(child_table_name) {
                let bits = _eval_field(token_field.range.len as usize, token_field.range.start as usize, token.bit_size as usize);
                vec![(None, BitPattern::Token((token.name, bits)))]
            }
            else {
                eval_table(child_table_name, constructors, tokens, ctx_reg, ctx_fields)
            }
        },
        _ => todo!()
    };
    
    println!("Created pattern {:?} with context {:?}", pats, ctx);
    return pats;
}

fn eval_table<'a>(
    table_name: &'a str,
    constructors: &'a HashMap<&'a str, Vec<PatternExpr>>,
    tokens: &'a HashMap<&'a str, (&'a Token<'a>, &TokenField)>,
    ctx_reg: &BitRange,
    ctx_fields: &HashMap<&'a str, &BitRange>
) -> Vec<(Option<BitPattern<'a>>, BitPattern<'a>)>
{
    let mut all_pats = vec![];

    if let Some(patterns) = constructors.get(table_name) {
        for pattern in patterns {
            let pats = eval_pattern(pattern, constructors, tokens, ctx_reg, ctx_fields);
            all_pats.extend(pats);
        }
    }

    return all_pats;
}

fn main() {
    let lang = get_language("x86", "x86:LE:64:default").unwrap();

    let contents = read_file("output.txt");
    let sleigh = match program(&contents) {
        Ok((_, prog)) => prog,
        _ => panic!()
    };

    let mut token_fields: HashMap<&str, (&Token, &TokenField)> = HashMap::new();
    for stmt in &sleigh.stmts {
        if let Stmt::Define(DefineStmt::Token(token)) = stmt {
            for field in &token.fields {
                token_fields.insert(field.name, (token, field));
            }
        }
    }

    // Create a bit vector for the entire register space.
    let mut reg_space_size: usize = 0;
    let mut registers = HashMap::new();
    let mut ctx_fields = HashMap::new();
    let mut ctx_reg_name: Option<&str> = None;

    for stmt in &sleigh.stmts {
        if let Stmt::Define(DefineStmt::Names(defns)) = stmt {
            if defns.name != "register" {
                continue;
            }

            let mut off = defns.offset;

            for name in &defns.names {
                if let SpaceName::Name(reg_name) = name {
                    //println!("{}", reg_name);
                    registers.insert(reg_name, BitRange { start: off * 8, len: defns.size * 8 });
                }

                off += defns.size;
            }

            reg_space_size = reg_space_size.max(off as usize);
        }
        else if let Stmt::Define(DefineStmt::Context(ctx_defn)) = stmt {
            ctx_reg_name = Some(ctx_defn.register);

            for field in &ctx_defn.fields {
                ctx_fields.insert(field.name, &field.range);
            }
        }
    }
    let ctx_base = &registers[&ctx_reg_name.unwrap()];

    // TODO: Figure out how to properly initialize the BitVec.
    let mut reg_space: BitVec<u8, Lsb0> = BitVec::with_capacity(reg_space_size * 8);
    for _ in 0..(reg_space_size * 8) {
        reg_space.push(false);
    }

    for (var, val) in lang.pspec.defaults {
        if let Some(range) = ctx_fields.get(&*var) {
            let start = (ctx_base.start + range.start) as usize;
            let end = start + (range.len as usize);
            reg_space[start .. end].store_le(val);
        }
    }
    //println!("{:?}", reg_space);

    let mut constructors: HashMap<&str, Vec<PatternExpr>> = HashMap::new();
    let mut tables: HashMap<&str, Vec<BitPattern>> = HashMap::new();

    for stmt in &sleigh.stmts {
        if let Stmt::Constructor(constructor) = stmt {
            let table_name = constructor.table;
            constructors.entry(table_name).or_insert(vec![]).push(*constructor.pattern.clone());
        }
    }

    for (table_name, _) in constructors.iter() {
        if tables.get(table_name) == None {
            println!("Processing {}", table_name);
            let pats = eval_table(table_name, &constructors, &token_fields, &ctx_base, &ctx_fields);
            tables.insert(table_name, pats);
        }
    }
    
    let data: [u8; 1] = [0x55];
}
