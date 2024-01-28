extern crate nom;

use nom::character::complete::*;
use nom::bytes::complete::*;
use nom::combinator::*;
use nom::character::*;
use nom::sequence::*;
use nom::branch::*;
use nom::error::*;
use nom::multi::*;
use nom::*;

use std::collections::HashMap;
use std::io::Write;
use std::fs::File;
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
    .map(|(next, res)| {
        (next, Stmt::COMMENT)
    })
}

fn comment(input: &str) -> Res<&str, Stmt> {
    terminated(
        comment_without_newline,
        line_ending)(input)
    .map(|(next, res)| {
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
    alt((define, attach, constructor))(input)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Stmt<'a> {
    DEFINE(DefineStmt<'a>),
    ATTACH(AttachStmt<'a>),
    CONSTRUCTOR(ConstructorStmt<'a>),
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
    WORDSIZE(u64)
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
        (next, SpaceAttribute::WORDSIZE(res.parse::<u64>().unwrap()))
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
        (next, DefineStmt::SPACE(SpaceDefinition { name: res.0, attrs: res.1 }))
    })
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SpaceName<'a> {
    NAME(&'a str),
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
        (next, SpaceName::NAME(res))
    })
}

fn none_space_name(input: &str) -> Res<&str, SpaceName> {
    tag("_")(input)
    .map(|(next, res)| {
        (next, SpaceName::NONE)
    })
}

fn space_name(input: &str) -> Res<&str, SpaceName> {
    alt((name_space_name, none_space_name))(input)
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

fn num(input: &str) -> Res<&str, u64> {
    alt((hex_num, dec_num))(input)
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
        (next, DefineStmt::NAMES(SpaceNamesDefinition { name: res.0, offset: res.1, size: size, names: res.3 }))
    })
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BitRangeDefinition<'a> {
    name: &'a str,
    reg: &'a str,
    bit_start: u64,
    num_bits: u64
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum FieldAttribute {
    SIGNED, HEX, DEC, NOFLOW
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TokenField<'a> {
    name: &'a str,
    bit_start: u64,
    num_bits: u64,
    attrs: Vec<FieldAttribute>
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ContextDefinition<'a> {
    register: &'a str,
    fields: Vec<TokenField<'a>>
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TokenDefinition<'a> {
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
                        bit_start: bit_start,
                        num_bits: (bit_end - bit_start) + 1,
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
        (next, DefineStmt::CONTEXT(ContextDefinition { register: res.0, fields: res.1 }))
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
        (next, DefineStmt::TOKEN(TokenDefinition { name: res.0.0, bit_size: bit_size, fields: res.1 }))
    })
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DefineStmt<'a> {
    ENDIANNESS(Endianness),
    ALIGNMENT(u64),
    SPACE(SpaceDefinition<'a>),
    NAMES(SpaceNamesDefinition<'a>),
    BITRANGE(Vec<BitRangeDefinition<'a>>),
    PCODEOP(&'a str),
    CONTEXT(ContextDefinition<'a>),
    TOKEN(TokenDefinition<'a>),
}

fn pcodeop_define(input: &str) -> Res<&str, DefineStmt> {
    terminated(
        preceded(
            tag("pcodeop "),
            identifier
        ),
        terminated(tag(";"), opt(comment_without_newline))
    )(input)
    .map(|(next, res)| {
        (next, DefineStmt::PCODEOP(res))
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
        (next, BitRangeDefinition { name: res.0, reg: res.1, bit_start: bit_start, num_bits: num_bits })
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
        (next, DefineStmt::BITRANGE(res))
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
        (next, DefineStmt::ENDIANNESS(res))
    })
}

fn alignment_define(input: &str) -> Res<&str, DefineStmt> {
    terminated(
        terminated(
            tag("alignment="),
            digit1),
        terminated(tag(";"), line_ending))(input)
    .map(|(next, res)| {
        (next, DefineStmt::ALIGNMENT(res.parse::<u64>().unwrap()))
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
        println!("{:?}", Stmt::DEFINE(res.clone()));
        (next, Stmt::DEFINE(res))
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
    VARIABLE(VariableAttachStmt<'a>),
    VALUE(ValueAttachStmt<'a>),
}

fn attach_variables(input: &str) -> Res<&str, AttachStmt> {
    delimited(
        terminated(tag("variables"), space1),
        separated_pair(space_name_list, multispace1, space_name_list),
        char(';')
    )(input)
    .map(|(next, res)| {
        (next, AttachStmt::VARIABLE(VariableAttachStmt { fields: res.0, registers: res.1 }))
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
        (next, AttachStmt::VALUE(ValueAttachStmt { fields: res.0, values: res.1 }))
    })
}

fn attach(input: &str) -> Res<&str, Stmt> {
    preceded(
        terminated(tag("attach"), space1),
        alt((attach_variables, attach_values))
    )(input)
    .map(|(next, res)| {
        println!("{:?}", Stmt::ATTACH(res.clone()));
        (next, Stmt::ATTACH(res))
    })
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DisplayPart<'a> {
    LITERAL(char),
    QUOTED_LITERAL(&'a str),
    IDENT(&'a str),
    EMPTY,
    SPACE,
}

fn ident_display_part(input: &str) -> Res<&str, DisplayPart> {
    identifier(input)
    .map(|(next, res)| {
        (next, DisplayPart::IDENT(res))
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
    .map(|(next, res)| {
        (next, DisplayPart::SPACE)
    })
}

fn literal_display_part(input: &str) -> Res<&str, DisplayPart> {
    anychar(input)
    .map(|(next, res)| {
        (next, DisplayPart::LITERAL(res))
    })
}

fn quoted_literal_display_part(input: &str) -> Res<&str, DisplayPart> {
    delimited(
        char('"'),
        take_until("\""),
        char('"')
    )(input)
    .map(|(next, res)| {
        (next, DisplayPart::QUOTED_LITERAL(res))
    })
}

fn display_part(input: &str) -> Res<&str, DisplayPart> {
    alt((
        ident_display_part,
        space_display_part,
        quoted_literal_display_part,
        literal_display_part
    ))(input)
}

fn display_section(input: &str) -> Res<&str, Vec<DisplayPart>> {
    take_until("is")(input)
    .and_then(|(next, res)| {
        if (res.len() == 0) {
            Ok((next, vec![DisplayPart::EMPTY]))
        }
        else {
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
    EQ((&'a str, u64)),
    NEQ((&'a str, u64)),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PatternExpr<'a> {
    CONSTRAINT(PatternConstraint<'a>),
    AND((Box<PatternExpr<'a>>, Box<PatternExpr<'a>>)),
    OR((Box<PatternExpr<'a>>, Box<PatternExpr<'a>>)),
    CONCAT((Box<PatternExpr<'a>>, Box<PatternExpr<'a>>)),
    EXTEND(Box<PatternExpr<'a>>),
    CONSTRUCTOR(&'a str),
    EMPTY
}

fn eq_constraint(input: &str) -> Res<&str, PatternConstraint> {
    separated_pair(
        identifier,
        char('='),
        num
    )(input)
    .map(|(next, res)| {
        (next, PatternConstraint::EQ(res))
    })
}

fn neq_constraint(input: &str) -> Res<&str, PatternConstraint> {
    separated_pair(
        identifier,
        tag("!="),
        num
    )(input)
    .map(|(next, res)| {
        (next, PatternConstraint::NEQ(res))
    })
}

fn constraint_pattern(input: &str) -> Res<&str, Box<PatternExpr>> {
    alt((eq_constraint, neq_constraint))(input)
    .map(|(next, res)| {
        (next, Box::new(PatternExpr::CONSTRAINT(res)))
    })
}

fn constructor_pattern(input: &str) -> Res<&str, Box<PatternExpr>> {
    identifier(input)
    .map(|(next, res)| {
        (next, Box::new(PatternExpr::CONSTRUCTOR(res)))
    })
}

fn extend_pattern(input: &str) -> Res<&str, Box<PatternExpr>> {
    terminated(
        pattern_expr,
        delimited(space0, tag("..."), space0)
    )(input)
    .map(|(next, res)| {
        (next, Box::new(PatternExpr::EXTEND(res)))
    })
}

fn _pattern_expr(input: &str) -> Res<&str, Box<PatternExpr>> {
    alt((
        constraint_pattern,
        constructor_pattern,
        delimited(
            char('('),
            pattern_expr,
            char(')')
        )
    ))(input)
}

fn pattern_expr(input: &str) -> Res<&str, Box<PatternExpr>> {
    let (input, first_expr) = _pattern_expr(input)?;
    let (input, ops) = many0(
        pair(
            delimited(
                space0,
                alt((
                    tag("&"), tag("|"), tag(";"),
                    tag("... &"), tag("... |"),
                )),
                space0
            ),
            _pattern_expr
        )
    )(input)?;

    let mut expr = first_expr;

    for (op, operand) in ops {
        expr = match op {
            "&" => Box::new(PatternExpr::AND((expr, operand))),
            "|" => Box::new(PatternExpr::OR((expr, operand))),
            ";" => Box::new(PatternExpr::CONCAT((expr, operand))),
            "... &" => Box::new(PatternExpr::AND((Box::new(PatternExpr::EXTEND(expr)), operand))),
            "... |" => Box::new(PatternExpr::OR((Box::new(PatternExpr::EXTEND(expr)), operand))),
            _ => unreachable!("Unimplemented pattern opcode")
        }
    }

    println!("{:?}", expr);
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
    ADD((Box<DisassemblyExpr<'a>>, Box<DisassemblyExpr<'a>>)),
    SUB((Box<DisassemblyExpr<'a>>, Box<DisassemblyExpr<'a>>)),
    MULT((Box<DisassemblyExpr<'a>>, Box<DisassemblyExpr<'a>>)),
    DIV((Box<DisassemblyExpr<'a>>, Box<DisassemblyExpr<'a>>)),
    SHIFT_LEFT((Box<DisassemblyExpr<'a>>, Box<DisassemblyExpr<'a>>)),
    SHIFT_RIGHT((Box<DisassemblyExpr<'a>>, Box<DisassemblyExpr<'a>>)),
    BIT_AND((Box<DisassemblyExpr<'a>>, Box<DisassemblyExpr<'a>>)),
    BIT_OR((Box<DisassemblyExpr<'a>>, Box<DisassemblyExpr<'a>>)),
    BIT_XOR((Box<DisassemblyExpr<'a>>, Box<DisassemblyExpr<'a>>)),
    BIT_NOT(Box<DisassemblyExpr<'a>>),
    IDENT(&'a str),
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
        (next, Box::new(DisassemblyExpr::BIT_NOT(res)))
    })
}

fn constructor_disas_expr(input: &str) -> Res<&str, Box<DisassemblyExpr>> {
    identifier(input)
    .map(|(next, res)| {
        (next, Box::new(DisassemblyExpr::IDENT(res)))
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
                     tag(">>"), tag("<<")
                )),
                space0
            ),
            _disassembly_expr
        )
    )(input)?;

    let mut expr = first_expr;

    for (op, operand) in ops {
        expr = match op {
            "&" => Box::new(DisassemblyExpr::BIT_AND((expr, operand))),
            "|" => Box::new(DisassemblyExpr::BIT_OR((expr, operand))),
            "^" => Box::new(DisassemblyExpr::BIT_XOR((expr, operand))),
            "+" => Box::new(DisassemblyExpr::ADD((expr, operand))),
            "-" => Box::new(DisassemblyExpr::SUB((expr, operand))),
            "*" => Box::new(DisassemblyExpr::MULT((expr, operand))),
            "/" => Box::new(DisassemblyExpr::DIV((expr, operand))),
            "<<" => Box::new(DisassemblyExpr::SHIFT_LEFT((expr, operand))),
            ">>" => Box::new(DisassemblyExpr::SHIFT_RIGHT((expr, operand))),
            _ => unreachable!("Unimplemented disassembly action opcode")
        }
    }

    //println!("{:?}", expr);
    Ok((input, expr))
}

fn disassembly_action(input: &str) -> Res<&str, DisassemblyAction> {
    separated_pair(
        identifier,
        delimited(space0, char('='), space0),
        terminated(disassembly_expr, char(';'))
    )(input)
    .map(|(next, res)| {
        (next, DisassemblyAction { lvalue: res.0, rvalue: res.1 })
    })
}

fn disassembly_actions(input: &str) -> Res<&str, Vec<DisassemblyAction>> {
    delimited(
        terminated(char('['), multispace0),
        separated_list0(line_ending, disassembly_action),
        preceded(multispace0, char(']'))
    )(input)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SemanticExprVariable<'a> {
    name: &'a str,
    size: Option<u64>
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SemanticExprNum {
    value: u64,
    size: Option<u64>
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SemanticExprValue<'a> {
    ADD((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    SUB((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    MULT((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    SHIFT_LEFT((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    SHIFT_RIGHT((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    AND((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    OR((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    BOOL_EQ((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    BOOL_NEQ((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    BOOL_AND((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    BOOL_OR((Box<SemanticExprValue<'a>>, Box<SemanticExprValue<'a>>)),
    BOOL_NOT(Box<SemanticExprValue<'a>>),
    ZEXT(Box<SemanticExprValue<'a>>),
    SEXT(Box<SemanticExprValue<'a>>),
    USER_DEFINED((&'a str, Vec<Box<SemanticExprValue<'a>>>)),
    REF((Option<&'a str>, u64, Box<SemanticExprValue<'a>>)),
    VARIABLE(SemanticExprVariable<'a>),
    IDENT(&'a str),
    NUM(SemanticExprNum),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SemanticExpr<'a> {
    EXPORT(Box<SemanticExprValue<'a>>),
    BUILD(&'a str),
    LOCAL_ASSIGN((SemanticExprVariable<'a>, Option<Box<SemanticExprValue<'a>>>),),
    ASSIGN((SemanticExprVariable<'a>, Box<SemanticExprValue<'a>>),),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SemanticAction<'a> {
    expr: Box<SemanticExpr<'a>>,
}

fn ident_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    semantic_expr_variable(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::VARIABLE(res)))
    })
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
            char('('),
            semantic_expr_value,
            char(')')
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
            char('('),
            semantic_expr_value,
            char(')')
        )
    )(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::SEXT(res)))
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
        (next, Box::new(SemanticExprValue::BOOL_NOT(res)))
    })
}

fn user_defined_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    tuple((
        identifier,
        delimited(
            char('('),
            separated_list0(terminated(char(','), space0), semantic_expr_value),
            char(')')
        )
    ))(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExprValue::USER_DEFINED(res)))
    })
}

fn ref_semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
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
        (next, Box::new(SemanticExprValue::REF(res)))
    })
}

fn _semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    alt((
        bool_not_semantic_expr_value,
        sext_semantic_expr_value,
        zext_semantic_expr_value,
        user_defined_semantic_expr_value,
        ident_semantic_expr_value,
        num_semantic_expr_value,
        ref_semantic_expr_value,
        delimited(
            char('('),
            semantic_expr_value,
            char(')')
        )
    ))(input)
}

fn semantic_expr_value(input: &str) -> Res<&str, Box<SemanticExprValue>> {
    let (input, first_expr) = _semantic_expr_value(input)?;
    let (input, ops) = many0(
        pair(
            delimited(
                space0,
                alt((
                    tag("+"), tag("-"), tag("*"),
                    tag("<<"), tag(">>"),
                    tag("=="), tag("!="),
                    tag("&&"), tag("||"),
                    tag("&"), tag("|"),
                )),
                space0
            ),
            _semantic_expr_value
        )
    )(input)?;

    let mut expr = first_expr;

    for (op, operand) in ops {
        expr = match op {
            "+" => Box::new(SemanticExprValue::ADD((expr, operand))),
            "-" => Box::new(SemanticExprValue::SUB((expr, operand))),
            "*" => Box::new(SemanticExprValue::MULT((expr, operand))),
            "<<" => Box::new(SemanticExprValue::SHIFT_LEFT((expr, operand))),
            ">>" => Box::new(SemanticExprValue::SHIFT_RIGHT((expr, operand))),
            "&" => Box::new(SemanticExprValue::AND((expr, operand))),
            "|" => Box::new(SemanticExprValue::OR((expr, operand))),
            "==" => Box::new(SemanticExprValue::BOOL_EQ((expr, operand))),
            "!=" => Box::new(SemanticExprValue::BOOL_NEQ((expr, operand))),
            "&&" => Box::new(SemanticExprValue::BOOL_AND((expr, operand))),
            "||" => Box::new(SemanticExprValue::BOOL_OR((expr, operand))),
            _ => unreachable!()
        }
    }

    //println!("{:?}", expr);
    Ok((input, expr))
}

fn export_semantic_expr(input: &str) -> Res<&str, Box<SemanticExpr>> {
    preceded(terminated(tag("export"), space1), semantic_expr_value)(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExpr::EXPORT(res)))
    })
}

fn build_semantic_expr(input: &str) -> Res<&str, Box<SemanticExpr>> {
    preceded(terminated(tag("build"), space1), identifier)(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExpr::BUILD(res)))
    })
}

fn semantic_expr_variable(input: &str) -> Res<&str, SemanticExprVariable> {
    tuple((
        identifier,
        opt(preceded(char(':'), num))
    ))(input)
    .map(|(next, res)| {
        (next, SemanticExprVariable { name: res.0, size: res.1 })
    })
}

fn local_assign_semantic_expr(input: &str) -> Res<&str, Box<SemanticExpr>> {
    preceded(
        terminated(tag("local"), space1),
        tuple((
            semantic_expr_variable,
            opt(preceded(
                delimited(space0, char('='), space0),
                semantic_expr_value
            ))
        ))
    )(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExpr::LOCAL_ASSIGN(res)))
    })
}

fn assign_semantic_expr(input: &str) -> Res<&str, Box<SemanticExpr>> {
    separated_pair(
        semantic_expr_variable,
        delimited(space0, char('='), space0),
        semantic_expr_value
    )(input)
    .map(|(next, res)| {
        //println!("{:?}", res);
        (next, Box::new(SemanticExpr::ASSIGN(res)))
    })
}

fn semantic_expr(input: &str) -> Res<&str, Box<SemanticExpr>> {
    alt((
        export_semantic_expr,
        build_semantic_expr,
        local_assign_semantic_expr,
        assign_semantic_expr,
    ))(input)
    .map(|(next, res)| {
        println!("{:?}", res);
        (next, res)
    })
}

fn semantic_action(input: &str) -> Res<&str, SemanticAction> {
    terminated(semantic_expr, char(';'))(input)
    .map(|(next, res)| {
        //println!("{:?}", res);
        (next, SemanticAction { expr: res })
    })
}

fn single_semantic_action(input: &str) -> Res<&str, Vec<SemanticAction>> {
    semantic_action(input)
    .map(|(next, res)| {
        (next, vec![res])
    })
}

fn semantic_actions(input: &str) -> Res<&str, Vec<SemanticAction>> {
    //println!("{}", &input[0..50]);
    delimited(
        terminated(char('{'), multispace0),
        alt((
            separated_list0(multispace0, semantic_action),
            single_semantic_action,
        )),
        preceded(multispace0, char('}'))
    )(input)
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
    actions: Option<Vec<DisassemblyAction<'a>>>,
    semantics: Vec<SemanticAction<'a>>
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
        println!("{}", res);
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
        terminated(table_header, space1),
        display_section,
        terminated(pattern_section, space1),
        opt(terminated(disassembly_actions, space1)),
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
        println!("{:#?}", Stmt::CONSTRUCTOR(constructor.clone()));
        (next, Stmt::CONSTRUCTOR(constructor))
    })
}

fn main() {
    let contents = read_file("output.txt");
    let sleigh = program(&contents);
    //println!("{:?}", sleigh);

    /*match sleigh.finish() {
        Ok(prog) => println!("{:?}", prog),
        Err(err) => println!("{}", err)
    }*/
}
