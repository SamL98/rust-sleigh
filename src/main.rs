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
    SIZE(u32),
    DEFAULT,
    WORDSIZE(u32)
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
        (next, SpaceAttribute::SIZE(res.parse::<u32>().unwrap()))
    })
}

fn space_wordsize_attr(input: &str) -> Res<&str, SpaceAttribute> {
    preceded(
        tag("wordsize="),
        digit1)(input)
    .map(|(next, res)| {
        (next, SpaceAttribute::WORDSIZE(res.parse::<u32>().unwrap()))
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
    offset: u32,
    size: u32,
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

fn dec_num(input: &str) -> Res<&str, u32> {
    digit1(input)
    .map(|(next, res)| {
        (next, res.parse::<u32>().unwrap())
    })
}

fn hex_num(input: &str) -> Res<&str, u32> {
    preceded(tag("0x"), hex_digit1)(input)
    .map(|(next, res)| {
        (next, u32::from_str_radix(res, 16).unwrap())
    })
}

fn num(input: &str) -> Res<&str, u32> {
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
        let size = res.2.parse::<u32>().unwrap();
        (next, DefineStmt::NAMES(SpaceNamesDefinition { name: res.0, offset: res.1, size: size, names: res.3 }))
    })
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BitRangeDefinition<'a> {
    name: &'a str,
    reg: &'a str,
    bit_start: u32,
    num_bits: u32
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum FieldAttribute {
    SIGNED, HEX, DEC, NOFLOW
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TokenField<'a> {
    name: &'a str,
    bit_start: u32,
    num_bits: u32,
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
    bit_size: u32,
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
        let bit_start = res.1.parse::<u32>().unwrap();
        let bit_end = res.2.parse::<u32>().unwrap();
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
        let bit_size = res.0.1.parse::<u32>().unwrap();
        (next, DefineStmt::TOKEN(TokenDefinition { name: res.0.0, bit_size: bit_size, fields: res.1 }))
    })
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DefineStmt<'a> {
    ENDIANNESS(Endianness),
    ALIGNMENT(u32),
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
        let bit_start = res.2.parse::<u32>().unwrap();
        let num_bits = res.3.parse::<u32>().unwrap();
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
        (next, DefineStmt::ALIGNMENT(res.parse::<u32>().unwrap()))
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
    values: Vec<u32>
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

fn num_list(input: &str) -> Res<&str, Vec<u32>> {
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
    IDENT(&'a str),
    SPACE,
}

fn ident_display_part(input: &str) -> Res<&str, DisplayPart> {
    identifier(input)
    .map(|(next, res)| {
        println!("{}", res);
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

fn display_part(input: &str) -> Res<&str, DisplayPart> {
    alt((ident_display_part, space_display_part, literal_display_part))(input)
}

fn display_section(input: &str) -> Res<&str, Vec<DisplayPart>> {
    take_until("is")(input)
    .and_then(|(next, res)| {
        println!("\"{}\"", res);
        many1(display_part)(res.trim_end())
        .map(|(_, res)| {
            println!("{:?}", res);
            (next, res)
        })
    })
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PatternExpr<'a> {
    CONSTRAINT((&'a str, u32)),
    AND((Box<PatternExpr<'a>>, Box<PatternExpr<'a>>)),
    OR((Box<PatternExpr<'a>>, Box<PatternExpr<'a>>)),
    CONCAT((Box<PatternExpr<'a>>, Box<PatternExpr<'a>>)),
    EXTEND(Box<PatternExpr<'a>>),
    CONSTRUCTOR(&'a str),
    EMPTY
}

fn constraint_pattern(input: &str) -> Res<&str, Box<PatternExpr>> {
    separated_pair(
        identifier,
        char('='),
        num
    )(input)
    .map(|(next, res)| {
        println!("{:?}", res);
        (next, Box::new(PatternExpr::CONSTRAINT(res)))
    })
}

fn and_pattern(input: &str) -> Res<&str, Box<PatternExpr>> {
    println!("trying and {}", &input[0..20]);
    separated_pair(
        pattern_section,
        delimited(space1, char('&'), space1),
        pattern_section
    )(input)
    .map(|(next, res)| {
        (next, Box::new(PatternExpr::AND((res.0, res.1))))
    })
}

fn or_pattern(input: &str) -> Res<&str, Box<PatternExpr>> {
    separated_pair(
        pattern_section,
        delimited(space1, char('|'), space1),
        pattern_section
    )(input)
    .map(|(next, res)| {
        (next, Box::new(PatternExpr::OR((res.0, res.1))))
    })
}

fn concat_pattern(input: &str) -> Res<&str, Box<PatternExpr>> {
    separated_pair(
        pattern_section,
        delimited(space1, char(';'), space1),
        pattern_section
    )(input)
    .map(|(next, res)| {
        (next, Box::new(PatternExpr::CONCAT((res.0, res.1))))
    })
}

fn extend_pattern(input: &str) -> Res<&str, Box<PatternExpr>> {
    terminated(pattern_section, preceded(space1, tag("...")))(input)
    .map(|(next, res)| {
        (next, Box::new(PatternExpr::EXTEND(res)))
    })
}

fn constructor_pattern(input: &str) -> Res<&str, Box<PatternExpr>> {
    identifier(input)
    .map(|(next, res)| {
        (next, Box::new(PatternExpr::CONSTRUCTOR(res)))
    })
}


fn pattern_expr(input: &str) -> Res<&str, Box<PatternExpr>> {
    println!("{}", &input[0..20]);
    alt((
        delimited(char('('), pattern_section, char(')')),
        and_pattern,
        or_pattern,
        concat_pattern,
        extend_pattern,
        constraint_pattern,
        constructor_pattern
    ))(input)
    .map(|(next, res)| {
        println!("{:?}", res);
        (next, res)
    })
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
    IDENT(&'a str)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DisassemblyAction<'a> {
    lvalue: &'a str,
    rvalue: Box<DisassemblyExpr<'a>>
}

fn add_disas_expr(input: &str) -> Res<&str, Box<DisassemblyExpr>> {
    separated_pair(
        disassembly_expr,
        delimited(space1, char('+'), space1),
        disassembly_expr
    )(input)
    .map(|(next, res)| {
        (next, Box::new(DisassemblyExpr::ADD((res.0, res.1))))
    })
}

fn sub_disas_expr(input: &str) -> Res<&str, Box<DisassemblyExpr>> {
    separated_pair(
        disassembly_expr,
        delimited(space1, char('-'), space1),
        disassembly_expr
    )(input)
    .map(|(next, res)| {
        (next, Box::new(DisassemblyExpr::SUB((res.0, res.1))))
    })
}

fn mult_disas_expr(input: &str) -> Res<&str, Box<DisassemblyExpr>> {
    separated_pair(
        disassembly_expr,
        delimited(space1, char('*'), space1),
        disassembly_expr
    )(input)
    .map(|(next, res)| {
        (next, Box::new(DisassemblyExpr::MULT((res.0, res.1))))
    })
}

fn div_disas_expr(input: &str) -> Res<&str, Box<DisassemblyExpr>> {
    separated_pair(
        disassembly_expr,
        delimited(space1, char('/'), space1),
        disassembly_expr
    )(input)
    .map(|(next, res)| {
        (next, Box::new(DisassemblyExpr::DIV((res.0, res.1))))
    })
}

fn shift_left_disas_expr(input: &str) -> Res<&str, Box<DisassemblyExpr>> {
    separated_pair(
        disassembly_expr,
        delimited(space1, tag("<<"), space1),
        disassembly_expr
    )(input)
    .map(|(next, res)| {
        (next, Box::new(DisassemblyExpr::SHIFT_LEFT((res.0, res.1))))
    })
}

fn shift_right_disas_expr(input: &str) -> Res<&str, Box<DisassemblyExpr>> {
    separated_pair(
        disassembly_expr,
        delimited(space1, tag(">>"), space1),
        disassembly_expr
    )(input)
    .map(|(next, res)| {
        (next, Box::new(DisassemblyExpr::SHIFT_RIGHT((res.0, res.1))))
    })
}

fn bit_and_disas_expr(input: &str) -> Res<&str, Box<DisassemblyExpr>> {
    separated_pair(
        disassembly_expr,
        delimited(space1, char('&'), space1),
        disassembly_expr
    )(input)
    .map(|(next, res)| {
        (next, Box::new(DisassemblyExpr::BIT_AND((res.0, res.1))))
    })
}

fn bit_or_disas_expr(input: &str) -> Res<&str, Box<DisassemblyExpr>> {
    separated_pair(
        disassembly_expr,
        delimited(space1, char('|'), space1),
        disassembly_expr
    )(input)
    .map(|(next, res)| {
        (next, Box::new(DisassemblyExpr::BIT_OR((res.0, res.1))))
    })
}

fn bit_xor_disas_expr(input: &str) -> Res<&str, Box<DisassemblyExpr>> {
    separated_pair(
        disassembly_expr,
        delimited(space1, char('^'), space1),
        disassembly_expr
    )(input)
    .map(|(next, res)| {
        (next, Box::new(DisassemblyExpr::BIT_XOR((res.0, res.1))))
    })
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

fn disassembly_expr(input: &str) -> Res<&str, Box<DisassemblyExpr>> {
    terminated(
        alt((
            delimited(char('('), disassembly_expr, char(')')),
            add_disas_expr,
            sub_disas_expr,
            mult_disas_expr,
            div_disas_expr,
            shift_left_disas_expr,
            shift_right_disas_expr,
            bit_and_disas_expr,
            bit_or_disas_expr,
            bit_xor_disas_expr,
            bit_not_disas_expr,
            constructor_disas_expr
        )),
        char(';')
    )(input)
}

fn disassembly_action(input: &str) -> Res<&str, DisassemblyAction> {
    separated_pair(
        identifier,
        delimited(space0, char('='), space0),
        disassembly_expr
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
pub enum SemanticExpr<'a> {
    IDENT(&'a str),
    EXPORT(Box<SemanticExpr<'a>>),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SemanticAction<'a> {
    expr: Box<SemanticExpr<'a>>,
}

fn export_semantic_expr(input: &str) -> Res<&str, Box<SemanticExpr>> {
    preceded(terminated(tag("export"), space1), semantic_expr)(input)
    .map(|(next, res)| {
        (next, Box::new(SemanticExpr::EXPORT(res)))
    })
}

fn semantic_expr(input: &str) -> Res<&str, Box<SemanticExpr>> {
    terminated(
        alt((
            delimited(char('('), semantic_expr, char(')')),
            export_semantic_expr
        )),
        char(';')
    )(input)
}

fn semantic_action(input: &str) -> Res<&str, SemanticAction> {
    semantic_expr(input)
    .map(|(next, res)| {
        (next, SemanticAction { expr: res })
    })
}

fn semantic_actions(input: &str) -> Res<&str, Vec<SemanticAction>> {
    delimited(
        terminated(char('{'), multispace0),
        separated_list0(line_ending, semantic_action),
        preceded(multispace0, char('}'))
    )(input)
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
        terminated(semantic_actions, space1),
    ))(input)
    .map(|(next, res)| {
        let constructor = ConstructorStmt {
            table: res.0,
            display: res.1,
            pattern: res.2,
            actions: res.3,
            semantics: res.4
        };
        println!("{:?}", Stmt::CONSTRUCTOR(constructor.clone()));
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
