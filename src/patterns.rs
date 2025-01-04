use crate::sleigh::opcode::OpCode;
use crate::sleigh::types::Varnode;

extern crate nom;

use nom::branch::*;
use nom::bytes::complete::*;
use nom::character::complete::*;
use nom::combinator::*;
use nom::error::*;
use nom::multi::*;
use nom::sequence::*;
use nom::*;

use std::collections::HashMap;

pub type Res<T, U> = IResult<T, U, Error<T>>;

fn identifier(input: &str) -> Res<&str, &str> {
    recognize(pair(
        alt((alpha1, tag("_"), tag("."))),
        many0_count(alt((alphanumeric1, tag("_"), tag(".")))),
    ))(input)
}

// fn where_clause(input: &str) -> Res<&str, WhereClause> {
// }

fn wildcard_pattern(input: &str) -> Res<&str, VarnodePattern> {
    tag("?")(input)
    .map(|(next, res)| {
        (next, VarnodePattern::Wildcard)
    })
}

fn rest_pattern(input: &str) -> Res<&str, VarnodePattern> {
    tag("...")(input)
    .map(|(next, res)| {
        (next, VarnodePattern::Rest)
    })
}

fn vnode_pattern(input: &str) -> Res<&str, VarnodePattern> {
    take_till(|c| c == ',' || c == ')')(input)
    .map(|(next, res)| {
        (next, VarnodePattern::Vnode(res.to_string()))
    })
}

fn varnode_pattern(input: &str) -> Res<&str, VarnodePattern> {
    alt((wildcard_pattern, rest_pattern, vnode_pattern))(input)
}

fn op_pattern(input: &str) -> Res<&str, OpPattern> {
    tuple((
        opt(terminated(varnode_pattern, space1)),
        identifier,
        delimited(
            char('('),
            separated_list1(tag(", "), varnode_pattern),
            char(')'),
        ),
    ))(input)
    .map(|(next, res)| {
        let op_pat = OpPattern {
            opcode: OpCode::from_str(res.1),
            inputs: res.2,
            output: res.0,
        };

        (next, op_pat)
    })
}

fn pcode_pattern(input: &str) -> Res<&str, PcodePattern> {
    tuple((
        op_pattern,
        // opt(where_clause),
    ))(input)
    .map(|(next, res)| {
        let pat = PcodePattern {
            op_pattern: res.0,
        };

        (next, pat)
    })
}

#[derive(Debug)]
pub enum VarnodePattern {
    Wildcard,
    Rest,
    Vnode(String),
}

#[derive(Debug)]
pub struct OpPattern {
    opcode: OpCode,
    inputs: Vec<VarnodePattern>,
    output: Option<VarnodePattern>,
}

#[derive(Debug)]
pub struct PcodePattern {
    op_pattern: OpPattern,
    // where_clause: Option<WhereClause>,
}

impl PcodePattern {
    pub fn new(s: &str) -> Self {
        pcode_pattern(s).unwrap().1
    }
}
