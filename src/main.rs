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

static SLEIGH_PATH: &'static str = "/Users/samlerner/ghidra_10.3_PUBLIC/Ghidra/Processors/x86/data/languages";

type Res<T, U> = IResult<T, U, Error<T>>;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Program<'a> {
    stmts: Vec<Stmt<'a>>
}

fn comment(input: &str) -> Res<&str, Stmt> {
    terminated(
        preceded(
            preceded(space0, tag("#")),
            take_until("\n")),
        line_ending)(input)
    .map(|(next, res)| {
        (next, Stmt::COMMENT())
    })
}

fn comment_no_newline(input: &str) -> Res<&str, Stmt> {
    preceded(
        preceded(space0, tag("#")),
        take_until("\n"))(input)
    .map(|(next, res)| {
        (next, Stmt::COMMENT())
    })
}

fn line_end_comment(input: &str) -> Res<&str, Option<Stmt>> {
    preceded(space0, opt(comment))(input)
}

fn line_end_comment_no_newline(input: &str) -> Res<&str, Option<Stmt>> {
    preceded(space0, opt(comment_no_newline))(input)
}

fn program(input: &str) -> Res<&str, Program> {
    /*separated_list0(
        multispace1,
        terminated(
            alt((
                comment, stmt
            )),
            line_end_comment_no_newline
        )
    )(input)*/
    many0(
        alt((
            terminated(
                terminated(
                    alt((comment, stmt)),
                    line_end_comment),
                take_while(is_newline_char)
            ),
            terminated(
                alt((comment, stmt)),
                line_end_comment),
        ))
    )(input)
    .map(|(next, res)| {
        (next, Program { stmts: res })
    })
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Stmt<'a> {
    DEFINE(DefineStmt<'a>),
    UNDEF(UndefStmt<'a>),
    INCLUDE(IncludeStmt<'a>),
    IFDEF(IfdefStmt<'a>),
    IFNDEF(IfndefStmt<'a>),
    IF(IfStmt<'a>),
    SLEIGH(&'a str),
    COMMENT()
}

fn stmt(input: &str) -> Res<&str, Stmt> {
    alt((comment, define, undef, include, ifdef, ifndef, ifstmt, sleigh))(input)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DefineStmt<'a> {
    name:  &'a str,
    value: &'a str
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

fn define(input: &str) -> Res<&str, Stmt> {
    preceded(
        terminated(tag("@define"), space1),
        separated_pair(identifier, space1, string))(input)
    .map(|(next, res)| {
        (next, Stmt::DEFINE(DefineStmt { name: res.0, value: res.1 }))
    })
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UndefStmt<'a> {
    name: &'a str
}

fn undef(input: &str) -> Res<&str, Stmt> {
    preceded(
        terminated(tag("@undef"), space1),
        identifier)(input)
    .map(|(next, res)| {
        (next, Stmt::UNDEF(UndefStmt { name: res }))
    })
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IncludeStmt<'a> {
    filename: &'a str
}

fn include(input: &str) -> Res<&str, Stmt> {
    preceded(
        terminated(tag("@include"), space1),
        string)(input)
    .map(|(next, res)| {
        (next, Stmt::INCLUDE(IncludeStmt { filename: res }))
    })
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Condition<'a> {
    VAR((&'a str, Vec<Stmt<'a>>)),
    EXPR((Expr<'a>, Vec<Stmt<'a>>)),
    ALWAYS(Vec<Stmt<'a>>)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IfdefStmt<'a> {
    cond:       Condition<'a>,
    else_block: Option<Condition<'a>>
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IfndefStmt<'a> {
    cond:       Condition<'a>,
    else_block: Option<Condition<'a>>
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IfStmt<'a> {
    cond:       Condition<'a>,
    elif_block: Option<Condition<'a>>,
    else_block: Option<Condition<'a>>
}

fn ifdef_line(input: &str) -> Res<&str, &str> {
    preceded(
        terminated(tag("@ifdef"), space1),
        terminated(identifier_ws, newline))(input)
}

fn else_line(input: &str) -> Res<&str, &str> {
    terminated(
        terminated(tag("@else"), space0), 
        line_ending)(input)
}

fn else_stmt(input: &str) -> Res<&str, Option<Condition>> {
    //println!("**else on {}", &input[0..20]);
    preceded(
        else_line,
        many_till(stmt, endif_line))(input)
    .map(|(next, res)| {
        //println!("else: {:?}, rest: {}", res, &next[0..20]);
        (next, Some(Condition::ALWAYS(res.0)))
    })
}

fn endif_line(input: &str) -> Res<&str, Option<Condition>> {
    terminated(
        terminated(tag("@endif"), space0),
        line_ending)(input)
    .map(|(next, _)| {
        //println!("endif, rest: \"{}\"", next);
        (next, None)
    })
}

fn ifdef(input: &str) -> Res<&str, Stmt> {
    tuple((ifdef_line,
           many_till(stmt, 
                     alt((else_stmt, 
                          endif_line)))))(input)
    .map(|(next, res)| {
        (next, Stmt::IFDEF(IfdefStmt { 
            cond:       Condition::VAR((res.0, res.1.0)),
            else_block: res.1.1
        }))
    })
}

fn ifndef_line(input: &str) -> Res<&str, &str> {
    preceded(
        terminated(tag("@ifndef"), space1),
        terminated(identifier_ws, newline))(input)
}

fn ifndef(input: &str) -> Res<&str, Stmt> {
    tuple((ifndef_line,
           many_till(stmt, 
                     alt((else_stmt, 
                          endif_line)))))(input)
    .map(|(next, res)| {
        (next, Stmt::IFNDEF(IfndefStmt { 
            cond:       Condition::VAR((res.0, res.1.0)),
            else_block: res.1.1
        }))
    })
}

fn if_line(input: &str) -> Res<&str, Expr> {
    preceded(
        terminated(tag("@if"), space1),
        expr_line)(input)
}

fn elif_line(input: &str) -> Res<&str, Expr> {
    preceded(
        terminated(tag("@elif"), space1),
        expr_line)(input)
}

fn elif_stmt(input: &str) -> Res<&str, (Option<Condition>, Option<Condition>)> {
    tuple((
        elif_line,
        many_till(stmt, 
                  alt((else_stmt,
                       endif_line)))))(input)
    .map(|(next, res)| {
        (next, (Some(Condition::EXPR((res.0, res.1.0))), res.1.1))
    })
}

fn dummy_cond_parser(input: &str) -> Res<&str, Option<Condition>> {
    Ok((input, None))
}

fn ifstmt(input: &str) -> Res<&str, Stmt> {
    tuple((if_line,
           many_till(stmt, 
                     alt((elif_stmt, 
                          tuple((dummy_cond_parser, else_stmt)),
                          tuple((dummy_cond_parser, endif_line)))))))(input)
    .map(|(next, res)| {
        (next, Stmt::IF(IfStmt { 
            cond:       Condition::EXPR((res.0, res.1.0)),
            elif_block: res.1.1.0,
            else_block: res.1.1.1
        }))
    })
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BoolOperator {
    EQ,
    NEQ
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BinaryOperator {
    AND,
    OR,
    XOR
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Expr<'a> {
    DEFINED(DefinedExpr<'a>),
    BINARY(BinaryExpr<'a>),
    BOOL(BoolExpr<'a>)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DefinedExpr<'a> {
    variable: &'a str
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BoolExpr<'a> {
    lhs: &'a str,
    op:  BoolOperator,
    rhs: &'a str
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BinaryExpr<'a> {
    lhs: Box<Expr<'a>>,
    op:  BinaryOperator,
    rhs: Box<Expr<'a>>
}

fn expr(input: &str) -> Res<&str, Expr> {
    //alt((defined_expr, bool_expr, binary_expr))(input)
    alt((binary_expr, defined_expr, bool_expr))(input)
}

fn expr_line(input: &str) -> Res<&str, Expr> {
    //println!("------------------");
    //println!("expr on {}", input);
    alt((
        terminated(terminated(defined_expr, space0), newline),
        terminated(terminated(bool_expr, space0), newline),
        terminated(terminated(binary_expr, space0), newline)))(input)
}

fn defined_expr(input: &str) -> Res<&str, Expr> {
    //println!("------------------");
    //println!("defined_expr on {}", input);
    preceded(
        tag("defined"),
        delimited(tag("("), identifier, tag(")")))(input)
    .map(|(next, res)| {
        (next, Expr::DEFINED(DefinedExpr { variable: res }))
    })
}

fn _bool_expr(input: &str) -> Res<&str, Expr> {
    tuple((
        terminated(identifier, space0),
        bool_operator,
        preceded(space0, string)))(input)
    .map(|(next, res)| {
        //println!("bool expr, lhs: {}, op: {:?}, rhs: {}, rest: {}", res.0, res.1, res.2, next);
        (next, Expr::BOOL(BoolExpr { lhs: res.0, op: res.1, rhs: res.2 }))
    })
}

fn bool_expr(input: &str) -> Res<&str, Expr> {
    //println!("------------------");
    //println!("bool_expr on {}", input);
    alt((
        delimited(tag("("), _bool_expr, tag(")")),
        _bool_expr))(input)
}

fn bool_operator(input: &str) -> Res<&str, BoolOperator> {
    alt((tag("=="), tag("!=")))(input)
    .map(|(next, res)| {
        match res {
            "==" => { (next, BoolOperator::EQ) }
            "!=" => { (next, BoolOperator::NEQ) },
            &_ => todo!()
        }
    })
}

fn _binary_expr(input: &str) -> Res<&str, Expr> {
    //println!("------------------");
    //println!("_binary_expr on {}", input);
    tuple((
        terminated(alt((defined_expr, bool_expr)), space0),
        binary_operator,
        preceded(space0, expr)))(input)
    .map(|(next, res)| {
        (next, Expr::BINARY(BinaryExpr { lhs: Box::new(res.0), op: res.1, rhs: Box::new(res.2) }))
    })
}

fn binary_expr(input: &str) -> Res<&str, Expr> {
    //println!("------------------");
    //println!("binary_expr on {}", input);
    alt((
        delimited(tag("("), _binary_expr, tag(")")),
        _binary_expr))(input)
}

fn binary_operator(input: &str) -> Res<&str, BinaryOperator> {
    //println!("------------------");
    //println!("binary_operator on {}", input);
    alt((tag("&&"), tag("||"), tag("^^")))(input)
    .map(|(next, res)| {
        let retval = match res {
            "&&" => (next, BinaryOperator::AND),
            "||" => (next, BinaryOperator::OR),
            "^^" => (next, BinaryOperator::XOR),
            &_ => todo!()
        };

        retval
    })
}

fn is_newline_char(chr: char) -> bool {
    let mut c = [0; 1];
    let _ = chr.encode_utf8(&mut c);
    is_newline(c[0])
}

fn sleigh(input: &str) -> Res<&str, Stmt> {
    terminated(
        take_till(is_newline_char),
        newline)(input)
    .map(|(next, res)| {
        (next, Stmt::SLEIGH(res))
    })
}

fn read_file(filename: &str) -> String {
    fs::read_to_string(format!("{}/{}", SLEIGH_PATH, filename)).expect("can't read file")
}

fn execute_define<'b>(s: DefineStmt<'b>, vars: &mut HashMap<String, String>, out: &mut File) {
    vars.insert(s.name.to_owned(), s.value.to_owned());
}

fn execute_undef<'b>(s: UndefStmt<'b>, vars: &mut HashMap<String, String>, out: &mut File) {
    vars.remove(&s.name.to_owned());
}

fn execute_include<'b>(s: IncludeStmt<'b>, vars: &mut HashMap<String, String>, out: &mut File) {
    println!("Processing {}", s.filename);

    let included_contents = read_file(s.filename) + "\n"; // hack
    let sleigh_prepro = program(&included_contents);
    //println!("{:?}", sleigh_prepro);

    match sleigh_prepro.finish() {
        Ok(prog) => execute_stmts(prog.1.stmts, vars, out),
        Err(err) => panic!("{}", err)
    }
}

fn execute_else<'b>(else_block: Option<Condition<'b>>, vars: &mut HashMap<String, String>, out: &mut File) {
    if else_block.is_some() {
        match else_block.unwrap() {
            Condition::ALWAYS(block) => execute_stmts(block, vars, out),
            _ => panic!("Unhandled condition type in else block")
        }
    }
}

fn execute_ifdef<'b>(s: IfdefStmt<'b>, vars: &mut HashMap<String, String>, out: &mut File) {
    match s.cond {
        Condition::VAR((name, block)) => match vars.get(name) {
            Some(_) => execute_stmts(block, vars, out),
            None    => execute_else(s.else_block, vars, out)
        },
        _ => panic!("Unhandled condition type in ifdef: {:?}", s.cond)
    }
}

fn execute_ifndef<'b>(s: IfndefStmt<'b>, vars: &mut HashMap<String, String>, out: &mut File) {
    match s.cond {
        Condition::VAR((name, block)) => match vars.get(name) {
            None    => execute_stmts(block, vars, out),
            Some(_) => execute_else(s.else_block, vars, out)
        },
        _ => panic!("Unhandled condition type in ifdef: {:?}", s.cond)
    }
}

fn evaluate_bool_expr<'b>(expr: BoolExpr<'b>, vars: &mut HashMap<String, String>) -> bool {
    let value = match vars.get(expr.lhs) {
        Some(value) => value,
        None        => panic!("Variable {} not defined", expr.lhs)
    };

    match expr.op {
        BoolOperator::EQ  => value == expr.rhs,
        BoolOperator::NEQ => value != expr.rhs
    }
}

fn evaluate_binary_expr<'b>(expr: BinaryExpr<'b>, vars: &mut HashMap<String, String>) -> bool {
    let lhs = evaluate_expr(*expr.lhs, vars);
    let rhs = evaluate_expr(*expr.rhs, vars);

    match expr.op {
        BinaryOperator::AND => lhs && rhs,
        BinaryOperator::OR  => lhs || rhs,
        BinaryOperator::XOR => (lhs && !rhs) || (!lhs && rhs)
    }
}

fn evaluate_expr<'b>(expr: Expr<'b>, vars: &mut HashMap<String, String>) -> bool {
    match expr {
        Expr::DEFINED(expr) => vars.get(expr.variable).is_some(),
        Expr::BOOL(expr)    => evaluate_bool_expr(expr, vars),
        Expr::BINARY(expr)  => evaluate_binary_expr(expr, vars)
    }
}

fn _execute_elif<'b>(expr: Expr<'b>, 
                     block: Vec<Stmt<'b>>, 
                     else_block: Option<Condition<'b>>, 
                     vars: &mut HashMap<String, String>, 
                     out: &mut File) {
    if evaluate_expr(expr, vars) {
        execute_stmts(block, vars, out);
    }
    else if else_block.is_some() {
        execute_else(else_block, vars, out);
    }
}

fn execute_elif<'b>(elif_block: Option<Condition<'b>>, 
                    else_block: Option<Condition<'b>>, 
                    vars: &mut HashMap<String, String>, 
                    out: &mut File) {
    if elif_block.as_ref().is_some() {
        match elif_block.unwrap() {
            Condition::EXPR((expr, block)) => _execute_elif(expr, block, else_block, vars, out),
            _ => panic!("Unabled condition type in elif")
        }
    }
}

fn _execute_if<'b>(expr: Expr<'b>, 
                   block: Vec<Stmt<'b>>, 
                   elif_block: Option<Condition<'b>>, 
                   else_block: Option<Condition<'b>>, 
                   vars: &mut HashMap<String, String>, 
                   out: &mut File) {
    if evaluate_expr(expr, vars) {
        execute_stmts(block, vars, out);
    }
    else if elif_block.as_ref().is_some() {
        execute_elif(elif_block, else_block, vars, out);
    }
    else if else_block.as_ref().is_some() {
        execute_else(else_block, vars, out);
    }
}

fn execute_if<'b>(s: IfStmt<'b>, vars: &mut HashMap<String, String>, out: &mut File) {
    let elif_block = s.elif_block;
    let else_block = s.else_block;

    match s.cond {
        Condition::EXPR((expr, block)) => _execute_if(expr, block, elif_block, else_block, vars, out),
        _ => panic!("Unhandled condition type in if: {:?}", s.cond)
    }
}

fn execute_sleigh<'b>(s: &'b str, vars: &mut HashMap<String, String>, out: &mut File) {
    let mut result = String::new();
    let mut chars = s.chars();

    while let Some(ch) = chars.next() {
        if ch == '$' {
            if let Some('(') = chars.next() {
                let mut var_name = String::new();
                while let Some(c) = chars.next() {
                    if c == ')' {
                        break;
                    }
                    var_name.push(c);
                }

                if let Some(val) = vars.get(var_name.as_str()) {
                    result.push_str(val);
                }
                else {
                    result.push('$');
                    result.push('(');
                    result.push_str(&var_name);
                    result.push(')');
                }
            }
            else {
                result.push('$');
            }
        }
        else {
            result.push(ch);
        }
    }

    writeln!(out, "{}", result).unwrap()
}

fn execute_stmts<'b>(stmts: Vec<Stmt<'b>>, vars: &mut HashMap<String, String>, out: &mut File) {
    for stmt in stmts {
        match stmt {
            Stmt::DEFINE(stmt)  => execute_define(stmt, vars, out),
            Stmt::UNDEF(stmt)   => execute_undef(stmt, vars, out),
            Stmt::INCLUDE(stmt) => execute_include(stmt, vars, out),
            Stmt::IFDEF(stmt)   => execute_ifdef(stmt, vars, out),
            Stmt::IFNDEF(stmt)  => execute_ifndef(stmt, vars, out),
            Stmt::IF(stmt)      => execute_if(stmt, vars, out),
            Stmt::SLEIGH(line)  => execute_sleigh(line, vars, out),
            Stmt::COMMENT()     => (),
            _                   => todo!("{:?}", stmt)
        }
    }
}

fn execute(prog: Program) {
    let mut vars = HashMap::<String, String>::new();
    let mut out = File::create("output.txt").unwrap();
    execute_stmts(prog.stmts, &mut vars, &mut out);
}

fn main() {
    let contents = read_file("x86-64.slaspec");
    let sleigh_prepro = program(&contents);
    //println!("{:?}", sleigh_prepro);

    match sleigh_prepro.finish() {
        Ok(prog) => execute(prog.1),
        Err(err) => println!("{}", err)
    }
}
