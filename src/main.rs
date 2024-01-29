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
pub struct MaskWord {
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PatternBlock {
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DecisionPattern {
    Context,
    Instruction,
    Combine,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DecisionTree {
    Leaf,
    NonLeaf
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Space {
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Scope {
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SymbolHead {
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Symbol {
    Scope(Scope),
    SymHead(SymbolHead),
    Subtable(Subtable),
    Varnode,
    Value,
    Varlist,
    Valuemap,
    Operand,
    Context,
    UserOp,
    Start,
    End,
    Next2,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Subtable {
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConstContextExpr {
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct FieldContextExpr {
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OperandContextExpr {
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Expr {
    Const,
    Operand,
    Field,
    Xor,
    Not,
    Add,
    Lshift,
    Rshift,
    Mult,
    And,
    Or,
    End,
    Start,
    Next2
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Constructor {
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OpPrintCommand {
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PrintPieceCommand {
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PrintCommand {
    Op(OpPrintCommand),
    Piece(PrintPieceCommand)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ContextOp {
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConstructorTemplate {
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OpTemplate {
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct HandleTemplate {
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ConsTemplate {
    Op(OpTemplate),
    Handle(HandleTemplate),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VarnodeTemplate {
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConstTemplate {
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Program {
    spaces: Vec<Space>,
    symbols: Vec<Symbol>
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
        tag("<space"),
        take_until("/>"),
        tag("/>"),
    )(input)
    .map(|(next, res)| {
        (next, Space{})
    })
}

fn spaces(input: &str) -> Res<&str, Vec<Space>> {
    tuple((
        terminated(
            delimited(
                tag("<spaces"),
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
        (next, res.1)
    })
}

fn scope(input: &str) -> Res<&str, Symbol> {
    delimited(
        tag("<scope"),
        take_until("/>"),
        tag("/>"),
    )(input)
    .map(|(next, res)| {
        (next, Symbol::Scope(Scope{}))
    })
}

/*fn subtable(input: &str) -> Res<&str, Symbol> {
    delimited(
        tag("<scope"),
        take_until("/>"),
        tag("/>"),
    )(input)
    .map(|(next, res)| {
        (next, Symbol{})
    })
}*/

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
                    tag("_sym_head")
                ),
                tag("userop_head")
            ))
        ),
        take_until("/>"),
        tag("/>")
    )(input)
    .map(|(next, res)| {
        (next, Symbol::SymHead(SymbolHead{}))
    })
}

fn operands(input: &str) -> Res<&str, Vec<&str>> {
    separated_list1(
        line_ending,
        delimited(
            tag("<oper"),
            take_until("/>"),
            tag("/>")
        )
    )(input)
}

fn opprint(input: &str) -> Res<&str, PrintCommand> {
    delimited(
        tag("<opprint"),
        take_until("/>"),
        tag("/>")
    )(input)
    .map(|(next, res)| {
        (next, PrintCommand::Op(OpPrintCommand{}))
    })
}

fn print_piece(input: &str) -> Res<&str, PrintCommand> {
    delimited(
        tag("<print piece"),
        take_until("/>"),
        tag("/>")
    )(input)
    .map(|(next, res)| {
        (next, PrintCommand::Piece(PrintPieceCommand{}))
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
    delimited(
        tag("<intb"),
        take_until("/>"),
        tag("/>")
    )(input)
    .map(|(next, res)| {
        (next, Expr::Const)
    })
}

fn operand_expr(input: &str) -> Res<&str, Expr> {
    delimited(
        tag("<operand_exp"),
        take_until("/>"),
        tag("/>")
    )(input)
    .map(|(next, res)| {
        (next, Expr::Operand)
    })
}

fn contextfield(input: &str) -> Res<&str, &str> {
    delimited(
        tag("<contextfield"),
        take_until("/>"),
        tag("/>")
    )(input)
}

fn field_expr(input: &str) -> Res<&str, Expr> {
    field(input)
    .map(|(next, res)| {
        (next, Expr::Field)
    })
}

fn start_expr(input: &str) -> Res<&str, Expr> {
    tag("<start_exp/>")(input).map(|(next, res)| { (next, (Expr::Start ))})
}

fn end_expr(input: &str) -> Res<&str, Expr> {
    tag("<end_exp/>")(input).map(|(next, res)| { (next, (Expr::End ))})
}

fn next2_expr(input: &str) -> Res<&str, Expr> {
    tag("<next2_exp/>")(input).map(|(next, res)| { (next, (Expr::Next2 ))})
}

fn not_expr(input: &str) -> Res<&str, Expr> {
    delimited(
        terminated(tag("<not_exp>"), line_ending),
        expr,
        terminated(line_ending, tag("</not_exp>"))
    )(input)
    .map(|(next, res)| {
        (next, Expr::Not)
    })
}

fn xor_expr(input: &str) -> Res<&str, Expr> {
    delimited(
        terminated(tag("<xor_exp>"), line_ending),
        separated_pair(
            expr,
            line_ending,
            expr
        ),
        terminated(line_ending, tag("</xor_exp>"))
    )(input)
    .map(|(next, res)| {
        (next, Expr::Xor)
    })
}

fn or_expr(input: &str) -> Res<&str, Expr> {
    delimited(
        terminated(tag("<or_exp>"), line_ending),
        separated_pair(
            expr,
            line_ending,
            expr
        ),
        terminated(line_ending, tag("</or_exp>"))
    )(input)
    .map(|(next, res)| {
        (next, Expr::Xor)
    })
}

fn and_expr(input: &str) -> Res<&str, Expr> {
    delimited(
        terminated(tag("<and_exp>"), line_ending),
        separated_pair(
            expr,
            line_ending,
            expr
        ),
        terminated(line_ending, tag("</and_exp>"))
    )(input)
    .map(|(next, res)| {
        (next, Expr::And)
    })
}

fn add_expr(input: &str) -> Res<&str, Expr> {
    delimited(
        terminated(tag("<plus_exp>"), line_ending),
        separated_pair(
            expr,
            opt(line_ending),
            expr
        ),
        terminated(line_ending, tag("</plus_exp>"))
    )(input)
    .map(|(next, res)| {
        (next, Expr::Add)
    })
}

fn lshift_expr(input: &str) -> Res<&str, Expr> {
    delimited(
        terminated(tag("<lshift_exp>"), line_ending),
        separated_pair(
            expr,
            opt(line_ending),
            expr
        ),
        terminated(line_ending, tag("</lshift_exp>"))
    )(input)
    .map(|(next, res)| {
        (next, Expr::Lshift)
    })
}

fn rshift_expr(input: &str) -> Res<&str, Expr> {
    delimited(
        terminated(tag("<rshift_exp>"), line_ending),
        separated_pair(
            expr,
            opt(line_ending),
            expr
        ),
        terminated(line_ending, tag("</rshift_exp>"))
    )(input)
    .map(|(next, res)| {
        (next, Expr::Rshift)
    })
}

fn mult_expr(input: &str) -> Res<&str, Expr> {
    delimited(
        terminated(tag("<mult_exp>"), line_ending),
        separated_pair(
            expr,
            opt(line_ending),
            expr
        ),
        terminated(line_ending, tag("</mult_exp>"))
    )(input)
    .map(|(next, res)| {
        (next, Expr::Mult)
    })
}

fn expr(input: &str) -> Res<&str, Expr> {
    println!("* context expr {}", &input[0..20]);
    alt((
        start_expr,
        end_expr,
        next2_expr,
        const_expr,
        operand_expr,
        field_expr,
        not_expr,
        xor_expr,
        or_expr,
        and_expr,
        add_expr,
        lshift_expr,
        rshift_expr,
        mult_expr
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
        println!("context {:?}", res.1);
        (next, ContextOp {})
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
        //println!("{:?}", res.1);
        (next, ConstTemplate {})
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
        println!("varnode {:?}", res.1);
        (next, None)
    })
}

fn null_varnode_template(input: &str) -> Res<&str, Option<VarnodeTemplate>> {
    tag("<null/>")(input)
    .map(|(next, res)| {
        (next, Some(VarnodeTemplate {}))
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
        println!("op {:?}", res.1);
        (next, ConsTemplate::Op(OpTemplate {}))
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
        (next, ConsTemplate::Handle(HandleTemplate {}))
    })
}

fn null_ops(input: &str) -> Res<&str, Vec<ConsTemplate>> {
    tag("<null/>")(input)
    .map(|(next, res)| {
        (next, vec![])
    })
}

fn constructor_template(input: &str) -> Res<&str, ConstructorTemplate> {
    delimited(
        terminated(
            delimited(
                tag("<construct_tpl"),
                take_until(">"),
                tag(">")
            ),
            line_ending
        ),
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
    )(input)
    .map(|(next, res)| {
        println!("construtor_tpl {:?}", res);
        (next, ConstructorTemplate {})
    })
}

fn constructor(input: &str) -> Res<&str, Constructor> {
    tuple((
        terminated(tag("<constructor"), terminated(take_until("\n"), line_ending)),
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
        println!("constructor {:?}", res.1);
        (next, Constructor {})
    })
}

fn mask_word(input: &str) -> Res<&str, MaskWord> {
    delimited(
        tag("<mask_word"),
        take_until("/>"),
        tag("/>")
    )(input)
    .map(|(next, res)| {
        println!("mask word {:?}", res);
        (next, MaskWord {})
    })
}

fn pattern_block(input: &str) -> Res<&str, PatternBlock> {
    tuple((
        terminated(
            delimited(
                tag("<pat_block"),
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
        println!("pattern block {:?}", res);
        (next, PatternBlock {})
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
        println!("combine pattern {:?}", res);
        (next, DecisionPattern::Combine)
    })
}

fn context_pattern(input: &str) -> Res<&str, DecisionPattern> {
    delimited(
        terminated(tag("<context_pat>"), line_ending),
        pattern_block,
        preceded(line_ending, tag("</context_pat>"))
    )(input)
    .map(|(next, res)| {
        println!("context pattern {:?}", res);
        (next, DecisionPattern::Context)
    })
}

fn instruction_pattern(input: &str) -> Res<&str, DecisionPattern> {
    delimited(
        terminated(tag("<instruct_pat>"), line_ending),
        pattern_block,
        preceded(line_ending, tag("</instruct_pat>"))
    )(input)
    .map(|(next, res)| {
        println!("instruct pattern {:?}", res);
        (next, DecisionPattern::Instruction)
    })
}

fn decision_pattern(input: &str) -> Res<&str, DecisionPattern> {
    alt((
        context_pattern,
        instruction_pattern,
        combine_pattern
    ))(input)
}

fn decision_pair(input: &str) -> Res<&str, DecisionPattern> {
    delimited(
        terminated(
            delimited(
                tag("<pair"),
                take_until(">"),
                tag(">")
            ),
            line_ending
        ),
        terminated(decision_pattern, line_ending),
        tag("</pair>")
    )(input)
}

fn decision_pairs(input: &str) -> Res<&str, DecisionTree> {
    separated_list1(
        line_ending,
        decision_pair
    )(input)
    .map(|(next, res)| {
        println!("decision pairs {:?}", res);
        (next, DecisionTree::Leaf)
    })
}

fn decision_body(input: &str) -> Res<&str, DecisionTree> {
    alt((decision_pairs, decision_tree))(input)
}

fn decision_tree(input: &str) -> Res<&str, DecisionTree> {
    //println!("decision tree {}", &input[0..20]);
    delimited(
        delimited(
            tag("<decision"),
            take_until(">"),
            terminated(tag(">"), line_ending)
        ),
        alt((
            terminated(separated_list1(line_ending, decision_body), line_ending),
            separated_list0(line_ending, decision_body),
        )),
        tag("</decision>")
    )(input)
    .map(|(next, res)| {
        println!("decision body {:?}", res);
        (next, DecisionTree::NonLeaf)
    })
}

fn subtable_sym(input: &str) -> Res<&str, Symbol> {
    //println!("subtable_sym {}", &input[0..50]);
    tuple((
        terminated(tag("<subtable_sym"), terminated(take_until("\n"), line_ending)),
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
        println!("{:?}", res.1.0.len());
        (next, Symbol::Subtable(Subtable {}))
    })
}

fn start_sym(input: &str) -> Res<&str, Symbol> {
    delimited(tag("<start_sym "), take_until("/>"), tag("/>"))(input)
    .map(|(next, res)| { (next, Symbol::Start) })
}
fn end_sym(input: &str) -> Res<&str, Symbol> {
    delimited(tag("<end_sym "), take_until("/>"), tag("/>"))(input)
    .map(|(next, res)| { (next, Symbol::Start) })
}
fn next2_sym(input: &str) -> Res<&str, Symbol> {
    delimited(tag("<next2_sym "), take_until("/>"), tag("/>"))(input)
    .map(|(next, res)| { (next, Symbol::Start) })
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
    .map(|(next, res)| { (next, Symbol::Varnode) })
}

fn tokenfield(input: &str) -> Res<&str, &str> {
    delimited(
        tag("<tokenfield"),
        take_until("/>"),
        tag("/>")
    )(input)
}

fn field(input: &str) -> Res<&str, &str> {
    alt((contextfield, tokenfield))(input)
}

fn valuetab(input: &str) -> Res<&str, &str> {
    //println!("valuetab {}", &input[0..20]);
    delimited(
        tag("<valuetab"),
        take_until("/>"),
        tag("/>")
    )(input)
}

fn valuemap_sym(input: &str) -> Res<&str, Symbol> {
    delimited(
        delimited(
            tag("<valuemap_sym "),
            take_until(">"),
            terminated(tag(">"), line_ending)
        ),
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
    )(input)
    .map(|(next, res)| { (next, Symbol::Valuemap) })
}

fn nonnull_var(input: &str) -> Res<&str, Option<&str>> {
    delimited(
        tag("<var"),
        take_until("/>"),
        tag("/>")
    )(input)
    .map(|(next, res)| { (next, Some(res)) })
}

fn null_var(input: &str) -> Res<&str, Option<&str>> {
    tag("<null/>")(input)
    .map(|(next, res)| { (next, None) })
}

fn var(input: &str) -> Res<&str, Option<&str>> {
    //println!("var {}", &input[0..20]);
    alt((nonnull_var, null_var))(input)
}

fn varlist_sym(input: &str) -> Res<&str, Symbol> {
    //println!("varlist {}", &input[0..50]);
    delimited(
        delimited(
            tag("<varlist_sym "),
            take_until(">"),
            terminated(tag(">"), line_ending)
        ),
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
    )(input)
    .map(|(next, res)| { (next, Symbol::Varlist) })
}

fn value_sym(input: &str) -> Res<&str, Symbol> {
    delimited(
        delimited(
            tag("<value_sym "),
            take_until(">"),
            terminated(tag(">"), line_ending)
        ),
        tokenfield,
        preceded(line_ending, tag("</value_sym>"))
    )(input)
    .map(|(next, res)| { (next, Symbol::Value) })
}

fn context_sym(input: &str) -> Res<&str, Symbol> {
    delimited(
        delimited(
            tag("<context_sym "),
            take_until(">"),
            terminated(tag(">"), line_ending)
        ),
        contextfield,
        preceded(line_ending, tag("</context_sym>"))
    )(input)
    .map(|(next, res)| { (next, Symbol::Context) })
}

fn operand_sym(input: &str) -> Res<&str, Symbol> {
    delimited(
        delimited(
            tag("<operand_sym "),
            take_until(">"),
            terminated(tag(">"), line_ending)
        ),
        tuple((
            operand_expr,
            opt(preceded(line_ending, expr)),
        )),
        preceded(line_ending, tag("</operand_sym>"))
    )(input)
    .map(|(next, res)| { (next, Symbol::Operand) })
}

fn userop(input: &str) -> Res<&str, Symbol> {
    delimited(
        tag("<userop "),
        take_until("/>"),
        tag("/>")
    )(input)
    .map(|(next, res)| { (next, Symbol::UserOp) })
}

fn sym(input: &str) -> Res<&str, Symbol> {
    println!("** {}", &input[0..20]);
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
                tag("<symbol_table"),
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
        println!("{:?}", res.1.len());
        (next, res.1)
    })
}

fn program(input: &str) -> Res<&str, Program> {
    tuple((
        terminated(
            delimited(
                char('<'),
                preceded(
                    tag("sleigh"),
                    take_until(">")
                ),
                char('>')
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
        (next, Program { spaces: res.2, symbols: res.3 })
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
    let contents = read_file("x86-64.sla");
    let res = program(&contents);
    //println!("{:?}", sla);

    match res.finish() {
        Ok((rest, sla)) => {
            println!("{:?}", sla);
            println!("success! {}", rest)
        },
        Err(err) => println!("err")
    }
}
