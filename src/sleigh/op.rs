use super::opcode::OpCode;
use super::seqnum::SeqNum;

use std::fmt::{self, Display, Debug};
use std::hash::Hash;

#[derive(Eq, PartialEq, Hash, Clone)]
pub struct Op<T> {
    pub seq: SeqNum,
    pub opcode: OpCode,
    pub inputs: Vec<T>,
    pub output: Option<T>,
}

pub trait FmtIface: Display {
    fn fmt_output(&self) -> String;
    fn fmt_call_target(&self) -> String;
}

pub fn parenthesize(s: String) -> String {
    let trim_s = s.trim_start_matches('*');
    let first_char = trim_s.chars().next().unwrap();
    let last_char = trim_s.chars().last().unwrap();

    if trim_s.contains(' ') && (first_char != '(' || last_char != ')') {
        format!("({})", s)
    } else {
        s
    }
}

fn fmt_unary<T: Display>(opstr: &str, inputs: &[T]) -> String {
    format!("{}({})", opstr, inputs[0])
}

fn fmt_binary<T: Display>(opstr: &str, inputs: &[T]) -> String {
    let lhs_str = parenthesize(inputs[0].to_string());
    let rhs_str = parenthesize(inputs[1].to_string());
    format!("{} {} {}", lhs_str, opstr, rhs_str)
}

fn fmt_func<T: Display>(opstr: &str, inputs: &[T]) -> String {
    format!("{}({})", opstr, inputs.iter()
        .map(|x| format!("{}", x))
        .collect::<Vec<String>>()
        .join(", "))
}

pub fn fmt_inputs<T: FmtIface>(opcode: OpCode, inputs: &[T], size: u64) -> String {
    match opcode {
        OpCode::Copy => inputs[0].to_string(),
        OpCode::Decl => inputs[0].fmt_output(),
        OpCode::DeclCopy => inputs[0].to_string(),
        OpCode::Store => format!("*{} = {}", parenthesize(inputs[0].to_string()), inputs[1]),
        OpCode::Load => format!("*{}", parenthesize(inputs[0].to_string())),
        OpCode::Deref => format!("*{}:{}", parenthesize(inputs[0].to_string()), size),
        OpCode::FieldAccess => format!("{}.{}", parenthesize(inputs[0].to_string()), inputs[1]),
        OpCode::FieldDeref => format!("{}->{}", parenthesize(inputs[0].to_string()), inputs[1]),
        OpCode::ArrayIndex => format!("{}[{}]", parenthesize(inputs[0].to_string()), inputs[1]),
        OpCode::AddrOf => format!("&{}", inputs[0]),
        OpCode::Branch => format!("\x1b[38;5;105mgoto\x1b[0m {}", inputs[0]),
        OpCode::BranchInd => format!("\x1b[38;5;105mgoto\x1b[0m [{}]", inputs[0]),
        OpCode::Call => format!("{}({})", inputs[0].fmt_call_target(), inputs[1..].iter()
            .map(|x| format!("{}", x))
            .collect::<Vec<String>>()
            .join(", ")),
        OpCode::CallInd => {
            let mut input_iter = inputs.iter();
            let _ = input_iter.next();

            format!("*({})({})", inputs[0], 
                input_iter
                .map(|x| format!("{}", x))
                .collect::<Vec<String>>()
                .join(", "))
        },
        OpCode::CBranch => format!("\x1b[38;5;105mif\x1b[0m ({}) \x1b[38;5;105mgoto\x1b[0m {}", inputs[1], inputs[0]),
        OpCode::Return => format!("\x1b[38;5;105mreturn\x1b[0m {}", inputs.iter()
            .map(|x| format!("{}", x))
            .collect::<Vec<String>>()
            .join(", ")),
        OpCode::MultiEqual => fmt_func("phi", inputs),
        OpCode::CPoolRef => fmt_func("cpool", inputs),
        OpCode::FloatAbs => fmt_func("abs", inputs),
        OpCode::FloatCeil => fmt_func("ceil", inputs),
        OpCode::FloatFloat2Float => fmt_func("float2float", inputs),
        OpCode::FloatFloor => fmt_func("floor", inputs),
        OpCode::FloatInt2Float => fmt_func("float", inputs),
        OpCode::FloatNan => fmt_func("nan", inputs),
        OpCode::FloatRound => fmt_func("round", inputs),
        OpCode::FloatSqrt => fmt_func("sqrt", inputs),
        OpCode::FloatTrunc => fmt_func("trunc", inputs),
        OpCode::IntCarry => fmt_func("carry", inputs),
        OpCode::IntSBorrow => fmt_func("sborrow", inputs),
        OpCode::IntSCarry => fmt_func("scarry", inputs),
        OpCode::IntSext => fmt_func("sext", inputs),
        OpCode::IntZext => fmt_func("zext", inputs),
        OpCode::New => fmt_func("newobject", inputs),
        OpCode::PopCount => fmt_func("popcount", inputs),
        OpCode::BoolAnd => fmt_binary("&&", inputs),
        OpCode::BoolOr => fmt_binary("||", inputs),
        OpCode::BoolXor => fmt_binary("^^", inputs),
        OpCode::FloatAdd => fmt_binary("f+", inputs),
        OpCode::FloatDiv => fmt_binary("f/", inputs),
        OpCode::FloatEqual => fmt_binary("f==", inputs),
        OpCode::FloatLess => fmt_binary("f<", inputs),
        OpCode::FloatLessEqual => fmt_binary("f<=", inputs),
        OpCode::FloatMult => fmt_binary("f*", inputs),
        OpCode::FloatNotEqual => fmt_binary("f!=", inputs),
        OpCode::FloatSub => fmt_binary("f-", inputs),
        OpCode::IntAdd => fmt_binary("+", inputs),
        OpCode::IntAnd => fmt_binary("&", inputs),
        OpCode::IntDiv => fmt_binary("/", inputs),
        OpCode::IntEqual => fmt_binary("==", inputs),
        OpCode::IntLess => fmt_binary("<", inputs),
        OpCode::IntGreater => fmt_binary(">", inputs),
        OpCode::IntLeft => fmt_binary("<<", inputs),
        OpCode::IntLessEqual => fmt_binary("<=", inputs),
        OpCode::IntGreaterEqual => fmt_binary(">=", inputs),
        OpCode::IntMult => fmt_binary("*", inputs),
        OpCode::IntNegate => fmt_unary("~", inputs),
        OpCode::IntNotEqual => fmt_binary("!=", inputs),
        OpCode::IntOr => fmt_binary("|", inputs),
        OpCode::IntRem => fmt_binary("%", inputs),
        OpCode::IntRight => fmt_binary(">>", inputs),
        OpCode::IntSDiv => fmt_binary("s/", inputs),
        OpCode::IntSLess => fmt_binary("s<", inputs),
        OpCode::IntSLessEqual => fmt_binary("s<=", inputs),
        OpCode::IntSGreater => fmt_binary("s>", inputs),
        OpCode::IntSGreaterEqual => fmt_binary("s>=", inputs),
        OpCode::IntSRem => fmt_binary("s%", inputs),
        OpCode::IntSRight => fmt_binary("s>>", inputs),
        OpCode::IntSub => fmt_binary("-", inputs),
        OpCode::IntXor => fmt_binary("^", inputs),
        OpCode::BoolNegate => fmt_unary("!", inputs),
        OpCode::FloatNeg => fmt_unary("f-", inputs),
        OpCode::Int2Comp => fmt_unary("-", inputs),
        OpCode::CallOther => fmt_func("callother", inputs),
        OpCode::SubPiece => format!("({})({})", inputs[0], inputs[1]),
        OpCode::Truncate => format!("{}:{}", parenthesize(inputs[0].to_string()), inputs[1]),
        OpCode::Switch => format!("\x1b[38;5;105mswitch\x1b[0m ({})", inputs[0]),
        _ => panic!("Don't know how to format {}!", opcode)
    }
}

fn fmt_output<T: FmtIface>(opcode: OpCode, output: Option<&T>) -> String {
    match output {
        Some(vnode) => if opcode == OpCode::DeclCopy {
            format!("{} = ", vnode.fmt_output())
        } else {
            format!("{} = ", vnode)
        },
        None        => "".to_string()
    }
}

impl<T: FmtIface> Display for Op<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}{}",
            fmt_output(self.opcode, self.output.as_ref()),
            fmt_inputs(self.opcode, &self.inputs, 0)
        )
    }
}

impl<T: FmtIface> Debug for Op<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

macro_rules! op_matches {
    ($op:expr, ($output:expr => $opcode:ident $($input:expr),*)) => {{
        $op.output
            .as_ref()
            .map(|out|
                out == $output && op_matches!($op, ($opcode $($input),*))
            ).unwrap_or(false)
    }};

    ($op:expr, ($opcode:ident $lhs:expr, $rhs:expr)) => {{
        $op.opcode == OpCode::$opcode &&
            $op.inputs.len() == 2 &&
            &$op.inputs[0] == $lhs &&
            &$op.inputs[1] == $rhs
    }};

    ($op:expr, ($opcode:ident $operand:expr)) => {{
        $op.opcode == OpCode::$opcode &&
            $op.inputs.len() == 1 &&
            &$op.inputs[0] == $operand
    }};
}

pub(crate) use op_matches;
