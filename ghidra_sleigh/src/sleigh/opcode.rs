use std::fmt;

#[repr(u32)]
#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug)]
pub enum OpCode {
    COPY = 1,
    LOAD,
    STORE,
    BRANCH,
    CBRANCH,
    BRANCHIND,
    CALL,
    CALLIND,
    CALLOTHER,
    RETURN,
    INT_EQUAL,
    INT_NOTEQUAL,
    INT_SLESS,
    INT_SLESSEQUAL,
    INT_LESS,
    INT_LESSEQUAL,
    INT_ZEXT,
    INT_SEXT,
    INT_ADD,
    INT_SUB,
    INT_CARRY,
    INT_SCARRY,
    INT_SBORROW,
    INT_2COMP,
    INT_NEGATE,
    INT_XOR,
    INT_AND,
    INT_OR,
    INT_LEFT,
    INT_RIGHT,
    INT_SRIGHT,
    INT_MULT,
    INT_DIV,
    INT_SDIV,
    INT_REM,
    INT_SREM,
    BOOL_NEGATE,
    BOOL_XOR,
    BOOL_AND,
    BOOL_OR,
    FLOAT_EQUAL,
    FLOAT_NOTEQUAL,
    FLOAT_LESS,
    FLOAT_LESSEQUAL,
    INVALID,
    FLOAT_NAN,
    FLOAT_ADD,
    FLOAT_DIV,
    FLOAT_MULT,
    FLOAT_SUB,
    FLOAT_NEG,
    FLOAT_ABS,
    FLOAT_SQRT,
    FLOAT_INT2FLOAT,
    FLOAT_FLOAT2FLOAT,
    FLOAT_TRUNC,
    FLOAT_CEIL,
    FLOAT_FLOOR,
    FLOAT_ROUND,
    MULTIEQUAL,
    INDIRECT,
    PIECE,
    SUBPIECE,
    CAST,
    PTRADD,
    PTRSUB,
    SEGMENTOP,
    CPOOLREF,
    NEW,
    INSERT,
    EXTRACT,
    POPCOUNT,
}

impl OpCode {
    pub fn is_unary(&self) -> bool {
        match self {
            OpCode::COPY
            | OpCode::BOOL_NEGATE
            | OpCode::FLOAT_ABS
            | OpCode::FLOAT_NEG
            | OpCode::INT_2COMP
            | OpCode::INT_NEGATE
            | OpCode::INT_SEXT
            | OpCode::INT_ZEXT
            | OpCode::POPCOUNT => true,
            _ => false,
        }
    }

    pub fn is_binary(&self) -> bool {
        match self {
            OpCode::BOOL_OR
            | OpCode::BOOL_AND
            | OpCode::BOOL_XOR
            | OpCode::INT_ADD
            | OpCode::INT_AND
            | OpCode::INT_CARRY
            | OpCode::INT_SCARRY
            | OpCode::INT_DIV
            | OpCode::INT_EQUAL
            | OpCode::INT_NOTEQUAL
            | OpCode::INT_LEFT
            | OpCode::INT_LESS
            | OpCode::INT_LESSEQUAL
            | OpCode::INT_MULT
            | OpCode::INT_NOTEQUAL
            | OpCode::INT_REM
            | OpCode::INT_RIGHT
            | OpCode::INT_SBORROW
            | OpCode::INT_SDIV
            | OpCode::INT_SLESS
            | OpCode::INT_SLESSEQUAL
            | OpCode::INT_SREM
            | OpCode::INT_SRIGHT
            | OpCode::INT_SUB
            | OpCode::INT_XOR
            | OpCode::INT_OR
            | OpCode::PIECE
            | OpCode::SUBPIECE
            | OpCode::FLOAT_ADD
            | OpCode::FLOAT_DIV
            | OpCode::FLOAT_EQUAL
            | OpCode::FLOAT_LESS
            | OpCode::FLOAT_LESSEQUAL
            | OpCode::FLOAT_MULT => true,
            _ => false,
        }
    }

    pub fn to_str(&self) -> String {
        let opstr = match self {
            &OpCode::COPY => "COPY",
            &OpCode::LOAD => "LOAD",
            &OpCode::STORE => "STORE",
            &OpCode::BRANCH => "BRANCH",
            &OpCode::CBRANCH => "CBRANCH",
            &OpCode::BRANCHIND => "BRANCHIND",
            &OpCode::CALL => "CALL",
            &OpCode::CALLIND => "CALLIND",
            &OpCode::CALLOTHER => "CALLOTHER",
            &OpCode::RETURN => "RETURN",
            &OpCode::INT_EQUAL => "INT_EQUAL",
            &OpCode::INT_NOTEQUAL => "INT_NOTEQUAL",
            &OpCode::INT_SLESS => "INT_SLESS",
            &OpCode::INT_SLESSEQUAL => "INT_SLESSEQUAL",
            &OpCode::INT_LESS => "INT_LESS",
            &OpCode::INT_LESSEQUAL => "INT_LESSEQUAL",
            &OpCode::INT_ZEXT => "INT_ZEXT",
            &OpCode::INT_SEXT => "INT_SEXT",
            &OpCode::INT_ADD => "INT_ADD",
            &OpCode::INT_SUB => "INT_SUB",
            &OpCode::INT_CARRY => "INT_CARRY",
            &OpCode::INT_SCARRY => "INT_SCARRY",
            &OpCode::INT_SBORROW => "INT_SBORROW",
            &OpCode::INT_2COMP => "INT_2COMP",
            &OpCode::INT_NEGATE => "INT_NEGATE",
            &OpCode::INT_XOR => "INT_XOR",
            &OpCode::INT_AND => "INT_AND",
            &OpCode::INT_OR => "INT_OR",
            &OpCode::INT_LEFT => "INT_LEFT",
            &OpCode::INT_RIGHT => "INT_RIGHT",
            &OpCode::INT_SRIGHT => "INT_SRIGHT",
            &OpCode::INT_MULT => "INT_MULT",
            &OpCode::INT_DIV => "INT_DIV",
            &OpCode::INT_SDIV => "INT_SDIV",
            &OpCode::INT_REM => "INT_REM",
            &OpCode::INT_SREM => "INT_SREM",
            &OpCode::BOOL_NEGATE => "BOOL_NEGATE",
            &OpCode::BOOL_XOR => "BOOL_XOR",
            &OpCode::BOOL_AND => "BOOL_AND",
            &OpCode::BOOL_OR => "BOOL_OR",
            &OpCode::FLOAT_EQUAL => "FLOAT_EQUAL",
            &OpCode::FLOAT_NOTEQUAL => "FLOAT_NOTEQUAL",
            &OpCode::FLOAT_LESS => "FLOAT_LESS",
            &OpCode::FLOAT_LESSEQUAL => "FLOAT_LESSEQUAL",
            &OpCode::FLOAT_NAN => "FLOAT_NAN",
            &OpCode::FLOAT_ADD => "FLOAT_ADD",
            &OpCode::FLOAT_DIV => "FLOAT_DIV",
            &OpCode::FLOAT_MULT => "FLOAT_MULT",
            &OpCode::FLOAT_SUB => "FLOAT_SUB",
            &OpCode::FLOAT_NEG => "FLOAT_NEG",
            &OpCode::FLOAT_ABS => "FLOAT_ABS",
            &OpCode::FLOAT_SQRT => "FLOAT_SQRT",
            &OpCode::FLOAT_INT2FLOAT => "FLOAT_INT2FLOAT",
            &OpCode::FLOAT_FLOAT2FLOAT => "FLOAT_FLOAT2FLOAT",
            &OpCode::FLOAT_TRUNC => "FLOAT_TRUNC",
            &OpCode::FLOAT_CEIL => "FLOAT_CEIL",
            &OpCode::FLOAT_FLOOR => "FLOAT_FLOOR",
            &OpCode::FLOAT_ROUND => "FLOAT_ROUND",
            &OpCode::MULTIEQUAL => "MULTIEQUAL",
            &OpCode::INDIRECT => "INDIRECT",
            &OpCode::PIECE => "PIECE",
            &OpCode::SUBPIECE => "SUBPIECE",
            &OpCode::CAST => "CAST",
            &OpCode::PTRADD => "PTRADD",
            &OpCode::PTRSUB => "PTRSUB",
            &OpCode::SEGMENTOP => "SEGMENTOP",
            &OpCode::CPOOLREF => "CPOOLREF",
            &OpCode::NEW => "NEW",
            &OpCode::INSERT => "INSERT",
            &OpCode::EXTRACT => "EXTRACT",
            &OpCode::POPCOUNT => "POPCOUNT",
            _ => unimplemented!(),
        };
        format!("{}", opstr)
    }
}

// impl fmt::Debug for OpCode {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         write!(f, "{}", self.to_st())
//     }
// }

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            &OpCode::COPY => "",
            &OpCode::LOAD => "load",
            &OpCode::STORE => "store",
            &OpCode::BRANCH => "goto",
            &OpCode::CBRANCH => "ifgoto",
            &OpCode::BRANCHIND => "goto",
            &OpCode::CALL => "call",
            &OpCode::CALLIND => "call",
            &OpCode::CALLOTHER => "callother",
            &OpCode::RETURN => "return",
            &OpCode::INT_EQUAL => "==",
            &OpCode::INT_NOTEQUAL => "!=",
            &OpCode::INT_SLESS => "s<",
            &OpCode::INT_SLESSEQUAL => "s<=",
            &OpCode::INT_LESS => "<",
            &OpCode::INT_LESSEQUAL => "<=",
            &OpCode::INT_ZEXT => "zext",
            &OpCode::INT_SEXT => "sext",
            &OpCode::INT_ADD => "+",
            &OpCode::INT_SUB => "-",
            &OpCode::INT_CARRY => "carry",
            &OpCode::INT_SCARRY => "scarry",
            &OpCode::INT_SBORROW => "sborrow",
            &OpCode::INT_2COMP => "-",
            &OpCode::INT_NEGATE => "~",
            &OpCode::INT_XOR => "^",
            &OpCode::INT_AND => "&",
            &OpCode::INT_OR => "|",
            &OpCode::INT_LEFT => "<<",
            &OpCode::INT_RIGHT => ">>",
            &OpCode::INT_SRIGHT => "s>>",
            &OpCode::INT_MULT => "*",
            &OpCode::INT_DIV => "/",
            &OpCode::INT_SDIV => "s/",
            &OpCode::INT_REM => "%",
            &OpCode::INT_SREM => "s%",
            &OpCode::BOOL_NEGATE => "!",
            &OpCode::BOOL_XOR => "^^",
            &OpCode::BOOL_AND => "&&",
            &OpCode::BOOL_OR => "||",
            &OpCode::FLOAT_EQUAL => "f==",
            &OpCode::FLOAT_NOTEQUAL => "f!=",
            &OpCode::FLOAT_LESS => "f<",
            &OpCode::FLOAT_LESSEQUAL => "f<=",
            &OpCode::FLOAT_NAN => "nan",
            &OpCode::FLOAT_ADD => "f+",
            &OpCode::FLOAT_DIV => "f/",
            &OpCode::FLOAT_MULT => "f*",
            &OpCode::FLOAT_SUB => "f-",
            &OpCode::FLOAT_NEG => "f-",
            &OpCode::FLOAT_ABS => "abs",
            &OpCode::FLOAT_SQRT => "sqrt",
            &OpCode::FLOAT_INT2FLOAT => "int2float",
            &OpCode::FLOAT_FLOAT2FLOAT => "float2float",
            &OpCode::FLOAT_TRUNC => "trunc",
            &OpCode::FLOAT_CEIL => "ceil",
            &OpCode::FLOAT_FLOOR => "floor",
            &OpCode::FLOAT_ROUND => "round",
            &OpCode::MULTIEQUAL => "phi",
            &OpCode::INDIRECT => "indirect",
            &OpCode::PIECE => "piece",
            &OpCode::SUBPIECE => "subpiece",
            &OpCode::INSERT => "insert",
            &OpCode::EXTRACT => "extract",
            &OpCode::POPCOUNT => "popcount",
            _ => unimplemented!(),
        };
        write!(f, "{}", s)
    }
}
