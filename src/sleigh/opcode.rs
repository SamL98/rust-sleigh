use std::str::FromStr;
use std::fmt;

#[repr(u32)]
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Copy, Clone, Debug)]
#[allow(dead_code)]
pub enum OpCode {
    Copy = 1,
    Load,
    Store,
    Branch,
    CBranch,
    BranchInd,
    Call,
    CallInd,
    CallOther,
    Return,
    IntEqual,
    IntNotEqual,
    IntSLess,
    IntSLessEqual,
    IntLess,
    IntLessEqual,
    IntZext,
    IntSext,
    IntAdd,
    IntSub,
    IntCarry,
    IntSCarry,
    IntSBorrow,
    Int2Comp,
    IntNegate,
    IntXor,
    IntAnd,
    IntOr,
    IntLeft,
    IntRight,
    IntSRight,
    IntMult,
    IntDiv,
    IntSDiv,
    IntRem,
    IntSRem,
    BoolNegate,
    BoolXor,
    BoolAnd,
    BoolOr,
    FloatEqual,
    FloatNotEqual,
    FloatLess,
    FloatLessEqual,
    FloatNan = 46,
    FloatAdd,
    FloatDiv,
    FloatMult,
    FloatSub,
    FloatNeg,
    FloatAbs,
    FloatSqrt,
    FloatInt2Float,
    FloatFloat2Float,
    FloatTrunc,
    FloatCeil,
    FloatFloor,
    FloatRound,
    MultiEqual,
    Indidrect,
    Piece,
    SubPiece,
    Cast,
    PtrAdd,
    PtrSub,
    SegmentOp,
    CPoolRef,
    New,
    Insert,
    Extract,
    PopCount,
    Label,
    IntSGreater,
    IntSGreaterEqual,
    IntGreater,
    IntGreaterEqual,
    AddrOf,
    Deref,
    Truncate,
    Decl,
    DeclCopy,
    ArrayIndex,
    FieldAccess,
    FieldDeref,
    Switch,
}

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseOpCodeError;

impl FromStr for OpCode {
    type Err = ParseOpCodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let opcode = match s {
            "COPY" => OpCode::Copy,
            "LOAD" => OpCode::Load,
            "STORE" => OpCode::Store,
            "BRANCH" => OpCode::Branch,
            "CBRANCH" => OpCode::CBranch,
            "BRANCHIND" => OpCode::BranchInd,
            "CALL" => OpCode::Call,
            "CALLIND" => OpCode::CallInd,
            "CALLOTHER" => OpCode::CallOther,
            "RETURN" => OpCode::Return,
            "INT_EQUAL" => OpCode::IntEqual,
            "INT_NOTEQUAL" => OpCode::IntNotEqual,
            "INT_SLESS" => OpCode::IntSLess,
            "INT_SLESSEQUAL" => OpCode::IntSLessEqual,
            "INT_LESS" => OpCode::IntLess,
            "INT_LESSEQUAL" => OpCode::IntLessEqual,
            "INT_ZEXT" => OpCode::IntZext,
            "INT_SEXT" => OpCode::IntSext,
            "INT_ADD" => OpCode::IntAdd,
            "INT_SUB" => OpCode::IntSub,
            "INT_CARRY" => OpCode::IntCarry,
            "INT_SCARRY" => OpCode::IntSCarry,
            "INT_SBORROW" => OpCode::IntSBorrow,
            "INT_2COMP" => OpCode::Int2Comp,
            "INT_NEGATE" => OpCode::IntNegate,
            "INT_XOR" => OpCode::IntXor,
            "INT_AND" => OpCode::IntAnd,
            "INT_OR" => OpCode::IntOr,
            "INT_LEFT" => OpCode::IntLeft,
            "INT_RIGHT" => OpCode::IntRight,
            "INT_SRIGHT" => OpCode::IntSRight,
            "INT_MULT" => OpCode::IntMult,
            "INT_DIV" => OpCode::IntDiv,
            "INT_SDIV" => OpCode::IntSDiv,
            "INT_REM" => OpCode::IntRem,
            "INT_SREM" => OpCode::IntSRem,
            "BOOL_NEGATE" => OpCode::BoolNegate,
            "BOOL_XOR" => OpCode::BoolXor,
            "BOOL_AND" => OpCode::BoolAnd,
            "BOOL_OR" => OpCode::BoolOr,
            "FLOAT_EQUAL" => OpCode::FloatEqual,
            "FLOAT_NOTEQUAL" => OpCode::FloatNotEqual,
            "FLOAT_LESS" => OpCode::FloatLess,
            "FLOAT_LESSEQUAL" => OpCode::FloatLessEqual,
            "FLOAT_NAN" => OpCode::FloatNan,
            "FLOAT_ADD" => OpCode::FloatAdd,
            "FLOAT_DIV" => OpCode::FloatDiv,
            "FLOAT_MULT" => OpCode::FloatMult,
            "FLOAT_SUB" => OpCode::FloatSub,
            "FLOAT_NEG" => OpCode::FloatNeg,
            "FLOAT_ABS" => OpCode::FloatAbs,
            "FLOAT_SQRT" => OpCode::FloatSqrt,
            "INT2FLOAT" => OpCode::FloatInt2Float,
            "FLOAT2FLOAT" => OpCode::FloatFloat2Float,
            "TRUNC" => OpCode::FloatTrunc,
            "CEIL" => OpCode::FloatCeil,
            "FLOOR" => OpCode::FloatFloor,
            "ROUND" => OpCode::FloatRound,
            "MULTIEQUAL" => OpCode::MultiEqual,
            "INDIRECT" => OpCode::Indidrect,
            "PIECE" => OpCode::Piece,
            "SUBPIECE" => OpCode::SubPiece,
            "CAST" => OpCode::Cast,
            "PTRADD" => OpCode::PtrAdd,
            "PTRSUB" => OpCode::PtrSub,
            "SEGMENTOP" => OpCode::SegmentOp,
            "CPOOLREF" => OpCode::CPoolRef,
            "NEW" => OpCode::New,
            "INSERT" => OpCode::Insert,
            "EXTRACT" => OpCode::Extract,
            "POPCOUNT" => OpCode::PopCount,
            "LABEL" => OpCode::Label,
            _ => {
                return Err(ParseOpCodeError);
            },
        };
        Ok(opcode)
    }
}

impl OpCode {
    pub fn inverse(self) -> Self {
        use OpCode::*;

        match self {
            IntAdd => IntSub,
            IntSub => IntAdd,
            IntEqual => IntNotEqual,
            IntNotEqual => IntEqual,
            IntSLess => IntSGreaterEqual,
            IntSLessEqual => IntSGreater,
            IntLess => IntGreaterEqual,
            IntLessEqual => IntGreater,
            IntSGreaterEqual => IntSLess,
            IntSGreater => IntSLessEqual,
            IntGreaterEqual => IntLess,
            IntGreater => IntLessEqual,
            _ => panic!("OpCode {} does not have an inverse", self),
        }
    }

    pub fn has_inverse(&self) -> bool {
        self.is_conditional()
    }

    pub fn is_conditional(&self) -> bool {
        use OpCode::*;

        matches!(self,
            BoolNegate |
            IntEqual |
            IntNotEqual |
            IntLess |
            IntSLess |
            IntLessEqual |
            IntSLessEqual |
            IntGreater |
            IntSGreater |
            IntGreaterEqual |
            IntSGreaterEqual
        )
    }

    pub fn is_commutative(&self) -> bool {
        use OpCode::*;

        matches!(self,
            IntAdd |
            IntAnd |
            IntOr |
            IntSub |
            IntMult |
            IntDiv |
            IntEqual |
            IntNotEqual
        )
    }

    pub fn is_associative(&self) -> bool {
        use OpCode::*;

        matches!(self,
            IntAdd
        )
    }

    pub fn increases(&self) -> bool {
        use OpCode::*;

        matches!(self,
            IntAdd |
            IntMult
        )
    }

    pub fn decreases(&self) -> bool {
        use OpCode::*;

        matches!(self,
            IntSub |
            IntDiv
        )
    }
}
