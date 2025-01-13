typedef uint32_t uintm;
typedef int32_t intm;

typedef uint64_t uint8;
typedef int64_t int8;
typedef uint32_t uint4;
typedef int32_t int4;
typedef uint16_t uint2;
typedef int16_t int2;
typedef uint8_t uint1;
typedef int8_t int1;

typedef uintptr_t uintp;
typedef int8 intb;
typedef uint8 uintb;

typedef enum {
 csleigh_CPUI_COPY = 1, csleigh_CPUI_LOAD = 2, csleigh_CPUI_STORE = 3, csleigh_CPUI_BRANCH = 4, csleigh_CPUI_CBRANCH = 5, csleigh_CPUI_BRANCHIND = 6, csleigh_CPUI_CALL = 7, csleigh_CPUI_CALLIND = 8, csleigh_CPUI_CALLOTHER = 9, csleigh_CPUI_RETURN = 10, csleigh_CPUI_INT_EQUAL = 11, csleigh_CPUI_INT_NOTEQUAL = 12, csleigh_CPUI_INT_SLESS = 13, csleigh_CPUI_INT_SLESSEQUAL = 14, csleigh_CPUI_INT_LESS = 15, csleigh_CPUI_INT_LESSEQUAL = 16, csleigh_CPUI_INT_ZEXT = 17, csleigh_CPUI_INT_SEXT = 18, csleigh_CPUI_INT_ADD = 19, csleigh_CPUI_INT_SUB = 20, csleigh_CPUI_INT_CARRY = 21, csleigh_CPUI_INT_SCARRY = 22, csleigh_CPUI_INT_SBORROW = 23, csleigh_CPUI_INT_2COMP = 24, csleigh_CPUI_INT_NEGATE = 25, csleigh_CPUI_INT_XOR = 26, csleigh_CPUI_INT_AND = 27, csleigh_CPUI_INT_OR = 28, csleigh_CPUI_INT_LEFT = 29, csleigh_CPUI_INT_RIGHT = 30, csleigh_CPUI_INT_SRIGHT = 31, csleigh_CPUI_INT_MULT = 32, csleigh_CPUI_INT_DIV = 33, csleigh_CPUI_INT_SDIV = 34, csleigh_CPUI_INT_REM = 35, csleigh_CPUI_INT_SREM = 36, csleigh_CPUI_BOOL_NEGATE = 37, csleigh_CPUI_BOOL_XOR = 38, csleigh_CPUI_BOOL_AND = 39, csleigh_CPUI_BOOL_OR = 40, csleigh_CPUI_FLOAT_EQUAL = 41, csleigh_CPUI_FLOAT_NOTEQUAL = 42, csleigh_CPUI_FLOAT_LESS = 43, csleigh_CPUI_FLOAT_LESSEQUAL = 44, csleigh_CPUI_FLOAT_NAN = 46, csleigh_CPUI_FLOAT_ADD = 47, csleigh_CPUI_FLOAT_DIV = 48, csleigh_CPUI_FLOAT_MULT = 49, csleigh_CPUI_FLOAT_SUB = 50, csleigh_CPUI_FLOAT_NEG = 51, csleigh_CPUI_FLOAT_ABS = 52, csleigh_CPUI_FLOAT_SQRT = 53, csleigh_CPUI_FLOAT_INT2FLOAT = 54, csleigh_CPUI_FLOAT_FLOAT2FLOAT = 55, csleigh_CPUI_FLOAT_TRUNC = 56, csleigh_CPUI_FLOAT_CEIL = 57, csleigh_CPUI_FLOAT_FLOOR = 58, csleigh_CPUI_FLOAT_ROUND = 59, csleigh_CPUI_MULTIEQUAL = 60, csleigh_CPUI_INDIRECT = 61, csleigh_CPUI_PIECE = 62, csleigh_CPUI_SUBPIECE = 63, csleigh_CPUI_CAST = 64, csleigh_CPUI_PTRADD = 65, csleigh_CPUI_PTRSUB = 66, csleigh_CPUI_SEGMENTOP = 67, csleigh_CPUI_CPOOLREF = 68, csleigh_CPUI_NEW = 69, csleigh_CPUI_INSERT = 70, csleigh_CPUI_EXTRACT = 71, csleigh_CPUI_POPCOUNT = 72,
} csleigh_OpCode;

typedef void *csleigh_Context;
typedef void *csleigh_AddrSpace;

typedef struct {
 csleigh_AddrSpace space;
 uintb offset;
} csleigh_Address;

typedef struct {
 csleigh_AddrSpace space;
 uintb offset;
 uint4 size;
} csleigh_Varnode;

typedef struct {
 csleigh_Address pc;
 uintm uniq;
 uintm order;
} csleigh_SeqNum;

typedef struct {
 csleigh_SeqNum seq;
 csleigh_OpCode opcode;
 csleigh_Varnode *output;
 csleigh_Varnode *inputs;
 unsigned int inputs_count;
} csleigh_PcodeOp;

typedef enum {
 csleigh_ERROR_TYPE_NOERROR = 0,
 csleigh_ERROR_TYPE_GENERIC = 1,
 csleigh_ERROR_TYPE_UNIMPL = 2,
 csleigh_ERROR_TYPE_BADDATA = 3,
} csleigh_ErrorType;

typedef struct {
 csleigh_Address address;
 int4 instruction_length;
} csleigh_UnimplError;

typedef struct {
 csleigh_Address address;
} csleigh_BadDataError;

typedef struct {
 csleigh_ErrorType type;
 const char *explain;
 union {
  csleigh_UnimplError unimpl;
  csleigh_BadDataError baddata;
 };
} csleigh_Error;

typedef struct {
 csleigh_Address address;
 int4 length;
 const char *asm_mnem;
 const char *asm_body;
 csleigh_PcodeOp *ops;
 unsigned int ops_count;
} csleigh_Translation;

typedef struct {
 csleigh_Error error;
 csleigh_Translation *instructions;
 unsigned int instructions_count;
} csleigh_TranslationResult;

typedef struct {
 const char *name;
 csleigh_Varnode varnode;
} csleigh_RegisterDefinition;

csleigh_Context csleigh_createContext(const char *slafile);
void csleigh_destroyContext(csleigh_Context c);
csleigh_TranslationResult *csleigh_translate(csleigh_Context c, const unsigned char *bytes, unsigned int num_bytes, uintb address, unsigned int max_instructions, _Bool bb_terminating);
void csleigh_freeResult(csleigh_TranslationResult *r);
void csleigh_setVariableDefault(csleigh_Context c, const char *name, uintm val);
int csleigh_Addr_isConstant(csleigh_Address *a);
csleigh_AddrSpace csleigh_Addr_getSpaceFromConst(csleigh_Address *a);
const char *csleigh_AddrSpace_getName(csleigh_AddrSpace as);
const char *csleigh_Sleigh_getRegisterName(csleigh_Context c, csleigh_AddrSpace as, uintb off, int4 size);
unsigned int csleigh_Sleigh_getNumRegisters(csleigh_Context c);
void csleigh_Sleigh_getAllRegisters(csleigh_Context c, unsigned int n, csleigh_RegisterDefinition *registers);
