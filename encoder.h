#ifndef encoder_h
#define encoder_h

typedef struct instruction_prefix_t
{
  unsigned char size;
  unsigned char data[4];
} instruction_prefix_t;
typedef struct instruction_opcode_t
{
  unsigned char size;
  unsigned char data[3];
} instruction_opcode_t;

typedef struct instruction_modrm_t
{
  unsigned char size;
  unsigned char mod;
  unsigned char reg_op;
  unsigned char rm;
} instruction_modrm_t;
typedef struct instruction_sib_t
{
  unsigned char size;
  unsigned char scale;
  unsigned char index;
  unsigned char base;
} instruction_sib_t;

typedef struct instruction_disp_t
{
  unsigned char size;
  unsigned char data[4];
} instruction_disp_t;

typedef struct instruction_imm_t
{
  unsigned char size;
  unsigned char data[4];
} instruction_imm_t;

typedef struct formated_instruction_t
{
  instruction_prefix_t prefix;
  instruction_opcode_t opcode;
  instruction_modrm_t modrm;
  instruction_sib_t sib;
  instruction_disp_t disp;
  instruction_imm_t imm;
} formated_instruction_t;

typedef struct instruction_t
{
  unsigned char size;
  unsigned char *data;
} instruction_t;

#define MAX_REG_NAME_LEN 7
#define MAX_REG_TYPE_LEN 7
typedef struct registers_table_entry_t
{
  unsigned char reg_value;
  char reg_name[MAX_REG_NAME_LEN + 1];
  char reg_type[MAX_REG_TYPE_LEN + 1];
} registers_table_entry_t;

#define MAX_HEX_ENCODING_LEN 63
#define MAX_READABLE_ENCODING_LEN 63
typedef struct instructions_table_entry_t
{
  char hex_encoding[MAX_HEX_ENCODING_LEN + 1];
  char readable_encoding[MAX_READABLE_ENCODING_LEN + 1];
  /* TODO other fields from intstructions.txt */
} instructions_table_entry_t;

#define MAX_OPERAND_TYPE_LEN 7
#define MAX_OPERAND_NAME_LEN 31
#define MAX_OPERAND_VALUE_LEN 32 //TODO FIX
typedef struct operand_t
{
  char type[MAX_OPERAND_TYPE_LEN + 1];
  char name[MAX_OPERAND_NAME_LEN + 1];
  unsigned char value[MAX_OPERAND_VALUE_LEN];
} operand_t;

#define MAX_INPUT_INSTRUCTION_LEN 31
#define MAX_OPCODE_LEN 7
#define OPERANDS_MAX_NUM 4
typedef struct formated_input_instruction_t
{
  char opcode[MAX_OPCODE_LEN + 1];
  unsigned char operands_counter;
  operand_t operands[OPERANDS_MAX_NUM];
} formated_input_instruction_t;
#endif

extern void init_encoder();
extern void cleanup_encoder();
extern void free_instruction(instruction_t *instruction);
extern void print_instruction(instruction_t *instruction);
extern instruction_t *encode_instruction(char *input);
