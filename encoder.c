#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "encoder.h"
#include "TST.h"

#define get_modrm_data(modrm) ((modrm->mod) << 6) | ((modrm->reg_op) << 3) | (modrm->rm)
#define get_sib_data(sib) ((sib->scale) << 6) | ((sib->index) << 3) | (sib->base)

TST *instructions_table;
TST *registers_table;

instruction_t *_make_instruction(
    instruction_prefix_t *prefix,
    instruction_opcode_t *opcode,
    instruction_modrm_t *modrm,
    instruction_sib_t *sib,
    instruction_disp_t *disp,
    instruction_imm_t *imm)
{
  /* check for errors in input */
  int error = 0;
  if (!prefix || prefix->size > 4)
    error = 1;
  else if (!opcode || opcode->size > 3)
    error = 2;
  else if (!modrm || modrm->size > 1)
    error = 3;
  else if (!sib || sib->size > 1)
    error = 4;
  else if (!disp || (disp->size != 0 && disp->size != 1 && disp->size != 2 && disp->size != 4))
    error = 5;
  else if (!imm || (imm->size != 0 && imm->size != 1 && imm->size != 2 && imm->size != 4))
    error = 6;
  /* action when error */
  if (error)
  {
    fprintf(stderr, "unexpected error[verification(%d)]\n", error);
    exit(1);
  }

  /* create instruction */
  instruction_t *instruction = malloc(sizeof(instruction_t));
  instruction->size = prefix->size + opcode->size + modrm->size + sib->size + disp->size + imm->size;
  instruction->data = malloc(instruction->size);

  /* fill instruction with prefix */
  size_t current_size = 0;
  memcpy(instruction->data + current_size, prefix->data, prefix->size);
  current_size += prefix->size;
  /* fill instruction with opcode */
  memcpy(instruction->data + current_size, opcode->data, opcode->size);
  current_size += opcode->size;
  /* fill instruction with modrm */
  unsigned char modrm_data = get_modrm_data(modrm);
  memcpy(instruction->data + current_size, &modrm_data, modrm->size);
  current_size += modrm->size;
  /* fill instruction with sib */
  unsigned char sib_data = get_sib_data(sib);
  memcpy(instruction->data + current_size, &sib_data, sib->size);
  current_size += sib->size;
  /* fill instruction with displacement */
  memcpy(instruction->data + current_size, disp->data, disp->size);
  current_size += disp->size;
  /* fill instruction with immediate value */
  memcpy(instruction->data + current_size, imm->data, imm->size);
  current_size += imm->size;

  /*verify the instruction size */
  if (current_size != instruction->size)
  {
    fprintf(stderr, "unexpected error[size]\n");
    exit(1);
  }

  /* return the instruction pointer */
  return instruction;
}

instruction_t *make_instruction(formated_instruction_t *formated)
{
  if (!formated)
    return NULL;
  return _make_instruction(&formated->prefix, &formated->opcode, &formated->modrm,
                           &formated->sib, &formated->disp, &formated->imm);
}

void free_instruction(instruction_t *instruction)
{
  if (!instruction)
    return;
  if (instruction->data)
  {
    free(instruction->data);
    instruction->data = NULL;
    instruction->size = 0;
  }
  free(instruction);
  instruction = NULL;
}

void print_instruction(instruction_t *instruction)
{
  if (!instruction || instruction->size == 0 || instruction->data == NULL)
  {
    printf("(empty)\n");
    return;
  }
  printf("0x");
  for (int i = 0; i < instruction->size; i++)
  {
    unsigned char byte = instruction->data[i];
    printf("%02x", byte);
  }
  printf("\n");
}

int is_hex_n(char *str, size_t n)
{
  if (!str)
    return 0;
  for (size_t i = 0; i < n; i++)
  {
    if (str[i] >= 48 && str[i] <= 57)
      continue;
    if (str[i] >= 65 && str[i] <= 70)
      continue;
    if (str[i] >= 97 && str[i] <= 102)
      continue;
    return 0;
  }
  return 1;
}
int is_hex(char *str)
{
  return is_hex_n(str, strlen(str));
}

int is_number_n(char *str, size_t n)
{
  if (!str)
    return 0;
  for (int i = 0; i < n; i++)
  {
    if (str[i] >= 48 && str[i] <= 57)
      continue;
    else
      return 0;
  }
  return 1;
}
int is_number(char *str)
{
  return is_number_n(str, strlen(str));
}

unsigned char hex_to_byte(char *hex)
{
  if (!hex || strlen(hex) != 2)
  {
    fprintf(stderr, "Unexpected error: cant convert hex value (0x%s) into a signle byte\n", hex);
    exit(1);
  }

  return (unsigned char)strtol(hex, NULL, 16);
}

void fill_formated_instruction_with_defaults(formated_instruction_t *formated, char *_default_encoding)
{
  if (!formated || !_default_encoding)
    return;
  /* copy string to heap */
  size_t default_encoding_len = strlen(_default_encoding);
  char *default_encoding = malloc(default_encoding_len);
  strcpy(default_encoding, _default_encoding);

  /* read information */
  int look_for_prefix = 1;
  int look_for_opcode = 1;
  int look_for_modrm = 1;
  int look_for_imm = 1;
  /* TODO: LOOK FOR DISP AND LOOK FOR SIB BYTES*/
  char *token = strtok(default_encoding, " ");
  do
  {
    if (!token)
      break;

    /* check errors */
    if (strlen(token) != 2)
    {
      fprintf(stderr, "Unexpected error: default foramt (%s)\n", token);
      exit(1);
    }

    /* if a hex value */
    if (is_hex_n(token, 2))
    {
      /* check prefixes */
      if (
          (look_for_prefix) && (formated->prefix.size < 4) &&
          (!strcmp(token, "F0") || !strcmp(token, "F2") ||
           !strcmp(token, "F3") || !strcmp(token, "2E") ||
           !strcmp(token, "36") || !strcmp(token, "3E") ||
           !strcmp(token, "26") || !strcmp(token, "64") ||
           !strcmp(token, "65") || !strcmp(token, "66") ||
           !strcmp(token, "67")))
      {
        formated->prefix.data[formated->prefix.size++] = hex_to_byte(token);
        continue;
      }

      /* stop looking for prefixes */
      look_for_prefix = 0;

      /* look for opcode */
      if (look_for_opcode)
      {
        formated->opcode.data[formated->opcode.size++] = hex_to_byte(token);
        if (!strcmp(token, "0F") || formated->opcode.size == 2)
        {
          continue;
        }
        /* stop looking for opcode bytes */
        look_for_opcode = 0;
      }
    }
    /* if not a hex value */
    else
    {
      if (token[0] == '/' && look_for_modrm)
      {
        if (token[1] == 'r')
        {
          formated->modrm.reg_op = 0;
          formated->modrm.size = 1;
          look_for_modrm = 0;
          continue;
        }
        else if (token[1] >= 48 && token[1] <= 55)
        {
          formated->modrm.reg_op = token[1] - 48;
          formated->modrm.size = 1;
          look_for_modrm = 0;
          continue;
        }
        else
        {
          fprintf(stderr, "Unexpected error: unknown token (%s)\n", token);
          exit(1);
        }
      }
      else if (token[0] == 'i' && look_for_imm)
      {
        switch (token[1])
        {
        case 'b':
          formated->imm.size = 1;
          look_for_modrm = 0;
          continue;
        case 'w':
          formated->imm.size = 2;
          look_for_modrm = 0;
          continue;
        case 'd':
          formated->imm.size = 4;
          look_for_modrm = 0;
          continue;
        default:
          fprintf(stderr, "Unexpected error: unknown token (%s)\n", token);
          exit(1);
        }
      }
      else
      {
        fprintf(stderr, "Unexpected error: unknown token (%s)\n", token);
        exit(1);
      }
    }

  } while ((token = strtok(NULL, " ")));

  /* cleanup */
  free(default_encoding);
  default_encoding = NULL;
}
void fill_formated_instruction_with_input(formated_instruction_t *formated, formated_input_instruction_t *formated_input_inst)
{
  if (!formated || !formated_input_inst)
    return;

  for (size_t i = 0; i < formated_input_inst->operands_counter; i++)
  {
    if (!strcmp(formated_input_inst->operands[i].type, "r8") ||
        !strcmp(formated_input_inst->operands[i].type, "r16") ||
        !strcmp(formated_input_inst->operands[i].type, "r32"))
    {
      formated->modrm.reg_op = formated_input_inst->operands[i].value[0];
    }
    else if (!strcmp(formated_input_inst->operands[i].type, "r/m8_r") ||
             !strcmp(formated_input_inst->operands[i].type, "r/m16_r") ||
             !strcmp(formated_input_inst->operands[i].type, "r/m32_r"))
    {
      formated->modrm.mod = 0b11;
      formated->modrm.rm = formated_input_inst->operands[i].value[0];
    }
    else if (!strcmp(formated_input_inst->operands[i].type, "imm8") ||
             !strcmp(formated_input_inst->operands[i].type, "imm16") ||
             !strcmp(formated_input_inst->operands[i].type, "imm32"))
    {
      memcpy(formated->imm.data, formated_input_inst->operands[i].value, formated->imm.size);
    }
    else
    {
      fprintf(stderr, "Unexpected Error: operands other than registers and immediates are not supported yet.\n");
      exit(1);
    }
  }
}

/* check if empty or commented line */
int is_ignored(char *line, size_t len)
{
  if (!line)
    return -1;
  int ignore = 0;
  for (int i = 0; i < len; i++)
  {
    if (ignore)
      break;
    else if (i == len - 1 && line[i] == '\n')
      ignore = 1;
    else if (line[i] == '#')
      ignore = 1;
    else if (line[i] == ' ' || line[i] == '\t')
      continue;
    else
      break;
  }
  return ignore;
}

/* right trim by just moving the string null terminator */
size_t rtrim(char *str)
{
  //TODO FIX
  size_t len = 0;
  if (!str || !(len = strlen(str)))
    return 0;
  size_t new_len = len;
  for (int i = len - 1; i >= 0; i--)
  {
    if (str[i] == ' ' || str[i] == '\t' || str[i] == '\n')
      new_len--;
    else
      break;
  }
  str[new_len] = '\0';
  return new_len;
}

/* initialize instructions table */
TST *init_instructions_table(char *instructions_file)
{
  if (!instructions_file)
    return NULL;

  /* open instructions file*/
  FILE *inst_f = fopen(instructions_file, "r");
  if (!inst_f)
    return NULL;

  /* init opcodes table */
  TST *instructions_table = TST_init();
  TSTInfo *instructions_table_info = (TSTInfo *)instructions_table->data;

  /* prepare for reading line */
  char *line = NULL;
  size_t buff_capacity = 0;
  size_t line_len;

  /* read line by line */
  while ((line_len = getline(&line, &buff_capacity, inst_f)) != EOF)
  {
    /* ignore empty and commented lines */
    if (is_ignored(line, line_len))
      continue;

    /* get relevant fields from the line */
    char *hex_encoding = strtok(line, "|");
    char *readable_encoding = strtok(NULL, "|");
    /* TODO other fields from intstructions.txt */

    /* remove terminating spaces */
    rtrim(hex_encoding);
    rtrim(readable_encoding);

    /* create instruction table entry */
    instructions_table_entry_t *table_entry = malloc(sizeof(instructions_table_entry_t));
    memset(table_entry, 0, sizeof(instructions_table_entry_t));
    strcpy(table_entry->hex_encoding, hex_encoding);
    strcpy(table_entry->readable_encoding, readable_encoding);

    /* keep track of mallocs */
    SLL_insert(instructions_table_info->memory_allocations, table_entry);

    /* add entry to table */
    TST_put(instructions_table, readable_encoding, table_entry);
  }
  /* close instructions file */
  fclose(inst_f);
  return instructions_table;
}

TST *init_registers_table(char *registers_file)
{
  if (!registers_file)
    return NULL;

  /* open registers file */
  FILE *reg_f = fopen(registers_file, "r");
  if (!reg_f)
    return NULL;

  /* init registers table */
  TST *registers_table = TST_init();
  TSTInfo *registers_table_info = (TSTInfo *)registers_table->data;

  /* prepare for reading line */
  char *line = NULL;
  size_t buff_capacity = 0;
  size_t line_len;

  /* read line by line */
  while ((line_len = getline(&line, &buff_capacity, reg_f)) != EOF)
  {
    /* ignore empty and commented lines */
    if (is_ignored(line, line_len))
      continue;

    /* get relevant fields from the line */
    char *reg_name = strtok(line, "|");
    char *reg_value = strtok(NULL, "|");
    char *reg_type = strtok(NULL, "|");

    /* remove terminating spaces */
    rtrim(reg_name);
    rtrim(reg_value);
    rtrim(reg_type);

    /* create register table entry */
    registers_table_entry_t *table_entry = malloc(sizeof(registers_table_entry_t));
    memset(table_entry, 0, sizeof(registers_table_entry_t));
    strcpy(table_entry->reg_name, reg_name);
    strcpy(table_entry->reg_type, reg_type);
    table_entry->reg_value = (unsigned char)atoi(reg_value);

    /* keep track of mallocs */
    SLL_insert(registers_table_info->memory_allocations, table_entry);

    /* add entry to table */
    TST_put(registers_table, reg_name, table_entry);
  }
  /* close registers file */
  fclose(reg_f);
  return registers_table;
}

void instructions_table_cleanup(TST *instructions_table)
{
  if (!instructions_table)
    return;
  TST_free(instructions_table);
  instructions_table = NULL;
}
void registers_table_cleanup(TST *registers_table)
{
  if (!registers_table)
    return;
  TST_free(registers_table);
  registers_table = NULL;
}

void str_to_input_instruction(char *_str, formated_input_instruction_t *inst)
{
  if (!_str || !inst || !registers_table)
    return;

  /* temporary copy the string */
  size_t len = strlen(_str);
  char *str = malloc(len + 1);
  stpncpy(str, _str, len);

  rtrim(str);
  char *opcode = strtok(str, " ");
  strcpy(inst->opcode, opcode);

  size_t max_reg_size = 8;
  for (int i = 0; i < OPERANDS_MAX_NUM; i++)
  {
    char *operand_str = strtok(NULL, ", ");
    if (!operand_str)
      break;
    inst->operands_counter++;
    strcpy(inst->operands[i].name, operand_str);

    registers_table_entry_t *entry = TST_get(registers_table, operand_str);
    if (entry)
    {
      strcpy(inst->operands[i].type, entry->reg_type);
      inst->operands[i].value[0] = entry->reg_value;
      if (!strcmp(entry->reg_type, "r16"))
      {
        if (max_reg_size < 16)
          max_reg_size = 16;
      }
      else if (!strcmp(entry->reg_type, "r32"))
      {
        if (max_reg_size < 32)
          max_reg_size = 32;
      }
    }
    else if (is_number(operand_str))
    {
      //TODO: FIX assumption -> assume int is 32bits
      unsigned int value = atoi(operand_str);
      if (value <= 0xff)
      {
        strcpy(inst->operands[i].type, "imm8");
        inst->operands[i].value[0] = (unsigned char)(value);
      }
      else if (value <= 0xffff && max_reg_size == 16)
      {
        strcpy(inst->operands[i].type, "imm16");
        inst->operands[i].value[1] = (unsigned char)(value >> 8);
        inst->operands[i].value[0] = (unsigned char)(value);
      }
      else if (value <= 0xffffffff)
      {
        strcpy(inst->operands[i].type, "imm32");
        inst->operands[i].value[3] = (unsigned char)(value >> 24);
        inst->operands[i].value[2] = (unsigned char)(value >> 16);
        inst->operands[i].value[1] = (unsigned char)(value >> 8);
        inst->operands[i].value[0] = (unsigned char)(value);
      }
      else
      {
        fprintf(stderr, "Unexpected error: immediate value is too large\n");
        exit(1);
      }
    }
    else
    {
      fprintf(stderr, "Unexpected error: operands other than numbers and registers are not supported yet\n");
      exit(1);
    }
  }

  // }
  /* cleanup */
  free(str);
}

void formated_input_instruction_to_gen_inst_str(formated_input_instruction_t *inst, char *inst_str)
{
  if (!inst || !inst_str)
    return;

  strcpy(inst_str, inst->opcode);
  for (size_t i = 0; i < inst->operands_counter; i++)
  {
    if (i == 0)
      strcat(inst_str, " ");

    strcat(inst_str, inst->operands[i].type);
    if (i != inst->operands_counter - 1)
      strcat(inst_str, ", ");
  }
}

instructions_table_entry_t *search_instructions_table(formated_input_instruction_t *inst)
{
  if (!inst || !instructions_table)
    return NULL;

  size_t num_register_operands = 0;
  for (size_t i = 0; i < inst->operands_counter; i++)
  {
    if (!strcmp(inst->operands[i].type, "r8") ||
        !strcmp(inst->operands[i].type, "r16") ||
        !strcmp(inst->operands[i].type, "r32"))
    {
      num_register_operands++;
    }
  }

  char inst_str[MAX_INPUT_INSTRUCTION_LEN + 1];
  if (num_register_operands == 0)
  {
    formated_input_instruction_to_gen_inst_str(inst, inst_str);
    return TST_get(instructions_table, inst_str);
  }
  else
  {
    formated_input_instruction_t temp_inst;
    memcpy((void *)&temp_inst, (void *)inst, sizeof(formated_input_instruction_t));
    for (size_t i = 0; i < num_register_operands; i++)
    {
      if (!strcmp(inst->operands[i].type, "r8"))
        strcpy(temp_inst.operands[i].type, "r/m8");
      else if (!strcmp(inst->operands[i].type, "r16"))
        strcpy(temp_inst.operands[i].type, "r/m16");
      else if (!strcmp(inst->operands[i].type, "r32"))
        strcpy(temp_inst.operands[i].type, "r/m32");
      else
        continue;
      formated_input_instruction_to_gen_inst_str(&temp_inst, inst_str);
      instructions_table_entry_t *entry = TST_get(instructions_table, inst_str);
      if (entry)
      {
        memcpy((void *)inst, (void *)&temp_inst, sizeof(formated_input_instruction_t));
        /*NOTE: r/m8_r, r/m16_r, and r/m32_r are for indicating that the r/m field is a register */
        strcat(inst->operands[i].type, "_r");
        return entry;
      }
      else
        memcpy((void *)&temp_inst, (void *)inst, sizeof(formated_input_instruction_t));
    }
  }
  return NULL;
}

instruction_t *encode_instruction(char *input)
{
  /* create input instruction */
  formated_input_instruction_t formated_input_instruction;
  memset(&formated_input_instruction, 0, sizeof(formated_input_instruction));

  /* parse input */
  str_to_input_instruction(input, &formated_input_instruction);

  /* search instructions table */
  instructions_table_entry_t *entry = search_instructions_table(&formated_input_instruction);
  if (!entry)
  {
    fprintf(stderr, "Unexpected Error: unknown instruction (%s)\n", input);
    exit(1);
  }

  /* created formated instruction */
  formated_instruction_t formated_instruction;
  memset(&formated_instruction, 0, sizeof(formated_instruction));

  /* fill the formated instruction with defaults of the instruction */
  fill_formated_instruction_with_defaults(&formated_instruction, entry->hex_encoding);
  fill_formated_instruction_with_input(&formated_instruction, &formated_input_instruction);

  /* create real instruction from formated instruction */
  instruction_t *instruction = make_instruction(&formated_instruction);
  return instruction;
}

void init_encoder()
{
  /* generate tables */
  instructions_table = init_instructions_table("instructions.txt");
  registers_table = init_registers_table("registers.txt");
}
void cleanup_encoder()
{
  /* cleanup */
  instructions_table_cleanup(instructions_table);
  registers_table_cleanup(registers_table);
}