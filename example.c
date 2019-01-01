#include "encoder.h"
int main()
{
  /*init*/
  init_encoder();

  /* encode x86 */
  instruction_t *instruction = encode_instruction("ADD EBX, 22");

  /* print instruction */
  print_instruction(instruction);

  /* clean up the instruction */
  free_instruction(instruction);

  /* cleanup the encoder */
  cleanup_encoder();
}