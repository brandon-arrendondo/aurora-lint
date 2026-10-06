/* The literal is 10 bytes (five 2-byte characters), not 5; a char-indexed scan used to cut it off a character boundary and panic. */

#include <string.h>

void copy_wide_literal(void)
{
  char buf[4];
  char *msg = "ééééé";
  strcpy(buf, msg);
}
