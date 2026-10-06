/* An unterminated literal holding non-ASCII text has no closing quote, so no length is read and nothing is reported by ARR00-C. */

#include <string.h>

void copy_unterminated(void)
{
  char buf[4];
  char *msg = "ééééé;
  strcpy(buf, msg);
}
