/*
 * Rule: STR34-C
 * Source: wiki
 * Status: FAIL - Should trigger STR34-C violation
 */

static int yy_string_get(void) {
  register unsigned char *c_str;
  register int c;

  c_str = bash_input.location.string;
  c = EOF;

  /* If the string doesn't exist or is empty, EOF found */
  if (c_str && *c_str) {
    c = *c_str++;
    bash_input.location.string = c_str;
  }
  return (c);
}