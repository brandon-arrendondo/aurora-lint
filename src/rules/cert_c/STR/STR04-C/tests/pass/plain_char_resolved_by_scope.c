/*
 * Rule: STR04-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger STR04-C violation
 *
 * Each argument is typed by the declaration its name resolves to, not by
 * another declaration of the same name: a plain-char local that shadows an
 * unsigned char global, and a plain-char local in one function next to an
 * unsigned char local of the same name in another. A plain unsigned char
 * value passed as strchr's int argument is a character, not a string.
 */

#include <string.h>

unsigned char name[16];

size_t local_shadows_global(void) {
  char name[] = "plain";
  return strlen(name);
}

void unrelated(void) {
  unsigned char buf[4] = {0};
  (void)buf;
}

size_t other_function(void) {
  char buf[] = "plain";
  return strlen(buf);
}

char *find(const char *s, unsigned char c) {
  return strchr(s, c);
}
