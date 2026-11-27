/*
 * Rule: DCL13-C
 * Source: testcases
 * Status: FAIL - A definition that leaves the pointee unchanged
 * Expect: count=2
 *
 * The definition never writes through `src` or `input`, so each is
 * reported there. The prototypes before it are not: a prototype shows
 * nothing of what the function does with the pointee.
 */

void process(char *dest, char *src);

int validate(char *input);

void process(char *dest, char *src) {
  while (*src) {
    *dest++ = *src++;
  }
  *dest = '\0';
}

int validate(char *input) { return input[0] != '\0'; }
