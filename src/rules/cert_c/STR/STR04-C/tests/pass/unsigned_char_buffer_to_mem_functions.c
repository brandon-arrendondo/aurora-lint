/*
 * Rule: STR04-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger STR04-C violation
 *
 * The mem* functions take bytes, not strings, so an unsigned char buffer
 * passed to one is not a string use.
 */

#include <string.h>

unsigned char frame[16];
unsigned char copy[16];

int fill_and_compare(void) {
  memset(frame, 0, sizeof frame);
  memcpy(copy, frame, sizeof frame);
  memmove(copy + 1, copy, 4);
  if (memchr(frame, 0x7e, sizeof frame) != NULL) {
    return 1;
  }
  return memcmp(frame, copy, sizeof frame);
}
