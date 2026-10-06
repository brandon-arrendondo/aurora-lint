#include <stddef.h>

/* Non-ASCII text ahead of the invocation: naïve — ünïcödé ✓ 日本語 */
#define UDECL(A) extern A

/* ✓ 日本語 */ UDECL(char label[16]); /* 日本語 ✓ */
