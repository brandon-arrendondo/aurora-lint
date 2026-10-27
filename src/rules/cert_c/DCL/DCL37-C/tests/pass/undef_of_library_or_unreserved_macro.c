/*
 * Rule: DCL37-C
 * Status: PASS - C 7.1.4 lets a program #undef a library macro such as NULL to
 * reach the function or object behind it. C 7.1.3 makes an #undef undefined
 * only for a name reserved for any use, and `_local_helper` and `MY_FLAG` are
 * not.
 */

#include <ctype.h>
#include <stddef.h>

#undef NULL
#undef toupper
#undef _local_helper
#undef MY_FLAG
