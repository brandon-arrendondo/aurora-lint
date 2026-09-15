/*
 * Rule: DCL05-C
 * Source: real-world (valkey src/valkeymodule.h API table, task 1173)
 * Status: PASS - Should NOT trigger DCL05-C violation
 *
 * A file-scope function-pointer variable with a single level of function
 * type is not a complex declarator.
 */

#define MODULE_API extern

MODULE_API int (*Module_CreateCommand)(void *ctx, const char *name, int flags);
MODULE_API void *(*Module_Alloc)(unsigned long bytes);

static void (*handlers[4])(int);

int use_them(void)
{
    handlers[0](1);
    return Module_CreateCommand(0, "x", 0);
}
