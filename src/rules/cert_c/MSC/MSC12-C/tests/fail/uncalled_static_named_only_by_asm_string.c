/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: FAIL - a name inside an asm string is no use the C program makes; the toolchain needs used to keep it
 */
static void asm_target(void) /* Expect: here */
{
}

void api(void)
{
    __asm__("call asm_target");
}
