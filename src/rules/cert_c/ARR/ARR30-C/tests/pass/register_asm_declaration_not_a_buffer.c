/*
 * Rule: ARR30-C
 * Source: task 912 (sel4 src/arch/arm/object/smc.c:42)
 * Status: PASS - Should NOT trigger ARR30-C violation
 * Reason: tree-sitter's C grammar has no rule for the GNU register-asm
 *         declaration, so `register word_t r7 asm("x7") = smc_args.arg[7];`
 *         parses as an ERROR followed by a stray `array_declarator`. The
 *         subscript READ `arg[7]` was then taken as a declaration of `arg`
 *         with size 7, making index 7 of an 8-element array read as out of
 *         bounds. A declaration that did not parse cannot size a buffer.
 */

typedef unsigned long word_t;
#define NUM_SMC_REGS 8

typedef struct smc_args_t_ {
    word_t arg[NUM_SMC_REGS];
} smc_args_t;

static smc_args_t doSMC(smc_args_t smc_args) {
    register word_t r0 asm("x0") = smc_args.arg[0];
    register word_t r7 asm("x7") = smc_args.arg[7];

    smc_args.arg[0] = r0;
    smc_args.arg[7] = r7;
    return smc_args;
}
