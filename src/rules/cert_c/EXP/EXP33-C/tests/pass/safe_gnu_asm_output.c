/* Variables initialized via GNU extended asm output constraints must not be
 * flagged as uninitialized when subsequently read.
 * Covers __asm__(), __asm() and __ASM() variants (all misparsed or misrecognised
 * by tree-sitter-c) and __asm volatile / __ASM volatile forms.
 */
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;

/* tree-sitter recognises __asm__ as gnu_asm_expression */
uint32_t read_register_asm_dbl(uint32_t value) {
    uint32_t result;
    __asm__("RRX %0, %1" : "=r"(result) : "r"(value) : "cc");
    return result;
}

/* two output operands */
uint32_t two_outputs(uint32_t a, uint32_t b) {
    uint32_t lo, hi;
    __asm__("SMULL %0, %1, %2, %3" : "=r"(lo), "=r"(hi) : "r"(a), "r"(b));
    return lo + hi;
}

/* __asm (single underscore) — misparsed as call_expression by tree-sitter */
uint32_t read_register_asm_single(void) {
    uint32_t res;
    __asm("MRS %0,APSR" : "=r" (res));
    return res;
}

/* __ASM (upper-case) — misparsed as call_expression */
uint32_t read_register_ASM(uint32_t value) {
    uint32_t result;
    __ASM("RRX %0, %1" : "=r"(result) : "r"(value) : "cc");
    return result;
}

/* __asm volatile — misparsed by tree-sitter (ERROR + expression_statement) */
uint32_t read_volatile_asm(void) {
    uint32_t res;
    __asm volatile("MRS %0,CONTROL" : "=r" (res));
    return res;
}

/* cast of asm-initialized variable */
uint8_t read_asm_cast(uint32_t addr) {
    uint32_t res;
    __ASM("LDRBT %0, [%1]" : "=r" (res) : "r" (addr) : "memory");
    return (uint8_t)res;
}
