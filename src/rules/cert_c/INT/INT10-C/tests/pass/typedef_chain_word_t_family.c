/*
 * Rule: INT10-C
 * Source: task 657 (seL4 delta-adjudication task 631)
 * Status: PASS - Should NOT trigger INT10-C violation
 *
 * seL4 typedefs `word_t` to `unsigned long`, then chains further aliases
 * (`paddr_t`, `pptr_t`, ...) onto `word_t` -- sometimes from a different
 * header than `word_t` itself. The declared-type map only records the alias
 * name as written (e.g. "paddr_t"), so recognizing the operand as unsigned
 * requires walking the full typedef chain, not just a one-level lookup.
 * Also covers `sizeof(...)`, which always yields `size_t` regardless of the
 * sized expression's own type.
 */

typedef unsigned long word_t;
typedef word_t paddr_t;
typedef word_t pptr_t;

paddr_t compute_offset(paddr_t addr, paddr_t base) {
    return (addr - base) % 4096;
}

pptr_t alloc_next(pptr_t allocated, word_t size_bits) {
    /* `allocated` is pptr_t -> word_t -> unsigned long: a two-level chain. */
    return allocated % (1UL << size_bits);
}

int hash_bucket(word_t hash, word_t buckets) {
    return hash % buckets;
}

int aligned_size(void) {
    struct { int x; } s;
    return sizeof(s) % 8;
}

int main(void) {
    return 0;
}
