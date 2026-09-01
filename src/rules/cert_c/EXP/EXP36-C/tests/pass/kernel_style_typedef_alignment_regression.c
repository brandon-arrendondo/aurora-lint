/*
 * Rule: EXP36-C
 * Source: hostap real-world audit (task 462, batch 16-40_b12)
 * Status: PASS - Linux/hostap-style fixed-width typedefs must not be
 *   misclassified as 4-byte-aligned pointer types
 *
 * u8/s8 (and their byte-order-tagged wrappers) are typedef'd from
 * uint8_t/int8_t, alignment 1 -- identical to char. Before this fix,
 * get_type_alignment() only recognized "uint8_t"/"int8_t" by name, so a
 * `u8 *`/`s8 *` target fell through to the "pointer type not in map ->
 * assume 4-byte alignment" default, fabricating an alignment-1-to-4
 * violation for every char*-to-u8* cast. Real example:
 * hostap's ieee802_11_common.h:375 casts a `char *` to `const u8 *`.
 */

typedef unsigned char u8;
typedef char s8;

void test_char_to_u8_cast(char *buf) {
    const u8 *p = (const u8 *)buf;
    (void)p;
}

void test_char_to_s8_cast(char *buf) {
    const s8 *p = (const s8 *)buf;
    (void)p;
}
