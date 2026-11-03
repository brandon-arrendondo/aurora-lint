/*
 * Rule: ARR02-C
 * Source: custom
 * Status: PASS - Should NOT trigger ARR02-C violation
 * Description: A GNU attribute between the declarator and the initializer,
 * which GCC accepts. The grammar has no place for it there: unrepaired, the
 * declaration ended at `blob[]` and read as an array with no bound and no
 * initializer, and the braced list after it as a compound statement. The
 * attribute is moved in front of the declarator, and the bound comes from
 * the initializer.
 */

static const unsigned char blob[] __attribute__((aligned(4))) = {
    0x01, 0x02, 0x03
};

unsigned char first_byte(void)
{
    return blob[0];
}
