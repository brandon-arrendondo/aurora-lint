/*
 * Rule: DCL05-C
 * Source: real-world (mbedtls library/asn1parse.c mbedtls_asn1_sequence,
 *         pure-ftpd puredb_write.h Hash0, seL4 lookupIOPDSlot_ret_t, task 1187)
 * Status: PASS - Should NOT trigger DCL05-C violation
 *
 * A typedef of a struct is not a pointer typedef because one of the struct's
 * members is a pointer: `const s_t x` const-qualifies the whole struct, so
 * the hazard the rule exists for does not arise.
 */

typedef struct s {
    int value;
    struct s *next;
    const char *name;
} s_t;

typedef struct {
    unsigned char *buf;
    unsigned long len;
} buffer_t;

int walk(const s_t *head)
{
    int n = 0;
    while (head) {
        n += head->value;
        head = head->next;
    }
    return n;
}
