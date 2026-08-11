/*
 * Rule: API05-C
 * Source: testcases
 * Status: FAIL - Should trigger API05-C violation
 */

/*
 * Reason: buf and len are genuinely tied together -- the function body
 * passes both to memcpy() as the source pointer and copy length -- so this
 * is a real conformant-array candidate, not just a coincidence of being the
 * only pointer/size_t pair in the signature (task 190; real example: curl's
 * chunk_append(const uint8_t *buf, size_t len)).
 */

#include <stddef.h>
extern void *memcpy(void *dest, const void *src, size_t n);

void chunk_append(const unsigned char *buf, size_t len)
{
    unsigned char tmp[16];
    memcpy(tmp, buf, len);
}
