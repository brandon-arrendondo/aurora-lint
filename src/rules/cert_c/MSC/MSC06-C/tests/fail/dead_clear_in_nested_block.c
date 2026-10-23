/*
 * Rule: MSC06-C
 * Source: synthetic
 * Status: FAIL - Should trigger MSC06-C violation
 *
 * A buffer of the function body cleared inside an inner block, with nothing
 * after the clear in either block, so the clear is the buffer's last use
 * before it goes out of scope. The spin loop's flag is a plain global whose
 * name merely appears in an unrelated volatile declaration.
 */
#include <string.h>

void use(char *buf);
int check(void);

void nested(void)
{
    char pwd[16];
    if (check()) {
        use(pwd);
        memset(pwd, 0, sizeof pwd);
    }
}

int busy;
volatile int busy_size = sizeof busy;

void spin(void)
{
    while (busy) {
    }
}
