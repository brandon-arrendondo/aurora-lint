/*
 * Rule: FIO42-C
 *
 * Status: PASS - Should NOT trigger FIO42-C violation
 *
 * In main, a stream opened into a member of a local struct and one opened
 * into an element of a local array are each closed by the same spelling.
 */
#include <stdio.h>

struct ctx {
    FILE *f;
};

int main(int argc, char **argv)
{
    struct ctx c;
    FILE *fs[2];
    if (argc < 2) {
        return 1;
    }
    c.f = fopen(argv[1], "r");
    if (c.f == NULL) {
        return 1;
    }
    fs[0] = fopen(argv[1], "r");
    if (fs[0] == NULL) {
        fclose(c.f);
        return 1;
    }
    fclose(fs[0]);
    fclose(c.f);
    return 0;
}
