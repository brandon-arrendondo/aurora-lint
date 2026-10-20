/*
 * Rule: FIO42-C
 *
 * Status: FAIL - Should trigger FIO42-C violation
 *
 * main hands the stream to a function another translation unit defines and
 * then exits; whatever that function does with it, the stream is still open
 * when the program ends.
 */
#include <stdio.h>
#include <stdlib.h>

void setup(FILE *f);

int main(void)
{
    FILE *f = fopen("log", "a");
    if (f == NULL)
        return 1;
    setup(f);
    exit(0);
}
