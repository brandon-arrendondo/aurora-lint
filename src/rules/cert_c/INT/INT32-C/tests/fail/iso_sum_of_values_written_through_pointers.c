/*
 * Rule: INT32-C
 * Source: regression
 * Status: FAIL - no data model is declared
 *
 * Both operands are initialised to zero and only ever changed through
 * sscanf's pointer arguments, so what they hold is whatever the input says.
 * Without a declared data model an int has no width to bound its range, the
 * range of the sum cannot be formed, and a fallback that reads each operand
 * from its declaration saw only the zeros and called the sum safe. A sum of
 * operands no width bounds is not proven to fit any width.
 */

#include <stdio.h>

struct record {
    int total;
};

void parse(const char *line, int limit, struct record *out) {
    int consumed = 0;
    int status = 0;
    int first = 0;
    int second = 0;
    int offset = 0;

    while (consumed <= limit) {
        if (line[0] == 'A') {
            status = sscanf(line, "A %i %i", &first, &second);
        }
        if (line[0] == 'S') {
            out->total = first + offset; /* VIOLATION */
        }
        if (line[0] == 'O') {
            status = sscanf(line, "O %i", &offset);
        }
    }
}
