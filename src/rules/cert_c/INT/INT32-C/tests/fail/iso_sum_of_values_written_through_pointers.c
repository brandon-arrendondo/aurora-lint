/*
 * Rule: INT32-C
 * Source: regression
 * Status: FAIL - no data model is declared
 *
 * Both operands are initialised to zero and only ever changed through
 * sscanf's pointer arguments, so what they hold is whatever the input says.
 * Without a declared data model an int has no width to bound its range, the
 * range of the sum cannot be formed, and a fallback that reads each operand
 * from its declaration saw only the zeros and called the sum safe. An operand
 * no width bounds is not proven to fit any width.
 */

#include <stdio.h>

typedef struct {
    int offsetX;
} Glyph;

void read_font(const char *buffer, int dataSize, Glyph *glyph) {
    int totalReadBytes = 0;
    int readVars = 0;
    int boxX = 0;
    int boxY = 0;
    int fontY = 0;

    while (totalReadBytes <= dataSize) {
        if (buffer[0] == 'B') {
            readVars = sscanf(buffer, "BBX %i %i", &boxX, &boxY);
        }
        if (buffer[0] == 'G') {
            glyph->offsetX = boxX + fontY; /* VIOLATION */
        }
        if (buffer[0] == 'F') {
            readVars = sscanf(buffer, "FONTBOUNDINGBOX %i", &fontY);
        }
    }
}
