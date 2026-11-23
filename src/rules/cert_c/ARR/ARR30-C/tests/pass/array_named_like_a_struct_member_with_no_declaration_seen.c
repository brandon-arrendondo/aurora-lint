/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A struct member's size is not that of an object of its name
 *
 * buf is declared in a header the scan does not show, of a size the file
 * does not say. The member s.buf is another object.
 */

#include "buffers.h"

struct holder {
    int buf[4];
};

int element(void)
{
    return buf[9];
}
