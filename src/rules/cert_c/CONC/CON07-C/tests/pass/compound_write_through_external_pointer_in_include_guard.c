/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: PASS - The pointer is a file-scope object with external linkage
 *
 * `cursor` is declared inside the include guard, outside any function, so
 * another file may point it somewhere else. Its initializer does not prove
 * it still points into `shared`.
 */

#ifndef CURSOR_H
#define CURSOR_H

static int shared[4];
int *cursor = shared;

void advance(void)
{
    (*cursor)++;
}

#endif
