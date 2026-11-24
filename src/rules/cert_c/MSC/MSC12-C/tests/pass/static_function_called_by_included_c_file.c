/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: PASS - an included .c file is part of this translation unit and may call the static
 *
 * names_generated.c is generated at build time and calls append_name.
 */
#include <stdio.h>

static void append_name(char *buffer, const char *name)
{
    sprintf(buffer, "%s", name);
}

#include "names_generated.c"

int describe(char *buffer)
{
    return buffer[0];
}
