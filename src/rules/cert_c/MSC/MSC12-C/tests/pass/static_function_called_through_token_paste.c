/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: PASS - a macro pastes the static's name together, so its expansion calls it
 */
#include <stdio.h>

#define PARSE(name, arg) parse_##name(arg)

static int parse_theme(const char *arg)
{
    return puts(arg);
}

int load(const char *arg)
{
    return PARSE(theme, arg);
}
