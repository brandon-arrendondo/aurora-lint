/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: PASS - the toolchain runs or keeps the static without a call in the code
 */
#include <stdio.h>

static void init_tables(void) __attribute__((constructor));

static void init_tables(void)
{
    puts("done");
}

__attribute__((destructor)) static void free_tables(void)
{
    puts("done");
}

static void kept(void) __attribute__((used));

static void kept(void)
{
    puts("done");
}

static void impl(void)
{
    puts("done");
}

void api(void) __attribute__((alias("impl")));
