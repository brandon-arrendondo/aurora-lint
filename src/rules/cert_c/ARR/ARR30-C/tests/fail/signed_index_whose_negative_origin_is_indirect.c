/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A signed index that may be negative is bounded from above only
 * Expect: count=10
 *
 * Each `d` may be negative where it indexes `b`: parsed by `atoi`, read by
 * `getchar` (which returns EOF, and whose byte a cast to `signed char`
 * may make negative), stored by a scanf-family call under another
 * of its names, set to -1 by one arm of `?:`, copied from a local that was
 * read from input, or produced by a macro whose expansion may be negative. The test of its lower end
 * is of another `d`, the one an inner declaration hides, or views it through
 * a cast to a type narrower than `int`, which a negative value passes
 * (`(unsigned char) -250` is 6). Parentheses around the index change nothing.
 */
#include <stdio.h>
#include <stdlib.h>

#define URAND31() (((unsigned)rand() << 30) ^ ((unsigned)rand() << 15) ^ rand())
#define RAND32() ((int)(rand() & 1 ? URAND31() : -URAND31() - 1))

extern int __isoc99_sscanf(const char *s, const char *format, ...);
extern int sscanf_s(const char *s, const char *format, ...);

void tested_lower_end_is_of_a_hidden_name(const char *s, const char *t)
{
    int b[10] = {0};
    int d = atoi(s);
    if (d >= 0)
    {
        int d = atoi(t);
        if (d < 10)
        {
            b[d] = 1; /* Expect: here */
        }
    }
}

void narrowing_unsigned_view(const char *s)
{
    int b[10] = {0};
    int d = atoi(s);
    if ((unsigned char)d < 10)
    {
        b[d] = 1; /* Expect: here */
    }
}

void negative_arm_of_a_conditional(int c)
{
    int b[10] = {0};
    int d = c ? -1 : 3;
    if (d < 10)
    {
        b[d] = 1; /* Expect: here */
    }
}

void parenthesized_index(const char *s)
{
    int b[10] = {0};
    int d = atoi(s);
    if (d < 10)
    {
        b[(d)] = 1; /* Expect: here */
    }
}

void redirected_scanf_name(const char *s)
{
    int b[10] = {0};
    int d = 0;
    if (__isoc99_sscanf(s, "%d", &d) != 1)
        return;
    if (d < 10)
    {
        b[d] = 1; /* Expect: here */
    }
}

void annex_k_scanf(const char *s)
{
    int b[10] = {0};
    int d = 0;
    if (sscanf_s(s, "%d", &d) != 1)
        return;
    if (d < 10)
    {
        b[d] = 1; /* Expect: here */
    }
}

void character_read(void)
{
    int b[10] = {0};
    int d = getchar();
    if (d < 10)
    {
        b[d] = 1; /* Expect: here */
    }
}

void character_read_as_a_signed_char(void)
{
    int b[10] = {0};
    int d = (signed char)getchar();
    if (d < 10)
    {
        b[d] = 1; /* Expect: here */
    }
}

void copied_from_input(void)
{
    int b[10] = {0};
    int d = -1;
    if (scanf("%d", &d) != 1)
        return;
    {
        int copy = d;
        int d = copy;
        if (d < 10)
        {
            b[d] = 1; /* Expect: here */
        }
    }
}

void macro_that_may_be_negative(void)
{
    int b[10] = {0};
    int d = RAND32();
    if (d < 10)
    {
        b[d] = 1; /* Expect: here */
    }
}
