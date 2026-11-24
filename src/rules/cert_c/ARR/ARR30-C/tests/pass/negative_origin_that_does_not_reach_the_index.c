/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - Nothing that may make the index negative reaches it
 *
 * The input is read into another `d`, one an inner declaration makes, or
 * only after the access; the -1 is stored in the operand of `sizeof`, which
 * is never evaluated; `ntohs` returns an unsigned 16-bit value, which an
 * `int` holds as it is; a cast to `uint8_t` leaves `getchar`'s result,
 * EOF included, a value from 0 to 255, which an `int` holds as it is. (A
 * cast to `unsigned char` does the same wherever `char` is narrower than
 * `int`, which ISO C does not promise.) With no negative origin in reach, the test of the
 * upper end bounds the access as it does on main.
 */
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

void input_read_into_a_hidden_name(void)
{
    int b[10] = {0};
    int d = 3;
    {
        int d;
        if (scanf("%d", &d) != 1)
            return;
    }
    if (d < 10)
    {
        b[d] = 1;
    }
}

void input_read_after_the_access(void)
{
    int b[10] = {0};
    int d = 3;
    if (d < 10)
    {
        b[d] = 1;
    }
    if (scanf("%d", &d) != 1)
        return;
}

int store_never_evaluated(void)
{
    int b[10] = {0};
    int d = 3;
    int size = (int)sizeof(d = -1);
    if (d < 10)
    {
        b[d] = 1;
    }
    return size;
}

void unsigned_short_result(unsigned short wire)
{
    int b[10] = {0};
    int d = ntohs(wire);
    if (d < 10)
    {
        b[d] = 1;
    }
}

void character_read_as_an_unsigned_byte(void)
{
    int b[10] = {0};
    int d = (uint8_t)getchar();
    if (d < 10)
    {
        b[d] = 1;
    }
}
