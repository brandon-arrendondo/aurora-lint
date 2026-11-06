/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: FAIL - A typedef every definition of which is signed is signed
 * Expect: count=3
 *
 * `lua_Integer` is whatever `LUA_INTEGER` expands to, and every
 * definition of that macro is signed. Each arm of `sqlite_int64` is a
 * signed type. A typedef's name says nothing: `my_uint8_alias_signed` is
 * a `signed char`. Each value may be negative where it is converted to
 * `size_t`.
 *
 * A regression guard: main reports the same three lines. It holds them
 * while signedness is read from every definition rather than the first.
 */

#include <string.h>
#include <stddef.h>

#if defined(_MSC_VER)
typedef __int64 sqlite_int64;
#else
typedef long long int sqlite_int64;
#endif
typedef sqlite_int64 sqlite3_int64;

#if defined(SMALL_INTEGERS)
#define LUA_INTEGER int
#else
#define LUA_INTEGER long long
#endif
typedef LUA_INTEGER lua_Integer;

typedef signed char my_uint8_alias_signed;

void zero(sqlite3_int64 nByte, char *p)
{
    memset(p, 0, nByte); /* Expect: here */
}

size_t position(lua_Integer pos)
{
    return (size_t)pos; /* Expect: here */
}

size_t widen(my_uint8_alias_signed v)
{
    return (size_t)v; /* Expect: here */
}
