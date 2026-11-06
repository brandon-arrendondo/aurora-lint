/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: PASS - A type's signedness comes from its definitions, never its name
 *
 * `str_size` is a pointer, whatever its name ends in, and `page_size` has
 * no definition in reach, so neither cast is an integer conversion this
 * file can show. `sqlite_int64` is `SQLITE_INT64_TYPE` in one arm, which
 * nothing here defines, so its definitions do not agree on a signedness.
 */

#ifdef SQLITE_INT64_TYPE
typedef SQLITE_INT64_TYPE sqlite_int64;
#else
typedef long long int sqlite_int64;
#endif

typedef char *str_size;

int from_pointer(str_size s)
{
    return (int)s;
}

int from_unknown(page_size v)
{
    return (int)v;
}

unsigned long from_mixed_arms(sqlite_int64 v)
{
    return (unsigned long)v;
}
