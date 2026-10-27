/*
 * Rule: EXP19-C
 * Source: custom
 * Status: FAIL - Should trigger EXP19-C violation
 * Description: A body that comes through #if arms is reported at the first
 * unbraced statement it can be, never at a directive line: a #pragma arm
 * leaves the body to the statement after the #endif, a nested #ifndef that
 * only defines a macro is passed over, a braced arm gives way to an
 * unbraced one.
 * Expect: count=4
 */

typedef int (*callback)(int);
int fallback(int);
void use_a(void);
void use_b(void);

callback pick(callback f)
{
    if (!f)
#if defined(__clang__)
#pragma clang diagnostic push
#endif
        /* the default */
        f = fallback; /* Expect: here */
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
    return f;
}

int protocol_for(int protocol)
{
    if (protocol == 6)
#ifdef __linux__
#  ifndef PROTO_ALT
#  define PROTO_ALT 262
#  endif
        protocol = PROTO_ALT; /* Expect: here */
#else
        return -1;
#endif
    return protocol;
}

void one_arm_braced(int x)
{
    if (x)
#ifdef FEATURE_A
    {
        use_a();
    }
#else
        use_b(); /* Expect: here */
#endif
}

void braced_arm_without_else(int x)
{
    while (x-- > 0)
#ifdef FEATURE_A
    {
        use_a();
    }
#endif
    use_b(); /* Expect: here */
}
