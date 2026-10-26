/*
 * Rule: EXP19-C
 * Source: custom
 * Status: FAIL - Should trigger EXP19-C violation
 * Description: An unbraced for or while body is reported where the body
 * starts, as an if's arms are. A body that comes through #if arms is
 * reported at the first statement of the first arm, not inside the
 * directive or past the end of the statement's line.
 */

void use_a(void);
void use_b(void);

void loops(int n)
{
    for (int i = 0; i < n; i++)
        use_a();

    while (n-- > 0)
        use_b();

    for (;;) use_a();
}

void through_arms(int x)
{
    if (x)
#ifdef FEATURE_A
        use_a();
#else
        use_b();
#endif

    while (x-- > 0)
#if defined(FEATURE_A)
        use_a();
#endif
    use_b();
}

int main(void)
{
    loops(1);
    through_arms(2);
    return 0;
}
