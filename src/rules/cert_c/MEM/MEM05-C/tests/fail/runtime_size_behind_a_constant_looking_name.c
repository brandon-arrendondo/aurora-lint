/*
 * Rule: MEM05-C
 * Source: custom
 * Status: FAIL - Should trigger MEM05-C violation
 * Description: Each size is not an integer constant expression, so each array
 * is a VLA however its size is spelled: a const object (C has no const
 * integer constants), a macro that is a variable in one #if arm, a macro over
 * a parameter, and a local that hides an enumerator of the same name.
 */
#ifdef DYN
#define mixed len
#else
#define mixed 64
#endif
#define doubled (n * 2)

enum { slots = 8 };

void runtime_sizes(int n, int len) {
    const int k = 4;
    char const_object[k];
    char one_arm_runtime[mixed];
    char over_parameter[doubled];
    {
        int slots = n;
        char hides_enumerator[slots];
        (void)hides_enumerator;
    }
    (void)const_object; (void)one_arm_runtime; (void)over_parameter; (void)len;
}
