/*
 * Rule: MEM05-C
 * Source: custom
 * Status: FAIL - Should trigger MEM05-C violation
 * Description: A chain of 16 block-scope typedefs, each an array sized by
 * sizeof of the one before twice, from a runtime-sized first typedef: every
 * level is a variable-length array type, so arrays sized by the last level,
 * or by an object of it, are VLAs. Reading each typedef's size anew at every
 * reference doubles the work per level, so the chain also bounds the rule's
 * time.
 */
void runtime_typedef_chain(int n) {
    typedef char t0[n];
    typedef char t1[sizeof(t0) + sizeof(t0)];
    typedef char t2[sizeof(t1) + sizeof(t1)];
    typedef char t3[sizeof(t2) + sizeof(t2)];
    typedef char t4[sizeof(t3) + sizeof(t3)];
    typedef char t5[sizeof(t4) + sizeof(t4)];
    typedef char t6[sizeof(t5) + sizeof(t5)];
    typedef char t7[sizeof(t6) + sizeof(t6)];
    typedef char t8[sizeof(t7) + sizeof(t7)];
    typedef char t9[sizeof(t8) + sizeof(t8)];
    typedef char t10[sizeof(t9) + sizeof(t9)];
    typedef char t11[sizeof(t10) + sizeof(t10)];
    typedef char t12[sizeof(t11) + sizeof(t11)];
    typedef char t13[sizeof(t12) + sizeof(t12)];
    typedef char t14[sizeof(t13) + sizeof(t13)];
    typedef char t15[sizeof(t14) + sizeof(t14)];
    typedef char t16[sizeof(t15) + sizeof(t15)];
    t16 x;
    char by_type[sizeof(t16)];
    char by_object[sizeof x];
    (void)x; (void)by_type; (void)by_object;
}
