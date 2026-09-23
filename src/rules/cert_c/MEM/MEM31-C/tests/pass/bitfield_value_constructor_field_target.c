/*
 * Rule: MEM31-C
 * Source: task_651
 * Status: PASS - Should NOT trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: PASS
 * Reason: same bitfield-generator value-constructor pattern as task 580
 * (task_580_bitfield_value_constructor.c), but reached through a struct
 * field instead of a bare identifier -- `fc_ret.remainder = cap_new(...)`
 * where `fc_ret` is a plain (non-pointer) local, never dereferenced,
 * indexed or NULL-checked. Task 580's pointer-evidence guard only ever
 * checked bare-identifier assignment targets against value_only_locals;
 * a field_expression/subscript_expression target bypassed the guard
 * entirely and inserted straight into allocated_memory, so this exact
 * seL4 shape (finaliseCap_ret_t fc_ret; fc_ret.remainder = cap_null_cap_new();)
 * still flagged a leak post-580 (task 627's delta-adjudication, 45 sel4
 * findings on ret.cap/fc_ret.remainder/fc_ret.cleanupInfo).
 */

typedef unsigned long word_t;

struct cap {
    word_t words[2];
};
typedef struct cap cap_t;

struct finaliseCap_ret {
    cap_t remainder;
    cap_t cleanupInfo;
};
typedef struct finaliseCap_ret finaliseCap_ret_t;

/* Declared here the way the generated header would declare them. */
cap_t cap_null_cap_new(void);

finaliseCap_ret_t finaliseCap(word_t final)
{
    finaliseCap_ret_t fc_ret;

    if (!final) {
        fc_ret.remainder = cap_null_cap_new();
        fc_ret.cleanupInfo = cap_null_cap_new();
        return fc_ret;
    }

    fc_ret.remainder = cap_null_cap_new();
    fc_ret.cleanupInfo = cap_null_cap_new();
    return fc_ret;
}
