/*
 * Rule: DCL37-C
 * Status: FAIL - the C header idiom for C++ callers. A declaration inside
 * extern "C" { ... } is still at file scope, where every name starting with
 * an underscore is reserved.
 * Expect: count=2
 */

#ifdef __cplusplus
extern "C" {
#endif

int _ext_var; /* Expect: here */
int _ext_fn(void); /* Expect: here */

#ifdef __cplusplus
}
#endif
