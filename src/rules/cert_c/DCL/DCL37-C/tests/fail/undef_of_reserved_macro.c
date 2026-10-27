/*
 * Rule: DCL37-C
 * Status: FAIL - removing a macro definition of a name reserved for any use
 * with #undef is undefined (C 7.1.3). That holds for a listed feature-test
 * macro too: its exemption covers defining it, not removing it.
 * Expect: count=3
 */

#undef __STDC_VERSION_GUARD /* Expect: here */
#undef _GNU_SOURCE /* Expect: here */
#  undef   _Alignas_helper /* Expect: here */
