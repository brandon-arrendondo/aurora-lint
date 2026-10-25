/*
 * Rule: INT01-C
 * Source: aurora-lint
 * Status: FAIL - a size parameter whose type this file does not declare
 *
 * ULONG is declared in a header the scan does not see. A type that is not
 * in reach is not known to be size_t, so the length named for a size is
 * still reported.
 */
int read_block(void *buffer, ULONG length);
