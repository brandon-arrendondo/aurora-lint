/*
 * Rule: INT01-C
 * Source: aurora-lint
 * Status: FAIL - an output size named for one with a letter after it
 *
 * sizep is the size word size with the letter p, for the pointer it is
 * written through: the size is returned in an int rather than a size_t.
 */
char *read_blob(const char *path, int *sizep);
