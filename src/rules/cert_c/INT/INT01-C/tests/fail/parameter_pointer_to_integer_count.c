/*
 * Rule: INT01-C
 * Source: aurora-lint
 * Status: FAIL - an output count parameter typed pointer to int
 *
 * count receives the number of elements the function returns, an object
 * size, through an int rather than a size_t.
 */
char **split_text(const char *text, char delimiter, int *count);
