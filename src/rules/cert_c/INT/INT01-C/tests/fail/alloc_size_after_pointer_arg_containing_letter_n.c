/*
 * Rule: INT01-C
 * Source: task 1151, mirroring sqlite's src/func.c upperFunc/lowerFunc
 *   (benchmark_adjudication data/sqlite/adjudication.csv src/func.c:514/533,
 *   ext/fts5/fts5_index.c:7052 - same "letter-n substring" reason)
 * Status: FAIL - Should trigger INT01-C violation, on the real size
 *   expression rather than the unrelated pointer argument
 *
 * contextMalloc's first argument is a pointer/handle ("context") that
 * happens to contain the letter 'n'. The old check's `.contains("n")` over
 * the whole argument text matched that pointer and returned before ever
 * reaching the real, non-size_t size expression `((i64)n) + 1` later in
 * the same call.
 */
#include <stddef.h>

typedef long long i64;
struct my_context {
  int dummy;
};

void *contextMalloc(struct my_context *context, i64 amount);

void upper(struct my_context *context, int n) {
  char *z1 = (char *)contextMalloc(context, ((i64)n) + 1);
  (void)z1;
}
