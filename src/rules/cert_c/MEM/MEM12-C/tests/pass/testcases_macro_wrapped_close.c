/*
 * Rule: MEM12-C
 * Source: testcases
 * Status: PASS - macro-wrapped fclose/free must not be missed as a deallocation
 */

#define SAFE_FCLOSE(f) fclose(f)
#define SAFE_FREE(p) free(p)

/* ... Assume the same struct used previously ... */

errno_t do_something(void) {
  FILE *fin1, *fin2;
  object_t *obj;
  errno_t ret_val = NOERR; /* Initially assume a successful return value */

  fin1 = fopen("some_file", "r");
  if (fin1 == NULL) {
    ret_val = errno;
    goto FAIL_FIN1;
  }

  fin2 = fopen("some_other_file", "r");
  if (fin2 == NULL) {
    ret_val = errno;
    goto FAIL_FIN2;
  }

  obj = malloc(sizeof(object_t));
  if (obj == NULL) {
    ret_val = errno;
    goto FAIL_OBJ;
  }

  /* ... More code ... */

SUCCESS:     /* Clean up everything */
  SAFE_FREE(obj);

FAIL_OBJ:   /* Otherwise, close only the resources we opened */
  SAFE_FCLOSE(fin2);

FAIL_FIN2:
  SAFE_FCLOSE(fin1);

FAIL_FIN1:
  return ret_val;
}
