/*
 * Rule: ENV02-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

extern char **environ;

int main(void) {
  if (multiple_vars_with_same_name()) {
    printf("Someone may be tampering.\n");
    return 1;
  }

  /* ... */

  return 0;
}

int multiple_vars_with_same_name(void) {
  size_t i;
  size_t j;
  size_t k;
  size_t l;
  size_t len_i;
  size_t len_j;

  for(size_t i = 0; environ[i] != NULL; i++) {
    for(size_t j = i; environ[j] != NULL; j++) {
      if (i != j) {
        k = 0;
        l = 0;

        len_i = strlen(environ[i]);
        len_j = strlen(environ[j]);

        while (k < len_i && l < len_j) {
          if (environ[i][k] != environ[j][l])
            break;

          if (environ[i][k] == '=')
            return 1;

          k++;
          l++;
        }
      }
    }
  }
  return 0;
}