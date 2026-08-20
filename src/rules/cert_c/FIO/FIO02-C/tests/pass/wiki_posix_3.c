/*
 * Rule: FIO02-C
 * Source: wiki
 * Status: PASS - Should NOT trigger FIO02-C violation
 */

char *realpath_res = NULL;
char *canonical_filename = NULL;
size_t path_size = 0;

/* Verify argv[1] is supplied */

path_size = (size_t)PATH_MAX;

if (path_size > 0) {
  canonical_filename = malloc(path_size);

  if (canonical_filename == NULL) {
    /* Handle error */
  }

  realpath_res = realpath(argv[1], canonical_filename);
}

if (realpath_res == NULL) {
  /* Handle error */
}

if (!verify_file(realpath_res)) {
  /* Handle error */
}
if (fopen(realpath_res, "w") == NULL ) {
  /* Handle error */
}

/* ... */

free(canonical_filename);
canonical_filename = NULL;