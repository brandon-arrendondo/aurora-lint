/*
 * Rule: INT01-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

void *alloc(size_t blocksize) {
  if (blocksize == 0) {
    return NULL;  /* Indicate failure */
  }
  return malloc(blocksize);
}

int read_counted_string(int fd) {
  size_t length;
  unsigned char *data;

  if (read_integer_from_network(fd, &length)) {
    return -1;
  }

  data = (unsigned char*)alloc(length+1);
  if (data == NULL) {
    return -1; /* Indicate failure */
  }

  if (read_network_data(fd, data, length)) {
    free(data);
    return -1;
  }
  data[length] = '\0';

  /* ... */
  free( data);
  return 0;
}