/*
 * Rule: FIO19-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

off_t file_size;
char *buffer;
struct stat stbuf;
int fd;
 
fd = open("foo.bin", O_RDONLY);
if (fd == -1) {
  /* Handle error */
}
 
if ((fstat(fd, &stbuf) != 0) || (!S_ISREG(stbuf.st_mode))) {
  /* Handle error */
}
 
file_size = stbuf.st_size;
 
buffer = (char*)malloc(file_size);
if (buffer == NULL) {
  /* Handle error */
}

/* ... */