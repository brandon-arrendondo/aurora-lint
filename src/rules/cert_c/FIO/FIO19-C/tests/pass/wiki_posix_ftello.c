/*
 * Rule: FIO19-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

FILE* fp;
int fd;
off_t file_size;
char *buffer;
struct stat st;
  
fd = open("foo.bin", O_RDONLY);
if (fd == -1) {
  /* Handle error */
}

fp = fdopen(fd, "r");
if (fp == NULL) {
  /* Handle error */
}

/* Ensure that the file is a regular file */
if ((fstat(fd, &st) != 0) || (!S_ISREG(st.st_mode))) {
  /* Handle error */
}
 
if (fseeko(fp, 0 , SEEK_END) != 0) {
  /* Handle error */
}
  
file_size = ftello(fp);
if (file_size == -1) {
  /* Handle error */
}
 
buffer = (char*)malloc(file_size);
if (buffer == NULL) {
  /* Handle error */
}

/* ... */