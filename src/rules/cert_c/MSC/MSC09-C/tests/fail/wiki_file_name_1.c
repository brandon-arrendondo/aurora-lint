/*
 * Rule: MSC09-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC09-C violation
 */

#include <fcntl.h>
#include <sys/stat.h>

int main(void) {
   char *file_name = "\xe5ngstr\xf6m";
   mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

   int fd = open(file_name, O_CREAT | O_EXCL | O_WRONLY, mode);
   if (fd == -1) {
      /* Handle error */
   }
}