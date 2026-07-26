/*
 * Rule: MSC23-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

#include <stdio.h>
 
void func( void ) {
  FILE *fp = fopen("text_file.txt", "rb");
  if (fp) {
    int counter = 0;
    while (!feof(fp) && !ferror(fp)) {
      ++counter;
      (void)fgetc(fp);
    }
    fclose(fp);
    printf("Number of characters read: %d\n", counter);
  }
}