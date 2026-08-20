/*
 * Rule: MSC23-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC23-C violation
 */

#include <stdio.h>
 
void func( void ) {
  FILE *fp = fopen("text_file.txt", "r");
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


/*
 * Contents of text_file.txt:
 * This has
 * CRLF newlines
 * in it.
 */