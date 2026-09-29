/* A C library header outside the project, shaped like glibc's: tolower
 * reads its argument twice in the replacement list, as __tobody does. */
#ifndef FIXTURE_CTYPE_H
#define FIXTURE_CTYPE_H
int tolower(int c);
#define tolower(c) ((c) >= 'A' && (c) <= 'Z' ? (c) + 32 : (c))
#endif
