/* getc may evaluate its stream more than once (C11 7.21.7.5). */
#ifndef FIXTURE_STDIO_H
#define FIXTURE_STDIO_H
typedef struct file FILE;
int getc(FILE *stream);
int _fill(FILE *stream);
#define getc(f) ((f)->n > 0 ? (f)->n-- : _fill(f))
#endif
