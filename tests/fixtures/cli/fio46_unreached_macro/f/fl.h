#ifndef FL_H
#define FL_H

#include <stdio.h>

int fl_fclose(FILE *f);

#define fclose(a) fl_fclose(a)

#endif
