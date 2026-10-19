/*
 * Rule: FIO21-C
 * Source: wiki
 * Status: PASS - Should NOT trigger FIO21-C violation
 *
 * CERT's first noncompliant example. The file name is a parameter, which
 * CERT presumes names a file in a shared directory; nothing in the source
 * says where it points. The ruled form (b) reports a creating open only
 * when its path is a literal under a shared directory or a name tmpnam(),
 * tempnam() or mktemp() produced, and never judges an argument by its
 * spelling, so this open is not reported. It was reported only because the
 * parameter is spelled file_name.
 */

#include <stdio.h>
 
void func(const char *file_name) {
  FILE *fp = fopen(file_name, "wb+");
  if (fp == NULL) {
    /* Handle error */
  }
}