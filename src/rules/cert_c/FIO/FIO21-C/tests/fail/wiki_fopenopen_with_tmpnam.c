/*
 * Rule: FIO21-C
 * Source: wiki
 * Status: FAIL - Should trigger FIO21-C violation
 */

#include <stdio.h>
 
void func(const char *file_name) {
  FILE *fp = fopen(file_name, "wb+");
  if (fp == NULL) {
    /* Handle error */
  }
}