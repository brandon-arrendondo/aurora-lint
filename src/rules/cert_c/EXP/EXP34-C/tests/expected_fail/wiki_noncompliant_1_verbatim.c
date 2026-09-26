/*
 * Rule: EXP34-C
 * Source: wiki, CERT EXP34-C "Noncompliant Code Example", verbatim
 * Status: EXPECTED_FAIL - CERT's own noncompliant example, not detected yet
 *
 * CERT's noncompliant example as written: png_malloc() may return a null
 * pointer, and chunkdata is passed to memcpy() without a check. png_malloc
 * is libpng's; whether it can return NULL depends on the library's
 * contract, which this file does not declare.
 */

#include <png.h> /* From libpng */
#include <string.h>
 
void func(png_structp png_ptr, int length, const void *user_data) { 
  png_charp chunkdata;
  chunkdata = (png_charp)png_malloc(png_ptr, length + 1);
  /* ... */
  memcpy(chunkdata, user_data, length);
  /* ... */
 }
