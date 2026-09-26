/*
 * Rule: EXP34-C
 * Source: wiki, CERT EXP34-C "Noncompliant Code Example" (the first, libpng), verbatim
 * Status: EXPECTED_FAIL - CERT's own noncompliant example, not detected yet
 *
 * png_malloc() is not proven to return a non-null pointer, and chunkdata is
 * passed to memcpy() without a check, so this is in scope. The adapted copy
 * in tests/fail/ substitutes malloc().
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
