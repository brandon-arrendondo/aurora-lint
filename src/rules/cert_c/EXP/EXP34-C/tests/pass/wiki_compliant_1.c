/*
 * Rule: EXP34-C
 * Source: wiki
 * Status: PASS - Should NOT trigger EXP34-C violation
 *
 * CERT's compliant example leaves each error branch as the placeholder
 * `/* Handle error */`. Read literally that branch falls through, so it
 * guards nothing; the placeholder stands for code that leaves, and this
 * copy spells that out as an explicit return.
 */

#include <png.h> /* From libpng */
#include <string.h>

 void func(png_structp png_ptr, size_t length, const void *user_data) { 
  png_charp chunkdata;
  if (length == SIZE_MAX) {
    /* Handle error */
    return;
  }
  if (NULL == user_data) {
    /* Handle error */
    return;
  }
  chunkdata = (png_charp)png_malloc(png_ptr, length + 1);
  if (NULL == chunkdata) {
    /* Handle error */
    return;
  }
  /* ... */
  memcpy(chunkdata, user_data, length);
  /* ... */

 }