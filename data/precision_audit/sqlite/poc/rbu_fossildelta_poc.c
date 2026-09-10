/*
** Same class of bug in ext/rbu/sqlite3rbu.c's rbuDeltaGetInt()/
** rbuDeltaOutputSize(), AS IT EXISTED at the pinned oracle commit
** b1a73ba34d05b32007315e4065c6468cc638e3af. rbuFossilDeltaFunc()
** (SQL function rbu_fossil_delta(X,D)) doesn't even guard SQL NULL on
** its D argument (unlike fossildelta.c's sibling functions), so
** SELECT rbu_fossil_delta(x'00', NULL) reaches rbuDeltaOutputSize with
** aDelta=NULL, nDelta=0 -- rbuDeltaGetInt then dereferences NULL
** unconditionally, identical crash shape to deltaGetInt().
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

/* verbatim from the pinned commit's ext/rbu/sqlite3rbu.c */
static unsigned int rbuDeltaGetInt(const char **pz, int *pLen){
  unsigned int v = 0;
  int c;
  unsigned char *z = (unsigned char*)*pz;
  unsigned char *zStart = z;
  while( (c = zValue[0x7f&*(z++)])>=0 ){
     v = (v<<6) + c;
  }
  z--;
  *pLen -= (int)(z - zStart);
  *pz = (char*)z;
  return v;
}

/* verbatim */
static int rbuDeltaOutputSize(const char *zDelta, int lenDelta){
  int size;
  size = rbuDeltaGetInt(&zDelta, &lenDelta);
  if( lenDelta<=0 || *zDelta!='\n' ){
    return -1;
  }
  return size;
}

int main(void){
  /* simulates: SELECT rbu_fossil_delta(x'00', NULL);
  ** rbuFossilDeltaFunc has NO SQLITE_NULL guard on argv[1] at all --
  ** sqlite3_value_blob(NULL-typed value) returns NULL, sqlite3_value_bytes
  ** returns 0. */
  const char *aDelta = 0;
  int nDelta = 0;

  printf("calling rbuDeltaOutputSize(NULL, 0), as rbuFossilDeltaFunc() "
         "would for SELECT rbu_fossil_delta(x'00', NULL)...\n");
  int nOut = rbuDeltaOutputSize(aDelta, nDelta);
  printf("nOut = %d (unreachable if rbuDeltaGetInt crashed first)\n", nOut);
  return 0;
}
