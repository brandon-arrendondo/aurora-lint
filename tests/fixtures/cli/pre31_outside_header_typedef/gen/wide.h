#ifndef WIDE_H
#define WIDE_H
/* Built outside the project, as a generated header is. */
#ifdef WIDE_INT64_TYPE
  typedef WIDE_INT64_TYPE wide_int64;
#elif defined(_MSC_VER)
  typedef __int64 wide_int64;
#else
  typedef long long int wide_int64;
#endif
typedef wide_int64 wide64;
#endif
