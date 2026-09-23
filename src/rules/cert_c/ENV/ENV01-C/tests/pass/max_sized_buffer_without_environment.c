/*
 * Rule: ENV01-C
 * Source: real-world -- the misfire shape (570 of 572 real-world labels)
 * Status: PASS - a PATH_MAX / NI_MAXHOST buffer is not an environment variable
 */

#include <stdio.h>
#include <string.h>

#define PATH_MAX 4096
#define NI_MAXHOST 1025
#define MYSQL_MAX_REQUEST_LENGTH 8192

static char who[PATH_MAX + 1];

int f(const char *dir, const char *name) {
  char buf[PATH_MAX];
  char hbuf[NI_MAXHOST];
  char query[MYSQL_MAX_REQUEST_LENGTH];
  snprintf(buf, sizeof buf, "%s/%s", dir, name);
  strcpy(hbuf, name);
  strcpy(query, dir);
  strcpy(who, buf);
  return (int)strlen(buf);
}
