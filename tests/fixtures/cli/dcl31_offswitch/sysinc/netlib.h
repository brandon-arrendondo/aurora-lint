/* A system header, reduced from c-ares' ares.h: a NetWare-only include of a
 * header no Linux host has, beside a sys/ directory that does exist. */
#ifndef NETLIB_H
#define NETLIB_H
#if (defined(NETWARE) && !defined(__NOVELL_LIBC__))
#include <sys/bsdskt.h>
#endif
#include <sys/netlib_missing.h>
int netlib_init(void);
#endif
