/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Expect: default=clean strict=violation
 * Reason: ntohs is free of side effects by the ISO C/POSIX library contract,
 * and GetLastError is outside that contract, so it is a call to an unknown
 * function. The default preset reports neither; the strict preset trusts no
 * library and reports both.
 */

unsigned short ntohs(unsigned short);
unsigned long GetLastError(void);

#ifdef VERBOSE
#define LOG(fmt, a, b) log_it(fmt, a, b)
#else
#define LOG(fmt, a, b)
#endif

void log_it(const char *, unsigned, unsigned long);

void n(unsigned short port) {
    LOG("port %u err %lu", ntohs(port), GetLastError());
}
