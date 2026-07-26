/*
 * Rule: ERR02-C
 * Source: wiki
 * Status: FAIL - Should trigger ERR02-C violation
 */

ssize_t read(int fildes, void *buf, size_t nbyte);