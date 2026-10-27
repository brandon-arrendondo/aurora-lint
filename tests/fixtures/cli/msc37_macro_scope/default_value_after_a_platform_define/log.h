#ifndef LOG_H
#define LOG_H

#if defined(__linux__)
#define FATAL_ABORTS 1
#endif

#ifndef FATAL_ABORTS
#define FATAL_ABORTS 1
#endif

__attribute__((noreturn)) void die(const char *m);
void log_msg(const char *m);

#ifdef FATAL_ABORTS
#define FATAL(m) die(m)
#else
#define FATAL(m) log_msg(m)
#endif

#endif
