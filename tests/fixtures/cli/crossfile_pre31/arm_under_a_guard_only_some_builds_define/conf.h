#ifndef CONF_H
#define CONF_H

/* A Windows build provides the conversion as a function. */
#if defined(WIN)
#define USE_FN
#endif

int use_once(int);

#if !defined(USE_FN)
#define conv(n) use_once((n))
#endif

#endif
