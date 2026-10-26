#ifndef CONF_H
#define CONF_H

#if defined(WIN)
#define USE_FN
#endif

#if !defined(USE_FN)
#define conv(n) ((n) + (n))
#endif

#endif
