/* One configuration leaves the flag zero-initialized, the other sets it. */
#ifdef FAST_PATH
int globalOn;
#else
int globalOn = 1;
#endif
