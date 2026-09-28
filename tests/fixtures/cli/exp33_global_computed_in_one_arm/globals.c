/* One configuration's initial value comes from the build (DEFAULT_FLAG
 * is passed with -D), which the scan cannot evaluate. */
#ifdef FAST_PATH
int globalFalse = 0;
#else
int globalFalse = DEFAULT_FLAG;
#endif
