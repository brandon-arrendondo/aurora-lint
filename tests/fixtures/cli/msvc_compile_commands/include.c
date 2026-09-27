/* msvc_idx.h is reachable only through the compile database's /I ../sdk. */
#include <msvc_idx.h>
static int table[8];
void set_last(void) { table[IDX] = 1; }
