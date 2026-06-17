/* A "safe free" macro mirroring curl's lib/curl_setup.h Curl_safefree(ptr):
 * it frees AND nulls its argument. Its name uppercases to contain "FREE", so
 * MEM30-C already treats it as a free — but only the macro-expansion engine
 * (function_macros + macro_nulls_param_indices) reveals the `(ptr) = NULL`, so
 * the pointer is freed but NOT left dangling (task 185, Phase 2c-iii). */
#ifndef SAFEFREE_H
#define SAFEFREE_H

#define my_safefree(ptr)  do { free(ptr); (ptr) = NULL; } while(0)

#endif
