/*
 * Rule: INT09-C
 * Status: PASS - curl.h-style idioms (task 452/453):
 * 1) explicit values built from #define macro arithmetic (not just prior
 *    enumerator names), so distinct type-tag macros must resolve to
 *    distinct values instead of phantom-colliding at 0.
 * 2) a call-syntax attribute-position macro (CURL_DEPRECATED) between an
 *    enumerator's name and its `=` initializer, split across lines.
 * 3) the whole enum wrapped in the standard extern "C" C/C++ interop idiom,
 *    which must not hide the #define macros above it from resolution.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define CURLINFO_STRING   0x100000
#define CURLINFO_LONG     0x200000
#define CURLINFO_DOUBLE   0x300000
#define CURLINFO_OFF_T    0x600000

#define CURL_DEPRECATED(version, message) \
  __attribute__((deprecated("since " #version ". " message)))

typedef enum {
  CURLINFO_NONE,
  CURLINFO_EFFECTIVE_URL    = CURLINFO_STRING + 1,
  CURLINFO_RESPONSE_CODE    = CURLINFO_LONG   + 2,
  CURLINFO_TOTAL_TIME       = CURLINFO_DOUBLE + 3,
  CURLINFO_SIZE_UPLOAD CURL_DEPRECATED(7.55.0, "Use CURLINFO_SIZE_UPLOAD_T")
                            = CURLINFO_DOUBLE + 7,
  CURLINFO_SIZE_UPLOAD_T    = CURLINFO_OFF_T  + 7,
  CURLINFO_SIZE_DOWNLOAD
                       CURL_DEPRECATED(7.55.0, "Use CURLINFO_SIZE_DOWNLOAD_T")
                            = CURLINFO_DOUBLE + 8,
  CURLINFO_SIZE_DOWNLOAD_T  = CURLINFO_OFF_T  + 8,
  CURLINFO_HEADER_SIZE      = CURLINFO_LONG   + 9
} CURLINFO;

#ifdef __cplusplus
} /* end of extern "C" */
#endif
