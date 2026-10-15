struct api_routines { void (*free)(void *); };
#define API_INIT const struct api_routines *api = 0;
#define api_free api->free
